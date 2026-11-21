"""An OUTBOUND connection/token vault for PCA agents: it holds an agent's third-party OAuth tokens and refreshes them, releasing a
fresh, least-privilege access token only when a verified Proof-Carrying Action proves authority over the provider and scopes.
A port of the TypeScript reference (@atlasauth/pca-connect): `oauth_scope` caveats, token refresh, the proxy-mode request
extractor, signed release receipts, the envelope-encrypted store and the TokenVault.

The reference's async functions are synchronous here. Injected transports are plain callables: `fetch(url, init)` returns an object
with `ok`, `status`, `json()` and `text()`; `proxy_fetch(req)` returns `{status, headers, body}`; the `replay` option is a one-time-use store
(`connect_replay.InMemoryReplayStore` or your own: `consume_once(key, retain_until_ms, now_ms) -> bool`). The key wrapper of the
encrypted store needs the optional `cryptography` package (AES-256-GCM)."""
from ._fin import fin
import base64
import json
import re
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

from .agent import KeyPair, sign_artifact
from .connect_replay import guard_pcactn_replay
from .escalation import escalation_action_digest
from .intent_wb import verify_artifact_sig
from .pca import utf8, hash_canonical, params_digest, strict_parse, unb64u, verify_pcactn_core, b64u
from .predicates import _UNDEF, _js_string
from .wallet import _entries, _g

__all__ = [
    "OAUTH_SCOPE_CAVEAT", "oauth_scope_caveat", "is_oauth_scope_caveat", "granted_oauth_scopes",
    "VaultError", "NotAuthorizedError", "ScopeExceededError", "ExpiredNoRefreshError", "RefreshFailedError", "UnknownConnectionError",
    "StoreError", "UnknownActionError", "UnconfirmedActionError", "RequestMismatchError", "BearerReleaseDisabledError", "ProxyFailedError",
    "DEFAULT_PROXY_HEADERS", "RELEASE_RECEIPT_DOMAIN", "http_extractor", "check_proxy_headers", "outbound_request_digest",
    "sign_release_receipt", "verify_release_receipt", "receipt_action_digest", "refresh_connection", "clone_connection",
    "InMemoryConnectionStore", "LocalKeyWrapper", "EncryptedConnectionStore", "TokenVault",
]

# ---- the oauth_scope caveat (authority.ts) ----------------------------------------------------------------------------------------

OAUTH_SCOPE_CAVEAT = "oauth_scope"


class InvalidUrlError(ValueError, TypeError):
    """The reference runtime's URL parser error (ERR_INVALID_URL)."""
    code = "ERR_INVALID_URL"


def oauth_scope_caveat(provider: str, scopes: Sequence[str]) -> Dict[str, Any]:
    """An `oauth_scope` caveat granting `scopes` on `provider`; duplicate scopes are collapsed."""
    return {"type": OAUTH_SCOPE_CAVEAT, "provider": provider, "scopes": list(dict.fromkeys(scopes))}


def is_oauth_scope_caveat(cv: Any) -> bool:
    if not isinstance(cv, dict) or "type" not in cv or "provider" not in cv or "scopes" not in cv:
        return False
    sc = cv["scopes"]
    return cv["type"] == OAUTH_SCOPE_CAVEAT and isinstance(cv["provider"], str) and isinstance(sc, list) and all(isinstance(x, str) for x in sc)


def granted_oauth_scopes(chain: Any, provider: str) -> Optional[set]:
    """The INTERSECTION of every `oauth_scope` caveat naming `provider` in the chain's leaf, or None when the chain grants nothing for
    it (so the vault can tell "not covered" from "covered but too narrow"). Run the chain verifier first."""
    if not isinstance(chain, list) or len(chain) == 0:
        return None
    leaf = chain[-1]
    if leaf is None:
        raise TypeError("Cannot read properties of null")
    if not isinstance(leaf, dict) or not isinstance(leaf.get("caveats"), list):
        return None
    effective: Optional[set] = None
    for cv in leaf["caveats"]:
        if not is_oauth_scope_caveat(cv) or cv["provider"] != provider:
            continue
        here = set(cv["scopes"])
        effective = here if effective is None else {s for s in effective if s in here}
    return effective


# ---- errors (errors.ts) -------------------------------------------------------------------------------------------------------------

class VaultError(Exception):
    """Base class of every typed refusal of the vault; branch on `.code`."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class NotAuthorizedError(VaultError):
    def __init__(self, message: str, checks: Any = None):
        super().__init__("not_authorized", message)
        self.checks = checks


class ScopeExceededError(VaultError):
    def __init__(self, provider: str, requested: Sequence[str], granted: Sequence[str], missing: Sequence[str]):
        super().__init__("scope_exceeded", "requested scopes exceed the capability's grant for '%s': not granted [%s]" % (provider, ", ".join(missing)))
        self.provider, self.requested, self.granted, self.missing = provider, list(requested), list(granted), list(missing)


class ExpiredNoRefreshError(VaultError):
    def __init__(self, provider: str, connection_id: str):
        super().__init__("expired_no_refresh", "connection '%s/%s' token is expired and has no refresh token" % (provider, connection_id))
        self.provider, self.connection_id = provider, connection_id


class RefreshFailedError(VaultError):
    def __init__(self, provider: str, detail: str, status: Optional[int] = None):
        super().__init__("refresh_failed", "refresh for '%s' failed: %s" % (provider, detail))
        self.provider = provider
        self.status = status


class UnknownConnectionError(VaultError):
    def __init__(self, agent_id: str, provider: str, connection_id: str):
        super().__init__("unknown_connection", "no connection for agent '%s' provider '%s' id '%s'" % (agent_id, provider, connection_id))
        self.agent_id, self.provider, self.connection_id = agent_id, provider, connection_id


class StoreError(VaultError):
    def __init__(self, message: str = "the connection store failed"):
        super().__init__("store_error", message)


class UnknownActionError(VaultError):
    def __init__(self, verb: str):
        super().__init__("unknown_action", "no pinned action definition for verb '%s': refusing to release a credential" % verb)


class UnconfirmedActionError(VaultError):
    def __init__(self, verb: str):
        super().__init__("unconfirmed_action", "the definition of '%s' has no valid signed confirmation: refusing to release a credential" % verb)


class RequestMismatchError(VaultError):
    def __init__(self, message: str):
        super().__init__("request_mismatch", message)


class BearerReleaseDisabledError(VaultError):
    def __init__(self):
        super().__init__("bearer_release_disabled", "this vault does not release bearer tokens to callers; use proxyCall(), or construct it with insecureBearerRelease: true (insecure: the caller can use the token for anything inside its scopes until it expires)")


class ProxyFailedError(VaultError):
    def __init__(self, message: str):
        super().__init__("proxy_failed", message)


# ---- stored connections (store.ts) ---------------------------------------------------------------------------------------------------

def clone_connection(c: Dict[str, Any]) -> Dict[str, Any]:
    a = c["authority"]
    auth = {"provider": a["provider"], "principal": a["principal"], "scopes": list(a["scopes"])}
    if "audience" in a:
        auth["audience"] = a["audience"]
    out = {"agentId": c["agentId"], "provider": c["provider"], "connectionId": c["connectionId"], "accessToken": c["accessToken"],
           "expiresAt": c["expiresAt"], "scopes": list(c["scopes"]), "authority": auth, "createdAt": c["createdAt"], "useCount": c["useCount"]}
    if "refreshToken" in c:
        out["refreshToken"] = c["refreshToken"]
    if "lastUsedAt" in c:
        out["lastUsedAt"] = c["lastUsedAt"]
    return out


def _key_string(key: Dict[str, Any]) -> str:
    return "%s\u0000%s\u0000%s" % (_js_string(key["agentId"]), _js_string(key["provider"]), _js_string(key["connectionId"]))


class InMemoryConnectionStore:
    """Process-local connection store; records are cloned in and out so callers cannot mutate vault state."""

    def __init__(self) -> None:
        self._map: Dict[str, Dict[str, Any]] = {}

    def get(self, key: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        found = self._map.get(_key_string(key))
        return None if found is None else clone_connection(found)

    def set(self, connection: Dict[str, Any]) -> None:
        self._map[_key_string(connection)] = clone_connection(connection)

    def delete(self, key: Dict[str, Any]) -> None:
        self._map.pop(_key_string(key), None)


# ---- the proxy-mode request extractor (proxy.ts) -----------------------------------------------------------------------------------

_SPECIAL_PORTS = {"ftp": 21, "http": 80, "https": 443, "ws": 80, "wss": 443}
_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_]+)\}")
_HEX = re.compile(r"[0-9A-Fa-f]{2}")


def _pct_encode(s: str, extra: str, allow_pct: bool = True) -> str:
    out = []
    for b in s.encode("utf-8", "surrogatepass"):
        if b < 0x21 or b > 0x7E or chr(b) in extra:
            out.append("%%%02X" % b)
        else:
            out.append(chr(b))
    return "".join(out)


class _Url:
    """The part of the WHATWG URL parse the extractor reads, for special schemes (http, https, ftp, ws, wss)."""

    def __init__(self, text: Any):
        if not isinstance(text, str):
            raise InvalidUrlError("Invalid URL")
        text = text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")  # the parser takes a USVString: a lone surrogate is U+FFFD
        s = re.sub(r"[\t\n\r]", "", text.strip("".join(chr(i) for i in range(0x21))))
        m = re.match(r"([A-Za-z][A-Za-z0-9+.\-]*):", s)
        if not m or m.group(1).lower() not in _SPECIAL_PORTS:
            raise InvalidUrlError("Invalid URL")
        self.scheme = m.group(1).lower()
        rest = s[m.end():].lstrip("/\\")
        end = next((i for i, ch in enumerate(rest) if ch in "/\\?#"), len(rest))
        auth, rest = rest[:end], rest[end:]
        self.username = self.password = ""
        if "@" in auth:
            userinfo, auth = auth.rsplit("@", 1)
            u, _, p = userinfo.partition(":")
            self.username, self.password = u, p
        host, port = auth, ""
        if auth.startswith("["):
            i = auth.find("]")
            if i < 0 or (auth[i + 1:] != "" and not auth[i + 1:].startswith(":")):
                raise InvalidUrlError("Invalid URL")
            host, port = auth[:i + 1], auth[i + 2:]
        elif ":" in auth:
            host, port = auth.split(":", 1)
        host = self._host(host)
        if port != "":
            if not re.fullmatch("[0-9]+", port) or int(port) > 65535:
                raise InvalidUrlError("Invalid URL")
            self.port = "" if int(port) == _SPECIAL_PORTS[self.scheme] else str(int(port))
        else:
            self.port = ""
        self.host = host
        frag = None
        if "#" in rest:
            rest, frag = rest.split("#", 1)
        query = None
        if "?" in rest:
            rest, query = rest.split("?", 1)
        self.hash = "" if not frag else "#" + _pct_encode(frag, '"<>`')
        self._query = "" if query is None else _pct_encode(query, "\"#<>'")
        self.search = "" if not self._query else "?" + self._query
        segs = re.split(r"[/\\]", rest[1:]) if rest else [""]
        out: List[str] = []
        for i, seg in enumerate(segs):
            low = seg.lower()
            last = i == len(segs) - 1
            if low in ("..", ".%2e", "%2e.", "%2e%2e"):
                if out:
                    out.pop()
                if last:
                    out.append("")
            elif low in (".", "%2e"):
                if last:
                    out.append("")
            else:
                out.append(_pct_encode(seg, "\"#<>?`{}"))
        self.pathname = "/" + "/".join(out)
        self.origin = "%s://%s%s" % (self.scheme, self.host, (":" + self.port) if self.port else "")

    @staticmethod
    def _host(h: str) -> str:
        if h == "":
            raise InvalidUrlError("Invalid URL")
        if h.startswith("["):
            import ipaddress
            try:
                return "[%s]" % ipaddress.IPv6Address(h[1:-1]).compressed if h.endswith("]") else _bad()
            except ValueError:
                raise InvalidUrlError("Invalid URL") from None
        h = _pct_decode_str(h).lower()
        if re.search("[\x00\t\n\r #/:<>?@\\[\\\\\\]^|%\x7f]", h) or h == "":
            raise InvalidUrlError("Invalid URL")
        if not h.isascii():
            try:
                h = h.encode("idna").decode("ascii")
            except UnicodeError:
                raise InvalidUrlError("Invalid URL") from None
        return h

    def search_params(self) -> List[Any]:
        return _form_pairs(self._query)


def _bad() -> str:
    raise InvalidUrlError("Invalid URL")


def _pct_decode_bytes(s: str) -> bytes:
    out = bytearray()
    i = 0
    raw = s.encode("utf-8", "surrogatepass")
    while i < len(raw):
        if raw[i] == 0x25 and i + 2 < len(raw) + 0 and _HEX.fullmatch(raw[i + 1:i + 3].decode("latin-1")):
            out.append(int(raw[i + 1:i + 3], 16))
            i += 3
        else:
            out.append(raw[i])
            i += 1
    return bytes(out)


def _pct_decode_str(s: str) -> str:
    return _pct_decode_bytes(s).decode("utf-8", "replace")


def _form_pairs(s: str) -> List[Any]:
    """application/x-www-form-urlencoded parse (URLSearchParams): '+' is a space, bad percent escapes stay literal."""
    out = []
    for seq in s.split("&"):
        if seq == "":
            continue
        k, _, v = seq.partition("=")
        out.append((_pct_decode_str(k.replace("+", " ")), _pct_decode_str(v.replace("+", " "))))
    return out


def _decode_uri_component(s: str) -> str:
    """decodeURIComponent: each run of %XX escapes must be well-formed UTF-8 (URIError otherwise); every other character, a lone
    surrogate included, passes through unchanged."""
    out: List[str] = []
    i = 0
    while i < len(s):
        if s[i] != "%":
            out.append(s[i])
            i += 1
            continue
        raw = bytearray()
        while i < len(s) and s[i] == "%":
            h = s[i + 1:i + 3]
            if not re.fullmatch("[0-9A-Fa-f]{2}", h):
                raise ValueError("URI malformed")
            raw.append(int(h, 16))
            i += 3
        try:
            out.append(bytes(raw).decode("utf-8"))
        except UnicodeDecodeError:
            raise ValueError("URI malformed") from None
    return "".join(out)


def _mismatch(m: str) -> None:
    raise RequestMismatchError("outbound request refused: " + m)


def _esc(s: str) -> str:
    return re.escape(s)


def http_extractor(spec: Dict[str, Any]) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """The extractor of one operation: maps an outbound request back to the action's parameters and refuses anything the pinned
    spec does not carry (an extra query key, body member, header or redirect target). Raises TypeError on a malformed spec."""
    spec_url = spec["url"]
    try:
        u = _Url(_PLACEHOLDER.sub("x", spec_url))
    except InvalidUrlError:
        raise
    except ValueError:
        raise InvalidUrlError("Invalid URL") from None
    if u.scheme != "https" or u.search != "" or u.hash != "" or u.username != "" or u.password != "":
        raise TypeError("httpExtractor: url must be https without query, fragment or userinfo")
    if spec["method"] != spec["method"].upper():
        raise TypeError("httpExtractor: method must be upper case")
    names: List[str] = []
    origin = u.origin
    template = spec_url[len(origin):]
    pat = []
    for i, part in enumerate(_PLACEHOLDER.split(template)):
        if i % 2 == 1:
            names.append(part)
            pat.append("([A-Za-z0-9._~%-]+)")
        else:
            pat.append(_esc(part))
    rx = re.compile("".join(pat))
    allowed_query = set(spec.get("query") or [])
    body_kind = spec.get("body")
    ctype = "application/json" if body_kind == "json" else "application/x-www-form-urlencoded" if body_kind == "form" else None

    def extract(req: Dict[str, Any]) -> Dict[str, Any]:
        if _g(req, "method") != spec["method"]:
            _mismatch("method %s is not %s" % (_js_string(_g(req, "method")), spec["method"]))
        try:
            r = _Url(_g(req, "url"))
        except ValueError:
            return _mismatch("the url does not parse")  # type: ignore[return-value]
        if r.origin != origin or r.username != "" or r.password != "" or r.hash != "":
            _mismatch("the url is not on the pinned origin")
        m = rx.fullmatch(r.pathname)
        if m is None:
            return _mismatch("the path does not match the pinned template")  # type: ignore[return-value]
        params: Dict[str, Any] = {}

        def put(k: str, v: Any) -> None:
            if k in params:
                _mismatch("parameter '%s' is carried twice" % k)
            params[k] = v

        for i, n in enumerate(names):
            try:
                v = _decode_uri_component(m.group(i + 1))
            except ValueError:
                _mismatch("a path segment is not valid percent-encoding")
            put(n, v)
        seen = set()
        for k, v in r.search_params():
            if k not in allowed_query:
                _mismatch("query key '%s' is not allowed" % k)
            if k in seen:
                _mismatch("query key '%s' is repeated" % k)
            seen.add(k)
            put(k, v)
        hdrs = _g(req, "headers")
        ct = next((v for h, v in ([] if hdrs is _UNDEF or hdrs is None else _entries(hdrs)) if h.lower() == "content-type"), _UNDEF)
        body = _g(req, "body")
        if body_kind is None:
            if body is not _UNDEF and body != "":
                _mismatch("this operation carries no body")
        else:
            if not isinstance(body, str) or len(body) == 0:
                return _mismatch("the body is missing")  # type: ignore[return-value]
            if ct is _UNDEF or ct.split(";")[0].strip().lower() != ctype:
                _mismatch("content-type must be %s" % ctype)
            fixed = dict(spec.get("fixed") or {})
            if body_kind == "json":
                try:
                    b = strict_parse(body)
                except Exception:  # noqa: BLE001
                    return _mismatch("the body is not strict JSON")  # type: ignore[return-value]
                if not isinstance(b, dict):
                    _mismatch("the body must be a JSON object")
                for k, v in b.items():
                    if k in fixed:
                        if hash_canonical(v) != hash_canonical(fixed[k]):
                            _mismatch("fixed member '%s' has another value" % k)
                        del fixed[k]
                    else:
                        put(k, v)
            else:
                keys = set()
                for k, v in _form_pairs(body[1:] if body.startswith("?") else body):
                    if k in keys:
                        _mismatch("form key '%s' is repeated" % k)
                    keys.add(k)
                    if k in fixed:
                        if v != fixed[k]:
                            _mismatch("fixed member '%s' has another value" % k)
                        del fixed[k]
                    else:
                        put(k, v)
            if len(fixed) > 0:
                _mismatch("fixed member(s) %s missing" % ", ".join(fixed))
        return params

    return extract


DEFAULT_PROXY_HEADERS = ("content-type", "accept", "idempotency-key")


def check_proxy_headers(headers: Any, allow: Sequence[str]) -> Dict[str, str]:
    """The request headers the agent may set (the vault sets Authorization itself); anything else is refused."""
    out: Dict[str, str] = {}
    for k, v in ([] if headers is None else _entries(headers)):
        n = k.lower()
        if n not in allow:
            _mismatch("header '%s' is not allowed" % k)
        if n in out:
            _mismatch("header '%s' is repeated" % k)
        if not isinstance(v, str) or re.search("[\r\n\x00]", v):
            _mismatch("header '%s' has an invalid value" % k)
        out[n] = v
    return out


# ---- release receipts (proxy.ts) ------------------------------------------------------------------------------------------------------

RELEASE_RECEIPT_DOMAIN = "atlas-pca/connect-release-receipt/v1\0"


def outbound_request_digest(method: str, url: str, headers: Dict[str, str], body: Optional[str]) -> str:
    return hash_canonical({"d": "atlas-pca/connect-request/v1", "method": method, "url": url, "headers": headers, "body": body})


def sign_release_receipt(body: Dict[str, Any], secret_key: bytes) -> Dict[str, Any]:
    """The receipt body plus an Ed25519 signature of the vault key over domain || canonical(body)."""
    return sign_artifact(RELEASE_RECEIPT_DOMAIN, body, KeyPair(secret_key, allow_insecure_signer=True))


def verify_release_receipt(r: Any, vault_pk: Any) -> bool:
    """True iff the receipt is signed by the pinned vault key."""
    return verify_artifact_sig(RELEASE_RECEIPT_DOMAIN, r, vault_pk)


def receipt_action_digest(p: Any) -> str:
    return escalation_action_digest(p)


# ---- token refresh (refresh.ts) -------------------------------------------------------------------------------------------------------

def _form_encode(params: Dict[str, str]) -> str:
    from urllib.parse import quote
    return "&".join("%s=%s" % (quote(k, safe="-_.!~*'()"), quote(v, safe="-_.!~*'()")) for k, v in params.items())


def _redact(text: str, secrets: Sequence[Optional[str]]) -> str:
    for s in secrets:
        if s is not None and len(s) > 0:
            text = text.replace(s, "[redacted]")
    return text


def _parse_token_response(body: Any, provider: str) -> Dict[str, Any]:
    if body is None or not isinstance(body, dict):
        raise RefreshFailedError(provider, "token endpoint returned a non-object body")
    at = body.get("access_token")
    if not isinstance(at, str) or len(at) == 0:
        raise RefreshFailedError(provider, "token endpoint response has no access_token")
    out: Dict[str, Any] = {"accessToken": at}
    ex = body.get("expires_in")
    if isinstance(ex, (int, float)) and not isinstance(ex, bool) and fin(ex) and ex > 0:
        out["expiresInSecs"] = ex
    rt = body.get("refresh_token")
    if isinstance(rt, str) and len(rt) > 0:
        out["refreshToken"] = rt
    scope = body.get("scope")
    js_ws = "\t\n\x0b\x0c\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
    if isinstance(scope, str) and len(re.sub("^[" + js_ws + "]+|[" + js_ws + "]+$", "", scope)) > 0:
        out["scopes"] = re.split("[" + js_ws + "]+", re.sub("^[" + js_ws + "]+|[" + js_ws + "]+$", "", scope))
    return out


def _jwt_expiry_ms(token: str) -> Optional[Any]:
    """Epoch-ms expiry claimed by a JWT access token; None for an opaque (non-JWT) token."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        pad = parts[1].replace("-", "+").replace("_", "/")
        claims = json.loads(base64.b64decode(pad + "=" * (-len(pad) % 4)).decode("utf-8"))
        exp = claims.get("exp") if isinstance(claims, dict) else None
        return exp * 1000 if isinstance(exp, (int, float)) and not isinstance(exp, bool) and fin(exp) else None
    except Exception:  # noqa: BLE001
        return None


def refresh_connection(connection: Dict[str, Any], config: Optional[Dict[str, Any]], refresh_token: str, requested: Sequence[str],
                       fetch: Optional[Callable[..., Any]], now: Any, default_token_lifetime_ms: Any) -> Dict[str, Any]:
    """Refresh `connection`'s access token at its provider's token endpoint. Returns the fields to apply to the connection (accessToken,
    refreshToken, expiresAt, scopes); raises RefreshFailedError on any transport or parse failure. No secret reaches an error."""
    provider = connection["provider"]
    secrets = [refresh_token, connection["accessToken"], (config or {}).get("clientSecret"), *((config or {}).get("extraParams") or {}).values()]
    if config is None:
        raise RefreshFailedError(provider, "no provider token-endpoint config")
    if fetch is None:
        raise RefreshFailedError(provider, "no fetch transport configured")
    params: Dict[str, str] = {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": config["clientId"]}
    if "clientSecret" in config:
        params["client_secret"] = config["clientSecret"]
    params.update(config.get("extraParams") or {})
    narrowing = config.get("supportsScopeNarrowing") is True
    if narrowing and len(requested) > 0:
        params["scope"] = " ".join(requested)
    try:
        res = fetch(config["tokenEndpoint"], {"method": "POST", "headers": {"content-type": "application/x-www-form-urlencoded", "accept": "application/json"},
                                              "body": _form_encode(params)})
    except Exception as e:  # noqa: BLE001
        raise RefreshFailedError(provider, "transport error: %s" % _redact(str(e), secrets)) from None
    if not res.ok:
        try:
            detail = _redact(_u16prefix(res.text(), 256), secrets)
        except Exception:  # noqa: BLE001
            detail = "<unreadable body>"
        raise RefreshFailedError(provider, "token endpoint %s: %s" % (res.status, detail), res.status)
    try:
        j = res.json()
    except Exception:  # noqa: BLE001
        raise RefreshFailedError(provider, "unparseable JSON body") from None
    parsed = _parse_token_response(j, provider)
    if "expiresInSecs" in parsed:
        expires_at = now + parsed["expiresInSecs"] * 1000
    else:
        jwt = _jwt_expiry_ms(parsed["accessToken"])
        expires_at = jwt if jwt is not None else now + default_token_lifetime_ms
    if "scopes" in parsed:
        scopes = parsed["scopes"]
    elif narrowing and len(requested) > 0:
        scopes = list(requested)
    else:
        scopes = list(connection["scopes"])
    return {"accessToken": parsed["accessToken"], "expiresAt": expires_at, "scopes": scopes, "refreshToken": parsed.get("refreshToken", refresh_token)}


def _u16prefix(s: str, n: int) -> str:
    b = s.encode("utf-16-le", "surrogatepass")
    return b[:2 * n].decode("utf-16-le", "surrogatepass")


# ---- envelope encryption of stored tokens (encrypted-store.ts) ----------------------------------------------------------------------------

_PREFIX = "pca1"


def _aesgcm() -> Any:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise RuntimeError("the encrypted connection store needs the 'cryptography' package") from None
    return AESGCM


def _seal(key: bytes, aad: bytes, plain: bytes, iv: Optional[bytes] = None) -> bytes:
    import os
    iv = iv if iv is not None else os.urandom(12)
    return iv + _aesgcm()(key).encrypt(iv, plain, aad)  # ciphertext || 16-byte tag, as the reference lays it out


def _open(key: bytes, aad: bytes, sealed: bytes) -> bytes:
    if len(sealed) < 12 + 16:
        raise ValueError("short ciphertext")
    return _aesgcm()(key).decrypt(sealed[:12], sealed[12:], aad)


def _unb64u_strict_chars(s: str) -> bytes:
    if not re.fullmatch("[A-Za-z0-9_-]*", s):
        raise ValueError("bad encoding")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class LocalKeyWrapper:
    """A key ring held in process memory (production keys belong behind a KMS implementing wrap and unwrap)."""

    def __init__(self, keys: Dict[str, bytes], active_id: str):
        self._keys: Dict[str, bytearray] = {}
        for i, k in keys.items():
            self.add_key(i, k)
        if active_id not in self._keys:
            raise ValueError("LocalKeyWrapper: the active key id is not in the key ring")
        self._active = active_id

    def add_key(self, key_id: str, key: bytes) -> None:
        if len(key_id) == 0:
            raise ValueError("LocalKeyWrapper: key id must not be empty")
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise ValueError("LocalKeyWrapper: keys must be 32 bytes")
        self._keys[key_id] = bytearray(key)

    def set_active(self, key_id: str) -> None:
        if key_id not in self._keys:
            raise ValueError("LocalKeyWrapper: the active key id is not in the key ring")
        self._active = key_id

    def remove_key(self, key_id: str) -> None:
        if key_id == self._active:
            raise ValueError("LocalKeyWrapper: cannot remove the active key")
        self._keys.pop(key_id, None)

    def destroy(self) -> None:
        for k in self._keys.values():
            for i in range(len(k)):
                k[i] = 0
        self._keys.clear()

    def wrap(self, dek: bytes, aad: bytes) -> Dict[str, Any]:
        k = self._keys.get(self._active)
        if k is None:
            raise ValueError("no active key")
        return {"keyId": self._active, "wrapped": _seal(bytes(k), aad, dek)}

    def unwrap(self, key_id: str, wrapped: bytes, aad: bytes) -> bytes:
        k = self._keys.get(key_id)
        if k is None:
            raise ValueError("unknown key id")
        return _open(bytes(k), aad, wrapped)


def _aad_for(key: Dict[str, Any], field: str) -> bytes:
    parts = ["pca-connect/v1", field, key["agentId"], key["provider"], key["connectionId"]]
    return utf8("|".join("%d:%s" % (len(utf8(p)), p) for p in parts))


def _encrypt_field(w: Any, key: Dict[str, Any], field: str, plain: str) -> str:
    import os
    aad = _aad_for(key, field)
    dek = os.urandom(32)
    wr = w.wrap(dek, aad)
    sealed = _seal(dek, aad, utf8(plain))
    return ".".join([_PREFIX, b64u(utf8(wr["keyId"])), b64u(wr["wrapped"]), b64u(sealed)])


def _decrypt_field(w: Any, key: Dict[str, Any], field: str, value: str) -> str:
    parts = value.split(".")
    if len(parts) != 4 or parts[0] != _PREFIX:
        raise ValueError("not an envelope")
    aad = _aad_for(key, field)
    dek = w.unwrap(_unb64u_strict_chars(parts[1]).decode("utf-8"), _unb64u_strict_chars(parts[2]), aad)
    return _open(dek, aad, _unb64u_strict_chars(parts[3])).decode("utf-8")


class EncryptedConnectionStore:
    """Wraps a connection store so `accessToken` and `refreshToken` are encrypted before they reach it. Fails closed: a stored token
    that is not an envelope, fails authentication or was sealed under an unknown key makes `get` raise a StoreError (no detail)."""

    encrypted = True

    def __init__(self, inner: Any, wrapper: Any):
        self._inner = inner
        self._wrapper = wrapper

    def get(self, key: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raw = self._inner.get(key)
        if raw is None:
            return None
        try:
            out = clone_connection(raw)
            k = {"agentId": raw["agentId"], "provider": raw["provider"], "connectionId": raw["connectionId"]}
            if k["agentId"] != key["agentId"] or k["provider"] != key["provider"] or k["connectionId"] != key["connectionId"]:
                raise ValueError("record key mismatch")
            out["accessToken"] = _decrypt_field(self._wrapper, k, "access", raw["accessToken"])
            if "refreshToken" in raw:
                out["refreshToken"] = _decrypt_field(self._wrapper, k, "refresh", raw["refreshToken"])
            return out
        except Exception:  # noqa: BLE001
            raise StoreError("a stored token could not be decrypted") from None

    def set(self, connection: Dict[str, Any]) -> None:
        k = {"agentId": connection["agentId"], "provider": connection["provider"], "connectionId": connection["connectionId"]}
        sealed = clone_connection(connection)
        try:
            sealed["accessToken"] = _encrypt_field(self._wrapper, k, "access", connection["accessToken"])
            if "refreshToken" in connection:
                sealed["refreshToken"] = _encrypt_field(self._wrapper, k, "refresh", connection["refreshToken"])
        except Exception:  # noqa: BLE001
            raise StoreError("a token could not be encrypted; nothing was stored") from None
        self._inner.set(sealed)

    def delete(self, key: Dict[str, Any]) -> None:
        self._inner.delete(key)

    def reencrypt(self, key: Dict[str, Any]) -> bool:
        """Re-encrypt one record under the wrapper's active key (run after rotating the key ring)."""
        c = self.get(key)
        if c is None:
            return False
        self.set(c)
        return True


# ---- the vault (vault.ts) -----------------------------------------------------------------------------------------------------------

_DEFAULT = object()


class TokenVault:
    """Holds an agent's third-party OAuth tokens and releases a fresh access token only for a verified PCActn. Options mirror the
    reference's (snake_case); `actions(verb)` returns a dict {verb, def_digest, confirmed, upstream: {provider, scopes_min}, extract?}
    or None; `receipts` is {"secret_key": 32-byte seed, "sink": callable?}; `replay` is the one-time-use store."""

    def __init__(self, store: Any = None, providers: Optional[Dict[str, Any]] = None, fetch: Any = None, now: Optional[Callable[[], Any]] = None,
                 audience: Any = None, pq_pins: Any = None, authorized_plan_roots: Any = None, insecure_skip_plan_root_check: bool = False,
                 expiry_leeway_ms: Any = None, default_connection_id: Optional[str] = None, require_action_binding: Optional[bool] = None,
                 resource_for: Optional[Callable[[str, str], str]] = None, use_verb: Any = _DEFAULT, default_token_lifetime_ms: Any = None,
                 replay: Any = None, is_revoked: Any = None, strict: Optional[bool] = None, actions: Any = None,
                 insecure_bearer_release: bool = False, proxy_fetch: Any = None, proxy_headers: Optional[Sequence[str]] = None,
                 max_proxy_response_bytes: Any = None, receipts: Optional[Dict[str, Any]] = None):
        if strict is not False:
            missing = []
            if getattr(store, "encrypted", None) is not True:
                missing.append("an encrypting store")
            if replay is None:
                missing.append("replay")
            if is_revoked is None:
                missing.append("isRevoked")
            if not isinstance(audience, str) or len(audience) == 0:
                missing.append("audience")
            if missing:
                raise ValueError("TokenVault strict mode requires %s" % ", ".join(missing))
        elif store is None:
            raise ValueError("TokenVault requires a store")
        self._actions = actions
        self._bearer = insecure_bearer_release is True
        self._proxy_fetch = proxy_fetch
        self._proxy_headers = [h.lower() for h in (DEFAULT_PROXY_HEADERS if proxy_headers is None else proxy_headers)]
        self._max_proxy = 4 * 1024 * 1024 if max_proxy_response_bytes is None else max_proxy_response_bytes
        self._receipts = receipts
        self._replay = replay
        self._is_revoked = is_revoked
        self._store = store
        self._providers = providers or {}
        self._fetch = fetch
        self._now = now if now is not None else (lambda: int(time.time() * 1000))
        self._audience = audience
        self._pq_pins = pq_pins
        self._plan_roots = authorized_plan_roots
        self._skip_plan_root = insecure_skip_plan_root_check is True
        self._leeway = 30_000 if expiry_leeway_ms is None else expiry_leeway_ms
        self._default_cid = "default" if default_connection_id is None else default_connection_id
        self._require_binding = True if require_action_binding is None else require_action_binding
        self._resource_for = resource_for or (lambda provider, cid: "oauth:%s" % provider)
        self._use_verb = "use_connection" if use_verb is _DEFAULT else use_verb
        self._default_lifetime = 300_000 if default_token_lifetime_ms is None else default_token_lifetime_ms

    def put_connection(self, agent_id: str, provider: str, access_token: str, expires_at: Any, scopes: Sequence[str], authority: Dict[str, Any],
                       connection_id: Optional[str] = None, refresh_token: Optional[str] = None) -> Dict[str, Any]:
        """Store (or replace) an agent's connection; the authority descriptor binds which capability may use it."""
        cid = connection_id if connection_id is not None else self._default_cid
        for k, val in (("agentId", agent_id), ("provider", provider), ("connectionId", cid), ("accessToken", access_token),
                       ("principal", authority.get("principal") if isinstance(authority, dict) else None)):
            if not isinstance(val, str) or len(val) == 0:
                raise TypeError("putConnection: %s must be a non-empty string" % k)
        if not (isinstance(expires_at, (int, float)) and not isinstance(expires_at, bool) and fin(expires_at)):
            raise TypeError("putConnection: expiresAt must be a finite number")
        if refresh_token is not None and (not isinstance(refresh_token, str) or len(refresh_token) == 0):
            raise TypeError("putConnection: refreshToken must be a non-empty string when given")
        if not isinstance(scopes, list) or any(not isinstance(s, str) for s in scopes):
            raise TypeError("putConnection: scopes must be a list of strings")
        auth = {"provider": provider, "principal": authority["principal"], "scopes": list(authority["scopes"] if authority.get("scopes") is not None else scopes)}
        if authority.get("audience") is not None:
            auth["audience"] = authority["audience"]
        conn = {"agentId": agent_id, "provider": provider, "connectionId": cid, "accessToken": access_token, "expiresAt": expires_at,
                "scopes": list(scopes), "authority": auth, "createdAt": self._now(), "useCount": 0}
        if refresh_token is not None:
            conn["refreshToken"] = refresh_token
        self._store_set(conn)
        return conn

    def get_connection_token(self, pcactn: Dict[str, Any], provider: str, connection_id: Optional[str] = None, scopes: Optional[List[str]] = None) -> Dict[str, Any]:
        """A FRESH access token iff `pcactn` verifies against the connection's bound principal and the chain's grant covers the requested
        provider and scopes. Disabled unless the vault was built with insecure_bearer_release (prefer `proxy_call`)."""
        if not self._bearer:
            raise BearerReleaseDisabledError()
        a = self._authorize(pcactn, provider, connection_id, scopes, False, None)
        token, refreshed = self._fresh_token(a)
        done = self._record_use(a, token)
        self._issue_receipt(pcactn, a, "bearer", None, None, "released", done["scopes"])
        exp = pcactn.get("exp")
        finite = isinstance(exp, (int, float)) and not isinstance(exp, bool) and fin(exp)
        return {"provider": a["provider"], "connectionId": a["connectionId"], "accessToken": done["accessToken"], "scopes": list(done["scopes"]),
                "expiresAt": min(done["expiresAt"], exp) if a["action"] is not None and finite else done["expiresAt"], "refreshed": refreshed}

    def proxy_call(self, pcactn: Dict[str, Any], request: Dict[str, Any], provider: str, connection_id: Optional[str] = None,
                   scopes: Optional[List[str]] = None) -> Dict[str, Any]:
        """Proxy mode: the vault makes the outbound call itself (the agent never holds the credential). The request must re-derive
        exactly the params the PCActn signed; the action is spent first; redirects are not followed; a receipt links release to effect."""
        if self._actions is None:
            raise TypeError("proxyCall requires the vault to be constructed with `actions`")
        if self._proxy_fetch is None:
            raise TypeError("proxyCall requires the vault to be constructed with `proxyFetch`")
        send_headers = check_proxy_headers(_g(request, "headers") if _g(request, "headers") is not _UNDEF else None, self._proxy_headers)
        a = self._authorize(pcactn, provider, connection_id, scopes, True, request)
        token, _refreshed = self._fresh_token(a)
        done = self._record_use(a, token)
        headers = dict(send_headers)
        headers["authorization"] = "Bearer %s" % done["accessToken"]
        body = request.get("body")
        req_digest = outbound_request_digest(request["method"], request["url"], send_headers, body)
        call = {"method": request["method"], "url": request["url"], "headers": headers, "redirect": "manual"}
        if "body" in request:
            call["body"] = body
        try:
            response = self._proxy_fetch(call)
        except Exception:  # noqa: BLE001
            self._issue_receipt(pcactn, a, "proxy", req_digest, None, "failed", done["scopes"])
            raise ProxyFailedError("the outbound call failed before a response") from None
        rbody = response.get("body") if isinstance(response, dict) else None
        size = len(rbody.encode("utf-8", "surrogatepass")) if isinstance(rbody, str) else float("inf")
        status = response.get("status") if isinstance(response, dict) else None
        ok_status = isinstance(status, (int, float)) and not isinstance(status, bool) and float(status).is_integer() and abs(status) <= 2 ** 53 - 1
        receipt = self._issue_receipt(pcactn, a, "proxy", req_digest, status if ok_status else None, "executed", done["scopes"])
        if size > self._max_proxy:
            raise ProxyFailedError("the response is larger than maxProxyResponseBytes (the call was made and the action is spent)")
        tok = done["accessToken"]
        rb = rbody.replace(tok, "[redacted]")
        rh: Dict[str, str] = {}
        for k, v in (response.get("headers") or {}).items():
            if k.lower() != "set-cookie":
                rh[k] = _js_string(v).replace(tok, "[redacted]")
        out: Dict[str, Any] = {"response": {"status": status, "headers": rh, "body": rb}}
        if receipt:
            out["receipt"] = receipt
        return out

    def _authorize(self, pcactn: Dict[str, Any], provider: str, connection_id: Optional[str], scopes: Optional[List[str]], need_action: bool,
                   request: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        cid = connection_id if connection_id is not None else self._default_cid
        chain = _g(pcactn, "cap_chain")  # a non-object PCActn has no members: `undefined`
        if not isinstance(chain, list) or len(chain) == 0:
            raise NotAuthorizedError("PCActn has no capability chain")
        leaf, root = chain[-1], chain[0]
        if leaf is None or root is None:
            raise NotAuthorizedError("PCActn capability chain is malformed")
        agent_id = _g(leaf, "holder")  # a non-object leaf or a missing holder is `undefined`
        connection = self._store_get({"agentId": agent_id, "provider": provider, "connectionId": cid})
        if connection is None:
            raise UnknownConnectionError(_js_string(agent_id), _js_string(provider), _js_string(cid))
        if root["issuer"] != connection["authority"]["principal"]:
            raise NotAuthorizedError("capability chain is not rooted at the connection's bound principal")
        now = self._now()
        audience = connection["authority"].get("audience", self._audience)
        # audience None accepts any audience: the Python verifier has no opt-out, so it is given the action's own signed aud
        v = verify_pcactn_core(pcactn, root, now=now, audience=pcactn.get("aud") if audience is None else audience,
                               authorized_plan_roots=self._plan_roots, insecure_skip_plan_root_check=self._skip_plan_root, pq_pins=self._pq_pins)
        if not v.allow:
            raise NotAuthorizedError("PCActn verification failed: %s" % (v.reason or "rejected"), v.checks)
        if self._is_revoked is not None:
            try:
                revoked = self._is_revoked(pcactn) is not False
            except Exception:  # noqa: BLE001
                raise NotAuthorizedError("revocation source unavailable") from None
            if revoked:
                raise NotAuthorizedError("the capability chain is revoked")
        action: Optional[Dict[str, Any]] = None
        act = pcactn["action"]
        if self._actions is not None:
            verb = act["verb"]
            action = self._actions(verb)
            if action is None or action["verb"] != verb:
                raise UnknownActionError(_js_string(verb))
            if action.get("confirmed") is not True:
                raise UnconfirmedActionError(verb)
            if action["upstream"]["provider"] != provider:
                raise NotAuthorizedError("the action '%s' is not for provider '%s'" % (verb, provider))
            smin = action["upstream"].get("scopes_min")
            if not isinstance(smin, list) or len(smin) == 0:
                raise NotAuthorizedError("the action '%s' declares no upstream scopes (nothing to release)" % verb)
        elif need_action:
            raise UnknownActionError(_js_string(act["verb"]))
        elif self._require_binding:
            expected = self._resource_for(provider, cid)
            if act["resource"] != expected:
                raise NotAuthorizedError("PCActn action resource '%s' is not for this connection (expected '%s')" % (act["resource"], expected))
            if self._use_verb is not None and act["verb"] != self._use_verb:
                raise NotAuthorizedError("PCActn action verb '%s' is not a connection-use verb (expected '%s')" % (act["verb"], self._use_verb))
        granted = granted_oauth_scopes(chain, provider)
        if granted is None:
            raise NotAuthorizedError("capability grants no authority for provider '%s'" % provider)
        if action is not None:
            mn = list(action["upstream"]["scopes_min"])
            requested = scopes if scopes is not None else mn
            beyond = [s for s in requested if s not in mn]
            if beyond:
                raise ScopeExceededError(provider, requested, mn, beyond)
            unheld = [s for s in mn if s not in connection["scopes"] or s not in connection["authority"]["scopes"]]
            if unheld:
                raise ScopeExceededError(provider, mn, connection["scopes"], unheld)
            if not need_action:
                extra = [s for s in connection["scopes"] if s not in mn]
                if extra:
                    raise ScopeExceededError(provider, mn, connection["scopes"], extra)
            ungranted = [s for s in mn if s not in granted]
            if ungranted:
                raise ScopeExceededError(provider, mn, list(granted), ungranted)
        else:
            requested = scopes if scopes is not None else connection["authority"]["scopes"]
        missing = [s for s in requested if s not in granted]
        if missing:
            raise ScopeExceededError(provider, requested, list(granted), missing)
        if need_action and action is not None:
            if request is None or action.get("extract") is None:
                raise RequestMismatchError("the action has no request extractor: proxy mode cannot bind the outbound request")
            try:
                params = action["extract"](request)
            except Exception as e:  # noqa: BLE001
                raise e if isinstance(e, RequestMismatchError) else RequestMismatchError("the outbound request could not be mapped to the action parameters") from None
            try:
                d = params_digest(params)
            except Exception:  # noqa: BLE001
                raise RequestMismatchError("the outbound request parameters are not canonical") from None
            if d != act.get("params_digest"):
                raise RequestMismatchError("the outbound request does not carry the parameters the PCActn signed")
        if self._replay is not None:
            verdict = guard_pcactn_replay(self._replay, pcactn, pcactn.get("aud"), now)
            if not verdict["ok"]:
                raise NotAuthorizedError("replay guard refused the action: %s" % verdict.get("reason"))
        return {"agentId": agent_id, "provider": provider, "connectionId": cid, "connection": connection, "requested": list(requested), "now": now, "action": action}

    def _fresh_token(self, a: Dict[str, Any]) -> Any:
        conn, now = a["connection"], a["now"]
        token, refreshed = conn, False
        num_ok = lambda x: isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x)  # noqa: E731
        if not num_ok(conn["expiresAt"]) or not num_ok(now) or conn["expiresAt"] - now <= self._leeway:
            if "refreshToken" not in conn:
                raise ExpiredNoRefreshError(a["provider"], a["connectionId"])
            updated = refresh_connection(conn, self._providers.get(a["provider"]), conn["refreshToken"], a["requested"], self._fetch, now, self._default_lifetime)
            token = dict(conn)
            token.update(updated)
            refreshed = True
        return token, refreshed

    def _record_use(self, a: Dict[str, Any], token: Dict[str, Any]) -> Dict[str, Any]:
        t = dict(token)
        t["lastUsedAt"] = a["now"]
        t["useCount"] = token["useCount"] + 1
        self._store_set(t)
        return t

    def _issue_receipt(self, pcactn: Dict[str, Any], a: Dict[str, Any], mode: str, request_digest: Optional[str], http_status: Any, outcome: str,
                       scopes: Sequence[str]) -> Optional[Dict[str, Any]]:
        if self._receipts is None:
            return None
        receipt = sign_release_receipt({"v": 1, "kind": "pca-release-receipt", "action_digest": receipt_action_digest(pcactn), "provider": a["provider"],
                                        "connection_id": a["connectionId"], "mode": mode, "scopes_released": sorted(scopes, key=lambda s: s.encode("utf-16-be")),
                                        "request_digest": request_digest, "http_status": http_status, "outcome": outcome, "ts": a["now"]},
                                       self._receipts["secret_key"])
        sink = self._receipts.get("sink")
        if sink is not None:
            try:
                sink(receipt)
            except Exception:  # noqa: BLE001 - a failing sink must not turn a made call into an error the caller retries
                pass
        return receipt

    def delete_connection(self, agent_id: str, provider: str, connection_id: Optional[str] = None) -> None:
        try:
            self._store.delete({"agentId": agent_id, "provider": provider, "connectionId": connection_id if connection_id is not None else self._default_cid})
        except VaultError:
            raise
        except Exception:  # noqa: BLE001 - the store's own error text can quote a record
            raise StoreError() from None

    def _store_get(self, key: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            return self._store.get(key)
        except VaultError:
            raise
        except Exception:  # noqa: BLE001
            raise StoreError() from None

    def _store_set(self, c: Dict[str, Any]) -> None:
        try:
            self._store.set(c)
        except VaultError:
            raise
        except Exception:  # noqa: BLE001
            raise StoreError() from None
