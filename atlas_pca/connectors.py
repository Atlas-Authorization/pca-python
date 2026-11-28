"""A declarative catalog of outbound OAuth connectors for the token vault: manifest validation and digests, the provider registry,
the authorize URL with PKCE and URL variables, access-token placement, authorization-code exchange and refresh into the vault, and
the manifest-to-vault-provider mapping. A port of the TypeScript reference (@atlasauth/pca-connectors); the seeded provider
manifests are in :mod:`atlas_pca.connectors_providers` (`BUILTIN_MANIFESTS`).

Manifests and option bags are plain dicts with the reference's member names. Injected transports are callables
(`fetch(url, init)` returning an object with `ok`, `status`, `json()` and `text()`); the vault is an `atlas_pca.connect.TokenVault`."""
from ._fin import fin
import re
import secrets
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote

from .connect import _Url
from .connectors_providers import BUILTIN_MANIFESTS
from .pca import b64u, hash_canonical, sha256, utf8
from .predicates import _UNDEF, _js_string

__all__ = [
    "ConnectorError", "ManifestValidationError", "UnknownProviderError", "RESERVED_AUTHORIZE_PARAMS", "RESERVED_TOKEN_PARAMS",
    "validate_manifest", "assert_manifest", "manifest_digest", "ProviderRegistry", "create_default_registry", "default_registry",
    "register_provider", "get_provider", "list_providers", "catalog_digest", "pkce_challenge", "substitute_vars", "build_authorize_url",
    "apply_access_token", "exchange_code", "refresh", "manifest_to_provider_config", "build_vault_providers",
]

_WS = "\t\n\x0b\x0c\r    -     　﻿"
_WS_OR_COMMA = re.compile("[" + _WS + ",]")
_WS_OR_COMMA_RUN = re.compile("[" + _WS + ",]+")
_TRIM = re.compile("^[" + _WS + "]+|[" + _WS + "]+$")


# ---- errors and manifest (manifest.ts) -------------------------------------------------------------------------------------------

class InvalidUrlError(ValueError):
    """The reference runtime's URL parser error (ERR_INVALID_URL)."""
    code = "ERR_INVALID_URL"


class ConnectorError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class ManifestValidationError(ConnectorError):
    def __init__(self, issues: List[str]):
        super().__init__("invalid provider manifest: %s" % "; ".join(issues))
        self.issues = list(issues)


class UnknownProviderError(ConnectorError):
    def __init__(self, provider_id: str):
        super().__init__("no connector registered for provider '%s'" % provider_id)
        self.provider_id = provider_id


RESERVED_AUTHORIZE_PARAMS = frozenset(["response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"])
RESERVED_TOKEN_PARAMS = frozenset(["grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier", "refresh_token"])
_ID_SOURCE = "^[a-z0-9][a-z0-9._-]*$"
_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]*")
_TOKEN_PLACEMENTS = ("bearer", "header", "query")
_REFRESH_MODES = ("refresh_token", "none")
_CLIENT_AUTHS = ("post", "basic")
_HEADER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")
_FORBIDDEN_HEADERS = frozenset(["host", "content-length", "content-type", "transfer-encoding", "connection", "cookie", "set-cookie"])
_QUERY_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")
_VAR = re.compile(r"\{(\w+)\}", re.ASCII)


def _prop(o: Any, k: str) -> Any:
    return o[k] if isinstance(o, dict) and k in o else _UNDEF


def _is_record(v: Any) -> bool:
    return isinstance(v, dict)


def _non_empty(v: Any) -> bool:
    return isinstance(v, str) and len(v) > 0


def _str_array(v: Any) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _str_record(v: Any) -> bool:
    return isinstance(v, dict) and all(isinstance(x, str) for x in v.values())


def _is_https_url(v: Any) -> bool:
    if not isinstance(v, str) or not v.startswith("https://"):
        return False
    try:
        u = _Url(_VAR.sub("x", v))
    except ValueError:
        return False
    if u.scheme != "https" or u.username != "" or u.password != "" or u.hash != "":
        return False
    raw_host = re.split("[/?#]", v[len("https://"):], 1)[0]
    return re.fullmatch(r"\{\w+\}(:\d+)?", raw_host, re.ASCII) is None


def _url_vars(url: str) -> List[str]:
    return _VAR.findall(url)


def _one_of(items) -> str:
    return " | ".join(items)


def validate_manifest(inp: Any) -> Dict[str, Any]:
    """{ok: True, manifest} or {ok: False, issues}: every problem of a provider manifest, no partial acceptance."""
    issues: List[str] = []
    if not _is_record(inp):
        return {"ok": False, "issues": ["manifest must be an object"]}
    mid = _prop(inp, "id")
    if not _non_empty(mid):
        issues.append("id must be a non-empty string")
    elif _ID_PATTERN.fullmatch(mid) is None:
        issues.append("id '%s' must be lowercase and match %s" % (mid, _ID_SOURCE))
    if not _non_empty(_prop(inp, "displayName")):
        issues.append("displayName must be a non-empty string")
    authorize_url = _prop(inp, "authorizeUrl")
    if not _is_https_url(authorize_url):
        issues.append("authorizeUrl must be an https:// URL")
    token_url = _prop(inp, "tokenUrl")
    if not _is_https_url(token_url):
        issues.append("tokenUrl must be an https:// URL")
    scopes_available = _prop(inp, "scopesAvailable")
    if not _str_array(scopes_available):
        issues.append("scopesAvailable must be an array of strings")
    default_scopes = _prop(inp, "defaultScopes")
    if not _str_array(default_scopes):
        issues.append("defaultScopes must be an array of strings")
    for name, lst in (("scopesAvailable", scopes_available), ("defaultScopes", default_scopes)):
        if _str_array(lst):
            if any(len(s) == 0 or _WS_OR_COMMA.search(s) for s in lst):
                issues.append("%s entries must be non-empty and contain no whitespace or comma (a separator inside a scope would smuggle in another scope)" % name)
            if len(set(lst)) != len(lst):
                issues.append("%s must not contain duplicates" % name)
    if _str_array(scopes_available) and _str_array(default_scopes) and len(scopes_available) > 0:
        missing = [s for s in default_scopes if s not in set(scopes_available)]
        if missing:
            issues.append("defaultScopes must be a subset of scopesAvailable (unknown: %s)" % ", ".join(missing))
    refresh_ = _prop(inp, "refresh")
    if not _is_record(refresh_):
        issues.append("refresh must be an object")
    else:
        mode = _prop(refresh_, "mode")
        if not isinstance(mode, str) or mode not in _REFRESH_MODES:
            issues.append("refresh.mode must be one of %s" % _one_of(_REFRESH_MODES))
        te = _prop(refresh_, "tokenEndpoint")
        if te is not _UNDEF and not _is_https_url(te):
            issues.append("refresh.tokenEndpoint, when present, must be an https:// URL")
        sn = _prop(refresh_, "supportsScopeNarrowing")
        if sn is not _UNDEF and not isinstance(sn, bool):
            issues.append("refresh.supportsScopeNarrowing must be a boolean")
        ep = _prop(refresh_, "extraParams")
        if ep is not _UNDEF and not _str_record(ep):
            issues.append("refresh.extraParams must be a string→string map")
        elif _str_record(ep):
            for k in ep:
                if k in RESERVED_TOKEN_PARAMS:
                    issues.append("refresh.extraParams may not set '%s': the request builder owns it" % k)
    placement = _prop(inp, "tokenPlacement")
    if not isinstance(placement, str) or placement not in _TOKEN_PLACEMENTS:
        issues.append("tokenPlacement must be one of %s" % _one_of(_TOKEN_PLACEMENTS))
    elif placement == "header" and not _non_empty(_prop(inp, "headerName")):
        issues.append("tokenPlacement 'header' requires a non-empty headerName")
    elif placement == "query" and not _non_empty(_prop(inp, "queryParam")):
        issues.append("tokenPlacement 'query' requires a non-empty queryParam")
    header_name = _prop(inp, "headerName")
    if isinstance(header_name, str) and (_HEADER_NAME.fullmatch(header_name) is None or header_name.lower() in _FORBIDDEN_HEADERS):
        issues.append("headerName '%s' must be an HTTP token and not a protocol header" % header_name)
    query_param = _prop(inp, "queryParam")
    if isinstance(query_param, str) and _QUERY_NAME.fullmatch(query_param) is None:
        issues.append("queryParam '%s' must be a plain parameter name" % query_param)
    sep_raw = _prop(inp, "scopeSeparator")
    if isinstance(sep_raw, str) and len(sep_raw) == 0:
        issues.append("scopeSeparator must not be empty")
    pkce = _prop(inp, "pkce")
    if pkce is not _UNDEF and not isinstance(pkce, bool):
        issues.append("pkce must be a boolean")
    scope_sep = _prop(inp, "scopeSeparator")
    if scope_sep is not _UNDEF and not isinstance(scope_sep, str):
        issues.append("scopeSeparator must be a string")
    auth_params = _prop(inp, "authParams")
    if auth_params is not _UNDEF and not _str_record(auth_params):
        issues.append("authParams must be a string→string map")
    elif _str_record(auth_params):
        for k in auth_params:
            if k in RESERVED_AUTHORIZE_PARAMS:
                issues.append("authParams may not set '%s': the request builder owns it" % k)
    client_auth = _prop(inp, "clientAuth")
    if client_auth is not _UNDEF and (not isinstance(client_auth, str) or client_auth not in _CLIENT_AUTHS):
        issues.append("clientAuth must be one of %s" % _one_of(_CLIENT_AUTHS))
    required_vars = _prop(inp, "requiredVars")
    if required_vars is not _UNDEF and not _str_array(required_vars):
        issues.append("requiredVars must be an array of strings")
    if _is_https_url(authorize_url) and _is_https_url(token_url):
        declared = list(dict.fromkeys(required_vars if _str_array(required_vars) else []))
        used = list(dict.fromkeys(_url_vars(authorize_url) + _url_vars(token_url)))
        for v in used:
            if v not in declared:
                issues.append("url uses '{%s}' but requiredVars does not declare it" % v)
        for v in declared:
            if v not in used:
                issues.append("requiredVars declares '%s' but no URL uses '{%s}'" % (v, v))
    docs_url = _prop(inp, "docsUrl")
    if docs_url is not _UNDEF and not isinstance(docs_url, str):
        issues.append("docsUrl must be a string")
    if issues:
        return {"ok": False, "issues": issues}
    return {"ok": True, "manifest": _freeze_manifest(inp)}


def _freeze_manifest(inp: Dict[str, Any]) -> Dict[str, Any]:
    raw = _prop(inp, "refresh")
    rr = raw if isinstance(raw, dict) else {}
    refresh_: Dict[str, Any] = {"mode": "none" if _prop(rr, "mode") == "none" else "refresh_token"}
    te = _prop(rr, "tokenEndpoint")
    if isinstance(te, str):
        refresh_["tokenEndpoint"] = te
    sn = _prop(rr, "supportsScopeNarrowing")
    if isinstance(sn, bool):
        refresh_["supportsScopeNarrowing"] = sn
    ep = _prop(rr, "extraParams")
    if _str_record(ep):
        refresh_["extraParams"] = dict(ep)
    tp = _prop(inp, "tokenPlacement")
    m: Dict[str, Any] = {
        "id": _prop(inp, "id") if isinstance(_prop(inp, "id"), str) else "",
        "displayName": _prop(inp, "displayName") if isinstance(_prop(inp, "displayName"), str) else "",
        "authorizeUrl": _prop(inp, "authorizeUrl") if isinstance(_prop(inp, "authorizeUrl"), str) else "",
        "tokenUrl": _prop(inp, "tokenUrl") if isinstance(_prop(inp, "tokenUrl"), str) else "",
        "scopesAvailable": list(_prop(inp, "scopesAvailable")) if _str_array(_prop(inp, "scopesAvailable")) else [],
        "defaultScopes": list(_prop(inp, "defaultScopes")) if _str_array(_prop(inp, "defaultScopes")) else [],
        "refresh": refresh_,
        "tokenPlacement": "header" if tp == "header" else "query" if tp == "query" else "bearer",
    }
    pkce = _prop(inp, "pkce")
    if isinstance(pkce, bool):
        m["pkce"] = pkce
    sep = _prop(inp, "scopeSeparator")
    if isinstance(sep, str):
        m["scopeSeparator"] = sep
    ap = _prop(inp, "authParams")
    if _str_record(ap):
        m["authParams"] = dict(ap)
    ca = _prop(inp, "clientAuth")
    if ca == "post" or ca == "basic":
        m["clientAuth"] = ca
    hn = _prop(inp, "headerName")
    if isinstance(hn, str):
        m["headerName"] = hn
    qp = _prop(inp, "queryParam")
    if isinstance(qp, str):
        m["queryParam"] = qp
    rv = _prop(inp, "requiredVars")
    if _str_array(rv):
        m["requiredVars"] = list(rv)
    du = _prop(inp, "docsUrl")
    if isinstance(du, str):
        m["docsUrl"] = du
    return m


def assert_manifest(inp: Any) -> Dict[str, Any]:
    r = validate_manifest(inp)
    if not r["ok"]:
        raise ManifestValidationError(r["issues"])
    return r["manifest"]


def manifest_digest(manifest: Dict[str, Any]) -> str:
    """The content address of a validated manifest: a pinned digest detects a swapped endpoint."""
    return hash_canonical(manifest)


# ---- registry (registry.ts) ---------------------------------------------------------------------------------------------------------

def _u16(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


class ProviderRegistry:
    def __init__(self) -> None:
        self._by_id: Dict[str, Dict[str, Any]] = {}

    def register(self, manifest: Any, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Validate and register a manifest; `expectedDigest` pins it, a duplicate id needs `replace: True`."""
        opts = opts or {}
        valid = assert_manifest(manifest)
        if opts.get("expectedDigest") is not None and manifest_digest(valid) != opts["expectedDigest"]:
            raise ConnectorError("manifest '%s' does not match the pinned digest" % valid["id"])
        if valid["id"] in self._by_id and opts.get("replace") is not True:
            raise ConnectorError("provider '%s' is already registered; pass { replace: true } to replace it deliberately" % valid["id"])
        self._by_id[valid["id"]] = valid
        return valid

    def get(self, provider_id: str) -> Optional[Dict[str, Any]]:
        return self._by_id.get(provider_id)

    def require(self, provider_id: str) -> Dict[str, Any]:
        m = self._by_id.get(provider_id)
        if m is None:
            raise UnknownProviderError(provider_id)
        return m

    def has(self, provider_id: str) -> bool:
        return provider_id in self._by_id

    def list(self) -> List[Dict[str, Any]]:
        return sorted(self._by_id.values(), key=lambda m: _u16(m["id"]))

    def ids(self) -> List[str]:
        return [m["id"] for m in self.list()]


def create_default_registry() -> ProviderRegistry:
    r = ProviderRegistry()
    for m in BUILTIN_MANIFESTS:
        r.register(m)
    return r


default_registry = create_default_registry()


def register_provider(manifest: Any, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return default_registry.register(manifest, opts)


def catalog_digest(registry: Optional[ProviderRegistry] = None) -> str:
    """One digest over the whole catalog (id and manifest digest, in id order)."""
    registry = registry or default_registry
    return hash_canonical([[m["id"], manifest_digest(m)] for m in registry.list()])


def get_provider(provider_id: str) -> Optional[Dict[str, Any]]:
    return default_registry.get(provider_id)


def list_providers() -> List[Dict[str, Any]]:
    return default_registry.list()


# ---- authorize URL, PKCE, URL variables and token placement (authorize.ts) ------------------------------------------------------------

_PKCE_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")
_MIN_STATE_CHARS = 16
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}")


def _random_token(n: int = 32) -> str:
    return b64u(secrets.token_bytes(n))


def pkce_challenge(verifier: str, method: str = "S256") -> str:
    """The PKCE challenge of a verifier: S256 (base64url of its SHA-256), or the verifier itself for "plain"."""
    return verifier if method == "plain" else b64u(sha256(utf8(verifier)))


def substitute_vars(url: str, vars: Any = _UNDEF) -> str:
    """Fill `{name}` placeholders from `vars`; each value must be a single DNS label so a value can never change the host."""
    def rep(m: "re.Match[str]") -> str:
        name = m.group(1)
        if vars is None:
            raise TypeError("Cannot convert undefined or null to object")
        v = vars[name] if isinstance(vars, dict) and name in vars else _UNDEF
        if v is _UNDEF:
            raise ConnectorError("missing URL variable '{%s}'" % name)
        if not isinstance(v, str) or _LABEL.fullmatch(v) is None:
            raise ConnectorError("URL variable '{%s}' must be a single DNS label (letters, digits and hyphens)" % name)
        return v
    return _VAR.sub(rep, url)


def _enc(v: Any) -> str:
    return quote(v if isinstance(v, str) else _js_string(v), safe="-_.!~*'()")


def _encode_form(params: List[Any]) -> str:
    return "&".join("%s=%s" % (_enc(k), _enc(v)) for k, v in params)


def _check_redirect_uri(uri: Any) -> None:
    text = _js_string(uri if uri is not _UNDEF else _UNDEF)
    try:
        u = _url_info(text)
    except ValueError:
        raise ConnectorError("buildAuthorizeUrl: redirectUri must be an absolute URL") from None
    if u["hash"] != "":
        raise ConnectorError("buildAuthorizeUrl: redirectUri must not have a fragment (RFC 6749 3.1.2)")
    if u["username"] != "" or u["password"] != "":
        raise ConnectorError("buildAuthorizeUrl: redirectUri must not carry credentials")
    local = u["hostname"] in ("localhost", "127.0.0.1", "[::1]")
    if u["protocol"] != "https:" and not (u["protocol"] == "http:" and local):
        raise ConnectorError("buildAuthorizeUrl: redirectUri must be https (http only for localhost)")


def _url_info(text: str) -> Dict[str, str]:
    """protocol, username, password, hostname and hash of an absolute URL (WHATWG parse; raises ValueError when it does not parse)."""
    s = re.sub(r"[\t\n\r]", "", text.strip("".join(chr(i) for i in range(0x21))))
    m = re.match(r"([A-Za-z][A-Za-z0-9+.\-]*):", s)
    if not m:
        raise InvalidUrlError("Invalid URL")
    scheme = m.group(1).lower()
    try:
        u = _Url(s)
        return {"protocol": scheme + ":", "username": u.username, "password": u.password, "hostname": u.host, "hash": u.hash}
    except ValueError:
        if scheme in ("http", "https", "ftp", "ws", "wss"):
            raise
    rest = s[m.end():]
    frag = rest.split("#", 1)[1] if "#" in rest else ""
    user = pw = host = ""
    if rest.startswith("//"):
        auth = re.split("[/?#]", rest[2:], 1)[0]
        if "@" in auth:
            ui, auth = auth.rsplit("@", 1)
            user, _, pw = ui.partition(":")
        host = auth.split(":", 1)[0]
    return {"protocol": scheme + ":", "username": user, "password": pw, "hostname": host, "hash": "#" + frag if frag else ""}


def _check_scopes(manifest: Dict[str, Any], scopes: Any, allow_unlisted: bool) -> None:
    if not isinstance(scopes, list):
        raise ConnectorError("buildAuthorizeUrl: scopes must be a list")
    seen = set()
    sep = manifest.get("scopeSeparator", " ")
    for s in scopes:
        if not isinstance(s, str) or len(s) == 0 or _WS_OR_COMMA.search(s) or sep in s:
            raise ConnectorError("buildAuthorizeUrl: every scope must be a non-empty string without whitespace, commas or the separator")
        if s in seen:
            raise ConnectorError("buildAuthorizeUrl: scope '%s' is listed twice" % s)
        seen.add(s)
        if not allow_unlisted and len(manifest["scopesAvailable"]) > 0 and s not in manifest["scopesAvailable"]:
            raise ConnectorError("buildAuthorizeUrl: scope '%s' is not offered by provider '%s'" % (s, manifest["id"]))


def build_authorize_url(provider_id: str, options: Dict[str, Any]) -> Dict[str, Any]:
    """The authorization URL (RFC 6749 3.1, RFC 7636) for a registered provider: {url, state, pkce?}. `options` carries clientId,
    redirectUri, scopes, state, pkce (False, True or {verifier, method}), vars, registry, extraParams, allowUnlistedScopes and
    allowPlainPkce. A random state / PKCE verifier is generated when none is given."""
    registry = options.get("registry") or default_registry
    manifest = registry.require(provider_id)
    scopes = options.get("scopes")
    if scopes is None:
        scopes = manifest["defaultScopes"]
    separator = manifest.get("scopeSeparator", " ")
    state = options.get("state")
    if state is None:
        state = _random_token()
    client_id = options.get("clientId")
    if not isinstance(client_id, str) or len(client_id) == 0:
        raise ConnectorError("buildAuthorizeUrl: clientId must be a non-empty string")
    _check_redirect_uri(options["redirectUri"] if "redirectUri" in options else _UNDEF)
    if not isinstance(state, str) or len(state) < _MIN_STATE_CHARS:
        raise ConnectorError("buildAuthorizeUrl: state must be at least %d characters (omit it to get a random one)" % _MIN_STATE_CHARS)
    _check_scopes(manifest, scopes, options.get("allowUnlistedScopes") is True)
    for k, _v in _js_entries(options.get("extraParams")):
        if k in RESERVED_AUTHORIZE_PARAMS:
            raise ConnectorError("buildAuthorizeUrl: extraParams may not set '%s'" % k)
    params: List[Any] = [["response_type", "code"], ["client_id", client_id], ["redirect_uri", options["redirectUri"]]]
    if len(scopes) > 0:
        params.append(["scope", separator.join(scopes)])
    params.append(["state", state])
    pk = options.get("pkce", _UNDEF)
    want = False if pk is False else True if pk is not _UNDEF else manifest.get("pkce") is True
    pkce = None
    if want:
        if isinstance(pk, dict):
            verifier = pk.get("verifier", _UNDEF)
            method = pk.get("method")
            method = "S256" if method is None else method
        elif pk is None:
            raise TypeError("Cannot read properties of null")
        else:
            verifier, method = _random_token(), "S256"
        if _PKCE_VERIFIER.fullmatch(_js_string(verifier)) is None:
            raise ConnectorError("buildAuthorizeUrl: the PKCE verifier must be 43 to 128 unreserved characters (RFC 7636)")
        if method != "S256" and not (method == "plain" and options.get("allowPlainPkce") is True):
            raise ConnectorError("buildAuthorizeUrl: PKCE method must be 'S256' (pass allowPlainPkce to use 'plain')")
        challenge = pkce_challenge(verifier, method)
        params.append(["code_challenge", challenge])
        params.append(["code_challenge_method", method])
        pkce = {"verifier": verifier, "challenge": challenge, "method": method}
    for k, v in (manifest.get("authParams") or {}).items():
        params.append([k, v])
    for k, v in _js_entries(options.get("extraParams")):
        params.append([k, v])
    base = substitute_vars(manifest["authorizeUrl"], options.get("vars", _UNDEF))
    out: Dict[str, Any] = {"url": "%s%s%s" % (base, "&" if "?" in base else "?", _encode_form(params)), "state": state}
    if pkce is not None:
        out["pkce"] = pkce
    return out


def _js_entries(x: Any) -> List[Any]:
    """Object.entries(x || {}): a string or an array has index keys, any other primitive has none."""
    if isinstance(x, dict):
        return list(x.items())
    if isinstance(x, str):
        return [(str(i), c) for i, c in enumerate(x)]
    if isinstance(x, list):
        return [(str(i), v) for i, v in enumerate(x)]
    return []


def apply_access_token(manifest: Dict[str, Any], access_token: Any) -> Optional[Dict[str, str]]:
    """How to present an access token: {kind: "header" | "query", name, value}. The token must be printable ASCII without spaces."""
    if not isinstance(access_token, str) or len(access_token) == 0 or re.search("[^\x21-\x7e]", access_token):
        raise ConnectorError("applyAccessToken: the access token must be a non-empty string of printable ASCII without spaces")
    placement = manifest.get("tokenPlacement")
    if placement == "bearer":
        return {"kind": "header", "name": "Authorization", "value": "Bearer %s" % access_token}
    if placement == "header":
        if "headerName" not in manifest:
            raise ConnectorError("manifest '%s' is header-placed but has no headerName" % _js_string(manifest.get("id", _UNDEF)))
        return {"kind": "header", "name": manifest["headerName"], "value": access_token}
    if placement == "query":
        if "queryParam" not in manifest:
            raise ConnectorError("manifest '%s' is query-placed but has no queryParam" % _js_string(manifest.get("id", _UNDEF)))
        return {"kind": "query", "name": manifest["queryParam"], "value": access_token}
    return None


# ---- code exchange, refresh and the vault bridge (exchange.ts) ----------------------------------------------------------------------

_DEFAULT_TOKEN_LIFETIME_MS = 3_600_000


def _redact(text: str, secrets_: List[Optional[str]]) -> str:
    for s in secrets_:
        if isinstance(s, str) and len(s) > 0:
            text = text.replace(s, "[redacted]")
    return text


def _check_extra_params(extra: Any, what: str) -> None:
    for k in (extra or {}):
        if k in RESERVED_TOKEN_PARAMS:
            raise ConnectorError("%s: extraParams may not set '%s'" % (what, k))


def _basic_auth_header(client_id: str, client_secret: str) -> str:
    import base64
    return "Basic " + base64.b64encode(utf8("%s:%s" % (client_id, client_secret))).decode("ascii")


def _parse_token_response(body: Any, provider: str) -> Dict[str, Any]:
    if not isinstance(body, dict):
        raise ConnectorError("[%s] token endpoint returned a non-object body" % provider)
    at = body.get("access_token")
    if not isinstance(at, str) or len(at) == 0:
        raise ConnectorError("[%s] token endpoint response has no access_token" % provider)
    out: Dict[str, Any] = {"accessToken": at}
    ex = body.get("expires_in")
    if isinstance(ex, (int, float)) and not isinstance(ex, bool) and fin(ex) and ex > 0:
        out["expiresInSecs"] = ex
    rt = body.get("refresh_token")
    if isinstance(rt, str) and len(rt) > 0:
        out["refreshToken"] = rt
    sc = body.get("scope")
    if isinstance(sc, str) and len(_TRIM.sub("", sc)) > 0:
        out["scopes"] = _WS_OR_COMMA_RUN.split(_TRIM.sub("", sc))
    return out


def _post_token(manifest: Dict[str, Any], token_endpoint: str, params: Dict[str, Any], client_secret: Optional[str], fetch: Callable[..., Any]) -> Dict[str, Any]:
    headers = {"content-type": "application/x-www-form-urlencoded", "accept": "application/json"}
    body = dict(params)
    if manifest.get("clientAuth") == "basic":
        if client_secret is None:
            raise ConnectorError("[%s] clientAuth 'basic' requires a clientSecret" % manifest["id"])
        client_id = body.get("client_id")
        if client_id is None or client_id is _UNDEF:
            raise ConnectorError("[%s] missing client_id for basic auth" % manifest["id"])
        headers["authorization"] = _basic_auth_header(client_id, client_secret)
        body.pop("client_id", None)
        body.pop("client_secret", None)
    secs = [client_secret, params.get("code"), params.get("code_verifier"), params.get("refresh_token"), headers.get("authorization")]
    try:
        if fetch is None:
            raise TypeError("fetchImpl is not a function")
        res = fetch(token_endpoint, {"method": "POST", "headers": headers, "body": _encode_form(list(body.items()))})
    except Exception as e:  # noqa: BLE001
        raise ConnectorError("[%s] token transport error: %s" % (manifest["id"], _redact(str(e), secs))) from None
    if not res.ok:
        try:
            t = res.text()
            b = t.encode("utf-16-le", "surrogatepass")[:512].decode("utf-16-le", "surrogatepass")
            detail = _redact(b, secs)
        except Exception:  # noqa: BLE001
            detail = "<unreadable body>"
        raise ConnectorError("[%s] token endpoint %s: %s" % (manifest["id"], res.status, detail))
    try:
        j = res.json()
    except Exception:  # noqa: BLE001
        raise ConnectorError("[%s] unparseable token JSON" % manifest["id"]) from None
    return _parse_token_response(j, manifest["id"])


def _store_connection(manifest: Dict[str, Any], parsed: Dict[str, Any], requested: List[str], bind: Dict[str, Any], now: Any,
                      prior_refresh_token: Optional[str] = None) -> Dict[str, Any]:
    expires_at = now + parsed["expiresInSecs"] * 1000 if "expiresInSecs" in parsed else now + _DEFAULT_TOKEN_LIFETIME_MS
    granted = parsed.get("scopes", requested)
    refresh_token = parsed.get("refreshToken", prior_refresh_token)
    a = bind["authority"]
    authority: Dict[str, Any] = {"principal": a["principal"], "scopes": a.get("scopes", requested)}
    if "audience" in a:
        authority["audience"] = a["audience"]
    return bind["vault"].put_connection(bind["agentId"], manifest["id"], parsed["accessToken"], expires_at, granted, authority,
                                        bind.get("connectionId"), refresh_token)


def _now(args: Dict[str, Any]) -> Any:
    import time
    n = args.get("now")
    return int(time.time() * 1000) if n is None else n


def exchange_code(args: Dict[str, Any]) -> Dict[str, Any]:
    """Exchange an authorization code for tokens at the provider's token endpoint and store the connection in the vault. `args`:
    providerId, clientId, clientSecret?, code, redirectUri, codeVerifier?, scopes?, fetch, bind {vault, agentId, connectionId?,
    authority {principal, scopes?, audience?}}, now?, registry?, vars?, extraParams?. Returns the stored connection."""
    registry = args.get("registry") or default_registry
    manifest = registry.require(args["providerId"])
    now = _now(args)
    requested = args.get("scopes")
    if requested is None:
        requested = manifest["defaultScopes"]
    code = args.get("code")
    if not isinstance(code, str) or len(code) == 0:
        raise ConnectorError("[%s] an authorization code is required" % manifest["id"])
    _check_extra_params(args.get("extraParams"), "[%s] exchangeCode" % manifest["id"])
    if manifest.get("pkce") is True and "codeVerifier" not in args:
        raise ConnectorError("[%s] provider uses PKCE; a codeVerifier is required to exchange the code" % manifest["id"])
    params: Dict[str, Any] = {"grant_type": "authorization_code", "code": code, "redirect_uri": args.get("redirectUri", _UNDEF),
                              "client_id": args.get("clientId", _UNDEF)}
    if "clientSecret" in args:
        params["client_secret"] = args["clientSecret"]
    if "codeVerifier" in args:
        params["code_verifier"] = args["codeVerifier"]
    params.update(args.get("extraParams") or {})
    endpoint = substitute_vars(manifest["tokenUrl"], args.get("vars", _UNDEF))
    parsed = _post_token(manifest, endpoint, params, args.get("clientSecret"), args.get("fetch"))
    return _store_connection(manifest, parsed, requested, args["bind"], now)


def refresh(args: Dict[str, Any]) -> Dict[str, Any]:
    """Refresh a connection's tokens at the provider and store the result in the vault (the refresh token is kept unless the provider
    rotates it). `args` as for exchange_code, with refreshToken in place of code, redirectUri and codeVerifier."""
    registry = args.get("registry") or default_registry
    manifest = registry.require(args["providerId"])
    if manifest["refresh"]["mode"] == "none":
        raise ConnectorError("[%s] provider does not support token refresh" % manifest["id"])
    now = _now(args)
    requested = args.get("scopes")
    if requested is None:
        requested = manifest["defaultScopes"]
    rt = args.get("refreshToken")
    if not isinstance(rt, str) or len(rt) == 0:
        raise ConnectorError("[%s] a refresh token is required" % manifest["id"])
    _check_extra_params(args.get("extraParams"), "[%s] refresh" % manifest["id"])
    params: Dict[str, Any] = {"grant_type": "refresh_token", "refresh_token": rt, "client_id": args.get("clientId", _UNDEF)}
    if "clientSecret" in args:
        params["client_secret"] = args["clientSecret"]
    params.update(manifest["refresh"].get("extraParams") or {})
    params.update(args.get("extraParams") or {})
    if manifest["refresh"].get("supportsScopeNarrowing") is True and len(requested) > 0:
        params["scope"] = manifest.get("scopeSeparator", " ").join(requested)
    endpoint = substitute_vars(manifest["refresh"].get("tokenEndpoint", manifest["tokenUrl"]), args.get("vars", _UNDEF))
    parsed = _post_token(manifest, endpoint, params, args.get("clientSecret"), args.get("fetch"))
    return _store_connection(manifest, parsed, requested, args["bind"], now, rt)


def manifest_to_provider_config(manifest: Dict[str, Any], creds: Dict[str, Any]) -> Dict[str, Any]:
    """The vault's token-endpoint configuration for a refreshable manifest (`creds`: clientId, clientSecret?, vars?)."""
    if manifest["refresh"]["mode"] == "none":
        raise ConnectorError("[%s] provider does not support token refresh; no ProviderConfig" % manifest["id"])
    config: Dict[str, Any] = {"tokenEndpoint": substitute_vars(manifest["refresh"].get("tokenEndpoint", manifest["tokenUrl"]), creds.get("vars", _UNDEF)),
                              "clientId": creds["clientId"]}
    if "clientSecret" in creds:
        config["clientSecret"] = creds["clientSecret"]
    if "supportsScopeNarrowing" in manifest["refresh"]:
        config["supportsScopeNarrowing"] = manifest["refresh"]["supportsScopeNarrowing"]
    if "extraParams" in manifest["refresh"]:
        config["extraParams"] = dict(manifest["refresh"]["extraParams"])
    return config


def build_vault_providers(creds_by_id: Dict[str, Dict[str, Any]], registry: Optional[ProviderRegistry] = None) -> Dict[str, Dict[str, Any]]:
    """The `providers` option of a TokenVault from per-provider credentials; non-refreshable providers are skipped."""
    registry = registry or default_registry
    out: Dict[str, Dict[str, Any]] = {}
    for pid, creds in creds_by_id.items():
        manifest = registry.require(pid)
        if manifest["refresh"]["mode"] == "none":
            continue
        out[pid] = manifest_to_provider_config(manifest, creds)
    return out
