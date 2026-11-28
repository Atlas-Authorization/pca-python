"""Web Bot Auth for Proof-Carrying Authority (the TypeScript reference, @atlasauth/pca-webbotauth).

RFC 9421 HTTP Message Signatures over outbound agent requests in the `web-bot-auth` profile (Ed25519), RFC 9530 `Content-Digest`,
signed key-directory responses and the PCA proof binding (the `PCA-Action` header is a covered component, so one request is both
bot-verified and proof-carrying). Verification FAILS CLOSED: any parse error, missing field, stale window, wrong tag, unknown key or
bad signature returns `{"valid": False, "reason": ...}` and never raises.

Inputs and results are plain dicts with the reference's member names (`created`, `expiresInSec`, `agentDirectoryUrl`, `signatureInput`, ...)
so a request signed here verifies in the TypeScript verifier and the reverse. Signing keys are an `atlas_pca.agent.KeyPair`, a
32-byte seed or a `{"secretKey": <seed bytes>}` dict. Time arguments are epoch seconds; where the reference reads the clock the default
is `time.time()`.

Differences from the reference:
- only special-scheme URLs (http, https, ws, wss, ftp) are signed or verified; a URL with credentials is refused wherever the
  serialized URL itself is needed (`@target-uri`, the directory fetch);
- `verify_signed_request` is synchronous (a resolver or replay cache that returns an awaitable is refused);
  `verify_signed_request_async` and `verify_signed_request_with_proof_async` await them;
- `fetch_key_directory` takes a synchronous `options["fetch"](url, init) -> response` (`status`, `headers.get(name)`, `text()`);
  without one it uses `urllib` with redirects refused.
"""
import base64
import hashlib
import hmac
import inspect
import json
import math
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import ed25519
from ._fin import fin
from .oauth import _parse_url, _pct
from .pca import canonicalize, decode_pca_header, hash_canonical, strict_parse
from .sdjwt_jws import b64u, js_json_parse_no_duplicates, js_to_string, node_b64url_decode

__all__ = [
    "WEB_BOT_AUTH_TAG", "WEB_BOT_AUTH_ALG", "WELL_KNOWN_DIRECTORY_PATH", "DIRECTORY_CONTENT_TYPE", "DEFAULT_SIGNATURE_LABEL",
    "DEFAULT_EXPIRES_SEC", "SIGNATURE_AGENT_HEADER", "PCA_HEADER", "PCA_PROOF_COMPONENT", "CONTENT_DIGEST_ALGS", "CONTENT_DIGEST_HEADER",
    "DIRECTORY_SIGNATURE_TAG", "jwk_thumbprint", "sign_request", "verify_signed_request", "verify_signed_request_async",
    "memory_replay_cache", "build_key_directory", "resolve_from_directory", "directory_handler", "proof_headers", "decode_proof_header",
    "sign_request_with_proof", "verify_signed_request_with_proof", "verify_signed_request_with_proof_async", "content_digest_bytes",
    "content_digest_header", "parse_content_digest", "verify_content_digest", "parse_key_directory", "sign_directory_response",
    "verify_directory_response", "fetch_key_directory",
]

WEB_BOT_AUTH_TAG = "web-bot-auth"
WEB_BOT_AUTH_ALG = "ed25519"
WELL_KNOWN_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
DIRECTORY_CONTENT_TYPE = "application/http-message-signatures-directory+json"
DEFAULT_SIGNATURE_LABEL = "sig1"
DEFAULT_EXPIRES_SEC = 300
SIGNATURE_AGENT_HEADER = "Signature-Agent"
PCA_HEADER = "PCA-Action"
PCA_PROOF_COMPONENT = PCA_HEADER.lower()
CONTENT_DIGEST_ALGS = ("sha-256", "sha-512")
CONTENT_DIGEST_HEADER = "Content-Digest"
DIRECTORY_SIGNATURE_TAG = "http-message-signatures-directory"

_DIRECTORY_LIFETIME_SEC = 86400
_MAX_ARTIFACT_BYTES = 524288
_UNDEF = object()
# JS String.prototype.trim / `\s`: WhiteSpace plus LineTerminator
_JS_WS = "\t\n\x0b\x0c\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
_SPECIAL_SCHEMES = ("http", "https", "ws", "wss", "ftp")


class WebBotAuthParseError(ValueError):
    """A malformed or unsupported signature field (the reference's internal parse error)."""


# ---- small JS-semantics helpers ----------------------------------------------------------------------------------------------

def _trim(s: str) -> str:
    return s.strip(_JS_WS)


def _utf8(s: str) -> bytes:
    # TextEncoder / Buffer.from(s, 'utf8') write a lone surrogate as U+FFFD
    return s.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _finite(v: Any) -> bool:
    """Number.isFinite."""
    return _num(v) and fin(v)


def _need_num(v: Any, what: str) -> Any:
    if not _num(v):
        raise TypeError("%s must be a number" % what)
    return v


def _need_str(v: Any, what: str) -> str:
    if not isinstance(v, str):
        raise TypeError("%s must be a string" % what)
    return v


def _is_str_eq(a: Any, b: Any) -> bool:
    """`a === b` for a JSON string `b`."""
    return isinstance(a, str) and isinstance(b, str) and a == b


def _truthy(v: Any) -> bool:
    if v is None or v is _UNDEF or v is False:
        return False
    if _num(v):
        return v == v and v != 0
    if isinstance(v, str):
        return v != ""
    return True


def _spread(x: Any) -> dict:
    """`{...x}` of a JSON value."""
    if isinstance(x, dict):
        return dict(x)
    if isinstance(x, list):
        return {str(i): v for i, v in enumerate(x)}
    if isinstance(x, str):
        return {str(i): c for i, c in enumerate(x)}
    return {}


def _entries(o: Any) -> List[Tuple[str, Any]]:
    """`Object.entries(o)`."""
    if isinstance(o, dict):
        return list(o.items())
    if isinstance(o, (list, str)):
        return [(str(i), v) for i, v in enumerate(o)]
    return []


def _list_of(x: Any, what: str) -> list:
    if not isinstance(x, list):
        raise TypeError("%s must be an array" % what)
    return x


def _parse_int(s: str) -> Any:
    v = int(s, 10)
    return v if abs(v) <= 2 ** 53 else float(v)  # Number.parseInt returns a double


def _node_b64decode(s: str) -> bytes:
    return node_b64url_decode(s)  # Buffer.from(s, 'base64'): both alphabets, invalid characters skipped, stops at '='


def _now_sec() -> int:
    return int(math.floor(time.time()))


def _seed_of(key: Any) -> Tuple[bytes, bool]:
    """(32-byte Ed25519 seed, allow the built-in signer) of a KeyPair, a seed or a {"secretKey": seed} dict."""
    allow = False
    if isinstance(key, dict):
        key = key.get("secretKey")
    elif hasattr(key, "seed"):
        allow = bool(getattr(key, "_allow_insecure", False))
        key = key.seed
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise TypeError("the signing key must be a KeyPair, a 32-byte seed or {'secretKey': seed}")
    return bytes(key), allow


def _ed_sign(key: Any, message: bytes) -> bytes:
    seed, allow = _seed_of(key)
    return ed25519.sign_secret(seed, message, allow)


def _ed_public(key: Any) -> bytes:
    return ed25519.public_key(_seed_of(key)[0])


def _ed_verify_x(x: str, message: bytes, sig: bytes) -> bool:
    """Ed25519 verify under the base64url `x` of a public key; False for any malformed key or signature."""
    try:
        if len(sig) != 64:
            return False
        pub = _node_b64decode(x)
        if len(pub) != 32:
            return False
        return ed25519.verify(pub, message, sig)
    except Exception:  # noqa: BLE001 - a malformed key is a failed verification
        return False


def jwk_thumbprint(public_key: bytes) -> str:
    """RFC 7638 JWK thumbprint of an Ed25519 public key (base64url of SHA-256 over the canonical JWK)."""
    return _thumbprint_of_x(b64u(bytes(public_key)))


def _thumbprint_of_x(x: str) -> str:
    return b64u(hashlib.sha256(('{"crv":"Ed25519","kty":"OKP","x":"%s"}' % x).encode("utf-8")).digest())


# ---- structured-field helpers (targeted to the RFC 9421 Signature-Input / Signature grammars) ---------------------------------

def _sf_string(s: Any) -> str:
    _need_str(s, "a structured-field string")
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


def _split_top_level(s: str, sep: str) -> List[str]:
    out: List[str] = []
    depth = 0
    in_str = False
    start = 0
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if in_str:
            if c == "\\":
                i += 1
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif c == sep and depth == 0:
            out.append(s[start:i])
            start = i + 1
        i += 1
    out.append(s[start:])
    return out


def _char_at(s: str, i: int) -> str:
    return s[i] if 0 <= i < len(s) else ""


def _read_sf_string(s: str, i: int) -> Tuple[str, int]:
    if _char_at(s, i) != '"':
        raise WebBotAuthParseError("expected a quoted string")
    out = []
    j = i + 1
    while j < len(s):
        c = s[j]
        if c == "\\":
            nx = _char_at(s, j + 1)
            if nx != '"' and nx != "\\":
                raise WebBotAuthParseError("invalid escape in string")
            out.append(nx)
            j += 1
        elif c == '"':
            return "".join(out), j + 1
        else:
            out.append(c)
        j += 1
    raise WebBotAuthParseError("unterminated string")


_INT_RE = re.compile(r"-?[0-9]+")
_DEC_RE = re.compile(r"-?[0-9]+\.[0-9]+")


def _parse_param_value(raw: str) -> Any:
    s = _trim(raw)
    if len(s) == 0:
        return True  # valueless parameter => boolean true
    if s[0] == '"':
        value, nxt = _read_sf_string(s, 0)
        if nxt != len(s):
            raise WebBotAuthParseError("trailing characters after string parameter")
        return value
    if s == "?1":
        return True
    if s == "?0":
        return False
    if _INT_RE.fullmatch(s):
        return _parse_int(s)
    if _DEC_RE.fullmatch(s):
        return float(s)
    return s  # token


def _index_of_top_level(s: str, ch: str) -> int:
    depth = 0
    in_str = False
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if in_str:
            if c == "\\":
                i += 1
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif c == ch and depth == 0:
            return i
        i += 1
    return -1


def _matching_paren(s: str, open_: int) -> int:
    if _char_at(s, open_) != "(":
        return -1
    depth = 0
    in_str = False
    i = open_
    n = len(s)
    while i < n:
        c = s[i]
        if in_str:
            if c == "\\":
                i += 1
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _parse_params(param_str: str) -> Dict[str, Any]:
    params: Dict[str, Any] = {}
    trimmed = _trim(param_str)
    if len(trimmed) == 0:
        return params
    if trimmed[0] != ";":
        raise WebBotAuthParseError('expected parameters to start with ";"')
    for part in _split_top_level(trimmed[1:], ";"):
        seg = _trim(part)
        if len(seg) == 0:
            continue
        eq = _index_of_top_level(seg, "=")
        if eq == -1:
            params[seg] = True
        else:
            params[_trim(seg[:eq])] = _parse_param_value(seg[eq + 1:])
    return params


# a JS `.` does not match a line terminator
_KEY_PARAM = re.compile(r';key=("(?:[^"\\]|\\[^\n\r\u2028\u2029])*")')
_MEMBER_PARAMS = re.compile(r'(;[a-z*][a-z0-9_.*-]*(=("(?:[^"\\]|\\[^\n\r\u2028\u2029])*"|[A-Za-z0-9_.:/*+%-]+))?)*')


def _parse_signature_input(value: str) -> List[dict]:
    entries: List[dict] = []
    for member_raw in _split_top_level(value, ","):
        member = _trim(member_raw)
        if len(member) == 0:
            continue
        eq = _index_of_top_level(member, "=")
        if eq == -1:
            raise WebBotAuthParseError("malformed Signature-Input member")
        label = _trim(member[:eq])
        params_raw = _trim(member[eq + 1:])
        if _char_at(params_raw, 0) != "(":
            raise WebBotAuthParseError("Signature-Input value must be an inner list")
        close = _matching_paren(params_raw, 0)
        if close == -1:
            raise WebBotAuthParseError("unterminated inner list")
        inner = params_raw[1:close]
        components: List[dict] = []
        for chunk_raw in _split_top_level(inner, " "):
            chunk = _trim(chunk_raw)
            if len(chunk) == 0:
                continue
            ident, nxt = _read_sf_string(chunk, 0)
            lowered = ident.lower()
            rest = _trim(chunk[nxt:])
            if len(rest) == 0:
                components.append({"id": lowered, "raw": '"%s"' % lowered, "key": None})
                continue
            # the only component parameter supported is `key` (dictionary member), on header components
            m = _KEY_PARAM.fullmatch(rest)
            if m is None or lowered.startswith("@"):
                raise WebBotAuthParseError('unsupported component parameters on "%s"' % ident)
            key = _read_sf_string(m.group(1), 0)[0]
            components.append({"id": lowered, "raw": '"%s";key=%s' % (lowered, _sf_string(key)), "key": key})
        params = _parse_params(params_raw[close + 1:])
        entries.append({"label": label, "components": components, "paramsRaw": params_raw, "params": params})
    return entries


def _parse_signature(value: str) -> Dict[str, bytes]:
    out: Dict[str, bytes] = {}
    for member_raw in _split_top_level(value, ","):
        member = _trim(member_raw)
        if len(member) == 0:
            continue
        eq = _index_of_top_level(member, "=")
        if eq == -1:
            raise WebBotAuthParseError("malformed Signature member")
        label = _trim(member[:eq])
        v = _trim(member[eq + 1:])
        if len(v) < 2 or v[0] != ":" or v[-1] != ":":
            raise WebBotAuthParseError("Signature value must be a byte sequence (:base64:)")
        out[label] = _node_b64decode(v[1:-1])
    return out


# ---- signature base (RFC 9421 section 2.5) -----------------------------------------------------------------------------------

def _normalize_headers(h: Any) -> Dict[str, str]:
    m: Dict[str, str] = {}
    if not _truthy(h):
        return m
    for k, v in _entries(h):
        name = k.lower()
        if isinstance(v, list):
            value = ", ".join(_trim(_need_str(x, "a header value")) for x in v)
        else:
            value = _trim(_need_str(v, "a header value"))
        prev = m.get(name)
        m[name] = value if prev is None else "%s, %s" % (prev, value)
    return m


class InvalidUrlError(ValueError):
    """The reference runtime's URL parser error."""
    code = "ERR_INVALID_URL"


def _url_parts(url: Any) -> Tuple[dict, Optional[str], bool, bool]:
    """(parsed URL, fragment or None, whether a `?` starts a query, whether it has credentials) of a special-scheme URL."""
    if not isinstance(url, str):
        raise InvalidUrlError("Invalid URL")
    u = _parse_url(url)
    if u is None or u["scheme"] not in _SPECIAL_SCHEMES:
        raise InvalidUrlError("Invalid URL")
    s = url.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
    s = re.sub(r"[\t\n\r]", "", re.sub(r"^[\x00-\x20]+|[\x00-\x20]+$", "", s))
    hash_at = s.find("#")
    nofrag = s if hash_at < 0 else s[:hash_at]
    authority = re.split(r"[/\\?#]", s[s.find(":") + 1:].lstrip("/\\"), maxsplit=1)[0]
    return u, (None if hash_at < 0 else s[hash_at + 1:]), "?" in nofrag, "@" in authority


def _href(url: Any) -> str:
    """`new URL(url).href` for a special-scheme URL without credentials; a URL with credentials is refused."""
    u, frag, has_query, creds = _url_parts(url)
    if creds:
        raise ValueError("a URL with credentials is not supported")
    out = "%s://%s%s%s" % (u["scheme"], u["host"], u["pathname"], u["search"])
    if has_query and u["search"] == "":
        out += "?"
    if frag is not None:
        out += "#" + _pct(frag, '"<>`')
    return out


def _build_context(method: Any, url: Any, headers: Dict[str, str]) -> dict:
    u = _url_parts(url)[0]
    return {
        "method": _need_str(method, "the method").upper(),
        "authority": u["host"].lower(),
        "path": "/" if u["pathname"] == "" else u["pathname"],
        "url": url,
        "scheme": u["scheme"].lower(),
        "query": "?" if u["search"] == "" else u["search"],
        "requestTarget": ("/" if u["pathname"] == "" else u["pathname"]) + u["search"],
        "headers": headers,
    }


def _dictionary_member(header: str, key: str, header_name: str) -> str:
    """RFC 9421 section 2.1.2: the serialized value of dictionary member `key`; only string members in canonical form."""
    for member_raw in _split_top_level(header, ","):
        member = _trim(member_raw)
        eq = _index_of_top_level(member, "=")
        if eq == -1 or _trim(member[:eq]) != key:
            continue
        value = _trim(member[eq + 1:])
        _v, nxt = _read_sf_string(value, 0)
        # parameters are allowed only in compact canonical form, so the verbatim text IS the serialization
        if _MEMBER_PARAMS.fullmatch(value[nxt:]) is None:
            raise WebBotAuthParseError('member "%s" of "%s" is not in canonical form' % (key, header_name))
        return value
    raise WebBotAuthParseError('"%s" has no dictionary member "%s"' % (header_name, key))


def _derive_component_value(component: dict, ctx: dict) -> str:
    cid = component["id"]
    if cid == "@method":
        return ctx["method"]
    if cid == "@authority":
        return ctx["authority"]
    if cid == "@path":
        return ctx["path"]
    if cid == "@target-uri":
        return _href(ctx["url"])
    if cid == "@scheme":
        return ctx["scheme"]
    if cid == "@query":
        return ctx["query"]
    if cid == "@request-target":
        return ctx["requestTarget"]
    if cid.startswith("@"):
        raise WebBotAuthParseError('unsupported derived component "%s"' % cid)
    v = ctx["headers"].get(cid)
    if v is None:
        raise WebBotAuthParseError('covered header "%s" is absent from the request' % cid)
    if component["key"] is not None:
        return _dictionary_member(v, component["key"], cid)
    return v


def _build_signature_base(components: List[dict], params_raw: str, ctx: dict) -> str:
    lines = ["%s: %s" % (c["raw"], _derive_component_value(c, ctx)) for c in components]
    lines.append('"@signature-params": %s' % params_raw)
    return "\n".join(lines)


# ---- sign_request ------------------------------------------------------------------------------------------------------------

def sign_request(input: dict, now: Optional[float] = None) -> dict:  # noqa: A002 - the reference's name
    """Build the `Signature-Input` / `Signature` header values over the RFC 9421 base (`@authority @method @path`, plus `@query`
    when the URL has a query string, the `Signature-Agent` component and any `coverHeaders`). `input`: method, url, headers?, key,
    keyid, created?, expiresInSec?, agentDirectoryUrl?, agentDirectoryKey?, components?, coverHeaders?, nonce?, label?.
    Returns {"signatureInput", "signature", "signatureAgent"?, "covered", "headers"}."""
    if input is not None and not isinstance(input, dict):
        input = {}  # any other value has no members in the reference (the URL parse below refuses it)
    label = input.get("label")
    if label is None:
        label = DEFAULT_SIGNATURE_LABEL
    created = input.get("created")
    if created is None:
        created = int(math.floor((time.time() if now is None else now)))
    _need_num(created, "created")
    ex = input.get("expiresInSec")
    expires = float(created) + float(_need_num(DEFAULT_EXPIRES_SEC if ex is None else ex, "expiresInSec"))

    working = _normalize_headers(input.get("headers"))
    emitted: Dict[str, str] = {}

    components: List[dict] = []
    comps = input.get("components", _UNDEF)
    derived = ["@authority", "@method", "@path"] if comps is _UNDEF or comps is None else list(_list_of(comps, "components"))
    # by default a URL with a query string also covers @query (the verifier requires it)
    if comps is _UNDEF and isinstance(input.get("url"), str) and re.search(r"\?[^#]", input["url"]):
        derived.append("@query")
    if "@authority" not in derived:
        raise ValueError("signRequest: the web-bot-auth profile requires @authority to be covered")
    for cid in derived:
        lower = _need_str(cid, "a component").lower()
        if not lower.startswith("@"):
            raise ValueError('signRequest: components must be derived components, got "%s" (use coverHeaders for headers)' % cid)
        components.append({"id": lower, "raw": '"%s"' % lower, "key": None})

    signature_agent: Optional[str] = None
    agent_url = input.get("agentDirectoryUrl", _UNDEF)
    agent_key = input.get("agentDirectoryKey", _UNDEF)
    if agent_url is not _UNDEF:
        if agent_key is _UNDEF:
            signature_agent = _sf_string(agent_url)
        else:
            signature_agent = "%s=%s" % (js_to_string(agent_key), _sf_string(agent_url))
        working["signature-agent"] = signature_agent
        emitted[SIGNATURE_AGENT_HEADER] = signature_agent
        if agent_key is _UNDEF:
            components.append({"id": "signature-agent", "raw": '"signature-agent"', "key": None})
        else:
            components.append({"id": "signature-agent", "raw": '"signature-agent";key=%s' % _sf_string(agent_key), "key": agent_key})
    elif agent_key is not _UNDEF:
        raise ValueError("signRequest: agentDirectoryKey requires agentDirectoryUrl")

    cover = input.get("coverHeaders")
    for name in ([] if cover is None else _list_of(cover, "coverHeaders")):
        lower = _need_str(name, "a covered header").lower()
        if lower not in working:
            raise ValueError('signRequest: covered header "%s" is not present in headers' % name)
        if not any(c["id"] == lower for c in components):
            components.append({"id": lower, "raw": '"%s"' % lower, "key": None})

    ctx = _build_context(input.get("method"), input.get("url"), working)

    # parameter order follows the Web Bot Auth architecture draft: created, keyid, alg, expires, nonce, tag
    inner_list = " ".join(c["raw"] for c in components)
    params_raw = "(%s);created=%s;keyid=%s;alg=%s;expires=%s" % (
        inner_list, js_to_string(created), _sf_string(input.get("keyid")), _sf_string(WEB_BOT_AUTH_ALG), js_to_string(expires))
    if input.get("nonce", _UNDEF) is not _UNDEF:
        params_raw += ";nonce=%s" % _sf_string(input["nonce"])
    params_raw += ";tag=%s" % _sf_string(WEB_BOT_AUTH_TAG)

    base = _build_signature_base(components, params_raw, ctx)
    sig = _ed_sign(input.get("key"), _utf8(base))

    signature_input = "%s=%s" % (js_to_string(label), params_raw)
    signature = "%s=:%s:" % (js_to_string(label), base64.b64encode(sig).decode("ascii"))
    emitted["Signature-Input"] = signature_input
    emitted["Signature"] = signature
    out = {"signatureInput": signature_input, "signature": signature, "covered": [c["id"] for c in components], "headers": emitted}
    if signature_agent is not None:
        out["signatureAgent"] = signature_agent
    return out


# ---- verify_signed_request ---------------------------------------------------------------------------------------------------

def _x_from_resolved(k: Any) -> Optional[str]:
    if k is None:
        return None
    if isinstance(k, (bytes, bytearray)):
        return b64u(bytes(k)) if len(k) == 32 else None
    if isinstance(k, dict) and isinstance(k.get("x"), str) and k.get("crv") == "Ed25519" and k.get("kty") == "OKP":
        return k["x"]
    return None


def _resolve_from_jwks(keyid: str, jwks: Any, now: Any, skew: Any) -> Optional[str]:
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        raise TypeError("jwks.keys is not an array")
    match = None
    for j in keys:
        if j is None:
            raise TypeError("a directory key must not be null")
        if isinstance(j, dict) and _is_str_eq(j.get("kid"), keyid):
            match = j
            break
    if match is None:
        return None
    # a published validity window is enforced; a bound that is not a finite number cannot be checked, so the key resolves to nothing
    for b in (match.get("nbf", _UNDEF), match.get("exp", _UNDEF)):
        if b is not _UNDEF and not _finite(b):
            return None
    if match.get("nbf", _UNDEF) is not _UNDEF and not (fin(now) and fin(skew) and now + skew >= match["nbf"]):
        return None
    if match.get("exp", _UNDEF) is not _UNDEF and not (fin(now) and fin(skew) and now - skew <= match["exp"]):
        return None
    return _x_from_resolved(match)


def _verify_core(req: Any, opts: Any):
    """The verification as a generator: it yields a resolver or replay-cache result that may be awaitable and receives its value."""
    try:
        opts = opts if isinstance(opts, dict) else {}
        resolve = opts.get("resolveKey")
        jwks = opts.get("jwks")
        if not _truthy(resolve) and not _truthy(jwks):
            return {"valid": False, "reason": "verifySignedRequest: provide resolveKey or jwks"}
        headers = _normalize_headers(req.get("headers"))
        sig_input_header = headers.get("signature-input")
        sig_header = headers.get("signature")
        if sig_input_header is None or sig_header is None:
            return {"valid": False, "reason": "missing Signature-Input or Signature header"}

        inputs = _parse_signature_input(sig_input_header)
        sigs = _parse_signature(sig_header)
        required_tag = opts.get("requiredTag", _UNDEF)
        if required_tag is _UNDEF:
            required_tag = WEB_BOT_AUTH_TAG

        chosen = None
        if opts.get("label", _UNDEF) is not _UNDEF:
            chosen = next((e for e in inputs if _is_str_eq(e["label"], opts["label"])), None)
        elif required_tag is not None:
            chosen = next((e for e in inputs if _is_str_eq(e["params"].get("tag"), required_tag)), None)
            if chosen is None and inputs:
                chosen = inputs[0]
        else:
            chosen = inputs[0] if inputs else None
        if chosen is None:
            return {"valid": False, "reason": "no matching signature in Signature-Input"}

        sig_bytes = sigs.get(chosen["label"])
        if sig_bytes is None:
            return {"valid": False, "reason": 'no Signature entry for label "%s"' % chosen["label"]}

        tag = chosen["params"].get("tag")
        tag = tag if isinstance(tag, str) else None
        if required_tag is not None and not _is_str_eq(tag, required_tag):
            return {"valid": False, "reason": 'tag "%s" does not match required "%s"' % ("undefined" if tag is None else tag, js_to_string(required_tag))}

        # @authority is required by the profile; @method and @path too, so a signature cannot be replayed on another method or path
        covered = set(c["id"] for c in chosen["components"])
        req_components = opts.get("requiredComponents", _UNDEF)
        required = ["@authority", "@method", "@path"] if req_components is _UNDEF or req_components is None else _iter(req_components)
        for cid in required:
            if cid not in covered:
                return {"valid": False, "reason": "%s is not a covered component" % js_to_string(cid)}
        if req_components is _UNDEF:
            url = _need_str(req.get("url"), "url")
            q = url.find("?")
            if q >= 0 and url[q + 1:].split("#")[0] != "" and "@query" not in covered:
                return {"valid": False, "reason": "@query is not a covered component"}

        alg = chosen["params"].get("alg", _UNDEF)
        if alg is not _UNDEF and not _is_str_eq(alg, WEB_BOT_AUTH_ALG):
            return {"valid": False, "reason": 'unsupported alg "%s"' % js_to_string(alg)}

        now = opts.get("now")
        if now is None:
            now = _now_sec()
        skew = opts.get("clockSkewSec")
        if skew is None:
            skew = 0
        created = chosen["params"].get("created")
        created = created if _num(created) else None
        expires = chosen["params"].get("expires")
        expires = expires if _num(expires) else None
        if expires is None and opts.get("requireExpires") is not False:
            return {"valid": False, "reason": "missing expires parameter"}
        if expires is not None and not (fin(now) and fin(skew) and fin(expires) and now <= expires + skew):
            return {"valid": False, "reason": "signature has expired"}
        if created is not None and not (fin(now) and fin(skew) and fin(created) and created <= now + skew):
            return {"valid": False, "reason": "signature created-time is in the future"}
        max_age = opts.get("maxAgeSec", _UNDEF)
        if max_age is not _UNDEF and created is not None and not (fin(now) and fin(skew) and now - created <= max_age + skew):
            return {"valid": False, "reason": "signature is older than maxAgeSec"}
        max_lifetime = opts.get("maxLifetimeSec")
        if max_lifetime is None:
            max_lifetime = 300
        if _finite(max_lifetime):
            if created is None:
                return {"valid": False, "reason": "missing created parameter (needed to bound the signature lifetime)"}
            if expires is not None and expires - created > max_lifetime:
                return {"valid": False, "reason": "signature lifetime exceeds maxLifetimeSec"}

        keyid = chosen["params"].get("keyid")
        if not isinstance(keyid, str):
            return {"valid": False, "reason": "missing keyid parameter"}
        if _truthy(resolve):
            x = _x_from_resolved((yield resolve(keyid)))
        elif _truthy(jwks):
            x = _resolve_from_jwks(keyid, jwks, now, skew)
        else:
            x = None
        if x is None:
            return {"valid": False, "reason": 'could not resolve key "%s"' % keyid}

        ctx = _build_context(req.get("method"), req.get("url"), headers)
        base = _build_signature_base(chosen["components"], chosen["paramsRaw"], ctx)
        if not _ed_verify_x(x, _utf8(base), sig_bytes):
            return {"valid": False, "reason": "signature does not verify under the resolved key"}

        nonce = chosen["params"].get("nonce")
        nonce = nonce if isinstance(nonce, str) else None
        cache = opts.get("replayCache")
        if _truthy(cache):
            if expires is not None:
                until = expires
            elif created is not None:
                until = created + (max_lifetime if _finite(max_lifetime) else 3600)
            else:
                until = now + 3600
            key = "%s|%s" % (keyid, nonce if nonce is not None else b64u(sig_bytes))
            if not (yield cache.claim(key, until + skew, now)):
                return {"valid": False, "reason": "replayed signature"}
        out = {"valid": True, "label": chosen["label"], "keyid": keyid, "covered": [c["id"] for c in chosen["components"]]}
        if created is not None:
            out["created"] = created
        if expires is not None:
            out["expires"] = expires
        if tag is not None:
            out["tag"] = tag
        if nonce is not None:
            out["nonce"] = nonce
        return out
    except Exception as e:  # noqa: BLE001 - fail closed
        return {"valid": False, "reason": "verification failed (fail closed): %s" % e}


def _iter(x: Any) -> list:
    """JS iteration (`for ... of x`) of a JSON value: arrays and strings only."""
    if isinstance(x, (list, tuple)):
        return list(x)
    if isinstance(x, str):
        return list(x)
    raise TypeError("not iterable")


def _drive(gen: Any) -> Any:
    try:
        v = next(gen)
        while True:
            if inspect.isawaitable(v):
                if hasattr(v, "close"):
                    v.close()
                v = gen.throw(TypeError("an awaitable resolver or replay cache needs verify_signed_request_async"))
            else:
                v = gen.send(v)
    except StopIteration as stop:
        return stop.value


async def _drive_async(gen: Any) -> Any:
    try:
        v = next(gen)
        while True:
            try:
                if inspect.isawaitable(v):
                    v = await v
            except Exception as e:  # noqa: BLE001 - surfaces inside the verification as a fail-closed result
                v = gen.throw(e)
                continue
            v = gen.send(v)
    except StopIteration as stop:
        return stop.value


def verify_signed_request(req: dict, opts: dict) -> dict:
    """Verify an RFC 9421 signature over `req` = {"method", "url", "headers"}. `opts`: resolveKey (keyid -> 32 raw bytes, a public
    JWK dict or None) or jwks ({"keys": [...]}), now?, clockSkewSec?, maxAgeSec?, requireExpires? (default true), requiredTag?
    (default "web-bot-auth"; None = not enforced), label?, requiredComponents? (default @authority @method @path, plus @query when the
    URL has a query string), maxLifetimeSec? (default 300; infinity disables), replayCache? (an object with
    `claim(key, expires_at_sec, now_sec)`; see `memory_replay_cache`). Never raises: returns {"valid": False, "reason"} on any failure."""
    return _drive(_verify_core(req, opts))


async def verify_signed_request_async(req: dict, opts: dict) -> dict:
    """`verify_signed_request` for a resolver or replay cache that returns an awaitable."""
    return await _drive_async(_verify_core(req, opts))


def memory_replay_cache(max_entries: Optional[int] = None) -> Any:
    """In-process single-use store for accepted signatures. Fails CLOSED (raises) when `max_entries` unexpired claims are held."""
    return _MemoryReplayCache(100_000 if max_entries is None else max_entries)


class _MemoryReplayCache:
    def __init__(self, max_entries: int):
        self._max = max_entries
        self._seen: Dict[str, Any] = {}

    def claim(self, key: str, expires_at_sec: Any, now_sec: Any) -> bool:
        if not (fin(now_sec) and fin(expires_at_sec)):
            return False
        if len(self._seen) >= self._max:
            for k in [k for k, exp in self._seen.items() if exp < now_sec]:
                del self._seen[k]
            if len(self._seen) >= self._max:
                raise RuntimeError("replay cache full")
        existing = self._seen.get(key)
        if existing is not None and not (existing < now_sec):
            return False
        self._seen[key] = expires_at_sec
        return True


# ---- key directory (JWKS) and handler ----------------------------------------------------------------------------------------

def build_key_directory(keys: List[dict]) -> dict:
    """JWKS for the agent's public keys: [{"publicKey": bytes, "keyid"?, "use"?, "nbf"?, "exp"?}]; `kid` defaults to the thumbprint."""
    out = []
    for k in keys:
        pk = bytes(k["publicKey"])
        kid = k.get("keyid")
        entry = {"kty": "OKP", "crv": "Ed25519", "x": b64u(pk), "kid": jwk_thumbprint(pk) if kid is None else kid}
        for f in ("use", "nbf", "exp"):
            if k.get(f, _UNDEF) is not _UNDEF:
                entry[f] = k[f]
        out.append(entry)
    return {"keys": out}


def resolve_from_directory(directory: dict, keyid: str) -> Optional[dict]:
    """The directory entry whose `kid` is `keyid`, or None."""
    for j in _list_of(directory.get("keys"), "directory.keys"):
        if j is None:
            raise TypeError("a directory key must not be null")
        if isinstance(j, dict) and _is_str_eq(j.get("kid"), keyid):
            return j
    return None


def _json(v: Any) -> str:
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


def directory_handler(keys: List[dict]) -> Callable[[str], Optional[dict]]:
    """A framework-agnostic handler: the 200 response when the path is the well-known directory path, else None."""
    body = _json(build_key_directory(keys))

    def handle(pathname: str) -> Optional[dict]:
        path = pathname.split("?")[0]
        if path != WELL_KNOWN_DIRECTORY_PATH:
            return None
        return {"status": 200, "headers": {"content-type": DIRECTORY_CONTENT_TYPE, "cache-control": "max-age=86400"}, "body": body}
    return handle


# ---- PCA proof binding -------------------------------------------------------------------------------------------------------

def proof_headers(pcactn: Any) -> Dict[str, str]:
    """The `PCA-Action` header carrying a PCActn (base64url of its canonical wire form)."""
    if pcactn is _UNDEF:
        raise TypeError("canonicalize: unsupported type undefined")
    return {PCA_HEADER: b64u(_utf8(canonicalize(pcactn)))}


def decode_proof_header(value: str) -> dict:
    """Reverse `proof_headers`: the `PCA-Action` header value to the PCActn. Raises on a malformed header or PCActn."""
    text = decode_pca_header(value)
    if len(text.encode("utf-8", "surrogatepass")) > _MAX_ARTIFACT_BYTES:
        raise ValueError("artifact exceeds size limit (max %d bytes)" % _MAX_ARTIFACT_BYTES)
    v = strict_parse(text)
    if not isinstance(v, dict):
        raise TypeError("decodePCActn: not an object")
    return v


def sign_request_with_proof(input: dict, now: Optional[float] = None) -> dict:  # noqa: A002
    """`sign_request` plus the PCActn in `PCA-Action` as a covered header. `input` is a `sign_request` input with `pcactn`."""
    proof = proof_headers(input.get("pcactn", _UNDEF))
    headers = _spread(input.get("headers") if input.get("headers") is not None else {})
    headers.update(proof)
    cover = input.get("coverHeaders")
    cover_headers = list(_iter([] if cover is None else cover)) + [PCA_PROOF_COMPONENT]
    rest = {k: v for k, v in input.items() if k != "pcactn"}
    rest["headers"] = headers
    rest["coverHeaders"] = cover_headers
    result = sign_request(rest, now)
    out = dict(result)
    out["headers"] = dict(result["headers"], **proof)
    out["proofHeader"] = proof
    return out


def _proof_stage(base: dict, req: dict, opts: dict) -> dict:
    if not base["valid"]:
        return base
    if PCA_PROOF_COMPONENT not in (base.get("covered") or []):
        return {"valid": False, "reason": "the %s proof header is not covered by the signature" % PCA_HEADER}
    header_value = _normalize_headers(req.get("headers")).get(PCA_PROOF_COMPONENT)
    if header_value is None:
        return {"valid": False, "reason": "missing %s header" % PCA_HEADER}
    try:
        pcactn = decode_proof_header(header_value)
    except Exception as e:  # noqa: BLE001
        return {"valid": False, "reason": "invalid PCActn in %s: %s" % (PCA_HEADER, e)}
    expected = opts.get("expectedPCActn", _UNDEF)
    if expected is not _UNDEF and hash_canonical(pcactn) != hash_canonical(expected):
        return {"valid": False, "reason": "carried PCActn does not match the expected proof"}
    out = dict(base)
    out["pcactn"] = pcactn
    return out


def verify_signed_request_with_proof(req: dict, opts: dict) -> dict:
    """`verify_signed_request` AND extract the proof: `PCA-Action` must be a covered component; `opts["expectedPCActn"]`, when given,
    must equal the carried PCActn by canonical digest. The returned `pcactn` is bound to the verified signature."""
    return _proof_stage(verify_signed_request(req, opts), req, opts)


async def verify_signed_request_with_proof_async(req: dict, opts: dict) -> dict:
    return _proof_stage(await verify_signed_request_async(req, opts), req, opts)


# ---- Content-Digest (RFC 9530) -----------------------------------------------------------------------------------------------

_DIGEST_MEMBER = re.compile(r"([a-z*][a-z0-9_\-.*]*)=:([A-Za-z0-9+/]*={0,2}):")


def _body_bytes(body: Any) -> bytes:
    if isinstance(body, str):
        return _utf8(body)
    if isinstance(body, (bytes, bytearray, memoryview)):
        return bytes(body)
    raise TypeError("the body must be a string or bytes")


class UnsupportedDigestError(ValueError):
    """The reference runtime's ERR_INVALID_ARG_TYPE for a digest name its table does not hold."""
    code = "ERR_INVALID_ARG_TYPE"


def content_digest_bytes(body: Any, alg: str) -> bytes:
    """The raw digest bytes of `body` under `alg` ("sha-256" or "sha-512")."""
    if not isinstance(alg, str) or alg not in CONTENT_DIGEST_ALGS:
        raise UnsupportedDigestError("unsupported digest algorithm")
    return (hashlib.sha256 if alg == "sha-256" else hashlib.sha512)(_body_bytes(body)).digest()


def content_digest_header(body: Any, algs: Optional[List[str]] = None) -> str:
    """The `Content-Digest` field value, e.g. `sha-256=:X48E9q...=:` (members in the given order, duplicates dropped)."""
    algs = ["sha-256"] if algs is None else _list_of(algs, "algs")
    if len(algs) == 0:
        raise ValueError("contentDigestHeader: name at least one algorithm")
    seen = set()
    parts = []
    for alg in algs:
        if not isinstance(alg, str) or alg not in CONTENT_DIGEST_ALGS:
            raise ValueError("contentDigestHeader: unsupported algorithm %s" % js_to_string(alg))
        if alg in seen:
            continue
        seen.add(alg)
        parts.append("%s=:%s:" % (alg, base64.b64encode(content_digest_bytes(body, alg)).decode("ascii")))
    return ", ".join(parts)


def parse_content_digest(value: str) -> Dict[str, bytes]:
    """Parse the dictionary: key -> byte sequence. Raises on anything that is not `key=:base64:` (parameters refused, repeats refused)."""
    out: Dict[str, bytes] = {}
    for raw in _need_str(value, "the Content-Digest value").split(","):
        member = _trim(raw)
        if len(member) == 0:
            raise ValueError("empty dictionary member")
        m = _DIGEST_MEMBER.fullmatch(member)
        if m is None:
            raise ValueError('malformed Content-Digest member "%s"' % member)
        key, b64 = m.group(1), m.group(2)
        if len(b64) % 4 != 0:
            raise ValueError('member "%s" is not canonical base64' % key)
        data = _node_b64decode(b64)
        if base64.b64encode(data).decode("ascii") != b64:
            raise ValueError('member "%s" is not canonical base64' % key)
        if key in out:
            raise ValueError('member "%s" appears twice' % key)
        out[key] = data
    return out


def verify_content_digest(header: Optional[str], body: Any, opts: Optional[dict] = None) -> dict:
    """Check `body` against a `Content-Digest` field value. Every supported member present must match; unsupported members are ignored;
    at least one supported member must be present; every algorithm in `opts["require"]` must be among the matched ones."""
    try:
        if header is None or _trim(_need_str(header, "the header")) == "":
            return {"valid": False, "reason": "missing Content-Digest"}
        members = parse_content_digest(header)
        matched: List[str] = []
        for alg in CONTENT_DIGEST_ALGS:
            got = members.get(alg)
            if got is None:
                continue
            if not hmac.compare_digest(got, content_digest_bytes(body, alg)):
                return {"valid": False, "reason": "%s digest does not match the content" % alg}
            matched.append(alg)
        if len(matched) == 0:
            return {"valid": False, "reason": "no supported digest algorithm (sha-256 or sha-512)"}
        req = (opts or {}).get("require")
        for alg in ([] if req is None else _iter(req)):
            if alg not in matched:
                return {"valid": False, "reason": "required %s digest is absent" % js_to_string(alg)}
        return {"valid": True, "matched": matched}
    except Exception as e:  # noqa: BLE001 - fail closed
        return {"valid": False, "reason": "malformed Content-Digest: %s" % e}


# ---- signed key-directory responses ------------------------------------------------------------------------------------------

_X_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_AUTHORITY_RE = re.compile(r"[a-z0-9.\-\[\]:]+")
_LABEL_RE = r"[a-z][a-z0-9_.*-]*"
_DIR_ENTRY = re.compile(r"(" + _LABEL_RE + r')=\("@authority";req\)((?:;[a-z]+=(?:[0-9]+|"[A-Za-z0-9_.\-]*"))*)')
_DIR_SIG = re.compile(r"(" + _LABEL_RE + r")=:([A-Za-z0-9+/]+={0,2}):")


def _json_parse(text: Any) -> Any:
    """JSON.parse that refuses NaN / Infinity and a duplicate member at any depth (`duplicate key "k"`): the publisher and a verifier must read
    the same keys from the same bytes."""
    return js_json_parse_no_duplicates(_need_str(text, "the document"))


def parse_key_directory(text: str) -> dict:
    """Strictly parse a directory document: every key must be a well-formed Ed25519 OKP JWK with a string `kid`. Raises otherwise."""
    doc = _json_parse(text)
    keys = doc.get("keys") if isinstance(doc, dict) else None
    if not isinstance(keys, list) or len(keys) == 0:
        raise ValueError("directory has no keys")
    for j in keys:
        if not isinstance(j, dict) or j.get("kty") != "OKP" or j.get("crv") != "Ed25519" or not isinstance(j.get("kid"), str) or j["kid"] == "":
            raise ValueError("directory contains a malformed key")
        x = j.get("x")
        if not isinstance(x, str) or _X_RE.fullmatch(x) is None or len(_node_b64decode(x)) != 32:
            raise ValueError("directory contains a malformed key")
        for f in ("nbf", "exp"):
            if j.get(f, _UNDEF) is not _UNDEF and not _finite(j[f]):
                raise ValueError("directory contains a malformed key")
    return doc


def sign_directory_response(input: dict, now: Optional[float] = None) -> dict:  # noqa: A002
    """Sign a directory response (RFC 9421 over `"@authority";req`, one signature per key). `input`: keys (signing keys), directory,
    authority (lower-case host or host:port), created?, expiresInSec?. Returns the exact `body` to serve and the `headers`."""
    keys = _list_of(input.get("keys"), "keys")
    if len(keys) == 0:
        raise ValueError("signDirectoryResponse: at least one signing key is required")
    authority = _need_str(input.get("authority"), "authority")
    if _AUTHORITY_RE.fullmatch(authority) is None:
        raise ValueError("signDirectoryResponse: authority must be a lower-case host or host:port")
    created = input.get("created")
    if created is None:
        created = int(math.floor(time.time() if now is None else now))
    _need_num(created, "created")
    ex = input.get("expiresInSec")
    expires = float(created) + float(_need_num(_DIRECTORY_LIFETIME_SEC if ex is None else ex, "expiresInSec"))
    directory = input.get("directory")
    body = _json(directory)
    inputs: List[str] = []
    sigs: List[str] = []
    dir_keys = _list_of(directory.get("keys") if isinstance(directory, dict) else None, "directory.keys")
    for i, k in enumerate(keys):
        x = b64u(_ed_public(k))
        if not any(isinstance(j, dict) and j.get("x") == x for j in dir_keys):
            raise ValueError("signDirectoryResponse: a signing key is not in the directory")
        keyid = _thumbprint_of_x(x)
        label = "sig%d" % (i + 1)
        params = '("@authority";req);created=%s;expires=%s;keyid="%s";alg="ed25519";tag="%s"' % (js_to_string(created), js_to_string(expires), keyid, DIRECTORY_SIGNATURE_TAG)
        base = '"@authority";req: %s\n"@signature-params": %s' % (authority, params)
        inputs.append("%s=%s" % (label, params))
        sigs.append("%s=:%s:" % (label, base64.b64encode(_ed_sign(k, _utf8(base))).decode("ascii")))
    return {"body": body, "headers": {"content-type": DIRECTORY_CONTENT_TYPE, "signature-input": ", ".join(inputs), "signature": ", ".join(sigs)}}


def verify_directory_response(input: dict, now: Optional[float] = None) -> dict:  # noqa: A002
    """Verify a signed directory response: `input` = {"authority", "headers" (lower-case `signature-input`, `signature`), "body", "now"?,
    "clockSkewSec"?, "maxLifetimeSec"?}. Fail closed: {"valid": False, "reason", "keys": []} unless at least one signature is valid;
    when valid, `keys` holds only the directory keys that carry a valid signature."""
    def fail(reason: str) -> dict:
        return {"valid": False, "reason": reason, "keys": []}
    try:
        headers = input["headers"]
        sig_input = headers.get("signature-input") if isinstance(headers, dict) else headers["signature-input"]
        sig_header = headers.get("signature")
        if not _truthy(sig_input) or not _truthy(sig_header):
            return fail("missing signature-input or signature header")
        directory = parse_key_directory(input.get("body"))
        sigs: Dict[str, bytes] = {}
        for part in sig_header.split(", "):
            m = _DIR_SIG.fullmatch(part)
            if m is None:
                return fail("malformed signature header")
            sigs[m.group(1)] = _node_b64decode(m.group(2))
        t = input.get("now")
        if t is None:
            t = int(math.floor(time.time() if now is None else now))
        skew = input.get("clockSkewSec")
        skew = 0 if skew is None else skew
        max_life = input.get("maxLifetimeSec")
        max_life = _DIRECTORY_LIFETIME_SEC if max_life is None else max_life
        good: Dict[str, dict] = {}
        last_reason = "no signature entry"
        for raw in sig_input.split(", "):
            m = _DIR_ENTRY.fullmatch(raw)
            if m is None:
                last_reason = 'malformed signature-input entry (must cover exactly "@authority";req)'
                continue
            label = m.group(1)
            params: Dict[str, str] = {}
            dup = False
            for p in m.group(2).split(";")[1:]:
                eq = p.find("=")
                k = p[:eq]
                if k in params:
                    dup = True
                params[k] = p[eq + 1:]
            if dup:
                last_reason = "duplicate signature parameter"
                continue

            def sv(k: str) -> Optional[str]:
                v = params.get(k)
                return v[1:-1] if v is not None and v.startswith('"') else None

            def nv(k: str) -> Optional[Any]:
                v = params.get(k)
                return _parse_int(v) if v is not None and re.fullmatch(r"[0-9]+", v) else None
            if sv("tag") != DIRECTORY_SIGNATURE_TAG:
                last_reason = "wrong tag"
                continue
            alg = params.get("alg")
            if alg is not None and alg != '"ed25519"':
                last_reason = "unsupported alg"
                continue
            created, expires = nv("created"), nv("expires")
            if created is None or expires is None:
                last_reason = "created and expires are required"
                continue
            if not (fin(t) and fin(skew) and created <= t + skew):
                last_reason = "signature created-time is in the future"
                continue
            if not (t <= expires + skew):
                last_reason = "signature has expired"
                continue
            if expires - created > max_life:
                last_reason = "signature lifetime exceeds maxLifetimeSec"
                continue
            keyid = sv("keyid")
            if keyid is None:
                last_reason = "missing keyid"
                continue
            key = next((j for j in directory["keys"] if _thumbprint_of_x(j["x"]) == keyid), None)
            if key is None:
                last_reason = "keyid is not the thumbprint of any directory key"
                continue
            if (_num(key.get("nbf")) and t + skew < key["nbf"]) or (_num(key.get("exp")) and t - skew > key["exp"]):
                last_reason = "directory key is outside its validity window"
                continue
            sig = sigs.get(label)
            if sig is None or len(sig) != 64:
                last_reason = "no valid signature bytes for the label"
                continue
            base = '"@authority";req: %s\n"@signature-params": %s' % (js_to_string(input.get("authority")), raw[len(label) + 1:])
            if not _ed_verify_x(key["x"], _utf8(base), sig):
                last_reason = "signature does not verify"
                continue
            good[key["kid"]] = key
        if len(good) == 0:
            return fail(last_reason)
        return {"valid": True, "keys": list(good.values())}
    except Exception as e:  # noqa: BLE001 - fail closed
        return fail("verification failed (fail closed): %s" % e)


# ---- fetch_key_directory -----------------------------------------------------------------------------------------------------

def _urllib_fetch(url: str, init: dict) -> Any:
    import urllib.error
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a: Any, **k: Any) -> Any:
            return None

    class _Res:
        def __init__(self, status: int, headers: Any, data: bytes):
            self.status, self.headers, self._data = status, headers, data

        def text(self) -> str:
            return self._data.decode("utf-8", "replace")

    req = urllib.request.Request(url, headers=init.get("headers") or {})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=init.get("timeout")) as r:
            return _Res(r.status, r.headers, r.read(1 << 20))
    except urllib.error.HTTPError as e:
        return _Res(e.code, e.headers, b"")


def fetch_key_directory(url: str, options: Optional[dict] = None) -> dict:
    """Fetch and strictly parse a Web Bot Auth key directory. FAIL-CLOSED: raises on a non-https URL, redirect, non-200 status, wrong
    content type, oversize body, invalid JSON, or any key that is not a well-formed Ed25519 OKP JWK. Never returns a partial directory.
    `options`: fetch? (`fetch(url, init) -> response`, `init` = {"redirect": "error", "timeout": seconds, "headers": {...}}), maxBytes?
    (characters, default 65536), timeoutMs? (default 5000), allowInsecureHttp?, requireSignature?, now?."""
    options = options or {}
    u = _url_parts(url)[0]
    if u["scheme"] != "https" and not (options.get("allowInsecureHttp") is True and u["scheme"] == "http"):
        raise ValueError("directory URL must be https")
    href = _href(url)
    do_fetch = options.get("fetch") or _urllib_fetch
    timeout_ms = options.get("timeoutMs")
    res = do_fetch(href, {"redirect": "error", "timeout": (5000 if timeout_ms is None else timeout_ms) / 1000.0,
                          "headers": {"accept": "application/http-message-signatures-directory+json"}})
    if res.status != 200:
        raise ValueError("directory fetch returned status %s" % res.status)
    ct = _trim((res.headers.get("content-type") or "").split(";")[0]).lower()
    if ct != DIRECTORY_CONTENT_TYPE:
        raise ValueError("directory has the wrong content type")
    text = res.text()
    max_bytes = options.get("maxBytes")
    if len(text.encode("utf-16-le", "surrogatepass")) // 2 > (65536 if max_bytes is None else max_bytes):
        raise ValueError("directory response is too large")
    directory = parse_key_directory(text)
    if options.get("requireSignature") is True:
        vin = {"authority": u["host"].lower(), "body": text,
               "headers": {"signature-input": res.headers.get("signature-input") or "", "signature": res.headers.get("signature") or ""}}
        if options.get("now") is not None:
            vin["now"] = options["now"]
        v = verify_directory_response(vin)
        if not v["valid"]:
            raise ValueError("directory signature: %s" % v["reason"])
        return {"keys": v["keys"]}
    return directory
