"""OAuth 2.1 / MCP-authorization interop bridge for PCA: RFC 9728 Protected Resource Metadata, the RFC 6750 / RFC 7235
WWW-Authenticate challenge, RFC 8707 resource indicators and token-audience binding, and the pure 401 / discovery glue. The
pca_grant authorization-details half lives in ``pca_grant``. Mirrors the TypeScript reference (@atlasauth/pca-oauth);
options are dicts keyed in snake_case (``authorization_servers``, ``error_description``, ``pca_challenge`` ...)."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from .a2a import NEED_MAX_ENCODED, validate_need
from .pca import b64u, canonical_bytes_strict

WELL_KNOWN_OAUTH_PRM = "/.well-known/oauth-protected-resource"
WELL_KNOWN_PCA_PATH = "/.well-known/pca-configuration"
DEFAULT_PCA_HINT = "send PCA-Action: <base64url PCActn> or JSON body {pcactn}"
_DEFAULT_SUITES = ("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65")
_DEFAULT_REQUIRED = ("counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound")


def _truthy(v: Any) -> bool:
    """JavaScript truthiness (an empty list or dict is truthy, 0 / NaN / "" / None / False are not)."""
    if v is None or v is False:
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v == v and v != 0
    if isinstance(v, str):
        return v != ""
    return True


def _spread(v: Any) -> List[Any]:
    if isinstance(v, (list, tuple, str)):
        return list(v)
    raise TypeError("not iterable")


def _js_json(v: Any) -> str:
    """JSON.stringify: compact, integral floats as ints, lone surrogates escaped."""
    def plain(x):
        if isinstance(x, float) and x == x and abs(x) < 1e21 and x == int(x):
            return int(x)
        if isinstance(x, dict):
            return {k: plain(y) for k, y in x.items()}
        if isinstance(x, (list, tuple)):
            return [plain(y) for y in x]
        return x
    t = json.dumps(plain(v), separators=(",", ":"), ensure_ascii=False)
    return re.sub("[\ud800-\udfff]", lambda m: "\\u%04x" % ord(m.group(0)), t)


def _is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _is_str_list(x: Any) -> bool:
    return isinstance(x, list) and all(isinstance(s, str) for s in x)


# ---- a WHATWG URL parse of an absolute URL (the reference runs on the platform URL class) ----
# shortcut: host IDNA uses the stdlib IDNA 2003 codec (UTS 46 differs for a few code points); file: drive letters are not special-cased.

_SPECIAL = {"ftp": 21, "file": None, "http": 80, "https": 443, "ws": 80, "wss": 443}
_FORBIDDEN_HOST = re.compile(r"[\x00\t\n\r #/:<>?@\[\\\]^|]")
_PATH_ENC = "\"<>`{}?"
_QUERY_ENC = "\"<>"


def _pct(s: str, extra: str, controls_only: bool = False) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if o < 0x20 or o > 0x7E or (not controls_only and (o == 0x20 or ch in extra)):
            out.append("".join("%%%02X" % b for b in ch.encode("utf-8")))
        else:
            out.append(ch)
    return "".join(out)


def _pct_decode(s: str) -> bytes:
    raw = s.encode("utf-8")
    return re.sub(rb"%([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), raw)


def _ipv4_number(part: str) -> Optional[int]:
    if part == "":
        return None
    radix = 10
    if len(part) >= 2 and part[:2] in ("0x", "0X"):
        part, radix = part[2:], 16
    elif len(part) >= 2 and part[0] == "0":
        part, radix = part[1:], 8
    if part == "":
        return 0
    digits = {10: "0123456789", 16: "0123456789abcdefABCDEF", 8: "01234567"}[radix]
    return int(part, radix) if all(c in digits for c in part) else None


def _ends_in_number(host: str) -> bool:
    parts = host.split(".")
    if parts[-1] == "":
        if len(parts) == 1:
            return False
        parts.pop()
    last = parts[-1]
    return last != "" and (all(c in "0123456789" for c in last) or _ipv4_number(last) is not None)


def _parse_ipv4(host: str) -> Optional[str]:
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    if len(parts) > 4:
        return None
    nums = []
    for p in parts:
        n = _ipv4_number(p)
        if n is None:
            return None
        nums.append(n)
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    v = nums[-1] + sum(n * 256 ** (3 - i) for i, n in enumerate(nums[:-1]))
    return ".".join(str((v >> (8 * k)) & 255) for k in (3, 2, 1, 0))


def _serialize_ipv6(packed: bytes) -> str:
    h = [int.from_bytes(packed[i:i + 2], "big") for i in range(0, 16, 2)]
    best, best_len, i = -1, 1, 0
    while i < 8:
        if h[i] == 0:
            j = i
            while j < 8 and h[j] == 0:
                j += 1
            if j - i > best_len:
                best, best_len = i, j - i
            i = j
        else:
            i += 1
    out, i = "", 0
    while i < 8:
        if i == best:
            out += "::" if i == 0 else ":"
            i += best_len
            continue
        out += "%x" % h[i] + ("" if i == 7 else ":")
        i += 1
    return "[" + out + "]"


def _parse_host(text: str, special: bool) -> Optional[str]:
    if text.startswith("["):
        if not text.endswith("]") or "%" in text:
            return None
        import ipaddress
        try:
            return _serialize_ipv6(ipaddress.IPv6Address(text[1:-1]).packed)
        except ValueError:
            return None
    if not special:
        return None if re.search(r"[\x00\t\n\r #/<>?@\[\\\]^|]", text) else _pct(text, "", True)
    domain = _pct_decode(text).decode("utf-8", "replace")
    if not domain.isascii():
        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    domain = domain.lower()
    if domain == "" or re.search(r"[\x00-\x20#%/:<>?@\[\\\]^|\x7f]", domain):
        return None
    if _ends_in_number(domain):
        return _parse_ipv4(domain)
    return domain


def _parse_url(s: str) -> Optional[Dict[str, Any]]:
    """The scheme, the serialized host[:port] (`host`), the `htu` (protocol//host + pathname), and for special schemes the
    `origin`, `pathname` and `search`; None when the platform URL class would refuse the text."""
    s = s.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
    s = re.sub(r"[\t\n\r]", "", re.sub(r"^[\x00-\x20]+|[\x00-\x20]+$", "", s))
    m = re.match(r"([A-Za-z][A-Za-z0-9+.\-]*):", s)
    if m is None:
        return None
    scheme = m.group(1).lower()
    rest = s[m.end():]
    special = scheme in _SPECIAL
    frag = rest.find("#")
    if frag >= 0:
        rest = rest[:frag]
    q = rest.find("?")
    query = None
    if q >= 0:
        rest, query = rest[:q], rest[q + 1:]
    host, port = "", None
    if special and scheme != "file":
        rest = re.sub(r"^[/\\]+", "", rest)
        cut = re.search(r"[/\\]", rest)
        authority, path = (rest[: cut.start()], rest[cut.start():]) if cut else (rest, "")
        has_cred = "@" in authority
        hostport = authority.rpartition("@")[2]
    elif rest.startswith("//") or (scheme == "file" and re.match(r"[/\\]{2}", rest)):
        body = rest[2:]
        cut = re.search(r"[/\\]" if special else r"/", body)
        authority, path = (body[: cut.start()], body[cut.start():]) if cut else (body, "")
        has_cred = "@" in authority and scheme != "file"
        hostport = authority.rpartition("@")[2] if scheme != "file" else authority
    else:
        if special:  # file: without an authority
            authority, path, has_cred, hostport = "", re.sub(r"^[/\\]", "/", rest), False, ""
        else:
            authority, path, has_cred, hostport = None, rest, False, ""
    if authority is not None:
        if hostport.startswith("["):
            end = hostport.find("]")
            if end < 0:
                return None
            htxt, after = hostport[: end + 1], hostport[end + 1:]
            if after and not after.startswith(":"):
                return None
            ptxt = after[1:] if after else None
        else:
            htxt, sep, ptxt = hostport.partition(":")
            ptxt = ptxt if sep else None
        if ptxt not in (None, ""):
            if not (ptxt.isascii() and ptxt.isdigit()) or int(ptxt) > 65535:
                return None
            port = None if _SPECIAL.get(scheme) == int(ptxt) else int(ptxt)
        if special and scheme != "file" and htxt == "":
            return None
        if has_cred and htxt == "" and ptxt is None and hostport == "":
            return None
        if htxt == "" and not special:
            host = ""
        elif htxt == "" and scheme == "file":
            host = ""
        else:
            ph = _parse_host(htxt, special)
            if ph is None:
                return None
            host = "" if (scheme == "file" and ph == "localhost") else ph
    hp = host + (":%d" % port if port is not None else "")
    if authority is None:  # an opaque path: only the control characters are encoded
        pathname = _pct(path, "", True)
    else:
        segs = (path.replace("\\", "/") if special else path).split("/")[1:] if path else []
        out: List[str] = []
        for i, seg in enumerate(segs):
            last = i == len(segs) - 1
            low = seg.lower()
            if low in ("..", ".%2e", "%2e.", "%2e%2e"):
                if out:
                    out.pop()
                if last:
                    out.append("")
            elif low in (".", "%2e"):
                if last:
                    out.append("")
            else:
                out.append(_pct(seg, _PATH_ENC))
        pathname = "/" + "/".join(out)
    res: Dict[str, Any] = {"scheme": scheme, "host": hp, "htu": "%s://%s%s" % (scheme, hp, pathname), "pathname": pathname}
    if special:
        res["origin"] = "%s://%s" % (scheme, hp)
        res["search"] = ("?" + _pct(query, _QUERY_ENC + "'")) if query else ""
    return res


def resource_identifier_problem(resource: Any) -> Optional[str]:
    """RFC 9728 section 1.2: the reason `resource` is not an https URL without a fragment, or None when it is valid."""
    if not isinstance(resource, str) or len(resource) == 0:
        return "resource identifier must be a non-empty string"
    u = _parse_url(resource)
    if u is None:
        return "resource identifier is not an absolute URL"
    if u["scheme"] != "https":
        return "resource identifier must use the https scheme"
    if "#" in resource:
        return "resource identifier must not contain a fragment"
    return None


def prm_path_for_resource(resource: str) -> str:
    """RFC 9728 section 3.1: the suffix goes between host and path/query. Raises ValueError on an invalid identifier."""
    problem = resource_identifier_problem(resource)
    if problem is not None:
        raise ValueError("prmPathForResource: " + problem)
    u = _parse_url(resource)
    assert u is not None
    return WELL_KNOWN_OAUTH_PRM + ("" if u["pathname"] == "/" else u["pathname"]) + u["search"]


def prm_url_for_resource(resource: str) -> str:
    u = _parse_url(resource) if isinstance(resource, str) else None
    if u is None or "origin" not in u:
        raise ValueError("prmUrlForResource: invalid resource identifier")
    return u["origin"] + prm_path_for_resource(resource)


def _build_discovery_document(opts: Dict[str, Any]) -> Dict[str, Any]:
    aud = opts.get("audience")
    if not isinstance(aud, str) or len(aud) == 0:
        raise ValueError("buildDiscoveryDocument: audience is required")
    def pick(k, default):
        return default if opts.get(k) is None else opts[k]
    doc: Dict[str, Any] = {
        "audience": aud,
        "pca_versions": pick("pca_versions", [2]),
        "signature_suites": pick("signature_suites", list(_DEFAULT_SUITES)),
        "action_header": pick("action_header", "PCA-Action"),
        "required_checks": pick("required_checks", list(_DEFAULT_REQUIRED)),
    }
    for k in ("endpoints", "trusted_roots", "metadata"):
        if _truthy(opts.get(k)):
            doc[k] = opts[k]
    return doc


def protected_resource_metadata(opts: Dict[str, Any]) -> Dict[str, Any]:
    """RFC 9728 Protected Resource Metadata plus the PCA block (the discovery document embedded). Raises on a bad resource."""
    resource = opts.get("resource")
    if not isinstance(resource, str) or len(resource) == 0:
        raise ValueError("protectedResourceMetadata: `resource` (the RS id = PCActn audience) is required")
    if opts.get("strict") is not False:
        problem = resource_identifier_problem(resource)
        if problem is not None:
            raise ValueError("protectedResourceMetadata: " + problem)
    discovery = _build_discovery_document({
        "audience": resource,
        "signature_suites": opts.get("signature_suites"),
        "pca_versions": opts.get("pca_versions"),
        "action_header": opts.get("action_header"),
        "required_checks": opts.get("required_checks"),
        "endpoints": opts.get("endpoints"),
        "trusted_roots": opts.get("trusted_roots"),
        "metadata": opts.get("metadata"),
    })
    cfg = opts.get("pca_configuration_endpoint")
    if cfg is None:
        cfg = resource.split("?")[0].rstrip("/") + WELL_KNOWN_PCA_PATH
    bm = opts.get("bearer_methods_supported")
    doc: Dict[str, Any] = {
        "resource": resource,
        "bearer_methods_supported": ["header"] if bm is None else bm,
        "pca_action_header": discovery["action_header"],
        "pca_signature_suites": _spread(discovery["signature_suites"]),
        "pca_versions": _spread(discovery["pca_versions"]),
        "pca_configuration_endpoint": cfg,
        "pca": discovery,
    }
    if _truthy(opts.get("authorization_servers")):
        doc["authorization_servers"] = _spread(opts["authorization_servers"])
    for k in ("resource_documentation", "resource_name"):
        if _truthy(opts.get(k)):
            doc[k] = opts[k]
    for k in ("scopes_supported", "resource_signing_alg_values_supported", "authorization_details_types_supported"):
        if _truthy(opts.get(k)):
            doc[k] = _spread(opts[k])
    return doc


def parse_protected_resource_metadata(value: Any, parse_opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Validate and narrow an untrusted PRM document. Raises ValueError on anything malformed (fail closed)."""
    opts = {} if parse_opts is None else parse_opts
    if not isinstance(value, dict):
        raise ValueError("parseProtectedResourceMetadata: not an object")
    v = value
    p = "parseProtectedResourceMetadata: "
    if not isinstance(v.get("resource"), str) or len(v["resource"]) == 0:
        raise ValueError(p + "missing `resource`")
    if not _is_str_list(v.get("bearer_methods_supported")):
        raise ValueError(p + "bearer_methods_supported must be a string[]")
    if not isinstance(v.get("pca_action_header"), str) or len(v["pca_action_header"]) == 0:
        raise ValueError(p + "missing pca_action_header")
    if not _is_str_list(v.get("pca_signature_suites")):
        raise ValueError(p + "pca_signature_suites must be a string[]")
    if not isinstance(v.get("pca_versions"), list) or not all(_is_num(n) for n in v["pca_versions"]):
        raise ValueError(p + "pca_versions must be a number[]")
    pca = v.get("pca")
    if not isinstance(pca, dict):
        raise ValueError(p + "missing embedded `pca` discovery document")
    if not isinstance(pca.get("audience"), str) or len(pca["audience"]) == 0:
        raise ValueError(p + "embedded pca.audience is required")
    if "expected_resource" in opts:
        if v["resource"] != opts["expected_resource"]:
            raise ValueError(p + "`resource` does not match the expected resource identifier")
        if pca["audience"] != opts["expected_resource"]:
            raise ValueError(p + "embedded pca.audience does not match the expected resource identifier")
    if opts.get("strict") is not False:
        if "expected_resource" not in opts:
            raise ValueError(p + "expectedResource is required (RFC 9728 section 3.3); pass strict: false to skip")
        problem = resource_identifier_problem(v["resource"])
        if problem is not None:
            raise ValueError(p + problem)
        if not all(m in ("header", "body", "query") for m in v["bearer_methods_supported"]):
            raise ValueError(p + "bearer_methods_supported has a value outside header/body/query")
    doc: Dict[str, Any] = {
        "resource": v["resource"],
        "bearer_methods_supported": v["bearer_methods_supported"],
        "pca_action_header": v["pca_action_header"],
        "pca_signature_suites": v["pca_signature_suites"],
        "pca_versions": v["pca_versions"],
        "pca": pca,
    }
    if isinstance(v.get("pca_configuration_endpoint"), str):
        doc["pca_configuration_endpoint"] = v["pca_configuration_endpoint"]
    for k in ("authorization_servers", "scopes_supported", "resource_signing_alg_values_supported"):
        if _is_str_list(v.get(k)):
            doc[k] = v[k]
    for k in ("resource_documentation", "resource_name"):
        if isinstance(v.get(k), str):
            doc[k] = v[k]
    return doc


def _quoted_param(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("pca-oauth: WWW-Authenticate parameter value must be a string")
    if re.search('["\\\\\x00-\x1f\x7f]', value):
        raise ValueError("pca-oauth: WWW-Authenticate parameter value may not contain a quote or newline")
    return value


def _encode_pca_need(need: Any) -> str:
    v = validate_need(need)
    if not v["ok"]:
        raise ValueError("encodePcaNeed: malformed need (%s)" % v["code"])
    enc = b64u(canonical_bytes_strict(need))
    if len(enc) > NEED_MAX_ENCODED:
        raise ValueError("encodePcaNeed: the need is too large for a header")
    return enc


def www_authenticate(prm_url: str, opts: Optional[Dict[str, Any]] = None) -> str:
    """The WWW-Authenticate value of a 401: the MCP `Bearer resource_metadata` challenge plus (by default) the PCA challenge."""
    o = {} if opts is None else opts
    if not isinstance(prm_url, str) or len(prm_url) == 0:
        raise ValueError("wwwAuthenticate: prmUrl is required")
    params = ['resource_metadata="%s"' % _quoted_param(prm_url)]
    if _truthy(o.get("error")):
        params.append('error="%s"' % _quoted_param(o["error"]))
    if _truthy(o.get("error_description")):
        params.append('error_description="%s"' % _quoted_param(o["error_description"]))
    if _truthy(o.get("scope")):
        params.append('scope="%s"' % _quoted_param(o["scope"]))
    if _truthy(o.get("pca_need")):
        params.append('pca_need="%s"' % _quoted_param(_encode_pca_need(o["pca_need"])))
    challenges = ["Bearer " + ", ".join(params)]
    include = True if o.get("include_pca") is None else _truthy(o["include_pca"])
    if _truthy(o.get("pca_challenge")):
        pc = o["pca_challenge"]
        if not isinstance(pc, str):
            raise TypeError("pca-oauth: pcaChallenge must be a string")
        if re.search("[\x00-\x08\x0a-\x1f\x7f]", pc):
            raise ValueError("pca-oauth: pcaChallenge may not contain control characters or newlines")
        challenges.append(pc)
    elif include:
        realm = "pca" if o.get("realm") is None else o["realm"]
        hint = DEFAULT_PCA_HINT if o.get("hint") is None else o["hint"]
        pca = 'PCA realm="%s"' % _quoted_param(realm)
        if _truthy(hint):
            pca += ', hint="%s"' % _quoted_param(hint)
        challenges.append(pca)
    return ", ".join(challenges)


def check_resource_indicator(resource_param: Any, expected_audience: str) -> Dict[str, Any]:
    """RFC 8707: the OAuth-layer echo of the audience (an early reject, never the security boundary; the signed `aud` is)."""
    if not isinstance(expected_audience, str) or len(expected_audience) == 0:
        raise ValueError("checkResourceIndicator: expectedAudience is required")
    if resource_param is None:
        return {"ok": False, "reason": "no resource indicator presented"}
    values = resource_param if isinstance(resource_param, list) else [resource_param]
    if len(values) == 0:
        return {"ok": False, "reason": "empty resource indicator"}
    for r in values:
        if not isinstance(r, str) or len(r) == 0:
            continue
        if r == expected_audience:
            return {"ok": True, "matched": r}
    return {"ok": False, "reason": "resource indicator %s does not match audience %s" % (_js_json(values), _js_json(expected_audience))}


def check_token_audience(aud: Any, expected_resource: str) -> Dict[str, Any]:
    """The `aud` of a verified token must be, or contain, exactly this resource identifier. No prefix or case tolerance."""
    if not isinstance(expected_resource, str) or len(expected_resource) == 0:
        raise ValueError("checkTokenAudience: expectedResource is required")
    if aud is None:
        return {"ok": False, "reason": "token has no audience"}
    values = aud if isinstance(aud, list) else [aud]
    if len(values) == 0:
        return {"ok": False, "reason": "token has an empty audience"}
    if any(isinstance(a, str) and a == expected_resource for a in values):
        return {"ok": True, "matched": expected_resource}
    return {"ok": False, "reason": "token audience %s does not include resource %s" % (_js_json(aud), _js_json(expected_resource))}


def oauth_discovery_handler(opts: Dict[str, Any]) -> Dict[str, Any]:
    """The path and body to serve the RFC 9728 document (`rfcPath` is an alias of `path`)."""
    body = protected_resource_metadata(opts)
    path = prm_path_for_resource(opts["resource"]) if resource_identifier_problem(opts["resource"]) is None else WELL_KNOWN_OAUTH_PRM
    return {"path": path, "body": body, "rfcPath": path}


def mcp_unauthorized(prm_url: str, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The complete MCP/OAuth 401: status, WWW-Authenticate header and a small JSON body pointing at the PRM."""
    o = {} if opts is None else opts
    body: Dict[str, Any] = {"error": "invalid_request" if o.get("error") is None else o["error"], "resource_metadata": prm_url}
    if _truthy(o.get("error_description")):
        body["error_description"] = o["error_description"]
    return {"status": 401, "headers": {"WWW-Authenticate": www_authenticate(prm_url, o)}, "body": body}


def upgrade_unauthorized_challenge(result: Dict[str, Any], prm_url: str, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Prepend the MCP `resource_metadata` challenge to a requirePCA deny result's own PCA challenge (kept verbatim)."""
    if not isinstance(result, dict):
        raise TypeError("upgradeUnauthorizedChallenge: result must be an object")
    existing = result.get("wwwAuthenticate")
    merged = dict(opts or {})
    if _truthy(existing):
        merged["pca_challenge"] = existing
    out = dict(result)
    out["wwwAuthenticate"] = www_authenticate(prm_url, merged)
    return out
