"""Agent passport as verifiable credentials (port of the TypeScript reference, @atlasauth/pca-vc).

A bridge, not a replacement: the PCA agent passport is re-expressed as a W3C VC 2.0 secured as an SD-JWT VC (EdDSA), with
did:key identifiers (Ed25519, multicodec 0xed01 + base58btc) and RFC 9421 HTTP message signatures (Web Bot Auth). Keys are
raw Ed25519 bytes: a 32-byte seed to sign, a 32-byte public key to verify. Option / argument dicts use snake_case names; an
absent key and a ``None`` value are told apart exactly as ``undefined`` and ``null`` are in the reference.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import math
import re
import secrets
import time
from typing import Any, Dict, List, Optional

from . import ed25519
from ._fin import fin
from .idna_host import domain_to_ascii
from .sdjwt import _js_number
from .sdjwt_jws import (
    CanonicalJwsError,
    OsslNotEnoughDataError,
    UNSET,
    assert_canonical_compact_jws,
    b64u,
    decode_canonical_base64url,
    is_number,
    js_json,
    js_json_bytes,
    js_json_parse_no_duplicates,
    js_to_string as js_str,
    jwt_verify,
    node_b64url_decode,
    sha256_ascii_b64u,
    sign_jwt,
)

VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
AGENT_PASSPORT_CONTEXT = "https://atlasauth.net/credentials/agent-passport/v1"
AGENT_PASSPORT_VC_TYPE = "AgentPassportCredential"

_V = "https://atlasauth.net/credentials/agent-passport/v1#"
_XSD = "http://www.w3.org/2001/XMLSchema#"
AGENT_PASSPORT_CONTEXT_DOC: Dict[str, Any] = {
    "@context": {
        "@protected": True,
        "AgentPassportCredential": {
            "@id": _V + "AgentPassportCredential",
            "@context": {
                "@protected": True,
                "id": "@id",
                "type": "@type",
                "passport_id": {"@id": _V + "passportId", "@type": _XSD + "string"},
                "model_id": {"@id": _V + "modelId", "@type": _XSD + "string"},
                "operator": {"@id": _V + "operator", "@type": _XSD + "string"},
                "hardware_rooted": {"@id": _V + "hardwareRooted", "@type": _XSD + "boolean"},
                "weights_measured": {"@id": _V + "weightsMeasured", "@type": _XSD + "boolean"},
                "issued_at": {"@id": _V + "issuedAt", "@type": _XSD + "integer"},
                "weights_digest": {"@id": _V + "weightsDigest", "@type": _XSD + "string"},
                "system_prompt_digest": {"@id": _V + "systemPromptDigest", "@type": _XSD + "string"},
                "tool_manifest_digest": {"@id": _V + "toolManifestDigest", "@type": _XSD + "string"},
                "runtime_measurement": {"@id": _V + "runtimeMeasurement", "@type": _XSD + "string"},
                "_sd": {"@id": _V + "selectiveDisclosureDigest", "@container": "@set"},
            },
        },
    },
}


def _canonical(v: Any) -> str:
    if v is None or not isinstance(v, (dict, list)):
        return js_json(v)
    if isinstance(v, list):
        return "[" + ",".join(_canonical(x) for x in v) + "]"
    return "{" + ",".join(js_json(k) + ":" + _canonical(v[k]) for k in sorted(v, key=_utf16_key)) + "}"


def _utf16_key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


# SHA-256 (hex) of the key-sorted JSON of the context document; changes whenever any term changes.
AGENT_PASSPORT_CONTEXT_DIGEST = hashlib.sha256(_canonical(AGENT_PASSPORT_CONTEXT_DOC).encode("utf-8")).hexdigest()


def resolve_agent_passport_context(iri: Any) -> Optional[dict]:
    """A document loader for JSON-LD processors: the bundled document for its IRI, None for anything else (never fetched)."""
    return AGENT_PASSPORT_CONTEXT_DOC if isinstance(iri, str) and iri == AGENT_PASSPORT_CONTEXT else None


class VcError(ValueError):
    """A refusal from this package (the message is the reference's)."""


class VcInvalidUrlError(VcError):
    """The reference runtime's URL parser error."""
    code = "ERR_INVALID_URL"


def _is_object(v: Any) -> bool:
    return isinstance(v, dict)


def _as_string(v: Any, label: str) -> str:
    if not isinstance(v, str):
        raise VcError("pca-vc: expected string for %s" % label)
    return v


def _as_number(v: Any, label: str) -> Any:
    if not is_number(v):
        raise VcError("pca-vc: expected number for %s" % label)
    return v


def _as_boolean(v: Any, label: str) -> bool:
    if not isinstance(v, bool):
        raise VcError("pca-vc: expected boolean for %s" % label)
    return v


def _bytes_arg(v: Any, what: str) -> bytes:
    if not isinstance(v, (bytes, bytearray)):
        raise VcError("pca-vc: %s must be bytes" % what)
    return bytes(v)


# ---- did:key (Ed25519) ----------------------------------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_MULTICODEC = bytes((0xED, 0x01))
_MAX_BASE58_INPUT = 1024  # an Ed25519 did:key body is 48 characters; an untrusted DID must not choose the work


def base58btc_encode(data: bytes) -> str:
    data = _bytes_arg(data, "base58btc input")
    zeros = 0
    while zeros < len(data) and data[zeros] == 0:
        zeros += 1
    n = int.from_bytes(data[zeros:], "big")
    digits: List[str] = []
    while n > 0:
        n, r = divmod(n, 58)
        digits.append(_B58[r])
    return "1" * zeros + "".join(reversed(digits))


def base58btc_decode(s: str) -> bytes:
    if not isinstance(s, str):
        raise VcError("pca-vc: base58btc input must be a string")
    if len(s.encode("utf-16-le", "surrogatepass")) // 2 > _MAX_BASE58_INPUT:
        raise VcError("pca-vc: base58btc input too long")
    zeros = 0
    while zeros < len(s) and s[zeros] == "1":
        zeros += 1
    n = 0
    for c in s[zeros:]:
        i = _B58.find(c)
        if i < 0:
            raise VcError("pca-vc: invalid base58btc character")
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * zeros + body


def did_key_from_ed25519(public_key: bytes) -> str:
    public_key = _bytes_arg(public_key, "Ed25519 public key")
    if len(public_key) != 32:
        raise VcError("pca-vc: Ed25519 public key must be 32 bytes")
    return "did:key:z" + base58btc_encode(_ED25519_MULTICODEC + public_key)


def ed25519_from_did_key(did: str) -> bytes:
    prefix = "did:key:z"
    if not isinstance(did, str) or not did.startswith(prefix):
        raise VcError("pca-vc: not a did:key:z… identifier")
    if len(did) > len(prefix) + 64:  # exactly 48 base58 characters
        raise VcError("pca-vc: did:key is not an Ed25519 (0xed01) key")
    mc = base58btc_decode(did[len(prefix):])
    if len(mc) != 34 or mc[0] != 0xED or mc[1] != 0x01:
        raise VcError("pca-vc: did:key is not an Ed25519 (0xed01) key")
    return mc[2:]


# ---- W3C VC 2.0 as an SD-JWT VC -------------------------------------------------------------------------------------

# The sensitive measurements, emitted as selectively-disclosable claims.
_SD_DIGEST_FIELDS = ("weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement")


def _ttl_number(v: Any) -> Any:
    """`now + ttlSec` in JavaScript, which jose then requires to be a finite number."""
    if v is None:
        return 0
    if isinstance(v, bool):
        return int(v)
    if is_number(v) and fin(v):
        return v
    raise VcError("pca-vc: ttlSec must be a finite number")


def passport_to_vc(passport: dict, args: Dict[str, Any]) -> str:
    """Emit an AgentPassport as an SD-JWT VC: ``<jwt>~<disclosure>~...~``. Args: issuer_key (32-byte seed), issuer_did,
    subject_did, ttl_sec (optional), now (epoch ms; defaults to the wall clock)."""
    if passport is None:
        raise VcError("pca-vc: passport must not be null")
    if not isinstance(passport, dict):
        passport = {}  # any other value has no members in the reference either
    issuer_key = args["issuer_key"]
    disclosures: List[str] = []
    sd: List[str] = []
    for field in _SD_DIGEST_FIELDS:
        if field not in passport:
            continue
        salt = b64u(secrets.token_bytes(16))
        disclosure = b64u(js_json_bytes([salt, field, passport[field]]))
        disclosures.append(disclosure)
        sd.append(sha256_ascii_b64u(disclosure))

    subject: Dict[str, Any] = {}
    if "subject_did" in args:
        subject["id"] = args["subject_did"]
    # the passport's own content-address, so a verifier can re-derive / match it
    for dst, src in (("passport_id", "id"), ("model_id", "model_id"), ("operator", "operator"),
                     ("hardware_rooted", "hardware_rooted"), ("issued_at", "issued_at")):
        if src in passport:
            subject[dst] = passport[src]
    if "weights_measured" in passport:
        subject["weights_measured"] = passport["weights_measured"]
    if sd:
        subject["_sd"] = sd

    vc = {"@context": [VC_CONTEXT, AGENT_PASSPORT_CONTEXT], "type": ["VerifiableCredential", AGENT_PASSPORT_VC_TYPE],
          "credentialSubject": subject}
    now_ms = args["now"] if args.get("now") is not None else time.time() * 1000
    now = math.floor(now_ms / 1000)
    # RFC 9901 s4.1.1: `_sd_alg` lives at the TOP LEVEL of the payload, never inside a nested object.
    payload: Dict[str, Any] = {"vc": vc}
    if sd:
        payload["_sd_alg"] = "sha-256"
    if "issuer_did" in args:
        payload["iss"] = args["issuer_did"]
    if "subject_did" in args:
        payload["sub"] = args["subject_did"]
    payload["iat"] = now
    if "ttl_sec" in args:
        payload["exp"] = now + _ttl_number(args["ttl_sec"])
    jwt = sign_jwt(payload, {"alg": "EdDSA", "typ": "vc+sd-jwt"}, issuer_key)
    return "".join(p + "~" for p in [jwt] + disclosures)


def verify_passport_vc(vc: str, issuer_verify_key: Any, options: Optional[dict] = None) -> dict:
    """Verify an SD-JWT VC produced by :func:`passport_to_vc` and reconstruct the passport. Returns
    {"passport", "issuerDid", "subjectDid"}; raises on any tamper (bad signature, forged or unknown disclosure, ...).
    Options: expected_issuer_did, now (epoch ms)."""
    options = options or {}
    if not isinstance(vc, str):
        raise VcError("pca-vc: SD-JWT must be a string")
    parts = vc.split("~")
    jwt = parts[0]
    if jwt == "":
        raise VcError("pca-vc: empty SD-JWT")
    disclosures = [p for p in parts[1:] if len(p) > 0]
    # Canonical-spelling gate BEFORE the JOSE layer: one accepted string form per JWT-VC / disclosure.
    assert_canonical_compact_jws(jwt)
    for d in disclosures:
        decode_canonical_base64url(d)

    # The algorithm is pinned: a raw-bytes key must never be accepted as an HMAC secret (algorithm confusion).
    payload, header = jwt_verify(jwt, issuer_verify_key, algorithms=["EdDSA"],
                                 now_ms=options["now"] if options.get("now") is not None else UNSET)
    if header.get("typ") != "vc+sd-jwt":
        raise VcError("pca-vc: header typ must be 'vc+sd-jwt'")
    vc_claim = payload.get("vc")
    if not _is_object(vc_claim):
        raise VcError("pca-vc: missing vc claim")
    ctx = vc_claim.get("@context")
    if not isinstance(ctx, list) or len(ctx) == 0 or ctx[0] != VC_CONTEXT:
        raise VcError("pca-vc: @context must begin with " + VC_CONTEXT)
    # Exactly the two contexts this package defines terms for: an extra or unknown context could redefine the passport terms.
    if len(ctx) != 2 or ctx[1] != AGENT_PASSPORT_CONTEXT:
        raise VcError("pca-vc: @context must be exactly [%s, %s]" % (VC_CONTEXT, AGENT_PASSPORT_CONTEXT))
    types = vc_claim.get("type")
    if not isinstance(types, list) or "VerifiableCredential" not in types or AGENT_PASSPORT_VC_TYPE not in types:
        raise VcError("pca-vc: type must include VerifiableCredential and " + AGENT_PASSPORT_VC_TYPE)
    cs = vc_claim.get("credentialSubject")
    if not _is_object(cs):
        raise VcError("pca-vc: missing credentialSubject")
    if "_sd_alg" in cs:
        raise VcError("pca-vc: _sd_alg must be a top-level claim")
    if "_sd_alg" in payload and payload["_sd_alg"] != "sha-256":
        raise VcError("pca-vc: unsupported _sd_alg (require sha-256)")

    sd_list = [x for x in cs["_sd"] if isinstance(x, str)] if isinstance(cs.get("_sd"), list) else []
    recovered: Dict[str, str] = {}
    seen: set = set()
    for disclosure in disclosures:
        digest = sha256_ascii_b64u(disclosure)
        if digest not in sd_list:
            raise VcError("pca-vc: disclosure does not match any _sd digest")
        if digest in seen:
            raise VcError("pca-vc: duplicate disclosure")
        seen.add(digest)
        try:
            decoded = js_json_parse_no_duplicates(node_b64url_decode(disclosure).decode("utf-8", "replace"))  # a repeated member is refused, numbers stay as written
        except (ValueError, RecursionError):
            raise VcError("pca-vc: malformed disclosure") from None
        if not isinstance(decoded, list) or len(decoded) != 3:
            raise VcError("pca-vc: malformed disclosure")
        name = _as_string(decoded[1], "disclosure name")
        if name not in _SD_DIGEST_FIELDS:
            raise VcError("pca-vc: unexpected disclosure claim '%s'" % name)
        if name in recovered:
            raise VcError("pca-vc: disclosure claim '%s' appears more than once" % name)
        recovered[name] = _as_string(decoded[2], "disclosure value")

    passport: Dict[str, Any] = {
        "id": _as_string(cs.get("passport_id"), "passport_id"),
        "model_id": _as_string(cs.get("model_id"), "model_id"),
        "operator": _as_string(cs.get("operator"), "operator"),
        "hardware_rooted": _as_boolean(cs.get("hardware_rooted"), "hardware_rooted"),
        "issued_at": _as_number(cs.get("issued_at"), "issued_at"),
    }
    if "weights_measured" in cs:
        passport["weights_measured"] = _as_boolean(cs["weights_measured"], "weights_measured")
    for field in _SD_DIGEST_FIELDS:
        if field in recovered:
            passport[field] = recovered[field]

    issuer_did = _as_string(payload.get("iss"), "iss")
    subject_did = _as_string(cs.get("id"), "credentialSubject.id")
    # The JWT `sub` and the VC subject id are the same identity; a disagreement is a malformed or spliced credential.
    if payload.get("sub") != subject_did:
        raise VcError("pca-vc: sub does not match credentialSubject.id")
    # The verification key is the caller's; binding it to the claimed issuer is theirs unless they pin the DID here.
    if "expected_issuer_did" in options and issuer_did != options["expected_issuer_did"]:
        raise VcError("pca-vc: iss does not match expectedIssuerDid")
    return {"passport": passport, "issuerDid": issuer_did, "subjectDid": subject_did}


# ---- RFC 9421 HTTP Message Signatures + Web Bot Auth ----------------------------------------------------------------

_SIG_LABEL = "sig1"
_JS_WS = "\t\n\x0b\x0c\r                  　﻿"
_SURROGATES = re.compile("[\ud800-\udfff]")
_WS_SPLIT = re.compile("[" + re.escape(_JS_WS) + "]+")
_COMPONENT = re.compile(r'"([^\n\r  ]*)"')
_ALG_PARAM = re.compile(r';alg="([^"]*)"')
_CREATED = re.compile(r";created=([0-9]+)")
_SPECIAL_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}
_FORBIDDEN_HOST = set(" #%/:<>?@[\\]^|") | {chr(c) for c in range(0x20)} | {"\x7f"}


def _js_trim(s: str) -> str:
    return s.strip(_JS_WS)


def _utf8(s: str) -> bytes:
    return _SURROGATES.sub("�", s).encode("utf-8")  # Buffer.from(s, 'utf8') replaces a lone surrogate


def _url_host(url: str) -> str:
    """`new URL(url).host` for the URLs a signed request carries (scheme, optional userinfo, host, optional non-default
    port). Anything the WHATWG parser would normalize in a way this does not model (percent-escapes or numeric forms in
    the host) is refused, so a signature never covers a host the verifier did not compute the same way."""
    if not isinstance(url, str):
        raise VcInvalidUrlError("Invalid URL")
    m = re.match(r"^[ \t\n\r\f]*([A-Za-z][A-Za-z0-9+.\-]*):(.*)$", url, re.S)
    if m is None:
        raise VcInvalidUrlError("Invalid URL")
    scheme, rest = m.group(1).lower(), m.group(2)
    special = scheme in _SPECIAL_PORTS
    if special:
        rest = rest.lstrip("/\\")
        end = re.search(r"[/\\?#]", rest)
    else:
        if not rest.startswith("//"):
            return ""
        rest = rest[2:]
        end = re.search(r"[/?#]", rest)
    authority = rest[: end.start()] if end else rest
    authority = authority[authority.rfind("@") + 1:]
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            raise VcInvalidUrlError("Invalid URL")
        host, port = authority[: close + 1], authority[close + 1:]
        if port != "" and not port.startswith(":"):
            raise VcInvalidUrlError("Invalid URL")
        port = port[1:]
        try:
            addr = ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            raise VcInvalidUrlError("Invalid URL") from None
        if "." in host or "%" in host:
            raise VcInvalidUrlError("Invalid URL")
        host = "[" + addr.compressed + "]"
    else:
        host, _, port = authority.partition(":")
        if ":" in port:
            raise VcInvalidUrlError("Invalid URL")
        if special:
            host = host.lower()
            if not host.isascii():
                host = domain_to_ascii(host)
                if host == "":
                    raise VcInvalidUrlError("Invalid URL")
        if (special and host == "") or any(c in _FORBIDDEN_HOST for c in host):
            raise VcInvalidUrlError("Invalid URL")
        last = host.rstrip(".").rsplit(".", 1)[-1] if special else ""
        if special and last[:1].isdigit() and not re.fullmatch(r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])", host):
            raise VcInvalidUrlError("Invalid URL")  # numeric host forms the WHATWG parser rewrites are not modelled
    if port != "":
        if not re.fullmatch(r"[0-9]+", port) or int(port) > 65535:
            raise VcInvalidUrlError("Invalid URL")
        if special and _SPECIAL_PORTS[scheme] == int(port):
            port = ""
        else:
            port = str(int(port))
    return host + (":" + port if port != "" else "")


def _normalize_headers(headers: Any) -> Dict[str, str]:
    if not isinstance(headers, dict):
        raise VcError("pca-vc: headers must be an object")
    return {str(k).lower(): v for k, v in headers.items()}


def _component_value(name: str, method: Any, url: str, headers: Dict[str, Any]) -> str:
    if name == "@method":
        return method.upper()
    if name == "@target-uri":
        return url
    if name == "@authority":
        return _url_host(url)
    v = headers.get(name)
    if not isinstance(v, str):
        raise VcError("pca-vc: covered header '%s' absent from request" % name)
    return _js_trim(v)


def _signature_base(components: List[str], sig_params_value: str, method: Any, url: str, headers: Dict[str, Any]) -> str:
    lines = ['"%s": %s' % (c, _component_value(c, method, url, headers)) for c in components]
    lines.append('"@signature-params": ' + sig_params_value)
    return "\n".join(lines)


def sign_request_message(args: Dict[str, Any]) -> Dict[str, str]:
    """Sign an HTTP request per RFC 9421 (EdDSA) with the Web Bot Auth `Signature-Agent` pattern. Args: method, url,
    headers, key (32-byte seed), keyid, created (unix seconds; defaults to now), signature_agent (key-directory URL),
    now (epoch ms, the clock behind the default `created`)."""
    method, url, key, keyid = args["method"], args["url"], args["key"], args["keyid"]
    now_ms = args["now"] if args.get("now") is not None else time.time() * 1000
    created = args["created"] if args.get("created") is not None else math.floor(now_ms / 1000)
    headers = _normalize_headers(args["headers"])
    if "host" not in headers:
        headers["host"] = _url_host(url)
    agent = args.get("signature_agent", UNSET)
    if agent is not UNSET:
        headers["signature-agent"] = '"%s"' % js_str(agent)

    components = ["@method", "@target-uri"] + sorted(headers.keys(), key=_utf16_key)
    inner = "(" + " ".join('"%s"' % c for c in components) + ")"
    params = ";created=%s;keyid=\"%s\";alg=\"ed25519\"" % (js_str(created), js_str(keyid))
    if agent is not UNSET:
        params += ';tag="web-bot-auth"'
    sig_params_value = inner + params

    base = _signature_base(components, sig_params_value, method, url, headers)
    key = _bytes_arg(key, "signing key")
    if len(key) < 32:
        raise OsslNotEnoughDataError("error:0680008E:asn1 encoding routines::not enough data")
    sig = ed25519.sign_secret(key, _utf8(base))
    out = {"signatureInput": "%s=%s" % (_SIG_LABEL, sig_params_value),
           "signature": "%s=:%s:" % (_SIG_LABEL, base64.b64encode(sig).decode("ascii"))}
    if agent is not UNSET:
        out["signatureAgent"] = '"%s"' % js_str(agent)
    return out


def _parse_components(sig_params_value: str) -> List[str]:
    open_, close = sig_params_value.find("("), sig_params_value.find(")")
    if open_ != 0 or close < 0:
        raise VcError("pca-vc: malformed @signature-params")
    inner = _js_trim(sig_params_value[open_ + 1: close])
    if inner == "":
        return []
    out = []
    for tok in _WS_SPLIT.split(inner):
        m = _COMPONENT.fullmatch(tok)
        if m is None:
            raise VcError("pca-vc: malformed component identifier")
        out.append(m.group(1))
    return out


def verify_request_signature(args: Dict[str, Any], verify_key: bytes) -> bool:
    """Verify an RFC 9421 signature produced by :func:`sign_request_message`; False on any mismatch. Args: method, url,
    headers, signature_input, signature, signature_agent, required_components, max_age_sec, now_sec."""
    try:
        sig_input = args["signature_input"]
        eq = sig_input.find("=")
        if eq < 0:
            return False
        sig_params_value = sig_input[eq + 1:]
        components = _parse_components(sig_params_value)
        req = args.get("required_components")
        for need in ([] if req is None else req):
            if need not in components:
                return False
        alg_param = _ALG_PARAM.search(sig_params_value)
        if alg_param is not None and alg_param.group(1) != "ed25519":
            return False
        if "max_age_sec" in args:
            created = _CREATED.search(sig_params_value)
            if created is None:
                return False
            now = args["now_sec"] if args.get("now_sec") is not None else math.floor(time.time())
            c = float(created.group(1))
            if not fin(now, c) or not (now - c <= _js_number(args["max_age_sec"])) or not (c - now <= 5):
                return False

        headers = _normalize_headers(args["headers"])
        if "host" not in headers:
            headers["host"] = _url_host(args["url"])
        if "signature-agent" in components and "signature-agent" not in headers:
            if "signature_agent" not in args:
                return False
            headers["signature-agent"] = args["signature_agent"]

        base = _signature_base(components, sig_params_value, args["method"], args["url"], headers)
        signature = args["signature"]
        sig_eq = signature.find("=")
        if sig_eq < 0:
            return False
        wrapped = _js_trim(signature[sig_eq + 1:])
        m = re.fullmatch(r":([^\n\r  ]*):", wrapped)
        if m is None:
            return False
        return ed25519.verify(_bytes_arg(verify_key, "verification key"), _utf8(base), node_b64url_decode(m.group(1)))
    except Exception:  # noqa: BLE001 - every malformed input is a refusal
        return False
