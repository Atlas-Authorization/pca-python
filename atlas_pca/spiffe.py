"""Bridge PCA agent identity with SPIFFE / SPIRE workload identity: SPIFFE ID parsing, JWT-SVID and X.509-SVID verification,
the SVID -> PCA holder binding, trust-bundle and revocation caches that fail closed, and SPIFFE evidence for blueprint admission.
Mirrors the TypeScript reference (@atlasauth/pca-spiffe). Options are dicts keyed in snake_case; the asynchronous reference
calls (bundle / revocation fetch, revocation checks) are plain synchronous callables here. Signatures and X.509 keys use the
optional ``cryptography`` package (imported lazily); Ed25519 uses ``atlas_pca.ed25519``. Every failure refuses.

Time: a ``now`` / ``current_date`` option is a ``datetime`` or epoch SECONDS (default: the clock). The caches take a ``now``
callable returning epoch MILLISECONDS."""
from __future__ import annotations

from ._fin import fin
import hashlib
import math
import re
import threading
import time
import weakref
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple

from . import ed25519
from .attest_cert import Cert
from .attest_common import crypto, ecdsa_verify_raw, key_type, rsa_pkcs1_verify
from .attest_der import x509_valid_at
from .dpop import JoseError, _b64u_int, _js_len, _utf8, assert_canonical_compact_jws, jws_verify_compact, jwt_claims_check
from .pca import b64u, decode_b64u_strict, utf8

# ---- errors ---------------------------------------------------------------------------------------------------------------


class SpiffeError(Exception):
    """A validation / parse / verification failure with a stable `code` (the reference's SpiffeErrorCode)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ---- SPIFFE ID ------------------------------------------------------------------------------------------------------------

SPIFFE_SCHEME = "spiffe://"
MAX_SPIFFE_ID_LENGTH = 2048
MAX_TRUST_DOMAIN_LENGTH = 255
_TRUST_DOMAIN_RE = re.compile(r"[a-z0-9._-]+")
_PATH_SEGMENT_RE = re.compile(r"[a-zA-Z0-9._-]+")


class SpiffeId(NamedTuple):
    id: str
    trust_domain: str
    path: str


def parse_spiffe_id(s: Any) -> SpiffeId:
    """Validate and parse `spiffe://<trust-domain>/<path>`; raises SpiffeError on anything malformed."""
    if not isinstance(s, str) or len(s) == 0:
        raise SpiffeError("malformed_spiffe_id", "SPIFFE ID must be a non-empty string")
    if _js_len(s) > MAX_SPIFFE_ID_LENGTH:
        raise SpiffeError("id_too_long", "SPIFFE ID exceeds %d bytes" % MAX_SPIFFE_ID_LENGTH)
    if not s.startswith(SPIFFE_SCHEME):
        raise SpiffeError("malformed_spiffe_id", 'SPIFFE ID must begin with "%s"' % SPIFFE_SCHEME)
    rest = s[len(SPIFFE_SCHEME):]
    slash = rest.find("/")
    trust_domain = rest if slash == -1 else rest[:slash]
    path = "" if slash == -1 else rest[slash:]
    if len(trust_domain) == 0:
        raise SpiffeError("empty_trust_domain", "SPIFFE ID has an empty trust domain")
    if _js_len(trust_domain) > MAX_TRUST_DOMAIN_LENGTH:
        raise SpiffeError("trust_domain_too_long", "trust domain exceeds %d bytes" % MAX_TRUST_DOMAIN_LENGTH)
    if _TRUST_DOMAIN_RE.fullmatch(trust_domain) is None:
        raise SpiffeError("invalid_trust_domain", 'trust domain "%s" must be lowercase and contain only [a-z0-9._-]' % trust_domain)
    if path != "":
        if path.endswith("/"):
            raise SpiffeError("invalid_path", "SPIFFE ID path must not end with a trailing slash")
        for seg in path.split("/")[1:]:
            if len(seg) == 0:
                raise SpiffeError("invalid_path", "SPIFFE ID path must not contain an empty segment")
            if seg in (".", ".."):
                raise SpiffeError("invalid_path", 'SPIFFE ID path must not contain a "." or ".." segment')
            if _PATH_SEGMENT_RE.fullmatch(seg) is None:
                raise SpiffeError("invalid_path", 'SPIFFE ID path segment "%s" contains an invalid character' % seg)
    return SpiffeId(SPIFFE_SCHEME + trust_domain + path, trust_domain, path)


# ---- minimal DER reader for the X.509 extensions the SVID rules depend on ----------------------------------------------------


class DerRangeError(ValueError):
    """A structural DER problem (the reference's RangeError)."""


class _Tlv(NamedTuple):
    tag: int
    start: int
    end: int


def _read_tlv(buf: bytes, off: int, limit: int) -> _Tlv:
    if off + 2 > limit:
        raise DerRangeError("der: truncated header")
    tag = buf[off]
    if (tag & 0x1F) == 0x1F:
        raise DerRangeError("der: high-tag-number form is not supported")
    ln = buf[off + 1]
    p = off + 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4:
            raise DerRangeError("der: unsupported length form")
        if p + n > limit:
            raise DerRangeError("der: truncated length")
        ln = 0
        for i in range(n):
            ln = ln * 256 + buf[p + i]
        p += n
    if p + ln > limit:
        raise DerRangeError("der: content exceeds container")
    return _Tlv(tag, p, p + ln)


def _children(buf: bytes, parent: _Tlv) -> List[_Tlv]:
    out: List[_Tlv] = []
    off = parent.start
    while off < parent.end:
        t = _read_tlv(buf, off, parent.end)
        out.append(t)
        off = t.end
    return out


def _at(buf: bytes, i: int) -> Optional[int]:
    return buf[i] if 0 <= i < len(buf) else None  # a JavaScript out-of-range read is undefined


_OID_KEY_USAGE = "551d0f"
_OID_SAN = "551d11"
_OID_BASIC_CONSTRAINTS = "551d13"
# extension OIDs understood well enough to ignore when marked critical
_KNOWN_CRITICAL = frozenset([_OID_KEY_USAGE, _OID_SAN, _OID_BASIC_CONSTRAINTS, "551d25", "551d0e", "551d23"])


class CertFacts:
    """The X.509 facts the SVID rules need, read from DER."""

    def __init__(self) -> None:
        self.basic_constraints_present = False
        self.is_ca = False
        self.path_len: Optional[int] = None
        self.key_usage_present = False
        self.digital_signature = False
        self.key_cert_sign = False
        self.crl_sign = False
        self.uri_sans: List[str] = []
        self.unknown_critical: List[str] = []
        self.bad_boolean = False  # a BOOLEAN that is not one byte long: OpenSSL (the reference's parser) refuses the certificate


def read_cert_facts(der: bytes) -> CertFacts:
    """Read the facts from a DER certificate. Raises DerRangeError on malformed DER."""
    der = bytes(der)
    cert = _read_tlv(der, 0, len(der))
    if cert.tag != 0x30 or cert.end != len(der):
        raise DerRangeError("der: certificate is not a single SEQUENCE")
    kids = _children(der, cert)
    tbs = kids[0] if kids else None
    if tbs is None or tbs.tag != 0x30:
        raise DerRangeError("der: missing tbsCertificate")
    ext_wrap = next((f for f in _children(der, tbs) if f.tag == 0xA3), None)
    facts = CertFacts()
    if ext_wrap is None:
        return facts
    wk = _children(der, ext_wrap)
    ext_seq = wk[0] if wk else None
    if ext_seq is None or ext_seq.tag != 0x30:
        raise DerRangeError("der: malformed extensions")
    seen = set()
    for ext in _children(der, ext_seq):
        parts = _children(der, ext)
        oid_t = parts[0] if parts else None
        if oid_t is None or oid_t.tag != 0x06:
            raise DerRangeError("der: malformed extension")
        oid = der[oid_t.start:oid_t.end].hex()
        if oid in seen:
            raise DerRangeError("der: duplicate extension")
        seen.add(oid)
        if len(parts) == 3 and parts[1].tag == 0x01 and parts[1].end - parts[1].start != 1:
            facts.bad_boolean = True
        critical = len(parts) == 3 and parts[1].tag == 0x01 and _at(der, parts[1].start) == 0xFF
        value_t = parts[-1]
        if value_t.tag != 0x04:
            raise DerRangeError("der: malformed extension value")
        if critical and oid not in _KNOWN_CRITICAL:
            facts.unknown_critical.append(oid)
        inner = _read_tlv(der, value_t.start, value_t.end)
        if oid == _OID_BASIC_CONSTRAINTS:
            facts.basic_constraints_present = True
            for c in _children(der, inner):
                if c.tag == 0x01:
                    if c.end - c.start != 1:
                        facts.bad_boolean = True
                    facts.is_ca = _at(der, c.start) == 0xFF
                elif c.tag == 0x02:
                    n = 0
                    for i in range(c.start, c.end):
                        n = n * 256 + der[i]
                    facts.path_len = n
        elif oid == _OID_KEY_USAGE:
            if inner.tag != 0x03 or inner.end - inner.start < 2:
                raise DerRangeError("der: malformed keyUsage")
            b0 = der[inner.start + 1]
            facts.key_usage_present = True
            facts.digital_signature = (b0 & 0x80) != 0
            facts.key_cert_sign = (b0 & 0x04) != 0
            facts.crl_sign = (b0 & 0x02) != 0
        elif oid == _OID_SAN:
            for gn in _children(der, inner):
                if gn.tag == 0x86:
                    facts.uri_sans.append(der[gn.start:gn.end].decode("latin-1"))
    return facts


# ---- clocks ---------------------------------------------------------------------------------------------------------------

def _now_ms(now: Any) -> float:
    if now is None:
        return time.time() * 1000
    if hasattr(now, "timestamp"):
        return now.timestamp() * 1000
    return float(now) * 1000


def _clock_ms() -> float:
    return time.time() * 1000


def _finite(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and fin(v)


# ---- JWT-SVID -------------------------------------------------------------------------------------------------------------

JWT_SVID_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512")
_HASHES = {"256": "sha256", "384": "sha384", "512": "sha512"}
_EC_ALG = {"ES256": ("P-256", 32), "ES384": ("P-384", 48), "ES512": ("P-521", 66)}
_EC_CURVE = {"P-256": "SECP256R1", "P-384": "SECP384R1", "P-521": "SECP521R1"}

# SVIDs the verify functions returned: svid_to_holder accepts only these
_VERIFIED: "weakref.WeakSet[Any]" = weakref.WeakSet()


class JwtSvid:
    def __init__(self, spiffe_id: SpiffeId, claims: Dict[str, Any], audience: List[Any], expires_at: Any):
        self.spiffe_id = spiffe_id
        self.claims = claims
        self.audience = audience
        self.expires_at = expires_at


class X509Svid:
    def __init__(self, spiffe_id: SpiffeId, certificate: Cert, public_key_der: str):
        self.spiffe_id = spiffe_id
        self.certificate = certificate
        self.public_key_der = public_key_der  # base64url SPKI DER


def _svid_verifier(jwk: Any, alg: str) -> Callable[[bytes, bytes], bool]:
    """verify(data, signature) for a public JWK under a JWT-SVID `alg` (RS / PS / ES, 256 / 384 / 512)."""
    if not isinstance(jwk, dict):
        raise TypeError("JWT-SVID key must be a JWK object")
    c = crypto()
    h = getattr(c.hashes, "SHA" + alg[2:])
    if alg.startswith("ES"):
        crv, size = _EC_ALG[alg]
        if jwk.get("kty") != "EC" or jwk.get("crv") != crv:
            raise TypeError("key does not match %s" % alg)
        pub = c.ec.EllipticCurvePublicNumbers(_b64u_int(jwk.get("x")), _b64u_int(jwk.get("y")), getattr(c.ec, _EC_CURVE[crv])()).public_key()

        def vec(data: bytes, sig: bytes) -> bool:
            if len(sig) != 2 * size:
                return False
            r, s = int.from_bytes(sig[:size], "big"), int.from_bytes(sig[size:], "big")
            try:
                pub.verify(c.utils.encode_dss_signature(r, s), data, c.ec.ECDSA(h()))
                return True
            except c.InvalidSignature:
                return False
        return vec
    if jwk.get("kty") != "RSA":
        raise TypeError("key does not match %s" % alg)
    n, e = _b64u_int(jwk.get("n")), _b64u_int(jwk.get("e"))
    if n.bit_length() < 2048 or n.bit_length() > 16384 or e % 2 == 0 or e < 3 or e.bit_length() > 32:
        raise TypeError("%s requires an RSA key of 2048 bits or larger with a valid exponent" % alg)
    rsa_pub = c.rsa.RSAPublicNumbers(e, n).public_key()
    pad = c.padding.PSS(c.padding.MGF1(h()), h().digest_size) if alg.startswith("PS") else c.padding.PKCS1v15()

    def vrsa(data: bytes, sig: bytes) -> bool:
        try:
            rsa_pub.verify(sig, data, pad, h())
            return True
        except c.InvalidSignature:
            return False
    return vrsa


def create_local_jwk_set(jwks: Any) -> Callable[[Dict[str, Any], Any], List[Dict[str, Any]]]:
    """The key resolver over a JWKS: kid / kty / alg / use / key_ops / crv filtering; exactly one key must match (a one-element list)."""
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list) or any(not isinstance(k, dict) for k in jwks["keys"]):
        raise JoseError("ERR_JWKS_INVALID", "JSON Web Key Set malformed")
    keys = jwks["keys"]

    def resolve(header: Dict[str, Any], token: Any = None) -> List[Dict[str, Any]]:
        alg, kid = header.get("alg"), header.get("kid")
        if not isinstance(alg, str) or alg[:2] not in ("RS", "PS", "ES", "Ed"):
            raise JoseError("ERR_JOSE_NOT_SUPPORTED", 'Unsupported "alg" value for a JSON Web Key Set')
        kty = "RSA" if alg[:2] in ("RS", "PS") else "EC" if alg[:2] == "ES" else "OKP"
        out = []
        for k in keys:
            ok = k.get("kty") == kty
            if ok and isinstance(kid, str):
                ok = k.get("kid") == kid
            if ok and isinstance(k.get("alg"), str):
                ok = k["alg"] == alg
            if ok and isinstance(k.get("use"), str):
                ok = k["use"] == "sig"
            if ok and isinstance(k.get("key_ops"), list):
                ok = "verify" in k["key_ops"]
            if ok and alg == "EdDSA":
                ok = k.get("crv") in ("Ed25519", "Ed448")
            if ok and alg in _EC_ALG:
                ok = k.get("crv") == _EC_ALG[alg][0]
            if ok:
                out.append(k)
        if not out:
            raise JoseError("ERR_JWKS_NO_MATCHING_KEY", "no applicable key found in the JSON Web Key Set")
        if len(out) != 1:  # the reference's verifier does not iterate the candidates: ambiguity refuses
            raise JoseError("ERR_JWKS_MULTIPLE_MATCHING_KEYS", "multiple matching keys found in the JSON Web Key Set")
        if "d" in out[0]:
            raise JoseError("ERR_JWKS_INVALID", "JSON Web Key Set members must be public keys")
        try:
            if alg != "EdDSA":
                _svid_verifier(out[0], alg)  # the key must import under this alg
        except (TypeError, ValueError):
            raise JoseError("ERR_JWKS_INVALID", "JSON Web Key Set member cannot be imported")
        return out
    return resolve


_TOL_RE = re.compile(r"([+-])? ?([0-9]+|[0-9]+\.[0-9]+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?", re.I)


def _tolerance(v: Any) -> Any:
    """A clock tolerance: a number of seconds, or a period string like "30s" / "2 minutes" / "1 hour ago" (the library's grammar)."""
    if not isinstance(v, str):
        return v
    m = _TOL_RE.fullmatch(v)
    if m is None or (m.group(4) and m.group(1)):
        raise TypeError("Invalid time period format")
    unit = m.group(3).lower()
    if unit.startswith("sec") or unit == "s":
        mult = 1
    elif unit.startswith("min") or unit == "m":
        mult = 60
    elif unit.startswith("h"):
        mult = 3600
    elif unit.startswith("d"):
        mult = 86400
    elif unit.startswith("w"):
        mult = 604800
    else:
        mult = 365.25 * 86400
    n = math.floor(float(m.group(2)) * mult + 0.5)  # Math.round
    return -n if m.group(1) == "-" or m.group(4) == "ago" else n


def verify_jwt_svid(token: Any, opts: Dict[str, Any]) -> JwtSvid:
    """Verify a JWT-SVID: signature against `key`, mandatory `aud`, `exp` / `nbf`, SPIFFE `sub` pinned to `trust_domain`.
    Options: audience (str | list), key (JWK dict or callable(header, token) -> JWK dict / list of JWKs), trust_domain, current_date,
    algorithms, clock_tolerance, revocation (callable(subject dict) -> exactly False to admit; present but not callable refuses)."""
    if "revocation" in opts and not callable(opts["revocation"]):
        raise SpiffeError("revocation_unavailable", "revocation must be a function")
    td = opts.get("trust_domain")
    if not isinstance(td, str) or len(td) == 0:
        raise SpiffeError("missing_trust_domain", "verify_jwt_svid requires `trust_domain` (an unpinned JWT-SVID would accept any trust domain the key signs for)")
    audience = opts.get("audience")
    if isinstance(audience, str):
        audience_list: Any = [audience]
    elif isinstance(audience, list):
        audience_list = audience
    else:
        raise TypeError("audience must be a string or a list")
    if len(audience_list) == 0 or any(not isinstance(a, str) or len(a) == 0 for a in audience_list):
        raise SpiffeError("missing_audience", "verify_jwt_svid requires a non-empty audience (JWT-SVID aud is mandatory)")
    algorithms = opts.get("algorithms")
    algorithms = list(JWT_SVID_ALGORITHMS) if algorithms is None else algorithms
    if not isinstance(algorithms, (list, tuple)):
        raise TypeError("algorithms must be a list")
    bad = next((a for a in algorithms if not isinstance(a, str) or a == "none" or a.upper().startswith("HS")), None)
    if bad is not None or len(algorithms) == 0:
        raise SpiffeError("forbidden_algorithm", "JWT-SVIDs must not use %s" % (bad if bad is not None else "an empty algorithm list"))
    try:
        parsed = assert_canonical_compact_jws(token)  # canonical-spelling gate BEFORE the signature check
    except Exception as cause:  # noqa: BLE001 - any gate refusal is a malformed token
        raise SpiffeError("malformed_token", str(cause))
    key = opts.get("key")

    def resolve(alg: str, header: Dict[str, Any]) -> Callable[[bytes, bytes], bool]:
        k = key(header, token) if callable(key) else key
        cands = k if callable(key) and isinstance(k, list) else [k]
        if not cands:
            raise JoseError("ERR_JWKS_NO_MATCHING_KEY", "no applicable key found in the JSON Web Key Set")
        vs = [_svid_verifier(x, alg) for x in cands]
        return lambda data, sig: any(v(data, sig) for v in vs)

    jws_verify_compact(token, parsed, list(algorithms), resolve)
    header, payload = parsed["header"], parsed["payload"]
    jwt_claims_check(header, payload, audience=audience, clock_tolerance=_tolerance(opts.get("clock_tolerance")), now=opts.get("current_date"))
    # JWT-SVID section 3: `typ`, when present, must be JWT or JOSE
    if "typ" in header and header["typ"] not in ("JWT", "JOSE"):
        raise SpiffeError("invalid_typ", "JWT-SVID header typ must be JWT or JOSE, got '%s'" % (header["typ"],))
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        raise SpiffeError("missing_exp", 'JWT-SVID is missing the required "exp" claim')
    sub = payload.get("sub")
    if not isinstance(sub, str):
        raise SpiffeError("invalid_subject", 'JWT-SVID "sub" must be a string SPIFFE ID')
    try:
        spiffe_id = parse_spiffe_id(sub)
    except SpiffeError as err:
        raise SpiffeError("invalid_subject", 'JWT-SVID "sub" is not a valid SPIFFE ID: %s' % err)
    if spiffe_id.trust_domain != td:
        raise SpiffeError("trust_domain_mismatch", 'JWT-SVID trust domain "%s" does not match expected "%s"' % (spiffe_id.trust_domain, td))
    aud = payload.get("aud")
    resolved = [aud] if isinstance(aud, str) else aud
    out = JwtSvid(spiffe_id, payload, resolved, exp)
    if "revocation" in opts:
        subject: Dict[str, Any] = {"spiffe_id": spiffe_id.id}
        if isinstance(payload.get("jti"), str):
            subject["jti"] = payload["jti"]
        subject["expires_at"] = exp
        subject["token_hash"] = b64u(hashlib.sha256(utf8(token)).digest())
        try:
            verdict = opts["revocation"](subject)
        except Exception as e:  # noqa: BLE001
            raise SpiffeError("revocation_unavailable", "revocation check failed: %s" % e)
        if verdict is True:
            raise SpiffeError("svid_revoked", "JWT-SVID for %s is revoked" % spiffe_id.id)
        if verdict is not False:
            raise SpiffeError("revocation_unavailable", "revocation check did not return a boolean")
    _VERIFIED.add(out)
    return out


# ---- X.509-SVID -----------------------------------------------------------------------------------------------------------

_PEM_CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----")


def _to_certificate(x: Any) -> Cert:
    """A certificate from PEM text (the first CERTIFICATE block) or DER bytes (a PEM held in bytes is read as PEM)."""
    try:
        if isinstance(x, str):
            m = _PEM_CERT_RE.search(x)
            if m is None:
                raise ValueError("no PEM certificate found")
            if re.match(r"-----BEGIN CERTIFICATE-----[ \t]*\r?\n", m.group(0)) is None:  # OpenSSL's PEM reader needs the header line terminated
                raise ValueError("error:0480006C:PEM routines::no start line")
            return Cert.from_pem(m.group(0))
        if isinstance(x, (bytes, bytearray)):
            b = bytes(x)
            if b.lstrip().startswith(b"-----BEGIN"):
                return _to_certificate(b.decode("latin-1"))
            return Cert(b)
        raise TypeError("certificate must be PEM text or DER bytes")
    except Exception as e:  # noqa: BLE001
        raise SpiffeError("malformed_certificate", "cannot parse certificate: %s" % e)


def _facts_of(cert: Cert) -> CertFacts:
    try:
        facts = read_cert_facts(cert.raw)
    except Exception as e:  # noqa: BLE001
        raise SpiffeError("malformed_certificate", "cannot read certificate extensions: %s" % e)
    if facts.bad_boolean:
        raise SpiffeError("malformed_certificate", "cannot parse certificate: malformed BOOLEAN")
    return facts


def _validate_leaf(cert: Cert) -> Tuple[SpiffeId, CertFacts]:
    """The X509-SVID leaf rules (SPIFFE X509-SVID section 4.3)."""
    facts = _facts_of(cert)
    if facts.unknown_critical:
        raise SpiffeError("unsupported_critical_extension", "certificate has an unsupported critical extension (%s)" % ", ".join(facts.unknown_critical))
    if len(facts.uri_sans) == 0:
        raise SpiffeError("no_uri_san", "X.509-SVID certificate has no URI SAN")
    if len(facts.uri_sans) > 1:
        raise SpiffeError("multiple_uri_san", "X.509-SVID certificate must have exactly one URI SAN, found %d" % len(facts.uri_sans))
    spiffe_id = parse_spiffe_id(facts.uri_sans[0])
    if spiffe_id.path == "":
        raise SpiffeError("leaf_root_path", "X.509-SVID leaf SPIFFE ID must have a non-root path")
    if facts.is_ca:
        raise SpiffeError("leaf_is_ca", "leaf certificate must not have the CA flag set to true")
    if not facts.digital_signature:
        raise SpiffeError("leaf_no_digital_signature", "leaf certificate must have 'digitalSignature' set as key usage")
    if facts.key_cert_sign:
        raise SpiffeError("leaf_cert_sign", "leaf certificate must not have 'keyCertSign' set as key usage")
    if facts.crl_sign:
        raise SpiffeError("leaf_crl_sign", "leaf certificate must not have 'cRLSign' set as key usage")
    return spiffe_id, facts


def parse_x509_svid(cert: Any) -> X509Svid:
    """Parse an X.509-SVID (PEM text or DER bytes) and apply the leaf rules. Does NOT check chain, validity or revocation."""
    certificate = _to_certificate(cert)
    spiffe_id, _ = _validate_leaf(certificate)
    return X509Svid(spiffe_id, certificate, b64u(certificate.spki_der))


def _certs_of(x: Any) -> List[Cert]:
    if isinstance(x, str):
        blocks = _PEM_CERT_RE.findall(x)
        if not blocks:
            raise SpiffeError("malformed_certificate", "no PEM certificate found")
        return [_to_certificate(b) for b in blocks]
    return [_to_certificate(x)]


def _validate_signer(cert: Cert, label: str) -> CertFacts:
    facts = _facts_of(cert)
    if facts.unknown_critical:
        raise SpiffeError("unsupported_critical_extension", "%s has an unsupported critical extension (%s)" % (label, ", ".join(facts.unknown_critical)))
    if not facts.is_ca:
        raise SpiffeError("chain_not_ca", "%s must have the CA flag set to true" % label)
    if not facts.key_usage_present or not facts.key_cert_sign:
        raise SpiffeError("chain_no_key_cert_sign", "%s must have 'keyCertSign' set as key usage" % label)
    return facts


def _within_validity(cert: Cert, now_ms: float) -> bool:
    return x509_valid_at(cert.raw, now_ms)


_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_ED25519_ALG = bytes.fromhex("300506032b6570")


def _signed_by(cert: Cert, issuer: Cert) -> bool:
    try:
        if cert.sig_alg_der == _ED25519_ALG and cert.inner_sig_alg_der == _ED25519_ALG:  # Ed25519 certificate signatures (X509_verify rules)
            spki = issuer.spki_der
            return (cert.sig_unused == 0 and cert.check_issued(issuer) and len(spki) == 44 and spki.startswith(_ED25519_SPKI_PREFIX)
                    and ed25519.verify(spki[12:], cert.tbs_der, cert.signature))
        return cert.check_issued(issuer) and cert.verify(issuer.public_key)
    except Exception:  # noqa: BLE001 - an unusable issuer key never verifies
        return False


def _serial_hex(cert: Cert) -> str:
    h = "%X" % int.from_bytes(cert.serial, "big")  # the form OpenSSL prints: no leading zeros, even length
    return "0" + h if len(h) % 2 else h


def _fingerprint256(cert: Cert) -> str:
    d = hashlib.sha256(cert.raw).hexdigest().upper()
    return ":".join(d[i:i + 2] for i in range(0, len(d), 2))


def verify_x509_svid(chain: Any, opts: Dict[str, Any]) -> X509Svid:
    """Verify an X.509-SVID against a trust bundle (SPIFFE X509-SVID section 4): leaf rules, trust domain, validity of every
    certificate, signatures, CA / keyCertSign / pathLenConstraint of every signer, and an anchor in `roots`. `chain` is PEM text
    or a list of PEM / DER items, leaf first. Options: trust_domain, roots, now, max_chain_length (8), revocation
    (callable(subject dict) -> exactly False to admit, run LAST for every certificate; present but not callable refuses)."""
    if "revocation" in opts and not callable(opts["revocation"]):
        raise SpiffeError("revocation_unavailable", "revocation must be a function")
    now_ms = _now_ms(opts.get("now"))
    if isinstance(chain, str):
        items = _certs_of(chain)
    elif isinstance(chain, (list, tuple)):
        items = [c for x in chain for c in _certs_of(x)]
    else:
        raise TypeError("chain must be PEM text or a list")
    if len(items) == 0:
        raise SpiffeError("chain_empty", "certificate chain is empty")
    max_len = opts.get("max_chain_length")
    if len(items) > (8 if max_len is None else max_len):
        raise SpiffeError("chain_too_long", "certificate chain is too long")
    leaf = items[0]
    spiffe_id, _ = _validate_leaf(leaf)
    if spiffe_id.trust_domain != opts.get("trust_domain"):
        raise SpiffeError("chain_trust_domain_mismatch", "SPIFFE ID trust domain '%s' is not '%s'" % (spiffe_id.trust_domain, opts.get("trust_domain")))
    roots_in = opts.get("roots")
    if not isinstance(roots_in, (list, tuple)):
        raise TypeError("roots must be a list")
    roots = [c for r in roots_in for c in _certs_of(r)]
    if len(roots) == 0:
        raise SpiffeError("chain_untrusted_root", "trust bundle has no X.509 authorities")
    for c in items:
        if not _within_validity(c, now_ms):
            raise SpiffeError("chain_expired", "a certificate in the chain is not within its validity period")
    # structure first: every signer is a CA with keyCertSign and a satisfied pathLenConstraint
    for i in range(1, len(items)):
        f = _validate_signer(items[i], "signing certificate #%d" % i)
        if f.path_len is not None and i - 1 > f.path_len:
            raise SpiffeError("chain_path_len", "signing certificate #%d pathLenConstraint exceeded" % i)
    below = len(items) - 1
    for i in range(len(items) - 1):
        if not _signed_by(items[i], items[i + 1]):
            raise SpiffeError("chain_signature", "certificate #%d is not signed by certificate #%d" % (i, i + 1))
    top = items[-1]
    if len(items) == 1 and any(r.raw == leaf.raw for r in roots):
        raise SpiffeError("chain_untrusted_root", "a leaf certificate cannot be its own trust anchor")
    top_is_anchor = len(items) > 1 and any(r.raw == top.raw for r in roots)
    if not top_is_anchor:
        signer = next((r for r in roots if _signed_by(top, r)), None)
        if signer is None:
            raise SpiffeError("chain_untrusted_root", "the chain does not lead to an authority in the trust bundle")
        if not _within_validity(signer, now_ms):
            raise SpiffeError("chain_expired", "the trust bundle authority is not within its validity period")
        f = _validate_signer(signer, "trust bundle authority")
        if f.path_len is not None and below > f.path_len:
            raise SpiffeError("chain_path_len", "trust bundle authority pathLenConstraint exceeded")
    if "revocation" in opts:
        for i, c in enumerate(items):
            try:
                verdict = opts["revocation"]({"spiffe_id": spiffe_id.id, "serial_number": _serial_hex(c), "fingerprint256": _fingerprint256(c),
                                              "position": i, "is_leaf": i == 0})
            except Exception as e:  # noqa: BLE001
                raise SpiffeError("revocation_unavailable", "revocation check failed: %s" % e)
            if verdict is True:
                raise SpiffeError("svid_revoked" if i == 0 else "chain_revoked",
                                  "X.509-SVID for %s is revoked" % spiffe_id.id if i == 0 else "signing certificate #%d of the chain is revoked" % i)
            if verdict is not False:
                raise SpiffeError("revocation_unavailable", "revocation check did not return a boolean")
    out = X509Svid(spiffe_id, leaf, b64u(leaf.spki_der))
    _VERIFIED.add(out)
    return out


# ---- SPIFFE ID <-> PCA agent-holder identity ------------------------------------------------------------------------------


class SpiffeHolder(NamedTuple):
    holder: str  # base64url Ed25519 public key (Capability.holder)
    spiffe_id: str
    trust_domain: str
    path: str


def _normalize_holder_key(holder_key: Any) -> str:
    if isinstance(holder_key, (bytes, bytearray)):
        if len(holder_key) != 32:
            raise SpiffeError("invalid_holder_key", "holder key must be a 32-byte Ed25519 public key")
        return b64u(bytes(holder_key))
    raw = decode_b64u_strict(holder_key, 32)
    if raw is None:
        raise SpiffeError("invalid_holder_key", "holder key must be a 32-byte Ed25519 public key encoded as base64url")
    return b64u(raw)


def holder_binding_message(spiffe_id: str, holder: str) -> bytes:
    """Domain-separated message a workload signs with its SVID key to bind a PCA holder key to its SPIFFE ID."""
    return _utf8("pca-spiffe-holder-binding-v1\n%s\n%s" % (spiffe_id, holder))


def _ed25519_raw_of_cert(cert: Cert) -> Optional[str]:
    spki = cert.spki_der
    if len(spki) == 44 and spki.startswith(_ED25519_SPKI_PREFIX):
        return b64u(spki[12:])
    return None


def _proof_verifies(cert: Cert, msg: bytes, sig: bytes) -> bool:
    spki = cert.spki_der
    if len(spki) == 44 and spki.startswith(_ED25519_SPKI_PREFIX):
        return ed25519.verify(spki[12:], msg, sig)
    key = cert.public_key
    t = key_type(key)
    if t == "ec":
        return ecdsa_verify_raw(key, sig, msg, "sha384" if key.curve.name == "secp384r1" else "sha256")
    if t == "rsa":
        return rsa_pkcs1_verify(key, sig, msg, "sha256")
    return False


def svid_to_holder(svid: Any, holder_key: Any = None, opts: Optional[Dict[str, Any]] = None) -> SpiffeHolder:
    """Bind a VERIFIED SVID (the object verify_jwt_svid / verify_x509_svid returned; anything else is `unverified_svid`) to a PCA
    holder. X.509 Ed25519: the holder IS the SVID key. Another key, or a different holder: `opts["proof"]`, a base64url signature by
    the SVID key over holder_binding_message (ECDSA is IEEE P1363). JWT-SVID: the token's cnf.jwk must equal the holder unless
    `opts["accept_unbound_jwt_holder"]` is True."""
    opts = opts or {}
    if not isinstance(svid, (JwtSvid, X509Svid)) or svid not in _VERIFIED:
        raise SpiffeError("unverified_svid", "svid_to_holder needs the result of verify_jwt_svid / verify_x509_svid (a string, a parsed-only SVID or a hand-built object is not accepted)")
    parsed = svid.spiffe_id
    if isinstance(svid, X509Svid):
        cert_ed = _ed25519_raw_of_cert(svid.certificate)
        if holder_key is None:
            if cert_ed is None:
                raise SpiffeError("invalid_holder_key", "the X.509-SVID key is not Ed25519, so the holder cannot be derived from it: pass holder_key and opts[\"proof\"]")
            holder = _normalize_holder_key(cert_ed)
        else:
            holder = _normalize_holder_key(holder_key)
            if cert_ed is None or cert_ed != holder:
                proof = opts.get("proof")
                if not isinstance(proof, str):
                    raise SpiffeError("holder_binding_failed", "the holder key is not the SVID key: opts[\"proof\"] (a signature by the SVID key over holder_binding_message) is required")
                sig = decode_b64u_strict(proof)
                ok = False
                try:
                    if sig is not None:
                        ok = bool(_proof_verifies(svid.certificate, holder_binding_message(parsed.id, holder), sig))
                except Exception:  # noqa: BLE001
                    ok = False
                if not ok:
                    raise SpiffeError("holder_binding_failed", "opts[\"proof\"] does not verify under the X.509-SVID key")
    else:
        if holder_key is None:
            raise SpiffeError("invalid_holder_key", "a JWT-SVID has no key of its own: pass holder_key")
        holder = _normalize_holder_key(holder_key)
        cnf = svid.claims.get("cnf")
        jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
        bound = isinstance(jwk, dict) and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519" and isinstance(jwk.get("x"), str) and jwk["x"] == holder
        if not bound and opts.get("accept_unbound_jwt_holder") is not True:
            raise SpiffeError("holder_binding_failed", "the JWT-SVID carries no cnf.jwk equal to the holder key (set accept_unbound_jwt_holder only if the key is authenticated by other means)")
    return SpiffeHolder(holder, parsed.id, parsed.trust_domain, parsed.path)


def holder_to_spiffe_id(holder: Any) -> str:
    """The validated, canonical SPIFFE ID a SpiffeHolder was bridged from."""
    return parse_spiffe_id(holder.spiffe_id if not isinstance(holder, dict) else holder.get("spiffe_id")).id


def spiffe_id_for_holder(svid: Any, leaf_holder: str, opts: Optional[Dict[str, Any]] = None) -> str:
    """The SPIFFE ID of a VERIFIED SVID bound to `leaf_holder` (the key that signed the PCActn); refuses otherwise."""
    h = svid_to_holder(svid, leaf_holder, opts)
    if h.holder != leaf_holder:
        raise SpiffeError("holder_binding_failed", "the SVID is not bound to the PCActn leaf holder")
    return h.spiffe_id


def workload_discharge_pin(label: str, svid: Any) -> Dict[str, str]:
    """A discharge-issuer pin for a workload: its own Ed25519 SVID key and SPIFFE ID, class `workload`."""
    h = svid_to_holder(svid)
    return {"label": label, "class": "workload", "pk": h.holder, "spiffe_id": h.spiffe_id}


# ---- trust-bundle cache (fails closed) ------------------------------------------------------------------------------------


def _check_windows(refresh_ms: Any, max_stale_ms: Any, code: str) -> None:
    if not (_finite(refresh_ms) and refresh_ms > 0) or not (_finite(max_stale_ms) and max_stale_ms >= refresh_ms):
        raise SpiffeError(code, "refresh_ms must be > 0 and max_stale_ms >= refresh_ms (both finite)")


def _bundle_usable(b: Any) -> bool:
    if not isinstance(b, dict):
        return False
    j = b.get("jwks")
    if "jwks" in b and j is None:
        raise TypeError("jwks is null")  # the reference reads `.keys` of it: a failed fetch, not an invalid bundle
    has_j = isinstance(j, dict) and isinstance(j.get("keys"), list) and len(j["keys"]) > 0
    x = b.get("x509_authorities")
    return has_j or (isinstance(x, list) and len(x) > 0)


class TrustBundleSource:
    """A trust-bundle cache that fails closed: before the first successful fetch, or past `max_stale_ms` after the last one,
    every call raises `trust_bundle_unavailable` (fetch failed) or `trust_bundle_invalid` (empty / malformed). A refresh REPLACES
    the bundle (never merged). A bundle is {"jwks": {"keys": [...]}, "x509_authorities": [PEM or DER, ...]}."""

    def __init__(self, opts: Dict[str, Any]):
        fetch = opts.get("fetch") if isinstance(opts, dict) else None
        if not callable(fetch):
            raise SpiffeError("trust_bundle_unavailable", "create_trust_bundle_source requires `fetch`")
        _check_windows(opts.get("refresh_ms"), opts.get("max_stale_ms"), "trust_bundle_unavailable")
        self._fetch = fetch
        self._refresh_ms = opts["refresh_ms"]
        self._max_stale_ms = opts["max_stale_ms"]
        self._now = opts.get("now") or _clock_ms
        self._good: Optional[Tuple[Dict[str, Any], float]] = None
        self._last_failure: Optional[SpiffeError] = None
        self._lock = threading.Lock()

    def _refresh(self) -> None:
        try:
            b = self._fetch()
            if not _bundle_usable(b):
                raise SpiffeError("trust_bundle_invalid", "fetched trust bundle has no authorities")
            self._good = (b, self._now())
            self._last_failure = None
        except Exception as e:  # noqa: BLE001
            self._last_failure = e if isinstance(e, SpiffeError) else SpiffeError("trust_bundle_unavailable", "trust bundle fetch failed: %s" % e)

    def _current(self) -> Dict[str, Any]:
        with self._lock:
            if self._good is None or self._now() - self._good[1] >= self._refresh_ms:
                self._refresh()
            if self._good is None or self._now() - self._good[1] > self._max_stale_ms:
                raise self._last_failure or SpiffeError("trust_bundle_unavailable", "no trust bundle available")
            return self._good[0]

    def jwt_key(self, header: Dict[str, Any], token: Any = None) -> List[Dict[str, Any]]:
        """Key resolver for verify_jwt_svid's `key` option."""
        jwks = self._current().get("jwks")
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list) or len(jwks["keys"]) == 0:
            raise SpiffeError("trust_bundle_invalid", "trust bundle has no JWT authorities")
        return create_local_jwk_set(jwks)(header, token)

    def x509_roots(self) -> List[Any]:
        """Authorities for verify_x509_svid's `roots` option."""
        roots = self._current().get("x509_authorities")
        if not isinstance(roots, list) or len(roots) == 0:
            raise SpiffeError("trust_bundle_invalid", "trust bundle has no X.509 authorities")
        return list(roots)


def create_trust_bundle_source(opts: Dict[str, Any]) -> TrustBundleSource:
    return TrustBundleSource(opts)


# ---- revocation source (fails closed) -------------------------------------------------------------------------------------


def _norm_hex(s: str) -> str:
    return s.replace(":", "").upper()


def _norm_serial(s: str) -> str:
    return re.sub(r"^0+(?=.)", "", _norm_hex(s))


def _list_of(raw: Dict[str, Any], key: str) -> List[str]:
    if key not in raw:
        return []
    v = raw[key]
    if not isinstance(v, list) or any(not isinstance(x, str) for x in v):
        raise SpiffeError("revocation_unavailable", 'revocation list field "%s" must be an array of strings' % key)
    return v


class _Snapshot:
    def __init__(self, lst: Any):
        if not isinstance(lst, dict):
            raise SpiffeError("revocation_unavailable", "revocation list must be an object")
        self.fingerprints = {_norm_hex(x) for x in _list_of(lst, "fingerprints")}
        self.serials = {_norm_serial(x) for x in _list_of(lst, "serials")}
        self.spiffe_ids = set(_list_of(lst, "spiffe_ids"))
        self.jtis = set(_list_of(lst, "jtis"))
        self.token_hashes = set(_list_of(lst, "token_hashes"))


class RevocationSource:
    """A revocation snapshot cache that fails closed, in the shape of TrustBundleSource. The fetched list is a dict of optional
    string lists: fingerprints, serials, spiffe_ids, jtis, token_hashes. `x509` uses the cached snapshot (call `ensure_fresh`
    first); `jwt` refreshes when due."""

    def __init__(self, opts: Dict[str, Any]):
        fetch = opts.get("fetch") if isinstance(opts, dict) else None
        if not callable(fetch):
            raise SpiffeError("revocation_unavailable", "create_revocation_source requires `fetch`")
        _check_windows(opts.get("refresh_ms"), opts.get("max_stale_ms"), "revocation_unavailable")
        self._fetch = fetch
        self._refresh_ms = opts["refresh_ms"]
        self._max_stale_ms = opts["max_stale_ms"]
        self._now = opts.get("now") or _clock_ms
        self._good: Optional[Tuple[_Snapshot, float]] = None
        self._last_failure: Optional[SpiffeError] = None
        self._lock = threading.Lock()

    def _run(self) -> None:
        try:
            self._good = (_Snapshot(self._fetch()), self._now())
            self._last_failure = None
        except Exception as e:  # noqa: BLE001
            self._last_failure = e if isinstance(e, SpiffeError) else SpiffeError("revocation_unavailable", "revocation fetch failed: %s" % e)

    def _usable(self) -> _Snapshot:
        if self._good is None or self._now() - self._good[1] > self._max_stale_ms:
            raise self._last_failure or SpiffeError("revocation_unavailable", "no revocation snapshot available")
        return self._good[0]

    def refresh(self) -> None:
        """Fetch now; raises `revocation_unavailable` when the fetch fails or returns a malformed snapshot."""
        with self._lock:
            self._run()
            if self._last_failure is not None:
                raise self._last_failure

    def ensure_fresh(self) -> None:
        """Fetch when older than refresh_ms; raises when no snapshot younger than max_stale_ms exists afterwards."""
        with self._lock:
            if self._good is None or self._now() - self._good[1] >= self._refresh_ms:
                self._run()
            self._usable()

    def x509(self, s: Dict[str, Any]) -> bool:
        snap = self._usable()
        return _norm_hex(s["fingerprint256"]) in snap.fingerprints or _norm_serial(s["serial_number"]) in snap.serials or s["spiffe_id"] in snap.spiffe_ids

    def jwt(self, s: Dict[str, Any]) -> bool:
        self.ensure_fresh()
        snap = self._usable()
        return s["spiffe_id"] in snap.spiffe_ids or (s.get("jti") is not None and s["jti"] in snap.jtis) or s["token_hash"] in snap.token_hashes


def create_revocation_source(opts: Dict[str, Any]) -> RevocationSource:
    return RevocationSource(opts)


# ---- evidence for blueprint admission -------------------------------------------------------------------------------------


def spiffe_admission_evidence(e: Dict[str, Any], instance_key: Any) -> Dict[str, Any]:
    """A workload admitted under its verified SPIFFE ID: the SVID is verified ({"kind": "x509", "chain", "verify", "bind"?} or
    {"kind": "jwt", "token", "verify", "bind"?}) then bound to the INSTANCE KEY. Anything unverifiable, unbound or for another key
    is {"ok": False, "bound": False, "reason": code}."""
    try:
        svid = verify_x509_svid(e["chain"], e["verify"]) if e["kind"] == "x509" else verify_jwt_svid(e["token"], e["verify"])
        h = svid_to_holder(svid, instance_key, e.get("bind") or {})
        if h.holder != instance_key:
            return {"ok": False, "bound": False, "reason": "SVID is bound to a different key"}
        return {"ok": True, "bound": True, "identity": {"spiffe_id": h.spiffe_id}}
    except Exception as err:  # noqa: BLE001
        code = getattr(err, "code", None)
        return {"ok": False, "bound": False, "reason": code if isinstance(code, str) else type(err).__name__}
