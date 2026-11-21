"""AP2 (Agent Payments Protocol) mandates as real SD-JWT credentials, bound to a PCA grant (the TypeScript reference, @atlasauth/pca-ap2).

PCA governs: it decides who may spend, how much, until when, and when a human must co-sign. AP2 is the mandate wire other parties verify.

- SD-JWT primitives (RFC 9901): strict compact parsing (duplicate keys, fatal UTF-8, canonical base64url), disclosure processing,
  the `sd_hash` / `issuer_jwt_hash` binding digests and ES256 (P-256) signing and verification.
- Mandate claim shapes (Intent/Cart/Payment, closed and open), their validators and ISO 4217 minor units.
- Open-mandate constraint evaluation against a closed mandate / checkout, issuance and presentation of delegation chains, chain and
  purchase verification, the single-use redeem ledger, settlement payloads (x402, Stripe shared payment tokens) and the PCA terms bridge.

Options, inputs and results are plain dicts with the reference's member names (`expectedAudience`, `resolveIssuerKey`, `agentJwk`, ...),
so a token issued here verifies in the TypeScript verifier and the reverse. Keys are `cryptography` P-256 key objects
(`ap2_key_pair_from_private_jwk` / `generate_ap2_key_pair` return {"publicJwk", "privateKey"}); `cryptography` is imported lazily and
is required for every ES256 operation. Time arguments are epoch seconds; where the reference reads the clock the default is `time.time()`.

Not ported: `verifyPcaBinding` (it needs the PCA core verifier and the payments policy decision) and its `PcaBindingError`.
`redeem_purchase` is synchronous (a ledger whose methods return awaitables is refused); `redeem_purchase_async` awaits them.
"""
import base64
import hashlib
import inspect
import json
import math
from ._fin import fin
import re
import secrets
import struct
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .agent import KeyPair, build_pcactn
from .payments import authorize_charge, charge_params, charge_plan_node, mandate_caveats, mandate_predicates
from .pca import hash_canonical, params_digest, ts_reason, verify_chain, verify_pcactn_core
from .risk import required_threshold
from .sdjwt_jws import b64u, jws_sign, js_json, js_to_string, node_b64url_decode

__all__ = [
    "Ap2Error", "Ap2KeyError", "AP2_COMMIT", "VCT_CHECKOUT", "VCT_CHECKOUT_OPEN", "VCT_PAYMENT", "VCT_PAYMENT_OPEN", "PCA_CLAIM", "FREQUENCIES",
    "PCA_BINDING_VERSION", "TYP_TERMINAL", "TYP_INTERMEDIATE", "b64u_encode", "b64u_decode", "is_object", "parse_json", "is_sd_alg", "sd_digest",
    "assert_p256_jwk", "generate_ap2_key_pair", "ap2_key_pair_from_private_jwk", "jwk_thumbprint", "hop_sd_jwt", "parse_sd_jwt_hop", "sd_hash_of",
    "issuer_jwt_hash_of", "verify_hop_signature", "process_disclosures", "new_salt", "disclosure_builder", "sign_sd_jwt", "sign_jwt_es256", "parse_jwt",
    "verify_jwt_es256", "currency_exponent", "to_minor_units", "from_minor_units", "open_payment_mandate_problems", "payment_mandate_problems",
    "open_checkout_mandate_problems", "checkout_mandate_problems", "assert_valid", "merchant_matches", "check_payment_constraints", "project_checkout",
    "checkout_total", "check_checkout_constraints", "issue_open_payment_mandate", "issue_open_checkout_mandate", "present_closed_payment",
    "present_closed_checkout", "split_chain", "verify_kb_hop", "verify_delegation_chain", "verify_checkout_chain", "verify_payment_chain",
    "verify_purchase", "redeem_purchase", "redeem_purchase_async", "ap2_budget_max", "ap2_budget_reads", "pca_open_claim",
    "payment_constraints_from_terms", "open_payment_mandate_from_pca", "open_checkout_mandate_from_pca", "pca_binding_nonce", "risk_ratio",
    "build_pca_payment_binding", "verify_pca_binding", "PcaBindingError", "to_atomic_units", "x402_settlement", "stripe_spt_settlement",
]

AP2_COMMIT = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43"
VCT_CHECKOUT = "mandate.checkout.1"
VCT_CHECKOUT_OPEN = "mandate.checkout.open.1"
VCT_PAYMENT = "mandate.payment.1"
VCT_PAYMENT_OPEN = "mandate.payment.open.1"
PCA_CLAIM = "x_pca"
FREQUENCIES = ("ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY")
PCA_BINDING_VERSION = 1
TYP_TERMINAL = ("kb+sd-jwt", "kb-sd-jwt")
TYP_INTERMEDIATE = ("kb+sd-jwt+kb", "kb-sd-jwt+kb")
_MAX_HOPS = 8
_ROOT_TYP = "dc+sd-jwt"
_SD_ALGS = ("sha-256", "sha-384", "sha-512")
_MAX_SAFE = 2 ** 53 - 1
_U = object()  # an absent member (JS undefined), distinct from JSON null


class Ap2Error(Exception):
    """Every failure raised while parsing or verifying carries a human-readable reason."""


class HashAlgorithmError(ValueError):
    """The reference runtime's ERR_INVALID_ARG_TYPE for a hash name its table does not hold."""

    code = "ERR_INVALID_ARG_TYPE"


class Ap2KeyError(ValueError):
    """A private JWK that cannot be imported as a P-256 key (the reference's Node ERR_CRYPTO_INVALID_JWK)."""

    code = "ERR_CRYPTO_INVALID_JWK"


class RangeError(ValueError):
    """The reference's RangeError (a number outside its allowed range)."""


# ---- JS-semantics helpers ----------------------------------------------------------------------------------------------------

def _g(o: Any, k: str) -> Any:
    """`o[k]`: a member of a JSON object; undefined for any other non-null value; null / undefined throw like the reference."""
    if isinstance(o, dict):
        return o[k] if k in o else _U
    if o is None or o is _U:
        raise TypeError("Cannot read properties of %s (reading '%s')" % ("null" if o is None else "undefined", k))
    return _U


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _finite(v: Any) -> bool:
    return _num(v) and fin(v)


def _neg0(v: Any) -> bool:
    return isinstance(v, float) and v == 0 and math.copysign(1.0, v) < 0


def _safe_int(v: Any) -> bool:
    """Number.isSafeInteger."""
    if not _num(v):
        return False
    if isinstance(v, float) and not (fin(v) and v == math.trunc(v)):
        return False
    return abs(int(v)) <= _MAX_SAFE


def _is_int(v: Any) -> bool:
    return _safe_int(v) and not _neg0(v)


def _is_nonneg_int(v: Any) -> bool:
    return _is_int(v) and v >= 0


def _is_str(v: Any) -> bool:
    return isinstance(v, str)


def _is_nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and len(v) > 0


def _truthy(v: Any) -> bool:
    if v is None or v is _U or v is False:
        return False
    if _num(v):
        return v == v and v != 0
    if isinstance(v, str):
        return v != ""
    return True


def _seq(a: Any, b: Any) -> bool:
    """`a === b` over JSON values (containers by identity)."""
    if a is _U or b is _U:
        return a is b
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _num(a) and _num(b):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return a is b


def _str(v: Any) -> str:
    """String(v)."""
    return "undefined" if v is _U else js_to_string(v)


def _jsorder(v: Any) -> Any:
    """Own-property order of a JS object: integer-like keys ascending first, then the rest in insertion order."""
    if isinstance(v, dict):
        idx = [k for k in v if isinstance(k, str) and re.fullmatch(r"0|[1-9][0-9]*", k) and int(k) < 2 ** 32 - 1]
        idx_set = set(idx)
        keys = sorted(idx, key=int) + [k for k in v if k not in idx_set]
        return {k: _jsorder(v[k]) for k in keys}
    if isinstance(v, list):
        return [_jsorder(x) for x in v]
    return v


def _stringify(v: Any) -> str:
    """JSON.stringify(v)."""
    return js_json(_jsorder(v))


def _utf8(s: str) -> bytes:
    return s.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")  # a lone surrogate is written as U+FFFD


def _parse_int(s: str) -> Any:
    if s == "-0":
        return -0.0
    v = int(s)
    return v if abs(v) <= 2 ** 53 else float(v)  # a JS number is a double


def _no_constant(name: str) -> Any:
    raise ValueError("invalid JSON constant " + name)


def _loads(text: str) -> Any:
    return json.loads(text, parse_int=_parse_int, parse_constant=_no_constant)


def _spread(x: Any) -> dict:
    if isinstance(x, dict):
        return dict(x)
    if isinstance(x, list):
        return {str(i): v for i, v in enumerate(x)}
    if isinstance(x, str):
        return {str(i): c for i, c in enumerate(x)}
    return {}


def _compact(**kw: Any) -> dict:
    """A dict without the members whose value is undefined (what JSON.stringify drops)."""
    return {k: v for k, v in kw.items() if v is not _U}


def _js_round(x: float) -> int:
    f = math.floor(x)
    return f + 1 if x - f >= 0.5 else f


def _to_json(v: Any) -> Any:
    """JSON.parse(JSON.stringify(v)): throws for undefined."""
    if v is _U:
        raise TypeError("JSON.parse: undefined is not valid JSON")
    return _loads(_stringify(v))


# ---- base64url + JSON helpers ------------------------------------------------------------------------------------------------

def b64u_encode(data: Any) -> str:
    return b64u(_utf8(data) if isinstance(data, str) else bytes(data))


def b64u_decode(s: str, what: str) -> bytes:
    """Strict base64url decode: canonical alphabet, no padding, and the encoding must round-trip."""
    if not isinstance(s, str) or re.fullmatch(r"[A-Za-z0-9_-]*", s) is None:
        raise Ap2Error("%s: not base64url" % what)
    buf = node_b64url_decode(s)
    if b64u(buf) != s:
        raise Ap2Error("%s: non-canonical base64url" % what)
    return buf


def is_object(v: Any) -> bool:
    return isinstance(v, dict)


def _assert_no_duplicate_keys(text: str, what: str) -> None:
    """Reject an object that repeats a key (JSON.parse keeps the last): run on text that already parsed."""
    stack: List[Optional[set]] = []
    expect_key = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            top = stack[-1] if stack else None
            if expect_key and top is not None:
                key = json.loads(text[i:j + 1])
                if key in top:
                    raise Ap2Error("%s: duplicate key %s" % (what, js_json(key)))
                top.add(key)
                expect_key = False
            i = j
        elif c == "{":
            stack.append(set())
            expect_key = True
        elif c == "[":
            stack.append(None)
            expect_key = False
        elif c == "}" or c == "]":
            if stack:
                stack.pop()
            expect_key = False
        elif c == ",":
            expect_key = bool(stack) and stack[-1] is not None
        i += 1


def parse_json(text: str, what: str) -> Any:
    """JSON.parse that rejects duplicate keys. Numbers are parsed as written (`1000.0` is accepted)."""
    try:
        v = _loads(text)
    except (ValueError, RecursionError, TypeError) as e:
        raise Ap2Error("%s: invalid JSON (%s)" % (what, e))
    _assert_no_duplicate_keys(text, what)
    return v


def _utf8_text(b: bytes, what: str) -> str:
    try:
        return bytes(b).decode("utf-8")  # fatal on any invalid sequence; a BOM is kept so JSON parsing refuses it
    except UnicodeDecodeError:
        raise Ap2Error("%s: not valid UTF-8" % what)


def _decode_json_segment(segment: str, what: str) -> dict:
    v = parse_json(_utf8_text(b64u_decode(segment, what), what), what)
    if not isinstance(v, dict):
        raise Ap2Error("%s: must be a JSON object" % what)
    return v


# ---- hashing ------------------------------------------------------------------------------------------------------------------

def is_sd_alg(v: Any) -> bool:
    return isinstance(v, str) and v in _SD_ALGS


def sd_digest(value: str, alg: str = "sha-256") -> str:
    """base64url(hash(ascii(value))): the digest used for disclosures, `sd_hash` and `checkout_hash`."""
    if not isinstance(value, str) or re.fullmatch(r"[\x20-\x7e]*", value) is None:
        raise Ap2Error("digest input must be ASCII")
    if not is_sd_alg(alg):
        raise HashAlgorithmError('The "algorithm" argument must be of type string. Received undefined')
    return b64u(hashlib.new(alg.replace("-", ""), value.encode("ascii")).digest())


# ---- ES256 keys (P-256) --------------------------------------------------------------------------------------------------------

def _ec() -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        raise ImportError("AP2 ES256 needs the 'cryptography' package (pip install cryptography)") from None
    return ec


def _public_key(jwk: dict) -> Any:
    ec = _ec()
    x = int.from_bytes(node_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(node_b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def assert_p256_jwk(jwk: Any, what: str) -> dict:
    """Validate a public JWK against `types/jwk.json` and prove the point is on the curve. Returns the JWK itself."""
    if not isinstance(jwk, dict):
        raise Ap2Error("%s: JWK must be an object" % what)
    if not _seq(jwk.get("kty", _U), "EC") or not _seq(jwk.get("crv", _U), "P-256"):
        raise Ap2Error("%s: JWK must be EC P-256" % what)
    for c in ("x", "y"):
        v = jwk.get(c, _U)
        if not isinstance(v, str) or re.fullmatch(r"[A-Za-z0-9_-]{43}", v) is None:
            raise Ap2Error("%s: bad JWK %s" % (what, c))
    if "d" in jwk:
        raise Ap2Error("%s: JWK carries private material" % what)
    if jwk.get("alg", _U) is not _U and not _seq(jwk["alg"], "ES256"):
        raise Ap2Error("%s: JWK alg must be ES256" % what)
    try:
        _public_key(jwk)
    except ValueError:
        raise Ap2Error("%s: JWK is not a valid P-256 point" % what)
    return jwk


def _public_jwk(pub: Any, kid: Any = _U) -> dict:
    n = pub.public_numbers()
    out = {"kty": "EC", "crv": "P-256", "x": b64u(n.x.to_bytes(32, "big")), "y": b64u(n.y.to_bytes(32, "big"))}
    if kid is not _U:
        out["kid"] = kid
    return out


def generate_ap2_key_pair(kid: Optional[str] = None) -> dict:
    """A fresh P-256 key pair: {"publicJwk" (never contains `d`), "privateKey"}."""
    key = _ec().generate_private_key(_ec().SECP256R1())
    return {"publicJwk": _public_jwk(key.public_key(), _U if kid is None else kid), "privateKey": key}


def ap2_key_pair_from_private_jwk(jwk: dict) -> dict:
    """Rebuild a key pair from a private JWK (`d` present), e.g. for fixtures. A JWK whose x / y do not match `d` is refused."""
    ec = _ec()
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or not all(isinstance(jwk.get(k), str) for k in ("d", "x", "y")):
        raise Ap2KeyError("Invalid JWK EC key")
    try:
        key = ec.derive_private_key(int.from_bytes(node_b64url_decode(jwk["d"]), "big"), ec.SECP256R1())
    except ValueError:
        raise Ap2KeyError("Invalid JWK EC key") from None
    pub = _public_jwk(key.public_key())
    if node_b64url_decode(jwk["x"]) != node_b64url_decode(pub["x"]) or node_b64url_decode(jwk["y"]) != node_b64url_decode(pub["y"]):
        raise Ap2KeyError("Invalid JWK EC key")
    kid = jwk.get("kid")
    return {"privateKey": key, "publicJwk": _public_jwk(key.public_key(), kid if isinstance(kid, str) else _U)}


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint (SHA-256) of an EC P-256 key."""
    canonical = '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (_str(_g(jwk, "x")), _str(_g(jwk, "y")))
    return b64u(hashlib.sha256(_utf8(canonical)).digest())


def _es256_sign(private_key: Any, signing_input: str) -> str:
    return b64u(jws_sign("ES256", private_key, signing_input.encode("ascii")))


def _es256_verify(jwk: dict, signing_input: str, signature: bytes) -> bool:
    if len(signature) != 64:
        return False
    ec = _ec()
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if r == 0 or s == 0:
        return False
    try:
        _public_key(jwk).verify(encode_dss_signature(r, s), signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---- compact JWT / SD-JWT parsing --------------------------------------------------------------------------------------------

def hop_sd_jwt(hop: dict) -> str:
    """The hop's `~`-joined serialisation: what `sd_hash` is computed over."""
    return "%s~%s" % (hop["jwt"], "".join("%s~" % d for d in hop["disclosures"]))


def parse_sd_jwt_hop(token: str) -> dict:
    """Parse one SD-JWT (`jwt~d1~...~dn~`; it must end with `~`). Returns {raw, jwt, header, payload, disclosures, sdAlg, signingInput, signature}."""
    if not isinstance(token, str) or len(token) == 0:
        raise Ap2Error("SD-JWT: empty")
    if token.startswith("~"):
        raise Ap2Error("SD-JWT: empty issuer JWT")
    if not token.endswith("~"):
        raise Ap2Error('SD-JWT: must end with "~" (a trailing KB-JWT is not an AP2 form)')
    parts = token[:-1].split("~")
    jwt = parts[0]
    disclosures = parts[1:]
    if any(len(d) == 0 for d in disclosures):
        raise Ap2Error("SD-JWT: empty disclosure segment")
    seg = jwt.split(".")
    if len(seg) != 3 or any(len(s) == 0 for s in seg):
        raise Ap2Error("SD-JWT: issuer JWT must be header.payload.signature")
    h, p, s = seg
    header = _decode_json_segment(h, "JWT header")
    payload = _decode_json_segment(p, "JWT payload")
    signature = b64u_decode(s, "JWT signature")
    raw_alg = payload.get("_sd_alg", _U)
    if raw_alg is not _U and not is_sd_alg(raw_alg):
        raise Ap2Error("SD-JWT: unsupported _sd_alg %s" % js_json(raw_alg))
    return {"raw": token, "jwt": jwt, "header": header, "payload": payload, "disclosures": disclosures,
            "sdAlg": raw_alg if is_sd_alg(raw_alg) else "sha-256", "signingInput": "%s.%s" % (h, p), "signature": signature}


def sd_hash_of(hop: dict, alg: Optional[str] = None) -> str:
    """`sd_hash` of a hop: the digest of `<jwt>~<d1>~...~` (the on-wire form of the preceding hop)."""
    return sd_digest(hop_sd_jwt(hop), hop["sdAlg"] if alg is None else alg)


def issuer_jwt_hash_of(hop: dict, alg: Optional[str] = None) -> str:
    """`issuer_jwt_hash` of a hop: the digest of the issuer-signed JWT alone."""
    return sd_digest(hop["jwt"], hop["sdAlg"] if alg is None else alg)


def verify_hop_signature(hop: dict, key: dict) -> bool:
    """Verify the issuer JWT's ES256 signature. Anything other than `alg: ES256` is rejected."""
    if not _seq(hop["header"].get("alg", _U), "ES256"):
        return False
    return _es256_verify(assert_p256_jwk(key, "verification key"), hop["signingInput"], hop["signature"])


def parse_jwt(jwt: str, what: str) -> dict:
    """Parse a compact JWT: {header, payload, signingInput, signature}."""
    seg = _need_str(jwt).split(".")
    if len(seg) != 3 or any(len(s) == 0 for s in seg):
        raise Ap2Error("%s: must be header.payload.signature" % what)
    h, p, s = seg
    return {"header": _decode_json_segment(h, "%s header" % what), "payload": _decode_json_segment(p, "%s payload" % what),
            "signingInput": "%s.%s" % (h, p), "signature": b64u_decode(s, "%s signature" % what)}


def _need_str(v: Any) -> str:
    if not isinstance(v, str):
        raise TypeError("expected a string")
    return v


def verify_jwt_es256(parsed: dict, key: dict) -> bool:
    if not _seq(parsed["header"].get("alg", _U), "ES256"):
        return False
    return _es256_verify(assert_p256_jwk(key, "verification key"), parsed["signingInput"], parsed["signature"])


# ---- disclosure processing (RFC 9901 section 7) -----------------------------------------------------------------------------

def _decode_disclosure(raw: str) -> dict:
    arr = parse_json(_utf8_text(b64u_decode(raw, "disclosure"), "disclosure"), "disclosure")
    if not isinstance(arr, list):
        raise Ap2Error("disclosure: must be a JSON array")
    if not arr or not isinstance(arr[0], str) or len(arr[0]) == 0:
        raise Ap2Error("disclosure: salt must be a non-empty string")
    if len(arr) == 3:
        name = arr[1]
        if not isinstance(name, str):
            raise Ap2Error("disclosure: claim name must be a string")
        if name == "_sd" or name == "...":
            raise Ap2Error("disclosure: claim name %s is reserved" % name)
        return {"kind": "property", "name": name, "value": arr[2], "raw": raw}
    if len(arr) == 2:
        return {"kind": "element", "value": arr[1], "raw": raw}
    raise Ap2Error("disclosure: array must have 2 or 3 elements")


def process_disclosures(payload: dict, disclosures: List[str], alg: str) -> dict:
    """Resolve every selectively-disclosable claim in `payload` using `disclosures`; `_sd`, `...` markers and `_sd_alg` are removed.
    Raises if a disclosure is duplicated, not referenced from the payload, collides with an existing claim, or is in the wrong position."""
    by_digest: Dict[str, dict] = {}
    for raw in disclosures:
        d = _decode_disclosure(raw)
        digest = sd_digest(raw, alg)
        if digest in by_digest:
            raise Ap2Error("SD-JWT: duplicate disclosure")
        by_digest[digest] = d
    used: set = set()

    def take(digest: Any, want: str) -> Optional[dict]:
        d = by_digest.get(digest) if isinstance(digest, str) else None
        if d is None:
            return None  # decoy digest, or a disclosure the holder chose not to reveal
        if digest in used:
            raise Ap2Error("SD-JWT: a digest is referenced more than once")
        if d["kind"] != want:
            raise Ap2Error("SD-JWT: a %s disclosure is referenced from a %s position" % (d["kind"], want))
        used.add(digest)
        return d

    def walk(node: Any, depth: int) -> Any:
        if depth > 32:
            raise Ap2Error("SD-JWT: nesting too deep")
        if isinstance(node, list):
            out: list = []
            for el in node:
                if isinstance(el, dict) and "..." in el:
                    if len(el) != 1 or not isinstance(el["..."], str):
                        raise Ap2Error("SD-JWT: malformed array digest placeholder")
                    d = take(el["..."], "element")
                    if d is not None:
                        out.append(walk(d["value"], depth + 1))
                else:
                    out.append(walk(el, depth + 1))
            return out
        if isinstance(node, dict):
            res: dict = {}
            for k, v in node.items():
                if k == "_sd" or k == "_sd_alg":
                    continue
                if k == "...":
                    raise Ap2Error('SD-JWT: "..." is only valid as the sole key of an array element')
                res[k] = walk(v, depth + 1)
            if "_sd" in node:
                sd = node["_sd"]
                if not isinstance(sd, list) or any(not isinstance(x, str) for x in sd):
                    raise Ap2Error("SD-JWT: _sd must be an array of strings")
                for digest in sd:
                    d = take(digest, "property")
                    if d is None or d["kind"] != "property":
                        continue
                    if d["name"] in res:
                        raise Ap2Error("SD-JWT: disclosed claim %s collides with an existing claim" % d["name"])
                    res[d["name"]] = walk(d["value"], depth + 1)
            return res
        return node

    result = walk(payload, 0)
    if len(used) != len(by_digest):
        raise Ap2Error("SD-JWT: a disclosure is not referenced by the signed payload")
    return result


# ---- issuing -----------------------------------------------------------------------------------------------------------------

def new_salt() -> str:
    return b64u(secrets.token_bytes(16))


class _DisclosureBuilder:
    def __init__(self, alg: str, salt: Callable[[], str]):
        self._alg = alg
        self._salt = salt
        self.disclosures: List[str] = []

    def element(self, value: Any) -> dict:
        """Array-element disclosure for `value`; returns the `{"...": digest}` placeholder."""
        raw = b64u_encode(_stringify([self._salt(), value]))
        self.disclosures.append(raw)
        return {"...": sd_digest(raw, self._alg)}

    def property(self, name: str, value: Any) -> str:
        """Property disclosure; returns the digest to put into the parent's `_sd`."""
        raw = b64u_encode(_stringify([self._salt(), name, value]))
        self.disclosures.append(raw)
        return sd_digest(raw, self._alg)


def disclosure_builder(alg: Optional[str] = None, salt: Optional[Callable[[], str]] = None) -> _DisclosureBuilder:
    return _DisclosureBuilder("sha-256" if alg is None else alg, new_salt if salt is None else salt)


def sign_sd_jwt(args: dict) -> str:
    """Sign `payload` as an ES256 JWT and append `disclosures`: `<jwt>~<d1>~...~<dn>~`. `args`: header, payload, disclosures, privateKey."""
    header = b64u_encode(_stringify(dict({"alg": "ES256"}, **_spread(args["header"]))))
    payload = b64u_encode(_stringify(args["payload"]))
    jwt = "%s.%s.%s" % (header, payload, _es256_sign(args["privateKey"], "%s.%s" % (header, payload)))
    return "%s~%s" % (jwt, "".join("%s~" % d for d in args["disclosures"]))


def sign_jwt_es256(args: dict) -> str:
    """Sign an arbitrary compact JWT (used for merchant-signed `checkout_jwt`). `args`: header, payload, privateKey."""
    header = b64u_encode(_stringify(dict({"alg": "ES256", "typ": "JWT"}, **_spread(args["header"]))))
    payload = b64u_encode(_stringify(args["payload"]))
    return "%s.%s.%s" % (header, payload, _es256_sign(args["privateKey"], "%s.%s" % (header, payload)))


# ---- currencies and minor units ----------------------------------------------------------------------------------------------

_ZERO_DECIMAL = frozenset(("BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "UYI", "VND", "VUV", "XAF", "XOF", "XPF"))
_THREE_DECIMAL = frozenset(("BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"))
_FOUR_DECIMAL = frozenset(("CLF", "UYW"))


def currency_exponent(currency: Any) -> int:
    """ISO 4217 minor-unit exponent for `currency` (2 for any code not in the 0/3/4-digit tables)."""
    text = currency if isinstance(currency, str) else _str(currency)  # RegExp#test coerces its argument
    if re.fullmatch(r"[A-Z]{3}", text) is None:
        raise Ap2Error("currency must be an ISO 4217 alpha-3 code, got %s" % ("undefined" if currency is _U else js_json(currency)))
    if isinstance(currency, str):
        if currency in _ZERO_DECIMAL:
            return 0
        if currency in _THREE_DECIMAL:
            return 3
        if currency in _FOUR_DECIMAL:
            return 4
    return 2


def to_minor_units(major: Any, currency: str) -> int:
    """A major-unit amount (`120.5` USD) to integer minor units (`12050`). Float drift (`0.1 + 0.2`) is refused rather than rounded away."""
    e = currency_exponent(currency)
    if not _num(major) or not fin(major) or major < 0:
        raise Ap2Error("amount must be a finite non-negative number, got %s" % _str(major))
    m = float(major)
    fixed = "%.*f" % (e, abs(m))
    if float(fixed) != m:
        raise Ap2Error("amount %s is not exactly representable in %s minor units" % (_str(major), currency))
    minor = int(fixed.replace(".", ""))
    if minor > _MAX_SAFE:
        raise Ap2Error("amount %s is outside the safe integer range in minor units" % _str(major))
    return minor


def from_minor_units(minor: Any, currency: str) -> Any:
    """Integer minor units to the major-unit number PCA budgets use (exact for any safe integer)."""
    e = currency_exponent(currency)
    if not _safe_int(minor) or minor < 0 or _neg0(minor):
        raise Ap2Error("minor-unit amount must be a non-negative safe integer, got %s" % _str(minor))
    return minor / (10 ** e)


# ---- mandate validators: each returns the list of problems (empty = valid) --------------------------------------------------

def _merchant_problems(v: Any, at: str) -> List[str]:
    if not isinstance(v, dict):
        return ["%s: not an object" % at]
    p: List[str] = []
    if not _is_nonempty_str(v.get("id")):
        p.append("%s.id: required string" % at)
    if not _is_nonempty_str(v.get("name")):
        p.append("%s.name: required string" % at)
    if v.get("website", _U) is not _U and not _is_str(v["website"]):
        p.append("%s.website: must be a string" % at)
    return p


def _currency_ok(v: Any) -> bool:
    return isinstance(v, str) and re.fullmatch(r"[A-Z]{3}", v) is not None


def _amount_problems(v: Any, at: str) -> List[str]:
    if not isinstance(v, dict):
        return ["%s: not an object" % at]
    p: List[str] = []
    if not _is_nonneg_int(v.get("amount", _U)):
        p.append("%s.amount: must be a non-negative integer (minor units)" % at)
    if not _currency_ok(v.get("currency", _U)):
        p.append("%s.currency: must be an ISO 4217 alpha-3 code" % at)
    return p


def _instrument_problems(v: Any, at: str) -> List[str]:
    if not isinstance(v, dict):
        return ["%s: not an object" % at]
    p: List[str] = []
    if not _is_nonempty_str(v.get("id")):
        p.append("%s.id: required string" % at)
    if not _is_nonempty_str(v.get("type")):
        p.append("%s.type: required string" % at)
    if v.get("description", _U) is not _U and not _is_str(v["description"]):
        p.append("%s.description: must be a string" % at)
    return p


def _pisp_problems(v: Any, at: str) -> List[str]:
    if not isinstance(v, dict):
        return ["%s: not an object" % at]
    return ["%s.%s: required string" % (at, k) for k in ("legal_name", "brand_name", "domain_name") if not _is_nonempty_str(v.get(k))]


def _time_problems(v: dict) -> List[str]:
    return ["%s: must be an integer epoch-seconds" % k for k in ("iat", "exp") if v.get(k, _U) is not _U and not _is_nonneg_int(v[k])]


def _cnf_problems(v: Any) -> List[str]:
    if not isinstance(v, dict) or not isinstance(v.get("jwk"), dict):
        return ["cnf: must be { jwk }"]
    try:
        assert_p256_jwk(v["jwk"], "cnf.jwk")
        return []
    except Ap2Error as e:
        return [str(e)]


def _pca_claim_problems(v: dict) -> List[str]:
    return ["%s: must be an object" % PCA_CLAIM] if v.get(PCA_CLAIM, _U) is not _U and not isinstance(v[PCA_CLAIM], dict) else []


def _list_problems(v: Any, at: str, each: Callable[[Any, str], List[str]]) -> List[str]:
    if not isinstance(v, list):
        return ["%s: must be an array" % at]
    out: List[str] = []
    for i, x in enumerate(v):
        out.extend(each(x, "%s[%d]" % (at, i)))
    return out


def _payment_constraint_problems(c: Any, at: str) -> List[str]:
    if not isinstance(c, dict) or not _is_str(c.get("type")):
        return ["%s: constraint must be an object with a string type" % at]
    t = c["type"]
    if t == "payment.agent_recurrence":
        p: List[str] = []
        if not _is_str(c.get("frequency")) or c["frequency"] not in FREQUENCIES:
            p.append("%s.frequency: not a known frequency" % at)
        if c.get("max_occurrences", _U) is not _U and not (_is_int(c["max_occurrences"]) and c["max_occurrences"] > 0):
            p.append("%s.max_occurrences: must be a positive integer" % at)
        return p
    if t == "payment.allowed_payees":
        return _list_problems(c.get("allowed"), "%s.allowed" % at, _merchant_problems)
    if t == "payment.allowed_payment_instruments":
        return _list_problems(c.get("allowed"), "%s.allowed" % at, _instrument_problems)
    if t == "payment.allowed_pisps":
        return _list_problems(c.get("allowed"), "%s.allowed" % at, _pisp_problems)
    if t == "payment.amount_range":
        p = []
        if not _currency_ok(c.get("currency")):
            p.append("%s.currency: must be an ISO 4217 alpha-3 code" % at)
        if not _is_nonneg_int(c.get("max", _U)):
            p.append("%s.max: must be a non-negative integer (minor units)" % at)
        if c.get("min", _U) is not _U and not _is_nonneg_int(c["min"]):
            p.append("%s.min: must be a non-negative integer (minor units)" % at)
        if _is_int(c.get("max", _U)) and _is_int(c.get("min", _U)) and c["min"] > c["max"]:
            p.append("%s: min exceeds max" % at)
        return p
    if t == "payment.budget":
        p = []
        if not _currency_ok(c.get("currency")):
            p.append("%s.currency: must be an ISO 4217 alpha-3 code" % at)
        mx = c.get("max", _U)
        if not _num(mx) or not fin(mx) or mx < 0:
            p.append("%s.max: must be a non-negative number (major units)" % at)
        return p
    if t == "payment.execution_date":
        return ["%s.%s: must be a string" % (at, k) for k in ("not_before", "not_after") if c.get(k, _U) is not _U and not _is_str(c[k])]
    if t == "payment.reference":
        return [] if _is_nonempty_str(c.get("conditional_transaction_id")) else ["%s.conditional_transaction_id: required string" % at]
    return ["%s: unknown constraint type %s" % (at, t)]


def _acceptable_item_problems(x: Any, ax: str) -> List[str]:
    if not isinstance(x, dict):
        return ["%s: not an object" % ax]
    return ["%s.%s: required string" % (ax, k) for k in ("id", "title") if not _is_nonempty_str(x.get(k))]


def _checkout_constraint_problems(c: Any, at: str) -> List[str]:
    if not isinstance(c, dict) or not _is_str(c.get("type")):
        return ["%s: constraint must be an object with a string type" % at]
    if c["type"] == "checkout.allowed_merchants":
        return _list_problems(c.get("allowed"), "%s.allowed" % at, _merchant_problems)
    if c["type"] == "checkout.line_items":
        items = c.get("items")
        if not isinstance(items, list) or len(items) == 0:
            return ["%s.items: must be a non-empty array" % at]
        out: List[str] = []
        for i, it in enumerate(items):
            a = "%s.items[%d]" % (at, i)
            if not isinstance(it, dict):
                out.append("%s: not an object" % a)
                continue
            if not _is_nonempty_str(it.get("id")):
                out.append("%s.id: required string" % a)
            if not _is_int(it.get("quantity", _U)) or it["quantity"] <= 0:
                out.append("%s.quantity: must be a positive integer" % a)
            out.extend(_list_problems(it.get("acceptable_items"), "%s.acceptable_items" % a, _acceptable_item_problems))
        return out
    return ["%s: unknown constraint type %s" % (at, c["type"])]


def _vct_problem(v: dict, want: str) -> List[str]:
    return [] if _seq(v.get("vct", _U), want) else ["vct: must be %s" % want]


def _has_type(constraints: Any, t: str) -> bool:
    return isinstance(constraints, list) and any(isinstance(c, dict) and _seq(c.get("type", _U), t) for c in constraints)


def open_payment_mandate_problems(v: Any) -> List[str]:
    if not isinstance(v, dict):
        return ["mandate: not an object"]
    p = _vct_problem(v, VCT_PAYMENT_OPEN) + _time_problems(v) + _cnf_problems(v.get("cnf")) + _pca_claim_problems(v)
    p.extend(_list_problems(v.get("constraints"), "constraints", _payment_constraint_problems))
    if isinstance(v.get("constraints"), list) and not _has_type(v["constraints"], "payment.reference"):
        p.append("constraints: must contain a payment.reference constraint")
    if v.get("payee", _U) is not _U:
        p.extend(_merchant_problems(v["payee"], "payee"))
    if v.get("payment_amount", _U) is not _U:
        p.extend(_amount_problems(v["payment_amount"], "payment_amount"))
    if v.get("payment_instrument", _U) is not _U:
        p.extend(_instrument_problems(v["payment_instrument"], "payment_instrument"))
    if v.get("pisp", _U) is not _U:
        p.extend(_pisp_problems(v["pisp"], "pisp"))
    if v.get("execution_date", _U) is not _U and not _is_str(v["execution_date"]):
        p.append("execution_date: must be a string")
    if v.get("risk_data", _U) is not _U and not isinstance(v["risk_data"], dict):
        p.append("risk_data: must be an object")
    return p


def payment_mandate_problems(v: Any) -> List[str]:
    if not isinstance(v, dict):
        return ["mandate: not an object"]
    p = _vct_problem(v, VCT_PAYMENT) + _time_problems(v) + _pca_claim_problems(v)
    if not _is_nonempty_str(v.get("transaction_id")):
        p.append("transaction_id: required string")
    p.extend(_merchant_problems(v.get("payee"), "payee"))
    p.extend(_amount_problems(v.get("payment_amount"), "payment_amount"))
    p.extend(_instrument_problems(v.get("payment_instrument"), "payment_instrument"))
    if v.get("pisp", _U) is not _U:
        p.extend(_pisp_problems(v["pisp"], "pisp"))
    if v.get("execution_date", _U) is not _U and not _is_str(v["execution_date"]):
        p.append("execution_date: must be a string")
    if v.get("risk_data", _U) is not _U and not isinstance(v["risk_data"], dict):
        p.append("risk_data: must be an object")
    return p


def open_checkout_mandate_problems(v: Any) -> List[str]:
    if not isinstance(v, dict):
        return ["mandate: not an object"]
    p = _vct_problem(v, VCT_CHECKOUT_OPEN) + _time_problems(v) + _cnf_problems(v.get("cnf")) + _pca_claim_problems(v)
    p.extend(_list_problems(v.get("constraints"), "constraints", _checkout_constraint_problems))
    if isinstance(v.get("constraints"), list) and not _has_type(v["constraints"], "checkout.line_items"):
        p.append("constraints: must contain a checkout.line_items constraint")
    return p


def checkout_mandate_problems(v: Any) -> List[str]:
    if not isinstance(v, dict):
        return ["mandate: not an object"]
    p = _vct_problem(v, VCT_CHECKOUT) + _time_problems(v) + _pca_claim_problems(v)
    if not _is_nonempty_str(v.get("checkout_jwt")):
        p.append("checkout_jwt: required string")
    if not _is_nonempty_str(v.get("checkout_hash")):
        p.append("checkout_hash: required string")
    return p


def assert_valid(v: Any, problems: Callable[[Any], List[str]], what: str) -> Any:
    p = problems(v)
    if p:
        raise Ap2Error("%s: %s" % (what, "; ".join(p)))
    return v


# ---- constraint evaluation ---------------------------------------------------------------------------------------------------

def merchant_matches(candidate: Any, target: Any) -> bool:
    cid, tid = _g(candidate, "id"), _g(target, "id")
    if _truthy(cid) and _truthy(tid):
        return _seq(cid, tid)
    return (_truthy(_g(candidate, "name")) and _truthy(_g(candidate, "website"))
            and _seq(_g(candidate, "name"), _g(target, "name")) and _seq(_g(candidate, "website"), _g(target, "website")))


def _sort_keys(v: Any) -> Any:
    if isinstance(v, list):
        return [_sort_keys(x) for x in v]
    if isinstance(v, dict):
        return {k: _sort_keys(v[k]) for k in sorted(v, key=lambda s: s.encode("utf-16-be", "surrogatepass"))}
    return v


def _same_json(a: Any, b: Any) -> bool:
    """JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b)); two undefined values are equal."""
    sa = None if a is _U else js_json(_sort_keys(a))
    sb = None if b is _U else js_json(_sort_keys(b))
    return sa == sb


_RFC3339 = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})(?:T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|([+-])([0-9]{2}):([0-9]{2})))?")


def _days_from_civil(y: int, m: int, d: int) -> int:
    y -= m <= 2
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _civil_from_days(z: int) -> Tuple[int, int, int]:
    z += 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + (3 if mp < 10 else -9)
    return y + (m <= 2), m, d


def _days_in_month(y: int, m: int) -> int:
    if m == 2:
        return 29 if (y % 4 == 0 and y % 100 != 0) or y % 400 == 0 else 28
    return 30 if m in (4, 6, 9, 11) else 31


def _parse_instant(s: Any) -> Optional[int]:
    """Epoch ms of an RFC 3339 instant, or None. STRICT and independent of the host time zone: `YYYY-MM-DD` (UTC midnight) or
    `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)`, with every component in range."""
    if not isinstance(s, str):
        return None
    m = _RFC3339.fullmatch(s)
    if m is None:
        return None
    y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if not (1 <= mo <= 12 and 1 <= d <= _days_in_month(y, mo)):
        return None
    day = _days_from_civil(y, mo, d) * 86400000
    if m.group(4) is None:
        return day
    h, mi, se = int(m.group(4)), int(m.group(5)), int(m.group(6))
    if h > 23 or mi > 59 or se > 59:
        return None
    ms = 0 if m.group(7) is None else int(m.group(7)[:3].ljust(3, "0"))
    offset = 0
    if m.group(8) != "Z":
        oh, om = int(m.group(10)), int(m.group(11))
        if oh > 23 or om > 59:
            return None
        offset = (1 if m.group(9) == "+" else -1) * (oh * 60 + om) * 60000
    return day + ((h * 60 + mi) * 60 + se) * 1000 + ms - offset


def _date_utc(y: int, month0: int, d: int) -> int:
    """Date.UTC: the years 0..99 mean 1900..1999."""
    if 0 <= y <= 99:
        y += 1900
    y += month0 // 12
    return _days_from_civil(y, month0 % 12 + 1, d) * 86400000


def _period_start(ms: Any, frequency: Any) -> Optional[Any]:
    """Start (epoch ms, UTC) of the calendar period of `frequency` that contains `ms`; None for an unknown frequency."""
    t = int(ms)  # TimeClip truncates
    days = t // 86400000
    y, mo, d = _civil_from_days(days)
    day = _date_utc(y, mo - 1, d)
    DAY = 86400000
    wd = (days + 4) % 7  # getUTCDay, 0 = Sunday
    if frequency == "ON_DEMAND":
        return 0
    if frequency == "DAILY":
        return day
    if frequency == "WEEKLY":
        return day - ((wd + 6) % 7) * DAY
    if frequency == "BIWEEKLY":
        week_start = day - ((wd + 6) % 7) * DAY
        week = 7 * DAY
        epoch_monday = -3 * DAY
        return epoch_monday + ((week_start - epoch_monday) // (2 * week)) * 2 * week
    if frequency == "MONTHLY":
        return _date_utc(y, mo - 1, 1)
    if frequency == "QUARTERLY":
        return _date_utc(y, ((mo - 1) // 3) * 3, 1)
    if frequency == "ANNUALLY":
        return _date_utc(y, 0, 1)
    return None


def _to_number(x: Any) -> float:
    """ToNumber for the relational comparisons below (anything not a plain scalar is NaN)."""
    if x is None or x is False:
        return 0.0
    if x is True:
        return 1.0
    if _num(x):
        return _f(x)
    if isinstance(x, str):
        t = x.strip("\t\n\x0b\x0c\r                  　﻿")
        if t == "":
            return 0.0
        try:
            return float(t) if re.fullmatch(r"[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?", t) or t in ("Infinity", "+Infinity", "-Infinity") else float("nan")
        except ValueError:
            return float("nan")
    return float("nan")


def _cmp(a: Any, b: Any, op: Callable[[Any, Any], bool]) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return op(a.encode("utf-16-be", "surrogatepass"), b.encode("utf-16-be", "surrogatepass"))
    x, y = _to_number(a), _to_number(b)
    return False if x != x or y != y else op(x, y)


def _f(x: Any) -> float:
    """float(x) with an int beyond the double range read as the infinity the reference reads (never an OverflowError)."""
    try:
        return float(x)
    except OverflowError:
        return math.inf if x > 0 else -math.inf


def _lt(a: Any, b: Any) -> bool:
    return _cmp(a, b, lambda p, q: p < q)


def _gt(a: Any, b: Any) -> bool:
    return _cmp(a, b, lambda p, q: p > q)


def _ge(a: Any, b: Any) -> bool:
    return _cmp(a, b, lambda p, q: p >= q)


def _le(a: Any, b: Any) -> bool:
    return _cmp(a, b, lambda p, q: p <= q)


def _context_problem(c: Any) -> Optional[str]:
    """A usage context with a NaN, negative or fractional counter would make the cap comparisons fail open: refuse it."""
    def ok(n: Any) -> bool:
        return _is_nonneg_int(n)
    last = _g(c, "lastUsedDate")
    if not ok(_g(c, "totalAmount")) or not ok(_g(c, "totalUses")) or (last is not _U and not ok(last)):
        return "mandate context must carry non-negative integer totalAmount, totalUses and lastUsedDate"
    return None


def _iter_list(x: Any) -> list:
    if not isinstance(x, list):
        raise TypeError("x is not iterable")
    return x


def _evaluate_payment(c: Any, closed: Any, o: dict) -> List[str]:
    amt = _g(closed, "payment_amount")
    t = _g(c, "type")
    ctx = o.get("context")
    if t == "payment.amount_range":
        v: List[str] = []
        if not _seq(_g(amt, "currency"), _g(c, "currency")):
            v.append("currency mismatch: expected %s, got %s" % (_str(_g(c, "currency")), _str(_g(amt, "currency"))))
        mn = _g(c, "min")
        if not _finite(_g(amt, "amount")):
            v.append("amount %s is not finite" % _str(_g(amt, "amount")))
        if mn is not _U and not _ge(_g(amt, "amount"), mn):
            v.append("amount %s below minimum %s" % (_str(_g(amt, "amount")), _str(mn)))
        if not _le(_g(amt, "amount"), _g(c, "max")):
            v.append("amount %s exceeds maximum %s" % (_str(_g(amt, "amount")), _str(_g(c, "max"))))
        return v
    if t == "payment.allowed_payees":
        return [] if any(merchant_matches(m, _g(closed, "payee")) for m in _iter_list(_g(c, "allowed"))) else \
            ["payee %s is not in the allowed list" % _str(_g(_g(closed, "payee"), "name"))]
    if t == "payment.allowed_payment_instruments":
        inst = _g(_g(closed, "payment_instrument"), "id")
        return [] if any(_seq(_g(i, "id"), inst) for i in _iter_list(_g(c, "allowed"))) else \
            ["payment instrument %s is not in the allowed list" % _str(inst)]
    if t == "payment.allowed_pisps":
        p = _g(closed, "pisp")
        if not _truthy(p):
            return ["missing PISP in the closed mandate"]
        return [] if any(_seq(_g(a, "legal_name"), _g(p, "legal_name")) and _seq(_g(a, "brand_name"), _g(p, "brand_name"))
                         and _seq(_g(a, "domain_name"), _g(p, "domain_name")) for a in _iter_list(_g(c, "allowed"))) else ["PISP is not in the allowed list"]
    if t == "payment.reference":
        h = o.get("openCheckoutHash")
        if not _truthy(h):
            return ["openCheckoutHash is required to evaluate a payment.reference constraint"]
        return [] if _seq(h, _g(c, "conditional_transaction_id")) else ["payment.reference does not match the open checkout mandate hash"]
    if t == "payment.budget":
        if not _seq(_g(amt, "currency"), _g(c, "currency")):
            return ["budget currency mismatch: expected %s, got %s" % (_str(_g(c, "currency")), _str(_g(amt, "currency")))]
        # the official SDK converts the budget with `int(max * 100)` for every currency; this reads it the same way
        if not _truthy(ctx):
            return ["mandate context is required to evaluate a budget"]
        bad = _context_problem(ctx)
        if bad:
            return [bad]
        scaled = _f(_to_number(_g(c, "max"))) * 100
        if not fin(scaled):
            return []  # NaN / Infinity compare false against everything, so the reference reports nothing here
        max_minor = _js_round(scaled)
        if abs(scaled - max_minor) > 1e-6:
            return ["budget.max is not a whole number of minor units"]
        spend = _f(ctx["totalAmount"]) + _f(_to_number(_g(amt, "amount")))
        if not (fin(spend) and spend <= max_minor):
            return ["cumulative spend %s exceeds budget %s (past spend %s)" % (js_to_string(spend), js_to_string(max_minor), _str(ctx["totalAmount"]))]
        return []
    if t == "payment.agent_recurrence":
        v = []
        freq = _g(c, "frequency")
        if not (_is_str(freq) and freq in FREQUENCIES):  # strict: an unknown frequency is a violation with or without a last-used date
            return ["unknown recurrence frequency"]
        if _truthy(ctx):
            bad = _context_problem(ctx)
            if bad:
                return [bad]
        mo = _g(c, "max_occurrences")
        if mo is not _U:
            if not _truthy(ctx):
                return ["mandate context is required to evaluate recurrence limits"]
            if not _lt(ctx["totalUses"], mo):
                v.append("maximum occurrences exceeded: %s >= %s" % (_str(ctx["totalUses"]), _str(mo)))
        if not _seq(_g(c, "frequency"), "ON_DEMAND"):
            if not _truthy(ctx):
                return ["mandate context is required to evaluate recurrence frequency"]
            last = ctx.get("lastUsedDate", _U)
            if last is not _U:
                try:
                    start = _period_start(_f(o["now"]) * 1000, _g(c, "frequency"))
                    used = start is not None and not (fin(start) and _lt(_f(last) * 1000, start))
                except (OverflowError, ValueError):  # a clock or last-used time beyond the double range is no usable time
                    used = True
                if used:
                    v.append("already used in the current %s period" % _str(_g(c, "frequency")))
        return v
    if t == "payment.execution_date":
        ed = _g(closed, "execution_date")
        at = _parse_instant(ed) if ed is not _U else _f(o["now"]) * 1000
        if at is None or not fin(at):
            return ["execution_date %s is not a valid instant" % _str(ed)]
        v = []
        for key, bound, before in (("not_before", _g(c, "not_before"), True), ("not_after", _g(c, "not_after"), False)):
            if bound is _U:
                continue
            b = _parse_instant(bound)
            if b is None:
                v.append("%s %s is not a valid instant" % (key, _str(bound)))
            elif (not (at >= b)) if before else (not (at <= b)):
                v.append("execution date is %s the allowed window (%s %s)" % ("before" if before else "after", key, _str(bound)))
        return v
    return ["unknown constraint type %s" % _str(t)]


def check_payment_constraints(open: dict, closed: dict, o: dict) -> List[str]:  # noqa: A002 - the reference's name
    """Violations of the open payment mandate's constraints and pre-set claims by `closed` (empty = satisfied).
    `o` = {"openCheckoutHash"?, "context"? ({"totalAmount", "totalUses", "lastUsedDate"?}), "now"}."""
    v: List[str] = []
    if _g(open, "payee") is not _U and not merchant_matches(open["payee"], _g(closed, "payee")):
        v.append("pre-set payee mismatch: expected %s, got %s" % (_str(_g(open["payee"], "name")), _str(_g(_g(closed, "payee"), "name"))))
    if _g(open, "payment_amount") is not _U and not _same_json(open["payment_amount"], _g(closed, "payment_amount")):
        v.append("pre-set payment_amount mismatch")
    if _g(open, "payment_instrument") is not _U and not _same_json(open["payment_instrument"], _g(closed, "payment_instrument")):
        v.append("pre-set payment_instrument mismatch")
    if _g(open, "pisp") is not _U and not _same_json(open["pisp"], _g(closed, "pisp")):
        v.append("pre-set pisp mismatch")
    if _g(open, "execution_date") is not _U and not _seq(open["execution_date"], _g(closed, "execution_date")):
        v.append("pre-set execution_date mismatch")
    constraints = _iter_list(_g(open, "constraints"))
    types = [_g(c, "type") for c in constraints]
    if "payment.agent_recurrence" in types:
        if "payment.amount_range" not in types:
            v.append("payment.agent_recurrence requires a payment.amount_range constraint")
        if "payment.budget" not in types:
            v.append("payment.agent_recurrence requires a payment.budget constraint")
    for c in constraints:
        v.extend(_evaluate_payment(c, closed, o))
    return v


def project_checkout(payload: dict) -> dict:
    """Validate and project the checkout payload (`checkout_jwt`); raises a descriptive message when malformed."""
    def bad(m: str) -> None:
        raise Ap2Error("checkout_jwt payload: %s" % m)
    pid, cur, lis, totals = _g(payload, "id"), _g(payload, "currency"), _g(payload, "line_items"), _g(payload, "totals")
    if not isinstance(pid, str) or not pid:
        bad("id is required")
    if not _currency_ok(cur):
        bad("currency must be ISO 4217")
    if not isinstance(lis, list) or len(lis) == 0:
        bad("line_items must be a non-empty array")
    if not isinstance(totals, list):
        bad("totals must be an array")
    line_items = []
    for i, li in enumerate(lis):
        if not isinstance(li, dict) or not isinstance(li.get("id"), str) or not isinstance(li.get("item"), dict):
            bad("line_items[%d] is malformed" % i)
        item = li["item"]
        price = item.get("price", _U)
        if not isinstance(item.get("id"), str) or not isinstance(item.get("title"), str) or not _safe_int(price) or price < 0 or _neg0(price):
            bad("line_items[%d].item needs id, title and integer minor-unit price" % i)
        qty = li.get("quantity", _U)
        if not _safe_int(qty) or qty < 1:
            bad("line_items[%d].quantity must be a positive integer" % i)
        line_items.append({"id": li["id"], "item": {"id": item["id"], "title": item["title"], "price": price}, "quantity": qty})
    tt = []
    for i, t in enumerate(totals):
        if not isinstance(t, dict) or not isinstance(t.get("type"), str) or not _safe_int(t.get("amount", _U)) or _neg0(t["amount"]):
            bad("totals[%d] is malformed" % i)
        tt.append({"type": t["type"], "amount": t["amount"]})
    merchant = None
    if payload.get("merchant", _U) is not _U:
        m = payload["merchant"]
        if not isinstance(m, dict) or not isinstance(m.get("id"), str) or not isinstance(m.get("name"), str):
            bad("merchant needs id and name")
        merchant = {"id": m["id"], "name": m["name"]}
        if isinstance(m.get("website"), str):
            merchant["website"] = m["website"]
    out = {"id": pid, "currency": cur, "line_items": line_items, "totals": tt}
    if merchant is not None:
        out["merchant"] = merchant
    return out


def checkout_total(c: dict) -> Optional[Any]:
    """The checkout's single `total` entry in minor units, or None if absent / ambiguous."""
    t = [x for x in c["totals"] if _seq(_g(x, "type"), "total")]
    return t[0]["amount"] if len(t) == 1 else None


def _line_item_violations(cart: list, reqs: list) -> List[str]:
    """Maximal-flow assignment of cart quantities to requirement slots (Edmonds-Karp): satisfied iff the flow equals both the
    required and the carted total."""
    qty: Dict[Any, Any] = {}
    for li in cart:
        k = li["item"]["id"]
        qty[k] = qty.get(k, 0) + li["quantity"]
    skus = list(qty.keys())
    S = 0
    T = 1 + len(skus) + len(reqs)
    cap: List[Dict[int, Any]] = [dict() for _ in range(T + 1)]

    def add(u: int, v: int, c: Any) -> None:
        cap[u][v] = cap[u].get(v, 0) + c
        cap[v][u] = cap[v].get(u, 0)
    INF = _MAX_SAFE
    for i, s in enumerate(skus):
        add(S, 1 + i, qty[s])
    for j, r in enumerate(reqs):
        add(1 + len(skus) + j, T, _g(r, "quantity"))
        ok = [_g(a, "id") for a in _iter_list(_g(r, "acceptable_items"))]
        for i, s in enumerate(skus):
            if any(_seq(s, x) for x in ok):
                add(1 + i, 1 + len(skus) + j, INF)
    flow: Any = 0
    while True:
        parent = {S: S}
        queue = [S]
        h = 0
        while h < len(queue) and T not in parent:
            u = queue[h]
            h += 1
            for v, c in list(cap[u].items()):
                if c > 0 and v not in parent:
                    parent[v] = u
                    queue.append(v)
        if T not in parent:
            break
        push: Any = INF
        v = T
        while v != S:
            push = min(push, cap[parent[v]][v])
            v = parent[v]
        v = T
        while v != S:
            u = parent[v]
            cap[u][v] = cap[u][v] - push
            cap[v][u] = cap[v][u] + push
            v = u
        flow += push
    required: Any = 0
    for r in reqs:
        required += _g(r, "quantity")
    carted: Any = 0
    for q in qty.values():
        carted += q
    if flow == required and flow == carted:
        return []
    return ["line items do not satisfy the constraint: assigned %s of %s required and %s carted units" % (js_to_string(flow), js_to_string(required), js_to_string(carted))]


def _evaluate_checkout(c: Any, checkout: dict) -> List[str]:
    t = _g(c, "type")
    if t == "checkout.allowed_merchants":
        m = checkout.get("merchant")
        if not _truthy(m):
            return ["missing merchant in the checkout"]
        return [] if any(merchant_matches(a, m) for a in _iter_list(_g(c, "allowed"))) else ["merchant %s is not in the allowed list" % _str(_g(m, "name"))]
    if t != "checkout.line_items":
        return ["unknown constraint type %s" % _str(t)]
    if len(checkout["line_items"]) == 0:
        return ["empty cart does not satisfy a line_items constraint"]
    return _line_item_violations(checkout["line_items"], _iter_list(_g(c, "items")))


def check_checkout_constraints(open: dict, checkout: dict) -> List[str]:  # noqa: A002
    """Violations of the open checkout mandate's constraints by `checkout` (empty = satisfied)."""
    out: List[str] = []
    for c in _iter_list(_g(open, "constraints")):
        out.extend(_evaluate_checkout(c, checkout))
    return out


# ---- issuing open mandates ---------------------------------------------------------------------------------------------------

def _sign_root(c: dict, mandate: dict, b: _DisclosureBuilder) -> str:
    element = b.element(mandate)
    issuer = c["issuer"]
    typ = c.get("typ")
    header: dict = {"typ": _ROOT_TYP if typ is None else typ}
    if issuer.get("kid", _U) is not _U:
        header["kid"] = issuer["kid"]
    if _truthy(issuer.get("x5c", _U)):
        header["x5c"] = issuer["x5c"]
    alg = c.get("sdAlg")
    return sign_sd_jwt({"header": header, "payload": {"delegate_payload": [element], "_sd_alg": "sha-256" if alg is None else alg},
                        "disclosures": b.disclosures, "privateKey": issuer["privateKey"]})


def _common_claims(c: dict) -> dict:
    jwk = assert_p256_jwk(c.get("agentJwk"), "agentJwk")
    iat, exp = c.get("iat", _U), c.get("exp", _U)
    if not _safe_int(iat) or not _safe_int(exp) or exp <= iat:
        raise Ap2Error("open mandate: need integer iat < exp (epoch seconds)")
    out = {"cnf": {"jwk": {"crv": "P-256", "kty": "EC", "x": jwk["x"], "y": jwk["y"]}}, "iat": iat, "exp": exp}
    if _truthy(c.get("pca", _U)):
        out[PCA_CLAIM] = c["pca"]
    return out


def _sd_payment_constraint(c: Any, b: _DisclosureBuilder) -> Any:
    t = _g(c, "type")
    if t == "payment.allowed_payees" or t == "payment.allowed_payment_instruments":
        return {"type": t, "allowed": [b.element(x) for x in _iter_list(_g(c, "allowed"))]}
    return c


def _sd_checkout_constraint(c: Any, b: _DisclosureBuilder) -> Any:
    t = _g(c, "type")
    if t == "checkout.allowed_merchants":
        return {"type": t, "allowed": [b.element(x) for x in _iter_list(_g(c, "allowed"))]}
    items = []
    for it in _iter_list(_g(c, "items")):
        items.append(_compact(id=_g(it, "id"), acceptable_items=[b.element(x) for x in _iter_list(_g(it, "acceptable_items"))], quantity=_g(it, "quantity")))
    return _compact(type=t, items=items)


def _assert_well_formed(wrapped: dict, problems: Callable[[Any], List[str]], what: str, plain_constraints: Any) -> None:
    plain = dict(wrapped, constraints=plain_constraints)
    p = problems(plain)
    if p:
        raise Ap2Error("%s: %s" % (what, "; ".join(p)))


def issue_open_payment_mandate(input: dict) -> str:  # noqa: A002
    """Issue an open Payment Mandate (`mandate.payment.open.1`) as a signed SD-JWT. `input`: issuer ({"privateKey", "kid"?, "x5c"?}),
    agentJwk, iat, exp, constraints, payee?, paymentAmount?, paymentInstrument?, pisp?, executionDate?, pca?, sdAlg?, salt?, typ?."""
    b = disclosure_builder(input.get("sdAlg"), input.get("salt"))
    mandate: dict = {"vct": VCT_PAYMENT_OPEN, "constraints": [_sd_payment_constraint(c, b) for c in _iter_list(input.get("constraints"))]}
    for member, key in (("payee", "payee"), ("payment_amount", "paymentAmount"), ("payment_instrument", "paymentInstrument"), ("pisp", "pisp")):
        if _truthy(input.get(key, _U)):
            mandate[member] = input[key]
    if input.get("executionDate", _U) is not _U:
        mandate["execution_date"] = input["executionDate"]
    mandate.update(_common_claims(input))
    _assert_well_formed(mandate, open_payment_mandate_problems, "open payment mandate", input["constraints"])
    return _sign_root(input, mandate, b)


def issue_open_checkout_mandate(input: dict) -> str:  # noqa: A002
    """Issue an open Checkout Mandate (`mandate.checkout.open.1`) as a signed SD-JWT (same `input` as the payment form, `constraints` are checkout constraints)."""
    b = disclosure_builder(input.get("sdAlg"), input.get("salt"))
    mandate: dict = {"vct": VCT_CHECKOUT_OPEN, "constraints": [_sd_checkout_constraint(c, b) for c in _iter_list(input.get("constraints"))]}
    mandate.update(_common_claims(input))
    _assert_well_formed(mandate, open_checkout_mandate_problems, "open checkout mandate", input["constraints"])
    return _sign_root(input, mandate, b)


# ---- presenting closed mandates (KB-SD-JWT hops) -----------------------------------------------------------------------------

def _present_hop(c: dict, build: Callable[[_DisclosureBuilder], dict]) -> str:
    if not _truthy(c.get("aud", _U)) or not _truthy(c.get("nonce", _U)):
        raise Ap2Error("closed mandate: aud and nonce are required")
    if not _safe_int(c.get("iat", _U)):
        raise Ap2Error("closed mandate: iat must be an integer")
    prev = parse_sd_jwt_hop(c.get("open"))
    b = disclosure_builder(prev["sdAlg"], c.get("salt"))
    mandate = build(b)
    element = b.element(mandate)
    mode = c.get("hashMode")
    mode = "sd_hash" if mode is None else mode
    payload = {"delegate_payload": [element], "iat": c["iat"], "aud": c["aud"], "nonce": c["nonce"]}
    payload[mode] = sd_hash_of(prev) if mode == "sd_hash" else issuer_jwt_hash_of(prev)
    payload["_sd_alg"] = prev["sdAlg"]
    hop = sign_sd_jwt({"header": {"typ": "kb+sd-jwt"}, "payload": payload, "disclosures": b.disclosures, "privateKey": c["agentKey"]["privateKey"]})
    return "%s~%s" % (c["open"], hop)  # hops are joined by "~~": the preceding token's own trailing "~" plus one separator "~"


def present_closed_payment(input: dict) -> str:  # noqa: A002
    """Present a closed Payment Mandate (`mandate.payment.1`) on top of an open payment mandate. `input`: open, agentKey ({"privateKey", "publicJwk"}),
    aud, nonce, iat, transactionId, payee, paymentAmount, paymentInstrument, pisp?, executionDate?, riskData?, exp?, pca?, hashMode?, salt?."""
    def build(_b: _DisclosureBuilder) -> dict:
        mandate: dict = {"vct": VCT_PAYMENT, "transaction_id": input.get("transactionId", _U), "payee": input.get("payee", _U),
                         "payment_amount": input.get("paymentAmount", _U), "payment_instrument": input.get("paymentInstrument", _U)}
        mandate = _compact(**mandate)
        if _truthy(input.get("pisp", _U)):
            mandate["pisp"] = input["pisp"]
        if input.get("executionDate", _U) is not _U:
            mandate["execution_date"] = input["executionDate"]
        if _truthy(input.get("riskData", _U)):
            mandate["risk_data"] = input["riskData"]
        if input.get("exp", _U) is not _U:
            mandate["exp"] = input["exp"]
        if _truthy(input.get("pca", _U)):
            mandate[PCA_CLAIM] = input["pca"]
        p = payment_mandate_problems(mandate)
        if p:
            raise Ap2Error("closed payment mandate: %s" % "; ".join(p))
        return mandate
    return _present_hop(input, build)


def present_closed_checkout(input: dict) -> str:  # noqa: A002
    """Present a closed Checkout Mandate (`mandate.checkout.1`) on top of an open checkout mandate (`input` as above with `checkoutJwt`)."""
    def build(b: _DisclosureBuilder) -> dict:
        prev_alg = parse_sd_jwt_hop(input["open"])["sdAlg"]
        jwt = input.get("checkoutJwt", _U)
        mandate: dict = {"_sd": [b.property("checkout_jwt", jwt)], "vct": VCT_CHECKOUT, "checkout_hash": sd_digest(jwt, prev_alg)}
        if input.get("exp", _U) is not _U:
            mandate["exp"] = input["exp"]
        if _truthy(input.get("pca", _U)):
            mandate[PCA_CLAIM] = input["pca"]
        p = checkout_mandate_problems(dict(mandate, checkout_jwt=jwt))
        if p:
            raise Ap2Error("closed checkout mandate: %s" % "; ".join(p))
        return mandate
    return _present_hop(input, build)


# ---- verifying a delegation chain --------------------------------------------------------------------------------------------

def split_chain(token: str) -> List[str]:
    """Split a `~~`-joined chain into hops, each restored to `<jwt>~<d>...~`."""
    if not isinstance(token, str) or len(token) == 0:
        raise Ap2Error("chain: empty")
    parts = token.split("~~")
    if len(parts) > _MAX_HOPS:
        raise Ap2Error("chain: more than %d hops" % _MAX_HOPS)
    return [p if i == len(parts) - 1 else "%s~" % p for i, p in enumerate(parts)]


def _check_times(label: str, o: dict, now: Any, skew: Any) -> None:
    exp, iat = o.get("exp", _U), o.get("iat", _U)
    if exp is not _U:
        if not _safe_int(exp) or _neg0(exp):
            raise Ap2Error("%s: exp must be an integer" % label)
        if not (_finite(now) and _finite(skew) and now <= exp + skew):
            raise Ap2Error("%s: expired at %s" % (label, _str(exp)))
    if iat is not _U:
        if not _safe_int(iat) or _neg0(iat):
            raise Ap2Error("%s: iat must be an integer" % label)
        if not (_finite(now) and _finite(skew) and iat <= now + skew):
            raise Ap2Error("%s: iat is in the future" % label)


def _delegate_mandate(claims: dict, label: str) -> dict:
    dp = claims.get("delegate_payload", _U)
    if not isinstance(dp, list):
        raise Ap2Error("%s: delegate_payload missing" % label)
    if len(dp) != 1 or not isinstance(dp[0], dict):
        raise Ap2Error("%s: delegate_payload must disclose exactly one mandate (got %d)" % (label, len(dp)))
    return dp[0]


def _cnf_jwk(mandate: dict, label: str) -> dict:
    cnf = mandate.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jwk"), dict):
        raise Ap2Error("%s: no cnf.jwk to delegate to" % label)
    return assert_p256_jwk(cnf["jwk"], "%s cnf.jwk" % label)


def verify_kb_hop(hop: dict, prev: dict, o: dict, label: str) -> dict:
    """Verify one key-binding hop against its predecessor (signature, typ, binding hash, times, aud/nonce). `prev` = {"hop", "mandate"};
    `o` = {"terminal", "expectedAudience"?, "expectedNonce"?, "now", "skew"}. Returns {"index": -1, "kind", "hop", "claims", "mandate"}."""
    typ = hop["header"].get("typ", _U)
    terminal = o["terminal"]
    allowed = TYP_TERMINAL if terminal else TYP_INTERMEDIATE
    if not isinstance(typ, str) or typ not in allowed:
        raise Ap2Error("%s: typ must be one of %s" % (label, ", ".join(allowed)))
    if hop["header"].get("crit", _U) is not _U:
        raise Ap2Error("%s: crit headers are not supported" % label)
    key = _cnf_jwk(prev["mandate"], "preceding mandate")
    if not verify_hop_signature(hop, key):
        raise Ap2Error("%s: signature does not verify under the preceding mandate's cnf.jwk" % label)
    claims = process_disclosures(hop["payload"], hop["disclosures"], hop["sdAlg"])
    has_sd = "sd_hash" in claims
    has_iss = "issuer_jwt_hash" in claims
    if has_sd == has_iss:
        raise Ap2Error("%s: exactly one of sd_hash / issuer_jwt_hash is required" % label)
    expected = sd_hash_of(prev["hop"]) if has_sd else issuer_jwt_hash_of(prev["hop"])
    actual = claims["sd_hash"] if has_sd else claims["issuer_jwt_hash"]
    if not _seq(actual, expected):
        raise Ap2Error("%s: %s does not match the preceding hop" % (label, "sd_hash" if has_sd else "issuer_jwt_hash"))
    if "iat" not in claims:
        raise Ap2Error("%s: iat is required" % label)
    _check_times(label, claims, o["now"], o["skew"])
    mandate = _delegate_mandate(claims, label)
    _check_times("%s mandate" % label, mandate, o["now"], o["skew"])
    has_cnf = isinstance(mandate.get("cnf"), dict)
    if terminal and has_cnf:
        raise Ap2Error("%s: a terminal hop must not carry cnf" % label)
    if not terminal and not has_cnf:
        raise Ap2Error("%s: an intermediate hop requires cnf" % label)
    if terminal:
        aud = o.get("expectedAudience", _U)
        if aud is _U or not _seq(claims.get("aud", _U), aud):
            raise Ap2Error("%s: aud mismatch" % label)
        nonce = o.get("expectedNonce", _U)
        if nonce is _U or not _seq(claims.get("nonce", _U), nonce):
            raise Ap2Error("%s: nonce mismatch" % label)
    return {"index": -1, "kind": "terminal" if terminal else "intermediate", "hop": hop, "claims": claims, "mandate": mandate}


def _reason(e: Exception) -> str:
    return str(e)


def verify_delegation_chain(token: str, o: dict) -> dict:
    """Verify a whole chain: root signature, then every hop in order. Never raises; reports the reason. `o`: resolveIssuerKey(header) -> public JWK or
    None, expectedAudience and expectedNonce (both required), now?, clockSkewSeconds? (default 60). Returns {"ok": True, "hops"} or {"ok": False, "reason"}."""
    try:
        if not _truthy(o.get("expectedAudience", _U)) or not _truthy(o.get("expectedNonce", _U)):
            raise Ap2Error("verify: expectedAudience and expectedNonce are required")
        now = o.get("now")
        now = int(math.floor(time.time())) if now is None else now
        skew = o.get("clockSkewSeconds")
        skew = 60 if skew is None else skew
        segments = [parse_sd_jwt_hop(s) for s in split_chain(token)]
        root = segments[0]
        if root["header"].get("crit", _U) is not _U:
            raise Ap2Error("root: crit headers are not supported")
        issuer_key = o["resolveIssuerKey"](root["header"])
        if not _truthy(issuer_key):
            raise Ap2Error("root: no issuer key for this header")
        if not verify_hop_signature(root, issuer_key):
            raise Ap2Error("root: signature does not verify under the issuer key")
        root_claims = process_disclosures(root["payload"], root["disclosures"], root["sdAlg"])
        _check_times("root", root_claims, now, skew)
        root_mandate = _delegate_mandate(root_claims, "root")
        _check_times("root mandate", root_mandate, now, skew)
        hops = [{"index": 0, "kind": "root", "hop": root, "claims": root_claims, "mandate": root_mandate}]
        for i in range(1, len(segments)):
            v = verify_kb_hop(segments[i], hops[i - 1], {"terminal": i == len(segments) - 1, "expectedAudience": o["expectedAudience"],
                                                         "expectedNonce": o["expectedNonce"], "now": now, "skew": skew}, "hop %d" % i)
            hops.append(dict(v, index=i))
        return {"ok": True, "hops": hops}
    except Exception as e:  # noqa: BLE001 - never raises
        return {"ok": False, "reason": _reason(e)}


def _pair(r: dict) -> Tuple[dict, dict]:
    if len(r["hops"]) != 2:
        raise Ap2Error("expected an open mandate followed by one closed mandate, got %d hop(s)" % len(r["hops"]))
    return r["hops"][0], r["hops"][1]


def _require_open_expiry(m: dict, label: str) -> None:
    if not _safe_int(m.get("exp", _U)):
        raise Ap2Error("%s: an open mandate must carry exp" % label)


def verify_checkout_chain(token: str, o: dict) -> dict:
    """Verify an open+closed checkout chain, the merchant-signed checkout, its hash, and the open constraints. `o` is the chain options plus
    resolveMerchantKey(header). Returns {"ok": True, open, closed, checkoutJwt, checkout, openHash, hops} or {"ok": False, reason, violations?}."""
    r = verify_delegation_chain(token, o)
    if not r["ok"]:
        return r
    try:
        open_hop, closed_hop = _pair(r)
        open_ = open_hop["mandate"]
        closed = closed_hop["mandate"]
        op = open_checkout_mandate_problems(open_)
        if op:
            raise Ap2Error("open checkout mandate: %s" % "; ".join(op))
        _require_open_expiry(open_, "open checkout mandate")
        cp = checkout_mandate_problems(closed)
        if cp:
            raise Ap2Error("closed checkout mandate: %s" % "; ".join(cp))
        alg = closed_hop["hop"]["sdAlg"]
        if sd_digest(closed["checkout_jwt"], alg) != closed["checkout_hash"]:
            raise Ap2Error("checkout_hash does not match checkout_jwt")
        jwt = parse_jwt(closed["checkout_jwt"], "checkout_jwt")
        key = o["resolveMerchantKey"](jwt["header"])
        if not _truthy(key):
            raise Ap2Error("checkout_jwt: no merchant key for this header")
        if not verify_jwt_es256(jwt, key):
            raise Ap2Error("checkout_jwt: merchant signature does not verify")
        checkout = project_checkout(jwt["payload"])
        violations = check_checkout_constraints(open_, checkout)
        if violations:
            return {"ok": False, "reason": "open checkout constraints violated: %s" % "; ".join(violations), "violations": violations}
        return {"ok": True, "open": open_, "closed": closed, "checkoutJwt": closed["checkout_jwt"], "checkout": checkout,
                "openHash": sd_hash_of(open_hop["hop"]), "hops": r["hops"]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": _reason(e)}


def verify_payment_chain(token: str, o: dict) -> dict:
    """Verify an open+closed payment chain and every open payment constraint. `o` is the chain options plus openCheckoutHash (the open
    checkout mandate's `sd_hash`), context? (usage state) and expectedTransactionId? (the closed checkout's `checkout_hash`)."""
    r = verify_delegation_chain(token, o)
    if not r["ok"]:
        return r
    try:
        open_hop, closed_hop = _pair(r)
        open_ = open_hop["mandate"]
        closed = closed_hop["mandate"]
        op = open_payment_mandate_problems(open_)
        if op:
            raise Ap2Error("open payment mandate: %s" % "; ".join(op))
        _require_open_expiry(open_, "open payment mandate")
        cp = payment_mandate_problems(closed)
        if cp:
            raise Ap2Error("closed payment mandate: %s" % "; ".join(cp))
        expected = o.get("expectedTransactionId", _U)
        if expected is not _U and not _seq(closed["transaction_id"], expected):
            raise Ap2Error("transaction_id does not match the checkout being settled")
        now = o.get("now")
        opts = {"openCheckoutHash": o.get("openCheckoutHash"), "now": int(math.floor(time.time())) if now is None else now}
        if _truthy(o.get("context", _U)):
            opts["context"] = o["context"]
        violations = check_payment_constraints(open_, closed, opts)
        if violations:
            return {"ok": False, "reason": "open payment constraints violated: %s" % "; ".join(violations), "violations": violations}
        return {"ok": True, "open": open_, "closed": closed, "openHash": sd_hash_of(open_hop["hop"]), "hops": r["hops"]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": _reason(e)}


def verify_purchase(checkout_token: str, payment_token: str, o: dict) -> dict:
    """Verify a complete purchase: the checkout chain, then the payment chain bound to it, and that the payment settles what the merchant quoted
    (payee, currency, total). `o`: resolveIssuerKey, resolveMerchantKey, checkout and payment ({"expectedAudience", "expectedNonce"}), context?, now?,
    clockSkewSeconds?."""
    base: dict = {"resolveIssuerKey": o["resolveIssuerKey"]}
    if o.get("now") is not None:
        base["now"] = o["now"]
    if o.get("clockSkewSeconds") is not None:
        base["clockSkewSeconds"] = o["clockSkewSeconds"]
    copts = dict(base)
    copts.update(_spread(o.get("checkout")))
    copts["resolveMerchantKey"] = o["resolveMerchantKey"]
    co = verify_checkout_chain(checkout_token, copts)
    if not co["ok"]:
        return {"ok": False, "reason": "checkout: %s" % co["reason"]}
    popts = dict(base)
    popts.update(_spread(o.get("payment")))
    popts["openCheckoutHash"] = co["openHash"]
    popts["expectedTransactionId"] = co["closed"]["checkout_hash"]
    if _truthy(o.get("context", _U)):
        popts["context"] = o["context"]
    pay = verify_payment_chain(payment_token, popts)
    if not pay["ok"]:
        return {"ok": False, "reason": "payment: %s" % pay["reason"]}
    total = checkout_total(co["checkout"])
    if total is None:
        return {"ok": False, "reason": "checkout: needs exactly one total entry"}
    amt = pay["closed"]["payment_amount"]
    if amt["currency"] != co["checkout"]["currency"]:
        return {"ok": False, "reason": "payment currency differs from the checkout currency"}
    if amt["amount"] != total:
        return {"ok": False, "reason": "payment amount %s differs from the checkout total %s" % (js_to_string(amt["amount"]), js_to_string(total))}
    merchant = co["checkout"].get("merchant")
    if not merchant:
        return {"ok": False, "reason": "checkout: no merchant to compare the payee with"}
    if merchant["id"] != pay["closed"]["payee"]["id"]:
        return {"ok": False, "reason": "payee differs from the checkout merchant"}
    return {"ok": True, "checkout": co, "payment": pay}


# ---- the redeem ledger -------------------------------------------------------------------------------------------------------

def _redeem_core(checkout_token: str, payment_token: str, o: dict, ledger: Any):
    """`verify_purchase` plus single use and server-owned cumulative state, as a generator that yields each ledger call (it may be awaitable)
    and receives its value. The usage context comes from `ledger`, never from the caller; a missing or failing ledger denies.
    A ledger has `reserve(open_mandate_hash, transaction_id, amount_minor) -> context dict | "replayed"` and `release(open_mandate_hash, transaction_id)`."""
    if not ledger or not callable(getattr(ledger, "reserve", None)) or not callable(getattr(ledger, "release", None)):
        return {"ok": False, "reason": "ledger_required"}
    # a zero context is the most permissive one for budget and recurrence, so a failure here is final
    first = verify_purchase(checkout_token, payment_token, dict(o, context={"totalAmount": 0, "totalUses": 0}))
    if not first["ok"]:
        return first
    open_hash = first["payment"]["openHash"]
    tx_id = first["payment"]["closed"]["transaction_id"]
    amount = first["payment"]["closed"]["payment_amount"]["amount"]
    try:
        ctx = yield ledger.reserve(open_hash, tx_id, amount)
    except Exception:  # noqa: BLE001
        return {"ok": False, "reason": "ledger_unavailable"}
    if ctx == "replayed":
        return {"ok": False, "reason": "replayed"}
    final = verify_purchase(checkout_token, payment_token, dict(o, context=ctx))
    if not final["ok"]:
        try:
            yield ledger.release(open_hash, tx_id)
        except Exception:  # noqa: BLE001 - the reservation stays: a failed release only ever over-counts spend
            pass
    return final


def _drive(gen: Any) -> Any:
    try:
        v = next(gen)
        while True:
            if inspect.isawaitable(v):
                if hasattr(v, "close"):
                    v.close()
                v = gen.throw(TypeError("an awaitable ledger needs redeem_purchase_async"))
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
            except Exception as e:  # noqa: BLE001 - surfaces inside the redeem as a ledger failure
                v = gen.throw(e)
                continue
            v = gen.send(v)
    except StopIteration as stop:
        return stop.value


def redeem_purchase(checkout_token: str, payment_token: str, o: dict, ledger: Any) -> dict:
    """`verify_purchase` plus single use and server-owned cumulative state (see `_redeem_core`). `o` is the `verify_purchase` options without `context`."""
    return _drive(_redeem_core(checkout_token, payment_token, o, ledger))


async def redeem_purchase_async(checkout_token: str, payment_token: str, o: dict, ledger: Any) -> dict:
    """`redeem_purchase` for a ledger whose `reserve` / `release` return awaitables."""
    return await _drive_async(_redeem_core(checkout_token, payment_token, o, ledger))


# ---- PCA terms -> AP2 open mandates ------------------------------------------------------------------------------------------

def _minor_term(v: Any, name: str) -> Any:
    """A PCA term as integer minor units; anything else (a major-unit float from an older mandate) is refused."""
    if not _safe_int(v) or v < 0 or _neg0(v):
        raise Ap2Error("PCA term %s must be a non-negative integer in minor units, got %s" % (name, _str(v)))
    return v


def pca_open_claim(mandate: dict) -> dict:
    """The `x_pca` claim of an open mandate: the principal-signed grant and the terms it was minted from."""
    return {"v": PCA_BINDING_VERSION, "grant": _to_json(_g(mandate, "grant")), "terms": _to_json(_g(mandate, "terms"))}


def _open_expiry(terms: dict, o: dict) -> Any:
    pe = _g(terms, "periodEnd")
    if pe is not _U and _num(pe) and not fin(pe):  # a period end beyond the double range (or NaN/Infinity) is no usable time
        raise Ap2Error("PCA term periodEnd must be a finite number, got %s" % _str(pe))
    period_end = None if pe is _U else math.floor(pe / 1000)
    exp = o.get("exp")
    exp = period_end if exp is None else exp
    if exp is None:
        raise Ap2Error("exp is required when the PCA terms have no period end")
    if period_end is not None and not (exp <= period_end):
        raise Ap2Error("exp must not exceed the PCA period end")
    return exp


def _merchants_for(terms: dict, merchants: list) -> list:
    out = []
    for mid in _iter_list(_g(terms, "merchants")):
        m = next((x for x in merchants if _seq(_g(x, "id"), mid)), None)
        if m is None:
            raise Ap2Error("no merchant descriptor supplied for PCA merchant %s" % _str(mid))
        out.append(m)
    return out


def _next_up(x: float) -> float:
    """Next representable double above a positive finite `x`."""
    return struct.unpack("<d", struct.pack("<Q", struct.unpack("<Q", struct.pack("<d", x))[0] + 1))[0]


def ap2_budget_max(cap_minor: Any, currency: str) -> float:
    """The value of AP2 `payment.budget.max` for a PCA cap in integer minor units. The official AP2 SDK reads it as `int(max * 100)` whatever the
    currency, a major-unit reader as `max * 10^exponent`: the value emitted never lets EITHER read more than the cap (nudged up by at most a few ulps
    when `cap / divisor` falls just under the exact decimal). Raises when no exact representation exists."""
    cap = _minor_term(cap_minor, "cumulativeCap")
    e = currency_exponent(currency)
    sdk_target = cap if e <= 2 else math.floor(cap / (10 ** (e - 2)))
    d = cap / (10 ** max(e, 2))
    for _ in range(8):
        if not (d > 0 and math.trunc(d * 100) < sdk_target):
            break
        d = _next_up(d)
    if math.trunc(d * 100) != sdk_target or _js_round(d * (10 ** e)) > cap:
        raise Ap2Error("cumulativeCap %s %s has no exact AP2 budget.max representation" % (_str(cap), _str(currency)))
    return d


def ap2_budget_reads(max: Any, currency: str) -> dict:  # noqa: A002
    """What the two readers of an AP2 `budget.max` read, in minor units of `currency`: the SDK (`int(max * 100)`) and a major-unit reader."""
    e = currency_exponent(currency)
    if not _num(max) or not fin(max) or max < 0:
        raise Ap2Error("budget.max must be a finite non-negative number, got %s" % _str(max))
    return {"sdk": float(math.trunc(float(max) * 100)), "major": float(_js_round(float(max) * (10 ** e)))}


def payment_constraints_from_terms(terms: dict, merchants: list, checkout_reference: str) -> list:
    """The AP2 open payment constraints a set of PCA terms denotes (PCA terms are integer minor units of the mandate currency; `budget.max` is derived by `ap2_budget_max`)."""
    cur = _g(terms, "currency")
    per_tx = _minor_term(_g(terms, "perTransactionCap"), "perTransactionCap")
    budget_max = ap2_budget_max(_g(terms, "cumulativeCap"), cur)
    recurrence = _compact(type="payment.agent_recurrence", frequency="ON_DEMAND")
    mt = _g(terms, "maxTransactionsPerPeriod")
    if mt is not _U:
        recurrence["max_occurrences"] = mt
    return [
        _compact(type="payment.amount_range", currency=cur, min=0, max=per_tx),
        {"type": "payment.allowed_payees", "allowed": _merchants_for(terms, merchants)},
        {"type": "payment.reference", "conditional_transaction_id": checkout_reference},
        _compact(type="payment.budget", currency=cur, max=budget_max),
        recurrence,
    ]


def _from_pca_input(mandate: dict, o: dict, constraints: Callable[[], list]) -> dict:
    out: dict = {"issuer": o["issuer"], "agentJwk": o["agentJwk"], "iat": o["iat"]}
    out["exp"] = _open_expiry(_g(mandate, "terms"), o)
    out["pca"] = pca_open_claim(mandate)
    out["constraints"] = constraints()
    if _truthy(o.get("salt", _U)):
        out["salt"] = o["salt"]
    return out


def open_payment_mandate_from_pca(mandate: dict, o: dict) -> str:
    """Issue the open payment mandate for a PCA mandate (grant + terms), chained to `o["checkoutReference"]`. `o`: issuer, agentJwk, merchants, iat,
    exp?, salt?, checkoutReference."""
    return issue_open_payment_mandate(_from_pca_input(
        mandate, o, lambda: payment_constraints_from_terms(_g(mandate, "terms"), o["merchants"], o["checkoutReference"])))


def open_checkout_mandate_from_pca(mandate: dict, o: dict) -> str:
    """Issue the open checkout mandate for a PCA mandate: the merchant allowlist and the acceptable line items (`o["lineItems"]`)."""
    return issue_open_checkout_mandate(_from_pca_input(
        mandate, o, lambda: [{"type": "checkout.line_items", "items": o["lineItems"]},
                             {"type": "checkout.allowed_merchants", "allowed": _merchants_for(_g(mandate, "terms"), o["merchants"])}]))


# ---- the closed payment: PCActn bound to the AP2 mandate ---------------------------------------------------------------------

def pca_binding_nonce(f: dict) -> str:
    """The value the PCActn's signed `nonce` must equal for these AP2 facts (transactionId, payeeId, amount, currency, instrumentId, openHash, agentJkt)."""
    return "ap2:%s" % hash_canonical(dict({"v": PCA_BINDING_VERSION}, **_spread(f)))


def risk_ratio(amount: Any, cap: Any) -> Any:
    """amount / cap, clamped to [0, 1] and rounded UP to 12 decimals (PCA's canonical encoding refuses numbers with more than 15 significant
    digits; rounding up can only raise the risk the threshold policy sees)."""
    r = amount / cap if cap > 0 else 1
    return min(1, max(0, math.ceil(r * 1e12 - 1e-6) / 1e12))


def build_pca_payment_binding(i: dict) -> dict:
    """Build the `x_pca` claim of a closed payment mandate: a PCActn authorising exactly this charge. `i`: mandate (the PCA mandate: grant + terms),
    open (the open payment mandate token), agentJwk, agentSecret (the grant holder's 32-byte Ed25519 seed), audience, counter, transactionId, payee,
    amount ({"amount", "currency"}), instrumentId, category?, now? (epoch ms), cosign? (callable over the built PCActn returning the threshold shares)."""
    amount = i["amount"]
    major = _minor_term(amount["amount"], "amount")  # the charge amount is integer minor units, as in the mandate
    payee = i["payee"]
    charge: dict = {"merchant": payee["id"], "amount": major, "currency": amount["currency"]}
    if i.get("category", _U) is not _U:
        charge["category"] = i["category"]
    mandate = i["mandate"]
    facts = {"transactionId": i["transactionId"], "payeeId": payee["id"], "amount": amount["amount"], "currency": amount["currency"],
             "instrumentId": i["instrumentId"], "openHash": sd_hash_of(parse_sd_jwt_hop(i["open"])), "agentJkt": jwk_thumbprint(i["agentJwk"])}
    risk = risk_ratio(major, mandate["terms"]["perTransactionCap"])
    node_id = "ap2:%s" % i["transactionId"]
    params = charge_params(mandate, charge)
    node = charge_plan_node(mandate, charge, node_id)
    kw: dict = {}
    if i.get("now") is not None:
        kw["now"] = i["now"]
    built = build_pcactn(mandate["grant"], [mandate["grant"]], [node], node_id, i["counter"], KeyPair(bytes(i["agentSecret"])), i["audience"], params=params,
                         nonce=pca_binding_nonce(facts), risk_claim={"r": risk, "inputs": dict(params, blastRadius=risk)}, **kw)
    pcactn = dict(built, threshold=i["cosign"](built)) if i.get("cosign") else built
    claim_charge: dict = {"amount": major, "currency": amount["currency"]}
    if i.get("category", _U) is not _U:
        claim_charge["category"] = i["category"]
    return {"v": PCA_BINDING_VERSION, "charge": claim_charge, "pcactn": _to_json(pcactn)}


# ---- verification of the PCA side of a verified AP2 chain --------------------------------------------------------------------

class PcaBindingError(Exception):
    """Raised when `verify_pca_binding` lacks the server-held state the policy decision needs (`code`: mandate_required | charge_history_required)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _is_rec(v: Any) -> bool:
    return isinstance(v, dict)


def _includes(lst: Any, v: Any) -> bool:
    return any(_seq(x, v) for x in lst) if isinstance(lst, list) else (isinstance(lst, str) and isinstance(v, str) and v in lst)


def _find_type(constraints: Any, t: str) -> Any:
    for c in _iter_list(constraints):
        if _g(c, "type") == t:
            return c
    return _U


def _constraints_within_terms(open_: Any, terms: Any) -> Optional[str]:
    """Check the open mandate's constraints never exceed the PCA terms (the AP2 side only narrows the grant)."""
    cur = _g(terms, "currency")
    per_tx = _minor_term(_g(terms, "perTransactionCap"), "perTransactionCap")
    constraints = _g(open_, "constraints")
    rng = _find_type(constraints, "payment.amount_range")
    if rng is _U:
        return "open mandate has no amount_range to compare with the PCA per-transaction cap"
    if not _seq(_g(rng, "currency"), cur):
        return "amount_range currency differs from the PCA terms"
    if not _le(_g(rng, "max"), per_tx):
        return "amount_range.max %s exceeds the PCA per-transaction cap %s" % (_str(_g(rng, "max")), _str(per_tx))
    payees = _find_type(constraints, "payment.allowed_payees")
    if payees is not _U and any(not _includes(_g(terms, "merchants"), _g(m, "id")) for m in _iter_list(_g(payees, "allowed"))):
        return "allowed_payees names a merchant outside the PCA allowlist"
    if payees is _U:
        return "open mandate has no allowed_payees; the PCA allowlist would not be enforced on the AP2 side"
    budget = _find_type(constraints, "payment.budget")
    if budget is _U:
        return "open mandate has no budget to compare with the PCA cumulative cap"
    if not _seq(_g(budget, "currency"), cur):
        return "budget exceeds the PCA cumulative cap"
    reads = ap2_budget_reads(_g(budget, "max"), cur)
    cap_minor = _minor_term(_g(terms, "cumulativeCap"), "cumulativeCap")
    if reads["sdk"] > cap_minor or reads["major"] > cap_minor:
        return "budget exceeds the PCA cumulative cap"
    rec = _find_type(constraints, "payment.agent_recurrence")
    max_tx = _g(terms, "maxTransactionsPerPeriod")
    if max_tx is not _U and (rec is _U or _g(rec, "max_occurrences") is _U or not _le(_g(rec, "max_occurrences"), max_tx)):
        return "max_occurrences is missing or exceeds the PCA transaction limit"
    period_end = _g(terms, "periodEnd")
    if period_end is not _U and (_g(open_, "exp") is _U or not fin(_to_number(period_end)) or not _le(_g(open_, "exp"), math.floor(_to_number(period_end) / 1000))):
        return "open mandate outlives the PCA period"
    return None


def verify_pca_binding(i: dict, decide: Callable[[Dict[str, Any]], Dict[str, Any]]) -> dict:
    """Verify the PCA side of a verified AP2 payment chain: the grant in the open mandate (signed by the expected principal, consistent with the
    terms it claims and with the open constraints), and the closed mandate's PCActn (valid under that grant, for this audience, committing to
    exactly this AP2 charge). Run it after `verify_payment_chain`. `decide` is the PCA policy engine (the decision runs on the server-held
    mandate, never skipped). `i`: open, closed, openHash, expectedPrincipal, audience, mandate (REQUIRED), recentChargeTimes (REQUIRED when the
    mandate limits the charge count), pqPins?, now?, hooks? ({attestation?, threshold?, revocation?: ctx -> {enforced, ok, reason?, t?}}),
    enforce? ({freshness?: core enforce_freshness dict, taint?: core enforce_taint dict}; any other gate is refused). Returns
    {"ok": True, pcactn, grant, terms} or {"ok": False, "reason"}; raises PcaBindingError when the mandate or history is missing."""
    if not callable(decide):
        raise Ap2Error("verify_pca_binding needs the PCA policy engine as `decide`")
    mandate = i.get("mandate", _U) if isinstance(i, dict) else _U
    if not _is_rec(mandate):
        raise PcaBindingError("mandate_required", "verifyPcaBinding needs the server-held PCA mandate (its live budget); the policy decision is never skipped")
    terms_of_mandate = mandate.get("terms")
    max_tx_m = terms_of_mandate.get("maxTransactionsPerPeriod", _U) if isinstance(terms_of_mandate, dict) else _U
    recent = i.get("recentChargeTimes")
    if max_tx_m is not _U and not (isinstance(recent, list) and all(_finite(t) for t in recent)):
        raise PcaBindingError("charge_history_required", "the mandate limits the charge count: pass recentChargeTimes from your own records")

    def fail(reason: str) -> dict:
        return {"ok": False, "reason": reason}

    try:
        oc = _g(_g(i, "open"), "x_pca")
        if not _is_rec(oc) or not _seq(oc.get("v", _U), PCA_BINDING_VERSION) or not _is_rec(oc.get("grant")) or not _is_rec(oc.get("terms")):
            return fail("open mandate carries no x_pca grant")
        grant = oc["grant"]
        terms = oc["terms"]
        chain_ok, chain_why = verify_chain([grant], i.get("expectedPrincipal"), pq_pins=i.get("pqPins"))
        if not chain_ok:
            return fail("PCA grant: %s" % ("invalid" if chain_why is None else chain_why))
        from .authorize import read_envelope  # deferred: authorize imports this package's payments
        env = read_envelope(grant)
        if env is None:
            return fail("PCA grant has no envelope")
        if hash_canonical(env["predicates"]) != hash_canonical(mandate_predicates(terms)) or hash_canonical(env["caveats"]) != hash_canonical(mandate_caveats(terms)):
            return fail("x_pca terms do not match the grant envelope")
        rp = env["risk_policy"]
        if not _seq(_g(rp, "kappa"), _g(terms, "perTransactionCap")) or not _seq(_g(rp, "bMax"), _g(terms, "cumulativeCap")):
            return fail("x_pca terms do not match the grant risk policy")
        within = _constraints_within_terms(i["open"], terms)
        if within:
            return fail(within)

        closed = i.get("closed")
        cc = _g(closed, "x_pca")
        if not _is_rec(cc) or not _seq(cc.get("v", _U), PCA_BINDING_VERSION) or not _is_rec(cc.get("pcactn")) or not _is_rec(cc.get("charge")):
            return fail("closed mandate carries no x_pca PCActn")
        pcactn = cc["pcactn"]
        charge = cc["charge"]
        amt = _g(closed, "payment_amount")
        payee = _g(closed, "payee")
        if not _seq(_g(charge, "currency"), _g(amt, "currency")) or not _seq(_g(charge, "amount"), _g(amt, "amount")):
            return fail("x_pca charge differs from the mandate payment_amount")
        cats = _g(terms, "categories")
        if cats is _U or cats is None:
            raise TypeError("Cannot read properties of %s (reading 'length')" % ("null" if cats is None else "undefined"))
        category = _g(charge, "category")
        if (len(cats) if isinstance(cats, (list, str)) else 0) > 0 and (not isinstance(category, str) or not _includes(cats, category)):
            return fail("x_pca charge lacks an allowed category")

        # the t the threshold hook REPORTS it enforced: a hook built for a smaller t cannot satisfy a charge that needs more
        hooks = i.get("hooks")
        hooks = hooks if isinstance(hooks, dict) else {}
        enforce = i.get("enforce")
        enforce = enforce if isinstance(enforce, dict) else {}
        if any(k not in ("freshness", "taint") for k in enforce):
            return fail("PCActn: an enforce gate other than freshness and taint is not supported by this verifier (fail closed)")
        enforced_t: Any = _U
        core_kw: dict = {}
        if i.get("now") is not None:
            core_kw["now"] = i["now"]
        if enforce.get("freshness") is not None:
            core_kw["enforce_freshness"] = enforce["freshness"]
        if enforce.get("taint") is not None:
            core_kw["enforce_taint"] = enforce["taint"]
        core = verify_pcactn_core(pcactn, grant, audience=i.get("audience"), insecure_skip_plan_root_check=True, **core_kw)
        if not core.allow:
            return fail("PCActn: %s" % ("rejected" if core.reason is None else ts_reason(core.reason)))
        hook_ctx = {"pcactn": pcactn, "grant": grant}
        if "now" in core_kw:
            hook_ctx["nowEpoch"] = core_kw["now"]
        for name in ("attestation", "threshold", "revocation"):
            hook = hooks.get(name)
            if hook is None:
                continue
            res = hook(hook_ctx)
            if name == "threshold" and _truthy(_g(res, "enforced")) and _truthy(_g(res, "ok")) and _num(_g(res, "t")):
                enforced_t = res["t"]
            if _truthy(_g(res, "enforced")) and not _truthy(_g(res, "ok")):
                why = _g(res, "reason")
                return fail("PCActn: %s: %s" % (name, "rejected" if why is _U or why is None else _str(why)))

        action = _g(pcactn, "action")
        if not _seq(_g(action, "verb"), "charge") or not _seq(_g(action, "resource"), "merchant:%s" % _str(_g(payee, "id"))):
            return fail("PCActn action is not a charge at this payee")
        params: dict = {"amount": _g(charge, "amount"), "currency": _g(charge, "currency")}
        if isinstance(category, str):
            params["category"] = category
        if params["amount"] is _U or params["currency"] is _U:
            raise Ap2Error("canonical JSON cannot encode an undefined charge member")
        if not _seq(_g(action, "params_digest"), params_digest(params)):
            return fail("PCActn params do not commit to the x_pca charge")
        agent_jwk = _g(_g(_g(i, "open"), "cnf"), "jwk")
        facts = {"transactionId": _g(closed, "transaction_id"), "payeeId": _g(payee, "id"), "amount": _g(amt, "amount"), "currency": _g(amt, "currency"),
                 "instrumentId": _g(_g(closed, "payment_instrument"), "id"), "openHash": i.get("openHash", _U), "agentJkt": jwk_thumbprint(agent_jwk)}
        if any(v is _U for v in facts.values()):
            raise Ap2Error("canonical JSON cannot encode an undefined binding fact")
        if not _seq(_g(pcactn, "nonce"), pca_binding_nonce(facts)):
            return fail("PCActn nonce does not bind this AP2 transaction, open mandate and agent key")
        per_tx = _minor_term(_g(terms, "perTransactionCap"), "perTransactionCap")
        if not (_finite(_g(amt, "amount")) and _le(_g(amt, "amount"), per_tx)):
            return fail("payment exceeds the PCA per-transaction cap")
        # the agent may not understate the risk of its own charge; a charge whose risk needs a human co-sign (t > 1) needs a threshold verifier
        recomputed = risk_ratio(_g(amt, "amount"), _g(terms, "perTransactionCap"))
        claimed = _g(_g(pcactn, "risk_claim"), "r")
        if not (_num(claimed) and claimed >= recomputed - 1e-9):
            return fail("PCActn understates the risk of this charge")
        need = required_threshold(claimed, rp)
        if need["t"] > 1 and not _truthy(hooks.get("threshold")):
            return fail("this charge needs a threshold of %d (human co-sign); supply hooks.threshold to verify it" % need["t"])
        if need["t"] > 1 and not (_num(enforced_t) and enforced_t >= need["t"]):
            return fail("this charge needs a threshold of %d but the threshold hook enforced t=%s; build it with createThresholdVerifier({ t: %d })"
                        % (need["t"], "unreported" if enforced_t is _U else _str(enforced_t), need["t"]))
        if not _seq(_g(amt, "currency"), _g(terms, "currency")) or not _includes(_g(terms, "merchants"), _g(payee, "id")):
            return fail("payment currency or payee is outside the PCA terms")

        if hash_canonical(mandate["grant"] if "grant" in mandate else None) != hash_canonical(grant):
            return fail("the supplied PCA mandate is not the one in the open mandate")
        # `grant` was verified above under the caller-pinned principal; the decision is bound to it
        spend: dict = {"merchant": _g(payee, "id"), "amount": _g(amt, "amount"), "currency": _g(amt, "currency")}
        if isinstance(category, str):
            spend["category"] = category
        spend["recentChargeTimes"] = recent if recent is not None else []
        if i.get("now") is not None:
            spend["now"] = i["now"]
        decision = authorize_charge(mandate, spend, grant, decide)
        if decision["outcome"] == "deny":
            return fail("PCA denies this charge: %s" % "; ".join(_str(r) for r in decision["reasons"]))
        if decision["outcome"] == "step_up" and not (_num(enforced_t) and enforced_t >= 2):
            return fail("PCA requires a human co-sign for this charge and no verified threshold (t >= 2) was enforced")
        return {"ok": True, "pcactn": pcactn, "grant": grant, "terms": terms}
    except Exception as e:  # noqa: BLE001 - totality: any fault is a refusal carrying the message
        return fail(str(e))


# ---- settlement backends (structural only, no network) ---------------------------------------------------------------------

def to_atomic_units(amount: dict, decimals: Any) -> str:
    """Integer minor units to an integer string of atomic units: scales by `10 ** (decimals - exponent)` exactly; when the asset has fewer decimals
    than the currency the division must be exact. Raises otherwise (fail closed)."""
    if not _num(decimals) or not fin(decimals) or decimals != math.trunc(decimals) or decimals < 0 or decimals > 18:
        raise RangeError("x402: decimals must be an integer in 0..18, got %s" % _str(decimals))
    amt = _g(amount, "amount")
    if not _safe_int(amt) or amt < 0 or _neg0(amt):
        raise RangeError("x402: amount %s cannot be expressed in atomic units with %s decimals" % (_str(amt), _str(decimals)))
    decimals = int(decimals)
    exp = currency_exponent(_g(amount, "currency"))
    minor = int(amt)
    if decimals >= exp:
        return str(minor * 10 ** (decimals - exp))
    div = 10 ** (exp - decimals)
    if minor % div != 0:
        raise RangeError("x402: amount %s cannot be expressed in atomic units with %s decimals" % (_str(amt), _str(decimals)))
    return str(minor // div)


def _ctx_get(ctx: Any, k: str) -> Any:
    return ctx.get(k) if isinstance(ctx, dict) else None


class _X402Settlement:
    """Coinbase x402 adapter: the HTTP 402 `Payment Required` challenge (`accepts`) plus the `X-PAYMENT` request header (standard base64 of the
    JSON payment payload). The payload is a placeholder envelope, not a signed authorization: the real rail settles on-chain."""

    rail = "x402"

    def settle(self, payment: dict, ctx: Optional[dict] = None) -> dict:
        network = _ctx_get(ctx, "network")
        network = "base-sepolia" if network is None else network
        dec = _ctx_get(ctx, "decimals")
        amt = payment["payment_amount"]
        requirement = {
            "scheme": "exact",
            "network": network,
            "maxAmountRequired": to_atomic_units(amt, 6 if dec is None else dec),  # x402 v1: a string in ATOMIC token units
            "resource": "" if _ctx_get(ctx, "resourceUrl") is None else _ctx_get(ctx, "resourceUrl"),
            "description": "AP2 payment mandate %s" % _str(payment["transaction_id"]),
            "payTo": payment["payee"]["id"] if _ctx_get(ctx, "payTo") is None else _ctx_get(ctx, "payTo"),
            "asset": amt["currency"] if _ctx_get(ctx, "asset") is None else _ctx_get(ctx, "asset"),
            "mimeType": "application/json",
            "maxTimeoutSeconds": 60 if _ctx_get(ctx, "maxTimeoutSeconds") is None else _ctx_get(ctx, "maxTimeoutSeconds"),
        }
        x_payment = base64.b64encode(_utf8(_stringify({"x402Version": 1, "scheme": "exact", "network": network,
                                                       "payload": {"transactionId": payment["transaction_id"], "amount": amt["amount"], "currency": amt["currency"]}}))).decode("ascii")
        return {"rail": "x402", "amount": amt, "merchant": payment["payee"]["id"],
                "payload": {"httpStatus": 402, "x402Version": 1, "error": "X-PAYMENT header is required", "accepts": [requirement], "header": {"X-PAYMENT": x_payment}}}


class _StripeSptSettlement:
    """Stripe Shared Payment Token adapter: a shared token the buyer's agent grants the merchant to pull a bounded amount. The token is the
    mandate's payment instrument id, never a raw PAN."""

    rail = "stripe-spt"

    def settle(self, payment: dict, ctx: Optional[dict] = None) -> dict:
        inst = payment["payment_instrument"]
        if inst.get("type") != "shared_payment_token":
            raise Ap2Error("stripe-spt: the payment instrument must be of type shared_payment_token, got %s" % _str(inst.get("type", _U)))
        payload = {"shared_payment_token": inst["id"], "amount": payment["payment_amount"]["amount"],
                   "currency": payment["payment_amount"]["currency"].lower()}
        if _truthy(_ctx_get(ctx, "payTo")):
            payload["on_behalf_of"] = ctx["payTo"]
        return {"rail": "stripe-spt", "amount": payment["payment_amount"], "merchant": payment["payee"]["id"], "payload": payload}


x402_settlement = _X402Settlement()
stripe_spt_settlement = _StripeSptSettlement()
