"""Phishing-resistant human co-sign for PCA step-up via WebAuthn / FIDO2 (port of the TypeScript reference,
@atlasauth/pca-webauthn).

A passkey assertion IS the human approval proof when its challenge equals the PCA step-up challenge (the action digest,
``sha256(threshold_message(pcactn))``): the signature covers ``authenticatorData || sha256(clientDataJSON)``, so a phished
origin fails the origin + rpIdHash binding and a replayed assertion fails the challenge binding. This is the SERVER-SIDE
verify. ES256 (P-256) and EdDSA (Ed25519), with a minimal, bounded COSE_Key / CBOR reader. Every public entry point fails
CLOSED. ES256 needs the optional ``cryptography`` package.

Dicts use snake_case names; an absent key and a ``None`` value are told apart exactly as ``undefined`` and ``null`` are in
the reference. Bytes are ``bytes``; an expected challenge may also be a base64url string.
"""
from __future__ import annotations

from ._fin import fin
import hashlib
import math
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from . import approval as _approval
from . import ed25519
from . import pca as _pca
from .sdjwt import _same
from .sdjwt_jws import UNSET, b64u, is_number, js_json_parse, js_to_string, truthy

_SURROGATES = re.compile("[\ud800-\udfff]")

MAX_AUTHENTICATOR_DATA_BYTES = 4096
MAX_CLIENT_DATA_BYTES = 8192
MAX_SIGNATURE_BYTES = 1024

# COSE_Key integer labels (RFC 9052 / RFC 9053).
_COSE_KTY, _COSE_CRV, _COSE_X, _COSE_Y = 1, -1, -2, -3
_COSE_KTY_OKP, _COSE_KTY_EC2 = 1, 2
_COSE_CRV_P256, _COSE_CRV_ED25519 = 1, 6
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_B64U_TOLERANT_TAIL = re.compile("=+\\Z")


class WebAuthnError(ValueError):
    """A refusal from this package (the message is the reference's)."""


def _utf8(s: str) -> bytes:
    return _SURROGATES.sub("�", s).encode("utf-8")  # TextEncoder replaces a lone surrogate


def _is_bytes(v: Any) -> bool:
    return isinstance(v, (bytes, bytearray))


def _as_record(v: Any) -> Optional[dict]:
    return v if isinstance(v, dict) else None


def _bytes_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def _base64url_to_bytes(s: Any) -> Optional[bytes]:
    """Tolerant base64url: the URL alphabet with or without `=` padding (`+` and `/` accepted); None for anything else."""
    if not isinstance(s, str):
        return None
    t = _B64U_TOLERANT_TAIL.sub("", s).replace("+", "-").replace("/", "_")
    return _pca.decode_b64u_strict(t)


# ---- minimal COSE_Key / CBOR reader ---------------------------------------------------------------------------------
# Unsigned ints (major 0), negative ints (1), byte strings (2) and maps (5), with 1/2/4-byte arguments. Indefinite length
# and 8-byte arguments are rejected; map keys must be integers; trailing bytes after the first item are ignored.

def _read_cbor_item(b: bytes, offset: int) -> Tuple[Any, int]:
    n = len(b)
    if offset >= n:
        raise WebAuthnError("cose: read past the end")
    initial = b[offset]
    major, ai = initial >> 5, initial & 0x1F
    p = offset + 1
    if ai < 24:
        arg = ai
    elif ai == 24:
        if p + 1 > n:
            raise WebAuthnError("cose: read past the end")
        arg, p = b[p], p + 1
    elif ai == 25:
        if p + 2 > n:
            raise WebAuthnError("cose: read past the end")
        arg, p = int.from_bytes(b[p:p + 2], "big"), p + 2
    elif ai == 26:
        if p + 4 > n:
            raise WebAuthnError("cose: read past the end")
        arg, p = int.from_bytes(b[p:p + 4], "big"), p + 4
    else:
        raise WebAuthnError("cose: unsupported CBOR argument encoding (8-byte or indefinite length)")

    if major == 0:
        return arg, p
    if major == 1:
        return -1 - arg, p
    if major == 2:
        end = p + arg
        if end > n:
            raise WebAuthnError("cose: byte string length out of range")
        return bytes(b[p:end]), end
    if major == 5:
        out: Dict[int, Any] = {}
        q = p
        for _ in range(arg):
            key, nxt = _read_cbor_item(b, q)
            if not isinstance(key, int):
                raise WebAuthnError("cose: non-integer map key")
            val, q = _read_cbor_item(b, nxt)
            out[key] = val
        return out, q
    raise WebAuthnError("cose: unsupported CBOR major type %d" % major)


def cose_key_to_jwk(data: bytes) -> dict:
    """Decode a raw COSE_Key (``attestedCredentialData.credentialPublicKey``) into an ES256 (EC2 / P-256) or EdDSA (OKP /
    Ed25519) JWK. Raises on malformed input or an unsupported key type."""
    if not _is_bytes(data):
        raise TypeError("coseKeyToJwk: expected bytes")
    value, _ = _read_cbor_item(bytes(data), 0)
    if not isinstance(value, dict):
        raise WebAuthnError("coseKeyToJwk: COSE_Key is not a CBOR map")
    kty = value.get(_COSE_KTY)
    if kty == _COSE_KTY_EC2:
        crv, x, y = value.get(_COSE_CRV), value.get(_COSE_X), value.get(_COSE_Y)
        if crv != _COSE_CRV_P256:
            raise WebAuthnError("coseKeyToJwk: EC2 key is not P-256 (crv != 1)")
        if not isinstance(x, bytes) or not isinstance(y, bytes):
            raise WebAuthnError("coseKeyToJwk: EC2 key missing an x/y coordinate")
        if len(x) != 32 or len(y) != 32:
            raise WebAuthnError("coseKeyToJwk: EC2 coordinate is not 32 bytes")
        return {"kty": "EC", "crv": "P-256", "x": b64u(x), "y": b64u(y), "alg": "ES256"}
    if kty == _COSE_KTY_OKP:
        crv, x = value.get(_COSE_CRV), value.get(_COSE_X)
        if crv != _COSE_CRV_ED25519:
            raise WebAuthnError("coseKeyToJwk: OKP key is not Ed25519 (crv != 6)")
        if not isinstance(x, bytes):
            raise WebAuthnError("coseKeyToJwk: OKP key missing its public key")
        if len(x) != 32:
            raise WebAuthnError("coseKeyToJwk: Ed25519 public key is not 32 bytes")
        return {"kty": "OKP", "crv": "Ed25519", "x": b64u(x), "alg": "EdDSA"}
    raise WebAuthnError("coseKeyToJwk: unsupported COSE key type (kty=%s)" % ("undefined" if kty is None else js_to_string(kty)))


def _resolve_key(pub: Any) -> Tuple[str, bytes]:
    """The signature algorithm and the raw bytes it verifies with (65-byte SEC1 point for ES256, 32 bytes for EdDSA)."""
    jwk = cose_key_to_jwk(pub) if _is_bytes(pub) else pub
    if not isinstance(jwk, dict):
        raise TypeError("cannot read properties of %s (reading 'kty')" % ("undefined" if jwk is None else "a non-object"))
    kty = jwk.get("kty")
    if kty == "EC":
        if jwk.get("crv") != "P-256":
            raise WebAuthnError("resolveKey: EC JWK is not P-256")
        x, y = _base64url_to_bytes(jwk.get("x")), _base64url_to_bytes(jwk.get("y"))
        if x is None or y is None or len(x) != 32 or len(y) != 32:
            raise WebAuthnError("resolveKey: invalid EC JWK coordinates")
        return "ES256", b"\x04" + x + y  # uncompressed SEC1 point
    if kty == "OKP":
        if jwk.get("crv") != "Ed25519":
            raise WebAuthnError("resolveKey: OKP JWK is not Ed25519")
        x = _base64url_to_bytes(jwk.get("x"))
        if x is None or len(x) != 32:
            raise WebAuthnError("resolveKey: invalid OKP JWK public key")
        return "EdDSA", x
    raise WebAuthnError("resolveKey: unsupported public key")


# ---- authenticatorData -----------------------------------------------------------------------------------------------

def parse_authenticator_data(auth_data: Any) -> Optional[dict]:
    """The fixed 37-byte header of authenticatorData (rpIdHash[32] || flags[1] || signCount[4]), or None when the buffer is not
    bytes or too short. The optional attested-credential-data / extension tail is not decoded."""
    if not _is_bytes(auth_data) or len(auth_data) < 37:
        return None
    d = bytes(auth_data)
    f = d[32]
    return {"rpIdHash": d[:32],
            "flags": {"up": bool(f & 0x01), "uv": bool(f & 0x04), "be": bool(f & 0x08), "bs": bool(f & 0x10), "at": bool(f & 0x40),
                      "ed": bool(f & 0x80)},
            "signCount": int.from_bytes(d[33:37], "big")}


# ---- step-up challenge binding ---------------------------------------------------------------------------------------

def build_step_up_challenge(pc_actn_or_digest: Union[dict, str, bytes]) -> bytes:
    """The WebAuthn challenge for a PCA step-up: ``sha256(threshold_message(pcactn))`` (its base64url form is the FROST
    action digest). Accepts a PCActn (or body), the base64url digest string, or raw 32-byte digest bytes."""
    if _is_bytes(pc_actn_or_digest):
        if len(pc_actn_or_digest) != 32:
            raise WebAuthnError("buildStepUpChallenge: digest bytes must be 32 bytes")
        return bytes(pc_actn_or_digest)
    if isinstance(pc_actn_or_digest, str):
        b = _pca.decode_b64u_strict(pc_actn_or_digest, 32)
        if b is None:
            raise WebAuthnError("buildStepUpChallenge: digest is not a canonical base64url 32-byte value")
        return b
    return hashlib.sha256(_pca.threshold_message(pc_actn_or_digest)).digest()


def build_approval_challenge(pc_actn_or_digest: Union[dict, str, bytes], render_digest: str) -> bytes:
    """What you see is what you sign: ``SHA-256(domain || action_digest || H(R))`` over the canonical render."""
    return _pca.unb64u(_approval.approval_challenge(b64u(build_step_up_challenge(pc_actn_or_digest)), render_digest))


def approval_challenge_for_actn(pc_actn_or_digest: Union[dict, str, bytes], render_digest: str) -> str:
    return b64u(build_approval_challenge(pc_actn_or_digest, render_digest))


def step_up_challenge_b64u(pc_actn_or_digest: Union[dict, str, bytes]) -> str:
    return b64u(build_step_up_challenge(pc_actn_or_digest))


# ---- assertion verification ------------------------------------------------------------------------------------------

def spc_payment_error(payment: Any, e: dict, rp_id: Any) -> Optional[str]:
    """None if the signed payment data equals the expectation (Secure Payment Confirmation / PSD2 dynamic linking), else why not."""
    p = _as_record(payment)
    if p is None:
        return "clientData.payment is missing"
    if "payeeName" not in e and "payeeOrigin" not in e:
        return "the expectation names no payee (refused: a payment approval must bind the payee)"
    if not _same(p.get("rpId", UNSET), rp_id):
        return "clientData.payment.rpId is not the verifier rpId"
    if not _same(p.get("topOrigin", UNSET), e.get("topOrigin", UNSET)):
        return "clientData.payment.topOrigin is not the verifier approval origin"
    total = _as_record(p.get("total"))
    if total is None or not _same(total.get("currency", UNSET), e["total"].get("currency", UNSET)) or \
            not _same(total.get("value", UNSET), e["total"].get("value", UNSET)):
        return "clientData.payment.total does not equal the canonical render"
    for k in ("payeeName", "payeeOrigin"):
        if k in e and not _same(p.get(k, UNSET), e[k]):
            return "clientData.payment.%s does not equal the canonical render" % k
    return None


def _is_uint32(v: Any) -> bool:
    if not is_number(v):
        return False
    if isinstance(v, float) and (not fin(v) or v != math.floor(v) or (v == 0 and math.copysign(1.0, v) < 0)):
        return False
    return 0 <= v <= 0xFFFFFFFF


def _fail(reason: str) -> dict:
    return {"ok": False, "reason": reason}


def _der_int(data: bytes) -> int:
    if data and data[0] & 128:
        raise ValueError("negative")
    if len(data) >= 1 and data[0] == 0 and not (len(data) > 1 and data[1] & 128):
        raise ValueError("unnecessary leading zero")
    return int.from_bytes(data, "big")


def _der_tlv(tag: int, data: bytes) -> Tuple[bytes, bytes]:
    if len(data) < 2 or data[0] != tag:
        raise ValueError("wrong tlv")
    first, pos = data[1], 2
    if not first & 128:
        length = first
    else:
        ll = first & 127
        if ll == 0 or ll > 4:
            raise ValueError("bad length of length")
        lb = data[pos:pos + ll]
        if len(lb) != ll or lb[0] == 0:
            raise ValueError("bad length bytes")
        if ll == 4 and lb[0] & 0x80:
            raise ValueError("length overflows 32 bits")
        length = int.from_bytes(lb, "big")
        pos += ll
        if length < 128:
            raise ValueError("not minimal encoding")
    v = data[pos:pos + length]
    if len(v) != length:
        raise ValueError("wrong value length")
    return v, data[pos + length:]


def _ecdsa_p256_verify(raw_point: bytes, signed_data: bytes, signature: bytes, is_der: bool, low_s: bool) -> bool:
    """ES256 over `signed_data`: a strictly-parsed DER or fixed 64-byte r||s signature, r and s in [1, n-1], optionally low-S."""
    try:
        if is_der:
            seq, left = _der_tlv(0x30, signature)
            if left:
                return False
            rb, rest = _der_tlv(0x02, seq)
            sb, left = _der_tlv(0x02, rest)
            if left:
                return False
            r, s = _der_int(rb), _der_int(sb)
        else:
            if len(signature) != 64:
                return False
            r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    except ValueError:
        return False
    if not (1 <= r < _P256_N and 1 <= s < _P256_N):
        return False
    if low_s and s > _P256_N >> 1:
        return False
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    try:
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(raw_point[1:33], "big"), int.from_bytes(raw_point[33:], "big"),
                                            ec.SECP256R1()).public_key()
        pub.verify(encode_dss_signature(r, s), signed_data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_assertion(assertion: dict, expect: dict) -> dict:
    """Verify a WebAuthn / FIDO2 assertion as a human step-up co-sign; FAIL CLOSED, never raises on hostile input.

    `assertion`: authenticator_data, client_data_json, signature (bytes) and public_key (a JWK dict or a raw COSE_Key).
    `expect`: expected_challenge (bytes or base64url), rp_id, origins, require_uv, the stored counter ``stored_sign_count``
    (REQUIRED: 0 for a credential never used), optional require_low_s, reject_cross_origin (default True), payment (SPC
    expectation: top_origin as ``topOrigin``, ``total``, ``payeeName`` / ``payeeOrigin``) and on_sign_count_regression
    (called once with {"storedSignCount", "reportedSignCount"} when the counter rule refuses a verified signature).
    Returns {"ok": True, "alg", "signCount", "flags"} or {"ok": False, "reason"}."""
    try:
        auth_data = assertion["authenticator_data"] if "authenticator_data" in assertion else None
        client_json = assertion["client_data_json"] if "client_data_json" in assertion else None
        signature = assertion["signature"] if "signature" in assertion else None
        public_key = assertion["public_key"] if "public_key" in assertion else None
        if not _is_bytes(auth_data):
            return _fail("authenticatorData is not bytes")
        if not _is_bytes(client_json):
            return _fail("clientDataJSON is not bytes")
        if not _is_bytes(signature):
            return _fail("signature is not bytes")
        if len(auth_data) > MAX_AUTHENTICATOR_DATA_BYTES:
            return _fail("authenticatorData is too large")
        if len(client_json) > MAX_CLIENT_DATA_BYTES:
            return _fail("clientDataJSON is too large")
        if len(signature) > MAX_SIGNATURE_BYTES:
            return _fail("signature is too large")
        rp_id = expect.get("rp_id")
        if not isinstance(rp_id, str) or len(rp_id) == 0:
            return _fail("rpId is required")
        origins = expect.get("origins")
        if not isinstance(origins, list) or len(origins) == 0:
            return _fail("origins allowlist is empty")
        if "stored_sign_count" not in expect:
            return _fail("storedSignCount is required (use 0 for a credential never used)")

        # clientDataJSON
        try:
            client_text = bytes(client_json).decode("utf-8-sig")  # a leading BOM is consumed, as TextDecoder does
        except UnicodeDecodeError:
            return _fail("clientDataJSON is not valid UTF-8")
        try:
            client_parsed = js_json_parse(client_text)
        except (ValueError, RecursionError):
            return _fail("clientDataJSON is not valid JSON")
        client = _as_record(client_parsed)
        if client is None:
            return _fail("clientDataJSON is not a JSON object")
        payment = expect.get("payment", UNSET)
        want_type = "webauthn.get" if payment is UNSET else "payment.get"
        if client.get("type") != want_type:
            return _fail('clientData.type is not "%s" (%s)' % (want_type, js_to_string(client["type"]) if "type" in client else "undefined"))
        if payment is not UNSET:
            pe = spc_payment_error(client.get("payment"), payment, rp_id)
            if pe:
                return _fail(pe)

        got_challenge = _pca.decode_b64u_strict(client.get("challenge"))  # canonical base64url only
        if got_challenge is None:
            return _fail("clientData.challenge is missing or not canonical base64url")
        exp_in = expect.get("expected_challenge")
        exp_challenge = bytes(exp_in) if _is_bytes(exp_in) else _pca.decode_b64u_strict(exp_in)
        if exp_challenge is None:
            return _fail("expectedChallenge is not decodable")
        if not _bytes_equal(got_challenge, exp_challenge):
            return _fail("clientData.challenge does not match the step-up challenge")

        origin = client.get("origin")
        if expect.get("reject_cross_origin") is not False:
            if "crossOrigin" in client:
                co = client["crossOrigin"]
                if co is True:
                    return _fail("clientData.crossOrigin is true")
                if co is not False:
                    return _fail("clientData.crossOrigin is not a boolean")
        if not isinstance(origin, str):
            return _fail("clientData.origin is missing")
        if not any(isinstance(o, str) and o == origin for o in origins):
            return _fail('clientData.origin "%s" is not in the allowlist' % origin)

        # authenticatorData
        parsed = parse_authenticator_data(auth_data)
        if parsed is None:
            return _fail("authenticatorData is too short (< 37 bytes)")
        if not _bytes_equal(parsed["rpIdHash"], hashlib.sha256(_utf8(rp_id)).digest()):
            return _fail("rpIdHash does not match sha256(rpId)")
        if not parsed["flags"]["up"]:
            return _fail("User Present (UP) flag is not set")
        if truthy(expect.get("require_uv")) and not parsed["flags"]["uv"]:
            return _fail("User Verified (UV) flag is required but not set")

        # signature over authenticatorData || sha256(clientDataJSON)
        signed_data = bytes(auth_data) + hashlib.sha256(bytes(client_json)).digest()
        try:
            alg, raw = _resolve_key(public_key)
        except Exception as e:  # noqa: BLE001 - any unusable key is a refusal carrying the reason
            return _fail("public key could not be resolved: %s" % e)

        sig = bytes(signature)
        if alg == "ES256":
            is_der = len(sig) > 0 and sig[0] == 0x30 and len(sig) != 64
            valid = _ecdsa_p256_verify(raw, signed_data, sig, is_der, expect.get("require_low_s") is True)
        else:
            # strict RFC 8032: canonical encodings, S < L, no small-order or mixed-order key or R
            valid = ed25519.verify(raw, signed_data, sig)
        if not valid:
            return _fail("assertion signature did not verify")

        # signature counter (clone detection), only after the signature verified so forged input cannot trigger the hook
        stored = expect["stored_sign_count"]
        if not _is_uint32(stored):
            return _fail("storedSignCount is not a uint32")
        if (parsed["signCount"] != 0 or stored != 0) and parsed["signCount"] <= stored:
            hook = expect.get("on_sign_count_regression")
            if callable(hook):
                hook({"storedSignCount": stored, "reportedSignCount": parsed["signCount"]})
            return _fail("signCount did not increase (possible cloned authenticator)")

        return {"ok": True, "alg": alg, "signCount": parsed["signCount"], "flags": parsed["flags"]}
    except Exception as e:  # noqa: BLE001 - fail closed on anything unforeseen
        return _fail("verification error (fail closed): %s" % e)
