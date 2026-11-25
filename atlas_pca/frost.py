"""FROST(Ed25519, SHA-512) threshold signing (RFC 9591): trusted-dealer key split, round-1 commit, round-2 sign, share-verified
aggregation and the in-process quorum cosign, native port of the TypeScript reference. The aggregate is an ordinary RFC 8032 Ed25519
signature under the group key.

Group and scalar arithmetic run in libsodium (system libsodium >= 1.0.18, reached through the handle pysodium loads; install the
`ristretto` extra): points are 32-byte Ed25519 encodings, every secret scalar is a 32-byte string combined with the
crypto_core_ed25519_scalar_* functions, never a Python int. Python ints appear only for public values (participant identifiers and
the Lagrange coefficients derived from them). libsodium refuses the identity and every small-order or mixed-order point; the
identity (a zero scalar times a point) is carried as None and encoded as the canonical identity encoding where the reference does."""
from __future__ import annotations

import ctypes
import hashlib
import os
from typing import Any, Dict, List, Optional

from . import ed25519 as _ed

L = _ed._q
CONTEXT_STRING = b"FROST-ED25519-SHA512-v1"
_SPENT: Dict[bytes, None] = {}
SPENT_COMMITMENT_CAP = 262_144
_ZERO = bytes(32)
_IDENTITY_ENC = b"\x01" + bytes(31)
_lib: Any = None


def _sodium() -> Any:
    global _lib
    if _lib is None:
        try:
            from ._sodium_path import prefer_bundled
            with prefer_bundled():
                import pysodium
        except ImportError as e:
            raise RuntimeError("FROST needs libsodium through pysodium (pip install 'atlas-pca[ristretto]')") from e
        lib = pysodium.sodium
        if lib.sodium_init() < 0:
            raise RuntimeError("libsodium failed to initialise")
        _lib = lib
    return _lib


def _buf(n: int = 32) -> Any:
    return ctypes.create_string_buffer(n)


# ---- scalars: 32-byte little-endian strings -------------------------------------------------------------------------------

def _c32(x: Any) -> bytes:
    """A 32-byte string for a libsodium call: anything else would be passed on as a bad pointer (a crash), so it is refused first."""
    if not isinstance(x, (bytes, bytearray)) or len(x) != 32:
        raise ValueError("frost: expected 32 bytes")
    return bytes(x)


def _sc2(fn: str, a: bytes, b: bytes) -> bytes:
    a, b = _c32(a), _c32(b)
    r = _buf()
    getattr(_sodium(), "crypto_core_ed25519_scalar_" + fn)(r, a, b)
    return r.raw


def sc_add(a: bytes, b: bytes) -> bytes:
    return _sc2("add", a, b)


def sc_mul(a: bytes, b: bytes) -> bytes:
    return _sc2("mul", a, b)


def reduce_bytes(b: bytes) -> bytes:
    """Reduce 0..64 little-endian bytes mod L (the reference's bytesToScalar); more than 64 bytes is refused."""
    if len(b) > 64:
        raise ValueError("frost: scalar input longer than 64 bytes")
    r = _buf()
    _sodium().crypto_core_ed25519_scalar_reduce(r, bytes(b) + bytes(64 - len(b)))
    return r.raw


def int_scalar(i: int) -> bytes:
    """A PUBLIC integer (identifier, Lagrange coefficient) as a scalar."""
    return (i % L).to_bytes(32, "little")


def scalar_to_bytes(s: Any) -> bytes:
    return reduce_bytes(s) if isinstance(s, (bytes, bytearray)) else int_scalar(s)


def bytes_to_scalar(b: bytes) -> bytes:
    return reduce_bytes(bytes(b))


def is_canonical_scalar(b: Any) -> bool:
    return isinstance(b, (bytes, bytearray)) and len(b) == 32 and int.from_bytes(b, "little") < L


def _is_id(i: Any) -> bool:
    return isinstance(i, int) and not isinstance(i, bool) and 0 < i <= 9007199254740991


def _h2s(m: bytes) -> bytes:
    return reduce_bytes(hashlib.sha512(m).digest())


def h1(m: bytes) -> bytes:
    return _h2s(CONTEXT_STRING + b"rho" + m)


def h2(m: bytes) -> bytes:
    return _h2s(m)


def h3(m: bytes) -> bytes:
    return _h2s(CONTEXT_STRING + b"nonce" + m)


def h4(m: bytes) -> bytes:
    return hashlib.sha512(CONTEXT_STRING + b"msg" + m).digest()


def h5(m: bytes) -> bytes:
    return hashlib.sha512(CONTEXT_STRING + b"com" + m).digest()


# ---- points: 32-byte encodings; None is the identity ----------------------------------------------------------------------

def _enc(p: Optional[bytes]) -> bytes:
    return _IDENTITY_ENC if p is None else p


def _mul_base(s: bytes) -> Optional[bytes]:
    s = reduce_bytes(s)
    if s == _ZERO:
        return None
    q = _buf()
    if _sodium().crypto_scalarmult_ed25519_base_noclamp(q, s) != 0:
        raise ValueError("frost: base-point multiplication refused")
    return q.raw


def _mul_pt(p: Optional[bytes], s: bytes) -> Optional[bytes]:
    s = reduce_bytes(s)
    if p is None or s == _ZERO:
        return None
    p = _c32(p)
    q = _buf()
    if _sodium().crypto_scalarmult_ed25519_noclamp(q, s, p) != 0:
        raise ValueError("frost: point multiplication refused")
    return q.raw


def _padd(a: Optional[bytes], b: Optional[bytes]) -> Optional[bytes]:
    if a is None:
        return b
    if b is None:
        return a
    a, b = _c32(a), _c32(b)
    r = _buf()
    if _sodium().crypto_core_ed25519_add(r, a, b) != 0:
        raise ValueError("frost: point addition refused")
    return None if r.raw == _IDENTITY_ENC else r.raw


def decode_safe_point(b: Any) -> bytes:
    """Strict check of any point a caller can influence: 32 bytes, canonical, on the curve, not small order (so not the identity),
    in the prime-order subgroup. Returns the canonical encoding."""
    if not isinstance(b, (bytes, bytearray)) or len(b) != 32:
        raise ValueError("frost: point must be 32 bytes")
    b = bytes(b)
    # libsodium 1.0.20 and older accept a mixed-order point (their subgroup test reads only X of L*P), so the group law decides first
    if not _ed.is_safe_point_bytes(b) or _sodium().crypto_core_ed25519_is_valid_point(b) != 1:
        raise ValueError("frost: point rejected (not canonical, off the curve, small order or not in the prime-order subgroup)")
    return b


def _validate_commitments(lst: Any, threshold: Optional[int] = None) -> None:
    if not isinstance(lst, list) or not lst:
        raise ValueError("frost: empty commitment list")
    if threshold is not None:
        if not _is_id(threshold):
            raise ValueError("frost: invalid threshold")
        if len(lst) < threshold:
            raise ValueError("frost: need at least t=%d commitments (got %d)" % (threshold, len(lst)))
    seen = set()
    for c in lst:
        if not isinstance(c, dict):
            raise ValueError("frost: malformed commitment")
        if not _is_id(c.get("identifier")):
            raise ValueError("frost: participant identifier must be a positive safe integer")
        if c["identifier"] in seen:
            raise ValueError("frost: duplicate commitment identifier %d" % c["identifier"])
        seen.add(c["identifier"])
        decode_safe_point(c.get("hiding"))
        decode_safe_point(c.get("binding"))


def trusted_dealer_keygen(t: int, n: int, secret: Optional[bytes] = None, coefficients: Optional[List[bytes]] = None,
                          identifiers: Optional[List[int]] = None) -> Dict[str, Any]:
    """t-of-n split: {groupPublicKey, participantShares: [{identifier, share, publicKey}], groupCommitment}."""
    if not (isinstance(t, int) and isinstance(n, int) and 1 <= t <= n):
        raise ValueError("frostTrustedDealerKeygen: need 1 <= t <= n (got t=%s, n=%s)" % (t, n))
    ids = identifiers if identifiers is not None else list(range(1, n + 1))
    if len(ids) != n:
        raise ValueError("frostTrustedDealerKeygen: identifiers.length must equal n")
    if len(set(ids)) != n:
        raise ValueError("frostTrustedDealerKeygen: identifiers must be distinct")
    if any(not isinstance(x, int) or isinstance(x, bool) or x <= 0 for x in ids):
        raise ValueError("frostTrustedDealerKeygen: identifiers must be positive integers")
    coeffs = [reduce_bytes(secret if secret is not None else os.urandom(32))]
    for i in range(1, t):
        c = coefficients[i - 1] if coefficients is not None and i - 1 < len(coefficients) else None
        coeffs.append(reduce_bytes(c if c is not None else os.urandom(32)))
    shares = []
    for i in ids:
        x, acc = int_scalar(i), _ZERO
        for a in reversed(coeffs):  # Horner on secret scalars
            acc = sc_add(sc_mul(acc, x), a)
        shares.append({"identifier": i, "share": acc, "publicKey": _enc(_mul_base(acc))})
    commit_ = [_enc(_mul_base(a)) for a in coeffs]
    return {"groupPublicKey": commit_[0], "participantShares": shares, "groupCommitment": commit_}


def verifying_share(share: bytes) -> bytes:
    return _enc(_mul_base(reduce_bytes(share)))


def commit(participant_share: Dict[str, Any], hiding_randomness: Optional[bytes] = None, binding_randomness: Optional[bytes] = None) -> Dict[str, Any]:
    """Round 1: a fresh (hiding, binding) nonce pair and the public commitments."""
    hr = hiding_randomness if hiding_randomness is not None else os.urandom(32)
    br = binding_randomness if binding_randomness is not None else os.urandom(32)
    for r in (hr, br):
        if len(r) != 32:
            raise ValueError("frostCommit: nonce randomness must be 32 bytes")
    sk = reduce_bytes(participant_share["share"])
    hn, bn = h3(bytes(hr) + sk), h3(bytes(br) + sk)
    return {"hidingNonce": hn, "bindingNonce": bn,
            "commitment": {"identifier": participant_share["identifier"], "hiding": _enc(_mul_base(hn)), "binding": _enc(_mul_base(bn))}}


def _sorted(lst: List[dict]) -> List[dict]:
    return sorted(lst, key=lambda c: c["identifier"])


def _binding_factors(group_pk: bytes, lst: List[dict], msg: bytes) -> Dict[int, bytes]:
    enc = b"".join(int_scalar(c["identifier"]) + bytes(c["hiding"]) + bytes(c["binding"]) for c in lst)
    prefix = bytes(group_pk) + h4(msg) + h5(enc)
    return {c["identifier"]: h1(prefix + int_scalar(c["identifier"])) for c in lst}


def _group_commitment(lst: List[dict], bf: Dict[int, bytes]) -> Optional[bytes]:
    r = None
    for c in lst:
        r = _padd(_padd(r, decode_safe_point(c["hiding"])), _mul_pt(decode_safe_point(c["binding"]), bf[c["identifier"]]))
    return r


def _lambda(participants: List[int], i: int) -> bytes:
    """Lagrange coefficient at zero: public integers only."""
    if i not in participants:
        raise ValueError("frost: identifier not in participant list")
    num = den = 1
    for j in participants:
        if j != i:
            num = num * j % L
            den = den * (j - i) % L
    if den == 0:
        raise ValueError("frost: modular inverse of zero")
    lam = num * pow(den, L - 2, L) % L
    if lam == 0:
        raise ValueError("frost: zero Lagrange coefficient")
    return int_scalar(lam)


def sign(identifier: int, share: bytes, group_public_key: bytes, nonces: Dict[str, bytes], message: bytes, signing_commitments: List[dict],
         threshold: Optional[int] = None, verification_share: Optional[bytes] = None, verification_shares: Optional[List[dict]] = None) -> Dict[str, Any]:
    """Round 2: this participant's signature share. One-shot: a nonce pair (and its public commitments) signs once, ever."""
    if not _is_id(identifier):
        raise ValueError("frost: participant identifier must be a positive safe integer")
    _validate_commitments(signing_commitments, threshold)
    decode_safe_point(group_public_key)
    hn, bn = bytes(nonces["hiding"]), bytes(nonces["binding"])
    if not any(hn) or not any(bn):
        raise ValueError("frostSign: zero/zeroized nonce")
    if hn == bn:
        raise ValueError("frostSign: hiding and binding nonce must differ")
    lst = _sorted(signing_commitments)
    mine = next((c for c in lst if c["identifier"] == identifier), None)
    if mine is None:
        raise ValueError("frostSign: this identifier has no commitment in the set")
    hiding, binding, sk = reduce_bytes(hn), reduce_bytes(bn), reduce_bytes(share)
    if _enc(_mul_base(hiding)) != bytes(mine["hiding"]) or _enc(_mul_base(binding)) != bytes(mine["binding"]):
        raise ValueError("frostSign: own commitment does not match nonces")
    keys = (b"h" + bytes(mine["hiding"]), b"b" + bytes(mine["binding"]))
    if any(k in _SPENT for k in keys):
        raise ValueError("frostSign: nonces already used (one-shot; reuse would leak the signing share)")
    if verification_share is not None and _enc(_mul_base(sk)) != decode_safe_point(verification_share):
        raise ValueError("frostSign: share does not match verification share")
    participants = [c["identifier"] for c in lst]
    if verification_shares is not None:
        acc = None
        for pid in participants:
            vs = next((v for v in verification_shares if v["identifier"] == pid), None)
            if vs is None:
                raise ValueError("frostSign: missing verification share for %d" % pid)
            acc = _padd(acc, _mul_pt(decode_safe_point(vs["publicKey"]), _lambda(participants, pid)))
        if _enc(acc) != decode_safe_point(group_public_key):
            raise ValueError("frostSign: group public key does not match the verification shares")
    bf = _binding_factors(group_public_key, lst, message)
    r = _group_commitment(lst, bf)
    c = h2(_enc(r) + bytes(group_public_key) + message)
    z = sc_add(sc_add(hiding, sc_mul(binding, bf[identifier])), sc_mul(sc_mul(_lambda(participants, identifier), sk), c))
    for k in keys:
        _SPENT[k] = None
    while len(_SPENT) > SPENT_COMMITMENT_CAP:
        _SPENT.pop(next(iter(_SPENT)))
    return {"identifier": identifier, "sigShare": z}


def verify_sig_share(identifier: int, public_key: bytes, commitment: dict, sig_share: dict, signing_commitments: List[dict],
                     group_public_key: bytes, message: bytes) -> bool:
    try:
        _validate_commitments(signing_commitments)
        lst = _sorted(signing_commitments)
        bf = _binding_factors(group_public_key, lst, message)
        if identifier not in bf:
            return False
        r = _group_commitment(lst, bf)
        comm_share = _padd(decode_safe_point(commitment["hiding"]), _mul_pt(decode_safe_point(commitment["binding"]), bf[identifier]))
        c = h2(_enc(r) + bytes(group_public_key) + message)
        lam = _lambda([x["identifier"] for x in lst], identifier)
        if not is_canonical_scalar(sig_share["sigShare"]):
            return False
        lhs = _mul_base(bytes(sig_share["sigShare"]))
        rhs = _padd(comm_share, _mul_pt(decode_safe_point(public_key), sc_mul(c, lam)))
        return _enc(lhs) == _enc(rhs)
    except Exception:  # noqa: BLE001
        return False


def aggregate(message: bytes, signing_commitments: List[dict], sig_shares: List[dict], group_public_key: bytes,
              verification_shares: List[dict], threshold: Optional[int] = None) -> bytes:
    """Verify every signature share, sum them and return the 64-byte Ed25519 signature; raises unless it verifies."""
    _validate_commitments(signing_commitments, threshold)
    decode_safe_point(group_public_key)
    lst = _sorted(signing_commitments)
    if not isinstance(sig_shares, list) or len(sig_shares) != len(lst):
        raise ValueError("frostAggregate: need exactly one signature share per commitment")
    seen = set()
    for s in sig_shares:
        if not any(c["identifier"] == s["identifier"] for c in lst):
            raise ValueError("frostAggregate: share from non-signer")
        if s["identifier"] in seen:
            raise ValueError("frostAggregate: duplicate signature share")
        seen.add(s["identifier"])
    if not isinstance(verification_shares, list):
        raise ValueError("frostAggregate: verificationShares are required (every signature share is verified before aggregation)")
    for s in sig_shares:
        vs = next((v for v in verification_shares if v["identifier"] == s["identifier"]), None)
        com = next(c for c in lst if c["identifier"] == s["identifier"])
        if vs is None or not verify_sig_share(s["identifier"], vs["publicKey"], com, s, lst, group_public_key, message):
            raise ValueError("frostAggregate: invalid signature share from participant %d" % s["identifier"])
    r = _group_commitment(lst, _binding_factors(group_public_key, lst, message))
    z = _ZERO
    for s in sig_shares:
        z = sc_add(z, reduce_bytes(s["sigShare"]))
    sig = _enc(r) + z
    if not _ed.verify(bytes(group_public_key), message, sig):
        raise ValueError("frostAggregate: aggregate signature does not verify (a share is invalid)")
    return sig


def cosign(group_public_key: bytes, quorum: List[dict], message: bytes, threshold: Optional[int] = None) -> bytes:
    """Run the whole protocol in process for a quorum of participant shares (the dealer / guardian-tier path)."""
    if not isinstance(quorum, list) or not quorum:
        raise ValueError("frostCosign: empty signing quorum")
    if threshold is not None and len(quorum) < threshold:
        raise ValueError("frostCosign: quorum of %d is below the threshold t=%d" % (len(quorum), threshold))
    ids = set()
    for p in quorum:
        if not _is_id(p["identifier"]):
            raise ValueError("frost: participant identifier must be a positive safe integer")
        if p["identifier"] in ids:
            raise ValueError("frostCosign: duplicate participant %d in quorum" % p["identifier"])
        ids.add(p["identifier"])
    vss = [{"identifier": p["identifier"], "publicKey": p["publicKey"]} for p in quorum]
    commits = [commit(p) for p in quorum]
    comms = [c["commitment"] for c in commits]
    shares = [sign(p["identifier"], p["share"], group_public_key, {"hiding": commits[i]["hidingNonce"], "binding": commits[i]["bindingNonce"]},
                   message, comms, threshold=threshold, verification_share=p["publicKey"], verification_shares=vss) for i, p in enumerate(quorum)]
    return aggregate(message, comms, shares, group_public_key, vss, threshold=threshold)
