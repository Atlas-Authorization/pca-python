"""BLS12-381 signature aggregation (IETF proof-of-possession ciphersuite), a rogue-key-safe key registry, the aggregated BLS
capability chain and aggregated witness cosignatures (the TypeScript reference, @atlasauth/pca-aggsig).

Backend: supranational blst through ctypes (atlas_pca.bls12): hash-to-curve, point arithmetic, subgroup checks, CoreVerify and the
pairing context are all blst's; nothing here implements a field, a curve or a pairing. The library is bound lazily (PCA_BLST_LIB or
the loader path); a missing one raises Bls12LibraryMissing, never a "bad input" result. Point multiplication is blst's constant-time
code, but the secret scalar itself passes through Python bytes and ints, which are not constant time, so every secret-key operation
(sign, pop_prove, public_key_of, key_gen, the cosign/mint/delegate helpers) still refuses until the caller opts in with
allow_insecure_bls_signer(True). Verification and aggregation work on public inputs only.
"""
from __future__ import annotations

import json
import secrets
from typing import Any, Dict, List, Optional

from . import bls12 as B
from .pca import b64u, canonical_bytes_strict, hash_canonical, unb64u

SIG_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
POP_DST = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
PUBLIC_KEY_LENGTH = 48
SIGNATURE_LENGTH = 96
BLS_SUITE = "bls12-381-pop"
MAX_CHAIN_DEPTH = 16
_R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001  # the BLS12-381 group order

_CAP_BLS_DOMAIN = b"atlas-pca/cap-bls/v1\x00"
_STH_WITNESS_BLS_DOMAIN = b"atlas-pca/sth-witness-bls/v1\x00"


AggsigBackendMissing = B.Bls12LibraryMissing  # libblst could not be loaded


_ALLOW_INSECURE_SIGNER = False
INSECURE_SIGNER_REFUSED = (
    "BLS signing handles the secret scalar in Python ints (not constant time); "
    "opt in with allow_insecure_bls_signer(True) only for tests or throwaway keys"
)


def allow_insecure_bls_signer(allow: bool = True) -> None:
    """Process-wide opt-in to the built-in, NOT constant time, secret-key arithmetic."""
    global _ALLOW_INSECURE_SIGNER
    _ALLOW_INSECURE_SIGNER = bool(allow)


def _require_signer() -> None:
    if not _ALLOW_INSECURE_SIGNER:
        raise RuntimeError(INSECURE_SIGNER_REFUSED)


def _bytes(v: Any, what: str) -> bytes:
    if not isinstance(v, (bytes, bytearray)):
        raise TypeError("%s: expected bytes" % what)
    return bytes(v)


def _is_compressed(b: Any, length: int) -> bool:
    return isinstance(b, (bytes, bytearray)) and len(b) == length and (b[0] & 0x80) != 0


def is_canonical_signature(sig: Any) -> bool:
    """A 96-byte compressed G2 point (canonical, on the curve, in the prime-order subgroup)."""
    if not _is_compressed(sig, SIGNATURE_LENGTH):
        return False
    try:
        B.G2.decode(bytes(sig))
        return True
    except ValueError:
        return False


def _sk_int(secret_key: Any) -> int:
    sk = _bytes(secret_key, "secret key")
    if len(sk) != 32:
        raise ValueError("invalid private key, expected 32 bytes, got %d" % len(sk))
    n = int.from_bytes(sk, "big")
    if not 1 <= n < _R:
        raise ValueError("expected valid private key: 1 <= n < %d, got %d" % (_R, n))
    return n


def public_key_of(secret_key: Any) -> bytes:
    _require_signer()
    return (B.G1.generator() * _sk_int(secret_key)).compress()


def key_gen() -> Dict[str, bytes]:
    _require_signer()
    sk = secrets.randbelow(_R - 1) + 1
    if sk == 1:
        raise RuntimeError("keyGen: entropy source produced the degenerate key 1 (RNG failure); refusing to continue")
    secret = sk.to_bytes(32, "big")
    return {"secret_key": secret, "public_key": public_key_of(secret)}


_KV_CACHE: Dict[bytes, bool] = {}


def key_validate(public_key: Any) -> bool:
    """KeyValidate: canonical compressed encoding, on curve, not the identity, in the prime-order subgroup."""
    if not _is_compressed(public_key, PUBLIC_KEY_LENGTH):
        return False
    pk = bytes(public_key)
    hit = _KV_CACHE.get(pk)
    if hit is not None:
        return hit
    try:
        ok = not B.G1.decode(pk).is_inf()
    except ValueError:
        ok = False
    if len(_KV_CACHE) < 4096:
        _KV_CACHE[pk] = ok
    return ok


def _sign_with(dst: str, sk: int, msg: bytes) -> bytes:
    return (B.G2.hash_to(msg, dst) * sk).compress()


def sign(secret_key: Any, msg: Any) -> bytes:
    _require_signer()
    return _sign_with(SIG_DST, _sk_int(secret_key), _bytes(msg, "message"))


def pop_prove(secret_key: Any) -> bytes:
    _require_signer()
    sk = _sk_int(secret_key)
    return _sign_with(POP_DST, sk, (B.G1.generator() * sk).compress())


def _core_verify(pk: bytes, msg: bytes, sig: bytes, pop: bool) -> bool:
    # blst's CoreVerify subgroup-checks the signature and refuses the identity key; the key was validated by the caller
    return B.core_verify(B.G1.decode(pk), B.G2.decode(sig), msg, POP_DST if pop else SIG_DST)


def verify(public_key: Any, msg: Any, sig: Any) -> bool:
    try:
        if not is_canonical_signature(sig):
            return False
        if not key_validate(public_key):
            return False
        return _core_verify(bytes(public_key), _bytes(msg, "message"), bytes(sig), False)
    except AggsigBackendMissing:
        raise
    except Exception:  # noqa: BLE001
        return False


def pop_verify(public_key: Any, pop: Any) -> bool:
    try:
        if not is_canonical_signature(pop):
            return False
        if not key_validate(public_key):
            return False
        return _core_verify(bytes(public_key), bytes(public_key), bytes(pop), True)
    except AggsigBackendMissing:
        raise
    except Exception:  # noqa: BLE001
        return False


def aggregate(sigs: Any) -> bytes:
    if not isinstance(sigs, (list, tuple)) or len(sigs) == 0:
        raise ValueError("aggregate: need at least one signature")
    for sg in sigs:
        if not is_canonical_signature(sg):
            raise ValueError("aggregate: every signature must be a 96-byte compressed G2 point")
    acc = B.G2.decode(bytes(sigs[0]))
    for sg in sigs[1:]:
        acc = acc + B.G2.decode(bytes(sg))
    return acc.compress()


def aggregate_public_keys(public_keys: Any) -> bytes:
    if not isinstance(public_keys, (list, tuple)) or len(public_keys) == 0:
        raise ValueError("aggregatePublicKeys: need at least one key")
    acc = B.G1.decode(_bytes(public_keys[0], "public key"))
    for pk in public_keys[1:]:
        acc = acc + B.G1.decode(_bytes(pk, "public key"))
    return acc.compress()


def _raw_aggregate_verify(public_keys: Any, msgs: Any, agg_sig: Any) -> bool:
    try:
        if not is_canonical_signature(agg_sig):
            return False
        if len(public_keys) == 0 or len(public_keys) != len(msgs):
            return False
        seen = set()
        for m in msgs:
            h = _bytes(m, "message")
            if h in seen:
                return False
            seen.add(h)
        for pk in public_keys:
            if not key_validate(pk):
                return False
        return B.aggregate_verify([B.G1.decode(bytes(k)) for k in public_keys], [bytes(m) for m in msgs], B.G2.decode(bytes(agg_sig)), SIG_DST)
    except AggsigBackendMissing:
        raise
    except Exception:  # noqa: BLE001
        return False


def _raw_fast_aggregate_verify(public_keys: Any, msg: Any, agg_sig: Any) -> bool:
    try:
        if not is_canonical_signature(agg_sig):
            return False
        if len(public_keys) == 0:
            return False
        for pk in public_keys:
            if not key_validate(pk):
                return False
        agg_pk = aggregate_public_keys(list(public_keys))
        if not key_validate(agg_pk):
            return False
        return _core_verify(agg_pk, _bytes(msg, "message"), bytes(agg_sig), False)
    except AggsigBackendMissing:
        raise
    except Exception:  # noqa: BLE001
        return False


# ---- registry: only keys admitted through a proof of possession may enter an aggregate (rogue-key defence)

_TOKEN = object()


class RegisteredKey:
    """A public key that passed KeyValidate and proof of possession. Not constructible directly: use register_key()."""

    __slots__ = ("_bytes",)

    def __init__(self, token: Any, key: bytes) -> None:
        if token is not _TOKEN:
            raise TypeError("RegisteredKey cannot be constructed directly; use register_key(public_key, pop)")
        object.__setattr__(self, "_bytes", bytes(key))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("RegisteredKey is immutable")

    @property
    def bytes(self) -> bytes:
        return self._bytes


def register_key(public_key: Any, pop: Any) -> Dict[str, Any]:
    """{"ok": True, "key": RegisteredKey} or {"ok": False, "reason": str}."""
    if not isinstance(public_key, (bytes, bytearray)) or not isinstance(pop, (bytes, bytearray)):
        return {"ok": False, "reason": "public key and proof of possession must be Uint8Arrays"}
    if not key_validate(public_key):
        return {"ok": False, "reason": "public key fails KeyValidate (not a canonical, non-identity, prime-order G1 point)"}
    if len(pop) != SIGNATURE_LENGTH:
        return {"ok": False, "reason": "proof of possession is not a 96-byte compressed G2 signature"}
    if not pop_verify(public_key, pop):
        return {"ok": False, "reason": "proof of possession does not verify for this key"}
    return {"ok": True, "key": RegisteredKey(_TOKEN, bytes(public_key))}


def is_registered_key(x: Any) -> bool:
    return isinstance(x, RegisteredKey)


class KeyRegistry:
    def __init__(self) -> None:
        self._keys: Dict[str, RegisteredKey] = {}

    def register(self, public_key: Any, pop: Any) -> Dict[str, Any]:
        r = register_key(public_key, pop)
        if r["ok"]:
            self._keys[bytes(public_key).hex()] = r["key"]
        return r

    def get(self, public_key: Any) -> Optional[RegisteredKey]:
        if isinstance(public_key, (bytes, bytearray)) and len(public_key) == PUBLIC_KEY_LENGTH:
            return self._keys.get(bytes(public_key).hex())
        return None

    def has(self, public_key: Any) -> bool:
        return self.get(public_key) is not None

    @property
    def size(self) -> int:
        return len(self._keys)


def check_registered(keys: Any) -> Optional[str]:
    if not isinstance(keys, (list, tuple)):
        return "keys must be an array of RegisteredKey"
    if len(keys) == 0:
        return "no keys"
    for i, k in enumerate(keys):
        if not is_registered_key(k):
            return "key %d is not a registered key: it was not admitted through registerKey (proof of possession)" % i
    return None


def aggregate_verify(keys: Any, msgs: Any, agg_sig: Any) -> bool:
    if check_registered(keys) is not None:
        return False
    return _raw_aggregate_verify([k.bytes for k in keys], msgs, agg_sig)


def fast_aggregate_verify(keys: Any, msg: Any, agg_sig: Any) -> bool:
    if check_registered(keys) is not None:
        return False
    seen = set()
    for k in keys:
        if k.bytes in seen:
            return False
        seen.add(k.bytes)
    return _raw_fast_aggregate_verify([k.bytes for k in keys], msg, agg_sig)


# ---- BLS capability chain (one aggregate signature over every hop)

def _body_of(c: Dict[str, Any]) -> Dict[str, Any]:
    parent = c.get("parent")
    return {"issuer": c["issuer"], "holder": c["holder"], "caveats": c["caveats"], "parent": None if parent is None else parent}


def _sig_message(body_digest: str) -> bytes:
    return _CAP_BLS_DOMAIN + unb64u(body_digest)


def cap_hash(c: Dict[str, Any]) -> str:
    """base64url(sha256(strict canonical of the capability without its signature))."""
    return hash_canonical({k: v for k, v in c.items() if k != "sig"})


def _clone_caveats(cs: Any) -> List[Any]:
    return json.loads(canonical_bytes_strict(cs).decode("utf-8"))


def _seal(body: Dict[str, Any], signer_secret: Any) -> Dict[str, Any]:
    body_digest = hash_canonical(_body_of(body))
    sig = b64u(sign(signer_secret, _sig_message(body_digest)))
    cap: Dict[str, Any] = {
        "id": body_digest, "issuer": body["issuer"], "holder": body["holder"], "caveats": body["caveats"],
        "body_digest": body_digest, "sig": sig, "suite": BLS_SUITE,
    }
    if "parent" in body:
        cap["parent"] = body["parent"]
    return cap


def bls_public_key(secret_key: Any) -> str:
    return b64u(public_key_of(secret_key))


def mint_bls_root(principal_secret: Any, principal_public: str, holder: str, caveats: Any) -> Dict[str, Any]:
    return _seal({"issuer": principal_public, "holder": holder, "caveats": _clone_caveats(caveats)}, principal_secret)


def bls_delegate(parent: Dict[str, Any], to_holder: str, added_caveats: Any, signer_secret: Any) -> Dict[str, Any]:
    return _seal(
        {
            "issuer": parent["holder"],
            "holder": to_holder,
            "caveats": _clone_caveats(parent["caveats"]) + _clone_caveats(added_caveats),
            "parent": cap_hash(parent),
        },
        signer_secret,
    )


def bls_attenuate(parent: Dict[str, Any], added_caveats: Any, signer_secret: Any) -> Dict[str, Any]:
    return bls_delegate(parent, parent["holder"], added_caveats, signer_secret)


def _well_typed(c: Any) -> bool:
    if not isinstance(c, dict):
        return False
    for k in ("id", "issuer", "holder", "body_digest", "sig"):
        if not isinstance(c.get(k), str):
            return False
    if c.get("suite") != BLS_SUITE:
        return False
    if "parent" in c and not isinstance(c["parent"], str):
        return False
    cav = c.get("caveats")
    if not isinstance(cav, list):
        return False
    return all(isinstance(cv, dict) and isinstance(cv.get("type"), str) for cv in cav)


def aggregate_chain_signatures(chain: Any) -> bytes:
    if not isinstance(chain, list) or len(chain) == 0:
        raise ValueError("aggregateChainSignatures: empty chain")
    return aggregate([unb64u(c["sig"]) for c in chain])


def verify_aggregated_chain(chain: Any, agg_sig: Any, registry: Any, expected_root_principal: Optional[str] = None) -> Dict[str, Any]:
    def no(reason: str) -> Dict[str, Any]:
        return {"ok": False, "reason": reason}

    if registry is None or not callable(getattr(registry, "get", None)):
        return no("a KeyRegistry of proof-of-possession-verified keys is required")
    if not isinstance(chain, list) or len(chain) == 0:
        return no("empty chain")
    if len(chain) > MAX_CHAIN_DEPTH:
        return no("chain too long (max %d hops)" % MAX_CHAIN_DEPTH)
    for i, c in enumerate(chain):
        if not _well_typed(c):
            return no("hop %d: malformed capability" % i)

    pks: List[RegisteredKey] = []
    msgs: List[bytes] = []
    root = chain[0]
    if "parent" in root:
        return no("hop 0: root must not have a parent")
    if expected_root_principal is not None and root["issuer"] != expected_root_principal:
        return no("hop 0: root issuer is not the expected principal")

    for i, c in enumerate(chain):
        try:
            digest = hash_canonical(_body_of(c))
        except Exception:  # noqa: BLE001
            return no("hop %d: malformed body" % i)
        if digest != c["body_digest"] or c["id"] != c["body_digest"]:
            return no("hop %d: body digest mismatch" % i)
        try:
            pk = registry.get(unb64u(c["issuer"]))
        except Exception:  # noqa: BLE001
            return no("hop %d: malformed issuer key" % i)
        if pk is None:
            return no("hop %d: issuer key has no verified proof of possession (not in the registry)" % i)
        if i > 0:
            parent = chain[i - 1]
            if c.get("parent") != cap_hash(parent):
                return no("hop %d: broken parent link" % i)
            if c["issuer"] != parent["holder"]:
                return no("hop %d: issuer is not the parent's bound holder" % i)
            if len(c["caveats"]) < len(parent["caveats"]):
                return no("hop %d: drops parent caveat(s)" % i)
            for j in range(len(parent["caveats"])):
                if hash_canonical(c["caveats"][j]) != hash_canonical(parent["caveats"][j]):
                    return no("hop %d: caveat %d altered or reordered" % (i, j))
        pks.append(pk)
        msgs.append(_sig_message(c["body_digest"]))

    try:
        for i, c in enumerate(chain):
            raw = unb64u(c["sig"])
            if b64u(raw) != c["sig"]:
                return no("hop %d: non-canonical sig encoding" % i)
        total = aggregate([unb64u(c["sig"]) for c in chain])
        if total != _bytes(agg_sig, "aggregate signature"):
            return no("hop sig fields do not sum to the aggregate signature")
    except Exception:  # noqa: BLE001
        return no("malformed hop sig")

    if not aggregate_verify(pks, msgs, agg_sig):
        return no("aggregate signature does not verify over all hops")
    return {"ok": True}


# ---- witnesses: BLS cosignatures over a signed tree head, aggregable into one signature

def _witness_message(h: Dict[str, Any]) -> bytes:
    for k in ("size", "root", "prev_root"):
        if k not in h:
            raise TypeError("canonicalize: undefined value for %s" % k)
    epoch = h.get("guardian_epoch")
    body = {"size": h["size"], "root": h["root"], "prev_root": h["prev_root"], "guardian_epoch": 0 if epoch is None else epoch}
    return _STH_WITNESS_BLS_DOMAIN + canonical_bytes_strict(body)


def cosign_tree_head(statement: Dict[str, Any], witness_secret: Any) -> Dict[str, str]:
    return {
        "key": b64u(public_key_of(witness_secret)),
        "sig": b64u(sign(witness_secret, _witness_message(statement))),
        "suite": BLS_SUITE,
    }


def verify_witness_cosignature(statement: Dict[str, Any], cosig: Any) -> bool:
    try:
        if not isinstance(cosig, dict) or cosig.get("suite") != BLS_SUITE:
            return False
        return verify(unb64u(cosig["key"]), _witness_message(statement), unb64u(cosig["sig"]))
    except AggsigBackendMissing:
        raise
    except Exception:  # noqa: BLE001
        return False


def aggregate_witness_cosignatures(cosigs: Any) -> bytes:
    if not isinstance(cosigs, list) or len(cosigs) == 0:
        raise ValueError("aggregateWitnessCosignatures: empty set")
    return aggregate([unb64u(c["sig"]) for c in cosigs])


def verify_aggregated_witness_cosignatures(statement: Dict[str, Any], witness_keys: Any, agg_sig: Any) -> bool:
    try:
        if not isinstance(witness_keys, (list, tuple)) or len(witness_keys) == 0:
            return False
        if len({k.bytes for k in witness_keys}) != len(witness_keys):
            return False
        return fast_aggregate_verify(witness_keys, _witness_message(statement), agg_sig)
    except AggsigBackendMissing:
        raise
    except Exception:  # noqa: BLE001
        return False
