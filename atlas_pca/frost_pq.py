"""FROST post-quantum composition: the group-algorithm registry (``ed25519`` | ``hybrid-ed25519-ml-dsa-65``), the signer-set digest, the HYBRID co-sign (the
FROST Ed25519 aggregate PLUS a guardian ML-DSA-65 signature over a representative that binds the group key, sha256(message) and the signer set) and its
verifier, and the PQ quorum block (t ML-DSA-65 signatures by distinct pooled keys over ``domain || sha256(message)``; the representative, the pool
normalisation and the verifier are :mod:`atlas_pca.pq_threshold`'s, re-exported). A port of the reference ``frost-pq`` module."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from . import frost as F
from .agent import PqKeyPair, sign_with_suite
from .intent_v2 import _js_string
from .pca import b64u, canonical_bytes_strict, decode_b64u_strict, verify_leaf_suite
from .pq_threshold import (MAX_PQ_QUORUM_ENTRIES, PQ_QUORUM_ALG, PQ_QUORUM_VERSION, normalize_pq_quorum_pool, pq_quorum_representative, verify_pq_quorum)

__all__ = ["DEFAULT_FROST_GROUP_ALG", "PQ_QUORUM_VERSION", "PQ_QUORUM_ALG", "MAX_PQ_QUORUM_ENTRIES", "resolve_frost_group_alg", "frost_signer_set_digest",
           "frost_cosign_representative", "sign_hybrid_frost_cosign", "verify_hybrid_frost_cosign", "pq_quorum_representative", "sign_pq_quorum",
           "normalize_pq_quorum_pool", "verify_pq_quorum"]

DEFAULT_FROST_GROUP_ALG = "ed25519"
_KNOWN = ("ed25519", "hybrid-ed25519-ml-dsa-65")
_COSIGN_DOMAIN = b"atlas-pca/frost-pq-cosign/v1\0"
_SIGNER_SET_DOMAIN = b"atlas-pca/frost-signer-set/v1\0"
_ML_DSA_65_PK_BYTES = 1952


def _known(x: Any) -> bool:
    return isinstance(x, str) and x in _KNOWN


def resolve_frost_group_alg(*group_alg: Any) -> Optional[str]:
    """The group algorithm a signature names: none given is the default, a known name itself, anything else None (refused). Called with no argument
    for "absent"."""
    if not group_alg:
        return DEFAULT_FROST_GROUP_ALG
    return group_alg[0] if _known(group_alg[0]) else None


def frost_signer_set_digest(signer_set: Any) -> bytes:
    """sha256(domain || canonical JSON of the sorted distinct participant ids). Raises for an empty set or an id that is not a positive safe integer."""
    if not isinstance(signer_set, list) or len(signer_set) == 0:
        raise ValueError("frostSignerSetDigest: empty signer set")
    ids = list(dict.fromkeys(signer_set))
    for i in ids:
        if isinstance(i, bool) or not isinstance(i, (int, float)) or i != int(i) or not (0 < i <= 9007199254740991):
            raise ValueError("frostSignerSetDigest: participant identifiers must be positive safe integers")
    ids = sorted(int(i) for i in ids)
    return hashlib.sha256(_SIGNER_SET_DOMAIN + canonical_bytes_strict(ids)).digest()


def frost_cosign_representative(group_public_key_b64u: Any, message: bytes, signer_set: Any, group_alg: str) -> bytes:
    """The bytes the guardian ML-DSA co-signature covers: domain || groupAlg || 0x00 || groupPublicKey || sha256(message) || signer-set digest."""
    gpk = decode_b64u_strict(group_public_key_b64u, 32)
    if gpk is None:
        raise ValueError("frostCosignRepresentative: groupPublicKey must be a 32-byte base64url point")
    return _COSIGN_DOMAIN + _js_string(group_alg).encode("utf-8") + b"\x00" + gpk + hashlib.sha256(bytes(message)).digest() + frost_signer_set_digest(signer_set)


def sign_hybrid_frost_cosign(group_public_key: bytes, quorum: List[dict], message: bytes, opts: Optional[dict] = None) -> Dict[str, Any]:
    """Run the quorum in process and return ``{"sig"}`` (classical) or ``{"sig", "groupAlg", "pq_sig", "pq_pk"}``. ``opts``: ``groupAlg`` (default ed25519),
    ``guardianMlDsa`` (a :class:`PqKeyPair`; required for the hybrid algorithm), ``threshold``."""
    opts = opts or {}
    group_alg = opts["groupAlg"] if opts.get("groupAlg") is not None else DEFAULT_FROST_GROUP_ALG
    if not _known(group_alg):
        raise ValueError("signHybridFrostCosign: unknown groupAlg '%s'" % _js_string(group_alg))
    aggregate = F.cosign(group_public_key, quorum, message, opts.get("threshold"))
    sig = b64u(aggregate)
    if group_alg == "ed25519":
        return {"sig": sig}
    pq: Optional[PqKeyPair] = opts.get("guardianMlDsa")
    if pq is None:
        raise TypeError("signHybridFrostCosign: '%s' requires a guardian ML-DSA-65 key pair" % group_alg)
    rep = frost_cosign_representative(b64u(bytes(group_public_key)), message, [p["identifier"] for p in quorum], group_alg)
    return {"sig": sig, "groupAlg": group_alg, "pq_sig": sign_with_suite("ml-dsa-65", None, pq, rep)["sig"], "pq_pk": pq.public}


def verify_hybrid_frost_cosign(artifact: Any, message: bytes, group_public_key_b64u: Any, signer_set: Any, opts: Optional[dict] = None) -> Dict[str, Any]:
    """Verify a (hybrid) FROST co-signature: ``{"ok", "groupAlg"?, "edOk", "pqOk", "reason"?}``. The hybrid algorithm needs ``opts["guardianPqPublicKey"]``
    (the REGISTERED guardian ML-DSA-65 key; the artifact's own ``pq_pk`` only has to match it) and BOTH halves must verify. ``opts["expectGroupAlg"]`` pins
    the algorithm. Never raises."""
    opts = opts or {}

    def deny(reason: str, group_alg: Optional[str] = None) -> Dict[str, Any]:
        out: Dict[str, Any] = {"ok": False, "edOk": False, "pqOk": False}
        if group_alg:
            out["groupAlg"] = group_alg
        out["reason"] = reason
        return out

    if not isinstance(artifact, dict) or not isinstance(artifact.get("sig"), str):
        return deny("malformed artifact")
    if not isinstance(group_public_key_b64u, str) or decode_b64u_strict(group_public_key_b64u, 32) is None:
        return deny("malformed group public key")
    group_alg = resolve_frost_group_alg(*(([artifact["groupAlg"]]) if "groupAlg" in artifact else []))
    if group_alg is None:
        return deny("unknown groupAlg '%s'" % _js_string(artifact.get("groupAlg")))
    if "expectGroupAlg" in opts:
        if not _known(opts["expectGroupAlg"]):
            return deny("unknown expected groupAlg '%s'" % _js_string(opts["expectGroupAlg"]))
        if opts["expectGroupAlg"] != group_alg:
            return deny("groupAlg '%s' does not match the required '%s'" % (group_alg, opts["expectGroupAlg"]), group_alg)
    try:
        ed_ok = verify_leaf_suite({"alg": "ed25519", "sig": artifact["sig"]}, group_public_key_b64u, bytes(message))
    except Exception:  # noqa: BLE001
        ed_ok = False
    if group_alg == "ed25519":
        return {"ok": True, "groupAlg": group_alg, "edOk": True, "pqOk": False} if ed_ok else deny("FROST Ed25519 group signature did not verify", group_alg)
    registered = opts.get("guardianPqPublicKey")
    if not isinstance(registered, str) or decode_b64u_strict(registered, _ML_DSA_65_PK_BYTES) is None:
        return deny("hybrid groupAlg requires a registered guardian ML-DSA-65 public key", group_alg)
    if "pq_pk" in artifact and artifact["pq_pk"] != registered:
        return deny("artifact pq_pk does not match the registered guardian ML-DSA key", group_alg)
    if not isinstance(artifact.get("pq_sig"), str):
        return deny("hybrid groupAlg declared but the guardian ML-DSA co-signature is missing", group_alg)
    try:
        rep = frost_cosign_representative(group_public_key_b64u, message, signer_set, group_alg)
        pq_ok = verify_leaf_suite({"alg": "ml-dsa-65", "sig": artifact["pq_sig"], "pq_pk": registered}, None, rep)
    except Exception:  # noqa: BLE001
        pq_ok = False
    if not ed_ok or not pq_ok:
        return {"ok": False, "groupAlg": group_alg, "edOk": ed_ok, "pqOk": pq_ok,
                "reason": "FROST Ed25519 group signature did not verify" if not ed_ok else "guardian ML-DSA-65 co-signature did not verify"}
    return {"ok": True, "groupAlg": group_alg, "edOk": True, "pqOk": True}


def sign_pq_quorum(message: bytes, key_pairs: List[PqKeyPair], pq_t: Optional[int] = None) -> Dict[str, Any]:
    """A PQ quorum block: one ML-DSA-65 signature per key over ``domain || sha256(message)``; ``pqT`` defaults to the number of signers."""
    rep = pq_quorum_representative(message)
    signers = [{"pk": k.public, "sig": sign_with_suite("ml-dsa-65", None, k, rep)["sig"]} for k in key_pairs]
    return {"v": PQ_QUORUM_VERSION, "alg": PQ_QUORUM_ALG, "pqT": len(signers) if pq_t is None else pq_t, "signers": signers}
