"""Transparency-ledger verification (Ed25519, plus every PQ / hybrid suite this runtime implements): RFC 6962 inclusion, RFC 9162 consistency, signed tree heads,
witness cosignatures, checkpoint chains, legacy witnessed heads and equivocation. Every function is total: any
malformed input returns False / a failing verdict, never raises. Verdicts match the shared extension-layer vectors.

A PQ or hybrid artifact verifies only under the verifier's pin for the Ed25519 identity it names: `pins` is
`{ed25519 b64u: PQ public key b64u}`. `pins=None` is ABSENT (cosigners then fall back to the witness policy's own
`pqPins`); `pins={}` is an explicit empty set that REPLACES them. A suite this runtime lacks is refused."""
from typing import Any, Dict, List, Optional

from .pca import (
    MAX_SAFE,
    _node_hash,
    b64u,
    canonical_bytes_strict,
    decode_b64u_strict,
    sha256,
    verify_inclusion,
)
from .intent_v2 import _UNDEF, _bind_suite_fields, _pinned_suite_error

EMPTY_TREE_ROOT = b64u(sha256(b""))
STH_DOMAIN = "atlas-pca/sth/v1\0"
STH_WITNESS_DOMAIN = "atlas-pca/sth-witness/v2\0"
LEDGER_HEAD_DOMAIN = "atlas-pca/ledger-head/v1\0"
_MAX_CONSISTENCY_PATH = 2 * 53 + 2  # longest path a tree of < 2^53 leaves can need


def _safe_int(v: Any) -> bool:
    """JS Number.isSafeInteger: a non-bool number that is integral and within +-(2^53-1)."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    return v == v and abs(v) <= MAX_SAFE and v == int(v)


def _signed(domain: str, body: dict, identity: Any, art: dict, pins: Optional[dict]) -> bool:
    """`art`'s signature (alg, pq_pk, sig, pq_sig) over domain || canonical(bindSuiteFields(body)) under `identity` and its pin."""
    alg, pq_pk = art.get("alg", _UNDEF), art.get("pq_pk", _UNDEF)
    msg = domain.encode() + canonical_bytes_strict(_bind_suite_fields(body, alg, pq_pk))
    return _pinned_suite_error(alg, identity, pq_pk, msg, art.get("sig", _UNDEF), art.get("pq_sig", _UNDEF), pins) is None


def verify_ledger_inclusion(root: Any, proof: Any, commit: Any) -> bool:
    """RFC 6962 inclusion of a ledger commit string under `root`."""
    return verify_inclusion(root, proof, commit)


def verify_ledger_consistency(old_root: Any, new_root: Any, proof: Any) -> bool:
    """RFC 9162 s2.1.4.2 consistency of the tree with `old_root` and the tree with `new_root`."""
    try:
        if not isinstance(old_root, str) or not isinstance(new_root, str):
            return False
        first, second = proof["oldSize"], proof["newSize"]
        if not _safe_int(first) or not _safe_int(second):
            return False
        first, second = int(first), int(second)
        if first < 0 or first > second:
            return False
        path_in = proof["path"]
        if not isinstance(path_in, list) or len(path_in) > _MAX_CONSISTENCY_PATH:
            return False
        if first == 0:
            if path_in or old_root != EMPTY_TREE_ROOT:
                return False
            return new_root == EMPTY_TREE_ROOT if second == 0 else True
        if first == second:
            return not path_in and old_root == new_root
        path = [decode_b64u_strict(p) for p in path_in]
        if any(p is None for p in path):
            return False
        if first & (first - 1) == 0:
            o = decode_b64u_strict(old_root)
            if o is None:
                return False
            path.insert(0, o)
        if not path:
            return False
        fn, sn = first - 1, second - 1
        while fn & 1:
            fn >>= 1
            sn >>= 1
        fr = sr = path[0]
        for c in path[1:]:
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                fr, sr = _node_hash(c, fr), _node_hash(c, sr)
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
            else:
                sr = _node_hash(sr, c)
            fn >>= 1
            sn >>= 1
        return sn == 0 and b64u(fr) == old_root and b64u(sr) == new_root
    except Exception:
        return False


def _witness_body(sth: dict) -> dict:
    ge = sth.get("guardian_epoch")
    return {
        "instance_id": sth["instance_id"], "principal": sth["principal"], "size": sth["size"], "root": sth["root"],
        "prev_root": sth["prev_root"], "guardian_epoch": 0 if ge is None else ge,
    }


def verify_witness_cosignature(sth: Any, cosig: Any, witness_public: Any, pins: Optional[dict] = None) -> bool:
    """One witness cosignature over the head statement, bound to this exact head."""
    try:
        if not isinstance(cosig, dict) or cosig.get("key") != witness_public or not isinstance(cosig.get("sig"), str):
            return False
        return _signed(STH_WITNESS_DOMAIN, _witness_body(sth), witness_public, cosig, pins)
    except Exception:
        return False


def verify_witness_cosignatures(sth: Any, policy: Any, pins: Optional[dict] = None) -> bool:
    """k-of-n: at least `threshold` DISTINCT trusted witnesses carry a valid cosignature."""
    try:
        threshold = policy.get("threshold")
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or threshold != int(threshold) or threshold < 0:
            return False
        if threshold == 0:
            return True
        trusted = set(policy.get("witnessKeys") or [])
        witnesses = sth.get("witnesses")
        if not trusted or not isinstance(witnesses, list):
            return False
        if pins is None:  # the caller's pins when passed (even empty), else the policy's own
            pins = policy.get("pqPins")
        counted = set()
        for w in witnesses:
            if not isinstance(w, dict) or not isinstance(w.get("key"), str) or not isinstance(w.get("sig"), str):
                continue
            if w["key"] not in trusted or w["key"] in counted or not verify_witness_cosignature(sth, w, w["key"], pins):
                continue
            counted.add(w["key"])
            if len(counted) >= threshold:
                return True
        return len(counted) >= threshold
    except Exception:
        return False


def verify_tree_head(sth: Any, guardian_public: Any, witness_policy: Optional[dict] = None, pins: Optional[dict] = None) -> bool:
    """Guardian signature over a signed tree head, plus the witness threshold when `witness_policy` is given."""
    try:
        if not isinstance(sth, dict) or sth.get("guardian") != guardian_public:
            return False
        if not _safe_int(sth.get("size")) or sth["size"] < 0:
            return False
        body = {k: sth[k] for k in ("instance_id", "principal", "size", "root", "prev_root", "timestamp")}
        if not _signed(STH_DOMAIN, body, guardian_public, sth, pins):
            return False
        return witness_policy is None or verify_witness_cosignatures(sth, witness_policy, pins)
    except Exception:
        return False


def verify_head_consistency(older: Any, newer: Any, proof: Any, guardian_public: Any, witness_policy: Optional[dict] = None,
                           pins: Optional[dict] = None) -> bool:
    """Both heads genuine, same log, the proof connects them, and (adjacent heads) newer.prev_root == older.root."""
    try:
        if not verify_tree_head(older, guardian_public, witness_policy, pins) or not verify_tree_head(newer, guardian_public, witness_policy, pins):
            return False
        if older["instance_id"] != newer["instance_id"] or older["principal"] != newer["principal"]:
            return False
        if not (_safe_int(proof["oldSize"]) and proof["oldSize"] == older["size"] and _safe_int(proof["newSize"]) and proof["newSize"] == newer["size"]):
            return False
        if newer["size"] == older["size"] + 1 and newer["prev_root"] != older["root"]:
            return False
        return verify_ledger_consistency(older["root"], newer["root"], proof)
    except Exception:
        return False


def verify_checkpoint_chain(chain: Any, guardian_public: Any, witness_policy: Optional[dict] = None,
                            pins: Optional[dict] = None) -> Dict[str, Any]:
    """Verify pinned checkpoints end to end. Returns {"ok": True} or {"ok": False, "at": index of the first bad one}."""
    try:
        if not isinstance(chain, list) or not chain:
            return {"ok": False, "at": 0}
        for i, cp in enumerate(chain):
            if not isinstance(cp, dict) or not verify_tree_head(cp.get("sth"), guardian_public, witness_policy, pins):
                return {"ok": False, "at": i}
            if i == 0:
                continue
            if not cp.get("proof") or not verify_head_consistency(chain[i - 1]["sth"], cp["sth"], cp["proof"], guardian_public, witness_policy, pins):
                return {"ok": False, "at": i}
        return {"ok": True}
    except Exception:
        return {"ok": False, "at": 0}


def verify_witnessed_head(wh: Any, witness_public: Any, pins: Optional[dict] = None) -> bool:
    """A legacy witness-signed ledger head."""
    try:
        if not isinstance(wh, dict) or wh.get("witness") != witness_public:
            return False
        body = {k: wh[k] for k in ("principal", "size", "root")}
        return _signed(LEDGER_HEAD_DOMAIN, body, witness_public, wh, pins)
    except Exception:
        return False


def detect_equivocation(a: Any, b: Any, witness_public: Any, pins: Optional[dict] = None) -> bool:
    """Two valid heads of one witness for the same principal and size with different roots."""
    return (
        verify_witnessed_head(a, witness_public, pins) and verify_witnessed_head(b, witness_public, pins)
        and a["principal"] == b["principal"] and a["size"] == b["size"] and a["root"] != b["root"]
    )
