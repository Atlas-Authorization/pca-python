"""Post-quantum t-of-n authorization by composition: a quorum certificate is t INDEPENDENT per-signer signatures over one
domain-separated message, counted, bound and de-duplicated on top of the signature-suite seam (no new cryptography).

A quorum set is n registered PQ signers (ML-DSA-65 / -87, SLH-DSA-SHA2-128f / -256s, FN-DSA, or Ed25519 + PQ hybrids), a threshold ``t``
and a diversity commitment ``minHashBased`` (at least that many hash-based, i.e. SLH-DSA, signers must sign). Its ``id`` commits to all of
it. Rotation: the old quorum signs the next set's id at ``epoch + 1``; ``verify_rotation_chain`` enforces linkage and monotone epochs.

Sets, shares, proofs and rotation certificates are plain dicts with the reference member names (``t``, ``minHashBased``, ``signers``,
``id``; ``i``, ``sig``, ``pq_sig``; ``set_id``, ``sigs``; ``from_set_id``, ``from_epoch``, ``to_set``, ``to_epoch``, ``proof``). The verifiers
are total and fail closed with the reference's reason strings; the signers raise."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from . import pq_backends
from .pca import _SIG_SUITES, _resolve_pq_key, _verify_suite, b64u, canonical_bytes_strict, decode_b64u_strict

_SET_DOMAIN = "atlas-pca/pq-quorum-set/v1"
_MSG_DOMAIN = b"atlas-pca/pq-quorum-msg/v1\0"
_ROTATION_KIND = "pq-quorum-rotation"
PQ_QUORUM_MAX_SIGNERS = 256
PQ_QUORUM_MAX_CHAIN = 1024
_SAFE = 9007199254740991
_ABSENT: Any = object()
_BAD_SET = {"ok": False, "reason": "bad-set"}
# which member of a signer's public keys is the PQ key of each family (LESS is not a quorum suite)
_PQ_KEY_MEMBER = {"ML-DSA-65": "mlDsaPub", "ML-DSA-87": "mlDsa87Pub", "SLH-DSA-SHA2-128f": "slhDsaPub", "SLH-DSA-SHA2-256s": "slhDsa256sPub",
                  "FN-DSA-512": "fnDsa512Pub", "FN-DSA-1024": "fnDsa1024Pub"}


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _safe_int(v: Any) -> bool:
    return _num(v) and v == v and abs(v) <= _SAFE and float(v).is_integer()


def _is_epoch(v: Any) -> bool:
    """A non-negative safe integer that is not negative zero."""
    return _safe_int(v) and v >= 0 and str(v)[0] != "-"


def _suite(alg: Any) -> Optional[tuple]:
    """(family, hybrid) of a PQ quorum suite, or None."""
    spec = _SIG_SUITES.get(alg) if isinstance(alg, str) else None
    return (spec[3], spec[2]) if spec is not None and spec[3] in _PQ_KEY_MEMBER else None


def _hash_based(alg: str) -> bool:
    return _SIG_SUITES[alg][3].startswith("SLH-DSA")


def _sha384(data: bytes) -> bytes:
    return hashlib.sha384(data).digest()


def _normalize(alg: Any, ed: Any, pq: Any) -> Optional[dict]:
    s = _suite(alg)
    if s is None or decode_b64u_strict(pq, pq_backends.KEY_TYPES[s[0]][0]) is None:
        return None
    if s[1]:
        return {"alg": alg, "ed": ed, "pq": pq} if decode_b64u_strict(ed, 32) is not None else None
    return {"alg": alg, "pq": pq} if ed is _ABSENT else None  # an Ed25519 key on a non-hybrid entry (null included) is refused


def _entry_key(e: dict) -> str:
    return "%s|%s|%s" % (e["alg"], e.get("ed", ""), e["pq"])


def _compute_id(t: Any, k: Any, signers: List[dict]) -> str:
    body = {"d": _SET_DOMAIN, "t": t, "k": k, "s": [{"a": e["alg"], "e": e.get("ed"), "p": e["pq"]} for e in signers]}
    return b64u(_sha384(canonical_bytes_strict(body)))


def _finalize(entries: List[dict], t: Any, k: Any) -> dict:
    n = len(entries)
    if n < 1 or n > PQ_QUORUM_MAX_SIGNERS or not _safe_int(t) or t < 1 or t > n or not _safe_int(k) or k < 0 or k > t:
        return dict(_BAD_SET)
    ordered = sorted(entries, key=_entry_key)  # the keys are ASCII: code-point order is the reference's string order
    seen = set()
    for e in ordered:
        for c in ((e["ed"], e["pq"]) if "ed" in e else (e["pq"],)):  # every KEY COMPONENT is distinct across the whole set
            if c in seen:
                return dict(_BAD_SET)
            seen.add(c)
    if sum(1 for e in ordered if _hash_based(e["alg"])) < k:
        return dict(_BAD_SET)
    return {"ok": True, "set": {"t": t, "minHashBased": k, "signers": ordered, "id": _compute_id(t, k, ordered)}}


def build_quorum_set(signers: Any, t: Any, min_hash_based: Any = 0) -> dict:
    """``{"ok": True, "set"}`` for signers ``[{"alg", "keys": {"edPub"?, "mlDsaPub"? | "mlDsa87Pub"? | "slhDsaPub"? | "slhDsa256sPub"? |
    "fnDsa512Pub"? | "fnDsa1024Pub"?}}]`` (base64url public keys), a threshold `t` (1..n) and `min_hash_based` (0..t, at most the number of
    SLH-DSA signers); ``{"ok": False, "reason": "bad-set"}`` on anything else. Signers are stored in canonical order."""
    try:
        if not isinstance(signers, list):
            return dict(_BAD_SET)
        entries = []
        for s in signers:
            if not isinstance(s, dict) or not isinstance(s.get("keys"), dict) or _suite(s.get("alg")) is None:
                return dict(_BAD_SET)
            e = _normalize(s["alg"], s["keys"].get("edPub", _ABSENT), s["keys"].get(_PQ_KEY_MEMBER[_suite(s["alg"])[0]]))
            if e is None:
                return dict(_BAD_SET)
            entries.append(e)
        return _finalize(entries, t, min_hash_based)
    except Exception:  # noqa: BLE001 - fail closed
        return dict(_BAD_SET)


def load_quorum_set(x: Any) -> dict:
    """Load a set from the wire: every entry is validated, the wire order must already be canonical and the id is RE-DERIVED and must
    match. ``{"ok": True, "set"}`` or ``{"ok": False, "reason": "bad-set"}``."""
    try:
        if not isinstance(x, dict) or not isinstance(x.get("signers"), list) or not isinstance(x.get("id"), str):
            return dict(_BAD_SET)
        entries = []
        for s in x["signers"]:
            e = _normalize(s.get("alg"), s.get("ed", _ABSENT), s.get("pq")) if isinstance(s, dict) else None
            if e is None:
                return dict(_BAD_SET)
            entries.append(e)
        r = _finalize(entries, x.get("t"), x.get("minHashBased"))
        if not r["ok"] or any(_entry_key(a) != _entry_key(b) for a, b in zip(r["set"]["signers"], entries)):
            return dict(_BAD_SET)
        return r if r["set"]["id"] == x["id"] else dict(_BAD_SET)
    except Exception:  # noqa: BLE001 - fail closed
        return dict(_BAD_SET)


def quorum_message(set_id: Any, epoch: Any, action_digest: Any) -> bytes:
    """The domain-separated bytes every signer signs. The arguments are not validated here (``verify_quorum`` does); a value the strict
    canonical form refuses (negative zero, an unsafe integer, a lone surrogate) raises."""
    return _MSG_DOMAIN + _sha384(canonical_bytes_strict({"set_id": set_id, "epoch": epoch, "action": action_digest}))


def quorum_action_digest(message: Any) -> str:
    """The action digest of an arbitrary message (bytes, or text as UTF-8): base64url SHA-384."""
    if isinstance(message, str):
        message = message.encode("utf-8")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("quorumActionDigest: bytes expected")
    return b64u(_sha384(bytes(message)))


def _at(signers: Any, index: Any) -> Any:
    """The signer at `index` as the reference's array lookup (an index may be the decimal text of one), or None."""
    if isinstance(index, str) and index.isascii() and index.isdigit() and str(int(index)) == index:
        index = int(index)
    if isinstance(index, float) and index.is_integer():
        index = int(index)
    ok = isinstance(signers, list) and isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(signers)
    return signers[index] if ok else None


def sign_quorum_share(qset: dict, index: Any, epoch: Any, action_digest: Any, ed: Any = None, pq: Any = None) -> dict:
    """Signer `index`'s share ``{"i", "sig", "pq_sig"?}`` over ``quorum_message(set id, epoch, action_digest)``. `ed` is the signer's
    Ed25519 ``KeyPair`` (hybrid suites) and `pq` its PQ key pair (``agent.generate_pq_keypair``). Raises on an unknown index or missing key
    material."""
    from .agent import sign_with_suite
    e = _at(qset["signers"], index)
    if e is None:
        raise IndexError("signQuorumShare: no such signer index")
    parts = sign_with_suite(e["alg"], ed, pq, quorum_message(qset["id"], epoch, action_digest))
    return {"i": index, **parts}


def assemble_quorum_proof(qset: dict, shares: Any) -> dict:
    return {"set_id": qset["id"], "sigs": list(shares)}


def _to_number(v: Any) -> float:
    if isinstance(v, bool):
        return 1 if v else 0
    if _num(v):
        return v
    if isinstance(v, str):
        try:
            return float(v) if v.strip() else 0
        except ValueError:
            return float("nan")
    return float("nan")


def _fail(reason: str, detail: Any = _ABSENT) -> dict:
    return {"ok": False, "reason": reason, **({} if detail is _ABSENT else {"detail": detail})}


def verify_quorum(inp: Any) -> dict:
    """Verify a quorum proof. `inp` is ``{"set", "proof", "epoch", "actionDigest", "expectedSetId"?, "requireHashBased"?}``. Total and
    fail closed: ``{"ok": True, "signers": [indices], "count", "hashBased"}`` or ``{"ok": False, "reason", "detail"?}`` with reason
    ``malformed`` | ``bad-set`` | ``set-mismatch`` | ``too-many-signatures`` | ``unknown-signer`` | ``duplicate-signer`` |
    ``bad-signature`` | ``below-threshold`` | ``diversity-unmet``. The first failing share wins, before the threshold is counted; a
    verifier's `requireHashBased` can raise the set's diversity commitment, never lower it."""
    try:
        if not isinstance(inp, dict):
            return _fail("malformed")
        loaded = load_quorum_set(inp.get("set"))
        if not loaded["ok"]:
            return _fail("bad-set")
        qset = loaded["set"]
        signers = qset["signers"]
        if "expectedSetId" in inp and not (isinstance(inp["expectedSetId"], str) and inp["expectedSetId"] == qset["id"]):
            return _fail("set-mismatch")
        if not _is_epoch(inp.get("epoch")) or not isinstance(inp.get("actionDigest"), str):
            return _fail("malformed")
        p = inp.get("proof")
        if not isinstance(p, dict) or not isinstance(p.get("set_id"), str) or not isinstance(p.get("sigs"), list):
            return _fail("malformed")
        if p["set_id"] != qset["id"]:
            return _fail("set-mismatch")
        if len(p["sigs"]) > len(signers):  # before any signature work
            return _fail("too-many-signatures")
        msg = quorum_message(qset["id"], inp["epoch"], inp["actionDigest"])
        seen: List[int] = []
        hash_based = 0
        for raw in p["sigs"]:
            if not isinstance(raw, dict) or not isinstance(raw.get("sig"), str):
                return _fail("malformed")
            i = raw.get("i")
            if not _is_epoch(i) or i >= len(signers):
                return _fail("unknown-signer")
            if int(i) in seen:
                return _fail("duplicate-signer", i)
            seen.append(int(i))
            e = signers[int(i)]
            hybrid = "ed" in e
            if hybrid != ("pq_sig" in raw):
                return _fail("bad-signature", i)
            key = _resolve_pq_key(e.get("ed", ""), None, trusted_pk=e["pq"])  # the set's own registered key, never one from the proof
            share = {"alg": e["alg"], "sig": raw["sig"], **({"pq_sig": raw["pq_sig"]} if hybrid else {})}
            if not _verify_suite(share, e.get("ed"), msg, key):
                return _fail("bad-signature", i)
            if _hash_based(e["alg"]):
                hash_based += 1
        if len(seen) < qset["t"]:
            return _fail("below-threshold")
        need = 0 if inp.get("requireHashBased") is None else _to_number(inp["requireHashBased"])
        k = max(qset["minHashBased"], need)
        if need != need or not _safe_int(k) or k < 0:
            return _fail("malformed")
        if hash_based < k:
            return _fail("diversity-unmet")
        return {"ok": True, "signers": sorted(seen), "count": len(seen), "hashBased": hash_based}
    except Exception:  # noqa: BLE001 - fail closed
        return _fail("malformed")


def verify_quorum_approval(qset: Any, proof: Any, message: Any, epoch: Any, opts: Optional[dict] = None) -> bool:
    """True iff `proof` is a valid quorum approval of the raw `message` bytes at `epoch`. `opts` may carry ``expectedSetId`` and
    ``requireHashBased``."""
    try:
        if not isinstance(message, (bytes, bytearray)):
            return False
        return verify_quorum({"set": qset, "proof": proof, "epoch": epoch, "actionDigest": quorum_action_digest(message),
                              **(opts if isinstance(opts, dict) else {})})["ok"]
    except Exception:  # noqa: BLE001
        return False


# ---- rotation --------------------------------------------------------------------------------------------------------------

def rotation_action_digest(to_set_id: Any, to_epoch: Any) -> str:
    """What the CURRENT quorum signs to hand over to the set `to_set_id` at `to_epoch`."""
    return b64u(_sha384(canonical_bytes_strict({"kind": _ROTATION_KIND, "to_set_id": to_set_id, "to_epoch": to_epoch})))


def _next_epoch(epoch: Any) -> Any:
    """epoch + 1 as the reference computes it (text is concatenated: such a certificate never verifies)."""
    if isinstance(epoch, str):
        return epoch + "1"
    if epoch is None or isinstance(epoch, bool):
        return int(bool(epoch)) + 1
    return epoch + 1


def build_rotation_cert(from_set: dict, from_epoch: Any, to_set: Any, shares: Any) -> dict:
    return {"from_set_id": from_set["id"], "from_epoch": from_epoch, "to_set": to_set, "to_epoch": _next_epoch(from_epoch),
            "proof": assemble_quorum_proof(from_set, shares)}


def sign_rotation_share(from_set: dict, index: Any, from_epoch: Any, to_set: dict, ed: Any = None, pq: Any = None) -> dict:
    """Signer `index` of the current set approves the rotation to `to_set` (see ``sign_quorum_share`` for the keys)."""
    return sign_quorum_share(from_set, index, from_epoch, rotation_action_digest(to_set["id"], _next_epoch(from_epoch)), ed, pq)


def verify_rotation_chain(genesis_set: Any, genesis_epoch: Any, chain: Any) -> dict:
    """Walk a rotation chain from a trusted genesis set and epoch: ``{"ok": True, "set", "epoch", "length"}`` (the current set) or
    ``{"ok": False, "reason", "at"}`` (`at` is the failing link, -1 before the first). Each link must name the current set, advance the
    epoch by exactly one, carry a loadable, different next set, and be approved by the CURRENT quorum."""
    def fail(reason: str, at: int) -> dict:
        return {"ok": False, "reason": reason, "at": at}
    try:
        g = load_quorum_set(genesis_set)
        if not g["ok"] or not _is_epoch(genesis_epoch):
            return fail("bad-set", -1)
        if not isinstance(chain, list):
            return fail("malformed", -1)
        if len(chain) > PQ_QUORUM_MAX_CHAIN:
            return fail("chain-too-long", -1)
        cur, epoch = g["set"], genesis_epoch
        for n, c in enumerate(chain):
            if not isinstance(c, dict) or not isinstance(c.get("from_set_id"), str) or not _is_epoch(c.get("from_epoch")) or not _is_epoch(c.get("to_epoch")):
                return fail("malformed", n)
            if c["from_set_id"] != cur["id"]:
                return fail("chain-broken", n)
            if c["from_epoch"] != epoch or c["to_epoch"] != epoch + 1:
                return fail("non-monotone-epoch", n)
            nxt = load_quorum_set(c.get("to_set"))
            if not nxt["ok"] or nxt["set"]["id"] == cur["id"]:
                return fail("bad-rotation", n)
            v = verify_quorum({"set": cur, "proof": c.get("proof"), "epoch": epoch,
                               "actionDigest": rotation_action_digest(nxt["set"]["id"], c["to_epoch"]), "expectedSetId": cur["id"]})
            if not v["ok"]:
                return fail(v["reason"], n)
            cur, epoch = nxt["set"], c["to_epoch"]
        return {"ok": True, "set": cur, "epoch": epoch, "length": len(chain)}
    except Exception:  # noqa: BLE001 - fail closed
        return fail("malformed", -1)


def _strict_eq(a: Any, b: Any) -> bool:
    """Equality of two JSON scalars of the same kind (both absent counts); containers never match."""
    if a is _ABSENT or b is _ABSENT or a is None or b is None:
        return a is b
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if (_num(a) and _num(b)) or (isinstance(a, str) and isinstance(b, str)):
        return a == b
    return False


def is_rotation_fork(a: Any, b: Any) -> bool:
    """Two rotation certificates that leave the same set at the same epoch for DIFFERENT next sets (evidence of equivocation)."""
    if not all(isinstance(x, dict) and isinstance(x.get("to_set"), dict) for x in (a, b)):
        return False
    ia, ib = a["to_set"].get("id"), b["to_set"].get("id")
    return _strict_eq(a.get("from_set_id", _ABSENT), b.get("from_set_id", _ABSENT)) and _strict_eq(a.get("from_epoch", _ABSENT), b.get("from_epoch", _ABSENT)) \
        and isinstance(ia, str) and isinstance(ib, str) and ia != ib


def _share_bytes(e: dict) -> int:
    sig_bytes, _, hybrid, family, _ = _SIG_SUITES[e["alg"]]
    return sig_bytes + (pq_backends.KEY_TYPES[family][1] if hybrid else 0)


def quorum_proof_size(qset: dict, indices: Any = None) -> dict:
    """Signature bytes of a proof: the t smallest and t largest signers and, with `indices`, the chosen ones (an unknown index counts 0).
    There is no compact (aggregated) form: ``compact`` is always False."""
    sizes = sorted(_share_bytes(e) for e in qset["signers"])
    t = qset["t"]
    r: Dict[str, Any] = {"minBytes": sum(sizes[:t]), "maxBytes": sum(sizes[len(sizes) - t:]), "t": t, "compact": False}
    if indices is not None:
        if not isinstance(indices, list):
            raise TypeError("quorumProofSize: indices must be a list")
        r["chosenBytes"] = sum(0 if _at(qset["signers"], i) is None else _share_bytes(_at(qset["signers"], i)) for i in indices)
    return r


__all__ = ["PQ_QUORUM_MAX_SIGNERS", "PQ_QUORUM_MAX_CHAIN", "build_quorum_set", "load_quorum_set", "quorum_message", "quorum_action_digest",
           "sign_quorum_share", "assemble_quorum_proof", "verify_quorum", "verify_quorum_approval", "rotation_action_digest",
           "build_rotation_cert", "sign_rotation_share", "verify_rotation_chain", "is_rotation_fork", "quorum_proof_size"]
