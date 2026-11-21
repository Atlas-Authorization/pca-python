"""Transparency-anchored allowlist verification (wire level), the native counterpart of `verifyAllowlistAnchored` in
@atlasauth/pca. It checks the log evidence for a manifest that has ALREADY been signature-verified elsewhere: a signed
tree head under the pinned log key, the RFC 6962 root over the supplied anchor entries, the manifest's inclusion proof,
the RFC 9162 consistency proof from a cached head, head freshness and the per-issuer version rules. Same outcome codes as
the reference (`missing-proof`, `bad-head`, `stale-head`, `bad-cache`, `log-rollback`, `split-view`,
`inconsistent-with-cache`, `feed-mismatch`, `bad-proof`, `not-anchored`, `anchored-rollback`, `log-conflict`); the reason
text is not part of the contract. Total: any malformed input is a refusal code, never an exception, never a pass.

    res = verify_allowlist_anchored({"issuer": "ops", "version": 3, "digest": d}, evidence,
                                    trust={"logKey": k, "instanceId": i, "principal": p}, now_ms=now, cached_head=prev)
    if res["ok"]: prev = evidence["head"]   # persist it: the cached head tightens every later check
"""
from typing import Any, Dict, Optional
import re

from .ledger import EMPTY_TREE_ROOT, _safe_int, verify_head_consistency, verify_ledger_inclusion, verify_tree_head
from .pca import hash_canonical, merkle_root

ANCHOR_DOMAIN = "pca-attest-allowlist-anchor/v1"
MAX_FEED = 100_000
DEFAULT_SKEW_MS = 60_000
DEFAULT_MAX_AGE_MS = 86_400_000
_DIGEST = re.compile(r"[A-Za-z0-9_-]{43}")

__all__ = ["ANCHOR_DOMAIN", "allowlist_anchor_commit", "verify_allowlist_anchored"]


def _no(code: str) -> Dict[str, Any]:
    return {"ok": False, "code": code}


def _entry(e: Any) -> bool:
    return (
        isinstance(e, dict) and len(e) == 3
        and isinstance(e.get("issuer"), str) and 0 < len(e["issuer"]) <= 200
        and _safe_int(e.get("version")) and e["version"] >= 1
        and isinstance(e.get("digest"), str) and _DIGEST.fullmatch(e["digest"]) is not None
    )


def allowlist_anchor_commit(e: Dict[str, Any]) -> str:
    """The leaf the log stores for an entry (issuer, version, manifest digest)."""
    return hash_canonical({"domain": ANCHOR_DOMAIN, "issuer": e["issuer"], "version": e["version"], "digest": e["digest"]})


def verify_allowlist_anchored(mine: Any, evidence: Any, trust: Any, now_ms: Any, max_head_age_ms: Any = None,
                              clock_skew_ms: Any = None, cached_head: Any = None, witnesses: Optional[dict] = None,
                              pins: Optional[dict] = None) -> Dict[str, Any]:
    """`mine`: the signature-verified manifest's {issuer, version, digest}. `evidence`: {head, entries, proof,
    consistency?}. `trust`: {logKey, instanceId, principal}. Returns {"ok": True, "highestAnchoredVersion": n} or
    {"ok": False, "code": ...}."""
    try:
        if not isinstance(evidence, dict) or not isinstance(evidence.get("proof"), dict) or evidence.get("head") is None \
                or not isinstance(evidence.get("entries"), list):
            return _no("missing-proof")
        if not isinstance(trust, dict) or not _safe_int(now_ms):
            return _no("bad-head")
        key, inst, princ = trust.get("logKey"), trust.get("instanceId"), trust.get("principal")
        head = evidence["head"]
        if not verify_tree_head(head, key, witnesses, pins) or head["instance_id"] != inst or head["principal"] != princ \
                or not _safe_int(head.get("timestamp")):
            return _no("bad-head")
        skew = DEFAULT_SKEW_MS if clock_skew_ms is None else max(0, clock_skew_ms)
        max_age = DEFAULT_MAX_AGE_MS if max_head_age_ms is None else max_head_age_ms
        if head["timestamp"] > now_ms + skew or now_ms - head["timestamp"] > max_age:
            return _no("stale-head")
        if cached_head is not None:
            if not verify_tree_head(cached_head, key, witnesses, pins) or cached_head["instance_id"] != inst \
                    or cached_head["principal"] != princ:
                return _no("bad-cache")
            if head["size"] < cached_head["size"]:
                return _no("log-rollback")
            if head["size"] == cached_head["size"] and head["root"] != cached_head["root"]:
                return _no("split-view")
            if head["size"] > cached_head["size"]:
                if not verify_head_consistency(cached_head, head, evidence.get("consistency"), key, witnesses, pins):
                    return _no("inconsistent-with-cache")
        entries = evidence["entries"]
        if len(entries) > MAX_FEED or len(entries) != head["size"] or not all(_entry(e) for e in entries):
            return _no("feed-mismatch")
        root = merkle_root([allowlist_anchor_commit(e) for e in entries]) if entries else EMPTY_TREE_ROOT
        if root != head["root"]:
            return _no("feed-mismatch")
        digests: Dict[int, str] = {}
        highest = 0
        for e in entries:
            if e["issuer"] != mine["issuer"]:
                continue
            if e["version"] in digests and digests[e["version"]] != e["digest"]:
                return _no("log-conflict")
            digests[e["version"]] = e["digest"]
            highest = max(highest, e["version"])
        proof = evidence["proof"]
        if not _entry(mine) or not _safe_int(proof.get("size")) or proof["size"] != head["size"] \
                or not verify_ledger_inclusion(head["root"], proof, allowlist_anchor_commit(mine)):
            return _no("bad-proof")
        if mine["version"] < highest:
            return _no("anchored-rollback")
        if digests.get(mine["version"]) != mine["digest"]:
            return _no("not-anchored")
        return {"ok": True, "highestAnchoredVersion": highest}
    except Exception:
        return _no("bad-head")
