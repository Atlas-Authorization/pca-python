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
import math
import re

from .ledger import EMPTY_TREE_ROOT, _safe_int, verify_head_consistency, verify_ledger_inclusion, verify_tree_head
from .pca import hash_canonical, merkle_root

ANCHOR_DOMAIN = "pca-attest-allowlist-anchor/v1"
MAX_FEED = 100_000
DEFAULT_SKEW_MS = 60_000
DEFAULT_MAX_AGE_MS = 86_400_000
_DIGEST = re.compile(r"[A-Za-z0-9_-]{43}")

__all__ = ["ANCHOR_DOMAIN", "allowlist_anchor_commit", "verify_allowlist_anchored", "AllowlistAnchorLog", "create_allowlist_anchor_log",
           "anchor_allowlist_head", "refresh_anchor_head", "evidence_for", "anchor_entry_of", "verify_allowlist_anchored_result"]


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
        # the freshness window must be a finite number: a NaN max age made `now - ts > max_age` False (every old head admitted)
        for w in (clock_skew_ms, max_head_age_ms):
            if w is not None and (isinstance(w, bool) or not isinstance(w, (int, float)) or not math.isfinite(w)):
                return _no("stale-head")
        key, inst, princ = trust.get("logKey"), trust.get("instanceId"), trust.get("principal")
        head = evidence["head"]
        if not verify_tree_head(head, key, witnesses, pins) or head["instance_id"] != inst or head["principal"] != princ \
                or not _safe_int(head.get("timestamp")):
            return _no("bad-head")
        skew = DEFAULT_SKEW_MS if clock_skew_ms is None else max(0, clock_skew_ms)
        max_age = DEFAULT_MAX_AGE_MS if max_head_age_ms is None else max_head_age_ms
        if not (head["timestamp"] <= now_ms + skew) or not (now_ms - head["timestamp"] <= max_age):
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


# ---- the operator side: the transparency log of anchored manifests ----

def anchor_entry_of(v: Dict[str, Any]) -> Dict[str, Any]:
    """The anchor entry of a verified manifest: ``{issuer, version, digest}``."""
    return {"issuer": v["issuer"], "version": v["version"], "digest": v["digest"]}


class AllowlistAnchorLog:
    """An operator's append-only log of (issuer, version, digest) anchors with its latest signed tree head."""

    def __init__(self, instance_id: str, principal: str) -> None:
        from .ledger_proofs import TransparencyLedger
        self.ledger = TransparencyLedger(principal)
        self.instance_id, self.principal = instance_id, principal
        self._entries: list = []
        self._latest: Optional[dict] = None

    def entries(self) -> list:
        return [dict(e) for e in self._entries]

    def latest(self) -> Optional[dict]:
        return self._latest


def create_allowlist_anchor_log(instance_id: str, principal: str) -> AllowlistAnchorLog:
    return AllowlistAnchorLog(instance_id, principal)


def _sign_head(log: AllowlistAnchorLog, guardian_secret: bytes, now_ms: Any, suite: Optional[dict] = None) -> dict:
    from .agent import KeyPair
    from .ledger import sign_tree_head
    h = log.ledger.head()
    sth = sign_tree_head(KeyPair(bytes(guardian_secret), allow_insecure_signer=True),
                         {"instance_id": log.instance_id, "principal": log.principal, "size": h["size"], "root": h["root"],
                          "prev_root": log._latest["root"] if log._latest is not None else "", "timestamp": now_ms},
                         (suite or {}).get("alg"), (suite or {}).get("pq"))
    log._latest = sth
    return sth


def evidence_for(log: AllowlistAnchorLog, index: Any, cached: Optional[dict] = None) -> Dict[str, Any]:
    """The evidence for the entry at ``index``: the latest head, every entry, the inclusion proof and, for a cached head older than the latest, the
    consistency proof from it."""
    if log._latest is None:
        raise ValueError("evidenceFor: log has no signed head")
    out: Dict[str, Any] = {"head": log._latest, "entries": log.entries(), "proof": log.ledger.inclusion_proof(index)}
    if cached is not None and cached["size"] > 0 and cached["size"] < log._latest["size"]:
        out["consistency"] = log.ledger.consistency_proof(cached["size"], log._latest["size"])
    return out


def anchor_allowlist_head(log: AllowlistAnchorLog, what: Any, guardian_secret: bytes, now_ms: Any, suite: Optional[dict] = None) -> Dict[str, Any]:
    """Anchor a manifest's entry (an entry, or a verified-manifest result) and sign the new head. The same version anchored again with the same digest
    is idempotent; another digest, or a lower version than anchored, raises."""
    entry = anchor_entry_of(what) if isinstance(what, dict) and "body" in what else dict(what)
    if not _entry(entry):
        raise TypeError("anchorAllowlistHead: malformed entry")
    same = next((i for i, e in enumerate(log._entries) if e["issuer"] == entry["issuer"] and e["version"] == entry["version"]), -1)
    if same >= 0:
        if log._entries[same]["digest"] != entry["digest"]:
            raise ValueError("anchorAllowlistHead: this version is already anchored with a different digest")
        index = same
    else:
        mx = max([e["version"] for e in log._entries if e["issuer"] == entry["issuer"]], default=0)
        if entry["version"] < mx:
            raise ValueError("anchorAllowlistHead: version %s is lower than the anchored %s" % (entry["version"], mx))
        index = log.ledger.append_commitment(allowlist_anchor_commit(entry))["index"]
        log._entries.append(entry)
        _sign_head(log, guardian_secret, now_ms, suite)
    if log._latest is None:
        _sign_head(log, guardian_secret, now_ms, suite)
    return evidence_for(log, index)


def refresh_anchor_head(log: AllowlistAnchorLog, guardian_secret: bytes, now_ms: Any, suite: Optional[dict] = None) -> dict:
    """Re-sign the current head with a new timestamp (freshness for the verifiers)."""
    if log.ledger.size == 0:
        raise ValueError("refreshAnchorHead: nothing anchored yet")
    return _sign_head(log, guardian_secret, now_ms, suite)


def verify_allowlist_anchored_result(verified: Any, evidence: Any, opts: Dict[str, Any]) -> Dict[str, Any]:
    """:func:`verify_allowlist_anchored` with the reference's argument and result shapes: ``opts`` = {trust (logKey, instanceId, principal, witnesses?,
    pqPins?), nowMs, maxHeadAgeMs?, clockSkewMs?, cachedHead?}; success carries the issuer, version, digest and the head."""
    trust = opts.get("trust") or {}
    r = verify_allowlist_anchored(verified, evidence, trust, opts.get("nowMs"), opts.get("maxHeadAgeMs"), opts.get("clockSkewMs"), opts.get("cachedHead"),
                                  trust.get("witnesses"), trust.get("pqPins"))
    if not r["ok"]:
        return r
    return {"ok": True, "issuer": verified["issuer"], "version": verified["version"], "digest": verified["digest"],
            "highestAnchoredVersion": r["highestAnchoredVersion"], "head": evidence["head"]}
