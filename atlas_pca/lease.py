"""Leases (verification side): a time-boxed grant that must be renewed, has a hard ``max_ttl`` cap, and dies when revoked.
Records and revocations are Ed25519-signed under a domain string over strict-canonical JSON. ``LeaseRegistry`` keeps the newest
record per ``lease_id`` (in memory) plus the revocations; ``check_lease`` gates a presented record. Total: no function raises.
Results are dicts shaped like the shared vectors (``lease-vectors.json``)."""
import re
from typing import Any, Dict, List, Optional, Sequence

from .k3 import is_obj, is_one, is_str, is_uint, verify_body

LEASE_DOMAIN = "atlas-pca/lease/v1\0"
LEASE_REVOKE_DOMAIN = "atlas-pca/lease-revoke/v1\0"
_MAX_APPROVERS = 16
_PATH_RE = re.compile(r"[a-z0-9_.-]{1,64}(/[a-z0-9_.-]{1,64}){0,7}")
_BODY_KEYS = ["v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at",
              "renewed_at", "expires_at", "max_ttl", "authority"]
_REV_KEYS = ["v", "target", "value", "revoked_at", "authority"]


def lease_cap(l: dict) -> int:
    return l["issued_at"] + l["max_ttl"]


def _well_formed(l: Any) -> bool:
    if not is_obj(l) or not is_one(l.get("v")) or not (is_str(l.get("lease_id"), 128) and is_str(l.get("grant_ref"), 256)
                                                      and is_str(l.get("holder"), 128) and is_str(l.get("requester"), 128)):
        return False
    p = l.get("path")
    if not (is_str(l.get("authority"), 128) and is_str(l.get("justification_digest"), 128)) or not isinstance(p, str) or not _PATH_RE.fullmatch(p):
        return False
    if not (is_uint(l.get("seq")) and l["seq"] >= 1 and is_uint(l.get("issued_at")) and is_uint(l.get("renewed_at"))
            and is_uint(l.get("expires_at")) and is_uint(l.get("max_ttl")) and l["max_ttl"] >= 1):
        return False
    if l["renewed_at"] < l["issued_at"] or l["expires_at"] <= l["renewed_at"] or (l["seq"] == 1 and l["renewed_at"] != l["issued_at"]):
        return False
    a = l.get("approvers")
    return isinstance(a, list) and len(a) <= _MAX_APPROVERS and all(is_str(x, 128) for x in a)


def verify_lease(l: Any) -> bool:
    """Well formed and signed by its ``authority`` over exactly its content. Does NOT check the cap."""
    return _well_formed(l) and verify_body(LEASE_DOMAIN, {k: l[k] for k in _BODY_KEYS}, l["authority"], l.get("sig"))


def _rev_well_formed(r: Any) -> bool:
    if not is_obj(r) or not is_one(r.get("v")) or not is_str(r.get("value"), 256) or not is_str(r.get("authority"), 128) or not is_uint(r.get("revoked_at")):
        return False
    if r.get("target") not in ("lease", "prefix", "grant"):
        return False
    return r["target"] != "prefix" or _PATH_RE.fullmatch(r["value"]) is not None


def verify_lease_revocation(r: Any) -> bool:
    return _rev_well_formed(r) and verify_body(LEASE_REVOKE_DOMAIN, {k: r[k] for k in _REV_KEYS}, r["authority"], r.get("sig"))


def path_under(path: str, prefix: str) -> bool:
    """``prefix`` covers ``path`` iff equal or ``path`` continues it at a segment boundary."""
    return path == prefix or path.startswith(prefix + "/")


def _covers(r: dict, l: dict) -> bool:
    if l["issued_at"] > r["revoked_at"]:
        return False
    if r["target"] == "lease":
        return l["lease_id"] == r["value"]
    if r["target"] == "grant":
        return l["grant_ref"] == r["value"]
    return path_under(l["path"], r["value"])


def sod_error(l: dict, p: Optional[dict] = None, chain: Sequence[str] = ()) -> Optional[str]:
    """Separation of duties over one record. Returns a reason or None."""
    p = p if isinstance(p, dict) else {}
    k = p.get("minApprovals")
    k = 1 if k is None else k
    if not is_uint(k) or k < 1:
        return "minApprovals must be a positive integer"
    eligible = p.get("eligibleApprovers")
    seen = set()
    for a in l["approvers"]:
        if a in seen:
            return "an approver is listed twice"
        seen.add(a)
        if a == l["requester"]:
            return "the requester may not approve their own request"
        if a == l["holder"]:
            return "the holder may not approve its own lease"
        if a in chain:
            return "an approver appears in the holder's delegation chain"
        if eligible is not None and a not in eligible:
            return "an approver is not eligible"
    n = len(l["approvers"])
    return None if n >= k else f"{n} approver(s), need {k}"


class LeaseRegistry:
    """``policy``: ``authorities`` (list of keys), optional ``minApprovals``, ``eligibleApprovers``, ``freshJustification`` (default true)."""

    def __init__(self, policy: dict) -> None:
        self.policy = policy
        self.leases: Dict[str, dict] = {}
        self.revocations: List[dict] = []

    def accept(self, rec: Any, chain: Sequence[str] = ()) -> dict:
        try:
            return self._accept(rec, chain)
        except Exception:
            return {"ok": False, "code": "store_unreachable"}

    def _accept(self, rec: Any, chain: Sequence[str]) -> dict:
        if not verify_lease(rec):
            return {"ok": False, "code": "bad_record"}
        l = rec
        if l["authority"] not in self.policy.get("authorities", []):
            return {"ok": False, "code": "unknown_authority"}
        sod = sod_error(l, self.policy, chain)
        if sod is not None:
            return {"ok": False, "code": "sod", "reason": sod}
        if l["expires_at"] > lease_cap(l):
            return {"ok": False, "code": "over_max_ttl"}
        if any(_covers(r, l) for r in self.revocations):
            return {"ok": False, "code": "revoked"}
        st = self.leases.get(l["lease_id"])
        cur = st["current"] if st else None
        if cur is None:
            if l["seq"] != 1:
                return {"ok": False, "code": "bad_seq", "reason": "a new lease starts at seq 1"}
        else:
            if l["seq"] < cur["seq"]:
                return {"ok": False, "code": "stale_seq"}
            if l["seq"] == cur["seq"]:
                return {"ok": True, "replaced": False, "seq": l["seq"]} if cur["sig"] == l["sig"] else {"ok": False, "code": "lease_fork"}
            if l["seq"] != cur["seq"] + 1:
                return {"ok": False, "code": "bad_seq", "reason": "renewals advance seq by exactly 1"}
            if any(l[k] != cur[k] for k in ("authority", "path", "grant_ref", "holder", "requester", "max_ttl", "issued_at")):
                return {"ok": False, "code": "renewal_mismatch"}
            if l["renewed_at"] >= cur["expires_at"]:
                return {"ok": False, "code": "expired_lease", "reason": "an expired lease cannot be renewed"}
            if l["renewed_at"] < cur["renewed_at"] or l["expires_at"] <= cur["expires_at"]:
                return {"ok": False, "code": "not_extending"}
            if self.policy.get("freshJustification", True) is not False and l["justification_digest"] == cur["justification_digest"]:
                return {"ok": False, "code": "stale_justification"}
        entry = {"seq": l["seq"], "renewed_at": l["renewed_at"], "expires_at": l["expires_at"], "justification_digest": l["justification_digest"]}
        self.leases[l["lease_id"]] = {"current": l, "history": (st["history"] if st else []) + [entry]}
        return {"ok": True, "replaced": True, "seq": l["seq"]}

    def revoke(self, rec: Any) -> dict:
        try:
            if not verify_lease_revocation(rec):
                return {"ok": False, "code": "bad_record"}
            if rec["authority"] not in self.policy.get("authorities", []):
                return {"ok": False, "code": "unknown_authority"}
            if not any(r["sig"] == rec["sig"] for r in self.revocations):
                self.revocations.append(rec)
            return {"ok": True, "revoked": sum(1 for s in self.leases.values() if _covers(rec, s["current"]))}
        except Exception:
            return {"ok": False, "code": "store_unreachable"}

    def get(self, lease_id: str) -> Optional[dict]:
        st = self.leases.get(lease_id)
        return st["current"] if st else None

    def history(self, lease_id: str) -> List[dict]:
        st = self.leases.get(lease_id)
        return list(st["history"]) if st else []


def check_lease(presented: Any, registry: LeaseRegistry, now: Any) -> dict:
    """Is ``presented`` a live lease? Verifies, newest record, window and cap, not revoked. Fails closed."""
    if not is_uint(now):
        return {"decision": "deny", "code": "bad_input"}
    if not verify_lease(presented):
        return {"decision": "deny", "code": "bad_record"}
    lid = presented["lease_id"]
    try:
        cur = registry.get(lid)
        if cur is None:
            return {"decision": "deny", "code": "unknown_lease", "lease_id": lid}
        if cur["sig"] != presented["sig"]:
            return {"decision": "deny", "code": "superseded", "lease_id": lid}
        if any(_covers(r, cur) for r in registry.revocations):
            return {"decision": "deny", "code": "revoked", "lease_id": lid}
        if now < cur["renewed_at"]:
            return {"decision": "deny", "code": "not_yet_valid", "lease_id": lid}
        if now >= lease_cap(cur):
            return {"decision": "deny", "code": "past_max_ttl", "lease_id": lid}
        if now >= cur["expires_at"]:
            return {"decision": "deny", "code": "expired", "lease_id": lid}
        return {"decision": "allow", "lease_id": lid, "expires_at": cur["expires_at"]}
    except Exception:
        return {"decision": "deny", "code": "store_unreachable", "lease_id": lid}
