"""Break-glass grants (verification side): a time-boxed, small-budget, loud emergency grant with a mandatory signed review after
the fact. Records and reviews are Ed25519-signed under a domain string over strict-canonical JSON. ``BreakGlassRegistry`` keeps
each holder's grants, numbered uses, reviews and freeze status in memory (one document per holder). Total: nothing raises.
Port of packages/pca-grants/src/breakglass.ts; replays break-glass-vectors.json."""
from typing import Any, Dict, List, Optional

from .k3 import is_obj, is_one, is_str, is_uint, verify_body

BREAK_GLASS_DOMAIN = "atlas-pca/break-glass/v1\0"
BREAK_GLASS_REVIEW_DOMAIN = "atlas-pca/break-glass-review/v1\0"
MAX_BREAK_GLASS_WINDOW_MS = 86_400_000
MAX_BREAK_GLASS_USES = 16
MAX_REVIEW_WITHIN_MS = 30 * 86_400_000
_BODY_KEYS = ["v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority"]
_REV_KEYS = ["v", "id", "outcome", "notes_digest", "at", "reviewer"]


def _well_formed(b: Any) -> bool:
    if not is_obj(b) or not is_one(b.get("v")) or not (is_str(b.get("id"), 128) and is_str(b.get("holder"), 128) and is_str(b.get("grant_ref"), 256)
                                                      and is_str(b.get("reason_digest"), 128) and is_str(b.get("notify_to"), 256) and is_str(b.get("authority"), 128)):
        return False
    if not is_uint(b.get("max_uses")) or b["max_uses"] < 1 or b["max_uses"] > MAX_BREAK_GLASS_USES:
        return False
    if not is_uint(b.get("issued_at")) or not is_uint(b.get("expires_at")) or b["expires_at"] <= b["issued_at"] \
            or b["expires_at"] - b["issued_at"] > MAX_BREAK_GLASS_WINDOW_MS:
        return False
    return is_uint(b.get("review_within")) and 1 <= b["review_within"] <= MAX_REVIEW_WITHIN_MS


def verify_break_glass(b: Any) -> bool:
    """Well formed and signed by its ``authority`` over exactly its content."""
    return _well_formed(b) and verify_body(BREAK_GLASS_DOMAIN, {k: b[k] for k in _BODY_KEYS}, b["authority"], b.get("sig"))


def _rv_well_formed(r: Any) -> bool:
    return (is_obj(r) and is_one(r.get("v")) and is_str(r.get("id"), 128) and r.get("outcome") in ("justified", "unjustified")
            and is_str(r.get("notes_digest"), 128) and is_uint(r.get("at")) and is_str(r.get("reviewer"), 128))


def verify_break_glass_review(r: Any) -> bool:
    return _rv_well_formed(r) and verify_body(BREAK_GLASS_REVIEW_DOMAIN, {k: r[k] for k in _REV_KEYS}, r["reviewer"], r.get("sig"))


def _frozen_in(grants: Dict[str, dict], now: int) -> bool:
    """A grant of this holder was judged unjustified, or has uses, no review and a review clock that has run out."""
    for e in grants.values():
        rv = e["review"]
        if (rv is not None and rv["outcome"] == "unjustified") or \
                (rv is None and e["uses"] and now >= e["uses"][0]["at"] + e["rec"]["review_within"]):
            return True
    return False


class BreakGlassRegistry:
    """``policy``: ``authorities`` and ``reviewers`` (lists of keys)."""

    def __init__(self, policy: dict) -> None:
        self.policy = policy
        self.holders: Dict[str, Dict[str, dict]] = {}

    def accept(self, rec: Any, now: Any) -> dict:
        try:
            if not verify_break_glass(rec) or not is_uint(now):
                return {"ok": False, "code": "bad_record"}
            if rec["authority"] not in self.policy.get("authorities", []):
                return {"ok": False, "code": "unknown_authority"}
            grants = self.holders.setdefault(rec["holder"], {})
            cur = grants.get(rec["id"])
            if cur is not None:
                return {"ok": True, "replaced": False} if cur["rec"]["sig"] == rec["sig"] else {"ok": False, "code": "id_conflict"}
            if _frozen_in(grants, now):
                return {"ok": False, "code": "holder_frozen"}
            grants[rec["id"]] = {"rec": rec, "uses": [], "review": None}
            return {"ok": True, "replaced": True}
        except Exception:
            return {"ok": False, "code": "store_unreachable"}

    def use(self, id: Any, holder: Any, action_digest: Any, now: Any, notified: Any) -> dict:
        """Record one use; ``notified`` must be True. Checks in order: input, existence, freeze, revocation, window, budget, notification."""
        try:
            if not (is_str(id, 128) and is_str(holder, 128) and is_str(action_digest, 128) and is_uint(now) and isinstance(notified, bool)):
                return {"decision": "deny", "code": "bad_input"}

            def deny(code: str) -> dict:
                return {"decision": "deny", "code": code, "id": id}
            grants = self.holders.get(holder, {})
            e = grants.get(id)
            if e is None:
                return deny("unknown_break_glass")
            rec = e["rec"]
            if _frozen_in(grants, now):
                return deny("holder_frozen")
            if e["review"] is not None and e["review"]["outcome"] == "unjustified":
                return deny("revoked")
            if now < rec["issued_at"]:
                return deny("not_yet_valid")
            if now >= rec["expires_at"]:
                return deny("expired")
            if len(e["uses"]) >= rec["max_uses"]:
                return deny("budget_exhausted")
            if notified is not True:
                return deny("not_notified")
            e["uses"].append({"n": len(e["uses"]) + 1, "action_digest": action_digest, "at": now})
            return {"decision": "allow", "id": id, "use": len(e["uses"]), "remaining": rec["max_uses"] - len(e["uses"]),
                    "review_due": e["uses"][0]["at"] + rec["review_within"]}
        except Exception:
            return {"decision": "deny", "code": "store_unreachable", "id": id if isinstance(id, str) else None}

    def review(self, rec: Any, holder: Any, now: Any) -> dict:
        """Record the signed review. The first review of a grant is final; a late review lifts an overdue freeze."""
        try:
            if not verify_break_glass_review(rec) or not is_str(holder, 128) or not is_uint(now):
                return {"ok": False, "code": "bad_record"}
            if rec["reviewer"] not in self.policy.get("reviewers", []):
                return {"ok": False, "code": "unknown_reviewer"}
            e = self.holders.get(holder, {}).get(rec["id"])
            if e is None:
                return {"ok": False, "code": "unknown_break_glass"}
            if rec["reviewer"] == e["rec"]["holder"] or rec["reviewer"] == e["rec"]["authority"]:
                return {"ok": False, "code": "sod"}
            if e["review"] is not None:
                return {"ok": True, "replaced": False} if e["review"]["sig"] == rec["sig"] else {"ok": False, "code": "already_reviewed"}
            if not e["uses"]:
                return {"ok": False, "code": "nothing_to_review"}
            if rec["at"] < e["uses"][0]["at"] or rec["at"] > now:
                return {"ok": False, "code": "bad_time"}
            e["review"] = rec
            return {"ok": True, "replaced": True}
        except Exception:
            return {"ok": False, "code": "store_unreachable"}

    def frozen(self, holder: Any, now: Any) -> bool:
        if not is_str(holder, 128) or not is_uint(now):
            return True  # fail closed
        try:
            return _frozen_in(self.holders.get(holder, {}), now)
        except Exception:
            return True

    def uses(self, holder: str, id: str) -> List[dict]:
        e = self.holders.get(holder, {}).get(id) if isinstance(holder, str) else None
        return [dict(u) for u in e["uses"]] if e else []
