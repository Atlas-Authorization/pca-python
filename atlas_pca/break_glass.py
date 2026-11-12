"""Break-glass grants (verification side): a time-boxed, small-budget, loud emergency grant with a mandatory signed review after
the fact. Records and reviews are Ed25519-signed under a domain string over strict-canonical JSON. ``BreakGlassRegistry`` keeps
each holder's grants, numbered uses, reviews and freeze status in a durable key-value store you pass (one document per shard of the
holder id; ``MemoryAtomicKv`` is for tests and single-process use). Total: nothing raises.
Port of packages/pca-grants/src/breakglass.ts; replays break-glass-vectors.json."""
from typing import Any, Dict, List, Optional

from .k3 import is_obj, is_one, is_str, is_uint, verify_body
from .lease import DEFAULT_LEASE_SHARDS, MAX_LEASE_SHARDS, shard_of

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


def _frozen_in(grants: Dict[str, dict], holder: str, now: int) -> bool:
    """A grant of this holder was judged unjustified, or has uses, no review and a review clock that has run out."""
    for e in grants.values():
        if e["rec"]["holder"] != holder:
            continue
        rv = e.get("review")
        if (rv is not None and rv["outcome"] == "unjustified") or \
                (rv is None and e["uses"] and now >= e["uses"][0]["at"] + e["rec"]["review_within"]):
            return True
    return False


def _bg_key(shards: int, i: int) -> str:
    return "breakglass/%d/%d" % (shards, i)


def _load_shard(x: Any) -> dict:
    return {"grants": dict(x["grants"])} if is_obj(x) and is_obj(x.get("grants")) else {"grants": {}}


class BreakGlassRegistry:
    """``policy``: ``authorities`` and ``reviewers`` (lists of keys). ``kv`` is REQUIRED: a durable key-value store with ``get(key)`` and an
    atomic ``update(key, fn)`` (:class:`atlas_pca.SqliteAtomicKv`; :class:`atlas_pca.MemoryAtomicKv` is for tests and single-process use).
    Each holder's grants live in the shard its id hashes to; ``shards`` is fixed for the life of the store."""

    def __init__(self, policy: dict, kv: Any = None, *, shards: int = DEFAULT_LEASE_SHARDS) -> None:
        if isinstance(kv, dict) or not callable(getattr(kv, "get", None)) or not callable(getattr(kv, "update", None)):  # a plain dict has both names but is no store
            raise TypeError("BreakGlassRegistry: a durable key-value store is required (MemoryAtomicKv() is for tests and single-process use)")
        if isinstance(shards, bool) or not isinstance(shards, int) or shards < 1 or shards > MAX_LEASE_SHARDS:
            raise ValueError("BreakGlassRegistry: shards must be an integer from 1 to 4096")
        self.policy = policy
        self.kv = kv
        self.shards = shards
        self._meta_ok: Optional[bool] = None

    def _ready(self) -> bool:
        if self._meta_ok is None:
            m = self.kv.update("breakglass/meta", lambda prev: {"v": 1, "shards": self.shards} if prev is None else None)
            self._meta_ok = is_obj(m) and m.get("shards") == self.shards
        return bool(self._meta_ok)

    def _key(self, holder: str) -> str:
        return _bg_key(self.shards, shard_of(holder, self.shards))

    def accept(self, rec: Any, now: Any) -> dict:
        """Register an issued record. A frozen holder gets no new one."""
        if not verify_break_glass(rec) or not is_uint(now):
            return {"ok": False, "code": "bad_record"}
        if rec["authority"] not in self.policy.get("authorities", []):
            return {"ok": False, "code": "unknown_authority"}
        out = [{"ok": False, "code": "store_unreachable"}]
        try:
            if not self._ready():
                return out[0]

            def step(prev: Any) -> Any:
                st = _load_shard(prev)
                cur = st["grants"].get(rec["id"])
                if cur is not None:
                    out[0] = {"ok": True, "replaced": False} if cur["rec"]["sig"] == rec["sig"] else {"ok": False, "code": "id_conflict"}
                    return None
                if _frozen_in(st["grants"], rec["holder"], now):
                    out[0] = {"ok": False, "code": "holder_frozen"}
                    return None
                st["grants"][rec["id"]] = {"rec": rec, "uses": []}
                out[0] = {"ok": True, "replaced": True}
                return st

            self.kv.update(self._key(rec["holder"]), step)
        except Exception:
            return {"ok": False, "code": "store_unreachable"}
        return out[0]

    def use(self, id: Any, holder: Any, action_digest: Any, now: Any, notified: Any) -> dict:
        """Record one use; ``notified`` must be True. Checks in order: input, existence, holder, freeze, revocation, window, budget, notification."""
        if not (is_str(id, 128) and is_str(holder, 128) and is_str(action_digest, 128) and is_uint(now) and isinstance(notified, bool)):
            return {"decision": "deny", "code": "bad_input"}
        out = [{"decision": "deny", "code": "store_unreachable", "id": id}]

        def deny(code: str) -> None:
            out[0] = {"decision": "deny", "code": code, "id": id}

        try:
            if not self._ready():
                return out[0]

            def step(prev: Any) -> Any:
                st = _load_shard(prev)
                e = st["grants"].get(id)
                if e is None:
                    return deny("unknown_break_glass")
                rec = e["rec"]
                if rec["holder"] != holder:
                    return deny("wrong_holder")
                if _frozen_in(st["grants"], holder, now):
                    return deny("holder_frozen")
                if e.get("review") is not None and e["review"]["outcome"] == "unjustified":
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
                out[0] = {"decision": "allow", "id": id, "use": len(e["uses"]), "remaining": rec["max_uses"] - len(e["uses"]),
                          "review_due": e["uses"][0]["at"] + rec["review_within"]}
                return st

            self.kv.update(self._key(holder), step)
        except Exception:
            return {"decision": "deny", "code": "store_unreachable", "id": id}
        return out[0]

    def review(self, rec: Any, holder: Any, now: Any) -> dict:
        """Record the signed review. The first review of a grant is final; a late review lifts an overdue freeze."""
        if not verify_break_glass_review(rec) or not is_str(holder, 128) or not is_uint(now):
            return {"ok": False, "code": "bad_record"}
        if rec["reviewer"] not in self.policy.get("reviewers", []):
            return {"ok": False, "code": "unknown_reviewer"}
        out = [{"ok": False, "code": "store_unreachable"}]
        try:
            if not self._ready():
                return out[0]

            def step(prev: Any) -> Any:
                st = _load_shard(prev)
                e = st["grants"].get(rec["id"])

                def fail(code: str) -> None:
                    out[0] = {"ok": False, "code": code}

                if e is None or e["rec"]["holder"] != holder:
                    return fail("unknown_break_glass")
                if rec["reviewer"] == e["rec"]["holder"] or rec["reviewer"] == e["rec"]["authority"]:
                    return fail("sod")
                if e.get("review") is not None:
                    if e["review"]["sig"] == rec["sig"]:
                        out[0] = {"ok": True, "replaced": False}
                        return None
                    return fail("already_reviewed")
                if not e["uses"]:
                    return fail("nothing_to_review")
                if rec["at"] < e["uses"][0]["at"] or rec["at"] > now:
                    return fail("bad_time")
                e["review"] = rec
                out[0] = {"ok": True, "replaced": True}
                return st

            self.kv.update(self._key(holder), step)
        except Exception:
            return {"ok": False, "code": "store_unreachable"}
        return out[0]

    def frozen(self, holder: Any, now: Any) -> bool:
        if not is_str(holder, 128) or not is_uint(now):
            return True  # fail closed
        try:
            if not self._ready():
                return True
            return _frozen_in(_load_shard(self.kv.get(self._key(holder)))["grants"], holder, now)
        except Exception:
            return True

    def uses(self, holder: str, id: str) -> List[dict]:
        """The numbered use log of a grant, oldest first."""
        if not self._ready() or not isinstance(holder, str) or not isinstance(id, str):
            return []
        e = _load_shard(self.kv.get(self._key(holder)))["grants"].get(id)
        return [dict(u) for u in e["uses"]] if e and e["rec"]["holder"] == holder else []
