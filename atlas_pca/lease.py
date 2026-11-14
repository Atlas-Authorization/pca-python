"""Leases (verification side): a time-boxed grant that must be renewed, has a hard ``max_ttl`` cap, and dies when revoked.
Records and revocations are Ed25519-signed under a domain string over strict-canonical JSON. ``LeaseRegistry`` keeps the newest
record per ``lease_id`` plus the revocations in a durable key-value store you pass (``MemoryAtomicKv`` is for tests and single-process use);
``check_lease`` gates a presented record. Total: no function raises.
Results are dicts shaped like the shared vectors (``lease-vectors.json``)."""
import hashlib
import re
import time
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


DEFAULT_LEASE_SHARDS = 16
MAX_LEASE_SHARDS = 4096
_META_KEY = "lease/meta"


def lease_shard_key(shards: int, i: int) -> str:
    return "lease/%d/%d" % (shards, i)


def shard_of(lease_id: str, shards: int) -> int:
    """The shard a lease id lives in: the first four bytes of SHA-256 of the id, modulo the shard count. Stable across processes."""
    return int.from_bytes(hashlib.sha256(lease_id.encode("utf-8")).digest()[:4], "big") % shards


def _load(x: Any) -> dict:
    return x if is_obj(x) and is_obj(x.get("leases")) and isinstance(x.get("revocations"), list) else {"leases": {}, "revocations": []}


def _own(m: dict, key: str) -> Optional[dict]:
    return m[key] if key in m else None


class LeaseRegistry:
    """``policy``: ``authorities`` (list of keys), optional ``minApprovals``, ``eligibleApprovers``, ``freshJustification`` (default true),
    ``maxTtlCeiling`` (longest accepted ``max_ttl``, ms; when set a revocation is pruned once ``revoked_at + ceiling`` is past).

    ``kv`` is REQUIRED: a durable key-value store with ``get(key)`` and an atomic ``update(key, fn)`` (:class:`atlas_pca.SqliteAtomicKv`;
    :class:`atlas_pca.MemoryAtomicKv` forgets everything on restart, so it is for tests and single-process use). Each lease lives in the
    shard its id hashes to; a path-prefix or grant revocation is written to every shard. ``shards`` is fixed for the life of the store.
    ``clock`` is the clock for revocation pruning (epoch ms)."""

    def __init__(self, policy: dict, kv: Any = None, *, shards: int = DEFAULT_LEASE_SHARDS, clock: Any = None) -> None:
        if isinstance(kv, dict) or not callable(getattr(kv, "get", None)) or not callable(getattr(kv, "update", None)):  # a plain dict has both names but is no store
            raise TypeError("LeaseRegistry: a durable key-value store is required (MemoryAtomicKv() is for tests and single-process use)")
        if isinstance(shards, bool) or not isinstance(shards, int) or shards < 1 or shards > MAX_LEASE_SHARDS:
            raise ValueError("LeaseRegistry: shards must be an integer from 1 to 4096")
        if isinstance(policy, dict) and "maxTtlCeiling" in policy and not (is_uint(policy["maxTtlCeiling"]) and policy["maxTtlCeiling"] >= 1):
            raise ValueError("LeaseRegistry: maxTtlCeiling must be a positive integer")
        self.policy = policy
        self.kv = kv
        self.shards = shards
        self._clock = clock if clock is not None else (lambda: int(time.time() * 1000))
        self._meta_ok: Optional[bool] = None

    @property
    def shard_count(self) -> int:
        return self.shards

    def _ready(self) -> bool:
        """Pin the shard count in the store on first use; a different count would make existing leases invisible, so it is refused."""
        if self._meta_ok is None:
            m = self.kv.update(_META_KEY, lambda prev: {"v": 1, "shards": self.shards} if prev is None else None)
            self._meta_ok = is_obj(m) and m.get("shards") == self.shards
        return bool(self._meta_ok)

    def _prune(self, st: dict) -> None:
        c = self.policy.get("maxTtlCeiling")
        if c is None:
            return
        now = self._clock()
        st["revocations"] = [r for r in st["revocations"] if r["revoked_at"] + c >= now]

    def accept(self, rec: Any, chain: Sequence[str] = ()) -> dict:
        """Take an issue (seq 1) or a renewal (seq = current + 1). ``chain``: the keys in the holder's delegation chain, for the SoD rule."""
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
        if "maxTtlCeiling" in self.policy and l["max_ttl"] > self.policy["maxTtlCeiling"]:
            return {"ok": False, "code": "ttl_ceiling"}
        out: List[dict] = [{"ok": False, "code": "store_unreachable"}]
        try:
            if not self._ready():
                return out[0]

            def step(prev: Any) -> Any:
                st = _load(prev)
                st = {"leases": dict(st["leases"]), "revocations": list(st["revocations"])}
                held = _own(st["leases"], l["lease_id"])
                cur = held["current"] if held else None

                def fail(code: str, reason: Optional[str] = None) -> None:
                    out[0] = {"ok": False, "code": code, **({"reason": reason} if reason else {})}

                if any(_covers(r, l) for r in st["revocations"]):
                    return fail("revoked")
                if cur is None:
                    if l["seq"] != 1:
                        return fail("bad_seq", "a new lease starts at seq 1")
                else:
                    if l["seq"] < cur["seq"]:
                        return fail("stale_seq")
                    if l["seq"] == cur["seq"]:
                        if cur["sig"] == l["sig"]:
                            out[0] = {"ok": True, "replaced": False, "seq": l["seq"]}
                            return None
                        return fail("lease_fork")
                    if l["seq"] != cur["seq"] + 1:
                        return fail("bad_seq", "renewals advance seq by exactly 1")
                    if any(l[k] != cur[k] for k in ("authority", "path", "grant_ref", "holder", "requester", "max_ttl", "issued_at")):
                        return fail("renewal_mismatch")
                    if l["renewed_at"] >= cur["expires_at"]:
                        return fail("expired_lease", "an expired lease cannot be renewed")
                    if l["renewed_at"] < cur["renewed_at"] or l["expires_at"] <= cur["expires_at"]:
                        return fail("not_extending")
                    if self.policy.get("freshJustification", True) is not False and l["justification_digest"] == cur["justification_digest"]:
                        return fail("stale_justification")
                entry = {"seq": l["seq"], "renewed_at": l["renewed_at"], "expires_at": l["expires_at"], "justification_digest": l["justification_digest"]}
                st["leases"][l["lease_id"]] = {"current": l, "history": (list(held["history"]) if held else []) + [entry]}
                self._prune(st)
                out[0] = {"ok": True, "replaced": True, "seq": l["seq"]}
                return st

            self.kv.update(lease_shard_key(self.shards, shard_of(l["lease_id"], self.shards)), step)
        except Exception:
            return {"ok": False, "code": "store_unreachable"}
        return out[0]

    def revoke(self, rec: Any) -> dict:
        """Take a signed revocation. Idempotent. A prefix or grant revocation is written to every shard; ``revoked`` counts the leases covered."""
        try:
            if not verify_lease_revocation(rec):
                return {"ok": False, "code": "bad_record"}
            if rec["authority"] not in self.policy.get("authorities", []):
                return {"ok": False, "code": "unknown_authority"}
            targets = [shard_of(rec["value"], self.shards)] if rec["target"] == "lease" else list(range(self.shards))
            n = [0]
            if not self._ready():
                return {"ok": False, "code": "store_unreachable"}
            for i in targets:
                def step(prev: Any) -> Any:
                    st = _load(prev)
                    st = {"leases": dict(st["leases"]), "revocations": list(st["revocations"])}
                    if not any(r["sig"] == rec["sig"] for r in st["revocations"]):
                        st["revocations"].append(rec)
                    n[0] += sum(1 for h in st["leases"].values() if _covers(rec, h["current"]))
                    self._prune(st)
                    return st

                self.kv.update(lease_shard_key(self.shards, i), step)
            return {"ok": True, "revoked": n[0]}
        except Exception:
            return {"ok": False, "code": "store_unreachable"}

    def _shard(self, lease_id: str) -> dict:
        if not self._ready():
            raise RuntimeError("shard count mismatch")
        return _load(self.kv.get(lease_shard_key(self.shards, shard_of(lease_id, self.shards))))

    def get(self, lease_id: str) -> Optional[dict]:
        held = _own(self._shard(lease_id)["leases"], lease_id)
        return held["current"] if held else None

    def history(self, lease_id: str) -> List[dict]:
        """The renewal ledger of a lease, oldest first."""
        held = _own(self._shard(lease_id)["leases"], lease_id)
        return list(held["history"]) if held else []

    def lookup(self, lease_id: str) -> Optional[dict]:
        """The newest record of a lease and whether a stored revocation covers it: ``{"current", "revoked"}``."""
        st = self._shard(lease_id)
        held = _own(st["leases"], lease_id)
        if held is None:
            return None
        return {"current": held["current"], "revoked": any(_covers(r, held["current"]) for r in st["revocations"])}

    def shard_revocations(self, i: int) -> List[dict]:
        """Revocations held by one shard (for operators and the conformance kit)."""
        if isinstance(i, bool) or not isinstance(i, int) or i < 0 or i >= self.shards:
            raise ValueError("no such shard")
        return _load(self.kv.get(lease_shard_key(self.shards, i)))["revocations"]


def check_lease(presented: Any, registry: LeaseRegistry, now: Any) -> dict:
    """Is ``presented`` a live lease? Verifies, newest record, window and cap, not revoked. Fails closed."""
    if not is_uint(now):
        return {"decision": "deny", "code": "bad_input"}
    if not verify_lease(presented):
        return {"decision": "deny", "code": "bad_record"}
    lid = presented["lease_id"]
    try:
        found = registry.lookup(lid)
        if found is None:
            return {"decision": "deny", "code": "unknown_lease", "lease_id": lid}
        cur = found["current"]
        if cur["sig"] != presented["sig"]:
            return {"decision": "deny", "code": "superseded", "lease_id": lid}
        if found["revoked"]:
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
