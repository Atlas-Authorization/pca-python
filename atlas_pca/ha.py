"""Guardian high availability: liveness, quorum, degrade mode, signer selection and failover over guardian health facts, plus a
durable, FENCED leader lease (at most one holder, a strictly monotone fencing epoch, store-side expiry, "no leader" whenever the
store errs). A port of the reference ``ha`` module, argument shapes included: a malformed set, clock or heartbeat counts as down and
the module never fails OPEN (losing quorum or the lease restricts authority, never widens it).

Lease safety holds IF the store's compare-and-swap is linearizable and the holder's clock error stays under ``skew_ms``. A downstream
that never checks the fencing epoch is not protected: check it with :class:`FenceGuard`."""
from __future__ import annotations

from ._fin import fin, to_float
import functools
import math
import time
from typing import Any, Callable, Dict, List, Optional

from .durable_state import create_memory_durable_kv

__all__ = ["MAX_LEASE_TTL_MS", "DEFAULT_LEASE_SKEW_MS", "live_guardians", "quorum_status", "degrade_mode", "select_signers", "failover_plan",
           "validate_guardian_set", "acquire_lease", "renew_lease", "release_lease", "assert_fence", "FenceError", "fenced_signer",
           "create_fence_guard", "FenceGuard", "KvLeaseStore"]

MAX_LEASE_TTL_MS = 3_600_000
DEFAULT_LEASE_SKEW_MS = 1_000
_MAX_HOLDER_LEN = 256
_UNDEF = object()  # a member the reference object does not have (distinct from a JSON null)


def _prop(o: Any, k: str) -> Any:
    """``o.k`` of the reference: a null object throws, a non-object (or an array) has no such member."""
    if o is None:
        raise TypeError("cannot read properties of null (reading '%s')" % k)
    return o.get(k, _UNDEF) if isinstance(o, dict) else _UNDEF


def _is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _finite(x: Any) -> bool:
    return _is_num(x) and fin(x)


def _integer(x: Any) -> bool:
    return _finite(x) and x == math.floor(x)


def _safe_integer(x: Any) -> bool:
    return _integer(x) and abs(x) <= 9007199254740991


def _truthy(x: Any) -> bool:
    return not (x is None or x is _UNDEF or x is False or (_is_num(x) and (x == 0 or x != x)) or x == "")


def _to_number(x: Any) -> float:
    """The reference's ToNumber for the relational operators (null 0, undefined NaN, booleans, numeric strings)."""
    if x is _UNDEF:
        return math.nan
    if x is None or x is False:
        return 0.0
    if x is True:
        return 1.0
    if _is_num(x):
        return to_float(x)
    if isinstance(x, str):
        t = x.strip()
        if t == "":
            return 0.0
        if t.lstrip("+-") == "Infinity" and len(t) - len(t.lstrip("+-")) <= 1:
            return -math.inf if t[0] == "-" else math.inf
        try:
            return float(t) if not t.lower().lstrip("+-") in ("nan", "inf", "infinity") and "_" not in t else math.nan
        except ValueError:
            return math.nan
    return math.nan


def _utf16_len(s: str) -> int:
    return len(s.encode("utf-16-be", "surrogatepass")) // 2


_COLLATOR: Any = None


def _locale_compare(a: Any, b: Any) -> int:
    """The reference's ``a.localeCompare(b)``: ICU root collation (UCA, tertiary strength, punctuation not ignored). Done by pyuca, a
    pure-Python UCA over the DUCET table: chosen over a hand-written Latin approximation (wrong beyond Latin) and over PyICU (needs a system
    ICU, no wheels), and it adds no native dependency. Known limit: DUCET and its Unicode version, not CLDR's root tailoring, so a few
    symbol orderings can differ; ids are expected to be words and digits."""
    global _COLLATOR
    if not isinstance(a, str):
        raise TypeError("localeCompare is not a function")
    if _COLLATOR is None:
        from pyuca import Collator
        _COLLATOR = Collator()
    bs = b if isinstance(b, str) else "undefined" if b is _UNDEF else "null" if b is None else str(b)
    ka, kb = _COLLATOR.sort_key(a), _COLLATOR.sort_key(bs)
    return (ka > kb) - (ka < kb)


def _is_obj(g: Any) -> bool:
    return isinstance(g, (dict, list))


def _opt(o: Any, k: str, default: Any) -> Any:
    """``o?.k ?? default``."""
    v = o.get(k) if isinstance(o, dict) else None
    return default if v is None else v


def live_guardians(guardian_set: Any, now: Any, opts: Optional[dict] = None) -> List[dict]:
    """Guardians flagged healthy AND with a fresh heartbeat at ``now``. Fails closed: a malformed set, a non-finite clock or stale
    window, a non-finite or FUTURE-dated heartbeat, or a non-boolean ``healthy`` counts as down."""
    stale = _opt(opts, "staleMs", 30_000)
    gs = _prop(guardian_set, "guardians") if guardian_set is not None else _UNDEF
    if not _finite(now) or not _finite(stale) or stale < 0 or not isinstance(gs, list) or not all(g is not None and _is_obj(g) for g in gs):
        return []
    return [g for g in gs if isinstance(g, dict) and g.get("healthy") is True and _finite(g.get("lastSeen")) and g["lastSeen"] <= now and now - g["lastSeen"] <= stale]


def _weight(g: dict) -> Any:
    w = g.get("weight")
    return w if _finite(w) else 0


def _order(live: List[dict]) -> List[dict]:
    def cmp(a: dict, b: dict) -> Any:
        return (_weight(b) - _weight(a)) or (b["lastSeen"] - a["lastSeen"]) or _locale_compare(a.get("id", _UNDEF), b.get("id", _UNDEF))
    return sorted(live, key=functools.cmp_to_key(cmp))


def quorum_status(guardian_set: Any, now: Any, opts: Optional[dict] = None) -> Dict[str, Any]:
    """{total, live, quorum, available, degraded}: total and live guardian counts, whether a co-sign quorum is reachable, whether some
    are live but below quorum. ``quorum`` is absent when the set has none."""
    live = len(live_guardians(guardian_set, now, opts))
    gs = _prop(guardian_set, "guardians") if guardian_set is not None else _UNDEF
    q = _prop(guardian_set, "quorum") if guardian_set is not None else _UNDEF
    out: Dict[str, Any] = {"total": len(gs) if isinstance(gs, list) else 0, "live": live}
    if q is not _UNDEF:
        out["quorum"] = q
    out["available"] = _integer(q) and q >= 1 and live >= q
    out["degraded"] = live > 0 and live < _to_number(q)
    return out


def degrade_mode(status: Any, policy: Optional[dict] = None) -> str:
    """'normal' (quorum available) | 'read-only' (below quorum, some live) | 'halt' (none live, or read-only switched off). Never fails open."""
    if _truthy(_prop(status, "available")):
        return "normal"
    live = _to_number(_prop(status, "live"))
    if live > 0 and (policy.get("allowReadOnly") if isinstance(policy, dict) else None) is not False:
        return "read-only"
    return "halt"


def select_signers(guardian_set: Any, now: Any, opts: Optional[dict] = None) -> List[Any]:
    """The ``quorum`` freshest, highest-weight live guardians; empty when quorum is not available."""
    live = live_guardians(guardian_set, now, opts)
    q = _prop(guardian_set, "quorum")
    if not _integer(q) or q < 1 or len(live) < q:
        return []
    return [g.get("id") for g in _order(live)[:int(q)]]


def failover_plan(guardian_set: Any, now: Any, opts: Optional[dict] = None) -> Dict[str, Any]:
    """{primary, standbys}: the preferred live guardian (None when none is live) and the others in preference order."""
    live = _order(live_guardians(guardian_set, now, opts))
    return {"primary": live[0].get("id") if live else None, "standbys": [g.get("id") for g in live[1:]]}


def validate_guardian_set(guardian_set: Any) -> Optional[str]:
    """An error string, or None when the set is well formed (quorum in range, unique non-empty ids)."""
    if not _is_obj(guardian_set):
        return "guardian set is not an object"
    gs, q = _prop(guardian_set, "guardians"), _prop(guardian_set, "quorum")
    if not isinstance(gs, list) or len(gs) == 0:
        return "guardian set is empty"
    if not _integer(q) or q < 1:
        return "quorum must be an integer ≥ 1"
    if q > len(gs):
        return "quorum exceeds guardian count"
    if not all(isinstance(g, dict) and isinstance(g.get("id"), str) and len(g["id"]) > 0 for g in gs):
        return "guardian id must be a non-empty string"
    if len({g["id"] for g in gs}) != len(gs):
        return "duplicate guardian ids"
    return None


# ---- durable, fenced leader lease ----

def _valid_record(r: Any) -> bool:
    return (isinstance(r, dict) and isinstance(r.get("holder"), str) and _safe_integer(r.get("epoch")) and r["epoch"] >= 1
            and _finite(r.get("expiresAt")) and r["expiresAt"] >= 0)


def _seq(a: Any, b: Any) -> bool:
    """Strict equality of two JSON values of the reference."""
    if _is_num(a) and _is_num(b):
        return a == b
    return type(a) is type(b) and a == b if isinstance(a, (str, bool)) else a is b


def _eq_lease(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return a is b
    return all(_seq(_prop(a, k), _prop(b, k)) for k in ("holder", "epoch", "expiresAt"))


def _lease_opts(holder: Any, o: Any) -> Optional[tuple]:
    if not isinstance(holder, str) or len(holder) == 0 or _utf16_len(holder) > _MAX_HOLDER_LEN:
        return None
    skew = _opt(o, "skewMs", DEFAULT_LEASE_SKEW_MS)
    ttl = o.get("ttlMs") if isinstance(o, dict) else None
    if not _integer(ttl) or ttl < 2 or ttl > MAX_LEASE_TTL_MS:
        return None
    if not _finite(skew) or skew < 0 or skew >= ttl:
        return None
    return ttl, skew


def _snapshot(store: Any) -> tuple:
    """Read the record and the store clock; a corrupt record or clock is a store error (never "free")."""
    cur = store.read()
    now = store.now()
    if not _finite(now) or (cur is not None and not _valid_record(cur)):
        raise ValueError("corrupt lease state")
    return cur, now


def _fail(reason: str, e: Optional[BaseException] = None) -> Dict[str, Any]:
    r: Dict[str, Any] = {"ok": False, "reason": reason}
    if e is not None:
        r["detail"] = str(e)
    return r


def _commit(store: Any, cur: Any, nxt: dict) -> Dict[str, Any]:
    return {"ok": True, "lease": nxt} if store.cas(cur, nxt) else _fail("lost-race")


def acquire_lease(store: Any, holder: Any, options: Any) -> Dict[str, Any]:
    """Take the lease if it is free (never held, released, or expired past the skew); the epoch increments on every takeover.
    {ok: True, lease} or {ok: False, reason: invalid | held | lost-race | store-error[, detail]}."""
    p = _lease_opts(holder, options)
    if not p:
        return _fail("invalid")
    try:
        cur, now = _snapshot(store)
        if cur is not None and cur["expiresAt"] + p[1] > now and cur["expiresAt"] != 0:
            return _fail("held")
        return _commit(store, cur, {"holder": holder, "epoch": (cur["epoch"] if cur else 0) + 1, "expiresAt": now + p[0]})
    except Exception as e:  # noqa: BLE001 - a store that errs means no leader
        return _fail("store-error", e)


def renew_lease(store: Any, lease: Any, options: Any) -> Dict[str, Any]:
    """Extend a lease the caller still holds; refused once the holder's own safe window (expiry minus skew) has passed, or after any takeover."""
    p = _lease_opts(lease["holder"], options) if _valid_record(lease) else None
    if not p:
        return _fail("invalid")
    try:
        cur, now = _snapshot(store)
        if not cur or cur["holder"] != lease["holder"] or cur["epoch"] != lease["epoch"]:
            return _fail("stale")
        if cur["expiresAt"] - p[1] <= now:
            return _fail("expired")
        return _commit(store, cur, {"holder": cur["holder"], "epoch": cur["epoch"], "expiresAt": now + p[0]})
    except Exception as e:  # noqa: BLE001
        return _fail("store-error", e)


def release_lease(store: Any, lease: Any) -> Dict[str, Any]:
    """Give the lease up early (expiresAt 0, epoch kept); only the current holder at the current epoch can."""
    if not _valid_record(lease):
        return _fail("invalid")
    try:
        cur, _ = _snapshot(store)
        if not cur or cur["holder"] != lease["holder"] or cur["epoch"] != lease["epoch"] or cur["expiresAt"] == 0:
            return _fail("stale")
        return _commit(store, cur, {"holder": cur["holder"], "epoch": cur["epoch"], "expiresAt": 0})
    except Exception as e:  # noqa: BLE001
        return _fail("store-error", e)


def assert_fence(store: Any, token: Any, skew_ms: Any = DEFAULT_LEASE_SKEW_MS) -> Dict[str, Any]:
    """Is this exact (holder, epoch) still the leader with its safe window open, per the store? Any error answers no."""
    try:
        if not _truthy(token) or not _finite(skew_ms) or skew_ms < 0:
            return {"ok": False, "reason": "stale"}
        cur, now = _snapshot(store)
        if not cur or not _seq(cur["holder"], _prop(token, "holder")) or not _seq(cur["epoch"], _prop(token, "epoch")):
            return {"ok": False, "reason": "stale"}
        return {"ok": True} if cur["expiresAt"] - skew_ms > now else {"ok": False, "reason": "expired"}
    except Exception:  # noqa: BLE001
        return {"ok": False, "reason": "store-error"}


class FenceError(Exception):
    """``reason``: stale | expired | store-error | no-lease."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__("fenced: %s" % reason)


def fenced_signer(store: Any, get_lease: Callable[[], Any], sign: Callable[..., Any], skew_ms: Any = DEFAULT_LEASE_SKEW_MS) -> Callable[..., Dict[str, Any]]:
    """Wrap a co-sign function so it only runs while the caller is the fenced leader. The fence is checked before AND after the
    signature: a leader that lost the lease mid-signature gets a FenceError and the signature is discarded. Check-then-sign is
    inherently racy: the downstream must also :meth:`FenceGuard.admit` the epoch."""
    def run(*a: Any) -> Dict[str, Any]:
        lease = get_lease()
        if not _truthy(lease):
            raise FenceError("no-lease")
        pre = assert_fence(store, lease, skew_ms)
        if not pre["ok"]:
            raise FenceError(pre["reason"])
        result = sign(*a)
        post = assert_fence(store, lease, skew_ms)
        if not post["ok"]:
            raise FenceError(post["reason"])
        return {"result": result, "epoch": lease["epoch"]}
    return run


class FenceGuard:
    """Resource-side fencing: remembers the highest epoch seen and refuses anything lower (a stale ex-leader's late write)."""

    def __init__(self, initial: Any = 0) -> None:
        self._hi = initial if _safe_integer(initial) and initial > 0 else 0  # -0 starts at 0 like any other non-positive value

    def admit(self, epoch: Any) -> bool:
        if not _safe_integer(epoch) or epoch < 1 or epoch < self._hi:
            return False
        self._hi = epoch
        return True

    def highest(self) -> Any:
        return self._hi


def create_fence_guard(initial: Any = 0) -> FenceGuard:
    return FenceGuard(initial)


class KvLeaseStore:
    """Reference lease store over any durable key/value store whose ``update`` is the atomic compare-and-swap
    (:func:`atlas_pca.durable_state.open_durable_state` survives restarts)."""

    def __init__(self, kv: Any = None, key: Optional[str] = None, now: Optional[Callable[[], Any]] = None) -> None:
        self._kv = kv if kv is not None else create_memory_durable_kv()
        self._key = key if key is not None else "ha/lease"
        self._now = now

    def read(self) -> Optional[dict]:
        v = self._kv.get(self._key)
        if v is not None and not _valid_record(v):
            raise ValueError("corrupt lease state")
        return v

    def cas(self, expected: Optional[dict], nxt: dict) -> bool:
        """Replace the record iff the stored one equals ``expected`` (None = none); the epoch never goes below the stored one."""
        if not _valid_record(nxt):
            raise ValueError("invalid lease record")
        matched = []

        def upd(prev: Any) -> Any:
            if prev is not None and not _valid_record(prev):
                return None
            if not _eq_lease(prev, expected) or nxt["epoch"] < (prev["epoch"] if prev is not None else 0):
                return None
            matched.append(True)
            return nxt

        self._kv.update(self._key, upd)
        return bool(matched)

    def now(self) -> Any:
        return self._now() if self._now is not None else int(time.time() * 1000)
