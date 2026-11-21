"""Dead-man liveness beacons v2 (a port of the reference ``beacons.ts``): an issuer (the grant's principal, or the operator / guardian) signs
short-lived beacons, authority is live only while a valid beacon covers the current moment, and the PCActn binds one through its signed
``freshness.beacon_ref`` (= ``beacon_ref(b)``). Fail closed: an absent, stale, unpinned-issuer, wrong-scope or replayed beacon is frozen."""
from typing import Any, Callable, Dict, List, Optional, Sequence

from .agent import KeyPair, sign_artifact
from .intent_v2 import _UNDEF, _bind_suite_fields, _resolve_registered
from .intent_wb import _js_str
from .ledger import _signed
from .pca import b64u, canonical_bytes_strict, hash_canonical
from .k3 import is_uint

import hashlib
import math
from ._fin import fin

GLOBAL_SCOPE = "*"
LIVENESS_DOMAIN = "atlas-pca/beacon/v2\0"
BEACON_EPOCH_MS = 60_000  # length of one beacon epoch
BEACON_MAX_VALIDITY_MS = 60 * 60_000  # HARD ceiling on not_after - issued_at
BEACON_CLOCK_SKEW_MS = 30_000  # tolerated clock skew for a beacon issued "in the future"
_MAX_SAFE = 9007199254740991


def _int(v: Any) -> bool:
    """``Number.isInteger``: an integral finite number (a float with no fraction counts), never a boolean."""
    return isinstance(v, int) and not isinstance(v, bool) or (isinstance(v, float) and v == v and abs(v) != float("inf") and v == int(v))


def _safe_nonneg(v: Any) -> bool:
    """``Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0)``."""
    return _int(v) and 0 <= v <= _MAX_SAFE and not (isinstance(v, float) and str(v)[0] == "-")


def _body(b: Dict[str, Any]) -> Dict[str, Any]:
    return {"v": b.get("v"), "instance": b.get("instance"), "scope": b.get("scope"), "epoch": b.get("epoch"), "seq": b.get("seq"),
            "issued_at": b.get("issued_at"), "not_after": b.get("not_after"), "issuer": b.get("issuer")}


def issue_liveness_beacon(issuer: KeyPair, instance: str, seq: int, issued_at: int, scope: str = GLOBAL_SCOPE, validity_ms: Optional[int] = None,
                          alg: Optional[str] = None, pq: Any = None) -> Dict[str, Any]:
    """A signed beacon (Ed25519 by default; pass ``alg`` and the issuer's PQ key pair for another suite). Raises ValueError outside the bounds."""
    validity = 5 * BEACON_EPOCH_MS if validity_ms is None else validity_ms
    if not _int(seq) or seq < 0:
        raise ValueError("issueLivenessBeacon: seq must be a non-negative integer")
    if not _int(issued_at) or issued_at < 0:
        raise ValueError("issueLivenessBeacon: issuedAt must be an integer")
    if not _int(validity) or validity <= 0 or validity > BEACON_MAX_VALIDITY_MS:
        raise ValueError("issueLivenessBeacon: validity must be in (0, %d] ms" % BEACON_MAX_VALIDITY_MS)
    body = {"v": 2, "instance": instance, "scope": scope, "epoch": issued_at // BEACON_EPOCH_MS, "seq": seq, "issued_at": issued_at,
            "not_after": issued_at + validity, "issuer": issuer.public}
    return sign_artifact(LIVENESS_DOMAIN, body, issuer, alg, pq)


def liveness_beacon_message(b: Dict[str, Any]) -> bytes:
    """The signed bytes of a beacon body: the domain, then the canonical JSON of the body with the suite bound in (``alg`` and ``pq_pk`` for a
    non-Ed25519 suite)."""
    if any(k not in b for k in ("v", "instance", "scope", "epoch", "seq", "issued_at", "not_after", "issuer")):
        raise ValueError("canonicalize: unsupported type undefined")  # strict canonical JSON refuses an undefined member
    return LIVENESS_DOMAIN.encode("utf-8") + canonical_bytes_strict(_bind_suite_fields(_body(b), b.get("alg", _UNDEF), b.get("pq_pk", _UNDEF)))


def beacon_ref(b: Dict[str, Any]) -> str:
    """The stable reference to a beacon: what the PCActn commits in ``freshness.beacon_ref``."""
    return b64u(hashlib.sha256(canonical_bytes_strict(dict(b))).digest())


def _to_num(v: Any) -> float:
    """JS ToNumber for a clock value: undefined and an unparseable string are NaN (every comparison false), null is 0."""
    if v is _UNDEF:
        return math.nan
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        try:
            return float(v)
        except OverflowError:  # an int beyond the double range is no usable clock
            return math.nan
    if isinstance(v, str):
        t = v.strip()
        try:
            return float(t) if t else 0.0
        except ValueError:
            return math.nan
    return math.nan


def _plus_skew(now: Any) -> float:
    """`now + BEACON_CLOCK_SKEW_MS` as JS evaluates it: a string concatenates (and is then read as a number)."""
    return _to_num(now + str(BEACON_CLOCK_SKEW_MS)) if isinstance(now, str) else _to_num(now) + BEACON_CLOCK_SKEW_MS


def verify_liveness_beacon(b: Any, issuers: Sequence[str], now: int, instance: str, scope: Optional[str] = None,
                           pq_pins: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Signature, pinned issuer, instance and scope binding, the HARD maximum validity and the freshness window: ``{"ok", "reason"?}``. Never raises."""
    try:
        if not isinstance(b, dict) or b.get("v") != 2 or _resolve_registered(b.get("alg", _UNDEF)) is None:
            return {"ok": False, "reason": "malformed beacon"}
        if b.get("instance") != instance:
            return {"ok": False, "reason": "wrong instance"}
        if b.get("issuer") not in issuers:
            return {"ok": False, "reason": "issuer not pinned"}
        if not _signed(LIVENESS_DOMAIN, _body(b), b["issuer"], b, pq_pins):
            return {"ok": False, "reason": "bad signature"}
        if not all(_int(b.get(k)) for k in ("epoch", "seq", "issued_at", "not_after")) or b["seq"] < 0:
            return {"ok": False, "reason": "malformed window"}
        if b["not_after"] <= b["issued_at"] or b["not_after"] - b["issued_at"] > BEACON_MAX_VALIDITY_MS:
            return {"ok": False, "reason": "validity exceeds the hard maximum"}
        if b["epoch"] != b["issued_at"] // BEACON_EPOCH_MS:
            return {"ok": False, "reason": "epoch does not match issued_at"}
        if not (fin(_plus_skew(now)) and _plus_skew(now) >= b["issued_at"]):
            return {"ok": False, "reason": "not yet valid"}
        if not (fin(_to_num(now)) and _to_num(now) <= b["not_after"]):
            return {"ok": False, "reason": "expired"}
        if scope is not None and b.get("scope") != GLOBAL_SCOPE and b.get("scope") != scope:
            return {"ok": False, "reason": "scope not covered"}
        return {"ok": True}
    except Exception:  # noqa: BLE001
        return {"ok": False, "reason": "malformed beacon"}


def accept_beacon(prev: Any, nxt: Any) -> Dict[str, Any]:
    """Monotonic acceptance: a beacon replaces the stored one only with a STRICTLY higher ``seq``; total (a malformed beacon is refused)."""
    seq = nxt.get("seq") if isinstance(nxt, dict) else None
    if not isinstance(nxt, dict) or not _safe_nonneg(seq):
        return {"ok": False, "reason": "malformed beacon"}
    if prev is not None and prev is not False and prev != 0 and prev != "":  # any object is truthy, an empty one included
        ps = prev.get("seq", _UNDEF) if isinstance(prev, dict) else _UNDEF
        if not seq > _to_num(ps):  # JS `next.seq > prev.seq`: a string reads as a number, an absent member is NaN
            return {"ok": False, "reason": "replayed beacon: seq %s <= %s" % (seq, _js_str(ps))}
    return {"ok": True}


def is_frozen_liveness(beacons: Sequence[Any], issuers: Sequence[str], now: int, instance: str, scope: Optional[str] = None,
                       pq_pins: Optional[Dict[str, str]] = None) -> bool:
    """Frozen unless at least one beacon verifies for (instance, scope, now). Absence is a freeze."""
    return not any(verify_liveness_beacon(b, issuers, now, instance, scope, pq_pins)["ok"] for b in beacons)


def _beacon_key(b: Dict[str, Any]) -> str:
    import json
    return "beacon-seq/v1/" + json.dumps([b["instance"], b["scope"], b["issuer"]], separators=(",", ":"), ensure_ascii=False)


class BeaconAcceptor:
    """Durable replay protection: keeps the highest accepted ``seq`` per (instance, scope, issuer) in an atomic key-value store (``update(key, fn)``,
    e.g. :class:`atlas_pca.SqliteAtomicKv`), under one atomic read-modify-write. FAIL CLOSED: when the store cannot decide the beacon is refused
    with ``beacon state unavailable``."""

    def __init__(self, kv: Any) -> None:
        if not callable(getattr(kv, "update", None)):
            raise TypeError("createBeaconAcceptor: a DurableKv is required")
        self.kv = kv

    def accept(self, b: Any, issuers: Sequence[str], now: int, instance: str, scope: Optional[str] = None,
               pq_pins: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        v = verify_liveness_beacon(b, issuers, now, instance, scope, pq_pins)
        if not v["ok"]:
            return v
        replay_of: List[Any] = []

        def step(prev: Any) -> Any:
            if prev is not None and not _safe_nonneg(prev):
                raise TypeError("junk on disk")
            if prev is not None and not b["seq"] > prev:
                replay_of.append(prev)
                return None
            return b["seq"]

        try:
            self.kv.update(_beacon_key(b), step)
        except Exception:  # noqa: BLE001
            return {"ok": False, "reason": "beacon state unavailable"}
        return {"ok": True} if not replay_of else {"ok": False, "reason": "replayed beacon: seq %d <= %d" % (b["seq"], replay_of[0])}


def create_beacon_acceptor(kv: Any) -> BeaconAcceptor:
    return BeaconAcceptor(kv)


def beacon_decision(present: bool, ok: bool, replayed: bool, ref_binds: bool) -> str:
    """The verified beacon-check decision: ``rejected`` / ``replayed`` / ``unbound`` / ``pass`` / ``not-enforced``."""
    if not present:
        return "not-enforced"
    if not ok:
        return "rejected"
    if replayed:
        return "replayed"
    return "pass" if ref_binds else "unbound"
