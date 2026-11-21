"""Dead-man liveness beacons v2 (a port of the reference ``beacons.ts``): an issuer (the grant's principal, or the operator / guardian) signs
short-lived beacons, authority is live only while a valid beacon covers the current moment, and the PCActn binds one through its signed
``freshness.beacon_ref`` (= ``beacon_ref(b)``). Fail closed: an absent, stale, unpinned-issuer, wrong-scope or replayed beacon is frozen."""
from typing import Any, Callable, Dict, List, Optional, Sequence

from .agent import KeyPair, sign_artifact
from .intent_v2 import _UNDEF, _resolve_registered
from .ledger import _signed
from .pca import b64u, canonical_bytes_strict, hash_canonical
from .k3 import is_uint

import hashlib

GLOBAL_SCOPE = "*"
LIVENESS_DOMAIN = "atlas-pca/beacon/v2\0"
BEACON_EPOCH_MS = 60_000  # length of one beacon epoch
BEACON_MAX_VALIDITY_MS = 60 * 60_000  # HARD ceiling on not_after - issued_at
BEACON_CLOCK_SKEW_MS = 30_000  # tolerated clock skew for a beacon issued "in the future"
_MAX_SAFE = 9007199254740991


def _int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


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


def beacon_ref(b: Dict[str, Any]) -> str:
    """The stable reference to a beacon: what the PCActn commits in ``freshness.beacon_ref``."""
    return b64u(hashlib.sha256(canonical_bytes_strict(dict(b))).digest())


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
        if now + BEACON_CLOCK_SKEW_MS < b["issued_at"]:
            return {"ok": False, "reason": "not yet valid"}
        if now > b["not_after"]:
            return {"ok": False, "reason": "expired"}
        if scope is not None and b.get("scope") != GLOBAL_SCOPE and b.get("scope") != scope:
            return {"ok": False, "reason": "scope not covered"}
        return {"ok": True}
    except Exception:  # noqa: BLE001
        return {"ok": False, "reason": "malformed beacon"}


def accept_beacon(prev: Any, nxt: Any) -> Dict[str, Any]:
    """Monotonic acceptance: a beacon replaces the stored one only with a STRICTLY higher ``seq``; total (a malformed beacon is refused)."""
    seq = nxt.get("seq") if isinstance(nxt, dict) else None
    if not isinstance(nxt, dict) or not _int(seq) or seq < 0 or seq > _MAX_SAFE:
        return {"ok": False, "reason": "malformed beacon"}
    if isinstance(prev, dict) and prev and not seq > prev.get("seq"):
        return {"ok": False, "reason": "replayed beacon: seq %d <= %s" % (seq, prev.get("seq"))}
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
            if prev is not None and not (isinstance(prev, int) and not isinstance(prev, bool) and 0 <= prev <= _MAX_SAFE):
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
