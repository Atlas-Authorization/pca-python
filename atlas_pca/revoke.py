"""Realtime revocation and a mid-run kill-switch (the TypeScript reference, @atlasauth/pca-revoke).

The core verifier is a pull check; this adds the ACTIVE boundary: a pluggable :class:`RevocationRegistry` keyed by capability
id, agent holder key, issuer key, or delegation-subtree prefix. :func:`check_revocation` walks EVERY hop of a PCActn's
``cap_chain`` and fails closed; :func:`verify_with_revocation` ANDs the core outcome with that gate; :func:`ingest_caep_event`
turns an OpenID Shared-Signals / CAEP event into registry entries. Entries are plain JSON-shaped dicts
(``kind``, ``value``, ``prefix``?, ``reason``, ``revokedAt`` in epoch ms, ``notBefore``?), the same shape the TypeScript package
stores, so a :class:`FileRevocationStore` file is interchangeable with it."""
from __future__ import annotations

from ._fin import fin
import copy
import json
import math
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

PREFIX_SEP = ","
KINDS = ("cap", "holder", "issuer", "prefix")

CAEP_EVENT_TYPES = {
    "sessionRevoked": "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
    "grantRevoked": "https://atlasauth.net/caep/grant-revoked",
    "killSwitch": "https://atlasauth.net/caep/kill-switch",
}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _finite(v: Any) -> bool:
    """A JSON number (not a bool) that is finite."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    try:
        return fin(float(v))
    except OverflowError:
        return False


def _nonempty(v: Any) -> bool:
    return isinstance(v, str) and len(v) > 0


def _key(kind: Any, value: Any) -> Any:
    return (kind, value)


def serialize_prefix(prefix: List[str]) -> str:
    return PREFIX_SEP.join(prefix)


def is_active_at(entry: Dict[str, Any], now: Any) -> bool:
    """True when a revocation is in effect at ``now`` (a future ``notBefore`` has not yet been reached)."""
    if not isinstance(entry, dict) or "notBefore" not in entry:
        return True
    nb = entry["notBefore"]
    # a non-finite clock or schedule can never be shown to be "in the future", so it bites
    if not _finite(now) or not _finite(nb):
        return True
    return now >= nb


# ---------------------------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------------------------

class InMemoryRevocationStore:
    """In-memory store (the default). One process; swap in a shared store for a fleet. Methods: ``add(entry)``,
    ``remove(kind, value) -> bool``, ``get(kind, value) -> entry | None``, ``all() -> list`` (a snapshot), ``clear()``."""

    def __init__(self) -> None:
        self._m: Dict[Any, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def add(self, entry: Dict[str, Any]) -> None:
        with self._lock:
            self._m[_key(entry.get("kind"), entry.get("value"))] = copy.deepcopy(entry)

    def remove(self, kind: Any, value: Any) -> bool:
        with self._lock:
            return self._m.pop(_key(kind, value), None) is not None

    def get(self, kind: Any, value: Any) -> Optional[Dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._m.get(_key(kind, value)))

    def all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [copy.deepcopy(e) for e in self._m.values()]

    def clear(self) -> None:
        with self._lock:
            self._m.clear()


def _valid_entry(e: Any) -> bool:
    if not isinstance(e, dict):
        return False
    if not isinstance(e.get("kind"), str) or e["kind"] not in KINDS:
        return False
    if not _nonempty(e.get("value")) or not isinstance(e.get("reason"), str) or not _finite(e.get("revokedAt")):
        return False
    if "notBefore" in e and not _finite(e["notBefore"]):
        return False
    if e["kind"] == "prefix":
        p = e.get("prefix")
        if not isinstance(p, list) or len(p) == 0 or any(not _nonempty(x) for x in p):
            return False
        if PREFIX_SEP.join(p) != e["value"]:
            return False
    return True


def _no_constant(name: str) -> Any:
    raise ValueError("non-JSON constant " + name)


class FileRevocationStore(InMemoryRevocationStore):
    """A durable store backed by one JSON file. Every change is written to a temporary file, flushed to disk, then renamed over
    the real file, so a crash leaves either the old or the new contents, never a torn file. Single process: two processes must not
    share one file. Fail closed: a file that exists but cannot be read or does not hold a valid entry list makes the constructor
    raise ``ValueError`` (starting empty would un-revoke everything)."""

    def __init__(self, path: str) -> None:
        super().__init__()
        self._path = path
        if not os.path.exists(path):
            return
        try:
            with open(path, "rb") as fh:
                parsed = json.loads(fh.read().decode("utf-8"), parse_constant=_no_constant)
        except Exception:  # noqa: BLE001 - any read/parse failure refuses to start empty
            raise ValueError("FileRevocationStore: the revocation file cannot be read as JSON; refusing to start empty")
        lst = parsed.get("entries") if isinstance(parsed, dict) else None
        if not isinstance(lst, list) or not all(_valid_entry(e) for e in lst):
            raise ValueError("FileRevocationStore: the revocation file is not a valid entry list; refusing to start empty")
        for e in lst:
            self._m[_key(e["kind"], e["value"])] = e

    def _flush(self) -> None:
        tmp = self._path + ".tmp"
        body = json.dumps({"v": 1, "entries": list(self._m.values())}, separators=(",", ":"), allow_nan=False).encode("utf-8")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, body)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self._path)

    def _write(self, change: Callable[[], Any]) -> Any:
        """Apply ``change`` and flush under the lock; on a failed flush put memory back, so memory never claims more than disk."""
        with self._lock:
            before = dict(self._m)
            out = change()
            try:
                self._flush()
            except BaseException:
                self._m.clear()
                self._m.update(before)
                raise
            return out

    def add(self, entry: Dict[str, Any]) -> None:
        self._write(lambda: self._m.__setitem__(_key(entry.get("kind"), entry.get("value")), copy.deepcopy(entry)))

    def remove(self, kind: Any, value: Any) -> bool:
        return self._write(lambda: self._m.pop(_key(kind, value), None) is not None)

    def clear(self) -> None:
        self._write(self._m.clear)


# ---------------------------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------------------------

class RevocationRegistry:
    """A live, mutable registry of revocations over any store (the in-memory one by default)."""

    def __init__(self, store: Any = None) -> None:
        self.store = store if store is not None else InMemoryRevocationStore()

    def revoke(self, input: Any) -> Dict[str, Any]:
        """Revoke a capability id, holder key, issuer key, or subtree prefix; returns the stored entry. ``input`` is
        ``{kind, value | prefix, reason?, revokedAt?, notBefore?}``; a malformed one raises ``TypeError``."""
        if not isinstance(input, dict):
            raise TypeError("revoke: input must be an object")
        revoked_at = input.get("revokedAt")
        if revoked_at is None:
            revoked_at = _now_ms()
        reason = input.get("reason")
        if reason is None:
            reason = ""
        if not _finite(revoked_at):
            raise TypeError("revoke: revokedAt must be a finite number")
        if "notBefore" in input and not _finite(input["notBefore"]):
            raise TypeError("revoke: notBefore must be a finite number")
        if not isinstance(reason, str):
            raise TypeError("revoke: reason must be a string")
        kind = input.get("kind")
        if kind == "prefix":
            p = input.get("prefix")
            if not isinstance(p, list) or len(p) == 0:
                raise TypeError("revoke: a prefix revocation requires a non-empty cap-id path")
            # the path is joined with ',': an element holding one would alias a different path
            if any(not _nonempty(x) or PREFIX_SEP in x for x in p):
                raise TypeError("revoke: every prefix element must be a non-empty string without ','")
            entry = {"kind": "prefix", "value": serialize_prefix(p), "prefix": list(p), "reason": reason, "revokedAt": revoked_at}
        else:
            # stricter than the reference, which would store a kind-less entry that no lookup can ever match
            if not isinstance(kind, str):
                raise TypeError("revoke: kind must be a string")
            if not _nonempty(input.get("value")):
                raise TypeError("revoke: a %s revocation requires a non-empty value" % kind)
            entry = {"kind": kind, "value": input["value"], "reason": reason, "revokedAt": revoked_at}
        if "notBefore" in input:
            entry["notBefore"] = input["notBefore"]
        self.store.add(entry)
        return entry

    def revoke_subtree(self, target: Any, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Revoke a delegation subtree: a root cap id (string) revokes every chain through it; an ordered cap-id path (list)
        revokes every chain whose hops begin with it. ``opts``: ``reason``, ``revokedAt``, ``notBefore``."""
        base = {"kind": "prefix", "prefix": target} if isinstance(target, list) else {"kind": "cap", "value": target}
        return self.revoke({**base, **(opts or {})})

    def unrevoke(self, key: Any) -> bool:
        """Remove a revocation (``{kind, value}`` or ``{kind: 'prefix', prefix}``); True when one was removed."""
        if not isinstance(key, dict):
            raise TypeError("unrevoke: key must be an object")
        kind = key.get("kind")
        if kind == "prefix":
            p = key.get("prefix")
            # a non-string element could never have been stored; refusing keeps the revocation (fail closed)
            if not isinstance(p, list) or len(p) == 0 or any(not isinstance(x, str) for x in p):
                return False
            return self.store.remove("prefix", serialize_prefix(p))
        if not isinstance(kind, str) or not isinstance(key.get("value"), str):
            return False
        return self.store.remove(kind, key["value"])

    def list(self) -> List[Dict[str, Any]]:
        return self.store.all()

    def lookup(self, kind: str, value: str) -> Optional[Dict[str, Any]]:
        return self.store.get(kind, value)

    def prefixes(self) -> List[Dict[str, Any]]:
        return [e for e in self.store.all() if e.get("kind") == "prefix"]

    def clear(self) -> None:
        self.store.clear()

    def kill_agent(self, holder: Any, reason: Any = None, revoked_at: Any = None) -> Dict[str, Any]:
        """KILL-SWITCH: instantly revoke an agent by its holder key (no ``notBefore``, so it bites at once)."""
        return self.revoke({"kind": "holder", "value": holder, "reason": "kill-switch: agent killed" if reason is None else reason, "revokedAt": revoked_at})

    def kill_subtree(self, root_cap_id: Any, reason: Any = None, revoked_at: Any = None) -> Dict[str, Any]:
        """KILL-SWITCH: instantly revoke the delegation subtree rooted at ``root_cap_id``."""
        return self.revoke({"kind": "cap", "value": root_cap_id, "reason": "kill-switch: subtree killed" if reason is None else reason, "revokedAt": revoked_at})


# ---------------------------------------------------------------------------------------------
# The revocation check
# ---------------------------------------------------------------------------------------------

def _match_reason(entry: Dict[str, Any]) -> str:
    base = "%s %s is revoked" % (entry["kind"], entry["value"])
    return "%s: %s" % (base, entry["reason"]) if len(entry["reason"]) > 0 else base


def _starts_with(ids: List[str], prefix: List[str]) -> bool:
    if len(prefix) == 0 or len(ids) < len(prefix):
        return False
    return all(ids[i] == prefix[i] for i in range(len(prefix)))


def _scan_revoked(chain: List[Dict[str, Any]], registry: RevocationRegistry, now: Any) -> Dict[str, Any]:
    ids: List[str] = []
    for hop in chain:
        # root -> leaf; cap id, then issuer, then holder
        for kind, key in (("cap", hop.get("id")), ("issuer", hop.get("issuer")), ("holder", hop.get("holder"))):
            if not _nonempty(key):
                continue
            entry = registry.lookup(kind, key)
            if entry and is_active_at(entry, now):
                return {"revoked": True, "matched": entry, "reason": _match_reason(entry)}
        if isinstance(hop.get("id"), str):
            ids.append(hop["id"])
    for entry in registry.prefixes():
        if entry.get("prefix") and _starts_with(ids, entry["prefix"]) and is_active_at(entry, now):
            return {"revoked": True, "matched": entry, "reason": _match_reason(entry)}
    return {"revoked": False}


def check_revocation(p: Any, registry: RevocationRegistry, now: Any = None) -> Dict[str, Any]:
    """Is any authority in this PCActn's ``cap_chain`` revoked at ``now`` (default: the clock)? Never raises and never reports
    "not revoked" because it could not look: a missing or malformed chain, a hop whose id, issuer or holder is not a non-empty
    string, a non-finite ``now``, or a store that raises all yield ``revoked: True`` with a reason starting
    ``revocation check failed closed``."""
    def closed(why: str) -> Dict[str, Any]:
        return {"revoked": True, "reason": "revocation check failed closed: " + why}

    if now is None:
        now = _now_ms()
    if not _finite(now):
        return closed("clock is not a finite number")
    chain = p.get("cap_chain") if isinstance(p, dict) else None
    if not isinstance(chain, list) or len(chain) == 0:
        return closed("the action carries no capability chain")
    for hop in chain:
        for k in ("id", "issuer", "holder"):
            v = hop.get(k) if isinstance(hop, dict) else None
            if not _nonempty(v):
                return closed("a chain hop has no " + k)
    try:
        return _scan_revoked(chain, registry, now)
    except Exception:  # noqa: BLE001 - a failing store denies; "Error" is the reference's name for a generic failure
        return closed("the revocation store failed (Error)")


def verify_with_revocation(p: Any, core_verify_result: Any, registry: RevocationRegistry, now: Any = None) -> Dict[str, Any]:
    """Allow ONLY if the core verified (``allow is True``) AND nothing in the chain is revoked."""
    core_allow = isinstance(core_verify_result, dict) and core_verify_result.get("allow") is True
    revocation = check_revocation(p, registry, now)
    allow = core_allow and not revocation["revoked"]
    if allow:
        return {"allow": allow, "coreAllow": core_allow, "revocation": revocation}
    if not core_allow:
        r = core_verify_result.get("reason") if isinstance(core_verify_result, dict) else None
        reason = "core verification failed" if r is None else r
    else:
        reason = revocation.get("reason", "revoked")
    return {"allow": allow, "coreAllow": core_allow, "revocation": revocation, "reason": reason}


# ---------------------------------------------------------------------------------------------
# Shared-Signals / CAEP bridge
# ---------------------------------------------------------------------------------------------

def _string_field(subject: Any, key: str) -> Optional[str]:
    v = subject.get(key) if isinstance(subject, dict) else None
    return v if _nonempty(v) else None


def _js_round(v: float) -> Any:
    if not fin(v):
        return v
    f = math.floor(v)
    r = f + 1 if v - f >= 0.5 else f
    return r if abs(r) < 2 ** 53 else float(r)


def _revoked_at_from(ts: Any) -> Any:
    """CAEP ``event_timestamp`` is integer SECONDS; the registry records epoch ms."""
    return _js_round(float(ts) * 1000) if _finite(ts) else _now_ms()


def ingest_caep_event(event: Any, registry: RevocationRegistry) -> List[Dict[str, Any]]:
    """Bridge a CAEP revocation event ``{type, payload}`` into registry entries (returned): ``grant-revoked`` revokes the cap id
    ``grant_ref``; ``kill-switch`` kills the ``agent`` holder (and ``grant_ref``'s cap when named); ``session-revoked`` kills the
    subject's ``holder``/``agent``/``id`` key when it carries one. A missing payload raises ``TypeError``."""
    if not isinstance(event, dict):
        raise TypeError("ingest_caep_event: event must be an object")
    payload = event.get("payload")
    if payload is None:
        raise TypeError("ingest_caep_event: event has no payload")
    ev = payload if isinstance(payload, dict) else {}
    added: List[Dict[str, Any]] = []
    t = event.get("type")

    def dflt(v: Any, d: str) -> Any:
        return d if v is None else v

    if t == CAEP_EVENT_TYPES["grantRevoked"]:
        if _nonempty(ev.get("grant_ref")):
            added.append(registry.revoke({"kind": "cap", "value": ev["grant_ref"], "reason": dflt(ev.get("reason"), "CAEP grant-revoked"),
                                          "revokedAt": _revoked_at_from(ev.get("event_timestamp"))}))
    elif t == CAEP_EVENT_TYPES["killSwitch"]:
        revoked_at = _revoked_at_from(ev.get("event_timestamp"))
        if _nonempty(ev.get("agent")):
            added.append(registry.kill_agent(ev["agent"], reason=dflt(ev.get("reason"), "CAEP kill-switch"), revoked_at=revoked_at))
        if _nonempty(ev.get("grant_ref")):
            added.append(registry.revoke({"kind": "cap", "value": ev["grant_ref"], "reason": dflt(ev.get("reason"), "CAEP kill-switch"), "revokedAt": revoked_at}))
    else:
        subject = ev.get("subject")
        if "subject" in ev and subject is None:
            raise TypeError("ingest_caep_event: subject is null")
        holder = _string_field(subject, "holder") or _string_field(subject, "agent") or _string_field(subject, "id")
        if holder is not None:
            reason = ev.get("reason_admin")
            if reason is None:
                reason = ev.get("reason_user")
            added.append(registry.kill_agent(holder, reason=dflt(reason, "CAEP session-revoked"), revoked_at=_revoked_at_from(ev.get("event_timestamp"))))
    return added


# ---------------------------------------------------------------------------------------------
# Store conformance
# ---------------------------------------------------------------------------------------------

@dataclass
class RevocationStoreCase:
    name: str
    run: Callable[[], None]


def _centry(kind: str, value: str, **extra: Any) -> Dict[str, Any]:
    e: Dict[str, Any] = {"kind": kind, "value": value, "reason": "r-%s-%s" % (kind, value), "revokedAt": 1000}
    if kind == "prefix":
        e["prefix"] = value.split(",")
    e.update(extra)
    return e


def _sorted(xs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(xs, key=lambda e: e["kind"] + e["value"])


def revocation_store_cases(make: Callable[[], Any], reopen: Optional[Callable[[Any], Any]] = None) -> List[RevocationStoreCase]:
    """Conformance cases for a revocation store: each ``run()`` raises ``AssertionError`` when the store breaks the contract.
    ``make`` returns a fresh, empty store. A persistent store passes ``reopen(previous)`` (a new handle on the same backing
    location) to run the durability case."""
    def eq(a: Any, b: Any) -> None:
        assert a == b, "%r != %r" % (a, b)

    def starts_empty() -> None:
        eq(make().all(), [])
        eq(make().get("cap", "x"), None)

    def add_get() -> None:
        s = make()
        e = _centry("cap", "c1", notBefore=5000)
        s.add(e)
        eq(s.get("cap", "c1"), e)

    def kinds_apart() -> None:
        s = make()
        for k in ("cap", "holder", "issuer"):
            s.add(_centry(k, "k"))
        eq(len(s.all()), 3)
        eq(s.remove("holder", "k"), True)
        eq(s.get("cap", "k")["kind"], "cap")
        eq(s.get("issuer", "k")["kind"], "issuer")
        eq(s.get("holder", "k"), None)

    def replaces() -> None:
        s = make()
        s.add(_centry("cap", "c", reason="first"))
        s.add(_centry("cap", "c", reason="second"))
        eq(len(s.all()), 1)
        eq(s.get("cap", "c")["reason"], "second")

    def remove_once() -> None:
        s = make()
        s.add(_centry("cap", "c"))
        eq(s.remove("cap", "c"), True)
        eq(s.remove("cap", "c"), False)
        eq(s.remove("cap", "never-added"), False)

    def prefix_distinct() -> None:
        s = make()
        for v in ("a,b", "a", "b,a"):
            s.add(_centry("prefix", v))
        eq(len(s.all()), 3)
        eq(s.remove("prefix", "a"), True)
        eq([e["value"] for e in _sorted(s.all())], ["a,b", "b,a"])

    def snapshot() -> None:
        s = make()
        s.add(_centry("cap", "c"))
        snap = s.all()
        snap.pop()
        snap.append(_centry("cap", "forged"))
        eq(len(s.all()), 1)
        eq(s.get("cap", "forged"), None)

    def clears() -> None:
        s = make()
        s.add(_centry("cap", "c"))
        s.add(_centry("prefix", "a,b"))
        s.clear()
        eq(s.all(), [])
        eq(s.get("cap", "c"), None)

    def interleaved() -> None:
        from concurrent.futures import ThreadPoolExecutor
        s = make()
        n = 200

        def pair(k: int) -> None:
            # each pair removes only its own earlier add, so the expected survivors do not depend on scheduling
            s.add(_centry("cap", "c%d" % (2 * k)))
            s.add(_centry("cap", "c%d" % (2 * k + 1)))
            s.remove("cap", "c%d" % (2 * k))

        with ThreadPoolExecutor(max_workers=16) as ex:
            for f in [ex.submit(pair, k) for k in range(n // 2)]:
                f.result()
        left = {e["value"] for e in s.all()}
        eq(len(left), n // 2)
        for i in range(n):
            eq(("c%d" % i) in left, i % 2 == 1)

    cases = [
        RevocationStoreCase("starts empty", starts_empty),
        RevocationStoreCase("add then get returns the whole entry, including notBefore", add_get),
        RevocationStoreCase("the same value under different kinds is kept apart", kinds_apart),
        RevocationStoreCase("add at an existing key replaces, it does not duplicate", replaces),
        RevocationStoreCase("remove reports whether something was removed, and only once", remove_once),
        RevocationStoreCase("prefix paths that differ stay distinct", prefix_distinct),
        RevocationStoreCase("all() is a snapshot: changing it does not change the store", snapshot),
        RevocationStoreCase("clear drops everything", clears),
        RevocationStoreCase("interleaved adds and removes from many threads lose nothing", interleaved),
    ]
    if reopen is not None:
        def durable() -> None:
            s = make()
            a = _centry("cap", "durable", notBefore=9000)
            b = _centry("prefix", "r,m")
            s.add(a)
            s.add(b)
            s.add(_centry("holder", "gone"))
            s.remove("holder", "gone")
            eq(_sorted(reopen(s).all()), _sorted([a, b]))

        cases.append(RevocationStoreCase("entries survive reopening the store", durable))
    return cases


def run_revocation_store_conformance(make: Callable[[], Any], reopen: Optional[Callable[[Any], Any]] = None) -> List[str]:
    """Run every case; returns the failure descriptions (an empty list means the store conforms)."""
    failures: List[str] = []
    for c in revocation_store_cases(make, reopen):
        try:
            c.run()
        except Exception as e:  # noqa: BLE001 - a store that raises fails the case
            failures.append("%s: %s: %s" % (c.name, type(e).__name__, e))
    return failures


__all__ = [
    "CAEP_EVENT_TYPES", "FileRevocationStore", "InMemoryRevocationStore", "RevocationRegistry", "RevocationStoreCase", "check_revocation",
    "ingest_caep_event", "is_active_at", "revocation_store_cases", "run_revocation_store_conformance", "serialize_prefix", "verify_with_revocation",
]
