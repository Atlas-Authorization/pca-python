"""Durable aggregate budgets (the TypeScript ``budget-ledger``): the ``BudgetLedger`` contract, the reference :class:`KvBudgetLedger`, signed
and anchored releases, and scoped admission.

CLAIMED: NO OVERSPEND AT PRINCIPAL, ORG AND FLEET SCOPE, given a ledger that is linearizable per key and durable. An accumulator with
``scope: principal | org | fleet`` counts the events of EVERY session and delegated agent of that scope in ONE state keyed by the scope id,
so N sessions share one cap and a split across sessions or agents buys nothing. A reservation counts as soon as it is made; the ledger refuses
one whose post-value would pass the accumulator's ``domain_max``, inside the same atomic step that records it.

TWO PHASES, THREE STEPS: ``reserve`` (counted at once), ``start`` (recorded BEFORE the effect runs), then ``commit`` (the effect happened) or
``release`` (it did not; a signed event, :func:`sign_release`, that can be anchored in a transparency log, :func:`anchor_release`).
``expire`` frees only a reservation that was never started: expiry needs no trusted clock. A release that never arrives only OVER-restricts.
:func:`admit_aggregate_action` refuses (``not_durable``) a ledger whose ``durable`` is not True, and denies ``scope_unbound`` when the caller
names no id for a scope the root uses. Synchronous. Events are dicts ``{id, verb, resource, params, t, status}``."""
import copy
import math
from ._fin import fin
import re
from typing import Any, Callable, Dict, List, Optional, Sequence
from urllib.parse import quote

from .agent import KeyPair
from .intent_history import acc_key_of, acc_post, acc_pre_state
from .intent_v2 import acc_selects
from .pca import _verify_b64u, b64u, canonical_bytes_strict, decode_b64u_strict, hash_canonical
from .store_errors import BudgetLedgerError, RangeError

__all__ = ["BudgetLedgerError", "scope_key", "KvBudgetLedger", "sign_release", "verify_release", "release_digest", "release_commit", "anchor_release",
           "aggregate_key_of", "admit_aggregate_action", "start_aggregate", "settle_aggregate", "RELEASE_DOMAIN", "reserve_in_doc"]

PREFIX = "pca-budget-ledger/v1/"
RELEASE_DOMAIN = "atlas-pca/budget-release/v1\x00"
_RELEASE_REASONS = ("effect_failed", "effect_not_run", "denied_downstream", "rollback")
_CTRL = re.compile("[\x00-\x1f]")
_SAFE = "-_.!~*'()"


def _is_int(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and x == x and abs(x) != float("inf") and int(x) == x and abs(x) <= 9007199254740991


def _id_ok(s: Any) -> bool:
    return isinstance(s, str) and 0 < len(s.encode("utf-16-le", "surrogatepass")) // 2 <= 256 and _CTRL.search(s) is None


def scope_key(scope: str, id: str) -> str:  # noqa: A002
    """The ledger key of a scope (``principal`` | ``org`` | ``fleet``) and its id. Injective: the id is percent-encoded."""
    if not _id_ok(id):
        raise BudgetLedgerError("invalid", "a scope id is a non-empty string of at most 256 characters without control characters")
    return "%s/%s" % (scope, quote(id, safe=_SAFE))


def _empty_doc() -> dict:
    return {"v": 1, "ver": 0, "events": []}


def _decode_doc(raw: Any) -> dict:
    if raw is None:
        return _empty_doc()
    if not isinstance(raw, dict) or raw.get("v") != 1 or not _is_int(raw.get("ver")) or not isinstance(raw.get("events"), list) \
            or not all(isinstance(e, dict) and isinstance(e.get("id"), str) for e in raw["events"]):
        raise BudgetLedgerError("store_corrupt", "budget document has the wrong shape")
    return raw


def _same_event(a: dict, b: dict) -> bool:
    k = lambda e: hash_canonical({"id": e.get("id"), "verb": e.get("verb"), "resource": e.get("resource"), "params": e.get("params"), "t": e.get("t")})  # noqa: E731
    return k(a) == k(b)


def reserve_in_doc(doc: dict, req: dict) -> dict:
    """Reserve ``req["event"]`` in `doc` (``{ver, events}``) unless it would pass an accumulator's cap. The pure transition every store is
    this plus a per-key lock."""
    e = req.get("event") if isinstance(req, dict) else None
    if not isinstance(e, dict) or not _id_ok(e.get("id")) or not isinstance(e.get("verb"), str) or not isinstance(e.get("resource"), str) \
            or not _is_int(e.get("t")) or not isinstance(e.get("params"), (dict, list)):
        raise RangeError("reserve: a malformed event")
    if not isinstance(req.get("accumulators"), list):
        raise RangeError("reserve: accumulators must be an array")
    if req.get("expectedVersion") is not None and (not _is_int(req["expectedVersion"]) or req["expectedVersion"] < 0):
        raise RangeError("reserve: expectedVersion must be a non-negative safe integer")
    if req.get("expiresAt") is not None and not _is_int(req["expiresAt"]):
        raise RangeError("reserve: expiresAt must be a safe integer")
    prior = next((x for x in doc["events"] if x["id"] == e["id"]), None)
    if prior is not None:
        return {"outcome": "replayed", "version": doc["ver"], "status": prior.get("status")} if _same_event(prior, e) else \
            {"outcome": "id_conflict", "version": doc["ver"]}
    if req.get("expectedVersion") is not None and req["expectedVersion"] != doc["ver"]:
        return {"outcome": "conflict", "version": doc["ver"]}
    post: Dict[str, Any] = {}
    for a in req["accumulators"]:
        if a.get("domain_max") is None:
            raise RangeError("reserve: accumulator %s has no domain_max (the cap)" % a.get("id"))
        if not acc_selects(a, e["verb"], req.get("schema")):
            continue
        try:
            p = acc_post(a, doc["events"], e["verb"], e["params"], e["t"], req.get("schema"))
        except Exception as err:  # noqa: BLE001
            raise BudgetLedgerError("store_corrupt", str(err) or "unreadable history") from None
        if not (fin(p) and p <= a["domain_max"]):
            return {"outcome": "over_cap", "version": doc["ver"], "acc": a["id"], "post": p, "cap": a["domain_max"]}
        post[a["id"]] = p
    entry = {"id": e["id"], "verb": e["verb"], "resource": e["resource"], "params": copy.deepcopy(e["params"]), "t": e["t"], "status": "reserved"}
    if req.get("expiresAt") is not None:
        entry["exp"] = req["expiresAt"]
    doc["events"].append(entry)
    doc["ver"] += 1
    return {"outcome": "reserved", "version": doc["ver"], "post": post}


def _find(doc: dict, id: str) -> Optional[dict]:  # noqa: A002
    return next((x for x in doc["events"] if x["id"] == id), None)


def _start_in_doc(doc: dict, id: str) -> dict:  # noqa: A002
    e = _find(doc, id)
    if e is None:
        return {"outcome": "unknown", "version": doc["ver"]}
    if e["status"] == "released":
        return {"outcome": "refused", "version": doc["ver"], "status": e["status"]}
    if e.get("started") or e["status"] == "committed":
        return {"outcome": "replayed", "version": doc["ver"]}
    e["started"] = True
    doc["ver"] += 1
    return {"outcome": "settled", "version": doc["ver"]}


def _commit_in_doc(doc: dict, id: str) -> dict:  # noqa: A002
    e = _find(doc, id)
    if e is None:
        return {"outcome": "unknown", "version": doc["ver"]}
    if e["status"] == "committed":
        return {"outcome": "replayed", "version": doc["ver"]}
    if e["status"] != "reserved":
        return {"outcome": "refused", "version": doc["ver"], "status": e["status"]}
    e["status"] = "committed"
    doc["ver"] += 1
    return {"outcome": "settled", "version": doc["ver"]}


def _release_in_doc(doc: dict, key: str, id: str, evidence: Any) -> dict:  # noqa: A002
    e = _find(doc, id)
    if e is None:
        return {"outcome": "unknown", "version": doc["ver"]}
    if e["status"] == "released":
        return {"outcome": "replayed", "version": doc["ver"]}
    if e["status"] != "reserved":
        return {"outcome": "refused", "version": doc["ver"], "status": e["status"]}
    if evidence is not None and (evidence.get("key") != key or evidence.get("id") != id):
        raise RangeError("release: the evidence is for another reservation")
    e["status"] = "released"
    if evidence:
        e["rel"] = copy.deepcopy(evidence)
    doc["ver"] += 1
    return {"outcome": "settled", "version": doc["ver"]}


def _expire_in_doc(doc: dict, now: Any) -> dict:
    if not _is_int(now):
        raise RangeError("expire: now must be a safe integer")
    released: List[str] = []
    for e in doc["events"]:
        if e["status"] == "reserved" and not e.get("started") and e.get("exp") is not None and e["exp"] <= now:
            e["status"] = "released"
            e["rel"] = {"reason": "expired", "at": now}
            released.append(e["id"])
    if released:
        doc["ver"] += 1
    return {"released": released, "version": doc["ver"]}


class KvBudgetLedger:
    """The reference budget ledger: one document per key in an atomic key-value store (``get`` / ``update``), so every operation is one atomic
    read-modify-write. `durable` is declared by the caller (a kv cannot tell): True only for a persistent one (:class:`atlas_pca.SqliteAtomicKv`)."""

    def __init__(self, kv: Any, durable: Any) -> None:
        if kv is None or not callable(getattr(kv, "get", None)) or not callable(getattr(kv, "update", None)):
            raise BudgetLedgerError("store_missing", "KvBudgetLedger needs an atomic kv")
        if not isinstance(durable, bool):
            raise BudgetLedgerError("invalid", "say whether the kv is durable (True or False)")
        self._kv, self.durable = kv, durable

    def _k(self, key: Any) -> str:
        if not _id_ok(key):
            raise RangeError("a ledger key is a non-empty string without control characters")
        return PREFIX + key

    def _txn(self, key: Any, fn: Callable[[dict], Any], writes: Callable[[Any], bool]) -> Any:
        out: List[Any] = []

        def upd(prev: Any) -> Any:
            d = _decode_doc(prev)
            out.append(fn(d))
            return d if writes(out[0]) else None
        self._kv.update(self._k(key), upd)
        return out[0]

    def snapshot(self, key: str) -> dict:
        d = _decode_doc(self._kv.get(self._k(key)))
        return {"version": d["ver"], "events": copy.deepcopy(d["events"])}

    def reserve(self, key: str, req: dict) -> dict:
        return self._txn(key, lambda d: reserve_in_doc(d, req), lambda r: r["outcome"] == "reserved")

    def start(self, key: str, id: str) -> dict:  # noqa: A002
        return self._txn(key, lambda d: _start_in_doc(d, id), lambda r: r["outcome"] == "settled")

    def commit(self, key: str, id: str) -> dict:  # noqa: A002
        return self._txn(key, lambda d: _commit_in_doc(d, id), lambda r: r["outcome"] == "settled")

    def release(self, key: str, id: str, evidence: Any = None) -> dict:  # noqa: A002
        return self._txn(key, lambda d: _release_in_doc(d, key, id, evidence), lambda r: r["outcome"] == "settled")

    def expire(self, key: str, now: Any) -> dict:
        return self._txn(key, lambda d: _expire_in_doc(d, now), lambda r: len(r["released"]) > 0)


# ---- signed, anchored releases ---------------------------------------------------------------------------------------

def _release_message(r: dict) -> bytes:
    body = {k: r.get(k) for k in ("v", "key", "id", "reason", "at", "signer")}
    return RELEASE_DOMAIN.encode("utf-8") + canonical_bytes_strict(body)


def sign_release(key: str, id: str, reason: str, at: Any, secret: KeyPair) -> dict:  # noqa: A002
    """A signed statement by the releaser that a reservation's effect did NOT happen (`reason`: effect_failed, effect_not_run,
    denied_downstream or rollback). `secret` is the releaser's :class:`KeyPair`."""
    if reason not in _RELEASE_REASONS or not _is_int(at) or not _id_ok(key) or not _id_ok(id):
        raise RangeError("signRelease: a malformed release")
    base = {"v": 1, "key": key, "id": id, "reason": reason, "at": at, "signer": secret.public}
    return dict(base, sig=b64u(secret.sign(_release_message(base))))


def verify_release(r: Any, expected_signer: Any) -> bool:
    """True iff `r` is well formed and signed by `expected_signer` over exactly its content. Never raises."""
    try:
        if not isinstance(r, dict) or r.get("v") != 1 or r.get("signer") != expected_signer or r.get("reason") not in _RELEASE_REASONS \
                or not _is_int(r.get("at")) or not _id_ok(r.get("key")) or not _id_ok(r.get("id")) or decode_b64u_strict(r.get("sig"), 64) is None:
            return False
        return _verify_b64u(expected_signer, _release_message(r), r["sig"])
    except Exception:  # noqa: BLE001
        return False


def release_digest(r: dict) -> str:
    return hash_canonical({"d": "atlas-pca/budget-release-ref/v1", "r": r})


def release_commit(r: dict) -> str:
    """The log leaf of a release."""
    return hash_canonical({"d": "atlas-pca/budget-release-leaf/v1", "digest": release_digest(r)})


def anchor_release(log: Any, r: dict) -> int:
    """Anchor a signed release in a transparency log store (retries on a position conflict). Returns the leaf index."""
    commit = release_commit(r)
    for _ in range(64):
        size = log.size()
        o = log.append(size, [commit])
        if o["outcome"] in ("appended", "replayed"):
            return size
    raise BudgetLedgerError("conflict_exhausted", "could not anchor the release: the log kept moving")


# ---- scoped admission ------------------------------------------------------------------------------------------------

def aggregate_key_of(a: dict, ids: dict) -> Optional[str]:
    """The ledger key of an accumulator for this admission, or None when it is session-scoped. Raises ``scope_unbound``."""
    scope = a.get("scope")
    if scope is None or scope == "session":
        return None
    i = ids.get(scope)
    if i is None:
        raise BudgetLedgerError("scope_unbound", "accumulator %s is %s-scoped but no %s id was given" % (a.get("id"), scope, scope))
    return scope_key(scope, i)


def _context_state(accs: List[dict], history: List[dict], cand: dict, schema: Any) -> Dict[str, Any]:
    state: Dict[str, Any] = {}
    for a in accs:
        if (a.get("holder") or {}).get("kind") != "site_local":
            continue
        if a.get("key") is not None and acc_key_of(a, cand["params"]) is None:
            continue  # the verifier fails the claim (missing key)
        state[a["id"]] = acc_pre_state(a, history, cand["params"], cand["t"], schema)
    return state


def admit_aggregate_action(ledger: Any, ids: dict, accumulators: Sequence[dict], schema: Any, event: dict, verify: Callable[[dict], dict],
                           expires_at: Optional[int] = None, max_attempts: Optional[int] = None) -> dict:
    """Admit one action against every non-session accumulator of the root, atomically per key: read each key's snapshot and compute the
    pre-states, ``verify(state)`` (the host's verifier; returns a dict with ``allow``), then on allow ``reserve`` in every key with the
    snapshot's version. A moved key repeats from the start; a key over its cap denies and releases what the earlier keys reserved.
    Refuses (raises ``not_durable``) a ledger that is not durable. Returns ``{"admitted": True, "verdict", "reservations", "state"}`` or
    ``{"admitted": False, "reason", "verdict"?}``."""
    scoped = [a for a in accumulators if a.get("scope") is not None and a["scope"] != "session"]
    if scoped and getattr(ledger, "durable", None) is not True:
        raise BudgetLedgerError("not_durable", "a principal, org or fleet aggregate needs a durable BudgetLedger (a restart would reset every cap)")
    by_key: Dict[str, List[dict]] = {}
    try:
        for a in scoped:
            by_key.setdefault(aggregate_key_of(a, ids), []).append(a)
    except BudgetLedgerError as e:
        if e.code == "scope_unbound":
            return {"admitted": False, "reason": "scope_unbound: %s" % e}
        raise
    keys = sorted(by_key, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
    for _ in range(256 if max_attempts is None else max_attempts):
        snaps: Dict[str, dict] = {}
        state: Dict[str, Any] = {}
        for k in keys:
            s = ledger.snapshot(k)
            snaps[k] = s
            state.update(_context_state(by_key[k], s["events"], event, schema))
        verdict = verify(state)
        if not verdict["allow"]:
            return {"admitted": False, "reason": "verifier denied", "verdict": verdict}
        done: List[dict] = []
        moved = False
        for k in keys:
            req = {"event": event, "accumulators": by_key[k], "schema": schema, "expectedVersion": snaps[k]["version"], "expiresAt": expires_at}
            r = ledger.reserve(k, {kk: v for kk, v in req.items() if v is not None})
            if r["outcome"] == "reserved" or (r["outcome"] == "replayed" and r.get("status") == "reserved"):
                done.append({"key": k, "id": event["id"]})
                continue
            for d in done:
                ledger.release(d["key"], d["id"])
            if r["outcome"] == "conflict":
                moved = True
                break
            if r["outcome"] == "over_cap":
                why = "over_cap: %s would reach %s (cap %s)" % (r["acc"], _js_num(r["post"]), _js_num(r["cap"]))
            elif r["outcome"] == "replayed":
                why = "already %s" % r.get("status")
            else:
                why = r["outcome"]
            return {"admitted": False, "reason": "aggregate: %s" % why, "verdict": verdict}
        if not moved:
            return {"admitted": True, "verdict": verdict, "reservations": done, "state": state}
    raise BudgetLedgerError("conflict_exhausted", "the aggregate kept moving under this admission")


def _js_num(x: Any) -> str:
    from .predicates import _js_number_string
    return _js_number_string(float(x))


def start_aggregate(ledger: Any, reservations: Sequence[dict]) -> bool:
    """BEFORE the effect: mark every reservation started (non-expirable). Returns False when any is refused (released or expired in the
    meantime): the effect must NOT run then."""
    for r in reservations:
        if ledger.start(r["key"], r["id"])["outcome"] not in ("settled", "replayed"):
            return False
    return True


def settle_aggregate(ledger: Any, reservations: Sequence[dict], status: str, evidence: Optional[Callable[[dict], Any]] = None) -> List[dict]:
    """After the effect: ``committed`` (it happened) or ``released`` (it did not; a signed `evidence` is stored and can be anchored)."""
    return [ledger.commit(r["key"], r["id"]) if status == "committed" else ledger.release(r["key"], r["id"], evidence(r) if evidence else None)
            for r in reservations]
