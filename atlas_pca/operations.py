"""Operation records (T3): execute an authorized operation at most once, with a durable record of what happened.

``authorize()`` decides and consumes the PCActn's replay counter. Between that decision and the end of the side effect the
process can crash, the client can time out and retry, or two workers can pick up the same authorization. This module
closes that gap with a record per operation id (``AuthorizedOperation.id``, the digest of the presented PCActn):

1. :func:`execute_authorized` creates the record in state ``pending`` BEFORE anything runs (one atomic create-if-absent:
   of N concurrent executions of one authorization exactly one gets to run ``fn``);
2. for an irreversible operation it re-checks revocation, expiry and approval immediately before ``fn`` (``recheck``;
   required, fail closed); a failed re-check records ``aborted`` and ``fn`` never runs;
3. it moves the record to ``executing`` and only then calls ``fn`` with the operation id as the idempotency key for the
   downstream call;
4. the record becomes ``committed`` (with ``fn``'s result) or ``failed`` (with its error) afterwards.

A second execution of the same id never runs ``fn`` again: it is answered from the record. Nothing is re-run after a crash
either. Once ``pending_timeout_ms`` has passed, a record still ``pending`` is settled as ``aborted`` (the side effect never
started: the agent may sign a fresh PCActn), and one still ``executing`` as ``uncertain`` (the side effect may or may not
have happened: an operator or a reconciliation job settles it with :func:`resolve_operation`, asking the downstream
system by the idempotency key). :func:`create_executor` combines ``authorize`` and ``execute_authorized`` so that a retry
of the same PCActn (which ``authorize`` refuses as a replay) is answered from the record instead of a bare replay denial.

Records are plain dicts with the reference's keys (``startedAt``, ``executingAt``, ``finishedAt``, ...), so a store shared
with other implementations holds one format. ``fn``'s result must be JSON-serialisable for a durable store.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .atomic_kv import MemoryAtomicKv
from .authorize import AuthorizeOptions, AuthorizeResult, _coerce
from .pca import hash_canonical, params_digest
from .revocation_staleness import effective_reversibility

OPERATION_PENDING_TIMEOUT_MS = 5 * 60_000

#: where an operation is in its execution
OPERATION_STATES = ("pending", "executing", "committed", "failed", "aborted", "uncertain")


# ---- stores ----------------------------------------------------------------------------------------------------------

class OperationStore:
    """The operation-record store protocol. ``create`` and ``transition`` MUST be atomic across every process and node that
    shares the store (a unique-key insert and a conditional ``UPDATE ... WHERE state = ?``, a Redis Lua script, a row lock).
    A call that cannot decide MUST raise; the executor then refuses or reports the outcome as unknown.

    ``create(record) -> None | dict``  insert `record` if no record with its id exists (returns None); otherwise return the
                                       existing record unchanged.
    ``get(id) -> dict | None``
    ``transition(id, from_state, next_record) -> bool``  replace the record only if its current state is `from_state`.
    ``list_open() -> list[dict]``      optional: records in state pending or executing (for :func:`recover_operations`).
    ``scope``                          ``"process"`` (records die with the process) or ``"shared"``.
    """

    scope = "shared"

    def create(self, record: dict) -> Optional[dict]:  # pragma: no cover - protocol
        raise NotImplementedError

    def get(self, id: str) -> Optional[dict]:  # pragma: no cover - protocol
        raise NotImplementedError

    def transition(self, id: str, from_state: str, next_record: dict) -> bool:  # pragma: no cover - protocol
        raise NotImplementedError


class MemoryOperationStore(OperationStore):
    """In-memory store for ONE process (tests, a single worker). Its records die with the process."""

    scope = "process"

    def __init__(self) -> None:
        import threading
        self._m: Dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self, record: dict) -> Optional[dict]:
        with self._lock:
            cur = self._m.get(record["id"])
            if cur is not None:
                return dict(cur)
            self._m[record["id"]] = dict(record)
            return None

    def get(self, id: str) -> Optional[dict]:
        with self._lock:
            r = self._m.get(id)
            return dict(r) if r is not None else None

    def transition(self, id: str, from_state: str, next_record: dict) -> bool:
        with self._lock:
            cur = self._m.get(id)
            if cur is None or cur.get("state") != from_state:
                return False
            self._m[id] = dict(next_record, id=id)
            return True

    def list_open(self) -> List[dict]:
        with self._lock:
            return [dict(r) for r in self._m.values() if r.get("state") in ("pending", "executing")]


def _as_record(v: Any) -> Optional[dict]:
    return v if isinstance(v, dict) and isinstance(v.get("id"), str) and isinstance(v.get("state"), str) else None


class KvOperationStore(OperationStore):
    """:class:`OperationStore` over any atomic key/value store with ``update(key, fn)`` (:class:`atlas_pca.SqliteAtomicKv`:
    crash-safe and multi-process-safe on one host). ``prefix`` namespaces the keys. It has no ``list_open``; recover a known
    id with :func:`recover_operation`."""

    def __init__(self, kv: Any, *, prefix: str = "pca-op:", scope: str = "shared") -> None:
        self._kv, self._pre, self.scope = kv, prefix, scope

    def create(self, record: dict) -> Optional[dict]:
        existing: List[Optional[dict]] = [None]

        def step(prev: Any) -> Any:
            existing[0] = _as_record(prev)
            return None if existing[0] is not None else dict(record)

        self._kv.update(self._pre + record["id"], step)
        return existing[0]

    def get(self, id: str) -> Optional[dict]:
        return _as_record(self._kv.get(self._pre + id))

    def transition(self, id: str, from_state: str, next_record: dict) -> bool:
        done = [False]

        def step(prev: Any) -> Any:
            cur = _as_record(prev)
            done[0] = cur is not None and cur.get("state") == from_state
            return dict(next_record, id=id) if done[0] else None

        self._kv.update(self._pre + id, step)
        return done[0]


def sqlite_operation_store(path: str) -> KvOperationStore:
    """A durable :class:`OperationStore` on a SQLite file (same backend family as :class:`atlas_pca.SqliteStateStore`)."""
    from .atomic_kv import SqliteAtomicKv
    return KvOperationStore(SqliteAtomicKv(path))


# ---- executing -------------------------------------------------------------------------------------------------------

@dataclass
class ExecutionHandle:
    """What the executed function receives. ``idempotency_key`` is the operation id: pass it as the idempotency key of
    the downstream call (e.g. an ``Idempotency-Key`` header)."""

    idempotency_key: str
    operation: Any
    pcactn: dict


@dataclass
class ExecuteOutcome:
    """The outcome of an execution attempt. ``replayed`` means it was answered from an existing record.

    ``status``: ``committed`` (``result``; ``recorded`` False = ``fn`` ran but the record could not be written, it stays
    executing and becomes uncertain), ``failed`` (``error``), ``aborted`` (``reason``), ``pending`` (another execution of
    this id is in flight), ``uncertain`` (``reason``; an earlier outcome is unknown, reconcile it), ``refused`` (nothing
    recorded: the authorization does not allow this operation, or the configuration is incomplete) or ``denied`` (the
    executor: ``authorization`` is the denying :class:`AuthorizeResult`, nothing ran)."""

    status: str
    operation_id: Optional[str] = None
    result: Any = None
    replayed: bool = False
    recorded: bool = True
    error: Optional[str] = None
    reason: Optional[str] = None
    authorization: Optional[AuthorizeResult] = None

    def to_dict(self) -> dict:
        s, i = self.status, self.operation_id
        if s == "committed":
            return {"status": s, "operationId": i, "result": self.result, "replayed": self.replayed, "recorded": self.recorded}
        if s == "failed":
            return {"status": s, "operationId": i, "error": self.error, "replayed": self.replayed}
        if s in ("aborted", "uncertain"):
            return {"status": s, "operationId": i, "reason": self.reason, "replayed": self.replayed}
        if s == "pending":
            return {"status": s, "operationId": i, "replayed": True}
        return {"status": s, "reason": self.reason}


def _clock() -> int:
    return int(time.time() * 1000)


def _store_ok(store: Any) -> bool:
    return store is not None and all(callable(getattr(store, m, None)) for m in ("create", "get", "transition"))


def _allowed(a: Any) -> Optional[tuple]:
    pcactn, op = getattr(a, "pcactn", None), getattr(a, "operation", None)
    if getattr(a, "allow", False) is not True or not isinstance(pcactn, dict) or not isinstance(getattr(op, "id", None), str) or op.id == "":
        return None
    return pcactn, op


def _settle_stale(store: Any, rec: dict, now: int, timeout_ms: float) -> dict:
    """Settle an open record older than `timeout_ms`: pending -> aborted (never started), executing -> uncertain."""
    st = rec.get("state")
    if st not in ("pending", "executing"):
        return rec
    # `executing` is aged from the moment `fn` was started (a slow re-check does not count against it)
    start = rec.get("executingAt", rec.get("startedAt")) if st == "executing" else rec.get("startedAt")
    if not now - start > timeout_ms:
        return rec
    if st == "pending":
        nxt = dict(rec, state="aborted", error="not started within %s ms of the claim: the side effect never ran" % _n(timeout_ms), finishedAt=now)
    else:
        nxt = dict(rec, state="uncertain", finishedAt=now,
                   error="no outcome recorded within %s ms of the start: the side effect may or may not have happened" % _n(timeout_ms))
    store.transition(rec["id"], st, nxt)
    # whatever is stored now (the original execution may have finished in between)
    return store.get(rec["id"]) or nxt


def _n(v: Any) -> str:
    from .predicates import _js_number_string
    return _js_number_string(float(v))


def _from_record(store: Any, rec0: dict, now: int, timeout_ms: float) -> ExecuteOutcome:
    """Answer an execution attempt from an existing record (never runs anything)."""
    rec = _settle_stale(store, rec0, now, timeout_ms)
    i, st = rec["id"], rec.get("state")
    if st == "committed":
        return ExecuteOutcome("committed", i, result=rec.get("result"), replayed=True, recorded=True)
    if st == "failed":
        return ExecuteOutcome("failed", i, error=rec.get("error") or "failed", replayed=True)
    if st == "aborted":
        return ExecuteOutcome("aborted", i, reason=rec.get("error") or "aborted", replayed=True)
    if st == "uncertain":
        return ExecuteOutcome("uncertain", i, reason=rec.get("error") or "outcome unknown", replayed=True)
    if st in ("pending", "executing"):
        return ExecuteOutcome("pending", i, replayed=True)
    return ExecuteOutcome("uncertain", i, reason="unknown record state '%s'" % st, replayed=True)


def _finish(store: Any, rec: dict, nxt: dict) -> bool:
    """Leave `executing` (or `uncertain`, when recovery settled a slow execution) for the final state."""
    out = dict(rec, **nxt)
    if store.transition(rec["id"], rec["state"], out):
        return True
    return rec["state"] == "executing" and bool(store.transition(rec["id"], "uncertain", out))


def _answer_current(store: Any, id: str, now: int, timeout_ms: float) -> ExecuteOutcome:
    cur = store.get(id)
    return _from_record(store, cur, now, timeout_ms) if cur else ExecuteOutcome("uncertain", id, reason="the operation record disappeared", replayed=True)


def _bound_to(op: Any, operation: Any) -> bool:
    try:
        return (isinstance(operation, dict) and op.verb == operation.get("verb") and op.resource == operation.get("resource")
                and op.params_digest == params_digest(operation.get("params")))
    except Exception:  # noqa: BLE001
        return False


def execute_authorized(authorization: Any, fn: Callable[[ExecutionHandle], Any], *, store: Any,
                       operation: Optional[dict] = None, recheck: Optional[Callable[[ExecutionHandle], dict]] = None,
                       recheck_for: str = "irreversible", reversibility_class: Optional[str] = None,
                       pending_timeout_ms: Optional[float] = None, now: Optional[Callable[[], int]] = None) -> ExecuteOutcome:
    """Execute an allowed ``authorize()`` result at most once, with a durable record (see the module doc). `fn` runs only if
    this call created the ``pending`` record and the re-check (when required) passed; every other outcome is answered from
    the record. A raise from `fn` is recorded as ``failed`` and returned, not re-raised.

    ``operation``  ``{"verb", "resource", "params"}`` the handler is about to execute: the authorization must be for exactly it.
    ``recheck``    ``(handle) -> {"ok": True} | {"ok": False, "reason": str}``: re-checks, immediately before `fn`, that the
                   authorization still stands (the grant is not revoked, the approval has not expired or been withdrawn).
                   REQUIRED for an irreversible operation (fail closed); with ``recheck_for="always"`` for every class. The
                   PCActn's own ``exp`` is always checked with it. A raise counts as a refusal.
    ``reversibility_class`` the server's authoritative class; the stricter of it and the signed class applies (missing =
                   irreversible).
    ``pending_timeout_ms`` an open record older than this is settled (pending -> aborted, executing -> uncertain). Default 5 min.
    ``now``        clock, epoch ms.
    """
    if not _store_ok(store):
        return ExecuteOutcome("refused", reason="executeAuthorized: missing required component: store (fail closed)")
    az = _allowed(authorization)
    if az is None:
        return ExecuteOutcome("refused", reason="executeAuthorized: the authorization did not allow an operation")
    pcactn, op = az
    if operation is not None and not _bound_to(op, operation):
        return ExecuteOutcome("refused", reason="executeAuthorized: the authorization is not for this operation (verb, resource or params differ)")
    clock = now or _clock
    timeout_ms = OPERATION_PENDING_TIMEOUT_MS if pending_timeout_ms is None else pending_timeout_ms
    action = pcactn.get("action") if isinstance(pcactn.get("action"), dict) else {}
    cls = effective_reversibility(reversibility_class, action.get("reversibility_class"))
    must_recheck = cls == "irreversible" or recheck_for == "always"
    if must_recheck and not callable(recheck):
        return ExecuteOutcome("refused", reason="executeAuthorized: a %s operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)" % cls)

    handle = ExecutionHandle(idempotency_key=op.id, operation=op, pcactn=pcactn)
    rec = {"id": op.id, "state": "pending", "verb": op.verb, "resource": op.resource, "params_digest": op.params_digest,
           "reversibility": cls, "startedAt": clock()}
    existing = store.create(rec)
    if existing is not None:
        return _from_record(store, existing, clock(), timeout_ms)

    if must_recheck:
        try:
            t = clock()
            exp = pcactn.get("exp")
            if isinstance(exp, (int, float)) and not isinstance(exp, bool) and t > exp:
                rc = {"ok": False, "reason": "the PCActn expired at %s" % _n(exp)}
            else:
                rc = recheck(handle)
        except Exception as e:  # noqa: BLE001
            rc = {"ok": False, "reason": "recheck error (fail closed): %s" % e}
        if not (isinstance(rc, dict) and rc.get("ok") is True):
            why = rc.get("reason") if isinstance(rc, dict) and rc.get("ok") is False and rc.get("reason") else "refused"
            reason = "recheck: %s" % why
            if _finish(store, rec, {"state": "aborted", "error": reason, "finishedAt": clock()}):
                return ExecuteOutcome("aborted", rec["id"], reason=reason, replayed=False)
            return _answer_current(store, rec["id"], clock(), timeout_ms)

    # the marker that separates "never started" from "maybe happened"; a recovery that settled the claim meanwhile wins
    running = dict(rec, state="executing", executingAt=clock())
    if not store.transition(rec["id"], "pending", running):
        return _answer_current(store, rec["id"], clock(), timeout_ms)

    try:
        result = fn(handle)
    except Exception as e:  # noqa: BLE001
        error = str(e)
        try:
            _finish(store, running, {"state": "failed", "error": error, "finishedAt": clock()})
        except Exception:  # noqa: BLE001
            pass
        return ExecuteOutcome("failed", rec["id"], error=error, replayed=False)
    try:
        recorded = _finish(store, running, {"state": "committed", "result": result, "finishedAt": clock()})
    except Exception:  # noqa: BLE001
        recorded = False
    return ExecuteOutcome("committed", rec["id"], result=result, replayed=False, recorded=recorded)


def recover_operation(store: Any, id: str, *, older_than_ms: Optional[float] = None, now: Optional[Callable[[], int]] = None) -> Optional[dict]:
    """:func:`recover_operations` for one id. Returns the record as it now stands (None: no record, it never started)."""
    r = store.get(id)
    if r is None:
        return None
    return _settle_stale(store, r, (now or _clock)(), OPERATION_PENDING_TIMEOUT_MS if older_than_ms is None else older_than_ms)


def recover_operations(store: Any, *, older_than_ms: Optional[float] = None, now: Optional[Callable[[], int]] = None) -> List[dict]:
    """Settle every open record older than `older_than_ms` (run it at startup and periodically): pending -> aborted (the side
    effect never started), executing -> uncertain. Returns the records it settled. Needs ``store.list_open``. Nothing is
    re-run: reconcile each ``uncertain`` one with :func:`resolve_operation`."""
    if not callable(getattr(store, "list_open", None)):
        raise TypeError("recover_operations: the store has no list_open (recover by id with recover_operation)")
    out = []
    for r in store.list_open():
        u = recover_operation(store, r["id"], older_than_ms=older_than_ms, now=now)
        if u is not None and u.get("state") != r.get("state"):
            out.append(u)
    return out


def resolve_operation(store: Any, id: str, outcome: dict, *, now: Optional[Callable[[], int]] = None) -> bool:
    """Settle an ``uncertain`` record after reconciling with the downstream system (look the idempotency key up there):
    ``{"state": "committed", "result"?}`` or ``{"state": "failed", "error"}``. False if the record is not ``uncertain``."""
    r = store.get(id)
    if r is None or r.get("state") != "uncertain":
        return False
    t = (now or _clock)()
    if outcome.get("state") == "committed":
        nxt = dict(r, state="committed", finishedAt=t)
        if "result" in outcome:
            nxt["result"] = outcome["result"]
    else:
        nxt = dict(r, state="failed", error=outcome.get("error"), finishedAt=t)
    return bool(store.transition(id, "uncertain", nxt))


class Executor:
    """``authorize`` + ``execute_authorized`` in one call, with retries answered from the record. Build it with
    :func:`create_executor`; call ``executor(pcactn, operation, fn)``."""

    def __init__(self, *, operations: Any, options: AuthorizeOptions, audience: str, resolve_grant: Callable,
                 recheck: Optional[Callable] = None, recheck_for: str = "irreversible",
                 reversibility_class_of: Optional[Callable[[dict], Optional[str]]] = None,
                 pending_timeout_ms: Optional[float] = None, now: Optional[Callable[[], int]] = None) -> None:
        self._ops, self._opts, self._aud, self._resolve = operations, options, audience, resolve_grant
        self._extra, self._recheck_for, self._cls_of = recheck, recheck_for, reversibility_class_of
        self._timeout = OPERATION_PENDING_TIMEOUT_MS if pending_timeout_ms is None else pending_timeout_ms
        self._now = now or _clock

    def _recheck(self, h: ExecutionHandle) -> dict:
        p = h.pcactn
        grant = self._resolve(p.get("grant_ref"))
        if not isinstance(grant, dict):
            return {"ok": False, "reason": "the grant is no longer known"}
        try:
            revoked = self._opts.is_revoked(p, grant)
        except Exception:  # noqa: BLE001
            revoked = None
        if revoked is not False:
            return {"ok": False, "reason": "the grant has been revoked" if revoked is True else "revocation could not be checked"}
        # a registered plan must still be executable: not revoked, the principal's approval not expired
        plans = self._opts.plans
        pl = p.get("plan") if isinstance(p.get("plan"), dict) else {}
        root = pl.get("root")
        if plans is not None and isinstance(root, str) and plans.get(p["grant_ref"], root) is not None:
            ps = plans.check(p["grant_ref"], root, node_id=pl.get("node_id"), now=self._now())
            if not ps["executable"]:
                return {"ok": False, "reason": ps.get("reason") or "plan is %s" % ps["state"]}
        return self._extra(h) if self._extra else {"ok": True}

    def __call__(self, pcactn: Any, operation: dict, fn: Callable[[ExecutionHandle], Any], *, intent_policy: Optional[dict] = None,
                 intent_v2: Any = None, escalation_answer: Any = None, provenance: Any = None) -> ExecuteOutcome:
        if not _store_ok(self._ops):
            return ExecuteOutcome("refused", reason="createExecutor: missing required component: operations (fail closed)")
        r = self._opts.run(pcactn, operation=operation, audience=self._aud, resolve_grant=self._resolve, now=self._now(),
                           intent_policy=intent_policy, intent_v2=intent_v2, escalation_answer=escalation_answer,
                           provenance=provenance)
        if r.allow:
            cls = self._cls_of(operation) if self._cls_of and isinstance(operation, dict) else None
            return execute_authorized(r, fn, store=self._ops, operation=operation, recheck=self._recheck,
                                      recheck_for=self._recheck_for, reversibility_class=cls,
                                      pending_timeout_ms=self._timeout, now=self._now)
        failed = [k for k, s in r.checks.items() if s == "fail"]
        if r.status != 403 or failed != ["replay"]:
            return ExecuteOutcome("denied", authorization=r, reason=r.reason)
        # a replay of a proof that is otherwise still valid now: answer from the record, if the first attempt made one
        p, _err = _coerce(pcactn)
        if p is None:
            return ExecuteOutcome("denied", authorization=r, reason=r.reason)
        rec = self._ops.get(hash_canonical(p))
        want = operation if isinstance(operation, dict) else {}
        if rec is None or rec.get("verb") != want.get("verb") or rec.get("resource") != want.get("resource") \
                or rec.get("params_digest") != params_digest(want.get("params")):
            return ExecuteOutcome("denied", authorization=r, reason=r.reason)
        return _from_record(self._ops, rec, self._now(), self._timeout)


def create_executor(*, operations: Any, options: AuthorizeOptions, audience: str, resolve_grant: Callable,
                    recheck: Optional[Callable[[ExecutionHandle], dict]] = None, recheck_for: str = "irreversible",
                    reversibility_class_of: Optional[Callable[[dict], Optional[str]]] = None,
                    pending_timeout_ms: Optional[float] = None, now: Optional[Callable[[], int]] = None) -> Executor:
    """Build an :class:`Executor`: `options` is the :class:`AuthorizeOptions` of the guard (store, revocation check, plan
    registry, ...). A second presentation of the same PCActn is refused by ``authorize`` as a replay; if that replay is the
    ONLY failing check (the proof, binding, policy and revocation all still pass now) and a record exists for its operation
    id and this operation, the record's outcome is returned (``replayed=True``) instead of the denial. No record means the
    first attempt never reached execution: the denial stands (the authorization was consumed; the agent signs a fresh PCActn).

    The executor always re-runs ``options.is_revoked`` against the grant from `resolve_grant`, checks the PCActn's expiry
    and, with ``options.plans``, that a registered plan is still executable; `recheck` adds to them (e.g. a step-up approval
    still stands). `reversibility_class_of(operation)` is the server's catalog class for an operation."""
    return Executor(operations=operations, options=options, audience=audience, resolve_grant=resolve_grant, recheck=recheck,
                    recheck_for=recheck_for, reversibility_class_of=reversibility_class_of,
                    pending_timeout_ms=pending_timeout_ms, now=now)
