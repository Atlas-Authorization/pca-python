"""Operation records (T3): replays packages/pca/conformance/operation-vectors.json scenario by scenario (a fresh in-memory
store, a fixed clock per step), plus concurrency on the in-memory and the durable store, the executor and recovery. A
missing vector file fails."""
import json
import os
import threading
from types import SimpleNamespace

import pytest

from atlas_pca import (AuthorizeOptions, KvOperationStore, MemoryOperationStore, MemoryStateStore, SqliteAtomicKv,
                       create_executor, execute_authorized, recover_operations, resolve_operation, sqlite_operation_store)
from atlas_pca.authorize import AuthorizedOperation, AuthorizeResult
from atlas_pca.pca import EMPTY_PARAMS_DIGEST, hash_canonical
from prov_harness import PIN, bundle_for

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "conformance", "operation-vectors.json"), encoding="utf-8") as f:
    DOC = json.load(f)
with open(os.path.join(HERE, "testdata", "authorize-fixtures.json"), encoding="utf-8") as f:
    FIX = json.load(f)


def _authorization(s):
    if s.get("not_allowed"):
        return AuthorizeResult(allow=False, status=403)
    pc = {}
    if "exp" in s:
        pc["exp"] = s["exp"]
    pc["action"] = {} if "signed_class" not in s else {"reversibility_class": s["signed_class"]}
    return SimpleNamespace(allow=True, pcactn=pc, operation=AuthorizedOperation(
        verb=s.get("verb", "payments.refund"), resource=s.get("resource", "/orders/1"),
        params_digest=s.get("params_digest", EMPTY_PARAMS_DIGEST), id=s["id"]))


def _recheck(spec):
    if spec is None:
        return None
    if spec == "ok":
        return lambda h: {"ok": True}
    if "refuse" in spec:
        return lambda h: {"ok": False, "reason": spec["refuse"]}

    def boom(h):
        raise RuntimeError(spec["throw"])
    return boom


def run_scenario(steps):
    store = MemoryOperationStore()
    out = []
    for s in steps:
        op = s["op"]
        if op == "seed":
            store.create(dict(s["record"]))
            out.append(None)
        elif op == "get":
            out.append(store.get(s["id"]))
        elif op == "recover":
            kw = {"older_than_ms": s["older_than_ms"]} if "older_than_ms" in s else {}
            out.append(sorted(({"id": x["id"], "state": x["state"]} for x in recover_operations(store, now=lambda: s["at"], **kw)),
                              key=lambda x: x["id"]))
        elif op == "recover_one":
            from atlas_pca import recover_operation
            kw = {"older_than_ms": s["older_than_ms"]} if "older_than_ms" in s else {}
            out.append(recover_operation(store, s["id"], now=lambda: s["at"], **kw))
        elif op == "resolve":
            out.append(resolve_operation(store, s["id"], s["outcome"], now=lambda: s["at"]))
        else:
            calls = [0]
            az = _authorization(s)
            opts = dict(store=None if s.get("no_store") else store, now=lambda: s["at"])
            if s.get("recheck") is not None:
                opts["recheck"] = _recheck(s["recheck"])
            if s.get("recheck_for"):
                opts["recheck_for"] = s["recheck_for"]
            if "server_class" in s:
                opts["reversibility_class"] = s["server_class"]
            if "timeout_ms" in s:
                opts["pending_timeout_ms"] = s["timeout_ms"]

            def fn(h, s=s, calls=calls, az=az, opts=opts):
                calls[0] += 1
                if s["fn"]["kind"] == "throw":
                    raise RuntimeError(s["fn"]["message"])
                if s["fn"]["kind"] == "reenter":
                    return execute_authorized(az, lambda _h: (_ for _ in ()).throw(RuntimeError("inner must not run")), **opts).status
                return h.idempotency_key if s["fn"].get("result") is None else s["fn"]["result"]

            outcome = execute_authorized(az, fn, **opts).to_dict()
            out.append({"outcome": outcome, "fn_calls": calls[0],
                        "record": None if s.get("no_store") or s.get("not_allowed") else store.get(s["id"])})
    return out


def test_corpus_is_complete():
    assert DOC["constants"] == {"pending_timeout_ms": 300000}
    assert len(DOC["scenarios"]) == 19


@pytest.mark.parametrize("scn", DOC["scenarios"], ids=lambda s: s["name"])
def test_scenario(scn):
    assert run_scenario(scn["steps"]) == scn["expect"]


# ---- concurrency -------------------------------------------------------------------------------------------------------

def _stores(tmp_path):
    return [MemoryOperationStore(), sqlite_operation_store(str(tmp_path / "ops.db"))]


def test_parallel_executions_of_one_id_run_fn_exactly_once(tmp_path):
    for store in _stores(tmp_path):
        az = _authorization({"id": "op-par", "signed_class": "reversible"})
        calls, outcomes = [], []
        gate = threading.Barrier(16)

        def go():
            gate.wait()
            outcomes.append(execute_authorized(az, lambda h: calls.append(1) or "done", store=store))

        ts = [threading.Thread(target=go) for _ in range(16)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        assert len(calls) == 1
        assert sum(1 for o in outcomes if o.status == "committed" and not o.replayed) == 1
        assert all(o.status in ("committed", "pending") for o in outcomes)


def test_parallel_executions_on_a_shared_file_run_fn_once(tmp_path):
    path = str(tmp_path / "shared.db")
    az = _authorization({"id": "op-shared", "signed_class": "reversible"})
    calls = []
    gate = threading.Barrier(8)

    def go():
        store = KvOperationStore(SqliteAtomicKv(path))  # its own connection, like another worker
        gate.wait()
        execute_authorized(az, lambda h: calls.append(1) or "done", store=store)

    ts = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(calls) == 1
    assert sqlite_operation_store(path).get("op-shared")["state"] == "committed"


def test_a_durable_record_survives_a_new_store_object(tmp_path):
    path = str(tmp_path / "ops.db")
    az = _authorization({"id": "op-dur", "signed_class": "reversible"})
    first = execute_authorized(az, lambda h: {"n": 1}, store=sqlite_operation_store(path))
    again = execute_authorized(az, lambda h: {"n": 2}, store=sqlite_operation_store(path))
    assert (first.result, again.result, again.replayed) == ({"n": 1}, {"n": 1}, True)


def test_an_unfinished_durable_record_is_never_rerun(tmp_path):
    path = str(tmp_path / "ops.db")
    store = sqlite_operation_store(path)
    store.create({"id": "op-x", "state": "executing", "verb": "v", "resource": "/r", "params_digest": EMPTY_PARAMS_DIGEST,
                  "reversibility": "reversible", "startedAt": 0, "executingAt": 0})
    az = _authorization({"id": "op-x", "signed_class": "reversible"})
    calls = []
    o = execute_authorized(az, lambda h: calls.append(1), store=sqlite_operation_store(path), now=lambda: 10 * 60_000)
    assert o.status == "uncertain" and calls == []


def test_recover_operations_needs_list_open():
    with pytest.raises(TypeError):
        recover_operations(KvOperationStore(SqliteAtomicKv(":memory:")))


# ---- the executor ----------------------------------------------------------------------------------------------------

def _executor(case, store, revoked=None, **kw):
    revoked = revoked if revoked is not None else {"v": False}
    opts = AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=lambda p, g: revoked["v"], plan="single-step", provenance_mediators=[PIN])
    return create_executor(operations=store, options=opts, audience=FIX["audience"], resolve_grant=lambda ref: case["grant"],
                           now=lambda: FIX["now"], **kw), revoked


def _case():
    c = next(c for c in FIX["cases"] if c["name"] == "envelope-max-spend-within")
    return c, c["steps"][0]


def test_executor_commits_when_the_default_recheck_passes_and_replays_from_the_record():
    c, s = _case()
    ex, revoked = _executor(c, MemoryOperationStore())
    calls = []
    first = ex(s["pcactn"], s["operation"], lambda h: calls.append(h.idempotency_key) or "paid", provenance=bundle_for(s["operation"]))
    assert first.status == "committed" and first.result == "paid" and first.replayed is False
    assert calls == [hash_canonical(s["pcactn"])]
    retry = ex(s["pcactn"], s["operation"], lambda h: calls.append("again") or "paid-twice", provenance=bundle_for(s["operation"]))
    assert (retry.status, retry.result, retry.replayed) == ("committed", "paid", True)
    assert len(calls) == 1


def test_executor_revoked_between_authorize_and_run_aborts():
    c, s = _case()
    state = {"v": False}
    calls = {"n": 0}

    def revoked(p, g):  # allows the authorize call, then reports revoked at the recheck
        calls["n"] += 1
        return calls["n"] > 1

    opts = AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=revoked, plan="single-step", provenance_mediators=[PIN])
    ex = create_executor(operations=MemoryOperationStore(), options=opts, audience=FIX["audience"],
                         resolve_grant=lambda ref: c["grant"], now=lambda: FIX["now"])
    ran = []
    o = ex(s["pcactn"], s["operation"], lambda h: ran.append(1), provenance=bundle_for(s["operation"]))
    assert o.status == "aborted" and o.reason == "recheck: the grant has been revoked" and ran == []


def test_executor_denial_without_a_record_stands():
    c, s = _case()
    ex, revoked = _executor(c, MemoryOperationStore())
    revoked["v"] = True
    o = ex(s["pcactn"], s["operation"], lambda h: 1, provenance=bundle_for(s["operation"]))
    assert o.status == "denied" and o.authorization.allow is False


def test_executor_without_a_store_refuses():
    c, s = _case()
    ex, _ = _executor(c, None)
    assert ex(s["pcactn"], s["operation"], lambda h: 1, provenance=bundle_for(s["operation"])).status == "refused"


def test_executor_rechecks_that_a_registered_plan_is_still_executable():
    from atlas_pca import PlanRegistry
    c, s = _case()
    p, gid = s["pcactn"], c["grant"]["id"]
    node = {"id": p["plan"]["node_id"], "verb": p["action"]["verb"], "resource": p["action"]["resource"],
            "params_digest": p["action"]["params_digest"], "reversibility_class": p["action"]["reversibility_class"]}
    reg = PlanRegistry(now=lambda: FIX["now"])
    root = reg.draft(gid, [node])["record"]["root"]
    assert reg.validate(gid, root)["ok"] and reg.commit(gid, root)["ok"] and reg.authorize(gid, root, {"by": "principal"})["ok"]
    calls = {"n": 0}

    def is_revoked(pc, g):  # the plan is revoked between the authorize call and the pre-execution recheck
        calls["n"] += 1
        if calls["n"] == 2:
            reg.revoke(gid, root, "principal withdrew approval")
        return False

    opts = AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=is_revoked, plan=None, plans=reg, provenance_mediators=[PIN])
    ex = create_executor(operations=MemoryOperationStore(), options=opts, audience=FIX["audience"],
                         resolve_grant=lambda ref: c["grant"], now=lambda: FIX["now"])
    ran = []
    o = ex(p, s["operation"], lambda h: ran.append(1), provenance=bundle_for(s["operation"]))
    assert o.status == "aborted" and ran == []
    assert o.reason == "recheck: plan %s is revoked (principal withdrew approval)" % root
