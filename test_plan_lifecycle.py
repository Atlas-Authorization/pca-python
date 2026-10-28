"""Plan lifecycle (T10): replays packages/pca/conformance/plan-vectors.json scenario by scenario (one fresh registry per
scenario, the clock set per step), plus concurrency, the durable store and the authorize(plans=...) wiring. A missing vector
file fails."""
import json
import os
import threading

import pytest

from atlas_pca import MemoryAtomicKv, MemoryStateStore, PlanRegistry, SqliteAtomicKv, authorize, plan_root

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "conformance", "plan-vectors.json"), encoding="utf-8") as f:
    DOC = json.load(f)
with open(os.path.join(HERE, "testdata", "authorize-fixtures.json"), encoding="utf-8") as f:
    FIX = json.load(f)

VALIDATORS = {
    "accept": lambda rec: {"ok": True},
    "refuse": lambda rec: {"ok": False, "reason": "node outside the grant"},
}


def _throwing(rec):
    raise RuntimeError("policy down")


VALIDATORS["throw"] = _throwing


def run_steps(reg, clock, steps):
    out = []
    for s in steps:
        clock["now"] = s["at"]
        op = s["op"]
        if op == "draft":
            out.append(reg.draft(s["grant"], s["nodes"]))
        elif op == "validate":
            out.append(reg.validate(s["grant"], s["root"]))
        elif op == "commit":
            out.append(reg.commit(s["grant"], s["root"]))
        elif op == "authorize":
            out.append(reg.authorize(s["grant"], s["root"], s["approval"]))
        elif op == "revoke":
            out.append(reg.revoke(s["grant"], s["root"], s["reason"]))
        elif op == "status":
            out.append(reg.status(s["grant"], s["root"], s["at"]))
        elif op == "check":
            out.append(reg.check(s["grant"], s["root"], now=s["at"], node_id=s.get("node_id"), operation=s.get("operation")))
        elif op == "is_plan_authorized":
            out.append(reg.is_plan_authorized(s["grant"], s["root"]))
        elif op == "context":
            out.append(reg.context(s["grant"], s["root"], s["at"]))
        else:
            raise AssertionError("unknown step " + op)
    return out


def _registry(scn, kv=None):
    clock = {"now": 0}
    v = VALIDATORS.get(scn.get("validator"))
    return PlanRegistry(kv=kv if kv is not None else MemoryAtomicKv(), now=lambda: clock["now"], validator=v), clock


def test_corpus_is_complete():
    assert len(DOC["scenarios"]) == 12
    assert sum(len(s["steps"]) for s in DOC["scenarios"]) == sum(len(s["expect"]) for s in DOC["scenarios"])


@pytest.mark.parametrize("scn", DOC["scenarios"], ids=lambda s: s["name"])
def test_scenario(scn):
    reg, clock = _registry(scn)
    assert run_steps(reg, clock, scn["steps"]) == scn["expect"]


@pytest.mark.parametrize("scn", DOC["scenarios"], ids=lambda s: s["name"])
def test_scenario_on_a_durable_store(scn, tmp_path):
    reg, clock = _registry(scn, SqliteAtomicKv(str(tmp_path / "plans.db")))
    assert run_steps(reg, clock, scn["steps"]) == scn["expect"]


def test_the_root_is_the_typescript_root():
    nodes = DOC["scenarios"][0]["steps"][0]["nodes"]
    assert plan_root(nodes) == DOC["scenarios"][0]["steps"][1]["root"]


def test_parallel_claims_of_one_transition_have_one_winner():
    reg = PlanRegistry(now=lambda: 1)
    nodes = [{"id": "n1", "verb": "v", "resource": "/r"}]
    root = reg.draft("g1", nodes)["record"]["root"]
    assert reg.validate("g1", root)["ok"]
    results, errs = [], []
    gate = threading.Barrier(16)

    def go():
        try:
            gate.wait()
            results.append(reg.commit("g1", root))
        except Exception as e:  # noqa: BLE001
            errs.append(e)

    ts = [threading.Thread(target=go) for _ in range(16)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert errs == []
    assert sum(1 for r in results if r["ok"]) == 1
    assert all(r["state"] == "committed" for r in results if not r["ok"])


def test_parallel_claims_on_a_shared_file_have_one_winner(tmp_path):
    path = str(tmp_path / "plans.db")
    nodes = [{"id": "n1", "verb": "v", "resource": "/r"}]
    first = PlanRegistry(kv=SqliteAtomicKv(path), now=lambda: 1)
    root = first.draft("g1", nodes)["record"]["root"]
    first.validate("g1", root)
    results = []
    gate = threading.Barrier(8)

    def go():
        reg = PlanRegistry(kv=SqliteAtomicKv(path), now=lambda: 1)  # its own connection, like another worker
        gate.wait()
        results.append(reg.commit("g1", root))

    ts = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(1 for r in results if r["ok"]) == 1


# ---- authorize(plans=...) ---------------------------------------------------------------------------------------------

def _fixture():
    c = next(c for c in FIX["cases"] if c["name"] == "envelope-max-spend-within")
    return c, c["steps"][0]


def _authorize(c, s, plans, plan=None):
    return authorize(s["pcactn"], operation=s["operation"], audience=FIX["audience"], resolve_grant=lambda ref: c["grant"],
                     state_store=MemoryStateStore(), is_revoked=lambda p, g: False, now=FIX["now"], plan=plan, plans=plans)


def test_an_unregistered_plan_is_refused_by_name():
    c, s = _fixture()
    r = _authorize(c, s, PlanRegistry())
    assert r.allow is False
    assert r.checks["plan_state"] == "fail" and r.checks["plan_root_authorized"] == "fail"
    root = s["pcactn"]["plan"]["root"]
    assert "plan_state: plan %s is unknown to the plan registry" % root in r.reasons


def test_a_registered_plan_is_executable_only_once_authorized():
    c, s = _fixture()
    p = s["pcactn"]
    node = {"id": p["plan"]["node_id"], "verb": p["action"]["verb"], "resource": p["action"]["resource"],
            "params_digest": p["action"]["params_digest"], "reversibility_class": p["action"]["reversibility_class"]}
    reg = PlanRegistry(now=lambda: FIX["now"])
    assert plan_root([node]) == p["plan"]["root"], "the fixture plan is a single-step plan"
    root = reg.draft(c["grant"]["id"], [node])["record"]["root"]
    for step in (reg.validate, reg.commit):
        assert step(c["grant"]["id"], root)["ok"]
    committed = _authorize(c, s, reg)
    assert committed.allow is False and committed.checks["plan_state"] == "fail"
    assert "committed but not authorized by the principal" in " ".join(committed.reasons)
    assert reg.authorize(c["grant"]["id"], root, {"by": "principal"})["ok"]
    ok = _authorize(c, s, reg)
    assert ok.allow is True and ok.checks["plan_state"] == "pass" and ok.checks["plan_root_authorized"] == "pass"
    assert reg.revoke(c["grant"]["id"], root, "changed my mind")["ok"]
    again = _authorize(c, s, reg)
    assert again.allow is False and again.checks["plan_state"] == "fail"
