"""Replay of every row of prohibition-vectors.json (constitution + monitor sections; clauses/check live in test_k05f_f_forbid.py, replayed
here too) and contracts-vectors.json (validate, check, advance, verify, enforcer)."""
import json
import os

import pytest

from atlas_pca.atomic_kv import MemoryAtomicKv
from atlas_pca.contract_enforcer import ContractEnforcer
from atlas_pca.contracts import advance_contract, check_contract, validate_contract, verify_contract
from atlas_pca.forbid_certificate import certify, check_forbid_certificate, clauses_error, decide_clauses
from atlas_pca.prohibitions import check_and_advance, check_prohibitions, empty_state, state_digest, tick_state, validate_constitution, verify_signed_safety_evidence

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    for p in (os.path.join(_HERE, "conformance", name), os.path.join(_HERE, "conformance", name)):
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
    raise FileNotFoundError(name)


PV, CV = _load("prohibition-vectors.json"), _load("contracts-vectors.json")


def test_every_table_is_populated():
    assert all(len(PV[k]) > 4 for k in ("clauses", "check", "constitution", "monitor", "evidence"))
    assert all(len(CV[k]) > 4 for k in ("validate", "check", "advance", "verify", "enforcer"))


@pytest.mark.parametrize("v", PV["clauses"], ids=[v["name"] for v in PV["clauses"]])
def test_prohibition_clauses(v):
    assert clauses_error(v["clauses"]) == v["expect"]["error"]
    d = decide_clauses(v["clauses"], v["action"], (v.get("options") or {}).get("precedence"), (v.get("options") or {}).get("permitSigners"))
    e = v["expect"]
    assert {"decision": d["decision"], "winner": d["witness"]["winner"], "shadowed": d["witness"]["shadowed"], "values": d["values"]} == {
        k: e[k] for k in ("decision", "winner", "shadowed", "values")}


@pytest.mark.parametrize("v", PV["check"], ids=[v["name"] for v in PV["check"]])
def test_prohibition_check(v):
    o = v.get("options") or {}
    assert check_forbid_certificate(v["certificate"], v["clauses"], v["action"], o.get("precedence"), o.get("permitSigners")) == v["expect"]
    if v["expect"]["ok"]:
        assert certify(v["clauses"], v["action"], o.get("precedence"), o.get("permitSigners")) == v["certificate"]


@pytest.mark.parametrize("v", PV["constitution"], ids=[v["name"] for v in PV["constitution"]])
def test_prohibition_constitution(v):
    assert validate_constitution(v["constitution"]) == v["expect"]["problems"]
    assert check_prohibitions(v["action"], v["constitution"], v["state"]) == v["expect"]["result"]


@pytest.mark.parametrize("v", PV["monitor"], ids=[v["name"] for v in PV["monitor"]])
def test_prohibition_monitor(v):
    st = empty_state(v["genesis_now"])
    for step in v["steps"]:
        cur = st
        if "now" in step:
            t = tick_state(st, step["now"])
            if not t["ok"]:
                assert {"allow": False, "decidedBy": "clock", "reason": t["reason"]} == step["expect"]
                continue
            cur = t["state"]
        r = check_and_advance(True, step["action"], v["constitution"], cur)
        st = r["next"] if r["allow"] else cur
        assert {"allow": r["allow"], "decidedBy": r["decidedBy"], "violated": r["prohibition"]["violated"], "seq": r["next"]["seq"]} == step["expect"]


@pytest.mark.parametrize("v", PV["evidence"], ids=[v["name"] for v in PV["evidence"]])
def test_prohibition_evidence(v):
    assert verify_signed_safety_evidence(v["signed"], v["expected"]) == v["expect"]


@pytest.mark.parametrize("v", CV["validate"], ids=[v["name"] for v in CV["validate"]])
def test_contract_validate(v):
    assert validate_contract(v["contract"]) == v["expect"]["problems"]


@pytest.mark.parametrize("v", CV["check"], ids=[v["name"] for v in CV["check"]])
def test_contract_check(v):
    assert check_contract(v["action"], v["contract"], v["state"]) == v["expect"]


@pytest.mark.parametrize("v", CV["verify"], ids=[v["name"] for v in CV["verify"]])
def test_contract_verify(v):
    assert verify_contract(v["contract"], v.get("principal")) == v["expect"]


@pytest.mark.parametrize("v", CV["advance"], ids=[v["name"] for v in CV["advance"]])
def test_contract_advance(v):
    st = empty_state(v["genesis_now"])
    for step in v["steps"]:
        op, o = step.get("options") or {}, {}
        for k in ("now", "expectedSeq"):
            if k in op:
                o[k] = op[k]
        if op.get("stale_digest_of_genesis"):
            o["expectedStateDigest"] = state_digest(empty_state(v["genesis_now"]))
        r = advance_contract(st, step["action"], v["contract"], o)
        if r["ok"]:
            st = r["next"]
        assert {"ok": r["ok"], "decidedBy": r["decidedBy"], "violated": r["violated"], "reasons": r["reasons"], "seq": r["next"]["seq"],
                "deadlines": r["next"].get("deadlines", {}), "latched": sorted(r["next"]["latched"]), "state_digest": state_digest(r["next"])} == step["expect"]


_HEAD, _SCENARIOS = CV["enforcer"][0], CV["enforcer"][1:]


@pytest.mark.parametrize("v", _SCENARIOS, ids=[v["name"] for v in _SCENARIOS])
def test_contract_enforcer(v):
    kv, wall = MemoryAtomicKv(), [_HEAD["clock"]]
    e = ContractEnforcer.open(kv, _HEAD["contract"], _HEAD["principal"], now=lambda: wall[0],
                              latch_on_violation=(v.get("options") or {}).get("latchOnViolation", True))
    if "stored_document" in v:
        kv.set("contract/" + _HEAD["contract"]["id"], v["stored_document"])
    for st in v["steps"]:
        if st["op"] == "check":
            wall[0] = st.get("wall", _HEAD["clock"])
            got = e.check(st["action"], st.get("permitted", True))
        elif st["op"] == "peek":
            got = e.peek(st["action"])
        elif st["op"] == "state":
            r = e.state()
            got = None if r is None else {"seq": r["state"]["seq"], "now": r["state"]["now"], "latched": r["latched"], "state_digest": state_digest(r["state"])}
        else:
            got = {"cleared": e.reset(st["sig"])}
        assert got == st["expect"]
