"""End-to-end `authorize()` replay of authorize-pq-pin-fixtures.json: a pinned issuer's classical grant is a downgrade and fails `pq_pin`
(exact reason), an unpinned issuer / empty pins still pass, a PQ grant needs the byte-equal pin."""
import copy
import json
import os

import pytest
from prov_harness import calm_risk

from atlas_pca import MemoryStateStore, authorize

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_HERE, "conformance", "authorize-pq-pin-fixtures.json"),
           os.path.join(_HERE, "conformance", "authorize-pq-pin-fixtures.json")):
    if os.path.exists(_p):
        with open(_p, encoding="utf-8") as _f:
            DOC = json.load(_f)
        break
else:
    raise FileNotFoundError("authorize-pq-pin-fixtures.json")


@pytest.mark.parametrize("case", DOC["cases"], ids=[c["name"] for c in DOC["cases"]])
def test_authorize_pq_pin_fixture(case):
    grant = copy.deepcopy(case["grant"])
    kw = {} if case["pq_pins"] is None else {"pq_pins": case["pq_pins"]}
    r = authorize(copy.deepcopy(case["pcactn"]), operation=DOC["operation"], audience=DOC["audience"], resolve_grant=lambda ref: grant,
                  state_store=MemoryStateStore(), is_revoked=lambda p, g: False, now=DOC["now"], plan="single-step", risk=calm_risk, **kw)
    exp = case["expect"]
    assert r.allow is exp["allow"], r.reasons
    assert r.status == exp["status"]
    assert r.checks.get("pq_pin", "absent") == exp["checks"]["pq_pin"]
    failed = {k for k, v in r.checks.items() if v == "fail"}
    assert set(exp["failed_includes"]) <= failed
    if not exp["allow"]:
        assert exp["reason"] in r.reasons


def test_core_refuses_a_classical_root_from_a_pinned_issuer():
    from atlas_pca import verify_pcactn_core
    c = next(c for c in DOC["cases"] if c["name"] == "classical-grant-empty-pins")
    grant = c["grant"]

    def core(pins):
        return verify_pcactn_core(copy.deepcopy(c["pcactn"]), copy.deepcopy(grant), DOC["now"], DOC["audience"], authorized_plan_roots=[c["pcactn"]["plan"]["root"]],
                                  pq_pins=pins)

    v = core({grant["issuer"]: "a-pq-key"})
    assert v.allow is False and v.checks["pq_pin"] is False
    assert "pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused" in v.reasons
    for pins in ({}, {"other": "x"}, None):
        w = core(pins)
        assert "pq_pin" not in w.checks and w.allow is True, w.reasons
