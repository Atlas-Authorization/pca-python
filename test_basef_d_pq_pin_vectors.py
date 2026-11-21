"""Server-side PQ pins (`pq_pins`, reference verifyPCActn `pqPins`; shared packages/pca/conformance/pq-pin-vectors.json): a non-Ed25519
grant passes the `pq_pin` check only with an own pin byte-equal to its pq_pk; an Ed25519 grant passes; unset: the check is not reported."""
import json
import os

import pytest

from atlas_pca.authorize import MemoryStateStore, authorize

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    for p in (os.path.join(_HERE, "conformance", name), os.path.join(_HERE, "conformance", name)):
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
    raise FileNotFoundError(name)


PQ = _load("pq-pin-vectors.json")["pq_pin"]
VECTORS = {v["name"]: v for v in _load("vectors.json")["vectors"]}


def subst(x, grant):
    if isinstance(x, str):
        if x == "$grant.issuer":
            return grant["issuer"]
        if x == "$grant.pq_pk":
            return grant["pq_pk"]
        if x == "$grant.pq_pk[0:20]":
            return grant["pq_pk"][:20]
        return x
    if isinstance(x, dict):
        return {subst(k, grant): subst(v, grant) for k, v in x.items()}
    return x


def run(case, pins_override="__none__"):
    v = VECTORS[case["vector"]]
    ctx = v["context"]
    grant = v["grant"]
    pins = subst(case["pq_pins"], grant) if pins_override == "__none__" else pins_override
    act = v["pcactn"]["action"]
    return authorize(v["pcactn"], operation={"verb": act["verb"], "resource": act["resource"], "params": {}}, audience=ctx["aud"],
                     resolve_grant=lambda ref: grant, state_store=MemoryStateStore(), is_revoked=lambda p, g: False, now=ctx["now"],
                     pq_pins=pins)


@pytest.mark.parametrize("case", PQ, ids=[c["name"] for c in PQ])
def test_pq_pin_vectors(case):
    r = run(case)
    exp = case["expect"]
    if exp["check"] == "absent":
        assert "pq_pin" not in r.checks
        return
    assert r.checks.get("pq_pin") == exp["check"]
    if exp["check"] == "fail":
        assert exp["reason"] in r.reasons


def test_an_own_entry_only_a_non_string_pin_is_a_mismatch():
    case = next(c for c in PQ if c["name"] == "pq-grant-pinned")
    grant = VECTORS[case["vector"]]["grant"]
    r = run(case, {grant["issuer"]: 5})
    assert r.checks["pq_pin"] == "fail" and "pq_pin: the grant pq_pk does not match the server-side pin" in r.reasons


def test_pins_given_as_a_string_never_match():
    case = next(c for c in PQ if c["name"] == "pq-grant-pinned")
    r = run(case, "not-a-mapping")
    assert r.checks["pq_pin"] == "fail"
