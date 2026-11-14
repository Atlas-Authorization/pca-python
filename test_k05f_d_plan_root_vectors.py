"""The core `plan_root_authorized` check (reference pcactn.ts, shared packages/pca/conformance/plan-root-vectors.json): given
`authorized_plan_roots` (even empty) it is enforced; omitted it fails unless `insecure_skip_plan_root_check` reports it not enforced; a
given list wins over the opt-out."""
import json
import os

import pytest

from atlas_pca import verify_pcactn_core

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    for p in (os.path.join(_HERE, "conformance", name), os.path.join(_HERE, "conformance", name)):
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
    raise FileNotFoundError(name)


PR = _load("plan-root-vectors.json")
VECTORS = {v["name"]: v for v in _load("vectors.json")["vectors"]}
CASES = PR["plan_root_authorized"]


def run(case, **over):
    v = VECTORS[case["vector"]]
    ctx = v["context"]
    opts = case["options"]
    roots = opts.get("authorizedPlanRoots")
    if roots is not None:
        roots = [v["pcactn"]["plan"]["root"] if r == "$plan_root" else r for r in roots]
    kw = {"authorized_plan_roots": roots, "insecure_skip_plan_root_check": opts.get("insecureSkipPlanRootCheck", False)}
    kw.update(over)
    return verify_pcactn_core(v["pcactn"], v["grant"], now=ctx["now"], audience=ctx["aud"], **kw)


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_plan_root_vectors(case):
    r = run(case)
    exp = case["expect"]
    assert r.allow is exp["allow"], r.reason
    if exp["check"] == "pass":
        assert r.checks["plan_root_authorized"] is True and "plan_root_authorized" not in r.not_enforced
    elif exp["check"] == "fail":
        assert r.checks["plan_root_authorized"] is False
    else:
        assert "plan_root_authorized" not in r.checks and r.not_enforced == ["plan_root_authorized"]
    if not exp["allow"]:
        assert r.reason == exp["reason"]


def test_a_string_is_not_a_list_of_roots():
    case = CASES[0]
    root = VECTORS[case["vector"]]["pcactn"]["plan"]["root"]
    r = run(case, authorized_plan_roots=root)  # a substring match would pass: the roots must be a collection
    assert r.allow is False and r.reason == "plan_root_authorized: the plan root has not been authorized by the principal"


def test_the_opt_out_must_be_exactly_true():
    case = next(c for c in CASES if c["name"] == "omitted")
    r = run(case, insecure_skip_plan_root_check=1)
    assert r.allow is False and r.checks["plan_root_authorized"] is False


def test_the_default_denies_with_the_reference_text():
    v = VECTORS["valid-in-plan-action"]
    ctx = v["context"]
    r = verify_pcactn_core(v["pcactn"], v["grant"], now=ctx["now"], audience=ctx["aud"])
    assert r.allow is False
    assert r.reason == ("plan_root_authorized: no authorized plan is configured for this verifier "
                        "(set authorizedPlanRoots, or the explicit insecureSkipPlanRootCheck)")
