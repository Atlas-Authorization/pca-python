"""The policy layer (policy-vectors.json): every vector's caveat projection AND whole decision (reason codes, unsatisfied caveat types per
group) is reproduced, none skipped."""
import json
import os

import pytest

from atlas_pca import policy_caveats
from atlas_pca.authorize import evaluate_agent_caveats, policy_decision

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_HERE, "conformance", "policy-vectors.json"), os.path.join(_HERE, "conformance", "policy-vectors.json")):
    if os.path.exists(_p):
        with open(_p, encoding="utf-8") as _f:
            VECS = json.load(_f)["policy_decision"]
        break
else:
    raise FileNotFoundError("policy-vectors.json")


def test_every_vector_is_present():
    assert len(VECS) == 413


@pytest.mark.parametrize("v", VECS, ids=[v["name"] for v in VECS])
def test_policy_vector(v):
    assert policy_decision(v["grant"], v["chain"], v["context"]) == v["expect"]["decision"]
    act = v["context"]["action"]
    call = {"tool": act["verb"] if isinstance(act.get("verb"), str) else "", "args": act["params"] if isinstance(act.get("params"), dict) else {}}
    ok, failed = evaluate_agent_caveats(policy_caveats(v["grant"], v["chain"]), v["context"], {"action": act}, call)
    assert {"allow": ok, "failed": failed} == v["expect"]["caveats"]
