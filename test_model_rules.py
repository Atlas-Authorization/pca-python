"""Rules 20 (units) and 21 (tighten-only) END TO END through authorize(): the shared vectors
packages/pca/conformance/model-rules-vectors.json (signed grants, decided by the TypeScript reference). A grant's `tighten[]`
rules, unit tags and polarity are signed policy: ignoring them would let a model move a decision up, so every case must decide
the same as the reference, reason text included (goal-to-decision T2, contracts C-50 / C-54)."""
import json
import os
import re

import pytest

from atlas_pca import MemoryStateStore, authorize
from prov_harness import prov

HERE = os.path.dirname(os.path.abspath(__file__))
DOC = json.load(open(os.path.join(HERE, "conformance", "model-rules-vectors.json"), encoding="utf-8"))
MODEL = re.compile(r"^(units|tighten|schema|intent_session): ")


def _run(c):
    g = c["grant"]
    ctx = c.get("context")
    return authorize(c["pcactn"], operation=c["operation"], audience=DOC["audience"],
                     resolve_grant=lambda ref: g if ref == g["id"] else None, state_store=MemoryStateStore(),
                     is_revoked=lambda p, gr: False, now=DOC["now"], plan="single-step",
                     context=(lambda p: dict(ctx)) if ctx else None, intent_v2=c.get("intent_v2"),
                     **prov(c["operation"]))  # provenance by default: a principal-direct bundle under the harness pin


@pytest.mark.parametrize("c", DOC["cases"], ids=[c["name"] for c in DOC["cases"]])
def test_model_rules_case(c):
    r, e = _run(c), c["expect"]
    assert (r.allow, r.decision, r.status) == (e["allow"], e["decision"], e["status"]), r.reasons
    assert sorted(n for n, s in r.checks.items() if s == "fail") == e["failed"]
    assert [x for x in r.reasons if MODEL.match(x)] == e["reasons"]
    for k in ("units", "tighten"):
        assert r.checks.get(k) == ({"pass": "pass", "fail": "fail"}[e[k]] if k in e else None)
    degraded = {n: x.get("reason") for n, x in (r.assurance or {}).items() if x.get("degraded")}
    assert degraded == e.get("degraded", {})


def test_the_vectors_exercise_every_decision():
    assert {c["expect"]["decision"] for c in DOC["cases"]} == {"allow", "escalate", "deny"}


def test_a_degraded_pass_is_refused_by_a_high_assurance_policy():
    c = next(x for x in DOC["cases"] if x["name"] == "legacy-model-path")
    g, ctx = c["grant"], c["context"]
    r = authorize(c["pcactn"], operation=c["operation"], audience=DOC["audience"], resolve_grant=lambda ref: g,
                  state_store=MemoryStateStore(), is_revoked=lambda p, gr: False, now=DOC["now"], plan="single-step",
                  context=lambda p: dict(ctx), require_assurance={"signature": "pq"})
    assert r.allow is False and "degraded compatibility mode" in " ".join(r.reasons)
