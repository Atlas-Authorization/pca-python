"""`forbid` in authorize (reference server/authorize.ts): forbid-wins clauses over the operation, an optional certificate the verifier recomputes."""
import json
import sys
import os

from atlas_pca.authorize import MemoryStateStore, authorize
from atlas_pca.forbid_certificate import certify

AZ = sys.modules["atlas_pca.authorize"]  # the module (the package attribute `authorize` is the function)

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_HERE, "conformance", "vectors.json"), os.path.join(_HERE, "conformance", "vectors.json")):
    if os.path.exists(_p):
        with open(_p, encoding="utf-8") as _f:
            V = {v["name"]: v for v in json.load(_f)["vectors"]}["valid-in-plan-action"]
        break
ACT = V["pcactn"]["action"]
OP = {"verb": ACT["verb"], "resource": ACT["resource"], "params": {"amount": 5}}
PERMIT = {"id": "p1", "kind": "permit", "signer": "user", "when": {"verb": ACT["verb"]}}
FORBID = {"id": "f1", "kind": "forbid", "signer": "org", "when": {"verb": ACT["verb"], "resource": ACT["resource"]}}
ESC = {"id": "e1", "kind": "escalate", "when": {"verb": ACT["verb"]}}


def run(forbid, **kw):
    return authorize(V["pcactn"], operation=OP, audience=V["context"]["aud"], resolve_grant=lambda ref: V["grant"], state_store=MemoryStateStore(),
                     is_revoked=lambda p, g: False, now=V["context"]["now"], forbid=forbid, **kw)


def test_a_matching_forbid_refuses_whoever_permits():
    r = run({"clauses": lambda op, g: [PERMIT, FORBID]})
    assert r.allow is False and r.reason == "forbid: deny by forbid f1" and r.checks == {"forbid": "fail"}


def test_no_matching_permit_is_a_default_deny_naming_nothing():
    r = run({"clauses": lambda op, g: []})
    assert r.reason == "forbid: deny by none"


def test_an_escalate_clause_refuses_with_its_id():
    r = run({"clauses": lambda op, g: [PERMIT, ESC]})
    assert r.reason == "forbid: escalate by escalate e1"


def test_an_allowed_operation_goes_on_to_the_guard():
    r = run({"clauses": lambda op, g: [PERMIT]})
    assert "forbid" not in r.checks


def test_the_clause_source_sees_the_operation_and_the_resolved_grant():
    seen = []
    run({"clauses": lambda op, g: seen.append((op, g["id"])) or [PERMIT]})
    assert seen == [(OP, V["grant"]["id"])]


def test_the_context_hook_extends_the_action_context():
    clause = {"id": "f2", "kind": "forbid", "when": {"verb": ACT["verb"], "where": [{"field": "env.region", "op": "eq", "value": "eu"}]}}
    assert run({"clauses": lambda op, g: [PERMIT, clause], "context": lambda op: {"env": {"region": "eu"}}}).reason == "forbid: deny by forbid f2"
    assert run({"clauses": lambda op, g: [PERMIT, clause], "context": lambda op: {"env": {"region": "us"}}}).checks.get("forbid") is None


def test_precedence_names_the_most_authoritative_forbid():
    f_user = dict(FORBID, id="a-user", signer="user")
    f_org = dict(FORBID, id="z-org", signer="org")
    assert run({"clauses": lambda op, g: [PERMIT, f_user, f_org], "precedence": ["org", "user"]}).reason == "forbid: deny by forbid z-org"
    assert run({"clauses": lambda op, g: [PERMIT, f_user, f_org]}).reason == "forbid: deny by forbid a-user"


def test_permit_signers_drop_a_permit_from_another_signer():
    assert run({"clauses": lambda op, g: [PERMIT], "permit_signers": ["org"]}).reason == "forbid: deny by none"


def test_a_required_certificate_must_be_present_and_recomputable():
    clauses = [PERMIT]
    f = {"clauses": lambda op, g: clauses, "require_certificate": True}
    assert run(f).reason == "forbid: the call carries no certificate (fail closed)"
    ctx = {"action": {"verb": OP["verb"], "resource": OP["resource"], "params": OP["params"]}}
    good = certify(clauses, ctx)
    assert "forbid" not in run(f, forbid_certificate=good).checks
    bad = dict(good, decision="deny")
    assert run(f, forbid_certificate=bad).reason == "forbid: certificate refused (certificate table does not entail its decision)"
    other = certify([PERMIT, {"id": "p2", "kind": "permit", "when": {"verb": "other"}}], ctx)
    assert run(f, forbid_certificate=other).reason == "forbid: certificate refused (certificate does not match the recomputed decision)"


def test_a_missing_clause_source_is_a_config_refusal():
    r = run({"clauses": None})
    assert r.allow is False and r.missing == ["forbid.clauses"]


def test_options_carry_the_forbid_field():
    o = AZ.AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=lambda p, g: False, plan="single-step", forbid={"clauses": lambda op, g: []})
    assert o.forbid is not None
