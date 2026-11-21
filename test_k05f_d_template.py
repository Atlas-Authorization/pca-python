"""`require_linked_template`: the grant must be the instantiation of the template it links (reference server/authorize.ts linkError)."""
import json
import sys
import os

from atlas_pca.authorize import MemoryStateStore, authorize

AZ = sys.modules["atlas_pca.authorize"]  # the module (the package attribute `authorize` is the function)

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_HERE, "conformance", "vectors.json"), os.path.join(_HERE, "conformance", "vectors.json")):
    if os.path.exists(_p):
        with open(_p, encoding="utf-8") as _f:
            V = {v["name"]: v for v in json.load(_f)["vectors"]}["valid-in-plan-action"]
        break
ACT = V["pcactn"]["action"]


def run(registry="REG", grant=None, store=None, **kw):
    g = V["grant"] if grant is None else grant
    return authorize(V["pcactn"], operation={"verb": ACT["verb"], "resource": ACT["resource"], "params": {}}, audience=V["context"]["aud"],
                     resolve_grant=lambda ref: g, state_store=store or MemoryStateStore(), is_revoked=lambda p, gr: False,
                     now=V["context"]["now"], require_linked_template={"registry": registry}, **kw)


def test_a_grant_without_template_ref_is_refused(monkeypatch):
    monkeypatch.setattr(AZ, "read_envelope", lambda g: {})  # a readable envelope that links no template
    r = run()
    assert r.allow is False and r.reason == "template: the grant carries no template_ref" and r.checks == {"template": "fail"}


def test_an_unreadable_envelope_is_refused(monkeypatch):
    monkeypatch.setattr(AZ, "read_envelope", lambda g: None)
    assert run().reason == "template: the grant has no readable envelope"


def test_a_link_that_does_not_verify_is_refused_with_its_reason(monkeypatch):
    monkeypatch.setattr(AZ, "read_envelope", lambda g: {"template_ref": {"x": 1}})
    seen = []
    monkeypatch.setattr("atlas_pca.policy_link.verify_linked_policy", lambda env, reg: seen.append((env, reg)) or {"ok": False, "reason": "grant policy differs"})
    assert run().reason == "template: grant policy differs" and seen == [({"template_ref": {"x": 1}}, "REG")]
    monkeypatch.setattr("atlas_pca.policy_link.verify_linked_policy", lambda env, reg: {"ok": False})
    assert run().reason == "template: refused"


def test_a_registry_factory_is_called_and_a_verified_link_passes_the_gate(monkeypatch):
    monkeypatch.setattr(AZ, "read_envelope", lambda g: {"template_ref": {"x": 1}})
    seen = []
    monkeypatch.setattr("atlas_pca.policy_link.verify_linked_policy", lambda env, reg: seen.append(reg) or {"ok": True})
    r = run(registry=lambda: "FROM-FACTORY")
    assert seen == ["FROM-FACTORY"] and not (r.checks.get("template") == "fail")


def test_a_missing_registry_is_a_config_refusal():
    r = run(registry=None)
    assert r.allow is False and r.missing == ["require_linked_template.registry"]
    assert r.reason == "authorize_config: missing required component(s): require_linked_template.registry (fail closed)"


def test_an_unreadable_pcactn_or_grant_is_left_to_the_verification():
    r = authorize("not json", operation={"verb": "v", "resource": "r", "params": {}}, audience="a", resolve_grant=lambda ref: None,
                  state_store=MemoryStateStore(), is_revoked=lambda p, g: False, require_linked_template={"registry": "R"})
    assert r.allow is False and r.status == 401

    def boom(ref):
        raise RuntimeError("down")
    r2 = authorize(V["pcactn"], operation={"verb": ACT["verb"], "resource": ACT["resource"], "params": {}}, audience=V["context"]["aud"],
                   resolve_grant=boom, state_store=MemoryStateStore(), is_revoked=lambda p, g: False, now=V["context"]["now"],
                   require_linked_template={"registry": "R"})
    assert r2.allow is False and "template" not in r2.checks
