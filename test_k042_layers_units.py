"""Kill tests: intent_layers fail-closed results (exact members and texts)."""
from atlas_pca import intent_layers as L

CTX = {"action": {"verb": "v", "resource": "r"}}
ALLOW = {"predicates": [{"verb": "*"}]}


def test_ceilings_evaluation_error_is_exact(monkeypatch):
    def boom(l, ctx):
        raise RuntimeError("kaput")

    monkeypatch.setattr(L, "_layer_admits", boom)
    r = L.decide_layer_ceilings({"org": ALLOW}, CTX)
    assert r == {"status": "fail", "layer": "org", "reason": "layers: evaluation error (fail closed): kaput"}
    assert list(r) == ["status", "layer", "reason"]


def test_unknown_grant_member_is_intent_denied_exactly():
    assert L.decide_layers({"task": [ALLOW], "bogus": 1}, CTX) == {"decision": "intent_denied"}
    assert L.decide_layers({"task": [ALLOW], "denied": "x"}, CTX) == {"decision": "intent_denied"}
    assert L.decide_layers({"task": [ALLOW]}, CTX) == {"decision": "admit", "by": 0}


def test_decide_layers_internal_error_is_intent_denied(monkeypatch):
    def boom(l, ctx):
        raise RuntimeError("kaput")

    monkeypatch.setattr(L, "_layer_admits", boom)
    assert L.decide_layers({"task": [ALLOW]}, CTX) == {"decision": "intent_denied"}
