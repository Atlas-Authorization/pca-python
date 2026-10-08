"""Tests for ``pca_guard_node`` / ``pca_route`` — the pre-tool proof check with step-up routing.

The guard node verifies the proof for the pending tool call(s). A valid, sufficient proof marks the
run ``approved`` (so a conditional edge sends it to the tool node); a missing / invalid / wrong-audience
/ insufficient-capability proof is a risky/insufficient action that maps to step-up. langgraph is not
installed here, so ``interrupt()`` cannot pause — the node instead exposes the step-up decision and
``pca_route`` routes to ``stepup`` (with langgraph present the node would pause for FROST/CIBA approval
and re-verify the resumed, stepped-up proof). All proofs come from the shared conformance vectors.
"""
import pytest

from atlas_pca_langgraph import (
    pca_context,
    pca_guard_node,
    pca_route,
)

from _vec import AUD, NOW, PCACTN, REQUIRE, RESOURCE, resolver, tampered_pcactn


class _AIMessage:
    def __init__(self, tool_calls):
        self.tool_calls = tool_calls


def _tc(name, args=None, id="call-1"):
    return {"name": name, "args": args or {}, "id": id}


def _state(tool_calls, **extra):
    state = {"messages": [_AIMessage(tool_calls)]}
    state.update(extra)
    return state


def _guard(*, require=REQUIRE, audience=AUD, **kw):
    return pca_guard_node(audience=audience, require=require, resolve_grant=resolver, now=NOW, **kw)


# ---- approved path -------------------------------------------------------------------

def test_valid_proof_is_approved_and_routes_to_tools():
    node = _guard()
    with pca_context(PCACTN):
        out = node(_state([_tc("place_order", {"sku": "a"})]))
    assert out["pca"]["ok"] is True
    assert out["pca"]["stepup"] is False
    assert out["PCA-Action"] == PCACTN         # verified proof stashed for the downstream tool node
    assert pca_route(out) == "approved"


def test_valid_proof_via_config():
    node = _guard()
    out = node(_state([_tc("place_order", {"sku": "a"})]),
               {"configurable": {"PCA-Action": PCACTN}})
    assert out["pca"]["ok"] is True
    assert pca_route(out) == "approved"


# ---- step-up path (fail closed -> route to step-up) ----------------------------------

def test_missing_proof_routes_to_stepup():
    node = _guard()
    out = node(_state([_tc("place_order", {"sku": "a"})]))  # no proof anywhere
    assert out["pca"]["ok"] is False
    assert out["pca"]["stepup"] is True
    assert "place_order" in out["pca"]["pending"]
    assert pca_route(out) == "stepup"


def test_invalid_proof_routes_to_stepup():
    node = _guard()
    with pca_context(tampered_pcactn()):
        out = node(_state([_tc("place_order", {"sku": "a"})]))
    assert out["pca"]["ok"] is False and out["pca"]["stepup"] is True
    assert pca_route(out) == "stepup"


def test_wrong_audience_routes_to_stepup():
    node = _guard(audience="rs-wrong")
    with pca_context(PCACTN):
        out = node(_state([_tc("place_order", {"sku": "a"})]))
    assert out["pca"]["ok"] is False and out["pca"]["stepup"] is True
    assert pca_route(out) == "stepup"


def test_insufficient_capability_routes_to_stepup():
    node = _guard(require="delete:%s" % RESOURCE)  # proof authorizes a different verb
    with pca_context(PCACTN):
        out = node(_state([_tc("place_order", {"sku": "a"})]))
    assert out["pca"]["ok"] is False and out["pca"]["stepup"] is True
    assert out["pca"]["required"] == "delete:%s" % RESOURCE
    assert pca_route(out) == "stepup"


def test_any_denied_call_in_the_batch_triggers_stepup():
    # one call sufficient, one not -> the batch steps up (fail closed on the risky one)
    require = {"place_order": REQUIRE, "cancel_order": "delete:%s" % RESOURCE}
    node = _guard(require=require)
    with pca_context(PCACTN):
        out = node(_state([_tc("place_order", {"sku": "a"}, id="c1"),
                           _tc("cancel_order", {"id": "b"}, id="c2")]))
    assert out["pca"]["ok"] is False
    assert out["pca"]["pending"] == ["cancel_order"]
    assert pca_route(out) == "stepup"


# ---- pca_route helper ----------------------------------------------------------------

def test_pca_route_custom_labels():
    approved = {"pca": {"ok": True}}
    denied = {"pca": {"ok": False, "stepup": True}}
    assert pca_route(approved, approved="go", stepup="hitl") == "go"
    assert pca_route(denied, approved="go", stepup="hitl") == "hitl"


def test_pca_route_fails_closed_on_missing_marker():
    assert pca_route({}) == "stepup"            # no marker at all
    assert pca_route({"pca": {}}) == "stepup"   # marker without ok
    assert pca_route({"pca": {"ok": False}}) == "stepup"


# ---- construction guards -------------------------------------------------------------

def test_requires_audience():
    with pytest.raises(ValueError):
        pca_guard_node(audience="", require=REQUIRE, resolve_grant=resolver)


def test_requires_verifier_or_resolver():
    with pytest.raises(ValueError):
        pca_guard_node(audience=AUD, require=REQUIRE)


def test_rejects_both_verifier_and_resolver():
    class V:
        def verify(self, pcactn, *, verb, resource, audience):
            raise AssertionError("not called")

    with pytest.raises(ValueError):
        pca_guard_node(audience=AUD, require=REQUIRE, verifier=V(), resolve_grant=resolver)


def test_malformed_require_entry_raises_at_call_time():
    node = _guard(require="not-a-pair")
    with pca_context(PCACTN):
        with pytest.raises(ValueError):
            node(_state([_tc("place_order", {"sku": "a"})]))
