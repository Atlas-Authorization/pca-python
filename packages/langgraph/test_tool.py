"""Tests for ``pca_tool`` — the single-tool guard.

A valid proof-carrying call runs and returns; a missing / invalid / wrong-audience /
insufficient-capability proof is rejected fail-closed and the underlying tool never runs. Proofs are
loaded from the shared conformance vectors (see ``_vec``), so nothing is minted or re-signed here, and
no langgraph/langchain install is needed (the guard is duck-typed).
"""
import json

import pytest

from atlas_pca.pca import b64u, canonical_bytes_strict
from atlas_pca_langgraph import (
    CoreVerifier,
    GuardedTool,
    PcaToolDenied,
    ToolDecision,
    pca_context,
    pca_tool,
    reset_pca_action,
    set_pca_action,
)

from _vec import AUD, NOW, PCACTN, REQUIRE, RESOURCE, VERB, resolver, tampered_pcactn


class _StructuredToolLike:
    """A stand-in for a LangChain StructuredTool: name/description and a ``func``."""

    def __init__(self):
        self.calls = []

        def place_order(sku, qty=1):
            self.calls.append((sku, qty))
            return {"ok": True, "sku": sku, "qty": qty}

        self.name = "place_order"
        self.description = "Place an order"
        self.func = place_order


def _guard(tool, *, require=REQUIRE, audience=AUD):
    return pca_tool(require, audience=audience, resolve_grant=resolver, now=NOW)(tool)


def _config(proof):
    return {"configurable": {"PCA-Action": proof}}


# ---- the happy path ------------------------------------------------------------------

def test_guard_returns_guarded_tool_without_langchain():
    # langchain_core is not installed in the test env, so the duck-typed GuardedTool is returned.
    guarded = _guard(_StructuredToolLike())
    assert isinstance(guarded, GuardedTool)
    assert guarded.name == "place_order"
    assert guarded.pca_required == REQUIRE
    assert callable(guarded.func)


def test_valid_proof_via_context_runs_and_returns():
    tool = _StructuredToolLike()
    guarded = _guard(tool)
    with pca_context(PCACTN):
        out = guarded("widget", qty=2)
    assert out == {"ok": True, "sku": "widget", "qty": 2}
    assert tool.calls == [("widget", 2)]  # the underlying tool actually ran


def test_valid_proof_via_invoke_entry():
    tool = _StructuredToolLike()
    guarded = _guard(tool)
    with pca_context(PCACTN):
        out = guarded.invoke({"sku": "bolt", "qty": 3})
    assert out == {"ok": True, "sku": "bolt", "qty": 3}
    assert tool.calls == [("bolt", 3)]


def test_valid_proof_via_config_configurable():
    tool = _StructuredToolLike()
    guarded = _guard(tool)
    out = guarded.invoke({"sku": "nut"}, config=_config(PCACTN))
    assert out["ok"] is True
    assert tool.calls == [("nut", 1)]


def test_valid_proof_via_inline_arg_is_popped_before_inner():
    tool = _StructuredToolLike()
    guarded = _guard(tool)
    out = guarded("sku-1", pca_action=PCACTN)  # proof carried inline
    assert out["ok"] is True
    assert tool.calls == [("sku-1", 1)]  # the inner tool never sees pca_action


def test_valid_proof_as_base64url_string():
    tool = _StructuredToolLike()
    guarded = _guard(tool)
    header = b64u(canonical_bytes_strict(PCACTN))  # the PCA-Action header encoding
    out = guarded("sku-9", pca_action=header)
    assert out["ok"] is True
    assert tool.calls == [("sku-9", 1)]


def test_wraps_plain_callable():
    seen = []

    def place(sku, qty=1):
        seen.append((sku, qty))
        return "placed %s x%d" % (sku, qty)

    guarded = _guard(place)
    assert isinstance(guarded, GuardedTool)
    with pca_context(PCACTN):
        assert guarded("bolt", qty=3) == "placed bolt x3"
    assert seen == [("bolt", 3)]


def test_require_none_requires_only_a_valid_proof():
    tool = _StructuredToolLike()
    guarded = pca_tool(None, audience=AUD, resolve_grant=resolver, now=NOW)(tool)
    assert guarded.pca_required is None
    with pca_context(PCACTN):
        assert guarded("x")["ok"] is True          # valid proof runs, no capability pinned
    with pca_context(tampered_pcactn()):
        with pytest.raises(PcaToolDenied):          # ...still fails closed on an invalid proof
            guarded("x")


# ---- fail closed ---------------------------------------------------------------------

def test_missing_proof_is_rejected_and_tool_not_run():
    tool = _StructuredToolLike()
    guarded = _guard(tool)
    with pytest.raises(PcaToolDenied) as ei:
        guarded("widget")  # no context, no inline proof, no config
    assert tool.calls == []  # never ran
    assert isinstance(ei.value.decision, ToolDecision)
    assert ei.value.decision.ok is False
    assert "no proof" in ei.value.decision.reason


def test_invalid_proof_is_rejected_and_tool_not_run():
    tool = _StructuredToolLike()
    guarded = _guard(tool)
    with pca_context(tampered_pcactn()):
        with pytest.raises(PcaToolDenied) as ei:
            guarded("widget")
    assert tool.calls == []
    assert ei.value.decision.verdict is not None
    assert ei.value.decision.verdict.checks["leaf_signature"] is False  # tampered sig


def test_wrong_audience_is_rejected_and_tool_not_run():
    tool = _StructuredToolLike()
    guarded = _guard(tool, audience="rs-wrong")  # proof was minted for AUD, not this one
    with pca_context(PCACTN):
        with pytest.raises(PcaToolDenied) as ei:
            guarded("widget")
    assert tool.calls == []
    assert ei.value.decision.verdict is not None
    assert ei.value.decision.verdict.checks["audience"] is False


def test_insufficient_capability_is_rejected_and_tool_not_run():
    tool = _StructuredToolLike()
    other = "delete:%s" % RESOURCE  # the proof authorizes VERB:RESOURCE, not this
    assert other != REQUIRE
    guarded = _guard(tool, require=other)
    with pca_context(PCACTN):
        with pytest.raises(PcaToolDenied) as ei:
            guarded("widget")
    assert tool.calls == []
    d = ei.value.decision
    assert d.verdict is not None and d.verdict.allow is True  # the proof itself is valid...
    assert "insufficient capability" in d.reason               # ...just not for this capability
    assert "%s:%s" % (VERB, RESOURCE) in d.reason


def test_unknown_grant_is_rejected():
    tool = _StructuredToolLike()
    guarded = pca_tool(REQUIRE, audience=AUD, resolve_grant=lambda ref: None, now=NOW)(tool)
    with pca_context(PCACTN):
        with pytest.raises(PcaToolDenied) as ei:
            guarded("widget")
    assert tool.calls == []
    assert "grant" in ei.value.decision.reason


def test_undecodable_inline_proof_fails_closed():
    tool = _StructuredToolLike()
    guarded = _guard(tool)
    with pytest.raises(PcaToolDenied):
        guarded("x", pca_action="!!!not-base64url-or-json!!!")
    assert tool.calls == []


# ---- plumbing ------------------------------------------------------------------------

def test_inline_proof_overrides_context():
    tool = _StructuredToolLike()
    guarded = _guard(tool)
    with pca_context(tampered_pcactn()):     # context holds a tampered proof...
        out = guarded("x", pca_action=PCACTN)  # ...but the valid inline proof wins
    assert out["ok"] is True


def test_set_reset_pca_action():
    tool = _StructuredToolLike()
    guarded = _guard(tool)
    token = set_pca_action(PCACTN)
    try:
        assert guarded("x")["ok"] is True
    finally:
        reset_pca_action(token)
    with pytest.raises(PcaToolDenied):
        guarded("x")  # proof no longer bound


def test_pca_tool_requires_verifier_or_resolver():
    with pytest.raises(ValueError):
        pca_tool(REQUIRE, audience=AUD)
    with pytest.raises(ValueError):
        pca_tool("not-a-pair", audience=AUD, resolve_grant=resolver)


def test_pca_tool_rejects_both_verifier_and_resolver():
    class V:
        def verify(self, pcactn, *, verb, resource, audience):
            raise AssertionError("not called")

    with pytest.raises(ValueError):
        pca_tool(REQUIRE, audience=AUD, verifier=V(), resolve_grant=resolver)


def test_custom_verifier_is_used():
    seen = {}

    class AlwaysDeny:
        def verify(self, pcactn, *, verb, resource, audience):
            seen["called"] = (verb, resource, audience)
            return ToolDecision(ok=False, reason="nope")

    tool = _StructuredToolLike()
    guarded = pca_tool(REQUIRE, audience=AUD, verifier=AlwaysDeny())(tool)
    with pytest.raises(PcaToolDenied):
        guarded("x", pca_action=PCACTN)
    assert seen["called"] == (VERB, RESOURCE, AUD)
    assert tool.calls == []


def test_core_verifier_decision_shape():
    v = CoreVerifier(resolver, now=NOW)
    ok = v.verify(PCACTN, verb=VERB, resource=RESOURCE, audience=AUD)
    assert ok.ok is True and ok["ok"] is True  # dict-style access too
    assert ok.required == REQUIRE
    assert json.dumps(ok.pcactn["action"])  # pcactn is carried through
