"""Tests for ``pca_tool`` — the single-tool guard.

A valid proof-carrying call runs and returns; a missing / invalid / wrong-audience /
insufficient-capability proof is rejected fail-closed and the underlying tool never runs. Proofs are
loaded from the shared conformance vectors (see ``_vec``), so nothing is minted or re-signed here, and
no google-adk install is needed (the guard is duck-typed).
"""
import asyncio
import json

import pytest

from atlas_pca.pca import b64u, canonical_bytes_strict
from atlas_pca_google_adk import (
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


class _State:
    """Dict-like stand-in for an ADK ``State`` (``.get`` + ``[]``)."""

    def __init__(self, data=None):
        self._d = dict(data or {})

    def get(self, key, default=None):
        return self._d.get(key, default)

    def __getitem__(self, key):
        return self._d[key]


class _ToolContext:
    """Stand-in for an ADK ``ToolContext``: carries session ``state``."""

    def __init__(self, state=None):
        self.state = _State(state)


class _FunctionToolLike:
    """A stand-in for an ADK FunctionTool: has name/description and a ``func``."""

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


# ---- the happy path ------------------------------------------------------------------

def test_guard_returns_guarded_tool_without_adk():
    # google-adk is not installed in the test env, so the duck-typed GuardedTool is returned.
    guarded = _guard(_FunctionToolLike())
    assert isinstance(guarded, GuardedTool)
    assert guarded.name == "place_order"
    assert guarded.pca_required == REQUIRE
    assert callable(guarded.func)


def test_valid_proof_via_context_runs_and_returns():
    tool = _FunctionToolLike()
    guarded = _guard(tool)
    with pca_context(PCACTN):
        out = guarded("widget", qty=2)
    assert out == {"ok": True, "sku": "widget", "qty": 2}
    assert tool.calls == [("widget", 2)]  # the underlying tool actually ran


def test_valid_proof_via_run_async_entry():
    tool = _FunctionToolLike()
    guarded = _guard(tool)
    with pca_context(PCACTN):
        out = asyncio.run(guarded.run_async(args={"sku": "bolt", "qty": 3}))
    assert out == {"ok": True, "sku": "bolt", "qty": 3}
    assert tool.calls == [("bolt", 3)]


def test_valid_proof_via_tool_context_state():
    tool = _FunctionToolLike()
    guarded = _guard(tool)
    ctx = _ToolContext(state={"PCA-Action": PCACTN})
    out = asyncio.run(guarded.run_async(args={"sku": "nut"}, tool_context=ctx))
    assert out["ok"] is True
    assert tool.calls == [("nut", 1)]


def test_valid_proof_via_inline_arg_is_popped_before_inner():
    tool = _FunctionToolLike()
    guarded = _guard(tool)
    out = guarded("sku-1", pca_action=PCACTN)  # proof carried inline
    assert out["ok"] is True
    # the inner tool must NOT see the pca_action keyword; only its own args
    assert tool.calls == [("sku-1", 1)]


def test_valid_proof_as_base64url_string():
    tool = _FunctionToolLike()
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


def test_tool_context_is_forwarded_to_inner_when_declared():
    seen = {}

    def place(sku, tool_context):
        seen["ctx"] = tool_context
        seen["agent_state"] = tool_context.state.get("agent")
        return "ok"

    guarded = _guard(place)
    ctx = _ToolContext(state={"PCA-Action": PCACTN, "agent": "shopper"})
    out = asyncio.run(guarded.run_async(args={"sku": "x"}, tool_context=ctx))
    assert out == "ok"
    assert seen["ctx"] is ctx            # the inner tool received the real tool_context
    assert seen["agent_state"] == "shopper"


# ---- fail closed ---------------------------------------------------------------------

def test_missing_proof_is_rejected_and_tool_not_run():
    tool = _FunctionToolLike()
    guarded = _guard(tool)
    with pytest.raises(PcaToolDenied) as ei:
        guarded("widget")  # no context, no inline proof, no tool_context
    assert tool.calls == []  # never ran
    assert isinstance(ei.value.decision, ToolDecision)
    assert ei.value.decision.ok is False
    assert "no proof" in ei.value.decision.reason


def test_invalid_proof_is_rejected_and_tool_not_run():
    tool = _FunctionToolLike()
    guarded = _guard(tool)
    with pca_context(tampered_pcactn()):
        with pytest.raises(PcaToolDenied) as ei:
            guarded("widget")
    assert tool.calls == []
    # a tampered leaf signature fails the crypto check
    assert ei.value.decision.verdict is not None
    assert ei.value.decision.verdict.checks["leaf_signature"] is False


def test_wrong_audience_is_rejected_and_tool_not_run():
    tool = _FunctionToolLike()
    guarded = _guard(tool, audience="rs-wrong")  # proof was minted for AUD, not this one
    with pca_context(PCACTN):
        with pytest.raises(PcaToolDenied) as ei:
            guarded("widget")
    assert tool.calls == []
    assert ei.value.decision.verdict is not None
    assert ei.value.decision.verdict.checks["audience"] is False


def test_insufficient_capability_is_rejected_and_tool_not_run():
    tool = _FunctionToolLike()
    # the proof authorizes VERB:RESOURCE; demand a different verb on the same resource
    other = "delete:%s" % RESOURCE
    assert other != REQUIRE
    guarded = _guard(tool, require=other)
    with pca_context(PCACTN):
        with pytest.raises(PcaToolDenied) as ei:
            guarded("widget")
    assert tool.calls == []
    d = ei.value.decision
    assert d.verdict is not None and d.verdict.allow is True  # the proof itself is valid...
    assert "insufficient capability" in d.reason               # ...just not for this capability
    assert "%s:%s" % (VERB, RESOURCE) in d.reason               # names what the proof does authorize


def test_unknown_grant_is_rejected():
    tool = _FunctionToolLike()
    guarded = pca_tool(REQUIRE, audience=AUD, resolve_grant=lambda ref: None, now=NOW)(tool)
    with pca_context(PCACTN):
        with pytest.raises(PcaToolDenied) as ei:
            guarded("widget")
    assert tool.calls == []
    assert "grant" in ei.value.decision.reason


def test_undecodable_inline_proof_fails_closed():
    tool = _FunctionToolLike()
    guarded = _guard(tool)
    with pytest.raises(PcaToolDenied):
        guarded("x", pca_action="!!!not-base64url-or-json!!!")
    assert tool.calls == []


# ---- plumbing ------------------------------------------------------------------------

def test_inline_proof_overrides_context():
    tool = _FunctionToolLike()
    guarded = _guard(tool)
    # context holds a tampered proof, but the valid inline proof wins
    with pca_context(tampered_pcactn()):
        out = guarded("x", pca_action=PCACTN)
    assert out["ok"] is True


def test_set_reset_pca_action():
    tool = _FunctionToolLike()
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


def test_custom_verifier_is_used():
    seen = {}

    class AlwaysDeny:
        def verify(self, pcactn, *, verb, resource, audience):
            seen["called"] = (verb, resource, audience)
            return ToolDecision(ok=False, reason="nope")

    tool = _FunctionToolLike()
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


def test_core_verifier_without_capability_requires_only_valid_proof():
    v = CoreVerifier(resolver, now=NOW)
    # verb/resource both None -> no capability gate, only the eight core checks + audience
    ok = v.verify(PCACTN, verb=None, resource=None, audience=AUD)
    assert ok.ok is True
    assert ok.required is None
    bad = v.verify(tampered_pcactn(), verb=None, resource=None, audience=AUD)
    assert bad.ok is False  # still fails closed on an invalid proof
