"""Tests for ``pca_tool`` — the single-tool guard for the Microsoft Agent Framework.

A valid proof-carrying call runs and returns; a missing / invalid / wrong-audience /
insufficient-capability proof is rejected fail-closed and the underlying tool never runs. Both
synchronous and ``async def`` tools are covered. Proofs are loaded from the shared conformance vectors
(see ``_vec``), so nothing is minted or re-signed here, and no agent_framework install is needed (the
guard is duck-typed, returning a :class:`GuardedFunction`).
"""
import asyncio
import json

import pytest

from atlas_pca.pca import b64u, canonical_bytes_strict
from atlas_pca_agent_framework import (
    CoreVerifier,
    GuardedFunction,
    PcaToolDenied,
    ToolDecision,
    pca_context,
    pca_tool,
    reset_pca_action,
    set_pca_action,
)

from _vec import AUD, NOW, PCACTN, REQUIRE, RESOURCE, VERB, resolver, tampered_pcactn


class _AIFunctionLike:
    """A stand-in for an ``@ai_function``-decorated AIFunction: name/description + the raw ``func``."""

    def __init__(self, name="place_order", *, is_async=False):
        self.name = name
        self.description = "Place an order"
        self.calls = []
        if is_async:
            async def func(sku, qty=1):
                self.calls.append((sku, qty))
                return {"ok": True, "sku": sku, "qty": qty}
        else:
            def func(sku, qty=1):
                self.calls.append((sku, qty))
                return {"ok": True, "sku": sku, "qty": qty}
        self.func = func


def _guard(tool, *, require=REQUIRE, audience=AUD):
    return pca_tool(require, audience=audience, resolve_grant=resolver, now=NOW)(tool)


# ---- the happy path ------------------------------------------------------------------

def test_valid_proof_via_context_runs_and_returns():
    tool = _AIFunctionLike()
    guarded = _guard(tool)
    assert isinstance(guarded, GuardedFunction)
    with pca_context(PCACTN):
        out = asyncio.run(guarded.invoke(arguments={"sku": "widget", "qty": 2}))
    assert out == {"ok": True, "sku": "widget", "qty": 2}
    assert tool.calls == [("widget", 2)]  # the underlying tool actually ran


def test_valid_proof_async_tool_runs_and_returns():
    tool = _AIFunctionLike(is_async=True)
    guarded = _guard(tool)
    assert guarded.is_async is True
    with pca_context(PCACTN):
        out = asyncio.run(guarded.invoke(arguments={"sku": "bolt"}))
    assert out == {"ok": True, "sku": "bolt", "qty": 1}
    assert tool.calls == [("bolt", 1)]


def test_valid_proof_via_inline_kwarg_is_popped_before_inner():
    tool = _AIFunctionLike()
    guarded = _guard(tool)
    out = asyncio.run(guarded.invoke(arguments={"sku": "sku-1", "pca_action": PCACTN}))
    assert out["ok"] is True
    assert tool.calls == [("sku-1", 1)]  # the inner tool never saw pca_action


def test_valid_proof_as_base64url_string():
    tool = _AIFunctionLike()
    guarded = _guard(tool)
    header = b64u(canonical_bytes_strict(PCACTN))  # the PCA-Action header encoding
    out = asyncio.run(guarded.invoke(arguments={"sku": "x", "pca_action": header}))
    assert out["ok"] is True
    assert len(tool.calls) == 1


def test_wraps_plain_callable():
    seen = []

    def place(sku, qty=1):
        seen.append((sku, qty))
        return "placed %s x%d" % (sku, qty)

    guarded = _guard(place)
    assert isinstance(guarded, GuardedFunction)
    with pca_context(PCACTN):
        assert guarded("bolt", qty=3) == "placed bolt x3"   # directly callable
        assert asyncio.run(guarded.invoke(arguments={"sku": "nut"})) == "placed nut x1"
    assert seen == [("bolt", 3), ("nut", 1)]


# ---- fail closed ---------------------------------------------------------------------

def test_missing_proof_is_rejected_and_tool_not_run():
    tool = _AIFunctionLike()
    guarded = _guard(tool)
    with pytest.raises(PcaToolDenied) as ei:
        asyncio.run(guarded.invoke(arguments={"sku": "widget"}))  # no context, no inline proof
    assert tool.calls == []  # never ran
    assert isinstance(ei.value.decision, ToolDecision)
    assert ei.value.decision.ok is False
    assert "no proof" in ei.value.decision.reason


def test_invalid_proof_is_rejected_and_tool_not_run():
    tool = _AIFunctionLike()
    guarded = _guard(tool)
    with pca_context(tampered_pcactn()):
        with pytest.raises(PcaToolDenied) as ei:
            asyncio.run(guarded.invoke(arguments={"sku": "widget"}))
    assert tool.calls == []
    assert ei.value.decision.verdict is not None
    assert ei.value.decision.verdict.checks["leaf_signature"] is False


def test_wrong_audience_is_rejected_and_tool_not_run():
    tool = _AIFunctionLike()
    guarded = _guard(tool, audience="rs-wrong")  # proof was minted for AUD, not this one
    with pca_context(PCACTN):
        with pytest.raises(PcaToolDenied) as ei:
            asyncio.run(guarded.invoke(arguments={"sku": "widget"}))
    assert tool.calls == []
    assert ei.value.decision.verdict is not None
    assert ei.value.decision.verdict.checks["audience"] is False


def test_insufficient_capability_is_rejected_and_tool_not_run():
    tool = _AIFunctionLike()
    other = "delete:%s" % RESOURCE  # the proof authorizes VERB:RESOURCE, not this
    assert other != REQUIRE
    guarded = _guard(tool, require=other)
    with pca_context(PCACTN):
        with pytest.raises(PcaToolDenied) as ei:
            asyncio.run(guarded.invoke(arguments={"sku": "widget"}))
    assert tool.calls == []
    d = ei.value.decision
    assert d.verdict is not None and d.verdict.allow is True   # the proof itself is valid...
    assert "insufficient capability" in d.reason               # ...just not for this capability
    assert "%s:%s" % (VERB, RESOURCE) in d.reason               # names what the proof does authorize


def test_unknown_grant_is_rejected():
    tool = _AIFunctionLike()
    guarded = pca_tool(REQUIRE, audience=AUD, resolve_grant=lambda ref: None, now=NOW)(tool)
    with pca_context(PCACTN):
        with pytest.raises(PcaToolDenied) as ei:
            asyncio.run(guarded.invoke(arguments={"sku": "widget"}))
    assert tool.calls == []
    assert "grant" in ei.value.decision.reason


def test_undecodable_inline_proof_fails_closed():
    tool = _AIFunctionLike()
    guarded = _guard(tool)
    with pytest.raises(PcaToolDenied):
        asyncio.run(guarded.invoke(arguments={"pca_action": "!!!not-base64url-or-json!!!"}))
    assert tool.calls == []


# ---- plumbing ------------------------------------------------------------------------

def test_inline_proof_overrides_context():
    tool = _AIFunctionLike()
    guarded = _guard(tool)
    with pca_context(tampered_pcactn()):   # context holds a bad proof, inline valid one wins
        out = asyncio.run(guarded.invoke(arguments={"sku": "a", "pca_action": PCACTN}))
    assert out["ok"] is True


def test_set_reset_pca_action():
    tool = _AIFunctionLike()
    guarded = _guard(tool)
    token = set_pca_action(PCACTN)
    try:
        assert asyncio.run(guarded.invoke(arguments={"sku": "x"}))["ok"] is True
    finally:
        reset_pca_action(token)
    with pytest.raises(PcaToolDenied):
        asyncio.run(guarded.invoke(arguments={"sku": "x"}))  # proof no longer bound


def test_preserves_inner_signature_for_schema_derivation():
    import inspect

    tool = _AIFunctionLike()
    guarded = _guard(tool)
    # The guarded wrapper reports the inner function's signature (so a rebuilt AIFunction derives the
    # right JSON schema), not the wrapper's ``*args, **kwargs``.
    params = list(inspect.signature(guarded._guarded).parameters)
    assert params == ["sku", "qty"]
    assert guarded.name == "place_order"


def test_pca_tool_requires_verifier_or_resolver():
    with pytest.raises(ValueError):
        pca_tool(REQUIRE, audience=AUD)
    with pytest.raises(ValueError):
        pca_tool("not-a-pair", audience=AUD, resolve_grant=resolver)
    with pytest.raises(ValueError):
        pca_tool(REQUIRE, audience=AUD, verifier=CoreVerifier(resolver, now=NOW), resolve_grant=resolver)


def test_custom_verifier_is_used():
    seen = {}

    class AlwaysDeny:
        def verify(self, pcactn, *, verb, resource, audience):
            seen["called"] = (verb, resource, audience)
            return ToolDecision(ok=False, reason="nope")

    tool = _AIFunctionLike()
    guarded = pca_tool(REQUIRE, audience=AUD, verifier=AlwaysDeny())(tool)
    with pytest.raises(PcaToolDenied):
        asyncio.run(guarded.invoke(arguments={"sku": "x", "pca_action": PCACTN}))
    assert seen["called"] == (VERB, RESOURCE, AUD)
    assert tool.calls == []


def test_core_verifier_decision_shape():
    v = CoreVerifier(resolver, now=NOW)
    ok = v.verify(PCACTN, verb=VERB, resource=RESOURCE, audience=AUD)
    assert ok.ok is True and ok["ok"] is True  # dict-style access too
    assert ok.required == REQUIRE
    assert json.dumps(ok.pcactn["action"])  # pcactn is carried through
