"""Tests for ``pca_tool`` — the single-tool guard.

A valid proof-carrying call runs and returns; a missing / invalid / wrong-audience /
insufficient-capability proof is rejected fail-closed and the underlying tool never runs. Proofs are
loaded from the shared conformance vectors (see ``_vec``), so nothing is minted or re-signed here, and
no crewai install is needed (the guard is duck-typed).
"""
import json

import pytest

from atlas_pca.pca import b64u, canonical_bytes_strict
from atlas_pca_crewai import (
    CoreVerifier,
    GuardedTool,
    PcaToolDenied,
    ToolDecision,
    pca_context,
    pca_tool,
    set_pca_action,
    reset_pca_action,
)

from _vec import AUD, NOW, PCACTN, REQUIRE, RESOURCE, VERB, resolver, tampered_pcactn


class _BaseToolLike:
    """A stand-in for a crewai BaseTool instance: has name/description/args_schema and ``_run``."""

    def __init__(self):
        self.name = "place_order"
        self.description = "Place an order"
        self.args_schema = None
        self.calls = []

    def _run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {"ok": True, "args": args, "kwargs": kwargs}


def _guard(tool, *, require=REQUIRE, audience=AUD):
    return pca_tool(require, audience=audience, resolve_grant=resolver, now=NOW)(tool)


# ---- the happy path ------------------------------------------------------------------

def test_valid_proof_via_context_runs_and_returns():
    tool = _BaseToolLike()
    guarded = _guard(tool)
    assert isinstance(guarded, GuardedTool)
    with pca_context(PCACTN):
        out = guarded.run("widget", qty=2)
    assert out["ok"] is True
    assert out["args"] == ("widget",)
    assert out["kwargs"] == {"qty": 2}
    assert len(tool.calls) == 1  # the underlying tool actually ran


def test_valid_proof_via_inline_kwarg_is_popped_before_inner():
    tool = _BaseToolLike()
    guarded = _guard(tool)
    out = guarded.run("sku-1", pca_action=PCACTN)  # proof carried inline
    assert out["ok"] is True
    # the inner tool must NOT see the pca_action keyword
    assert "pca_action" not in tool.calls[0][1]
    assert tool.calls[0] == (("sku-1",), {})


def test_valid_proof_as_base64url_string():
    tool = _BaseToolLike()
    guarded = _guard(tool)
    header = b64u(canonical_bytes_strict(PCACTN))  # the PCA-Action header encoding
    out = guarded.run(pca_action=header)
    assert out["ok"] is True
    assert len(tool.calls) == 1


def test_wraps_plain_callable():
    seen = []

    def place(sku, qty=1):
        seen.append((sku, qty))
        return "placed %s x%d" % (sku, qty)

    guarded = _guard(place)
    with pca_context(PCACTN):
        assert guarded("bolt", qty=3) == "placed bolt x3"
    assert seen == [("bolt", 3)]


# ---- fail closed ---------------------------------------------------------------------

def test_missing_proof_is_rejected_and_tool_not_run():
    tool = _BaseToolLike()
    guarded = _guard(tool)
    with pytest.raises(PcaToolDenied) as ei:
        guarded.run("widget")  # no context, no inline proof
    assert tool.calls == []  # never ran
    assert isinstance(ei.value.decision, ToolDecision)
    assert ei.value.decision.ok is False
    assert "no proof" in ei.value.decision.reason


def test_invalid_proof_is_rejected_and_tool_not_run():
    tool = _BaseToolLike()
    guarded = _guard(tool)
    with pca_context(tampered_pcactn()):
        with pytest.raises(PcaToolDenied) as ei:
            guarded.run("widget")
    assert tool.calls == []
    # a tampered leaf signature fails the crypto check
    assert ei.value.decision.verdict is not None
    assert ei.value.decision.verdict.checks["leaf_signature"] is False


def test_wrong_audience_is_rejected_and_tool_not_run():
    tool = _BaseToolLike()
    guarded = _guard(tool, audience="rs-wrong")  # proof was minted for AUD, not this one
    with pca_context(PCACTN):
        with pytest.raises(PcaToolDenied) as ei:
            guarded.run("widget")
    assert tool.calls == []
    assert ei.value.decision.verdict is not None
    assert ei.value.decision.verdict.checks["audience"] is False


def test_insufficient_capability_is_rejected_and_tool_not_run():
    tool = _BaseToolLike()
    # the proof authorizes VERB:RESOURCE; demand a different verb on the same resource
    other = "delete:%s" % RESOURCE
    assert other != REQUIRE
    guarded = _guard(tool, require=other)
    with pca_context(PCACTN):
        with pytest.raises(PcaToolDenied) as ei:
            guarded.run("widget")
    assert tool.calls == []
    d = ei.value.decision
    assert d.verdict is not None and d.verdict.allow is True  # the proof itself is valid...
    assert "insufficient capability" in d.reason               # ...just not for this capability
    assert "%s:%s" % (VERB, RESOURCE) in d.reason               # names what the proof does authorize


def test_unknown_grant_is_rejected():
    tool = _BaseToolLike()
    guarded = pca_tool(REQUIRE, audience=AUD, resolve_grant=lambda ref: None, now=NOW)(tool)
    with pca_context(PCACTN):
        with pytest.raises(PcaToolDenied) as ei:
            guarded.run("widget")
    assert tool.calls == []
    assert "grant" in ei.value.decision.reason


def test_undecodable_inline_proof_fails_closed():
    tool = _BaseToolLike()
    guarded = _guard(tool)
    with pytest.raises(PcaToolDenied):
        guarded.run(pca_action="!!!not-base64url-or-json!!!")
    assert tool.calls == []


# ---- plumbing ------------------------------------------------------------------------

def test_inline_proof_overrides_context():
    tool = _BaseToolLike()
    guarded = _guard(tool)
    # context holds a tampered proof, but the valid inline proof wins
    with pca_context(tampered_pcactn()):
        out = guarded.run(pca_action=PCACTN)
    assert out["ok"] is True


def test_set_reset_pca_action():
    tool = _BaseToolLike()
    guarded = _guard(tool)
    token = set_pca_action(PCACTN)
    try:
        assert guarded.run("x")["ok"] is True
    finally:
        reset_pca_action(token)
    with pytest.raises(PcaToolDenied):
        guarded.run("x")  # proof no longer bound


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

    tool = _BaseToolLike()
    guarded = pca_tool(REQUIRE, audience=AUD, verifier=AlwaysDeny())(tool)
    with pytest.raises(PcaToolDenied):
        guarded.run("x", pca_action=PCACTN)
    assert seen["called"] == (VERB, RESOURCE, AUD)
    assert tool.calls == []


def test_core_verifier_decision_shape():
    v = CoreVerifier(resolver, now=NOW)
    ok = v.verify(PCACTN, verb=VERB, resource=RESOURCE, audience=AUD)
    assert ok.ok is True and ok["ok"] is True  # dict-style access too
    assert ok.required == REQUIRE
    assert json.dumps(ok.pcactn["action"])  # pcactn is carried through
