"""Tests for the Pydantic AI PCA tool guard.

The valid PCActn fixture is the known-good ``valid-in-plan-action`` vector from the shared conformance
set (the same source as ``sdks/python-pca/test_server.py`` and ``sdks/fastmcp-pca``), so the signed
bytes are real — no crypto is minted here, no network. The vector's action is ``verb="write"`` over
``resource="db/orders"``, i.e. it authorizes the capability ``write:db/orders``.

Everything but the final ``test_pydantic_ai_*`` case runs with ``pydantic_ai`` absent: the guard is
driven duck-typed through a tiny fake ``RunContext`` and plain functions.
"""
import asyncio
import json
import os
from dataclasses import dataclass
from typing import Optional

import pytest

from atlas_pca.pca import b64u, canonical_bytes_strict
from atlas_pca_pydantic_ai import (
    CoreVerifier,
    PCADecision,
    PCADeps,
    PCAGuard,
    PCARejected,
    capability_satisfies,
    extract_pcactn,
    parse_capability,
    pca_tool,
)

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "conformance")


def _valid_vector():
    with open(os.path.join(DIR, "vectors.json"), encoding="utf-8") as f:
        doc = json.load(f)
    return next(x for x in doc["vectors"] if x["name"] == "valid-in-plan-action")


VEC = _valid_vector()
PCACTN = VEC["pcactn"]
GRANT = VEC["grant"]
NOW = VEC["context"]["now"]
AUD = VEC["context"]["aud"]
# The capability this proof authorizes: action.verb:action.resource == "write:db/orders".
CAP = "%s:%s" % (PCACTN["action"]["verb"], PCACTN["action"]["resource"])


def _resolver(grant_ref):
    return GRANT if grant_ref == PCACTN["grant_ref"] else None


def _header_value(pcactn=PCACTN):
    return b64u(canonical_bytes_strict(pcactn))


def _verifier(now=NOW):
    # The spec signature carries no `now`; a fixed-clock CoreVerifier is how a test pins the window.
    return CoreVerifier(resolve_grant=_resolver, now=now)


def _guard(*, audience=AUD, verifier=None):
    return PCAGuard(audience=audience, verifier=verifier if verifier is not None else _verifier())


# ---- a minimal, framework-free stand-in for pydantic_ai.RunContext ------------------

@dataclass
class RunContext:
    """Duck-typed RunContext: the guard only reads ``.deps`` and detects the annotation name."""

    deps: object


# ---- capability matching (pure) ------------------------------------------------------

def test_capability_exact_and_wildcards():
    assert capability_satisfies(parse_capability("write:db/orders"), "write", "db/orders")
    assert capability_satisfies(parse_capability("write:db/*"), "write", "db/orders")
    assert capability_satisfies(parse_capability("write:db/*"), "write", "db/orders/line/1")
    assert capability_satisfies(parse_capability("*:db/orders"), "write", "db/orders")
    assert not capability_satisfies(parse_capability("write:db/*"), "write", "db")  # subtree, not the prefix itself
    assert not capability_satisfies(parse_capability("delete:db/orders"), "write", "db/orders")  # wrong verb
    assert not capability_satisfies(parse_capability("write:db/secrets"), "write", "db/orders")  # wrong resource


@pytest.mark.parametrize("bad", ["noseparator", ":resource", "verb:", ""])
def test_parse_capability_rejects_malformed(bad):
    with pytest.raises(ValueError):
        parse_capability(bad)


# ---- extract_pcactn: the PCA-Action convention --------------------------------------

def test_extract_from_deps_attribute_b64u():
    pcactn, err = extract_pcactn(PCADeps(pca_action=_header_value()), None)
    assert err is None and pcactn is not None and pcactn["aud"] == AUD


def test_extract_from_deps_attribute_inline_object():
    pcactn, err = extract_pcactn(PCADeps(pca_action=PCACTN), None)
    assert err is None and pcactn is not None and pcactn["grant_ref"] == PCACTN["grant_ref"]


def test_extract_from_deps_mapping():
    pcactn, err = extract_pcactn({"PCA-Action": _header_value()}, None)
    assert err is None and pcactn is not None


def test_extract_from_arguments_fallback():
    pcactn, err = extract_pcactn(None, {"PCA-Action": _header_value()})
    assert err is None and pcactn is not None


def test_extract_absent_and_undecodable():
    assert extract_pcactn(PCADeps(), None) == (None, "absent")
    assert extract_pcactn(None, {}) == (None, "absent")
    assert extract_pcactn(PCADeps(pca_action="!!!not-b64u!!!"), None) == (None, "undecodable")


# ---- PCAGuard.decide(): the pure decision -------------------------------------------

def _decide(guard, cap=CAP, **kw):
    return guard.decide(parse_capability(cap), **kw)


def test_valid_proof_allows_via_deps():
    d = _decide(_guard(), deps=PCADeps(pca_action=_header_value()))
    assert d.allow is True
    assert d.verdict is not None and d.verdict.allow is True
    assert str(d.required) == CAP
    assert d.pcactn is not None and d.pcactn["aud"] == AUD


def test_valid_proof_allows_via_arguments_string():
    d = _decide(_guard(), arguments={"PCA-Action": _header_value()})
    assert d.allow is True


def test_valid_proof_allows_via_arguments_inline_object():
    d = _decide(_guard(), arguments={"PCA-Action": PCACTN})
    assert d.allow is True


def test_missing_proof_is_rejected_fail_closed():
    d = _decide(_guard(), deps=PCADeps(), arguments={})
    assert d.allow is False
    assert d.reason == "no PCActn presented"
    assert d.verdict is None  # never got as far as verifying


def test_undecodable_proof_is_rejected():
    d = _decide(_guard(), deps=PCADeps(pca_action="!!!not-base64url!!!"))
    assert d.allow is False
    assert d.reason == "PCActn could not be decoded"


def test_wrong_audience_is_rejected():
    d = _decide(_guard(audience="agent://some-other-server"), deps=PCADeps(pca_action=_header_value()))
    assert d.allow is False
    assert d.verdict is not None and d.verdict.checks["audience"] is False


def test_unknown_grant_is_rejected():
    guard = PCAGuard(audience=AUD, verifier=CoreVerifier(resolve_grant=lambda ref: None, now=NOW))
    d = _decide(guard, deps=PCADeps(pca_action=_header_value()))
    assert d.allow is False
    assert d.reason == "unknown_grant"


def test_tampered_proof_fails_signature():
    tampered = dict(PCACTN)
    tampered["counter"] = PCACTN["counter"] + 1  # changes the signed body -> leaf signature must fail
    d = _decide(_guard(), deps=PCADeps(pca_action=_header_value(tampered)))
    assert d.allow is False
    assert d.verdict is not None and d.verdict.checks["leaf_signature"] is False


def test_insufficient_capability_is_rejected():
    # proof authorizes write:db/orders; the tool demands a different capability
    d = _decide(_guard(), cap="delete:db/orders", deps=PCADeps(pca_action=_header_value()))
    assert d.allow is False
    assert d.reason is not None and d.reason.startswith("insufficient_capability")
    assert d.verdict is not None and d.verdict.allow is True  # the proof was valid; only the capability failed


def test_resolve_grant_path_builds_core_verifier():
    # Exercise the pca_tool/PCAGuard resolve_grant branch (no explicit verifier). Wall-clock would reject
    # the fixed-time vector on validity, so this only asserts the proof is *parsed and verified* (not a
    # fail-closed extraction error) — the validity check is what the fixed-clock tests cover.
    guard = PCAGuard(audience=AUD, resolve_grant=_resolver)
    d = _decide(guard, deps=PCADeps(pca_action=_header_value()))
    assert d.verdict is not None  # we got past extraction + grant resolution into the core verifier


# ---- the pca_tool / guard.tool wrapper (duck-typed, no pydantic_ai) -----------------

def test_wrapper_runs_sync_tool_on_valid_proof_and_returns():
    ran = []

    @_guard().tool(CAP)
    def transfer(ctx: RunContext, amount: int) -> str:
        ran.append(amount)
        return "transferred %d" % amount

    out = transfer(RunContext(deps=PCADeps(pca_action=_header_value())), 10)
    assert out == "transferred 10"
    assert ran == [10]


def test_wrapper_does_not_run_tool_on_rejection():
    for deps in (PCADeps(), PCADeps(pca_action="!!!bad!!!")):
        ran = []

        @_guard().tool(CAP)
        def transfer(ctx: RunContext, amount: int) -> str:
            ran.append(amount)
            return "nope"

        with pytest.raises(PCARejected) as exc:
            transfer(RunContext(deps=deps), 10)
        assert exc.value.decision.allow is False
        assert ran == []  # fail closed: the tool body never executed


def test_wrapper_rejects_wrong_audience_without_running():
    ran = []

    @_guard(audience="agent://other").tool(CAP)
    def transfer(ctx: RunContext, amount: int) -> str:
        ran.append(amount)
        return "nope"

    with pytest.raises(PCARejected):
        transfer(RunContext(deps=PCADeps(pca_action=_header_value())), 10)
    assert ran == []


def test_wrapper_rejects_insufficient_capability_without_running():
    ran = []

    @_guard().tool("delete:db/orders")
    def wipe(ctx: RunContext) -> str:
        ran.append(True)
        return "nope"

    with pytest.raises(PCARejected) as exc:
        wipe(RunContext(deps=PCADeps(pca_action=_header_value())))
    assert exc.value.decision.reason is not None
    assert exc.value.decision.reason.startswith("insufficient_capability")
    assert ran == []


def test_pca_tool_signature_matches_spec_and_wraps():
    # pca_tool(require, *, audience, verifier=None, resolve_grant=None) with an explicit verifier.
    ran = []

    @pca_tool(CAP, audience=AUD, verifier=_verifier())
    def transfer(ctx: RunContext, amount: int) -> str:
        ran.append(amount)
        return "ok %d" % amount

    assert transfer(RunContext(deps=PCADeps(pca_action=_header_value())), 7) == "ok 7"
    assert ran == [7]
    # ...and the resolve_grant form.

    @pca_tool(CAP, audience=AUD, resolve_grant=_resolver)
    def also(ctx: RunContext) -> str:
        return "ok"

    # resolve_grant builds a wall-clock verifier; the fixed-time vector is expired now, so it rejects —
    # which still proves the branch wired a working verifier (fail-closed, not a crash).
    with pytest.raises(PCARejected):
        also(RunContext(deps=PCADeps(pca_action=_header_value())))


def test_pca_tool_rejects_both_verifier_and_resolve_grant():
    with pytest.raises(ValueError):
        pca_tool(CAP, audience=AUD, verifier=_verifier(), resolve_grant=_resolver)


def test_pca_tool_requires_audience():
    with pytest.raises(ValueError):
        pca_tool(CAP, audience="", verifier=_verifier())


def test_tool_plain_no_ctx_uses_arguments_channel():
    # An @agent.tool_plain-style function (no RunContext); the proof rides the arguments and is stripped
    # before the real tool runs.
    ran = []

    @_guard().tool(CAP)
    def lookup(query: str) -> str:
        ran.append(query)
        return "result for %s" % query

    out = lookup(query="orders", **{"PCA-Action": _header_value()})
    assert out == "result for orders"
    assert ran == ["orders"]


def test_async_tool_runs_on_valid_proof():
    ran = []

    @_guard().tool(CAP)
    async def transfer(ctx: RunContext, amount: int) -> str:
        ran.append(amount)
        return "async %d" % amount

    out = asyncio.run(transfer(RunContext(deps=PCADeps(pca_action=_header_value())), 3))
    assert out == "async 3"
    assert ran == [3]


def test_async_tool_rejected_does_not_run():
    ran = []

    @_guard().tool(CAP)
    async def transfer(ctx: RunContext, amount: int) -> str:
        ran.append(amount)
        return "nope"

    with pytest.raises(PCARejected):
        asyncio.run(transfer(RunContext(deps=PCADeps()), 3))
    assert ran == []


def test_wrapper_preserves_name_and_signature():
    import inspect

    @_guard().tool(CAP)
    def transfer(ctx: RunContext, amount: int) -> str:
        return "ok"

    assert transfer.__name__ == "transfer"
    params = list(inspect.signature(transfer).parameters)
    assert params == ["ctx", "amount"]  # the "PCA-Action" key is NOT in the tool's model-facing schema


def test_decision_is_dataclass_shape():
    d: PCADecision = _decide(_guard(), deps=PCADeps(pca_action=_header_value()))
    assert d.allow is True and d.tool is None  # decide() alone sets no tool name
    d2 = _decide(_guard(), deps=PCADeps())
    assert d2.allow is False


# ---- real Pydantic AI integration (skipped unless installed) ------------------------

def test_pydantic_ai_rejected_subclasses_model_retry():
    pytest.importorskip("pydantic_ai")
    from pydantic_ai import ModelRetry
    assert issubclass(PCARejected, ModelRetry)


def test_pydantic_ai_agent_tool_runs_with_valid_proof():
    pytest.importorskip("pydantic_ai")
    from pydantic_ai import Agent, RunContext as RealRunContext
    from pydantic_ai.models.test import TestModel

    agent: Agent[PCADeps, str] = Agent(TestModel(), deps_type=PCADeps)
    ran: list = []

    @agent.tool
    @pca_tool(CAP, audience=AUD, verifier=_verifier())
    def transfer(ctx: RealRunContext[PCADeps], amount: int) -> str:
        ran.append(amount)
        return "transferred %d" % amount

    # TestModel calls the tool without a real LLM; deps carry the proof out-of-band.
    result = agent.run_sync("go", deps=PCADeps(pca_action=_header_value()))
    assert ran, "the guarded tool should have run under a valid proof"
    assert "transferred" in str(result.output)


def test_pydantic_ai_agent_tool_rejected_without_proof():
    pytest.importorskip("pydantic_ai")
    from pydantic_ai import Agent, RunContext as RealRunContext
    from pydantic_ai.models.test import TestModel

    agent: Agent[PCADeps, str] = Agent(TestModel(), deps_type=PCADeps)
    ran: list = []

    @agent.tool
    @pca_tool(CAP, audience=AUD, verifier=_verifier())
    def transfer(ctx: RealRunContext[PCADeps], amount: int) -> str:
        ran.append(amount)
        return "transferred %d" % amount

    # No proof on deps: every call is refused (PCARejected -> ModelRetry). TestModel keeps retrying and
    # the run ultimately raises rather than succeeding; the one invariant is the tool body never ran.
    with pytest.raises(Exception):
        agent.run_sync("go", deps=PCADeps())
    assert ran == []
