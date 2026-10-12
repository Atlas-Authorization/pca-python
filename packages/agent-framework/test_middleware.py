"""Tests for ``pca_function_middleware`` — the agent-wide, per-tool gate.

A single function-invocation middleware gates every tool a Microsoft Agent Framework agent can invoke:
a valid proof lets the tool run, and a missing / invalid / wrong-audience / insufficient-capability
proof is denied fail-closed (the tool never runs) with a deny result routed back to the model. A tiny
fake agent reproduces the Agent Framework's function-middleware dispatch (the middleware receives a
``FunctionInvocationContext`` with ``.function`` / ``.arguments`` and a ``next`` that runs the tool;
not calling ``next`` short-circuits the call and ``context.result`` supplies the outcome), so no
agent_framework install is needed.
"""
import asyncio

import pytest

from atlas_pca_agent_framework import (
    PcaFunctionMiddleware,
    PcaToolDenied,
    pca_context,
    pca_function_middleware,
)

from _vec import AUD, NOW, PCACTN, REQUIRE, RESOURCE, VERB, resolver, tampered_pcactn


class _FunctionContext:
    """Stand-in for an Agent Framework ``FunctionInvocationContext``."""

    def __init__(self, function, arguments):
        self.function = function
        self.arguments = arguments
        self.result = None


class _AIFunctionLike:
    """Stand-in for an ``AIFunction``: a ``name`` and a recording async ``invoke``."""

    def __init__(self, name, result=None):
        self.name = name
        self.ran = 0
        self.saw = None
        self._result = result if result is not None else ("%s-ok" % name)

    async def invoke(self, **kwargs):
        self.ran += 1
        self.saw = kwargs
        return self._result


class _Agent:
    """Reproduces the Agent Framework's function-middleware dispatch for a tool-calling agent.

    The framework wraps each tool invocation with the middleware pipeline: it builds a context, then
    calls ``middleware.process(context, next)`` where ``next`` invokes the tool and records its result
    on ``context.result``. A middleware that denies sets ``context.result`` itself and never calls
    ``next``, so the tool never runs.
    """

    def __init__(self, tools, middleware):
        self.tools = {t.name: t for t in tools}
        self.middleware = middleware

    async def invoke_tool(self, name, arguments):
        tool = self.tools[name]
        ctx = _FunctionContext(tool, dict(arguments))

        async def run_tool(c):
            c.result = await tool.invoke(**c.arguments)

        await self.middleware.process(ctx, run_tool)
        return ctx.result


def _mw(require=REQUIRE, *, audience=AUD, **kw):
    return pca_function_middleware(audience=audience, require=require, resolve_grant=resolver,
                                   now=NOW, **kw)


def _run(coro):
    return asyncio.run(coro)


# ---- a whole agent, gated ------------------------------------------------------------

def test_agent_runs_tool_with_valid_proof():
    tool = _AIFunctionLike("place_order")
    agent = _Agent([tool], _mw())
    with pca_context(PCACTN):
        out = _run(agent.invoke_tool("place_order", {"sku": "widget"}))
    assert out == "place_order-ok"
    assert tool.ran == 1


def test_agent_denies_missing_proof_and_tool_not_run():
    tool = _AIFunctionLike("place_order")
    agent = _Agent([tool], _mw())
    out = _run(agent.invoke_tool("place_order", {"sku": "widget"}))  # no proof anywhere
    assert tool.ran == 0                      # the tool never ran
    assert out["pca"]["allowed"] is False     # deny result routed back to the model
    assert "no proof" in out["error"]


def test_agent_denies_invalid_proof():
    tool = _AIFunctionLike("place_order")
    agent = _Agent([tool], _mw())
    with pca_context(tampered_pcactn()):
        out = _run(agent.invoke_tool("place_order", {"sku": "widget"}))
    assert tool.ran == 0
    assert out["pca"]["allowed"] is False


def test_agent_denies_wrong_audience():
    tool = _AIFunctionLike("place_order")
    agent = _Agent([tool], _mw(audience="rs-wrong"))
    with pca_context(PCACTN):
        out = _run(agent.invoke_tool("place_order", {"sku": "widget"}))
    assert tool.ran == 0
    assert out["pca"]["allowed"] is False


def test_agent_denies_insufficient_capability_via_mapping():
    place = _AIFunctionLike("place_order")
    cancel = _AIFunctionLike("cancel_order")
    # place_order's required capability is what the proof authorizes; cancel_order's is not.
    require = {"place_order": REQUIRE, "cancel_order": "delete:%s" % RESOURCE}
    agent = _Agent([place, cancel], _mw(require))
    with pca_context(PCACTN):
        ok = _run(agent.invoke_tool("place_order", {"sku": "a"}))
        denied = _run(agent.invoke_tool("cancel_order", {"id": "b"}))
    assert ok == "place_order-ok" and place.ran == 1
    assert cancel.ran == 0
    assert "insufficient capability" in denied["error"]
    assert denied["pca"]["required"] == "delete:%s" % RESOURCE


def test_mapping_tool_without_entry_needs_only_a_valid_proof():
    tool = _AIFunctionLike("search")
    # `search` is absent from the map -> no capability gate, but a valid proof is still required.
    agent = _Agent([tool], _mw({"place_order": REQUIRE}))
    denied = _run(agent.invoke_tool("search", {"q": "x"}))           # no proof -> denied
    assert tool.ran == 0 and denied["pca"]["allowed"] is False
    assert denied["pca"]["required"] is None                        # no specific capability required
    with pca_context(PCACTN):
        assert _run(agent.invoke_tool("search", {"q": "x"})) == "search-ok"   # valid proof -> runs
    assert tool.ran == 1


def test_callable_require_receives_function_and_none_means_valid_proof_only():
    tool = _AIFunctionLike("ping")
    seen = {}

    def spec(function):
        seen["name"] = getattr(function, "name", None)
        return None  # every tool: valid proof, no capability

    agent = _Agent([tool], _mw(spec))
    with pca_context(PCACTN):
        assert _run(agent.invoke_tool("ping", {})) == "ping-ok"
    assert tool.ran == 1
    assert seen["name"] == "ping"  # the callable received the AIFunction being invoked


# ---- proof channels ------------------------------------------------------------------

def test_inline_proof_in_arguments_is_stripped_before_the_tool_runs():
    tool = _AIFunctionLike("place_order")
    agent = _Agent([tool], _mw())
    out = _run(agent.invoke_tool("place_order", {"sku": "widget", "pca_action": PCACTN}))
    assert out == "place_order-ok"
    assert tool.ran == 1
    assert tool.saw == {"sku": "widget"}  # the reserved pca_action key was removed


def test_raise_on_deny_raises_instead_of_setting_result():
    tool = _AIFunctionLike("place_order")
    agent = _Agent([tool], _mw(raise_on_deny=True))
    with pytest.raises(PcaToolDenied):
        _run(agent.invoke_tool("place_order", {"sku": "widget"}))  # no proof
    assert tool.ran == 0


def test_middleware_is_callable_as_function_style_hook():
    tool = _AIFunctionLike("place_order")
    mw = _mw()
    ctx = _FunctionContext(tool, {"sku": "z"})

    async def run_tool(c):
        c.result = await tool.invoke(**c.arguments)

    with pca_context(PCACTN):
        _run(mw(ctx, run_tool))          # __call__ delegates to process
    assert ctx.result == "place_order-ok"
    assert tool.ran == 1


# ---- pure decision + construction guards ---------------------------------------------

def test_decide_is_pure_and_fail_closed():
    tool = _AIFunctionLike("place_order")
    mw = _mw()
    # no proof -> deny
    assert mw.decide(function=tool, name="place_order", arguments={"sku": "x"}).ok is False
    # a valid proof carried inline -> allow (and the inline key is stripped from arguments in place)
    args = {"sku": "x", "pca_action": PCACTN}
    decision = mw.decide(function=tool, name="place_order", arguments=args)
    assert decision.ok is True
    assert "pca_action" not in args


def test_returns_pca_function_middleware_instance():
    assert isinstance(_mw(), PcaFunctionMiddleware)


def test_requires_audience():
    with pytest.raises(ValueError):
        pca_function_middleware(audience="", require=REQUIRE, resolve_grant=resolver)


def test_requires_verifier_or_resolver():
    with pytest.raises(ValueError):
        pca_function_middleware(audience=AUD, require=REQUIRE)


def test_rejects_both_verifier_and_resolver():
    class V:
        def verify(self, pcactn, *, verb, resource, audience):
            raise AssertionError("not called")

    with pytest.raises(ValueError):
        pca_function_middleware(audience=AUD, require=REQUIRE, verifier=V(), resolve_grant=resolver)


def test_malformed_require_entry_raises_at_call_time():
    tool = _AIFunctionLike("place_order")
    agent = _Agent([tool], _mw("not-a-pair"))
    with pca_context(PCACTN):
        with pytest.raises(ValueError):
            _run(agent.invoke_tool("place_order", {"sku": "x"}))
