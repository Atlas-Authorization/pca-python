"""End-to-end tests against the REAL haystack-ai (skipped when it is not installed).

A real ``ToolInvoker`` executes real ``Tool`` objects for an assistant message carrying tool calls, and
a real ``Pipeline`` carries it. Run with ``make test-real`` (or ``sdks/scripts/test-adapters-real.sh``).
Proofs are the shared conformance vectors (see ``_vec``).
"""
from typing import Any, List

import pytest

pytest.importorskip("haystack")

from haystack import Pipeline, component  # noqa: E402
from haystack.components.agents import Agent  # noqa: E402
try:  # ToolInvoker exists in haystack-ai 2.x; haystack-ai 3.x runs tools inside the Agent instead
    from haystack.components.tools import ToolInvoker
except ImportError:  # pragma: no cover - depends on the installed major version
    ToolInvoker = None  # type: ignore[assignment,misc]
from haystack.dataclasses import ChatMessage, ToolCall  # noqa: E402
from haystack.tools import Tool  # noqa: E402

from atlas_pca_haystack import guard_tool_invoker, pca_context, pca_tool  # noqa: E402

from _vec import AUD, NOW, PCACTN, REQUIRE, resolver, tampered_pcactn  # noqa: E402

RAN: List[str] = []


@pytest.fixture(autouse=True)
def _clear() -> None:
    RAN.clear()


def _place_order(sku: str) -> str:
    RAN.append(sku)
    return "ordered %s" % sku


def _raw_tool() -> Tool:
    return Tool(name="place_order", description="Place an order",
                parameters={"type": "object", "properties": {"sku": {"type": "string"}},
                            "required": ["sku"]},
                function=_place_order)


def _guarded(**kw: Any) -> Tool:
    opts = {"audience": AUD, "resolve_grant": resolver, "now": NOW}
    opts.update(kw)
    return pca_tool(REQUIRE, **opts)(_raw_tool())


def _messages() -> List[ChatMessage]:
    return [ChatMessage.from_assistant(tool_calls=[ToolCall(tool_name="place_order",
                                                            arguments={"sku": "A1"}, id="c1")])]


def test_guarded_tool_is_a_real_tool_with_original_schema() -> None:
    t = _guarded()
    assert isinstance(t, Tool)
    assert t.name == "place_order"
    assert t.parameters["properties"] == {"sku": {"type": "string"}}


needs_invoker = pytest.mark.skipif(ToolInvoker is None, reason="haystack-ai >= 3 has no ToolInvoker")


@needs_invoker
def test_tool_invoker_runs_with_proof() -> None:
    inv = ToolInvoker(tools=[_guarded()])
    with pca_context(PCACTN):
        out = inv.run(messages=_messages())
    result = out["tool_messages"][0].tool_call_result
    assert result.error is False
    assert result.result == "ordered A1"
    assert RAN == ["A1"]


@needs_invoker
@pytest.mark.parametrize("proof", [None, "tampered"])
def test_tool_invoker_denies_without_running(proof: Any) -> None:
    inv = ToolInvoker(tools=[_guarded()], raise_on_failure=False)
    ctx = tampered_pcactn() if proof == "tampered" else None
    with pca_context(ctx):
        out = inv.run(messages=_messages())
    result = out["tool_messages"][0].tool_call_result
    assert result.error is True
    assert "proof" in result.result.lower() or "signature" in result.result.lower() or result.result
    assert RAN == []


@needs_invoker
def test_tool_invoker_raise_on_failure_surfaces_denial() -> None:
    inv = ToolInvoker(tools=[_guarded()], raise_on_failure=True)
    with pytest.raises(Exception) as ei:
        inv.run(messages=_messages())
    assert "no proof-carrying action presented" in str(ei.value)
    assert RAN == []


@needs_invoker
def test_wrong_audience_denied() -> None:
    inv = ToolInvoker(tools=[_guarded(audience="rs-other")], raise_on_failure=False)
    with pca_context(PCACTN):
        out = inv.run(messages=_messages())
    assert out["tool_messages"][0].tool_call_result.error is True
    assert RAN == []


@needs_invoker
def test_guard_tool_invoker_gates_existing_invoker_in_pipeline() -> None:
    inv = ToolInvoker(tools=[_raw_tool()], raise_on_failure=False)
    guard_tool_invoker(inv, audience=AUD, require={"place_order": REQUIRE}, resolve_grant=resolver, now=NOW)
    pipe = Pipeline()
    pipe.add_component("invoker", inv)
    with pca_context(PCACTN):
        ok = pipe.run({"invoker": {"messages": _messages()}})
    assert ok["invoker"]["tool_messages"][0].tool_call_result.result == "ordered A1"
    assert RAN == ["A1"]
    RAN.clear()
    denied = pipe.run({"invoker": {"messages": _messages()}})
    assert denied["invoker"]["tool_messages"][0].tool_call_result.error is True
    assert RAN == []


def test_direct_tool_invoke_denied() -> None:
    with pytest.raises(Exception) as ei:  # Tool.invoke wraps the denial in a ToolInvocationError
        _guarded().invoke(sku="A1")
    assert "no proof-carrying action presented" in str(ei.value)
    assert RAN == []
    assert _guarded().invoke(sku="A1", pca_action=PCACTN) == "ordered A1"


@component
class _ScriptedChat:
    """Offline chat generator: asks for the tool once, then answers."""

    @component.output_types(replies=List[ChatMessage])
    def run(self, messages: List[ChatMessage], tools: Any = None, **kwargs: Any) -> Any:
        if messages[-1].tool_call_results:
            return {"replies": [ChatMessage.from_assistant("done")]}
        return {"replies": [ChatMessage.from_assistant(tool_calls=[
            ToolCall(tool_name="place_order", arguments={"sku": "A1"}, id="c1")])]}


def _agent(tool: Tool) -> Agent:
    agent = Agent(chat_generator=_ScriptedChat(), tools=[tool], max_agent_steps=3, raise_on_tool_invocation_failure=False)
    agent.warm_up()
    return agent


def _tool_results(out: Any) -> List[Any]:
    return [r for m in out["messages"] for r in m.tool_call_results]


def test_agent_runs_guarded_tool_with_proof() -> None:
    with pca_context(PCACTN):
        out = _agent(_guarded()).run(messages=[ChatMessage.from_user("order A1")])
    (res,) = _tool_results(out)
    assert res.error is False and res.result == "ordered A1"
    assert RAN == ["A1"]


@pytest.mark.parametrize("ctx", [None, "tampered"])
def test_agent_denies_without_running(ctx: Any) -> None:
    proof = tampered_pcactn() if ctx == "tampered" else None
    with pca_context(proof):
        out = _agent(_guarded()).run(messages=[ChatMessage.from_user("order A1")])
    (res,) = _tool_results(out)
    assert res.error is True
    assert RAN == []


def test_guarded_tool_keeps_all_original_tool_fields() -> None:
    raw = _raw_tool()
    raw.outputs_to_string = {"source": "x"}  # a field a naive rebuild would silently drop
    guarded = pca_tool(REQUIRE, audience=AUD, resolve_grant=resolver, now=NOW)(raw)
    assert guarded.outputs_to_string == {"source": "x"}


def test_async_function_is_guarded_too() -> None:
    import asyncio

    async def place_async(sku: str) -> str:
        RAN.append("async-" + sku)
        return "ordered"

    raw = _raw_tool()
    if not hasattr(raw, "async_function"):
        pytest.skip("this haystack-ai has no async_function")
    raw.async_function = place_async
    guarded = pca_tool(REQUIRE, audience=AUD, resolve_grant=resolver, now=NOW)(raw)
    with pytest.raises(Exception) as ei:
        asyncio.run(guarded.invoke_async(sku="A1"))
    assert "no proof-carrying action presented" in str(ei.value)
    assert RAN == []
    with pca_context(PCACTN):
        assert asyncio.run(guarded.invoke_async(sku="A1")) == "ordered"
    assert RAN == ["async-A1"]
