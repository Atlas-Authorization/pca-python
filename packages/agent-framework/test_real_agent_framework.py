"""End-to-end tests against the REAL Microsoft Agent Framework (skipped when it is not installed).

A scripted offline chat client (with the framework's real function-invocation layer) drives a real
``Agent``: the model asks for the tool, the framework executes it (or PCA denies it), and the result goes
back to the model. Run with ``make test-real`` (or ``sdks/scripts/test-adapters-real.sh``). Proofs are the
shared conformance vectors (see ``_vec``).
"""
import asyncio
from typing import Any, List, Mapping, Sequence

import pytest

pytest.importorskip("agent_framework")

from agent_framework import (  # noqa: E402
    Agent,
    BaseChatClient,
    ChatResponse,
    Content,
    FunctionInvocationLayer,
    FunctionTool,
    Message,
    tool,
)

from atlas_pca_agent_framework import pca_context, pca_function_middleware, pca_tool  # noqa: E402

from _vec import AUD, NOW, PCACTN, REQUIRE, resolver, tampered_pcactn  # noqa: E402

RAN: List[str] = []
RESULTS: List[str] = []


@pytest.fixture(autouse=True)
def _clear() -> None:
    RAN.clear()
    RESULTS.clear()


class _ScriptedClient(FunctionInvocationLayer, BaseChatClient):
    """Turn 1: call place_order. Turn 2: record the tool result text and answer."""

    def _inner_get_response(self, *, messages: Sequence[Message], stream: bool, options: Mapping[str, Any],
                            **kwargs: Any) -> Any:
        async def go() -> ChatResponse:
            results = [c for m in messages for c in m.contents if c.type == "function_result"]
            if results:
                RESULTS.append(str(results[-1].result))
                return ChatResponse(messages=[Message(role="assistant", contents=["done"])])
            call = Content.from_function_call(call_id="c1", name="place_order", arguments={"sku": "A1"})
            return ChatResponse(messages=[Message(role="assistant", contents=[call])])

        return go()


def _raw() -> FunctionTool:
    @tool
    async def place_order(sku: str) -> str:
        """Place an order for a sku."""
        RAN.append(sku)
        return "ordered %s" % sku

    return place_order


def _opts(**kw: Any) -> Any:
    o = {"audience": AUD, "resolve_grant": resolver, "now": NOW}
    o.update(kw)
    return o


def _run(agent: Agent) -> None:
    asyncio.run(agent.run("order A1"))


def test_guarded_tool_is_a_real_function_tool_and_keeps_its_fields() -> None:
    raw = tool(_raw().func, name="place_order", description="Place an order", approval_mode="never_require",
               additional_properties={"k": "v"})
    g = pca_tool(REQUIRE, **_opts())(raw)
    assert isinstance(g, FunctionTool)
    assert g.name == "place_order"
    assert g.description == "Place an order"
    assert g.additional_properties.get("k") == "v"


def test_pca_tool_allows_with_proof_in_real_agent() -> None:
    agent = Agent(client=_ScriptedClient(), tools=[pca_tool(REQUIRE, **_opts())(_raw())])
    with pca_context(PCACTN):
        _run(agent)
    assert RAN == ["A1"]
    assert RESULTS == ["ordered A1"]


@pytest.mark.parametrize("proof", [None, "tampered"])
def test_pca_tool_denies_in_real_agent(proof: Any) -> None:
    agent = Agent(client=_ScriptedClient(), tools=[pca_tool(REQUIRE, **_opts())(_raw())])
    with pca_context(tampered_pcactn() if proof else None):
        _run(agent)
    assert RAN == []
    assert len(RESULTS) == 1 and RESULTS[0]  # the model was handed an error result, the tool never ran


def test_function_middleware_allows_and_denies_in_real_agent() -> None:
    mw = pca_function_middleware(**_opts(), require={"place_order": REQUIRE})
    agent = Agent(client=_ScriptedClient(), tools=[_raw()], middleware=[mw])
    with pca_context(PCACTN):
        _run(agent)
    assert RAN == ["A1"]
    assert RESULTS == ["ordered A1"]

    RAN.clear()
    RESULTS.clear()
    with pca_context(tampered_pcactn()):
        _run(agent)
    assert RAN == []
    assert "allowed" in RESULTS[0] and "False" in RESULTS[0] or "error" in RESULTS[0]


def test_function_middleware_wrong_audience_and_capability_denied() -> None:
    for kw in ({"audience": "rs-other"}, {"require": {"place_order": "write:other/thing"}}):
        opts = _opts()
        opts.pop("audience") if "audience" in kw else None
        mw = pca_function_middleware(**{"require": {"place_order": REQUIRE}, **opts, **kw})
        agent = Agent(client=_ScriptedClient(), tools=[_raw()], middleware=[mw])
        RAN.clear()
        with pca_context(PCACTN):
            _run(agent)
        assert RAN == []
