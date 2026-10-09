"""End-to-end tests against the REAL langgraph / langchain-core (skipped when they are not installed).

Run with the framework installed: ``make test-real`` (or ``sdks/scripts/test-adapters-real.sh``).
The proofs are the shared conformance vectors (see ``_vec``); nothing is minted here.
"""
from typing import Any, Dict, List

import pytest

pytest.importorskip("langgraph")
pytest.importorskip("langchain_core")

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage  # noqa: E402
from langchain_core.tools import StructuredTool, tool  # noqa: E402
from langgraph.checkpoint.memory import MemorySaver  # noqa: E402
from langgraph.graph import END, START, StateGraph, MessagesState  # noqa: E402
from langgraph.prebuilt import ToolNode  # noqa: E402
from langgraph.types import Command  # noqa: E402

from atlas_pca_langgraph import (  # noqa: E402
    PcaToolDenied,
    guard_tool_node,
    pca_guard_node,
    pca_route,
    pca_tool,
)

from _vec import AUD, NOW, PCACTN, REQUIRE, resolver, tampered_pcactn  # noqa: E402

CALLS: List[str] = []


def _make_tool(require: str = REQUIRE, audience: str = AUD) -> Any:
    @pca_tool(require, audience=audience, resolve_grant=resolver, now=NOW)
    @tool
    def place_order(sku: str, qty: int = 1) -> str:
        """Place an order."""
        CALLS.append(sku)
        return "ordered %s x%d" % (sku, qty)

    return place_order


@pytest.fixture(autouse=True)
def _clear() -> None:
    CALLS.clear()


def _tool_graph(tools: List[Any]) -> Any:
    g = StateGraph(MessagesState)
    g.add_node("tools", ToolNode(tools, handle_tool_errors=True))
    g.add_edge(START, "tools")
    g.add_edge("tools", END)
    return g.compile()


def _ai_call(args: Dict[str, Any]) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": "place_order", "args": args, "id": "c1"}])


def test_pca_tool_returns_real_structured_tool() -> None:
    t = _make_tool()
    assert isinstance(t, StructuredTool)
    assert t.name == "place_order"
    assert "sku" in t.args


def test_real_toolnode_allows_with_proof_in_config() -> None:
    graph = _tool_graph([_make_tool()])
    out = graph.invoke({"messages": [_ai_call({"sku": "A1", "qty": 2})]},
                       {"configurable": {"PCA-Action": PCACTN}})
    msg = out["messages"][-1]
    assert isinstance(msg, ToolMessage)
    assert msg.content == "ordered A1 x2"
    assert msg.status == "success"
    assert CALLS == ["A1"]


def test_real_toolnode_denies_without_proof() -> None:
    graph = _tool_graph([_make_tool()])
    out = graph.invoke({"messages": [_ai_call({"sku": "A1"})]})
    msg = out["messages"][-1]
    assert msg.status == "error"
    assert "no proof-carrying action presented" in msg.content
    assert CALLS == []


def test_real_toolnode_denies_tampered_signature() -> None:
    graph = _tool_graph([_make_tool()])
    out = graph.invoke({"messages": [_ai_call({"sku": "A1"})]},
                       {"configurable": {"PCA-Action": tampered_pcactn()}})
    msg = out["messages"][-1]
    assert msg.status == "error"
    assert CALLS == []


def test_real_toolnode_denies_wrong_audience_and_capability() -> None:
    out = _tool_graph([_make_tool(audience="rs-other")]).invoke(
        {"messages": [_ai_call({"sku": "A1"})]}, {"configurable": {"PCA-Action": PCACTN}})
    assert out["messages"][-1].status == "error"
    out = _tool_graph([_make_tool(require="write:other/resource")]).invoke(
        {"messages": [_ai_call({"sku": "A1"})]}, {"configurable": {"PCA-Action": PCACTN}})
    assert out["messages"][-1].status == "error"
    assert CALLS == []


def test_direct_invoke_denied_raises_and_never_runs() -> None:
    t = _make_tool()
    with pytest.raises(PcaToolDenied) as ei:
        t.invoke({"sku": "A1"})
    assert ei.value.decision.reason == "no proof-carrying action presented"
    assert CALLS == []
    assert t.invoke({"sku": "A1"}, config={"configurable": {"PCA-Action": PCACTN}}) == "ordered A1 x1"


def test_pca_tool_node_in_real_graph_state_channel() -> None:
    @tool
    def place_order(sku: str, qty: int = 1) -> str:
        """Place an order."""
        CALLS.append(sku)
        return "ordered %s" % sku

    node = guard_tool_node(ToolNode([place_order]), audience=AUD, require={"place_order": REQUIRE},
                           resolve_grant=resolver, now=NOW)
    g = StateGraph(dict)  # type: ignore[type-var]
    g.add_node("tools", node)
    g.add_edge(START, "tools")
    g.add_edge("tools", END)
    compiled = g.compile()
    ok = compiled.invoke({"messages": [_ai_call({"sku": "B2"})], "PCA-Action": PCACTN})
    assert ok["messages"][-1].status == "success"
    assert CALLS == ["B2"]
    CALLS.clear()
    bad = compiled.invoke({"messages": [_ai_call({"sku": "B2"})], "PCA-Action": tampered_pcactn()})
    assert bad["messages"][-1].status == "error"
    assert CALLS == []


def _guard_graph() -> Any:
    @tool
    def place_order(sku: str, qty: int = 1) -> str:
        """Place an order."""
        CALLS.append(sku)
        return "ordered %s" % sku

    class State(MessagesState):
        pca: dict
        # the proof rides state under the literal key "PCA-Action" via a TypedDict functional alias

    State.__annotations__["PCA-Action"] = dict
    g = StateGraph(State)
    g.add_node("pca", pca_guard_node(audience=AUD, require=REQUIRE, resolve_grant=resolver, now=NOW))
    g.add_node("tools", ToolNode([place_order]))
    g.add_node("review", lambda s: {"messages": [HumanMessage(content="stepped up")]})
    g.add_edge(START, "pca")
    g.add_conditional_edges("pca", pca_route, {"approved": "tools", "stepup": "review"})
    g.add_edge("tools", END)
    g.add_edge("review", END)
    return g.compile(checkpointer=MemorySaver())


def test_guard_node_approves_valid_proof_then_runs_tool() -> None:
    graph = _guard_graph()
    out = graph.invoke({"messages": [_ai_call({"sku": "C3"})], "PCA-Action": PCACTN},
                       {"configurable": {"thread_id": "ok"}})
    assert out["messages"][-1].content == "ordered C3"
    assert CALLS == ["C3"]


def test_guard_node_interrupts_then_rejects_bad_resume_and_accepts_good() -> None:
    graph = _guard_graph()
    cfg = {"configurable": {"thread_id": "t1"}}
    paused = graph.invoke({"messages": [_ai_call({"sku": "C3"})]}, cfg)
    assert "__interrupt__" in paused
    payload = paused["__interrupt__"][0].value
    assert payload["type"] == "pca_step_up"
    assert payload["reason"] == "no proof-carrying action presented"
    assert CALLS == []

    # a tampered resume must NOT route to the tool node
    out = graph.invoke(Command(resume=tampered_pcactn()), cfg)
    assert CALLS == []
    assert out["messages"][-1].content == "stepped up"

    # a good stepped-up proof on a fresh thread approves and the tool runs
    cfg2 = {"configurable": {"thread_id": "t2"}}
    graph.invoke({"messages": [_ai_call({"sku": "D4"})]}, cfg2)
    out = graph.invoke(Command(resume=PCACTN), cfg2)
    assert out["messages"][-1].content == "ordered D4"
    assert CALLS == ["D4"]
