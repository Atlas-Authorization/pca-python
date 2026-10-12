"""Tests for ``PcaToolNode`` / ``guard_tool_node`` — the node-level gate over a LangGraph ToolNode.

A single node reads the pending tool calls off the last message and gates every tool: a valid proof
lets the tool run (result comes back as a ToolMessage), and a missing / invalid / wrong-audience /
insufficient-capability proof is denied fail-closed (the tool never runs; an error ToolMessage with
``status="error"`` is returned). A duck-typed AIMessage/ToolNode reproduce LangGraph's contract, so no
langgraph install is needed.
"""
import pytest

from atlas_pca_langgraph import (
    PcaToolNode,
    ToolMessageLike,
    guard_tool_node,
    pca_context,
)

from _vec import AUD, NOW, PCACTN, REQUIRE, RESOURCE, VERB, resolver, tampered_pcactn


class _Tool:
    """A stand-in for a LangChain tool: a ``name`` and a recording ``func``."""

    def __init__(self, name, result=None):
        self.name = name
        self.description = name
        self.ran = 0
        self._result = result if result is not None else ("%s-ok" % name)

        def func(**kwargs):
            self.ran += 1
            self.saw = kwargs
            return self._result

        self.func = func


class _AIMessage:
    """A stand-in for a LangChain AIMessage carrying ``tool_calls``."""

    def __init__(self, tool_calls):
        self.tool_calls = tool_calls


class _ToolNodeLike:
    """A stand-in for ``langgraph.prebuilt.ToolNode``: a ``tools_by_name`` mapping."""

    def __init__(self, tools):
        self.tools_by_name = {t.name: t for t in tools}


def _tc(name, args=None, id="call-1"):
    return {"name": name, "args": args or {}, "id": id}


def _state(tool_calls, **extra):
    state = {"messages": [_AIMessage(tool_calls)]}
    state.update(extra)
    return state


def _node(tools, *, require=REQUIRE, audience=AUD):
    return PcaToolNode(tools, audience=audience, require=require, resolve_grant=resolver, now=NOW)


# ---- the happy path ------------------------------------------------------------------

def test_valid_proof_runs_tool_and_returns_tool_message():
    tool = _Tool("place_order")
    node = _node([tool])
    with pca_context(PCACTN):
        out = node(_state([_tc("place_order", {"sku": "widget"})]))
    msgs = out["messages"]
    assert len(msgs) == 1
    assert isinstance(msgs[0], ToolMessageLike)
    assert msgs[0].content == "place_order-ok"
    assert msgs[0].status == "success"
    assert msgs[0].tool_call_id == "call-1"
    assert tool.ran == 1
    assert tool.saw == {"sku": "widget"}  # inner tool never saw pca_action


def test_proof_via_state_key():
    tool = _Tool("place_order")
    node = _node([tool])
    out = node(_state([_tc("place_order", {"sku": "a"})], **{"PCA-Action": PCACTN}))
    assert out["messages"][0].status == "success"
    assert tool.ran == 1


def test_proof_via_config_configurable():
    tool = _Tool("place_order")
    node = _node([tool])
    out = node(_state([_tc("place_order", {"sku": "a"})]),
               {"configurable": {"PCA-Action": PCACTN}})
    assert out["messages"][0].status == "success"
    assert tool.ran == 1


def test_invoke_entrypoint():
    tool = _Tool("place_order")
    node = _node([tool])
    with pca_context(PCACTN):
        out = node.invoke(_state([_tc("place_order", {"sku": "a"})]))
    assert out["messages"][0].status == "success"


def test_gates_every_pending_call_in_one_super_step():
    place = _Tool("place_order")
    read = _Tool("read_order")
    node = PcaToolNode([place, read], audience=AUD, require=None, resolve_grant=resolver, now=NOW)
    with pca_context(PCACTN):
        out = node(_state([_tc("place_order", {"sku": "a"}, id="c1"),
                           _tc("read_order", {"id": "b"}, id="c2")]))
    assert [m.status for m in out["messages"]] == ["success", "success"]
    assert place.ran == 1 and read.ran == 1


# ---- fail closed ---------------------------------------------------------------------

def test_missing_proof_denies_and_tool_not_run():
    tool = _Tool("place_order")
    node = _node([tool])
    out = node(_state([_tc("place_order", {"sku": "widget"})]))  # no proof anywhere
    assert tool.ran == 0
    msg = out["messages"][0]
    assert msg.status == "error"
    assert "no proof" in msg.content


def test_invalid_proof_denies_and_tool_not_run():
    tool = _Tool("place_order")
    node = _node([tool])
    with pca_context(tampered_pcactn()):
        out = node(_state([_tc("place_order", {"sku": "widget"})]))
    assert tool.ran == 0
    assert out["messages"][0].status == "error"


def test_wrong_audience_denies_and_tool_not_run():
    tool = _Tool("place_order")
    node = _node([tool], audience="rs-wrong")
    with pca_context(PCACTN):
        out = node(_state([_tc("place_order", {"sku": "widget"})]))
    assert tool.ran == 0
    assert out["messages"][0].status == "error"


def test_insufficient_capability_denies_via_mapping():
    place = _Tool("place_order")
    cancel = _Tool("cancel_order")
    require = {"place_order": REQUIRE, "cancel_order": "delete:%s" % RESOURCE}
    node = _node([place, cancel], require=require)
    with pca_context(PCACTN):
        out = node(_state([_tc("place_order", {"sku": "a"}, id="c1"),
                           _tc("cancel_order", {"id": "b"}, id="c2")]))
    statuses = {m.tool_call_id: m.status for m in out["messages"]}
    assert statuses == {"c1": "success", "c2": "error"}
    assert place.ran == 1 and cancel.ran == 0


def test_mapping_tool_without_entry_needs_only_a_valid_proof():
    tool = _Tool("search")  # absent from the map -> no capability gate, but a valid proof is required
    node = _node([tool], require={"place_order": REQUIRE})
    out = node(_state([_tc("search", {"q": "x"})]))  # no proof -> denied
    assert tool.ran == 0 and out["messages"][0].status == "error"
    with pca_context(PCACTN):
        ok = node(_state([_tc("search", {"q": "x"})]))  # valid proof -> runs
    assert ok["messages"][0].status == "success" and tool.ran == 1


def test_unknown_tool_name_is_an_error_message():
    tool = _Tool("place_order")
    node = _node([tool])
    with pca_context(PCACTN):
        out = node(_state([_tc("ghost_tool", {})]))
    assert tool.ran == 0
    assert out["messages"][0].status == "error"
    assert "no such guarded tool" in out["messages"][0].content


def test_no_pending_calls_returns_empty():
    tool = _Tool("place_order")
    node = _node([tool])
    assert node(_state([])) == {"messages": []}
    assert node({"messages": []}) == {"messages": []}


# ---- guard_tool_node wrapping an existing ToolNode -----------------------------------

def test_guard_tool_node_wraps_a_tool_node():
    place = _Tool("place_order")
    base = _ToolNodeLike([place])
    guarded = guard_tool_node(base, audience=AUD, require=REQUIRE, resolve_grant=resolver, now=NOW)
    assert isinstance(guarded, PcaToolNode)
    # fails closed without a proof...
    out = guarded(_state([_tc("place_order", {"sku": "a"})]))
    assert place.ran == 0 and out["messages"][0].status == "error"
    # ...runs with a valid one
    with pca_context(PCACTN):
        ok = guarded(_state([_tc("place_order", {"sku": "a"})]))
    assert ok["messages"][0].status == "success" and place.ran == 1


def test_guard_tool_node_accepts_a_plain_tool_list():
    tool = _Tool("place_order")
    guarded = guard_tool_node([tool], audience=AUD, require=REQUIRE, resolve_grant=resolver, now=NOW)
    with pca_context(PCACTN):
        out = guarded(_state([_tc("place_order", {"sku": "a"})]))
    assert out["messages"][0].status == "success"


# ---- construction guards -------------------------------------------------------------

def test_requires_audience():
    with pytest.raises(ValueError):
        PcaToolNode([_Tool("t")], audience="", require=REQUIRE, resolve_grant=resolver)


def test_requires_verifier_or_resolver():
    with pytest.raises(ValueError):
        PcaToolNode([_Tool("t")], audience=AUD, require=REQUIRE)


def test_rejects_both_verifier_and_resolver():
    class V:
        def verify(self, pcactn, *, verb, resource, audience):
            raise AssertionError("not called")

    with pytest.raises(ValueError):
        PcaToolNode([_Tool("t")], audience=AUD, require=REQUIRE, verifier=V(), resolve_grant=resolver)


def test_malformed_require_entry_raises_at_construction():
    with pytest.raises(ValueError):
        PcaToolNode([_Tool("place_order")], audience=AUD, require="not-a-pair", resolve_grant=resolver)
