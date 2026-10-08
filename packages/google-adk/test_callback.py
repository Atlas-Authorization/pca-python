"""Tests for ``pca_before_tool_callback`` — the agent-wide gate.

A single ``before_tool_callback`` gates every tool an ADK agent can call: a valid proof lets the tool
run, and a missing / invalid / wrong-audience / insufficient-capability proof is denied fail-closed
(the tool never runs) and the deny result is routed back to the model. A tiny fake agent reproduces
ADK's dispatch contract (``before_tool_callback`` returning a dict short-circuits the tool with that
dict as its result; returning ``None`` runs the tool), so no google-adk install is needed.
"""
import pytest

from atlas_pca_google_adk import (
    PcaToolDenied,
    pca_before_tool_callback,
    pca_context,
)

from _vec import AUD, NOW, PCACTN, REQUIRE, RESOURCE, VERB, resolver, tampered_pcactn


class _State:
    def __init__(self, data=None):
        self._d = dict(data or {})

    def get(self, key, default=None):
        return self._d.get(key, default)

    def __getitem__(self, key):
        return self._d[key]


class _ToolContext:
    def __init__(self, state=None):
        self.state = _State(state)


class _FunctionTool:
    """A stand-in for an ADK FunctionTool: a ``name`` and a recording ``func``."""

    def __init__(self, name, result=None):
        self.name = name
        self.ran = 0
        self._result = result if result is not None else ("%s-ok" % name)

        def func(**kwargs):
            self.ran += 1
            self.saw = kwargs
            return self._result

        self.func = func


class _Agent:
    """Reproduces ADK's before_tool_callback dispatch contract for a tools-calling agent."""

    def __init__(self, tools, before_tool_callback):
        self.tools = {t.name: t for t in tools}
        self.before_tool_callback = before_tool_callback

    def call_tool(self, name, args, tool_context=None):
        tool = self.tools[name]
        # ADK calls the callback first; a dict return short-circuits the tool with that dict.
        override = self.before_tool_callback(tool=tool, args=args, tool_context=tool_context)
        if override is not None:
            return override
        return tool.func(**args)


def _cb(require=REQUIRE, *, audience=AUD, **kw):
    return pca_before_tool_callback(audience=audience, require=require, resolve_grant=resolver,
                                    now=NOW, **kw)


# ---- a whole agent, gated ------------------------------------------------------------

def test_agent_runs_tool_with_valid_proof():
    tool = _FunctionTool("place_order")
    agent = _Agent([tool], _cb())
    with pca_context(PCACTN):
        out = agent.call_tool("place_order", {"sku": "widget"})
    assert out == "place_order-ok"
    assert tool.ran == 1


def test_agent_denies_missing_proof_and_tool_not_run():
    tool = _FunctionTool("place_order")
    agent = _Agent([tool], _cb())
    out = agent.call_tool("place_order", {"sku": "widget"})  # no proof anywhere
    assert tool.ran == 0                      # the tool never ran
    assert out["pca"]["allowed"] is False     # deny result routed back to the model
    assert "no proof" in out["error"]


def test_agent_denies_invalid_proof():
    tool = _FunctionTool("place_order")
    agent = _Agent([tool], _cb())
    with pca_context(tampered_pcactn()):
        out = agent.call_tool("place_order", {"sku": "widget"})
    assert tool.ran == 0
    assert out["pca"]["allowed"] is False


def test_agent_denies_wrong_audience():
    tool = _FunctionTool("place_order")
    agent = _Agent([tool], _cb(audience="rs-wrong"))
    with pca_context(PCACTN):
        out = agent.call_tool("place_order", {"sku": "widget"})
    assert tool.ran == 0
    assert out["pca"]["allowed"] is False


def test_agent_denies_insufficient_capability_via_mapping():
    place = _FunctionTool("place_order")
    cancel = _FunctionTool("cancel_order")
    # place_order's required capability is what the proof authorizes; cancel_order's is not.
    require = {"place_order": REQUIRE, "cancel_order": "delete:%s" % RESOURCE}
    agent = _Agent([place, cancel], _cb(require))
    with pca_context(PCACTN):
        ok = agent.call_tool("place_order", {"sku": "a"})
        denied = agent.call_tool("cancel_order", {"id": "b"})
    assert ok == "place_order-ok" and place.ran == 1
    assert cancel.ran == 0
    assert "insufficient capability" in denied["error"]
    assert denied["pca"]["required"] == "delete:%s" % RESOURCE


def test_mapping_tool_without_entry_needs_only_a_valid_proof():
    tool = _FunctionTool("search")
    # `search` is absent from the map -> no capability gate, but a valid proof is still required.
    agent = _Agent([tool], _cb({"place_order": REQUIRE}))
    denied = agent.call_tool("search", {"q": "x"})           # no proof -> denied
    assert tool.ran == 0 and denied["pca"]["allowed"] is False
    assert denied["pca"]["required"] is None                 # no specific capability was required
    with pca_context(PCACTN):
        assert agent.call_tool("search", {"q": "x"}) == "search-ok"   # valid proof -> runs
    assert tool.ran == 1


def test_callable_require_none_means_valid_proof_only():
    tool = _FunctionTool("ping")
    agent = _Agent([tool], _cb(lambda t: None))  # every tool: valid proof, no capability
    with pca_context(PCACTN):
        assert agent.call_tool("ping", {}) == "ping-ok"
    assert tool.ran == 1


# ---- proof channels ------------------------------------------------------------------

def test_inline_proof_in_args_is_stripped_before_the_tool_runs():
    tool = _FunctionTool("place_order")
    agent = _Agent([tool], _cb())
    out = agent.call_tool("place_order", {"sku": "widget", "pca_action": PCACTN})
    assert out == "place_order-ok"
    assert tool.ran == 1
    assert tool.saw == {"sku": "widget"}  # the reserved pca_action key was removed


def test_proof_via_tool_context_state():
    tool = _FunctionTool("place_order")
    agent = _Agent([tool], _cb())
    ctx = _ToolContext(state={"PCA-Action": PCACTN})
    out = agent.call_tool("place_order", {"sku": "widget"}, tool_context=ctx)
    assert out == "place_order-ok"
    assert tool.ran == 1


def test_raise_on_deny_raises_instead_of_returning():
    tool = _FunctionTool("place_order")
    agent = _Agent([tool], _cb(raise_on_deny=True))
    with pytest.raises(PcaToolDenied):
        agent.call_tool("place_order", {"sku": "widget"})  # no proof
    assert tool.ran == 0


# ---- construction guards -------------------------------------------------------------

def test_requires_audience():
    with pytest.raises(ValueError):
        pca_before_tool_callback(audience="", require=REQUIRE, resolve_grant=resolver)


def test_requires_verifier_or_resolver():
    with pytest.raises(ValueError):
        pca_before_tool_callback(audience=AUD, require=REQUIRE)


def test_rejects_both_verifier_and_resolver():
    class V:
        def verify(self, pcactn, *, verb, resource, audience):
            raise AssertionError("not called")

    with pytest.raises(ValueError):
        pca_before_tool_callback(audience=AUD, require=REQUIRE, verifier=V(), resolve_grant=resolver)


def test_malformed_require_entry_raises_at_call_time():
    tool = _FunctionTool("place_order")
    agent = _Agent([tool], _cb("not-a-pair"))
    with pca_context(PCACTN):
        with pytest.raises(ValueError):
            agent.call_tool("place_order", {"sku": "x"})
