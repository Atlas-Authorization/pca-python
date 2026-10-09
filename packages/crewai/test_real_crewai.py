"""End-to-end tests against the REAL crewai (skipped when it is not installed).

Run with ``make test-real`` (or ``sdks/scripts/test-adapters-real.sh``). Proofs are the shared
conformance vectors (see ``_vec``); nothing is minted here.
"""
from typing import Any, List

import pytest

pytest.importorskip("crewai")

from crewai import Agent, Crew, Task  # noqa: E402
from crewai.llms.base_llm import BaseLLM  # noqa: E402
from crewai.tools import BaseTool, tool  # noqa: E402

from atlas_pca_crewai import PcaToolDenied, guard_crew, guard_tools, pca_context, pca_tool  # noqa: E402

from _vec import AUD, NOW, PCACTN, REQUIRE, resolver, tampered_pcactn  # noqa: E402

RAN: List[str] = []


@pytest.fixture(autouse=True)
def _clear() -> None:
    RAN.clear()


def _raw_tool() -> Any:
    @tool("place_order")
    def place_order(sku: str) -> str:
        """Place an order for a sku."""
        RAN.append(sku)
        return "ordered %s" % sku

    return place_order


def _guard(raw: Any, **kw: Any) -> Any:
    opts = {"audience": AUD, "resolve_grant": resolver, "now": NOW}
    opts.update(kw)
    return pca_tool(REQUIRE, **opts)(raw)


def test_guarded_tool_is_a_real_basetool() -> None:
    t = _guard(_raw_tool())
    assert isinstance(t, BaseTool)
    assert t.name == "place_order"


def test_real_run_allows_with_proof_context() -> None:
    t = _guard(_raw_tool())
    with pca_context(PCACTN):
        assert t.run(sku="A1") == "ordered A1"
    assert RAN == ["A1"]


def test_real_run_allows_with_inline_proof() -> None:
    t = _guard(_raw_tool())
    assert t.run(sku="A1", pca_action=PCACTN) == "ordered A1"
    assert RAN == ["A1"]


@pytest.mark.parametrize("make_ctx,reason", [
    (lambda: None, "no proof-carrying action presented"),
    (lambda: tampered_pcactn(), None),
])
def test_real_run_denies(make_ctx: Any, reason: Any) -> None:
    t = _guard(_raw_tool())
    proof = make_ctx()
    with pytest.raises(PcaToolDenied) as ei:
        if proof is None:
            t.run(sku="A1")
        else:
            with pca_context(proof):
                t.run(sku="A1")
    if reason:
        assert ei.value.decision.reason == reason
    assert RAN == []


def test_real_run_denies_wrong_audience() -> None:
    t = _guard(_raw_tool(), audience="rs-other")
    with pytest.raises(PcaToolDenied):
        t.run(sku="A1", pca_action=PCACTN)
    assert RAN == []


class _ScriptedLLM(BaseLLM):
    """A deterministic offline LLM: first turn calls the tool (ReAct text), second gives the answer."""

    model: str = "scripted"
    turns: int = 0

    def call(self, messages: Any, tools: Any = None, callbacks: Any = None, available_functions: Any = None,
             from_task: Any = None, from_agent: Any = None, response_model: Any = None) -> str:
        self.turns += 1
        if self.turns == 1:
            return 'Thought: I must order.\nAction: place_order\nAction Input: {"sku": "Z9"}'
        return "Thought: I now know the final answer\nFinal Answer: done"

    def supports_function_calling(self) -> bool:
        return False

    def supports_stop_words(self) -> bool:
        return False

    def get_context_window_size(self) -> int:
        return 8192


def _crew(tools: List[Any]) -> Crew:
    agent = Agent(role="buyer", goal="order", backstory="orders things", tools=tools,
                  llm=_ScriptedLLM(model="scripted"), allow_delegation=False, max_iter=3)
    task = Task(description="order Z9", expected_output="done", agent=agent)
    return Crew(agents=[agent], tasks=[task], verbose=False)


def _kickoff(crew: Crew) -> str:
    return str(crew.kickoff())


def test_guard_crew_runs_tool_in_real_kickoff_with_proof() -> None:
    crew = guard_crew(_crew([_raw_tool()]), audience=AUD, require={"place_order": REQUIRE},
                      resolve_grant=resolver, now=NOW)
    with pca_context(PCACTN):
        assert _kickoff(crew) == "done"
    assert RAN == ["Z9"]


def test_guard_crew_blocks_tool_in_real_kickoff_without_proof() -> None:
    crew = guard_crew(_crew([_raw_tool()]), audience=AUD, require={"place_order": REQUIRE},
                      resolve_grant=resolver, now=NOW)
    _kickoff(crew)
    assert RAN == []


def test_guard_tools_list() -> None:
    (g,) = guard_tools([_raw_tool()], audience=AUD, require=REQUIRE, resolve_grant=resolver, now=NOW)
    assert isinstance(g, BaseTool)
    with pytest.raises(PcaToolDenied):
        g.run(sku="x")
