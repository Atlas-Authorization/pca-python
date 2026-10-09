"""End-to-end tests against the REAL google-adk (skipped when it is not installed).

A scripted offline model drives a real ``LlmAgent`` through a real ``Runner``: the model asks for the
tool, ADK executes (or the PCA guard denies) it, and the model then sees the tool response. Run with
``make test-real`` (or ``sdks/scripts/test-adapters-real.sh``). Proofs are the shared conformance
vectors (see ``_vec``).
"""
import asyncio
from typing import Any, AsyncGenerator, Dict, List, Optional

import pytest

pytest.importorskip("google.adk")

from google.adk.agents import LlmAgent  # noqa: E402
from google.adk.models.base_llm import BaseLlm  # noqa: E402
from google.adk.models.llm_request import LlmRequest  # noqa: E402
from google.adk.models.llm_response import LlmResponse  # noqa: E402
from google.adk.runners import InMemoryRunner  # noqa: E402
from google.adk.tools import FunctionTool  # noqa: E402
from google.genai import types  # noqa: E402

from atlas_pca_google_adk import pca_before_tool_callback, pca_tool  # noqa: E402

from _vec import AUD, NOW, PCACTN, REQUIRE, resolver, tampered_pcactn  # noqa: E402

RAN: List[str] = []
SEEN: List[Dict[str, Any]] = []


@pytest.fixture(autouse=True)
def _clear() -> None:
    RAN.clear()
    SEEN.clear()


class ScriptedLlm(BaseLlm):
    """Turn 1: call the (only) tool. Turn 2: echo the tool response so the test can read it."""

    model: str = "scripted"

    async def generate_content_async(self, llm_request: LlmRequest, stream: bool = False
                                     ) -> AsyncGenerator[LlmResponse, None]:
        last = llm_request.contents[-1]
        responses = [p.function_response for p in (last.parts or []) if p.function_response]
        if responses:
            SEEN.append(dict(responses[0].response or {}))
            yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text="done")]))
            return
        yield LlmResponse(content=types.Content(role="model", parts=[types.Part(
            function_call=types.FunctionCall(name=next(iter(llm_request.tools_dict)), args={"sku": "A1"}))]))


def place_order(sku: str) -> str:
    """Place an order for a sku."""
    RAN.append(sku)
    return "ordered %s" % sku


def place_order_ctx(sku: str, tool_context: Any) -> str:
    """Place an order for a sku (declares tool_context)."""
    RAN.append(sku)
    return "ordered %s" % sku


def _guard(fn: Any, **kw: Any) -> Any:
    opts = {"audience": AUD, "resolve_grant": resolver, "now": NOW}
    opts.update(kw)
    return pca_tool(REQUIRE, **opts)(fn)


async def _run(agent: LlmAgent, state: Optional[Dict[str, Any]]) -> None:
    runner = InMemoryRunner(agent=agent, app_name="pca")
    session = await runner.session_service.create_session(app_name="pca", user_id="u", state=state or {})
    msg = types.Content(role="user", parts=[types.Part(text="order A1")])
    async for _ in runner.run_async(user_id="u", session_id=session.id, new_message=msg):
        pass


def _agent(**kw: Any) -> LlmAgent:
    return LlmAgent(name="buyer", model=ScriptedLlm(model="scripted"), instruction="order things", **kw)


def test_guarded_tool_is_a_real_function_tool() -> None:
    t = _guard(place_order)
    assert isinstance(t, FunctionTool)
    assert t.name == "place_order"


@pytest.mark.parametrize("fn", [place_order, place_order_ctx])
def test_runner_allows_with_proof_in_session_state(fn: Any) -> None:
    asyncio.run(_run(_agent(tools=[_guard(fn)]), {"PCA-Action": PCACTN}))
    assert RAN == ["A1"]
    assert SEEN == [{"result": "ordered A1"}]


@pytest.mark.parametrize("state,why", [
    (None, "no proof-carrying action presented"),
    ({"PCA-Action": tampered_pcactn()}, None),
])
def test_runner_denies_and_tool_never_runs(state: Any, why: Optional[str]) -> None:
    # a raising guard aborts the agent run (fail closed): the tool never runs and the model never sees a result
    with pytest.raises(Exception) as ei:
        asyncio.run(_run(_agent(tools=[_guard(place_order)]), state))
    assert RAN == []
    assert SEEN == []
    assert "PcaToolDenied" in repr(ei.value.__cause__ or ei.value) or "proof" in str(ei.value.__cause__)
    if why:
        assert why in str(ei.value.__cause__ or ei.value)


def test_function_tool_run_async_denies_directly() -> None:
    t = _guard(place_order_ctx)

    class Ctx:
        state: Dict[str, Any] = {}

    async def go() -> Any:
        return await t.run_async(args={"sku": "A1"}, tool_context=Ctx())  # type: ignore[arg-type]

    with pytest.raises(Exception) as ei:
        asyncio.run(go())
    assert "no proof-carrying action presented" in str(ei.value)
    assert RAN == []


def test_before_tool_callback_allows_and_denies_in_runner() -> None:
    cb = pca_before_tool_callback(audience=AUD, require={"place_order": REQUIRE},
                                  resolve_grant=resolver, now=NOW)
    asyncio.run(_run(_agent(tools=[FunctionTool(place_order)], before_tool_callback=cb),
                     {"PCA-Action": PCACTN}))
    assert RAN == ["A1"]
    assert SEEN == [{"result": "ordered A1"}]

    RAN.clear()
    SEEN.clear()
    asyncio.run(_run(_agent(tools=[FunctionTool(place_order)], before_tool_callback=cb),
                     {"PCA-Action": tampered_pcactn()}))
    assert RAN == []
    assert SEEN[0]["pca"] == {"allowed": False, "required": REQUIRE}
    assert "error" in SEEN[0]


def test_before_tool_callback_wrong_audience_denied() -> None:
    cb = pca_before_tool_callback(audience="rs-other", require=REQUIRE, resolve_grant=resolver, now=NOW)
    asyncio.run(_run(_agent(tools=[FunctionTool(place_order)], before_tool_callback=cb),
                     {"PCA-Action": PCACTN}))
    assert RAN == []
    assert SEEN[0]["pca"]["allowed"] is False


def test_model_declaration_hides_injected_context_and_proof_args() -> None:
    decl = _guard(place_order)._get_declaration()
    assert decl is not None
    schema = decl.parameters_json_schema or {}
    props = set((schema.get("properties") or {}).keys())
    assert props == {"sku"}
