"""End-to-end tests against the REAL Pydantic AI (skipped when it is not installed).

A scripted ``FunctionModel`` drives a real ``Agent``: it asks for the tool, the guard allows or refuses,
and the refusal reaches the model as a retry prompt carrying the reason. Run with ``make test-real`` (or
``sdks/scripts/test-adapters-real.sh``). Proofs are the shared conformance vectors.
"""
import copy
import json
import os
from typing import Any, List

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent, RunContext, Tool  # noqa: E402
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models.function import AgentInfo, FunctionModel  # noqa: E402

from atlas_pca.pca import b64u, canonical_bytes_strict  # noqa: E402
from atlas_pca_pydantic_ai import CoreVerifier, PCADeps, PCAGuard, pca_tool  # noqa: E402

_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "conformance")
with open(os.path.join(_DIR, "vectors.json"), encoding="utf-8") as _f:
    _VEC = next(v for v in json.load(_f)["vectors"] if v["name"] == "valid-in-plan-action")
PCACTN = _VEC["pcactn"]
GRANT = _VEC["grant"]
NOW = _VEC["context"]["now"]
AUD = _VEC["context"]["aud"]
CAP = "%s:%s" % (PCACTN["action"]["verb"], PCACTN["action"]["resource"])
RAN: List[int] = []
RETRIES: List[str] = []


def _resolver(ref: Any) -> Any:
    return GRANT if ref == PCACTN["grant_ref"] else None


def _verifier() -> CoreVerifier:
    return CoreVerifier(resolve_grant=_resolver, now=NOW)


def _wire(p: Any = PCACTN) -> str:
    return b64u(canonical_bytes_strict(p))


def _tampered() -> Any:
    bad = copy.deepcopy(PCACTN)
    bad["sig"] = ("B" if bad["sig"][0] != "B" else "C") + bad["sig"][1:]
    return bad


@pytest.fixture(autouse=True)
def _clear() -> None:
    RAN.clear()
    RETRIES.clear()


def _model(tool_name: str = "transfer") -> FunctionModel:
    """Call the tool once; if it was refused (a retry prompt), record why and give up with text."""

    def fn(messages: List[ModelMessage], info: AgentInfo) -> ModelResponse:
        last = messages[-1]
        for part in getattr(last, "parts", []):
            kind = type(part).__name__
            if kind == "RetryPromptPart":
                RETRIES.append(str(part.content))
                return ModelResponse(parts=[TextPart("refused")])
            if kind == "ToolReturnPart":
                return ModelResponse(parts=[TextPart("done: %s" % part.content)])
        return ModelResponse(parts=[ToolCallPart(tool_name, {"amount": 5})])

    return FunctionModel(fn)


def test_allows_with_proof_on_deps_sync_and_async() -> None:
    agent: Agent[PCADeps, str] = Agent(_model(), deps_type=PCADeps)

    @agent.tool
    @pca_tool(CAP, audience=AUD, verifier=_verifier())
    async def transfer(ctx: RunContext[PCADeps], amount: int) -> str:
        RAN.append(amount)
        return "transferred %d" % amount

    out = agent.run_sync("go", deps=PCADeps(pca_action=_wire()))
    assert out.output == "done: transferred 5"
    assert RAN == [5]


def test_allows_with_inline_object_on_deps_and_tool_constructor() -> None:
    guard = PCAGuard(audience=AUD, verifier=_verifier())

    def transfer(ctx: RunContext[PCADeps], amount: int) -> str:
        RAN.append(amount)
        return "transferred %d" % amount

    agent: Agent[PCADeps, str] = Agent(_model(), deps_type=PCADeps, tools=[Tool(guard.wrap(transfer, CAP))])
    out = agent.run_sync("go", deps=PCADeps(pca_action=PCACTN))
    assert "transferred 5" in out.output
    assert RAN == [5]


@pytest.mark.parametrize("deps,why", [
    (PCADeps(), "no PCActn presented"),
    (PCADeps(pca_action="!!bad!!"), "could not be decoded"),
])
def test_refusal_reaches_model_as_retry_with_reason(deps: PCADeps, why: str) -> None:
    agent: Agent[PCADeps, str] = Agent(_model(), deps_type=PCADeps)

    @agent.tool
    @pca_tool(CAP, audience=AUD, verifier=_verifier())
    def transfer(ctx: RunContext[PCADeps], amount: int) -> str:
        RAN.append(amount)
        return "x"

    out = agent.run_sync("go", deps=deps)
    assert out.output == "refused"
    assert RAN == []
    assert why in RETRIES[0]


def test_tampered_wrong_audience_and_insufficient_capability_refused() -> None:
    cases = [
        (CAP, AUD, PCADeps(pca_action=_wire(_tampered()))),
        (CAP, "agent://other", PCADeps(pca_action=_wire())),
        ("delete:db/orders", AUD, PCADeps(pca_action=_wire())),
    ]
    for cap, aud, deps in cases:
        agent: Agent[PCADeps, str] = Agent(_model(), deps_type=PCADeps)

        @agent.tool
        @pca_tool(cap, audience=aud, verifier=_verifier())
        def transfer(ctx: RunContext[PCADeps], amount: int) -> str:
            RAN.append(amount)
            return "x"

        assert agent.run_sync("go", deps=deps).output == "refused"
    assert RAN == []
    assert len(RETRIES) == 3
    assert "insufficient_capability" in RETRIES[2]


def test_tool_plain_has_no_deps_so_it_is_refused() -> None:
    agent: Agent[None, str] = Agent(_model())

    @agent.tool_plain
    @pca_tool(CAP, audience=AUD, verifier=_verifier())
    def transfer(amount: int) -> str:
        RAN.append(amount)
        return "x"

    assert agent.run_sync("go").output == "refused"
    assert RAN == []
    assert "no PCActn presented" in RETRIES[0]


def test_proof_in_model_supplied_arguments_never_runs_the_tool() -> None:
    """The arguments channel is model-controlled; Pydantic AI's strict tool schema refuses the extra key
    before the guard, so the tool never runs. The supported channel is ``RunContext.deps``."""

    def fn(messages: List[ModelMessage], info: AgentInfo) -> ModelResponse:
        for part in getattr(messages[-1], "parts", []):
            if type(part).__name__ == "RetryPromptPart":
                RETRIES.append(str(part.content))
                return ModelResponse(parts=[TextPart("refused")])
        return ModelResponse(parts=[ToolCallPart("transfer", {"amount": 5, "PCA-Action": _wire()})])

    agent: Agent[None, str] = Agent(FunctionModel(fn))

    @agent.tool_plain
    @pca_tool(CAP, audience=AUD, verifier=_verifier())
    def transfer(amount: int) -> str:
        RAN.append(amount)
        return "x"

    assert agent.run_sync("go").output == "refused"
    assert RAN == []
    assert "extra_forbidden" in RETRIES[0]
