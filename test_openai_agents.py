"""atlas_pca.openai_agents against fake Agents-SDK objects (FunctionTool-like, run context, guardrail data); `agents` is never installed."""
import ast
import asyncio
import json
import os
import sys
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from atlas_pca import openai_agents as oa
from atlas_pca.adapters import PcaDenied
from atlas_pca.agent import DEFAULT_RISK_POLICY, Agent, keypair_from_seed, mint_grant
from atlas_pca.authorize import AuthorizeResult, MemoryStateStore
from atlas_pca.pca import b64u

PRINCIPAL = keypair_from_seed(b"\x01" * 32, allow_insecure_signer=True)
HOLDER = keypair_from_seed(b"\x02" * 32, allow_insecure_signer=True)
ENV = {"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": DEFAULT_RISK_POLICY}
GRANT = mint_grant(PRINCIPAL, HOLDER.public, ENV, "refund orders", salt="s")["grant"]


def run(coro):
    return asyncio.run(coro)


@dataclass
class FunctionTool:  # the shape of the SDK's FunctionTool that the adapter touches
    name: str
    description: str
    on_invoke_tool: Callable[..., Any]
    needs_approval: Any = False


def fn_tool(seen):
    async def invoke(ctx, raw):
        seen.append(raw)
        return "done"
    return FunctionTool("refund", "d", invoke)


def ctx_with(proof, **extra):
    return SimpleNamespace(context={"pca": proof, **extra}, tool_arguments="{}")


def signed(order=1, agent=None):
    a = agent or Agent(HOLDER, GRANT, "rs-test")
    act = a.act("refund", "orders/%d" % order, {"order": order})
    return a, json.dumps(act.pcactn, separators=(",", ":")), act


def test_no_top_level_agents_import():
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "atlas_pca", "openai_agents.py")).read()
    for n in ast.parse(src).body:
        names = [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module or ""] if isinstance(n, ast.ImportFrom) else []
        assert not any(x == "agents" or x.startswith("agents.") for x in names)


def test_function_tool_signature_only_with_real_core_verify():
    a, proof, act = signed()
    seen = []
    verify = {"grant": GRANT, "authorized_plan_roots": [act.pcactn["plan"]["root"]]}
    t = oa.with_pca_tool(fn_tool(seen), mode="signature-only", verify=verify, audience="rs-test", verb="refund")
    assert t.name == "refund" and t is not None
    assert run(t.on_invoke_tool(ctx_with(proof), '{"order":1}')) == "done" and seen == ['{"order":1}']
    with pytest.raises(oa.PcaToolDenied) as e:  # wrong audience: refused before the tool runs
        run(oa.with_pca_tool(fn_tool(seen), mode="signature-only", verify=verify, audience="other").on_invoke_tool(ctx_with(proof), "{}"))
    assert e.value.kind == "verify" and len(seen) == 1
    with pytest.raises(oa.PcaToolDenied) as e:  # no audience at all: fail closed
        run(oa.with_pca_tool(fn_tool(seen), mode="signature-only", verify=verify).on_invoke_tool(ctx_with(proof), "{}"))
    assert e.value.kind == "verify"
    with pytest.raises(oa.PcaToolDenied) as e:
        run(oa.with_pca_tool(fn_tool(seen), mode="signature-only", verify=verify, audience="rs-test").on_invoke_tool(ctx_with(None), "{}"))
    assert e.value.kind == "missing" and len(seen) == 1


def test_dict_tool_and_pca_tools_list():
    async def execute(i, rc=None):
        return i
    tools = oa.pca_tools([{"name": "a", "execute": execute}, {"name": "b", "execute": execute}], mode="signature-only",
                         verify=lambda p: {"allow": True}, audience="x", only=["a"])
    assert tools[1]["execute"] is execute and tools[0]["execute"] is not execute
    assert run(tools[0]["execute"]({"k": 1}, {"context": {"pca": json.dumps({"action": {"verb": "v"}})}})) == {"k": 1}


class FakeAuth:
    def __init__(self, result):
        self.state_store, self.is_revoked, self.seen = MemoryStateStore(), (lambda *_a: False), []
        self.result = result

    def run(self, pcactn, **kw):
        self.seen.append(kw)
        return self.result


def result(allow=False, status=403, **kw):
    return AuthorizeResult(allow=allow, status=status, checks=kw.pop("checks", {}), reasons=[kw.get("reason", "x")], **kw)


def full(auth, **kw):
    return oa.with_pca_tool(fn_tool([]), authorize=auth, resolve_grant=lambda ref: GRANT, audience="rs", verb="refund", resource="orders/1", **kw)


PROOF = json.dumps({"action": {"verb": "refund", "resource": "orders/1"}})


def kind_of(auth, proof=PROOF):
    with pytest.raises(oa.PcaToolDenied) as e:
        run(full(auth).on_invoke_tool(ctx_with(proof), '{"order": 1}'))
    return e.value.kind


def test_full_mode_decisions_and_kinds():
    ok = FakeAuth(result(allow=True, status=200, checks={"replay": "pass"}))
    assert run(full(ok).on_invoke_tool(ctx_with(PROOF, pcaProvenance={"b": 1}), '{"order": 1}')) == "done"
    kw = ok.seen[0]
    assert kw["operation"] == {"verb": "refund", "resource": "orders/1", "params": {"order": 1}}
    assert kw["audience"] == "rs" and kw["provenance"] == {"b": 1}
    assert kind_of(FakeAuth(result(status=401))) == "verify"
    assert kind_of(FakeAuth(result(checks={"revocation": "fail"}))) == "revoked"
    assert kind_of(FakeAuth(result(checks={"replay": "fail"}))) == "replay"
    assert kind_of(FakeAuth(result(checks={"policy": "fail"}))) == "policy"
    assert kind_of(FakeAuth(result(missing=["state_store"]))) == "config"
    assert kind_of(FakeAuth(result(allow=True)), proof=json.dumps({"action": {"verb": "other"}})) == "binding"  # never reaches authorize

    class Boom(FakeAuth):
        def run(self, *a, **k):
            raise RuntimeError("store down")
    assert kind_of(Boom(None)) == "policy"


def test_full_mode_is_a_configuration_error_when_incomplete():
    tool = fn_tool([])
    good = FakeAuth(result(allow=True))
    with pytest.raises(TypeError, match="needs.*verify|pass `authorize`"):
        oa.with_pca_tool(tool, audience="rs")
    with pytest.raises(TypeError, match="full policy mode is missing resolve_grant"):
        oa.with_pca_tool(tool, authorize=good, audience="rs", verb="v", resource="r")
    with pytest.raises(TypeError, match="missing .*operation"):
        oa.with_pca_tool(tool, authorize=good, resolve_grant=lambda r: GRANT, audience="rs")
    with pytest.raises(TypeError, match="missing audience"):
        oa.with_pca_tool(tool, authorize=good, resolve_grant=lambda r: GRANT, verb="v", resource="r")
    with pytest.raises(TypeError, match="is missing state_store"):
        oa.with_pca_tool(tool, authorize=SimpleNamespace(state_store=None, is_revoked=lambda *a: False, run=lambda *a, **k: None),
                         resolve_grant=lambda r: GRANT, audience="rs", verb="v", resource="r")


def test_custom_operation_and_provenance_source():
    ok = FakeAuth(result(allow=True, status=200))
    t = oa.with_pca_tool(fn_tool([]), authorize=ok, resolve_grant=lambda r: GRANT, audience="rs",
                         operation=lambda i, rc: {"verb": "refund", "resource": "orders/1", "params": {"o": i["order"]}},
                         provenance=lambda i, rc: b64u(b'{"s":1}'))
    run(t.on_invoke_tool(ctx_with(PROOF), '{"order": 1}'))
    assert ok.seen[0]["operation"]["params"] == {"o": 1} and ok.seen[0]["provenance"] == {"s": 1}
    assert oa.provenance_from("not json") is None and oa.provenance_from('{"a":1}') == {"a": 1}


def test_recorder_and_hooks_on_function_tool():
    got = []
    rec = SimpleNamespace(tool=lambda n, o: got.append((n, o)))
    t = oa.with_pca_tool(fn_tool([]), mode="signature-only", verify=lambda p: {"allow": True}, audience=None, recorder=rec,
                         on_verified=lambda r, p, i: got.append(("verified", i)), on_deny=lambda e, i: got.append(("deny", e.kind)))
    assert run(t.on_invoke_tool(ctx_with(PROOF), '{"order": 2}')) == "done"
    assert got == [("verified", {"order": 2}), ("refund", "done")]
    with pytest.raises(oa.PcaToolDenied):
        run(t.on_invoke_tool(SimpleNamespace(context={}), "{}"))
    assert got[-1] == ("deny", "missing")


def fake_sdk(monkeypatch):
    class Out:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class ToolOut(Out):
        @staticmethod
        def allow(output_info=None):
            return ToolOut(behavior="allow", output_info=output_info)

        @staticmethod
        def reject_content(message, output_info=None):
            return ToolOut(behavior="reject", message=message, output_info=output_info)

    class Guard(Out):
        pass
    mod = SimpleNamespace(GuardrailFunctionOutput=Out, ToolGuardrailFunctionOutput=ToolOut, InputGuardrail=Guard, ToolInputGuardrail=Guard)
    monkeypatch.setitem(sys.modules, "agents", mod)


def test_guardrails_without_and_with_the_sdk(monkeypatch):
    g = oa.pca_input_guardrail(verify=lambda p: {"allow": True}, audience=None)
    monkeypatch.setitem(sys.modules, "agents", None)  # not installed
    out = run(g.input_guardrail_function(SimpleNamespace(context={"pca": PROOF}), object(), "hi"))
    assert out == {"tripwire_triggered": False, "output_info": {"verb": "refund"}}
    with pytest.raises(ImportError):
        g.as_input_guardrail()
    fake_sdk(monkeypatch)
    assert run(g.input_guardrail_function(SimpleNamespace(context={}), object(), "hi")).tripwire_triggered is True
    ig = g.as_input_guardrail()
    assert ig.name == "pca-input-guardrail" and ig.guardrail_function == g.input_guardrail_function
    tg = oa.pca_tool_guard(verify=lambda p: {"allow": True}, audience=None, name="t")
    data = lambda proof: SimpleNamespace(context=SimpleNamespace(context={"pca": proof}, tool_arguments="{}"), agent=None)  # noqa: E731
    assert run(tg.tool_guardrail_function(data(PROOF))).behavior == "allow"
    rej = run(tg.tool_guardrail_function(data(None)))
    assert rej.behavior == "reject" and rej.message.startswith("PCA tool denied (missing)")
    assert tg.as_tool_input_guardrail().name == "t"


REQ = {"id": "r1", "tier": 2}


def test_step_up_review_and_needs_approval():
    calls = []

    def review(agent, verb, resource, params, opts):
        calls.append((verb, resource, params, opts))
        return {"auto": {"kind": "auto"}, "deny": {"kind": "deny", "reason": "no"}, "up": {"kind": "step_up", "request": REQ}}[verb]

    def intent(tool, input):
        return None if tool == "free" else {"verb": input["k"], "resource": "res"}

    kw = dict(intent=intent, review=review, goal="g", now=5)
    assert oa.review_tool_call(None, "free", {}, **kw) == {"tool": "free", "review": {"kind": "auto"}}
    r = oa.review_tool_call(None, "t", {"k": "up"}, **kw)
    assert r["review"]["request"] is REQ and calls[-1] == ("up", "res", {"k": "up"}, {"goal": "g", "now": 5})
    with pytest.raises(TypeError):
        oa.review_tool_call(None, "t", {"k": "up"}, intent=intent)
    assert oa.pending_step_ups([r, oa.review_tool_call(None, "t", {"k": "auto"}, **kw)]) == [{"tool": "t", "request": REQ}]

    stepped, approved = [], []
    f = oa.pca_needs_approval(None, tool_name="t", on_step_up=stepped.append, approved=lambda q: q["id"] in approved, **kw)
    assert run(f({}, {"k": "auto"}, "c")) is False
    assert run(f({}, {"k": "deny"}, "c")) is True
    assert run(f({}, {"k": "up"}, "c")) is True and stepped == [{"tool": "t", "request": REQ}]
    approved.append("r1")
    assert run(f({}, {"k": "up"}, "c")) is False and len(stepped) == 1
    assert run(oa.pca_needs_approval(None, tool_name="t", deny_needs_approval=False, **kw)({}, {"k": "deny"})) is False

    base = FunctionTool("t", "d", lambda *a: None)
    w = oa.with_approval(base, None, **kw)
    assert w is not base and w.name == "t" and base.needs_approval is False
    assert run(w.needs_approval({}, {"k": "up"}, "c")) is True


def test_attach_pca_signs_each_call_and_fast_fails():
    a = Agent(HOLDER, GRANT, "rs-test")
    seen, proofs = [], []
    t = oa.attach_pca(a, "refund", lambda p: "orders/%s" % p["order"], fn_tool(seen), on_proof=lambda pca, p: proofs.append((pca, p)))
    assert run(t.on_invoke_tool(None, '{"order": 7}')) == "done"
    assert proofs[0][1] == {"order": 7} and proofs[0][0].pcactn["action"]["resource"] == "orders/7" and seen == ['{"order": 7}']
    with pytest.raises(TypeError):
        run(t.on_invoke_tool(None, "[1]"))
    bad = oa.attach_pca(a, "wipe", "orders/1", fn_tool(seen))
    with pytest.raises(PcaDenied):
        run(bad.on_invoke_tool(None, "{}"))
    assert len(seen) == 1
