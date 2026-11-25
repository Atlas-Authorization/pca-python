"""Replay of the TypeScript reference's OpenAI Agents adapter logic (proof sources, guard pipeline, per-tool option merging, guardrails,
step-up) from test-data/ref-openai-agents.json.gz. Tools, verifiers and hooks are rebuilt from the same declarative descriptors."""
import asyncio
import re

from base_oracle import canon, load_ref, run

from atlas_pca import openai_agents as oa

CAMEL = {"tripwire_triggered": "tripwireTriggered", "output_info": "outputInfo"}


def norm(m):
    m = re.sub(r"proof could not be decoded: [\s\S]*$", "proof could not be decoded: ", str(m))
    return re.sub(r"(full policy mode is missing)[\s\S]*$", r"\1", m)


def stub(d, calls):
    def verify(p):
        v = (p.get("action") or {}).get("verb") if isinstance(p, dict) else None
        calls.append(["verify", d["stub"], v])
        if d.get("throws"):
            raise Exception(d["throws"])
        out = {"allow": d["allow"], "checks": {"sig": "pass" if d["allow"] else "fail"}}
        if "reason" in d:
            out["reason"] = d["reason"]
        return out
    return verify


def build_opts(d, calls):
    out = {k: d[k] for k in ("mode", "verb", "audience", "name") if k in d}
    if d.get("verify"):
        out["verify"] = stub(d["verify"], calls)
    if d.get("authorize") is not None:
        out["authorize"] = d["authorize"]
    if d.get("require"):
        r = d["require"]
        out["require"] = oa.proof_from_input_headers(*r["headers"]) if "headers" in r else (lambda *_a, c=r["const"]: c)
    if d.get("onDeny"):
        out["on_deny"] = lambda e, i: calls.append(["onDeny", e.kind, i])
    if d.get("onVerified"):
        out["on_verified"] = lambda r, p, i: calls.append(["onVerified", r["allow"], (p.get("action") or {}).get("verb"), i])
    if d.get("recorder"):
        out["recorder"] = type("Rec", (), {"tool": staticmethod(lambda n, o: calls.append(["recorded", n, o]))})()
    return out


class Tool:
    def __init__(self, td, calls):
        self.name, self.description = td.get("name"), "d"
        for k, v in (td.get("extra") or {}).items():
            setattr(self, k, v)
        if not td.get("noExecute"):
            async def execute(input, rc=None):
                calls.append(["exec", td.get("name"), input])
                if td.get("throws"):
                    raise Exception(td["throws"])
                return {"echo": input, "tool": td.get("name")}
            self.execute = execute


def err_of(e, calls):
    out = {"err": "PcaToolDenied" if isinstance(e, oa.PcaToolDenied) else "TypeError" if isinstance(e, TypeError) else "Error",
           "message": norm(e), "calls": calls}
    if isinstance(e, oa.PcaToolDenied):
        out.update(kind=e.kind, verb=e.verb)
        if e.checks is not None:
            out["checks"] = e.checks
    return out


async def outcome(t, input, rc, no_rc, calls):
    try:
        out = await t.execute(input, None if no_rc else rc)
    except Exception as e:  # noqa: BLE001
        return err_of(e, calls)
    return {"ok": True, "out": out, "calls": calls, "name": getattr(t, "name", None), "extra": getattr(t, "extra", None),
            "hasNeedsApproval": hasattr(t, "needs_approval")}


def build_error(e, calls):
    return {"err": "TypeError" if isinstance(e, TypeError) else "Error", "message": norm(e), "calls": calls, "build": True}


def with_tool(a):
    calls = []
    try:
        t = oa.with_pca_tool(Tool(a["tool"], calls), **build_opts(a["options"], calls))
    except Exception as e:  # noqa: BLE001
        return build_error(e, calls)
    return asyncio.run(outcome(t, a["input"], a.get("runContext"), bool(a.get("noRunContext")), calls))


def tools_of(a):
    calls = []
    tools = {k: Tool(v, calls) for k, v in a["tools"].items()}
    o = a["options"]
    per = {k: build_opts(v, calls) for k, v in o["per"].items()} if "per" in o else None
    try:
        g = oa.pca_tools(tools, per=per, only=o.get("only"), **build_opts(o, calls))
    except Exception as e:  # noqa: BLE001
        return build_error(e, calls)

    async def all_():
        res = {}
        for k, t in g.items():
            r = await outcome(t, a["input"], a["runContext"], False, calls)
            r["same"] = t is tools[k]
            res[k] = r
        return res
    return asyncio.run(all_())


def guardrail(a):
    calls = []
    kw = build_opts(a["options"], calls)
    kw.pop("mode", None)
    g = (oa.pca_input_guardrail if a["kind"] == "input" else oa.pca_tool_guard)(**kw)
    try:
        r = asyncio.run(g.execute(a["args"]))
    except Exception as e:  # noqa: BLE001
        return {"err": "Error", "message": norm(e), "calls": calls}
    return {"name": g.name, "result": {CAMEL[k]: v for k, v in r.items()}, "calls": calls}


def intent_null(calls):
    def intent(t, i):
        calls.append(["intent", t, i])
        return None
    return intent


def review(a):
    calls = []
    r = oa.review_tool_call(None, a["tool"], a.get("input"), intent=intent_null(calls))
    return {"r": r, "calls": calls}


def needs(a):
    calls = []
    kw = {"intent": intent_null(calls)}
    if a.get("toolName") is not None:
        kw["tool_name"] = a["toolName"]
    if a["via"] == "direct":
        f = oa.pca_needs_approval(None, **kw)
        return {"value": asyncio.run(f({}, a["input"], "c1")), "calls": calls}
    td = a["tool"]

    class T:
        description = "d"

        async def execute(self, *_a):
            return 1
    t = T()
    t.name = td.get("name")
    t = oa.with_approval(t, None, **kw)
    return {"value": asyncio.run(t.needs_approval({}, a["input"], "c1")), "calls": calls, "name": t.name, "extra": None,
            "hasExecute": callable(t.execute)}


def test_openai_agents_vectors():
    count, by_fn = load_ref("openai-agents")
    assert count >= 150
    assert set(by_fn) == {"proofFromRunContext", "guardrailProofFromContext", "provenanceFromRunContext", "proofFromInputHeaders",
                          "pendingStepUps", "withPcaTool", "pcaTools", "guardrail", "reviewToolCall", "needsApproval"}
    run(by_fn["proofFromRunContext"], lambda a: oa.proof_from_run_context(a.get("input"), a.get("runContext")))
    run(by_fn["guardrailProofFromContext"], lambda a: oa.guardrail_proof_from_context(a["args"]))
    run(by_fn["provenanceFromRunContext"], lambda a: oa.provenance_from_run_context(None, a["runContext"]))
    run(by_fn["proofFromInputHeaders"], lambda a: oa.proof_from_input_headers(a.get("field", "headers"), a.get("header", "PCA-Action"))(a.get("input")))
    run(by_fn["pendingStepUps"], lambda r: oa.pending_step_ups(r))
    cmp = lambda got, out, c: canon(_clean(got)) == canon(_clean(out))  # noqa: E731
    run(by_fn["withPcaTool"], with_tool, compare=cmp)
    run(by_fn["pcaTools"], tools_of, compare=cmp)
    run(by_fn["guardrail"], guardrail, compare=cmp)
    run(by_fn["reviewToolCall"], review)
    run(by_fn["needsApproval"], needs)


def _clean(v):
    """The reference's messages with the language-specific tails cut (same cuts as norm on the native side)."""
    if isinstance(v, str):
        return norm(v)
    if isinstance(v, dict):
        return {k: _clean(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_clean(x) for x in v]
    return v
