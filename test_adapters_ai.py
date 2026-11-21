"""Agent-side AI-stack adapters (atlas_pca.adapters / openai / anthropic / langchain / llamaindex) with fake tool objects."""
import asyncio
import json

import pytest

from atlas_pca.adapters import PcaCall, PcaDenied, bridge_tool_call, guard, js_json
from atlas_pca.agent import DEFAULT_RISK_POLICY, Agent, keypair_from_seed, mint_grant
from atlas_pca.adapters import provenance_headers, record_input, record_messages, with_principal_input
from atlas_pca.anthropic import extract_tool_uses, handle_tool_use, handle_tool_uses
from atlas_pca.arg_provenance import create_provenance_recorder
from atlas_pca.langchain import with_pca as lc_with_pca, with_pca_agent
from atlas_pca.anthropic import with_pca_messages
from atlas_pca.llamaindex import with_pca_engine
from atlas_pca.openai import with_pca_completions
from atlas_pca.llamaindex import with_pca as li_with_pca
from atlas_pca.openai import dispatch_tool_call, dispatch_tool_calls
from atlas_pca.pca import decode_pca_header

PRINCIPAL = keypair_from_seed(b"\x01" * 32, allow_insecure_signer=True)
HOLDER = keypair_from_seed(b"\x02" * 32, allow_insecure_signer=True)
ENV = {"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": DEFAULT_RISK_POLICY}
GRANT = mint_grant(PRINCIPAL, HOLDER.public, ENV, "refund orders", salt="s")["grant"]


def make_agent():
    return Agent(HOLDER, GRANT, "rs-test")


def mapping(call):
    if call["name"] == "refund":
        return {"verb": "refund", "resource": "orders/" + str(call["arguments"]["order"])}
    if call["name"] == "wipe":
        return {"verb": "wipe", "resource": "orders/1"}
    return None


def run(coro):
    return asyncio.run(coro)


def test_js_json_matches_json_stringify():
    assert js_json({"a": [1, 2.0, 2.5, None, True], "b": "é "}) == '{"a":[1,2,2.5,null,true],"b":"é "}'
    assert js_json(float("nan")) == "null"


def test_bridge_declines_unmapped_and_signs_mapped():
    a = make_agent()
    assert bridge_tool_call(a, {"name": "other", "arguments": {}}, mapping) is None
    pca = bridge_tool_call(a, {"name": "refund", "arguments": {"order": 7}}, mapping)
    assert isinstance(pca, PcaCall)
    assert json.loads(pca.encoded) == pca.pcactn
    assert decode_pca_header(pca.headers["PCA-Action"]) == pca.encoded
    assert pca.pcactn["counter"] == 1


def test_guard_allows_denies_and_skips_dry_run():
    a = make_agent()
    seen = []
    ok = guard(a, "refund", lambda p: "orders/%s" % p["order"], lambda p, pca: seen.append(pca) or "done")
    assert ok({"order": 1}) == "done" and seen[0].pcactn["counter"] == 1
    bad = guard(a, "wipe", "orders/1", lambda p, pca: "ran")
    with pytest.raises(PcaDenied) as e:
        bad({})
    assert str(e.value).startswith("PCA denied wipe on orders/1: ")
    assert (e.value.verb, e.value.resource) == ("wipe", "orders/1")
    assert guard(a, "wipe", "orders/1", lambda p, pca: "ran", fail_fast=False)({}) == "ran"

    async def arun(p, pca):
        return "async"
    assert run(guard(a, "refund", "orders/1", arun)({})) == "async"


def test_guard_fail_fast_refuses_an_out_of_grant_resource_the_chain_check_alone_admits():
    a = make_agent()
    ran = []
    g = guard(a, "refund", lambda p: p["res"], lambda p, pca: ran.append(1) or "done")
    assert g({"res": "orders/1"}) == "done"
    with pytest.raises(PcaDenied):
        g({"res": "users/1"})
    assert ran == [1]


def test_openai_dispatch():
    a = make_agent()
    call = {"id": "c1", "type": "function", "function": {"name": "refund", "arguments": ' {"order": 5} '}}
    msg = run(dispatch_tool_call(a, call, mapping, {"refund": lambda args, pca: {"ok": True, "n": args["order"], "s": "é"}}))
    assert msg == {"role": "tool", "tool_call_id": "c1", "content": '{"ok":true,"n":5,"s":"é"}'}
    noh = run(dispatch_tool_call(a, call, mapping, {}))
    assert json.loads(noh["content"])["pca"] and list(json.loads(noh["content"])) == ["pca"]

    async def ah(args, pca):
        return [1]
    assert run(dispatch_tool_call(a, call, mapping, {"refund": ah}))["content"] == "[1]"
    empty = {"id": "c2", "function": {"name": "wipe", "arguments": ""}}
    assert list(json.loads(run(dispatch_tool_call(a, empty, mapping, {}))["content"])) == ["pca"]  # no dry run in dispatch
    declined = {"id": "c3", "function": {"name": "zzz", "arguments": "{}"}}
    with pytest.raises(ValueError, match='^dispatchToolCall: no PCActn for unmapped tool "zzz" \\(the mapping declined\\)$'):
        run(dispatch_tool_call(a, declined, mapping, {}))
    arr = {"id": "c4", "function": {"name": "refund", "arguments": "[1]"}}
    with pytest.raises(ValueError, match="^dispatchToolCall: tool_call arguments must be a JSON object$"):
        run(dispatch_tool_call(a, arr, mapping, {}))


def test_openai_object_shapes_and_batch():
    class NS:
        def __init__(self, **kw):
            self.__dict__.update(kw)
    a = make_agent()
    calls = [NS(id="a", function=NS(name="refund", arguments='{"order":1}')), NS(id="b", function=NS(name="refund", arguments='{"order":2}'))]
    out = run(dispatch_tool_calls(a, calls, mapping, {"refund": lambda args, pca: pca.pcactn["counter"]}))
    assert [m["tool_call_id"] for m in out] == ["a", "b"] and [m["content"] for m in out] == ["1", "2"]


def test_anthropic_tool_use():
    a = make_agent()
    block = {"type": "tool_use", "id": "t1", "name": "refund", "input": {"order": 3}}
    assert run(handle_tool_use(a, block, mapping, {"refund": lambda i, p: {"ok": 1.0}})) == {"type": "tool_result", "tool_use_id": "t1", "content": '{"ok":1}'}
    nomap = run(handle_tool_use(a, {"type": "tool_use", "id": "t2", "name": "x", "input": {}}, mapping, {}))
    assert nomap == {"type": "tool_result", "tool_use_id": "t2", "content": 'No proof-carrying authority is mapped for tool "x".', "is_error": True}
    assert run(handle_tool_use(a, block, mapping, {}))["content"] == 'No handler registered for tool "refund".'

    def boom(i, p):
        raise ValueError("boom")
    assert run(handle_tool_use(a, block, mapping, {"refund": boom})) == {"type": "tool_result", "tool_use_id": "t1", "content": "boom", "is_error": True}
    fallback = run(handle_tool_use(a, block, mapping, {"refund": lambda i, p: None}))
    assert list(json.loads(fallback["content"])) == ["pca"]
    content = [{"type": "text", "text": "hi"}, block, dict(block, id="t9")]
    assert extract_tool_uses(content) == [block, dict(block, id="t9")]
    res = run(handle_tool_uses(a, content, mapping, {"refund": lambda i, p: "r"}))
    assert [r["tool_use_id"] for r in res] == ["t1", "t9"] and all(r["content"] == '"r"' for r in res)


class LcTool:
    name = "refund"

    def __init__(self):
        self.calls = []

    def func(self, **kw):
        self.calls.append(("func", kw))
        return "f"

    def invoke(self, a, config=None):
        self.calls.append(("invoke", a, config))
        return "i"

    async def ainvoke(self, a, config=None):
        return "ai"


def test_langchain_wraps_and_keeps_shape():
    a, t, proofs = make_agent(), LcTool(), []
    w = lc_with_pca(a, "refund", "orders/1", t, on_proof=lambda pca, args: proofs.append((pca, args)))
    assert w is not t and w.name == "refund"
    assert w.func(order=1) == "f" and w.invoke({"order": 2}, {"tags": []}) == "i" and run(w.ainvoke({"order": 3})) == "ai"
    assert t.calls == [("func", {"order": 1}), ("invoke", {"order": 2}, {"tags": []})]
    assert [p[1] for p in proofs] == [{"order": 1}, {"order": 2}, {"order": 3}]
    with pytest.raises(TypeError):
        w.func(1)
    with pytest.raises(TypeError):
        w.invoke("text")
    with pytest.raises(PcaDenied):
        lc_with_pca(a, "wipe", "orders/1", t).func(order=1)
    with pytest.raises(TypeError, match="none of func"):
        lc_with_pca(a, "refund", "orders/1", object())
    assert lc_with_pca(a, "wipe", "orders/1", t, fail_fast=False).func(order=1) == "f"


def test_llamaindex_wraps_call_and_acall():
    class Tool:
        metadata = {"name": "refund"}

        def call(self, **kw):
            return ("c", kw)

        async def acall(self, **kw):
            return ("ac", kw)
    a, t = make_agent(), Tool()
    w = li_with_pca(a, "refund", lambda args: "orders/%s" % args["order"], t)
    assert w.metadata is t.metadata
    assert w.call(order=4) == ("c", {"order": 4}) and run(w.acall(order=5)) == ("ac", {"order": 5})
    with pytest.raises(PcaDenied):
        li_with_pca(a, "wipe", "orders/1", t).call(order=1)
    with pytest.raises(TypeError, match="neither call"):
        li_with_pca(a, "refund", "orders/1", object())


def make_prov_agent():
    rec = create_provenance_recorder(mediator="harness", kid="k1", secret_key=b"\x03" * 32, session="A" * 43)
    return Agent(HOLDER, GRANT, "rs-test", provenance=rec), rec


def origins(rec):
    return [(r["origin"], r["source"]) for r in rec.receipts()]


def test_agent_without_recorder_is_unchanged():
    act = make_agent().act("refund", "orders/1", {})
    assert act.provenance is None and "PCA-Provenance" not in act.headers


def test_agent_act_attaches_bundle_and_header():
    a, rec = make_prov_agent()
    rec.principal("refund order 1")
    act = a.act("refund", "orders/1", {"amount": 1})
    assert act.provenance["kind"] == "pca-provenance" and [r["origin"] for r in act.provenance["receipts"]] == ["principal", "action"]
    assert act.headers["PCA-Provenance"] == provenance_headers(act.provenance)["PCA-Provenance"]
    assert a.delegate(keypair_from_seed(b"\x04" * 32, allow_insecure_signer=True)).provenance is rec


def test_openai_records_messages_and_tool_results():
    a, rec = make_prov_agent()
    seen = []
    create = with_pca_completions(a, lambda **kw: seen.append(kw) or "resp")
    msgs = [{"role": "user", "content": "refund 5"}, {"role": "assistant", "content": "ok"}]
    assert create(model="m", messages=msgs) == "resp" and create(model="m", messages=msgs) == "resp"
    assert origins(rec) == [("principal", "user")]  # the second turn adds nothing: already recorded
    call = {"id": "c1", "function": {"name": "refund", "arguments": '{"order": 5}'}}
    msg = run(dispatch_tool_call(a, call, mapping, {"refund": lambda args, pca: {"ok": True}}))
    assert origins(rec)[-2:] == [("action", "refund"), ("tool", "refund")]
    assert msg["content"] == '{"ok":true}'


def test_guard_and_anthropic_record_tool_results():
    a, rec = make_prov_agent()
    guard(a, "refund", "orders/1", lambda p, pca: {"n": 1})({"order": 1})
    assert origins(rec) == [("action", "refund"), ("tool", "refund")]
    block = {"type": "tool_use", "id": "t1", "name": "refund", "input": {"order": 3}}

    def boom(i, p):
        raise ValueError("boom")
    run(handle_tool_use(a, block, mapping, {"refund": boom}))
    assert origins(rec)[-1] == ("tool", "refund") and rec.receipts()[-1]["content_digest"]
    create = with_pca_messages(a, lambda **kw: None)
    create(messages=[{"role": "user", "content": [{"type": "text", "text": "hi"}]}])
    assert origins(rec)[-1] == ("principal", "user")


def test_langchain_and_llamaindex_wrappers_record_input():
    a, rec = make_prov_agent()
    got = []

    class Runnable:
        def invoke(self, input, config=None):
            got.append(input)
            return "r"
    w = with_pca_agent(a, Runnable())
    assert w.invoke({"input": "what is up"}) == "r" and got == [{"input": "what is up"}]
    assert origins(rec) == [("principal", "user")]

    class Engine:
        def chat(self, message, chat_history=None):
            return message
    e = with_pca_engine(a, Engine())
    assert e.chat("hello", chat_history=[{"role": "user", "content": "earlier"}]) == "hello"
    assert [o for o, _ in origins(rec)] == ["principal", "principal", "principal"]


def test_record_helpers_without_recorder_do_nothing():
    a = make_agent()
    record_messages(a, [{"role": "user", "content": "x"}])
    record_input(a, "x")
    assert with_principal_input(a, lambda x: x + 1)(1) == 2
