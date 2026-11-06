"""Reviewer acceptance for the ``authorize`` pipeline (0.5, the default) in this adapter.

Signed fixtures from the TypeScript reference (sdks/python-pca/testdata/authorize-fixtures.json): a $100 grant
(envelope ``max_spend``). In authorize mode a validly signed $400 call, a $50 proof used for a $400 call, a proof for
one tool used on another, a replay and a revoked grant are all refused before the tool runs; a guard built without
``authorize`` options refuses, and ``signature_only=True`` is the explicit opt-in to the core checks only.
"""
import json
import os

import pytest

from atlas_pca import AuthorizeOptions, MemoryStateStore
from atlas_pca.pca import b64u
from prov_harness import PIN, prov_header, recorder

_FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "testdata",
                    "authorize-fixtures.json")
with open(_FIX, encoding="utf-8") as _f:
    FIX = json.load(_f)
NOW, AUD = FIX["now"], FIX["audience"]
GRANTS = {c["grant"]["id"]: c["grant"] for c in FIX["cases"]}


def _proof(name):
    return next(c for c in FIX["cases"] if c["name"] == name)["steps"][0]["pcactn"]


P50, P400 = _proof("envelope-max-spend-within"), _proof("envelope-max-spend-400-refused")
SEND, REFUND = "payments.send:payments/acme", "payments.refund:payments/acme"
A50, A400 = {"amount": 50, "currency": "usd"}, {"amount": 400, "currency": "usd"}


def opts(revoked=False, store=True):
    # provenance by default stays on: the harness mediator is pinned and each call presents its principal-direct bundle
    return AuthorizeOptions(state_store=MemoryStateStore() if store else None, is_revoked=lambda p, g: revoked,
                            provenance_mediators=[PIN])


def resolve(ref):
    return GRANTS.get(ref)

from atlas_pca_fastmcp import pca_guard


def op_of(require, args):
    verb, resource = require.split(":", 1)
    return {"verb": verb, "resource": resource, "params": dict(args)}


def make(require, authorize, calls, resolve_grant=resolve, signature_only=False, recorder=None, labelled=True):
    kw = {"authorize": authorize} if authorize is not None else {}
    kw["signature_only"] = signature_only
    mw = pca_guard(audience=AUD, resolve_grant=resolve_grant, now=NOW, tool_capability={"pay": require},
                   recorder=recorder, **kw)

    def call(proof, args):
        meta = {"PCA-Action": proof}
        if labelled and recorder is None:  # the agent's principal-direct bundle rides next to the proof
            meta.update(prov_header(op_of(require, args)))
        d = mw.decide("pay", meta=meta, arguments=dict(args))
        if d.allow:
            calls.append(args)
        return d.allow, d.reason
    return call


def test_proof_in_arguments_is_not_a_param():
    calls = []
    mw = pca_guard(audience=AUD, resolve_grant=resolve, now=NOW, tool_capability={"pay": SEND}, authorize=opts())
    d = mw.decide("pay", arguments=dict(A50, **{"PCA-Action": P50}, **prov_header(op_of(SEND, A50))))
    assert d.allow is True and d.authorization.operation.verb == "payments.send"


def test_wildcard_capability_refused():
    mw = pca_guard(audience=AUD, resolve_grant=resolve, now=NOW, tool_capability={"pay": "payments.send:payments/*"},
                   authorize=opts())
    d = mw.decide("pay", meta={"PCA-Action": P50}, arguments=dict(A50))
    assert d.allow is False and d.reason.startswith("operation: the tool declares no capability")


def test_400_under_100_refused_before_the_tool_runs():
    calls = []
    call = make(SEND, opts(), calls)
    assert call(P400, A400) == (False, "policy: caveat(s) not satisfied: max_spend")
    assert calls == []


def test_default_without_authorize_options_refuses_with_authorize_config():
    calls = []
    ok, reason = make(SEND, None, calls)(P50, A50)
    assert (ok, calls) == (False, [])
    assert reason == "authorize_config: missing required component(s): state_store, is_revoked (fail closed)"


def test_signature_only_verifies_the_signature_only():
    calls = []
    call = make(SEND, None, calls, signature_only=True)  # core checks only: the signature is valid, so $400 runs
    assert call(P400, A400) == (True, None)
    assert calls == [A400]


def test_signature_only_and_authorize_together_is_a_construction_error():
    with pytest.raises(ValueError):
        make(SEND, opts(), [], signature_only=True)


def test_signed_50_used_for_400_refused():
    calls = []
    ok, reason = make(SEND, opts(), calls)(P50, A400)
    assert (ok, calls) == (False, [])
    assert reason == "operation: the proof's params_digest does not match the params of this payments.send operation"


def test_proof_for_x_used_for_y_refused():
    calls = []
    ok, reason = make(REFUND, opts(), calls)(P50, A50)
    assert (ok, calls) == (False, [])
    assert reason.startswith("operation: the proof is for payments.send on payments/acme")


def test_replay_refused():
    calls = []
    call = make(SEND, opts(), calls)
    assert call(P50, A50) == (True, None)
    ok, reason = call(P50, A50)
    assert (ok, reason) == (False, "replay: 1 is not greater than last seen 1 (replay)")
    assert calls == [A50]


def test_revoked_refused():
    calls = []
    assert make(SEND, opts(revoked=True), calls)(P50, A50) == (False, "revocation: the grant is revoked")
    assert calls == []


def test_missing_store_refused():
    calls = []
    ok, reason = make(SEND, opts(store=False), calls)(P50, A50)
    assert (ok, calls) == (False, [])
    assert reason == "authorize_config: missing required component(s): state_store (fail closed)"


def test_authorize_needs_resolve_grant_not_verifier():
    with pytest.raises(ValueError):
        make(SEND, opts(), [], resolve_grant=None)


# ---- provenance by default ----------------------------------------------------------------------------------------------

def test_tool_derived_argument_on_a_sensitive_call_does_not_allow():
    """The amount came from a tool result, not from the principal: the call escalates and the tool never runs."""
    rec = recorder()
    rec.principal("pay the invoice from my inbox")
    rec.tool("inbox.read", "Invoice: amount 50 currency usd")
    meta = {"PCA-Action": P50, "PCA-Provenance": b64u(json.dumps(rec.for_action(op_of(SEND, A50))).encode("utf-8"))}
    d = pca_guard(audience=AUD, resolve_grant=resolve, now=NOW, tool_capability={"pay": SEND},
                  authorize=opts()).decide("pay", meta=meta, arguments=dict(A50))
    assert (d.allow, d.authorization.decision) == (False, "escalate")
    assert d.reason == ("provenance_flow: escalate: the choice of payments.send derives from untrusted content; amount, "
                      "currency derive from untrusted content [tool:inbox.read]: the principal must confirm "
                      "(prompt-injection path)")


def test_unlabelled_sensitive_call_does_not_allow():
    calls = []
    ok, reason = make(SEND, opts(), calls, labelled=False)(P50, A50)
    assert (ok, calls) == (False, [])
    assert reason.startswith("provenance_flow: escalate:") and "[unlabelled]" in reason


def test_unreadable_bundle_is_refused():
    d = pca_guard(audience=AUD, resolve_grant=resolve, now=NOW, tool_capability={"pay": SEND}, authorize=opts()).decide(
        "pay", meta={"PCA-Action": P50, "PCA-Provenance": "%%%"}, arguments=dict(A50))
    assert (d.allow, d.reason) == (False, "provenance_flow: the provenance bundle is unreadable (fail closed)")


def test_recorder_builds_the_bundle_and_records_the_result():
    """An in-process agent's recorder: its bundle allows, the bundle key never reaches the tool, and the tool's result
    lands in the chain as untrusted tool output."""
    import asyncio
    from types import SimpleNamespace

    rec = recorder()
    rec.principal("send 50 usd")
    mw = pca_guard(audience=AUD, resolve_grant=resolve, now=NOW, tool_capability={"pay": SEND}, authorize=opts(),
                   recorder=rec)
    args = dict(A50)
    seen = []

    async def call_next(ctx):
        seen.append(dict(ctx.message.arguments))
        return "paid"

    ctx = SimpleNamespace(message=SimpleNamespace(name="pay", arguments=args, meta={"PCA-Action": P50}))
    assert asyncio.run(mw.on_call_tool(ctx, call_next)) == "paid"
    assert seen == [A50]
    last = rec.receipts()[-1]
    assert (last["origin"], last["source"]) == ("tool", "pay")


# ---- the README sample runs as written ---------------------------------------------------------------------------------

def _readme_sample():
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "README.md"), encoding="utf-8") as fh:
        text = fh.read()
    section = text[text.index("## Full authorization"):]
    return section.split("```python\n", 1)[1].split("```", 1)[0]


def test_readme_sample_runs(tmp_path, monkeypatch):
    import time

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(time, "time", lambda: NOW / 1000)  # the sample runs on the wall clock; the fixtures are dated
    env = {"resolve": resolve, "is_revoked": lambda p, g: False, "agent_mediator_pin": PIN}
    exec(compile(_readme_sample(), "README.md", "exec"), env)  # noqa: S102
    meta = {"PCA-Action": P50, **prov_header(op_of(SEND, A50))}  # the agent sends its provenance bundle with the proof
    assert env["guard"].decide("send_payment", meta=meta, arguments=dict(A50)).allow is True
    assert env["guard"].decide("send_payment", meta=meta, arguments=dict(A50)).allow is False  # replay
