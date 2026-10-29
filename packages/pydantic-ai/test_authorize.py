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
from prov_harness import PIN, bundle_for, recorder

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

from atlas_pca_pydantic_ai import PCADeps, PCARejected, pca_tool


class Ctx:
    def __init__(self, deps):
        self.deps = deps


def make(require, authorize, calls, resolve_grant=resolve, signature_only=False, recorder=None, labelled=True):
    def pay(ctx: "RunContext", amount, currency):  # noqa: F821
        calls.append({"amount": amount, "currency": currency})
        return "paid"

    kw = {"authorize": authorize} if authorize is not None else {}
    if signature_only and authorize is None:  # the core verifier's clock: the fixtures are dated
        from atlas_pca_pydantic_ai.verifier import CoreVerifier
        tool = pca_tool(require, audience=AUD, verifier=CoreVerifier(resolve_grant=resolve_grant, now=NOW),
                        signature_only=True)(pay)
    else:
        tool = pca_tool(require, audience=AUD, resolve_grant=resolve_grant, now=NOW, signature_only=signature_only,
                        recorder=recorder, **kw)(pay)

    def call(proof, args):
        verb, resource = require.split(":", 1)
        # the host puts the proof and the agent's principal-direct provenance bundle on the run's deps
        bundle = bundle_for({"verb": verb, "resource": resource, "params": dict(args)}) \
            if labelled and recorder is None else None
        try:
            tool(Ctx(PCADeps(pca_action=proof, pca_provenance=bundle)), **args)
            return True, None
        except PCARejected as e:
            return False, e.decision.reason
    return call


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
    calls = []
    ok, reason = make(SEND, opts(), calls, recorder=rec)(P50, A50)
    assert (ok, calls) == (False, [])
    assert reason == ("provenance_flow: escalate: the choice of payments.send derives from untrusted content; amount, "
                      "currency derive from untrusted content [tool:inbox.read]: the principal must confirm "
                      "(prompt-injection path)")


def test_unlabelled_sensitive_call_does_not_allow():
    calls = []
    ok, reason = make(SEND, opts(), calls, labelled=False)(P50, A50)
    assert (ok, calls) == (False, [])
    assert reason.startswith("provenance_flow: escalate:") and "[unlabelled]" in reason


def test_recorder_builds_the_bundle_and_records_the_result():
    """Principal input only: the recorder's bundle allows, and the result lands in the chain as untrusted tool output."""
    rec = recorder()
    rec.principal("send 50 usd")
    calls = []
    assert make(SEND, opts(), calls, recorder=rec)(P50, A50) == (True, None)
    assert calls == [A50]
    last = rec.receipts()[-1]
    assert (last["origin"], last["source"]) == ("tool", "payments.send")


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
    from prov_harness import SEED

    env = {"resolve": resolve, "is_revoked": lambda p, g: False, "mediator_seed": SEED}
    exec(compile(_readme_sample(), "README.md", "exec"), env)  # noqa: S102
    env["recorder"].principal("Send 50 usd")  # what the principal asked for, recorded by the agent harness
    assert env["send_payment"](Ctx(PCADeps(pca_action=P50)), **A50) == "sent 50 usd"
    with pytest.raises(PCARejected):
        env["send_payment"](Ctx(PCADeps(pca_action=P50)), **A50)  # replay
