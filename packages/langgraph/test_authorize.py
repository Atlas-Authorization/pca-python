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
    return AuthorizeOptions(state_store=MemoryStateStore() if store else None, is_revoked=lambda p, g: revoked)


def resolve(ref):
    return GRANTS.get(ref)

from atlas_pca_langgraph import PcaToolDenied, PcaToolNode, pca_tool


def make(require, authorize, calls, resolve_grant=resolve, signature_only=False):
    def pay(amount, currency):
        calls.append({"amount": amount, "currency": currency})
        return "paid"

    kw = {"authorize": authorize} if authorize is not None else {}
    kw["signature_only"] = signature_only
    tool = pca_tool(require, audience=AUD, resolve_grant=resolve_grant, now=NOW, **kw)(pay)

    def call(proof, args):
        try:
            tool.run(pca_action=proof, **args)
            return True, None
        except PcaToolDenied as e:
            return False, e.decision.reason
    return call


def test_tool_node_authorize():
    calls = []

    def pay(amount, currency):
        calls.append(amount)
        return "paid"

    pay.name = "pay"
    node = PcaToolNode([pay], audience=AUD, require=SEND, resolve_grant=resolve, now=NOW, authorize=opts())

    def run(proof, args):
        state = {"messages": [{"tool_calls": [{"name": "pay", "args": args, "id": "c1"}]}], "PCA-Action": proof}
        msg = node(state)["messages"][0]
        return msg.status, msg.content

    assert run(P400, A400) == ("error", "policy: caveat(s) not satisfied: max_spend")
    assert run(P50, A50) == ("success", "paid")
    assert run(P50, A50)[0] == "error"  # replay
    assert calls == [50]


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
    env = {"resolve": resolve, "is_revoked": lambda p, g: False}
    exec(compile(_readme_sample(), "README.md", "exec"), env)  # noqa: S102
    assert env["send_payment"].run(pca_action=P50, **A50) == "sent 50 usd"
    with pytest.raises(PcaToolDenied):
        env["send_payment"].run(pca_action=P50, **A50)  # replay
