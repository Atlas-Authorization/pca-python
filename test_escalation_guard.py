"""authorize(): an escalate decision is surfaced distinctly, refused without an answer, admitted only by a bound principal
answer (spent by the replay counter), and never upgraded from a deny (goal-to-decision T2, contract C-50 / C-51)."""
import json
import os

import pytest

import sys

from atlas_pca import MemoryStateStore, SqliteStateStore, authorize

az = sys.modules["atlas_pca.authorize"]  # the module (the package attribute `authorize` is the function)
from atlas_pca.escalation import (ESCALATION_ANSWER_DOMAIN, escalation_action_digest, escalation_history_head,
                                  escalation_policy_digest)
from atlas_pca.pca import Verdict, b64u, canonical_bytes_strict, decode_b64u_strict

ed = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = json.load(open(os.path.join(HERE, "testdata", "authorize-fixtures.json"), encoding="utf-8"))
KEYS = json.load(open(os.path.join(HERE, "conformance", "keys.json"), encoding="utf-8"))
SK = ed.Ed25519PrivateKey.from_private_bytes(decode_b64u_strict(KEYS["principal"]["seed"], 32))
PUB = KEYS["principal"]["public"]
NOW, AUD = FIX["now"], FIX["audience"]
CASE = next(c for c in FIX["cases"] if c["steps"][0]["expect"]["allow"] is True and len(c["steps"]) == 1)


def _inject(monkeypatch, checks, reason, reasons=None):
    real = az.verify_pcactn_core

    def fake(*a, **k):
        v = real(*a, **k)
        return Verdict(False, {**v.checks, **{c: False for c in checks}}, reason, list(reasons or []))

    monkeypatch.setattr(az, "verify_pcactn_core", fake)


def _run(store, answer=None, principals=(PUB,), step=None):
    s = step or CASE["steps"][0]
    return authorize(s["pcactn"], operation=s["operation"], audience=AUD, resolve_grant=lambda ref: CASE["grant"],
                     state_store=store, is_revoked=lambda p, g: False, now=NOW, plan="single-step",
                     escalation_principals=list(principals), escalation_answer=answer, insecure_unbound_approval=True)


def _answer(last=None, **o):
    s = CASE["steps"][0]
    body = {"v": 1, "kind": "pca-escalation-answer", "principal": PUB, "policy_digest": escalation_policy_digest(CASE["grant"]),
            "action_digest": escalation_action_digest(s["pcactn"]), "history_head": escalation_history_head(last), "decision": "allow",
            "iat": NOW, "expires_at": NOW + 600_000, "nonce": b64u(bytes([9]) * 16)}
    body.update(o)
    return {**body, "sig": b64u(SK.sign(ESCALATION_ANSWER_DOMAIN.encode() + canonical_bytes_strict(body)))}


def test_baseline_is_allow():
    r = _run(MemoryStateStore())
    assert (r.allow, r.decision, r.escalation) == (True, "allow", None)


def test_escalate_without_answer_is_refused_and_surfaced(monkeypatch):
    _inject(monkeypatch, ["provenance"], "provenance: intent_required: a question is required")
    r = _run(MemoryStateStore())
    assert (r.allow, r.decision, r.status) == (False, "escalate", 403)
    assert r.escalation["kind"] == "pca-escalation-request" and r.escalation["verb"] == CASE["steps"][0]["operation"]["verb"]
    assert r.checks["provenance"] == "fail"


def test_hard_failure_is_deny_not_escalate(monkeypatch):
    _inject(monkeypatch, ["provenance", "leaf_signature"], "provenance: intent_required: q")
    r = _run(MemoryStateStore())
    assert (r.allow, r.decision, r.escalation) == (False, "deny", None)


@pytest.mark.parametrize("make_store", [MemoryStateStore, lambda: SqliteStateStore(":memory:")])
def test_valid_answer_admits_once_and_the_counter_spends_it(monkeypatch, make_store):
    _inject(monkeypatch, ["provenance"], "provenance: intent_required: q")
    store = make_store()
    a = _answer()
    r = _run(store, a)
    assert (r.allow, r.decision) == (True, "allow")
    assert r.escalation == {"answered_by": PUB}
    again = _run(store, _answer(last=CASE["steps"][0]["pcactn"]["counter"]))
    assert again.allow is False and again.checks["replay"] == "fail"


def test_bad_answers_stay_escalate(monkeypatch):
    _inject(monkeypatch, ["provenance"], "provenance: intent_required: q")
    for ans in [_answer(decision="deny"), _answer(policy_digest=b64u(bytes(32))), _answer(action_digest=b64u(bytes(32))),
                _answer(history_head=escalation_history_head(99)), _answer(expires_at=NOW - 1, iat=NOW - 5), {"junk": 1}]:
        r = _run(MemoryStateStore(), ans)
        assert (r.allow, r.decision) == (False, "escalate")
    assert _run(MemoryStateStore(), _answer(), principals=[KEYS["rogue"]["public"]]).allow is False
    assert _run(MemoryStateStore(), _answer(), principals=[]).allow is False


def test_answer_never_upgrades_a_deny(monkeypatch):
    _inject(monkeypatch, ["provenance", "leaf_signature"], "provenance: intent_required: q")
    r = _run(MemoryStateStore(), _answer())
    assert (r.allow, r.decision) == (False, "deny")


def test_store_without_last_is_a_configuration_error(monkeypatch):
    _inject(monkeypatch, ["provenance"], "provenance: intent_required: q")

    class Bare:
        def __init__(self):
            self.m = MemoryStateStore()

        def claim(self, key, counter):
            return self.m.claim(key, counter)

    r = _run(Bare(), _answer())
    assert (r.allow, r.decision, r.status) == (False, "deny", 403)
    assert r.checks == {"authorize_config": "fail"} and r.missing == ["state_store.last (required by escalation_principals)"]
    from atlas_pca import AuthorizeOptions
    with pytest.raises(ValueError, match="last"):
        AuthorizeOptions(state_store=Bare(), is_revoked=lambda p, g: False, escalation_principals=[PUB])
    AuthorizeOptions(state_store=Bare(), is_revoked=lambda p, g: False)  # no escalation: a store without last is fine


def test_multi_check_escalation_is_an_escalation(monkeypatch):
    # three failing checks, every one escalate-class, the core carries all three reasons (the fold of the v2 pipeline)
    rs = ["provenance: intent_required: q1", "facts: intent_required: q2", "classes: escalate: q3"]
    _inject(monkeypatch, ["provenance", "facts", "classes"], rs[0], rs)
    r = _run(MemoryStateStore())
    assert (r.allow, r.decision) == (False, "escalate")
    assert r.escalation["reasons"] == rs and r.reasons[:3] == rs
    ok = _run(MemoryStateStore(), _answer())
    assert (ok.allow, ok.decision) == (True, "allow")  # one answer upgrades every escalate-class failure at once
    assert all(v != "fail" for v in ok.checks.values())


def test_multi_check_with_one_hard_failure_is_a_deny(monkeypatch):
    rs = ["provenance: intent_required: q1", "facts: intent_required: q2", "classes: class receipt does not verify"]
    _inject(monkeypatch, ["provenance", "facts", "classes"], rs[0], rs)
    r = _run(MemoryStateStore(), _answer())
    assert (r.allow, r.decision, r.escalation) == (False, "deny", None)
    assert r.reasons[:3] == rs


def test_a_failing_check_with_no_reason_of_its_own_is_a_deny(monkeypatch):
    _inject(monkeypatch, ["provenance", "facts"], "provenance: intent_required: q", ["provenance: intent_required: q"])
    r = _run(MemoryStateStore(), _answer())
    assert (r.allow, r.decision) == (False, "deny")


def test_require_pca_guard_surfaces_escalate_and_reads_the_answer_header(monkeypatch):
    from atlas_pca import AuthorizeOptions, require_pca
    from atlas_pca.pca import b64u as enc

    _inject(monkeypatch, ["provenance"], "provenance: intent_required: q")
    s = CASE["steps"][0]
    guard = require_pca(audience=AUD, resolve_grant=lambda ref: CASE["grant"], now=NOW,
                        authorize=AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=lambda p, g: False,
                                                   escalation_principals=[PUB], insecure_unbound_approval=True),
                        operation=lambda h, b: s["operation"])
    hdr = {"PCA-Action": enc(json.dumps(s["pcactn"]).encode())}
    r = guard(hdr, None)
    assert (r.ok, r.decision, r.status) == (False, "escalate", 403)
    assert r.escalation["kind"] == "pca-escalation-request"
    assert "escalat" not in (r.www_authenticate or "").lower()
    ok = guard({**hdr, "PCA-Escalation-Answer": enc(json.dumps(_answer()).encode())}, None)
    assert (ok.ok, ok.decision) == (True, "allow")


# ---- K7: an answer is bound to the canonical approval render -------------------------------------------------------------
RD, RD2 = b64u(bytes([5]) * 32), b64u(bytes([6]) * 32)


def _run_render(store, answer=None, render=None, require=True):
    s = CASE["steps"][0]
    return authorize(s["pcactn"], operation=s["operation"], audience=AUD, resolve_grant=lambda ref: CASE["grant"],
                     state_store=store, is_revoked=lambda p, g: False, now=NOW, plan="single-step",
                     escalation_principals=[PUB], escalation_answer=answer, escalation_render=render, insecure_unbound_approval=not require)


def test_render_bound_answer_admits_and_the_request_carries_the_digest(monkeypatch):
    _inject(monkeypatch, ["provenance"], "provenance: intent_required: q")
    asked = _run_render(MemoryStateStore(), None, lambda p: RD)
    assert asked.decision == "escalate" and asked.escalation["render_digest"] == RD
    r = _run_render(MemoryStateStore(), _answer(render_digest=RD), lambda p: RD)
    assert (r.allow, r.decision) == (True, "allow")


def test_render_mismatch_missing_unchecked_and_required(monkeypatch):
    _inject(monkeypatch, ["provenance"], "provenance: intent_required: q")
    assert _run_render(MemoryStateStore(), _answer(render_digest=RD2), lambda p: RD).allow is False
    assert _run_render(MemoryStateStore(), _answer(), lambda p: RD).allow is False  # an answer for no render
    assert _run_render(MemoryStateStore(), _answer(render_digest=RD)).allow is False  # a render the verifier did not recompute
    assert _run_render(MemoryStateStore(), _answer(), lambda p: None, require=True).allow is False
    assert _run_render(MemoryStateStore(), _answer(render_digest=RD), lambda p: (_ for _ in ()).throw(RuntimeError("def unknown")), require=True).allow is False


def test_unbound_approval_is_refused_by_default(monkeypatch):
    _inject(monkeypatch, ["provenance"], "provenance: intent_required: q")
    s = CASE["steps"][0]
    kw = dict(operation=s["operation"], audience=AUD, resolve_grant=lambda ref: CASE["grant"], is_revoked=lambda p, g: False, now=NOW,
              plan="single-step", escalation_principals=[PUB], escalation_answer=_answer())
    assert authorize(s["pcactn"], state_store=MemoryStateStore(), **kw).allow is False
    assert authorize(s["pcactn"], state_store=MemoryStateStore(), insecure_unbound_approval=True, **kw).allow is True
