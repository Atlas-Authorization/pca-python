"""The undo-window coordinator (atlas_pca.undo_coordinator): admission, the durable record, the one-click veto, the compensation at most
once, finalization, and every fail-closed refusal. Hand-written (no shared corpus exists for the coordinator in any language)."""
import pytest

from atlas_pca.agent import DEFAULT_RISK_POLICY, Agent, keypair_from_seed, mint_grant
from atlas_pca.operations import MemoryOperationStore
from atlas_pca.undo import UndoError
from atlas_pca.undo_coordinator import KvUndoStore, MemoryUndoStore, create_undo_coordinator, report_undo_effect
from atlas_pca.atomic_kv import MemoryAtomicKv

P = keypair_from_seed(b"\x01" * 32, allow_insecure_signer=True)
H = keypair_from_seed(b"\x02" * 32, allow_insecure_signer=True)
D43 = "A" * 43
ENV = {"predicates": [{"verb": "pay", "resource": "invoice:*"}, {"verb": "pay.refund", "resource": "invoice:*"}], "caveats": [],
       "risk_policy": DEFAULT_RISK_POLICY}
GRANT = mint_grant(P, H.public, ENV, "pay invoices", salt="s")["grant"]
OP = {"verb": "pay", "resource": "invoice:1", "params": {"amount": 5}}


class Engine:
    def plan(self, op, ctx):
        return {"def_digest": D43, "compensation": {"verb": "pay.refund", "params": {}, "def_digest": D43, "target_param": "payment"}}


class Notifier:
    def __init__(self, deliver=True):
        self.deliver, self.notices = deliver, []

    def notify(self, n):
        self.notices.append(n)
        return {"delivered": self.deliver} if self.deliver else {"delivered": False, "reason": "no channel"}


def build(clock, notifier=None, store=None, engine=None, **kw):
    calls, alerts = [], []
    c = create_undo_coordinator(store=store or MemoryUndoStore(), engine=engine or Engine(), signerSecret=b"\x09" * 32, audience="rs",
                                resolveGrant=lambda ref, pc: GRANT, compensate=lambda call: calls.append(call) or {"refund": "r1"},
                                operations=MemoryOperationStore(), notifier=notifier or Notifier(), alert=alerts.append,
                                now=lambda: clock[0], insecureVolatileStore=True, **kw)
    return c, calls, alerts


def action(cls=None):
    extra = {} if cls is None else {"reversibility_class": cls}
    return Agent(H, GRANT, "rs", clock=lambda: 1_000).act("pay", "invoice:1", {"amount": 5}, **extra).pcactn


def test_veto_with_the_token_compensates_once():
    clock = [1_000]
    c, calls, alerts = build(clock)
    adm = c.admit(action(), OP, False, GRANT)
    assert "refused" not in adm
    info = c.open(adm)
    assert info["obligation"]["kind"] == "undo_window" and c.get(adm["id"])["state"] == "open"
    c.record_effect(adm["id"], {"id": "pay_1"}, True)
    clock[0] = 2_000
    v = c.veto(adm["id"], token=info["token"])
    assert v["ok"] is True and v["record"]["state"] == "compensated" and v["replayed"] is False
    assert [x["operation"]["params"] for x in calls] == [{"payment": "pay_1"}]
    again = c.veto(adm["id"], token=info["token"])  # the same veto is a replay: the compensation never runs twice
    assert again["ok"] is True and again["replayed"] is True and len(calls) == 1 and alerts == []


def test_a_token_for_another_record_or_after_the_window_is_refused():
    clock = [1_000]
    c, calls, _ = build(clock)
    adm = c.admit(action(), OP, False, GRANT)
    info = c.open(adm)
    assert c.veto(adm["id"], token="not a token")["ok"] is False
    clock[0] = adm["window_end"] + 1
    late = c.veto(adm["id"], token=info["token"])
    assert late["ok"] is False and calls == []


def test_finalize_closes_the_window_and_alerts_an_unreported_effect():
    clock = [1_000]
    c, calls, alerts = build(clock)
    adm = c.admit(action(), OP, False, GRANT)
    c.open(adm)
    assert c.finalize_due() == []  # the window is still open
    clock[0] = adm["window_end"] + 5
    assert c.finalize_due() == [adm["id"]] and c.get(adm["id"])["state"] == "finalized"
    assert [a["code"] for a in alerts] == ["effect_unknown"] and calls == []


def test_a_window_nobody_was_told_about_is_aborted():
    clock = [1_000]
    c, _, alerts = build(clock, notifier=Notifier(deliver=False))
    adm = c.admit(action(), OP, False, GRANT)
    with pytest.raises(UndoError):
        c.open(adm)
    assert c.get(adm["id"])["state"] == "finalized" and alerts[0]["code"] == "notify_failed" and alerts[0]["level"] == "critical"


def test_admission_refuses_what_is_not_confirmed_reversible():
    clock = [1_000]
    c, _, _ = build(clock)
    assert c.admit(action("irreversible"), OP, False, GRANT)["refused"].startswith("the signed class is irreversible")
    none, _, _ = build(clock, engine=type("E", (), {"plan": staticmethod(lambda op, ctx: None)})())
    assert "not confirmed reversible" in none.admit(action(), OP, False, GRANT)["refused"]
    off, _, _ = build(clock, policy=lambda op, grant: {"mode": "off"})
    assert off.admit(action(), OP, False, GRANT)["refused"] == "policy: undo windows are off"
    only_esc, _, _ = build(clock, policy=lambda op, grant: {"mode": "escalations"})
    assert "windows only replace approvals" in only_esc.admit(action(), OP, False, GRANT)["refused"]
    assert "refused" not in only_esc.admit(action(), OP, True, GRANT)


def test_a_compensation_the_grant_does_not_allow_is_refused():
    clock = [1_000]

    class Wide:
        def plan(self, op, ctx):
            return {"def_digest": D43, "compensation": {"verb": "admin.delete", "params": {}, "def_digest": D43}}
    c, _, _ = build(clock, engine=Wide())
    assert "not authorized under the grant" in c.admit(action(), OP, False, GRANT)["refused"]


def test_a_volatile_store_and_missing_components_fail_closed():
    base = dict(store=MemoryUndoStore(), engine=Engine(), signerSecret=b"\x09" * 32, audience="rs", resolveGrant=lambda r, p: GRANT,
                compensate=lambda c: None, operations=MemoryOperationStore(), notifier=Notifier(), alert=lambda a: None)
    with pytest.raises(UndoError) as e:
        create_undo_coordinator(**base)
    assert e.value.code == "not_durable"
    with pytest.raises(UndoError) as e2:
        create_undo_coordinator(**dict(base, audience=""))
    assert e2.value.code == "config"


def test_the_kv_store_and_effect_reporting():
    clock = [1_000]
    c, calls, _ = build(clock, store=KvUndoStore(MemoryAtomicKv(), False))
    adm = c.admit(action(), OP, False, GRANT)
    info = c.open(adm)
    assert c.get(adm["id"])["ver"] == 0
    rec = report_undo_effect(c, adm["id"], {"status": "committed", "result": {"id": "p9"}})
    assert rec["effect"]["result"] == {"id": "p9"}
    assert c.veto(adm["id"], operator="ops")["record"]["state"] == "compensated" and calls[0]["operation"]["params"] == {"payment": "p9"}
    assert info["id"] == adm["id"]


def test_approval_channels_and_the_undo_notifier():
    from types import SimpleNamespace
    from atlas_pca.approval_channels import (build_slack_message, create_approval_dispatcher, slack_approval_channel, text_approval_channel,
                                             webhook_approval_channel)
    from atlas_pca.undo_coordinator import undo_notifier_from_dispatcher
    sent, texts = [], []
    ok = lambda url, init: sent.append((url, init)) or SimpleNamespace(ok=True, status=200)  # noqa: E731
    d = create_approval_dispatcher([slack_approval_channel("https://hooks.example/s", ok), webhook_approval_channel(None, ok),
                                    text_approval_channel("email", texts.append)])
    clock = [1_000]
    notifier = undo_notifier_from_dispatcher(d, lambda token, id_: "https://rs.example/undo?t=%s&id=%s" % (token, id_))
    c, _, _ = build(clock, notifier=notifier)
    adm = c.admit(action(), OP, False, GRANT)
    info = c.open(adm)
    assert len(sent) == 1 and sent[0][0] == "https://hooks.example/s" and len(texts) == 1  # the disabled webhook channel is skipped
    assert info["token"] in sent[0][1]["body"] and "Already done: pay on invoice:1" in texts[0]["text"]
    down = create_approval_dispatcher([slack_approval_channel("https://hooks.example/s", lambda u, i: SimpleNamespace(ok=False, status=500))])
    out = down.notify_all({"id": "r", "verb": "v", "resource": "x", "tier": 3, "reason": "why", "r": 0, "lineage": {"because": "b", "chain": []}})
    assert out[0]["delivered"] is False and out[0]["reason"] == "slack webhook returned 500"
    assert build_slack_message({"id": "r", "verb": "v", "resource": "x", "tier": 3, "reason": "why", "r": 0,
                                "lineage": {"because": "b", "chain": []}}, {"inboxUrl": "https://i.example/a#frag"})["blocks"][-1]["elements"][0]["url"] \
        == "https://i.example/a?stepup=r&decision=approve#frag"


def _released_event(budget):
    from atlas_pca.budget_ledger import KvBudgetLedger
    clock = [1_000]
    ledger = KvBudgetLedger(MemoryAtomicKv(), True)
    c, calls, _ = build(clock, budget=budget(ledger))
    adm = c.admit(action(), OP, False, GRANT)
    c.open(adm)
    ev = {"id": adm["id"], "verb": "pay", "resource": "invoice:1", "params": {}, "t": 1_000}
    assert ledger.reserve("principal/p", {"event": ev, "accumulators": []})["outcome"] == "reserved"
    c.hold_budget(adm["id"], [{"key": "principal/p", "id": adm["id"]}])
    c.record_effect(adm["id"], {"id": "pay_1"}, True)
    v = c.veto(adm["id"], operator="ops")
    assert v["record"]["state"] == "compensated" and calls
    return ledger.snapshot("principal/p")["events"][0]


def test_a_release_carries_no_evidence_unless_the_caller_supplies_it():
    event = _released_event(lambda ledger: ledger)
    assert event["status"] == "released" and "rel" not in event


def test_the_callers_release_evidence_is_what_the_ledger_stores():
    from atlas_pca.agent import KeyPair
    from atlas_pca.budget_ledger import sign_release, verify_release
    signer = KeyPair(b"\x09" * 32)
    seen = []

    def evidence(r, how):
        seen.append((r["key"], how))
        return sign_release(r["key"], r["id"], how, 1_000, signer)

    event = _released_event(lambda ledger: {"ledger": ledger, "evidence": evidence})
    assert seen == [("principal/p", "rollback")]
    assert event["status"] == "released" and verify_release(event["rel"], signer.public) and event["rel"]["reason"] == "rollback"


def test_rollback_on_slash_needs_a_bond_ledger():
    c, _, _ = build([1_000])
    with pytest.raises(UndoError) as e:
        c.rollback_on_slash({"claimId": "x"})
    assert e.value.code == "config"
