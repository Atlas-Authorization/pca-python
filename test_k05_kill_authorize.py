"""k05 mutation kill (group authorize): the replay stores, the envelope readers, the tool-schema checker, the assurance report
and labels, and the _authorize pipeline seams (argument forwarding, defaults, workflow / plan registry / escalation / undo /
provenance wiring). Strings and limits are the TypeScript reference's (agent-native.ts, envelope.ts, risk.ts,
require-pca.ts); the refusal texts with no TypeScript counterpart are this SDK's documented ones."""
import copy
import importlib
import inspect
import json
import os
import types
from collections import UserDict

import pytest

from atlas_pca.caveat_lang import K1_CAVEAT_TYPES
from atlas_pca.escalation import escalation_action_digest, escalation_history_head, escalation_policy_digest
from atlas_pca.pca import Verdict, hash_canonical
from atlas_pca.revocation_staleness import RevocationStaleness
from prov_harness import prov

Z = importlib.import_module("atlas_pca.authorize")

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "testdata", "authorize-fixtures.json"), encoding="utf-8") as _f:
    FIX = json.load(_f)
NOW, AUD = FIX["now"], FIX["audience"]
CASE = next(c for c in FIX["cases"] if c["name"] == "envelope-max-spend-within")
P0, OP, G = CASE["steps"][0]["pcactn"], CASE["steps"][0]["operation"], CASE["grant"]
HOLDER = P0["cap_chain"][-1]["holder"]
NODE = {"id": "n1", "verb": "payments.send", "resource": "payments/acme", "params_digest": P0["action"]["params_digest"],
        "reversibility_class": "irreversible"}
INNER = {"verb": "payments.send", "resource": "payments/acme", "params": OP["params"], "reversibility_class": "irreversible"}
PRED = {"verb": ["payments.send"], "resource": "payments/*"}


def run(**kw):
    p = kw.pop("pcactn", None)
    p = copy.deepcopy(P0) if p is None else p
    grant = kw.pop("grant", None)
    opts = dict(operation=OP, audience=AUD, resolve_grant=lambda ref: G if grant is None else grant,
                state_store=Z.MemoryStateStore(), is_revoked=lambda _p, _g: False, now=NOW, plan="single-step")
    opts.update(prov(OP))
    opts.update(kw)
    return Z.authorize(p, **opts)


def inject(monkeypatch):
    """The core accepts whatever PCActn is presented (to reach the pipeline stages behind it with odd shapes)."""
    base = Z.verify_pcactn_core(copy.deepcopy(P0), G, now=NOW, audience=AUD)
    v = Verdict(True, dict(base.checks), None, [])
    monkeypatch.setattr(Z, "verify_pcactn_core", lambda *a, **k: v)
    return v


def inject_escalate(monkeypatch):
    base = Z.verify_pcactn_core(copy.deepcopy(P0), G, now=NOW, audience=AUD)
    checks = dict(base.checks)
    checks["provenance"] = False
    reason = "provenance: intent_required: q"
    monkeypatch.setattr(Z, "verify_pcactn_core", lambda *a, **k: Verdict(False, dict(checks), reason, [reason]))


def grant_with(**env_over):
    g = copy.deepcopy(G)
    next(c for c in g["caveats"] if c.get("type") == "envelope").update(env_over)
    return g


def spy_on(monkeypatch, name, ret=None):
    calls = []
    real = getattr(Z, name)

    def f(*a, **k):
        calls.append((a, k))
        return real(*a, **k) if ret is None else ret

    monkeypatch.setattr(Z, name, f)
    return calls


# ---- the replay stores ---------------------------------------------------------------------------------------------------

def test_once_args_message():
    for args in (("", 10, 5), ("k", 4, 5)):
        with pytest.raises(ValueError) as e:
            Z._once_args(*args)
        assert str(e.value) == "consume_once: invalid key or retention horizon"
    Z._once_args("k", 5, 5)


class Recording(Z.StateStore):
    def __init__(self, ok=True):
        self.calls, self.ok = [], ok

    def claim(self, key, counter):
        self.calls.append((key, counter))
        return Z.ClaimResult(self.ok)


def test_base_consume_once_falls_back_to_claim_one():
    s = Recording()
    assert s.consume_once("k", 10, 5) is True
    assert s.calls == [("k", 1)]
    assert Recording(False).consume_once("k", 10, 5) is False
    s = Recording()
    for args in (("", 10, 5), ("k", 4, 5)):
        with pytest.raises(ValueError):
            s.consume_once(*args)
    assert s.calls == []


def test_memory_consume_once_keeps_a_record_that_expires_exactly_now():
    s = Z.MemoryStateStore()
    assert s.consume_once("A", 100, 50) is True
    assert s.consume_once("B", 200, 100) is True  # A's horizon equals now: still live, so not pruned
    assert s.consume_once("A", 300, 100) is False


def test_sqlite_timeout_default_and_connect_arguments(monkeypatch):
    assert inspect.signature(Z.SqliteStateStore.__init__).parameters["timeout"].default == 30.0
    seen, real = [], Z.sqlite3.connect

    def spy(*a, **k):
        seen.append((a, k))
        return real(*a, **k)

    monkeypatch.setattr(Z.sqlite3, "connect", spy)
    Z.SqliteStateStore(":memory:", timeout=7.5)
    assert seen == [((":memory:",), {"timeout": 7.5, "isolation_level": None})]


def test_sqlite_claim_conflict_without_a_row():
    class Cur:
        rowcount = 0

        def fetchone(self):
            return None

    class Conn:
        def execute(self, *_a):
            return Cur()

    s = Z.SqliteStateStore(":memory:")
    s._conn = lambda: Conn()
    assert s.claim("k", 1) == Z.ClaimResult(False, None)


# ---- the envelope ---------------------------------------------------------------------------------------------------------

def test_validate_risk_policy_array_shapes():
    assert Z._validate_risk_policy([]) == "risk_policy.weights missing"
    assert Z._validate_risk_policy({"weights": []}) == "risk_policy.weights.alpha must be finite and >= 0"


def test_read_envelope_needs_a_real_dict():
    assert Z.read_envelope(G) is not None
    assert Z.read_envelope(UserDict(G)) is None


def test_root_caveats_drops_only_the_first_envelope():
    a, b = {"type": "a"}, {"type": "envelope", "n": 2}
    g = {"caveats": ["junk", {"type": "envelope", "n": 1}, a, b]}
    assert Z.root_caveats(g) == ["junk", a, b]


def test_requires_attestation_min_measurement():
    assert Z._requires_attestation({"min_measurement": "abc"}) is True
    assert Z._requires_attestation({"min_measurement": ""}) is False
    assert Z._requires_attestation({}) is False


# ---- the tool-schema checker ----------------------------------------------------------------------------------------------

class Odd:
    def __eq__(self, other):
        return True

    __hash__ = None


def test_js_eq_string_vs_a_foreign_object():
    assert Z._js_eq("a", Odd()) is False
    assert Z._js_eq(Odd(), "a") is False


def test_object_schema_node_budget_boundary():
    assert Z._object_schema_error({}, Z._ABSENT, 1, {"nodes": 255}) is None
    assert Z._object_schema_error({}, Z._ABSENT, 1, {"nodes": 256}) == "schema too large"


def test_integer_spec_bounds_are_validated():
    assert Z.validate_arg_schema({"props": {"x": {"type": "integer", "min": "a"}}}) == "x: bad min"
    assert Z.validate_arg_schema({"props": {"x": {"type": "integer", "max": None}}}) == "x: bad max"
    assert Z.validate_arg_schema({"props": {"x": {"type": "integer", "min": 5, "max": 1}}}) == "x: min > max"
    assert Z.validate_arg_schema({"props": {"x": {"type": "integer", "min": 1, "max": 5}}}) is None


def test_show_cuts_a_lone_surrogate_key():
    k = "a" * 10 + "\ud800" + "b" * 60
    assert Z._show(k) == '"' + "a" * 10 + "\\ud800" + "b" * 37 + '…"'


def _tool_cav(schema, tool="t"):
    return {"type": "tool_schema", "tool": tool, "schema": schema, "schema_digest": hash_canonical(schema),
            "binding_digest": hash_canonical({"tool": tool, "signature_digest": "undefined", "schema": schema})}


def test_tool_schema_value_node_budget_starts_at_zero():
    schema = {"props": {"a": {"type": "array", "maxItems": 4096,
                              "items": {"type": "array", "maxItems": 4096, "items": {"type": "boolean"}}}}}
    cav = _tool_cav(schema)
    ok = {"tool": "t", "args": {"a": [[True] * 4096, [True] * 4096, [True] * 1804]}}  # exactly 10000 value nodes
    assert Z.evaluate_tool_schema(cav, ok) == (True, None)
    over = {"tool": "t", "args": {"a": [[True] * 4096, [True] * 4096, [True] * 1805]}}
    assert Z.evaluate_tool_schema(cav, over) == (False, "args.a[2][1804]: too many values")


# ---- the agent caveat evaluator -----------------------------------------------------------------------------------------

def test_agent_caveat_satisfied_guards():
    cv = {"type": "predicates", "allow": [PRED]}
    act = {"action": INNER}
    assert Z._agent_caveat_satisfied(cv, {}, act, {}) is True
    assert Z._agent_caveat_satisfied(UserDict(cv), {}, act, {}) is False
    assert Z._agent_caveat_satisfied("x", {}, act, {}) is False
    assert Z._agent_caveat_satisfied(cv, [], act, {}) is False
    assert Z._agent_caveat_satisfied(dict(cv, allow=(PRED,)), {}, act, {}) is False
    assert Z._agent_caveat_satisfied(cv, {}, UserDict(act), {}) is False


# ---- AuthorizeResult ---------------------------------------------------------------------------------------------------------

def test_authorize_result_item_access():
    r = Z.AuthorizeResult(allow=False, status=403)
    assert r["status"] == 403 and r["allow"] is False
    assert r.get("status") == 403
    assert r.get("nope", 7) == 7
    assert r.get("nope") is None


# ---- assurance labels and the report ------------------------------------------------------------------------------------------

def _labelled(level, **kw):
    f = lambda: 0  # noqa: E731
    return Z.set_assurance_label(f, level, **kw)


def test_multi_root_level():
    plain = {"verifier": lambda: 0}
    assert Z.multi_root_level([plain], 1) == "unknown"
    assert Z.multi_root_level([{"verifier": _labelled("weird")}], 1) == "unknown"
    # a required root takes a slot and is not also an optional candidate
    roots = [{"verifier": _labelled("software"), "required": True}, {"verifier": _labelled("hardware")},
             {"verifier": _labelled("hardware")}]
    assert Z.multi_root_level(roots, 2) == "hardware"
    # an explicit required: False is optional
    both = [{"verifier": _labelled("hardware"), "required": False}, {"verifier": _labelled("hardware"), "required": False}]
    assert Z.multi_root_level(both, 2) == "multi_root"


def test_weakest_order():
    assert Z._weakest(["pq", "unknown"]) == "unknown"
    assert Z._weakest(["unknown", "ed25519"]) == "unknown"
    assert Z._weakest(["hybrid", "ed25519"]) == "ed25519"
    assert Z._weakest(["pq", "hybrid"]) == "hybrid"
    assert Z._weakest(["pq"]) == "pq"
    assert Z._weakest([]) == "unknown"


def test_unavailable_treats_an_absent_alg_as_ed25519(monkeypatch):
    monkeypatch.setattr(Z, "suite_available", lambda a: False)
    assert Z._unavailable(None) is True
    assert Z._unavailable("ed25519") is True
    assert Z._unavailable("not-a-suite") is False
    monkeypatch.setattr(Z, "suite_available", lambda a: True)
    assert Z._unavailable(None) is False


def test_report_hook_levels_only_for_their_own_check():
    hk = {"revocation": _labelled("software")}
    out = Z.assurance_report({}, {"operation": "pass", "revocation": "pass"}, hooks=hk)
    assert out["operation"] == {"outcome": "pass"}
    assert out["revocation"] == {"outcome": "pass", "level": "software"}


def test_report_awaiting_audit_flag_of_a_label():
    on = Z.assurance_report({}, {"revocation": "pass"}, hooks={"revocation": _labelled("software", awaiting_audit=True)})
    assert on["revocation"] == {"outcome": "pass", "level": "software", "awaiting_audit": True}
    off = Z.assurance_report({}, {"revocation": "pass"}, hooks={"revocation": _labelled("software", awaiting_audit=False)})
    assert off["revocation"] == {"outcome": "pass", "level": "software"}


def test_report_chain_hops_and_levels():
    out = Z.assurance_report({"cap_chain": ["junk", {"alg": None}]}, {"chain": "pass"})
    assert out["chain"] == {"outcome": "pass", "suites": ["ed25519", "ed25519"], "level": "ed25519"}
    out = Z.assurance_report({"cap_chain": [{"alg": None}, {}]}, {"chain": "pass"}, allow_unbound_pq=True)
    assert out["chain"]["level"] == "ed25519"
    out = Z.assurance_report({"cap_chain": [{"alg": "ml-dsa-65"}]}, {"chain": "pass"}, allow_unbound_pq=True)
    assert out["chain"]["level"] == "unbound_pq"
    out = Z.assurance_report({"cap_chain": [{"alg": "ml-dsa-65"}]}, {"chain": "pass"})
    assert out["chain"]["level"] == "pq"


def test_report_chain_unsupported_needs_a_failed_chain_and_a_missing_backend(monkeypatch):
    monkeypatch.setattr(Z, "suite_available", lambda a: a != "ml-dsa-65")
    pq = {"cap_chain": [{"alg": "ml-dsa-65"}]}
    assert Z.assurance_report(pq, {"chain": "pass"})["chain"]["outcome"] == "pass"
    assert Z.assurance_report({"cap_chain": [{"alg": None}]}, {"chain": "fail"})["chain"] == {"outcome": "fail"}
    assert Z.assurance_report(pq, {"chain": "fail"})["chain"] == {
        "outcome": "unsupported", "reason": "a capability suite has no backend in this runtime"}


def test_report_degraded_for_an_absent_check_is_ignored():
    out = Z.assurance_report({}, {"policy": "pass"}, {"tighten": "why"})
    assert out == {"policy": {"outcome": "pass"}}
    out = Z.assurance_report({}, {"tighten": "pass"}, {"tighten": "why"})
    assert out["tighten"] == {"outcome": "pass", "degraded": True, "reason": "why"}


def _um(report, require):
    return Z.unmet_assurance(report, require)


def test_unmet_assurance_default_texts():
    assert _um({"x": {"outcome": "unsupported"}}, {}) == \
        "assurance: unsupported: x (not implemented); a high-assurance policy never accepts it"
    assert _um({"x": {"outcome": "pass", "degraded": True}}, {}) == \
        "assurance: x rests on a degraded compatibility mode (degraded); a high-assurance policy never accepts it"
    assert _um({}, {"b": 1, "a": 2}) == "assurance: unknown assurance requirement(s): a, b (fail closed)"


def test_unmet_assurance_awaiting_audit_aliases():
    rep = {"x": {"outcome": "pass", "awaiting_audit": True, "level": "frost"}}
    assert _um(rep, {}) == ("assurance: x rests on crypto awaiting audit (frost); set allowAwaitingAudit or list the scheme "
                            "to accept it")
    for k in ("allowAwaitingAudit", "allow_awaiting_audit", "allowPreview", "allow_preview"):
        assert _um(rep, {k: True}) is None


def test_unmet_assurance_awaiting_audit_scan_continues_past_other_entries():
    rep = {"a": {"outcome": "fail"}, "b": {"outcome": "pass", "awaiting_audit": True, "level": "x"}}
    assert _um(rep, {}) == ("assurance: b rests on crypto awaiting audit (x); set allowAwaitingAudit or list the scheme to "
                            "accept it")
    rep = {"threshold": {"outcome": "pass", "awaiting_audit": True, "level": "frost"},
           "other": {"outcome": "pass", "awaiting_audit": True, "level": "x"}}
    assert _um(rep, {"threshold": ["frost"]}) == ("assurance: other rests on crypto awaiting audit (x); set allowAwaitingAudit "
                                                 "or list the scheme to accept it")
    assert _um({"attestation": {"outcome": "pass", "awaiting_audit": True}}, {}) == (
        "assurance: attestation rests on crypto awaiting audit (unknown); set allowAwaitingAudit or list the scheme to accept it")


def test_unmet_assurance_attestation_levels():
    assert _um({"attestation": {"outcome": "pass", "level": "weird"}}, {"attestation": "software"}) == \
        "assurance: software attestation required but the evidence is weird"
    assert _um({"attestation": {"outcome": "pass"}}, {"attestation": "hardware"}) == \
        "assurance: hardware attestation required but the evidence is unknown"
    assert _um({"attestation": {"outcome": "pass", "level": "software"}}, {"attestation": "software"}) is None


def test_unmet_assurance_zk_levels():
    hw = "assurance: zk compliance (attested_vm_hardware) required but the prover key is not bound to hardware evidence"
    for lv in ({"level": "unknown"}, {}, {"level": "attested_vm"}):
        assert _um({"zk_compliance": dict({"outcome": "pass"}, **lv)}, {"zk": "attested_vm_hardware"}) == hw
    assert _um({"zk_compliance": {"outcome": "pass", "level": "weird"}}, {"zk": "attested_vm"}) == \
        "assurance: zk compliance (attested_vm) required but the evidence is weird"
    assert _um({"zk_compliance": {"outcome": "pass"}}, {"zk": "proof"}) == \
        "assurance: zk compliance (proof) required but the evidence is unknown"


def test_unmet_assurance_signature_and_threshold_texts():
    assert _um({"leaf_signature": {"outcome": "pass"}}, {"signature": "pq"}) == \
        "assurance: post-quantum signatures required but leaf_signature is unknown"
    assert _um({}, {"threshold": ["frost", "mpc"]}) == \
        "assurance: threshold (frost | mpc) required but there is no threshold evidence"


# ---- model rules ---------------------------------------------------------------------------------------------------------

def test_needs_model_rules():
    assert Z._needs_model_rules(G) is False
    assert Z._needs_model_rules({"caveats": []}) is False
    assert Z._needs_model_rules(grant_with(units={})) is True
    assert Z._needs_model_rules(grant_with(tighten=[])) is True
    assert Z._needs_model_rules(grant_with(model_polarity="strict")) is True
    one = dict(PRED, where=[{"field": "env.class.x"}])
    assert Z._needs_model_rules(grant_with(predicates=[one])) is True


def test_degraded_of():
    assert Z._degraded_of(Verdict(True, {}, None, [], True)) == {"tighten": Z.LEGACY_POLARITY_DEGRADED}
    assert Z._degraded_of(Verdict(True, {}, None, [])) is None


# ---- _decisive / _coerce / _revocation_ids ------------------------------------------------------------------------------------

def test_decisive_prefers_operation_and_skips_passing_checks():
    assert Z._decisive({"policy": "fail", "operation": "fail"}, ["policy: x", "operation: y"]) == "operation: y"
    assert Z._decisive({"a": "pass", "b": "fail"}, ["a: x", "b: y"]) == "b: y"
    assert Z._decisive({"x": "fail"}, ["other: z"]) == "other: z"
    assert Z._decisive({"x": "pass"}, []) == "denied"
    assert Z._decisive({"a": "fail", "b": "fail"}, ["b: 1", "a: 2"]) == "a: 2"


def test_coerce_oversized_and_bytes():
    assert Z._coerce("x" * 524289) == (None, "undecodable")
    assert Z._coerce(b"x" * 524289) == (None, "undecodable")
    assert Z._coerce(b'{"a": 1}') == ({"a": 1}, None)
    assert Z._coerce(bytearray(b'{"a": 1}')) == ({"a": 1}, None)
    assert Z._coerce(b"\xff") == (None, "undecodable")


def test_revocation_ids_pass_the_pcactn():
    pol = RevocationStaleness(ids=lambda q: ["a", q["k"]])
    assert Z._revocation_ids(pol, {"k": "v"}) == ["a", "v"]


# ---- authorize(): forwarding and defaults -----------------------------------------------------------------------------------

def test_authorize_forwards_every_argument_in_order(monkeypatch):
    got = []
    monkeypatch.setattr(Z, "_authorize", lambda *a: got.append(a) or Z._refuse(403, "x", "y"))
    names = ["pcactn", "operation", "audience", "resolve_grant", "state_store", "is_revoked", "now", "plan", "context",
             "intent_policy", "intent_v2", "allowed_suites", "require", "require_assurance", "escalation_principals",
             "escalation_answer", "escalation_request_ttl_ms", "revocation_staleness", "plans", "k1", "uses_store",
             "fresh_at", "escalation_render", "insecure_unbound_approval", "workflow", "workflow_step", "provenance",
             "provenance_request", "provenance_mediators", "provenance_actions", "provenance_observed", "undo_admit"]
    vals = {n: object() for n in names}
    vals["now"], vals["escalation_request_ttl_ms"] = 5, 12345
    kw = {n: v for n, v in vals.items() if n != "pcactn"}
    Z.authorize(vals["pcactn"], **kw)
    assert got == [tuple(vals[n] for n in names)]


def test_authorize_internal_defaults():
    ps = inspect.signature(Z._authorize).parameters
    assert ps["escalation_request_ttl_ms"].default == 3_600_000
    assert ps["insecure_unbound_approval"].default is False


def test_core_receives_the_options(monkeypatch):
    calls = spy_on(monkeypatch, "verify_pcactn_core")
    run(intent_policy={"x": 1}, allowed_suites=["ed25519"], fresh_at=lambda _p: {"sentinel": 1}, intent_v2=None)
    k = calls[-1][1]
    assert k["intent_policy"] == {"x": 1} and k["allowed_suites"] == ["ed25519"]
    assert k["fresh_at"] == {"sentinel": 1} and k["audience"] == AUD and k["now"] == NOW
    assert k["intent_v2"] is None  # no model rules in this grant: nothing is made up


def test_intent_v2_is_completed_only_when_needed(monkeypatch):
    calls = spy_on(monkeypatch, "verify_pcactn_core")
    run(grant=grant_with(units={}))
    assert calls[-1][1]["intent_v2"] == {"params": OP["params"]}
    run(grant=grant_with(units={}), intent_v2={"params": {"custom": 1}})
    assert calls[-1][1]["intent_v2"] == {"params": {"custom": 1}}
    run(grant=grant_with(units={}), intent_v2="x")
    assert calls[-1][1]["intent_v2"] == "x"
    run(intent_v2={"y": 1})
    assert calls[-1][1]["intent_v2"] == {"y": 1, "params": OP["params"]}


def test_now_defaults_to_the_wall_clock(monkeypatch):
    monkeypatch.setattr(Z, "time", types.SimpleNamespace(time=lambda: 1234.5))
    calls = spy_on(monkeypatch, "verify_pcactn_core")
    run(now=None)
    assert calls[-1][1]["now"] == 1234500


def test_callbacks_receive_the_pcactn():
    seen = {"ctx": [], "v2": [], "fa": [], "rev": []}
    run(context=lambda q: seen["ctx"].append(q) or {}, intent_v2=lambda q: seen["v2"].append(q) or {},
        fresh_at=lambda q: seen["fa"].append(q) or None,
        is_revoked=lambda q, g: seen["rev"].append((q, g)) or False)
    assert seen["ctx"] == [P0] and seen["v2"] == [P0] and seen["fa"] == [P0] and seen["rev"] == [(P0, G)]


def test_reasons_are_seeded_from_the_core_verdict_only_when_it_refuses(monkeypatch):
    base = Z.verify_pcactn_core(copy.deepcopy(P0), G, now=NOW, audience=AUD)
    monkeypatch.setattr(Z, "verify_pcactn_core", lambda *a, **k: Verdict(True, dict(base.checks), "stale", ["stale"]))
    r = run()
    assert r.allow is True and r.reasons == []
    monkeypatch.setattr(Z, "verify_pcactn_core", lambda *a, **k: Verdict(False, dict(base.checks), None, []))
    r = run()
    assert r.allow is True and r.reasons == []
    monkeypatch.setattr(Z, "verify_pcactn_core", lambda *a, **k: Verdict(False, dict(base.checks), "why", []))
    assert run().reasons == ["why"]


# ---- authorize(): the plan registry ------------------------------------------------------------------------------------------

class Plans:
    def __init__(self, ret=None):
        self.ret = ret

    def context(self, grant_ref, root, now):
        return self.ret


def _plans(authorized, executable):
    return Plans({"plan": [NODE], "planAuthorized": authorized, "status": {"state": "s", "executable": executable}})


def test_registry_keeps_the_context_and_reports_principal_plan(monkeypatch):
    calls = spy_on(monkeypatch, "_provenance_flow")
    r = run(plans=_plans(True, True), plan=None, context=lambda _p: {"reversibility_class": "irreversible"})
    assert r.checks["reversibility"] == "pass"
    assert calls[-1][0][8] is True
    run(plans=_plans(True, False), plan=None)
    assert calls[-1][0][8] is False
    run(plans=_plans(False, True), plan=None)
    assert calls[-1][0][8] is False


def test_unknown_plan_state_reason():
    r = run(plans=Plans(), plan=None)
    assert "plan_state: plan %s is unknown to the plan registry" % P0["plan"]["root"] in r.reasons


def test_provenance_gate_receives_the_request_state(monkeypatch):
    calls = spy_on(monkeypatch, "_provenance_flow")
    p = copy.deepcopy(P0)
    run(pcactn=p)
    a = calls[-1][0]
    assert a[2] is p and a[8] is False and a[9] is False


# ---- authorize(): the workflow gate ------------------------------------------------------------------------------------------

def test_workflow_request_is_built_from_the_step(monkeypatch):
    reqs = []
    monkeypatch.setattr(Z, "admit_step", lambda r: reqs.append(r) or {"decision": "allow"})
    pf = spy_on(monkeypatch, "_provenance_flow")
    step = {"commitment": "C", "receipts": ["r"], "step": "s1", "units": {"u": 1}, "goal_digest": "GD"}
    run(workflow={"principal": "PR", "rs_signer": "RS"}, workflow_step=step)
    assert reqs == [{"workflow": "C", "principal": "PR", "rs_signer": "RS", "receipts": ["r"], "now": NOW,
                     "request": {"step": "s1", "verb": OP["verb"], "resource": OP["resource"], "params": OP["params"],
                                 "units": {"u": 1}, "goal_digest": "GD", "plan_root": P0["plan"]["root"]}}]
    assert pf[-1][0][9] is True
    run(workflow={"principal": "PR", "rs_signer": "RS"}, workflow_step={"commitment": "C"})
    assert reqs[-1]["request"]["units"] == {} and reqs[-1]["request"]["goal_digest"] is None
    run(workflow={"principal": "PR", "rs_signer": "RS"}, workflow_step={"commitment": "C", "units": None})
    assert reqs[-1]["request"]["units"] == {}


def test_workflow_plan_root_extraction(monkeypatch):
    reqs = []
    monkeypatch.setattr(Z, "admit_step", lambda r: reqs.append(r) or {"decision": "deny"})
    for plan, root in ((None, None), ({"root": 5}, None), ({"root": "R"}, "R"), ("x", None)):
        p = copy.deepcopy(P0)
        p["plan"] = plan
        run(pcactn=p, workflow={"principal": "PR"}, workflow_step={"commitment": "C"})
        assert reqs[-1]["request"]["plan_root"] == root


def test_workflow_non_mapping_step_is_an_empty_step(monkeypatch):
    reqs = []
    monkeypatch.setattr(Z, "admit_step", lambda r: reqs.append(r) or {"decision": "deny", "code": "c"})
    r = run(workflow={"principal": "PR"}, workflow_step=["x"])
    assert r.checks == {"workflow": "fail"} and r.reason == "workflow: c"
    assert reqs[0]["workflow"] is None and reqs[0]["receipts"] is None


def test_workflow_refusal_texts(monkeypatch):
    out = {}
    monkeypatch.setattr(Z, "admit_step", lambda r: out)
    p = copy.deepcopy(P0)
    out.update(decision="deny")
    r = run(pcactn=p, workflow={"principal": "PR"}, workflow_step={"commitment": "C"})
    assert (r.status, r.reason, r.decision) == (403, "workflow: refused", "deny") and r.pcactn is p
    out.update(code="c1", step=3)
    r = run(pcactn=p, workflow={"principal": "PR"}, workflow_step={"commitment": "C"})
    assert r.reason == "workflow: c1 (step 3)"
    out.update(decision="escalate")
    assert run(pcactn=p, workflow={"principal": "PR"}, workflow_step={"commitment": "C"}).decision == "escalate"


# ---- authorize(): revocation staleness -------------------------------------------------------------------------------------------

def _signed(p, cls):
    p["action"]["reversibility_class"] = cls
    return p


def test_freshness_class_is_the_stricter_of_server_and_signed(monkeypatch):
    inject(monkeypatch)
    rs = RevocationStaleness()
    r = run(pcactn=_signed(copy.deepcopy(P0), "reversible"), revocation_staleness=rs,
            context=lambda _p: {"reversibility_class": "irreversible"})
    assert r.checks["freshness"] == "fail"
    assert "freshness: no verifiable (guardian-signed) revocation state for an irreversible action" in r.reasons
    r = run(pcactn=_signed(copy.deepcopy(P0), "reversible"), revocation_staleness=rs,
            context=lambda _p: {"reversibility_class": "reversible"})
    assert r.checks["freshness"] == "not-enforced"


def test_freshness_with_a_non_dict_action(monkeypatch):
    inject(monkeypatch)
    p = copy.deepcopy(P0)
    p["action"] = None
    r = run(pcactn=p, revocation_staleness=RevocationStaleness())
    assert "authorize" not in r.checks and r.checks["freshness"] == "fail"


def test_freshness_epoch_argument(monkeypatch):
    inject(monkeypatch)
    calls = spy_on(monkeypatch, "check_revocation_state", {"ok": True, "epoch": 9})
    rs = RevocationStaleness()
    ctx = lambda _p: {"revocation_state": {"k": 1}}  # noqa: E731
    for fr, want in ((None, Z._MISSING_EPOCH), ({}, Z._MISSING_EPOCH), ("x", Z._MISSING_EPOCH), ({"epoch": 5}, 5)):
        p = copy.deepcopy(P0)
        if fr is None:
            p.pop("freshness")
        else:
            p["freshness"] = fr
        r = run(pcactn=p, revocation_staleness=rs, context=ctx)
        assert "authorize" not in r.checks and r.checks["freshness"] == "pass"
        assert calls[-1][1]["pcactn_epoch"] is want or calls[-1][1]["pcactn_epoch"] == want


# ---- authorize(): operation / grant / plan shapes behind a permissive core -------------------------------------------------------

def test_grant_ref_must_match_the_supplied_grant():
    r = run(resolve_grant=lambda ref: dict(G, id="other"))
    assert r.checks["grant_ref"] == "fail"
    assert "grant_ref: does not reference the supplied grant" in r.reasons


def test_odd_pcactn_shapes_never_crash_the_pipeline(monkeypatch):
    inject(monkeypatch)
    p = copy.deepcopy(P0)
    p["action"] = None
    r = run(pcactn=p)
    assert "authorize" not in r.checks and r.checks["operation"] == "fail"
    p = copy.deepcopy(P0)
    p["plan"] = None
    r = run(pcactn=p)
    assert "authorize" not in r.checks and r.checks["plan_root_authorized"] == "fail"
    p = copy.deepcopy(P0)
    p["cap_chain"] = None
    r = run(pcactn=p)
    assert "authorize" not in r.checks and r.allow is False and "delegated_caveats" not in r.checks
    assert r.checks["replay"] == "fail"
    assert "replay: no counter stream for this proof (fail closed)" in r.reasons
    p["cap_chain"] = ["x"]
    r = run(pcactn=p)
    assert "authorize" not in r.checks and r.checks["delegated_caveats"] == "fail"
    p["cap_chain"] = [{"holder": "h", "caveats": None}]
    assert "authorize" not in run(pcactn=p).checks
    p["cap_chain"] = [{"holder": "h", "caveats": "junk"}]
    r = run(pcactn=p)
    assert r.checks["delegated_caveats"] == "fail"
    assert "delegated_caveats: delegation caveat(s) not satisfied: <malformed caveats>" in r.reasons
    r = run(resolve_grant=lambda ref: dict(G, caveats=None))
    assert "authorize" not in r.checks and "policy: grant carries no valid envelope" in r.reasons


def test_unmatched_plan_with_a_throwing_leaf_cannot_pass_on_an_empty_root(monkeypatch):
    inject(monkeypatch)
    p = copy.deepcopy(P0)
    p["plan"]["root"] = ""
    r = run(pcactn=p, plan=None, context=lambda _p: {"plan": ["bad"], "plan_authorized": True})
    assert r.checks["plan_root_authorized"] == "fail"
    assert "plan_root_authorized: known plan does not match plan.root" in r.reasons


def test_no_counter_stream_is_a_deny_not_an_escalation(monkeypatch):
    inject_escalate(monkeypatch)
    p = copy.deepcopy(P0)
    p["cap_chain"] = []
    r = run(pcactn=p)
    assert (r.decision, r.escalation, r.allow) == ("deny", None, False)
    nogid = {k: v for k, v in G.items() if k != "id"}
    r = run(resolve_grant=lambda ref: nogid)
    assert "authorize" not in r.checks and r.decision == "deny"


# ---- authorize(): the policy step -----------------------------------------------------------------------------------------------

def test_policy_failure_texts(monkeypatch):
    inject(monkeypatch)
    g = grant_with(caveats=[{"type": "nope1"}, {"type": "nope2"}])
    g["caveats"] = g["caveats"] + [{"type": "nope3"}, {"type": "nope4"}]
    r = run(grant=g)
    assert "policy: caveat(s) not satisfied: nope1, nope2" in r.reasons
    assert "policy: root caveat(s) not satisfied: nope3, nope4" in r.reasons
    r = run(resolve_grant=lambda ref: {"id": G["id"]})
    assert "policy: grant carries no valid envelope" in r.reasons


def test_policy_default_reasons(monkeypatch):
    inject(monkeypatch)
    monkeypatch.setattr(Z, "evaluate_predicates", lambda *a: {"allowed": False})
    assert "policy: action not permitted by envelope predicates" in run().reasons

    def boom(*a):
        raise RuntimeError("x")

    monkeypatch.setattr(Z, "evaluate_predicates", boom)
    r = run()
    assert "policy: policy evaluation error (fail closed)" in r.reasons and r.checks["policy"] == "fail"


def test_non_list_root_caveats_fail_closed(monkeypatch):
    inject(monkeypatch)
    monkeypatch.setattr(Z, "root_caveats", lambda g: "x")
    assert "policy: root caveat(s) not satisfied: <malformed caveats>" in run().reasons


def test_caveat_context_and_tool_call(monkeypatch):
    inject(monkeypatch)
    calls = spy_on(monkeypatch, "evaluate_agent_caveats")
    p = copy.deepcopy(P0)
    p["cap_chain"] = [{"holder": "h1", "caveats": []}, {"holder": "h2", "caveats": []}]
    p["tool_binding"] = "tb"
    run(pcactn=p)
    assert calls and all(a[1]["delegation_depth"] == 1 for a, _k in calls)
    assert calls[0][0][3] == {"tool": "payments.send", "args": OP["params"], "tool_signature_digest": "tb"}
    p = copy.deepcopy(P0)
    p["action"]["verb"] = None
    calls.clear()
    run(pcactn=p)
    assert calls[0][0][3]["tool"] == ""


def test_reversibility_class_falls_back_to_the_plan_node(monkeypatch):
    inject(monkeypatch)
    calls = spy_on(monkeypatch, "evaluate_agent_caveats")
    nodes = [{"id": "other", "reversibility_class": "irreversible"}, "junk",
             {"id": "n1", "reversibility_class": "reversible"}]
    p = copy.deepcopy(P0)
    del p["action"]["reversibility_class"]
    p["plan"]["node_id"] = "n1"
    r = run(pcactn=p, context=lambda _p: {"plan": nodes, "plan_authorized": True})
    assert "authorize" not in r.checks and calls[0][0][1]["reversibility_class"] == "reversible"
    p["plan"]["node_id"] = "zz"
    calls.clear()
    r = run(pcactn=p, context=lambda _p: {"plan": nodes, "plan_authorized": True})
    assert "authorize" not in r.checks and "reversibility_class" not in calls[0][0][1]


def test_predicate_env_is_built_from_the_request(monkeypatch):
    inject(monkeypatch)
    calls = []
    monkeypatch.setattr(Z, "_v2_env", lambda *a: calls.append(a) or None)
    p = copy.deepcopy(P0)
    run(pcactn=p, intent_v2={"y": 1}, context=lambda _p: {"env": {"e": 1}})
    a = calls[0]
    assert a[0] is p and a[1] is G and a[3] == NOW and a[4] == {"e": 1}
    assert a[2] == {"y": 1, "params": OP["params"], "env": {"e": 1}}


def test_delegation_texts_and_k1_inputs(monkeypatch):
    inject(monkeypatch)
    fake = {"ok": False, "failed": ["kf"], "reasons": ["why1", "why2"], "plain": [{"type": "n1"}, {"type": "n2"}], "bound": []}
    monkeypatch.setattr(Z, "evaluate_k1", lambda *a: fake)
    p = copy.deepcopy(P0)
    p["cap_chain"] = [{"holder": "h", "caveats": []}]
    r = run(pcactn=p, k1={"narrow": 1})
    assert "delegated_caveats: delegation caveat(s) not satisfied: n1, n2, kf (why1; why2)" in r.reasons
    ok = {"ok": True, "failed": [], "reasons": [], "plain": [], "bound": []}
    monkeypatch.setattr(Z, "evaluate_k1", lambda *a: ok)
    p["cap_chain"] = []
    assert run(pcactn=p, k1={"narrow": 1}).checks["delegated_caveats"] == "pass"
    k1cav = {"type": K1_CAVEAT_TYPES[0]}
    g = dict(G, caveats=list(G["caveats"]) + [k1cav])
    p["cap_chain"] = [{"holder": "h", "caveats": []}]
    r = run(pcactn=p, grant=g, k1={})
    assert "delegated_caveats: delegation caveat(s) not satisfied: a root K1 caveat is not carried by the leaf" in r.reasons


def test_non_mapping_require_assurance_is_refused():
    r = run(require_assurance=["x"])
    assert r.checks["assurance"] == "fail"
    assert "assurance: unknown assurance requirement(s): invalid (fail closed)" in r.reasons


# ---- authorize(): escalation ------------------------------------------------------------------------------------------------------

def test_escalation_request_inputs(monkeypatch):
    inject_escalate(monkeypatch)
    calls = spy_on(monkeypatch, "build_escalation_request")
    store = Z.MemoryStateStore()
    store.claim(Z.state_key(G["id"], HOLDER), 0)  # the 0.4 key: the upgrade carries it over
    seen = []
    p = copy.deepcopy(P0)
    r = run(pcactn=p, state_store=store, escalation_request_ttl_ms=4321,
            escalation_render=lambda q: seen.append(q) or "RD")
    k = calls[-1][1]
    assert r.decision == "escalate"
    assert k["last_counter"] == 0 and k["ttl_ms"] == 4321 and k["render_digest"] == "RD" and k["pcactn"] is p
    assert seen == [p]
    run(state_store=Z.MemoryStateStore())
    assert calls[-1][1]["ttl_ms"] == 3_600_000 and calls[-1][1]["last_counter"] is None


def test_escalation_ignores_a_head_it_cannot_read(monkeypatch):
    inject_escalate(monkeypatch)
    calls = spy_on(monkeypatch, "build_escalation_request")

    class BadLast(Z.MemoryStateStore):
        def last(self, key):
            return "bad"

    run(state_store=BadLast())
    assert calls[-1][1]["last_counter"] is None


def test_escalation_with_a_store_that_cannot_report_its_head(monkeypatch):
    inject_escalate(monkeypatch)

    class Bare:
        def __init__(self):
            self.m = Z.MemoryStateStore()

        def claim(self, key, counter):
            return self.m.claim(key, counter)

    r = run(state_store=Bare(), escalation_answer={"junk": 1}, insecure_unbound_approval=True)
    assert r.decision == "escalate" and not [x for x in r.reasons if x.startswith("escalation:")]

    class Raising(Z.MemoryStateStore):
        def last(self, key):
            raise RuntimeError("down")

    r = run(state_store=Raising(), escalation_answer={"junk": 1}, insecure_unbound_approval=True, escalation_principals=["pk"])
    assert r.decision == "escalate" and not [x for x in r.reasons if x.startswith("escalation:")]


def test_escalation_render_failure_requires_a_render(monkeypatch):
    inject_escalate(monkeypatch)

    def boom(q):
        raise RuntimeError("x")

    r = run(escalation_render=boom, escalation_answer={"junk": 1}, escalation_principals=["pk"])
    assert ("escalation: an approval render is required and none could be recomputed (pass escalation_render, or "
            "insecure_unbound_approval=True)") in r.reasons


def test_escalation_answer_is_bound_to_the_head(monkeypatch):
    inject_escalate(monkeypatch)
    calls = []
    monkeypatch.setattr(Z, "verify_escalation_answer", lambda *a: calls.append(a) or {"ok": False, "reason": "r"})
    store = Z.MemoryStateStore()
    store.claim(Z.state_key(G["id"], HOLDER), 0)
    ans, p = {"junk": 1}, copy.deepcopy(P0)
    bind = {"policy_digest": escalation_policy_digest(G), "action_digest": escalation_action_digest(p),
            "history_head": escalation_history_head(0)}
    r = run(pcactn=p, state_store=store, escalation_answer=ans, insecure_unbound_approval=True, escalation_principals=["pk"])
    assert calls[-1][0] is ans and calls[-1][1] == ["pk"] and calls[-1][2] == bind and calls[-1][3] == NOW
    assert "escalation: r" in r.reasons and r.decision == "escalate"
    run(pcactn=p, state_store=store, escalation_answer=ans, escalation_render=lambda q: "RD", escalation_principals=["pk"])
    assert calls[-1][2] == dict(bind, render_digest="RD")


# ---- the undo admission and the provenance gate -------------------------------------------------------------------------------------

def test_undo_admission_needs_real_dicts():
    adm = {"id": "op_1", "window_end": 5000, "compensation": {"verb": "payments.refund"}}
    assert Z._undo_admission(lambda a, b, c: adm, {}, {}, {}) == adm
    assert Z._undo_admission(lambda a, b, c: UserDict(adm), {}, {}, {}) is None
    assert Z._undo_admission(lambda a, b, c: dict(adm, compensation=UserDict(adm["compensation"])), {}, {}, {}) is None
    assert Z._undo_admission(lambda a, b, c: None, {}, {}, {}) is None


def _pf(env=None, op=None, p=None, **kw):
    a = dict(bundle=None, request=None, mediators=(), actions=None, observed=None, plan=False, control=False)
    a.update(kw)
    return Z._provenance_flow(env, op, {} if p is None else p, a["bundle"], a["request"], a["mediators"], a["actions"],
                              a["observed"], a["plan"], a["control"])


def test_provenance_flow_unbound_operation():
    msg = ("fail", "no operation is bound to this request (fail closed)")
    for op in ([], "x", {"verb": None, "resource": "r"}, {"verb": "v", "resource": None}, {"verb": 1, "resource": 2}):
        assert _pf(op=op) == msg


def test_provenance_flow_inputs(monkeypatch):
    seen, din = [], []
    monkeypatch.setattr(Z, "decide_arg_provenance", lambda d: din.append(d) or {"outcome": "pass"})
    op = {"verb": "v", "resource": "r", "params": {}}
    o = {"verb": "v", "resource": "r", "params": {}}
    p = {"p": 1}
    bundle = {"receipts": [{"session": "S0"}, {"session": "S1"}]}
    obs = lambda q, oo, s: seen.append((q, oo, s)) or [{"origin": "x", "source": "y"}]  # noqa: E731
    assert _pf(op=op, p=p, bundle=bundle, observed=obs, mediators=None, plan=True, control=True) == ("pass", None)
    assert seen == [(p, o, "S0")]
    assert din[-1] == {"bundle": bundle, "operation": o, "mediators": None, "principal_plan": True,
                       "principal_control": True, "observed": [{"origin": "x", "source": "y"}]}
    _pf(op=op, p=p, bundle={"receipts": [{"session": 5}]}, observed=obs)
    assert seen[-1][2] is None
    _pf(op=op, p=p, bundle={"receipts": {"a": 1}}, observed=obs)
    assert seen[-1][2] is None
    facts = {"effects": []}
    _pf(op=op, bundle=bundle, actions=lambda oo: facts)
    assert din[-1]["action"] is facts and din[-1]["mediators"] == []
    _pf(op=op, bundle=bundle)
    assert "action" not in din[-1]


# ---- _v2_env -------------------------------------------------------------------------------------------------------------------------

def test_v2_env_without_an_intent_session_is_the_host_env(monkeypatch):
    import atlas_pca.intent_v2 as IV

    def boom(*a):
        raise AssertionError("not consulted")

    monkeypatch.setattr(IV, "decide_intent_v2", boom)
    env = {"acc": 1}
    assert Z._v2_env({}, {}, None, 1, env) is env


def test_v2_env_merge(monkeypatch):
    import atlas_pca.intent_v2 as IV

    calls, ret = [], {}
    monkeypatch.setattr(IV, "decide_intent_v2", lambda *a: calls.append(a) or ret)
    p, g = {"intent_session": 1}, {"g": 1}
    host = {k: "host" for k in ("acc", "mon", "canon", "world", "prov", "class")}
    host["keep"] = 1
    ret.update({"env": {}})
    assert Z._v2_env(p, g, "V2", 7, host) == {"keep": 1}
    assert calls[-1] == (p, g, "V2", 7) and host["acc"] == "host"  # the host env is not modified
    ret.update({"env": {"acc": 1, "mon": None}})
    assert Z._v2_env(p, g, None, 7, {"keep": 1}) == {"keep": 1, "acc": 1}
    assert Z._v2_env(p, g, None, 7, None) == {"acc": 1}
    assert Z._v2_env(p, g, None, 7, [1]) == {"acc": 1}
    ret.clear()
    ret.update({"env": None})
    assert Z._v2_env(p, g, None, 7, {"keep": 1}) == {"keep": 1}
    ret.clear()
    assert Z._v2_env(p, g, None, 7, {}) == {}


# ---- is_authorized_for / AuthorizeOptions ---------------------------------------------------------------------------------------------

def test_is_authorized_for(monkeypatch):
    opb = {"verb": "v", "resource": "r", "params": {"a": 1}}
    good = Z.AuthorizedOperation("v", "r", Z.params_digest({"a": 1}), "id")
    assert Z.is_authorized_for(Z.AuthorizeResult(allow=True, status=200, operation=good), opb) is True
    assert Z.is_authorized_for(types.SimpleNamespace(allow=True, operation=good), opb) is False
    assert Z.is_authorized_for(Z.AuthorizeResult(allow=False, status=403, operation=good), opb) is False
    listy = Z.AuthorizedOperation("v", "r", Z.params_digest([]), "id")
    assert Z.is_authorized_for(Z.AuthorizeResult(allow=True, status=200, operation=listy),
                               {"verb": "v", "resource": "r", "params": []}) is False

    def boom(_p):
        raise RuntimeError("x")

    monkeypatch.setattr(Z, "params_digest", boom)
    assert Z.is_authorized_for(Z.AuthorizeResult(allow=True, status=200, operation=good), opb) is False


class Bare:
    def claim(self, key, counter):
        return Z.ClaimResult(True)


def test_options_escalation_message():
    with pytest.raises(ValueError) as e:
        Z.AuthorizeOptions(state_store=Bare(), escalation_principals=["pk"])
    assert str(e.value) == ("AuthorizeOptions: escalation_principals needs a state_store with last(key): an escalation answer "
                            "is bound to the holder's history head")


def _options(**over):
    f = dict(plan=object(), context=object(), require=object(), require_assurance=object(), escalation_principals=object(),
             escalation_request_ttl_ms=999, escalation_render=object(), insecure_unbound_approval=object(),
             revocation_staleness=object(), plans=object(), k1=None, uses_store=object(), workflow=object(),
             workflow_step=None, provenance_mediators=object(), provenance_actions=object(), provenance_observed=object(),
             undo_admit=object())
    f.update(over)
    return Z.AuthorizeOptions(state_store=Z.MemoryStateStore(), is_revoked=object(), **f)


def test_options_run_forwards_everything(monkeypatch):
    got = []
    monkeypatch.setattr(Z, "authorize", lambda pc, **k: got.append((pc, k)) or "R")
    o = _options(k1={"b": 2})
    pc, op, rg = object(), object(), object()
    ip, iv, ea, fa, ws, pv, rq, al = (object() for _ in range(8))
    assert o.run(pc, operation=op, audience="A", resolve_grant=rg, now=7, intent_policy=ip, intent_v2=iv, escalation_answer=ea,
                 presented_k1={"a": 1}, fresh_at=fa, workflow=ws, provenance=pv, request=rq, allowed_suites=al) == "R"
    assert got[0][0] is pc
    want = dict(operation=op, audience="A", resolve_grant=rg, state_store=o.state_store, is_revoked=o.is_revoked, now=7,
                plan=o.plan, context=o.context, intent_policy=ip, intent_v2=iv, allowed_suites=al, require=o.require,
                require_assurance=o.require_assurance, escalation_principals=o.escalation_principals, escalation_answer=ea,
                escalation_request_ttl_ms=999, escalation_render=o.escalation_render,
                insecure_unbound_approval=o.insecure_unbound_approval, revocation_staleness=o.revocation_staleness,
                plans=o.plans, k1={"a": 1, "b": 2}, uses_store=o.uses_store, fresh_at=fa, workflow=o.workflow,
                workflow_step=ws, provenance=pv, provenance_request=rq, provenance_mediators=o.provenance_mediators,
                provenance_actions=o.provenance_actions, provenance_observed=o.provenance_observed, undo_admit=o.undo_admit)
    assert got[0][1] == want


def test_options_run_k1_sources(monkeypatch):
    got = []
    monkeypatch.setattr(Z, "authorize", lambda pc, **k: got.append(k["k1"]))
    seen = []
    kw = dict(operation={}, audience="A", resolve_grant=None)
    _options(k1=lambda q: seen.append(q) or {"c": 3}).run("PC", presented_k1={"d": 4}, **kw)
    assert seen == ["PC"] and got[-1] == {"d": 4, "c": 3}

    def boom(q):
        raise RuntimeError("x")

    _options(k1=boom).run("PC", **kw)
    assert got[-1] is None
    _options(k1=UserDict({"a": 1})).run("PC", **kw)
    assert got[-1] is None
    _options(k1=None).run("PC", presented_k1={"d": 4}, **kw)
    assert got[-1] is None


def test_tool_call_checks_the_escalation_store_requirement():
    o = Z.AuthorizeOptions(state_store=Bare(), is_revoked=lambda a, b: False)
    o.escalation_principals = ["pk"]
    r = Z.authorize_tool_call(o, {}, verb="v", resource="r", params={}, audience="A", resolve_grant=lambda ref: None)
    assert r.missing == ["state_store.last (required by escalation_principals)"]
