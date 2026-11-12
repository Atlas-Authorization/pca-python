"""k05 mutation-kill tests, group "server": a2a, missing_context, obligations, server, django, fastapi and store_conformance.
Expectations follow the TypeScript references (pca-need.ts, missing-context.ts, obligations.ts) and the module docs. Deterministic."""
import asyncio
import copy
import json
import threading
from collections.abc import Mapping

import pytest

from atlas_pca import a2a as A
from atlas_pca import missing_context as MC
from atlas_pca import obligations as O
from atlas_pca import server
from atlas_pca import store_conformance as SC
from atlas_pca.agent import _sign_body, keypair_from_seed
from atlas_pca.authorize import AuthorizeOptions, AuthorizeResult
from atlas_pca.pca import BOND_UNSUPPORTED, Verdict, b64u
from atlas_pca.pca_grant import chain_digest
from atlas_pca.refusal_help import refusal_doc_url
from test_server import AUD, NOW, PCACTN, _header_value, _resolver

HV = _header_value(PCACTN)


def _b64(x):
    return b64u(json.dumps(x).encode("utf-8"))


# ================================================================================================================== a2a

BASE_NEED = {"v": 1, "kind": "scope", "verb": "read", "resource": "r"}


def _need(**kw):
    return A.validate_need(dict(BASE_NEED, **kw))


def _ok(**kw):
    return _need(**kw)["ok"]


def test_need_string_fields_and_bounds():
    assert _ok(verb="v" * 128) and not _ok(verb="v" * 129) and not _ok(verb="")
    assert _ok(resource="r" * 512) and not _ok(resource="r" * 513)
    for k in ("grant_ref", "policy_digest"):
        assert _ok(**{k: "g" * 128})
        assert _need(**{k: "g" * 129}) == {"ok": False, "code": "bad_field"}
        assert _need(**{k: ""}) == {"ok": False, "code": "bad_field"}
        assert _need(**{k: 5}) == {"ok": False, "code": "bad_field"}


def test_need_scopes():
    assert _ok(scopes=["s" * 128]) and _ok(scopes=[]) and _ok(scopes=["s"] * 16)
    assert not _ok(scopes=["s" * 129]) and not _ok(scopes=["s"] * 17) and not _ok(scopes=["a b"]) and not _ok(scopes="x")


def test_need_tier_and_version():
    esc = dict(kind="escalate")
    assert _ok(tier=2, **esc) and _ok(tier=3, **esc) and not _ok(tier=4, **esc) and not _ok(tier=1, **esc)
    assert not _ok(tier=2) and not _ok(**esc)
    assert A.validate_need(dict(BASE_NEED, v=1.0))["ok"] is True
    for v in (2, 2.0, True, "1"):
        assert A.validate_need(dict(BASE_NEED, v=v)) == {"ok": False, "code": "bad_version"}


def test_need_limits():
    assert _ok(limits={"a": 0}) and _ok(limits={"a": 0.5}) and _ok(limits={"k" * 64: 1})
    assert not _ok(limits={"k" * 65: 1}) and not _ok(limits={"a": -1})
    assert _ok(limits={"k%d" % i: 1 for i in range(16)}) and not _ok(limits={"k%d" % i: 1 for i in range(17)})
    assert not _ok(limits={"a": float("nan")}) and not _ok(limits={"a": float("inf")}) and not _ok(limits={"a": True})
    assert _need(limits=[]) == {"ok": False, "code": "bad_field"}


def test_need_discharges():
    d = {"issuer": "i" * 512, "claim": "c" * 256}
    assert _ok(discharges=[]) and _ok(discharges=[d]) and _ok(discharges=[d] * 16)
    assert not _ok(discharges=[d] * 17) and not _ok(discharges={}) and not _ok(discharges="x")
    assert not _ok(discharges=[dict(d, issuer="i" * 513)]) and not _ok(discharges=[dict(d, claim="c" * 257)])
    assert not _ok(discharges=[dict(d, claim="")]) and not _ok(discharges=[dict(d, issuer="")])
    assert not _ok(discharges=[dict(d, extra=1)]) and not _ok(discharges=[5])


def test_decode_need_length_boundary_and_utf8():
    assert A.decode_need("A" * 2048) == {"ok": False, "code": "bad_json"}  # exactly the limit is not too long
    assert A.decode_need("A" * 2049) == {"ok": False, "code": "too_long"}
    assert A.decode_need(None) == {"ok": False, "code": "bad_base64"}
    assert A.decode_need(b64u(b"\xff\xfe")) == {"ok": False, "code": "bad_utf8"}


def test_resume_gate_no_need():
    assert A.resume_gate("TASK_STATE_AUTH_REQUIRED", None, "x", {}) == "no_valid_need"
    assert A.resume_gate("TASK_STATE_AUTH_REQUIRED", "!", "x", {}) == "no_valid_need"


def test_chain_extension_first_hop():
    assert A.check_chain_extension([["a"], ["a", "b"]]) == {"ok": True}
    assert A.check_chain_extension([["a"], ["b"]]) == {"ok": False, "failedHop": 1, "reason": "chain_does_not_extend_previous_hop"}


def test_check_push_empty_task_id_without_payload_task():
    salt = "s" * 16
    tok = A.push_token("", ["a"], salt)
    assert A.check_push("", ["a"], salt, tok, {}) == {"ok": False, "reason": "task_mismatch"}
    tok = A.push_token("t", ["a"], salt)
    assert A.check_push("t", ["a"], salt, tok, {"task": {"id": "t"}}) == {"ok": True}


KP = keypair_from_seed(bytes(range(32)))
CH = b64u(b"\x01" * 32)
_DEL = object()


def _rcpt(kp=KP, **ov):
    base = {"v": 1, "task_id": "t", "state": "TASK_STATE_WORKING", "seq": 0, "prev": None, "chain": CH, "issued_at": 1, "signer": kp.public}
    base.update(ov)
    base = {k: v for k, v in base.items() if v is not _DEL}
    body = {k: base[k] for k in ("v", "task_id", "state", "seq", "prev", "chain", "issued_at", "signer") if k in base}
    return dict(base, sig=_sign_body(kp, A.RECEIPT_DOMAIN, body))


def test_verify_receipt_every_structural_refusal_on_a_signed_receipt():
    ok = lambda r: A.verify_receipt(r, KP.public)  # noqa: E731
    assert ok(_rcpt()) and ok(_rcpt(seq=1, prev=CH))
    bad = [
        _rcpt(v=2), _rcpt(v=True), _rcpt(signer="other"), _rcpt(task_id=""), _rcpt(task_id=5), _rcpt(state="BAD"),
        _rcpt(seq=-1, prev=CH), _rcpt(issued_at=-1), _rcpt(chain=b64u(b"\x01" * 16)), _rcpt(chain=None),
        _rcpt(seq=1, prev=b64u(b"\x01" * 16)), _rcpt(seq=1, prev="short"), _rcpt(seq=1, prev="!!"), _rcpt(seq=1, prev=5),
        _rcpt(seq=0, prev=CH), _rcpt(seq=1, prev=None), _rcpt(prev=_DEL), dict(_rcpt(), sig=5),
    ]
    for i, r in enumerate(bad):
        assert ok(r) is False, i
    assert A.verify_receipt([], KP.public) is False


def test_receipt_chain_broken_link_each_half():
    ids = ["cap"]
    ch = chain_digest(ids)
    r0 = _rcpt(chain=ch)
    good = _rcpt(chain=ch, seq=1, prev=A.receipt_digest(r0))
    assert A.check_receipt_chain([r0, good], KP.public, "t", ids) == {"ok": True, "terminal": False, "last_state": "TASK_STATE_WORKING"}
    bad_seq = _rcpt(chain=ch, seq=2, prev=A.receipt_digest(r0))
    bad_prev = _rcpt(chain=ch, seq=1, prev=CH)
    for r in (bad_seq, bad_prev):
        assert A.check_receipt_chain([r0, r], KP.public, "t", ids) == {"ok": False, "code": "broken_link", "at": 1}


# ================================================================================================================== missing_context

BOUND = {"action": {"verb": "v", "resource": "r", "params": {"amount": 1}}, "subject": {"id": "u"}, "env": {"tier": "gold"}}
ASTRAL, BMP = "\U00010000", "￿"  # UTF-16 order: ASTRAL < BMP; code point order: BMP < ASTRAL


def test_supplier_table_forbidden_segments():
    for k in ("env.constructor", "action.params.__proto__", "subject.a.prototype"):
        assert MC.supplier_table_error({k: "principal"}) == "bad supplier path '%s'" % k
    assert MC.supplier_table_error({"env.a": "x"}) == "bad supplier for 'env.a'"


def _nest(n, leaf):
    v = leaf
    for _ in range(n):
        v = {"a": v}
    return v


def test_leaves_depth_boundary_and_order():
    out = {}
    MC._leaves(_nest(17, 1), "p", out)
    assert out == {"p" + ".a" * 17: 1}
    out = {}
    MC._leaves(_nest(18, 1), "p", out)
    assert out == {"p" + ".a" * 17: {"a": 1}}
    out = {}
    MC._leaves({BMP: 1, ASTRAL: 2}, "p", out)
    assert list(out) == ["p." + ASTRAL, "p." + BMP]


def test_bind_does_not_alias_the_bound_context():
    b = copy.deepcopy(BOUND)
    r = MC.bind_context(b, {"action": {"params": {"x": 2}}})
    assert r["context"]["action"]["params"] == {"amount": 1, "x": 2} and r["conflicts"] == []
    assert b == BOUND


def test_bind_creates_an_absent_action_with_defaults():
    r = MC.bind_context({"env": {}}, {"action": {"params": {"a": 1}}})
    assert r == {"context": {"env": {}, "action": {"verb": "", "resource": "", "params": {"a": 1}}}, "conflicts": [], "dropped": []}


def test_bind_refuses_to_write_below_or_over_a_bound_non_object():
    r = MC.bind_context({"action": "s"}, {"action": {"params": {"a": 1}}})
    assert r == {"context": {"action": "s"}, "conflicts": ["action.params.a"], "dropped": []}
    r = MC.bind_context({"action": {}, "env": "x"}, {"env": {"a": 1}})
    assert r == {"context": {"action": {}, "env": "x"}, "conflicts": ["env.a"], "dropped": []}
    r = MC.bind_context(5, {"env": {"a": 1}})
    assert r == {"context": 5, "conflicts": ["env.a"], "dropped": []}
    deep = MC.bind_context({"env": {"a": {"b": "x"}}}, {"env": {"a": {"b": {"c": 1}}}})
    assert deep["conflicts"] == ["env.a.b.c"] and deep["context"] == {"env": {"a": {"b": "x"}}}
    shallow = MC.bind_context({"env": {"a": "x"}}, {"env": {"a": {"b": {"c": 1}}}})
    assert shallow["conflicts"] == ["env.a.b.c"]
    # every blocked path is reported, not just the first
    many = MC.bind_context({"env": {"a": "s", "b": "t"}}, {"env": {"a": {"x": 1}, "b": {"y": 1}}})
    assert many["conflicts"] == ["env.a.x", "env.b.y"]


def test_bind_conflict_and_drop_order_follow_utf16():
    r = MC.bind_context({"env": {BMP: 0, ASTRAL: 0}}, {"env": {BMP: 1, ASTRAL: 1}})
    assert r["conflicts"] == ["env." + ASTRAL, "env." + BMP]
    r = MC.bind_context({"action": {}}, {"env": {BMP: 1, ASTRAL: 2}}, {"env": "agent_declared_untrusted"})
    assert r["dropped"] == ["env." + ASTRAL, "env." + BMP]


def test_bind_a_dropped_path_does_not_stop_the_rest():
    r = MC.bind_context({"action": {}}, {"env": {"a": 1, "b": 2}}, {"env.a": "agent_declared_untrusted"})
    assert r == {"context": {"action": {}, "env": {"b": 2}}, "conflicts": [], "dropped": ["env.a"]}


def test_bind_fails_closed_when_a_step_raises(monkeypatch):
    def boom(path, table):
        raise RuntimeError

    monkeypatch.setattr(MC, "supplier_of", boom)
    r = MC.bind_context({"action": {}}, {"env": {BMP: 1, ASTRAL: 2}})
    assert r["conflicts"] == ["env." + ASTRAL, "env." + BMP]

    class Bad(dict):
        def get(self, *a):
            raise RuntimeError

    assert MC.bind_context({"action": {}}, Bad())["conflicts"] == ["?"]


B2 = {"action": {"verb": "v", "resource": "r"}, "env": {"a": 1}}


def _cond(f, op="eq", value=1):
    return {"field": f, "op": op, "value": value}


def test_decide_group_children_are_evaluated_against_the_context():
    r = MC.decide_with_missing([{"all_of": [_cond("env.a"), _cond("env.b")]}], B2)
    assert r == {"decision": "escalate", "reason": "escalate: missing_context principal:env.b",
                 "missing": [{"path": "env.b", "supplier": "principal"}]}


def test_decide_single_character_field_is_missing_context():
    r = MC.decide_with_missing([_cond("x")], B2)
    assert r["decision"] == "escalate" and r["missing"] == [{"path": "x", "supplier": "principal"}]


def test_decide_ill_typed_conditions():
    assert MC.decide_with_missing([[1]], B2) == {"decision": "deny", "reason": "ill_typed_context", "missing": []}
    assert MC.decide_with_missing([_cond("env.b"), [1]], B2) == {"decision": "deny", "reason": "ill_typed_context", "missing": []}


def test_decide_params_that_are_not_an_object_are_missing():
    b = {"action": {"verb": "v", "resource": "r", "params": "s"}}
    r = MC.decide_with_missing([_cond("action.params")], b)
    assert r["decision"] == "escalate" and r["missing"] == [{"path": "action.params", "supplier": "principal"}]


def test_decide_missing_order_and_untrusted_join():
    r = MC.decide_with_missing([_cond("env." + BMP), _cond("env." + ASTRAL)], B2)
    assert [m["path"] for m in r["missing"]] == ["env." + ASTRAL, "env." + BMP]
    assert r["reason"] == "escalate: missing_context principal:env.%s,principal:env.%s" % (ASTRAL, BMP)
    r = MC.decide_with_missing([_cond("env.p"), _cond("env.q")], B2, None, {"env": "agent_declared_untrusted"})
    assert r["decision"] == "deny" and r["reason"] == "missing_context_untrusted: env.p,env.q"
    assert r["missing"] == [{"path": "env.p", "supplier": "agent_declared_untrusted"}, {"path": "env.q", "supplier": "agent_declared_untrusted"}]


def test_decide_fails_closed(monkeypatch):
    def boom(t):
        raise RuntimeError

    monkeypatch.setattr(MC, "supplier_table_error", boom)
    assert MC.decide_with_missing([_cond("env.a")], B2) == {"decision": "deny", "reason": "evaluation error (fail closed)", "missing": []}


# ================================================================================================================== obligations

def _oe(o):
    return O.obligation_error(o)


def test_obligation_param_limits_and_messages():
    assert _oe({"kind": "log", "params": {"sink": "s" * 128}}) is None
    for p in ({"sink": "s" * 129}, {"sink": ""}):
        assert _oe({"kind": "log", "params": p}) == "log.sink must be a non-empty string of at most 128 characters"
    assert _oe({"kind": "notify", "params": {"to": "t" * 256}}) is None
    assert _oe({"kind": "notify", "params": {"to": "t" * 257}}) == "notify.to is required (a non-empty string of at most 256 characters)"
    assert _oe({"kind": "watermark", "params": {"id": "t" * 128}}) is None
    assert _oe({"kind": "watermark", "params": {"id": "t" * 129}}) == "watermark.id is required (a non-empty string of at most 128 characters)"
    assert _oe({"kind": "undo_window", "params": {"id": "x"}}) == (
        "undo_window needs id (a non-empty string of at most 128 characters) and window_end (a non-negative safe integer)")
    assert _oe({"kind": "log", "due": -1}) == "due must be a non-negative safe integer"
    assert _oe({"kind": "log", "params": []}) == "params must be an object"


def test_obligation_redact_fields():
    fields = ["f%d" % i for i in range(32)]
    assert _oe({"kind": "redact", "params": {"fields": fields}}) is None
    msg = "redact.fields must be 1..32 dotted field paths"
    assert _oe({"kind": "redact", "params": {"fields": fields + ["g"]}}) == msg
    assert _oe({"kind": "redact", "params": {"fields": []}}) == msg
    assert _oe({"kind": "redact", "params": {"fields": ["1x"]}}) == msg
    assert _oe({"kind": "redact", "params": {"fields": ["a", "a"]}}) == "redact.fields has a duplicate"


def test_obligation_key_includes_due():
    assert O.obligation_key({"kind": "log", "due": 5}) == O.canonicalize_strict({"kind": "log", "params": {}, "due": 5})
    assert O.obligation_key({"kind": "log", "due": 5}) != O.obligation_key({"kind": "log"})
    assert O.obligation_key({"kind": "log", "due": 5}) != O.obligation_key({"kind": "log", "due": 6})


def _logs(prefix, n):
    return [{"kind": "log", "params": {"sink": "%s%d" % (prefix, i)}} for i in range(n)]


def test_merge_limit_and_failure_shape(monkeypatch):
    one = O.merge_obligations(_logs("a", 16))
    assert one["ok"] is True and len(one["obligations"]) == 16
    over = O.merge_obligations(_logs("a", 16), _logs("b", 16))
    assert over == {"ok": False, "reason": "more than 16 obligations after merging"}

    def boom(x):
        raise RuntimeError

    monkeypatch.setattr(O, "obligations_error", boom)
    assert O.merge_obligations([]) == {"ok": False, "reason": "evaluation error (fail closed)"}


def test_gate_lists_unsupported_kinds_sorted():
    obs = [{"kind": "watermark", "params": {"id": "x"}}, {"kind": "log"}]
    r = O.pep_obligation_gate("allow", False, obs, [])
    assert r["unsupported"] == ["log", "watermark"] and r["decision"] == "deny"
    assert r["reason"] == "the enforcement point does not support obligation(s) log, watermark"


def test_outcome_bad_inputs_are_overdue_everything(monkeypatch):
    obs = [{"kind": "require_receipt"}]
    want = {"outcome": "escalate", "overdue": [0], "status": "obligation_unmet"}
    assert O.obligation_outcome(obs, "", 1) == want  # not a list
    assert O.obligation_outcome(obs, 5, 1) == want
    assert O.obligation_outcome([{"kind": "zzz"}], [], 1) == want  # malformed obligations
    assert O.obligation_outcome(obs, [], 1) == {"outcome": "ok", "overdue": []}

    def boom(x):
        raise RuntimeError

    monkeypatch.setattr(O, "obligations_error", boom)
    assert O.obligation_outcome(obs, [], 1) == {"outcome": "escalate", "overdue": [], "status": "obligation_unmet"}


# ================================================================================================================== server

def test_get_header_edge_cases():
    g = server._get_header
    assert g({"x": []}, "x") is None
    assert g({"pca-action": 5, "PCA-Action": "v"}, "PCA-Action") == "v"

    class Fast:
        def get(self, k):
            return "fast" if k == "X-A" else None

        def items(self):
            return []

    assert g(Fast(), "X-A") == "fast" and g(Fast(), "x-a") is None


class _Exact(Mapping):
    """A case-sensitive mapping that keeps duplicates in insertion order."""

    def __init__(self, pairs):
        self.pairs = pairs

    def __getitem__(self, k):
        for a, b in self.pairs:
            if a == k:
                return b
        raise KeyError(k)

    def __iter__(self):
        return iter([a for a, _ in self.pairs])

    def __len__(self):
        return len(self.pairs)


def test_presented_k1_reads_the_exact_header_first():
    h = _Exact([("pca-discharges", _b64(["b"])), ("PCA-Discharges", _b64(["a"])), ("pca-narrow", _b64("nb")), ("PCA-Narrow", _b64("na"))])
    assert server.presented_k1(h) == {"discharges": ["a"], "narrow": "na"}


def test_presented_k1_error_messages():
    with pytest.raises(ValueError, match=r"^PCA-Discharges must be a JSON array$"):
        server.presented_k1({"PCA-Discharges": _b64({"a": 1})})


def test_presented_k1_wraps_foreign_errors(monkeypatch):
    class Boom(Exception):
        pass

    def bad(text):
        raise Boom()

    monkeypatch.setattr(server, "strict_parse", bad)
    with pytest.raises(ValueError, match=r"^unreadable K1 header: Boom$") as ei:
        server.presented_k1({"PCA-Narrow": _b64(1)})
    assert isinstance(ei.value.__cause__, Boom)


def test_as_authorize_options_type_error_text():
    with pytest.raises(TypeError, match=r"^authorize must be an AuthorizeOptions, a dict of its fields, or None$"):
        server.as_authorize_options(5)


def test_escalation_answer_and_workflow_from_the_body():
    assert server.extract_escalation_answer({}, '{"escalation_answer": {"k": 1}}') == {"k": 1}
    assert server.extract_escalation_answer({}, "[1]") is None and server.extract_escalation_answer({}, None) is None
    assert server.extract_escalation_answer({"PCA-Escalation-Answer": _b64({"h": 1})}, None) == {"h": 1}
    assert server.extract_workflow_step({}, '{"workflow": {"s": 1}}') == {"s": 1}
    assert server.extract_workflow_step({}, "[1]") is None and server.extract_workflow_step({}, None) is None


def test_workflow_callback_receives_headers_and_body():
    seen = []
    h, b = {"X": "1"}, b"body"
    assert server.extract_workflow_step(h, b, lambda a, c: seen.append((a, c)) or "step") == "step"
    assert seen[0][0] is h and seen[0][1] is b

    def boom(a, c):
        raise RuntimeError

    assert server.extract_workflow_step(h, b, boom) == {}


VERDICT = Verdict(allow=False)


def _az(workflow=None, step=None):
    az = AuthorizeOptions()
    az.workflow = workflow
    az.workflow_step = step
    az.calls = []

    def run(pcactn, **kw):
        az.calls.append((pcactn, kw))
        return AuthorizeResult(allow=False, status=403, reason="why", decision="deny", verdict=VERDICT)

    az.run = run
    return az


def test_workflow_refusal_passes_everything_to_authorize():
    seen = []
    az = _az(workflow="not-a-mapping", step=lambda h, b: seen.append((h, b)) or {"s": 1})
    g = server.require_pca(audience=AUD, resolve_grant=_resolver, now=NOW, authorize=az)
    headers, body = {"X": "1"}, '{"escalation_answer": {"z": 1}}'
    r = g(headers, body)
    assert seen[0][0] is headers and seen[0][1] is body
    pcactn, kw = az.calls[0]
    assert pcactn is None and kw["workflow"] == {"s": 1} and kw["fresh_at"] is None
    assert kw["request"][0] is headers and kw["request"][1] is body
    assert kw["escalation_answer"] == {"z": 1} and kw["presented_k1"] == {}
    assert (r.ok, r.status, r.error) == (False, 403, "why")
    assert r.verdict is VERDICT and r.authorization is not None
    assert r.www_authenticate == server.challenge(AUD, "insufficient_authority")


def test_authorize_mode_unreadable_discharges_are_no_discharges():
    az = _az()
    g = server.require_pca(audience=AUD, resolve_grant=_resolver, now=NOW, authorize=az)
    r = g({"PCA-Action": HV, "PCA-Discharges": "!!"}, None)
    pcactn, kw = az.calls[0]
    assert pcactn == PCACTN and kw["presented_k1"] == {} and r.pcactn == PCACTN and r.verdict is VERDICT


def test_bond_ref_is_refused_with_the_full_result(monkeypatch):
    v = Verdict(allow=True)
    monkeypatch.setattr(server, "verify_pcactn_core", lambda p, g, **kw: v)
    p = dict(PCACTN, bond_ref="b")
    g = server.require_pca(audience=AUD, resolve_grant=_resolver, now=NOW, signature_only=True)
    r = g({}, json.dumps({"pcactn": p}))
    assert (r.ok, r.status, r.error) == (False, 403, BOND_UNSUPPORTED)
    assert r.verdict is v and r.pcactn == p
    assert r.www_authenticate == 'PCA realm="pca", audience="%s", error="insufficient_authority"' % AUD


def test_fresh_at_callable_gets_the_pcactn(monkeypatch):
    got = {}
    monkeypatch.setattr(server, "verify_pcactn_core", lambda p, g, **kw: got.update(kw) or Verdict(allow=True))
    seen = []
    g = server.require_pca(audience=AUD, resolve_grant=_resolver, now=NOW, signature_only=True,
                           fresh_at=lambda p: seen.append(p) or {"signer": "s"})
    g({"PCA-Action": HV}, None)
    assert seen == [PCACTN] and got["fresh_at"] == {"signer": "s"}


# ================================================================================================================== django

DJ_AZ = AuthorizeOptions()


def dj_op(request):
    return None


def _dj_settings():
    from test_server_exact import _django
    s = _django()
    for n in ("PCA_SIGNATURE_ONLY", "PCA_AUDIENCE", "PCA_RESOLVE_GRANT", "PCA_NOW", "PCA_INTENT_V2", "PCA_INTENT_POLICY",
              "PCA_FRESH_AT", "PCA_AUTHORIZE", "PCA_OPERATION", "PCA_ALLOWED_SUITES"):
        if hasattr(s, n):
            delattr(s, n)
    s.PCA_AUDIENCE = AUD
    s.PCA_RESOLVE_GRANT = _resolver
    return s


@pytest.fixture
def dj(monkeypatch):
    pytest.importorskip("django")
    s = _dj_settings()
    import atlas_pca.django as mod

    seen = {}
    calls = []

    def fake(**kw):
        seen.clear()
        seen.update(kw)

        def guard(headers, body=None, **k):
            calls.append((headers, body, k))
            return server.PCAResult(ok=True, status=200, verdict=None, pcactn={})
        return guard

    monkeypatch.setattr(mod, "require_pca", fake)
    yield s, mod, seen, calls
    for n in ("PCA_SIGNATURE_ONLY", "PCA_AUDIENCE", "PCA_RESOLVE_GRANT", "PCA_AUTHORIZE", "PCA_OPERATION", "PCA_ALLOWED_SUITES"):
        if hasattr(s, n):
            delattr(s, n)


def test_django_dotted_authorize_and_operation(dj):
    s, mod, seen, _ = dj
    s.PCA_AUTHORIZE = "test_k05_kill_server.DJ_AZ"
    s.PCA_OPERATION = "test_k05_kill_server.dj_op"
    mw = mod.PCAMiddleware(lambda r: None)
    assert seen["authorize"] is DJ_AZ and mw._operation is dj_op and seen["signature_only"] is False


def test_django_configuration_messages(dj):
    from django.core.exceptions import ImproperlyConfigured
    s, mod, seen, _ = dj
    s.PCA_AUTHORIZE = 5
    with pytest.raises(ImproperlyConfigured, match=r"^settings\.PCA_AUTHORIZE must be an AuthorizeOptions, a dict of its fields or a dotted path to one$"):
        mod.PCAMiddleware(lambda r: None)
    s.PCA_AUTHORIZE = {}
    s.PCA_SIGNATURE_ONLY = True
    with pytest.raises(ImproperlyConfigured, match=r"^settings\.PCA_SIGNATURE_ONLY and settings\.PCA_AUTHORIZE are mutually exclusive$"):
        mod.PCAMiddleware(lambda r: None)
    del s.PCA_SIGNATURE_ONLY
    with pytest.raises(ImproperlyConfigured, match=r"^settings\.PCA_AUTHORIZE needs settings\.PCA_OPERATION: a callable \(request\) -> \{verb, resource, params\} or its dotted path$"):
        mod.PCAMiddleware(lambda r: None)


def test_django_settings_reach_the_guard(dj):
    s, mod, seen, _ = dj
    s.PCA_SIGNATURE_ONLY = True
    s.PCA_OPERATION = 5
    s.PCA_ALLOWED_SUITES = ["x"]
    mw = mod.PCAMiddleware(lambda r: None)
    assert mw._operation is None and seen["allowed_suites"] == ["x"] and "authorize" not in seen


def test_django_guard_call_arguments(dj):
    from django.test import RequestFactory
    s, mod, seen, calls = dj
    s.PCA_AUTHORIZE = {}

    def op(request):
        raise RuntimeError

    s.PCA_OPERATION = op
    mw = mod.PCAMiddleware(lambda r: "resp")
    req = RequestFactory().post("/x", data=b"abc", content_type="application/octet-stream")
    assert mw(req) == "resp"
    headers, body, k = calls[0]
    assert body == b"abc" and k == {"operation": None}
    r = mw._deny(server.PCAResult(ok=False, status=403, error="replay"))
    assert json.loads(r.content)["doc"] == refusal_doc_url("replay") and json.loads(r.content)["doc"].endswith("#replay")


# ================================================================================================================== fastapi

class _Req:
    def __init__(self, body=b"data"):
        self.headers = {"H": "1"}
        self._body = body

        class state:  # noqa: N801
            pass
        self.state = state

    async def body(self):
        return self._body


def _fa_dep(monkeypatch, result, **kw):
    pytest.importorskip("fastapi")
    import atlas_pca.fastapi as fa

    seen, calls = {}, []

    def fake(**k):
        seen.update(k)

        def guard(headers, body=None, **o):
            calls.append((headers, body, o))
            return result
        return guard

    monkeypatch.setattr(fa, "require_pca", fake)
    return fa, fa.RequirePCA(audience=AUD, resolve_grant=_resolver, **kw), seen, calls


def test_fastapi_refusal_class():
    pytest.importorskip("fastapi")
    import atlas_pca.fastapi as fa

    cls = fa._refusal_class()
    assert cls is not None and cls is fa._refusal_class()
    e = cls(403, "d", {"a": "b"}, "u")
    assert (e.status_code, e.detail, e.headers, e.doc) == (403, "d", {"a": "b"}, "u")
    e2 = cls(401, "x")
    assert e2.doc == "" and e2.headers is None and e2.status_code == 401 and e2.detail == "x"


def test_fastapi_operation_and_guard_arguments(monkeypatch):
    ok = server.PCAResult(ok=True, status=200, verdict=None, pcactn={})
    fa, dep, seen, calls = _fa_dep(monkeypatch, ok, authorize={}, allowed_suites=["x"])
    assert seen["allowed_suites"] == ["x"]
    req = _Req()
    asyncio.run(dep(req))
    assert calls[0][1] == b"data" and calls[0][2] == {"operation": None}
    got = []
    fa, dep, seen, calls = _fa_dep(monkeypatch, ok, authorize={}, operation=lambda r, b: got.append((r, b)) or {"verb": "v"})
    asyncio.run(dep(req))
    assert got == [(req, b"data")] and calls[0][2] == {"operation": {"verb": "v"}}

    def boom(r, b):
        raise RuntimeError

    fa, dep, seen, calls = _fa_dep(monkeypatch, ok, authorize={}, operation=boom)
    asyncio.run(dep(req))
    assert calls[0][2] == {"operation": None} and calls[0][1] == b"data"


def test_fastapi_refusal_detail():
    pytest.importorskip("fastapi")
    from fastapi import HTTPException

    def refuse(monkeypatch, **res):
        fa, dep, _, _ = _fa_dep(monkeypatch, server.PCAResult(ok=False, status=403, **res), authorize={})
        with pytest.raises(HTTPException) as ei:
            asyncio.run(dep(_Req()))
        return ei.value

    mp = pytest.MonkeyPatch()
    try:
        e = refuse(mp, error=None, decision="escalate", escalation={"k": 1})
        assert e.detail == {"error": "escalation required", "decision": "escalate", "escalation": {"k": 1}}
        assert e.headers is None and e.doc == refusal_doc_url("escalation required")
        e = refuse(mp, error="e", decision="escalate", escalation={"k": 1}, www_authenticate="w")
        assert e.detail == {"error": "e", "decision": "escalate", "escalation": {"k": 1}} and e.headers == {"WWW-Authenticate": "w"}
        e = refuse(mp, error=None, decision="deny")
        assert e.detail == "proof-carrying authority required"
        e = refuse(mp, error="q", decision="deny")
        assert e.detail == "q"
    finally:
        mp.undo()


# ================================================================================================================== store_conformance

class _SBe:
    def __init__(self):
        self.lock = threading.Lock()
        self.last = {}
        self.log = []
        self.n = 0


class _SH:
    def __init__(self, be):
        self.be = be
        self.id = be.n
        be.n += 1

    def claim(self, key, counter):
        with self.be.lock:
            self.be.log.append((self.id, key, counter))
            last = self.be.last.get(key)
            if last is not None and counter <= last:
                return (False, last)
            self.be.last[key] = counter
            return (True,)


def test_state_conformance_calls_the_store_with_the_documented_keys_and_counters():
    import re
    be = _SBe()
    rep = SC.run_state_store_conformance(lambda: _SH(be), threads=2, rounds=2, handles=2, restart=lambda: None)
    assert rep.ok and [r.status for r in rep.results] == ["pass"] * 6
    by = {}
    for hid, key, c in be.log:
        by.setdefault(key, []).append((hid, c))
    runs = {k.split(":", 1)[1] for k in by}
    assert len(runs) == 1 and re.fullmatch(r"[0-9a-f]{12}", next(iter(runs)))
    run = next(iter(runs))
    cs = lambda name: [c for _, c in by[name + ":" + run]]  # noqa: E731
    assert set(by) == {n + ":" + run for n in ("seq", "seq-other", "burst", "conc", "dur", "crash", "retry")}
    assert cs("seq") == [1, 1, 5, 3, 5] and cs("seq-other") == [2 - 1]
    assert sorted(cs("burst")) == [1, 1, 2, 2] and sorted(cs("conc")) == [1, 1, 2, 2]
    assert cs("dur") == [7, 7, 8] and cs("crash") == [1, 1, 2]
    retry = by["retry:" + run]
    assert [c for _, c in retry[:3]] == [1, 1, 2] and sorted(c for _, c in retry[3:]) == [3, 3]
    assert len({h for h, c in retry if c == 3}) == 2  # the in-flight race uses two different handles


class _OBe:
    def __init__(self):
        self.lock = threading.Lock()
        self.recs = {}
        self.log = []
        self.returned = []


class _OH:
    def __init__(self, be):
        self.be = be

    def create(self, record):
        with self.be.lock:
            self.be.log.append(("create", record))
            if record["id"] in self.be.recs:
                return dict(self.be.recs[record["id"]])
            self.be.recs[record["id"]] = dict(record)
            return None

    def get(self, i):
        with self.be.lock:
            self.be.log.append(("get", i))
            r = self.be.recs.get(i)
            r = None if r is None else dict(r)
            self.be.returned.append((i, r))
            return r

    def transition(self, i, frm, nxt):
        with self.be.lock:
            self.be.log.append(("transition", i, frm, dict(nxt)))
            cur = self.be.recs.get(i)
            if cur is None or cur["state"] != frm:
                return False
            self.be.recs[i] = dict(nxt)
            return True


def test_operation_conformance_passes_the_documented_records():
    import re
    be = _OBe()
    rep = SC.run_operation_store_conformance(lambda: _OH(be), threads=2, rounds=2, handles=2, restart=lambda: None)
    assert rep.ok and [r.status for r in rep.results] == ["pass"] * 6
    tr = [e for e in be.log if e[0] == "transition"]
    cr = [e for e in be.log if e[0] == "create"]

    def of(prefix):
        return [e for e in tr if e[1].startswith(prefix + ":")]

    run = re.fullmatch(r"op-sem:([0-9a-f]{12})", next(e[1] for e in tr if e[1].startswith("op-sem:"))).group(1)
    sem = "op-sem:" + run
    rec = lambda i, st: {"id": i, "state": st, "verb": "v", "resource": "/r", "params_digest": "d", "reversibility": "reversible", "startedAt": 1}  # noqa: E731
    assert [e for e in tr if e[1] == "nope:" + run] == [("transition", "nope:" + run, "pending", rec("nope", "pending"))]
    sem_calls = [e[1:] for e in tr if e[1] == sem]
    assert sem_calls == [(sem, "executing", rec(sem, "executing")),
                         (sem, "pending", dict(rec(sem, "executing"), executingAt=2)),
                         (sem, "pending", rec(sem, "aborted"))]
    assert [e[1]["verb"] for e in cr if e[1]["id"] == sem] == ["v", "other"]
    # copies: the helper mutates what get returned and what it handed to create
    assert [r for i, r in be.returned if i == "op-copy:" + run][0]["state"] == "committed"
    assert [e[1] for e in cr if e[1]["id"] == "op-copy:" + run + "-b"][0]["state"] == "failed"
    for prefix in ("op-cas", "op-shared"):
        calls = of(prefix)
        assert calls and all(re.fullmatch(prefix + r":[0-9a-f]{12}(:\d+)?", e[1]) for e in calls)
        assert all(e[2] == "pending" and e[3]["id"] == e[1] and e[3]["state"] == "executing" for e in calls)
        assert {e[3]["executingAt"] for e in calls} == {0, 1}
    assert all(re.fullmatch(r"op-create:" + run + r":\d+", e[1]["id"]) for e in cr if e[1]["id"].startswith("op-create"))
    dur = of("op-dur")
    assert len(dur) == 1 and dur[0][3]["id"] == dur[0][1] and dur[0][3]["state"] == "executing" and dur[0][3]["executingAt"] == 3
