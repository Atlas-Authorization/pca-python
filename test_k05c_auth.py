"""Kill tests (agent, authorize, break_glass, decision, escalation, missing_context, operations, readside, stepup, sigstore):
defaults and hand-offs the existing suites do not pin."""
import inspect
import os
import sqlite3
import sys
import threading

import pytest

from atlas_pca import agent as AG
from atlas_pca import break_glass as BG
from atlas_pca import decision as DC
from atlas_pca import escalation as ES
from atlas_pca import missing_context as MC
from atlas_pca import operations as OP
from atlas_pca import readside as RS
from atlas_pca import stepup as SU
from atlas_pca.pca import b64u

AZ = sys.modules["atlas_pca.authorize"]  # the module (the package attribute `authorize` is the function)


# ---- agent

def _producer():
    from test_agent_producer import RoundTrip
    t = RoundTrip("test_chain_verifies")
    t.setUp()
    return t


def test_agent_public_is_its_key():
    t = _producer()
    a = AG.Agent(t.agent_key, t.grant, "rs-test")
    assert a.public == t.agent_key.public


def test_act_defaults_the_lifetime_to_the_agent_ttl():
    t = _producer()
    a = AG.Agent(t.agent_key, t.grant, "rs-test", clock=lambda: 1_800_000_000_000, ttl_ms=12_345)
    p = a.act("refund", "orders/1").pcactn
    assert p["exp"] - p["iat"] == 12_345
    p = a.act("refund", "orders/1", ttl_ms=777).pcactn
    assert p["exp"] - p["iat"] == 777


# ---- authorize

def test_sqlite_state_store_busy_timeout_default(tmp_path):
    s = AZ.SqliteStateStore(str(tmp_path / "s.db"))
    assert s._conn().execute("PRAGMA busy_timeout").fetchone() == (30000,)


def test_consume_once_drops_expired_rows_and_extends_a_refused_one(tmp_path):
    path = str(tmp_path / "once.db")
    s = AZ.SqliteStateStore(path)
    assert s.consume_once("a", 100, 50) is True
    assert s.consume_once("b", 300, 200) is True
    db = sqlite3.connect(path)
    assert db.execute("SELECT key, retain_until FROM %s ORDER BY key" % s.ONCE_TABLE).fetchall() == [("b", 300)]  # "a" expired at 100 < 200
    assert s.consume_once("m", 500, 270) is True
    assert s.consume_once("m", 900, 280) is False           # refused (retained until 500) ...
    assert db.execute("SELECT retain_until FROM %s WHERE key = 'm'" % s.ONCE_TABLE).fetchone() == (900,)   # ... and its horizon is extended
    assert s.consume_once("m", 1000, 800) is False          # 900 >= 800: still retained
    db.close()


def test_a_fault_in_the_stock_evaluator_leaves_the_caveat_unsatisfied(monkeypatch):
    def boom(*a):
        raise RuntimeError("boom")

    monkeypatch.setattr(AZ, "evaluate_caveats", boom)
    assert AZ._agent_caveat_satisfied({"type": "max_spend", "max": 1}, {}, {}, {}) is False


def test_malformed_agent_caveats_are_unsatisfied():
    assert AZ._agent_caveat_satisfied(5, {}, {}, {}) is False
    assert AZ._agent_caveat_satisfied({"type": "sealed"}, 5, {}, {}) is False


def test_tool_call_passes_the_escalation_principals_to_the_component_check():
    class NoLast:
        pass

    o = AZ.AuthorizeOptions(escalation_principals=["pk"])
    object.__setattr__(o, "state_store", NoLast())
    object.__setattr__(o, "is_revoked", lambda *a: False)
    r = AZ.authorize_tool_call(o, "x", verb="v", resource="r", params={}, audience="aud", resolve_grant=lambda *a: None)
    assert r.allow is False and "state_store.last (required by escalation_principals)" in (r.missing or [])


# ---- decision / escalation

def test_unit_confusion_ignores_terms_that_are_not_action_param_paths():
    tag = {"kind": "money", "currency": "USD", "exponent": 2}
    inp = {"units": {}, "verb": "v", "schema_units": {"u": tag}, "verb_params": {"bad": {"unit": "u"}},
           "predicates": [[{"verb": "v", "where": [{"field": "bad", "op": "eq", "value": 1}]}]]}
    assert DC.decide_units(inp) == {"ok": True}


def test_the_first_pin_naming_the_principal_decides(monkeypatch):
    t = _producer()
    a = AG.Agent(t.agent_key, t.grant, "rs-test")
    p = a.act("refund", "orders/1").pcactn
    now = p["iat"]
    req = AG.build_escalation_request("rs-test", t.grant, p, 0, ["escalate: big refund"], now)
    ans = AG.sign_escalation_answer(t.principal, req, "allow", now, now + 60_000)
    bind = {k: req[k] for k in ("policy_digest", "action_digest", "history_head")}
    pins = [{"pk": t.principal.public, "marker": 1}, {"pk": t.principal.public, "marker": 2}]
    seen = []
    monkeypatch.setattr(ES, "verify_artifact_sig", lambda d, answer, pin: seen.append(pin) or False)
    assert ES.verify_escalation_answer(ans, pins, bind, now) == {"ok": False, "reason": "escalation answer signature invalid"}
    assert seen == [pins[0]]


# ---- missing_context

def test_bound_values_are_deep_copied_into_the_context():
    supplied = {"env": {"x": [{"a": 1}]}}
    r = MC.bind_context({"env": {}}, supplied)
    supplied["env"]["x"][0]["a"] = 2
    assert r["context"]["env"]["x"] == [{"a": 1}]


# ---- operations

def test_operation_store_protocol_methods_are_abstract():
    s = OP.OperationStore()
    for call in (lambda: s.create({}), lambda: s.get("i"), lambda: s.transition("i", "a", {})):
        with pytest.raises(NotImplementedError):
            call()


# ---- readside

def test_redact_read_refuses_each_malformed_request_stage(monkeypatch):
    monkeypatch.setattr(RS, "_grade_grant", lambda g, p, n: ({}, None))
    deny = RS._out("deny", "bad_request")
    ok = {"grant": {}, "principal": b64u(bytes(32)), "now": 1, "verb": "v", "resource": "r", "purpose": "p", "salt": "s" * 16,
          "schema": {"fields": {"a": "pub"}, "required": []}, "record": {}, "tighten": {}, "counts": {}}
    assert RS.redact_read(dict(ok, verb=5)) == deny
    assert RS.redact_read(dict(ok, schema=None)) == deny
    assert RS.redact_read(dict(ok, record={"a": {}})) == deny
    assert RS.redact_read(dict(ok, tighten=5)) == deny
    assert RS.redact_read(dict(ok, tighten={"A": "x"})) == deny
    assert RS.redact_read(dict(ok, counts=5)) == deny
    assert RS.redact_read(dict(ok, counts={"A": 1})) == deny
    assert RS.redact_read(dict(ok, salt="short")) == deny
    assert RS.redact_read(dict(ok, principal="x")) == deny
    assert RS.redact_read(dict(ok, schema={"fields": {"a": "pub"}, "required": ["b"]})) == deny


# ---- stepup

class _Store(SU.SecretStore):
    def __init__(self):
        self.seed = None

    def load(self):
        return self.seed

    def save(self, secret):
        self.seed = secret


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_file_secret_store_tightens_an_existing_file(tmp_path):
    path = tmp_path / "k"
    path.write_text("x")
    os.chmod(path, 0o644)
    SU.FileSecretStore(str(path)).save(bytes(32))
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_device_key_exists_is_false_when_the_store_faults_and_import_persists_the_seed():
    class Bad(SU.SecretStore):
        def load(self):
            raise RuntimeError("boom")

    assert SU.PrincipalDeviceKey(Bad()).exists is False
    store = _Store()
    k = SU.PrincipalDeviceKey(store)
    assert k.exists is False
    seed = os.urandom(32)
    k.import_secret(b64u(seed))
    assert store.seed == seed and k.exists is True


def test_transport_sends_the_given_method_url_headers_and_body(monkeypatch):
    seen = {}

    class Resp:
        status = 204

        def read(self):
            return b""

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Opener:
        def open(self, req, timeout=None):
            seen["req"], seen["timeout"] = req, timeout
            return Resp()

    monkeypatch.setattr(SU, "_OPENER", Opener())
    assert SU._urllib_transport(7)("DELETE", "https://h.example/x", {"X-A": "b"}, b"body") == (204, "")
    req = seen["req"]
    assert req.get_method() == "DELETE" and req.full_url == "https://h.example/x" and req.data == b"body" and seen["timeout"] == 7
    assert req.get_header("X-a") == "b"


def test_step_up_urls_quote_every_path_segment():
    k = SU.PrincipalDeviceKey(_Store())
    c = SU.StepUpClient("https://dash.example/", "https://inst.example", "acct/1", "i:d/2", k, lambda: "t", transport=lambda *a: (200, "[]"))
    assert c._stepups_url() == "https://dash.example/v1/dashboard/accounts/acct%2F1/instances/i%3Ad%2F2/pca/stepups"


# ---- sigstore: the CA search stops at the CA that issued the certificate

def test_ca_search_stops_at_the_first_issuing_ca(monkeypatch):
    pytest.importorskip("cryptography")
    from atlas_pca import sigstore_bundle as S
    from k05_oracle import dec
    from test_k05_sigstore_diff import CASES, ROOTS
    n = 0
    seen = {"n": 0}
    real = S._chain_ok

    def spy(*a):
        seen["n"] += 1
        return real(*a)

    monkeypatch.setattr(S, "_chain_ok", spy)
    for c in CASES["verifySigstoreBundleCore"]:
        if n >= 3:
            break
        if not c["out"].get("ok"):
            continue
        b, ref = dec(c["args"])
        roots = ROOTS[ref["$root"]]
        if not roots.cas:
            continue
        seen["n"] = 0
        assert S.verify_sigstore_bundle_core(b, roots)["ok"] is True
        single = seen["n"]
        seen["n"] = 0
        assert S.verify_sigstore_bundle_core(b, roots._replace(cas=list(roots.cas) + list(roots.cas)))["ok"] is True
        assert seen["n"] == single
        n += 1
    assert n >= 1
