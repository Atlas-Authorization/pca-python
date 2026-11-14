"""`require_verified_principal` / `resolve_principal` and `require_passport` (reference server/authorize.ts, require-pca.ts)."""
import json
import os

import sys

import pytest

from atlas_pca.authorize import MemoryStateStore, authorize

AZ = sys.modules["atlas_pca.authorize"]  # the module (the package attribute `authorize` is the function)

_HERE = os.path.dirname(os.path.abspath(__file__))


def _vectors():
    for p in (os.path.join(_HERE, "conformance", "vectors.json"), os.path.join(_HERE, "conformance", "vectors.json")):
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return {v["name"]: v for v in json.load(f)["vectors"]}
    raise FileNotFoundError("vectors.json")


V = _vectors()["valid-in-plan-action"]
ACT = V["pcactn"]["action"]


def run(**kw):
    return authorize(V["pcactn"], operation={"verb": ACT["verb"], "resource": ACT["resource"], "params": {}}, audience=V["context"]["aud"],
                     resolve_grant=lambda ref: V["grant"], state_store=MemoryStateStore(), is_revoked=lambda p, g: False,
                     now=V["context"]["now"], **kw)


def test_no_resolver_and_not_required_reports_no_principal_check():
    assert "principal" not in run().checks


def test_a_verified_principal_passes():
    seen = []
    r = run(resolve_principal=lambda pub, grant: seen.append((pub, grant["id"])) or {"pub": pub, "verified": True, "subject_type": "user", "subject_id": "u1"},
            require_verified_principal=True)
    assert r.checks["principal"] == "pass" and seen == [(V["grant"]["issuer"], V["grant"]["id"])]


@pytest.mark.parametrize("resolved", [None, {}, {"verified": False}, {"verified": 0}])
def test_an_unverified_principal_is_refused_only_when_required(resolved):
    r = run(resolve_principal=lambda pub, grant: resolved, require_verified_principal=True)
    assert r.checks["principal"] == "fail" and r.allow is False
    assert "principal: the grant issuer is not an enrolled, verified principal" in r.reasons
    assert run(resolve_principal=lambda pub, grant: resolved).checks["principal"] == "not-enforced"


def test_require_verified_without_a_resolver_is_refused():
    r = run(require_verified_principal=True)
    assert r.checks["principal"] == "fail" and r.allow is False
    assert "principal: requireVerifiedPrincipal needs a resolvePrincipal resolver" in r.reasons


def test_a_resolver_that_raises_denies_fail_closed():
    def boom(pub, grant):
        raise RuntimeError("down")
    r = run(resolve_principal=boom)
    assert r.allow is False and r.reason == "authorize: error (fail closed): RuntimeError"


# ---- passport ----------------------------------------------------------------------------------------------------------------------------

def test_passport_failures_refuse_before_the_pcactn_is_read(monkeypatch):
    calls = []

    def fake(sp, issuers, now, **kw):
        calls.append((sp, issuers, now, kw))
        return "unknown_issuer"
    monkeypatch.setattr("atlas_pca.passport.verify_passport", fake)
    store = MemoryStateStore()
    r = authorize(V["pcactn"], operation={"verb": ACT["verb"], "resource": ACT["resource"], "params": {}}, audience=V["context"]["aud"],
                  resolve_grant=lambda ref: V["grant"], state_store=store, is_revoked=lambda p, g: False, now=V["context"]["now"],
                  require_passport={"trusted_issuers": ["i1"], "now": lambda: 123, "clock_skew_ms": 5, "revoked": "R"}, passport={"p": 1})
    assert r.allow is False and r.reason == "passport: unknown_issuer" and r.checks == {"passport": "fail"}
    leaf = V["pcactn"]["cap_chain"][-1]["holder"]
    assert calls == [({"p": 1}, ["i1"], 123, {"clock_skew_ms": 5, "max_evidence_age_ms": None, "subject": leaf, "revoked": "R", "pq_pins": None,
                                              "attest": None, "default_verifier": None})]
    assert store.last("%s:%s" % (V["grant"]["id"], leaf)) is None  # the replay counter was not touched


def test_a_verifying_passport_lets_the_call_through(monkeypatch):
    monkeypatch.setattr("atlas_pca.passport.verify_passport", lambda *a, **k: None)
    r = run(require_passport={"trusted_issuers": ["i1"]}, passport={"passport": {"hardware_rooted": False}})
    assert r.checks.get("passport") is None and "passport" not in r.reasons


def test_hardware_needs_a_passport_whose_hardware_evidence_verified(monkeypatch):
    rp = {"trusted_issuers": ["i1"], "hardware": True}
    # the passport verifier accepts hardware_rooted only after its evidence verified (and says why when it did not)
    monkeypatch.setattr("atlas_pca.passport.verify_passport", lambda *a, **k: None)
    assert run(require_passport=rp, passport={"passport": {"hardware_rooted": False}}).reason == "passport: hardware_evidence_missing"
    assert run(require_passport=rp, passport={"passport": {"hardware_rooted": True}}).reason != "passport: hardware_evidence_missing"
    assert run(require_passport={"trusted_issuers": ["i1"]}, passport={"passport": {"hardware_rooted": False}}).reason != "passport: hardware_evidence_missing"
    for why in ("hardware_verifier_missing", "hardware_attestation_failed", "hardware_identity_mismatch"):
        monkeypatch.setattr("atlas_pca.passport.verify_passport", lambda *a, why=why, **k: why)
        assert run(require_passport=rp, passport={"passport": {"hardware_rooted": True}}).reason == "passport: " + why


def test_an_unreadable_pcactn_is_left_to_the_guard(monkeypatch):
    monkeypatch.setattr("atlas_pca.passport.verify_passport", lambda *a, **k: pytest.fail("no leaf: no passport check"))
    r = authorize("not json", operation={"verb": "v", "resource": "r", "params": {}}, audience="a", resolve_grant=lambda ref: None,
                  state_store=MemoryStateStore(), is_revoked=lambda p, g: False, require_passport={"trusted_issuers": []})
    assert r.allow is False and r.status == 401


def test_options_carry_the_new_fields():
    o = AZ.AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=lambda p, g: False, plan="single-step", require_verified_principal=True)
    assert o.resolve_principal is None and o.require_verified_principal is True and o.require_passport is None


# ---- the passport gate on an allow: assurance entry and the subject recheck --------------------------------------------------------------

def _admitted(monkeypatch, pcactn):
    """The guard admits and reports ``pcactn`` as the verified proof."""
    monkeypatch.setattr(AZ, "_authorize", lambda *a, **k: AZ.AuthorizeResult(allow=True, status=200, decision="allow", pcactn=pcactn))
    monkeypatch.setattr("atlas_pca.passport.verify_passport", lambda *a, **k: None)


def _gated(presented, **rp):
    return authorize(presented, operation={"verb": "v", "resource": "r", "params": {}}, audience="a", resolve_grant=lambda ref: None,
                     state_store=MemoryStateStore(), is_revoked=lambda p, g: False,
                     require_passport=dict({"trusted_issuers": ["i1"]}, **rp), passport={"passport": {"hardware_rooted": rp.get("rooted", False)}})


def _proof(holder):
    return {"cap_chain": [{"holder": holder}]}


def test_an_allow_carries_the_passport_assurance(monkeypatch):
    _admitted(monkeypatch, _proof("leaf"))
    r = _gated(_proof("leaf"))
    assert r.allow is True and r.assurance["passport"] == {"outcome": "pass", "level": "software"}


def test_a_hardware_rooted_allow_reports_the_verifier_label(monkeypatch):
    _admitted(monkeypatch, _proof("leaf"))
    attest = AZ.set_assurance_label(lambda doc, expected: {}, "hardware", vendor="amd-sev-snp")
    r = _gated(_proof("leaf"), attest=attest, rooted=True)
    assert r.assurance["passport"] == {"outcome": "pass", "level": "hardware", "vendor": "amd-sev-snp"}
    assert _gated(_proof("leaf"), attest=lambda d, e: {}, rooted=True).assurance["passport"] == {"outcome": "pass", "level": "unknown"}


def test_an_unreadable_leaf_never_allows_under_the_gate(monkeypatch):
    _admitted(monkeypatch, _proof("leaf"))
    r = _gated("not json")
    assert r.allow is False and r.status == 403 and r.checks == {"passport": "fail"} and r.reason == "passport: subject_mismatch"


def test_a_different_verified_leaf_never_allows_under_the_gate(monkeypatch):
    _admitted(monkeypatch, _proof("another"))
    r = _gated(_proof("leaf"))
    assert r.allow is False and r.reason == "passport: subject_mismatch"
