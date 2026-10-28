"""authorize() assurance labels (0.5, T8).

Every result says what each check rests on; features this SDK does not implement (zk compliance, attestation, threshold
co-signatures, bonds, a suite whose backend is missing) are ``unsupported`` and never a pass; ``require_assurance``
denies weaker, missing or unsupported evidence before any replay state is written.
"""
import json
import os
import sys

import pytest

from atlas_pca import AuthorizeOptions, MemoryStateStore, assurance_report, authorize, unmet_assurance

az = sys.modules["atlas_pca.authorize"]  # the module (`atlas_pca.authorize` the attribute is the function)
HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "testdata", "authorize-fixtures.json"), encoding="utf-8") as f:
    FIX = json.load(f)
NOW = FIX["now"]
AUD = FIX["audience"]


def case(name):
    return next(c for c in FIX["cases"] if c["name"] == name)


class SpyStore(MemoryStateStore):
    def __init__(self):
        super().__init__()
        self.claims = 0

    def claim(self, key, counter):
        self.claims += 1
        return super().claim(key, counter)


def run(name, store=None, **kw):
    c = case(name)
    s = c["steps"][0]
    return authorize(s["pcactn"], operation=s["operation"], audience=AUD, resolve_grant=lambda ref: c["grant"],
                     state_store=store if store is not None else MemoryStateStore(), is_revoked=lambda p, g: False, now=NOW,
                     plan="single-step", **kw)


def test_every_result_carries_the_report():
    r = run("envelope-predicate-within")
    assert r.allow is True
    assert r.assurance["leaf_signature"] == {"outcome": "pass", "level": "ed25519", "suites": ["ed25519"]}
    assert r.assurance["chain"] == {"outcome": "pass", "level": "ed25519", "suites": ["ed25519"]}
    assert r.assurance["counter_format"] == {"outcome": "pass"}
    assert r.assurance["replay"] == {"outcome": "pass"}
    assert "counter" not in r.assurance
    assert {k: v["outcome"] for k, v in r.assurance.items()} == r.checks
    # a refusal before verification reports its check
    c = case("envelope-predicate-within")
    refused = authorize(c["steps"][0]["pcactn"], operation=c["steps"][0]["operation"], audience=AUD,
                        resolve_grant=lambda ref: c["grant"], state_store=None, is_revoked=lambda p, g: False, now=NOW)
    assert refused.allow is False
    assert refused.assurance == {"authorize_config": {"outcome": "fail"}}


def test_attestation_is_unsupported_here():
    r = run("attestation-bound")
    assert r.allow is False
    assert r.checks["attestation"] == "fail"  # the released status is unchanged (B7)
    assert r.assurance["attestation"] == {"outcome": "unsupported",
                                          "reason": "attestation verification is not implemented by this SDK"}


@pytest.mark.parametrize("req, why", [
    ({"signature": "pq"}, "assurance: post-quantum signatures required but leaf_signature is ed25519"),
    ({"attestation": "software"}, "assurance: software attestation required but there is no attestation evidence"),
    ({"zk": "attested_vm"}, "assurance: zk compliance (attested_vm) required but there is no zk_compliance evidence"),
    ({"threshold": ["multisig"]}, "assurance: threshold (multisig) required but there is no threshold evidence"),
    ({"signature": "classical"}, "assurance: unknown signature requirement 'classical' (fail closed)"),
    ({"hardware": True}, "assurance: unknown assurance requirement(s): hardware (fail closed)"),
    ("hardware", "assurance: unknown assurance requirement(s): invalid (fail closed)"),
])
def test_require_assurance_denies_before_the_claim(req, why):
    store = SpyStore()
    r = run("envelope-predicate-within", store, require_assurance=req)
    assert {"allow": r.allow, "status": r.status, "assurance": r.checks.get("assurance"), "reason": r.reason} == \
        {"allow": False, "status": 403, "assurance": "fail", "reason": why}
    assert store.claims == 0


def test_an_empty_requirement_passes_and_the_options_forward_it():
    store = SpyStore()
    r = run("envelope-predicate-within", store, require_assurance={})
    assert (r.allow, r.checks["assurance"], store.claims) == (True, "pass", 1)
    o = AuthorizeOptions(state_store=MemoryStateStore(), is_revoked=lambda p, g: False,
                         require_assurance={"signature": "pq"})
    c = case("envelope-predicate-within")
    d = o.run(c["steps"][0]["pcactn"], operation=c["steps"][0]["operation"], audience=AUD,
              resolve_grant=lambda ref: c["grant"], now=NOW)
    assert (d.allow, d.checks["assurance"]) == (False, "fail")


def test_without_the_option_nothing_changes():
    r = run("envelope-predicate-within")
    assert "assurance" not in r.checks


# ---- the pure report ---------------------------------------------------------------------------------------------

def test_unsupported_features_are_reported_and_deny_any_requirement():
    p = {"cap_chain": [{"alg": "hybrid-ed25519-ml-dsa-65"}], "alg": "hybrid-ed25519-ml-dsa-65",
         "zk_compliance": {"v": 1}, "threshold": {"shares": []}, "bond_ref": "b"}
    rep = assurance_report(p, {"leaf_signature": "pass", "chain": "pass", "zk_compliance": "fail"})
    assert rep == {
        "leaf_signature": {"outcome": "pass", "level": "hybrid", "suites": ["hybrid-ed25519-ml-dsa-65"]},
        "chain": {"outcome": "pass", "level": "hybrid", "suites": ["hybrid-ed25519-ml-dsa-65"]},
        "zk_compliance": {"outcome": "unsupported", "reason": "zk compliance verification is not implemented by this SDK"},
        "threshold": {"outcome": "unsupported", "reason": "threshold co-signatures are not verified by this SDK"},
        "bond": {"outcome": "unsupported", "reason": "bond verification is not implemented by this verifier"},
    }
    assert unmet_assurance(rep, {}) == ("assurance: unsupported: zk_compliance (zk compliance verification is not implemented "
                                        "by this SDK); a high-assurance policy never accepts it")
    plain = assurance_report({"cap_chain": [{"alg": "hybrid-ed25519-ml-dsa-65"}], "alg": "ml-dsa-65"},
                             {"leaf_signature": "pass", "chain": "pass"})
    assert unmet_assurance(plain, {"signature": "pq"}) is None
    assert plain["leaf_signature"]["level"] == "pq"


def test_signature_levels(monkeypatch):
    monkeypatch.setattr(az, "suite_available", lambda alg: True)  # a failure here is a plain failure, not a missing backend
    weak = assurance_report({"cap_chain": [{"alg": "hybrid-ed25519-ml-dsa-65"}, {}], "alg": "ml-dsa-65"},
                            {"leaf_signature": "pass", "chain": "pass"})
    assert weak["chain"] == {"outcome": "pass", "level": "ed25519", "suites": ["hybrid-ed25519-ml-dsa-65", "ed25519"]}
    assert unmet_assurance(weak, {"signature": "pq"}) == "assurance: post-quantum signatures required but chain is ed25519"
    failed = assurance_report({"cap_chain": [{}], "alg": "ml-dsa-65"}, {"leaf_signature": "fail", "chain": "pass"})
    assert unmet_assurance(failed, {"signature": "pq"}) == \
        "assurance: post-quantum signatures required but the leaf_signature check is fail"
    assert [az._sig_level(a) for a in (None, "ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "nope", 7)] == \
        ["ed25519", "ed25519", "pq", "hybrid", "unknown", "unknown"]


def test_a_suite_without_a_backend_is_unsupported(monkeypatch):
    monkeypatch.setattr(az, "suite_available", lambda alg: alg == "ed25519")
    rep = assurance_report({"cap_chain": [{"alg": "ml-dsa-65"}], "alg": "ml-dsa-65"},
                           {"leaf_signature": "fail", "chain": "fail"})
    assert rep["leaf_signature"] == {"outcome": "unsupported",
                                     "reason": "signature suite 'ml-dsa-65' has no backend in this runtime"}
    assert rep["chain"] == {"outcome": "unsupported", "reason": "a capability suite has no backend in this runtime"}
    # a plain failure of an available suite stays a failure
    monkeypatch.setattr(az, "suite_available", lambda alg: True)
    assert assurance_report({"alg": "ml-dsa-65"}, {"leaf_signature": "fail"}) == {"leaf_signature": {"outcome": "fail"}}
