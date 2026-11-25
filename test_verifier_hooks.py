"""The attestation and zk verifier hooks of the core (verify_pcactn_core(attestation_hook=, zk_hook=)) and of authorize(attestation=, zk=).
A carried zk_compliance proof is verified when a zk hook enforces it and is REFUSED otherwise (no hook, or a hook that did not enforce):
the fail-closed default. The PCActn, grant and statement are the reference's (testdata/ref-zk.json.gz, case createZkVerifier/ok)."""
import copy
import inspect
import os

import importlib

A = importlib.import_module("atlas_pca.authorize")  # the package re-exports the function under the module's name
from atlas_pca import zk as Z
from atlas_pca.pca import verify_pcactn_core
from base_oracle import HERE, load

_, CASES = load("zk", os.path.join(HERE, "testdata", "ref-zk.json.gz"))
SPEC, CTX = next(c for c in CASES["createZkVerifier"] if c["name"] == "createZkVerifier/ok")["args"]
P, GRANT, NOW = CTX["pcactn"], CTX["grant"], SPEC["nowMs"]
PLAIN = {k: v for k, v in P.items() if k != "zk_compliance"}


def _core(p=P, **kw):
    return verify_pcactn_core(copy.deepcopy(p), GRANT, now=NOW, audience=P["aud"], insecure_skip_plan_root_check=True, **kw)


def _zk_hook(**over):
    kw = {"policy_commitments": SPEC["policyCommitments"], "now": lambda: NOW}
    kw.update(over)
    return Z.create_zk_verifier(SPEC["trustedProverKeys"], **kw)


def test_a_carried_proof_with_no_zk_hook_is_refused():
    v = _core()
    assert v.allow is False and v.checks["zk_compliance"] is False


def test_a_hook_that_does_not_enforce_is_refused_like_no_hook():
    for res in ({}, {"enforced": False, "ok": True}, {"ok": True}):
        v = _core(zk_hook=lambda _ctx, res=res: res)
        assert v.allow is False and v.checks["zk_compliance"] is False, res


def test_the_zk_verifier_hook_passes_the_check_for_a_valid_statement():
    seen = []

    def hook(ctx, inner=_zk_hook()):
        seen.append(ctx)
        return inner(ctx)
    v = _core(zk_hook=hook)
    assert v.checks["zk_compliance"] is True
    assert len(seen) == 1 and seen[0]["grant"] == GRANT and seen[0]["nowEpoch"] == NOW and seen[0]["pcactn"]["zk_compliance"] == P["zk_compliance"]


def test_the_zk_verifier_hook_fails_the_check_for_a_rejected_statement():
    assert _core(zk_hook=Z.create_zk_verifier([], now=lambda: NOW)).checks["zk_compliance"] is False
    assert _core(zk_hook=_zk_hook(now=lambda: NOW + 10 ** 9)).checks["zk_compliance"] is False
    tampered = copy.deepcopy(P)
    tampered["zk_compliance"]["plan_commit"] = "AAAA"
    assert _core(tampered, zk_hook=_zk_hook()).checks["zk_compliance"] is False


def test_an_enforced_refusal_without_a_reason_and_a_raising_hook_both_deny():
    assert _core(zk_hook=lambda _ctx: {"enforced": True, "ok": False}).checks["zk_compliance"] is False

    def boom(_ctx):
        raise RuntimeError("verifier down")
    v = _core(zk_hook=boom)
    assert v.allow is False and v.checks.get("zk_compliance") is not True and v.checks.get("malformed") is False


def test_no_carried_proof_means_no_zk_check_and_the_hook_is_not_called():
    called = []
    v = _core(PLAIN, zk_hook=lambda ctx: called.append(ctx) or {"enforced": True, "ok": True})
    assert "zk_compliance" not in v.checks and called == []
    assert v.checks == _core(PLAIN).checks


def test_the_attestation_hook_passes_fails_or_stays_unreported():
    assert _core(PLAIN, attestation_hook=lambda _ctx: {"enforced": True, "ok": True}).checks["attestation"] is True
    v = _core(PLAIN, attestation_hook=lambda _ctx: {"enforced": True, "ok": False, "reason": "measurement not allowlisted"})
    assert v.allow is False and v.checks["attestation"] is False
    assert "attestation" not in _core(PLAIN, attestation_hook=lambda _ctx: {"enforced": False}).checks
    assert "attestation" not in _core(PLAIN).checks
    seen = []
    _core(PLAIN, attestation_hook=lambda ctx: seen.append(ctx) or {})
    assert len(seen) == 1 and seen[0]["grant"] == GRANT and seen[0]["nowEpoch"] == NOW


def test_a_passing_attestation_hook_alone_changes_only_that_check():
    base, withhook = _core(PLAIN), _core(PLAIN, attestation_hook=lambda _ctx: {"enforced": True, "ok": True})
    assert {k: v for k, v in withhook.checks.items() if k != "attestation"} == base.checks and withhook.allow == base.allow


def test_authorize_takes_and_forwards_both_hooks():
    for fn in (A.authorize, A._authorize):
        params = inspect.signature(fn).parameters
        assert params["attestation"].default is None and params["zk"].default is None
    opts = A.AuthorizeOptions()
    assert opts.attestation is None and opts.zk is None
    hook = Z.create_zk_verifier([])
    assert A._hooks_of(None, None, None, hook) == {"zk": hook} and A._hooks_of({"zk": "mine"}, None, hook, hook) == {"zk": "mine", "attestation": hook}
    report = A.assurance_report(P, {"zk_compliance": "pass"}, None, hooks=A._hooks_of(None, None, None, hook))
    assert report["zk_compliance"]["outcome"] == "pass" and report["zk_compliance"]["level"] == "attested_vm"


# ---- the server guard forwards both hooks (the reference's requirePCA `hooks`) -------------------------------------------

def _guard_headers(p):
    from atlas_pca.pca import b64u, canonical_bytes_strict
    return {"PCA-Action": b64u(canonical_bytes_strict(p))}


def test_the_signature_only_guard_forwards_the_zk_and_attestation_hooks():
    from atlas_pca import require_pca
    kw = dict(audience=P["aud"], resolve_grant=lambda _ref: GRANT, now=NOW, signature_only=True)
    bare = require_pca(**kw)(_guard_headers(P))
    assert bare.ok is False and bare.status == 403 and bare.verdict.checks["zk_compliance"] is False
    seen = []

    def att(ctx):
        seen.append(ctx)
        return {"enforced": True, "ok": True}
    r = require_pca(hooks={"zk": _zk_hook(), "attestation": att}, **kw)(_guard_headers(P))
    assert r.verdict.checks["zk_compliance"] is True and r.verdict.checks["attestation"] is True
    assert r.verdict.checks == _core(zk_hook=_zk_hook(), attestation_hook=att).checks and r.ok is r.verdict.allow
    assert len(seen) == 2 and seen[0]["grant"] == GRANT and seen[0]["nowEpoch"] == NOW
    denied = require_pca(hooks={"attestation": lambda _ctx: {"enforced": True, "ok": False}}, **kw)(_guard_headers(PLAIN))
    assert denied.ok is False and denied.status == 403 and denied.verdict.checks["attestation"] is False
    for bad in (5, "zk", [_zk_hook()]):
        try:
            require_pca(hooks=bad, **kw)
        except TypeError:
            continue
        raise AssertionError("hooks=%r accepted" % (bad,))


def test_the_authorize_guard_forwards_the_hooks_and_the_authorize_options_win(monkeypatch):
    from atlas_pca import require_pca
    got = []

    def spy(pcactn, **kw):
        got.append((kw.get("attestation"), kw.get("zk")))
        return A.AuthorizeResult(allow=False, status=403, reason="spy")
    monkeypatch.setattr(A, "authorize", spy)
    h1, h2, own = (lambda _c: {}), (lambda _c: {}), (lambda _c: {})
    kw = dict(audience=P["aud"], resolve_grant=lambda _ref: GRANT, now=NOW, operation=lambda _h, _b: {"verb": "v", "resource": "r", "params": {}})
    require_pca(hooks={"attestation": h1, "zk": h2}, **kw)(_guard_headers(P))
    require_pca(hooks={"attestation": h1, "zk": h2}, authorize={"zk": own}, **kw)(_guard_headers(P))
    require_pca(hooks={"zk": h2}, authorize=A.AuthorizeOptions(attestation=own), **kw)(_guard_headers(P))
    require_pca(**kw)(_guard_headers(P))
    assert got == [(h1, h2), (h1, own), (own, h2), (None, None)]


def test_the_attestation_option_builds_the_hook_per_request_and_an_explicit_hook_wins():
    from atlas_pca import require_pca
    kw = dict(audience=P["aud"], resolve_grant=lambda _ref: GRANT, now=NOW, signature_only=True)
    # no server-issued binding: the built hook is closed, so the attestation check is a denial (fail closed), never skipped
    closed = require_pca(attestation={"trustedAttestorKeys": []}, **kw)(_guard_headers(P))
    assert closed.verdict.checks["attestation"] is False and closed.ok is False
    # the built hook is consulted with the verifier context (expectedBinding is the server's own source of the binding)
    clocks = []
    opts = {"trustedAttestorKeys": [], "expectedBinding": lambda ctx: clocks.append(ctx["nowEpoch"])}
    require_pca(attestation=opts, **kw)(_guard_headers(P))
    assert clocks and clocks[0] == NOW
    # an explicit hook wins over the option
    explicit = require_pca(attestation={"trustedAttestorKeys": []}, hooks={"attestation": lambda _c: {"enforced": True, "ok": True}}, **kw)(_guard_headers(P))
    assert explicit.verdict.checks["attestation"] is True
