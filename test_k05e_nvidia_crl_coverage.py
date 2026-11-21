"""NVIDIA CRL coverage: by default every non-root chain certificate that names a CRL distribution point must be covered by a
verified CRL from its issuer. Before 0.5 any ONE fresh CRL (for example only the root's) satisfied the check, so a revoked device
certificate passed. Mirrors packages/pca/src/mutation-kill-nvidia-crl-coverage.test.ts (the TypeScript reference)."""
import pytest

pytest.importorskip("cryptography")

from cryptography import x509

from atlas_pca import attest_nvidia as N
from atlas_pca.attest_amd import AttestConstructError
from atlas_pca.attest_cert import Cert
from test_attest_units import NOW
from test_k05_kill_attest_crypto import W, crl, mk
from test_k05_kill_attest_nv import hctx, mkhook, rim_ok

LEAF = "O=Acme, CN=NV Leaf"
INTER = "CN=NV Inter"


def _cdp():
    return x509.CRLDistributionPoints([x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier("http://crl.example/ica.crl")], relative_name=None, reasons=None, crl_issuer=None)])


def cdp_chain():
    """leaf 0 <- inter 1 <- root 2; the leaf and the intermediate both name a CRL distribution point."""
    w = W()
    inter = mk("NV Inter", "NV Root", w.inter.public_key(), w.root, 0x2002, True, extra=[(_cdp(), False)])
    leaf = mk(("Acme", "NV Leaf"), "NV Inter", w.leaf.public_key(), w.inter, 0x2001, False, extra=[(_cdp(), False)])
    return [Cert(leaf), Cert(inter), Cert(w.root_der)]


def plain_chain():
    w = W()
    return [Cert(w.leaf_der), Cert(w.inter_der), Cert(w.root_der)]


def rev(chain, crls, *rest):
    return N.check_nvidia_chain_revocation(chain, crls, NOW, *rest)


def missing(subject):
    return {"ok": False, "reason": "no verified CRL from the issuer of chain certificate '%s'" % subject}


def test_fixture_precondition_cdp_presence():
    assert [(N._CDP_OID_DER in c.raw) for c in cdp_chain()] == [True, True, False]
    assert [(N._CDP_OID_DER in c.raw) for c in plain_chain()] == [False, False, False]


def test_the_root_crl_alone_no_longer_satisfies_the_default():
    w = W()
    ch = cdp_chain()
    assert rev(ch, [crl(w.root)]) == missing(LEAF)  # before the fix: passed
    assert rev(ch, [crl(w.root)], None, "cdp") == missing(LEAF)
    # the intermediate's CRL alone leaves the intermediate (CDP, issued by the root) uncovered
    assert rev(ch, [crl(w.inter)]) == missing(INTER)


def test_a_crl_from_the_issuer_of_every_cdp_certificate_passes():
    w = W()
    assert rev(cdp_chain(), [crl(w.inter), crl(w.root)]) == {"ok": True, "verifiedCrls": 2}


def test_a_revoked_certificate_still_fails_as_revoked():
    w = W()
    assert rev(cdp_chain(), [crl(w.inter, [0x2001]), crl(w.root)]) == {"ok": False, "reason": "chain certificate '%s' is revoked" % LEAF}
    assert rev(cdp_chain(), [crl(w.inter), crl(w.root, [0x2002])]) == {"ok": False, "reason": "chain certificate '%s' is revoked" % INTER}


def test_all_demands_a_crl_for_certificates_without_a_cdp_and_cdp_does_not():
    w = W()
    ch = plain_chain()
    assert rev(ch, [crl(w.inter)], None, "cdp") == {"ok": True, "verifiedCrls": 1}
    assert rev(ch, [crl(w.inter)]) == {"ok": True, "verifiedCrls": 1}
    assert rev(ch, [crl(w.inter)], None, "all") == missing(INTER)
    assert rev(ch, [crl(w.inter), crl(w.root)], None, "all") == {"ok": True, "verifiedCrls": 2}


def test_an_explicit_index_list_demands_exactly_those_certificates():
    w = W()
    ch = plain_chain()
    assert rev(ch, [crl(w.inter)], None, [0]) == {"ok": True, "verifiedCrls": 1}
    assert rev(ch, [crl(w.inter)], None, [1]) == missing(INTER)
    assert rev(ch, [crl(w.inter)], None, []) == {"ok": True, "verifiedCrls": 1}


@pytest.mark.parametrize("bad,text", [(2, "2"), (3, "3"), (-1, "-1"), (1.5, "1.5"), (True, "true"), ("0", "0")])
def test_an_index_that_is_not_a_non_root_chain_certificate_fails_with_its_text(bad, text):
    w = W()
    assert rev(plain_chain(), [crl(w.inter), crl(w.root)], None, [bad]) == {
        "ok": False, "reason": "requireCrlFor index %s is not a non-root chain certificate" % text}


def test_none_demands_no_coverage_but_still_enforces_what_was_supplied():
    w = W()
    ch = cdp_chain()
    assert rev(ch, [crl(w.root)], None, "none") == {"ok": True, "verifiedCrls": 1}
    assert rev(ch, [crl(w.inter, [0x2001])], None, "none")["ok"] is False


def test_a_chain_with_no_cdp_anywhere_demands_nothing_beyond_the_supplied_crls():
    w = W()
    assert rev(plain_chain(), [crl(w.root)]) == {"ok": True, "verifiedCrls": 1}
    assert rev([], [crl(w.root)])["ok"] is False  # no chain certificate verifies it: unchanged


def test_the_issuer_requirement_is_additive_to_the_coverage():
    w = W()
    assert rev(cdp_chain(), [crl(w.root)], ["NV Root"]) == missing(LEAF)
    assert rev(cdp_chain(), [crl(w.inter), crl(w.root)], ["NV Root"]) == {"ok": True, "verifiedCrls": 2}


# ---- through the collateral hook: the policy reaches the check only when CRLs are required --------------------------------------

def _flow(monkeypatch, **opts):
    monkeypatch.setattr(N, "verify_nvidia_rim", lambda xml, pins, now: rim_ok() if xml == "D" else rim_ok("GH100", "96.00.9F.00.04"))
    monkeypatch.setattr(N, "compare_report_to_rims", lambda r, d, v: {"ok": True})
    monkeypatch.setattr(N, "check_nvidia_chain_ocsp", lambda chain, ocsp, now: {"ok": True})
    seen = []
    monkeypatch.setattr(N, "check_nvidia_chain_revocation", lambda chain, crls, now, req, rcf: (seen.append(rcf), {"ok": True})[1])
    bundle = {"driverRimXml": "D", "vbiosRimXml": "V", "crls": [b"c"], "ocsp": [b"o"]}
    assert mkhook(resolve=lambda ids, ev: bundle, **opts)(hctx()) is None
    return seen


@pytest.mark.parametrize("opts,want", [
    ({}, ["cdp"]),
    ({"revocation": "crl"}, ["cdp"]),
    ({"revocation": "both"}, ["cdp"]),
    ({"revocation": "both", "requireCrlFor": "all"}, ["all"]),
    ({"requireCrlFor": [0, 1]}, [[0, 1]]),
    ({"requireCrlFor": None}, ["cdp"]),
    ({"revocation": "ocsp"}, ["none"]),
    ({"revocation": "ocsp", "requireCrlFor": "all"}, ["none"]),
    ({"requireCrls": False}, ["none"]),
])
def test_the_hook_passes_the_policy_only_when_crls_are_required(monkeypatch, opts, want):
    assert _flow(monkeypatch, **opts) == want


def test_ocsp_only_mode_with_a_partial_crl_set_demands_no_coverage():
    w = W()
    # the real check: supplied CRLs are enforced, none is demanded ("none" is what the hook passes in this mode)
    assert rev(cdp_chain(), [crl(w.root)], None, "none") == {"ok": True, "verifiedCrls": 1}


@pytest.mark.parametrize("bad", ["everything", 3, [1.5], [-1], ["0"], [True], {"a": 1}])
def test_a_malformed_policy_is_refused_at_construction(bad):
    with pytest.raises(AttestConstructError, match="malformed requireCrlFor"):
        mkhook(requireCrlFor=bad)


@pytest.mark.parametrize("ok", [None, "cdp", "all", [0, 1], []])
def test_a_well_formed_policy_constructs(ok):
    mkhook(requireCrlFor=ok)
