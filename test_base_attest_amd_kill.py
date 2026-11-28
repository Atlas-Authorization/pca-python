"""AMD SEV-SNP kill tests of the 0.5 full mutation baseline: verify_genuine_sev_snp_report's exact fail-closed result
dicts (the `ok` flag, not only the reason), the verifier's handling of a malformed inner result (seam: the genuine path
always returns report AND measured on ok), and the critical-SPL-extension reason."""
import pytest

pytest.importorskip("cryptography")

from atlas_pca import attest_amd as A
from test_attest_units import EXP, evidence_resolver, ext, integer, sev_report, tbs_of

CFG = {"family": "genoa", "binding": "report-data", "policy": {"measurements": ["00" * 48]}}
EV = {"report": bytes(1184), "vcekDer": b"a", "askArkPem": ""}


def test_genuine_wrong_length_is_an_exact_refusal():
    assert A.verify_genuine_sev_snp_report(bytes(1000), b"", "", None, 1) == {
        "ok": False, "reason": "report length 1000 is not the canonical 1184"}
    rep = bytearray(sev_report())
    rep[1183] = 1
    assert A.verify_genuine_sev_snp_report(bytes(rep), b"", "", None, 1) == {
        "ok": False, "reason": "report signature block has non-zero reserved bytes"}


@pytest.mark.parametrize("inner,want", [
    ({"ok": True, "report": {"report_data": b""}}, "SEV-SNP report invalid: unknown"),
    ({"ok": True, "measured": "m"}, "SEV-SNP report invalid: unknown"),
    ({"ok": False}, "SEV-SNP report invalid: unknown"),
    ({"ok": False, "reason": ""}, "SEV-SNP report invalid: "),  # `??` keeps an empty reason
    ({"ok": False, "reason": "x"}, "SEV-SNP report invalid: x"),
])
def test_verifier_refuses_an_incomplete_genuine_result(monkeypatch, inner, want):
    monkeypatch.setattr(A, "verify_genuine_sev_snp_report", lambda *a, **k: inner)
    v = A.AmdSnpVerifier(dict(CFG, resolve_evidence=evidence_resolver(EV)))
    assert v.verify({}, EXP, 1_800_000_000_000) == {"ok": False, "reason": want}


@pytest.mark.parametrize("which,name", [("1.3.6.1.4.1.3704.1.3.1", "bootloader"), ("1.3.6.1.4.1.3704.1.3.2", "tee"),
                                        ("1.3.6.1.4.1.3704.1.3.3", "snp"), ("1.3.6.1.4.1.3704.1.3.8", "microcode")])
def test_critical_spl_extension_reason(which, name):
    tcb = 4 | (2 << 8) | (3 << 48) | (200 << 56)
    report = A.parse_sev_snp_report(sev_report(reported_tcb=tcb))
    exts = [ext("1.3.6.1.4.1.3704.1.4", False, bytes([0x22]) * 64)]
    for o, val in (("1.3.6.1.4.1.3704.1.3.1", integer(4)), ("1.3.6.1.4.1.3704.1.3.2", integer(2)),
                   ("1.3.6.1.4.1.3704.1.3.3", integer(3)), ("1.3.6.1.4.1.3704.1.3.8", b"\x02\x02\x00\xc8")):
        exts.append(ext(o, o == which, val))
    assert A.check_vcek_report_binding(tbs_of(*exts), report) == (
        "VCEK %s SPL extension is marked critical (the AMD profile is non-critical)" % name)
