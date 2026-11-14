"""Gate-level kills for verify_pcactn_core: the freshness anchor gate (every operand and bound, including the shapes the wire
check normally refuses, reached through the wire seam), the classical-root downgrade check under a PQ pin, the taint gate's
three inputs, and the defaults of the unchecked core."""
import pytest

import atlas_pca.pca as pca
import test_k05f_g_taint as TT
import test_mutation_kill_b as B

NOW = B.NOW
MISSING = "freshness_anchor: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)"
MISCONF = "freshness_anchor: freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)"
FUTURE = "freshness_anchor: freshness anchor is in the future"


def _run(monkeypatch, freshness, gate, bypass_wire=False, drop=False):
    monkeypatch.setattr(pca, "_verify_suite", lambda *a, **k: True)  # only the gate is under test, not the signature
    p = B._pcactn([B.ROOT], B.AGENT)
    if drop:
        del p["freshness"]
    else:
        p["freshness"] = freshness  # set after signing: the suite check is stubbed
    if bypass_wire:
        monkeypatch.setattr(pca, "validate_wire_v2", lambda _p: None)
    return pca.verify_pcactn_core(p, B.ROOT, now=NOW, audience=B.AUD, insecure_skip_plan_root_check=True, enforce_freshness=gate)


def _fr(epoch, beacon_ref="b"):
    return {"epoch": epoch, "beacon_ref": beacon_ref, "accumulator_witness": "w"}


def _ok(v):
    return v.allow is True and v.checks["freshness_anchor"] is True and v.reason is None


# ---- clock skew: max(0, skew) for a finite number, else 0 ------------------------------------------------------------

@pytest.mark.parametrize("skew", [None, 0, -5, True, float("nan"), float("inf"), "3"])
def test_no_usable_skew_means_zero_skew(monkeypatch, skew):
    gate = {"max_age_ms": 10 ** 12, "epoch_ms": 1, "now": 10 ** 9}
    if skew is not None:
        gate["clock_skew_ms"] = skew
    v = _run(monkeypatch, _fr(10 ** 9 + 1), gate)  # anchor = now + 1
    assert v.allow is False and v.reason == FUTURE


def test_a_positive_skew_covers_exactly_its_width(monkeypatch):
    gate = {"max_age_ms": 10 ** 12, "epoch_ms": 1, "now": 10 ** 9, "clock_skew_ms": 2}
    assert _ok(_run(monkeypatch, _fr(10 ** 9 + 2), gate))
    assert _run(monkeypatch, _fr(10 ** 9 + 3), gate).reason == FUTURE
    assert _ok(_run(monkeypatch, _fr(10 ** 9), dict(gate, clock_skew_ms=0)))  # anchor == now is not the future


# ---- the gate's own configuration -------------------------------------------------------------------------------------

def test_epoch_ms_must_be_a_finite_positive_number(monkeypatch):
    base = {"max_age_ms": 0, "now": 100}
    assert _ok(_run(monkeypatch, _fr(200), dict(base, epoch_ms=0.5)))  # 200 * 0.5 == now, age 0
    assert _ok(_run(monkeypatch, _fr(100), dict(base, epoch_ms=1)))
    for bad in (0, -1, float("nan"), float("inf"), "1", True):
        v = _run(monkeypatch, _fr(100), dict(base, epoch_ms=bad))
        assert v.allow is False and v.reason == MISCONF, bad


def test_max_age_must_be_a_finite_non_negative_number(monkeypatch):
    base = {"epoch_ms": 1, "now": 100}
    assert _ok(_run(monkeypatch, _fr(100), dict(base, max_age_ms=0)))  # age 0 <= 0
    assert _run(monkeypatch, _fr(99), dict(base, max_age_ms=0)).reason == "freshness_anchor: freshness anchor is stale (older than 0 ms)"
    for bad in (-1, None, float("nan"), float("inf"), "5", True):
        gate = dict(base)
        if bad is not None:
            gate["max_age_ms"] = bad
        v = _run(monkeypatch, _fr(100), gate)
        assert v.allow is False and v.reason == MISCONF, bad


# ---- the anchor shape (the gate refuses what the wire check would have refused first) ------------------------------------

@pytest.mark.parametrize("fr", [_fr(5, ""), _fr(5, 7), _fr(5, None), _fr(True), _fr(5.0), _fr(0), _fr(-1), _fr("5"), _fr(None)])
def test_a_malformed_anchor_is_missing_at_the_gate(monkeypatch, fr):
    v = _run(monkeypatch, fr, {"max_age_ms": 10 ** 18, "now": 10 ** 16, "epoch_ms": 1}, bypass_wire=True)
    assert v.allow is False and v.checks["freshness_anchor"] is False and v.reason == MISSING


def test_an_unsafe_integer_epoch_is_denied_before_the_gate(monkeypatch):
    # canonicalisation refuses |n| > 2^53-1 first, so the verdict is a deny (never an allow) and the gate is not reached
    v = _run(monkeypatch, _fr(2 ** 53), {"max_age_ms": 10 ** 18, "now": 10 ** 16, "epoch_ms": 1}, bypass_wire=True)
    assert v.allow is False and v.checks["malformed"] is False and "freshness_anchor" not in v.checks


@pytest.mark.parametrize("fr", ["x", [], 5, None])
def test_a_non_object_freshness_is_a_missing_anchor_not_a_fault(monkeypatch, fr):
    v = _run(monkeypatch, fr, {"max_age_ms": 10 ** 12}, bypass_wire=True)
    assert v.allow is False and v.reason == MISSING and v.checks.get("malformed") is not False


def test_an_absent_freshness_member_is_a_missing_anchor(monkeypatch):
    v = _run(monkeypatch, None, {"max_age_ms": 10 ** 12}, bypass_wire=True, drop=True)
    assert v.allow is False and v.reason == MISSING and v.checks.get("malformed") is not False


def test_the_anchor_bounds_are_inclusive_where_they_must_be(monkeypatch):
    big = {"max_age_ms": 10 ** 16, "now": 10 ** 16, "epoch_ms": 1}
    assert _ok(_run(monkeypatch, _fr(1), big))  # epoch 1 is a real anchor
    assert _ok(_run(monkeypatch, _fr(2 ** 53 - 1), big))  # the largest safe integer is a real anchor
    assert _ok(_run(monkeypatch, _fr(5, "x"), {"max_age_ms": 10 ** 16}))  # a one-character beacon_ref is a real ref


# ---- the unchecked core's own defaults ---------------------------------------------------------------------------------

def test_the_unchecked_core_defaults_to_refusing_an_unauthorized_plan_root():
    p = B._pcactn([B.ROOT], B.AGENT)
    v = pca._verify_pcactn_core_unchecked(p, B.ROOT, NOW, B.AUD, None)
    assert v.allow is False and v.checks["plan_inclusion"] is True and v.not_enforced == []
    assert v.reason == ("plan_root_authorized: no authorized plan is configured for this verifier "
                        "(set authorizedPlanRoots, or the explicit insecureSkipPlanRootCheck)")


# ---- the PQ pin downgrade check ----------------------------------------------------------------------------------------

def _pinned(monkeypatch, alg, pins="pin"):
    monkeypatch.setattr(pca, "_verify_suite", lambda *a, **k: True)
    monkeypatch.setattr(pca, "verify_chain", lambda *a, **k: (True, None))
    monkeypatch.setattr(pca, "validate_wire_v2", lambda _p: None)  # the hop is not re-signed for its alg: only the pin check is under test
    grant = dict(B.ROOT)
    if alg != "absent":
        grant["alg"] = alg
    p = B._pcactn([grant], B.AGENT)
    pq_pins = {grant["issuer"]: pins} if pins is not None else {}
    return pca.verify_pcactn_core(p, grant, now=NOW, audience=B.AUD, insecure_skip_plan_root_check=True, pq_pins=pq_pins)


@pytest.mark.parametrize("alg", ["absent", "ed25519"])
def test_a_classical_root_from_a_pinned_issuer_is_a_downgrade(monkeypatch, alg):
    v = _pinned(monkeypatch, alg)
    assert v.allow is False and v.checks["pq_pin"] is False
    assert v.reason == "pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused"


def test_a_non_classical_root_or_an_unpinned_issuer_is_no_downgrade(monkeypatch):
    v = _pinned(monkeypatch, "ml-dsa-65")
    assert v.allow is True and "pq_pin" not in v.checks and v.reason is None
    unpinned = _pinned(monkeypatch, "ed25519", pins=None)
    assert unpinned.allow is True and "pq_pin" not in unpinned.checks


# ---- the taint gate's inputs --------------------------------------------------------------------------------------------

def test_the_core_taint_gate_reads_registry_graph_and_bound(monkeypatch):
    prov = TT.prov("d-trusted", "g-node")
    gate = {"registry": TT.reg(), "resource_graph": TT.Graph("g-node"), "max_taint": 0.25}
    ok = TT.core(prov, gate, monkeypatch)
    assert ok.allow is True and ok.checks["taint_gate"] is True
    tight = TT.core(prov, dict(gate, max_taint=0), monkeypatch)
    assert tight.allow is False and tight.reason == "taint_gate: information-flow taint 0.25 exceeds policy max 0"
    no_graph = TT.core(prov, {"registry": TT.reg(), "max_taint": 0.25}, monkeypatch)
    assert no_graph.allow is False and no_graph.reason == "taint_gate: information-flow taint 1 exceeds policy max 0.25"
    no_registry = TT.core(prov, {"resource_graph": TT.Graph("g-node"), "max_taint": 1}, monkeypatch)
    assert no_registry.allow is False and no_registry.reason == "taint_gate: taint: no trusted-input registry"
