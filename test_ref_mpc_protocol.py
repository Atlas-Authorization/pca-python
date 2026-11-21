"""The distributed SPDZ-style protocol (atlas_pca.mpc_net_protocol) over loopback mutual TLS, three parties in one process through the
launcher: dealer and no-dealer runs agree with the deterministic engine, and the refusals (a lying dealer, a lying opened share, a wrong OT
operand, a bad base-OT proof, an inconsistent OT-extension matrix, a silent party) abort with no output and name the right party.
Identities are fresh per run. The no-dealer runs do real OT in pure Python: they use Q = 1 and long receive deadlines (a single event loop
runs every party, so a party computing delays the others' reads)."""
import asyncio

import pytest

pytest.importorskip("cryptography")
pysodium = pytest.importorskip("pysodium")

from atlas_pca.mpc import Compose, DecisionVector  # noqa: E402
from atlas_pca.mpc_net import NetAbort  # noqa: E402
from atlas_pca.mpc_net_launch import LaunchOptions, launch_local  # noqa: E402
from atlas_pca.mpc_net_prep import Behavior  # noqa: E402
from atlas_pca.mpc_net_protocol import DealerConfig, PartyConfig, run_dealer, run_party  # noqa: E402
from atlas_pca.mpc_spdz import DealerFault, SpdzRunner  # noqa: E402

DEALER_Q = 4
OT_Q = 1
DEALER_INPUTS = [DecisionVector(1, 1, 1), DecisionVector(1, 2, 3), DecisionVector(1, 1, 2)]
OT_INPUTS = [DecisionVector(1, 1, 0), DecisionVector(1, 2, 1), DecisionVector(1, 1, 1)]


def launch(o):
    return asyncio.run(launch_local(o))


def dealer_opts(**kw):
    return LaunchOptions(n=3, vectors=DEALER_INPUTS, Q=DEALER_Q, offline="trusted-dealer", insecure_trusted_dealer=True, dealer_seed=7,
                         recv_timeout_ms=60_000, kill_after_ms=240_000, **kw)


def ot_opts(**kw):
    return LaunchOptions(n=3, vectors=OT_INPUTS, Q=OT_Q, recv_timeout_ms=900_000, connect_timeout_ms=120_000, kill_after_ms=1_800_000, **kw)


def parties(l):
    return [o for o in l.outputs if o.role == "party"]


def assert_refused_and_named(l, kind, blamed):
    named = False
    for o in parties(l):
        assert o.result is None, "no party may produce output"
        a = o.abort
        if a is not None and a.kind == kind and a.blamed == blamed:
            named = True
    assert named, "an honest party names party %s with kind %s: %s" % (blamed, kind, [repr(o.error) for o in parties(l)])


def engine(vectors, q):
    r = SpdzRunner.compose_secure_malicious(vectors, q=q, seed=1, insecure_trusted_dealer=True)
    assert r.composed == Compose.compose_clear(vectors, q)
    return r.composed


def assert_agree(l, vectors, q, mode):
    clear = engine(vectors, q)
    digest = None
    ps = parties(l)
    assert len(ps) == 3
    for o in ps:
        assert o.error is None, repr(o.error)
        assert o.result.composed == clear
        assert o.result.offline_mode == mode
        assert o.result.identifiable_abort is True
        digest = digest or o.result.transcript_digest
        assert o.result.transcript_digest == digest


# ---- trusted-dealer mode ----

def test_dealer_mode_agrees_with_the_deterministic_engine():
    assert_agree(launch(dealer_opts()), DEALER_INPUTS, DEALER_Q, "trusted-dealer")


def test_a_wrong_product_from_the_dealer_is_detected_and_blamed():
    l = launch(dealer_opts(dealer_fault=DealerFault(keep_c_delta=1)))
    assert_refused_and_named(l, "dealer", 3)


def test_a_wrong_mac_share_from_the_dealer_is_detected_and_blamed():
    l = launch(dealer_opts(mac_fault_at_input=0))
    assert_refused_and_named(l, "dealer", 3)


def test_a_lying_opened_share_is_named_by_its_pairwise_tag():
    l = launch(dealer_opts(behaviors={1: Behavior("open-lie", "mul0")}))
    assert_refused_and_named(l, "mac-check", 1)


def test_a_non_canonical_field_element_is_refused():
    l = launch(dealer_opts(behaviors={2: Behavior("noncanonical", "mul0")}))
    assert_refused_and_named(l, "malformed", 2)


def test_a_silent_party_is_blamed_by_timeout():
    o = dealer_opts(behaviors={2: Behavior("silent", "mul0")})
    o.recv_timeout_ms = 8_000
    o.kill_after_ms = 120_000
    l = launch(o)
    assert_refused_and_named(l, "timeout", 2)


def test_a_bad_pairwise_tag_is_named():
    l = launch(dealer_opts(behaviors={1: Behavior("bad-tag", "mul0")}))
    assert_refused_and_named(l, "mac-check", 1)


def test_a_forged_mac_share_is_caught_by_the_mac_check():
    l = launch(dealer_opts(behaviors={1: Behavior("mac-lie", "mul1")}))
    assert_refused_and_named(l, "mac-check", 1)


def test_a_lying_mac_residual_is_named_by_the_blame_round():
    l = launch(dealer_opts(behaviors={2: Behavior("sigma-lie")}))
    assert_refused_and_named(l, "mac-check", 2)


def test_a_wrong_length_array_is_malformed():
    l = launch(dealer_opts(behaviors={1: Behavior("short-array", "mul0")}))
    assert_refused_and_named(l, "malformed", 1)


def test_a_coin_seed_that_does_not_match_its_commitment_is_named():
    l = launch(dealer_opts(behaviors={1: Behavior("bad-coin-open")}))
    assert_refused_and_named(l, "commitment", 1)


def test_a_mac_residual_that_does_not_match_its_commitment_is_named():
    l = launch(dealer_opts(behaviors={1: Behavior("bad-sigma-open")}))
    assert_refused_and_named(l, "commitment", 1)


def test_equivocation_never_yields_an_output():
    l = launch(dealer_opts(behaviors={1: Behavior("equivocate", "mul0")}))
    for o in parties(l):
        assert o.result is None


def test_a_crashed_party_is_named_as_disconnected_or_timed_out():
    o = dealer_opts(behaviors={1: Behavior("crash", "mul1")})
    o.recv_timeout_ms = 8_000
    o.kill_after_ms = 120_000
    l = launch(o)
    named = False
    for p in parties(l):
        assert p.result is None
        if p.abort is not None and p.abort.kind in ("disconnect", "timeout") and p.abort.blamed == 1:
            named = True
    assert named


def test_test_hooks_and_the_dealer_opt_in_are_enforced_before_any_traffic():
    base = dict(id=0, n=3, input=DEALER_INPUTS[0], mesh=None, session_id="s", Q=DEALER_Q)
    with pytest.raises(NetAbort) as e:
        asyncio.run(run_party(PartyConfig(offline="trusted-dealer", **base)))
    assert e.value.kind == "local"
    with pytest.raises(NetAbort) as e:
        asyncio.run(run_party(PartyConfig(offline="trusted-dealer", insecure_trusted_dealer=True, behavior=Behavior("open-lie", "out"), **base)))
    assert e.value.kind == "local"
    with pytest.raises(ValueError):
        asyncio.run(run_dealer(DealerConfig(n=3, mesh=None)))
    with pytest.raises(ValueError):
        launch(LaunchOptions(n=3, vectors=DEALER_INPUTS, Q=DEALER_Q, offline="trusted-dealer"))


# ---- no-dealer mode (OT offline phase over the mesh) ----

def test_no_dealer_agrees_with_the_deterministic_engine():
    assert_agree(launch(ot_opts()), OT_INPUTS, OT_Q, "no-dealer")


def test_a_wrong_ot_operand_is_caught_by_the_sacrifice_and_attributed():
    assert_refused_and_named(launch(ot_opts(behaviors={1: Behavior("offline-lie", None)})), "mac-check", 1)


def test_an_inconsistent_ot_extension_matrix_is_caught_by_the_kos_check():
    assert_refused_and_named(launch(ot_opts(behaviors={2: Behavior("ot-u-lie", None)})), "ot-check", 2)


def test_a_bad_base_ot_proof_is_refused():
    assert_refused_and_named(launch(ot_opts(behaviors={1: Behavior("ot-proof-lie", None)})), "ot-check", 1)
