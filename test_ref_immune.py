"""Behavioural immune system (adaptation, the no-widen check, signed tightening proposals, the durable store) replayed against the
TypeScript reference. Guardian keys are derived from seed labels (sha256("atlas-pca-conformance/immune/" + label)), never carried."""
import hashlib

import pytest

from atlas_pca import ed25519
from atlas_pca import immune as I
from atlas_pca.atomic_kv import MemoryAtomicKv, SqliteAtomicKv
from atlas_pca.pca import b64u
from base_oracle import load_ref, run

ed25519.allow_insecure_signer()  # signing needs `cryptography` otherwise; the vectors use throwaway seeds
COUNT, CASES = load_ref("immune-java")


def sd(label):
    return hashlib.sha256(("atlas-pca-conformance/immune/" + label).encode("utf-8")).digest()


def pin(opts):
    """The pinned guardian "@g" is the public key of the seed labelled g."""
    if isinstance(opts, dict) and opts.get("guardian") == "@g":
        return dict(opts, guardian=b64u(ed25519.public_key(sd("g"))))
    return opts


def _store(subject, ops):
    kv = MemoryAtomicKv()
    st = I.create_immune_store(kv, subject)
    out = []
    for op in ops:
        try:
            if op[0] == "seed":
                kv.set("immune/state/" + subject, op[1])
                out.append(None)
            elif op[0] == "get":
                out.append(st.get())
            elif op[0] == "observe":
                out.append(st.observe(op[1]))
            elif op[0] == "lastEpoch":
                out.append(st.last_epoch())
            elif op[0] == "apply":
                out.append(st.apply(op[1], op[2], pin(op[3])))
            else:
                raise AssertionError("op %s" % op[0])
        except (ValueError, TypeError, RuntimeError):
            out.append({"$err": "Error"})
    return out


def _skip_stored_null(c):
    """The key/value interface reads a stored None as an absent key, so a state seeded as null cannot be told from none."""
    if c["fn"] == "store" and any(op[0] == "seed" and op[1] is None for op in c["args"][1]):
        return "stored null is an absent key"
    return None


MAP = {
    "adapt": I.adapt,
    "noWidenViolation": I.no_widen_violation,
    "policyDigest": I.policy_digest,
    "immuneStateDigest": I.immune_state_digest,
    "issueTighteningProposal": lambda base, state, epoch, now, label: I.issue_tightening_proposal(base, state, epoch, now, sd(label)),
    "applyTightening": lambda base, p, o: I.apply_tightening(base, p, pin(o)),
    "store": _store,
}


def test_corpus_is_the_full_oracle():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn], skip=_skip_stored_null)


# ---- units beyond the corpus ----------------------------------------------------------------------

BASE = {"weights": {"alpha": 0.25, "beta": 0.2, "gamma": 0.2, "delta": 0.2, "epsilon": 0.1, "zeta": 0.05},
        "theta1": 0.25, "theta2": 0.6, "kappa": 1, "lambda": 0.0005, "rho": 0.5, "bMax": 1}


def _hot_state():
    s = I.initial_state()
    for i in range(4):
        s = I.observe(s, {"r": 0.9, "at": 1_800_000_000_000 + i, "denied": True})
    return s


def test_a_calm_state_restores_the_base_exactly():
    a = I.assess(I.initial_state())
    assert a["level"] == "calm" and a["score"] == 0
    ad = I.adapt(BASE, a)
    assert ad["changed"] is False and ad["policy"] is BASE


def test_a_threat_only_tightens():
    a = I.assess(_hot_state())
    assert a["level"] == "high" and a["score"] == 1
    ad = I.adapt(BASE, a)
    assert ad["changed"] is True and ad["policy"]["kappa"] == 3
    assert I.no_widen_violation(BASE, ad["policy"]) is None
    assert I.no_widen_violation(ad["policy"], BASE) == "kappa decreased"
    with pytest.raises(ValueError):
        I.assert_no_widen(ad["policy"], BASE)


def test_a_malformed_state_is_the_maximal_threat():
    for bad in (None, {}, dict(_hot_state(), ewma=2), dict(_hot_state(), seeded=1)):
        a = I.assess(bad)
        assert a["level"] == "high" and a["score"] == 1 and a["signals"][0].startswith("invalid immune state: ")


def test_a_non_finite_timestamp_does_not_poison_the_counters():
    s = I.observe(I.initial_state(), {"r": 0.5, "at": 1000, "denied": True})
    s = I.observe(s, {"r": 0.5, "at": float("nan"), "denied": True})
    assert I.validate_immune_state(s) is None and s["lastAt"] == 1000 and s["denies"] == 2


def test_proposal_roundtrip_and_replay_floor(tmp_path):
    secret, state, t0 = sd("g"), _hot_state(), 1_800_000_000_000
    p = I.issue_tightening_proposal(BASE, state, 3, t0, secret)
    o = {"guardian": p["guardian"], "now": t0 + 1000, "maxAgeMs": 60_000, "state": state}
    kv = SqliteAtomicKv(str(tmp_path / "immune.db"))
    try:
        st = I.create_immune_store(kv, "alice")
        assert st.last_epoch() == 0
        assert st.apply(BASE, p, o)["ok"] is True and st.last_epoch() == 3
        assert st.apply(BASE, p, o) == {"ok": False, "reason": "replayed-epoch"}
        st2 = I.create_immune_store(kv, "alice")  # a restart keeps the floor
        assert st2.last_epoch() == 3
        assert st2.observe({"r": 0.4, "at": t0})["seeded"] is True and st2.get()["baseline"]["n"] == 1
    finally:
        kv.close()
    assert I.apply_tightening(BASE, p, dict(o, guardian=None)) == {"ok": False, "reason": "guardian"}
    assert I.apply_tightening(BASE, p, None) == {"ok": False, "reason": "malformed"}
    assert I.apply_tightening(BASE, dict(p, rationale="x"), dict(o, lastEpoch=0)) == {"ok": False, "reason": "signature"}


def test_issue_refuses_bad_inputs():
    for args in ((dict(BASE, kappa=-1), _hot_state(), 1, 0), (BASE, _hot_state(), 0, 0), (BASE, _hot_state(), 1, float("inf"))):
        with pytest.raises(ValueError):
            I.issue_tightening_proposal(*args, sd("g"))
