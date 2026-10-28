"""Revocation staleness (T9): replays packages/pca/conformance/staleness-vectors.json (`max_age`, `effective_reversibility`,
`age`, `epoch`, `gate`) and checks the authorize() wiring. A missing vector file fails."""
import base64
import json
import os

import pytest

from atlas_pca import (MemoryStateStore, RevocationStaleness, authorize, check_revocation_age, check_revocation_epoch,
                       check_revocation_state, effective_reversibility, revocation_max_age_ms, REVOCATION_EPOCH_VALIDITY_MS,
                       verify_non_membership)

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "conformance", "staleness-vectors.json"), encoding="utf-8") as f:
    DOC = json.load(f)
with open(os.path.join(HERE, "testdata", "authorize-fixtures.json"), encoding="utf-8") as f:
    FIX = json.load(f)

GUARD = DOC["guardian_public"]
NAN = float("nan")


def _num(v):
    return NAN if v == "NaN" else v


def _policy(p):
    """The TypeScript policy object -> the Python dataclass (None = staleness off)."""
    if p is None:
        return None
    return RevocationStaleness(max_revocation_age_ms=p.get("maxRevocationAgeMs"), staleness=p.get("staleness"),
                               guardian_public=GUARD)


def _same(want, got, ok_only=False):
    assert got["ok"] == want["ok"]
    if not ok_only:
        assert got.get("reason") == want.get("reason")


def test_corpus_is_complete():
    assert DOC["constants"] == {"refresh_ms": 60000, "validity_ms": 300000, "irreversible_max_age_ms": 120000, "skew_ms": 60000}
    assert [len(DOC[k]) for k in ("max_age", "effective_reversibility", "age", "epoch", "gate")] == [15, 14, 13, 25, 28]


@pytest.mark.parametrize("v", DOC["max_age"], ids=lambda v: "%s-%s" % (json.dumps(v["policy"]), v["class"]))
def test_max_age(v):
    p = v["policy"]
    assert revocation_max_age_ms(_policy(p), v["class"]) == v["max_age_ms"]


@pytest.mark.parametrize("v", DOC["effective_reversibility"], ids=lambda v: "%s-%s" % (v["server_class"], v["signed_class"]))
def test_effective_reversibility(v):
    assert effective_reversibility(v["server_class"], v["signed_class"]) == v["effective"]


@pytest.mark.parametrize("i", range(len(DOC["age"])))
def test_age(i):
    v = DOC["age"][i]
    got = check_revocation_age(_num(v["issued_at"]), v["now"], _num(v["max_age_ms"]), v.get("what", "revocation state"))
    _same(v["result"], got, v.get("ok_only", False))


@pytest.mark.parametrize("v", DOC["epoch"], ids=lambda v: v["name"])
def test_epoch(v):
    kw = {}
    if "max_age_ms" in v:
        kw["max_age_ms"] = _num(v["max_age_ms"])
    if "grant_ref" in v:
        kw["grant_ref"] = v["grant_ref"]
    if "last_accepted_epoch" in v:
        kw["last_accepted_epoch"] = v["last_accepted_epoch"]
    if "pcactn_epoch" in v:
        kw["pcactn_epoch"] = v["pcactn_epoch"]
    got = check_revocation_epoch(v["epoch"], v["guardian_public"], v["now"], **kw)
    _same(v["result"], got, v.get("ok_only", False))


@pytest.mark.parametrize("v", DOC["gate"], ids=lambda v: v["name"])
def test_gate(v):
    pol = _policy(v.get("policy"))
    if pol is not None and v.get("allow_unsigned_root_for_irreversible"):
        pol.allow_unsigned_root_for_irreversible = True
    mode = v["mode"]
    if mode == "epoch":
        state = {"kind": "epoch", "epoch": v["epoch"]}
        if v.get("bare_root"):
            state["root"] = v["bare_root"]
    elif mode == "root":
        state = {"kind": "root", "root": DOC["revocation_root"], "issued_at": v["root_issued_at"]}
    else:
        state = None
    got = check_revocation_state(pol, state, now=v["now"], grant_ref="g1", signed_class=v.get("signed_class"),
                                 server_class=v.get("server_class"), pcactn_epoch=0, guardian_public=GUARD)
    _same(v["result"], got)


def test_policy_validation_is_a_construction_error():
    for bad in ({"max_revocation_age_ms": -5}, {"max_revocation_age_ms": 0}, {"max_revocation_age_ms": True},
                {"staleness": {"irreversible": 0}}, {"staleness": {"costly": "x"}}):
        with pytest.raises(ValueError):
            RevocationStaleness(**bad)


# ---- authorize(): the staleness step ------------------------------------------------------------------------------------

def _case():
    return next(c for c in FIX["cases"] if c["name"] == "envelope-max-spend-within")


def _run(state, policy, server_class=None):
    c = _case()
    s = c["steps"][0]
    pcactn = json.loads(json.dumps(s["pcactn"]))
    ctx = {"reversibility_class": server_class} if server_class else {}
    if state is not None:
        ctx["revocation_state"] = state
    return authorize(pcactn, operation=s["operation"], audience=FIX["audience"], resolve_grant=lambda ref: c["grant"],
                     state_store=MemoryStateStore(), is_revoked=lambda p, g: False, now=FIX["now"], plan="single-step",
                     context=lambda p: ctx, revocation_staleness=policy)


def test_authorize_without_the_policy_ignores_state():
    r = _run({"kind": "root", "root": "r", "issued_at": 0}, None)
    assert r.allow is True and "freshness" not in r.checks


def test_authorize_stale_root_denied_fresh_admitted():
    # every signed fixture action is `irreversible`, so an unsigned root is accepted only when allowed, within the window
    pol = RevocationStaleness(allow_unsigned_root_for_irreversible=True, staleness={"irreversible": 10_000},
                              ids=lambda p: [])  # freshness only; the proof step has its own tests below
    now = FIX["now"]
    fresh = _run({"kind": "root", "root": "r", "issued_at": now - 10_000}, pol)
    assert fresh.allow is True and fresh.checks["freshness"] == "pass"
    stale = _run({"kind": "root", "root": "r", "issued_at": now - 10_001}, pol)
    assert stale.allow is False and stale.checks["freshness"] == "fail"
    assert stale.reason == ("freshness: revocation root is 10001 ms old, over the verifier's maximum of 10000 ms "
                            "(stale revocation state)")
    unknown = _run({"kind": "root", "root": "r", "issued_at": None}, pol)
    assert unknown.allow is False and unknown.reason == "freshness: revocation root age is unknown (unverifiable revocation state)"
    assert _run(None, pol).allow is True  # unsigned/absent state is accepted when allowed (the boolean hook decided)


def test_authorize_signed_epoch_for_another_grant_is_refused():
    ep = next(v for v in DOC["gate"] if v["name"] == "epoch-reversible-fresh")["epoch"]
    pol = RevocationStaleness(guardian_public=GUARD)
    r = _run({"kind": "epoch", "epoch": ep}, pol, server_class="irreversible")
    assert r.allow is False and r.reason == "freshness: revocation epoch is for a different grant"


def test_authorize_on_epoch_accepted_runs_only_on_allow():
    seen = []
    pol = RevocationStaleness(allow_unsigned_root_for_irreversible=True, on_epoch_accepted=lambda e, p: seen.append(e))
    assert _run(None, pol).allow is True and seen == []  # no epoch involved


def test_authorize_irreversible_needs_signed_state():
    pol = RevocationStaleness()
    r = _run(None, pol)
    assert r.allow is False and r.checks["freshness"] == "fail"
    assert r.reason.endswith("no verifiable (guardian-signed) revocation state for an irreversible action")
    r = _run({"kind": "root", "root": "r", "issued_at": FIX["now"]}, pol)
    assert r.allow is False and "unsigned revocation root refused" in r.reason
    assert _run(None, RevocationStaleness(allow_unsigned_root_for_irreversible=True)).allow is True


def test_authorize_bad_policy_type_is_a_config_denial():
    r = _run(None, {"max_revocation_age_ms": 1})
    assert r.allow is False and r.checks == {"authorize_config": "fail"}


# ---- per-capability non-membership (membership + gate_ids tables) ---------------------------------------------------------

def test_membership_vectors():
    assert len(DOC["membership"]) == 27
    for v in DOC["membership"]:
        assert verify_non_membership(v["root"], v["proof"], v["id"]) is v["ok"], v["name"]


def _signed_main_epoch(issued):
    """The vectors' signed epoch over the main set (guardian seed: 32 bytes of 0x0b), re-signed at `issued`."""
    from atlas_pca import ed25519
    from atlas_pca.intent_v2 import _epoch_message
    seed = bytes([11]) * 32
    b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
    rs = DOC["revocation_set"]
    ep = {"instance_id": "i", "grant_ref": "g1", "epoch": 0, "set_size": rs["size"], "root": rs["root"], "issued_at": issued,
          "not_after": issued + 600_000}
    ep["guardian"] = b64u(ed25519.public_key(seed))
    ep["sig"] = b64u(ed25519.sign(seed, _epoch_message(ep)))
    return ep


def test_gate_ids_vectors():
    assert len(DOC["gate_ids"]) == 10
    pol = RevocationStaleness(max_revocation_age_ms=REVOCATION_EPOCH_VALIDITY_MS, guardian_public=GUARD)
    for v in DOC["gate_ids"]:
        ep = _signed_main_epoch(v["epoch_issued_at"])
        assert ep["guardian"] == GUARD
        got = check_revocation_state(pol, {"kind": "epoch", "epoch": ep}, now=v["now"], grant_ref="g1", signed_class="costly",
                                     pcactn_epoch=0, ids=v["ids"], proof_for=lambda rid, v=v: v["proofs"].get(rid))
        _same(v["result"], got)


def test_authorize_every_chain_capability_needs_a_proof():
    # default ids = the PCActn's cap_chain; a gate with no proof source denies (fail closed), with a valid proof it admits
    pol = RevocationStaleness(allow_unsigned_root_for_irreversible=True)
    state = {"kind": "root", "root": "r", "issued_at": FIX["now"]}
    r = _run(state, pol)
    assert r.allow is False and r.checks["freshness"] == "fail" and r.reason.startswith("freshness: no non-membership proof for ")
    # an empty set's root admits the empty proof for any id
    from atlas_pca.intent_v2 import _bind_root, _EMPTY_TREE
    state = {"kind": "root", "root": _bind_root(0, _EMPTY_TREE), "issued_at": FIX["now"]}
    pol = RevocationStaleness(allow_unsigned_root_for_irreversible=True, proof_for=lambda rid, p: {"size": 0})
    r = _run(state, pol)
    assert r.allow is True, r.reason
    # a raising proof source fails closed
    def boom(rid, p):
        raise RuntimeError("x")
    r = _run(state, RevocationStaleness(allow_unsigned_root_for_irreversible=True, proof_for=boom))
    assert r.allow is False and r.checks["freshness"] == "fail"
