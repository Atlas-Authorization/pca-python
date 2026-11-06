"""Mutation kills (intent): the Intent Layer M2 `envelope.intent` code paths of atlas_pca/pca.py -- validate_intent_wire,
intent_goal / intent_goal_commit, intent_policy_active, root_goal_commit, decide_intent_binding and the `intent` check in
verify_pcactn_core. Self-contained: PCActns and root grants are minted here with a tiny RFC 8032 signer over the verifier's
own curve arithmetic, so every assertion is an exact verdict / check map / reason / return value. Every boundary is pinned
on both sides so an off-by-one, negated or deleted-branch mutant dies."""
import copy
import hashlib

from atlas_pca import ed25519 as E
from atlas_pca.pca import (
    CAP_DOMAIN, EMPTY_PARAMS_DIGEST, ENVELOPE_INTENT_FIELDS, INTENT_GOAL_COMMIT_DOMAIN, INTENT_GOAL_PREFIX,
    MAX_INTENT_GOAL_SALT_LEN, PCACTN_OPTIONAL_FIELDS, PCACTN_VERSION, PPM_ONE, _plan_leaf, b64u, canonical_bytes_strict,
    conditions_digest, decide_intent_binding, hash_canonical, intent_goal, intent_goal_commit, intent_policy_active,
    merkle_root, root_goal_commit, sha256, threshold_message, unb64u, validate_intent_wire, validate_wire_v2,
    verify_pcactn_core,
)


# ---- minting helpers (tests only) -----------------------------------------------------------------------------------

def _enc(P):
    zi = E._inv(P[2])
    x, y = P[0] * zi % E._p, P[1] * zi % E._p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _keys(label):
    h = hashlib.sha512(hashlib.sha256(label.encode()).digest()).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:], _enc(E._mul(a, E._G))


def _sign(k, msg):
    a, prefix, A = k
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % E._q
    R = _enc(E._mul(r, E._G))
    h = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % E._q
    return R + ((r + h * a) % E._q).to_bytes(32, "little")


def _pub(k):
    return b64u(k[2])


PRINCIPAL, AGENT = _keys("ki-principal"), _keys("ki-agent")
AUD = "aud-kill-intent"
NOW = 1_700_000_000_000
MAX_SAFE = 9_007_199_254_740_991

REF = b64u(sha256(b"ki/ref"))
MAP = b64u(sha256(b"ki/map"))
OTHER = b64u(sha256(b"ki/other"))
SALT = "c2FsdC1pbnRlbnQ"
INTENT = {"ref": REF, "map_digest": MAP, "goal_salt": SALT, "fidelity_ppm": 950_000, "residual_risk_ppm": 4_310_000}


def _commit(ref=REF, map_digest=MAP, salt=SALT):
    """The goal commitment built independently of the library constants (pins the domain / prefix literals)."""
    body = {"d": "atlas-pca/goal/v1\u0000", "goal": "pca-intent:v1:" + ref + ":" + map_digest, "salt": salt}
    return b64u(hashlib.sha256(canonical_bytes_strict(body)).digest())


ENV = {"type": "envelope", "goal_commit": _commit()}


def _root(caveats):
    body = {"issuer": _pub(PRINCIPAL), "holder": _pub(AGENT), "caveats": caveats, "parent": None}
    d = hash_canonical(body)
    return {"id": d, "issuer": body["issuer"], "holder": body["holder"], "caveats": caveats, "body_digest": d,
            "sig": b64u(_sign(PRINCIPAL, CAP_DOMAIN + unb64u(d)))}


def _pcactn(root, **extra):
    action = {"verb": "read", "resource": "db/x", "params_digest": EMPTY_PARAMS_DIGEST, "reversibility_class": "reversible"}
    leaf = _plan_leaf("n1", action, conditions_digest())
    p = {
        "ver": PCACTN_VERSION, "action": action, "grant_ref": root["id"], "cap_chain": [root],
        "plan": {"root": merkle_root([leaf]), "inclusion_proof": {"index": 0, "size": 1, "path": []}, "node_id": "n1"},
        "attestation": {"epoch": 1, "quote_digest": "q", "model_id": "m", "measurement": "me", "operator": "o"},
        "provenance": {"causal_hash": "c", "taint_level": 0, "trusted_refs": []},
        "freshness": {"epoch": 1, "beacon_ref": "b", "accumulator_witness": "w"},
        "counter": 0, "risk_claim": {"r": 0, "inputs": {}}, "aud": AUD, "iat": NOW - 1000, "exp": NOW + 600_000,
    }
    p.update(extra)
    p["sig"] = b64u(_sign(AGENT, threshold_message(p)))
    return p


G = _root([{"type": "max_spend", "usd": 1}, ENV])
P_BOUND = _pcactn(G, intent=dict(INTENT))
P_PLAIN = _pcactn(G)
ALL_OK = {"wire": True, "version": True, "audience": True, "validity": True, "chain": True, "grant_ref_bound": True,
          "plan_inclusion": True, "leaf_signature": True, "counter_format": True}


def _verify(p, grant=G, policy=None, **kw):
    kw.setdefault("now", NOW)
    kw.setdefault("audience", AUD)
    return verify_pcactn_core(p, grant, intent_policy=policy, **kw)


def _with(**over):
    i = dict(INTENT)
    i.update(over)
    return i


def _without(k):
    return {x: v for x, v in INTENT.items() if x != k}


# ---- constants ------------------------------------------------------------------------------------------------------

def test_constants_pinned():
    assert INTENT_GOAL_PREFIX == "pca-intent:v1:"
    assert INTENT_GOAL_COMMIT_DOMAIN == "atlas-pca/goal/v1\x00"
    assert PPM_ONE == 1_000_000
    assert MAX_INTENT_GOAL_SALT_LEN == 128
    assert ENVELOPE_INTENT_FIELDS == ("ref", "map_digest", "goal_salt", "fidelity_ppm", "residual_risk_ppm")
    assert "intent" in PCACTN_OPTIONAL_FIELDS


# ---- validate_intent_wire: exact reasons and both sides of every boundary ------------------------------------------

def test_wire_well_formed_and_edges():
    assert validate_intent_wire(dict(INTENT)) is None
    assert validate_intent_wire(_with(fidelity_ppm=0)) is None
    assert validate_intent_wire(_with(fidelity_ppm=1_000_000)) is None
    assert validate_intent_wire(_with(residual_risk_ppm=0)) is None
    assert validate_intent_wire(_with(residual_risk_ppm=MAX_SAFE)) is None
    assert validate_intent_wire(_with(goal_salt="é" * 64)) is None  # exactly 128 UTF-8 bytes
    assert validate_intent_wire(_with(goal_salt="a" * 128)) is None
    assert validate_intent_wire(_with(goal_salt="a")) is None


def test_wire_not_an_object():
    for v in (None, [dict(INTENT)], [], "x", 1, True):
        assert validate_intent_wire(v) == "'intent' must be an object", repr(v)


def test_wire_unknown_and_missing_members():
    assert validate_intent_wire(_with(note="x")) == "unknown field 'intent.note'"
    # unknown is reported before missing
    m = _without("ref")
    m["extra"] = 1
    assert validate_intent_wire(m) == "unknown field 'intent.extra'"
    for k in ("ref", "map_digest", "goal_salt", "fidelity_ppm", "residual_risk_ppm"):
        assert validate_intent_wire(_without(k)) == "missing field 'intent.%s'" % k
    assert validate_intent_wire({}) == "missing field 'intent.ref'"


def test_wire_digests():
    r = "'intent.ref' is not canonical base64url (32 bytes)"
    m = "'intent.map_digest' is not canonical base64url (32 bytes)"
    assert validate_intent_wire(_with(ref=b64u(b"x" * 31))) == r
    assert validate_intent_wire(_with(ref=b64u(b"x" * 33))) == r
    assert validate_intent_wire(_with(ref=REF + "=")) == r
    assert validate_intent_wire(_with(ref=1)) == r
    assert validate_intent_wire(_with(ref=None)) == r
    assert validate_intent_wire(_with(map_digest=b64u(b"x" * 31))) == m
    assert validate_intent_wire(_with(map_digest="+" + MAP[1:])) == m
    assert validate_intent_wire(_with(map_digest=1)) == m
    # ref checked before map_digest
    assert validate_intent_wire(_with(ref=1, map_digest=1)) == r


def test_wire_goal_salt():
    s = "'intent.goal_salt' must be a non-empty string (<= 128 UTF-8 bytes)"
    assert validate_intent_wire(_with(goal_salt="")) == s
    assert validate_intent_wire(_with(goal_salt="é" * 64 + "a")) == s  # 129 bytes
    assert validate_intent_wire(_with(goal_salt="a" * 129)) == s
    assert validate_intent_wire(_with(goal_salt="é" * 65)) == s  # 65 chars < 128 but 130 bytes: bytes, not chars
    assert validate_intent_wire(_with(goal_salt=5)) == s
    assert validate_intent_wire(_with(goal_salt=None)) == s
    assert validate_intent_wire(_with(goal_salt=["a"])) == s


def test_wire_fidelity():
    f = "'intent.fidelity_ppm' must be a safe integer in [0, 1000000]"
    for bad in (-1, 1_000_001, 1.5, "950000", True, False, None, -0.0, MAX_SAFE + 1, float("nan")):
        assert validate_intent_wire(_with(fidelity_ppm=bad)) == f, repr(bad)


def test_wire_residual():
    r = "'intent.residual_risk_ppm' must be a non-negative safe integer"
    for bad in (-1, 0.25, "1", True, False, None, -0.0, MAX_SAFE + 1):
        assert validate_intent_wire(_with(residual_risk_ppm=bad)) == r, repr(bad)
    # fidelity checked before residual
    assert validate_intent_wire(_with(fidelity_ppm=-1, residual_risk_ppm=-1)).startswith("'intent.fidelity_ppm'")


def test_wire_in_validate_wire_v2_and_verify_is_terminal():
    assert validate_wire_v2(P_BOUND) is None
    for bad in (None, [dict(INTENT)], "x", _with(note=1), _without("goal_salt"), _with(fidelity_ppm=True),
                _with(residual_risk_ppm=True), _with(goal_salt="é" * 64 + "a"), _with(fidelity_ppm=1_000_001)):
        p = _pcactn(G, intent=bad)
        assert validate_wire_v2(p) == validate_intent_wire(bad), repr(bad)
        v = _verify(p)
        assert (v.allow, v.checks) == (False, {"wire": False}), repr(bad)
        assert v.reason == "wire: " + validate_intent_wire(bad)


# ---- goal helpers ---------------------------------------------------------------------------------------------------

def test_intent_goal_and_commit():
    assert intent_goal(REF) == "pca-intent:v1:" + REF
    assert intent_goal(REF, None) == "pca-intent:v1:" + REF
    assert intent_goal(REF, "") == "pca-intent:v1:" + REF
    assert intent_goal(REF, MAP) == "pca-intent:v1:" + REF + ":" + MAP
    assert intent_goal_commit(REF, MAP, SALT) == _commit()
    assert intent_goal_commit(REF, MAP, "other") != _commit()
    assert intent_goal_commit(MAP, REF, SALT) != _commit()


def test_intent_policy_active():
    for p in (None, {}, {"require": False}, {"require": 1}, {"require": "true"}, {"require": None}, "min_fidelity_ppm",
              ["min_fidelity_ppm"], 1):
        assert intent_policy_active(p) is False, repr(p)
    for p in ({"require": True}, {"min_fidelity_ppm": 0}, {"max_residual_risk_ppm": 0}, {"min_fidelity_ppm": -1},
              {"max_residual_risk_ppm": None}, {"require": False, "min_fidelity_ppm": 1}):
        assert intent_policy_active(p) is True, repr(p)


def test_root_goal_commit():
    assert root_goal_commit(G) == _commit()
    assert root_goal_commit({"caveats": [ENV]}) == _commit()
    # first envelope wins (decoy first)
    assert root_goal_commit({"caveats": [{"type": "envelope", "goal_commit": "decoy"}, ENV]}) == "decoy"
    # a non-object caveat (or a non-envelope one) before the envelope is skipped
    assert root_goal_commit({"caveats": ["envelope", 1, None, [ENV], {"type": "Envelope", "goal_commit": "x"}, ENV]}) == _commit()
    # the first envelope without a string goal_commit ends the search (no fall-through to a later one)
    assert root_goal_commit({"caveats": [{"type": "envelope", "goal_commit": 7}, ENV]}) is None
    assert root_goal_commit({"caveats": [{"type": "envelope"}, ENV]}) is None
    assert root_goal_commit({"caveats": []}) is None
    assert root_goal_commit({"caveats": {"type": "envelope", "goal_commit": "x"}}) is None
    assert root_goal_commit({"caveats": None}) is None
    assert root_goal_commit({}) is None
    assert root_goal_commit(None) is None
    assert root_goal_commit([ENV]) is None


# ---- decide_intent_binding ------------------------------------------------------------------------------------------

REQ = "this verifier requires an intent binding but the PCActn carries none"
MIS = "intent policy misconfigured: thresholds must be non-negative safe integers (fail closed)"
NOENV = "the root grant carries no envelope goal commitment to bind the intent to"
OPEN = "intent ref / map_digest / goal_salt do not open the root grant's goal commitment"


def test_decide_absent():
    for pol in (None, {}, {"require": False}, {"require": 1}, "min_fidelity_ppm"):
        assert decide_intent_binding(None, G, pol) == ("absent", None), repr(pol)
    assert decide_intent_binding(None, None, None) == ("absent", None)


def test_decide_active_without_intent():
    assert decide_intent_binding(None, G, {"require": True}) == ("fail", REQ)
    assert decide_intent_binding(None, G, {"min_fidelity_ppm": 0}) == ("fail", REQ)
    assert decide_intent_binding(None, G, {"max_residual_risk_ppm": 0}) == ("fail", REQ)
    # misconfiguration is reported first (step 0 before step 1)
    assert decide_intent_binding(None, G, {"min_fidelity_ppm": -1}) == ("fail", MIS)


def test_decide_misconfigured():
    for pol in ({"min_fidelity_ppm": -1}, {"max_residual_risk_ppm": -1}, {"min_fidelity_ppm": 0.5},
                {"max_residual_risk_ppm": 0.5}, {"min_fidelity_ppm": None}, {"min_fidelity_ppm": True},
                {"max_residual_risk_ppm": False}, {"max_residual_risk_ppm": "5"}, {"min_fidelity_ppm": MAX_SAFE + 1},
                {"require": True, "min_fidelity_ppm": 0, "max_residual_risk_ppm": -1}):
        assert decide_intent_binding(dict(INTENT), G, pol) == ("fail", MIS), repr(pol)
    # 0 is a valid threshold on both sides (>= 0, not > 0)
    assert decide_intent_binding(_with(fidelity_ppm=0), G, {"min_fidelity_ppm": 0, "max_residual_risk_ppm": MAX_SAFE}) == ("pass", None)
    assert decide_intent_binding(_with(residual_risk_ppm=0), G, {"max_residual_risk_ppm": 0}) == ("pass", None)


def test_decide_threshold_numeric_value_rule():
    # valid iff the NUMERIC VALUE is a safe integer >= 0, whatever the runtime form (cross-language rule)
    for pol in ({"min_fidelity_ppm": -0.0}, {"max_residual_risk_ppm": -0.0}, {"min_fidelity_ppm": 950000.5},
                {"max_residual_risk_ppm": 4310000.5}, {"min_fidelity_ppm": float("nan")}, {"max_residual_risk_ppm": float("inf")},
                {"min_fidelity_ppm": float("-inf")}, {"max_residual_risk_ppm": 9007199254740992.0}, {"min_fidelity_ppm": -1.0}):
        assert decide_intent_binding(dict(INTENT), G, pol) == ("fail", MIS), repr(pol)
    ok = ("pass", None)
    assert decide_intent_binding(dict(INTENT), G, {"min_fidelity_ppm": 950000.0}) == ok
    assert decide_intent_binding(dict(INTENT), G, {"min_fidelity_ppm": 0.0, "max_residual_risk_ppm": 4310000.0}) == ok
    assert decide_intent_binding(dict(INTENT), G, {"max_residual_risk_ppm": float(MAX_SAFE)}) == ok
    assert decide_intent_binding(_with(fidelity_ppm=1_000_000), G, {"min_fidelity_ppm": 1e6}) == ok
    assert decide_intent_binding(_with(fidelity_ppm=999_999), G, {"min_fidelity_ppm": 1e6}) == (
        "fail", "intent fidelity 999999 ppm is below the policy minimum 1000000")
    assert decide_intent_binding(dict(INTENT), G, {"max_residual_risk_ppm": 4309999.0}) == (
        "fail", "intent residual risk 4310000 ppm exceeds the policy maximum 4309999")
    # a policy from JSON text (the conformance `intent_policy_json` form): floats stay floats and still bind
    import json
    assert decide_intent_binding(dict(INTENT), G, json.loads('{"min_fidelity_ppm":950000.0,"max_residual_risk_ppm":4.31e6}')) == ok
    assert decide_intent_binding(dict(INTENT), G, json.loads('{"min_fidelity_ppm":-0.0}')) == ("fail", MIS)


def test_decide_binding():
    assert decide_intent_binding(dict(INTENT), G) == ("pass", None)
    assert decide_intent_binding(dict(INTENT), G, {"require": True}) == ("pass", None)
    # a non-dict policy is inactive and never indexed (a substring `in` on a str must not be reached)
    assert decide_intent_binding(dict(INTENT), G, "min_fidelity_ppm max_residual_risk_ppm") == ("pass", None)
    assert decide_intent_binding(dict(INTENT), {"caveats": []}) == ("fail", NOENV)
    assert decide_intent_binding(dict(INTENT), {}) == ("fail", NOENV)
    assert decide_intent_binding(dict(INTENT), "grant") == ("fail", NOENV)
    assert decide_intent_binding(dict(INTENT), {"caveats": [{"type": "envelope", "goal_commit": 7}]}) == ("fail", NOENV)
    assert decide_intent_binding(dict(INTENT), {"caveats": [{"type": "envelope", "goal_commit": "decoy"}, ENV]}) == ("fail", OPEN)
    assert decide_intent_binding(dict(INTENT), {"caveats": ["x", None, 3, ENV]}) == ("pass", None)
    assert decide_intent_binding(_with(goal_salt="wrong"), G) == ("fail", OPEN)
    assert decide_intent_binding(_with(ref=OTHER), G) == ("fail", OPEN)
    assert decide_intent_binding(_with(map_digest=OTHER), G) == ("fail", OPEN)
    assert decide_intent_binding(_with(ref=MAP, map_digest=REF), G) == ("fail", OPEN)
    # map-less goal (pca-intent:v1:<ref>) does not bind: the slot requires the map
    g = {"caveats": [{"type": "envelope", "goal_commit": hash_canonical(
        {"d": "atlas-pca/goal/v1\u0000", "goal": "pca-intent:v1:" + REF, "salt": SALT})}]}
    assert decide_intent_binding(dict(INTENT), g) == ("fail", OPEN)


def test_decide_thresholds_inclusive():
    i = dict(INTENT)
    assert decide_intent_binding(i, G, {"min_fidelity_ppm": 950_000}) == ("pass", None)
    assert decide_intent_binding(i, G, {"min_fidelity_ppm": 949_999}) == ("pass", None)
    assert decide_intent_binding(i, G, {"min_fidelity_ppm": 950_001}) == (
        "fail", "intent fidelity 950000 ppm is below the policy minimum 950001")
    assert decide_intent_binding(i, G, {"max_residual_risk_ppm": 4_310_000}) == ("pass", None)
    assert decide_intent_binding(i, G, {"max_residual_risk_ppm": 4_310_001}) == ("pass", None)
    assert decide_intent_binding(i, G, {"max_residual_risk_ppm": 4_309_999}) == (
        "fail", "intent residual risk 4310000 ppm exceeds the policy maximum 4309999")
    # min checked before max
    assert decide_intent_binding(i, G, {"min_fidelity_ppm": 950_001, "max_residual_risk_ppm": 0})[1].startswith("intent fidelity")
    # binding checked before thresholds
    assert decide_intent_binding(_with(goal_salt="wrong"), G, {"min_fidelity_ppm": 950_001}) == ("fail", OPEN)


def test_decide_never_raises():
    st, why = decide_intent_binding({"fidelity_ppm": 1}, G)
    assert st == "fail" and why.startswith("intent binding error (fail closed): ")
    st, why = decide_intent_binding(_with(ref=None), G)
    assert st == "fail" and why.startswith("intent binding error (fail closed): ")


# ---- verify_pcactn_core: the `intent` check in the verdict ----------------------------------------------------------

def test_verify_bound_reports_intent_last():
    for pol in (None, {"require": True}, {"min_fidelity_ppm": 950_000, "max_residual_risk_ppm": 4_310_000}):
        v = _verify(P_BOUND, policy=pol)
        assert (v.allow, v.checks, v.reason) == (True, dict(ALL_OK, intent=True), None), repr(pol)
        assert list(v.checks)[-1] == "intent"


def test_verify_absent_is_pre_m2():
    for pol in (None, {}, {"require": False}, {"require": 1}, "x"):
        v = _verify(P_PLAIN, policy=pol)
        assert (v.allow, v.checks, v.reason) == (True, ALL_OK, None), repr(pol)
        assert "intent" not in v.checks
    v = verify_pcactn_core(P_PLAIN, G, now=NOW, audience=AUD)  # default argument
    assert (v.allow, v.checks) == (True, ALL_OK)


def test_verify_active_policy_without_intent():
    for pol in ({"require": True}, {"min_fidelity_ppm": 1}, {"max_residual_risk_ppm": 5}):
        v = _verify(P_PLAIN, policy=pol)
        assert (v.allow, v.checks, v.reason) == (False, dict(ALL_OK, intent=False), "intent: " + REQ), repr(pol)
        assert list(v.checks)[-1] == "intent"


def test_verify_intent_failures():
    v = _verify(P_BOUND, policy={"min_fidelity_ppm": 950_001})
    assert (v.allow, v.checks) == (False, dict(ALL_OK, intent=False))
    assert v.reason == "intent: intent fidelity 950000 ppm is below the policy minimum 950001"
    v = _verify(P_BOUND, policy={"max_residual_risk_ppm": -1})
    assert (v.allow, v.checks, v.reason) == (False, dict(ALL_OK, intent=False), "intent: " + MIS)
    for caveats in ([{"type": "max_spend", "usd": 1}], [{"type": "envelope", "goal_commit": "decoy"}, ENV]):
        g = _root(caveats)
        v = _verify(_pcactn(g, intent=dict(INTENT)), grant=g)
        assert v.allow is False and v.checks == dict(ALL_OK, intent=False), repr(caveats)
    g = _root([{"type": "envelope", "goal_commit": 7}])
    v = _verify(_pcactn(g, intent=dict(INTENT)), grant=g)
    assert (v.allow, v.checks, v.reason) == (False, dict(ALL_OK, intent=False), "intent: " + NOENV)
    # an envelope that is not the first caveat binds
    g = _root([{"type": "max_spend", "usd": 1}, {"type": "note", "n": 1}, ENV])
    assert _verify(_pcactn(g, intent=dict(INTENT)), grant=g).allow is True


def test_verify_tamper_after_signing():
    p = copy.deepcopy(P_BOUND)
    p["intent"]["fidelity_ppm"] = 999_999
    v = _verify(p)
    assert v.allow is False
    assert v.checks == dict(ALL_OK, leaf_signature=False, intent=True)
    assert v.reason.startswith("leaf_signature: ")


def test_verify_first_failure_reason_wins():
    v = _verify(P_BOUND, policy={"min_fidelity_ppm": 950_001}, audience="other")
    assert v.checks["audience"] is False and v.checks["intent"] is False
    assert v.reason.startswith("audience: ")


def test_verify_edges_through_signed_pcactn():
    for over in ({"fidelity_ppm": 0}, {"fidelity_ppm": 1_000_000}, {"residual_risk_ppm": 0},
                 {"residual_risk_ppm": MAX_SAFE}):
        v = _verify(_pcactn(G, intent=_with(**over)))
        assert (v.allow, v.checks) == (True, dict(ALL_OK, intent=True)), repr(over)
    salt = "é" * 64
    g = _root([{"type": "envelope", "goal_commit": _commit(salt=salt)}])
    v = _verify(_pcactn(g, intent=_with(goal_salt=salt)), grant=g)
    assert (v.allow, v.checks) == (True, dict(ALL_OK, intent=True))
