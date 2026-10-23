"""Mutation kills (Intent Layer v2 W-A): the `intent_session` wire slot, the v2 goal amendment of rule 12, the session
grant caveat in the policy layer, rule 13 (session root, delta chain, session revocation), rule 14 (signed action schema,
closed-world conformance), rule 15 (accumulators, sequencer receipts, monitors), the `layers` slot, the W-B reporting
rules and the pipeline order (checks 1-4 independent) of atlas_pca/intent_v2.py and the hooks in atlas_pca/pca.py.
Self-contained: schemas, session roots, grants, receipts, key sets, revocation epochs and PCActns are minted here with a
tiny RFC 8032 signer over the verifier's own curve arithmetic, so every assertion is an exact verdict / check map / reason.
Every boundary is pinned on both sides so an off-by-one, negated or deleted-branch mutant dies."""
import base64
import hashlib
import json

import atlas_pca.intent_v2 as V2
from atlas_pca import ed25519 as E
from atlas_pca.pca import (
    CAP_DOMAIN, MAX_SESSION_SEQ, PCACTN_OPTIONAL_FIELDS, PCACTN_VERSION, _build, _leaf_hash, _plan_leaf, _split, b64u,
    canonical_bytes_strict, conditions_digest, decide_intent_binding, evaluate_caveats, grant_session_caveat,
    hash_canonical, intent_goal_commit, intent_session_caveat_error, merkle_root, params_digest, sha256,
    suite_available, threshold_message, unb64u, validate_intent_session_wire, validate_wire_v2, verify_pcactn_core,
)
from atlas_pca.intent_v2 import (
    ACC_RECEIPT_DOMAIN, ACTION_SCHEMA_DOMAIN, INTENT_SESSION_SIG_DOMAIN, REVEPOCH_DOMAIN, SEQUENCER_KEYS_DOMAIN,
    acc_receipt_digest, acc_value_of, action_schema_digest, canon_projection, check_session_revocation, combine_acc,
    conform_action, decide_intent_v2, intent_v2_active, monitor_states, pcactn_reservation_digest, pre_state_error,
    receipt_arithmetic_ok, session_root_digest, verify_action_schema, verify_non_membership,
    verify_receipt_against_holder, verify_session_root,
)
from atlas_pca.server import require_pca


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


def _d(label):
    return b64u(sha256(label.encode()))


PRINCIPAL, AGENT, SITE = _keys("k2-principal"), _keys("k2-agent"), _keys("k2-site")
SEQ_ROOT, SEQ, STRANGER = _keys("k2-seq-root"), _keys("k2-seq"), _keys("k2-stranger")
AUD = "skyair.example"
NOW = 1_800_000_000_000
REF, MAP0, MAP1, SESSION = _d("k2/ref"), _d("k2/map0"), _d("k2/map1"), _d("k2/session")

UNSIGNED = {
    "v": 1, "kind": "pca-action-schema", "site": "https://skyair.example", "aud": AUD, "version": "2026-10-01",
    "units": {"usd_cents": {"kind": "money", "currency": "USD", "exponent": 2}},
    "verbs": [
        {"verb": "air.book", "kind": "write", "params": {
            "action.params.offer_id": {"type": "string", "semantic": "product.ref", "sensitivity": "material"},
            "action.params.total": {"type": "integer", "unit": "usd_cents", "min": 0, "max": 5_000_000,
                                    "semantic": "money.amount", "sensitivity": "critical",
                                    "accumulates_into": ["spend.usd_cents"]},
            "action.params.add_ons": {"type": "set", "values": ["none", "tripshield", "seat_plus"], "default": ["none"],
                                      "principal_neutral_default": True, "semantic": "product.addon",
                                      "sensitivity": "material"},
            "action.params.refundable": {"type": "boolean", "semantic": "flag", "sensitivity": "material"},
            "action.params.passengers": {"type": "array", "max_items": 9, "max_len": 64, "semantic": "person.identity",
                                         "sensitivity": "critical", "required": False},
            "action.params.note": {"type": "string", "semantic": "text.note", "sensitivity": "free", "required": False,
                                   "max_len": 16},
        }, "reversibility_by": {"param": "action.params.refundable", "map": {"true": "reversible", "false": "irreversible"}}},
        {"verb": "air.search", "kind": "read", "params": {
            "action.params.from": {"type": "string", "values": ["SFO", "JFK"], "semantic": "place.airport",
                                   "sensitivity": "material"},
            "action.params.date": {"type": "date", "semantic": "schedule.date", "sensitivity": "material"},
            "action.params.pax": {"type": "integer", "min": 1, "max": 9, "semantic": "quantity", "sensitivity": "material"},
        }, "reversibility": "reversible"},
    ],
}


def _sign_schema(doc, signer=SITE, kid="skyair-2026"):
    body = {k: v for k, v in doc.items() if k != "sig"}
    return dict(body, sig={"alg": "ed25519", "kid": kid,
                           "value": b64u(_sign(signer, ACTION_SCHEMA_DOMAIN.encode() + canonical_bytes_strict(body)))})


SCHEMA = _sign_schema(UNSIGNED)
KEYS = [{"kid": "skyair-2026", "alg": "ed25519", "pk": _pub(SITE)}]
SD = action_schema_digest(SCHEMA)

TRIP = {"id": "trip_spend", "agg": "sum", "unit": "usd_cents", "sel": {"accumulates_into": "spend.usd_cents"},
        "win": {"kind": "task"}, "key": None, "domain_max": 500_000, "holder": {"kind": "site_local"}}
QUESTIONS = {"id": "questions", "agg": "count", "sel": {"event": "intent_required"}, "win": {"kind": "task"}, "key": None,
             "cap": 6, "holder": {"kind": "wallet"}}


def _root_of(signer=PRINCIPAL, **over):
    body = {"v": 1, "kind": "pca-intent-session", "session": SESSION, "principals": [{"key": _pub(PRINCIPAL)}],
            "intent_ref": REF, "schema": {"aud": AUD, "digest": SD}, "layers": {"task": {"map_digest": MAP0}},
            "accumulators": [TRIP, QUESTIONS], "monitors": [], "question_uri": "https://atlas.example/q",
            "expires_at": NOW + 86_400_000}
    body.update(over)
    body["signer"] = _pub(PRINCIPAL)
    body["sig"] = b64u(_sign(signer, INTENT_SESSION_SIG_DOMAIN.encode() + canonical_bytes_strict(body)))
    return body


S0 = _root_of()
R0 = session_root_digest(S0)


def _commit_v2(map_digest, salt, session=SESSION):
    body = {"d": "atlas-pca/goal/v1\u0000", "goal": "pca-intent:v2:" + session + ":" + map_digest, "salt": salt}
    return b64u(hashlib.sha256(canonical_bytes_strict(body)).digest())


def _grant(seq=0, prev=None, map_digest=MAP0, salt="salt0", root=R0, signer=PRINCIPAL, session=SESSION):
    sc = {"type": "intent_session", "session": session, "seq": seq, "root": root}
    if prev is not None:
        sc["prev"] = prev
    caveats = [{"type": "envelope", "goal_commit": _commit_v2(map_digest, salt, session)}, sc]
    body = {"issuer": _pub(signer), "holder": _pub(AGENT), "caveats": caveats, "parent": None}
    d = hash_canonical(body)
    return {"id": d, "issuer": body["issuer"], "holder": body["holder"], "caveats": caveats, "body_digest": d,
            "sig": b64u(_sign(signer, CAP_DOMAIN + unb64u(d)))}


G0 = _grant()
D1 = _grant(seq=1, prev=G0["id"], map_digest=MAP1, salt="salt1")
PARAMS = {"offer_id": "OF-1", "total": 38_900, "add_ons": ["none"], "refundable": False}


def _intent(map_digest=MAP0, salt="salt0", ref=REF):
    return {"ref": ref, "map_digest": map_digest, "goal_salt": salt, "fidelity_ppm": 1_000_000, "residual_risk_ppm": 0}


def _is(**over):
    i = {"session": SESSION, "root": R0, "seq": 0, "schema": SD, "acc": [{"id": "trip_spend", "post": 38_900}]}
    i.update(over)
    return i


def _unsigned(grant, params=PARAMS, intent="default", **extra):
    action = {"verb": "air.book", "resource": "skyair.example/bookings", "params_digest": params_digest(params),
              "reversibility_class": "irreversible"}
    leaf = _plan_leaf("book", action, conditions_digest())
    p = {
        "ver": PCACTN_VERSION, "action": action, "grant_ref": grant["id"], "cap_chain": [grant],
        "plan": {"root": merkle_root([leaf]), "inclusion_proof": {"index": 0, "size": 1, "path": []}, "node_id": "book"},
        "attestation": {"epoch": 1, "quote_digest": "q", "model_id": "m", "measurement": "me", "operator": "o"},
        "provenance": {"causal_hash": "c", "taint_level": 0, "trusted_refs": []},
        "freshness": {"epoch": 1, "beacon_ref": "b", "accumulator_witness": "w"},
        "counter": 1, "risk_claim": {"r": 0, "inputs": {}}, "aud": AUD, "iat": NOW - 1000, "exp": NOW + 600_000,
    }
    if intent is not None:
        p["intent"] = _intent() if intent == "default" else intent
    p.update(extra)
    return p


def _signed(p):
    p = dict(p)
    p.pop("sig", None)
    p["sig"] = b64u(_sign(AGENT, threshold_message(p)))
    return p


def _pcactn(grant=G0, **kw):
    return _signed(_unsigned(grant, **kw))


P0 = _pcactn(intent_session=_is())


def _ctx(**over):
    c = {"params": PARAMS, "schema": {"docs": [SCHEMA], "keys": KEYS}, "session": {"root": S0, "grants": []},
         "acc": {"state": {"trip_spend": {"sum": 0}}, "monitors": {}}}
    c.update(over)
    return c


CORE_OK = {"wire": True, "version": True, "audience": True, "validity": True, "chain": True, "grant_ref_bound": True,
           "plan_inclusion": True, "leaf_signature": True, "counter": True}
V2_OK = dict(CORE_OK, intent=True, schema=True, intent_session=True, accumulators=True)


def _verify(p=P0, grant=G0, ctx="default"):
    return verify_pcactn_core(p, grant, now=NOW, audience=AUD, intent_v2=_ctx() if ctx == "default" else ctx)


def _decide(p=P0, grant=G0, ctx="default", now=NOW):
    return decide_intent_v2(p, grant, _ctx() if ctx == "default" else ctx, now)


def _names(d):
    return [c["name"] for c in d["checks"]]


def _check(d, name):
    return next(c for c in d["checks"] if c["name"] == name)


# ---- constants ------------------------------------------------------------------------------------------------------

def test_constants_pinned():
    assert "intent_session" in PCACTN_OPTIONAL_FIELDS
    assert MAX_SESSION_SEQ == 2_147_483_647
    assert ACTION_SCHEMA_DOMAIN == "atlas-pca/action-schema/v1\x00"
    assert V2.ACTION_SCHEMA_REF_DOMAIN == "atlas-pca/action-schema-ref/v1"
    assert INTENT_SESSION_SIG_DOMAIN == "atlas-pca/intent-session/v1\x00"
    assert V2.INTENT_SESSION_REF_DOMAIN == "atlas-pca/intent-session-ref/v1"
    assert ACC_RECEIPT_DOMAIN == "atlas-pca/acc-receipt/v1\x00"
    assert V2.ACC_RECEIPT_REF_DOMAIN == "atlas-pca/acc-receipt-ref/v1"
    assert V2.ACC_RESERVE_DOMAIN == "atlas-pca/acc-reserve/v1"
    assert SEQUENCER_KEYS_DOMAIN == "atlas-pca/sequencer-keys/v1\x00"
    assert REVEPOCH_DOMAIN == "atlas-pca/revepoch/v1\x00"
    assert V2.RECEIPT_SKEW_MS == 60_000
    assert V2.DEFAULT_MAX_LEN == 1024 and V2.DEFAULT_MAX_ITEMS == 64
    assert V2.session_revocation_id("s") == "pca-intent:session:s"
    assert V2.map_revocation_id("m") == "pca-intent:map:m"
    assert V2.delta_revocation_id("g") == "pca-intent:delta:g"
    assert V2.profile_revocation_id("p", 3) == "pca-intent:profile:p@3"
    assert V2.session_revocation_scope("s") == "pca-intent-session:s"
    assert action_schema_digest(SCHEMA) == b64u(hashlib.sha256(canonical_bytes_strict(
        {"d": "atlas-pca/action-schema-ref/v1", "s": SCHEMA})).digest())
    assert session_root_digest(S0) == b64u(hashlib.sha256(canonical_bytes_strict(
        {"d": "atlas-pca/intent-session-ref/v1", "s": S0})).digest())


# ---- the wire slot (rule 13, terminal `wire`) -----------------------------------------------------------------------

def test_wire_slot_ok_and_not_object():
    assert validate_intent_session_wire(_is()) is None
    assert validate_intent_session_wire({"session": SESSION, "root": R0, "seq": 0, "schema": SD}) is None
    for v in (None, [_is()], "x", 1, True):
        assert validate_intent_session_wire(v) == "'intent_session' must be an object"


def test_wire_slot_members_and_order():
    assert validate_intent_session_wire(dict(_is(), note="x")) == "unknown field 'intent_session.note'"
    # unknown wins over missing; JS key order: an array-index key is reported first
    assert validate_intent_session_wire({"zz": 1, "7": 1}) == "unknown field 'intent_session.7'"
    for k in ("session", "root", "seq", "schema"):
        v = _is()
        del v[k]
        assert validate_intent_session_wire(v) == "missing field 'intent_session.%s'" % k
    assert validate_intent_session_wire({"schema": SD}) == "missing field 'intent_session.session'"
    short = b64u(sha256(b"x")[:31])
    for k in ("session", "root", "schema"):
        assert validate_intent_session_wire(_is(**{k: short})) == "'intent_session.%s' is not canonical base64url (32 bytes)" % k
    assert validate_intent_session_wire(_is(session=short, root=short)) == "'intent_session.session' is not canonical base64url (32 bytes)"


def test_wire_slot_seq_bounds():
    bad = "'intent_session.seq' must be a safe integer in [0, 2147483647]"
    assert validate_intent_session_wire(_is(seq=0)) is None
    assert validate_intent_session_wire(_is(seq=2_147_483_647)) is None
    assert validate_intent_session_wire(_is(seq=5.0)) is None
    for s in (-1, 2_147_483_648, 1.5, -0.0, True, "1", None):
        assert validate_intent_session_wire(_is(seq=s)) == bad, repr(s)


def test_wire_slot_acc():
    assert validate_intent_session_wire(_is(acc=[])) is None
    assert validate_intent_session_wire(_is(acc=[{"id": "a%d" % i, "post": 0} for i in range(16)])) is None
    assert validate_intent_session_wire(_is(acc=[{"id": "a%d" % i, "post": 0} for i in range(17)])) == \
        "'intent_session.acc' must be an array of at most 16 entries"
    assert validate_intent_session_wire(_is(acc={})) == "'intent_session.acc' must be an array of at most 16 entries"
    assert validate_intent_session_wire(_is(acc=None)) == "'intent_session.acc' must be an array of at most 16 entries"
    assert validate_intent_session_wire(_is(acc=[1])) == "'intent_session.acc[0]' must be an object"
    assert validate_intent_session_wire(_is(acc=[{"id": "a", "post": 0, "x": 1}])) == "unknown field 'intent_session.acc[0].x'"
    idbad = "'intent_session.acc[0].id' must match [A-Za-z0-9_]{1,64}"
    for i in ("a-b", "", "a" * 65, "a\n", 5):
        assert validate_intent_session_wire(_is(acc=[{"id": i, "post": 0}])) == idbad, repr(i)
    assert validate_intent_session_wire(_is(acc=[{"id": "a" * 64, "post": 0}])) is None
    assert validate_intent_session_wire(_is(acc=[{"id": "a", "post": 1}, {"id": "a", "post": 2}])) == \
        "'intent_session.acc' ids must be distinct"
    for p in (-1, 1.5, -0.0, True, "1", 2 ** 53):
        assert validate_intent_session_wire(_is(acc=[{"id": "a", "post": p}])) == \
            "'intent_session.acc[0].post' must be a non-negative safe integer", repr(p)
    assert validate_intent_session_wire(_is(acc=[{"id": "a", "post": 2 ** 53 - 1, "receipt": SD}])) is None
    assert validate_intent_session_wire(_is(acc=[{"id": "a", "post": 0, "receipt": "x"}])) == \
        "'intent_session.acc[0].receipt' is not canonical base64url (32 bytes)"


def test_wire_slot_digest_lists_and_prov():
    ds = [_d("f%d" % i) for i in range(17)]
    for name, mx in (("facts", 16), ("classes", 8), ("labels", 16)):
        assert validate_intent_session_wire(_is(**{name: ds[:mx]})) is None
        assert validate_intent_session_wire(_is(**{name: ds[:mx + 1]})) == \
            "'intent_session.%s' must be an array of at most %d digests" % (name, mx)
        assert validate_intent_session_wire(_is(**{name: ["x"]})) == \
            "'intent_session.%s' entries must be canonical base64url (32 bytes)" % name
        assert validate_intent_session_wire(_is(**{name: [ds[0], ds[0]]})) == "'intent_session.%s' entries must be distinct" % name
    assert validate_intent_session_wire(_is(offer_set=SD)) is None
    assert validate_intent_session_wire(_is(offer_set="x")) == "'intent_session.offer_set' is not canonical base64url (32 bytes)"
    ok = {"action.params.p%d" % i: ["r"] for i in range(32)}
    assert validate_intent_session_wire(_is(prov=ok)) is None
    assert validate_intent_session_wire(_is(prov=dict(ok, **{"action.params.x": ["r"]}))) == \
        "'intent_session.prov' must be an object of at most 32 entries"
    assert validate_intent_session_wire(_is(prov=[])) == "'intent_session.prov' must be an object of at most 32 entries"
    assert validate_intent_session_wire(_is(prov={"env.x": ["r"]})) == "'intent_session.prov' key 'env.x' is not action.params.<name>"
    assert validate_intent_session_wire(_is(prov={"action.params.a.b": ["r"]})) == \
        "'intent_session.prov' key 'action.params.a.b' is not action.params.<name>"
    refs = "'intent_session.prov.action.params.t' must be 1..8 non-empty strings of at most 256 UTF-8 bytes"
    assert validate_intent_session_wire(_is(prov={"action.params.t": ["r"] * 8})) is None
    assert validate_intent_session_wire(_is(prov={"action.params.t": ["é" * 128]})) is None  # 256 bytes
    for r in ([], ["r"] * 9, [""], ["é" * 128 + "a"], ["\ud800"], [1], "r"):
        assert validate_intent_session_wire(_is(prov={"action.params.t": r})) == refs, repr(r)


def test_wire_slot_is_part_of_validate_wire_v2():
    p = _signed(_unsigned(G0, intent_session=_is(seq=-1)))
    assert validate_wire_v2(p) == "'intent_session.seq' must be a safe integer in [0, 2147483647]"
    v = verify_pcactn_core(p, G0, now=NOW, audience=AUD, intent_v2=_ctx())
    assert (v.allow, v.checks) == (False, {"wire": False})
    assert v.reason == "wire: 'intent_session.seq' must be a safe integer in [0, 2147483647]"
    # the intent slot is checked before intent_session
    p = _signed(_unsigned(G0, intent=dict(_intent(), fidelity_ppm=-1), intent_session=_is(seq=-1)))
    assert validate_wire_v2(p).startswith("'intent.fidelity_ppm'")


# ---- the session grant caveat and the policy layer ------------------------------------------------------------------

def test_session_caveat_shape():
    c0 = {"type": "intent_session", "session": SESSION, "seq": 0, "root": R0}
    assert intent_session_caveat_error(c0) is None
    assert intent_session_caveat_error(dict(c0, seq=1, prev=G0["id"])) is None
    assert intent_session_caveat_error(dict(c0, seq=MAX_SESSION_SEQ, prev=G0["id"])) is None
    for c in (None, [], dict(c0, type="envelope"), {"session": SESSION}):
        assert intent_session_caveat_error(c) == "not an intent_session caveat"
    assert intent_session_caveat_error(dict(c0, x=1)) == "intent_session caveat: unknown member 'x'"
    assert intent_session_caveat_error(dict(c0, root="x")) == "intent_session caveat: session and root must be canonical base64url (32 bytes)"
    for s in (-1, MAX_SESSION_SEQ + 1, 0.5, True):
        assert intent_session_caveat_error(dict(c0, seq=s)) == "intent_session caveat: seq must be a safe integer in [0, 2147483647]"
    assert intent_session_caveat_error(dict(c0, prev=G0["id"])) == "intent_session caveat: prev is present exactly when seq > 0"
    assert intent_session_caveat_error(dict(c0, seq=1)) == "intent_session caveat: prev is present exactly when seq > 0"
    assert intent_session_caveat_error(dict(c0, seq=1, prev="x")) == "intent_session caveat: prev must be canonical base64url (32 bytes)"
    assert grant_session_caveat(G0) == G0["caveats"][1]
    assert grant_session_caveat({"caveats": [{"type": "x"}, c0, dict(c0, seq=1)]}) == c0
    assert grant_session_caveat({"caveats": "x"}) is None and grant_session_caveat([]) is None


def test_session_caveat_in_policy_layer():
    c0 = {"type": "intent_session", "session": SESSION, "seq": 0, "root": R0}
    assert evaluate_caveats([c0], {"now": NOW}) == (True, [])
    assert evaluate_caveats([dict(c0, seq=-1)], {"now": NOW}) == (False, ["intent_session"])
    assert evaluate_caveats([c0], {}) == (False, ["intent_session"])  # every built-in type but max_spend needs `now`


# ---- the v2 goal amendment of rule 12 -------------------------------------------------------------------------------

def test_v2_goal_amendment():
    i = _intent()
    assert intent_goal_commit(i["ref"], MAP0, "salt0", SESSION) == _commit_v2(MAP0, "salt0")
    assert intent_goal_commit(i["ref"], MAP0, "salt0") != _commit_v2(MAP0, "salt0")
    assert decide_intent_binding(i, G0, None, SESSION) == ("pass", None)
    assert decide_intent_binding(i, G0, None) == (
        "fail", "intent ref / map_digest / goal_salt do not open the root grant's goal commitment")
    # through the verifier: with intent_session the v2 goal opens; without it the v1 goal does not
    assert _verify().checks["intent"] is True
    v = _verify(_pcactn())
    assert (v.allow, v.checks) == (False, dict(CORE_OK, intent=False))  # no v2 check reported (back-compat)


# ---- the whole pipeline: allow, reporting conditions, independence and order -----------------------------------------

def test_allow_g0_exact_checks():
    v = _verify()
    assert (v.allow, v.checks, v.reason) == (True, V2_OK, None)
    d = _decide()
    assert _names(d) == ["schema", "intent_session", "accumulators"]
    assert d["env"] == {"canon": {"add_ons": '["none"]', "refundable": "false"}, "acc": {"trip_spend": {"post": 38_900}},
                        "mon": {}}
    assert d["schema"] is SCHEMA


def test_allow_delta_d1_and_unheld():
    p1 = _pcactn(D1, intent=_intent(MAP1, "salt1"), intent_session=_is(seq=1, acc=[{"id": "trip_spend", "post": 77_800}]))
    ctx = _ctx(session={"root": S0, "grants": [G0]}, acc={"state": {"trip_spend": {"sum": 38_900}}, "monitors": {}})
    v = verify_pcactn_core(p1, D1, now=NOW, audience=AUD, intent_v2=ctx)
    assert (v.allow, v.checks) == (True, V2_OK)
    ctx["session"] = {"root": S0, "grants": []}
    d = _decide(p1, D1, ctx)
    assert _check(d, "intent_session") == {"name": "intent_session", "ok": False,
                                           "reason": "the verifier does not hold the 1 earlier grants of this session"}


def test_reporting_conditions():
    plain = _pcactn()
    assert _decide(plain, ctx=_ctx())["checks"] == []
    assert intent_v2_active(plain, _ctx()) is False and intent_v2_active(P0, None) is True
    assert _names(_decide(plain, ctx=_ctx(policy={"session": {"require": True}}))) == ["intent_session"]
    assert _check(_decide(plain, ctx=_ctx(policy={"session": {"require": True}})), "intent_session")["reason"] == \
        "this verifier requires an intent_session but the PCActn carries none"
    assert _decide(plain, ctx=_ctx(policy={"schema": {"closed_world": True}}))["checks"] == [{"name": "schema", "ok": True}]
    # layers: only with the member AND a configured `layers` ({} = no ceilings, passes)
    assert _names(_decide(plain, ctx=_ctx(layers={}))) == []
    assert _names(_decide(ctx=_ctx(layers={}))) == ["schema", "intent_session", "layers", "accumulators"]
    assert _check(_decide(ctx=_ctx(layers={})), "layers")["ok"] is True
    # NULL RULING: a null `layers` (or ceiling) is a malformed context, not "no ceilings"
    bad = "malformed v2 context: layers must be an object"
    assert _decide(ctx=_ctx(layers=None))["checks"] == [{"name": n, "ok": False, "reason": bad}
                                                       for n in ("schema", "intent_session", "accumulators")]
    assert _check(_decide(ctx=_ctx(layers={"org": None})), "schema")["reason"] == \
        "malformed v2 context: layers.org must be {predicates: [...]}"
    assert _check(_decide(ctx=_ctx(layers={"team": {"predicates": []}})), "schema")["reason"] == \
        "malformed v2 context: layers: unknown member 'team'"
    v = verify_pcactn_core(plain, G0, now=NOW, audience=AUD, intent_v2=_ctx(policy={"session": {"require": True}}))
    assert v.checks == dict(CORE_OK, intent=False, intent_session=False) and v.allow is False


def test_pipeline_order_and_independence():
    # params that do not open the digest: schema fails and the accumulator value no longer matches; intent_session passes
    d = _decide(ctx=_ctx(params=dict(PARAMS, total=1)))
    assert [(c["name"], c["ok"]) for c in d["checks"]] == [("schema", False), ("intent_session", True), ("accumulators", False)]
    assert _check(d, "schema")["reason"] == "params do not hash to action.params_digest"
    # no session root: intent_session and accumulators fail, schema still passes
    d = _decide(ctx=_ctx(session={"grants": []}))
    assert [(c["name"], c["ok"]) for c in d["checks"]] == [("schema", True), ("intent_session", False), ("accumulators", False)]
    assert _check(d, "intent_session")["reason"] == "no session root for this session"
    assert _check(d, "accumulators")["reason"] == "no session root for this session"
    # an org ceiling fails layers only; the layers slot sits between intent_session and accumulators
    org = {"org": {"predicates": [{"verb": "air.book", "where": [{"field": "action.params.total", "op": "lte", "value": 10_000}]}]}}
    d = _decide(ctx=_ctx(layers=org))
    assert [(c["name"], c["ok"]) for c in d["checks"]] == [("schema", True), ("intent_session", True), ("layers", False),
                                                           ("accumulators", True)]
    v = _verify(ctx=_ctx(layers=org))
    assert v.allow is False and v.checks == dict(V2_OK, layers=False)
    assert v.reason.startswith("layers: layers: the action is outside the org ceiling")
    # the layers env carries env.canon only when schema passed
    site = {"site": {"predicates": [{"verb": "air.book", "where": [{"field": "env.canon.add_ons", "op": "eq", "value": '["none"]'}]}]}}
    assert _check(_decide(ctx=_ctx(layers=site)), "layers")["ok"] is True
    bad_schema = _ctx(layers=site, schema={"docs": [SCHEMA], "keys": []})
    assert _check(_decide(ctx=bad_schema), "layers")["ok"] is False


def test_first_v2_failure_is_the_reason_after_core():
    v = _verify(ctx=_ctx(acc={"state": {}, "monitors": {}}))
    assert v.checks == dict(V2_OK, accumulators=False)
    assert v.reason == "accumulators: no state for site-local accumulator 'trip_spend'"
    v = _verify(ctx=_ctx(acc={"state": {}, "monitors": {}}, session={"grants": []}))
    assert v.reason == "intent_session: no session root for this session"


# ---- rule 14: schema step order and conformance ---------------------------------------------------------------------

def test_schema_step_reasons_in_order():
    r = lambda ctx, p=P0: _check(_decide(p, ctx=ctx), "schema")["reason"]
    assert r(_ctx(schema={"docs": [], "keys": KEYS})) == "this verifier has no action schema configured"
    assert r(_ctx(schema={"keys": KEYS})) == "the schema context must be {docs: [...], keys: [...]}"
    assert r(_ctx(schema={"docs": [SCHEMA]})) == "the schema context must be {docs: [...], keys: [...]}"
    assert r(_ctx(schema={"docs": "x", "keys": KEYS})) == "the schema context must be {docs: [...], keys: [...]}"
    other = _sign_schema(dict(UNSIGNED, version="v2"))
    assert r(_ctx(schema={"docs": [other], "keys": KEYS})) == "intent_session.schema names no schema this verifier accepts"
    assert r(_ctx(schema={"docs": [SCHEMA], "keys": [dict(KEYS[0], pk=_pub(STRANGER))]})) == \
        "schema does not verify: schema signature invalid"
    other_aud = _sign_schema(dict(UNSIGNED, aud="hotel.example"))
    p = _pcactn(intent_session=_is(schema=action_schema_digest(other_aud)))
    assert r(_ctx(schema={"docs": [SCHEMA, other_aud], "keys": KEYS}), p) == "schema aud does not match the PCActn aud"
    assert r(_ctx(params=None)) == "malformed v2 context: params must be an object"
    noparams = _ctx()
    del noparams["params"]
    assert r(noparams) == "no plaintext params to check against the schema (closed world needs them)"
    extra = dict(PARAMS, reseller="x")
    p = _pcactn(params=extra, intent_session=_is())
    assert r(_ctx(params=extra), p) == \
        "schema_violation: undeclared_param: parameter 'action.params.reseller' is not declared for 'air.book'"
    # closed world without the member: the FIRST accepted schema
    plain = _pcactn()
    assert _decide(plain, ctx=_ctx(policy={"schema": {"closed_world": True}}, schema={"docs": [other_aud, SCHEMA], "keys": KEYS}))[
        "checks"] == [{"name": "schema", "ok": False, "reason": "schema aud does not match the PCActn aud"}]


def test_verify_action_schema():
    assert verify_action_schema(SCHEMA, KEYS) == {"ok": True}
    assert verify_action_schema(SCHEMA, [{"kid": "other", "pk": _pub(SITE)}]) == {"ok": False, "reason": "no schema key with kid 'skyair-2026'"}
    assert verify_action_schema(SCHEMA, "x")["reason"] == "the schema keys must be an array"
    assert verify_action_schema(SCHEMA, {"0": KEYS[0]})["reason"] == "the schema keys must be an array"
    assert verify_action_schema(SCHEMA, [dict(KEYS[0], pq_pk=5)])["reason"] == "the schema key pq_pk must be a string"
    assert verify_action_schema(SCHEMA, [{"kid": "skyair-2026", "pk": "x"}])["reason"] == "schema key pk is not canonical base64url (32 bytes)"
    assert verify_action_schema(SCHEMA, [{"kid": "skyair-2026", "pk": _pub(SITE)}]) == {"ok": True}  # absent alg = ed25519
    # an ML-DSA key entry: refused as unsupported_suite when this runtime has no ML-DSA backend (no dilithium-py,
    # OpenSSL < 3.5), else it is a suite mismatch against the ed25519 signature
    assert verify_action_schema(SCHEMA, [dict(KEYS[0], alg="ml-dsa-65")])["reason"] == (
        "sig.alg does not match the pinned key suite" if suite_available("ml-dsa-65")
        else "schema key: unsupported_suite: 'ml-dsa-65'")
    assert verify_action_schema(SCHEMA, [dict(KEYS[0], alg="nope")])["reason"] == "schema key: unsupported_suite: 'nope'"
    assert verify_action_schema(SCHEMA, [dict(KEYS[0], alg=None)])["reason"] == "schema key: alg must be a string"
    mism = dict(SCHEMA, sig=dict(SCHEMA["sig"], alg="ml-dsa-65"))
    assert verify_action_schema(mism, KEYS)["reason"] == (
        "sig.alg does not match the pinned key suite" if suite_available("ml-dsa-65")
        else "sig.alg: unsupported_suite: 'ml-dsa-65'")
    assert verify_action_schema(dict(SCHEMA, version="x"), KEYS)["reason"] == "schema signature invalid"
    assert verify_action_schema(dict(SCHEMA, extra=1), KEYS)["reason"] == "unknown member 'extra'"
    assert verify_action_schema(dict(SCHEMA, sig=dict(SCHEMA["sig"], alg=None)), KEYS)["reason"] == "sig.alg: alg must be a string"
    assert verify_action_schema(dict(SCHEMA, sig=dict(SCHEMA["sig"], alg="nope")), KEYS)["reason"] == "sig.alg: unsupported_suite: 'nope'"
    nosig = {k: v for k, v in SCHEMA.items() if k != "sig"}
    assert V2.action_schema_shape_error(nosig, signed=False) is None
    assert V2.action_schema_shape_error(SCHEMA, signed=False) == "an unsigned schema must not carry sig"


def test_schema_shape_boundaries():
    sh = V2.action_schema_shape_error
    verbs = [{"verb": "v%d" % i, "kind": "read", "params": {}} for i in range(257)]
    base = {k: v for k, v in UNSIGNED.items() if k != "verbs"}
    assert sh(dict(base, verbs=verbs[:256]), signed=False) is None
    assert sh(dict(base, verbs=verbs), signed=False) == "verbs must be 1..256 entries"
    assert sh(dict(base, verbs=[]), signed=False) == "verbs must be 1..256 entries"
    params = {"action.params.p%d" % i: {"type": "boolean", "semantic": "s", "sensitivity": "free"} for i in range(65)}
    one = lambda ps: dict(base, verbs=[{"verb": "x", "kind": "read", "params": ps}])
    assert sh(one(dict(list(params.items())[:64])), signed=False) is None
    assert sh(one(params), signed=False) == "verb 'x': more than 64 parameters"
    i = lambda **d: one({"action.params.n": dict({"type": "integer", "semantic": "s", "sensitivity": "free"}, **d)})
    assert sh(i(min=1, max=1), signed=False) is None
    assert sh(i(min=2, max=1), signed=False) == "verb 'x': action.params.n: min > max"
    assert sh(i(max_len=1), signed=False) is None
    assert sh(i(max_len=0), signed=False) == "verb 'x': action.params.n: max_len must be a positive safe integer"
    assert sh(i(accumulates_into=["u"] * 1), signed=False) is None
    assert sh(i(accumulates_into=["u%d" % k for k in range(9)]), signed=False) == "verb 'x': action.params.n: accumulates_into must be 1..8 unit ids"
    assert sh(i(unit="usd_cents"), signed=False) is None
    for name in ("__proto__", "constructor", "prototype"):
        assert sh(one({"action.params." + name: {"type": "boolean", "semantic": "s", "sensitivity": "free"}}), signed=False) == \
            "verb 'x': parameter name 'action.params.%s' is reserved (__proto__ / constructor / prototype)" % name
    assert sh(one({"action.params.proto": {"type": "boolean", "semantic": "s", "sensitivity": "free"}}), signed=False) is None
    assert sh(i(default=0), signed=False) is None
    assert sh(i(default=None), signed=False) == "verb 'x': action.params.n: default must not be null (absent = no default)"
    assert sh(i(unit="eur"), signed=False) == \
        "verb 'x': action.params.n: unit must name a declared unit of an integer parameter"
    assert sh(dict(base, units={"usd": {"kind": "money", "exponent": 18}}, verbs=[{"verb": "x", "kind": "read", "params": {}}]), signed=False) is None
    assert sh(dict(base, units={"usd": {"kind": "money", "exponent": 19}}, verbs=[{"verb": "x", "kind": "read", "params": {}}]), signed=False) == \
        "unit 'usd': exponent must be an integer in [0, 18]"
    assert sh(dict(base, verbs=[{"verb": "x", "kind": "read", "params": {}}, {"verb": "x", "kind": "read", "params": {}}]), signed=False) == \
        "verb 'x' is declared twice"


def _conform(params, verb="air.book", doc=SCHEMA):
    c = conform_action(doc, verb, params)
    return (c["ok"],) if c["ok"] else (c["ok"], c["code"], c.get("path"))


def test_conform_codes_and_order():
    assert _conform(PARAMS) == (True,)
    assert _conform([]) == (False, "params_not_object", None)
    assert _conform(PARAMS, verb="air.cancel") == (False, "unknown_verb", None)
    assert _conform(dict(PARAMS, zz=1, aa=1)) == (False, "undeclared_param", "action.params.aa")
    assert _conform({"offer_id": "x", "extra": 1}) == (False, "undeclared_param", "action.params.extra")
    assert _conform({}) == (False, "missing_param", "action.params.add_ons")
    p = {k: v for k, v in PARAMS.items() if k != "refundable"}
    assert _conform(p) == (False, "missing_param", "action.params.refundable")
    assert _conform(dict(PARAMS, note="x", passengers=[])) == (True,)


def test_conform_integer_bounds():
    path = "action.params.total"
    assert _conform(dict(PARAMS, total=0)) == (True,)
    assert _conform(dict(PARAMS, total=5_000_000)) == (True,)
    assert _conform(dict(PARAMS, total=5_000_000.0)) == (True,)
    assert _conform(dict(PARAMS, total=5_000_001)) == (False, "out_of_domain", path)
    assert _conform(dict(PARAMS, total=-1)) == (False, "out_of_domain", path)
    for t in ("38900", 1.5, -0.0, True, None, 2 ** 53):
        assert _conform(dict(PARAMS, total=t)) == (False, "bad_type", path), repr(t)


def test_conform_string_set_array_bool():
    assert _conform(dict(PARAMS, note="é" * 8)) == (True,)  # 16 UTF-8 bytes
    assert _conform(dict(PARAMS, note="é" * 8 + "a")) == (False, "out_of_domain", "action.params.note")
    assert _conform(dict(PARAMS, note="\ud800")) == (False, "bad_type", "action.params.note")
    assert _conform(dict(PARAMS, refundable="false")) == (False, "bad_type", "action.params.refundable")
    assert _conform(dict(PARAMS, add_ons=[])) == (True,)
    assert _conform(dict(PARAMS, add_ons=["none", "tripshield", "seat_plus"])) == (True,)
    assert _conform(dict(PARAMS, add_ons=["none", "none"])) == (False, "out_of_domain", "action.params.add_ons")
    assert _conform(dict(PARAMS, add_ons=["bag"])) == (False, "out_of_domain", "action.params.add_ons")
    assert _conform(dict(PARAMS, add_ons=[1])) == (False, "bad_type", "action.params.add_ons")
    assert _conform(dict(PARAMS, add_ons="none")) == (False, "bad_type", "action.params.add_ons")
    assert _conform(dict(PARAMS, passengers=["p%d" % i for i in range(9)])) == (True,)
    assert _conform(dict(PARAMS, passengers=["p%d" % i for i in range(10)])) == (False, "out_of_domain", "action.params.passengers")
    assert _conform(dict(PARAMS, passengers=["x" * 64])) == (True,)
    assert _conform(dict(PARAMS, passengers=["x" * 65])) == (False, "bad_type", "action.params.passengers")
    assert _conform(dict(PARAMS, passengers=[1])) == (False, "bad_type", "action.params.passengers")


def test_conform_dates():
    s = lambda d: _conform({"from": "SFO", "date": d, "pax": 2}, verb="air.search")
    for ok in ("2028-02-29", "2000-02-29", "2026-12-31", "0001-01-01", "2026-01-31"):
        assert s(ok) == (True,), ok
    for bad in ("2026-02-29", "1900-02-29", "2026-1-05", "0000-01-01", "2026-13-01", "2026-04-31", "2026-01-00",
                "2026-01-01\n", "２０２６-01-01", "2026-01-32"):
        assert s(bad) == (False, "out_of_domain", "action.params.date"), bad
    assert s(20260101) == (False, "bad_type", "action.params.date")
    assert _conform({"from": "LAX", "date": "2026-11-20", "pax": 2}, verb="air.search") == (False, "out_of_domain", "action.params.from")
    assert _conform({"from": "SFO", "date": "2026-11-20", "pax": 0}, verb="air.search") == (False, "out_of_domain", "action.params.pax")
    assert _conform({"from": "SFO", "date": "2026-11-20", "pax": 9}, verb="air.search") == (True,)


def test_canon_projection():
    assert canon_projection(SCHEMA, "air.book", dict(PARAMS, add_ons=["tripshield", "none"], refundable=True, passengers=["b", "a"])) == \
        {"add_ons": '["none","tripshield"]', "passengers": '["b","a"]', "refundable": "true"}
    assert canon_projection(SCHEMA, "air.nope", PARAMS) == {}


# ---- rule 13: session step order -------------------------------------------------------------------------------------

def _sess(p=P0, grant=G0, ctx="default"):
    return _check(_decide(p, grant, ctx), "intent_session")


def test_policy_closed_and_typed():
    plain = _pcactn()
    pol_err = lambda pol: "malformed v2 context: " + V2.intent_v2_context_error(_ctx(policy=pol))
    cases = (
        (None, "policy must be an object"), ([], "policy must be an object"), ("x", "policy must be an object"),
        ({"other": 1}, "policy: unknown member 'other'"),
        ({"session": None}, "policy.session must be an object"), ({"session": []}, "policy.session must be an object"),
        ({"session": {"x": 1}}, "policy.session: unknown member 'x'"),
        ({"session": {"require": None}}, "policy.session.require must be a boolean"),
        ({"session": {"require": 1}}, "policy.session.require must be a boolean"),
        ({"session": {"require": "true"}}, "policy.session.require must be a boolean"),
        ({"session": {"max_revocation_age_s": None}}, "policy.session.max_revocation_age_s must be a non-negative safe integer"),
        ({"schema": "x"}, "policy.schema must be an object"),
        ({"schema": {"closed": True}}, "policy.schema: unknown member 'closed'"),
        ({"schema": {"closed_world": None}}, "policy.schema.closed_world must be a boolean"),
        ({"schema": {"closed_world": 0}}, "policy.schema.closed_world must be a boolean"),
    )
    for bad in (-1, 1.5, "60", True, -0.0, 2 ** 53):
        cases += (({"session": {"max_revocation_age_s": bad}},
                   "policy.session.max_revocation_age_s must be a non-negative safe integer"),)
    for pol, why in cases:
        reason = "malformed v2 context: " + why
        assert pol_err(pol) == reason, repr(pol)
        # malformed whether or not the policy would activate a check: without the member schema + intent_session fail,
        # with it accumulators too
        assert _decide(plain, ctx=_ctx(policy=pol))["checks"] == [
            {"name": "schema", "ok": False, "reason": reason}, {"name": "intent_session", "ok": False, "reason": reason}], repr(pol)
        assert _decide(ctx=_ctx(policy=pol))["checks"] == [
            {"name": n, "ok": False, "reason": reason} for n in ("schema", "intent_session", "accumulators")], repr(pol)
    v = verify_pcactn_core(plain, G0, now=NOW, audience=AUD, intent_v2=_ctx(policy={"session": {"max_revocation_age_s": "60"}}))
    assert v.checks == dict(CORE_OK, intent=False, schema=False, intent_session=False)
    # the first malformed member (in key order) is the reason
    assert pol_err({"session": {"require": 1}, "schema": {"closed_world": 0}}) == \
        "malformed v2 context: policy.session.require must be a boolean"
    # explicit false flags and in-range ages are well-formed (absent = default)
    assert _decide(plain, ctx=_ctx(policy={"session": {"require": False}, "schema": {"closed_world": False}}))["checks"] == []
    assert V2.intent_v2_context_error(_ctx(policy={"session": {"max_revocation_age_s": 0}, "schema": {}})) is None
    assert V2.intent_v2_context_error(_ctx(policy={})) is None
    # the in-step guard of rule 13 step 0 (reached only through _session_step directly)
    r = V2._session_step(P0, G0, _ctx(policy={"session": {"max_revocation_age_s": -1}}), NOW)
    assert r["reason"] == "session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)"


def test_malformed_context_members():
    for k, v, why in (("params", None, "params must be an object"), ("params", [], "params must be an object"),
                      ("schema", None, "schema must be an object"), ("session", "x", "session must be an object"),
                      ("acc", None, "acc must be an object"), ("wb", None, "wb must be an object"),
                      ("wb", {"policy": None}, "wb.policy must be an object"),
                      ("wb", {"artifacts": None}, "wb.artifacts must be an object"),
                      ("wb", {"artifacts": {"facts": "x"}}, "wb.artifacts.facts must be an array"),
                      ("wb", {"policy": {"classifiers": {}}}, "wb.policy.classifiers must be an array")):
        assert _check(_decide(ctx=_ctx(**{k: v})), "intent_session")["reason"] == "malformed v2 context: " + why, (k, v)
    assert _check(_decide(ctx="x"), "schema")["reason"] == "malformed v2 context: the v2 verifier context must be an object"


def test_clock_must_be_a_safe_integer():
    for now in (NOW + 0.5, -0.0, True, "1", None, 2 ** 53):
        d = _decide(now=now)
        assert [c["name"] for c in d["checks"] if not c["ok"]][:3] == ["schema", "intent_session", "accumulators"], repr(now)
        assert _check(d, "intent_session")["reason"] == "the verifier clock is not a safe integer (fail closed)"
    assert _decide(now=float(NOW))["checks"][0] == {"name": "schema", "ok": True}


def test_session_step_reasons():
    p = _signed(dict(_unsigned(G0, intent=None), intent_session=_is()))
    assert _sess(p)["reason"] == "an intent_session needs the envelope.intent binding"
    assert _sess(ctx=_ctx(session={"root": None}))["reason"] == "session root: session root is not an object"
    forged = _root_of(signer=STRANGER)
    assert _sess(ctx=_ctx(session={"root": forged}))["reason"] == "session root: session root signature invalid"
    other = _root_of(question_uri="https://other.example/q")
    assert _sess(ctx=_ctx(session={"root": other}))["reason"] == "intent_session.root is not the digest of the session root"
    p = _pcactn(intent=_intent(ref=_d("k2/x")), intent_session=_is())
    assert _sess(p)["reason"] == "intent.ref is not the session statement"
    p = _pcactn(intent_session=_is(seq=1))
    assert _sess(p, ctx=_ctx(session={"root": S0, "grants": [G0]}))["reason"] == \
        "the admitting root is bound to another session, root or seq"
    forged_g = _grant(signer=AGENT)
    assert _sess(_pcactn(forged_g, intent_session=_is()), forged_g)["reason"] == \
        "the admitting root is not signed by a session principal"
    nocav = dict(G0, caveats=[G0["caveats"][0]])
    assert _sess(grant=nocav)["reason"] == "admitting root: not an intent_session caveat"


def test_session_root_expiry_boundary():
    def at(exp):
        S = _root_of(expires_at=exp)
        R = session_root_digest(S)
        g = _grant(root=R)
        p = _pcactn(g, intent_session=_is(root=R))
        return _sess(p, g, _ctx(session={"root": S, "grants": []}))
    assert at(NOW + 1)["ok"] is True
    assert at(NOW)["reason"] == "the session root has expired"


def test_session_seq0_must_use_task_map():
    g = _grant(map_digest=MAP1)
    p = _pcactn(g, intent=_intent(MAP1), intent_session=_is())
    assert _sess(p, g)["reason"] == "a seq-0 action must use the session task map"


def test_session_delta_chain():
    p1 = _pcactn(D1, intent=_intent(MAP1, "salt1"), intent_session=_is(seq=1, acc=[{"id": "trip_spend", "post": 77_800}]))
    c = lambda grants, grant=D1: _sess(p1, grant, _ctx(session={"root": S0, "grants": grants}))
    assert c([G0])["ok"] is True
    assert c([G0, "ignored"])["ok"] is True  # only the first `seq` held grants are read
    assert c("x")["reason"] == "the session grants must be an array"
    assert c(None)["reason"] == "the session grants must be an array"  # null is not "none held"
    assert c([])["reason"] == "the verifier does not hold the 1 earlier grants of this session"
    assert c(["G0"])["reason"] == "session grant 0 is not a capability"
    assert c([dict(G0, id=5)])["reason"] == "session grant 0 is not a capability"
    assert c([dict(G0, alg=5)])["reason"] == "session grant 0: alg must be a string"
    assert c([dict(G0, alg="nope")])["reason"] == "session grant 0: unsupported_suite: 'nope'"
    assert c([_grant(seq=1, prev=G0["id"])])["reason"] == "session grant 0 does not belong to this session at seq 0"
    assert c([_grant(signer=AGENT)])["reason"] == "session grant 0 is not signed by a session principal"
    loose = _grant(seq=1, prev=_d("k2/nope"), map_digest=MAP1, salt="salt1")
    p = _pcactn(loose, intent=_intent(MAP1, "salt1"), intent_session=_is(seq=1, acc=[{"id": "trip_spend", "post": 77_800}]))
    assert _sess(p, loose, _ctx(session={"root": S0, "grants": [G0]}))["reason"] == "the admitting root does not chain to grant 0"
    D2 = _grant(seq=2, prev=D1["id"], map_digest=MAP1, salt="salt2")
    p2 = _pcactn(D2, intent=_intent(MAP1, "salt2"), intent_session=_is(seq=2))
    assert _sess(p2, D2, _ctx(session={"root": S0, "grants": [G0, D1]}))["ok"] is True
    bad1 = _grant(seq=1, prev=_d("k2/nope"), map_digest=MAP1, salt="salt1")
    assert _sess(p2, D2, _ctx(session={"root": S0, "grants": [G0, bad1]}))["reason"] == "session grant 1 does not chain to grant 0"


# ---- rule 13 step 7: session revocation -------------------------------------------------------------------------------

def _bind(n, tree):
    return b64u(sha256(b"pca-revset/v1\x00" + canonical_bytes_strict({"size": n, "tree": tree})))


def _incl(ids, i):
    hs = [_leaf_hash(x) for x in ids]
    path = []

    def go(h, j):
        if len(h) == 1:
            return
        k = _split(len(h))
        if j < k:
            go(h[:k], j)
            path.append({"side": "R", "hash": b64u(_build(h[k:]))})
        else:
            go(h[k:], j - k)
            path.append({"side": "L", "hash": b64u(_build(h[:k]))})
    go(hs, i)
    return {"index": i, "size": len(ids), "path": path}


def _set(revoked):
    ids = sorted(set(revoked), key=lambda s: s.encode())
    root = _bind(len(ids), merkle_root(ids) if ids else b64u(sha256(b"")))
    return ids, root


def _nonmember(ids, x):
    lo = 0
    while lo < len(ids) and ids[lo].encode() < x.encode():
        lo += 1
    p = {"size": len(ids)}
    if lo > 0:
        p["lo"] = {"id": ids[lo - 1], "proof": _incl(ids, lo - 1)}
    if lo < len(ids):
        p["hi"] = {"id": ids[lo], "proof": _incl(ids, lo)}
    return p


REV_AUTH = _keys("k2-revocation-authority")  # the session's DEDICATED revocation authority (never a principal)
_U = object()


def _epoch(revoked, issued, signer=REV_AUTH, scope=None, not_after=None, epoch=None):
    ids, root = _set(revoked)
    body = {"instance_id": "ana", "grant_ref": scope or "pca-intent-session:" + SESSION,
            "epoch": len(ids) if epoch is None else epoch, "set_size": len(ids), "root": root, "issued_at": issued,
            "not_after": issued + 300_000 if not_after is None else not_after}
    return ids, dict(body, guardian=_pub(signer), sig=b64u(_sign(signer, REVEPOCH_DOMAIN.encode() + canonical_bytes_strict(body))))


def _ev(revoked, issued=NOW - 10_000, **kw):
    ids, ep = _epoch(list(revoked), issued, **kw)
    return {"epoch": ep, "revoked": ids}


DEF_REVOKED = ("pca-intent:map:a", "pca-intent:session:zzzz")
SID = "pca-intent:session:" + SESSION


def _rev(revoked=DEF_REVOKED, issued=NOW - 10_000, signer=REV_AUTH, scope=None, rids=None, max_age=60_000, now=NOW,
         not_after=None, call_scope=None, revoked_list=_U, last=_U, epoch=None, authority=_U):
    rids = [SID] if rids is None else rids
    ids, ep = _epoch(list(revoked), issued, signer, scope, not_after, epoch)
    ev = {"epoch": ep, "revoked": ids if revoked_list is _U else revoked_list}
    kw = {} if last is _U else {"last": last}
    return check_session_revocation(ev, session=SESSION, authority=_pub(REV_AUTH) if authority is _U else authority,
                                    ids=rids, now=now, max_age_ms=max_age, scope=call_scope, **kw)


def test_revocation_boundaries():
    assert _rev() == {"ok": True}
    assert _rev(revoked=()) == {"ok": True}
    assert _rev(issued=NOW - 60_000) == {"ok": True}
    assert _rev(issued=NOW - 60_001)["reason"] == "the session revocation epoch is older than 60000 ms"
    assert _rev(issued=NOW + 60_000, max_age=0) == {"ok": True}
    assert _rev(issued=NOW + 60_001)["reason"] == "revocation epoch issued in the future"
    assert _rev(not_after=NOW) == {"ok": True}
    assert _rev(not_after=NOW - 1)["reason"] == "revocation epoch expired (stale revocation root)"
    assert _rev(issued=NOW, max_age=0) == {"ok": True}
    for bad in (-1, 1.5, -0.0, True, None, "60"):
        assert _rev(max_age=bad)["reason"] == "revocation max age misconfigured (fail closed)", repr(bad)
    assert _rev(now=NOW + 0.5)["reason"] == "the verifier clock is not a safe integer (fail closed)"
    assert _rev(rids="x")["reason"] == "ids must be an array and the authority a key"
    assert _rev(authority=None)["reason"] == "ids must be an array and the authority a key"
    assert _rev(revoked=[SID])["reason"] == "'%s' is revoked" % SID
    assert _rev(rids=[SID, 5])["reason"] == "'5' is revoked"  # a non-string id never passes
    # ONLY the dedicated authority: a principal's (or any other key's) epoch is refused
    for signer in (PRINCIPAL, STRANGER):
        assert _rev(signer=signer)["reason"] == "the revocation epoch is not signed by the session revocation authority"
    assert _rev(scope="pca-intent-session:" + _d("k2/s2"))["reason"] == "revocation epoch is for a different grant"
    assert _rev(scope="custom", call_scope="custom") == {"ok": True}


def test_revocation_full_revoked_list():
    ids, _ = _set(DEF_REVOKED)
    assert _rev(revoked_list=None)["reason"] == "revoked must be an array of ids"
    assert _rev(revoked_list="x")["reason"] == "revoked must be an array of ids"
    assert _rev(revoked_list=[ids[0], 5])["reason"] == "revoked must be an array of ids"
    assert _rev(revoked_list=list(reversed(ids)))["reason"] == "revoked must be sorted by UTF-8 bytes and distinct"
    assert _rev(revoked_list=[ids[0], ids[0]])["reason"] == "revoked must be sorted by UTF-8 bytes and distinct"
    assert _rev(revoked_list=ids[:1])["reason"] == "the epoch must be numbered by its set size and list exactly set_size ids"
    assert _rev(revoked_list=ids + ["zzz"])["reason"] == "the epoch must be numbered by its set size and list exactly set_size ids"
    assert _rev(epoch=3)["reason"] == "the epoch must be numbered by its set size and list exactly set_size ids"
    assert _rev(revoked_list=[ids[0], "pca-intent:z"])["reason"] == "the revoked list is not the signed set (root mismatch)"
    _, empty_root = _set([])
    assert V2.revset_root([]) == empty_root and V2.revset_root(ids) == _set(DEF_REVOKED)[1]
    # UTF-8 byte order, not code points of a UTF-16 sort: U+FFFF sorts before U+10000 in both, U+E000 before U+10000
    assert V2.compare_utf8("", "\U00010000") < 0 and V2.compare_utf8("￿", "\U00010000") < 0


def test_revocation_append_only():
    last2 = _ev(DEF_REVOKED)  # epoch 2
    ext = list(DEF_REVOKED) + ["pca-intent:map:b"]
    assert _rev(revoked=ext, last=last2) == {"ok": True}  # extension
    assert _rev(last=last2) == {"ok": True}  # re-presentation of the same epoch
    # DROP: same size with another member, or larger without one of the tracked ids
    assert _rev(revoked=("pca-intent:map:a", "pca-intent:map:c"), last=last2)["reason"] == \
        "the epoch drops 'pca-intent:session:zzzz', revoked in the last accepted epoch (not append-only)"
    assert _rev(revoked=("pca-intent:map:a", "pca-intent:map:c", "pca-intent:map:d"), last=last2)["reason"] == \
        "the epoch drops 'pca-intent:session:zzzz', revoked in the last accepted epoch (not append-only)"
    # ROLLBACK: an older (smaller) epoch than the tracked one
    assert _rev(revoked=("pca-intent:map:a",), last=last2)["reason"] == "revocation epoch rollback (older than the last accepted)"
    # a malformed tracked epoch fails closed
    for bad in (None, [], {"epoch": last2["epoch"]}, dict(last2, revoked=["x"]), dict(last2, epoch=dict(last2["epoch"], set_size="2")),
                dict(last2, x=1), dict(last2, proofs={})):  # the tracked evidence is CLOSED too
        assert _rev(last=bad)["reason"] == "the tracked last epoch is malformed (fail closed)", repr(bad)
    # the tracked epoch need not be signed by anyone in particular: only its shape and list are checked
    assert _rev(last=_ev(["pca-intent:map:a"], signer=STRANGER)) == {"ok": True}


def test_revocation_epoch_and_evidence_shapes():
    ids, ep = _epoch([], NOW - 1000)
    call = lambda ev, **kw: check_session_revocation(ev, session=SESSION, authority=_pub(REV_AUTH), ids=kw.pop("ids", []),
                                                     now=NOW, max_age_ms=60_000, **kw)
    assert call({"epoch": ep, "revoked": []}) == {"ok": True}
    for ev in (None, [ep], "x"):
        assert call(ev)["reason"] == "no session revocation epoch supplied", repr(ev)
    for ev in ({"epoch": None, "revoked": []}, {"epoch": 0, "revoked": []}, {"epoch": [ep], "revoked": []}):
        assert call(ev)["reason"] == "the revocation epoch must be an object", repr(ev)
    # the evidence is CLOSED: an EXTRA member (the first in key order) is malformed; a MISSING one falls through to the
    # epoch shape step or (after signature, scope, freshness and age) to the revoked-list step
    unk = "the revocation evidence has the unknown member '%s' (it is exactly {epoch, revoked})"
    assert call({"epoch": ep, "revoked": [], "proofs": {}})["reason"] == unk % "proofs"
    assert call({"epoch": ep, "revoked": [], "x": None})["reason"] == unk % "x"
    assert call({"zz": 1, "7": 1, "epoch": ep, "revoked": []})["reason"] == unk % "7"  # Object.keys order
    assert call({"x": 1})["reason"] == unk % "x"  # before the epoch shape step
    for ev in ({}, {"revoked": []}):
        assert call(ev)["reason"] == "the revocation epoch must be an object", repr(ev)
    assert call({"epoch": ep})["reason"] == "revoked must be an array of ids"
    assert call({"epoch": dict(ep, root=_d("x"))})["reason"] == "revocation epoch signature invalid"  # signature first
    assert call({"epoch": ep, "revoked": None})["reason"] == "revoked must be an array of ids"
    for k in ("instance_id", "grant_ref", "root", "guardian", "sig"):
        assert call({"epoch": dict(ep, **{k: 5}), "revoked": []})["reason"] == "revocation epoch %s must be a string" % k
    for k, bad in (("issued_at", "1"), ("issued_at", None), ("not_after", 1.5), ("not_after", -0.0), ("epoch", -1),
                   ("set_size", True)):
        assert call({"epoch": dict(ep, **{k: bad}), "revoked": []})["reason"] == \
            "revocation epoch %s must be a non-negative safe integer" % k, (k, bad)
    assert call({"epoch": dict(ep, guardian_epoch=None), "revoked": []})["reason"] == \
        "revocation epoch guardian_epoch must be a non-negative safe integer"
    assert call({"epoch": dict(ep, alg="nope"), "revoked": []})["reason"] == "revocation epoch alg: unsupported_suite: 'nope'"
    assert call({"epoch": dict(ep, alg=None), "revoked": []})["reason"] == "revocation epoch alg: alg must be a string"
    assert call({"epoch": dict(ep, pq_pk=None), "revoked": []})["reason"] == "revocation epoch pq_pk must be a string"
    assert call({"epoch": dict(ep, instance_id="other"), "revoked": []})["reason"] == "revocation epoch signature invalid"
    no_inst = {k: v for k, v in ep.items() if k != "instance_id"}
    assert call({"epoch": no_inst, "revoked": []})["reason"] == "revocation epoch instance_id must be a string"
    # check_revocation_epoch on its own: the instants are safe integers too
    assert V2.check_revocation_epoch(dict(ep, not_after="9"), ep["guardian"], NOW)["reason"] == "malformed revocation epoch"


def test_non_membership_proofs():
    ids, root = _set(["b", "d", "f"])
    assert verify_non_membership(root, _nonmember(ids, "c"), "c") is True
    assert verify_non_membership(root, _nonmember(ids, "a"), "a") is True
    assert verify_non_membership(root, _nonmember(ids, "g"), "g") is True
    assert verify_non_membership(root, _nonmember(ids, "c"), "e") is False  # not bracketing e
    pr = _nonmember(ids, "c")
    assert verify_non_membership(root, {"size": 3, "lo": pr["lo"]}, "c") is False  # lo not the last leaf
    assert verify_non_membership(root, {"size": 3, "hi": pr["hi"]}, "c") is False  # hi not the first leaf
    assert verify_non_membership(root, {"size": 3, "lo": pr["lo"], "hi": _nonmember(ids, "e")["hi"]}, "c") is False
    assert verify_non_membership(root, {"size": 3}, "c") is False
    assert verify_non_membership(root, {"size": -1}, "c") is False
    assert verify_non_membership(root, {"size": 3.5}, "c") is False
    _, empty = _set([])
    assert verify_non_membership(empty, {"size": 0}, "c") is True
    assert verify_non_membership(empty, {"size": 0, "lo": pr["lo"]}, "c") is False
    assert verify_non_membership(root, None, "c") is False
    assert verify_non_membership(root, dict(pr, hi=None), "c") is False  # STRICT: a present lo / hi is an object
    assert verify_non_membership(root, dict(pr, size=3.0), "c") is True
    assert verify_non_membership(root, dict(pr, size=True), "c") is False
    assert verify_non_membership(root, _nonmember(ids, "c"), 5) is False


REV_S = {"epoch_uri": "https://atlas.example/rev", "max_age_s": 60, "key": _pub(REV_AUTH)}


def test_session_revocation_in_pipeline():
    S = _root_of(revocation=REV_S)
    R = session_root_digest(S)
    g = _grant(root=R)
    p = _pcactn(g, intent_session=_is(root=R))
    need = ["pca-intent:session:" + SESSION, "pca-intent:map:" + MAP0, "pca-intent:delta:" + g["id"]]

    def go(revoked, issued, signer=REV_AUTH, policy=None, rev="default", last=_U):
        ev = _ev(revoked, issued, signer=signer) if rev == "default" else rev
        sess = {"root": S, "grants": []}
        if ev is not None:
            sess["revocation"] = ev
        if last is not _U:
            sess["revocation_last"] = last
        c = _ctx(session=sess, **({"policy": policy} if policy else {}))
        return _sess(p, g, c)
    assert go(["pca-intent:session:zz"], NOW - 30_000)["ok"] is True
    assert go([], NOW - 60_000)["ok"] is True
    assert go([], NOW - 61_000)["reason"] == "revocation: the session revocation epoch is older than 60000 ms"
    assert go([], NOW, rev=None)["reason"] == "revocation: no session revocation epoch supplied"
    assert go([], NOW, rev=dict(_ev([]), x=1))["reason"] == \
        "revocation: the revocation evidence has the unknown member 'x' (it is exactly {epoch, revoked})"
    assert go([], NOW - 1000, last=dict(_ev([]), x=1))["reason"] == "revocation: the tracked last epoch is malformed (fail closed)"
    for x in need:
        assert go([x], NOW - 1000)["reason"] == "revocation: '%s' is revoked" % x
    assert go([], NOW - 1000, signer=PRINCIPAL)["reason"] == \
        "revocation: the revocation epoch is not signed by the session revocation authority"
    assert go([], NOW - 20_000, policy={"session": {"max_revocation_age_s": 10}})["reason"] == \
        "revocation: the session revocation epoch is older than 10000 ms"
    assert go([], NOW - 10_000, policy={"session": {"max_revocation_age_s": 10}})["ok"] is True
    # the tracked last epoch (session.revocation_last): append-only
    assert go(["pca-intent:map:x"], NOW - 1000, last=_ev(["pca-intent:map:x"]))["ok"] is True
    assert go(["pca-intent:map:y"], NOW - 1000, last=_ev(["pca-intent:map:x"]))["reason"] == \
        "revocation: the epoch drops 'pca-intent:map:x', revoked in the last accepted epoch (not append-only)"
    assert go([], NOW - 1000, last=_ev(["pca-intent:map:x"]))["reason"] == \
        "revocation: revocation epoch rollback (older than the last accepted)"
    assert _check(_decide(p, g, _ctx(session={"root": S, "grants": [], "revocation_last": None})), "intent_session")["reason"] == \
        "the tracked last revocation epoch must be an object"
    # a policy age with no authority in S fails
    assert _sess(ctx=_ctx(policy={"session": {"max_revocation_age_s": 60}}))["reason"] == \
        "revocation: the policy requires a revocation epoch but the session root names no revocation authority"


# ---- rule 15: accumulators ------------------------------------------------------------------------------------------

def _acc(p=P0, ctx="default", grant=G0):
    return _check(_decide(p, grant, ctx), "accumulators")


def _p_acc(acc):
    return _pcactn(intent_session=_is(acc=acc))


def test_acc_claims():
    assert _acc(_p_acc([{"id": "trip_spend", "post": 38_899}]))["reason"] == \
        "claimed post 38899 for 'trip_spend' differs from the verifier's 38900"
    assert _acc(_p_acc([]))["reason"] == "no claim for accumulator 'trip_spend' that this action feeds"
    assert _acc(_p_acc([{"id": "trip_spend", "post": 38_900}, {"id": "nope", "post": 0}]))["reason"] == \
        "claim 'nope' names no accumulator of the session"
    assert _acc(_p_acc([{"id": "trip_spend", "post": 38_900}, {"id": "questions", "post": 1}]))["reason"] == \
        "accumulator 'questions' is wallet-held and cannot be claimed at a site"
    assert _acc(_p_acc([{"id": "trip_spend", "post": 38_900, "receipt": SD}]))["reason"] == \
        "accumulator 'trip_spend' is site-local: a receipt is not accepted"


def test_acc_state_and_domain():
    st = lambda s: _ctx(acc={"state": s, "monitors": {}})
    assert _acc(ctx=st({}))["reason"] == "no state for site-local accumulator 'trip_spend'"
    assert _acc(ctx=st({"trip_spend": {"count": 0}}))["reason"] == "accumulator 'trip_spend': pre-state of a sum accumulator is {sum}"
    assert _acc(ctx=st({"trip_spend": {"sum": -1}}))["reason"] == "accumulator 'trip_spend': pre-state sum must be a non-negative safe integer"
    assert _acc(_p_acc([{"id": "trip_spend", "post": 500_000}]), st({"trip_spend": {"sum": 461_100}}))["ok"] is True
    assert _acc(_p_acc([{"id": "trip_spend", "post": 500_001}]), st({"trip_spend": {"sum": 461_101}}))["reason"] == \
        "accumulator 'trip_spend' post 500001 is outside its domain (max 500000)"
    assert _acc(_p_acc([{"id": "trip_spend", "post": 2 ** 53 - 1}]), st({"trip_spend": {"sum": 2 ** 53 - 38_900}}))["reason"] == \
        "accumulator 'trip_spend' overflows 2^53-1"
    noparams = _ctx()
    del noparams["params"]
    assert _acc(ctx=noparams)["reason"] == "no plaintext params to compute accumulator values"
    assert _acc(ctx=_ctx(schema={"docs": [], "keys": KEYS}))["reason"] == \
        "accumulator 'trip_spend' selects by accumulates_into but the session schema is not available"


def test_acc_monitors():
    mon = {"id": "hotel_after_flight", "kind": "requires_prior", "p": {"verb": "air.book"}, "q": {"verb": "hotel.book"},
           "status": "committed"}
    S = _root_of(monitors=[mon])
    R = session_root_digest(S)
    g = _grant(root=R)
    p = _pcactn(g, intent_session=_is(root=R))
    c = lambda m: _acc(p, _ctx(session={"root": S, "grants": []}, acc={"state": {"trip_spend": {"sum": 0}}, "monitors": m}), g)
    assert c({"hotel_after_flight": "unmet"})["ok"] is True
    assert c({"hotel_after_flight": "met"})["ok"] is True
    assert c({})["reason"] == "no valid state for monitor 'hotel_after_flight'"
    assert c({"hotel_after_flight": "maybe"})["reason"] == "no valid state for monitor 'hotel_after_flight'"
    assert monitor_states({"kind": "responds_within", "within": 2}) == ["idle", "pending:1", "pending:2", "missed"]
    assert monitor_states({"kind": "never"}) == ["clean", "seen"] and monitor_states({"kind": "always"}) == ["ok", "broken"]


def test_acc_distinct_max_keyed_count():
    DIST = {"id": "payees", "agg": "distinct", "val": "action.params.offer_id", "sel": {"verbs": ["air.book"]},
            "win": {"kind": "task"}, "key": None, "domain_max": 3, "holder": {"kind": "site_local"}}
    MAX = {"id": "largest", "agg": "max", "val": "action.params.total", "sel": {"verbs": ["air.book"]},
           "win": {"kind": "task"}, "key": None, "holder": {"kind": "site_local"}}
    CNT = {"id": "per_offer", "agg": "count", "sel": {"verbs": ["air.book"]}, "win": {"kind": "sliding", "ms": 60_000},
           "key": "action.params.offer_id", "domain_max": 1, "holder": {"kind": "site_local"}}
    S = _root_of(accumulators=[DIST, MAX, CNT])
    R = session_root_digest(S)
    g = _grant(root=R)
    good = [{"id": "payees", "post": 2}, {"id": "largest", "post": 40_000}, {"id": "per_offer", "post": 1}]
    st = {"payees": {"values": ['"OF-1"', '"OF-9"']}, "largest": {"max": 40_000}, "per_offer": {"count": 0}}
    run = lambda acc, state: _acc(_pcactn(g, intent_session=_is(root=R, acc=acc)),
                                  _ctx(session={"root": S, "grants": []}, acc={"state": state, "monitors": {}}), g)
    assert run(good, st)["ok"] is True
    assert run(good, dict(st, payees={"values": ['"OF-7"', '"OF-9"']}))["reason"] == \
        "claimed post 2 for 'payees' differs from the verifier's 3"
    assert run(good[:2] + [{"id": "per_offer", "post": 2}], dict(st, per_offer={"count": 1}))["reason"] == \
        "accumulator 'per_offer' post 2 is outside its domain (max 1)"
    assert run(good, dict(st, payees={"values": ["a", "a"]}))["reason"] == "accumulator 'payees': pre-state values must be distinct"
    # key on free text is refused
    NOTE = dict(CNT, id="per_note", key="action.params.note", domain_max=5)
    S2 = _root_of(accumulators=[NOTE])
    R2 = session_root_digest(S2)
    g2 = _grant(root=R2)
    params = dict(PARAMS, note="hi")
    p2 = _pcactn(g2, params=params, intent_session=_is(root=R2, acc=[{"id": "per_note", "post": 1}]))
    c2 = _ctx(params=params, session={"root": S2, "grants": []}, acc={"state": {"per_note": {"count": 0}}, "monitors": {}})
    assert _acc(p2, c2, g2)["reason"] == "accumulator 'per_note': the key must be a schema-declared identity (not free text)"
    p3 = _pcactn(g2, intent_session=_is(root=R2, acc=[{"id": "per_note", "post": 1}]))
    assert _acc(p3, dict(c2, params=PARAMS), g2)["reason"] == "accumulator 'per_note': the key parameter action.params.note is missing"


def test_acc_unselected_and_helpers():
    other = dict(TRIP, id="other", sel={"verbs": ["hotel.book"]}, val="action.params.total")
    S = _root_of(accumulators=[TRIP, other])
    R = session_root_digest(S)
    g = _grant(root=R)
    base = _ctx(session={"root": S, "grants": []}, acc={"state": {"trip_spend": {"sum": 0}, "other": {"sum": 7}}, "monitors": {}})
    d = _decide(_pcactn(g, intent_session=_is(root=R)), g, base)
    assert _check(d, "accumulators")["ok"] is True and d["env"]["acc"] == {"trip_spend": {"post": 38_900}, "other": {"post": 7}}
    p = _pcactn(g, intent_session=_is(root=R, acc=[{"id": "trip_spend", "post": 38_900}, {"id": "other", "post": 7}]))
    assert _acc(p, base, g)["reason"] == "claim 'other' for an accumulator this action does not feed"
    bad = dict(base, acc={"state": {"trip_spend": {"sum": 0}, "other": {"max": 7}}, "monitors": {}})
    assert _acc(_pcactn(g, intent_session=_is(root=R)), bad, g)["reason"] == "accumulator 'other': pre-state of a sum accumulator is {sum}"
    assert pre_state_error({"agg": "sum"}, {"sum": 0, "x": 1}) == "pre-state of a sum accumulator is {sum}"
    assert pre_state_error({"agg": "count"}, {"count": 1.0}) is None
    assert pre_state_error({"agg": "max"}, []) == "pre-state must be an object"
    assert combine_acc({"agg": "max"}, {"max": 5}, {"val": 9}) == 9 and combine_acc({"agg": "count"}, {"count": 2 ** 53 - 1}, {"val": 1}) is None
    assert acc_value_of({"agg": "sum", "val": "action.params.x"}, "v", {"x": -1}) == {"ok": False, "reason": "action.params.x must be a non-negative safe integer"}
    assert acc_value_of({"agg": "distinct", "val": "action.params.x"}, "v", {"x": 1.5})["ok"] is False
    assert acc_value_of({"agg": "distinct", "val": "action.params.x"}, "v", {"x": 7}) == {"ok": True, "val": 1, "key": "7"}
    for agg, r, val, ok in (("sum", (1, 2, 3), 2, True), ("sum", (1, 2, 4), 2, False), ("sum", (1, 2, 3), 3, False),
                            ("count", (1, 1, 2), 9, True), ("count", (1, 2, 3), 2, False),
                            ("max", (5, 3, 5), 3, True), ("max", (5, 3, 3), 3, False),
                            ("distinct", (4, 0, 4), 1, True), ("distinct", (4, 1, 5), 1, True), ("distinct", (4, 2, 6), 1, False)):
        assert receipt_arithmetic_ok({"agg": agg}, {"pre": r[0], "delta": r[1], "post": r[2]}, val) is ok, (agg, r, val)


# ---- rule 15: sequenced accumulators, receipts and the sequencer key set ----------------------------------------------

SEQ_ACC = dict(TRIP, holder={"kind": "sequenced", "uri": "https://atlas.example/seq", "root": _pub(SEQ_ROOT)})
S_SEQ = _root_of(accumulators=[SEQ_ACC])
R_SEQ = session_root_digest(S_SEQ)
G_SEQ = _grant(root=R_SEQ)


def _keyset(keys, signer=SEQ_ROOT, issued=NOW - 100, version=1):
    body = {"v": 1, "kind": "pca-sequencer-keys", "sequencer": _pub(signer), "version": version, "issued_at": issued,
            "keys": keys}
    return dict(body, sig=b64u(_sign(signer, SEQUENCER_KEYS_DOMAIN.encode() + canonical_bytes_strict(body))))


KS = _keyset([{"kid": "s2", "pk": _pub(SEQ), "not_before": NOW - 1000, "not_after": NOW + 1000}])
DRAFT = _unsigned(G_SEQ)
RES = pcactn_reservation_digest(DRAFT)


def _receipt(signer=SEQ, **over):
    body = {"v": 1, "kind": "pca-acc-receipt", "session": SESSION, "acc": "trip_spend", "seq": 3, "pre": 10_000,
            "delta": 38_900, "post": 48_900, "pcactn_digest": RES, "aud": AUD, "issued_at": NOW, "expires_at": NOW + 60_000,
            "kid": "s2", "ledger": {"index": 7, "head": _d("k2/head")}, "signer": _pub(SEQ)}
    body.update(over)
    return dict(body, sig=b64u(_sign(signer, ACC_RECEIPT_DOMAIN.encode() + canonical_bytes_strict(body))))


RC = _receipt()


def _p_seq(rc, post=48_900):
    return _signed(dict(DRAFT, intent_session=_is(root=R_SEQ, acc=[{"id": "trip_spend", "post": post, "receipt": acc_receipt_digest(rc)}])))


def _c_seq(receipts, last=None, keys=None):
    acc = {"receipts": receipts, "monitors": {}, "sequencer_keys": [KS] if keys is None else keys}
    if last is not None:
        acc["last_seq"] = {"trip_spend": last}
    return _ctx(session={"root": S_SEQ, "grants": []}, acc=acc)


def test_receipt_allow_and_reservation_digest():
    assert pcactn_reservation_digest(_p_seq(RC)) == RES  # sig and intent_session are excluded
    v = verify_pcactn_core(_p_seq(RC), G_SEQ, now=NOW, audience=AUD, intent_v2=_c_seq([RC]))
    assert (v.allow, v.checks) == (True, V2_OK)


def test_receipt_reasons():
    a = lambda rc, ctx, post=48_900: _acc(_p_seq(rc, post), ctx, G_SEQ)
    p_norc = _signed(dict(DRAFT, intent_session=_is(root=R_SEQ)))
    assert _acc(p_norc, _c_seq([RC]), G_SEQ)["reason"] == "accumulator 'trip_spend' is sequenced: the claim needs a reservation receipt"
    assert a(RC, _c_seq([]))["reason"] == "the reservation receipt for 'trip_spend' was not presented"
    sig_reason = ("the reservation receipt for 'trip_spend' is not signed by a key the session sequencer's root-signed key set "
                  "lists for its issue time")
    assert a(RC, _c_seq([RC], keys=[]))["reason"] == sig_reason
    assert a(RC, _c_seq([RC], keys=[_keyset(KS["keys"], signer=STRANGER)]))["reason"] == sig_reason
    forged = _receipt(signer=STRANGER)
    assert a(forged, _c_seq([forged]))["reason"] == sig_reason
    other = _receipt(aud="hotel.example")
    assert a(other, _c_seq([other]))["reason"] == "the reservation receipt for 'trip_spend' is for another session, accumulator or audience"
    elsewhere = _receipt(pcactn_digest=_d("k2/other"))
    assert a(elsewhere, _c_seq([elsewhere]))["reason"] == "the reservation receipt for 'trip_spend' is for another action"
    at = _receipt(expires_at=NOW)
    assert a(at, _c_seq([at]))["ok"] is True
    # expired = well formed (issued_at <= expires_at) and signed, but now > expires_at; the reference checks the signature
    # (incl. the shape) first, so expires_at < issued_at is refused as unsigned, never as expired
    late = _receipt(issued_at=NOW - 1000, expires_at=NOW - 1)
    assert a(late, _c_seq([late]))["reason"] == "the reservation receipt for 'trip_spend' has expired"
    inverted = _receipt(expires_at=NOW - 1)
    assert a(inverted, _c_seq([inverted]))["reason"] == sig_reason
    assert a(RC, _c_seq([RC], last=2))["ok"] is True
    assert a(RC, _c_seq([RC], last=3))["reason"] == "the reservation receipt for 'trip_spend' replays seq 3 (last accepted 3)"
    assert a(RC, _c_seq([RC], last=None))["ok"] is True
    bent = _receipt(post=48_901)
    assert a(bent, _c_seq([bent]), 48_901)["reason"] == "the reservation receipt for 'trip_spend' does not add up"


def test_receipt_last_seq_strict():
    replay = "the reservation receipt for 'trip_spend' replays seq 3 (last accepted %s)"
    not_int = "acc.last_seq values must be non-negative safe integers"
    ctx = _c_seq([RC])
    ctx["acc"]["last_seq"] = {"trip_spend": 2.0}
    assert _acc(_p_seq(RC), ctx, G_SEQ)["ok"] is True
    ctx["acc"]["last_seq"] = {"trip_spend": 3.0}
    assert _acc(_p_seq(RC), ctx, G_SEQ)["reason"] == replay % "3"
    # STRICT: every last_seq value is a non-negative safe integer (no null-as-0, no numeric strings, no -0), any id
    for bad in (None, "2", True, False, [], {}, 1.5, -0.0, -1, 2 ** 53):
        ctx["acc"]["last_seq"] = {"other": bad}
        assert _acc(_p_seq(RC), ctx, G_SEQ)["reason"] == not_int, repr(bad)
    # own members only: another id's entry (or an own "constructor") is "no last seq" for trip_spend
    for ls in ({"other": 99}, {}, {"constructor": 99}):
        ctx["acc"]["last_seq"] = ls
        assert _acc(_p_seq(RC), ctx, G_SEQ)["ok"] is True, repr(ls)
    for k, v, why in (("last_seq", [], "acc.last_seq must be an object"), ("last_seq", None, "acc.last_seq must be an object"),
                      ("last_seq", "x", "acc.last_seq must be an object"), ("state", [], "acc.state must be an object"),
                      ("state", None, "acc.state must be an object"), ("monitors", "x", "acc.monitors must be an object"),
                      ("receipts", None, "acc.receipts must be an array"), ("receipts", "r", "acc.receipts must be an array"),
                      ("sequencer_keys", {}, "acc.sequencer_keys must be an array")):
        c2 = _c_seq([RC])
        c2["acc"][k] = v
        assert _acc(_p_seq(RC), c2, G_SEQ)["reason"] == why, (k, v)
    assert _acc(ctx=_ctx(acc=None))["reason"] == "malformed v2 context: acc must be an object"
    # the schema context is checked by accumulators too
    assert _acc(ctx=_ctx(schema={"docs": None, "keys": KEYS}))["reason"] == "the schema context must be {docs: [...], keys: [...]}"
    # an own "__proto__" state key is data: no trip_spend state
    assert _acc(ctx=_ctx(acc={"state": json.loads('{"__proto__": {"sum": 0}}'), "monitors": {}}))["reason"] == \
        "no state for site-local accumulator 'trip_spend'"


def test_receipt_against_holder_boundaries():
    h = SEQ_ACC["holder"]
    assert verify_receipt_against_holder(RC, h, [KS], NOW) is True
    assert verify_receipt_against_holder(_receipt(issued_at=NOW + 60_000), h, [KS], NOW) is False  # after KS not_after
    ks = _keyset([{"kid": "s2", "pk": _pub(SEQ), "not_before": NOW - 1000}])
    assert verify_receipt_against_holder(_receipt(issued_at=NOW + 60_000), h, [ks], NOW) is True
    assert verify_receipt_against_holder(_receipt(issued_at=NOW + 60_001, expires_at=NOW + 60_001), h, [ks], NOW) is False
    assert verify_receipt_against_holder(_receipt(issued_at=NOW - 1000), h, [ks], NOW) is True
    assert verify_receipt_against_holder(_receipt(issued_at=NOW - 1001), h, [ks], NOW) is False
    assert verify_receipt_against_holder(_receipt(issued_at=NOW + 1000), h, [KS], NOW) is True
    assert verify_receipt_against_holder(_receipt(issued_at=NOW + 1001), h, [KS], NOW) is False
    assert verify_receipt_against_holder(_receipt(kid="s9"), h, [KS], NOW) is False
    assert verify_receipt_against_holder(RC, h, [ks, KS], NOW) is True  # some key set
    assert verify_receipt_against_holder(RC, h, "xy", NOW) is False
    hybrid_entry = _keyset([{"kid": "s2", "pk": _pub(SEQ), "alg": "hybrid-ed25519-ml-dsa-65", "not_before": 0}])
    assert verify_receipt_against_holder(RC, h, [hybrid_entry], NOW) is False  # entry suite != receipt suite


def test_receipt_lifetime_and_freshness():
    h = SEQ_ACC["holder"]
    rerr = V2.receipt_against_holder_error
    shape = V2.acc_receipt_shape_error
    # lifetime: issued_at <= expires_at <= issued_at + 15 min
    assert shape(_receipt(expires_at=NOW + 900_000)) is None
    assert shape(_receipt(expires_at=NOW)) is None
    for bad in (NOW + 900_001, NOW - 1):
        assert shape(_receipt(expires_at=bad)) == "receipt.expires_at must be within 900000 ms after issued_at", bad
    assert V2.MAX_RECEIPT_LIFETIME_MS == 900_000 and V2.DEFAULT_MAX_RECEIPT_AGE_MS == 900_000
    assert V2.DEFAULT_MAX_KEYSET_AGE_MS == 3_600_000 and V2.RECEIPT_SKEW_MS == 60_000
    ks0 = _keyset([{"kid": "s2", "pk": _pub(SEQ), "not_before": 0}])
    # receipt age: default 15 min, inclusive; a policy bound replaces it
    assert rerr(_receipt(issued_at=NOW - 900_000, expires_at=NOW), h, [ks0], NOW) is None
    assert rerr(_receipt(issued_at=NOW - 900_001, expires_at=NOW - 1), h, [ks0], NOW) == "invalid"
    assert rerr(_receipt(issued_at=NOW - 1000), h, [ks0], NOW, 1000) is None
    assert rerr(_receipt(issued_at=NOW - 1001), h, [ks0], NOW, 1000) == "invalid"
    # key-set age: default 1 h, inclusive; issued at most 60 s ahead
    assert rerr(RC, h, [_keyset(ks0["keys"], issued=NOW - 3_600_000)], NOW) is None
    assert rerr(RC, h, [_keyset(ks0["keys"], issued=NOW - 3_600_001)], NOW) == "invalid"
    assert rerr(RC, h, [_keyset(ks0["keys"], issued=NOW - 5_000)], NOW, None, 5_000) is None
    assert rerr(RC, h, [_keyset(ks0["keys"], issued=NOW - 5_001)], NOW, None, 5_000) == "invalid"
    assert rerr(RC, h, [_keyset(ks0["keys"], issued=NOW + 60_000)], NOW) is None
    assert rerr(RC, h, [_keyset(ks0["keys"], issued=NOW + 60_001)], NOW) == "invalid"
    # tracked key-set version: an older set than the tracked one is refused; version >= 1 by shape
    assert rerr(RC, h, [_keyset(ks0["keys"], version=2)], NOW, None, None, 2) is None
    assert rerr(RC, h, [_keyset(ks0["keys"], version=1)], NOW, None, None, 2) == "invalid"
    assert rerr(RC, h, [_keyset(ks0["keys"], version=1), _keyset(ks0["keys"], version=3)], NOW, None, None, 2) is None
    # tracked {version, digest}: same version needs the same set; a malformed tracked entry fails closed
    k2 = _keyset(ks0["keys"], version=2)
    tr = {"version": 2, "digest": V2.sequencer_key_set_digest(k2)}
    assert rerr(RC, h, [k2], NOW, None, None, None, tr) is None
    assert rerr(RC, h, [_keyset(ks0["keys"], version=2, issued=NOW - 99)], NOW, None, None, None, tr) == "invalid"
    assert rerr(RC, h, [_keyset(ks0["keys"], version=1)], NOW, None, None, None, tr) == "invalid"
    assert rerr(RC, h, [_keyset(ks0["keys"], version=3)], NOW, None, None, None, tr) is None
    assert rerr(RC, h, [k2], NOW, None, None, None, {"version": 2}) == "invalid"
    assert V2.sequencer_key_set_shape_error(_keyset(ks0["keys"], version=0)) == "version must be a safe integer >= 1"
    assert V2.sequencer_key_set_shape_error(dict(ks0, version=None)) == "version must be a safe integer >= 1"
    # a RETIRED key stops verifying once retired (not_after < now - 60 s), even for a receipt inside its window
    ret = lambda na: _keyset([{"kid": "s2", "pk": _pub(SEQ), "not_before": 0, "not_after": na}])
    assert rerr(_receipt(issued_at=NOW - 60_000, expires_at=NOW), h, [ret(NOW - 60_000)], NOW) is None
    assert rerr(_receipt(issued_at=NOW - 60_001, expires_at=NOW), h, [ret(NOW - 60_001)], NOW) == "invalid"
    # misconfigured bounds or a non-integer clock fail closed
    for args in ((NOW + 0.5,), (NOW, -1), (NOW, None, 1.5), (NOW, None, None, -1), (NOW, None, None, True)):
        assert rerr(RC, h, [ks0], *args) == "invalid", args


def test_receipt_policy_acc_in_pipeline():
    def run(policy=None, versions=_U, ks=None):
        c = _c_seq([RC], keys=[KS] if ks is None else ks)
        if versions is not _U:
            c["acc"]["keyset_versions"] = versions
        if policy is not None:
            c["policy"] = {"acc": policy}
        return _acc(_p_seq(RC), c, G_SEQ)
    sig_reason = ("the reservation receipt for 'trip_spend' is not signed by a key the session sequencer's root-signed key set "
                  "lists for its issue time")
    assert run()["ok"] is True
    assert run({"max_receipt_age_s": 0})["ok"] is True  # RC is issued at now
    late = _receipt(issued_at=NOW - 2000, expires_at=NOW + 1000)
    ks0 = _keyset([{"kid": "s2", "pk": _pub(SEQ), "not_before": 0}])
    c = _c_seq([late], keys=[ks0])
    c["policy"] = {"acc": {"max_receipt_age_s": 1}}
    assert _acc(_p_seq(late), c, G_SEQ)["reason"] == sig_reason
    c["policy"] = {"acc": {"max_receipt_age_s": 2}}
    assert _acc(_p_seq(late), c, G_SEQ)["ok"] is True
    assert run({"max_keyset_age_s": 0})["reason"] == sig_reason  # KS was issued 100 ms ago
    # the tracked key set of a root is exactly {version, digest}: rollback and same-version EQUIVOCATION are skipped
    root = _pub(SEQ_ROOT)
    dks = V2.sequencer_key_set_digest(KS)
    assert dks == b64u(hashlib.sha256(canonical_bytes_strict({"d": "atlas-pca/sequencer-keys-ref/v1", "k": KS})).digest())
    assert run(versions={root: {"version": 1, "digest": dks}})["ok"] is True
    assert run(versions={root: {"version": 1, "digest": _d("k2/other-set")}})["reason"] == sig_reason  # equivocation
    assert run(versions={root: {"version": 2, "digest": dks}})["reason"] == sig_reason  # rollback
    newer = _keyset(KS["keys"], version=2)
    assert run(versions={root: {"version": 1, "digest": dks}}, ks=[newer])["ok"] is True  # a newer version passes
    assert run(versions={root: {"version": 1, "digest": dks}}, ks=[_keyset(KS["keys"], issued=NOW - 50), KS])["ok"] is True
    assert run(versions={"other-root": {"version": 9, "digest": dks}})["ok"] is True  # own member of this holder's root only
    tk = "acc.keyset_versions: "
    for bad, why in ((1, "a tracked key set must be an object {version, digest}"),
                     (None, "a tracked key set must be an object {version, digest}"),
                     ([], "a tracked key set must be an object {version, digest}"),
                     ({"version": 1, "digest": dks, "x": 1}, "a tracked key set has the unknown member 'x'"),
                     ({"version": 0, "digest": dks}, "a tracked key set version must be a safe integer >= 1"),
                     ({"version": "1", "digest": dks}, "a tracked key set version must be a safe integer >= 1"),
                     ({"digest": dks}, "a tracked key set version must be a safe integer >= 1"),
                     ({"version": 1}, "a tracked key set digest must be canonical base64url (32 bytes)"),
                     ({"version": 1, "digest": "AA"}, "a tracked key set digest must be canonical base64url (32 bytes)")):
        assert run(versions={root: bad})["reason"] == tk + why, repr(bad)
    for v in (None, [], "x"):
        assert run(versions=v)["reason"] == "acc.keyset_versions must be an object"
    # policy.acc is closed and typed
    for pol, why in (({"x": 1}, "policy.acc: unknown member 'x'"), ({"max_receipt_age_s": -1}, "policy.acc.max_receipt_age_s must be a non-negative safe integer"),
                     ({"max_keyset_age_s": "60"}, "policy.acc.max_keyset_age_s must be a non-negative safe integer"),
                     ({"max_receipt_age_s": None}, "policy.acc.max_receipt_age_s must be a non-negative safe integer")):
        assert V2.intent_v2_context_error({"policy": {"acc": pol}}) == why, pol
    assert V2.intent_v2_context_error({"policy": {"acc": None}}) == "policy.acc must be an object"
    assert V2.intent_v2_context_error({"policy": {"acc": {}}}) is None


# ---- the W-B unit: reporting and env -----------------------------------------------------------------------------------

def test_wb_reporting(monkeypatch):
    seen = {}

    def fake(out):
        def f(inp):
            seen["inp"] = inp
            return out
        return f
    monkeypatch.setattr(V2, "decide_intent_wb", fake({"outcome": "admit", "checks": {"facts": "pass", "provenance": "pass"},
                                                      "env": {"world": {"w": 1}, "prov": {}, "class": None}}))
    d = _decide(ctx=_ctx(wb={"artifacts": {}}))
    assert _names(d) == ["schema", "intent_session", "accumulators", "facts", "provenance"]
    assert d["env"]["world"] == {"w": 1} and d["env"]["prov"] == {} and "class" not in d["env"]
    assert seen["inp"]["artifacts"] == {} and seen["inp"]["policy"] == {}  # present artifacts pass; absent policy -> {}
    assert seen["inp"]["session"] == SESSION and seen["inp"]["aud"] == AUD and seen["inp"]["now"] == NOW
    assert seen["inp"]["action"] == {"verb": "air.book", "resource": "skyair.example/bookings", "params": PARAMS}
    _decide(ctx=_ctx(wb={}))
    assert "artifacts" not in seen["inp"]
    # NULL RULING: a present null is malformed and fails the W-B unit closed (decide_intent_wb is not called)
    for wb, why in (({"policy": None}, "wb.policy must be an object"), ({"artifacts": None}, "wb.artifacts must be an object"),
                    (None, "wb must be an object")):
        seen.clear()
        assert _decide(ctx=_ctx(wb=wb))["checks"] == [{"name": n, "ok": False, "reason": "malformed v2 context: " + why}
                                                     for n in ("schema", "intent_session", "accumulators")]
        assert seen == {}
    monkeypatch.setattr(V2, "decide_intent_wb", fake({"outcome": "question", "checks": {"provenance": "question"},
                                                      "env": {"prov": {"x": 1}}, "reason": "tainted"}))
    d = _decide()
    assert _check(d, "provenance") == {"name": "provenance", "ok": False, "reason": "intent_required: tainted"}
    assert d["env"]["prov"] == {"x": 1}
    monkeypatch.setattr(V2, "decide_intent_wb", fake({"outcome": "question", "checks": {"provenance": "question"}, "env": {}}))
    assert _check(_decide(), "provenance")["reason"] == "intent_required: a question is required"
    monkeypatch.setattr(V2, "decide_intent_wb", fake({"outcome": "deny", "checks": {"facts": "fail"}, "env": {"world": {"w": 1}}}))
    d = _decide()
    assert _check(d, "facts") == {"name": "facts", "ok": False, "reason": "rejected"} and "world" not in d["env"]
    v = _verify()
    assert v.allow is False and v.checks == dict(V2_OK, facts=False) and v.reason == "facts: rejected"

    def boom(inp):
        raise ValueError("x")
    monkeypatch.setattr(V2, "decide_intent_wb", boom)
    assert _check(_decide(), "facts") == {"name": "facts", "ok": False, "reason": "W-B error (fail closed): x"}
    # without intent_session the W-B unit is never called
    monkeypatch.setattr(V2, "decide_intent_wb", boom)
    assert _decide(_pcactn(), ctx=_ctx(policy={"schema": {"closed_world": True}}))["checks"] == [{"name": "schema", "ok": True}]


def test_run_guard_fails_only_the_running_check(monkeypatch):
    def boom(*a):
        raise RuntimeError("bad")
    monkeypatch.setattr(V2, "_acc_step", boom)
    d = _decide()
    assert [(c["name"], c["ok"]) for c in d["checks"]] == [("schema", True), ("intent_session", True), ("accumulators", False)]
    assert _check(d, "accumulators")["reason"] == "accumulators error (fail closed): bad"


# ---- session root verification ---------------------------------------------------------------------------------------

def test_session_root_verification():
    assert verify_session_root(S0) == {"ok": True}
    assert verify_session_root(dict(S0, expires_at=NOW))["reason"] == "session root signature invalid"
    assert verify_session_root(dict(S0, signer=_pub(AGENT)))["reason"] == "signer is not one of the session principals"
    assert verify_session_root(dict(S0, x=1))["reason"] == "session root: unknown member 'x'"
    assert verify_session_root(dict(S0, pq_pk="AA"))["reason"] == "an ed25519 session root must not carry pq_pk / pq_sig"
    sh = V2.session_root_shape_error
    many = [{"key": _d("p%d" % i)} for i in range(17)]
    assert sh(dict(S0, principals=many[:16], signer=many[0]["key"])) is None
    assert sh(dict(S0, principals=many)) == "principals must be 1..16 keys"
    assert sh(dict(S0, principals=[])) == "principals must be 1..16 keys"
    assert sh(dict(S0, principals=[{"key": _pub(PRINCIPAL)}] * 2)) == "principal keys must be distinct"
    assert sh(dict(S0, schema={"aud": AUD, "digest": SD, "x": 1})) == "schema must be {aud, digest}"
    assert sh(dict(S0, layers={"task": {"map_digest": MAP0}, "std": {"profile": "p", "version": 1, "digest": SD}})) is None
    assert sh(dict(S0, layers={"task": {"map_digest": MAP0}, "std": {"profile": "p", "version": 0, "digest": SD}})) == \
        "layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)"
    assert sh(dict(S0, layers={"task": {"map_digest": MAP0}, "std": None})) == \
        "layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)"
    assert sh(dict(S0, layers={"task": {"map_digest": MAP0}, "org": None})) == \
        "layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)"
    assert sh(dict(S0, layers={"task": {"map_digest": MAP0}, "org": {"digest": SD}})) is None
    assert sh(dict(S0, revocation=dict(REV_S, pq_pk="AA"))) is None
    assert sh(dict(S0, revocation={"epoch_uri": "u", "max_age_s": 60, "pq_pk": "AA"})) == \
        "revocation.key (the dedicated revocation authority) is required: canonical base64url (32 bytes)"
    assert sh(dict(S0, revocation=dict(REV_S, key=_pub(PRINCIPAL)))) == \
        "revocation.key must not be a session principal (a dedicated revocation authority)"
    assert sh(dict(S0, revocation=dict(REV_S, pq_pk="A"))) == "revocation.pq_pk must be canonical base64url"
    assert sh(dict(S0, revocation=dict(REV_S, x=1))) == "revocation must be {epoch_uri, max_age_s, key, pq_pk?}"
    assert sh(dict(S0, principals=[{"key": _pub(PRINCIPAL), "alg": "nope"}])) == "principal alg: unsupported_suite: 'nope'"
    assert sh(dict(S0, alg="nope")) == "alg: unsupported_suite: 'nope'"
    accs = [dict(TRIP, id="a%d" % i) for i in range(17)]
    assert sh(dict(S0, accumulators=accs[:16])) is None
    assert sh(dict(S0, accumulators=accs)) == "accumulators must be an array of at most 16"
    assert sh(dict(S0, accumulators=[TRIP, TRIP])) == "accumulator and monitor ids must be distinct"
    assert sh(dict(S0, question_uri="")) == "question_uri must be a non-empty string"
    assert sh(dict(S0, expires_at=-1)) == "expires_at must be a non-negative safe integer (epoch ms)"
    assert sh(dict(S0, revocation=dict(REV_S, max_age_s=-1))) == "revocation.max_age_s must be a non-negative safe integer"


def test_accumulator_and_monitor_decl_errors():
    ae = V2.accumulator_decl_error
    assert ae(TRIP) is None and ae(QUESTIONS) is None
    for name in ("__proto__", "constructor", "prototype"):
        assert ae(dict(TRIP, id=name)) == "accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"
        assert V2.monitor_decl_error({"id": name, "kind": "never", "p": {"verb": "a"}}) == \
            "monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype"
    assert ae(dict(TRIP, holder=dict(SEQ_ACC["holder"], root_alg="nope"))) == \
        "accumulator 'trip_spend': holder.root_alg: unsupported_suite: 'nope'"
    assert ae(dict(TRIP, holder=dict(SEQ_ACC["holder"], root_alg=None))) == "accumulator 'trip_spend': holder.root_alg: alg must be a string"
    assert ae(dict(TRIP, key="action.params.x")) is None
    assert ae({k: v for k, v in TRIP.items() if k != "key"}) == "accumulator 'trip_spend': key must be null or action.params.<name>"
    assert ae(dict(TRIP, win={"kind": "sliding", "ms": 1})) is None
    assert ae(dict(TRIP, win={"kind": "sliding", "ms": 0})) == "accumulator 'trip_spend': win sliding needs a positive ms"
    assert ae(dict(TRIP, win={"kind": "period", "ms": 1, "t0": 0})) is None
    assert ae(dict(TRIP, win={"kind": "period", "ms": 1, "t0": -1})) == "accumulator 'trip_spend': win period needs a positive ms and t0 >= 0"
    assert ae(dict(TRIP, win={"kind": "task", "x": 1})) == "accumulator 'trip_spend': win {kind: task} has no other member"
    assert ae(dict(TRIP, val="action.params.total", sel={"verbs": ["v"] * 64})) is None
    assert ae(dict(TRIP, sel={"verbs": ["v"] * 65})) == "accumulator 'trip_spend': sel.verbs must be 1..64 verb names"
    assert ae(dict(TRIP, sel={"verbs": ["v"], "event": "question"})) == \
        "accumulator 'trip_spend': sel names actions (verbs / accumulates_into) or a wallet event, exactly one kind"
    assert ae(dict(QUESTIONS, holder={"kind": "site_local"})) == "accumulator 'questions': wallet events are wallet-held and only wallet events are"
    assert ae(dict(TRIP, agg="max")) == "accumulator 'trip_spend': max needs val"
    assert ae(dict(TRIP, agg="count", val="action.params.total")) == "accumulator 'trip_spend': count takes no val"
    assert ae(dict(TRIP, holder=SEQ_ACC["holder"])) is None
    assert ae(dict(TRIP, holder=dict(SEQ_ACC["holder"], key="x"))) == "accumulator 'trip_spend': holder sequenced has unknown member 'key'"
    me = V2.monitor_decl_error
    m = {"id": "m", "kind": "responds_within", "p": {"verb": "a"}, "q": {"verb": ["b"]}, "within": 64}
    assert me(m) is None
    assert me(dict(m, within=65)) == "monitor 'm': within must be an integer in 1..64"
    assert me(dict(m, within=0)) == "monitor 'm': within must be an integer in 1..64"
    assert me({k: v for k, v in m.items() if k != "q"}) == "monitor 'm': q is required exactly for requires_prior / precedes / responds_within"
    assert me(dict(m, kind="never")) == "monitor 'm': q is required exactly for requires_prior / precedes / responds_within"
    assert me(dict(m, p={"verb": []})) == "monitor 'm': p must be a predicate"


# ---- middleware: intent_v2 as a dict or a per-request callable ---------------------------------------------------------

def _header(p):
    return base64.urlsafe_b64encode(json.dumps(p).encode()).rstrip(b"=").decode()


def test_require_pca_intent_v2_dict_and_callable():
    hdr = {"PCA-Action": _header(P0)}
    g = require_pca(audience=AUD, resolve_grant=lambda ref: G0, now=NOW, intent_v2=_ctx())
    r = g(hdr)
    assert (r.ok, r.status, r.verdict.checks) == (True, 200, V2_OK)
    calls = []
    g = require_pca(audience=AUD, resolve_grant=lambda ref: G0, now=NOW, intent_v2=lambda p: calls.append(p) or _ctx())
    assert g(hdr).ok is True and calls == [P0]
    g = require_pca(audience=AUD, resolve_grant=lambda ref: G0, now=NOW, intent_v2=lambda p: None)
    r = g(hdr)
    assert (r.ok, r.status) == (False, 403) and r.verdict.checks["schema"] is False

    def boom(p):
        raise KeyError("store down")
    r = require_pca(audience=AUD, resolve_grant=lambda ref: G0, now=NOW, intent_v2=boom)(hdr)
    assert (r.ok, r.status, r.error, r.verdict) == (False, 403, "intent_v2_context_error", None)
    # without intent_v2 the member is still verified (and the v2 checks fail closed for want of state)
    r = require_pca(audience=AUD, resolve_grant=lambda ref: G0, now=NOW)(hdr)
    assert r.status == 403 and r.verdict.checks["intent_session"] is False


# ---- suites: one dispatch, unimplemented registered suites are `unsupported_suite` ------------------------------------

from atlas_pca.pca import supported_suites  # noqa: E402

# A registered suite atlas_pca.pca's dispatch does not implement (none left once every suite is wired: then these
# assertions have nothing to pin and the test returns).
_REGISTRY = ("ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65", "slh-dsa-sha2-128f",
             "hybrid-ed25519-slh-dsa-sha2-128f", "ml-dsa-87", "hybrid-ed25519-ml-dsa-87", "slh-dsa-sha2-256s",
             "hybrid-ed25519-slh-dsa-sha2-256s", "fn-dsa-512", "less-cat1", "hybrid-ed25519-less-cat1", "fn-dsa-1024")
UNIMPL = sorted(set(_REGISTRY) - set(supported_suites())) or ["no-such-suite-v9"]  # an unknown name is unsupported too
FAKE_PQ = b64u(b"\x01" * 32)


def test_unsupported_suite_through_the_dispatch():
    x = UNIMPL[0]
    err = V2._pinned_suite_error(x, _pub(SITE), FAKE_PQ, b"m", "AA", V2._UNDEF, {_pub(SITE): FAKE_PQ})
    assert err.startswith("unsupported_suite") and x in err
    assert V2._pinned_suite_error("nope", _pub(SITE), FAKE_PQ, b"m", "AA", V2._UNDEF, None) == "unsupported_suite: 'nope'"
    assert V2._pinned_suite_error(5, _pub(SITE), FAKE_PQ, b"m", "AA", V2._UNDEF, None) == "invalid"
    assert V2._pinned_suite_error("ed25519", _pub(SITE), V2._UNDEF, b"m", "AA", V2._UNDEF, None) == "invalid"
    assert V2._pinned_suite_error("ed25519", _pub(SITE), V2._UNDEF, b"m", b64u(_sign(SITE, b"m")), V2._UNDEF, None) is None
    # schema (rule 14)
    doc = dict(SCHEMA, sig=dict(SCHEMA["sig"], alg=x))
    key = dict(KEYS[0], alg=x, pq_pk=FAKE_PQ)
    r = verify_action_schema(doc, [key])
    assert r == {"ok": False, "reason": "sig.alg: unsupported_suite: '%s'" % x}, r
    p = _pcactn(intent_session=_is(schema=action_schema_digest(doc)))
    rs = _check(_decide(p, ctx=_ctx(schema={"docs": [doc], "keys": [key]})), "schema")["reason"]
    assert rs == "schema does not verify: sig.alg: unsupported_suite: '%s'" % x, rs
    assert verify_action_schema(SCHEMA, [key])["reason"] == "schema key: unsupported_suite: '%s'" % x
    # session root (rule 13): R3-01 runs the verifier-pin checks BEFORE suite availability, so the root reaches the
    # suite dispatch only under the verifier's pin for its signer; unpinned, it is refused for the missing pin.
    sx = dict(S0, alg=x, pq_pk=FAKE_PQ)
    pins = {sx["signer"]: FAKE_PQ}
    unpinned = ("session root suite '%s' needs the signer's PQ key pinned by the verifier (pq_pins); "
                "the root's own principals entry proves nothing about who signed it" % x)
    assert verify_session_root(sx, pins)["reason"] == "alg: unsupported_suite: '%s'" % x
    assert verify_session_root(sx)["reason"] == unpinned
    rx = session_root_digest(sx)
    gx = _grant(root=rx)
    px = _pcactn(gx, intent_session=_is(root=rx))
    d = _decide(px, gx, _ctx(session={"root": sx, "grants": [], "pq_pins": pins}))
    assert _check(d, "intent_session")["reason"] == "session root: alg: unsupported_suite: '%s'" % x
    assert _check(d, "accumulators")["reason"] == "session root: alg: unsupported_suite: '%s'" % x
    d = _decide(px, gx, _ctx(session={"root": sx, "grants": []}))
    assert _check(d, "intent_session")["reason"] == "session root: " + unpinned
    assert _check(d, "accumulators")["reason"] == "session root: " + unpinned
    # a held grant whose suite the dispatch does not implement
    p1 = _pcactn(D1, intent=_intent(MAP1, "salt1"), intent_session=_is(seq=1, acc=[{"id": "trip_spend", "post": 77_800}]))
    assert _sess(p1, D1, _ctx(session={"root": S0, "grants": [dict(G0, alg=x)]}))["reason"] == \
        "session grant 0: unsupported_suite: '%s'" % x
    # revocation epoch (rule 13 step 7)
    ids, ep = _epoch([], NOW - 1000)
    ep = dict(ep, alg=x, pq_pk=FAKE_PQ)
    r = check_session_revocation({"epoch": ep, "revoked": []}, session=SESSION, authority=_pub(REV_AUTH), ids=[], now=NOW,
                                 max_age_ms=60_000)
    assert r["reason"] == "revocation epoch alg: unsupported_suite: '%s'" % x, r
    # accumulator receipt and sequencer key set (rule 15)
    rcx = _receipt(alg=x, pq_pk=FAKE_PQ)
    ksx = _keyset([{"kid": "s2", "pk": _pub(SEQ), "alg": x, "not_before": 0}])
    assert V2.receipt_against_holder_error(rcx, SEQ_ACC["holder"], [ksx], NOW) == "receipt.alg: unsupported_suite: '%s'" % x
    ra = _acc(_p_seq(rcx), _c_seq([rcx], keys=[ksx]), G_SEQ)["reason"]
    assert ra == "the reservation receipt for 'trip_spend': receipt.alg: unsupported_suite: '%s'" % x, ra
    assert V2.receipt_against_holder_error(RC, SEQ_ACC["holder"], [ksx], NOW) == "key alg: unsupported_suite: '%s'" % x
    ks_alg = dict(_keyset([{"kid": "s2", "pk": _pub(SEQ), "not_before": 0}]), alg=x, pq_pk=FAKE_PQ)
    assert V2.sequencer_key_set_error(ks_alg, _pub(SEQ_ROOT)) == "alg: unsupported_suite: '%s'" % x
    assert V2.receipt_against_holder_error(RC, SEQ_ACC["holder"], [ks_alg], NOW) == "alg: unsupported_suite: '%s'" % x
    # a verifying key set wins over an unsupported one
    assert V2.receipt_against_holder_error(RC, SEQ_ACC["holder"], [ks_alg, KS], NOW) is None


# ---- rule 19: the committed map, the v2c goal and the Z0 `map` check ---------------------------------------------------

from atlas_pca import intent_map as IM  # noqa: E402

BOOK_DIMS = [
    {"kind": "num", "path": "action.params.total", "lo": 0, "hi": 5_000_000, "cuts": [40_000]},
    {"kind": "cat", "path": "action.resource", "values": [
        {"kind": "exact", "value": "skyair.example/bookings"}, {"kind": "prefix", "value": "skyair."},
        {"kind": "prefix", "value": "sky"}, {"kind": "other", "value": IM.MAP_OTHER}]},
]
METRICS = {"residual_risk_ppm": 1000, "burden_ppm": 0, "uncertainty_ppm": 0, "disagreement_ppm": 0, "mean_harm_ppm": 0,
           "fidelity_est_ppm": 990_000, "entropy_mbits": 0, "questions": 0, "conflicts": 0}
CM = IM.commit_map(
    [{"verb": "air.search", "dims": []}, {"verb": "air.book", "dims": BOOK_DIMS}],
    {"air.book": [{"cell": [i, j], "p_ppm": 900_000, "in_grant": i == 0} for i in range(3) for j in range(4)],
     "air.search": [{"cell": [], "p_ppm": 1_000_000, "in_grant": True}]},
    METRICS, _d("k2/learner"), sha256(b"k2/secret"))
MC = CM["map_commit"]
DISC = CM["disclose"]("air.book", "skyair.example/bookings", PARAMS)
SM = _root_of(layers={"task": {"map_digest": MC}})
RM = session_root_digest(SM)


def _commit_v2c(map_digest, salt, session=SESSION):
    body = {"d": "atlas-pca/goal/v1\u0000", "goal": "pca-intent:v2c:" + session + ":" + map_digest, "salt": salt}
    return b64u(hashlib.sha256(canonical_bytes_strict(body)).digest())


def _grant_c(map_digest=MC, salt="salt0", root=RM):
    sc = {"type": "intent_session", "session": SESSION, "seq": 0, "root": root}
    caveats = [{"type": "envelope", "goal_commit": _commit_v2c(map_digest, salt)}, sc]
    body = {"issuer": _pub(PRINCIPAL), "holder": _pub(AGENT), "caveats": caveats, "parent": None}
    d = hash_canonical(body)
    return {"id": d, "issuer": body["issuer"], "holder": body["holder"], "caveats": caveats, "body_digest": d,
            "sig": b64u(_sign(PRINCIPAL, CAP_DOMAIN + unb64u(d)))}


GM = _grant_c()
PM = _pcactn(GM, intent=_intent(MC), intent_session=_is(root=RM, map_form="commit"))


def _cm(**over):
    c = _ctx(session={"root": SM, "grants": []}, map={"disclosure": DISC})
    c.update(over)
    return c


def test_map_constants_and_tree():
    assert IM.MAP_TAG_HEADER == "atlas-pca/intent-map/header/v1\x00" and IM.MAP_TAG_CELL == "atlas-pca/intent-map/cell/v1\x00"
    assert IM.MAP_TAG_METRICS == "atlas-pca/intent-map/metrics/v1\x00" and IM.MAP_TAG_LEARNER == "atlas-pca/intent-map/learner/v1\x00"
    assert IM.MAP_TAG_NODE == "atlas-pca/intent-map/node/v1\x00" and IM.MAP_TAG_COMMIT == "atlas-pca/intent-map/commit/v1\x00"
    assert IM.MAP_OTHER == "⊥" and IM.MAX_MAP_LEAVES == 1 << 24 and IM.MAX_VERB_CELLS == 1 << 20
    assert CM["size"] == 17  # 2 headers + 12 + 1 cells + metrics + learner
    # the builder's commitment is the primitive's: leaves in order, each with its own salt and tag
    assert IM.commit_leaves(CM["leaves"]) == MC
    # map_commit binds the size: SHA-256(TAG_COMMIT || u64be(n) || root)
    hs = [IM.map_leaf_hash(e["kind"], unb64u(e["salt"]), e["leaf"]) for e in CM["leaves"]]
    root = IM.map_tree_root(hs)
    assert MC == b64u(hashlib.sha256(IM.MAP_TAG_COMMIT.encode() + (17).to_bytes(8, "big") + root).digest())
    assert IM.map_commit_of(18, root) != MC
    # a kind tag is part of the leaf hash: the same leaf under another kind hashes differently
    e = CM["leaves"][2]
    assert IM.map_leaf_hash("cell", unb64u(e["salt"]), e["leaf"]) != IM.map_leaf_hash("metrics", unb64u(e["salt"]), e["leaf"])
    # RFC 9162 openings for every index; a wrong-length path or index outside the tree is refused
    for i in range(17):
        path = [unb64u(x) for x in IM.map_audit_path(hs, i)]
        assert IM.map_root_from_path(i, 17, hs[i], path) == root
        assert IM.map_root_from_path(i, 17, hs[i], path + [hs[0]]) is None
        assert IM.map_root_from_path(i, 17, hs[i], path[:-1]) != root
    assert IM.map_root_from_path(17, 17, hs[0], []) is None and IM.map_root_from_path(-1, 17, hs[0], []) is None
    assert IM.map_root_from_path(0, 1, hs[0], []) == hs[0]
    try:
        IM.commit_leaves([])
        raise AssertionError("an empty leaf list has no commitment")
    except ValueError:
        pass


def test_cell_of_omega():
    h = DISC["header"]["leaf"]
    c = lambda res, **p: IM.map_cell_of(h, res, dict(PARAMS, **p))
    ex = "skyair.example/bookings"
    assert c(ex) == {"cell": [0, 0], "flat": 0}
    assert c(ex, total=39_999)["cell"] == [0, 0] and c(ex, total=40_000)["cell"] == [1, 0] and c(ex, total=40_001)["cell"] == [2, 0]
    assert c(ex, total=0)["cell"] == [0, 0] and c(ex, total=5_000_000)["cell"] == [2, 0] and c(ex, total=5_000_000.0)["cell"] == [2, 0]
    assert c("skyair.example/other")["cell"] == [0, 1]  # the longest prefix (skyair.) beats the shorter one (sky)
    assert c("skyline")["cell"] == [0, 2]
    assert c("airfare")["cell"] == [0, 3] and c("")["cell"] == [0, 3]  # neither exact nor prefix: other
    assert c(ex, total=45_000) == {"cell": [2, 0], "flat": 8}
    for bad in (-1, 5_000_001, "38900", 1.5, True, None, -0.0):
        assert "error" in c(ex, total=bad), repr(bad)
    assert "error" in IM.map_cell_of(h, ex, {k: v for k, v in PARAMS.items() if k != "total"})
    for res in (None, 5, IM._ABSENT, "\ud800"):
        assert "error" in IM.map_cell_of(h, res, PARAMS), repr(res)
    # an own "__proto__" parameter is ordinary data, never a fallback for `total`
    assert "error" in IM.map_cell_of(h, ex, {"__proto__": {"total": 1}})
    # exact beats every prefix, even a longer one
    hx = dict(h, dims=[{"kind": "cat", "path": "action.resource", "values": [
        {"kind": "exact", "value": "ab"}, {"kind": "prefix", "value": "abc"}, {"kind": "other", "value": IM.MAP_OTHER}]}], cells=3)
    assert IM.map_cell_of(hx, "ab", {})["cell"] == [0] and IM.map_cell_of(hx, "abcd", {})["cell"] == [1]
    assert IM.map_num_cells({"lo": 0, "hi": 10, "cuts": [0, 10]}) == [(0, 0), (1, 9), (10, 10)]
    assert IM.map_num_cells({"lo": 5, "hi": 5, "cuts": []}) == [(5, 5)]


def _dm(disc=None, action=None, params=IM._ABSENT, eps=IM._ABSENT, commit=MC):
    a = action or {"verb": "air.book", "resource": "skyair.example/bookings", "params_digest": params_digest(PARAMS)}
    kw = {}
    if params is not IM._ABSENT:
        kw["params"] = params
    if eps is not IM._ABSENT:
        kw["max_residual_risk_ppm"] = eps
    return IM.decide_map_disclosure(commit, a, DISC if disc is None else disc, **kw)


def _with(entry, **over):
    d = json.loads(json.dumps(DISC))
    d[entry].update(over)
    return d


def test_map_disclosure_decision():
    assert _dm(params=PARAMS) == {"ok": True, "cell": [0, 0], "p_ppm": 900_000, "residual_risk_ppm": 1000}
    assert _dm(params=PARAMS, eps=1000)["ok"] is True
    assert _dm(params=PARAMS, eps=999)["reason"] == "the committed residual risk 1000 ppm exceeds ε = 999"
    r = lambda *a, **k: _dm(*a, **k)["reason"]
    assert r(params=PARAMS, commit="x") == "the PCActn carries no map commitment"
    assert r(params=None) == "params must be an object"
    assert r(params=[]) == "params must be an object"
    assert r() == "the params do not hash to action.params_digest"  # params absent = {}
    assert r(params=dict(PARAMS, total=1)) == "the params do not hash to action.params_digest"
    other = {"verb": "air.search", "resource": "skyair.example/bookings", "params_digest": params_digest(PARAMS)}
    assert r(params=PARAMS, action=other) == "the disclosed header is not the action's verb"
    assert r(_with("header", index=2), params=PARAMS) == "the disclosed header does not fit the committed layout"
    assert r(_with("header", index=1), params=PARAMS) == "the header leaf does not open the map commitment"
    assert r(_with("header", salt=_d("x")), params=PARAMS) == "the header leaf does not open the map commitment"
    assert r(_with("cell", salt=_d("x")), params=PARAMS) == "the cell leaf does not open the map commitment"
    assert r(_with("cell", leaf=dict(DISC["cell"]["leaf"], p_ppm=1)), params=PARAMS) == "the cell leaf does not open the map commitment"
    assert r(_with("metrics", path=list(reversed(DISC["metrics"]["path"]))), params=PARAMS) == \
        "the metrics leaf does not open the map commitment"
    big = json.loads(json.dumps(DISC))
    big["size"] = 18
    assert r(big, params=PARAMS) == "the header leaf does not open the map commitment"
    assert r(commit=IM.commit_leaves(CM["leaves"][:-1]), params=PARAMS) == "the header leaf does not open the map commitment"
    # another cell of the same map opens but is not the action's cell
    swapped = CM["disclose"]("air.book", "skyair.example/other", PARAMS)
    assert r(_with("cell", **swapped["cell"]), params=PARAMS) == "the disclosed cell is not the action's cell"
    # the action's cell outside the committed grant
    p2 = dict(PARAMS, total=45_000)
    d2 = CM["disclose"]("air.book", "skyair.example/bookings", p2)
    a2 = {"verb": "air.book", "resource": "skyair.example/bookings", "params_digest": params_digest(p2)}
    assert r(d2, action=a2, params=p2) == "the action's cell is outside the committed grant"
    # a zero-dimension verb: its single cell
    ps = {"verb": "air.search", "resource": "x", "params_digest": params_digest({})}
    assert IM.decide_map_disclosure(MC, ps, CM["disclose"]("air.search", "x", {}))["cell"] == []
    assert IM.decide_map_primitive({"map_commit": MC, "action": ps, "disclosure": CM["disclose"]("air.search", "x", {})})["ok"] is True
    # never raises
    assert IM.decide_map_disclosure(MC, None, DISC)["reason"].startswith("map error (fail closed)")
    assert IM.decide_map_primitive(None) == {"ok": False, "reason": "input must be an object"}


def test_map_disclosure_shapes():
    me = IM.map_disclosure_error
    assert me(DISC) is None
    assert me(None) == "the disclosure must be exactly {size, header, cell, metrics}"
    assert me(dict(DISC, x=1)) == "the disclosure must be exactly {size, header, cell, metrics}"
    for sz in (3, 1 << 24 + 1, "17", 17.5, -0.0, None):
        assert me(dict(DISC, size=sz)) == "disclosure.size must be a safe integer in [4, 16777216]", sz
    assert me(dict(DISC, size=4)) is None and me(dict(DISC, size=1 << 24)) is None
    assert me(_with("header", x=1)) == "disclosure.header must be exactly {index, salt, leaf, path}"
    assert me(_with("cell", index=-1)) == "disclosure.cell.index must be a non-negative safe integer"
    assert me(_with("metrics", salt="AA")) == "disclosure.metrics.salt must be canonical base64url (32 bytes)"
    assert me(_with("cell", path=[_d("x")] * 65)) == "disclosure.cell.path must be an array of 32-byte digests"
    assert me(_with("cell", path=[_d("x")] * 64)) is None
    # leaf kinds cannot be confused: a metrics leaf in the cell slot is not a cell leaf
    assert me(_with("cell", leaf=METRICS)) == "the cell leaf must be exactly {verb, cell, p_ppm, in_grant}"
    assert me(_with("metrics", leaf=dict(METRICS, log2_vs_mbits=3))) is None
    assert me(_with("metrics", leaf=dict(METRICS, log2_vs_mbits=None))) == "metrics.log2_vs_mbits must be a non-negative safe integer"
    assert me(_with("metrics", leaf=dict(METRICS, questions="0"))) == "metrics.questions must be a non-negative safe integer"
    cl = DISC["cell"]["leaf"]
    assert IM.map_cell_error(dict(cl, p_ppm=1_000_001)) == "cell.p_ppm must be a safe integer in [0, 1000000]"
    assert IM.map_cell_error(dict(cl, p_ppm=1_000_000)) is None
    assert IM.map_cell_error(dict(cl, in_grant=1)) == "cell.in_grant must be a boolean"
    assert IM.map_cell_error(dict(cl, cell=[0] * 17)) == "cell.cell must be an array of non-negative safe integers"
    assert IM.map_learner_error({"learner_digest": "x"}) == "learner.learner_digest must be canonical base64url (32 bytes)"
    hl = DISC["header"]["leaf"]
    he = IM.map_header_error
    assert he(hl) is None
    assert he(dict(hl, cells=11)) == "header.cells is not the product of the dimensions' cell counts"
    assert he(dict(hl, first=1 << 24)) == "header.first must be a leaf index"
    assert he(dict(hl, verb="")) == "header.verb must be a non-empty string of at most 128 UTF-8 bytes"
    assert he(dict(hl, verb="v" * 129)) == "header.verb must be a non-empty string of at most 128 UTF-8 bytes"
    num = dict(BOOK_DIMS[0])
    dims = lambda d: dict(hl, dims=[d], cells=3)
    assert he(dims(dict(num, cuts=[40_000, 40_000]))) == "header.dims[0].cuts must be strictly increasing safe integers in [lo, hi]"
    assert he(dims(dict(num, cuts=[5_000_001]))) == "header.dims[0].cuts must be strictly increasing safe integers in [lo, hi]"
    assert he(dims(dict(num, lo=6_000_000))) == "header.dims[0] lo / hi must be safe integers with lo <= hi"
    assert he(dims(dict(num, path="action.resource"))) == "header.dims[0].path must be action.params.<name>"
    assert he(dims(dict(num, kind="int"))) == "header.dims[0].kind must be num or cat"
    cat = BOOK_DIMS[1]
    vals = cat["values"]
    catd = lambda v: dict(hl, dims=[dict(cat, values=v)], cells=len(v))
    assert he(catd(vals[:-1])) == "header.dims[0].values must end with the other value"
    assert he(catd([vals[-1]] + vals[:-1])) == "header.dims[0].values: exactly one other ('⊥'), last; prefixes non-empty"
    assert he(catd([{"kind": "prefix", "value": ""}, vals[-1]])) == "header.dims[0].values: exactly one other ('⊥'), last; prefixes non-empty"
    assert he(catd([vals[0], vals[0], vals[-1]])) == "header.dims[0].values must be distinct"
    assert he(catd([vals[-1]])) is None  # only the other value
    assert he(dict(hl, dims=[num, dict(num)], cells=9)) == "header.dims paths must be distinct"


def test_map_wire_goal_and_pipeline():
    assert validate_intent_session_wire(_is(map_form="commit")) is None
    for bad in ("Commit", None, 1, ""):
        assert validate_intent_session_wire(_is(map_form=bad)) == "'intent_session.map_form' must be \"commit\" when present"
    # v2c goal: a grant minted over the commit form opens only under it, and the plain v2 grant never under it
    assert intent_goal_commit(REF, MC, "salt0", SESSION, "commit") == _commit_v2c(MC, "salt0")
    assert intent_goal_commit(REF, MC, "salt0", SESSION) == _commit_v2(MC, "salt0")
    assert decide_intent_binding(_intent(MC), GM, None, SESSION, "commit") == ("pass", None)
    assert decide_intent_binding(_intent(MC), GM, None, SESSION)[0] == "fail"
    assert decide_intent_binding(_intent(MAP0), G0, None, SESSION, "commit")[0] == "fail"
    v = verify_pcactn_core(PM, GM, now=NOW, audience=AUD, intent_v2=_cm())
    assert (v.allow, v.checks, v.reason) == (True, dict(V2_OK, map=True), None)
    d = _decide(PM, GM, _cm())
    assert _names(d) == ["schema", "intent_session", "accumulators", "map"]
    # the map check is independent of the earlier ones and before W-B
    d = _decide(PM, GM, _cm(session={"grants": []}))
    assert [(c["name"], c["ok"]) for c in d["checks"]] == [("schema", True), ("intent_session", False),
                                                           ("accumulators", False), ("map", True)]
    assert _check(_decide(PM, GM, _cm(map={})), "map")["reason"] == "no disclosure of the committed map was presented"
    assert _check(_decide(PM, GM, _cm(policy={"map": {"max_residual_risk_ppm": 999}})), "map")["reason"] == \
        "the committed residual risk 1000 ppm exceeds ε = 999"
    assert _check(_decide(PM, GM, _cm(policy={"map": {"max_residual_risk_ppm": 1000}})), "map")["ok"] is True
    pm_noi = _signed(dict(_unsigned(GM, intent=None), intent_session=_is(root=RM, map_form="commit")))
    assert _check(_decide(pm_noi, GM, _cm()), "map")["reason"] == "a committed map needs the envelope.intent binding"
    # policy.map.require: without the commit form the map check is reported and fails (also without intent_session)
    need = 'this verifier requires a committed map (intent_session.map_form "commit")'
    d = _decide(ctx=_ctx(policy={"map": {"require": True}}))
    assert _names(d) == ["schema", "intent_session", "accumulators", "map"] and _check(d, "map")["reason"] == need
    assert _decide(_pcactn(), ctx=_ctx(policy={"map": {"require": True}}))["checks"] == [{"name": "map", "ok": False, "reason": need}]
    assert _decide(_pcactn(), ctx=_ctx(policy={"map": {"require": False}}))["checks"] == []
    assert intent_v2_active(_pcactn(), _ctx(policy={"map": {"require": True}})) is True
    # a malformed context with the commit form fails map too
    bad = "malformed v2 context: map must be an object"
    assert _decide(PM, GM, _cm(map=None))["checks"] == [{"name": n, "ok": False, "reason": bad}
                                                     for n in ("schema", "intent_session", "accumulators", "map")]
    assert _decide(ctx=_ctx(map=None))["checks"] == [{"name": n, "ok": False, "reason": bad}
                                                   for n in ("schema", "intent_session", "accumulators")]
    for m, why in (({"x": 1}, "map: unknown member 'x'"), ([], "map must be an object")):
        assert V2.intent_v2_context_error({"map": m}) == why
    for pol, why in (({"x": 1}, "policy.map: unknown member 'x'"), ({"require": "true"}, "policy.map.require must be a boolean"),
                     ({"require": None}, "policy.map.require must be a boolean"),
                     ({"max_residual_risk_ppm": -1}, "policy.map.max_residual_risk_ppm must be a non-negative safe integer")):
        assert V2.intent_v2_context_error({"policy": {"map": pol}}) == why, pol
    assert V2.intent_v2_context_error({"policy": {"map": None}}) == "policy.map must be an object"
    assert V2.intent_v2_context_error({"policy": {"session": {}, "schema": {}, "acc": {}, "map": {}}}) is None


# ---- 45a1599e: the W-B entry points never throw -------------------------------------------------------------------------

def test_wb_entry_points_are_total():
    from atlas_pca import intent_wb as WB
    for bad in (None, [], "x", 5, True):
        assert WB.decide_intent_wb(bad) == {"outcome": "deny", "checks": {"facts": "fail"}, "env": {},
                                            "reason": "facts: the W-B context is malformed: input must be an object"}, repr(bad)
        assert WB.intent_wb_context_error(bad) == "input must be an object"
        assert WB.decide_intent_world(bad) == {"ok": False, "reason": "facts: input must be an object"}
        assert WB.decide_param_provenance(bad)["reason"] == "provenance: input must be an object"
        assert WB.decide_classifier_dimensions(bad) == {"ok": False, "reason": "classes: input must be an object"}
        assert WB.intent_world_active(bad) is False and WB.classifier_check_active(bad) is False
        assert WB.intent_provenance_active(bad) is False
        assert WB.artifact_suite_error(bad) == "artifact must be an object"
    assert WB.ratio_ppm(1.5, 2) is None and WB.ratio_ppm(1, 2.5) is None and WB.ratio_ppm(1, 2) == 500_000
    assert WB.offer_matches(None, {}) is False and WB.query_covers({}, None) is False
    assert WB.flow_rule_for(None, "pii") is None and WB.flow_rule_for({"*": []}, 5) is None
    assert WB.flow_allowed({"*": ["a"]}, 5, "o", "a") is False and WB.flow_allowed({"*": ["a"]}, "pii", None, "a") is False
    assert WB.parse_label_ref(None) is None and WB.parse_label_ref(5) is None
    assert WB.decide_offer_set(None, "x", {}, {}, AUD, SESSION, NOW, 0)["reason"] == \
        "offers: policy misconfigured (fail closed): offers policy must be an object"
