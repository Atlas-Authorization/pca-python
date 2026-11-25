"""k05 mutation-kill tests, group "actions": the action kit (actions.py), its registry layer (actions_registry.py), linked policy
templates (policy_link.py) and the read-side vault (read_vault.py / readside.py). Expectations follow the TypeScript references
(pca-actions/src, pca/src/policy-link.ts, read-vault.ts, readside.ts). Signatures are made with throwaway keys at test load."""
import pytest

from atlas_pca import actions as A
from atlas_pca import actions_registry as AR
from atlas_pca import policy_link as PL
from atlas_pca import read_vault as RV
from atlas_pca import readside as RS
from atlas_pca.agent import KeyPair, _sign_body
from atlas_pca.pca import b64u
from test_k5_read_vault import VA

CORE = A.CORE_REGISTRY
KP = KeyPair(bytes(range(32)))
KS = KeyPair(bytes(range(1, 33)))
KT = KeyPair(bytes(range(2, 34)))
KR = KeyPair(bytes(range(3, 35)))


# ============================================================================================================== small helpers

def test_id_class_chars_exact():
    d, lo = "0123456789", "abcdefghijklmnopqrstuvwxyz"
    up = lo.upper()
    want = {"digits": d, "hex": d + "abcdef", "alnum": d + lo + up, "slug": d + lo + "-_", "uuid": d + "abcdef-", "any_safe": d + lo + up + "._-:/"}
    assert set(A.ID_CLASSES) == set(want)
    for c, w in want.items():
        assert A._id_class_chars(c) == w, c


def test_lone_surrogate_range():
    assert A._has_lone_surrogate("\ud800") and A._has_lone_surrogate("\udfff") and A._has_lone_surrogate("a\udc00b")
    assert not A._has_lone_surrogate("퟿") and not A._has_lone_surrogate("") and not A._has_lone_surrogate("")


def test_blank_reason_separators():
    for s in ("", " ", "\x1c", "\x1d", "\x1e", "\x1f", "　﻿\x1f \t"):
        assert A._blank_reason(s) is True, repr(s)
    for s in ("a", "\x1b", "\x20x", " . "):
        assert A._blank_reason(s) is False, repr(s)


def test_sort_uniq_string_order_of_js_sort():
    assert A._sort_uniq([10, 9, 10]) == [10, 9]  # String(10) < String(9)
    assert A._sort_uniq(["b", "a", "b"]) == ["a", "b"]
    assert A._sort_uniq(["￿", "\U00010000"]) == ["\U00010000", "￿"]  # UTF-16 code units
    assert A._sort_uniq(None) == []


def test_jget_messages():
    with pytest.raises(TypeError, match=r"Cannot read properties of undefined \(reading 'x'\)"):
        A._jget(A._UNDEF, "x")
    with pytest.raises(TypeError, match=r"Cannot read properties of null \(reading 'x'\)"):
        A._jget(None, "x")
    assert A._jget({"x": 1}, "x") == 1 and A._jget({}, "x") is A._UNDEF and A._jget([1], "x") is A._UNDEF


def test_jown_array_and_string_keys():
    for o in ([7, 8], "ab"):
        assert A._jown(o, "length") is True
        assert A._jown(o, "0") is True and A._jown(o, "1") is True
        assert A._jown(o, "2") is False  # index < length
        assert A._jown(o, "01") is False and A._jown(o, "x") is False and A._jown(o, "LENGTH") is False
    assert A._jown({"a": 1}, "a") is True and A._jown({"a": 1}, "b") is False and A._jown(5, "a") is False


def test_jtruthy_and_jnum():
    for x in (None, A._UNDEF, False, 0, 0.0, float("nan"), ""):
        assert A._jtruthy(x) is False, x
    for x in (True, 1, -1, 0.5, "a", "0", [], {}):
        assert A._jtruthy(x) is True, x
    assert A._jnum(True) == 1.0 and A._jnum(False) == 0.0 and A._jnum(None) == 0.0 and A._jnum(3) == 3.0
    n = A._jnum({})
    assert n != n


# ============================================================================================================== validate_def

SEG32, SEG29 = "b" * 32, "c" * 29
S128 = "a" * 32 + "." + SEG32 + "." + SEG32 + "." + SEG29  # 128 bytes, valid verb / alias / resource type shape


def base_def(**over):
    d = {"v": 1, "kind": "pca-action-def", "verb": "acme.thing.get", "title": "t", "effects": ["read"],
         "resource": {"type": "thing", "id": "*", "scope": "one"}, "params": {}, "review": {"state": "authored"}}
    d.update(over)
    return d


def test_validate_def_baseline_and_length_bounds():
    assert A.validate_def(base_def()) is None
    assert len(S128) == 128
    # alias 128 bytes ok / 129 refused
    assert A.validate_def(base_def(aliases=[S128])) is None
    assert A.validate_def(base_def(aliases=[S128 + "c"])) == "aliases must be distinct verb-shaped names other than the verb"
    # verb 128 bytes ok / 129 refused
    assert A.validate_def(base_def(verb=S128)) is None
    assert A.validate_def(base_def(verb=S128 + "c")) == "verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)"
    # resource.type 128 ok / 129 refused
    r = {"type": S128, "id": "*", "scope": "one"}
    assert A.validate_def(base_def(resource=r)) is None
    assert A.validate_def(base_def(resource=dict(r, type=S128 + "c"))) == "resource.type is malformed"


def test_validate_def_is_total_with_the_exact_prefix():
    e = A.validate_def({1: 2})
    assert e == "malformed def: 'int' object is not iterable"


def test_param_unit_and_ccy_member_checks():
    ok = {"type": "integer", "unit": {"kind": "money", "ccy": {"from": "c"}, "exp": 2}}
    c = {"type": "string"}
    assert A.validate_def(base_def(params={"a": ok, "c": c})) is None
    bad = {"type": "integer", "unit": {"kind": "money", "ccy": {"from": "c", "x": "c"}, "exp": 2}}
    assert A.validate_def(base_def(params={"a": bad, "c": c})) == "a: unit.ccy.from must name a declared parameter"
    assert A.validate_def(base_def(params={"a": {"type": "integer", "unit": {"kind": "count"}}})) is None
    assert A.validate_def(base_def(params={"a": {"type": "integer", "unit": {"kind": "count", "x": 1}}})) == "a: unit has unknown members"
    assert A.validate_def(base_def(params={"a": {"type": "integer", "unit": {"kind": "count", "ccy": "USD"}}})) == "a: unit has unknown members"


def test_review_dismissed_reason_accepted():
    a = {"def_digest": "d", "traits_digest": "t", "facts_digest": "f", "final_traits": [], "reviewer_kid": "k", "ts": 1, "sig": "s",
         "dismissed": [{"trait": "x.t", "reason": "r" * 256}]}
    assert A._review_error({"state": "confirmed", "attestation": a}) is None
    a["dismissed"] = [{"trait": "x.t", "reason": "r" * 257}]
    assert A._review_error({"state": "confirmed", "attestation": a}) == "review.attestation.dismissed must be {trait, reason} entries"


def test_bindings_member_lengths():
    assert A._bindings_error({"mcp": {"tool": "t" * 256}}) is None
    assert A._bindings_error({"mcp": {"tool": "t" * 257}}) == "bindings.mcp.tool must be a non-empty string"
    assert A._bindings_error({"openapi": {"operationId": "o", "method": "m" * 257}}) == "bindings.openapi.method must be a non-empty string"
    assert A._bindings_error({"openapi": {"operationId": "o", "method": "m" * 256}}) is None


# ============================================================================================================== registries

def tdef(i, implies=()):
    return {"id": "x.t%d" % i, "implies": list(implies), "floor": A.profile(), "card_phrase": "p"}


def test_registry_depth_cycle_and_diamond():
    chain8 = [tdef(i, ["x.t%d" % (i - 1)] if i else []) for i in range(8)]
    assert A.registry_error(chain8) is None
    chain9 = [tdef(i, ["x.t%d" % (i - 1)] if i else []) for i in range(9)]
    assert A.registry_error(chain9) == "trait 'x.t8': implies depth 9 exceeds 8"
    cyc = [tdef(0, ["x.t1"]), tdef(1, ["x.t0"])]
    assert A.registry_error(cyc) == "trait 'x.t0': implies cycle"
    diamond = [tdef(0), tdef(1, ["x.t0"]), tdef(2, ["x.t0"]), tdef(3, ["x.t1", "x.t2"])]
    assert A.registry_error(diamond) is None
    assert A.registry_error([tdef(0, ["x.t0"])]) == "trait 'x.t0': implies cycle"


def test_registry_card_phrase_units():
    def one(cp):
        t = tdef(0)
        t["card_phrase"] = cp
        return A.registry_error([t])
    assert one("a" * 120) is None and one("\U0001F600" * 60) is None
    msg = "trait 'x.t0': card_phrase must be a non-empty string up to 120 characters"
    assert one("a" * 121) == msg and one("\U0001F600" * 61) == msg and one("") == msg and one(5) == msg


def test_build_registry_reserves_pca_namespace_by_default():
    d = dict(tdef(0), id="pca.zz")
    with pytest.raises(A.ActionKitError) as ei:
        A.build_registry([d])
    assert ei.value.code == "bad_registry" and str(ei.value) == "trait 'pca.zz': the pca. namespace is reserved for core traits"
    assert "pca.zz" in A.build_registry([d], core=True)


def test_registry_of_schema_empty_trait_defs_is_the_core_registry():
    assert A.registry_of_schema({"trait_defs": []}) is CORE
    assert A.registry_of_schema({}) is CORE
    assert A.registry_of_schema({"trait_defs": [tdef(0)]}) is not CORE


# ============================================================================================================== normalize

def test_normalize_orders_params_by_utf16_and_copies_values():
    d = base_def(params={"￿": {"type": "string"}, "\U00010000": {"type": "string"}})
    assert list(A.normalize(d)["params"]) == ["\U00010000", "￿"]
    p = {"type": "string", "values": ["a", "b"]}
    out = A._normalize_param(p)
    assert out["values"] == ["a", "b"] and out["values"] is not p["values"]


# ============================================================================================================== signed confirmation

def pins_for(kp=KP, **over):
    key = {"kid": "k1", "pk": kp.public, "roles": ["reviewer"]}
    key.update(over)
    return {"keys": [key]}


def conf_body(v, **over):
    body = {"def_digest": v["def"], "traits_digest": A.traits_digest(CORE), "facts_digest": A.facts_digest(v), "final_traits": ["pca.bulk"],
            "dismissed": [], "reviewer_kid": "k1", "ts": 100}
    body.update(over)
    return body


def signed_verb(kp=KP, **over):
    v = {"verb": "a.b.c", "def": "D" * 43, "traits": ["pca.bulk"], "effects": ["read"]}
    body = conf_body(v, **over)
    v["confirmation"] = dict(body, sig=b64u(kp.sign(A.review_message(body))))
    return v


def vce(v, pins=None):
    return A.verb_confirmation_error(v, CORE, pins if pins is not None else pins_for())


def test_verb_confirmation_good_and_validity_window():
    assert vce(signed_verb()) is None
    assert vce(signed_verb(), pins_for(not_before=100, not_after=100)) is None
    msg = "the time is outside the key validity"
    assert vce(signed_verb(), pins_for(not_before=101)) == msg
    assert vce(signed_verb(), pins_for(not_after=99)) == msg


def test_verb_confirmation_error_texts():
    assert A.verb_confirmation_error(signed_verb(), CORE, None) == "no reviewer keys are pinned"
    v = signed_verb()
    del v["confirmation"]
    assert vce(v) == "no valid confirmation"
    v = signed_verb()
    v["confirmation"]["sig"] = 5
    assert vce(v) == "no valid confirmation"
    v = signed_verb()
    v["confirmation"] = None
    assert vce(v) == "no valid confirmation"
    v = signed_verb()
    v["confirmation"]["def_digest"] = "E" * 43
    assert vce(v) == "the confirmation covers a different def digest"
    v = signed_verb()
    v["def"] = 5
    assert vce(v) == "the confirmation covers a different def digest"
    v = signed_verb()
    v["confirmation"]["traits_digest"] = "E" * 43
    assert vce(v) == "made against a different trait registry"
    v = signed_verb()
    v["confirmation"]["facts_digest"] = "E" * 43
    assert vce(v) == "the confirmation covers different verb facts"
    v = signed_verb()
    v["traits"] = []
    assert vce(v) == "the verb does not carry every trait the reviewer signed"
    v = signed_verb()
    v["confirmation"]["reviewer_kid"] = "zz"
    assert vce(v) == "no pinned key 'zz'"
    assert vce(signed_verb(), pins_for(roles=["importer"])) == "key 'k1' does not hold the reviewer role"
    v = signed_verb()
    v["confirmation"]["ts"] = 101
    assert vce(v) == "the signature is invalid"


def test_verb_confirmation_malformed_members():
    for over in ({"reviewer_kid": 5}, {"ts": "x"}, {"final_traits": "pca.bulk"}, {"dismissed": {}}, {"final_traits": ["pca.bulk", 5]}):
        v = signed_verb()
        v["confirmation"].update(over)
        assert vce(v) == "malformed", over
    v = signed_verb()
    v["confirmation"]["reviewer_kid"] = 5  # a bad kid alone, with a good ts
    assert vce(v) == "malformed"
    v = signed_verb()
    v["confirmation"]["ts"] = 1.5  # a bad ts alone, with a good kid
    assert vce(v) == "malformed"


def test_verb_confirmation_dismissed_rules():
    msg = "a dismissed trait is also final, or has no reason"
    assert vce(signed_verb(dismissed=[{"trait": "pca.bulk", "reason": "r"}])) == msg
    assert vce(signed_verb(dismissed=[{"trait": "pca.other", "reason": " \x1f"}])) == msg
    assert vce(signed_verb(dismissed=[{"trait": "pca.other", "reason": "ok"}])) is None


def test_verb_confirmation_total_messages():
    assert vce(None).startswith("malformed confirmation: ") and "get" in vce(None)
    v = {"def": "D" * 43, "confirmation": {"sig": "x"}}
    assert vce(v) == "malformed confirmation: 'def_digest'"


def test_reviewer_pins_texts_and_kid_bound():
    pk = KP.public
    key = {"kid": "k", "pk": pk, "roles": ["reviewer", "importer"]}
    assert A.reviewer_pins_error({"keys": [key]}) == "key 'k': an importer or model key cannot hold the reviewer role"
    assert A.reviewer_pins_error({"keys": [dict(key, roles=["reviewer", "model"])]}) == "key 'k': an importer or model key cannot hold the reviewer role"
    assert A.reviewer_pins_error({"keys": [dict(key, roles=["reviewer"])]}) is None
    assert A.reviewer_pins_error({"keys": [dict(key, kid="k" * 128, roles=["reviewer"])]}) is None
    assert A.reviewer_pins_error({"keys": [dict(key, kid="k" * 129, roles=["reviewer"])]}) == "a pinned key needs a kid"


def def_level(kp=KP, **over):
    d = base_def()
    body = {"def_digest": A.def_digest(d), "traits_digest": A.traits_digest(CORE), "facts_digest": "F" * 43, "final_traits": [], "dismissed": [],
            "reviewer_kid": "k1", "ts": 5}
    body.update(over)
    d["review"] = {"state": "confirmed", "attestation": dict(body, sig=b64u(kp.sign(A.review_message(body))))}
    return d


def test_confirmed_def_takes_hint_traits_and_unconfirmed_takes_top():
    d, pins = def_level(), pins_for()
    assert A.verify_attestation(d, CORE, pins) is True
    assert A.hint_traits(d) == []
    assert A.traits_of(d, CORE, pins) == []
    assert A.traits_of(d, CORE, None) == sorted(CORE) and A.traits_of(d, CORE) == sorted(CORE)
    e = A.effective(d, CORE, pins)
    assert e["confirmed"] is True and e["traits"] == [] and e["closure"] == [] and e["floor"] == A.BOTTOM
    u = A.effective(d, CORE, None)
    assert u["confirmed"] is False and u["traits"] == sorted(CORE) and u["floor"] == A.floor_of(CORE, sorted(CORE))
    assert A.verify_attestation(d, A.CORE_REGISTRY, pins_for(roles=["importer"])) is False


def test_effective_builds_the_hint_view_even_unconfirmed():
    tiny = A.build_registry([tdef(0)])
    d = base_def(effects=["delete"])
    with pytest.raises(A.ActionKitError) as ei:
        A.effective(d, tiny, None)
    assert ei.value.code == "unknown_trait"


# ============================================================================================================== rule 22 (schema floors)

TINY = A.build_registry([tdef(0)])


def sv(**over):
    v = {"verb": "a.b.c", "kind": "read", "effects": ["read"], "traits": ["x.t0"], "floors": A.profile(), "params": {}}
    v.update(over)
    return v


def err(v):
    return A.schema_verb_floor_error(v, TINY, None)


def fl(rev):
    return A.profile({"rev": rev})


def test_schema_floor_honest_and_rev_order():
    assert err(sv()) is None
    low = "schema_floor_forged: floors.rev is below the declared reversibility"
    assert err(sv(reversibility="rate_limited", floors=fl("reversible"))) == low
    assert err(sv(reversibility="rate_limited", floors=fl("rate_limited"))) is None  # equal is enough
    assert err(sv(reversibility="rate_limited", floors=fl("irreversible"))) is None
    assert err(sv(reversibility="bogus", floors=fl("reversible"))) is None  # an unknown class never lowers the bar
    assert err(sv(reversibility="irreversible", floors=fl("irreversible"))) == "schema_traits_forged: missing implied trait pca.irreversible"


def test_schema_floor_reversibility_by_default_and_domain():
    rb = {"param": "action.params.m", "map": {"a": "reversible"}, "default": "rate_limited"}
    params = {"action.params.m": {"type": "string"}}
    low = "schema_floor_forged: floors.rev is below the declared reversibility"
    assert err(sv(reversibility_by=rb, params=params, floors=fl("rate_limited"))) is None
    assert err(sv(reversibility_by=rb, params=params, floors=fl("reversible"))) == low
    nodef = {"param": "action.params.m", "map": {"a": "reversible"}}
    assert err(sv(reversibility_by=nodef, params=params, floors=fl("irreversible"))) == "schema_traits_forged: missing implied trait pca.irreversible"
    # a boolean parameter whose both values are mapped: the default is never reached
    bm = {"param": "action.params.m", "map": {"true": "reversible", "false": "rate_limited"}, "default": "irreversible"}
    assert err(sv(reversibility_by=bm, params={"action.params.m": {"type": "boolean"}}, floors=fl("rate_limited"))) is None
    # a closed string domain, fully mapped / not fully mapped
    sm = {"param": "action.params.m", "map": {"a": "reversible", "b": "rate_limited"}, "default": "irreversible"}
    sp = {"action.params.m": {"type": "string", "values": ["a", "b"]}}
    assert err(sv(reversibility_by=sm, params=sp, floors=fl("rate_limited"))) is None
    sp2 = {"action.params.m": {"type": "string", "values": ["a", "b", "c"]}}
    assert err(sv(reversibility_by=sm, params=sp2, floors=fl("rate_limited"))) == "schema_traits_forged: missing implied trait pca.irreversible"
    # an unknown parameter falls to the default
    assert err(sv(reversibility_by=dict(sm, param="action.params.zz"), params=sp, floors=fl("rate_limited"))) == \
        "schema_traits_forged: missing implied trait pca.irreversible"


def test_schema_floor_array_reversibility_quirk():
    # JS: an array decl's .map is a function; its own keys are length / name, so a domain of exactly those is "covered"
    params = {"action.params.undefined": {"type": "string", "values": ["length", "name"]}}
    assert err(sv(reversibility=[], params=params, floors=fl("reversible"))) is None
    params2 = {"action.params.undefined": {"type": "string", "values": ["length", "other"]}}
    assert err(sv(reversibility=[], params=params2, floors=fl("reversible"))) == "schema_traits_forged: missing implied trait pca.irreversible"
    for vals in (["LENGTH", "name"], ["length", "NAME"], ["length", "nam"]):
        p = {"action.params.undefined": {"type": "string", "values": vals}}
        assert err(sv(reversibility=[], params=p, floors=fl("reversible"))) == "schema_traits_forged: missing implied trait pca.irreversible", vals


# ============================================================================================================== registry layer

def fake_suite(calls, ret=None):
    def f(*a):
        calls.append(a)
        return ret
    return f


def test_verify_registry_sig_passes_absent_pq_members_as_undefined(monkeypatch):
    calls = []
    monkeypatch.setattr(AR, "_pinned_suite_error", fake_suite(calls))
    keys = [{"kid": "k", "pk": KS.public}]
    assert AR.verify_registry_sig("d\0", {"a": 1}, {"kid": "k", "value": "x"}, keys) == {"ok": True}
    a = calls[0]
    assert a[0] == "ed25519" and a[1] == KS.public and a[2] is AR._UNDEF and a[5] is AR._UNDEF and a[6] is None
    assert a[3] == AR._message("d\0", {"a": 1}) and a[4] == "x"
    calls.clear()
    keys = [{"kid": "k", "pk": KS.public, "pq_pk": "PQ"}]
    AR.verify_registry_sig("d\0", {"a": 1}, {"kid": "k", "value": "x", "pq_value": "pv"}, keys)
    a = calls[0]
    assert a[2] == "PQ" and a[5] == "pv" and a[6] == {KS.public: "PQ"}


def mk_reapp(kp=KR, drop=(), **over):
    body = {"v": 1, "kind": AR.REAPPROVAL_KIND, "grant": "g1", "verb": "a.b.c", "diff": "D" * 43}
    body.update(over)
    for k in drop:
        del body[k]
    return dict(body, sig={"alg": "ed25519", "value": b64u(kp.sign(AR._message(AR.REAPPROVAL_DOMAIN, body)))})


def test_reapproval_valid_rules(monkeypatch):
    ok = lambda r, g="g1", v="a.b.c", d="D" * 43: AR.reapproval_valid(r, g, KR.public, v, d)  # noqa: E731
    assert ok(mk_reapp()) is True
    assert ok(mk_reapp(x=1)) is False  # signed, but with a member outside the closed set
    assert ok(mk_reapp(drop=("grant",)), g=None) is False
    assert ok(mk_reapp(drop=("verb",)), v=None) is False
    assert ok(mk_reapp(drop=("diff",)), d=None) is False
    assert ok(mk_reapp(), g="g2") is False and ok(mk_reapp(), v="a.b.d") is False and ok(mk_reapp(), d="E" * 43) is False
    assert ok(mk_reapp(v=True)) is False
    # an out-of-profile body cannot be canonicalised: refused, not accepted
    r = {"v": 1, "kind": AR.REAPPROVAL_KIND, "grant": "g1", "verb": "a.b.c", "diff": 1.5, "sig": {"alg": "ed25519", "value": "AAAA"}}
    assert ok(r, d=1.5) is False
    calls = []
    monkeypatch.setattr(AR, "_pinned_suite_error", fake_suite(calls))
    assert ok(mk_reapp()) is True
    a = calls[0]
    assert a[0] == "ed25519" and a[1] == KR.public and a[2] is AR._UNDEF and a[5] is AR._UNDEF and a[6] is None


class Eq:
    def __eq__(self, o):
        return True

    __hash__ = None


def test_same_is_js_triple_equals():
    assert AR._same(Eq(), []) is False and AR._same([], Eq()) is False and AR._same(Eq(), {}) is False
    x = [1]
    assert AR._same(x, x) is True and AR._same([1], [1]) is False and AR._same({}, {}) is False
    assert AR._same(True, 1) is False and AR._same(1, 1) is True and AR._same("a", "a") is True and AR._same(None, None) is True


def test_a_utf16_keeps_lone_surrogates():
    assert AR.A_utf16("\ud800") == b"\xd8\x00" and AR.A_utf16("a") == b"\x00a" and AR.A_utf16("\U00010000") == b"\xd8\x00\xdc\x00"


NS, VERB = "acme", "acme.thing.get"
PINNED, XD, YD, PD = "A" * 43, "B" * 43, "C" * 43, "E" * 43


def mk_rec(frm, to, cls):
    body = {"v": 1, "kind": AR.EVOLUTION_RECORD_KIND, "ns": NS, "verb": VERB, "from": frm, "to": to, "class": cls, "reasons": []}
    return dict(body, sig={"alg": "ed25519", "kid": "rk", "value": b64u(KS.sign(AR._message(AR.EVOLUTION_DOMAIN, body)))})


def pin_input(presented, records, verb=VERB, verbs=None):
    pin = {"pack": {"ns": NS, "root": "R" * 43}, "defs": {VERB: PINNED}, "on_new_action": "deny"}
    doc = {"pack": {"ns": NS, "root": "S" * 43}, "verbs": verbs if verbs is not None else [{"verb": VERB, "def": presented}]}
    return {"pin": pin, "doc": doc, "verb": verb, "keys": [{"kid": "rk", "pk": KS.public}], "grant": {"id": "g1", "issuer": KR.public},
            "records": records, "reapprovals": []}


def test_decide_pin_unknown_verb_needs_a_verb_member():
    out = AR.decide_pin(pin_input(PINNED, [], verb=None, verbs=[{}]))
    assert out["code"] == "unknown_verb"


def test_decide_pin_first_parent_wins_in_a_blocked_diamond():
    recs = [mk_rec(PINNED, XD, "widen"), mk_rec(PINNED, YD, "widen"), mk_rec(XD, PD, "widen"), mk_rec(YD, PD, "widen")]
    out = AR.decide_pin(pin_input(PD, recs))
    assert out["ok"] is False and out["code"] == "def_changed" and out["escalate"] is False
    assert out["needs_reapproval"] == AR.evolution_diff_digest(recs[0])


def test_decide_pin_removed_and_added_records_never_chain():
    recs = [mk_rec(PINNED, None, "removed"), mk_rec(None, PD, "added")]
    out = AR.decide_pin(pin_input(PD, recs))
    assert out == {"ok": False, "code": "def_changed", "escalate": False,
                   "reason": "the definition differs from the pinned digest and no signed evolution record chains to it"}
    # a free (narrow) step does chain
    assert AR.decide_pin(pin_input(XD, [mk_rec(PINNED, XD, "narrow")])) == {"ok": True, "via": "chain"}


def good_pack(**shard):
    ref = {"name": "s1", "digest": "D" * 43, "uri": "u"}
    ref.update(shard)
    return {"v": 1, "kind": AR.ACTION_PACK_KIND, "ns": NS, "version": "1.0.0", "stability": "stable", "traits_digest": "T" * 43,
            "roles_digest": "T" * 43, "rules_digest": "T" * 43, "root": "T" * 43, "defs": {"shards": [ref]},
            "source": {"kind": "k", "uri": "u", "spec_digest": "s", "licence": "l", "licence_notes": ""}, "prev": None, "evolution": [],
            "sig": {"alg": "ed25519", "kid": "k", "value": "v"}}


def test_pack_shape_shard_ref_each_condition():
    assert AR.pack_shape_error(good_pack()) is None
    bad = "pack: bad shard digest or uri"
    assert AR.pack_shape_error(good_pack(digest="x")) == bad
    assert AR.pack_shape_error(good_pack(uri="")) == bad
    assert AR.pack_shape_error(good_pack(uri="u" * 2049)) == bad
    assert AR.pack_shape_error(good_pack(uri=5)) == bad
    assert AR.pack_shape_error(good_pack(uri="u" * 2048)) is None


def test_pack_defs_ignores_a_non_dict_shard_map():
    pack = {"ns": NS, "version": "1.0.0", "defs": {"shards": [{"name": "s1", "digest": "x", "uri": "u"}]}}
    with pytest.raises(A.ActionKitError) as ei:
        AR.pack_defs(pack, ["junk"])
    assert ei.value.code == "missing_shard"


class Big(list):
    def __init__(self, n):
        super().__init__()
        self._n = n

    def __len__(self):
        return self._n


def test_verify_pack_def_count_bounds_and_total(monkeypatch):
    pack = {"sig": {}, "traits_digest": A.traits_digest(CORE), "roles_digest": A.tables_digest(), "rules_digest": AR.rules_digest()}
    monkeypatch.setattr(AR, "pack_shape_error", lambda x, signed=True: None)
    monkeypatch.setattr(AR, "verify_registry_sig", lambda *a: {"ok": True})
    monkeypatch.setattr(AR, "_sorted_unique_defs_error", lambda defs: None)
    many = "the pack lists no defs or too many"
    for n, refused in ((0, True), (1_000_001, True), (1_000_000, False)):
        monkeypatch.setattr(AR, "pack_defs", lambda p, s=None, n=n: Big(n))
        r = AR.verify_pack(pack, [])
        assert r["ok"] is False
        assert (r["reason"] == many) is refused, (n, r)
    def boom(x, signed=True):
        raise ValueError("boom")
    monkeypatch.setattr(AR, "pack_shape_error", boom)
    assert AR.verify_pack({}, []) == {"ok": False, "reason": "pack verification error: boom"}


# ============================================================================================================== policy_link

def tpl(body=None, slots=None, tid="tpl"):
    return {"v": 1, "kind": PL.TEMPLATE_KIND, "id": tid, "version": "1",
            "slots": slots or {"s": {"type": "string"}}, "body": body or {"predicates": [{"verb": {"$slot": "s"}}]}}


def signed_tpl(d=None, kp=KT):
    d = d or tpl()
    return {"def": d, "signer": kp.public, "sig": b64u(kp.sign(PL._message(PL.TEMPLATE_SIG_DOMAIN, PL.template_digest(d))))}


def overlay(digest, tid="tpl", where=None, cav=None, kp=KT):
    o = {"v": 1, "kind": PL.TIGHTEN_KIND, "template_id": tid, "version_digest": digest, "add_where": where or [], "add_caveats": cav or []}
    return {"overlay": o, "signer": kp.public, "sig": b64u(kp.sign(PL._message(PL.TIGHTEN_SIG_DOMAIN, PL.hash_canonical(o))))}


def test_is_int_floats_and_bounds():
    assert PL._is_int(9007199254740991.0) is True and PL._is_int(9007199254740992.0) is False
    assert PL._is_int(-5.0) is True and PL._is_int(0.0) is True and PL._is_int(-0.0) is False and PL._is_int(1.5) is False
    assert PL._is_int(9007199254740991) is True and PL._is_int(True) is False


def test_verify_template_and_tighten_messages():
    t = signed_tpl()
    assert PL.verify_template(t, [KT.public]) == {"ok": True}
    assert PL.verify_template(t, [KS.public]) == {"ok": False, "reason": "template signer is not trusted"}
    assert PL.verify_template(t, 5) == {"ok": False, "reason": "template verification error (fail closed)"}
    o = overlay(PL.template_digest(t["def"]))
    assert PL.verify_tighten(o, [KT.public]) == {"ok": True}
    assert PL.verify_tighten(o, [KS.public]) == {"ok": False, "reason": "overlay signer is not trusted"}
    assert PL.verify_tighten(o, 5) == {"ok": False, "reason": "overlay verification error (fail closed)"}


def test_slot_value_bounds_and_texts():
    se = PL._slot_value_error
    s = {"type": "string"}
    assert se("n", s, "a" * 256) is None
    for v in ("a" * 257, "", 5):
        assert se("n", s, v) == "slot 'n' must be a string of 1..256 characters", v
    i = {"type": "integer", "min": 5, "max": 7}
    assert se("n", i, 5) is None and se("n", i, 7) is None
    assert se("n", i, 4) == "slot 'n' is below its minimum" and se("n", i, 8) == "slot 'n' is above its maximum"
    st = {"type": "set"}
    assert se("n", st, ["m%d" % k for k in range(64)]) is None
    for v in (["m%d" % k for k in range(65)], [], [1], "a"):
        assert se("n", st, v) == "slot 'n' must be a non-empty list of strings"


def inst(body, slots, sdecl=None):
    return PL.instantiate_template(tpl(body, sdecl), slots)


def test_instantiate_matcher_guards_and_splicing():
    wild = "slot 's' would inject a wildcard or regex matcher into a verb or resource"
    for key in ("verb", "resource"):
        body = {"predicates": [{key: {"$slot": "s"}}]}
        assert inst(body, {"s": "a*"}) == {"ok": False, "reason": wild}
        assert inst(body, {"s": "re:x"}) == {"ok": False, "reason": wild}
        assert inst(body, {"s": "ok"}) == {"ok": True, "policy": {"predicates": [{key: "ok"}], "caveats": []}}
    nested = {"predicates": [{"verb": [{"$slot": "s"}]}]}
    assert inst(nested, {"s": "a*"}) == {"ok": False, "reason": wild}
    assert inst({"predicates": [{"verb": {"$slot": "s"}}]}, {"s": ["a", "b*"]}, {"s": {"type": "set", "values": ["a", "b*"]}}) == {"ok": False, "reason": wild}
    assert inst({"predicates": [{"name": {"$slot": "s"}}]}, {"s": "a*"})["ok"] is True  # not a verb / resource position
    # splicing
    sp = lambda pre, post: {"predicates": [{"name": {"$slot": "s", "pre": pre, "post": post}}]}  # noqa: E731
    assert inst(sp("", "x"), {"s": "ab"})["policy"]["predicates"] == [{"name": "abx"}]
    assert inst(sp("p.", ""), {"s": "ab"})["policy"]["predicates"] == [{"name": "p.ab"}]
    spl = "slot 's' cannot be spliced into a string (wildcard or non-string)"
    assert inst(sp("p", ""), {"s": "a*b"}) == {"ok": False, "reason": spl}
    assert inst(sp("p", ""), {"s": "a\u0000b"}) == {"ok": False, "reason": spl}
    assert inst(sp("p", ""), {"s": 5}, {"s": {"type": "integer"}}) == {"ok": False, "reason": spl}
    assert inst(sp("", "x"), {"s": "a*"}) == {"ok": False, "reason": spl}
    rx_ = "slot 's' would inject a regex matcher"
    assert inst(sp("", "x"), {"s": "re:a"}) == {"ok": False, "reason": rx_}
    assert inst(sp("re:", ""), {"s": "a"})["policy"]["predicates"] == [{"name": "re:a"}]
    assert inst(sp("x", "y"), {"s": "re:a"})["policy"]["predicates"] == [{"name": "xre:ay"}]


def test_instantiate_total_texts(monkeypatch):
    assert PL.instantiate_template(tpl(), 5) == {"ok": False, "reason": "slots must be an object"}
    monkeypatch.setattr(PL, "_fill", lambda *a: (_ for _ in ()).throw(RuntimeError("x")))
    assert PL.instantiate_template(tpl(), {"s": "v"}) == {"ok": False, "reason": "instantiation error (fail closed)"}


def test_template_ref_digest_lengths():
    ref = lambda **k: dict({"template_id": "tpl", "version_digest": "x", "slots": {}}, **k)  # noqa: E731
    assert PL.template_ref_error(ref(version_digest="x" * 128)) is None
    for v in ("x" * 129, "", 5):
        assert PL.template_ref_error(ref(version_digest=v)) == "template_ref.version_digest invalid", v
    b = lambda d: {"template_id": "tpl", "version_digest": "x", "bind_params_digest": d}  # noqa: E731
    for d in ("y", "y" * 128):
        assert PL.template_ref_error(b(d)) is None
    for d in ("y" * 129, "", 5):
        assert PL.template_ref_error(b(d)) == "template_ref.bind_params_digest invalid", d


def test_resolve_link_reasons_and_overlays():
    t = signed_tpl()
    dg = PL.template_digest(t["def"])
    reg = {"templates": {dg: t}, "trusted": [KT.public], "overlays": []}
    ref = {"template_id": "tpl", "version_digest": dg, "slots": {"s": "v"}}
    base = {"ok": True, "policy": {"predicates": [{"verb": "v"}], "caveats": []}, "overlays": 0}
    assert PL.resolve_link(ref, reg) == base
    assert PL.resolve_link(ref, dict(reg, templates={})) == {"ok": False, "reason": "template version is not in the registry"}
    assert PL.resolve_link(ref, dict(reg, templates=[])) == {"ok": False, "reason": "template version is not in the registry"}
    assert PL.resolve_link(ref, dict(reg, trusted=[KS.public])) == {"ok": False, "reason": "template signer is not trusted"}
    assert PL.resolve_link(dict(ref, version_digest="fake"), dict(reg, templates={"fake": t})) == \
        {"ok": False, "reason": "registry entry does not match its digest"}
    assert PL.resolve_link(dict(ref, template_id="other"), reg) == {"ok": False, "reason": "template id does not match the reference"}
    assert PL.resolve_link(ref, None) == {"ok": False, "reason": "link resolution error (fail closed)"}
    m1 = overlay(dg, where=[{"a": 1}], cav=[{"type": "c"}])
    m2 = overlay(dg, where=[{"b": 2}])
    other = overlay(dg, tid="other")
    stale = overlay("z" * 10)
    out = PL.resolve_link(ref, dict(reg, overlays=["junk", other, stale, m1, m2]))
    assert out == {"ok": True, "policy": {"predicates": [{"verb": "v", "where": [{"a": 1}, {"b": 2}]}], "caveats": [{"type": "c"}]}, "overlays": 2}
    assert PL.resolve_link(ref, dict(reg, overlays=[other, m1]))["overlays"] == 1
    forged = dict(m1, sig=m2["sig"])
    assert PL.resolve_link(ref, dict(reg, overlays=[forged])) == {"ok": False, "reason": "bad overlay signature"}
    assert PL.resolve_link(ref, dict(reg, overlays=[overlay(dg, kp=KS)])) == {"ok": False, "reason": "overlay signer is not trusted"}


# ============================================================================================================== read_vault / readside

PR = KP.public


def agg_grant(**rule_over):
    rule = {"verb": "v", "resource_prefix": "p/", "purposes": ["a"], "fns": ["count", "sum"], "min_group": 1, "clamp": 10, "epsilon_micro": 5, "dp": False}
    rule.update(rule_over)
    body = {"v": 1, "id": "ag", "principal": PR, "issued_at": 0, "expires_at": 10**13, "rules": [rule], "epsilon_budget_micro": 100, "max_queries": 10}
    return {"body": body, "sig": _sign_body(KP, RV.AGGREGATE_DOMAIN, body)}


def agg_in(g, **over):
    inp = {"grant": g, "principal": PR, "now": 1000, "verb": "v", "resource": "p/x", "purpose": "a", "fn": "count", "values": [1, 2, 3],
           "salt": "s" * 16, "noise": "seeded", "state": RV.empty_aggregate_state()}
    inp.update(over)
    return inp


def test_aggregate_without_dp_charges_nothing():
    r = RV.aggregate_read(agg_in(agg_grant()))
    assert r["decision"] == "allow" and r["value"] == 3 and r["charged_micro"] == 0
    assert r["state"]["spent_micro"] == 0 and r["state"]["queries"] == 1
    r = RV.aggregate_read(agg_in(agg_grant(dp=True), noise="seeded"))
    assert r["decision"] == "allow" and r["charged_micro"] == 5 and r["state"]["spent_micro"] == 5


def test_detokenize_expires_exactly_at_the_grant_end():
    c = next(c for c in VA["vault"] if c["name"] == "allowed-class-to-allowed-sink")
    g = VA["grants"]["vault"][c["detok_grant"]]
    exp = g["body"]["expires_at"]
    inp = dict(c["detok"], grant=g, now=exp, token="tok_x", store=RV.memory_vault())
    assert RV.detokenize(inp) == {"decision": "deny", "code": "expired", "value": None}
    assert RV.detokenize(dict(inp, now=exp - 1))["code"] == "unknown_token"


def test_vault_store_failure_returns_the_exact_denial():
    c = next(c for c in VA["vault"] if c["name"] == "allowed-class-to-allowed-sink")
    inp = dict(c["redact"], grant=VA["grants"]["vault"][c["redact_grant"]])
    counts = RS.redact_read(inp)["counts"]

    class Down:
        def put(self, token, entry):
            raise RuntimeError("down")
    assert RV.redact_read_with_vault(inp, Down()) == {"decision": "deny", "code": "bad_request", "view": {}, "fields": {}, "labels": [], "counts": counts}


def test_discrete_laplace_step_bound(monkeypatch):
    class D:
        def uniform(self, n):
            return 0

    def run(n_true):
        calls = {"n": 0}

        def fake(d, num, den):
            calls["n"] += 1
            return True if calls["n"] == 1 else calls["n"] - 1 <= n_true
        monkeypatch.setattr(RV, "_bern_exp_small", fake)
        return RV.discrete_laplace(D(), 1, 1)
    assert run(100_000) == 100_000
    with pytest.raises(RV.SamplerRangeError):
        run(100_001)


def test_read_grant_sink_label_caps():
    c = next(c for c in VA["vault"] if c["name"] == "allowed-class-to-allowed-sink")
    body = VA["grants"]["vault"][c["redact_grant"]]["body"]
    labels = lambda n: ["l%02d" % i for i in range(n)]  # noqa: E731
    mk = lambda **r: dict(body, sinks={"s": dict({"allow": [], "escalate": []}, **r)})  # noqa: E731
    assert RS.valid_read_grant_body(body) is True
    assert RS.valid_read_grant_body(mk(allow=labels(16))) is True and RS.valid_read_grant_body(mk(allow=labels(17))) is False
    assert RS.valid_read_grant_body(mk(escalate=labels(16))) is True and RS.valid_read_grant_body(mk(escalate=labels(17))) is False


def test_bmp_boundary():
    assert RS._bmp("￿") is True and RS._bmp("abc") is True and RS._bmp("") is True
    assert RS._bmp("\U00010000") is False and RS._bmp("a\U00010001") is False
