"""k05 mutation kills (intent group, atlas_pca/intent_v2.py): the v2 schema shape checks (_param_decl_error v2 members,
schema_floors_error, confirmation_shape_error, _verb_decl_error v2, action_schema_shape_error v2 members), every branch of
param_value_violation, and rules 20 / 21 / pin of _model_rules plus the v2-schema refusal of _schema_step (seams
monkeypatched). Every expectation is the TypeScript reference (packages/pca/src/action-schema.ts, intent-v2.ts)."""
import importlib

import atlas_pca.actions_registry as AR
AZ = importlib.import_module("atlas_pca.authorize")  # the package attribute is the function
import atlas_pca.intent_v2 as V2

D32 = "A" * 43  # canonical base64url of 32 zero bytes
S64 = "A" * 86  # canonical base64url of 64 zero bytes
P2 = {"type": "string", "semantic": "s", "sensitivity": "free"}
FLOORS = {"risk": 0, "rev": "reversible", "blast_ppm": 0, "esc": 0, "caveats": [], "context": [], "prules": []}
VERB = {"verb": "x.do", "kind": "write", "params": {}, "effects": ["create"], "traits": [], "def": D32, "floors": FLOORS}
CONF = {"def_digest": D32, "traits_digest": D32, "facts_digest": D32, "final_traits": [], "dismissed": [],
        "reviewer_kid": "k", "ts": 0, "sig": S64}
DOC1 = {"v": 1, "kind": "pca-action-schema", "site": "https://s", "aud": "a", "version": "1",
        "verbs": [{"verb": "x", "kind": "read", "params": {}}]}
DOC2 = {"v": 2, "kind": "pca-action-schema", "site": "https://s", "aud": "a", "version": "1", "verbs": [VERB]}


def _pd(path="action.params.a", v2=True, units=None, **kw):
    return V2._param_decl_error(path, dict(P2, **kw), units, v2)


def _vd(v2=True, drop=(), **kw):
    v = {k: x for k, x in dict(VERB, **kw).items() if k not in drop}
    return V2._verb_decl_error(v, None, v2)


def _fl(**kw):
    return V2.schema_floors_error(dict(FLOORS, **kw))


def _cf(drop=(), **kw):
    return V2.confirmation_shape_error({k: x for k, x in dict(CONF, **kw).items() if k not in drop})


def _sh(doc=DOC2, **kw):
    return V2.action_schema_shape_error(dict(doc, **kw), signed=False)


# ---- _param_decl_error -----------------------------------------------------------------------------------------------

def test_param_decl_v2_role_format_provenance():
    E = "action.params.a: "
    assert _pd() is None
    assert _pd(role="r") is None and _pd(role="r" * 128) is None
    for bad in ("", "r" * 129, 5, None):
        assert _pd(role=bad) == E + "role must be a non-empty string"
    assert _pd(v2=False, role="r") == E + "unknown member 'role'"
    assert _pd(format="email") is None and _pd(format="id:user") is None
    assert V2._param_decl_error("action.params.a", dict(P2, type="object_ref", format="uuid"), None, True) is None
    for d in (dict(P2, format="nope"), dict(P2, format=5), dict(P2, type="integer", format="email"),
              dict(P2, type="set", values=["a"], format="email")):
        assert V2._param_decl_error("action.params.a", d, None, True) == E + "format must be a known format on a string parameter"
    assert _pd(v2=False, format="email") == E + "unknown member 'format'"
    for ok in ("first_party", "tool", "agent"):
        assert _pd(provenance_min=ok) is None
    for bad in ("x", 5, None, "Tool"):
        assert _pd(provenance_min=bad) == E + "unknown provenance_min"


def test_param_decl_v2_tags():
    E = "action.params.a: tags must be distinct known tags"
    assert _pd(tags=[]) is None and _pd(tags=["pii"]) is None
    assert _pd(tags=list(V2.SCHEMA_V2_TAGS)) is None  # all 9: the length bound is inclusive
    assert _pd(tags=["pii", "pii"]) == E  # a duplicate alone (length within bound) is refused
    assert _pd(tags=list(V2.SCHEMA_V2_TAGS) + ["pii"]) == E
    assert _pd(tags=["nope"]) == E and _pd(tags=["pii", 5]) == E
    assert _pd(tags="pii") == E and _pd(tags=None) == E and _pd(tags={"pii": 1}) == E
    assert _pd(v2=False, tags=["pii"]) == "action.params.a: unknown member 'tags'"


def test_param_decl_v2_types_and_paths():
    assert _pd(type="datetime") is None and _pd(type="object_ref") is None
    assert _pd(type="duration", min=0, max=5) is None
    assert _pd(v2=False, type="duration") == "action.params.a: unknown type"
    assert _pd(v2=False, type="datetime") == "action.params.a: unknown type"
    assert _pd(v2=False, type="object_ref") == "action.params.a: unknown type"
    assert _pd(v2=False, type="duration", min=0) == "action.params.a: unknown type"
    assert _pd(type="string", min=0) == "action.params.a: min must be a safe integer on an integer parameter"
    assert _pd(type="duration", max=1.5) == "action.params.a: max must be a safe integer on an integer parameter"
    assert _pd(type="array", items="integer", min=0, max=3) is None
    assert _pd(type="array", items="string", min=0) == "action.params.a: min must be a safe integer on an integer parameter"
    assert _pd(path="action.params.a.b.c") is None
    assert _pd(path="action.params.a.b.c.d") == "parameter path 'action.params.a.b.c.d' is not action.params.<name>"
    assert _pd(path="action.params.a.b", v2=False) == "parameter path 'action.params.a.b' is not action.params.<name>"
    assert _pd(path="action.params.a.constructor") == \
        "parameter name 'action.params.a.constructor' is reserved (__proto__ / constructor / prototype)"
    assert V2._param_decl_error("action.params.a", "x", None, True) == "action.params.a: declaration must be an object"


def test_param_decl_generic_branches():
    E = "action.params.a: "
    assert _pd(type="bool") == E + "unknown type"
    assert _pd(semantic="") == E + "semantic must be a non-empty string"
    assert _pd(semantic="s" * 128) is None and _pd(semantic="s" * 129) == E + "semantic must be a non-empty string"
    assert _pd(sensitivity="x") == E + "unknown sensitivity"
    assert _pd(required=1) == E + "required must be a boolean" and _pd(required=False) is None
    assert _pd(values=["v%d" % i for i in range(256)]) is None
    assert _pd(values=["v%d" % i for i in range(257)]) == E + "values must be 1..256 strings"
    assert _pd(values=[]) == E + "values must be 1..256 strings"
    assert _pd(values=[""]) == E + "values must be 1..256 strings"
    assert _pd(values="a") == E + "values must be 1..256 strings"
    assert _pd(values=["a", "a"]) == E + "values must be distinct"
    assert _pd(type="integer", values=["a"]) == E + "values apply to string and set only"
    assert _pd(type="set") == E + "a set needs values"
    assert _pd(type="set", values=["a"]) is None
    assert _pd(type="integer", min=2, max=1) == E + "min > max"
    assert _pd(type="integer", min=1, max=1) is None
    assert _pd(type="integer", unit="u", units={"u": {}}) is None
    assert _pd(type="integer", unit="v", units={"u": {}}) == E + "unit must name a declared unit of an integer parameter"
    assert _pd(type="string", unit="u", units={"u": {}}) == E + "unit must name a declared unit of an integer parameter"
    assert _pd(type="integer", unit="u", units=None) == E + "unit must name a declared unit of an integer parameter"
    assert _pd(type="integer", unit=5, units={"5": {}}) == E + "unit must name a declared unit of an integer parameter"
    assert _pd(max_len=1) is None
    for bad in (0, -1, 1.5, "3", True):
        assert _pd(max_len=bad) == E + "max_len must be a positive safe integer"
    assert _pd(type="array", items="x") is None
    assert _pd(type="string", items="x") == E + "items applies to array only"
    assert _pd(type="array", items="x" * 65) == E + "items applies to array only"
    for k in ("min_items", "max_items"):
        assert _pd(type="array", **{k: 0}) is None
        assert _pd(type="string", **{k: 0}) == E + "%s must be a non-negative safe integer on a set or array" % k
        assert _pd(type="array", **{k: -1}) == E + "%s must be a non-negative safe integer on a set or array" % k
    assert _pd(type="array", min_items=2, max_items=1) == E + "min_items > max_items"
    assert _pd(type="array", min_items=1, max_items=1) is None
    assert _pd(default=None) == E + "default must not be null (absent = no default)"
    assert _pd(principal_neutral_default=1) == E + "principal_neutral_default must be a boolean"
    assert _pd(principal_neutral_default=True) == E + "principal_neutral_default needs a default"
    assert _pd(principal_neutral_default=True, default="x") is None
    assert _pd(principal_neutral_default=False) is None
    I = lambda ai: _pd(type="integer", accumulates_into=ai)  # noqa: E731
    assert _pd(accumulates_into=["u"]) == E + "accumulates_into applies to integer parameters only"
    assert I(["u%d" % i for i in range(8)]) is None
    assert I([]) == E + "accumulates_into must be 1..8 unit ids" and I("u") == E + "accumulates_into must be 1..8 unit ids"
    assert I(["U"]) == E + "accumulates_into entries must be unit ids"
    assert I(["u" * 64]) is None and I(["u" * 65]) == E + "accumulates_into entries must be unit ids"
    assert I(["u", "u"]) == E + "accumulates_into must be distinct"
    assert _pd(issued_by_site="x") == E + "issued_by_site must be a boolean" and _pd(issued_by_site=True) is None
    assert _pd(description="") == E + "description must be a string" and _pd(description="d" * 1024) is None
    assert _pd(description="d" * 1025) == E + "description must be a string"


# ---- schema_floors_error -----------------------------------------------------------------------------------------------

def test_floors_risk_esc_rev_blast():
    R = "floors.risk and floors.esc must be integers in 0..3"
    assert _fl() is None  # risk 0 and esc 0 are both inside 0..3
    assert _fl(risk=3, esc=3) is None and _fl(risk=1.0, esc=2) is None
    for k in ("risk", "esc"):
        for bad in (-1, 4, True, "1", None, 1.5):
            assert _fl(**{k: bad}) == R
    assert V2.schema_floors_error({k: v for k, v in FLOORS.items() if k != "esc"}) == R
    for rev in ("reversible", "rate_limited", "irreversible"):
        assert _fl(rev=rev) is None
    assert _fl(rev="x") == "floors.rev is not a reversibility class"
    assert _fl(rev=None) == "floors.rev is not a reversibility class"
    assert _fl(blast_ppm=1_000_000) is None
    for bad in (1_000_001, -1, "0", None):
        assert _fl(blast_ppm=bad) == "floors.blast_ppm must be an integer in 0..1000000"
    assert V2.schema_floors_error([]) == "floors must be an object"
    assert V2.schema_floors_error({"x": 1}) == "floors: unknown member 'x'"


def test_floors_sets():
    assert _fl(caveats=["amount_cap", "window"]) is None
    assert _fl(caveats=sorted(V2.SCHEMA_V2_CAVEATS)) is None
    assert _fl(caveats=["window"] * 64) == "floors.caveats must be sorted and distinct"  # 64 passes the length bound
    assert _fl(caveats=["window"] * 65) == "floors.caveats must be an array of known entries"
    assert _fl(caveats=["window", "amount_cap"]) == "floors.caveats must be sorted and distinct"
    assert _fl(caveats=["amount_cap", "count_cap", "approval_ref"]) == "floors.caveats must be sorted and distinct"
    assert _fl(caveats=["amount_cap", "amount_cap"]) == "floors.caveats must be sorted and distinct"
    assert _fl(caveats=["nope"]) == "floors.caveats must be an array of known entries"
    assert _fl(caveats=[5]) == "floors.caveats must be an array of known entries"
    assert _fl(caveats="window") == "floors.caveats must be an array of known entries"
    assert _fl(context=["approval_ref", "dry_run_first", "session_taint_max:abc"]) is None
    assert _fl(context=["session_taint_max:" + "a" * 16]) is None
    for bad in ("session_taint_max:", "session_taint_max:" + "a" * 17, "session_taint_max:A", "nope"):
        assert _fl(context=[bad]) == "floors.context must be an array of known entries"
    assert _fl(context=["session_taint_max:a", "approval_ref"]) == "floors.context must be sorted and distinct"
    assert _fl(prules=["array_bounded", "export_bounded"]) is None
    assert _fl(prules=["export_bounded", "array_bounded"]) == "floors.prules must be sorted and distinct"
    assert _fl(prules=["window"]) == "floors.prules must be an array of known entries"
    assert _fl(caveats=["nope"], context=["nope"]) == "floors.caveats must be an array of known entries"
    assert _fl(context=None) == "floors.context must be an array of known entries"


# ---- confirmation_shape_error ------------------------------------------------------------------------------------------

def test_confirmation_shape():
    D = "confirmation: def_digest, traits_digest and facts_digest must be canonical base64url SHA-256 digests"
    assert _cf() is None
    assert V2.confirmation_shape_error("x") == "confirmation must be an object"
    assert _cf(x=1) == "confirmation: unknown member 'x'"
    for k in ("def_digest", "traits_digest", "facts_digest"):
        assert _cf(**{k: "A" * 42}) == D
        assert _cf(drop=(k,)) == D
    assert _cf(sig=D32) == "confirmation: sig must be a canonical base64url 64-byte signature"
    FT = "confirmation: final_traits must be trait ids"
    assert _cf(final_traits=["a.a", "b.a"]) is None
    for bad in ("a.a", ["A.a"], ["a"], [5], ["a.b"] * 65):
        assert _cf(final_traits=bad) == FT
    assert _cf(final_traits=["a" + "b" * 31 + ".c"]) is None and _cf(final_traits=["a" + "b" * 32 + ".c"]) == FT
    FS = "confirmation: final_traits must be sorted and distinct"
    assert _cf(final_traits=["a.b"] * 64) == FS
    assert _cf(final_traits=["b.a", "a.a"]) == FS and _cf(final_traits=["a.a", "b.a", "a.b"]) == FS
    DM = "confirmation: dismissed entries must be {trait, reason}"
    ok = {"trait": "a.b", "reason": "r"}
    assert _cf(dismissed=[ok]) is None and _cf(dismissed=[ok] * 64) is None
    assert _cf(dismissed=[ok] * 65) == "confirmation: dismissed must be an array"
    assert _cf(dismissed="x") == "confirmation: dismissed must be an array"
    assert _cf(dismissed=[dict(ok, reason="r" * 256)]) is None
    for bad in (dict(ok, x=1), dict(ok, trait=5), dict(ok, trait="bad"), dict(ok, reason=""), dict(ok, reason="r" * 257),
                {"trait": "a.b"}, "x"):
        assert _cf(dismissed=[bad]) == DM
    RK = "confirmation: reviewer_kid must be a non-empty string"
    assert _cf(reviewer_kid="k" * 128) is None
    assert _cf(reviewer_kid="") == RK and _cf(reviewer_kid="k" * 129) == RK and _cf(reviewer_kid=5) == RK
    TS = "confirmation: ts must be a non-negative safe integer"
    for ok_ts in (0, 5.0, 2 ** 53 - 1):
        assert _cf(ts=ok_ts) is None
    for bad in (-1, True, 1.5, "0", 2 ** 53, -0.0, None):
        assert _cf(ts=bad) == TS
    assert _cf(drop=("ts",)) == TS


# ---- _verb_decl_error --------------------------------------------------------------------------------------------------

def test_verb_decl_v2_effects():
    EF = "verb 'x.do': effects must be 1..12 known effects"
    ES = "verb 'x.do': effects must be sorted and distinct"
    assert _vd() is None
    assert _vd(effects=sorted(V2.SCHEMA_V2_EFFECTS)) is None  # all 12, sorted: the bound is inclusive
    assert _vd(drop=("effects",)) == EF and _vd(effects=[]) == EF and _vd(effects="create") == EF
    assert _vd(effects=["nope"]) == EF and _vd(effects=["create", 5]) == EF
    assert _vd(effects=["create"] * 13) == EF
    assert _vd(effects=["create"] * 12) == ES
    assert _vd(effects=["update", "create"]) == ES  # first pair
    assert _vd(effects=["create", "update", "delete"]) == ES  # only the last pair is out of order
    assert _vd(effects=["create", "delete", "update"]) is None
    K = "verb 'x.do': kind read must hold exactly when every effect is read"
    assert _vd(kind="read", effects=["read"]) is None
    assert _vd(kind="read", effects=["create"]) == K
    assert _vd(kind="write", effects=["read"]) == K
    assert _vd(kind="read", effects=["create", "read"]) == K
    assert _vd(kind="write", effects=["create", "read"]) is None
    assert _vd(effects=[], traits=None) == EF  # effects are checked before traits


def test_verb_decl_v2_traits_def_floors_confirmation():
    T = "verb 'x.do': traits must be trait ids"
    TS = "verb 'x.do': traits must be sorted and distinct"
    assert _vd(traits=["a.x", "b.x"]) is None
    for bad in (None, "a.x", ["A.x"], [5], ["a.x"] * 65):
        assert _vd(traits=bad) == T
    assert _vd(drop=("traits",)) == T
    assert _vd(traits=["a.x"] * 64) == TS and _vd(traits=["b.x", "a.x"]) == TS
    assert _vd(traits=["a.x", "c.x", "b.x"]) == TS
    DF = "verb 'x.do': def must be a canonical base64url SHA-256 digest"
    assert _vd(drop=("def",)) == DF and _vd(**{"def": "A" * 42}) == DF and _vd(**{"def": S64}) == DF
    assert _vd(drop=("floors",)) == "verb 'x.do': floors must be an object"
    assert _vd(floors=dict(FLOORS, esc=4)) == "verb 'x.do': floors.risk and floors.esc must be integers in 0..3"
    assert _vd(confirmation=CONF) is None
    assert _vd(confirmation="x") == "verb 'x.do': confirmation must be an object"
    assert _vd(confirmation=dict(CONF, ts=-1)) == "verb 'x.do': confirmation: ts must be a non-negative safe integer"


def test_verb_decl_v1_v2_member_sets_and_parents():
    assert _vd(v2=False) == "verb entry: unknown member 'traits'"
    v1 = {"verb": "x", "kind": "read", "params": {}}
    assert V2._verb_decl_error(dict(v1, effects=[]), None, False) == "verb 'x': effects must be an object"
    assert V2._verb_decl_error(dict(v1, effects={}), None, False) is None
    assert _vd(harm=[]) == "verb 'x.do': harm must be an object" and _vd(returns=5) == "verb 'x.do': returns must be an object"
    assert _vd(harm={}, returns={}) is None
    ps = {"action.params.a": P2, "action.params.a.b": P2}
    assert _vd(params=ps) == "verb 'x.do': parameter 'action.params.a' is both a value and the parent of 'action.params.a.b'"
    assert _vd(params={"action.params.a": P2, "action.params.ab": P2}) is None
    assert _vd(params={"action.params.a": dict(P2, role="")}) == "verb 'x.do': action.params.a: role must be a non-empty string"


def test_verb_decl_generic_branches():
    at = "verb 'x.do': "
    assert V2._verb_decl_error("x", None, True) == "verb entry must be an object"
    assert _vd(x=1) == "verb entry: unknown member 'x'"
    assert _vd(verb="") == "verb entry: verb must be a non-empty string"
    assert _vd(verb="v" * 129) == "verb entry: verb must be a non-empty string"
    assert _vd(verb="v" * 128) is None
    assert _vd(kind="x") == at + "kind must be read or write"
    assert _vd(params=[]) == at + "params must be an object"
    many = {"action.params.p%d" % i: P2 for i in range(65)}
    assert _vd(params=many) == at + "more than 64 parameters"
    assert _vd(params=dict(list(many.items())[:64])) is None
    assert _vd(reversibility="x") == at + "unknown reversibility"
    assert _vd(reversibility="irreversible") is None
    ps = {"action.params.a": P2}
    rb = {"param": "action.params.a", "map": {"t": "reversible"}}
    assert _vd(params=ps, reversibility_by=rb) is None
    assert _vd(params=ps, reversibility_by=dict(rb, default="irreversible")) is None
    assert _vd(params=ps, reversibility_by=dict(rb, x=1)) == at + "reversibility_by must be {param, map, default?}"
    assert _vd(params=ps, reversibility_by="x") == at + "reversibility_by must be {param, map, default?}"
    assert _vd(params=ps, reversibility_by=dict(rb, param="action.params.b")) == at + "reversibility_by.param must be a declared parameter"
    assert _vd(params=ps, reversibility_by=dict(rb, param=5)) == at + "reversibility_by.param must be a declared parameter"
    for m in ({}, {"t": "x"}, "x"):
        assert _vd(params=ps, reversibility_by=dict(rb, map=m)) == at + "reversibility_by.map must map values to reversibility classes"
    assert _vd(params=ps, reversibility_by=dict(rb, default="x")) == at + "reversibility_by.default is not a reversibility class"
    assert _vd(mcp={"tool": "t"}) is None
    for bad in ({"tool": "t", "x": 1}, {"tool": ""}, {}, "t"):
        assert _vd(mcp=bad) == at + "mcp must be {tool}"
    assert _vd(openapi={"operationId": "o"}) is None
    for bad in ({"operationId": "o", "x": 1}, {"operationId": 5}, {}):
        assert _vd(openapi=bad) == at + "openapi must be {operationId}"
    assert _vd(world=[]) is None and _vd(world="x") == at + "world must be an array"
    assert _vd(description="d") is None and _vd(description="") == at + "description must be a string"


# ---- action_schema_shape_error v2 members ------------------------------------------------------------------------------

def test_schema_shape_v2_pack_and_traits():
    P = "pack must be {ns, version, root}"
    pk = {"ns": "n", "version": "1", "root": D32}
    assert _sh() is None
    assert _sh(pack=pk) is None
    assert _sh(pack=dict(pk, ns="n" * 64, version="v" * 128)) is None
    for bad in ({"ns": "n", "version": "1"}, dict(pk, x=1), dict(pk, ns=""), dict(pk, ns="n" * 65),
                dict(pk, version="v" * 129), dict(pk, version=1), dict(pk, root="A" * 42), "x", None):
        assert _sh(pack=bad) == P
    assert _sh(DOC1, pack=pk) == "unknown member 'pack'"
    assert _sh(traits_digest=D32) is None
    assert _sh(traits_digest="x") == "traits_digest must be a canonical base64url SHA-256 digest"
    assert _sh(DOC1, traits_digest=D32) == "unknown member 'traits_digest'"
    assert _sh(trait_defs=[{}] * 64) is None
    for bad in ([{}] * 65, [1], {}, "x"):
        assert _sh(trait_defs=bad) == "trait_defs must be an array of up to 64 objects"
    assert _sh(traits_digest="x", pack="x") == "traits_digest must be a canonical base64url SHA-256 digest"


def test_schema_shape_version_typing():
    assert _sh(v=2.0) is None
    assert _sh(DOC1, v=True) == "unsupported schema version"
    assert _sh(DOC1, v=3) == "unsupported schema version"
    assert _sh(DOC1, v="1") == "unsupported schema version"
    assert _sh(verbs=DOC1["verbs"]) == "verb 'x': effects must be 1..12 known effects"  # a v1 verb in a v2 document
    assert V2.action_schema_shape_error(DOC2) == "sig must be an object"
    assert V2.action_schema_shape_error(dict(DOC2, sig={}), signed=False) == "an unsigned schema must not carry sig"


# ---- param_value_violation ----------------------------------------------------------------------------------------------

def _pv(d, x):
    return V2.param_value_violation(d, x)


def _bt(r):
    return {"code": "bad_type", "reason": r}


def _od(r):
    return {"code": "out_of_domain", "reason": r}


def test_value_string_and_object_ref():
    s = {"type": "string"}
    assert _pv(s, "a") is None and _pv(s, "") is None
    assert _pv(s, 5) == _bt("expected a string") and _pv(s, "\ud800") == _bt("expected a string")
    assert _pv(s, "a" * 1024) is None and _pv(s, "a" * 1025) == _od("longer than 1024 UTF-8 bytes")
    assert _pv(dict(s, max_len=3), "abc") is None
    assert _pv(dict(s, max_len=3), "abcd") == _od("longer than 3 UTF-8 bytes")
    assert _pv(dict(s, max_len=3), "éé") == _od("longer than 3 UTF-8 bytes")  # 4 UTF-8 bytes, 2 chars
    assert _pv(dict(s, max_len=4), "éé") is None
    assert _pv(dict(s, values=["a", "b"]), "a") is None
    assert _pv(dict(s, values=["a", "b"]), "c") == _od("not one of the declared values")
    assert _pv(dict(s, format="email"), "a@b.co") is None
    assert _pv(dict(s, format="email"), "x") == _od("not a valid email")
    assert _pv(dict(s, format="zzz"), "x") == _od("not a valid zzz")
    assert _pv(dict(s, values=["x"], format="email"), "x") == _od("not a valid email")
    o = {"type": "object_ref"}
    for bad in ("", 5, None, "\ud800"):
        assert _pv(o, bad) == _bt("expected a non-empty id string")
    assert _pv(o, "a" * 1024) is None and _pv(o, "a" * 1025) == _od("longer than 1024 UTF-8 bytes")
    assert _pv(dict(o, max_len=3), "abc") is None
    assert _pv(dict(o, max_len=3), "abcd") == _od("longer than 3 UTF-8 bytes")
    assert _pv(dict(o, format="id:user"), "u_1") is None
    assert _pv(dict(o, format="id:user"), "a b") == _od("not a valid id:user")


def test_value_datetime_duration_integer_boolean():
    dt = {"type": "datetime"}
    BAD = _od("not an RFC 3339 UTC datetime YYYY-MM-DDTHH:MM:SS[.fff]Z")
    assert _pv(dt, 5) == _bt("expected an RFC 3339 UTC string")
    assert _pv(dt, "2024-02-29T23:59:59.999Z") is None and _pv(dt, "2024-01-01T00:00:00Z") is None
    for bad in ("2026-02-29T00:00:00Z", "2024-02-29T24:00:00Z", "2024-01-01T00:00:00.1234Z", "2024-01-01T00:00:00",
                "2024-01-01T00:60:00Z", "2024-13-01T00:00:00Z", "x"):
        assert _pv(dt, bad) == BAD
    du = {"type": "duration"}
    for bad in ("5", True, 1.5, 2 ** 53, None):
        assert _pv(du, bad) == _bt("expected a safe integer (milliseconds)")
    assert _pv(du, -1) == _od("a duration is not negative") and _pv(du, 0) is None
    assert _pv(dict(du, min=10), 9) == _od("below min 10") and _pv(dict(du, min=10), 10) is None
    assert _pv(dict(du, max=20), 21) == _od("above max 20") and _pv(dict(du, max=20), 20) is None
    i = {"type": "integer"}
    for bad in ("5", True, 1.5, 2 ** 53, None):
        assert _pv(i, bad) == _bt("expected a safe integer")
    assert _pv(i, -5) is None and _pv(i, 2 ** 53 - 1) is None
    assert _pv(dict(i, min=-5), -6) == _od("below min -5") and _pv(dict(i, min=-5), -5) is None
    assert _pv(dict(i, max=7), 8) == _od("above max 7") and _pv(dict(i, max=7), 7) is None
    assert _pv(dict(i, min=0, max=7), 8) == _od("above max 7")
    b = {"type": "boolean"}
    assert _pv(b, False) is None and _pv(b, True) is None
    assert _pv(b, 0) == _bt("expected a boolean") and _pv(b, "true") == _bt("expected a boolean")


def test_value_date_set_array_unknown():
    d = {"type": "date"}
    BAD = _od("not a calendar date YYYY-MM-DD")
    assert _pv(d, 5) == _bt("expected a YYYY-MM-DD string")
    for ok in ("2000-02-29", "2024-02-29", "2024-04-30", "0001-01-01", "2023-12-31"):
        assert _pv(d, ok) is None
    for bad in ("2023-02-29", "1900-02-29", "0000-01-01", "2024-13-01", "2024-00-10", "2024-04-31", "2024-01-00",
                "2024-1-01", "x"):
        assert _pv(d, bad) == BAD
    s = {"type": "set", "values": ["a", "b", "c"]}
    assert _pv(s, "a") == _bt("expected an array of strings") and _pv(s, ["a", 1]) == _bt("expected an array of strings")
    assert _pv(s, ["a", "a"]) == _od("set members must be distinct")
    assert _pv(s, ["z"]) == _od("set member not among the declared values")
    assert _pv(s, []) is None and _pv(s, ["a", "b", "c"]) is None
    SZ = _od("set size outside the declared bounds")
    assert _pv(dict(s, min_items=1), []) == SZ and _pv(dict(s, min_items=1), ["a"]) is None
    assert _pv(dict(s, max_items=2), ["a", "b", "c"]) == SZ and _pv(dict(s, max_items=2), ["a", "b"]) is None
    a = {"type": "array"}
    assert _pv(a, "x") == _bt("expected an array")
    assert _pv(a, [5]) == _bt("array items must be strings of at most 1024 UTF-8 bytes")
    assert _pv(dict(a, max_len=2), ["abc"]) == _bt("array items must be strings of at most 2 UTF-8 bytes")
    assert _pv(dict(a, max_len=2), ["ab", ""]) is None
    assert _pv(dict(a, min=10), ["a"]) is None  # min / max apply to integer items only
    ai = {"type": "array", "items": "integer"}
    assert _pv(ai, ["1"]) == _bt("array items must be safe integers") and _pv(ai, [True]) == _bt("array items must be safe integers")
    assert _pv(dict(ai, min=0, max=5), [0, 5]) is None
    assert _pv(dict(ai, min=0, max=5), [-1]) == _od("array item outside min/max")
    assert _pv(dict(ai, min=0, max=5), [6]) == _od("array item outside min/max")
    assert _pv(dict(ai, max=5), [6]) == _od("array item outside min/max") and _pv(dict(ai, max=5), [-9]) is None
    assert _pv(dict(ai, min=0), [-1]) == _od("array item outside min/max") and _pv(dict(ai, min=0), [99]) is None
    L = _od("array length outside the declared bounds")
    assert _pv(a, ["a"] * 64) is None and _pv(a, ["a"] * 65) == L
    assert _pv(dict(a, min_items=2), ["a"]) == L and _pv(dict(a, min_items=2), ["a", "b"]) is None
    assert _pv(dict(a, max_items=1), ["a", "b"]) == L
    assert _pv({"type": "nope"}, 1) == _bt("unknown declared type") and _pv({}, 1) == _bt("unknown declared type")
    try:
        _pv(None, 1)  # TS: null.max_len throws
        raise AssertionError("a null declaration must raise")
    except TypeError:
        pass


# ---- _model_rules (rules 20 / 21 and the grant pin) and _schema_step v2 ------------------------------------------------

ACTION = {"verb": "v", "resource": "r", "params": {}}


def _mr(monkeypatch, env, ctx=None, out=None, grant=None, tighten=None, paths=False, units=None):
    calls = {}
    monkeypatch.setattr(AZ, "read_envelope", lambda g: env)
    monkeypatch.setattr(V2, "model_paths_read", lambda preds, single: paths)

    def ft(inp):
        calls["tighten"] = inp
        return tighten if tighten is not None else {"legacy": False, "outcome": "ok"}

    def fu(inp):
        calls["units"] = inp
        return units if units is not None else {"ok": True}
    monkeypatch.setattr(V2, "decide_tighten", ft)
    monkeypatch.setattr(V2, "decide_units", fu)
    ran = []

    def run(name, f):
        r = f()
        ran.append((name, r))
        return r
    out = {} if out is None else out
    V2._model_rules(out, {}, grant if grant is not None else {}, ctx, run, ACTION)
    return ran, out, calls


def test_allow_side_predicates():
    assert V2._allow_side_predicates(None, None) == [None]
    assert V2._allow_side_predicates({"predicates": [1]}, None) == [[1]]
    assert V2._allow_side_predicates({}, {"layers": {"org": {"predicates": [2]}, "site": 5, "std": {}}}) == [None, [2], None, None]
    assert V2._allow_side_predicates({"predicates": [1]}, {"layers": {"std": {"predicates": [3]}}}) == [[1], None, None, [3]]


def test_model_rules_nothing_reported(monkeypatch):
    assert _mr(monkeypatch, None)[0] == []
    assert _mr(monkeypatch, {})[0] == []
    assert _mr(monkeypatch, {"predicates": []}, ctx={"policy": {}})[0] == []


def test_model_rules_tighten(monkeypatch):
    base = {"predicates": [None], "single_source": [], "context": {"action": ACTION, "env": {}}}
    ran, out, calls = _mr(monkeypatch, {"tighten": "T"}, tighten={"legacy": False, "outcome": "refuse"})
    assert ran == [("tighten", {"ok": False, "reason": "refused"})]
    assert calls["tighten"] == dict(base, tighten="T") and "legacy_model_polarity" not in out
    ran, out, _ = _mr(monkeypatch, {"tighten": "T"}, tighten={"legacy": True, "outcome": "ok"})
    assert ran == [("tighten", {"ok": True})] and out["legacy_model_polarity"] is True
    ran, _, _ = _mr(monkeypatch, {"tighten": "T"}, tighten={"legacy": False, "outcome": "deny", "reason": "why"})
    assert ran == [("tighten", {"ok": False, "reason": "why"})]
    ran, _, calls = _mr(monkeypatch, None, paths=True)
    assert ran == [("tighten", {"ok": True})] and calls["tighten"] == base
    ran, _, calls = _mr(monkeypatch, {"model_polarity": "legacy"})
    assert calls["tighten"] == dict(base, polarity="legacy")
    ran, _, calls = _mr(monkeypatch, {"model_polarity": "legacy"}, ctx={"policy": {"model_polarity": "strict"}})
    assert [n for n, _ in ran] == ["tighten"] and calls["tighten"] == base
    ran, _, calls = _mr(monkeypatch, {}, ctx={"policy": {"model_polarity": "strict"}})
    assert [n for n, _ in ran] == ["tighten"] and calls["tighten"] == base
    ran, _, calls = _mr(monkeypatch, {"model_polarity": "x"}, ctx={"policy": {"model_polarity": "legacy"}})
    assert calls["tighten"] == dict(base, polarity="legacy")
    ran, _, calls = _mr(monkeypatch, {"tighten": "T"}, ctx={"env": {"a": 1, "b": 1}, "layers": {"org": {"predicates": [7]}}},
                        out={"env": {"b": 2}, "single_source": ["s"]})
    assert calls["tighten"] == {"predicates": [None, [7], None, None], "single_source": ["s"], "tighten": "T",
                                "context": {"action": ACTION, "env": {"a": 1, "b": 2}}}
    _, _, calls = _mr(monkeypatch, {"tighten": "T"}, ctx={"env": "x"}, out={"single_source": None})
    assert calls["tighten"] == dict(base, tighten="T")


def test_model_rules_units(monkeypatch):
    doc = {"verbs": [{"verb": "v", "params": {"p": 1}}], "units": {"u": 1}}
    ran, _, calls = _mr(monkeypatch, {"units": "U"}, out={"schema": doc}, units={"ok": False, "reason": "why"})
    assert ran == [("units", {"ok": False, "reason": "why"})]
    assert calls["units"] == {"units": "U", "verb": "v", "predicates": [None], "schema_units": {"u": 1}, "verb_params": {"p": 1}}
    ran, _, calls = _mr(monkeypatch, {"units": "U"}, out={"schema": {"verbs": [{"verb": "w"}], "units": None}})
    assert ran == [("units", {"ok": True})]
    assert calls["units"] == {"units": "U", "verb": "v", "predicates": [None], "schema_units": None}
    _, _, calls = _mr(monkeypatch, {"units": "U"}, out={"schema": {"verbs": [{"verb": "v"}]}})
    assert calls["units"] == {"units": "U", "verb": "v", "predicates": [None]}
    monkeypatch.setattr(V2, "_schema_step", lambda p, ctx: {"ok": False, "reason": "s"})
    ran, _, calls = _mr(monkeypatch, {"units": "U"})
    assert ran == [("units", {"ok": False, "reason": "s"})] and "units" not in calls
    monkeypatch.setattr(V2, "_schema_step", lambda p, ctx: {"ok": True, "doc": doc})
    _, _, calls = _mr(monkeypatch, {"units": "U"})
    assert calls["units"]["verb_params"] == {"p": 1}


def test_model_rules_pin(monkeypatch):
    """intent-v2.ts modelRules 'pin' (fail-open fix: the Python verifier ignored a grant's action pin)."""
    seen = []

    def fake(ret):
        def f(i):
            seen.append(i)
            return ret
        return f
    doc = {"verbs": []}
    monkeypatch.setattr(AR, "decide_pin", fake({"ok": True, "via": "exact"}))
    ran, _, _ = _mr(monkeypatch, {"actions": "PIN"}, out={"schema": doc}, grant={"id": "g", "issuer": "i"},
                    ctx={"actions": {"records": [1], "keys": None}})
    assert ran == [("pin", {"ok": True})]
    assert seen[-1] == {"pin": "PIN", "doc": doc, "verb": "v", "records": [1], "keys": [], "reapprovals": [],
                        "grant": {"id": "g", "issuer": "i"}}
    monkeypatch.setattr(AR, "decide_pin", fake({"ok": False, "code": "def_changed", "escalate": False, "reason": "r",
                                                "needs_reapproval": "D"}))
    ran, _, _ = _mr(monkeypatch, {"actions": "PIN"}, out={"schema": doc})
    assert ran == [("pin", {"ok": False, "reason": "def_changed: r (re-approve diff D)"})]
    monkeypatch.setattr(AR, "decide_pin", fake({"ok": False, "code": "new_action", "escalate": True, "reason": "r"}))
    ran, _, _ = _mr(monkeypatch, {"actions": "PIN", "units": "U"}, out={"schema": doc})
    assert ran == [("pin", {"ok": False, "reason": "escalate: new_action: r"}), ("units", {"ok": True})]
    n = len(seen)
    monkeypatch.setattr(V2, "_schema_step", lambda p, ctx: {"ok": False, "reason": "s"})
    ran, _, _ = _mr(monkeypatch, {"actions": "PIN"})
    assert ran == [("pin", {"ok": False, "reason": "s"})] and len(seen) == n


def test_model_rules_pin_real_decide_pin_fails_closed(monkeypatch):
    ran, _, _ = _mr(monkeypatch, {"actions": {}}, out={"schema": {"verbs": [{"verb": "v"}]}})
    assert len(ran) == 1 and ran[0][0] == "pin" and ran[0][1]["ok"] is False
    assert ran[0][1]["reason"].startswith("bad_pin: ")


