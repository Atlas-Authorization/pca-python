"""Mutation kills (Intent Layer v2 W-B): rules 16 (decide_intent_world + the offer set), 17 (decide_param_provenance + label
receipts + flow rules), 18 (decide_classifier_dimensions) and their composition decide_intent_wb in atlas_pca/intent_wb.py.
Self-contained: facts, offer sets, label receipts and classifier verdicts are signed here with a tiny RFC 8032 signer over
the verifier's own curve arithmetic (the M2 kill-test pattern), so every assertion is an exact verdict / reason / value.
Every boundary is pinned on both sides and the first-failure ORDER is pinned with inputs that fail two steps."""
import copy
import hashlib

from atlas_pca import ed25519 as E
from atlas_pca.intent_wb import (
    DEFAULT_WORLD_SKEW_MS, FACT_DOMAIN, FACT_REF_DOMAIN, INTENT_CLASSIFIER_DOMAIN, INTENT_CLASSIFIER_REF_DOMAIN,
    LABEL_REF_PREFIX, LABELS_DOMAIN, LABELS_REF_DOMAIN, MAX_CLASSIFIER_LABELS, MAX_COMMITTED_CLASSES,
    MAX_COMMITTED_FACTS, MAX_COMMITTED_LABELS, MAX_LABEL_FIELDS, MAX_OFFER_ATTRS, MAX_OFFERS, MAX_PROV_PATHS,
    MAX_PROV_REFS, MAX_QUERY_KEYS, MAX_RELATIONAL, MAX_WORLDS, OFFER_SET_DOMAIN, OFFER_SET_REF_DOMAIN, PUBLIC_CLASS,
    artifact_message, classifier_check_active, classifier_content_digest, classifier_verdict_ref,
    decide_classifier_dimensions, decide_intent_wb, decide_intent_world, decide_param_provenance, fact_ref,
    flow_allowed, flow_rule_for, intent_provenance_active, intent_wb_active, intent_world_active, is_param_path, is_prov_path, label_receipt_ref, lower_median,
    offer_set_ref, parse_label_ref, ratio_ppm, resolve_param_path, scalar_eq, validate_fact_wire,
    validate_classifier_verdict_wire, validate_labels_wire, validate_offer_set_wire, value_digest,
)
from atlas_pca.intent_wb import (
    UNSUPPORTED_SUITE, artifact_suite_error, decide_read_purpose, intent_wb_context_error, validate_wb_context,
)
from atlas_pca.pca import b64u, hash_canonical, sha256, suite_available

_ABSENT = object()  # test marker: delete the member


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


def _signed(domain, body, k):
    return dict(body, sig=b64u(_sign(k, artifact_message(domain, body))))


def _d(label):
    return b64u(sha256(label.encode()))


NOW = 1_800_000_000_000
AUD = "skyair.example"
SESSION = _d("wb/session")
OTHER_SESSION = _d("wb/other-session")
MAX_SAFE = 9_007_199_254_740_991
O = [_keys("wbk/oracle-%d" % i) for i in range(1, 5)]
ROGUE = _keys("wbk/rogue")
SITE = _keys("wbk/site")
GOV = _keys("wbk/gov")
J = [_keys("wbk/judge-%d" % i) for i in range(1, 4)]
ACTION = {"verb": "air.book", "resource": "skyair.example/bookings",
          "params": {"offer_id": "OF-2", "total": 77_800, "quote": 38_900, "pax": 2}}


# ---- rule 16 fixtures -----------------------------------------------------------------------------------------------

def fact(i, value, t_obs=NOW - 1_000, subject="OF-2", kid=None, key=None, name="fare"):
    body = {"v": 1, "kind": "pca-fact", "name": name, "subject": subject, "value": value, "t_obs": t_obs,
            "oracle": kid or "o%d" % (i + 1)}
    return _signed(FACT_DOMAIN, body, key or O[i])


def oracles(n=3):
    return [{"kid": "o%d" % (i + 1), "pk": _pub(O[i])} for i in range(n)]


def fare_world(**over):
    w = {"name": "fare", "subject_path": "action.params.offer_id", "oracles": oracles(), "freshness_ms": 60_000,
         "min_oracles": 3, "max_faulty": 1}
    w.update(over)
    return w


def W(fs, policy, **over):  # `fs` (not `facts`): a caller may override the input member facts=...
    i = {"now": NOW, "aud": AUD, "session": SESSION, "action": copy.deepcopy(ACTION),
         "committed": {"facts": [fact_ref(f) for f in fs]}, "facts": fs, "policy": policy}
    i.update(over)
    return i


def three():
    return [fact(0, 39_800), fact(1, 39_900), fact(2, 1)]


def with_params(**p):
    a = copy.deepcopy(ACTION)
    a["params"].update(p)
    return a


def ok_world(r):
    assert r["ok"] is True, r
    return r["world"]


def reason(r):
    assert r.get("ok") is False or r.get("outcome") == "deny", r
    return r["reason"]


# ---- constants and helpers ------------------------------------------------------------------------------------------

def test_constants_pinned():
    assert FACT_DOMAIN == "atlas-pca/fact/v1\x00" and FACT_REF_DOMAIN == "atlas-pca/fact-ref/v1"
    assert OFFER_SET_DOMAIN == "atlas-pca/offer-set/v1\x00" and OFFER_SET_REF_DOMAIN == "atlas-pca/offer-set-ref/v1"
    assert LABELS_DOMAIN == "atlas-pca/labels/v1\x00" and LABELS_REF_DOMAIN == "atlas-pca/labels-ref/v1"
    assert INTENT_CLASSIFIER_DOMAIN == "atlas-pca/intent-classifier/v1\x00"
    assert INTENT_CLASSIFIER_REF_DOMAIN == "atlas-pca/intent-classifier-ref/v1"
    assert (MAX_COMMITTED_FACTS, MAX_WORLDS, MAX_RELATIONAL, DEFAULT_WORLD_SKEW_MS) == (16, 16, 16, 60_000)
    assert (MAX_OFFERS, MAX_OFFER_ATTRS, MAX_QUERY_KEYS) == (256, 32, 32)
    assert (MAX_LABEL_FIELDS, MAX_PROV_PATHS, MAX_PROV_REFS, MAX_COMMITTED_LABELS) == (64, 32, 8, 16)
    assert (MAX_COMMITTED_CLASSES, MAX_CLASSIFIER_LABELS) == (8, 32)
    assert LABEL_REF_PREFIX == "pca-labels:" and PUBLIC_CLASS == "public"


def test_refs_are_domain_separated_content_addresses():
    f = fact(0, 5)
    assert fact_ref(f) == b64u(hashlib.sha256(
        ('{"d":"atlas-pca/fact-ref/v1","f":' + _canon(f) + "}").encode()).digest())
    assert fact_ref(f) == hash_canonical({"d": "atlas-pca/fact-ref/v1", "f": f})
    assert offer_set_ref({"x": 1}) == hash_canonical({"d": "atlas-pca/offer-set-ref/v1", "o": {"x": 1}})
    assert label_receipt_ref({"x": 1}) == hash_canonical({"d": "atlas-pca/labels-ref/v1", "l": {"x": 1}})
    assert classifier_verdict_ref({"x": 1}) == hash_canonical({"d": "atlas-pca/intent-classifier-ref/v1", "c": {"x": 1}})
    assert value_digest({"b": 1, "a": [2]}) == hash_canonical({"a": [2], "b": 1}) == classifier_content_digest({"a": [2], "b": 1})
    # the reference covers the signature
    g = dict(f, sig=fact(0, 6)["sig"])
    assert fact_ref(g) != fact_ref(f)


def _canon(v):
    from atlas_pca.pca import canonicalize_strict
    return canonicalize_strict(v)


def test_artifact_message_excludes_sig():
    body = {"b": 1, "a": "x"}
    assert artifact_message("dom\x00", dict(body, sig="zz")) == b"dom\x00" + b'{"a":"x","b":1}'


def test_lower_median_and_ratio_exact():
    assert lower_median([3]) == 3
    assert lower_median([40, 10, 30, 20]) == 20  # index floor(3/2) = 1, never the upper median 30
    assert lower_median([5, 1, 9]) == 5
    assert lower_median([2, 1]) == 1
    assert ratio_ppm(0, 1) == 0
    assert ratio_ppm(1, 3) == 333_333  # floor, not round
    assert ratio_ppm(2, 3) == 666_666
    assert ratio_ppm(5, 0) is None
    assert ratio_ppm(5, -1) is None
    assert ratio_ppm(-1, 5) is None
    assert ratio_ppm(MAX_SAFE, 1_000_000) == MAX_SAFE  # exactly the safe maximum
    assert ratio_ppm(MAX_SAFE, 999_999) is None  # one past it
    # exact (BigInt) arithmetic: a binary64 product would give ...292
    assert ratio_ppm(9_007_199_254_738_991, 1_000_003) == 9_007_172_233_222_291


def test_scalar_eq_typed():
    assert scalar_eq(2, 2.0) and scalar_eq("a", "a") and scalar_eq(True, True)
    assert not scalar_eq(2, "2") and not scalar_eq(True, 1) and not scalar_eq(1, True) and not scalar_eq(False, 0)
    assert not scalar_eq("1", 1) and not scalar_eq(None, 0) and scalar_eq(None, None)


def test_param_path_resolution_and_shape():
    p = {"a": {"b": 1}, "x-y": 2, "__proto__": 3, "constructor": 4}
    assert resolve_param_path(p, "action.params.a.b") == {"found": True, "value": 1}
    assert resolve_param_path(p, "action.params.a") == {"found": True, "value": {"b": 1}}
    assert resolve_param_path(p, "action.params.x-y") == {"found": True, "value": 2}
    assert resolve_param_path(p, "action.params.__proto__") == {"found": False}
    assert resolve_param_path(p, "action.params.constructor") == {"found": False}
    assert resolve_param_path(p, "action.params.a.c") == {"found": False}
    assert resolve_param_path(p, "action.params.a.b.c") == {"found": False}  # 1 is not an object
    assert resolve_param_path(p, "action.params.") == {"found": False}
    assert resolve_param_path(p, "action.paramsa") == {"found": False}
    assert resolve_param_path({"k" * 64: 1}, "action.params." + "k" * 64)["found"] is True
    assert resolve_param_path({"k" * 65: 1}, "action.params." + "k" * 65)["found"] is False
    assert resolve_param_path({"a\n": 1}, "action.params.a\n")["found"] is False
    assert is_param_path("action.params." + ".".join(["s"] * 8)) is True
    assert is_param_path("action.params." + ".".join(["s"] * 9)) is False
    assert is_param_path("action.params.a..b") is False
    assert is_param_path("action.params.prototype") is False
    assert is_param_path(5) is False


# ---- rule 16: successes and boundaries ------------------------------------------------------------------------------

def test_world_empty_and_inactive():
    r = decide_intent_world({"now": NOW, "aud": AUD, "session": SESSION, "action": ACTION, "committed": {}, "policy": {}})
    assert r == {"ok": True, "world": {}, "single_source": []}
    assert intent_world_active({"committed": {}, "policy": {}}) is False
    assert intent_world_active({"committed": {"facts": []}, "policy": {"worlds": [], "relational": []}}) is False
    assert intent_world_active({"committed": {"facts": ["x"]}, "policy": {}}) is True
    # strict typing: offer_set must be a STRING, worlds / relational non-empty ARRAYS, offers a plain OBJECT
    assert intent_world_active({"committed": {"offer_set": "x"}, "policy": {}}) is True
    assert intent_world_active({"committed": {"offer_set": ""}, "policy": {}}) is True
    for os_ in (None, 5, {"length": 43}, ["x"]):
        assert intent_world_active({"committed": {"offer_set": os_}, "policy": {}}) is False, os_
    assert intent_world_active({"committed": {}, "policy": {"worlds": [{}]}}) is True
    assert intent_world_active({"committed": {}, "policy": {"relational": [{}]}}) is True
    assert intent_world_active({"committed": {}, "policy": {"offers": {}}}) is True
    for off in (None, [], [{}], "x", 1):
        assert intent_world_active({"committed": {}, "policy": {"offers": off}}) is False, off
    for obj in ({}, {"length": 2}, {"0": {}, "length": 1}, "ab"):
        assert intent_world_active({"committed": {"facts": obj}, "policy": {"worlds": obj, "relational": obj}}) is False, obj
    assert intent_world_active({"committed": None, "policy": None}) is False


def test_world_median_variants():
    assert ok_world(decide_intent_world(W(three(), {"worlds": [fare_world()]}))) == {"fare": 39_800}
    pol = {"worlds": [fare_world(oracles=oracles(4), min_oracles=4)]}
    fs = [fact(0, 40), fact(1, 10), fact(2, 30), fact(3, 20)]
    assert ok_world(decide_intent_world(W(fs, pol))) == {"fare": 20}
    r = decide_intent_world(W([fact(0, 5)], {"worlds": [fare_world(min_oracles=1, max_faulty=0)]}))
    assert r == {"ok": True, "world": {"fare": 5}, "single_source": ["fare"]}
    r = decide_intent_world(W([fact(0, "gold"), fact(1, "gold"), fact(2, "gold")], {"worlds": [fare_world()]}))
    assert r == {"ok": True, "world": {"fare": "gold"}, "single_source": []}


def test_world_freshness_inclusive_bounds():
    pol = {"worlds": [fare_world()]}
    fs = [fact(0, 5, NOW - 60_000), fact(1, 6, NOW + 60_000), fact(2, 7)]
    assert ok_world(decide_intent_world(W(fs, pol))) == {"fare": 6}
    fs = [fact(0, 5, NOW - 60_001), fact(1, 6, NOW + 60_000), fact(2, 7)]
    assert reason(decide_intent_world(W(fs, pol))) == "facts: world 'fare' has 2 fresh fact(s), needs 3"
    fs = [fact(0, 5, NOW - 60_000), fact(1, 6, NOW + 60_001), fact(2, 7)]
    assert reason(decide_intent_world(W(fs, pol))) == "facts: world 'fare' has 2 fresh fact(s), needs 3"
    # skew 0: t_obs == now is fresh, now + 1 is not
    pol0 = {"skew_ms": 0, "worlds": [fare_world(min_oracles=2, max_faulty=0)]}
    assert ok_world(decide_intent_world(W([fact(0, 5, NOW), fact(1, 9, NOW)], pol0))) == {"fare": 5}
    r = decide_intent_world(W([fact(0, 5, NOW + 1), fact(1, 9, NOW)], pol0))
    assert reason(r) == "facts: world 'fare' has 1 fresh fact(s), needs 2"
    # freshness_ms 0: only now - t_obs <= 0
    pol = {"worlds": [fare_world(freshness_ms=0, min_oracles=1, max_faulty=0)]}
    assert ok_world(decide_intent_world(W([fact(0, 5, NOW)], pol))) == {"fare": 5}
    assert reason(decide_intent_world(W([fact(0, 5, NOW - 1)], pol))) == "facts: world 'fare' has 0 fresh fact(s), needs 1"


def test_world_stale_is_not_an_error_and_min_oracles_edge():
    pol = {"worlds": [fare_world(min_oracles=2, max_faulty=0)]}
    assert ok_world(decide_intent_world(W([fact(0, 5, NOW - 60_001), fact(1, 6), fact(2, 9)], pol))) == {"fare": 6}
    assert reason(decide_intent_world(W([], {"worlds": [fare_world()]}))) == "facts: world 'fare' has 0 fresh fact(s), needs 3"


def test_world_string_and_mixed_values():
    pol = {"worlds": [fare_world()]}
    fs = [fact(0, "gold"), fact(1, "gold"), fact(2, "silver")]
    assert reason(decide_intent_world(W(fs, pol))) == "facts: world 'fare': string facts disagree"
    fs = [fact(0, 1), fact(1, "x"), fact(2, 3)]
    assert reason(decide_intent_world(W(fs, pol))) == "facts: world 'fare': facts mix integer and string values"


def test_world_subject_paths():
    pol = {"worlds": [fare_world(subject_path="action.resource", min_oracles=1, max_faulty=0)]}
    assert ok_world(decide_intent_world(W([fact(0, 5, subject="skyair.example/bookings")], pol))) == {"fare": 5}
    pol = {"worlds": [fare_world(subject_path="action.verb", min_oracles=1, max_faulty=0)]}
    assert ok_world(decide_intent_world(W([fact(0, 5, subject="air.book")], pol))) == {"fare": 5}
    # a non-string subject value never matches
    pol = {"worlds": [fare_world(subject_path="action.params.pax", min_oracles=1, max_faulty=0)]}
    assert reason(decide_intent_world(W([fact(0, 5, subject="2")], pol))) == "facts: a 'fare' fact names another subject"
    pol = {"worlds": [fare_world(subject_path="action.params.nope", min_oracles=1, max_faulty=0)]}
    assert reason(decide_intent_world(W([fact(0, 5)], pol))) == "facts: a 'fare' fact names another subject"


# ---- rule 16: the per-fact checks, in order --------------------------------------------------------------------------

def test_world_fact_checks_and_order():
    pol = {"worlds": [fare_world()]}
    r = decide_intent_world(W([fact(0, 1), fact(1, 2), fact(2, 3, kid="o9")], pol))
    assert reason(r) == "facts: oracle 'o9' is not pinned for world 'fare'"
    r = decide_intent_world(W([fact(0, 1), fact(1, 2), fact(2, 3, key=ROGUE)], pol))
    assert reason(r) == "facts: bad oracle signature on a 'fare' fact"
    r = decide_intent_world(W([fact(0, 1), fact(1, 2), fact(2, 3, subject="OF-1")], pol))
    assert reason(r) == "facts: a 'fare' fact names another subject"
    r = decide_intent_world(W(three() + [fact(0, 5, NOW - 2_000)], pol))
    assert reason(r) == "facts: two facts from oracle 'o1' for world 'fare'"
    r = decide_intent_world(W(three() + [fact(0, "gold", name="tier")], pol))
    assert reason(r) == "facts: fact for undeclared world 'tier'"
    # order inside one fact: unpinned beats bad signature; bad signature beats other subject; subject beats duplicate
    r = decide_intent_world(W([fact(0, 1), fact(1, 2), fact(2, 3, kid="o9", key=ROGUE)], pol))
    assert reason(r) == "facts: oracle 'o9' is not pinned for world 'fare'"
    r = decide_intent_world(W([fact(0, 1), fact(1, 2), fact(2, 3, subject="OF-1", key=ROGUE)], pol))
    assert reason(r) == "facts: bad oracle signature on a 'fare' fact"
    r = decide_intent_world(W(three() + [fact(0, 5, NOW - 2_000, subject="OF-1")], pol))
    assert reason(r) == "facts: a 'fare' fact names another subject"
    # committed order decides which failing fact is reported
    fs = [fact(0, 1, kid="o8"), fact(1, 2, key=ROGUE), fact(2, 3)]
    assert reason(decide_intent_world(W(fs, pol))) == "facts: oracle 'o8' is not pinned for world 'fare'"
    i = W(fs, pol)
    i["committed"]["facts"].reverse()
    assert reason(decide_intent_world(i)) == "facts: bad oracle signature on a 'fare' fact"
    # tampered after signing (the commitment covers the tampered bytes)
    fs = three()
    fs[2] = dict(fs[2], value=39_850)
    assert reason(decide_intent_world(W(fs, pol))) == "facts: bad oracle signature on a 'fare' fact"
    # per-fact failures beat the freshness / count step
    fs = [fact(0, 1, NOW - 999_999), fact(1, 2, key=ROGUE)]
    assert reason(decide_intent_world(W(fs, pol))) == "facts: bad oracle signature on a 'fare' fact"


def test_world_commitments():
    pol = {"worlds": [fare_world()]}
    base = W(three(), pol)
    assert reason(decide_intent_world(dict(base, facts=three()[:2]))) == \
        "facts: a committed fact was not supplied (or is malformed)"
    d0 = fact_ref(three()[0])
    assert reason(decide_intent_world(dict(base, committed={"facts": [d0, d0]}))) == "facts: duplicate committed fact digest"
    assert reason(decide_intent_world(dict(base, committed={"facts": ["abc"]}))) == \
        "facts: a committed fact digest is not canonical base64url (32 bytes)"
    assert reason(decide_intent_world(dict(base, committed={"facts": {}}))) == \
        "facts: committed facts must be a list of at most 16 digests"
    assert reason(decide_intent_world(dict(base, committed={"facts": [d0, "abc", d0]}))) == \
        "facts: a committed fact digest is not canonical base64url (32 bytes)"  # in order: the bad digest comes first
    ds = [_d("c%d" % i) for i in range(16)]
    assert reason(decide_intent_world(dict(base, committed={"facts": ds}))) == \
        "facts: a committed fact was not supplied (or is malformed)"  # 16 passes step 1
    assert reason(decide_intent_world(dict(base, committed={"facts": ds + [_d("c16")]}))) == \
        "facts: committed facts must be a list of at most 16 digests"
    assert reason(decide_intent_world(dict(base, committed={"facts": ["x"] * 17}))) == \
        "facts: committed facts must be a list of at most 16 digests"  # length before content
    assert reason(decide_intent_world(dict(base, committed={"facts": [d0], "offer_set": "abc"}))) == \
        "facts: the committed offer_set is not canonical base64url (32 bytes)"
    assert reason(decide_intent_world(dict(base, committed={"facts": [d0], "offer_set": None}))) == \
        "facts: the committed offer_set is not canonical base64url (32 bytes)"
    # step 1 (facts list) beats step 1 (offer_set) and step 2
    assert reason(decide_intent_world(dict(base, committed={"facts": ["abc"], "offer_set": "abc"}))) == \
        "facts: a committed fact digest is not canonical base64url (32 bytes)"
    # ABSENT VS NULL: absent `committed` / `committed.facts` = {} / []; present null or wrong type fails
    Z = "facts: world 'fare' has 0 fresh fact(s), needs 3"
    assert reason(decide_intent_world(dict(base, committed={}))) == Z
    i = dict(base)
    del i["committed"]
    assert reason(decide_intent_world(i)) == Z
    assert reason(decide_intent_world(dict(base, committed={"facts": None}))) == \
        "facts: committed facts must be a list of at most 16 digests"
    for bad in (None, [], "x", 5):
        assert reason(decide_intent_world(dict(base, committed=bad))) == "facts: committed must be an object", bad


def test_world_supplied_facts_ignored_or_malformed():
    pol = {"worlds": [fare_world()]}
    i = W(three(), pol)
    i["facts"] = three() + [fact(0, 999_999, key=ROGUE), "junk", 7, None]
    assert ok_world(decide_intent_world(i)) == {"fare": 39_800}
    fs = three()
    fs[0] = dict(fs[0], note="x")
    assert reason(decide_intent_world(W(fs, pol))) == "facts: a committed fact was not supplied (or is malformed)"
    bad = fact(0, 1, t_obs=-1)
    assert reason(decide_intent_world(W([bad, fact(1, 2), fact(2, 3)], pol))) == \
        "facts: a committed fact was not supplied (or is malformed)"
    # a lone surrogate has no strict reference: unmatched, never an exception
    lone = dict(fact(0, 1), subject="\ud800")
    i = W([fact(1, 2)], pol)
    i["facts"].append(lone)
    i["committed"]["facts"].append(_d("lone"))
    assert reason(decide_intent_world(i)) == "facts: a committed fact was not supplied (or is malformed)"
    # supplied facts: absent = []; present null or anything but a real array fails (a string is never iterated)
    for v in (_ABSENT, []):
        i = W(three(), pol)
        if v is _ABSENT:
            del i["facts"]
        else:
            i["facts"] = v
        assert reason(decide_intent_world(i)) == "facts: a committed fact was not supplied (or is malformed)", v
    for bad in (None, {"a": 1}, "abc", "", 5, True):
        i = W(three(), pol)
        i["facts"] = bad
        assert reason(decide_intent_world(i)) == "facts: facts must be an array", bad
    # nothing committed: the supplied list is still judged
    i = W([], {})
    i["facts"] = "abc"
    assert reason(decide_intent_world(i)) == "facts: facts must be an array"
    # the step-1 commitment checks come before the supplied-list check
    i = W(three(), pol)
    i["facts"] = None
    i["committed"]["facts"] = ["abc"]
    assert reason(decide_intent_world(i)) == "facts: a committed fact digest is not canonical base64url (32 bytes)"


def test_fact_wire_exact():
    f = fact(0, 5)
    assert validate_fact_wire(f) is None
    assert validate_fact_wire([]) == "fact must be an object"
    assert validate_fact_wire(dict(f, x=1)) == "unknown member 'fact.x'"
    g = dict(f)
    del g["sig"]
    assert validate_fact_wire(g) == "missing member 'fact.sig'"
    assert validate_fact_wire(dict(f, v=True)) == 'fact must be {v: 1, kind: "pca-fact"}'
    assert validate_fact_wire(dict(f, v=1.0)) is None
    assert validate_fact_wire(dict(f, kind="pca-facts")) == 'fact must be {v: 1, kind: "pca-fact"}'
    assert validate_fact_wire(dict(f, name="a" * 64)) is None
    assert validate_fact_wire(dict(f, name="a" * 65)) == "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$"
    assert validate_fact_wire(dict(f, name="fare\n")) == "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$"
    assert validate_fact_wire(dict(f, name="1a")) == "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$"
    assert validate_fact_wire(dict(f, subject="é" * 128)) is None
    assert validate_fact_wire(dict(f, subject="é" * 128 + "a")) == "'fact.subject' must be a non-empty string (<= 256 bytes)"
    assert validate_fact_wire(dict(f, subject="")) == "'fact.subject' must be a non-empty string (<= 256 bytes)"
    for v in (MAX_SAFE, -MAX_SAFE, 0, 5.0, "x" * 256):
        assert validate_fact_wire(dict(f, value=v)) is None, v
    for v in (MAX_SAFE + 1, 1.5, -0.0, True, None, "", "x" * 257, [1]):
        assert validate_fact_wire(dict(f, value=v)) == \
            "'fact.value' must be a safe integer or a non-empty string (<= 256 bytes)", v
    assert validate_fact_wire(dict(f, t_obs=0)) is None
    for t in (-1, -0.0, 1.5, "1", MAX_SAFE + 1):
        assert validate_fact_wire(dict(f, t_obs=t)) == "'fact.t_obs' must be a non-negative safe integer", t
    assert validate_fact_wire(dict(f, oracle="k" * 64)) is None
    assert validate_fact_wire(dict(f, oracle="k" * 65)) == "'fact.oracle' must be a non-empty string (<= 64 bytes)"
    assert validate_fact_wire(dict(f, sig=1)) == "'fact.sig' must be a string"
    # first failure: name before subject
    assert validate_fact_wire(dict(f, name="X", subject="")) == "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$"
    # unknown members are reported in JS key order (array-index keys first)
    assert validate_fact_wire(dict(f, zz=1, **{"7": 1})) == "unknown member 'fact.7'"


# ---- rule 16: policy sanity -----------------------------------------------------------------------------------------

def _pol_reason(policy, facts=()):
    return reason(decide_intent_world(W(list(facts), policy)))


def test_world_policy_sanity():
    P = "facts: policy misconfigured (fail closed): "
    assert _pol_reason([]) == P + "world policy must be an object"
    assert _pol_reason({"skew_ms": -1}) == P + "skew_ms must be a non-negative safe integer"
    assert _pol_reason({"skew_ms": None}) == P + "skew_ms must be a non-negative safe integer"
    assert decide_intent_world(W([], {"skew_ms": 0}))["ok"] is True
    assert _pol_reason({"worlds": [fare_world(name="w%d" % i) for i in range(17)]}) == P + "worlds must be a list of at most 16"
    assert _pol_reason({"worlds": {}}) == P + "worlds must be a list of at most 16"
    sixteen = [fare_world(name="w%d" % i) for i in range(16)]
    assert _pol_reason({"worlds": sixteen}) == "facts: world 'w0' has 0 fresh fact(s), needs 3"
    assert _pol_reason({"worlds": [1]}) == P + "world entry must be an object"
    assert _pol_reason({"worlds": [fare_world(name="Fare")]}) == P + "dimension name 'Fare' must match ^[a-z][a-z0-9_]{0,63}$"
    assert _pol_reason({"worlds": [fare_world(name=5)]}) == P + "dimension name '5' must match ^[a-z][a-z0-9_]{0,63}$"
    w = fare_world()
    del w["name"]
    assert _pol_reason({"worlds": [w]}) == P + "missing member 'world.name'"  # closed member set
    assert _pol_reason({"worlds": [fare_world(), fare_world()]}) == P + "duplicate dimension name 'fare'"
    assert _pol_reason({"worlds": [fare_world(subject_path="params.offer_id")]}) == P + "world 'fare': subject_path must be rooted at action."
    assert _pol_reason({"worlds": [fare_world(freshness_ms=-1)]}) == P + "world 'fare': freshness_ms must be a non-negative safe integer"
    assert _pol_reason({"worlds": [fare_world(max_faulty=-1)]}) == P + "world 'fare': max_faulty must be a non-negative safe integer"
    assert _pol_reason({"worlds": [fare_world(min_oracles=2)]}) == P + "world 'fare': min_oracles must be a safe integer >= 2*max_faulty+1"
    assert _pol_reason({"worlds": [fare_world(min_oracles=1, max_faulty=0)]}) == "facts: world 'fare' has 0 fresh fact(s), needs 1"
    assert _pol_reason({"worlds": [fare_world(min_oracles=0, max_faulty=0)]}) == P + "world 'fare': min_oracles must be a safe integer >= 2*max_faulty+1"
    assert _pol_reason({"worlds": [fare_world(oracles=oracles(2))]}) == P + "world 'fare': fewer pinned oracles than min_oracles"
    dup = oracles() + [{"kid": "o1", "pk": _pub(O[3])}]
    assert _pol_reason({"worlds": [fare_world(oracles=dup)]}) == P + "world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk"
    assert _pol_reason({"worlds": [fare_world(oracles=oracles(2) + [{"kid": "o3", "pk": "abc"}])]}) == \
        P + "world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk"
    assert _pol_reason({"worlds": [fare_world(oracles=oracles(2) + [{"kid": "k" * 65, "pk": _pub(O[2])}])]}) == \
        P + "world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk"
    # check order inside a world: subject_path before freshness before max_faulty before min_oracles
    assert _pol_reason({"worlds": [fare_world(subject_path="x", freshness_ms=-1)]}) == P + "world 'fare': subject_path must be rooted at action."
    assert _pol_reason({"worlds": [fare_world(freshness_ms=-1, max_faulty=-1)]}) == P + "world 'fare': freshness_ms must be a non-negative safe integer"
    # policy sanity beats a malformed commitment
    i = W([], {"skew_ms": -1})
    i["committed"] = {"facts": {}}
    assert reason(decide_intent_world(i)) == P + "skew_ms must be a non-negative safe integer"


def test_relational_policy_sanity():
    P = "facts: policy misconfigured (fail closed): "
    sub = lambda n, a="action.params.total", b="action.params.quote", fn="sub": {"name": n, "fn": fn, "a": a, "b": b}  # noqa: E731
    assert _pol_reason({"relational": [sub("r%d" % i) for i in range(17)]}) == P + "relational must be a list of at most 16"
    assert decide_intent_world(W([], {"relational": [sub("r%d" % i) for i in range(16)]}))["ok"] is True
    assert _pol_reason({"relational": ["x"]}) == P + "relational entry must be an object"
    assert _pol_reason({"relational": [sub("Fare")]}) == P + "dimension name 'Fare' must match ^[a-z][a-z0-9_]{0,63}$"
    assert _pol_reason({"relational": [sub("r", fn="add")]}) == P + "relational 'r': fn must be \"sub\" or \"ratio_ppm\""
    assert _pol_reason({"relational": [sub("a", a="env.world.b"), sub("b")]}) == \
        P + "relational 'a': operand 'env.world.b' must be an action.params path or an earlier env.world dimension"
    assert _pol_reason({"relational": [sub("a", a="env.world.a")]}) == \
        P + "relational 'a': operand 'env.world.a' must be an action.params path or an earlier env.world dimension"
    assert _pol_reason({"relational": [sub("a", b="params.total")]}) == \
        P + "relational 'a': operand 'params.total' must be an action.params path or an earlier env.world dimension"
    assert _pol_reason({"relational": [sub("a", b=None)]}) == \
        P + "relational 'a': operand 'null' must be an action.params path or an earlier env.world dimension"
    assert _pol_reason({"worlds": [fare_world()], "relational": [sub("fare")]}) == P + "duplicate dimension name 'fare'"
    # a relational operand may name a world (worlds are claimed first) or an earlier relational
    pol = {"worlds": [fare_world(min_oracles=1, max_faulty=0)],
           "relational": [sub("a", a="env.world.fare"), sub("b", a="env.world.a", b="env.world.fare")]}
    assert ok_world(decide_intent_world(W([fact(0, 100)], pol))) == {"fare": 100, "a": 100 - 38_900, "b": 100 - 38_900 - 100}


def test_relational_values_and_boundaries():
    def run(rel, **params):
        return decide_intent_world(W([], {"relational": rel}, action=with_params(**params)))

    r = run([{"name": "d", "fn": "sub", "a": "action.params.quote", "b": "action.params.total"}])
    assert ok_world(r) == {"d": -38_900}
    pol = {"worlds": [fare_world(min_oracles=1, max_faulty=0)], "relational": [
        {"name": "excess_vs_quote", "fn": "sub", "a": "action.params.total", "b": "action.params.quote"},
        {"name": "vs_fare", "fn": "sub", "a": "action.params.quote", "b": "env.world.fare"},
        {"name": "ratio", "fn": "ratio_ppm", "a": "action.params.total", "b": "env.world.fare"},
        {"name": "third", "fn": "ratio_ppm", "a": "action.params.pax", "b": "env.world.ratio"}]}
    r = decide_intent_world(W([fact(0, 38_900)], pol))
    assert r == {"ok": True, "world": {"fare": 38_900, "excess_vs_quote": 38_900, "vs_fare": 0, "ratio": 2_000_000, "third": 1},
                 "single_source": ["fare"]}
    assert list(r["world"]) == ["fare", "excess_vs_quote", "vs_fare", "ratio", "third"]
    sub = {"name": "r", "fn": "sub", "a": "action.params.x", "b": "action.params.y"}
    rat = {"name": "r", "fn": "ratio_ppm", "a": "action.params.x", "b": "action.params.y"}
    U = "facts: relational 'r': result undefined or outside the safe integer range"
    M = "facts: relational 'r': an operand is missing or not a safe integer"
    assert ok_world(run([sub], x=MAX_SAFE, y=0)) == {"r": MAX_SAFE}
    assert reason(run([sub], x=MAX_SAFE, y=-1)) == U
    assert ok_world(run([sub], x=-MAX_SAFE, y=0)) == {"r": -MAX_SAFE}
    assert reason(run([sub], x=-MAX_SAFE, y=1)) == U
    assert ok_world(run([rat], x=0, y=5)) == {"r": 0}
    assert reason(run([rat], x=5, y=0)) == U
    assert reason(run([rat], x=-5, y=5)) == U
    assert reason(run([rat], x=5, y=-5)) == U
    assert ok_world(run([rat], x=MAX_SAFE, y=1_000_000)) == {"r": MAX_SAFE}
    assert reason(run([rat], x=MAX_SAFE, y=999_999)) == U
    assert reason(run([rat], x=9_007_199_255, y=1)) == U
    assert ok_world(run([rat], x=9_007_199_254_738_991, y=1_000_003)) == {"r": 9_007_172_233_222_291}
    assert ok_world(run([sub], x=5.0, y=2)) == {"r": 3}
    for bad in ("5", True, None, 1.5, -0.0, MAX_SAFE + 1, [5], {"a": 1}):
        assert reason(run([sub], x=bad, y=1)) == M, bad
    assert reason(run([dict(sub, b="action.params.nope")], x=1)) == M
    # an operand that is an env.world string value is not a safe integer
    pol = {"worlds": [fare_world(min_oracles=1, max_faulty=0)],
           "relational": [{"name": "r", "fn": "sub", "a": "env.world.fare", "b": "action.params.total"}]}
    assert reason(decide_intent_world(W([fact(0, "gold")], pol))) == M
    # relational runs in policy order: the first failing entry is reported
    r = run([dict(rat, name="p", a="action.params.x", b="action.params.y"), dict(sub, name="q", a="action.params.nope")], x=1, y=0)
    assert reason(r) == "facts: relational 'p': result undefined or outside the safe integer range"
    # a world failure is reported before any relational failure
    pol = {"worlds": [fare_world()], "relational": [dict(sub, a="action.params.nope")]}
    assert reason(decide_intent_world(W([], pol))) == "facts: world 'fare' has 0 fresh fact(s), needs 3"


# ---- rule 16 step 6: offer sets -------------------------------------------------------------------------------------

OFFERS = [{"offer_id": "OF-1", "price": 38_900, "stops": 1, "refundable": False},
          {"offer_id": "OF-2", "price": 39_800, "stops": 0, "refundable": False},
          {"offer_id": "OF-3", "price": 41_200, "stops": 0, "refundable": True}]
QUERY = {"from": "SFO", "to": "JFK", "date": "2026-11-20", "pax": 2}


def offer_set(key=SITE, **over):
    body = {"v": 1, "kind": "pca-offer-set", "site": AUD, "session": SESSION, "query": dict(QUERY), "rank": "price_asc",
            "complete": True, "offers": copy.deepcopy(OFFERS), "issued_at": NOW - 10_000, "kid": "skyair-2026"}
    body.update(over)
    return _signed(OFFER_SET_DOMAIN, body, key)


def offer_policy(**over):
    p = {"name": "excess_cents", "site_keys": [{"kid": "skyair-2026", "pk": _pub(SITE)}], "max_age_ms": 600_000,
         "offer_param": "action.params.offer_id", "filter": {"query": dict(QUERY), "offer": {"refundable": False}}}
    p.update(over)
    return p


def OS(os_, policy=None, **over):
    i = {"now": NOW, "aud": AUD, "session": SESSION, "action": copy.deepcopy(ACTION),
         "committed": {"offer_set": offer_set_ref(os_)}, "offer_set": os_, "policy": {"offers": policy or offer_policy()}}
    i.update(over)
    return i


def test_offers_success_and_edges():
    assert ok_world(decide_intent_world(OS(offer_set()))) == {"excess_cents": 900}
    assert ok_world(decide_intent_world(OS(offer_set(), action=with_params(offer_id="OF-1")))) == {"excess_cents": 0}
    assert ok_world(decide_intent_world(OS(offer_set(query={"from": "SFO", "to": "JFK"})))) == {"excess_cents": 900}
    assert ok_world(decide_intent_world(OS(offer_set(query={})))) == {"excess_cents": 900}
    assert ok_world(decide_intent_world(OS(offer_set(issued_at=NOW - 600_000)))) == {"excess_cents": 900}
    assert ok_world(decide_intent_world(OS(offer_set(issued_at=NOW + 60_000)))) == {"excess_cents": 900}
    # empty offer filter: every offer counts for the minimum
    pol = offer_policy(filter={"query": dict(QUERY), "offer": {}})
    assert ok_world(decide_intent_world(OS(offer_set(), pol, action=with_params(offer_id="OF-3")))) == {"excess_cents": 2_300}
    # the offer world comes after worlds and relational
    i = W([fact(0, 38_900)], {"worlds": [fare_world(min_oracles=1, max_faulty=0)],
                              "relational": [{"name": "d", "fn": "sub", "a": "action.params.total", "b": "env.world.fare"}],
                              "offers": offer_policy()})
    os_ = offer_set()
    i["committed"]["offer_set"] = offer_set_ref(os_)
    i["offer_set"] = os_
    r = decide_intent_world(i)
    assert r == {"ok": True, "world": {"fare": 38_900, "d": 38_900, "excess_cents": 900}, "single_source": ["fare"]}
    assert list(r["world"]) == ["fare", "d", "excess_cents"]


def test_offers_refusals_exact():
    def R(i):
        return reason(decide_intent_world(i))
    F = "facts: offers: "
    assert R(OS(offer_set(issued_at=NOW - 600_001))) == F + "the offer set is stale"
    assert R(OS(offer_set(issued_at=NOW + 60_001))) == F + "the offer set is issued in the future"
    assert R(OS(offer_set(query=dict(QUERY, stops=0)))) == F + "the search was narrowed beyond the intent filter (coverage)"
    assert R(OS(offer_set(query=dict(QUERY, date="2026-11-21")))) == F + "the search was narrowed beyond the intent filter (coverage)"
    assert R(OS(offer_set(query=dict(QUERY, pax="2")))) == F + "the search was narrowed beyond the intent filter (coverage)"
    pol = offer_policy(filter={"query": dict(QUERY, flex=1), "offer": {"refundable": False}})
    assert R(OS(offer_set(query=dict(QUERY, flex=True)), pol)) == F + "the search was narrowed beyond the intent filter (coverage)"
    assert R(OS(offer_set(complete=False))) == F + "the offer set is not declared complete"
    assert R(OS(offer_set(kid="other"))) == F + "signing key 'other' is not pinned"
    assert R(OS(offer_set(key=ROGUE))) == F + "bad site signature"
    assert R(OS(offer_set(site="evil.example"))) == F + "the offer set was issued for another audience"
    assert R(OS(offer_set(session=OTHER_SESSION))) == F + "the offer set is bound to another session"
    assert R(OS(offer_set(), action=with_params(offer_id="OF-9"))) == F + "the chosen offer is not in the signed offer set"
    assert R(OS(offer_set(), action=with_params(offer_id="OF-3"))) == F + "the chosen offer does not satisfy the intent filter"
    assert R(OS(offer_set(), action=with_params(offer_id=2))) == F + "the action names no offer id at the declared parameter"
    a = copy.deepcopy(ACTION)
    del a["params"]["offer_id"]
    assert R(OS(offer_set(), action=a)) == F + "the action names no offer id at the declared parameter"
    assert R(dict(OS(offer_set()), committed={})) == F + "the PCActn commits no offer set but the policy requires one"
    i = OS(offer_set())
    del i["offer_set"]
    assert R(i) == F + "the committed offer set was not supplied"
    # a present null offer_set is refused by the input check before the offers rule (oracle-facts.ts)
    assert R(dict(OS(offer_set()), offer_set=None)) == "facts: offer_set must be an object"
    assert R(dict(OS(offer_set()), committed={"offer_set": offer_set_ref(offer_set(issued_at=NOW - 9_000))})) == \
        F + "the supplied offer set does not match the committed reference"
    # an offer filter key the chosen offer lacks: no match
    pol = offer_policy(filter={"query": dict(QUERY), "offer": {"meal": True}})
    assert R(OS(offer_set(), pol)) == F + "the chosen offer does not satisfy the intent filter"
    # typed scalar equality on the offer filter: refundable 0 is not false
    pol = offer_policy(filter={"query": dict(QUERY), "offer": {"refundable": 0}})
    assert R(OS(offer_set(), pol)) == F + "the chosen offer does not satisfy the intent filter"


def test_offers_check_order():
    def R(i):
        return reason(decide_intent_world(i))
    F = "facts: offers: "
    # wire before reference; reference before kid; kid before signature; signature before audience
    assert R(dict(OS(offer_set()), offer_set=dict(offer_set(), rank="x"))) == F + "'offer_set.rank' must be \"price_asc\""
    assert R(dict(OS(offer_set()), committed={"offer_set": offer_set_ref(offer_set(kid="other"))}, offer_set=offer_set(kid="other"))) == \
        F + "signing key 'other' is not pinned"
    assert R(OS(offer_set(kid="other", key=ROGUE, site="evil.example"))) == F + "signing key 'other' is not pinned"
    assert R(OS(offer_set(key=ROGUE, site="evil.example"))) == F + "bad site signature"
    # audience before session before future before stale before complete before coverage before the chosen offer
    assert R(OS(offer_set(site="evil.example", session=OTHER_SESSION))) == F + "the offer set was issued for another audience"
    assert R(OS(offer_set(session=OTHER_SESSION, issued_at=NOW + 60_001))) == F + "the offer set is bound to another session"
    assert R(OS(offer_set(issued_at=NOW - 600_001, complete=False))) == F + "the offer set is stale"
    assert R(OS(offer_set(complete=False, query=dict(QUERY, stops=0)))) == F + "the offer set is not declared complete"
    assert R(OS(offer_set(query=dict(QUERY, stops=0)), action=with_params(offer_id="OF-9"))) == \
        F + "the search was narrowed beyond the intent filter (coverage)"
    # the max_age bound uses the policy, the future bound the world skew
    i = OS(offer_set(issued_at=NOW + 1))
    i["policy"]["skew_ms"] = 0
    assert R(i) == F + "the offer set is issued in the future"
    pol = offer_policy(max_age_ms=0)
    assert ok_world(decide_intent_world(OS(offer_set(issued_at=NOW), pol))) == {"excess_cents": 900}
    assert R(OS(offer_set(issued_at=NOW - 1), pol)) == F + "the offer set is stale"
    # facts are decided before the offer set
    i = OS(offer_set(site="evil.example"))
    i["policy"]["worlds"] = [fare_world()]
    assert R(i) == "facts: world 'fare' has 0 fresh fact(s), needs 3"


def test_offer_set_wire_bounds():
    os_ = offer_set()
    assert validate_offer_set_wire(os_) is None
    W_ = validate_offer_set_wire
    assert W_(dict(os_, query={"k%d" % i: i for i in range(32)})) is None
    assert W_(dict(os_, query={"k%d" % i: i for i in range(33)})) == "'offer_set.query' must be an object with <= 32 keys"
    assert W_(dict(os_, query={"a": {"b": 1}})) == "'offer_set.query.a' must be a scalar"
    assert W_(dict(os_, query={"a": None})) == "'offer_set.query.a' must be a scalar"
    assert W_(dict(os_, query={"k" * 65: 1})) == "'offer_set.query.%s' must be a scalar" % ("k" * 65)
    assert W_(dict(os_, query={"z": [], "5": []})) == "'offer_set.query.5' must be a scalar"  # JS key order
    many = [{"offer_id": "O%d" % i, "price": i} for i in range(256)]
    assert W_(dict(os_, offers=many)) is None
    assert W_(dict(os_, offers=many + [{"offer_id": "X", "price": 1}])) == "'offer_set.offers' must hold 1..256 offers"
    assert W_(dict(os_, offers=[])) == "'offer_set.offers' must hold 1..256 offers"
    attrs = {"a%d" % i: i for i in range(32)}
    assert W_(dict(os_, offers=[dict({"offer_id": "X", "price": 1}, **attrs)])) is None
    assert W_(dict(os_, offers=[dict({"offer_id": "X", "price": 1, "a32": 1}, **attrs)])) == "offer 0: more than 32 attributes"
    assert W_(dict(os_, offers=[OFFERS[0], OFFERS[0]])) == "offer 1: duplicate offer_id"
    assert W_(dict(os_, offers=[{"offer_id": "OF-2", "price": -1}])) == "offer 0: 'price' must be a non-negative safe integer"
    assert W_(dict(os_, offers=[{"offer_id": "OF-2", "price": 0}])) is None
    assert W_(dict(os_, offers=[{"offer_id": "x" * 128, "price": 0}])) is None
    assert W_(dict(os_, offers=[{"offer_id": "x" * 129, "price": 0}])) == "offer 0: 'offer_id' must be a non-empty string (<= 128 bytes)"
    assert W_(dict(os_, offers=[{"offer_id": "OF-2", "price": 1, "x": {"y": 1}}])) == "offer 0: attribute 'x' must be a scalar"
    assert W_(dict(os_, offers=[5])) == "offer 0 must be an object"
    assert W_(dict(os_, rank="price_desc")) == "'offer_set.rank' must be \"price_asc\""
    assert W_(dict(os_, complete=1)) == "'offer_set.complete' must be a boolean"
    assert W_(dict(os_, issued_at=-1)) == "'offer_set.issued_at' must be a non-negative safe integer"
    assert W_(dict(os_, kid="")) == "'offer_set.kid' must be a non-empty string (<= 64 bytes)"
    assert W_(dict(os_, session="abc")) == "'offer_set.session' must be canonical base64url (32 bytes)"
    assert W_(dict(os_, site="s" * 257)) == "'offer_set.site' must be a non-empty string (<= 256 bytes)"
    assert W_(dict(os_, extra=1)) == "unknown member 'offer_set.extra'"


def test_offer_policy_sanity():
    P = "facts: policy misconfigured (fail closed): "
    def R(pol):
        return reason(decide_intent_world(OS(offer_set(), pol)))
    assert R(offer_policy(site_keys=[])) == P + "offers policy needs at least one pinned site key"
    assert R(offer_policy(name=5)) == P + "offers policy needs a name"
    assert R(offer_policy(name="Bad")) == P + "dimension name 'Bad' must match ^[a-z][a-z0-9_]{0,63}$"
    k = {"kid": "skyair-2026", "pk": _pub(SITE)}
    assert R(offer_policy(site_keys=[k, k])) == P + "offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk"
    assert R(offer_policy(max_age_ms=-1)) == P + "offers policy: max_age_ms must be a non-negative safe integer"
    assert R(offer_policy(offer_param="params.offer_id")) == P + "offers policy: offer_param must be an action.params.* path"
    assert R(offer_policy(filter={"query": {}})) == P + "offers policy: filter must be exactly {query: {}, offer: {}}"
    assert R(offer_policy(filter={"query": {}, "offer": {}, "x": {}})) == P + "offers policy: filter must be exactly {query: {}, offer: {}}"
    assert R(dict(offer_policy(), extra=1)) == P + "unknown member 'offers.extra'"
    assert R(offer_policy(site_keys=[{"kid": "skyair-2026", "pk": _pub(SITE), "x": 1}])) == \
        P + "offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk"
    assert R(offer_policy(filter={"query": {"a": [1]}, "offer": {}})) == P + "offers policy: filter values must be scalars"
    assert R(offer_policy(filter={"query": {}, "offer": {"a": None}})) == P + "offers policy: filter values must be scalars"
    i = OS(offer_set())
    i["policy"]["worlds"] = [fare_world(name="excess_cents")]
    assert reason(decide_intent_world(i)) == P + "duplicate dimension name 'excess_cents'"


# ---- rule 17: provenance --------------------------------------------------------------------------------------------

PARAMS = {"offer_id": "OF-1", "payment_ref": "pm_ana_visa", "add_ons": "tripshield", "passport": "X1234567", "note": "hi",
          "pax": {"lead": "px_ana"}}
POLICY = {
    "params": {"action.params.offer_id": "material", "action.params.add_ons": "material",
               "action.params.payment_ref": "critical", "action.params.passport": "critical"},
    "registry": {"skyair:offer_set:1": "first_party", "wallet:profile:ana": "trusted", "web:ad": "web", "tool:fx": "tool",
                 "agent:planner": "agent"},
    "label_keys": [{"site": AUD, "kid": "k1", "pk": _pub(SITE)}, {"site": "gov.example", "kid": "g1", "pk": _pub(GOV)}],
}
CLEAN = {"action.params.offer_id": ["skyair:offer_set:1"], "action.params.payment_ref": ["wallet:profile:ana"],
         "action.params.add_ons": ["wallet:profile:ana"], "action.params.passport": ["wallet:profile:ana"]}
T = {"action.params.add_ons": "trusted", "action.params.offer_id": "first_party", "action.params.passport": "trusted",
     "action.params.payment_ref": "trusted"}


def P(prov_over=None, policy_over=None, **over):
    prov = dict(CLEAN)
    prov.update(prov_over or {})
    pol = copy.deepcopy(POLICY)
    pol.update(policy_over or {})
    i = {"aud": AUD, "session": SESSION, "action": {"params": copy.deepcopy(PARAMS)}, "prov": prov, "policy": pol}
    i.update(over)
    return i


def receipt(site, key, kid, fields, session=SESSION):
    body = {"v": 1, "kind": "pca-labels", "site": site, "session": session, "response_digest": _d("wb/response"),
            "fields": fields, "issued_at": NOW - 5_000, "kid": kid}
    return _signed(LABELS_DOMAIN, body, key)


PASSPORT = receipt(AUD, SITE, "k1", {"travellers[0].passport": {"class": "pii.identity", "value_digest": hash_canonical("X1234567")}})
GOVR = receipt("gov.example", GOV, "g1", {"passport": {"class": "pii.identity", "value_digest": hash_canonical("X1234567")},
                                          "name": {"class": "pii.identity", "value_digest": hash_canonical("Ana")}})


def lref(r, f):
    return "pca-labels:%s#%s" % (label_receipt_ref(r), f)


def with_label(r, f, **policy_over):
    i = P(None, policy_over, committed_labels=[label_receipt_ref(r)], labels=[r])
    i["prov"]["action.params.passport"] = [lref(r, f)]
    return i


def prov(i):
    return decide_param_provenance(i)


def test_prov_pass_and_question_shapes():
    r = prov(P())
    assert r == {"outcome": "pass", "labels": T, "classes": {},
                 "env": {"action": {"params": {"add_ons": "trusted", "offer_id": "first_party", "passport": "trusted",
                                               "payment_ref": "trusted"}}}}
    r = prov(P({"action.params.offer_id": ["skyair:offer_set:1", "web:ad"]}))
    assert r["outcome"] == "question" and r["friction"] == "tap"
    assert r["reason"] == "provenance: a tainted value needs the principal (lazy question)"
    assert r["labels"] == dict(T, **{"action.params.offer_id": "web"})
    assert set(r) == {"outcome", "reason", "friction", "labels", "classes", "env"}


def test_prov_registry_lookup_is_own_and_exact():
    for refs in (["made-up"], ["__proto__", "constructor", "toString"], ["Wallet:profile:ana"], ["wallet:profile:ana "]):
        r = prov(P({"action.params.offer_id": refs}))
        assert r["labels"]["action.params.offer_id"] == "agent", refs
    # the join is the least trusted (highest rank) of the refs
    for refs, want in ((["wallet:profile:ana", "skyair:offer_set:1"], "first_party"), (["tool:fx", "web:ad"], "web"),
                       (["web:ad", "tool:fx", "wallet:profile:ana"], "web"), (["agent:planner", "wallet:profile:ana"], "agent"),
                       (["wallet:profile:ana"] * 8, "trusted")):
        assert prov(P({"action.params.note": refs}))["labels"]["action.params.note"] == want, refs


def test_prov_undeclared_and_free_params():
    i = P()
    del i["prov"]["action.params.payment_ref"]
    r = prov(i)
    assert (r["outcome"], r["friction"], r["labels"]["action.params.payment_ref"]) == ("question", "typed", "agent")
    i = P()
    del i["prov"]  # absent prov = {}
    r = prov(i)
    assert r["labels"] == {k: "agent" for k in T} and r["friction"] == "typed"
    assert reason(prov(dict(P(), prov=None))) == "provenance: 'prov' must be an object"  # present null: malformed
    r = prov(P(None, {"params": dict(POLICY["params"], **{"action.params.seat": "material"})}))
    assert r["outcome"] == "pass" and r["labels"] == T
    r = prov(P({"action.params.note": ["web:ad"]}))
    assert r["outcome"] == "pass" and r["labels"]["action.params.note"] == "web"
    r = prov(P({"action.params.pax": ["wallet:profile:ana"]}))
    assert r["outcome"] == "pass" and r["labels"]["action.params.pax"] == "trusted"


def test_prov_tainted_modes():
    def go(prov_over, pol_over):
        return prov(P(prov_over, pol_over))
    r = go({"action.params.add_ons": ["web:ad"]}, {"material_tainted": "question_typed"})
    assert (r["outcome"], r["friction"]) == ("question", "typed")
    assert go({"action.params.add_ons": ["web:ad"]}, {"material_tainted": "allow"})["outcome"] == "pass"
    r = go({"action.params.add_ons": ["web:ad"]}, {"material_tainted": "deny"})
    assert reason(r) == "provenance: tainted material parameter 'action.params.add_ons' (provenance 'web') is denied by policy"
    r = go({"action.params.payment_ref": ["tool:fx"]}, {"critical_tainted": "question"})
    assert (r["outcome"], r["friction"]) == ("question", "tap")
    r = go({"action.params.payment_ref": ["tool:fx"]}, {})
    assert (r["outcome"], r["friction"]) == ("question", "typed")
    r = go({"action.params.payment_ref": ["tool:fx"]}, {"critical_tainted": "deny"})
    assert reason(r) == "provenance: tainted critical parameter 'action.params.payment_ref' (provenance 'tool') is denied by policy"
    # TAINTED starts at tool (rank 2): first_party (rank 1) never triggers a mode
    assert go({"action.params.payment_ref": ["skyair:offer_set:1"]}, {"critical_tainted": "deny"})["outcome"] == "pass"
    assert go({"action.params.add_ons": ["tool:fx"]}, {"material_tainted": "deny"})["outcome"] == "deny"
    # tap + typed together: typed
    r = go({"action.params.add_ons": ["web:ad"], "action.params.payment_ref": ["tool:fx"]}, {})
    assert (r["outcome"], r["friction"]) == ("question", "typed")
    # a deny on a later path beats a question on an earlier one (the loop does not stop at a question)
    r = go({"action.params.add_ons": ["web:ad"], "action.params.payment_ref": ["tool:fx"]}, {"critical_tainted": "deny"})
    assert reason(r) == "provenance: tainted critical parameter 'action.params.payment_ref' (provenance 'tool') is denied by policy"
    # ascending path order picks the first deny: add_ons < offer_id
    r = go({"action.params.add_ons": ["web:ad"], "action.params.offer_id": ["web:ad"]}, {"material_tainted": "deny"})
    assert reason(r) == "provenance: tainted material parameter 'action.params.add_ons' (provenance 'web') is denied by policy"


def test_prov_critical_max():
    r = prov(P({"action.params.payment_ref": ["tool:fx"]}, {"critical_max": "tool"}))
    assert (r["outcome"], r["friction"]) == ("question", "typed")
    r = prov(P({"action.params.payment_ref": ["tool:fx"]}, {"critical_max": "first_party"}))
    assert reason(r) == ("provenance: critical parameter 'action.params.payment_ref' has provenance 'tool', above the policy "
                         "maximum 'first_party'")
    i = P(None, {"critical_max": "trusted"})
    del i["prov"]["action.params.passport"]
    assert reason(prov(i)) == ("provenance: critical parameter 'action.params.passport' has provenance 'agent', above the "
                               "policy maximum 'trusted'")
    assert prov(P(None, {"critical_max": "trusted"}))["outcome"] == "pass"
    # a material parameter is never capped
    assert prov(P({"action.params.add_ons": ["agent:planner"]}, {"critical_max": "trusted", "material_tainted": "allow"}))["outcome"] == "pass"
    # the cap is checked before the tainted modes
    r = prov(P({"action.params.add_ons": ["web:ad"], "action.params.payment_ref": ["tool:fx"]},
               {"critical_max": "first_party", "material_tainted": "deny"}))
    assert reason(r).startswith("provenance: critical parameter 'action.params.payment_ref'")
    # a deny returns the labels computed so far
    assert r["labels"]["action.params.payment_ref"] == "tool" and r["env"] == {}


def test_prov_label_receipts():
    r = prov(with_label(PASSPORT, "travellers[0].passport"))
    assert r["outcome"] == "pass" and r["labels"]["action.params.passport"] == "first_party"
    assert r["classes"] == {"action.params.passport": ["pii.identity"]}
    i = with_label(PASSPORT, "travellers[0].passport")
    i["action"]["params"]["passport"] = "Y7654321"
    r = prov(i)
    assert r["labels"]["action.params.passport"] == "agent" and r["classes"] == {"action.params.passport": ["pii.identity"]}
    r = prov(with_label(GOVR, "passport", flows={"pii.*": [AUD]}))
    assert r["labels"]["action.params.passport"] == "tool" and (r["outcome"], r["friction"]) == ("question", "typed")
    pub = receipt("gov.example", GOV, "g1", {"passport": {"class": "public", "value_digest": hash_canonical("X1234567")}})
    r = prov(with_label(pub, "passport"))
    assert r["labels"]["action.params.passport"] == "tool" and r["classes"] == {"action.params.passport": ["public"]}
    assert prov(with_label(GOVR, "passport", flows={"*": [AUD]}))["outcome"] == "question"
    i = with_label(PASSPORT, "travellers[0].passport")
    i["prov"]["action.params.passport"] = [lref(PASSPORT, "travellers[0].passport"), "wallet:profile:ana"]
    assert prov(i)["labels"]["action.params.passport"] == "first_party"
    # the field name is split at the FIRST '#'
    hashy = receipt(AUD, SITE, "k1", {"a#b": {"class": "pii.identity", "value_digest": hash_canonical("X1234567")}})
    assert prov(with_label(hashy, "a#b"))["labels"]["action.params.passport"] == "first_party"
    assert parse_label_ref("pca-labels:%s#a#b" % label_receipt_ref(hashy)) == {"receipt": label_receipt_ref(hashy), "field": "a#b"}
    # a structured value: the digest is over its strict canonical form
    st = receipt(AUD, SITE, "k1", {"pax": {"class": "pii.contact", "value_digest": hash_canonical({"lead": "px_ana"})}})
    i = P(None, None, committed_labels=[label_receipt_ref(st)], labels=[st])
    i["prov"]["action.params.pax"] = [lref(st, "pax")]
    r = prov(i)
    assert r["labels"]["action.params.pax"] == "first_party" and r["classes"] == {"action.params.pax": ["pii.contact"]}


def test_labels_wire_bounds():
    vd = hash_canonical("v")
    base = dict(PASSPORT)
    assert validate_labels_wire(base) is None
    f64 = {"f%d" % i: {"class": "pii.x", "value_digest": vd} for i in range(64)}
    assert validate_labels_wire(dict(base, fields=f64)) is None
    f65 = dict(f64, f64={"class": "pii.x", "value_digest": vd})
    assert validate_labels_wire(dict(base, fields=f65)) == "'labels.fields' must hold 1..64 fields"
    assert validate_labels_wire(dict(base, fields={})) == "'labels.fields' must hold 1..64 fields"
    c128 = "a" * 128
    assert validate_labels_wire(dict(base, fields={"f": {"class": c128, "value_digest": vd}})) is None
    assert validate_labels_wire(dict(base, fields={"f": {"class": c128 + "a", "value_digest": vd}})) == "label field 'f': invalid data class"
    for bad in ("Pii", "pii.", ".pii", "pii..x", "pii.X", "pii\n", "1pii"):
        assert validate_labels_wire(dict(base, fields={"f": {"class": bad, "value_digest": vd}})) == "label field 'f': invalid data class", bad
    assert validate_labels_wire(dict(base, fields={"f": {"class": "pii", "value_digest": vd, "x": 1}})) == \
        "label field 'f' must be exactly {class, value_digest}"
    assert validate_labels_wire(dict(base, fields={"f": {"class": "pii", "value_digest": "abc"}})) == \
        "label field 'f': value_digest must be canonical base64url (32 bytes)"
    assert validate_labels_wire(dict(base, fields={"k" * 257: {"class": "pii", "value_digest": vd}})) == \
        "label field paths must be non-empty strings (<= 256 bytes)"
    # fields are reported in JS key order (array-index keys first)
    assert validate_labels_wire(dict(base, fields={"z": {"class": "X", "value_digest": vd}, "3": {"class": "Y", "value_digest": vd}})) == \
        "label field '3': invalid data class"
    assert validate_labels_wire(dict(base, v=2)) == 'label receipt must be {v: 1, kind: "pca-labels"}'
    assert validate_labels_wire(dict(base, response_digest="x")) == "'labels.response_digest' must be canonical base64url (32 bytes)"
    assert validate_labels_wire(dict(base, issued_at=-1)) == "'labels.issued_at' must be a non-negative safe integer"


def test_prov_classes_sorted_deduplicated():
    a = receipt(AUD, SITE, "k1", {"f1": {"class": "pii.zeta", "value_digest": hash_canonical("X1234567")},
                                  "f2": {"class": "pii.alpha", "value_digest": hash_canonical("X1234567")},
                                  "f3": {"class": "pii.zeta", "value_digest": hash_canonical("X1234567")}})
    i = P(None, None, committed_labels=[label_receipt_ref(a)], labels=[a])
    i["prov"]["action.params.passport"] = [lref(a, "f1"), lref(a, "f2"), lref(a, "f3")]
    r = prov(i)
    assert r["classes"] == {"action.params.passport": ["pii.alpha", "pii.zeta"]}


def test_prov_label_refusals_exact():
    D = "provenance: "
    base = with_label(PASSPORT, "travellers[0].passport")
    assert reason(prov(dict(base, committed_labels=[]))) == \
        D + "label ref on 'action.params.passport' names a receipt the PCActn does not commit"
    assert reason(prov(dict(base, labels=[]))) == D + "label receipt for 'action.params.passport' was not supplied"
    bad = receipt(AUD, ROGUE, "k1", PASSPORT["fields"])
    assert reason(prov(with_label(bad, "travellers[0].passport"))) == \
        D + "label receipt for 'action.params.passport': bad label receipt signature"
    unp = receipt(AUD, SITE, "k9", PASSPORT["fields"])
    assert reason(prov(with_label(unp, "travellers[0].passport"))) == \
        D + "label receipt for 'action.params.passport': no pinned label key for site 'skyair.example' kid 'k9'"
    # the pin is per (site, kid): kid g1 under the site skyair.example is not pinned
    cross = receipt(AUD, GOV, "g1", PASSPORT["fields"])
    assert reason(prov(with_label(cross, "travellers[0].passport"))) == \
        D + "label receipt for 'action.params.passport': no pinned label key for site 'skyair.example' kid 'g1'"
    oth = receipt(AUD, SITE, "k1", PASSPORT["fields"], OTHER_SESSION)
    assert reason(prov(with_label(oth, "travellers[0].passport"))) == \
        D + "label receipt for 'action.params.passport' is bound to another session"
    assert reason(prov(with_label(PASSPORT, "travellers[1].passport"))) == \
        D + "label receipt for 'action.params.passport' has no field 'travellers[1].passport'"
    assert reason(prov(P({"action.params.passport": ["pca-labels:abc#passport"]}))) == \
        D + "malformed label ref on 'action.params.passport'"
    i = P({"action.params.passport": ["pca-labels:%s" % label_receipt_ref(PASSPORT)]},
          committed_labels=[label_receipt_ref(PASSPORT)], labels=[PASSPORT])
    assert reason(prov(i)) == D + "malformed label ref on 'action.params.passport'"
    i = P({"action.params.passport": ["pca-labels:%s#" % label_receipt_ref(PASSPORT)]},
          committed_labels=[label_receipt_ref(PASSPORT)], labels=[PASSPORT])
    assert reason(prov(i)) == D + "malformed label ref on 'action.params.passport'"
    # a receipt with an extra member is malformed: it has no reference, so the commitment is unmatched
    x = dict(PASSPORT, note="x")
    i = P(None, None, committed_labels=[label_receipt_ref(x)], labels=[x])
    i["prov"]["action.params.passport"] = [lref(x, "travellers[0].passport")]
    assert reason(prov(i)) == D + "label receipt for 'action.params.passport' was not supplied"
    # order: committed before supplied before signature before session before field
    assert reason(prov(dict(base, committed_labels=[], labels=[]))) == \
        D + "label ref on 'action.params.passport' names a receipt the PCActn does not commit"
    both = receipt(AUD, ROGUE, "k1", PASSPORT["fields"], OTHER_SESSION)
    assert reason(prov(with_label(both, "travellers[1].passport"))) == \
        D + "label receipt for 'action.params.passport': bad label receipt signature"
    oth2 = receipt(AUD, SITE, "k1", PASSPORT["fields"], OTHER_SESSION)
    assert reason(prov(with_label(oth2, "nope"))) == D + "label receipt for 'action.params.passport' is bound to another session"
    # refs in list order: a bad first ref is reported even when a later ref is also bad
    i = P({"action.params.passport": ["pca-labels:abc#x", "pca-labels:%s#y" % _d("zz")]})
    assert reason(prov(i)) == D + "malformed label ref on 'action.params.passport'"


def test_prov_flows():
    D = "provenance: "
    assert reason(prov(with_label(GOVR, "passport"))) == \
        D + "flow: class 'pii.identity' from 'gov.example' may not reach 'skyair.example' (parameter 'action.params.passport')"
    r = prov(with_label(GOVR, "passport", flows={"pii.*": [AUD], "pii.identity": ["elsewhere.example"]}))
    assert reason(r).startswith(D + "flow: class 'pii.identity'")
    assert r["classes"] == {"action.params.passport": ["pii.identity"]}  # classes attached before the flow check fails
    assert prov(with_label(GOVR, "passport", flows={"pii.*": ["elsewhere.example"], "pii.identity": [AUD]}))["outcome"] == "question"
    # the longest prefix wins over a shorter one, and over '*'
    assert prov(with_label(GOVR, "passport", flows={"pii.*": ["x"], "pii.identity.*": ["y"], "*": [AUD]}))["outcome"] == "deny"
    assert prov(with_label(GOVR, "passport", flows={"*": ["x"], "pii.*": [AUD]}))["outcome"] == "question"
    # a flow to the origin is always allowed (the label-first-party case needs no rule)
    assert prov(with_label(PASSPORT, "travellers[0].passport"))["outcome"] == "pass"
    # flows are checked before the critical cap
    r = prov(with_label(GOVR, "passport", critical_max="trusted"))
    assert reason(r).startswith(D + "flow: ")


def test_flow_rule_helpers():
    rules = {"pii.*": ["a"], "pii.identity": ["b"], "*": ["c"], "payment.card.*": ["d"], "payment.*": ["e"]}
    assert flow_rule_for(rules, "pii.identity") == "pii.identity"
    assert flow_rule_for(rules, "pii.contact") == "pii.*"
    assert flow_rule_for(rules, "piix") == "*"  # 'pii.*' keeps the dot: never matches 'piix'
    assert flow_rule_for(rules, "pii") == "*"
    assert flow_rule_for(rules, "payment.card.pan") == "payment.card.*"
    assert flow_rule_for({"pii.*": ["a"]}, "other") is None
    assert flow_allowed({}, "pii.x", "o.example", "o.example") is True
    assert flow_allowed({}, "public", "o.example", "x.example") is True
    assert flow_allowed({}, "pii.x", "o.example", "x.example") is False
    assert flow_allowed({"pii.x": ["x.example"]}, "pii.x", "o.example", "x.example") is True
    assert flow_allowed({"pii.x": []}, "pii.x", "o.example", "x.example") is False


def test_prov_wire_bounds_and_order():
    D = "provenance: "
    params = {"p%d" % i: i for i in range(33)}
    ok = {"aud": AUD, "session": SESSION, "action": {"params": params}, "policy": {"params": {}},
          "prov": {"action.params.p%d" % i: ["x"] for i in range(32)}}
    assert prov(ok)["outcome"] == "pass"  # free params: classified, never gate
    bad = dict(ok, prov={"action.params.p%d" % i: ["x"] for i in range(33)})
    assert reason(prov(bad)) == D + "'prov' holds more than 32 paths"
    assert prov(P({"action.params.note": ["wallet:profile:ana"] * 8}))["outcome"] == "pass"
    assert reason(prov(P({"action.params.offer_id": ["r%d" % i for i in range(9)]}))) == \
        D + "'prov.action.params.offer_id' must hold 1..8 refs"
    assert reason(prov(P({"action.params.offer_id": []}))) == D + "'prov.action.params.offer_id' must hold 1..8 refs"
    assert reason(prov(P({"action.params.offer_id": "x"}))) == D + "'prov.action.params.offer_id' must hold 1..8 refs"
    assert reason(prov(P({"action.params.offer_id": [""]}))) == \
        D + "'prov.action.params.offer_id' refs must be non-empty strings (<= 256 bytes)"
    assert reason(prov(P({"action.params.offer_id": ["x" * 257]}))) == \
        D + "'prov.action.params.offer_id' refs must be non-empty strings (<= 256 bytes)"
    assert prov(P({"action.params.offer_id": ["x" * 256]}))["labels"]["action.params.offer_id"] == "agent"
    assert reason(prov(P({"action.params.offer_id": [5]}))) == \
        D + "'prov.action.params.offer_id' refs must be non-empty strings (<= 256 bytes)"
    K = "'prov' key '%s' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)"
    for k in ("action.params.pax.lead", "action.params.add-ons", "env.world.x", "action.params.__proto__",
              "action.params.constructor", "action.params.prototype", "action.params." + "a" * 65, "action.params.",
              "action.params.a\n"):
        assert reason(prov(P({k: ["wallet:profile:ana"]}))) == D + K % k, k
    long_ = "a" * 64
    i = P({"action.params." + long_: ["wallet:profile:ana"]})
    i["action"]["params"][long_] = 1
    assert prov(i)["outcome"] == "pass"
    assert reason(prov(dict(P(), prov=[]))) == D + "'prov' must be an object"
    assert reason(prov(P({"action.params.seat": ["wallet:profile:ana"]}))) == \
        D + "prov names 'action.params.seat', a parameter the action does not carry"
    # wire is reported in JS key order: an array-index-like key is never a prov key, but ordering still applies
    assert is_prov_path("action.params.x") and not is_prov_path("action.params.x-y")
    # prov wire beats committed labels; committed labels beat "not carried"
    i = P({"action.params.seat": ["x"]}, committed_labels="x")
    assert reason(prov(i)) == D + "committed labels must be a list of at most 16 digests"
    i = P({"action.params.offer_id": []}, committed_labels="x")
    assert reason(prov(i)) == D + "'prov.action.params.offer_id' must hold 1..8 refs"


def test_prov_committed_labels():
    D = "provenance: "
    ds = [_d("l%d" % i) for i in range(16)]
    assert prov(P(committed_labels=ds))["outcome"] == "pass"
    assert reason(prov(P(committed_labels=ds + [_d("l16")]))) == D + "committed labels must be a list of at most 16 digests"
    assert reason(prov(P(committed_labels=[ds[0], ds[0]]))) == D + "committed labels must be distinct canonical 32-byte digests"
    assert reason(prov(P(committed_labels=["abc"]))) == D + "committed labels must be distinct canonical 32-byte digests"
    assert reason(prov(P(committed_labels=None))) == D + "committed labels must be a list of at most 16 digests"
    assert reason(prov(P(committed_labels={}))) == D + "committed labels must be a list of at most 16 digests"
    i = P()
    i.pop("committed_labels", None)
    assert prov(i)["outcome"] == "pass"


def test_prov_optional_members():
    D = "provenance: "
    assert prov(P(labels=[]))["outcome"] == "pass"
    for bad in (None, {"a": 1}, "abc", 5):  # present null / non-array: deny (never iterated)
        assert reason(prov(P(labels=bad))) == D + "labels must be an array", bad
    # action must be an object; absent params = {} (every declared prov path is then "not carried"); null params deny
    NC = D + "prov names 'action.params.add_ons', a parameter the action does not carry"
    assert reason(prov(P(action={}))) == NC
    for a in (None, "x", []):
        assert reason(prov(P(action=a))) == D + "action must be an object", a
    i = P()
    del i["action"]
    assert reason(prov(i)) == D + "action must be an object"
    for pr in (None, [], "x"):
        assert reason(prov(P(action={"params": pr}))) == D + "action.params must be an object", pr
    # order: prov wire, committed labels, action, action.params, labels
    assert reason(prov(P(committed_labels=None, action=None))) == D + "committed labels must be a list of at most 16 digests"
    assert reason(prov(P(action=None, labels=None))) == D + "action must be an object"
    assert reason(prov(P(action={"params": None}, labels=None))) == D + "action.params must be an object"
    assert reason(prov(P({"action.params.seat": ["x"]}, labels=None))) == D + "labels must be an array"
    # optional policy members: absent = default; PRESENT (null included) is validated and a null is a misconfiguration
    PM = D + "policy misconfigured (fail closed): "
    for k, want in (("registry", "registry must be an object"), ("label_keys", "label_keys must be a list"),
                    ("critical_max", "critical_max must be a taint level"),
                    ("material_tainted", "material_tainted must be allow | question | question_typed | deny"),
                    ("critical_tainted", "critical_tainted must be question | question_typed | deny"),
                    ("flows", "flows must be an object")):
        assert reason(prov(P(None, {k: None}))) == PM + want, k
        i = P()
        i["policy"].pop(k, None)
        assert prov(i)["outcome"] in ("pass", "question"), k


def test_prov_policy_sanity():
    D = "provenance: policy misconfigured (fail closed): "
    assert reason(prov(P(None, {"registry": {"x": "super"}}))) == D + "registry entry 'x' must map to a taint level"
    assert reason(prov(P(None, {"registry": {"x": "constructor"}}))) == D + "registry entry 'x' must map to a taint level"
    assert reason(prov(P(None, {"registry": []}))) == D + "registry must be an object"
    assert reason(prov(P(None, {"critical_max": "none"}))) == D + "critical_max must be a taint level"
    assert reason(prov(P(None, {"critical_max": None}))) == D + "critical_max must be a taint level"
    assert reason(prov(P(None, {"critical_tainted": "allow"}))) == D + "critical_tainted must be question | question_typed | deny"
    assert reason(prov(P(None, {"material_tainted": "maybe"}))) == D + "material_tainted must be allow | question | question_typed | deny"
    assert reason(prov(P(None, {"flows": {"PII!": [AUD]}}))) == D + "flow pattern 'PII!' is not a class, a 'prefix.*' or '*'"
    assert reason(prov(P(None, {"flows": {".*": [AUD]}}))) == D + "flow pattern '.*' is not a class, a 'prefix.*' or '*'"
    assert reason(prov(P(None, {"flows": {"pii": AUD}}))) == D + "flow pattern 'pii' needs a list of audiences"
    assert reason(prov(P(None, {"flows": {"pii": [""]}}))) == D + "flow pattern 'pii' needs a list of audiences"
    assert reason(prov(P(None, {"flows": []}))) == D + "flows must be an object"
    assert reason(prov(P(None, {"label_keys": {}}))) == D + "label_keys must be a list"
    assert reason(prov(P(None, {"label_keys": [{"site": AUD, "kid": "k1", "pk": "abc"}]}))) == \
        D + "every label key needs site, kid, a 32-byte pk and an optional string pq_pk"
    assert reason(prov(P(None, {"params": {"env.x": "material"}}))) == D + "policy param 'env.x' is not an action.params path"
    assert reason(prov(P(None, {"params": {"action.params.x": "free"}}))) == \
        D + "policy param 'action.params.x': sensitivity must be material or critical"
    assert reason(prov(P(None, {"params": []}))) == D + "provenance policy needs a params map"
    i = P()
    del i["policy"]
    assert reason(prov(i)) == D + "provenance policy needs a params map"
    # policy sanity beats a malformed prov
    assert reason(prov(dict(P(None, {"critical_max": "none"}), prov=[]))) == D + "critical_max must be a taint level"


def test_prov_env_overlap_through_policy_params():
    pol = dict(POLICY["params"], **{"action.params.pax.lead": "material"})
    i = P({"action.params.pax": ["wallet:profile:ana"]}, {"params": pol})
    r = prov(i)
    assert reason(r) == "provenance: provenance paths overlap at 'action.params.pax.lead'"
    assert r["env"] == {} and r["labels"]["action.params.pax.lead"] == "agent"
    # a nested policy path alone nests into env
    i = P(None, {"params": dict(POLICY["params"], **{"action.params.pax.lead": "material"}), "material_tainted": "allow"})
    r = prov(i)
    assert r["outcome"] == "pass" and r["env"]["action"]["params"]["pax"] == {"lead": "agent"}


# ---- rule 18: classifier verdicts -----------------------------------------------------------------------------------

MESSAGE = "We are sorry for the delay."
TONE = {"id": "tone", "param": "action.params.body", "labels": ["neutral", "apologetic", "hostile", "other"],
        "keys": [_pub(j) for j in J], "k": 2, "measurements": ["m-tone-1"]}


def verdict(j, lbl, **over):  # `lbl` (not `label`): a caller may override the member label=...
    body = {"v": 1, "kind": "pca-intent-classification", "classifier": "tone", "session": SESSION,
            "content_digest": classifier_content_digest(MESSAGE), "label": lbl, "measurement": "m-tone-1"}
    body.update(over)
    body["judge"] = over.get("judge", _pub(j))
    return _signed(INTENT_CLASSIFIER_DOMAIN, body, j)


def C(vs, **policy_over):
    pol = dict(TONE)
    pol.update(policy_over)
    return {"session": SESSION, "action": {"params": {"body": MESSAGE}}, "committed": [classifier_verdict_ref(v) for v in vs],
            "verdicts": vs, "policy": {"classifiers": [pol]}}


def cls(i):
    return decide_classifier_dimensions(i)


def test_classifier_quorum():
    r = cls(C([verdict(J[0], "apologetic"), verdict(J[1], "apologetic"), verdict(J[2], "neutral")]))
    assert r["ok"] is True and r["classes"] == {"tone": "apologetic"}
    assert r["votes"] == {"tone": {"apologetic": 2, "neutral": 1}}
    assert cls(C([verdict(J[0], "neutral")], k=1))["classes"] == {"tone": "neutral"}
    pol = dict(TONE)
    del pol["measurements"]
    i = C([verdict(J[0], "neutral", measurement="anything"), verdict(J[1], "neutral", measurement="else")])
    i["policy"]["classifiers"] = [pol]
    assert cls(i)["classes"] == {"tone": "neutral"}
    assert cls({"session": SESSION, "action": {"params": {}}, "committed": [], "verdicts": [], "policy": {"classifiers": []}}) == \
        {"ok": True, "classes": {}, "votes": {}}
    body = {"b": "x", "a": [1, 2]}
    vs = [verdict(j, "neutral", content_digest=classifier_content_digest(body)) for j in J[:2]]
    i = C(vs)
    i["action"] = {"params": {"body": {"a": [1, 2], "b": "x"}}}
    assert cls(i)["classes"] == {"tone": "neutral"}
    # k = |keys| with every judge agreeing
    assert cls(C([verdict(j, "other") for j in J], k=3))["classes"] == {"tone": "other"}


def test_classifier_refusals_exact():
    F = "classes: classifier 'tone': "
    assert reason(cls(C([verdict(J[0], "apologetic"), verdict(J[1], "neutral")]))) == F + "no label reaches the quorum 2"
    assert reason(cls(C([verdict(J[0], "apologetic"), verdict(J[1], "neutral")], k=1))) == F + "ambiguous, 2 labels reach the quorum"
    assert reason(cls(C([verdict(J[0], "apologetic"), verdict(ROGUE, "apologetic")]))) == F + "judge key is not on the allowlist"
    t = dict(verdict(J[1], "apologetic"), label="neutral")
    assert reason(cls(C([verdict(J[0], "neutral"), t]))) == F + "bad verdict signature"
    # a verdict claiming an allowlisted judge but signed by another key
    forged = verdict(ROGUE, "apologetic", judge=_pub(J[1]))
    assert reason(cls(C([forged]))) == F + "bad verdict signature"
    assert reason(cls(C([verdict(J[0], "apologetic"), verdict(J[1], "apologetic", session=OTHER_SESSION)]))) == \
        F + "verdict bound to another session"
    assert reason(cls(C([verdict(J[1], "apologetic", content_digest=classifier_content_digest("other text"))]))) == \
        F + "verdict is about other content"
    assert reason(cls(C([verdict(J[1], "sarcastic")]))) == F + "label 'sarcastic' is not in its label set"
    assert reason(cls(C([verdict(J[1], "apologetic", measurement="m-evil")]))) == F + "measurement is not pinned"
    assert reason(cls(C([verdict(J[0], "apologetic"), verdict(J[0], "neutral"), verdict(J[1], "apologetic")]))) == \
        F + "two verdicts from one judge"
    i = C([verdict(J[0], "apologetic"), verdict(J[1], "apologetic")])
    i["action"] = {"params": {}}
    assert reason(cls(i)) == F + "the action carries no 'action.params.body'"
    assert reason(cls(C([verdict(J[0], "x", classifier="spam")]))) == "classes: verdict for undeclared classifier 'spam'"
    assert reason(cls(C([]))) == F + "no label reaches the quorum 2"
    # uncommitted verdicts do not vote
    i = C([verdict(J[0], "apologetic"), verdict(J[1], "apologetic")])
    i["committed"] = i["committed"][:1]
    assert reason(cls(i)) == F + "no label reaches the quorum 2"


def test_classifier_check_order():
    F = "classes: classifier 'tone': "
    # allowlist before signature before session before content before label before measurement before double vote
    assert reason(cls(C([verdict(ROGUE, "sarcastic", session=OTHER_SESSION)]))) == F + "judge key is not on the allowlist"
    t = dict(verdict(J[0], "apologetic", session=OTHER_SESSION), label="neutral")
    assert reason(cls(C([t]))) == F + "bad verdict signature"
    assert reason(cls(C([verdict(J[0], "sarcastic", session=OTHER_SESSION)]))) == F + "verdict bound to another session"
    v = verdict(J[0], "sarcastic", content_digest=classifier_content_digest("x"))
    assert reason(cls(C([v]))) == F + "verdict is about other content"
    assert reason(cls(C([verdict(J[0], "sarcastic", measurement="m-evil")]))) == F + "label 'sarcastic' is not in its label set"
    v2 = verdict(J[0], "neutral", measurement="m-evil")
    assert reason(cls(C([verdict(J[0], "apologetic"), v2]))) == F + "measurement is not pinned"
    # committed order decides the reported verdict
    i = C([verdict(J[0], "sarcastic"), verdict(J[1], "apologetic", session=OTHER_SESSION)])
    assert reason(cls(i)) == F + "label 'sarcastic' is not in its label set"
    i["committed"].reverse()
    assert reason(cls(i)) == F + "verdict bound to another session"
    # per-verdict checks before the quorum step
    assert reason(cls(C([verdict(J[0], "sarcastic")], k=1))) == F + "label 'sarcastic' is not in its label set"
    # quorum is evaluated in policy order
    two = {"id": "aaa", "param": "action.params.body", "labels": ["x"], "keys": [_pub(J[0])], "k": 1}
    i = C([verdict(J[0], "apologetic"), verdict(J[1], "apologetic")])
    i["policy"]["classifiers"].insert(0, two)
    assert reason(cls(i)) == "classes: classifier 'aaa': no label reaches the quorum 1"


def test_classifier_commitments_and_wire():
    vs = [verdict(J[0], "apologetic")]
    base = C(vs)
    E_ = "classes: committed verdicts must be distinct canonical 32-byte digests"
    d0 = classifier_verdict_ref(vs[0])
    assert reason(cls(dict(base, committed=[d0, d0]))) == E_
    assert reason(cls(dict(base, committed=["abc"]))) == E_
    ds = [_d("c%d" % i) for i in range(8)]
    assert reason(cls(dict(base, committed=ds))) == "classes: a committed verdict was not supplied (or is malformed)"
    assert reason(cls(dict(base, committed=ds + [_d("c8")]))) == "classes: committed verdicts must be a list of at most 8 digests"
    assert reason(cls(dict(base, committed={}))) == "classes: committed verdicts must be a list of at most 8 digests"
    x = dict(verdict(J[0], "apologetic"), note="x")
    i = C([x, verdict(J[1], "apologetic")])
    assert reason(cls(i)) == "classes: a committed verdict was not supplied (or is malformed)"
    assert reason(cls(dict(base, verdicts=[]))) == "classes: a committed verdict was not supplied (or is malformed)"
    NS = "classes: a committed verdict was not supplied (or is malformed)"
    for bad in (None, {"a": 1}, "abc", 5):  # present null / non-array: fails (never iterated)
        assert reason(cls(dict(base, verdicts=bad))) == "classes: verdicts must be an array", bad
    i = dict(base)
    del i["verdicts"]  # absent = []
    assert reason(cls(i)) == NS
    Q = "classes: classifier 'tone': no label reaches the quorum 2"
    assert reason(cls(dict(base, committed=None))) == "classes: committed verdicts must be a list of at most 8 digests"
    i = dict(base)
    del i["committed"]  # absent = []
    assert reason(cls(i)) == Q
    assert reason(cls(dict(base, committed={}))) == "classes: committed verdicts must be a list of at most 8 digests"
    # action must be an object; absent params = {}; present null params fail
    assert reason(cls(dict(base, action={}))) == "classes: classifier 'tone': the action carries no 'action.params.body'"
    for a in (None, "x", []):
        assert reason(cls(dict(base, action=a))) == "classes: action must be an object", a
    for pr in (None, [], "x"):
        assert reason(cls(dict(base, action={"params": pr}))) == "classes: action.params must be an object", pr
    # order: committed, verdicts, action, action.params
    assert reason(cls(dict(base, committed=None, verdicts=None))) == "classes: committed verdicts must be a list of at most 8 digests"
    assert reason(cls(dict(base, verdicts=None, action=None))) == "classes: verdicts must be an array"
    assert reason(cls(dict(base, action={"params": None}))) == "classes: action.params must be an object"
    # wire bounds
    for over, ok in (({"label": "l" * 64}, True), ({"label": "l" * 65}, False), ({"measurement": "m" * 256}, True),
                     ({"measurement": "m" * 257}, False), ({"classifier": "Tone"}, False), ({"judge": "abc"}, False)):
        v = verdict(J[0], "neutral", **over)
        assert (validate_classifier_verdict_wire(v) is None) is ok, over


def test_classifier_policy_sanity():
    F = "classes: policy misconfigured (fail closed): "
    v = [verdict(J[0], "apologetic")]
    assert reason(cls(C(v, k=4))) == F + "classifier 'tone': k must be an integer in [1, 3]"
    assert reason(cls(C(v, k=0))) == F + "classifier 'tone': k must be an integer in [1, 3]"
    assert reason(cls(C(v, k=1.5))) == F + "classifier 'tone': k must be an integer in [1, 3]"
    assert reason(cls(C(v, labels=["a", "a"]))) == F + "classifier 'tone': labels must be distinct non-empty strings"
    assert reason(cls(C(v, labels=["l" * 65]))) == F + "classifier 'tone': labels must be distinct non-empty strings"
    assert reason(cls(C(v, labels=[]))) == F + "classifier 'tone': labels must hold 1..32 strings"
    assert reason(cls(C(v, labels=["l%d" % i for i in range(33)]))) == F + "classifier 'tone': labels must hold 1..32 strings"
    assert reason(cls(C(v, labels=["l%d" % i for i in range(32)] + []))) == "classes: classifier 'tone': label 'apologetic' is not in its label set"
    assert reason(cls(C(v, keys=[]))) == F + "classifier 'tone': keys must be distinct 32-byte keys"
    assert reason(cls(C(v, keys=[_pub(J[0]), _pub(J[0])]))) == F + "classifier 'tone': keys must be distinct 32-byte keys"
    assert reason(cls(C(v, param="body"))) == F + "classifier 'tone': param must be an action.params path"
    assert reason(cls(C(v, measurements="m"))) == F + "classifier 'tone': measurements must be a list of strings"
    assert reason(cls(C(v, measurements=[1]))) == F + "classifier 'tone': measurements must be a list of strings"
    assert reason(cls(C(v, id="Tone"))) == F + "every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$"
    i = C(v)
    i["policy"]["classifiers"].append(dict(TONE))
    assert reason(cls(i)) == F + "every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$"
    assert reason(cls(dict(C(v), policy={}))) == F + "classifier policy needs a classifiers list"
    # policy sanity beats a malformed commitment
    assert reason(cls(dict(C(v, k=4), committed={}))) == F + "classifier 'tone': k must be an integer in [1, 3]"
    assert classifier_check_active({"committed": [], "policy": {"classifiers": []}}) is False
    assert classifier_check_active({"committed": ["x"], "policy": {"classifiers": []}}) is True
    assert classifier_check_active({"policy": {"classifiers": [{}]}}) is True
    assert classifier_check_active({"committed": {}, "policy": {}}) is False
    assert classifier_check_active({"committed": {"length": 1}, "policy": {"classifiers": {"length": 3}}}) is False
    assert classifier_check_active({"committed": "ab", "policy": {"classifiers": "ab"}}) is False
    assert classifier_check_active({"committed": [], "policy": None}) is False


def test_classifier_proto_named_ids_and_labels_are_ordinary_keys():
    labels = ["constructor", "__proto__", "toString", "valueOf", "hasOwnProperty"]
    pol = {"id": "constructor", "param": "action.params.body", "labels": labels, "keys": [_pub(J[0]), _pub(J[1])], "k": 2}
    for _round in range(2):  # repeatable: no state leaks across calls
        for lab in labels:
            vs = [verdict(j, lab, classifier="constructor", measurement="m") for j in J[:2]]
            i = {"session": SESSION, "action": {"params": {"body": MESSAGE}}, "committed": [classifier_verdict_ref(v) for v in vs],
                 "verdicts": vs, "policy": {"classifiers": [pol]}}
            r = cls(i)
            assert r["ok"] is True and r["classes"] == {"constructor": lab}, lab
            assert r["votes"] == {"constructor": {lab: 2}}
    vs = [verdict(J[0], "toString", classifier="constructor", measurement="m"),
          verdict(J[1], "valueOf", classifier="constructor", measurement="m")]
    i = {"session": SESSION, "action": {"params": {"body": MESSAGE}}, "committed": [classifier_verdict_ref(v) for v in vs],
         "verdicts": vs, "policy": {"classifiers": [pol]}}
    assert reason(cls(i)) == "classes: classifier 'constructor': no label reaches the quorum 2"


def test_proto_named_world_flow_and_field_keys():
    pol = {"worlds": [fare_world(name="constructor", min_oracles=1, max_faulty=0)],
           "relational": [{"name": "valueof", "fn": "sub", "a": "env.world.constructor", "b": "action.params.pax"}]}
    r = decide_intent_world(W([fact(0, 7, name="constructor")], pol))
    assert r == {"ok": True, "world": {"constructor": 7, "valueof": 5}, "single_source": ["constructor"]}
    assert flow_rule_for({}, "constructor") is None
    assert flow_allowed({}, "constructor", "a.example", "b.example") is False
    assert flow_allowed({"constructor": ["b.example"]}, "constructor", "a.example", "b.example") is True
    fr = receipt(AUD, SITE, "k1", {"__proto__": {"class": "pii.identity", "value_digest": hash_canonical("X1234567")}})
    assert prov(with_label(fr, "__proto__"))["labels"]["action.params.passport"] == "first_party"
    assert reason(prov(with_label(fr, "constructor"))) == \
        "provenance: label receipt for 'action.params.passport' has no field 'constructor'"


# ---- composition: decide_intent_wb ----------------------------------------------------------------------------------

def WB(**over):
    i = {"now": NOW, "aud": AUD, "session": SESSION, "action": copy.deepcopy(ACTION), "intent_session": {}, "artifacts": {},
         "policy": {}}
    i.update(over)
    return i


def test_wb_inactive_admits_with_nothing_reported():
    assert decide_intent_wb(WB()) == {"outcome": "admit", "checks": {}, "env": {}}
    i = WB()
    for k in ("artifacts", "policy"):
        del i[k]
    assert decide_intent_wb(i) == {"outcome": "admit", "checks": {}, "env": {}}  # absent artifacts / policy are empty
    # an empty labels list does not activate rule 17; a present prov member does, and a null prov is then refused
    assert decide_intent_wb(WB(intent_session={"labels": []}))["checks"] == {}
    r = decide_intent_wb(WB(intent_session={"prov": None}))
    assert r == {"outcome": "deny", "checks": {"provenance": "fail"}, "env": {}, "reason": "provenance: 'prov' must be an object"}
    r = decide_intent_wb(WB(intent_session={"prov": {}}))
    assert r == {"outcome": "admit", "checks": {"provenance": "pass"}, "env": {"prov": {}}}


def test_wb_context_error_fails_facts():
    def ctx(reason_):
        return {"outcome": "deny", "checks": {"facts": "fail"}, "env": {}, "reason": "facts: the W-B context is malformed: " + reason_}
    i = WB()
    del i["intent_session"]
    assert decide_intent_wb(i) == ctx("intent_session must be an object")  # required
    for v in (None, [], "x"):
        assert decide_intent_wb(WB(intent_session=v)) == ctx("intent_session must be an object"), v
        assert decide_intent_wb(WB(artifacts=v)) == ctx("artifacts must be an object"), v
        assert decide_intent_wb(WB(policy=v)) == ctx("policy must be an object"), v
    for k in ("facts", "labels", "verdicts"):
        for v in (None, {}, "x", 5):
            assert decide_intent_wb(WB(artifacts={k: v})) == ctx("artifacts.%s must be an array" % k), (k, v)
    for v in (None, [], "x"):
        assert decide_intent_wb(WB(artifacts={"offer_set": v})) == ctx("artifacts.offer_set must be an object"), v
        assert decide_intent_wb(WB(policy={"world": v})) == ctx("policy.world must be an object"), v
        assert decide_intent_wb(WB(policy={"provenance": v})) == ctx("policy.provenance must be an object"), v
    for v in (None, {}, "x"):
        assert decide_intent_wb(WB(policy={"classifiers": v})) == ctx("policy.classifiers must be an array"), v
    # the context is checked before activity: even an inactive unit fails on a malformed member
    assert decide_intent_wb(WB(policy={"world": {"offers": None}, "provenance": None})) == ctx("policy.provenance must be an object")
    # order: intent_session, artifacts (facts, labels, verdicts, offer_set), policy (world, provenance, classifiers)
    assert decide_intent_wb(WB(intent_session=None, artifacts=None, policy=None)) == ctx("intent_session must be an object")
    assert decide_intent_wb(WB(artifacts=None, policy=None)) == ctx("artifacts must be an object")
    assert decide_intent_wb(WB(artifacts={"offer_set": None, "verdicts": None, "labels": None})) == ctx("artifacts.labels must be an array")
    assert decide_intent_wb(WB(artifacts={"offer_set": None}, policy=None)) == ctx("artifacts.offer_set must be an object")
    assert decide_intent_wb(WB(policy={"classifiers": None, "provenance": None, "world": None})) == ctx("policy.world must be an object")
    assert decide_intent_wb(WB(policy={"classifiers": None, "provenance": None})) == ctx("policy.provenance must be an object")
    # the helper itself
    assert intent_wb_context_error({"intent_session": {}}) is None
    assert intent_wb_context_error({"intent_session": {}, "artifacts": {"facts": [], "labels": [], "verdicts": [], "offer_set": {}},
                                    "policy": {"world": {}, "provenance": {}, "classifiers": []}}) is None
    assert intent_wb_context_error({}) == "intent_session must be an object"
    assert intent_wb_context_error(None) == "input must be an object"  # intent-env.ts: the input itself first


def test_wb_absent_policy_members_default():
    # absent policy members take their defaults ({}, {params: {}}, [])
    D = _d("x")
    r = decide_intent_wb(WB(intent_session={"facts": [D]}))
    assert r == {"outcome": "deny", "checks": {"facts": "fail"}, "env": {},
                 "reason": "facts: a committed fact was not supplied (or is malformed)"}
    r = decide_intent_wb(WB(intent_session={"prov": {}}))
    assert r == {"outcome": "admit", "checks": {"provenance": "pass"}, "env": {"prov": {}}}
    r = decide_intent_wb(WB(intent_session={"classes": [D]}))
    assert r == {"outcome": "deny", "checks": {"classes": "fail"}, "env": {},
                 "reason": "classes: a committed verdict was not supplied (or is malformed)"}
    # an intent_session member of the wrong type is judged by its rule
    r = decide_intent_wb(WB(intent_session={"facts": [D], "offer_set": None}))
    assert r["reason"] == "facts: the committed offer_set is not canonical base64url (32 bytes)"
    r = decide_intent_wb(WB(intent_session={"prov": {}, "labels": None}))
    assert r["reason"] == "provenance: committed labels must be a list of at most 16 digests"

def test_wb_facts_then_provenance_then_classes():
    fs = [fact(0, 5)]
    pol = {"world": {"worlds": [fare_world(min_oracles=1, max_faulty=0)]}}
    r = decide_intent_wb(WB(intent_session={"facts": [fact_ref(f) for f in fs]}, artifacts={"facts": fs}, policy=pol))
    assert r == {"outcome": "admit", "checks": {"facts": "pass"}, "env": {"world": {"fare": 5}}, "single_source": ["fare"]}
    # two oracles: no single_source key at all
    fs = [fact(0, 5), fact(1, 7)]
    pol2 = {"world": {"worlds": [fare_world(min_oracles=2, max_faulty=0)]}}
    r = decide_intent_wb(WB(intent_session={"facts": [fact_ref(f) for f in fs]}, artifacts={"facts": fs}, policy=pol2))
    assert r == {"outcome": "admit", "checks": {"facts": "pass"}, "env": {"world": {"fare": 5}}}


def test_wb_facts_failure_ends_the_unit():
    pol = {"world": {"worlds": [fare_world()]}, "provenance": {"params": {}}, "classifiers": [dict(TONE)]}
    r = decide_intent_wb(WB(policy=pol))
    assert r == {"outcome": "deny", "checks": {"facts": "fail"}, "env": {},
                 "reason": "facts: world 'fare' has 0 fresh fact(s), needs 3"}


def test_wb_provenance_question_and_classes():
    action = {"verb": "msg.send", "resource": "r", "params": {"body": MESSAGE, "offer_id": "OF-1"}}
    vs = [verdict(J[0], "apologetic"), verdict(J[1], "apologetic")]
    prov_pol = {"params": {"action.params.offer_id": "material"}, "registry": {"web:ad": "web"}}
    s = {"prov": {"action.params.offer_id": ["web:ad"]}, "classes": [classifier_verdict_ref(v) for v in vs]}
    r = decide_intent_wb(WB(action=action, intent_session=s, artifacts={"verdicts": vs},
                            policy={"provenance": prov_pol, "classifiers": [dict(TONE)]}))
    assert r == {"outcome": "question", "checks": {"provenance": "question", "classes": "pass"},
                 "env": {"prov": {"action": {"params": {"offer_id": "web"}}}, "class": {"tone": "apologetic"}},
                 "reason": "provenance: a tainted value needs the principal (lazy question)", "friction": "tap"}
    # a classes failure after a provenance question denies and keeps the question's friction and env.prov
    r = decide_intent_wb(WB(action=action, intent_session=dict(s, classes=s["classes"][:1]), artifacts={"verdicts": vs},
                            policy={"provenance": prov_pol, "classifiers": [dict(TONE)]}))
    assert r == {"outcome": "deny", "checks": {"provenance": "question", "classes": "fail"},
                 "env": {"prov": {"action": {"params": {"offer_id": "web"}}}},
                 "reason": "classes: classifier 'tone': no label reaches the quorum 2", "friction": "tap"}


def test_wb_provenance_deny_keeps_facts():
    fs = [fact(0, 5)]
    s = {"facts": [fact_ref(f) for f in fs], "prov": {"action.params.nope": ["x"]}}
    pol = {"world": {"worlds": [fare_world(min_oracles=1, max_faulty=0)]}, "classifiers": [dict(TONE)]}
    r = decide_intent_wb(WB(intent_session=s, artifacts={"facts": fs}, policy=pol))
    assert r == {"outcome": "deny", "checks": {"facts": "pass", "provenance": "fail"}, "env": {"world": {"fare": 5}},
                 "single_source": ["fare"],
                 "reason": "provenance: prov names 'action.params.nope', a parameter the action does not carry"}
    # absent provenance policy defaults to {params: {}}
    r = decide_intent_wb(WB(intent_session={"prov": {"action.params.total": ["x"]}}))
    assert r == {"outcome": "admit", "checks": {"provenance": "pass"},
                 "env": {"prov": {"action": {"params": {"total": "agent"}}}}}


def test_wb_offer_set_passthrough_and_absence():
    os_ = offer_set()
    pol = {"world": {"offers": offer_policy()}}
    r = decide_intent_wb(WB(intent_session={"offer_set": offer_set_ref(os_)}, artifacts={"offer_set": os_}, policy=pol))
    assert r == {"outcome": "admit", "checks": {"facts": "pass"}, "env": {"world": {"excess_cents": 900}}}
    r = decide_intent_wb(WB(intent_session={"offer_set": offer_set_ref(os_)}, policy=pol))
    assert r["reason"] == "facts: offers: the committed offer set was not supplied"
    r = decide_intent_wb(WB(policy=pol))
    assert r["reason"] == "facts: offers: the PCActn commits no offer set but the policy requires one"
    # a committed offer set activates rule 16 even without a policy (and passes: nothing requires it)
    r = decide_intent_wb(WB(intent_session={"offer_set": offer_set_ref(os_)}))
    assert r == {"outcome": "admit", "checks": {"facts": "pass"}, "env": {"world": {}}}


def test_wb_classes_only_and_total():
    vs = [verdict(J[0], "neutral"), verdict(J[1], "neutral")]
    action = {"verb": "v", "resource": "r", "params": {"body": MESSAGE}}
    r = decide_intent_wb(WB(action=action, intent_session={"classes": [classifier_verdict_ref(v) for v in vs]},
                            artifacts={"verdicts": vs}, policy={"classifiers": [dict(TONE)]}))
    assert r == {"outcome": "admit", "checks": {"classes": "pass"}, "env": {"class": {"tone": "neutral"}}}
    # committed verdicts without a declared classifier: active, refused
    r = decide_intent_wb(WB(action=action, intent_session={"classes": [classifier_verdict_ref(v) for v in vs]},
                            artifacts={"verdicts": vs}))
    assert r["outcome"] == "deny" and r["checks"] == {"classes": "fail"}
    assert r["reason"] == "classes: verdict for undeclared classifier 'tone'"
    # never raises; a non-object input is a malformed context
    r = decide_intent_wb(None)
    assert r == {"outcome": "deny", "checks": {"facts": "fail"}, "env": {},
                 "reason": "facts: the W-B context is malformed: input must be an object"}


# ---- the clock: a non-safe-integer `now` is never coerced -----------------------------------------------------------

def test_clock_non_integer_now_makes_every_fact_stale():
    pol = {"worlds": [fare_world(min_oracles=1, max_faulty=0)]}
    assert ok_world(decide_intent_world(W([fact(0, 5, NOW)], pol))) == {"fare": 5}
    assert ok_world(decide_intent_world(W([fact(0, 5, NOW)], pol, now=float(NOW)))) == {"fare": 5}  # 1.8e12 is the same number
    for now in (str(NOW), NOW + 0.5, None, float("nan"), float("inf"), True, -0.0, MAX_SAFE + 1, [NOW]):
        assert reason(decide_intent_world(W([fact(0, 5, NOW)], pol, now=now))) == \
            "facts: world 'fare' has 0 fresh fact(s), needs 1", now
    i = W([fact(0, 5, NOW)], pol)
    del i["now"]
    assert reason(decide_intent_world(i)) == "facts: world 'fare' has 0 fresh fact(s), needs 1"
    # the clock is checked after the per-fact checks (a bad signature still wins)
    assert reason(decide_intent_world(W([fact(0, 5, NOW, key=ROGUE)], pol, now="x"))) == "facts: bad oracle signature on a 'fare' fact"
    # dimensions that need no clock are still computed
    rel = {"relational": [{"name": "d", "fn": "sub", "a": "action.params.total", "b": "action.params.quote"}]}
    for now in (str(NOW), None, NOW + 0.5):
        assert ok_world(decide_intent_world(W([], rel, now=now))) == {"d": 38_900}
    # safe-integer edges of the clock itself
    assert ok_world(decide_intent_world(W([fact(0, 5, 0)], {"worlds": [fare_world(min_oracles=1, max_faulty=0)]}, now=0))) == {"fare": 5}
    big = {"worlds": [fare_world(min_oracles=1, max_faulty=0, freshness_ms=MAX_SAFE)]}
    assert ok_world(decide_intent_world(W([fact(0, 5, 0)], big, now=MAX_SAFE))) == {"fare": 5}


def test_clock_offer_set_needs_a_safe_integer_now():
    N = "facts: offers: no usable clock (now must be a safe integer): the offer set counts as stale"
    for now in (str(NOW), NOW + 0.5, None, float("nan"), True, -0.0):
        assert reason(decide_intent_world(OS(offer_set(), now=now))) == N, now
    i = OS(offer_set())
    del i["now"]
    assert reason(decide_intent_world(i)) == N
    assert ok_world(decide_intent_world(OS(offer_set(), now=float(NOW)))) == {"excess_cents": 900}
    # audience and session are checked before the clock; completeness after it
    assert reason(decide_intent_world(OS(offer_set(site="evil.example"), now="x"))) == \
        "facts: offers: the offer set was issued for another audience"
    assert reason(decide_intent_world(OS(offer_set(session=OTHER_SESSION), now="x"))) == \
        "facts: offers: the offer set is bound to another session"
    assert reason(decide_intent_world(OS(offer_set(complete=False), now="x"))) == N


# ---- activity: intent_provenance_active, intent_wb_active -----------------------------------------------------------

def test_intent_provenance_active_strict():
    assert intent_provenance_active({}) is False
    assert intent_provenance_active({"prov": None}) is True  # present, even null: rule 17 judges it
    assert intent_provenance_active({"prov": {}}) is True
    assert intent_provenance_active({"prov": "x"}) is True
    assert intent_provenance_active({"labels": ["x"]}) is True
    for lab in ([], {"length": 1}, "ab", None):
        assert intent_provenance_active({"labels": lab}) is False, lab
    assert intent_provenance_active({"policy": {}}) is True
    assert intent_provenance_active({"policy": {"params": {}}}) is True
    for pol in (None, [], [{}], "x", 0):
        assert intent_provenance_active({"policy": pol}) is False, pol


def test_intent_wb_active_cases():
    D = _d("act")
    none = {"facts": False, "provenance": False, "classes": False}
    def A(s, p=None):
        return intent_wb_active({"intent_session": s, "policy": {} if p is None else p})
    assert A({}) == none
    assert intent_wb_active({}) == none
    assert intent_wb_active({"intent_session": None, "policy": None}) == none
    assert intent_wb_active(None) == none
    # a container that is absent or not a plain object has no members
    for c in (None, [], "x", 5):
        assert intent_wb_active({"intent_session": c, "policy": c}) == none, c
    assert intent_wb_active({"policy": {"world": None, "provenance": None, "classifiers": None}}) == none
    assert A({"facts": [D]}) == dict(none, facts=True)
    assert A({"facts": []}) == none
    assert A({"facts": {"0": D, "length": 1}}) == none
    assert A({"offer_set": D}) == dict(none, facts=True)
    assert A({"offer_set": {"length": 43}}) == none
    assert A({"offer_set": None}) == none
    assert A({}, {"world": {"worlds": [{"name": "x"}]}}) == dict(none, facts=True)
    assert A({}, {"world": {"worlds": {"length": 2}, "relational": {"length": 1}}}) == none
    assert A({}, {"world": {"relational": [{}]}}) == dict(none, facts=True)
    assert A({}, {"world": {"offers": {}}}) == dict(none, facts=True)
    assert A({}, {"world": {"offers": []}}) == none
    assert A({}, {"world": None}) == none
    assert A({"prov": {}}) == dict(none, provenance=True)
    assert A({"prov": None}) == dict(none, provenance=True)
    assert A({"labels": [D]}) == dict(none, provenance=True)
    assert A({"labels": {"length": 1}}) == none
    assert A({}, {"provenance": {"params": {}}}) == dict(none, provenance=True)
    assert A({}, {"provenance": []}) == none
    assert A({}, {"provenance": None}) == none
    assert A({"classes": [D]}) == dict(none, classes=True)
    assert A({"classes": {"length": 1}}) == none
    assert A({}, {"classifiers": [{"id": "tone"}]}) == dict(none, classes=True)
    assert A({}, {"classifiers": {"length": 3}}) == none
    assert A({}, {"classifiers": None}) == none
    assert A({"facts": [D], "prov": {}, "classes": [D]}) == {"facts": True, "provenance": True, "classes": True}


def test_wb_activity_drives_reporting():
    # an object with its own length never activates a check (members of the right container type)
    r = decide_intent_wb(WB(intent_session={"facts": {"length": 1}, "labels": {"length": 1}, "classes": {"length": 1},
                                            "offer_set": {"length": 43}},
                            policy={"world": {"worlds": {"length": 2}}}))
    assert r == {"outcome": "admit", "checks": {}, "env": {}}
    # a plain-object provenance policy is active even with nothing committed
    r = decide_intent_wb(WB(policy={"provenance": {"params": {"action.params.total": "material"}}}))
    assert r == {"outcome": "question", "checks": {"provenance": "question"},
                 "env": {"prov": {"action": {"params": {"total": "agent"}}}},
                 "reason": "provenance: a tainted value needs the principal (lazy question)", "friction": "tap"}

def test_world_optional_members():
    P_ = "facts: policy misconfigured (fail closed): "
    OK = {"ok": True, "world": {}, "single_source": []}
    for k, want in (("worlds", "worlds must be a list of at most 16"), ("relational", "relational must be a list of at most 16"),
                    ("offers", "offers policy must be an object"), ("skew_ms", "skew_ms must be a non-negative safe integer")):
        assert reason(decide_intent_world(W([], {k: None}))) == P_ + want, k  # present null: malformed
    assert reason(decide_intent_world(W([], None))) == P_ + "world policy must be an object"
    i = W([], {})
    del i["policy"]
    assert decide_intent_world(i) == OK  # absent policy = {}
    assert reason(decide_intent_world(W([], {"worlds": {}}))) == P_ + "worlds must be a list of at most 16"
    # pins: optional pq_pk absent, or a non-empty string
    assert reason(decide_intent_world(W([], {"worlds": [fare_world(oracles=oracles(2) + [{"kid": "o3", "pk": _pub(O[2]), "pq_pk": None}])]}))) == \
        P_ + "world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk"
    assert reason(decide_intent_world(W([], {"worlds": [fare_world(oracles=oracles(2) + [{"kid": "o3", "pk": _pub(O[2]), "pq_pk": ""}])]}))) == \
        P_ + "world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk"
    assert reason(decide_intent_world(W([], {"worlds": [fare_world(oracles=oracles(2) + [{"kid": "o3", "pk": _pub(O[2]), "pq_pk": "x"}])]}))) == \
        "facts: world 'fare' has 0 fresh fact(s), needs 3"
    assert reason(decide_intent_world(OS(offer_set(), offer_policy(site_keys=[{"kid": "skyair-2026", "pk": _pub(SITE), "pq_pk": None}])))) == \
        P_ + "offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk"
    # action must be an object; absent params = {}; present null params fail (always checked, after policy sanity)
    assert decide_intent_world(W([], {}, action={"verb": "v", "resource": "r"})) == OK
    for a in (None, [], "x"):
        assert reason(decide_intent_world(W([], {}, action=a))) == "facts: action must be an object", a
    i = W([], {})
    del i["action"]
    assert reason(decide_intent_world(i)) == "facts: action must be an object"
    for pr in (None, [], "x"):
        assert reason(decide_intent_world(W([], {}, action={"verb": "v", "resource": "r", "params": pr}))) == \
            "facts: action.params must be an object", pr
    r = decide_intent_world(W([], {"relational": [{"name": "d", "fn": "sub", "a": "action.params.x", "b": "action.params.y"}]},
                              action={"verb": "v", "resource": "r"}))
    assert reason(r) == "facts: relational 'd': an operand is missing or not a safe integer"
    # supplied offer_set: absent ok, present must be an object even without an offers policy
    for v in (None, [], "x"):
        assert reason(decide_intent_world(W([], {}, offer_set=v))) == "facts: offer_set must be an object", v
    assert decide_intent_world(W([], {}, offer_set={})) == OK
    # order: policy, action, action.params, committed, committed.facts, digests, committed offer_set, facts, offer_set
    assert reason(decide_intent_world(W([], {"skew_ms": None}, action=None))) == P_ + "skew_ms must be a non-negative safe integer"
    assert reason(decide_intent_world(W([], {}, action=None, committed=None))) == "facts: action must be an object"
    assert reason(decide_intent_world(W([], {}, action={"params": None}, committed=None))) == "facts: action.params must be an object"
    assert reason(decide_intent_world(W([], {}, committed=None, facts=None))) == "facts: committed must be an object"
    assert reason(decide_intent_world(W([], {}, committed={"facts": None}, facts=None))) == \
        "facts: committed facts must be a list of at most 16 digests"
    assert reason(decide_intent_world(W([], {}, committed={"facts": [], "offer_set": None}, facts=None))) == \
        "facts: the committed offer_set is not canonical base64url (32 bytes)"
    assert reason(decide_intent_world(W([], {}, facts=None, offer_set=None))) == "facts: facts must be an array"

def test_validate_wb_context():
    assert validate_wb_context({}) is None
    assert validate_wb_context({"artifacts": {"facts": [], "labels": [], "verdicts": [], "offer_set": {}},
                                "policy": {"world": {}, "provenance": {}, "classifiers": []}}) is None
    for wb in (None, [], "x"):
        assert validate_wb_context(wb) == "wb must be an object", wb
    for a in (None, [], "x"):
        assert validate_wb_context({"artifacts": a}) == "wb.artifacts must be an object", a
    for k in ("facts", "labels", "verdicts"):
        for v in (None, {}, "x"):
            assert validate_wb_context({"artifacts": {k: v}}) == "wb.artifacts.%s must be an array" % k, (k, v)
    for v in (None, [], "x"):
        assert validate_wb_context({"artifacts": {"offer_set": v}}) == "wb.artifacts.offer_set must be an object", v
    for p in (None, [], "x"):
        assert validate_wb_context({"policy": p}) == "wb.policy must be an object", p
    for k in ("world", "provenance"):
        for v in (None, [], "x"):
            assert validate_wb_context({"policy": {k: v}}) == "wb.policy.world / provenance must be objects", (k, v)
    for v in (None, {}, "x"):
        assert validate_wb_context({"policy": {"classifiers": v}}) == "wb.policy.classifiers must be an array", v
    # order: artifacts before policy; facts before labels before verdicts before offer_set
    assert validate_wb_context({"artifacts": {"offer_set": None, "verdicts": None}, "policy": None}) == "wb.artifacts.verdicts must be an array"
    assert validate_wb_context({"artifacts": {"labels": None, "facts": None}}) == "wb.artifacts.facts must be an array"
    assert validate_wb_context({"artifacts": None, "policy": None}) == "wb.artifacts must be an object"
    assert validate_wb_context({"policy": {"classifiers": None, "provenance": None}}) == "wb.policy.world / provenance must be objects"


# ---- closed member sets (README "closed and typed") ----------------------------------------------------------------

def test_closed_policy_members():
    P_ = "facts: policy misconfigured (fail closed): "
    assert reason(decide_intent_world(W([], {"extra": 1}))) == P_ + "unknown member 'policy.extra'"
    assert reason(decide_intent_world(W([], {"worlds": [dict(fare_world(), note=1)]}))) == P_ + "unknown member 'world.note'"
    o3 = dict(oracles()[2], note=1)
    assert reason(decide_intent_world(W([], {"worlds": [fare_world(oracles=oracles(2) + [o3])]}))) == \
        P_ + "world 'fare': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk"
    rel = {"name": "d", "fn": "sub", "a": "action.params.total", "b": "action.params.quote", "c": 1}
    assert reason(decide_intent_world(W([], {"relational": [rel]}))) == P_ + "unknown member 'relational.c'"
    rel = {"name": "d", "fn": "sub", "a": "action.params.total"}
    assert reason(decide_intent_world(W([], {"relational": [rel]}))) == P_ + "missing member 'relational.b'"
    # the policy closed set is checked before skew_ms
    assert reason(decide_intent_world(W([], {"skew_ms": -1, "extra": 1}))) == P_ + "unknown member 'policy.extra'"
    D = "provenance: policy misconfigured (fail closed): "
    assert reason(prov(P(None, {"extra": 1}))) == D + "unknown member 'policy.extra'"
    lk = dict(POLICY["label_keys"][0], note=1)
    assert reason(prov(P(None, {"label_keys": [lk]}))) == D + "every label key needs site, kid, a 32-byte pk and an optional string pq_pk"
    F = "classes: policy misconfigured (fail closed): "
    v = [verdict(J[0], "apologetic")]
    i = C(v)
    i["policy"]["extra"] = 1
    assert reason(cls(i)) == F + "unknown member 'policy.extra'"
    assert reason(cls(C(v, note=1))) == F + "every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}"
    pol = dict(TONE)
    del pol["k"]
    i = C(v)
    i["policy"]["classifiers"] = [pol]
    assert reason(cls(i)) == F + "every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}"
    # pq_keys: an object mapping allowlisted keys to non-empty strings
    assert reason(cls(C(v, pq_keys={_pub(J[0]): "x"}))) == "classes: classifier 'tone': no label reaches the quorum 2"
    for bad in (None, [], {_pub(ROGUE): "x"}, {_pub(J[0]): ""}, {_pub(J[0]): None}):
        assert reason(cls(C(v, pq_keys=bad))) == F + "classifier 'tone': pq_keys must map allowlisted keys to PQ keys", bad
    # the W-B context objects are closed too
    assert decide_intent_wb(WB(artifacts={"x": []}))["reason"] == "facts: the W-B context is malformed: unknown member 'artifacts.x'"
    assert decide_intent_wb(WB(policy={"x": {}}))["reason"] == "facts: the W-B context is malformed: unknown member 'policy.x'"


# ---- suite capability: alg / pq_pk / pq_sig on every W-B artifact ----------------------------------------------------

def test_artifact_suite_error():
    assert UNSUPPORTED_SUITE == "unsupported_suite"
    assert artifact_suite_error({}) is None
    assert artifact_suite_error({"alg": "ed25519"}) is None
    if suite_available("ml-dsa-65"):
        assert artifact_suite_error({"alg": "ml-dsa-65", "pq_pk": "x"}) is None
        assert artifact_suite_error({"alg": "hybrid-ed25519-ml-dsa-65", "pq_pk": "x", "pq_sig": "y"}) is None
        assert artifact_suite_error({"alg": "ml-dsa-65", "pq_pk": None}) == "pq_pk must be a string"
        assert artifact_suite_error({"alg": "ml-dsa-65", "pq_pk": "x", "pq_sig": 1}) == "pq_sig must be a string"
    else:  # no ML-DSA backend (no dilithium-py, OpenSSL < 3.5): the suite is refused first, before the pq_* type checks
        assert artifact_suite_error({"alg": "ml-dsa-65", "pq_pk": "x"}) == "unsupported_suite: 'ml-dsa-65'"
        assert artifact_suite_error({"alg": "hybrid-ed25519-ml-dsa-65", "pq_pk": "x", "pq_sig": "y"}) == \
            "unsupported_suite: 'hybrid-ed25519-ml-dsa-65'"
        assert artifact_suite_error({"alg": "ml-dsa-65", "pq_pk": None}) == "unsupported_suite: 'ml-dsa-65'"
        assert artifact_suite_error({"alg": "ml-dsa-65", "pq_pk": "x", "pq_sig": 1}) == "unsupported_suite: 'ml-dsa-65'"
    # the pq_* type checks on a suite every runtime has
    assert artifact_suite_error({"alg": "ed25519", "pq_pk": None}) == "pq_pk must be a string"
    assert artifact_suite_error({"pq_sig": 1}) == "pq_sig must be a string"
    assert artifact_suite_error({"alg": "no-such-suite"}) == "unsupported_suite: 'no-such-suite'"
    for bad in (None, 5, ["ed25519"]):
        assert artifact_suite_error({"alg": bad}) == "alg must be a string", bad
    assert artifact_suite_error({"pq_sig": "x"}) == "an ed25519 artifact must not carry pq_pk / pq_sig"
    assert artifact_suite_error({"alg": "ed25519", "pq_pk": "x"}) == "an ed25519 artifact must not carry pq_pk / pq_sig"
    # the unsupported suite is reported before the type checks of pq_pk / pq_sig
    assert artifact_suite_error({"alg": "no-such-suite", "pq_pk": 1}) == "unsupported_suite: 'no-such-suite'"


def _fact_with(i, value, **suite):
    body = {"v": 1, "kind": "pca-fact", "name": "fare", "subject": "OF-2", "value": value, "t_obs": NOW - 1_000,
            "oracle": "o%d" % (i + 1)}
    body.update({k: v for k, v in suite.items() if k != "pq_sig"})
    f = _signed(FACT_DOMAIN, body, O[i])
    if "pq_sig" in suite:
        f["pq_sig"] = suite["pq_sig"]
    return f


def test_fact_suites():
    pol = {"worlds": [fare_world(min_oracles=1, max_faulty=0)]}
    # explicit alg "ed25519" is signed into the body and verifies
    assert ok_world(decide_intent_world(W([_fact_with(0, 5, alg="ed25519")], pol))) == {"fare": 5}
    # pq_sig is outside the signed bytes, but an ed25519 fact must not carry it
    r = decide_intent_world(W([_fact_with(0, 5, pq_sig="x")], pol))
    assert reason(r) == "facts: fact signature suite: an ed25519 artifact must not carry pq_pk / pq_sig"
    r = decide_intent_world(W([_fact_with(0, 5, alg="no-such-suite")], pol))
    assert reason(r) == "facts: fact signature suite: unsupported_suite: 'no-such-suite'"
    assert UNSUPPORTED_SUITE in reason(r)
    r = decide_intent_world(W([_fact_with(0, 5, alg=7)], pol))
    assert reason(r) == "facts: fact signature suite: alg must be a string"
    # the suite is checked before anything else about the fact (an undeclared world, an unpinned oracle)
    r = decide_intent_world(W([_fact_with(0, 5, alg="no-such-suite")], {"worlds": []}))
    assert reason(r) == "facts: fact signature suite: unsupported_suite: 'no-such-suite'"
    # a PQ fact under a pin without pq_pk never verifies (the artifact's own pq_pk alone authorises nothing)
    ml = suite_available("ml-dsa-65")  # absent (no dilithium-py, OpenSSL < 3.5): every ML-DSA fact is unsupported_suite
    r = decide_intent_world(W([_fact_with(0, 5, alg="ml-dsa-65", pq_pk="A" * 10)], pol))
    assert reason(r) == ("facts: bad oracle signature on a 'fare' fact" if ml
                         else "facts: fact signature suite: unsupported_suite: 'ml-dsa-65'")
    # a pinned pq_pk that differs from the artifact's: refused before any PQ verification
    pinned = {"worlds": [fare_world(min_oracles=1, max_faulty=0,
                                    oracles=[{"kid": "o1", "pk": _pub(O[0]), "pq_pk": "B" * 10}])]}
    r = decide_intent_world(W([_fact_with(0, 5, alg="hybrid-ed25519-ml-dsa-65", pq_pk="A" * 10, pq_sig="x")], pinned))
    assert reason(r) == ("facts: bad oracle signature on a 'fare' fact" if ml
                         else "facts: fact signature suite: unsupported_suite: 'hybrid-ed25519-ml-dsa-65'")
    # wire: the suite members are allowed (closed set + optional members)
    assert validate_fact_wire(_fact_with(0, 5, alg="ml-dsa-65", pq_pk="x", pq_sig="y")) is None


def test_offer_label_verdict_suites():
    ml = suite_available("ml-dsa-65")  # absent (no dilithium-py, OpenSSL < 3.5): an ML-DSA artifact is unsupported_suite
    o = offer_set(alg="no-such-suite")
    assert reason(decide_intent_world(OS(o))) == "facts: offers: signature suite: unsupported_suite: 'no-such-suite'"
    o = offer_set(alg="ml-dsa-65", pq_pk="x")
    assert reason(decide_intent_world(OS(o))) == ("facts: offers: bad site signature" if ml  # no pinned pq_pk
                                                  else "facts: offers: signature suite: unsupported_suite: 'ml-dsa-65'")
    # suite before the kid pin
    o = offer_set(alg="no-such-suite", kid="other")
    assert reason(decide_intent_world(OS(o))) == "facts: offers: signature suite: unsupported_suite: 'no-such-suite'"
    r_ = receipt(AUD, SITE, "k1", PASSPORT["fields"])
    bad = _signed(LABELS_DOMAIN, dict({k: v for k, v in r_.items() if k != "sig"}, alg="no-such-suite"), SITE)
    assert reason(prov(with_label(bad, "travellers[0].passport"))) == \
        "provenance: label receipt for 'action.params.passport': signature suite: unsupported_suite: 'no-such-suite'"
    v = verdict(J[0], "apologetic", alg="no-such-suite")
    assert reason(cls(C([v]))) == "classes: verdict signature suite: unsupported_suite: 'no-such-suite'"
    v = verdict(J[0], "apologetic", alg="no-such-suite", classifier="spam")
    assert reason(cls(C([v]))) == "classes: verdict signature suite: unsupported_suite: 'no-such-suite'"  # before the classifier
    v = verdict(J[0], "apologetic", alg="ml-dsa-65", pq_pk="x")
    want = ("classes: classifier 'tone': bad verdict signature" if ml
            else "classes: verdict signature suite: unsupported_suite: 'ml-dsa-65'")
    assert reason(cls(C([v]))) == want  # no pq_keys pin
    assert reason(cls(C([v], pq_keys={_pub(J[0]): "y"}))) == want  # pin differs


# ---- READ PURPOSE (decide_read_purpose) ------------------------------------------------------------------------------

COVER = {"booking": ["pii.identity", "itinerary"], "support": ["pii.*", "internal"], "comparison": []}
RFIELDS = [{"path": "passengers[].name", "class": "pii.identity"},
           {"path": "passengers[].email", "class": "pii.contact", "optional": True},
           {"path": "loyalty", "class": "internal", "optional": True},
           {"path": "fares", "class": "public"}]
MAL = {"outcome": "deny", "minimise": [], "uncovered": []}


def RP(**over):
    i = {"fields": copy.deepcopy(RFIELDS), "purpose": "booking", "coverage": copy.deepcopy(COVER)}
    i.update(over)
    return decide_read_purpose(i)


def test_read_purpose_outcomes():
    assert RP() == {"outcome": "allow", "minimise": ["loyalty", "passengers[].email"], "uncovered": []}
    assert RP(purpose="support") == {"outcome": "allow", "minimise": [], "uncovered": []}
    q = {"outcome": "question", "minimise": ["loyalty", "passengers[].email"], "uncovered": ["passengers[].name"]}
    assert RP(purpose="comparison") == q
    assert RP(purpose="comparison", on_uncovered="deny") == dict(q, outcome="deny")
    assert RP(purpose="comparison", on_uncovered="question") == q
    assert RP(purpose="nope") == q
    for pname in ("constructor", "__proto__", "toString"):  # own-member lookup only
        assert RP(purpose=pname) == q, pname
    # an own "__proto__" purpose is ordinary data
    assert RP(purpose="__proto__", coverage={"__proto__": ["pii.*", "internal"]}) == {"outcome": "allow", "minimise": [], "uncovered": []}
    # patterns: exact, prefix keeps the dot, '*'
    assert RP(fields=[{"path": "x", "class": "piix"}], coverage={"booking": ["pii.*"]})["uncovered"] == ["x"]
    assert RP(fields=[{"path": "x", "class": "secret"}], coverage={"booking": ["*"]})["outcome"] == "allow"
    # optional must be exactly true to minimise
    assert RP(fields=[{"path": "x", "class": "secret", "optional": False}]) == {"outcome": "question", "minimise": [], "uncovered": ["x"]}
    # de-duplicated
    assert RP(fields=[{"path": "x", "class": "secret"}, {"path": "x", "class": "secret"}]) == \
        {"outcome": "question", "minimise": [], "uncovered": ["x"]}
    assert RP(fields=[]) == {"outcome": "allow", "minimise": [], "uncovered": []}


def test_read_purpose_utf8_byte_order():
    mixed = ["z\U0001F600", "z\uFFFD", "z\u00E9", "za", "\U0001F600", "\uFFFD", "a"]
    fields = []
    for i, p in enumerate(mixed):
        fields.append({"path": p, "class": "secret", "optional": i % 2 == 0})
        fields.append({"path": p + "!", "class": "secret"})
    r = RP(fields=fields)
    assert r == {"outcome": "question",
                 "minimise": ["a", "z\u00E9", "z\U0001F600", "\U0001F600"],
                 "uncovered": ["a!", "za", "za!", "z\u00E9!", "z\uFFFD", "z\uFFFD!", "z\U0001F600!", "\uFFFD", "\uFFFD!",
                               "\U0001F600!"]}
    # U+FFFD sorts BEFORE U+1F600 in UTF-8 bytes (UTF-16 order would put it after)
    r = RP(fields=[{"path": "\U0001F600", "class": "secret"}, {"path": "\uFFFD", "class": "secret"}])
    assert r["uncovered"] == ["\uFFFD", "\U0001F600"]


def test_read_purpose_malformed():
    for over in ({"fields": None}, {"fields": {}}, {"fields": "x"}, {"coverage": None}, {"coverage": []},
                 {"purpose": None}, {"purpose": 5}, {"coverage": {"booking": "pii.*"}}, {"coverage": {"booking": [1]}},
                 {"coverage": {"other": None}}, {"on_uncovered": "allow"}, {"on_uncovered": None},
                 {"fields": [{"path": "x", "class": "secret", "optional": None}]},
                 {"fields": [{"path": "x", "class": "secret", "optional": 1}]},
                 {"fields": [{"path": None, "class": "secret"}]}, {"fields": [{"path": "x"}]}, {"fields": [None]}):
        assert RP(**over) == MAL, over
    assert decide_read_purpose({"fields": [], "purpose": "booking"}) == MAL  # coverage absent
    assert decide_read_purpose(None) == MAL


def test_typed_policy_numbers_and_enums():
    P_ = "facts: policy misconfigured (fail closed): "
    for bad in ("60000", 1.5, True, None, -1):
        assert reason(decide_intent_world(W([], {"skew_ms": bad}))) == P_ + "skew_ms must be a non-negative safe integer", bad
    for k, want in (("freshness_ms", "freshness_ms must be a non-negative safe integer"),
                    ("max_faulty", "max_faulty must be a non-negative safe integer")):
        for bad in ("1", 0.5, True, None):
            assert _pol_reason({"worlds": [fare_world(**{k: bad})]}) == P_ + "world 'fare': " + want, (k, bad)
    for bad in ("3", 3.5, True):
        assert _pol_reason({"worlds": [fare_world(min_oracles=bad)]}) == \
            P_ + "world 'fare': min_oracles must be a safe integer >= 2*max_faulty+1", bad
    for bad in ("600000", 1.5, False):
        assert reason(decide_intent_world(OS(offer_set(), offer_policy(max_age_ms=bad)))) == \
            P_ + "offers policy: max_age_ms must be a non-negative safe integer", bad
    for bad in (1, True, None, ["sub"]):
        rel = {"name": "d", "fn": bad, "a": "action.params.total", "b": "action.params.quote"}
        assert reason(decide_intent_world(W([], {"relational": [rel]}))) == P_ + "relational 'd': fn must be \"sub\" or \"ratio_ppm\"", bad
    D = "provenance: policy misconfigured (fail closed): "
    for bad in (4, True, ["agent"]):
        assert reason(prov(P(None, {"critical_max": bad}))) == D + "critical_max must be a taint level", bad
        assert reason(prov(P(None, {"material_tainted": bad}))) == D + "material_tainted must be allow | question | question_typed | deny", bad
        assert reason(prov(P(None, {"critical_tainted": bad}))) == D + "critical_tainted must be question | question_typed | deny", bad
    F = "classes: policy misconfigured (fail closed): "
    v = [verdict(J[0], "apologetic")]
    for bad in ("2", 2.5, True, None):
        assert reason(cls(C(v, k=bad))) == F + "classifier 'tone': k must be an integer in [1, 3]", bad
    assert reason(cls(C(v, k=2.0))) == "classes: classifier 'tone': no label reaches the quorum 2"  # 2.0 is the JSON number 2
