"""PCA 0.4.1 native fixes (shared corpus packages/pca/conformance/vectors.json):

  * per-suite threshold share signatures in `wire` (the `r041-share-*` vectors; also run by test_conformance.py),
  * the root-caveat policy helpers `policy_caveats` / `evaluate_caveats` (incl. `max_spend`), table
    `primitives.caveat_eval`,
  * the strict `PCA-Action` header decoder `decode_pca_header`, table `primitives.pca_header`.

Helpers are looked up at call time so a missing export fails each case on its own (not the whole module).
"""
import copy
import json
import os

import pytest

import atlas_pca
from atlas_pca import require_pca, validate_wire_v2
from atlas_pca.server import extract_pcactn

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance")
with open(os.path.join(DIR, "vectors.json"), encoding="utf-8") as _f:
    DOC = json.load(_f)
PRIM = DOC["primitives"]
CAVEAT_EVAL = PRIM["caveat_eval"]
PCA_HEADER = PRIM["pca_header"]
SHARE_VECTORS = [v for v in DOC["vectors"] if v["name"].startswith("r041-share-") and v.get("requires") is None]


def _helpers():
    return atlas_pca.policy_caveats, atlas_pca.evaluate_caveats


# ---- primitives.caveat_eval -------------------------------------------------------------------------------------

def test_caveat_eval_table_shape():
    names = {c["name"]: c for c in CAVEAT_EVAL}
    assert len(CAVEAT_EVAL) >= 40
    assert names["r041-root-max-spend-exceeded"]["expect"]["allow"] is False
    assert names["r041-root-max-spend-within"]["expect"]["allow"] is True


@pytest.mark.parametrize("case", CAVEAT_EVAL, ids=[c["name"] for c in CAVEAT_EVAL])
def test_caveat_eval(case):
    policy_caveats, evaluate_caveats = _helpers()
    ok, failed = evaluate_caveats(policy_caveats(case["grant"], case["chain"]), case["context"])
    assert {"allow": ok, "failed": list(failed)} == case["expect"]


def _ctx(**kw):
    c = {"now": 1800000000000, "action": {"verb": "pay", "resource": "r", "params": {"amount": 10}}}
    c.update(kw)
    return c


def test_policy_caveats_shapes():
    policy_caveats, _ = _helpers()
    env = {"type": "envelope", "predicates": []}
    g = {"caveats": [{"type": "a"}, env, {"type": "b"}, dict(env)]}
    leaf = {"caveats": [{"type": "x"}, {"type": "y"}, {"type": "c"}, {"type": "d"}, {"type": "e"}]}
    # first envelope removed (order kept), second kept; hop-appended caveats beyond len(grant.caveats)
    assert policy_caveats(g, [g, leaf]) == [{"type": "a"}, {"type": "b"}, env, {"type": "e"}]
    assert policy_caveats(g, []) == [{"type": "a"}, {"type": "b"}, env]
    assert policy_caveats(g, None) == [{"type": "a"}, {"type": "b"}, env]
    assert policy_caveats(g, "nope") == [{"type": "a"}, {"type": "b"}, env]
    assert policy_caveats(g, [{"caveats": "x"}]) == [{"type": "a"}, {"type": "b"}, env]
    # non-list grant caveats pass through and are refused by evaluate_caveats
    assert policy_caveats({"caveats": "x"}, []) == "x"
    assert policy_caveats(None, []) is None
    assert policy_caveats({"caveats": [1, None]}, [[1]]) == [1, None]
    # the input is not mutated
    assert len(g["caveats"]) == 4


def test_evaluate_caveats_total():
    _, evaluate_caveats = _helpers()
    assert evaluate_caveats("x", _ctx()) == (False, ["<malformed caveats>"])
    assert evaluate_caveats(None, _ctx()) == (False, ["<malformed caveats>"])
    assert evaluate_caveats([], _ctx()) == (True, [])
    assert evaluate_caveats([], None) == (True, [])
    assert evaluate_caveats([1, "s", None, [], {"type": 5}, {}], _ctx()) == (False, ["<malformed>"] * 6)
    assert evaluate_caveats([{"type": "max_spend", "usd": 100}], None) == (False, ["max_spend"])
    assert evaluate_caveats([{"type": "max_spend", "usd": 100}], "ctx") == (False, ["max_spend"])
    for t in ("note", "envelope", "resource_prefix", "predicates", "tool_schema", "unknown"):
        assert evaluate_caveats([{"type": t}], _ctx()) == (False, [t])


def test_max_spend_numbers():
    _, ev = _helpers()
    cv = [{"type": "max_spend", "usd": 100}]

    def spend(params, now=1800000000000):
        ctx = {"action": {"params": params}}
        if now is not None:
            ctx["now"] = now
        return ev(cv, ctx)[0]

    assert spend({"amount": 100}) is True
    assert spend({"amount": 100}, now=None) is True  # max_spend does not need `now`
    assert spend({"amount": 100.0000001}) is False
    assert spend({"amount": True}) is False  # a bool is not a number
    assert spend({"amount": float("inf")}) is False
    assert spend({"amount": float("nan")}) is False
    assert spend({"amount": 10 ** 400}) is False  # not a finite double
    assert spend({"amount": "1"}) is False
    assert spend({"amount": 1, "currency": "usd"}) is True
    assert spend({"amount": 1, "currency": None}) is False
    assert spend({"amount": 1, "currency": ["usd"]}) is False
    assert spend([1]) is False
    assert ev([{"type": "max_spend", "usd": True}], {"action": {"params": {"amount": 0}}})[0] is False
    assert ev([{"type": "max_spend", "usd": float("inf")}], {"action": {"params": {"amount": 0}}})[0] is False
    assert ev([{"type": "max_spend", "usd": 0}], {"action": {"params": {"amount": 0}}})[0] is True
    assert ev(cv, {"action": "x"})[0] is False
    assert ev(cv, {"action": {"params": {"amount": 1}}, "now": "x"})[0] is True
    # double semantics, like the reference: 2^53+1 rounds to 2^53
    assert ev([{"type": "max_spend", "usd": float(2 ** 53)}], {"action": {"params": {"amount": 2 ** 53 + 1}}})[0] is True


def test_stock_caveats_need_now():
    _, ev = _helpers()
    for cv in ({"type": "expires", "at": 10}, {"type": "not_before", "at": 0}, {"type": "budget_alloc", "limit": 1},
               {"type": "delegation_depth", "max": 5}):
        assert ev([cv], {"delegation_depth": 0})[0] is False
        assert ev([cv], {"now": True, "delegation_depth": 0})[0] is False
        assert ev([cv], {"now": 1, "delegation_depth": 0})[0] is True
    assert ev([{"type": "delegation_depth", "max": 5}], {"now": 1, "delegation_depth": True})[0] is False
    assert ev([{"type": "budget_alloc", "limit": -1}], {"now": 1})[0] is False
    assert ev([{"type": "rate", "max": 1, "per_secs": 1}], {"now": 5000, "recent_action_times": [4000, True, "x", 5001]})[0] is True
    assert ev([{"type": "rate", "max": 1, "per_secs": 1}], {"now": 5000, "recent_action_times": [4001]})[0] is False
    assert ev([{"type": "rate", "max": 1, "per_secs": 0}], {"now": 5000, "recent_action_times": []})[0] is False
    assert ev([{"type": "reversibility_max", "class": "irreversible"}], {"now": 1, "reversibility_class": "rate_limited"})[0] is True
    assert ev([{"type": "reversibility_max", "class": "reversible"}], {"now": 1, "reversibility_class": "bogus"})[0] is False
    # reads ctx.reversibility_class, not ctx.action.reversibility_class
    assert ev([{"type": "reversibility_max", "class": "irreversible"}], {"now": 1, "action": {"reversibility_class": "reversible"}})[0] is False
    assert ev([{"type": "max_blast_radius", "max": 0.5}], {"now": 1, "blast_radius": 0.5})[0] is True


# ---- primitives.pca_header --------------------------------------------------------------------------------------

@pytest.mark.parametrize("case", PCA_HEADER, ids=[c["name"] for c in PCA_HEADER])
def test_pca_header(case):
    decode_pca_header = atlas_pca.decode_pca_header
    try:
        text = decode_pca_header(case["input"])
        valid = True
    except ValueError:
        valid = False
    assert valid is case["valid"]
    if valid:
        assert text == case["text"]


def test_pca_header_non_string():
    decode_pca_header = atlas_pca.decode_pca_header
    for bad in (None, 5, b"e30"):
        with pytest.raises(ValueError):
            decode_pca_header(bad)
    assert issubclass(atlas_pca.PcaHeaderError, ValueError)


@pytest.mark.parametrize("value", [" e30", "e30 ", "e30\t", "e30=", "e3+", "", "77u_e30"])
def test_extract_header_strict(value):
    pcactn, err = extract_pcactn({"PCA-Action": value}, None)
    assert pcactn is None and err == "undecodable"


def test_guard_header_whitespace_is_401():
    vec = next(x for x in DOC["vectors"] if x["name"] == "valid-in-plan-action")
    from atlas_pca.pca import b64u, canonical_bytes_strict
    hdr = b64u(canonical_bytes_strict(vec["pcactn"]))
    guard = require_pca(audience=vec["context"]["aud"], resolve_grant=lambda ref: vec["grant"], now=vec["context"]["now"])
    ok = guard({"PCA-Action": hdr}, None)
    assert ok.ok is True
    bad = guard({"PCA-Action": hdr + " "}, None)
    assert bad.ok is False and bad.status == 401


# ---- per-suite share wire ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("v", SHARE_VECTORS, ids=[v["name"] for v in SHARE_VECTORS])
def test_share_wire(v):
    err = validate_wire_v2(v["pcactn"])
    assert (err is None) is v["expect"]["checks"]["wire"], err


def _share_base():
    v = next(x for x in SHARE_VECTORS if x["name"] == "r041-share-ml-dsa-65-carried")
    return copy.deepcopy(v["pcactn"])


def test_share_wire_reasons():
    p = _share_base()
    assert validate_wire_v2(p) is None
    p["threshold"]["shares"][0]["alg"] = None
    assert validate_wire_v2(p) == "threshold.shares[0]: 'alg' must be a string"
    p["threshold"]["shares"][0]["alg"] = "ml-dsa-87"
    assert validate_wire_v2(p) == "threshold.shares[0]: unknown signature alg 'ml-dsa-87'"
    p["threshold"]["shares"][0]["alg"] = "ml-dsa-65"
    p["threshold"]["shares"][0]["sig"] = p["threshold"]["shares"][0]["sig"][:-4]
    assert validate_wire_v2(p) == "threshold.shares[0]: 'sig' is not canonical base64url (3309 bytes) for alg 'ml-dsa-65'"
    # a share pq_pk is an optional echo, not judged by wire (even when malformed)
    p = _share_base()
    p["threshold"]["shares"][0]["pq_pk"] = "!!"
    assert validate_wire_v2(p) is None
