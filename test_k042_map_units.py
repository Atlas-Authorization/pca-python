"""Kill tests for atlas_pca.intent_map helpers: byte encodings, tree hashing and inclusion verification over every
(index, size), commit_leaves refusals, cell selection ties, and the disclosure decision's fail-closed results."""
import hashlib

import pytest

from atlas_pca import intent_map as M
from atlas_pca.pca import b64u, decode_b64u_strict, params_digest


def test_encodings():
    assert M._u64be(0) == bytes(8) and M._u64be(1) == b"\x00" * 7 + b"\x01" and M._u64be(2 ** 40) == (2 ** 40).to_bytes(8, "big")
    assert M._u16len("abc") == 3 and M._u16len("\U0001F600") == 2 and M._u16len("￿") == 1 and M._u16len("\U00010000") == 2
    assert M._u16len("") == 0 and M._u16len("a\U0001F600b") == 4 and M._u16len("\ud800") == 1


def test_hash_domains_and_errors():
    salt = bytes(range(32))
    leaf = {"learner_digest": "oYPfuowHnO_E-SdgwM9qFMZs-nCcDU9vh6mge4XccmU"}
    from atlas_pca.pca import canonical_bytes_strict
    assert M.map_leaf_hash("learner", salt, leaf) == hashlib.sha256(M._TAGS["learner"].encode() + salt + canonical_bytes_strict(leaf)).digest()
    assert M.map_node_hash(b"L" * 32, b"R" * 32) == hashlib.sha256(M.MAP_TAG_NODE.encode() + b"L" * 32 + b"R" * 32).digest()
    assert M.map_leaf_salt(salt, 5) == hashlib.sha256(M.MAP_TAG_SALT.encode() + salt + (5).to_bytes(8, "big")).digest()
    assert M.map_commit_of(7, b"r" * 32) == b64u(hashlib.sha256(M.MAP_TAG_COMMIT.encode() + (7).to_bytes(8, "big") + b"r" * 32).digest())
    for bad in (bytes(31), bytes(33), b""):
        with pytest.raises(ValueError) as e:
            M.map_leaf_hash("learner", bad, leaf)
        assert str(e.value) == "map_leaf_hash: the salt is 32 bytes"
    with pytest.raises(ValueError) as e:
        M.map_tree_root([])
    assert str(e.value) == "map tree: empty"


def hs(n):
    return [hashlib.sha256(bytes([i])).digest() for i in range(n)]


@pytest.mark.parametrize("size", list(range(1, 40)))
def test_inclusion_roundtrip_every_index(size):
    h = hs(size)
    root = M.map_tree_root(h)
    for i in range(size):
        path = [decode_b64u_strict(x, 32) for x in M.map_audit_path(h, i)]
        assert M.map_root_from_path(i, size, h[i], path) == root, (i, size)
        if size > 1:
            assert M.map_root_from_path(i, size, h[i], path[:-1]) is None
            assert M.map_root_from_path(i, size, h[i], path + [path[0]]) is None
            assert M.map_root_from_path((i + 1) % size, size, h[i], path) != root
        else:
            assert M.map_root_from_path(i, size, h[i], [bytes(32)]) is None
    assert M.map_root_from_path(size, size, h[0], []) is None
    assert M.map_root_from_path(-1, size, h[0], []) is None


def test_commit_leaves_refusals():
    salt = b64u(bytes(32))
    leaf = {"learner_digest": "oYPfuowHnO_E-SdgwM9qFMZs-nCcDU9vh6mge4XccmU"}
    ok = {"kind": "learner", "salt": salt, "leaf": leaf}
    assert isinstance(M.commit_leaves([ok]), str)
    for bad in ([], None, {}, "x", ()):
        with pytest.raises(ValueError) as e:
            M.commit_leaves(bad)
        assert str(e.value) == "commit_leaves: a non-empty leaf list"
    kind_msg = "commit_leaves: each entry is {kind, salt, leaf} with a known kind"
    for bad in (5, None, "x", [], {"kind": "nope", "salt": salt, "leaf": leaf}, {"salt": salt, "leaf": leaf}, {"kind": 1}):
        with pytest.raises(ValueError) as e:
            M.commit_leaves([bad])
        assert str(e.value) == kind_msg
    salt_msg = "commit_leaves: salt must be canonical base64url (32 bytes) and leaf present"
    for bad in (dict(ok, salt=b64u(bytes(16))), dict(ok, salt=b64u(bytes(33))), dict(ok, salt="!"), dict(ok, salt=None),
                {"kind": "learner", "salt": salt}, {"kind": "learner", "leaf": leaf}):
        with pytest.raises(ValueError) as e:
            M.commit_leaves([bad])
        assert str(e.value) == salt_msg


def header(cells_dim):
    return {"verb": "v", "first": 1, "cells": len(cells_dim), "dims": [{"kind": "cat", "path": "action.resource", "values": cells_dim}]}


def test_cell_of_prefix_ties_and_defaults():
    vals = [{"kind": "prefix", "value": "ab"}, {"kind": "prefix", "value": "ab"}, {"kind": "prefix", "value": "a"}, {"kind": "other", "value": "⊥"}]
    h = header(vals)
    assert M.map_cell_of(h, "abc", {}) == {"cell": [0], "flat": 0}  # the first of equal-length prefixes wins
    assert M.map_cell_of(h, "ax", {}) == {"cell": [2], "flat": 2}
    assert M.map_cell_of(h, "zz", {}) == {"cell": [3], "flat": 3}
    assert M.map_cell_of(h, "", {}) == {"cell": [3], "flat": 3}
    assert "error" in M.map_cell_of(h, 5, {})  # a non-string resource is outside every categorical dimension
    assert "error" in M.map_cell_of(h, M._ABSENT, {})
    hp = {"verb": "v", "first": 1, "cells": 3, "dims": [{"kind": "num", "path": "action.params.n", "lo": 0, "hi": 10, "cuts": [5]}]}
    assert M.map_cell_of(hp, None, {"n": 7}) == {"cell": [2], "flat": 2}
    assert "error" in M.map_cell_of(hp, None, {})  # an absent parameter is outside the dimension
    assert "error" in M.map_cell_of(hp, None, {"n": None})  # null is not an integer either
    assert "error" in M.map_cell_of(hp, None, {"n": 11})
    assert "error" in M.map_cell_of(hp, None, None)
    assert M.map_cell_of(hp, None, {"n": 0}) == {"cell": [0], "flat": 0}


def test_disclosure_fail_closed_results():
    r = M.decide_map_disclosure("x", {"verb": "v"}, None)
    assert r["ok"] is False and list(r)[0] == "ok"
    mc = b64u(bytes(32))
    res = M.decide_map_disclosure(mc, "not-an-object", _good_disclosure())
    assert res == {"ok": False, "reason": "map error (fail closed): the action must be an object"}
    assert M.decide_map_disclosure(mc, None, _good_disclosure()) == res
    assert M.decide_map_disclosure(mc, [1], _good_disclosure()) == res


def _good_disclosure():
    m = _build()
    return m["disclose"]("v", "r", {})


def _build():
    metrics = {"residual_risk_ppm": 1, "burden_ppm": 0, "uncertainty_ppm": 0, "disagreement_ppm": 0, "mean_harm_ppm": 0,
               "fidelity_est_ppm": 1, "entropy_mbits": 0, "questions": 0, "conflicts": 0}
    h = {"verb": "v", "dims": [{"kind": "cat", "path": "action.resource", "values": [{"kind": "exact", "value": "r"}, {"kind": "other", "value": "⊥"}]}]}
    cells = {"v": [{"cell": [0], "p_ppm": 1, "in_grant": True}, {"cell": [1], "p_ppm": 2, "in_grant": False}]}
    return M.commit_map([h], cells, metrics, "oYPfuowHnO_E-SdgwM9qFMZs-nCcDU9vh6mge4XccmU", bytes(range(32)))


def test_disclosure_resource_and_params_digest_edges():
    m = _build()
    d = m["disclose"]("v", "r", {})
    act = {"verb": "v", "resource": "r", "params_digest": params_digest({})}
    assert M.decide_map_disclosure(m["map_commit"], act, d)["ok"] is True
    # an absent params argument is {}; an absent resource is outside the categorical dimension; absent digest never matches
    assert M.decide_map_disclosure(m["map_commit"], {"verb": "v", "params_digest": params_digest({})}, d)["ok"] is False
    assert M.decide_map_disclosure(m["map_commit"], {"verb": "v", "resource": "r"}, d)["reason"] == "the params do not hash to action.params_digest"
    assert M.decide_map_disclosure(m["map_commit"], dict(act, params_digest=None), d)["reason"] == "the params do not hash to action.params_digest"
    r = M.decide_map_disclosure(m["map_commit"], {"verb": "v", "params_digest": params_digest({})}, d)
    assert r["reason"].startswith("the action's action.resource lies outside")
    # tampered leaf: the salt must be 32 bytes and every path entry 32 bytes, or the leaf does not open
    bad = dict(d, header=dict(d["header"], salt=b64u(bytes(16))))
    assert M.decide_map_disclosure(m["map_commit"], act, bad)["ok"] is False
    assert M._opens("header", dict(d["header"], salt=b64u(bytes(16))), d["size"], m["map_commit"]) is False
    assert M._opens("header", dict(d["header"], path=[b64u(bytes(16))] * len(d["header"]["path"])), d["size"], m["map_commit"]) is False
    assert M._opens("header", d["header"], d["size"], m["map_commit"]) is True
    assert M._opens("header", d["header"], d["size"], b64u(bytes(32))) is False
    assert M._opens("header", d["header"], d["size"] + 1, m["map_commit"]) is False


def test_param_name_chars():
    assert M._is_param_name("a_b1") and M._is_param_name("_") and M._is_param_name("A" * 64)
    assert not M._is_param_name("") and not M._is_param_name("a" * 65) and not M._is_param_name("a-b") and not M._is_param_name("a b")
    assert not M._is_param_name("é") and not M._is_param_name("a.b")


def test_metrics_optional_member():
    base = {"residual_risk_ppm": 1, "burden_ppm": 0, "uncertainty_ppm": 0, "disagreement_ppm": 0, "mean_harm_ppm": 0,
            "fidelity_est_ppm": 1, "entropy_mbits": 0, "questions": 0, "conflicts": 0}
    assert M.map_metrics_error(base) is None
    assert M.map_metrics_error(dict(base, log2_vs_mbits=3)) is None
    assert M.map_metrics_error(dict(base, log2_vs_mbits=-1)) == "metrics.log2_vs_mbits must be a non-negative safe integer"
    assert M.map_metrics_error(dict(base, log2_vs_mbits=None)) == "metrics.log2_vs_mbits must be a non-negative safe integer"
    bad = dict(base, conflicts=-1)
    assert M.map_metrics_error(dict(bad, log2_vs_mbits=3)) == "metrics.conflicts must be a non-negative safe integer"
