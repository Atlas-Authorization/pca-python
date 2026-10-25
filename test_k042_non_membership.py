"""Kill tests: sorted-Merkle non-membership proofs (verify_non_membership / _leaf_ok) on proofs built here from the
RFC 6962 tree: every accepted shape (between, below the first, above the last, empty set) and each rejection (size,
bracketing order incl. equality, adjacency, edge indices, proof shape, side, sibling hash, root)."""
import copy

import pytest

from atlas_pca.intent_v2 import _EMPTY_TREE, _bind_root, revset_root, verify_non_membership
from atlas_pca.pca import _build, _leaf_hash, _node_hash, _path_shape, _split, b64u

IDS = ["b", "d", "f", "h", "j"]  # five leaves: an uneven RFC 6962 tree
ROOT = revset_root(IDS)


def _audit(hs, idx):
    if len(hs) == 1:
        return []
    k = _split(len(hs))
    if idx < k:
        return _audit(hs[:k], idx) + [("R", _build(hs[k:]))]
    return _audit(hs[k:], idx - k) + [("L", _build(hs[:k]))]


def leaf_proof(ids, i):
    hs = [_leaf_hash(x) for x in ids]
    return {"index": i, "size": len(ids), "path": [{"side": s, "hash": b64u(h)} for s, h in _audit(hs, i)]}


def entry(ids, i):
    return {"id": ids[i], "proof": leaf_proof(ids, i)}


def proof_for(ids, rid):
    lo = max([i for i, x in enumerate(ids) if x < rid], default=None)
    hi = min([i for i, x in enumerate(ids) if x > rid], default=None)
    p = {"size": len(ids)}
    if lo is not None:
        p["lo"] = entry(ids, lo)
    if hi is not None:
        p["hi"] = entry(ids, hi)
    return p


def test_path_builder_matches_the_verifier_shape():
    for n in range(1, 12):
        for i in range(n):
            assert [s["side"] for s in leaf_proof(list("abcdefghijkl")[:n], i)["path"]] == _path_shape(i, n)


@pytest.mark.parametrize("rid", ["a", "c", "e", "g", "i", "k", "bb", "ba", "jz"])
def test_accepts_every_bracketing(rid):
    assert verify_non_membership(ROOT, proof_for(IDS, rid), rid) is True


@pytest.mark.parametrize("n", range(1, 10))
def test_accepts_for_every_set_size(n):
    ids = list("bdfhjlnpr")[:n]
    root = revset_root(ids)
    for rid in ["a", "z"] + [x + "a" for x in ids]:
        assert verify_non_membership(root, proof_for(ids, rid), rid) is True


def test_empty_set():
    root = revset_root([])
    assert root == _bind_root(0, _EMPTY_TREE)
    assert verify_non_membership(root, {"size": 0}, "x") is True
    assert verify_non_membership(ROOT, {"size": 0}, "x") is False
    assert verify_non_membership(root, {"size": 0, "lo": entry(IDS, 0)}, "x") is False
    assert verify_non_membership(root, {"size": 0, "hi": entry(IDS, 0)}, "x") is False
    assert verify_non_membership(root, {"size": 0, "lo": entry(IDS, 0), "hi": entry(IDS, 1)}, "x") is False
    assert verify_non_membership(root, {"size": 1}, "x") is False


def test_members_are_refused():
    for rid in IDS:
        for lo in range(len(IDS)):
            for hi in range(len(IDS)):
                p = {"size": 5, "lo": entry(IDS, lo), "hi": entry(IDS, hi)}
                assert verify_non_membership(ROOT, p, rid) is False
    assert verify_non_membership(ROOT, {"size": 5, "lo": entry(IDS, 0)}, "b") is False


def test_input_types():
    p = proof_for(IDS, "c")
    for bad in (None, [], "x", 5, [p]):
        assert verify_non_membership(ROOT, bad, "c") is False
    for rid in (None, 5, ["c"], b"c"):
        assert verify_non_membership(ROOT, p, rid) is False
    assert verify_non_membership("x", p, "c") is False
    assert verify_non_membership(None, p, "c") is False
    assert verify_non_membership(ROOT[:-1] + ("A" if ROOT[-1] != "A" else "B"), p, "c") is False


@pytest.mark.parametrize("size", [-1, 1.5, "5", None, True, 4, 6, 0, float("inf")])
def test_size(size):
    p = proof_for(IDS, "c")
    p["size"] = size
    assert verify_non_membership(ROOT, p, "c") is False


def test_lo_hi_shapes():
    p = proof_for(IDS, "c")
    for bad in (None, [], "x", 5):
        assert verify_non_membership(ROOT, dict(p, lo=bad), "c") is False
        assert verify_non_membership(ROOT, dict(p, hi=bad), "c") is False
    q = {"size": 5}
    assert verify_non_membership(ROOT, q, "c") is False  # neither bracket
    for key in ("lo", "hi"):
        r = copy.deepcopy(p)
        r[key]["id"] = 5
        assert verify_non_membership(ROOT, r, "c") is False
        r = copy.deepcopy(p)
        del r[key]["id"]
        assert verify_non_membership(ROOT, r, "c") is False
        r = copy.deepcopy(p)
        del r[key]["proof"]
        assert verify_non_membership(ROOT, r, "c") is False


def test_ordering_is_strict_and_utf8():
    # lo must be < rid, rid < hi: equal and inverted brackets fail
    assert verify_non_membership(ROOT, {"size": 5, "lo": entry(IDS, 1), "hi": entry(IDS, 2)}, "d") is False
    assert verify_non_membership(ROOT, {"size": 5, "lo": entry(IDS, 1), "hi": entry(IDS, 2)}, "b") is False
    assert verify_non_membership(ROOT, {"size": 5, "lo": entry(IDS, 1), "hi": entry(IDS, 2)}, "f") is False
    assert verify_non_membership(ROOT, {"size": 5, "lo": entry(IDS, 1), "hi": entry(IDS, 2)}, "g") is False
    assert verify_non_membership(ROOT, {"size": 5, "lo": entry(IDS, 1), "hi": entry(IDS, 2)}, "e") is True
    # lo alone: rid above the last only
    assert verify_non_membership(ROOT, {"size": 5, "lo": entry(IDS, 4)}, "k") is True
    assert verify_non_membership(ROOT, {"size": 5, "lo": entry(IDS, 4)}, "j") is False
    assert verify_non_membership(ROOT, {"size": 5, "lo": entry(IDS, 4)}, "a") is False
    assert verify_non_membership(ROOT, {"size": 5, "hi": entry(IDS, 0)}, "a") is True
    assert verify_non_membership(ROOT, {"size": 5, "hi": entry(IDS, 0)}, "b") is False
    assert verify_non_membership(ROOT, {"size": 5, "hi": entry(IDS, 0)}, "c") is False
    # UTF-8 order, not code-unit order: an astral id sorts after U+FFFF
    ids = ["￿", "\U0001F600"]
    root = revset_root(ids)
    assert verify_non_membership(root, proof_for_sorted(ids, "￾"), "￾") is True


def proof_for_sorted(ids, rid):
    p = {"size": len(ids)}
    p["hi"] = entry(ids, 0)
    return p


def test_edges_and_adjacency():
    # lo only but not the last leaf; hi only but not the first leaf
    assert verify_non_membership(ROOT, {"size": 5, "lo": entry(IDS, 3)}, "k") is False
    assert verify_non_membership(ROOT, {"size": 5, "hi": entry(IDS, 1)}, "a") is False
    # non-adjacent bracket
    assert verify_non_membership(ROOT, {"size": 5, "lo": entry(IDS, 0), "hi": entry(IDS, 2)}, "c") is False
    assert verify_non_membership(ROOT, {"size": 5, "lo": entry(IDS, 1), "hi": entry(IDS, 1)}, "c") is False
    assert verify_non_membership(ROOT, {"size": 5, "lo": entry(IDS, 2), "hi": entry(IDS, 1)}, "e") is False


def _mut(path, fn):
    p = proof_for(IDS, "e")  # lo = d (1), hi = f (2)
    t = p[path]["proof"]
    fn(t)
    return p


@pytest.mark.parametrize("which", ["lo", "hi"])
def test_leaf_proof_rejections(which):
    def check(fn):
        assert verify_non_membership(ROOT, _mut(which, fn), "e") is False

    check(lambda t: t.update(index=t["index"] + 1))
    check(lambda t: t.update(index=-1))
    check(lambda t: t.update(index=1.5))
    check(lambda t: t.update(index="1"))
    check(lambda t: t.update(index=None))
    check(lambda t: t.pop("index"))
    check(lambda t: t.update(index=5))
    check(lambda t: t.update(size=4))
    check(lambda t: t.update(size=6))
    check(lambda t: t.update(size=None))
    check(lambda t: t.pop("size"))
    check(lambda t: t.update(path=None))
    check(lambda t: t.pop("path"))
    check(lambda t: t.update(path={}))
    check(lambda t: t.update(path=t["path"][:-1]))
    check(lambda t: t.update(path=t["path"] + [t["path"][0]]))
    check(lambda t: t["path"][0].update(side="L" if t["path"][0]["side"] == "R" else "R"))
    check(lambda t: t["path"][0].update(side=None))
    check(lambda t: t["path"][0].pop("side"))
    check(lambda t: t["path"][0].update(hash=None))
    check(lambda t: t["path"][0].pop("hash"))
    check(lambda t: t["path"][0].update(hash="A" * 43))
    check(lambda t: t["path"][0].update(hash=t["path"][0]["hash"] + "A"))
    check(lambda t: t["path"][0].update(hash=t["path"][0]["hash"][:-1]))
    check(lambda t: t["path"].__setitem__(0, "x"))
    check(lambda t: t["path"].__setitem__(0, None))
    check(lambda t: t["path"].__setitem__(-1, dict(t["path"][-1], hash=t["path"][0]["hash"])))
    check(lambda t: t.update(index=True))
    # an unmodified proof passes
    assert verify_non_membership(ROOT, _mut(which, lambda t: None), "e") is True
