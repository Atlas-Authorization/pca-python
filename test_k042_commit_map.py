"""Kill tests for atlas_pca.intent_map.commit_map / disclose: leaf order, per-leaf salts, the commitment (recomputed
independently through commit_leaves), the disclosure round trip through decide_map_disclosure, and every refusal."""
import pytest

from atlas_pca.intent_map import (
    MAX_MAP_LEAVES, commit_leaves, commit_map, decide_map_disclosure, map_leaf_salt,
)
from atlas_pca.pca import b64u, params_digest

SECRET = bytes(range(32))
METRICS = {"residual_risk_ppm": 1200, "burden_ppm": 3, "uncertainty_ppm": 4, "disagreement_ppm": 0, "mean_harm_ppm": 10,
           "fidelity_est_ppm": 990000, "entropy_mbits": 12, "questions": 2, "conflicts": 0}
DIGEST = "oYPfuowHnO_E-SdgwM9qFMZs-nCcDU9vh6mge4XccmU"
DIMS = [{"kind": "num", "path": "action.params.total", "lo": 0, "hi": 100, "cuts": [40]},
        {"kind": "cat", "path": "action.params.cabin",
         "values": [{"kind": "exact", "value": "economy"}, {"kind": "other", "value": "⊥"}]}]  # 3 x 2 = 6 cells
H_B = {"verb": "b.book", "dims": DIMS}
H_A = {"verb": "a.read", "dims": [{"kind": "cat", "path": "action.resource",
                                   "values": [{"kind": "exact", "value": "r"}, {"kind": "other", "value": "⊥"}]}]}


def _cells(n):
    return [{"cell": [i], "p_ppm": i, "in_grant": True} for i in range(n)]


def _cells_b():
    out = []
    for i in range(3):
        for j in range(2):
            out.append({"cell": [i, j], "p_ppm": 10 * i + j, "in_grant": i != 2})
    return out


def _build(**kw):
    a = dict(headers=[H_B, H_A], cells={"a.read": _cells(2), "b.book": _cells_b()}, metrics=METRICS,
             learner_digest=DIGEST, secret=SECRET)
    a.update(kw)
    return commit_map(a["headers"], a["cells"], a["metrics"], a["learner_digest"], a["secret"])


def test_layout_order_and_commitment():
    m = _build()
    assert m["size"] == 2 + 2 + 6 + 2 == len(m["leaves"])
    kinds = [x["kind"] for x in m["leaves"]]
    assert kinds == ["header"] * 2 + ["cell"] * 8 + ["metrics", "learner"]
    h0, h1 = m["leaves"][0]["leaf"], m["leaves"][1]["leaf"]
    assert (h0["verb"], h0["first"], h0["cells"]) == ("a.read", 2, 2)  # sorted by verb bytes
    assert (h1["verb"], h1["first"], h1["cells"]) == ("b.book", 4, 6)
    assert [x["leaf"]["verb"] for x in m["leaves"][2:10]] == ["a.read"] * 2 + ["b.book"] * 6
    assert m["leaves"][4]["leaf"] == {"verb": "b.book", "cell": [0, 0], "p_ppm": 0, "in_grant": True}
    assert m["leaves"][11]["leaf"] == {"learner_digest": DIGEST}
    assert m["leaves"][10]["leaf"] == METRICS
    for i, x in enumerate(m["leaves"]):
        assert x["salt"] == b64u(map_leaf_salt(SECRET, i))
    assert m["map_commit"] == commit_leaves(m["leaves"])
    assert _build()["map_commit"] == m["map_commit"]
    assert _build(secret=bytes(32))["map_commit"] != m["map_commit"]


def test_disclosure_round_trip_and_refusals():
    m = _build()
    params = {"total": 40, "cabin": "economy"}
    d = m["disclose"]("b.book", "res", params)
    assert d["size"] == m["size"] and d["metrics"]["index"] == m["size"] - 2 and d["header"]["index"] == 1
    assert d["cell"]["index"] == 4 + 1 * 2 + 0  # total 40 is the cut cell (index 1)
    act = {"verb": "b.book", "resource": "res", "params_digest": params_digest(params)}
    assert decide_map_disclosure(m["map_commit"], act, d, params)["ok"] is True
    p2 = {"total": 10, "cabin": "z"}
    act2 = {"verb": "b.book", "resource": "x", "params_digest": params_digest(p2)}
    out = decide_map_disclosure(m["map_commit"], act2, m["disclose"]("b.book", "x", p2), p2, 0)
    assert out["ok"] is False and "exceeds" in out["reason"]
    with pytest.raises(ValueError, match="^commit_map.disclose: verb nope is not in the map$"):
        m["disclose"]("nope", "r", {})
    with pytest.raises(ValueError, match="commit_map.disclose: the action's"):
        m["disclose"]("b.book", "r", {"total": 500, "cabin": "economy"})


def test_refusals():
    with pytest.raises(ValueError, match="^commit_map: the secret is 32 bytes$"):
        _build(secret=bytes(31))
    with pytest.raises(ValueError, match="^commit_map: the secret is 32 bytes$"):
        _build(secret=bytes(33))
    with pytest.raises(ValueError, match="^commit_map: duplicate verb$"):
        _build(headers=[H_A, H_A])
    with pytest.raises(ValueError, match="^commit_map: verb a.read needs 2 cell leaves$"):
        _build(cells={"a.read": _cells(1), "b.book": _cells_b()})
    with pytest.raises(ValueError, match="^commit_map: verb b.book needs 6 cell leaves$"):
        _build(cells={"a.read": _cells(2)})
    with pytest.raises(ValueError, match="^commit_map: verb a.read needs 2 cell leaves$"):
        _build(cells={"a.read": "xx", "b.book": _cells_b()})
    with pytest.raises(ValueError, match="^commit_map: "):
        _build(metrics={})
    with pytest.raises(ValueError, match="^commit_map: "):
        _build(learner_digest="x")
    bad = _cells(2)
    bad[0] = {"cell": [0], "p_ppm": -1, "in_grant": True}
    with pytest.raises(ValueError, match="^commit_map: "):
        _build(cells={"a.read": bad, "b.book": _cells_b()})
    with pytest.raises(ValueError, match="^commit_map: the map has too few or too many leaves$"):
        commit_map([], {}, METRICS, DIGEST, SECRET)
    assert MAX_MAP_LEAVES > 4


def test_smallest_map_and_leaf_cap(monkeypatch):
    tiny = commit_map([{"verb": "v", "dims": []}], {"v": [{"cell": [], "p_ppm": 0, "in_grant": True}]}, METRICS, DIGEST,
                      SECRET)
    assert tiny["size"] == 4
    assert tiny["disclose"]("v", "r", {})["cell"]["index"] == 1
    import atlas_pca.intent_map as im
    monkeypatch.setattr(im, "MAX_MAP_LEAVES", 12)
    assert _build()["size"] == 12  # exactly the cap is fine
    monkeypatch.setattr(im, "MAX_MAP_LEAVES", 11)
    with pytest.raises(ValueError, match="^commit_map: the map has too few or too many leaves$"):
        _build()


def test_disclose_first_verb_reads_the_resource():
    m = _build()
    d = m["disclose"]("a.read", "r", {})  # the first header (index 0) and a cell keyed on action.resource
    assert d["header"]["index"] == 0 and d["cell"]["index"] == 2
    d = m["disclose"]("a.read", "other", {})
    assert d["cell"]["index"] == 3
