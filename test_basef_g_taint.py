"""L4 information-flow taint and the enforce_taint gate (reference taint.ts, verified-core computeTaintVerified / taintGateVerified)."""
import copy
import itertools
import json
import os

import pytest

import atlas_pca.pca as PCA
from atlas_pca import verify_pcactn_core
from atlas_pca import taint as T

ALL = [{"kind": k} for k in T.TAINT_LEVELS]
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_HERE, "conformance", "vectors.json"), os.path.join(_HERE, "conformance", "vectors.json")):
    if os.path.exists(_p):
        with open(_p, encoding="utf-8") as _f:
            V = {v["name"]: v for v in json.load(_f)["vectors"]}["valid-in-plan-action"]
        break


def reg(**kw):
    r = T.InMemoryTrustedInputRegistry()
    r.record_trusted("d-trusted").record_first_party("d-first").record_tool("d-tool", "search").record_web("d-web")
    return r


def prov(*refs):
    return {"causal_hash": "", "taint_level": 0, "trusted_refs": list(refs)}


class Graph:
    def __init__(self, *ids):
        self.ids = set(ids)

    def node(self, i):
        return {"id": i} if i in self.ids else None


def test_levels_values_and_ranks():
    assert T.TAINT_LEVELS == ("trusted", "first_party", "tool", "web", "agent")
    assert [T.taint_value(x) for x in ALL] == [0, 0.25, 0.5, 0.75, 1]
    assert [T.label_rank(x) for x in ALL] == [0, 1, 2, 3, 4]
    for bad in (None, {}, {"kind": "constructor"}, {"kind": 5}, "agent", {"kind": "__proto__"}):
        assert T.label_rank(bad) == 4 and T.taint_value(bad) == 1


def test_join_is_a_commutative_associative_idempotent_semilattice():
    assert T.join_label({"kind": "trusted"}, {"kind": "web"}) == {"kind": "web"}
    assert T.join_label({"kind": "agent"}, {"kind": "trusted"}) == {"kind": "agent"}
    assert T.join_label({"kind": "first_party"}, {"kind": "tool", "id": "a"}) == {"kind": "tool", "id": "a"}
    for a, b in itertools.product(ALL, ALL):
        assert T.taint_value(T.join_label(a, b)) == T.taint_value(T.join_label(b, a))
    for a in ALL:
        assert T.join_label(a, a) == a and T.join_label(a, {"kind": "trusted"}) == a
    for a, b, c in itertools.product(ALL, ALL, ALL):
        assert T.taint_value(T.join_label(T.join_label(a, b), c)) == T.taint_value(T.join_label(a, T.join_label(b, c)))
    assert T.join_label({"kind": "tool", "id": "a"}, {"kind": "tool", "id": "b"}) == {"kind": "tool"}
    assert T.join_label({"kind": "agent", "id": "p"}, {"kind": "agent", "id": "q"}) == {"kind": "agent"}
    assert T.join_label({"kind": "tool", "id": "a"}, {"kind": "tool", "id": "a"}) == {"kind": "tool", "id": "a"}


def test_the_empty_lineage_joins_to_the_worst_case():
    assert T.join_labels([]) == {"kind": "agent"} and T.taint_value(T.join_labels([])) == 1


def test_classify_ref_never_reads_the_agents_label():
    r = reg()
    assert T.classify_ref("d-trusted", r) == {"kind": "trusted"}
    assert T.classify_ref("d-web", r) == {"kind": "web"}
    assert T.classify_ref("d-tool", r) == {"kind": "tool", "id": "search"}
    assert T.classify_ref("doc:policy-1", r, Graph("doc:policy-1")) == {"kind": "first_party"}
    r.record_trusted("doc:policy-1")
    assert T.classify_ref("doc:policy-1", r, Graph("doc:policy-1")) == {"kind": "trusted"}  # the registry wins over the graph
    for bad in ("", 42, None, ["x"]):
        assert T.classify_ref(bad, r) == {"kind": "agent"}
    assert T.classify_ref("unknown", r) == {"kind": "agent", "id": "unknown"}
    assert T.classify_ref("x" * 129, r) == {"kind": "agent"} and T.classify_ref("x" * 128, r) == {"kind": "agent", "id": "x" * 128}


def test_a_throwing_graph_is_the_worst_case():
    class Boom:
        def node(self, i):
            raise RuntimeError("x")
    assert T.classify_ref("a", T.EMPTY_REGISTRY, Boom()) == {"kind": "agent", "id": "a"}


def test_compute_taint_of_an_all_trusted_lineage_is_zero_and_unverifiable_is_high():
    r = reg()
    res = T.compute_taint(prov("d-trusted"), r)
    assert res == {"taint": 0, "label": {"kind": "trusted"}, "refs": [{"ref": "d-trusted", "label": {"kind": "trusted"}}], "valid": True}
    assert T.compute_taint(prov("d-trusted", "d-web"), r)["taint"] == 0.75
    assert T.compute_taint(prov("d-trusted", "unknown-ref"), r)["taint"] == 1
    assert T.compute_taint(prov("d-first"), r)["taint"] == 0.25
    assert T.compute_taint(prov("d-tool"), r)["taint"] == 0.5
    empty = T.compute_taint(prov(), r)
    assert empty["valid"] is True and empty["taint"] == 1


@pytest.mark.parametrize("p,reason", [
    (None, "taint: provenance is absent or malformed"), ("x", "taint: provenance is absent or malformed"), ([], "taint: provenance is absent or malformed"),
    ({"trusted_refs": "a"}, "taint: trusted_refs must be an array"), ({"trusted_refs": ["a", 5]}, "taint: trusted_refs must be non-empty strings"),
    ({"trusted_refs": [""]}, "taint: trusted_refs must be non-empty strings")])
def test_malformed_provenance_fails_closed(p, reason):
    assert T.compute_taint(p, reg()) == {"taint": 1, "label": {"kind": "agent"}, "refs": [], "valid": False, "reason": reason}


def test_a_missing_registry_fails_closed_and_the_agents_taint_level_is_ignored():
    assert T.compute_taint(prov("u1"), None)["reason"] == "taint: no trusted-input registry"
    assert T.compute_taint(prov("u1"), T.EMPTY_REGISTRY)["taint"] == 1
    assert T.compute_taint({"taint_level": 0, "trusted_refs": ["u1"]}, T.EMPTY_REGISTRY)["taint"] == 1


def test_a_throwing_registry_is_reported_invalid():
    class Boom:
        def lookup(self, d):
            raise RuntimeError("reg down")
    assert T.compute_taint(prov("q"), Boom()) == {"taint": 1, "label": {"kind": "agent"}, "refs": [], "valid": False,
                                                  "reason": "taint: evaluation error (fail closed): reg down"}


def test_the_order_of_the_refs_does_not_matter():
    r = reg()
    a, b = T.compute_taint(prov("d-trusted", "d-web", "d-tool"), r), T.compute_taint(prov("d-tool", "d-trusted", "d-web"), r)
    assert a["taint"] == b["taint"] and a["label"] == b["label"]


def test_the_registry_ignores_malformed_records():
    r = T.InMemoryTrustedInputRegistry().record("", {"kind": "trusted"}).record("d", {"kind": "constructor"}).record(5, {"kind": "web"}).record("e", None)
    assert r.size == 0
    r.record_tool("d", "search")
    assert r.lookup("d") == {"kind": "tool", "id": "search"} and r.size == 1 and r.lookup("zz") is None
    got = r.lookup("d")
    got["id"] = "x"
    assert r.lookup("d") == {"kind": "tool", "id": "search"}


# ---- the gate ---------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("refs,mx,ok,reason", [
    (("d-trusted",), 0, True, None), (("d-first",), 0.25, True, None), (("d-first",), 0.24, False, "information-flow taint 0.25 exceeds policy max 0.24"),
    (("d-web",), 0.5, False, "information-flow taint 0.75 exceeds policy max 0.5"), (("zz",), 0, False, "information-flow taint 1 exceeds policy max 0"),
    (("zz",), 1, True, None), (("d-tool",), 0.5, True, None), (("d-tool",), 0.49, False, "information-flow taint 0.5 exceeds policy max 0.49"),
])
def test_the_gate_compares_the_independently_computed_taint(refs, mx, ok, reason):
    r = T.taint_gate(prov(*refs), reg(), None, mx)
    assert r == ({"ok": True} if ok else {"ok": False, "reason": reason})


@pytest.mark.parametrize("mx", [-1, float("nan"), float("inf"), "0.5", None, True])
def test_a_misconfigured_bound_never_passes(mx):
    assert T.taint_gate(prov("d-trusted"), reg(), None, mx) == {"ok": False, "reason": "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)"}


def test_an_invalid_lineage_is_denied_even_at_an_unbounded_max():
    assert T.taint_gate(None, reg(), None, 1)["reason"] == "taint: provenance is absent or malformed"
    assert T.taint_gate(None, reg(), None, -1)["reason"] == "taint: provenance is absent or malformed"  # a misconfigured max does not mask it


# ---- through the core verifier ----------------------------------------------------------------------------------------------------------

def core(provenance, gate, monkeypatch):
    monkeypatch.setattr(PCA, "_verify_suite", lambda *a, **k: True)  # the provenance member is signed: only the gate is under test
    p = copy.deepcopy(V["pcactn"])
    p["provenance"] = provenance
    return verify_pcactn_core(p, V["grant"], now=V["context"]["now"], audience=V["context"]["aud"], insecure_skip_plan_root_check=True, enforce_taint=gate)


def test_the_core_gate_passes_a_verified_lineage_and_refuses_the_rest(monkeypatch):
    good = core(prov("d-trusted"), {"registry": reg(), "max_taint": 0}, monkeypatch)
    assert good.allow is True and good.checks["taint_gate"] is True
    bad = core(prov("zz"), {"registry": reg(), "max_taint": 0.5}, monkeypatch)
    assert bad.allow is False and bad.checks["taint_gate"] is False
    assert bad.reason == "taint_gate: information-flow taint 1 exceeds policy max 0.5"
    stub = core({"causal_hash": "", "taint_level": 0, "trusted_refs": []}, {"registry": reg(), "max_taint": 0.5}, monkeypatch)
    assert stub.reason == "taint_gate: information-flow taint 1 exceeds policy max 0.5"


def test_the_core_gate_is_off_by_default_and_a_throwing_hook_fails_closed(monkeypatch):
    v = verify_pcactn_core(V["pcactn"], V["grant"], now=V["context"]["now"], audience=V["context"]["aud"], insecure_skip_plan_root_check=True)
    assert "taint_gate" not in v.checks

    class Boom:
        def get(self, k, d=None):
            raise RuntimeError("cfg")
    r = core(prov("d-trusted"), Boom(), monkeypatch)
    assert r.allow is False and r.reason == "taint_gate: taint gate error (fail closed): cfg"
