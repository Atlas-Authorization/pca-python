"""Replays the TS-reference oracle of the information-flow taint module (testdata/ref-taint.json.gz, 2344 cases): the level names and
constants, label rank / value / join, the trusted-input registry op scripts, classify_ref and compute_taint over registry and
resource-graph specs (including a registry or graph that throws and a registry that vouches for any kind). Every fn has a handler and
the totals are asserted; a reference refusal needs a native exception."""
import os

import pytest

from atlas_pca import taint as T
from base_oracle import HERE, load, run

COUNT, CASES = load("taint", os.path.join(HERE, "testdata", "ref-taint.json.gz"))


def _registry(rs):
    if rs is None:
        return None
    if rs.get("mode") == "fixed":
        return type("Fixed", (), {"lookup": staticmethod(lambda d: rs["fixed"])})()
    if rs.get("mode") == "throws":
        def boom(d):
            raise RuntimeError("registry boom")
        return type("Throws", (), {"lookup": staticmethod(boom)})()
    r = T.InMemoryTrustedInputRegistry()
    for d, label in rs.get("records") or []:
        r.record(d, label)
    return r


def _graph(gs):
    if not gs:
        return None

    def node(i):
        if gs.get("throws"):
            raise RuntimeError("graph boom")
        return {"id": i} if i in gs["nodes"] else None

    return type("G", (), {"node": staticmethod(node)})()


def _ctx(c):
    return _registry(c["registry"]), _graph(c.get("graph"))


def _registry_ops(ops):
    r, out = T.InMemoryTrustedInputRegistry(), []
    for op, *a in ops:
        if op == "lookup":
            out.append(r.lookup(a[0]))
        elif op == "size":
            out.append(r.size)
        elif op == "emptyLookup":
            out.append(T.EMPTY_REGISTRY.lookup(a[0]))
        else:
            getattr(r, {"record": "record", "recordTrusted": "record_trusted", "recordFirstParty": "record_first_party",
                        "recordTool": "record_tool", "recordWeb": "record_web"}[op])(*a)
            out.append(None)
    return out


HANDLERS = {
    "constants": lambda: {"TAINT_LEVELS": list(T.TAINT_LEVELS), "BOTTOM": T.BOTTOM, "TOP": T.TOP},
    "isTaintLevel": T.is_taint_level,
    "labelRank": T.label_rank,
    "taintValue": T.taint_value,
    "joinLabel": T.join_label,
    "joinLabels": T.join_labels,
    "registry": _registry_ops,
    "classifyRef": lambda ref, c: T.classify_ref(ref, *_ctx(c)),
    "computeTaint": lambda p, c: T.compute_taint(p, *_ctx(c)),
}
TOTALS = {"constants": 1, "isTaintLevel": 24, "labelRank": 27, "taintValue": 27, "joinLabel": 400, "joinLabels": 25, "registry": 9,
          "classifyRef": 841, "computeTaint": 990}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 2344 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS
    assert sum(1 for cs in CASES.values() for c in cs if isinstance(c["out"], dict) and "$throws" in c["out"]) == 150


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_taint_replay(fn):
    assert run(CASES[fn], HANDLERS[fn]) == (TOTALS[fn], 0)
