"""Replays the TS-reference oracle of the connector action catalog (testdata/ref-catalog.json.gz, 75 cases): defineAction, the
fail-closed spec of an unknown verb, the built-in rows with the default digest and the presets, and catalog scenarios (get, forConnector,
all, resolve, resolveAction, digest, the pin, extension). Every fn and every scenario op has a handler and the totals are asserted.
A scenario op that the reference refuses is {"$err": true}: the native must raise there, and only there."""
import math
import os

import pytest

from atlas_pca import catalog as C
from base_oracle import HERE, canon, load

COUNT, CASES = load("catalog", os.path.join(HERE, "testdata", "ref-catalog.json.gz"))


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        return {k: _dec(x) for k, x in v.items()}
    return [_dec(x) for x in v] if isinstance(v, list) else v


def _extended(cat, extra):
    e = C.extend_catalog(cat, extra)
    return {"all": e.all(), "digest": C.catalog_digest(e)}


def _pinned(cat, expected):
    C.assert_catalog_pinned(cat, C.catalog_digest(cat) if expected == "$self" else expected)
    return True


OPS = {  # op -> (handler, number of arguments; an argument the op leaves out is None)
    "get": (lambda cat, verb: cat.get(verb), 1),
    "forConnector": (lambda cat, c: cat.for_connector(c), 1),
    "all": (lambda cat: cat.all(), 0),
    "resolve": (lambda cat, c, a: cat.resolve(c, a), 2),
    "resolveAction": (C.resolve_action, 1),
    "digest": (C.catalog_digest, 0),
    "assertPinned": (_pinned, 1),
    "extend": (_extended, 1),
}
SEEN_OPS = set()


def _scenario(actions, ops):
    cat = C.build_catalog(actions)
    out = []
    for op in ops:
        SEEN_OPS.add(op[0])
        try:
            fn, n = OPS[op[0]]  # an op the reference does not know ("bogus") is refused on both sides
            out.append(fn(cat, *(list(op[1:]) + [None] * n)[:n]))
        except Exception:  # noqa: BLE001 - a refused op, compared against the reference's {"$err": true}
            out.append({"$err": True})
    return out


HANDLERS = {
    "defineAction": C.define_action,
    "uncataloguedSpec": C.uncatalogued_spec,
    "builtin": lambda: {"actions": C.BUILTIN_ACTIONS, "digest": C.catalog_digest(C.DEFAULT_CATALOG), "blast": C.BLAST},
    "catalog": _scenario,
}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 75 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == {"defineAction": 39, "uncataloguedSpec": 13, "builtin": 1, "catalog": 22}
    ops = {op[0] for c in CASES["catalog"] for op in c["args"][1]}
    assert ops == set(OPS) | {"bogus"}


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_catalog_replay(fn):
    bad = []
    for c in CASES[fn]:
        out = c["out"]
        threw = isinstance(out, dict) and "$throws" in out
        try:
            got = HANDLERS[fn](*_dec(c["args"]))
        except Exception as e:  # noqa: BLE001 - a native refusal, compared against the reference
            if not threw:
                bad.append("%s\n    native raised %s: %s\n    ref:    %s" % (c["name"], type(e).__name__, e, canon(out)[:300]))
            continue
        if threw or canon(got) != canon(out):
            bad.append("%s\n    native: %s\n    ref:    %s" % (c["name"], canon(got)[:600], canon(out)[:600]))
    assert not bad, "%d of %d differ from the reference:\n  %s" % (len(bad), len(CASES[fn]), "\n  ".join(bad[:25]))


def test_the_built_in_catalog_is_the_reference_catalog():
    ref = CASES["builtin"][0]["out"]
    assert len(C.BUILTIN_ACTIONS) == 21 and C.BUILTIN_ACTIONS == ref["actions"]
    C.assert_catalog_pinned(C.DEFAULT_CATALOG, ref["digest"])
    with pytest.raises(ValueError):
        C.assert_catalog_pinned(C.build_catalog(C.BUILTIN_ACTIONS[:-1]), ref["digest"])
