"""Differential kill tests (rule 13: the `intent_session` wire member, the grant caveat, the signed session root and the
session revocation step) against the shared TS-generated oracle testdata/k042-sessrevoc-cases.json
(tools/pca-audit/java-mutate/k042-sessrevoc-oracle.mts; Java K042SessRevocTest runs the same file). Exact reasons are
compared; a thrown-internal-error text only up to its language-neutral prefix "(fail closed): "."""
import json
import os

import pytest

from atlas_pca.intent_v2 import check_session_revocation, session_root_shape_error, verify_session_root
from atlas_pca.pca import intent_session_caveat_error, validate_intent_session_wire

with open(os.path.join(os.path.dirname(__file__), "testdata", "k042-sessrevoc-cases.json"), encoding="utf-8") as fh:
    G = json.load(fh)

FAIL_CLOSED = "(fail closed): "
REV_PARAMS = ("session", "authority", "ids", "now", "max_age_ms", "last", "scope")


def _j(t):
    return json.loads(t, parse_int=lambda s: -0.0 if s == "-0" else int(s))


def _same(name, want, got):
    if isinstance(want, str) and want.endswith(FAIL_CLOSED):
        assert got is not None and got.startswith(want), "%s: %r" % (name, got)
    else:
        assert got == want, name


def _ids(k):
    return [c["name"] for c in G[k]]


def _reason(r):
    return None if r["ok"] else r["reason"]


def test_corpus_sizes():
    assert [len(G[k]) for k in ("wire", "caveat", "root", "rev", "prim")] == [62, 17, 158, 100, 27]


@pytest.mark.parametrize("c", G["wire"], ids=_ids("wire"))
def test_wire(c):
    _same(c["name"], c["reason"], validate_intent_session_wire(_j(c["v"])))


@pytest.mark.parametrize("c", G["caveat"], ids=_ids("caveat"))
def test_caveat(c):
    _same(c["name"], c["reason"], intent_session_caveat_error(_j(c["c"])))


@pytest.mark.parametrize("c", G["root"], ids=_ids("root"))
def test_root(c):
    s = _j(c["s"])
    _same("shape " + c["name"], c["shape"], session_root_shape_error(s))
    pins = _j(c["pq_pins"]) if c.get("pq_pins") is not None else None
    got = verify_session_root(s, pins)
    if not got["ok"] and "unsupported_suite" in got["reason"] and not (c["verify"] or "").startswith("unsupported_suite"):
        pytest.skip("PQ suite unavailable on this host")
    _same("verify " + c["name"], c["verify"], _reason(got))


@pytest.mark.parametrize("c", G["rev"], ids=_ids("rev"))
def test_revocation(c):
    ev = _j(c["ev"]) if c["ev"] is not None else None
    ids = _j(c["ids"]) if c["ids"] is not None else None
    kw = {}
    if c["last"] is not None:
        kw["last"] = _j(c["last"])
    if c["scope"] is not None:
        kw["scope"] = c["scope"]
    got = check_session_revocation(ev, session=c["session"], authority=_j(c["authority"]), ids=ids, now=c["now"],
                                   max_age_ms=c["maxAge"], **kw)
    _same(c["name"], c["reason"], _reason(got))


@pytest.mark.parametrize("c", G["prim"], ids=_ids("prim"))
def test_primitive(c):
    i = _j(c["text"])
    if not isinstance(i, dict):
        pytest.skip("not an object")
    ev = {k: v for k, v in i.items() if k not in REV_PARAMS}
    kw = {"last": i["last"]} if "last" in i else {}  # the reference primitive ignores a `scope` input member
    got = check_session_revocation(ev, session=i.get("session"), authority=i.get("authority"), ids=i.get("ids"),
                                   now=i.get("now"), max_age_ms=i.get("max_age_ms"), **kw)
    _same(c["name"], c["reason"], _reason(got))
