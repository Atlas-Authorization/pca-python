"""Differential replay of the data-flow model, the trace rules and the detector adapters (atlas_pca.dataflow) against the
vectors generated from the TypeScript reference (@atlasauth/pca-dataflow). Tagged values are rebuilt from the JSON specs the
generator describes; Ed25519 receipts are deterministic and compared byte for byte."""
import pytest

from atlas_pca import dataflow as D
from atlas_pca.agent import KeyPair
from base_oracle import load_ref, run

COUNT, CASES = load_ref("dataflow-py")
RS_COUNT, RS_CASES = load_ref("dataflow-rs")

OPS = {"concat": lambda *a: "|".join(a), "first": lambda a: a, "count": lambda *a: len(a)}


def _ro(s):
    return s.get("readers")


def _set(a):
    return set(a) if isinstance(a, list) else a


def build(s):
    k = s["k"]
    if k == "trusted":
        return D.from_trusted_query(s["value"], _ro(s))
    if k == "tool":
        return D.from_tool_output(s["name"], s["value"], _ro(s))
    if k == "source":
        return D.from_source(s["source"], s["value"], s.get("trusted", False), _ro(s))
    if k == "tag":
        c = s["cap"]
        if not isinstance(c, dict):
            return D.tag(s["value"], c)
        return D.tag(s["value"], D.Capability(_set(c["sources"]), c.get("isTrusted"), _set(c["readers"]) if "readers" in c else None))
    if k == "derive":
        return D.derive([build(x) for x in s["inputs"]], OPS[s["op"]])
    if k == "raw":
        return s["value"]
    if k == "fake":
        return {"value": s["value"], "cap": {}}
    raise AssertionError(k)


def _cap(c):
    out = {"sources": D._sorted(c.sources), "isTrusted": c.is_trusted}
    if c.readers is not None:
        out["readers"] = D._sorted(c.readers)
    return out


def out_t(t):
    return dict(tagged=True, value=t.value, **_cap(t.cap)) if D.is_tagged(t) else {"tagged": False}


def sink_of(s):
    if not isinstance(s, dict):
        return s
    a = s.get("accepts")
    if not isinstance(a, dict):
        return {"id": s.get("id"), "accepts": a}
    return {"id": s.get("id"), "accepts": {"external": a.get("external"), "require_trusted": a.get("require_trusted"),
                                           "allowed_sources": _set(a.get("allowed_sources")), "denied_sources": _set(a.get("denied_sources"))}}


def governor(g):
    def sink_for(act):
        if g["kind"] == "throw":
            raise RuntimeError("no sink")
        return sink_of(g["map"].get(act["verb"], g["default"]) if g["kind"] == "byVerb" else g["sink"])
    return sink_for


def mk(args):
    return [None if s is None else build(s) for s in args] if isinstance(args, list) else args


def _check(ac, ar, gv, ex=None):
    return D.check_action(ac, mk(ar), governor(gv), ex)


def _dual(q, op):
    qs = {"tool": lambda p: D.from_tool_output("q", "r:" + p), "trusted": D.from_trusted_query, "raw": lambda p: p,
          "fake": lambda p: {"value": p, "cap": {}}}
    r = D.dual_context(build(q), lambda x: "plan:" + x, qs[op])
    return {"plan": r["plan"], "result": out_t(r["result"])}


def _mixed(_x):
    return D.level_of(D.derive([D.from_tool_output("a", 1), D.from_source("user", 2)], lambda a, b: a + b))


def _ctx(c):
    out = {"detector": c["detector"], "version": c["version"], "content": c["content"],
           "secret_key": KeyPair(bytes([c["seed"]]) * 32, allow_insecure_signer=True), "now": c["now"]}
    for k in ("session", "calibration_ref"):
        if k in c:
            out[k] = c[k]
    return out


def _adapter(fn):
    return lambda resp, c: fn(resp, _ctx(c))


def _key(n):
    return KeyPair(bytes([n]) * 32, allow_insecure_signer=True)


def _caps(*specs):
    return [build(s).cap for s in specs]


T = lambda v: {"k": "trusted", "value": v}  # noqa: E731
L = lambda name, v: {"k": "tool", "name": name, "value": v}  # noqa: E731

MAP = {
    "build": lambda x: out_t(build(x)),
    "levelOf": None,  # per-case below
    "toolProvenance": D.tool_provenance,
    "combineCaps": None,
    "unionSources": None,
    "classifyFlow": lambda a, b: D.classify_flow(build(a), sink_of(b)),
    "canFlow": lambda a, b: D.can_flow(build(a), sink_of(b)),
    "externalSendSink": lambda i: D.external_send_sink(i),
    # the native sink policy keys are snake_case; the reference spells the same member requireTrusted
    "sensitiveSink": lambda i: {"id": D.sensitive_sink(i)["id"], "accepts": {"requireTrusted": D.sensitive_sink(i)["accepts"]["require_trusted"]}},
    "checkAction": _check,
    "dualContext": _dual,
    "lakeraReceipt": _adapter(D.lakera_receipt),
    "promptSecurityReceipt": _adapter(D.prompt_security_receipt),
    "genericReceipt": _adapter(D.generic_receipt),
    "detectorInputDigest": D.detector_input_digest,
    "signDetectorReceipt": lambda b, s: D.sign_detector_receipt(b, _key(s)),
    "detectorReceiptShapeError": D.detector_receipt_shape_error,
    "detectorReceiptRef": D.detector_receipt_ref,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 783 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(k for k, v in MAP.items() if v is not None))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])


def _label(c):
    return c["name"].split("/", 1)[1].split("#")[0]


def test_level_of_cases():
    # the generator names each case by what it builds; the specs are in the case args
    for c in CASES["levelOf"]:
        name = _label(c)
        if name == "null":
            assert D.level_of(None) == c["out"]
        elif name == "string":
            assert D.level_of("trusted") == c["out"]
        elif name == "mixed tool+user":
            assert _mixed(0) == c["out"]
        elif name == "empty derive":
            assert D.level_of(D.derive([], lambda: 1)) == c["out"]
        else:
            assert D.level_of(build(c["args"][0])) == c["out"], c["name"]


def test_combine_and_union_cases():
    by = {_label(c): c for c in CASES["combineCaps"]}
    assert _cap(D.combine_caps([])) == by["empty"]["out"]
    three = D.combine_caps(_caps(T("a"), dict(T("b"), readers=["x", "y"]), dict(T("c"), readers=["y"])))
    assert _cap(three) == by["three"]["out"]
    assert _cap(D.combine_caps(_caps(T("a"), L("w", "b")))) == by["untrusted"]["out"]
    assert D._sorted(D.union_sources(_caps(T("a"), L("w", "b")))) == CASES["unionSources"][0]["out"]


# ---- trace rules ---------------------------------------------------------------------------------------------------------

def _invariant(id, text, opts):
    o = opts if isinstance(opts, dict) else {}
    return D.parse_invariant_rule(id, text, o.get("horizon"), o.get("dropUnsupported"))


def _compile_texts(rules, table):
    return D.compile_trace_rules([D.parse_trace_rule(i, t) for i, t in rules], table)


def _trifecta(table, edges, opts=None):
    o = opts or {}
    return D.lethal_trifecta(table, edges, o.get("untrusted"), o.get("untrusted_traits"))


RS_MAP = {
    "parseTraceRule": D.parse_trace_rule,
    "parseInvariantRule": _invariant,
    "compileTexts": _compile_texts,
    "compileTraceRules": D.compile_trace_rules,
    "lethalTrifecta": _trifecta,
    "categoryId": D.category_id,
}


def test_trace_corpus_is_the_full_oracle():
    assert set(RS_CASES) == set(RS_MAP)


@pytest.mark.parametrize("fn", sorted(RS_MAP))
def test_trace_rules_match_the_reference(fn):
    run(RS_CASES[fn], RS_MAP[fn])
