"""Differential kill tests (rule 16 facts / relational dimensions / offer sets, rule 17 provenance / label receipts / flows /
read purpose) against the shared TS-generated oracle testdata/k042-oracleprov.json.gz
(tools/pca-audit/java-mutate/k042-oracleprov-oracle.mjs; Java K042OracleProvOracleTest runs the same file). Every case
compares the FULL result, member order included."""
import gzip
import json
import os

import pytest

from atlas_pca import intent_wb as W

with gzip.open(os.path.join(os.path.dirname(__file__), "testdata", "k042-oracleprov.json.gz"), "rt", encoding="utf-8") as fh:
    CASES = json.load(fh, parse_int=lambda t: -0.0 if t == "-0" else int(t))["cases"]

VALIDATORS = {
    "validateFactWire": W.validate_fact_wire,
    "validateWorldPolicy": W.validate_world_policy,
    "validateOfferPolicy": W.validate_offer_policy,
    "validateOfferSetWire": W.validate_offer_set_wire,
    "validateLabelsWire": W.validate_labels_wire,
    "validateFlowRules": W.validate_flow_rules,
    "validateProvenancePolicy": W.validate_provenance_policy,
    "validateProvWire": W.validate_prov_wire,
}


def ser(v):
    """JSON text keeping member ORDER (a reordered world / labels map is a difference), numbers by value."""
    if isinstance(v, dict):
        return "{" + ",".join("%s:%s" % (json.dumps(k), ser(x)) for k, x in v.items()) + "}"
    if isinstance(v, list):
        return "[" + ",".join(ser(x) for x in v) + "]"
    if isinstance(v, float) and v == int(v) and abs(v) < 1e17:
        return str(int(v))
    return json.dumps(v)


def _run(c):
    kind = c["kind"]
    if kind == "fn":
        return ser(VALIDATORS[c["fn"]](c["arg"])), ser(c["want"])
    if kind == "ratio":
        return ser(W.ratio_ppm(c["a"], c["b"])), ser(c["want"])
    if kind == "flowRule":
        return ser(W.flow_rule_for(c["rules"], c["cls"])), ser(c["want"])
    if kind == "flowAllowed":
        return ser(W.flow_allowed(c["rules"], c["cls"], c["origin"], c["aud"])), ser(c["want"])
    if kind == "active":
        inp = {k: c[k] for k in ("committed", "policy") if k in c}
        return ser(W.intent_world_active(inp)), ser(c["expect"])
    if kind == "read":
        r, e = W.decide_read_purpose(c["input"]), c["expect"]
        pick = lambda d: {k: d[k] for k in ("outcome", "minimise", "uncovered")}  # noqa: E731
        return ser(pick(r)), ser(pick(e))
    if kind == "world":
        r, e = W.decide_intent_world(c["input"]), c["expect"]
        if r["ok"]:
            got = "ok %s %s" % (ser(r["world"]), ser(r.get("single_source")))
        else:
            got = "fail %s" % ser(r["reason"])
        if e["ok"]:
            want = "ok %s %s" % (ser(e["world"]), ser(e.get("single_source")))
        else:
            want = "fail %s" % ser(e["reason"])
        return got, want
    if kind == "prov":
        r, e = W.decide_param_provenance(c["input"]), c["expect"]
        parts = lambda d: " | ".join([d["outcome"], ser(d.get("reason")), ser(d.get("friction")), ser(d["labels"]),  # noqa: E731
                                      ser(d["classes"]), ser(d["env"])])
        return parts(r), parts(e)
    raise AssertionError("unknown kind " + kind)


def test_corpus_is_the_full_oracle():
    assert len(CASES) > 1900


@pytest.mark.parametrize("kind", ["fn", "ratio", "flowRule", "flowAllowed", "active", "read", "world", "prov"])
def test_matches_the_reference(kind):
    bad = []
    for c in CASES:
        if c["kind"] != kind:
            continue
        try:
            got, want = _run(c)
        except Exception as ex:  # noqa: BLE001
            bad.append("%s threw %r" % (c["name"], ex))
            continue
        if got != want:
            bad.append("%s\n   got  %s\n   want %s" % (c["name"], got, want))
    assert bad == [], "\n".join(bad[:40])
