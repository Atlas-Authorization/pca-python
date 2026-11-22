"""Replay of the proved goal kernel (atlas_pca.goal_kernel over the Dafny extraction in atlas_pca/goal_kernel_gen).

1. Token-tape corpus (the goal-kernel corpus in test-data, from the reference's extracted JavaScript kernel on the goal conformance
   vectors): every op's output tape must be identical.
2. Typed front door on the goal conformance vectors themselves (when the monorepo layout puts them at ../../packages/pca-conformance):
   reasons, policy digest, and decision + witness of every probe.
Without the extraction the kernel tests skip, unless PCA_GOAL_KERNEL_REQUIRE=1 (CI after extraction), where they fail."""
import json
import os

import pytest

from atlas_pca import goal_kernel as K
from atlas_pca.goal_codec import decode_goal, encode_goal
from atlas_pca.goal_compiler import policy_digest
from base_oracle import load_ref

COUNT, BY_FN = load_ref("goal-kernel")
HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "..", "..", "packages", "pca-conformance", "vectors", "goal")


@pytest.fixture(scope="module")
def kernel():
    if not K.available():
        if os.environ.get("PCA_GOAL_KERNEL_REQUIRE") == "1":
            pytest.fail("PCA_GOAL_KERNEL_REQUIRE=1 but the extracted goal kernel is missing")
        pytest.skip("extracted goal kernel not present (atlas_pca/goal_kernel_gen)")
    return K


def test_corpus_shape():
    assert COUNT == len(BY_FN["kernel"]) and COUNT > 150


def test_tape_text_round_trip():
    for c in BY_FN["kernel"]:
        for x in [c["args"][0], c["args"][1], c["out"]["compile"]]:
            assert K.tape_to_text(K.tape_from_text(x)) == x
    assert K.tape_from_text("k5 i-3 s s68.1f600") == [["k", 5], ["i", -3], ["s", ""], ["s", "h\U0001f600"]]


def test_kernel_tapes(kernel):
    bad = []
    for c in BY_FN["kernel"]:
        g, o, probes = K.tape_from_text(c["args"][0]), K.tape_from_text(c["args"][1]), c["args"][2]
        want = c["out"]
        for op in ("typecheck", "compile", "render"):
            got = K.tape_to_text(kernel.kernel_call(op, g, o))
            if got != want[op]:
                bad.append("%s %s: %s != %s" % (c["name"], op, got[:120], want[op][:120]))
        assert len(probes) == len(want["probes"])
        for i, ((a, h), (dg, dp)) in enumerate(zip(probes, want["probes"])):
            at, ht = K.tape_from_text(a), K.tape_from_text(h)
            for op, w in (("decideg", dg), ("decidep", dp)):
                got = K.tape_to_text(kernel.kernel_call(op, g, o, at, ht))
                if got != w:
                    bad.append("%s#%d %s: %s != %s" % (c["name"], i, op, got, w))
    assert not bad, "%d divergent tape(s):\n%s" % (len(bad), "\n".join(bad[:25]))


def test_malformed_input_is_refused(kernel):
    assert kernel.kernel_call("typecheck", [["i", 7]], []) == [["i", 9]]
    with pytest.raises(Exception):
        kernel.kernel_call("typecheck", [["k", 1.5]], [])
    with pytest.raises(ValueError):
        kernel.kernel_call("nope", [], [])


def test_huge_string_does_not_overflow(kernel):
    big = [["s", "a" * (1 << 20)]]
    for op in ("typecheck", "compile", "render"):
        assert kernel.kernel_call(op, big, [])[0][0] == "i"


def _vectors():
    if not os.path.isdir(VECTORS):
        return []
    out = []
    for f in sorted(os.listdir(VECTORS)):
        if f.endswith(".json") and f != "index.json":
            with open(os.path.join(VECTORS, f), encoding="utf-8") as fh:
                v = json.load(fh)
            if v.get("kind") != "fn":
                out.append(v)
    return out


_RANK = {"deny": 0, "escalate": 1, "allow": 2}


def _strip(g):
    """Strip(g) of the proof: drop every grant a hole depends on (a global hole touches all of them), holes emptied."""
    hs = g.get("holes") or []
    return dict(g, grants=[x for x in g["grants"] if not any(h.get("global") or x["gid"] in (h.get("affects") or []) for h in hs)], holes=[])


def test_typed_front_door_on_conformance_vectors(kernel):
    vs = _vectors()
    if not vs:
        pytest.skip("goal conformance vectors not in this layout")
    bad = []
    for v in vs:
        if kernel.typecheck(v["goal"], v["ontology"]) != v["compile"]["reasons"]:
            bad.append(v["id"] + ": reasons")
        r = kernel.compile_goal(v["goal"], v["ontology"])
        if (policy_digest(r["policy"]) if r["ok"] else None) != v["policy_digest"]:
            bad.append(v["id"] + ": policy_digest")
        if decode_goal(kernel.render_tape(v["goal"])) != decode_goal(encode_goal(v["goal"])):
            bad.append(v["id"] + ": render")
        if not v["compile"]["ok"]:
            continue
        for i, p in enumerate(v["probes"]):
            d = kernel.decide_policy(v["goal"], v["ontology"], p["action"], p["history"])
            got = {"decision": d["decision"], "witness": d["witness"]} if d["ok"] else {"decision": "deny", "witness": None}
            if got != p["expect"] or (d["ok"] and d["decision"] == "allow" and not d["witnessChecked"]):
                bad.append("%s#%d: %r != %r" % (v["id"], i, got, p["expect"]))
            if d["ok"]:
                # with holes the compiler lowers Strip(g) (the grants a hole touches removed, holes emptied): the policy decision equals the goal
                # decision of the STRIPPED goal exactly, and is never more permissive than the goal decision of g itself (no holes: Strip(g) == g)
                dg = kernel.decide_goal(_strip(v["goal"]), v["ontology"], p["action"], p["history"])
                if dg != d["decision"]:
                    bad.append("%s#%d: decide_goal(Strip g) != decide_policy" % (v["id"], i))
                full = kernel.decide_goal(v["goal"], v["ontology"], p["action"], p["history"])
                if _RANK[d["decision"]] > _RANK[full]:
                    bad.append("%s#%d: decide_policy is more permissive than decide_goal(g)" % (v["id"], i))
                if not v["goal"].get("holes") and full != d["decision"]:
                    bad.append("%s#%d: decide_goal != decide_policy" % (v["id"], i))
    assert not bad, "%d divergence(s):\n%s" % (len(bad), "\n".join(bad[:25]))


def test_proved_kernel_review_wiring(kernel):
    pk = kernel.proved_kernel()
    assert pk.compile is kernel.compile_goal and pk.decide is kernel.decide_goal and pk.policy_digest is policy_digest
