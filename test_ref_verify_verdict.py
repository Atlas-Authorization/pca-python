"""Replays the TS-reference oracle of the flagship verifier's FULL verdict (testdata/ref-verify-verdict.json.gz, 1022 cases, one fn verifyVerdict(pcactn, opts)):
allow, r, requiredThreshold, every check with its tri-state status under the reference's names, the reasons (exact texts, exact order), the budget
and the assurance report. Hooks are constant data in the corpus ({enforced, ok, reason?, t?} | {throws} | {raw}); they become callables here. A
`hooks.replay` entry is not a hook of the reference's verifier and is ignored.

Counted deviations (every other member compares exactly; numbers to a relative 1e-12):
- JS-engine message texts: a reference reason that starts with one of the engine markers below is compared by that prefix only (the rest is the
  language's own error text); strict-parser wording the same way.
- allowUnboundPq: the legacy unbound-PQ opt-out is never ported; the flag is ignored, and the two corpus cases that set it are Ed25519 ones, which
  the opt-out does not change."""
import copy
import math
import os

from atlas_pca.verify_verdict import verify_pcactn_verdict
from base_oracle import HERE, dec, load

COUNT, CASES = load("verify-verdict", os.path.join(HERE, "testdata", "ref-verify-verdict.json.gz"))
TOTAL = 1022
ENGINE_TEXT = 11  # cases whose reference reasons carry a JS-engine / strict-parser text (6 verifier error, 3 strict JSON, 2 malformed)
UNBOUND_PQ_OPT_OUT = 2
_CLIP = {"verifier error (fail closed): ": "verifier error (fail closed): ", "undecodable PCActn: strict JSON: ": "undecodable PCActn: ",
         "malformed PCActn: Cannot read properties": "malformed PCActn: "}


def _hook(spec):
    if not isinstance(spec, dict):
        return lambda ctx: spec
    if "throws" in spec:
        def boom(ctx):
            raise RuntimeError(spec["throws"])
        return boom
    if "raw" in spec:
        return lambda ctx: copy.deepcopy(spec["raw"])
    return lambda ctx: copy.deepcopy(spec)


def _opts(o):
    o = copy.deepcopy(o)
    if isinstance(o.get("hooks"), dict):
        o["hooks"] = {n: _hook(h) for n, h in o["hooks"].items() if n != "replay"}
    att = (o.get("enforce") or {}).get("attestation")
    if isinstance(att, dict) and "verifier" in att:
        att["verifier"] = _hook(att["verifier"])
    return o


def _engine(reason):
    return next((m for m in _CLIP if isinstance(reason, str) and reason.startswith(m)), None)


def _reasons_equal(got, ref):
    if not isinstance(got, list) or len(got) != len(ref):
        return False
    for g, r in zip(got, ref):
        m = _engine(r)
        if not (isinstance(g, str) and g.startswith(_CLIP[m]) if m else g == r):
            return False
    return True


def _same(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b or math.isclose(a, b, rel_tol=1e-12, abs_tol=1e-15)
    if isinstance(a, dict) and isinstance(b, dict):
        return set(a) == set(b) and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    return a == b


def _equal(got, ref):
    if not isinstance(got, dict) or set(got) != set(ref) or not _reasons_equal(got["reasons"], ref["reasons"]):
        return False
    return all(_same(got[k], ref[k]) for k in ref if k != "reasons")


def test_total_and_fn_names():
    assert COUNT == TOTAL == len(CASES["verifyVerdict"]) and set(CASES) == {"verifyVerdict"}


def test_every_verdict_matches_the_reference():
    bad, engine, opt_out = [], 0, 0
    for c in CASES["verifyVerdict"]:
        pcactn, opts = dec(copy.deepcopy(c["args"]))
        ref = c["out"]
        engine += any(_engine(r) for r in ref["reasons"])
        opt_out += isinstance(opts, dict) and "allowUnboundPq" in opts
        got = verify_pcactn_verdict(pcactn, _opts(opts))
        if not _equal(got, ref):
            bad.append((c["name"], got, ref))
    assert not bad, "%d of %d differ from the TS reference:\n%s" % (len(bad), TOTAL, "\n".join(
        "  %s\n    native: %s\n    ref:    %s" % (n, str(g)[:600], str(r)[:600]) for n, g, r in bad[:25]))
    assert engine == ENGINE_TEXT and opt_out == UNBOUND_PQ_OPT_OUT


def test_the_unbound_pq_opt_out_changes_nothing():
    # the flag is ignored: the same options without it give the same verdict
    for c in CASES["verifyVerdict"]:
        pcactn, opts = dec(copy.deepcopy(c["args"]))
        if isinstance(opts, dict) and "allowUnboundPq" in opts:
            without = {k: v for k, v in opts.items() if k != "allowUnboundPq"}
            assert verify_pcactn_verdict(pcactn, _opts(opts)) == verify_pcactn_verdict(pcactn, _opts(without))


def _unknown_requirement(axis, value):
    pcactn, opts = dec(copy.deepcopy(CASES["verifyVerdict"][0]["args"]))
    opts["requireAssurance"] = {axis: value}
    v = verify_pcactn_verdict(pcactn, _opts(opts))
    assert v["allow"] is False and v["checks"]["assurance"] == "fail"
    assert any(r.startswith("assurance: ") for r in v["reasons"])


def test_an_unknown_attestation_requirement_refuses():
    _unknown_requirement("attestation", "quantum")


def test_an_unknown_zk_requirement_refuses():
    _unknown_requirement("zk", "magic")
