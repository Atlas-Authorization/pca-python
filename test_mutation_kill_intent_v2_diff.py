"""Mutation kills (Intent Layer v2), differential: atlas_pca.intent_v2.decide_intent_v2 / intent_v2_active against the TS
reference decideIntentV2. testdata/k042-intentv2-cases.json.gz is the shared, language-neutral oracle
(tools/pca-audit/java-mutate/k042-intentv2-oracle.mts; the Java K042IntentV2DiffTest runs the same file): every case
asserts the EXACT check list (name, ok, reason, in order), the canonical env and `active`. A thrown-internal-error
reason is compared up to its language-neutral prefix "<check> error (fail closed): "."""
import gzip
import json
import os

import pytest

from atlas_pca.intent_v2 import decide_intent_v2, intent_v2_active, suite_capability_error
from atlas_pca.pca import canonicalize

with gzip.open(os.path.join(os.path.dirname(__file__), "testdata", "k042-intentv2-cases.json.gz"), "rt",
               encoding="utf-8") as fh:
    CASES = json.load(fh)["cases"]

FAIL_CLOSED = "(fail closed): "


def _j(t):
    return json.loads(t, parse_int=lambda s: -0.0 if s == "-0" else int(s))


def _ctx(cs):
    if "ctx" not in cs:
        return None
    ctx = _j(cs["ctx"])
    if "wp" in cs:  # a host supplying the plaintext params it parsed from the request
        ctx = dict(ctx)
        ctx["params"] = _j(cs["wp"])
    return ctx


def _checks(out, want):
    got = []
    for i, c in enumerate(out["checks"]):
        r = c.get("reason")
        w = want[i] if i < len(want) else None
        if r is not None and isinstance(w, dict) and w.get("prefix") and FAIL_CLOSED in r:
            r = r[: r.index(FAIL_CLOSED) + len(FAIL_CLOSED)]
        got.append((c["name"], c["ok"], r))
    return got


def test_corpus_is_the_full_oracle():
    assert len(CASES) > 1000


@pytest.mark.parametrize("cs", CASES, ids=[c["name"] for c in CASES])
def test_case_matches_the_reference(cs):
    p, grant, ctx = _j(cs["p"]), _j(cs["grant"]), _ctx(cs)
    if "ctx" in cs and ctx is None:
        # Python API: ctx None IS the absent context (documented); a JSON-null context (malformed in TS) has no separate
        # Python spelling. No conformance vector uses one.
        pytest.skip("JSON-null v2 context: not expressible in the Python API (None = absent)")
    out = decide_intent_v2(p, grant, ctx, cs["now"])
    for c in out["checks"]:  # a PQ suite this host's backend lacks is reported unsupported_suite here, by design
        if "unsupported_suite" in (c.get("reason") or "") and any(
                suite_capability_error(a) for a in ("ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f", "slh-dsa-sha2-256s")
                if a in c["reason"]):
            pytest.skip("PQ suite unavailable on this host")
    want = cs["checks"]
    assert _checks(out, want) == [(w["name"], w["ok"], w.get("reason")) for w in want]
    # TS always returns an env ({} when nothing applies); Python omits an empty one: same content
    assert canonicalize(out.get("env") or {}) == cs.get("env", "{}")
    assert intent_v2_active(p, ctx) == (cs["active"] in (True, "true", "True"))
