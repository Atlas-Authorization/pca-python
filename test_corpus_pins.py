"""Every committed reference corpus is pinned: its case total is asserted here (so a regenerated or truncated corpus cannot silently shrink a
replay), every corpus is read by at least one replay test, and every fn of a corpus is named by a replay test that reads it (a fn without a
handler would otherwise be skipped silently). The handlers that are built programmatically, not spelled out, are listed in DYNAMIC with the
reason; the corpora whose replay is still open are in OPEN."""
import glob
import gzip
import json
import os
import re

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
PINS = {
    "base-actionregistry": 21429,
    "base-actions": 65203,
    "base-actionschema": 16139,
    "base-approval": 4791,
    "base-argprov": 9825,
    "base-authorize": 13320,
    "base-caveatlang": 16104,
    "base-intenthistory": 29179,
    "base-mesh": 16267,
    "base-prohibitions": 21781,
    "base-provgate": 4616,
    "base-sigstore": 7002,
    "base-undo": 5985,
    "ref-a2a": 6337,
    "ref-abe": 254,
    "ref-acp": 6391,
    "ref-action-pin": 111,
    "ref-action-schema": 173,
    "ref-action-schema-draft": 104,
    "ref-actions-author": 503,
    "ref-actions-author-py": 151,
    "ref-actions-build-py": 183,
    "ref-actions-compat": 133,
    "ref-actions-derive": 1829,
    "ref-actions-diff": 1302,
    "ref-actions-evolve": 154,
    "ref-actions-hosted-py": 91,
    "ref-actions-import-core": 1267,
    "ref-actions-import-review": 362,
    "ref-actions-import-sdl": 1033,
    "ref-actions-import-suggest": 1236,
    "ref-actions-lint": 2231,
    "ref-actions-render-facade": 864,
    "ref-actions-review-py": 229,
    "ref-actions-rules-py": 2766,
    "ref-actions-sel-conf": 1266,
    "ref-actions-signbuiltins-py": 4,
    "ref-actions-templates-py": 169,
    "ref-actions-test-runner": 47,
    "ref-actions-yaml-load-py": 105,
    "ref-adapters": 71,
    "ref-agent-native": 1632,
    "ref-agentcard": 449,
    "ref-aggsig": 552,
    "ref-analyzer": 6309,
    "ref-ap2": 3528,
    "ref-ap2-java-extra": 127,
    "ref-attest-allowlist": 959,
    "ref-attest-eat": 1452,
    "ref-attest-vendors": 758,
    "ref-attest-maa": 261,
    "ref-attest-nvidia": 467,
    "ref-attest-nvidia-rim": 163,
    "ref-attest-pq-software": 137,
    "ref-attest-puf": 278,
    "ref-attestation-soft": 512,
    "ref-authzen": 3095,
    "ref-bbs": 278,
    "ref-beacons": 174,
    "ref-budget-forecast": 326,
    "ref-catalog": 75,
    "ref-ciba": 200,
    "ref-compliance": 812,
    "ref-connect": 845,
    "ref-connectors": 1708,
    "ref-connectors-providers": 40,
    "ref-contracts": 1269,
    "ref-control-blue": 362,
    "ref-control-evals": 3702,
    "ref-core-frost-java": 170,
    "ref-core-mesh-domain-java": 18,
    "ref-core-mesh-proof-java": 8,
    "ref-core-research-java": 6188,
    "ref-core-small-surface": 1113,
    "ref-core-stores-java": 227,
    "ref-core-sweep-java": 2167,
    "ref-core-yaml-anchors-java": 32,
    "ref-core-yaml-java": 823,
    "ref-dataflow-py": 783,
    "ref-dataflow-rs": 142,
    "ref-decide-derive": 240,
    "ref-decide-java": 226,
    "ref-doctor": 1597,
    "ref-dpop": 1040,
    "ref-durable-state": 232,
    "ref-entropy": 562,
    "ref-erc7715": 4314,
    "ref-events": 1071,
    "ref-evidence": 1772,
    "ref-evidence-bundle-py": 204,
    "ref-explain": 2107,
    "ref-fetch": 59,
    "ref-fndsa": 480,
    "ref-frontier-signals": 690,
    "ref-frost-dkg": 439,
    "ref-frost-net": 634,
    "ref-gateway": 444,
    "ref-gateway-worker-py": 88,
    "ref-gnap": 2120,
    "ref-goal": 2213,
    "ref-goal-bench": 461,
    "ref-goal-drift": 152,
    "ref-goal-examples": 132,
    "ref-goal-interpret": 4859,
    "ref-goal-kernel": 203,
    "ref-goal-legacy": 125,
    "ref-goal-nversion": 93,
    "ref-goal-ontology": 2579,
    "ref-goal-precedent": 34,
    "ref-goal-review": 450,
    "ref-goal-roundtrip": 78,
    "ref-goal-selectors-java": 363,
    "ref-goal-selectors-py": 1034,
    "ref-grants": 2767,
    "ref-ha": 753,
    "ref-harness": 824,
    "ref-idjag": 370,
    "ref-immune-java": 559,
    "ref-intent-attest": 134,
    "ref-intent-glue-py": 146,
    "ref-intent-jit": 219,
    "ref-intent-layers": 419,
    "ref-intent-learner": 443,
    "ref-intent-map": 183,
    "ref-intent-misc": 795,
    "ref-intent-misc2": 770,
    "ref-intent-multi-agg": 76,
    "ref-intent-nl-java": 250,
    "ref-intent-omega": 5377,
    "ref-intent-profile": 1996,
    "ref-intent-refine": 179,
    "ref-intent-render": 269,
    "ref-intent-routing": 849,
    "ref-intent-runtime": 585,
    "ref-intent-schema": 267,
    "ref-intent-stats": 995,
    "ref-intent-world": 52,
    "ref-invariants": 312,
    "ref-kem": 464,
    "ref-mcp": 2749,
    "ref-mesh-issue": 787,
    "ref-mpc": 1570,
    "ref-mpc-endemic": 80,
    "ref-mpc-net": 349,
    "ref-mpc-ot": 440,
    "ref-nl-approval": 206,
    "ref-notary": 1752,
    "ref-oauth": 840,
    "ref-objective-risk": 4052,
    "ref-oidc": 662,
    "ref-openai-agents": 192,
    "ref-oprf": 508,
    "ref-otel": 1075,
    "ref-passport": 516,
    "ref-payments": 3144,
    "ref-payments-java-extra": 137,
    "ref-policy-bridge": 4361,
    "ref-policy-ci": 2060,
    "ref-policy-ci-java-extra": 162,
    "ref-policy-debug": 553,
    "ref-pq-threshold": 212,
    "ref-pq-threshold-java-extra": 100,
    "ref-pq-threshold-quorum": 389,
    "ref-progress": 723,
    "ref-prohibitions": 1637,
    "ref-rag": 397,
    "ref-ratchet": 1095,
    "ref-ratchet-kat": 0,  # known-answer file, not a case corpus (read by test_ref_ratchet.py)
    "ref-reputation": 85,
    "ref-revoke": 1921,
    "ref-rotate": 1239,
    "ref-safety-certificate": 262,
    "ref-sandbox": 1604,
    "ref-schema": 3216,
    "ref-scim": 1124,
    "ref-scitt": 8036,
    "ref-sdjwt": 353,
    "ref-semantic-threshold": 186,
    "ref-sevsnp-helpers": 248,
    "ref-siem": 1290,
    "ref-signals": 2409,
    "ref-spiffe": 3346,
    "ref-spiffe-svid": 1157,
    "ref-store-conformance": 2205,
    "ref-store-conformance-java": 49,
    "ref-store-conformance-pca-state-py": 4,
    "ref-taint": 2344,
    "ref-testing": 2594,
    "ref-txn-tokens": 106,
    "ref-vc": 338,
    "ref-verify-verdict": 1022,
    "ref-vdf": 6673,
    "ref-wallet": 7360,
    "ref-wallet-learner-py": 239,
    "ref-webauthn-py": 361,
    "ref-webbotauth": 1253,
    "ref-zk": 1429,
}
# fns whose handler is generated or dispatched by a rule rather than named
DYNAMIC = {
    "ref-kem": {"hybridKemKeygen", "hybridKem1024Keygen", "hybridEncapsulate1024", "hybridDecapsulate1024"},  # the 768 / 1024 handlers are built by one factory
    "ref-durable-state": {"scenario"},  # one scenario runner dispatches on the case's own steps
    "ref-intent-nl-java": {"nlRun"},  # the fallthrough of the replay runs the compilers over the case
}
# corpora whose replay is still open (the exact remainder of the parity program)
OPEN = set()  # no corpus is left without a replay


def _corpora():
    out = {}
    for path in sorted(glob.glob(os.path.join(HERE, "testdata", "*.json.gz")) + glob.glob(os.path.join(HERE, "test-data", "*.json.gz"))):
        name = os.path.basename(path)[:-8]
        if name.startswith(("ref-", "base-")) and name not in out and not name.endswith("-gen") and name != "ref-dpop-rsa":  # generated in CI, never committed
            out[name] = path
    return out


def _tests():
    return {os.path.basename(f): open(f, encoding="utf-8").read() for f in glob.glob(os.path.join(HERE, "test_*.py")) if not f.endswith("test_corpus_pins.py")}


def _users(name, tests):
    suf = re.sub(r"^(ref|base)-", "", name)
    pats = [name + ".json", '("%s")' % suf, '"%s"' % name, "'%s'" % name, 'load_ref("%s"' % suf, "load_ref('%s'" % suf, 'load("%s"' % suf, "load('%s'" % suf, 'load_gen("%s"' % suf]
    return [f for f, t in tests.items() if any(p in t for p in pats)]


def _load(path):
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return json.load(fh)


def test_every_corpus_is_pinned_and_the_pins_name_a_corpus():
    found = _corpora()
    assert set(found) >= set(PINS), sorted(set(PINS) - set(found))
    assert not (set(found) - set(PINS)), "unpinned corpora: %s" % sorted(set(found) - set(PINS))


@pytest.mark.parametrize("name", sorted(PINS))
def test_corpus_total_is_pinned(name):
    d = _load(_corpora()[name])
    if "cases" in d:
        assert len(d["cases"]) == PINS[name] == d.get("count", PINS[name])


def test_every_corpus_is_replayed_and_every_fn_is_named():
    tests, bad = _tests(), []
    for name, path in _corpora().items():
        if name in OPEN:
            continue
        users = _users(name, tests)
        if not users:
            bad.append("%s: no replay test reads it" % name)
            continue
        text = "\n".join(tests[f] for f in users)
        d = _load(path)
        for fn in sorted({c["fn"].split("@")[0] for c in d.get("cases", [])} - DYNAMIC.get(name, set())):
            if '"%s"' % fn not in text and "'%s'" % fn not in text:
                bad.append("%s: fn %s has no handler in %s" % (name, fn, users))
    assert not bad, "\n".join(bad[:40])
