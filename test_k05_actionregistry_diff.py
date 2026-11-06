"""k05 differential oracle: the action registry (atlas_pca.actions_registry: evolution records, registry signatures,
re-approvals, the grant pin, signed packs + shards, the rollback tracker, rule 22 decide, pack proofs) against the shared
TS-generated testdata/k05-actionregistry.json.gz."""
import pytest

from atlas_pca import actions_registry as R
from k05_oracle import canon, load, run

COUNT, CASES = load("actionregistry")
# the tracker's pinned keys (the generator's ALLKEYS [reg-1, reg-ml, reg-hy]) travel as the keys argument of verifyPack cases
ALLKEYS = next(c["args"][1] for c in CASES["verifyPack"]
               if isinstance(c["args"][1], list) and [k.get("kid") for k in c["args"][1]] == ["reg-1", "reg-ml", "reg-hy"])


def _reason(v):
    return None if v["ok"] else v["reason"]


def _verify_pack(p, keys, shards):
    v = R.verify_pack(p, keys, shards)
    return {"ok": True, "digest": v["digest"], "verbs": [d["verb"] for d in v["defs"]]} if v["ok"] else v


def _tracker(steps):
    t = R.PackTracker(ALLKEYS)
    return [t.accept(p, s) for p, s in steps]


def _tracker_eq(got, out, _c):
    """ok / status / code exact; the reason only for bad_pack (the other reasons are free text)."""
    def k(r):
        return {x: r.get(x) for x in ("ok", "status", "code")} | ({"reason": r.get("reason")} if r.get("code") == "bad_pack" else {})
    return canon([k(r) for r in got]) == canon([k(r) for r in out])


def _sign(x):
    return (x > 0) - (x < 0)


MAP = {
    "compareVersions": (lambda a, b: _sign(R.compare_versions(a, b)), {}),
    "packDefs": (lambda p, s: [d["verb"] for d in R.pack_defs(p, s)], {}),
    "evolutionRecordError": (lambda x, signed: R.evolution_record_error(x, signed=signed), {}),
    "evolutionDiffDigest": (R.evolution_diff_digest, {}),
    "verifyRegistrySig": (lambda d, b, s, k: _reason(R.verify_registry_sig(d, b, s, k)), {}),
    "verifyEvolutionRecord": (lambda r, k: _reason(R.verify_evolution_record(r, k)), {}),
    "reapprovalValid": (R.reapproval_valid, {}),
    "actionPinError": (R.action_pin_error, {}),
    "decidePin": (R.decide_pin, {}),
    "packShapeError": (lambda x, signed: R.pack_shape_error(x, signed=signed), {}),
    "verifyPack": (_verify_pack, {}),
    "packTracker": (_tracker, {"compare": _tracker_eq}),
    "rule22Decide": (R.rule22_decide, {}),
    "verifyPackProof": (R.verify_pack_proof, {}),
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 21429 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    call, kw = MAP[fn]
    run(CASES[fn], call, **kw)
