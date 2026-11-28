"""Differential replay of the capability ratchet and risk accumulator (atlas_pca.ratchet, ratchet_accumulator, ratchet_group)
against the TypeScript reference (@atlasauth/pca-ratchet): the shared vector corpus, an independent ristretto255 known-answer
set, and prover roundtrips (the reference provers draw fresh randomness, so their proofs are compared by verdict)."""
import gzip
import hashlib
import json
import os

import pytest

from atlas_pca import ed25519
from atlas_pca import ratchet as R
from atlas_pca import ratchet_accumulator as A
from atlas_pca import ratchet_group as GR
from base_oracle import HERE, b64d, load_ref, run

COUNT, CASES = load_ref("ratchet")
AUTH = hashlib.sha256(b"atlas-pca-conformance/ratchet-authority").digest()


@pytest.fixture(autouse=True, scope="module")
def _pure_signer():
    ed25519.allow_insecure_signer(True)  # throwaway test keys only
    GR.allow_insecure_prover(True)
    yield
    ed25519.allow_insecure_signer(False)
    GR.allow_insecure_prover(False)


class Big(int):
    """A reference bigint argument: the reference refuses a plain number where a bigint is required."""


def rv(x):
    if isinstance(x, dict):
        if len(x) == 1 and "$bigint" in x:
            return Big(int(x["$bigint"]))
        return {k: rv(v) for k, v in x.items()}
    if isinstance(x, list):
        return [rv(v) for v in x]
    return x


def big_out(x):
    return {"$bigint": str(x)}


def need_big(b):
    if not isinstance(b, Big):
        raise TypeError("a bigint is required")
    return int(b)


_ABSENT = object()


def commit_risk(r, b=_ABSENT):
    A._as_units(rv(r))  # the reference validates the risk before it reads the blinding
    c = A.commit_risk(rv(r), None if b is _ABSENT else need_big(rv(b)))
    return {"commitment": c["commitment"], "blinding": big_out(c["blinding"])}


def open_commitment(c, r, b):
    b = rv(b)
    return isinstance(b, Big) and A.open_commitment(c, rv(r), int(b))


def prove_budget(risks, blindings, b_max):
    risks, blindings = rv(risks), rv(blindings)
    if len(risks) == len(blindings):
        blindings = [need_big(x) for x in blindings]
    return A.prove_budget(risks, blindings, rv(b_max))


def prove_risk_range(r, b):
    return A.prove_risk_range(rv(r), need_big(rv(b)))


def issue_risk_commitment(r, d, k=None):
    return R.issue_risk_commitment(rv(r), d, bytes(3) if k == "short" else AUTH)


def quantizer(rs):
    q = R.RiskQuantizer()
    out = []
    for r in rs:
        try:
            out.append(big_out(q.next(r)))
        except Exception:  # noqa: BLE001 - the reference records only that it refused
            out.append({"$err": True})
    out.append(big_out(q.total_units))
    return out


def clone_path(v, path, value):
    c = json.loads(json.dumps(v))
    t = c
    for k in path[:-1]:
        if isinstance(t, dict):
            t = t.get(k)
        elif isinstance(t, list) and isinstance(k, int) and 0 <= k < len(t):
            t = t[k]
        else:
            t = None
    key = path[-1] if path else "undefined"  # the reference indexes path[-1], undefined for an empty path
    if isinstance(t, (dict, list)):
        if value == "__DEL__":
            if isinstance(t, dict):
                t.pop(key, None)
        elif isinstance(t, dict):
            t[key if isinstance(key, str) else str(key)] = value
        elif isinstance(key, int) and 0 <= key < len(t):
            t[key] = value
    return c


class ThrowingStore:
    def claim(self, nullifier, record):
        raise RuntimeError("boom")


def scenario(spec):
    store = ThrowingStore() if spec.get("store") == "throws" else R.memory_spent_leaf_store()
    state = None
    root = None
    sigs = []
    out = []
    for s in spec["ops"]:
        try:
            op = s["op"]
            if op == "derive":
                d = R.derive_ratchet_root(s["seed"], s["depth"])
                state, root = d["state"], d["rootCommitment"]  # the signatures of an earlier tree stay addressable (sigRef)
                out.append({"root": root, "leafPubKeys": state["leafPubKeys"], "available": R.available_leaves(state)})
            elif op == "sign":
                r = R.sign_at_leaf(state, s["leaf"], s["msg"])
                state = r["newState"]
                sigs.append(r["signature"])
                out.append({"signature": r["signature"]})
            elif op == "avail":
                out.append(R.available_leaves(state))
            elif op == "isAvail":
                out.append(R.is_leaf_available(state, s["leaf"]))
            elif op in ("verify", "once"):
                sig = sigs[s["sigRef"]]
                for p, v in s.get("set") or []:
                    sig = clone_path(sig, p, v)
                rc = "other-root" if s.get("root") == "other" else root
                if op == "verify":
                    out.append(R.verify_leaf_signature(rc, s["leaf"], s["msg"], sig))
                else:
                    out.append(R.verify_leaf_signature_once(rc, s["leaf"], s["msg"], sig, store))
            else:
                raise ValueError("bad op")
        except Exception as e:  # noqa: BLE001 - the reference records the error code or just that it refused
            c = getattr(e, "code", None)
            out.append({"$err": c if isinstance(c, str) else True})
    return out


MAP = {
    "leafNullifier": R.leaf_nullifier,
    "counterToLeafIndex": R.counter_to_leaf_index,
    "leafIndexToCounter": R.leaf_index_to_counter,
    "leafIndexForAction": R.leaf_index_for_action,
    "riskToUnits": lambda r: big_out(R.risk_to_units(r)),
    "budgetCeilingUnits": lambda p: big_out(R.budget_ceiling_units(p)),
    "quantizer": quantizer,
    "ratchet": scenario,
    "commitRisk": commit_risk,
    "addCommitments": A.add_commitments,
    "openCommitment": open_commitment,
    "verifyRiskRange": A.verify_risk_range,
    "verifyBudget": lambda s, b, p: A.verify_budget(s, rv(b), p),
    "verifyBoundedBudget": lambda c, r, b, p: A.verify_bounded_budget(c, r, rv(b), p),
    "proveBudget": prove_budget,
    "proveRiskRange": prove_risk_range,
    "issueRiskCommitment": issue_risk_commitment,
    "verifyRiskAttestation": R.verify_risk_attestation,
    "verifyAttestedBudget": lambda i, d, k, b, p: R.verify_attested_budget(i, d, k, rv(b), p),
}


def _bad_bytes(v):
    """A {"$bytes": <non-string>} argument: the shared decoder cannot represent it (the reference refuses it while decoding)."""
    if isinstance(v, dict):
        if len(v) == 1 and "$bytes" in v:
            return not isinstance(v["$bytes"], str)
        return any(_bad_bytes(x) for x in v.values())
    if isinstance(v, list):
        return any(_bad_bytes(x) for x in v)
    return False


def _skip(c):
    return "malformed $bytes argument" if _bad_bytes(c["args"]) else None


def test_corpus_is_the_full_oracle():
    assert COUNT == 1095 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn], skip=_skip)


# ---- independent known answers (ristretto255 and an accumulator transcript from other implementations) ----------------

with gzip.open(os.path.join(HERE, "test-data", "ref-ratchet-kat.json.gz"), "rt", encoding="utf-8") as _fh:
    KAT = json.load(_fh)


def _hex(b64):
    return b64d(b64).hex()


def test_base_multiples_and_generator_match_the_independent_encoding():
    rs = KAT["ristretto"]
    for i, expected in enumerate(rs["baseMultiples"]):
        assert GR.to_raw_bytes(GR.mul(GR.G, i)).hex() == expected
    assert GR.to_raw_bytes(GR.H).hex() == rs["H"]


def test_pedersen_commitments_match_the_independent_encoding():
    for p in KAT["ristretto"]["pedersen"]:
        blinding = int.from_bytes(bytes.fromhex(p["b"]), "little")
        assert _hex(A.commit_risk(int(p["v"]), blinding)["commitment"]) == p["C"]


def test_budget_verdicts_match_the_independent_verifier():
    for b in KAT["ristretto"]["budget"]:
        assert A.verify_budget(b["sum"], int(b["bMax"]), b["proof"]) is (b["oracle"] == "1"), b["name"]


def test_recorded_transcript_verifies_and_is_bound_to_its_statement():
    k = KAT["r2"]
    cs, rps, b_max, bp, total = k["commitments"], k["rangeProofs"], k["bMax"], k["budgetProof"], k["sum"]
    assert A.verify_risk_range(cs[0], rps[0]) and A.verify_risk_range(cs[1], rps[1])
    assert A.verify_budget(total, b_max, bp)
    assert A.verify_bounded_budget(cs, rps, b_max, bp)
    assert not A.verify_risk_range(cs[1], rps[0])
    assert not A.verify_budget(total, b_max + 1, bp)
    assert not A.verify_bounded_budget(cs, rps + [rps[0]], b_max, bp)


# ---- provers (random coins): roundtrips ---------------------------------------------------------------------------------

def test_budget_prover_roundtrip():
    risks, blindings = [30, 12], [11, 22]
    total = A.add_commitments([A.commit_risk(r, b)["commitment"] for r, b in zip(risks, blindings)])
    assert A.verify_budget(total, 42, A.prove_budget(risks, blindings, 42))
    assert not A.verify_budget(total, 41, A.prove_budget(risks, blindings, 41))


def test_attested_pipeline_roundtrip():
    pub = R.b64u(ed25519.public_key(AUTH))
    iss = R.issue_risk_commitment(9, "only", AUTH)
    items = [{"commitment": iss["commitment"], "rangeProof": iss["rangeProof"], "attestation": iss["attestation"]}]
    proof = A.prove_budget([9], [iss["blinding"]], 9)
    assert R.verify_attested_budget(items, ["only"], pub, 9, proof)
    assert not R.verify_attested_budget(items, ["other"], pub, 9, proof)
