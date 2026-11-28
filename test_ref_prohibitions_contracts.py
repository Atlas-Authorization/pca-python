"""Replays the TS-reference oracles testdata/ref-prohibitions.json.gz (1637 cases: the constants, validateWhen, whenMatches,
signConstitution, the non-strict advanceState, evidenceDigest, composeAuthority) and testdata/ref-contracts.json.gz (1269 cases: the whole
contract surface) beside the shared vectors and the base prohibitions corpus. Every fn has a handler and the totals are asserted. A secret is
{"$seed": label} = sha256("atlas-pca-conformance/" + label), delivered by the loader as base64url; a reference throw is a native raise."""
import os

import pytest

from atlas_pca import contracts as C
from atlas_pca import prohibitions as P
from base_oracle import HERE, b64d, load, run

P_COUNT, P_CASES = load("prohibitions", os.path.join(HERE, "testdata", "ref-prohibitions.json.gz"))
C_COUNT, C_CASES = load("contracts", os.path.join(HERE, "testdata", "ref-contracts.json.gz"))

P_MAP = {
    "constants": lambda: {n: getattr(P, n) for n in ("CONSTITUTION_VERSION", "CONSTITUTION_SIG_DOMAIN", "EVIDENCE_VERSION", "SAFETY_EVIDENCE_SIG_DOMAIN",
                                                    "STATE_DIGEST_DOMAIN", "STATE_CHAIN_DOMAIN", "MAX_LEDGER", "MAX_INVARIANTS", "MAX_DEADLINE")},
    "validateWhen": P.validate_when,
    "whenMatches": P.when_matches,
    "signConstitution": lambda c, sk: P.sign_constitution(c, b64d(sk)),
    "advanceState": P.advance_state,
    "evidenceDigest": P.evidence_digest,
    "composeAuthority": P.compose_authority,
}
C_MAP = {
    "constants": lambda: {n: getattr(C, n) for n in ("CONTRACT_VERSION", "CONTRACT_SIG_DOMAIN", "MAX_CLAUSES", "MAX_CLAUSE_DEPTH")},
    "validateClause": lambda clause, seen, depth: C.validate_clause(clause, set(seen), depth),
    "contractId": C.contract_id,
    "signContract": lambda c, sk: C.sign_contract(c, b64d(sk)),
    "embeddedConstitution": C.embedded_constitution,
    "contractFromConstitution": C.contract_from_constitution,
    "checkContract": C.check_contract,
    "advanceContract": C.advance_contract,
    "checkAndAdvanceContract": C.check_and_advance_contract,
}


def test_corpora_are_complete_and_every_fn_is_handled():
    assert P_COUNT == 1637 and set(P_CASES) == set(P_MAP)
    assert C_COUNT == 1269 and set(C_CASES) == set(C_MAP)


@pytest.mark.parametrize("fn", sorted(P_MAP))
def test_prohibitions_match_the_reference(fn):
    ran, skipped = run(P_CASES[fn], P_MAP[fn])
    assert ran == len(P_CASES[fn]) and skipped == 0


@pytest.mark.parametrize("fn", sorted(C_MAP))
def test_contracts_match_the_reference(fn):
    ran, skipped = run(C_CASES[fn], C_MAP[fn])
    assert ran == len(C_CASES[fn]) and skipped == 0
