"""The pca-state profile (store behind the real require_pca guard, real signed PCActns): the reference adapters get the verdicts the TypeScript
reference gives them, and the CLI runs the profile."""
import pytest

from atlas_pca import store_conformance_cli as CLI
from atlas_pca import store_conformance_pca_state as S
from base_oracle import load_ref

COUNT, CASES = load_ref("store-conformance-pca-state-py")
TESTS = ["one-instance", "instances", "crash-after-claim", "retry-after-timeout"]


@pytest.mark.parametrize("case", CASES["pcaStateRun"], ids=lambda c: c["name"])
def test_reference_adapters_get_the_reference_verdicts(case):
    a = S.REFERENCE_ADAPTERS[case["args"][0]["adapter"]]({})
    try:
        r = S.run_pca_state_conformance(a, tests=TESTS, rounds=3, copies=8, instances=3)
    finally:
        if a.teardown:
            a.teardown()
    got = {t["test"]: [t["status"], t.get("admitted")] for t in r["tests"]}
    assert got == case["out"]


def test_cli_runs_the_profile_and_reports_a_bad_store():
    out = []
    code = CLI.main(["--profile", "pca-state", "--adapter", "builtin:bad-unshared", "--tests", "instances", "--rounds", "2"], print_=out.append)
    assert code == 1 and "FAIL" in out[0]
    out = []
    assert CLI.main(["--profile", "pca-state", "--adapter", "builtin:durable-file", "--tests", "one-instance,instances", "--rounds", "2"], print_=out.append) == 0
