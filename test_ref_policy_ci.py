"""Differential replay of the policy-safety CI gate (atlas_pca.policy_ci) against vectors generated from the TypeScript reference
(@atlasauth/pca-policy-ci): normalization of every accepted input shape, the lint rules over the analyzer, summary and exit codes, the
pinned lint-rule digest, the authoring gates and the command line (run against small files in a temporary directory)."""
import os
import tempfile

import pytest

from atlas_pca import policy_ci as P
from base_oracle import load_ref, run

COUNT, CASES = load_ref("policy-ci")


def _run_cli(spec):
    """Write each member of `files` (name -> text) into a fresh directory, run the command line there, return {code, lines}."""
    prev = os.getcwd()
    with tempfile.TemporaryDirectory() as d:
        for name, text in spec["files"].items():
            with open(os.path.join(d, name), "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
        os.chdir(d)
        try:
            lines = []
            code = P.run(spec["argv"], lines.append)
        finally:
            os.chdir(prev)
    return {"code": code, "lines": lines}


MAP = {
    "normalizePolicyInput": P.normalize_policy_input,
    "normalizeChain": P.normalize_chain,
    "isCapability": P.is_capability,
    "isEnvelope": P.is_envelope,
    "lintPolicy": lambda i, o=None: P.lint_policy(i, o),
    "lintChain": lambda c, o=None: P.lint_chain(c, o),
    "lint": lambda i, o=None: P.lint(i, o),
    "lintPolicies": lambda items, o=None: P.lint_policies(items, o),
    "summarize": lambda r, o=None: P.summarize(r, o),
    "checkLintRulesPin": P.check_lint_rules_pin,
    "toAnalyzerPolicy": P.to_analyzer_policy,
    "diffCommand": lambda a, b, o=None: P.diff_command(a, b, o),
    "testCommand": P.test_command,
    "coverageCommand": P.coverage_command,
    "parseArgs": P.parse_args,
    "run": _run_cli,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 2060 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])


def test_dangerous_verb_matches_a_keyword_inside_the_verb():
    # reference isDangerousVerb: verb.toLowerCase().includes(keyword.toLowerCase())
    from atlas_pca.policy_ci import _is_dangerous_verb
    assert _is_dangerous_verb("Payments.Transfer", ["transfer"])
    assert _is_dangerous_verb("db.delete_all", ["DELETE"])
    assert not _is_dangerous_verb("delete", ["delete_all"])  # the keyword is not inside the verb
    assert not _is_dangerous_verb("payments.read", ["transfer"])
