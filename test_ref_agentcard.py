"""Signed Agent Cards, AgentFacts attestations, hosting handlers and registry entries (atlas_pca.agentcard) replayed against
vectors generated from the TypeScript reference (@atlasauth/pca-agentcard)."""
import re

import pytest

from atlas_pca import agentcard as A
from base_oracle import canon, load_ref, run

COUNT, CASES = load_ref("agentcard")

_COLON = re.compile(r"^(signature( \d+)? did not verify|could not resolve verification key): .*$", re.S)


def _fix(s):
    return _COLON.sub(r"\1", s) if isinstance(s, str) else s


def _norm(r):
    """The reasons that quote the JOSE library are compared up to the first colon."""
    if isinstance(r, dict):
        c = dict(r)
        if isinstance(c.get("reason"), str):
            c["reason"] = _fix(c["reason"])
        if isinstance(c.get("attestations"), list):
            c["attestations"] = [dict(a, reason=_fix(a["reason"])) if isinstance(a, dict) and isinstance(a.get("reason"), str) else a for a in c["attestations"]]
        return c
    return r


def _eq(got, out, _c):
    return canon(_norm(got)) == canon(_norm(out))


def _handler(make):
    return lambda value, path, req: make(value, A.WELL_KNOWN_AGENT_CARD_PATH if path is None and make is A.agent_card_handler else
                                         (A.WELL_KNOWN_AGENT_FACTS_PATH if path is None else path))(req)


MAP = {
    "constants": lambda: {"DEFAULT_ALG": A.DEFAULT_ALG, "AGENT_FACTS_CONTEXT": list(A.AGENT_FACTS_CONTEXT), "PCA_ATTESTOR_ID": A.PCA_ATTESTOR_ID,
                          "WELL_KNOWN_AGENT_CARD_PATH": A.WELL_KNOWN_AGENT_CARD_PATH, "WELL_KNOWN_AGENT_FACTS_PATH": A.WELL_KNOWN_AGENT_FACTS_PATH},
    "jcsBytes": A.jcs_bytes,
    "validateAgentCard1": A.validate_agent_card1,
    "buildAgentCard": A.build_agent_card,
    "issueSignedAgentCard": lambda card, k, x=None: A.issue_signed_agent_card(card, k, x),
    "verifyAgentCard": A.verify_agent_card,
    "issueAgentFacts": A.issue_agent_facts,
    "addAttestation": A.add_attestation,
    "verifyAgentFacts": A.verify_agent_facts,
    "agentCardHandler": _handler(A.agent_card_handler),
    "agentFactsHandler": _handler(A.agent_facts_handler),
    "toRegistryEntry": A.to_registry_entry,
}


def test_every_function_in_the_corpus_is_replayed():
    assert COUNT > 0 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn], compare=_eq)
