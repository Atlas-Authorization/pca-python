"""Differential replay: the hosted action registry (publish gate, verifier view, grant facts, call context, rate keys) against the TypeScript reference."""
import pytest

from atlas_pca import actions as A
from atlas_pca import actions_hosted as H
from base_oracle import load_ref, run

COUNT, CASES = load_ref("actions-hosted-py")

_SAMPLE_VERBS = None


def _sample(d):
    out = {}
    for k, p in d["params"].items():
        if p.get("required") is False:
            continue
        role = p.get("role")
        t = p["type"]
        out[k] = ("abc12345" if isinstance(role, str) and role.startswith("id.") else 7 if t == "integer" else True if t == "boolean"
                  else p["values"][0] if p.get("values") else ["x"] if t == "array" else [] if t == "set" else "2030-01-01T00:00:00Z" if t == "datetime" else "val")
    return out


def _view_probe(versions, pins):
    """Mirror of the generator's probe: lookups, provenance, floors and undo plans for the fixed verb list (first 6 + the 7th def of the pack set)."""
    case = _view_probe.case
    verbs = case["verbs"]
    v = H.hosted_view(versions, pins)
    grants = case["grants"]
    ctxs = case["ctxs"]
    return {
        "versions": v.versions,
        "lookups": [v.lookup(x) for x in verbs],
        "prov": [v.provenance({"verb": x}) for x in verbs],
        "floors": [v.floor(x, g, c) for x in verbs for g in grants for c in ctxs],
        "undo": [v.undo_plan({"verb": d["verb"], "params": _sample(d)}) for d in case["defs"]],
    }


GRANTS = [{"caveats": [], "max_esc": 3, "preauth_esc": 0}, {"caveats": ["amount_cap", "window", "bogus"], "max_esc": 3, "preauth_esc": 3},
          {"caveats": ["amount_cap", "count_cap", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap"], "max_esc": 1, "preauth_esc": 1},
          {"caveats": [], "max_esc": 0, "preauth_esc": 0}]
CTXS = [[], ["fresh_revocation"], ["fresh_revocation", "idempotency", "approval_ref", "revocable", "dry_run_first"]]


def _probe_cases():
    from atlas_pca.actions_builtin import BUILTIN_DEFS, DOMAIN_DEFS
    alld = BUILTIN_DEFS + DOMAIN_DEFS
    d6 = alld[:6]
    return {"verbs": [d["verb"] for d in d6] + [alld[6]["verb"], "unknown.verb"], "defs": d6 + [alld[6]], "grants": GRANTS, "ctxs": CTXS}


def _probe(versions, pins):
    _view_probe.case = _probe_cases()
    return _view_probe(versions, pins)


def _gate(i):
    return H.publish_gate(i)



class _NullParams:
    """The params the reference receives as null: any member read throws, as the TypeError it raises."""

    def get(self, key, default=None):
        raise TypeError("Cannot read properties of null (reading '%s')" % key)


MAP = {
    "publishGate": _gate,
    "hostedVersionDigest": H.hosted_version_digest,
    "rulesDocError": H.rules_doc_error,
    "registryOfTraits": lambda t: {"digest": A.traits_digest(H.registry_of_traits(t))},
    "hostedView": _probe,
    "grantFactsOf": H.grant_facts_of,
    "hostedCallContext": lambda lk, params: H.hosted_call_context(lk, _NullParams() if params is None else params),  # JSON null is not undefined: reading it throws
    "rateKeysOf": H.rate_keys_of,
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
