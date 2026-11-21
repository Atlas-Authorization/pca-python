"""Replays the TS-reference oracle of the seeded connector provider catalog (testdata/ref-connectors-providers.json.gz, 40 cases): each of the 15
provider manifests by name (the manifest itself, its digest, that it validates), the structural invariants every built-in holds, the built-in
order (part of the contract for display) with the catalog digest, and ids outside the catalog, which are never found. Every fn has a handler and
the totals are asserted."""
import os

import pytest

from atlas_pca import connectors as C
from atlas_pca.connectors_providers import BUILTIN_BY_ID, BUILTIN_MANIFESTS
from base_oracle import HERE, load, run

COUNT, CASES = load("connectors-providers", os.path.join(HERE, "testdata", "ref-connectors-providers.json.gz"))
NAMES = ["google", "github", "slack", "notion", "hubspot", "atlassian", "salesforce", "microsoft", "shopify", "snowflake", "linear", "zoom", "stripe",
         "dropbox", "airtable"]


def _provider(i):
    m = BUILTIN_BY_ID[i]
    return {"manifest": m, "digest": C.manifest_digest(m), "valid": C.validate_manifest(m)["ok"]}


def _invariants(i):
    m = BUILTIN_BY_ID[i]
    return {"defaultScopesSubset": all(s in m["scopesAvailable"] for s in m["defaultScopes"]),
            "scopesUnique": len(set(m["scopesAvailable"])) == len(m["scopesAvailable"]), "idMatchesKey": m["id"] == i,
            "httpsEndpoints": all(u.startswith("https://") for u in (m["authorizeUrl"], m["tokenUrl"]))}


HANDLERS = {
    "provider": _provider, "invariants": _invariants,
    "builtinManifests": lambda: {"ids": [m["id"] for m in BUILTIN_MANIFESTS], "digests": [C.manifest_digest(m) for m in BUILTIN_MANIFESTS],
                                 "catalogDigest": C.catalog_digest()},
    "unknownProvider": lambda i: {"found": C.get_provider(i) is not None},
}
TOTALS = {"provider": 15, "invariants": 15, "builtinManifests": 1, "unknownProvider": 9}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 40 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS
    assert [c["args"][0] for c in CASES["provider"]] == NAMES and set(BUILTIN_BY_ID) == set(NAMES)


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_connectors_providers_replay(fn):
    assert run(CASES[fn], HANDLERS[fn]) == (TOTALS[fn], 0)
