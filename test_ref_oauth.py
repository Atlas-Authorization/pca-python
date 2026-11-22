"""Differential replay of the OAuth / MCP-authorization bridge (atlas_pca.oauth and the pca_grant authorization-details
helpers) against the vectors generated from the TypeScript reference (@atlasauth/pca-oauth)."""
import re

import pytest

from atlas_pca import oauth as O, pca_grant as G
from base_oracle import load_ref, run

COUNT, CASES = load_ref("oauth")


def snake(o):
    """The reference's camelCase option names -> the native snake_case dict keys (top level only)."""
    if not isinstance(o, dict):
        return o
    return {re.sub(r"([A-Z])", lambda m: "_" + m.group(1).lower(), k): v for k, v in o.items()}


def _build(g):
    return G.build_detail(g["chainIds"], g.get("chainRef"), g.get("bundleRevision"), g.get("locations"))


def _authz(a):
    return G.authorize_token(a["authorizationDetails"], a["resource"], a["chainIds"], a["proofVerified"])


MAP = {
    "resourceIdentifierProblem": O.resource_identifier_problem,
    "prmPathForResource": O.prm_path_for_resource,
    "prmUrlForResource": O.prm_url_for_resource,
    "protectedResourceMetadata": lambda o: O.protected_resource_metadata(snake(o)),
    "oauthDiscoveryHandler": lambda o: O.oauth_discovery_handler(snake(o)),
    "parseProtectedResourceMetadata": lambda d, p=None: O.parse_protected_resource_metadata(d, snake(p)),
    "wwwAuthenticate": lambda u, w=None: O.www_authenticate(u, snake(w)),
    "mcpUnauthorized": lambda u, w=None: O.mcp_unauthorized(u, snake(w)),
    "upgradeUnauthorizedChallenge": lambda r, u, w=None: O.upgrade_unauthorized_challenge(r, u, snake(w)),
    "checkResourceIndicator": O.check_resource_indicator,
    "checkTokenAudience": O.check_token_audience,
    "buildPcaGrantDetail": _build,
    "pcaGrantRequestParam": G.request_param,
    "authorizePcaGrantToken": _authz,
    "oauthScopeForAction": G.oauth_scope_for_action,
}


def test_every_oracle_function_is_replayed():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
