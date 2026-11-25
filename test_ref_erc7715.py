"""ERC-7715 wallet permissions (atlas_pca.erc7715: grant to permission request, supported-permissions filter, granted-permission
check, grant digest) replayed against vectors generated from the TypeScript reference (@atlasauth/pca-erc7715). A chain id crosses
as a decimal string in the corpus and becomes an int here; ``owners`` maps a context handle to the grant digest it is bound to."""
from atlas_pca import erc7715 as E
from base_oracle import load_ref, run

COUNT, CASES = load_ref("erc7715")


def _conv(x):
    return dict(x, chainId=int(x["chainId"])) if isinstance(x, dict) and isinstance(x.get("chainId"), str) else x


def _verify(g, sent, got, x):
    o = {}
    if "allowedManagers" in x:
        o["allowedManagers"] = x["allowedManagers"]
    if x.get("owners"):
        o["contextOwner"] = lambda c: x["owners"].get(c)
    return E.verify_granted_permission(g, sent, got, o)


MAP = {
    "grantToPermissionRequest": lambda g, o: E.grant_to_permission_request(g, _conv(o)),
    "supportsRequest": E.supports_request,
    "revokeParams": E.revoke_params,
    "verifyGrantedPermission": _verify,
    "grantDigestOf": E.grant_digest_of,
}


def test_every_function_in_the_corpus_is_replayed():
    assert COUNT > 0 and set(CASES) == set(MAP)


def test_matches_the_reference():
    for fn in sorted(MAP):
        run(CASES[fn], MAP[fn])
