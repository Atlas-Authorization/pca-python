"""Differential oracle: FGA for RAG (atlas_pca.rag) against the vectors generated from the TypeScript reference (@atlasauth/pca-rag):
aclsFromMetadata, compilePolicy, principalFromPCActn and filterDocuments (OpenFGA closures, deny-overrides-permit, fail-closed drops,
the decision digest)."""
from atlas_pca import rag as R
from base_oracle import load_ref, run

COUNT, CASES = load_ref("rag")


def _principal(p=None, o=None):
    o = o if isinstance(o, dict) else {}
    return R.principal_from_pcactn(p, id=o.get("id"), **{k: o[k] for k in ("attributes", "env") if k in o})


MAP = {
    "aclsFromMetadata": lambda acl=None, tags=None: R.acls_from_metadata(acl, tags),
    "compilePolicy": lambda p=None: R.compile_policy(p),
    "principalFromPCActn": _principal,
    "filterDocuments": lambda pr=None, docs=None, pol=None: R.filter_documents(pr, docs, pol),
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in CASES.values()) and set(CASES) == set(MAP)


def test_matches_the_reference():
    for fn in sorted(MAP):
        ran, _ = run(CASES[fn], MAP[fn])
        assert ran == len(CASES[fn])
