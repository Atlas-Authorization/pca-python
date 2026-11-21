"""Differential replay: pack build, signing and verification, source sync and the domain bindings against the TypeScript reference."""
import pytest

from atlas_pca import ed25519

from atlas_pca import actions as A
from atlas_pca import actions_build as B
from atlas_pca import actions_builtin as BI
from atlas_pca import actions_sync as S
from base_oracle import load_ref, run

ed25519.allow_insecure_signer()  # signing needs `cryptography` otherwise; the vectors use throwaway seeds
COUNT, CASES = load_ref("actions-build-py")
CORE = A.CORE_REGISTRY


def _opt(c):
    return lambda _d: c


def _sync(a, c):
    return S.sync_source(a["current"], a["imported"], a["specDigest"], a["now"], a.get("lock"), CORE, _opt(c))


MAP = {
    "buildArtifacts": lambda ds, cfg, c: B.build_artifacts(ds, cfg, CORE, _opt(c)),
    "toolActionMapOf": lambda ds, t, a: B.tool_action_map_of(ds)(t, a),
    "generateTypes": B.generate_types,
    "packConsistencyError": lambda p: B.pack_consistency_error(p, CORE),
    "signPack": lambda p, k, s: B.sign_pack(p, k, s, CORE),
    "verifyPack": lambda p, k: B.verify_signed_pack(p, k, CORE),
    "packKeyOf": B.pack_key_of,
    "syncSource": _sync,
    "syncText": lambda a, c: S.sync_text(_sync(a, c)),
    "domainVerbs": BI.domain_verbs,
    "domainRoles": BI.domain_roles,
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
