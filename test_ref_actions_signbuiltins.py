"""Differential replay: sign_builtins (release signing of the built-in defs) against the TypeScript reference."""
from atlas_pca import actions_builtin as B
from atlas_pca import ed25519
from base_oracle import b64d, load_ref, run

ed25519.allow_insecure_signer()  # signing needs `cryptography` otherwise; the secret is derived from a seed label
COUNT, CASES = load_ref("actions-signbuiltins-py")


def _sign(a):
    signed = B.sign_builtins(a["kid"], b64d(a["secret"]), a["ts"], defs=B.BUILTIN_DEFS[a["from"]:a["to"]])
    return [[d["verb"], d["review"]["state"], d["review"]["attestation"]] for d in signed]


def test_matches_the_reference():
    assert COUNT == 4
    run(CASES["signBuiltins"], lambda a: _sign(a))
