"""Differential replay of the Wesolowski VDF and PCA timelock (atlas_pca.vdf) against the TypeScript reference
(@atlasauth/pca-vdf) corpus. Big integers cross the corpus as decimal strings."""
import pytest

from atlas_pca import vdf as V
from base_oracle import b64d, load_ref, run

COUNT, CASES = load_ref("vdf")


def B(s):
    if not isinstance(s, str):
        raise TypeError("bigint arg")
    return int(s)


def S(n):
    return str(n)


def _pf(p):
    return {"y": S(p["y"]), "pi": S(p["pi"])}


def _verdict(f):
    return lambda x, y, pi, t, n: f(B(x), B(y), B(pi), t, B(n))


def _hash_to_prime(a, b, t, n, bits=V.CHALLENGE_PRIME_BITS):
    return S(V.hash_to_prime(B(a), B(b), t, B(n), bits))


def _proof_in(p):
    # JSON numbers stand for JS numbers (not bigints): float keeps them distinct from a bigint
    if p is None or not isinstance(p, dict):
        return p
    f = lambda v: int(v) if isinstance(v, str) else (float(v) if isinstance(v, int) else v)  # noqa: E731
    return dict(p, **{k: f(p[k]) for k in ("y", "pi") if k in p})


def _opts(o):
    return dict(steps=o.get("steps"), n=B(o["N"]), beacon=o.get("beacon"), allow_insecure_dev_modulus=o.get("allowInsecureDevModulus"))


def _require(act, o):
    q = V.require_timelock(act, **_opts(o))
    return {"kind": q["kind"], "x": S(q["x"]), "steps": q["steps"], "N": S(q["N"]), "actionDigest": q["actionDigest"]}


def _prove(act, steps, n, o):
    p = V.prove_timelock_elapsed(act, steps, B(n), o.get("beacon"), o.get("allowInsecureDevModulus"))
    return {"kind": p["kind"], "y": S(p["y"]), "pi": S(p["pi"]), "steps": p["steps"]}


MAP = {
    "isProbablePrime": lambda a: V.is_probable_prime(B(a)),
    "isMillerRabinProbablePrime": lambda a: V.is_miller_rabin_probable_prime(B(a)),
    "isStrongLucasProbablePrime": lambda a: V.is_strong_lucas_probable_prime(B(a)),
    "modpow": lambda a, b, c: S(V.modpow(B(a), B(b), B(c))),
    "gcd": lambda a, b: S(V.gcd(B(a), B(b))),
    "canonicalVdfOutput": lambda a, b: S(V.canonical_vdf_output(B(a), B(b))),
    "bigIntToBytes": lambda a: V.big_int_to_bytes(B(a)),
    "bytesRoundTrip": lambda b: V.big_int_to_bytes(V.bytes_to_big_int(b64d(b))),
    "hashToPrime": _hash_to_prime,
    "sequentialSquare": lambda a, t, n: S(V.sequential_square(B(a), t, B(n))),
    "vdfEval": lambda x, t, n: _pf(V.vdf_eval(B(x), t, B(n))),
    "vdfEvalCanonical": lambda x, t, n: _pf(V.vdf_eval_canonical(B(x), t, B(n))),
    "vdfVerifyDetailed": _verdict(V.vdf_verify_detailed),
    "vdfVerifyCanonicalDetailed": _verdict(V.vdf_verify_canonical_detailed),
    "checkProductionModulus": lambda a: V.check_production_modulus(B(a)),
    "deriveTimelockInput": lambda act, n, bc: S(V.derive_timelock_input(act, B(n), bc)),
    "requireTimelock": _require,
    "proveTimelockElapsed": _prove,
    "verifyTimelock": lambda act, p, o: V.verify_timelock(act, _proof_in(p), **_opts(o)),
}


def test_corpus_is_covered():
    assert COUNT == 6673 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])


def test_dev_modulus_is_refused_by_the_production_screen():
    setup = V.insecure_dev_setup(bits=64)
    assert not V.check_production_modulus(setup["N"])["ok"]
