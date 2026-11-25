"""Differential replay of the FN-DSA registry, framing, hybrid composition and backend seam (atlas_pca.fndsa) against the
TypeScript reference (@atlasauth/pca-fndsa) corpus. The Falcon primitive is not covered (the reference ships none): every case
runs through the deterministic hash-derived test backend or an explicit stub backend."""
import pytest

from atlas_pca import ed25519 as ED, fndsa as F
from base_oracle import canon, load_ref, run

COUNT, CASES = load_ref("fndsa")


@pytest.fixture(scope="module", autouse=True)
def _signers():
    ED.allow_insecure_signer(True)  # only matters when `cryptography` is absent
    yield
    ED.allow_insecure_signer(False)
    F.reset_falcon_backend()


@pytest.fixture(autouse=True)
def _no_leaked_backend():
    """No test here may leave a mock/test backend registered for the next one."""
    yield
    F.reset_falcon_backend()


def _boom(*_a):
    raise RuntimeError("backend exploded")


def _install(kind):
    F.reset_falcon_backend()
    mock = F.register_test_backend()
    if kind == "mock":
        return
    backends = {
        "none": lambda: F.reset_falcon_backend(),
        "verify-only": lambda: F.set_falcon_backend(F.FalconBackend(mock.verify)),
        "short-sig": lambda: F.set_falcon_backend(F.FalconBackend(mock.verify, lambda sk, m: bytes(10))),
        "all-true": lambda: F.set_falcon_backend(F.FalconBackend(lambda *a: True, mock.sign)),
        "throws": lambda: F.set_falcon_backend(F.FalconBackend(_boom, mock.sign)),
    }
    backends[kind]()


def _with(kind, f):
    try:
        _install(kind)
        return f()
    finally:
        F.reset_falcon_backend()


def _suite(a):
    s = F.resolve_fndsa_alg(a)
    return None if s is None else {
        "alg": s.alg, "variant": s.variant, "hasEd25519": s.has_ed25519, "sigBytes": s.sig_bytes, "needsPqPk": s.needs_pq_pk,
        "pqPkBytes": s.pq_pk_bytes, "needsPqSig": s.needs_pq_sig, "pqSigBytes": s.pq_sig_bytes, "fnSigBytes": s.fn_sig_bytes,
    }


def _kat_verify(variant, pk, msg, sig, vectors):
    F.reset_falcon_backend()
    F.register_test_backend(vectors)
    try:
        return F.fndsa_verify(variant, pk, msg, sig)
    finally:
        F.reset_falcon_backend()


def _kp(variant, seed="default"):
    return F.mock_keypair(variant, seed)


def _sign_in(inp):
    return _with("mock", lambda: F.sign_pca_with_fndsa(inp.get("alg"), inp.get("leaf"), inp.get("fnDsa"), inp.get("edSecret")))


def _verify_in(kind):
    return lambda inp: _with(kind, lambda: F.verify_pca_fndsa(
        inp.get("alg"), inp.get("leaf"), inp.get("holder"), inp.get("pq_pk"), inp.get("sig"), inp.get("pq_sig")))


MAP = {
    "resolveFnDsaAlg": _suite,
    "isKnownFnDsaAlg": F.is_known_fndsa_alg,
    "isFnDsaVariant": F.is_fndsa_variant,
    "hashKat": F.hash_kat,
    "mockKeypair": _kp,
    "fndsaLeafMessage": F.fndsa_leaf_message,
    "fndsaSignWith": lambda k, v, sk, m: _with(k, lambda: F.fndsa_sign(v, sk, m)),
    "fndsaVerifyWith": lambda k, v, pk, m, s: _with(k, lambda: F.fndsa_verify(v, pk, m, s)),
    "fndsaVerifyKat": _kat_verify,
    "signPcaWithFndsa": _sign_in,
    "verifyPcaFndsa": _verify_in("mock"),
    "verifyPcaFndsaNone": _verify_in("none"),
}


def test_corpus_is_covered():
    assert COUNT == 480 and set(CASES) == set(MAP) | {"fndsaSignKat"}


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])


def test_sign_kat_table_takes_precedence():
    for c in CASES["fndsaSignKat"]:
        variant = c["name"].split("/")[1]

        def sign(vectors, v=variant):
            F.reset_falcon_backend()
            F.register_test_backend(vectors)
            try:
                return F.fndsa_sign(v, _kp(v, "ref")["sk"], b"m")
            finally:
                F.reset_falcon_backend()

        run([c], sign)


def test_no_backend_refuses():
    F.reset_falcon_backend()
    pk = bytes(F.FN_DSA_512_PUBLIC_KEY_BYTES)
    with pytest.raises(F.FnDsaBackendMissing):
        F.fndsa_verify("fn-dsa-512", pk, b"m", bytes(F.FN_DSA_512_SIGNATURE_BYTES))
