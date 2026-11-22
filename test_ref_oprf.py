"""Differential replay of the RFC 9497 ristretto255-SHA512 OPRF/VOPRF/POPRF and the PCA private-revocation / private-rate-limit
layer (atlas_pca.oprf) against the TypeScript reference (@atlasauth/pca-oprf) corpus. Server-secret operations run on the
pure-Python group, so the module opts in to it (allow_insecure_prover) for the duration of these tests."""
import pytest

from atlas_pca import oprf as O, ratchet_group as G
from base_oracle import canon, covered, load_gen, load_ref, merge_cases, require_gen, run

COUNT, _MAIN = load_ref("oprf")
_GEN = load_gen("oprf")
CASES = merge_cases(_MAIN, _GEN)

_CAMEL = {
    "secret_key": "secretKey", "public_key": "publicKey", "blind": "blind", "blinded_element": "blindedElement",
    "evaluated_element": "evaluatedElement", "tweaked_key": "tweakedKey", "proof": "proof",
}
_NUL = object()  # a JSON null where the reference distinguishes it from "absent": a non-bytes value, so it is refused


@pytest.fixture(scope="module", autouse=True)
def _insecure_prover():
    G.allow_insecure_prover(True)
    yield
    G.allow_insecure_prover(False)


def cm(d):
    return {_CAMEL[k]: v for k, v in d.items()}


def nn(v):
    return _NUL if v is None else v


def _finalize(data, blind, ev, mode, opts=None):
    o = opts or {}
    return O.finalize(data, blind, ev, mode, o.get("proof"), o.get("publicKey"), o.get("blindedElement"))


def _finalize_poprf(data, blind, ev, info, o):
    return O.finalize_poprf(data, blind, ev, info, o.get("proof"), o.get("blindedElement"), o.get("tweakedKey"))


def _revocation(sk, ids, mode):
    x = O.build_revocation_set(sk, ids, mode)
    out = {"outputs": sorted(x["outputs"]), "mode": x["mode"]}
    if "public_key" in x:
        out["publicKey"] = x["public_key"]
    return out


def _revocation_eq(got, out, c):
    got = dict(got)
    if c["name"].endswith("-dups"):
        got.pop("publicKey", None)
    if c["name"].endswith("-surrogate"):
        got = got["mode"]
    return canon(got) == canon(out)


def _poprf_eval_eq(got, out, c):
    # without a pinned proof nonce the reference's proof is random: only the deterministic part is comparable
    if c["name"].endswith("bep-sk0"):
        return canon(got["evaluatedElement"]) == canon(out["evaluatedElement"])
    return canon(got) == canon(out)


def _is_revoked(cap_id, op):
    sk = op["sk"]
    st = O.build_revocation_set(sk, op["revoked"], op["mode"])
    real = O.make_revocation_evaluator(O.serialize_scalar(12345) if op.get("lie") == "wrong-key" else sk, op["mode"])
    if op.get("lie") == "no-proof":
        ev = lambda b: {"evaluated_element": real(b)["evaluated_element"]}  # noqa: E731
    else:
        ev = real
    return O.is_revoked_private(cap_id, ev, st)


def _private_rate(identifier, window, op):
    sk = op["sk"]
    return O.private_rate_token(identifier, window, O.make_rate_evaluator(sk), op.get("pk") or O.public_key_for(sk))


def _counter(limit, steps):
    c = O.RateWindowCounter(limit)
    out = []
    for s in steps:
        if s[0] == "hit":
            out.append(c.hit(s[1]))
        elif s[0] == "count":
            out.append(c.count(s[1]))
        else:
            c.reset()
            out.append(None)
    return out


MAP = {
    "deriveKeyPair": (lambda s, i, m: cm(O.derive_key_pair(s, i, m)), {}),
    "publicKeyFor": (O.public_key_for, {}),
    "deserializeScalar": (lambda b: str(O.deserialize_scalar(b)), {}),
    "serializeScalar": (lambda s: O.serialize_scalar(int(s)), {}),
    "hashToGroup": (lambda a, m: O.serialize_element(O.hash_to_group(a, m)), {}),
    "deserializeElement": (lambda b: O.serialize_element(O.deserialize_element(b)), {}),
    "blind": (lambda i, m, *r: cm(O.blind(i, m, *map(nn, r))), {}),
    "blindEvaluate": (lambda sk, b, m, *r: cm(O.blind_evaluate(sk, b, m, *map(nn, r))), {}),
    "evaluate": (O.evaluate, {}),
    "finalize": (_finalize, {}),
    "blindPoprf": (lambda i, n, pk, *r: cm(O.blind_poprf(i, n, pk, *map(nn, r))), {}),
    "blindEvaluatePoprf": (lambda sk, b, n, *r: cm(O.blind_evaluate_poprf(sk, b, n, *map(nn, r))), {"compare": _poprf_eval_eq}),
    "finalizePoprf": (_finalize_poprf, {}),
    "evaluatePoprf": (O.evaluate_poprf, {}),
    "toHex": (O.to_hex, {}),
    "bytesEqual": (O.bytes_equal, {}),
    "buildRevocationSet": (_revocation, {"compare": _revocation_eq}),
    "isRevokedPrivate": (_is_revoked, {}),
    "rateToken": (O.rate_token, {}),
    "rateTokenHex": (O.rate_token_hex, {}),
    "privateRateToken": (_private_rate, {}),
    "rateCounter": (_counter, {}),
}


def test_corpus_is_covered():
    assert COUNT == 508 and covered(CASES, _GEN, MAP)  # 508 committed; the private-key cases are in the generated -gen corpus


def test_secret_corpus_present():
    if _GEN is None:
        require_gen("oprf")


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    call, kw = MAP[fn]
    if fn not in CASES:
        require_gen("oprf")
    run(CASES[fn], call, **kw)


def test_secret_key_paths_need_no_opt_in_on_the_libsodium_backend():
    # libsodium is constant time, so nothing is gated: the old opt-in is accepted and ignored
    G.allow_insecure_prover(False)
    try:
        assert len(O.derive_key_pair(bytes(32), b"", "oprf")["secret_key"]) == 32
    finally:
        G.allow_insecure_prover(True)
