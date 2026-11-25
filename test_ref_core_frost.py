"""Differential replay of FROST(Ed25519, SHA-512) threshold signing against the TypeScript reference corpus (includes the RFC 9591
Ed25519 test vectors). Needs libsodium through pysodium (the `ristretto` extra)."""
import os

import pytest

pytest.importorskip("pysodium")
from atlas_pca import ed25519 as ED, frost as F  # noqa: E402
from base_oracle import HERE, covered, load, load_gen, merge_cases, require_gen, run  # noqa: E402

COUNT, _MAIN = load("core-frost-java", os.path.join(HERE, "test-data", "ref-core-frost-java.json.gz"))
_GEN = load_gen("core-frost-java")
CASES = merge_cases(_MAIN, _GEN)


def _keygen(o):
    return F.trusted_dealer_keygen(o["t"], o["n"], o.get("secret"), o.get("coefficients"), o.get("identifiers"))


def _hash(which, msg):
    return {"H1": F.h1, "H2": F.h2, "H3": F.h3, "H4": F.h4, "H5": F.h5}[which](msg)


def _commit(i, share, hr, br):
    return F.commit({"identifier": i, "share": share}, hr, br)


def _sign(i, share, gpk, nonces, msg, comms, opts=None):
    o = opts or {}
    return F.sign(i, share, gpk, nonces, msg, comms, o.get("threshold"), o.get("verificationShare"), o.get("verificationShares"))


def _aggregate(msg, comms, shares, gpk, opts):
    return F.aggregate(msg, comms, shares, gpk, opts.get("verificationShares"), opts.get("threshold"))


def _verify_share(o):
    g = (o or {}).get if isinstance(o, dict) else (lambda k: None)
    return F.verify_sig_share(g("identifier"), g("publicKey"), g("commitment"), g("sigShare"), g("signingCommitments"), g("groupPublicKey"), g("message"))


def _flow(o):
    kg = _keygen(o)
    by = {s["identifier"]: s for s in kg["participantShares"]}
    commits = [_commit(i, by[i]["share"], r["hr"], r["br"]) for i, r in zip(o["signers"], o["randomness"])]
    comms = [c["commitment"] for c in commits]
    vss = [{"identifier": i, "publicKey": by[i]["publicKey"]} for i in o["signers"]]
    shares = [_sign(i, by[i]["share"], kg["groupPublicKey"], {"hiding": c["hidingNonce"], "binding": c["bindingNonce"]}, o["message"], comms,
                    {"threshold": o.get("threshold"), "verificationShare": by[i]["publicKey"], "verificationShares": vss})
              for i, c in zip(o["signers"], commits)]
    agg = F.aggregate(o["message"], comms, shares, kg["groupPublicKey"], vss, o.get("threshold"))
    return {**kg, "commitments": comms, "sigShares": shares, "aggregate": agg}


def _cosign(gpk, quorum, msg, opts=None):
    sig = F.cosign(gpk, quorum, msg, (opts or {}).get("threshold"))
    return ED.verify(gpk, msg, sig)


MAP = {"scalar": F.reduce_bytes, "isCanonicalScalar": F.is_canonical_scalar, "hash": _hash, "decodeSafePoint": F.decode_safe_point,
       "keygen": _keygen, "verifyingShare": F.verifying_share, "commit": _commit, "flow": _flow, "sign": _sign, "aggregate": _aggregate,
       "verifySigShare": _verify_share, "cosign": _cosign}


def test_corpus_is_covered():
    assert COUNT == 170 and covered(CASES, _GEN, MAP)  # 170 committed; the private-key cases are in the generated -gen corpus


def test_secret_corpus_present():
    if _GEN is None:
        require_gen("core-frost-java")


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    if fn not in CASES:
        require_gen("core-frost-java")
    for c in CASES[fn]:
        if isinstance(c["args"], dict):  # flow records its argument object bare
            c["args"] = [c["args"]]
    run(CASES[fn], MAP[fn])
