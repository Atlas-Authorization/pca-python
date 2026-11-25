"""Differential replay of the hybrid PQ threshold signer, step-up fold, core threshold hook and full step-up verification
against the TypeScript reference corpus (java-lane generator). hybridSign records everything except the random FROST nonces'
signature bytes: the replay compares the artifact with the frost signature length and the standalone verdict."""
import pytest

from atlas_pca import ed25519 as ED, frost as FR, mldsa, pq_backends, pq_threshold as T
from base_oracle import load_ref, run

pytest.importorskip("pysodium")  # FROST group math runs in libsodium
if not pq_backends.openssl_available("ML-DSA-65"):  # signing runs only through libcrypto; the verify-only fallback does not sign
    pytest.skip("no ML-DSA-65 signing backend (OpenSSL 3.5+)", allow_module_level=True)

COUNT, CASES = load_ref("pq-threshold-java-extra")


@pytest.fixture(scope="module", autouse=True)
def _insecure():
    ED.allow_insecure_signer(True)
    yield
    ED.allow_insecure_signer(False)


def _hook(opts, pcactn):
    return T.create_hybrid_threshold_verifier(opts)({"pcactn": pcactn, "grant": {}, "nowEpoch": 1_800_000_000_000})


def _checks(core):
    # the native core reports only enforced checks, by its own names
    from atlas_pca.pca import ts_check_name
    return {ts_check_name(k): "pass" if v else "fail" for k, v in core.checks.items()}


def _step_up(su, opts):
    r = T.verify_hybrid_step_up(su, opts)
    out = {"allow": r["allow"], "pq": r["pq"], "checks": _checks(r["core"])}
    if "reason" in r:
        out["reason"] = r["reason"]
    return out


def _cmp_step_up(got, out, c):
    from atlas_pca.pca import ts_reason
    exp, g = dict(out), dict(got)
    ne = {k for k, v in out["checks"].items() if v == "not-enforced"}
    exp["checks"] = {k: v for k, v in out["checks"].items() if k not in ne}
    g["checks"] = {k: v for k, v in got["checks"].items() if k not in ne}  # `audience: null` accepts any aud (reference: not-enforced)
    if "reason" in g:
        g["reason"] = ts_reason(g["reason"])
    for d in (g, exp):  # the refusal wording of a missing audience is the native core's own
        if str(d.get("reason", "")).startswith("audience:"):
            d["reason"] = "audience:"
    return g == exp


def _sign(a):
    kg = FR.trusted_dealer_keygen(a["t"], a["n"], secret=a["secret"], coefficients=a["coefficients"])
    by = {s["identifier"]: s for s in kg["participantShares"]}
    quorum = [by.get(i) for i in a["quorum"]]
    gk = kg["groupPublicKey"]
    pqk = [pq_backends.OpensslKey("ML-DSA-65", seed=s) for s in a["pqSeeds"]]
    art = T.hybrid_threshold_sign(a["action"], {"groupPublicKey": T.b64u(gk) if a.get("groupAsString") else gk, "quorum": quorum,
                                                "t": a["signT"] if a.get("signT") is not None else a["t"]},
                                  [pqk[i] for i in a["pq"]], a.get("pqT"))
    parts = [{"identifier": s["identifier"], "publicKey": T.b64u(s["publicKey"])} for s in kg["participantShares"]]
    desc = T.issue_group_descriptor(a["authSeed"], T.b64u(gk), a["t"], parts)
    pool = [T.b64u(k.public) for k in pqk]
    verdict = T.verify_hybrid_threshold(a["action"], art, {
        "groupKey": T.b64u(gk), "pqPublicKeys": pool, "t": a["t"], "pqT": a["pqT"] if a.get("pqT") is not None else len(a["pq"]),
        "groupDescriptor": desc, "trustedAuthorities": [T.b64u(ED.public_key(a["authSeed"]))]})
    frost = {k: v for k, v in art["frost"].items() if k != "sig"}
    frost["sigLen"] = len(art["frost"]["sig"])
    return {"artifact": {**art, "frost": frost}, "verdict": verdict}


def test_fold():
    run(CASES["fold"], T.fold_hybrid_step_up)


def test_hook():
    run(CASES["hook"], _hook)


def test_step_up():
    run(CASES["stepUp"], _step_up, compare=_cmp_step_up)


def test_hybrid_sign():
    run(CASES["hybridSign"], _sign)
