"""Replays the TS-reference oracle of the PUF attestation root (testdata/ref-attest-puf.json.gz, 278 cases): the constants, the repetition-code bound, the
simulated PUF, the fuzzy extractor (enrollment and reproduction at every noise distance, every malformed helper and response), the TPM endorsement-key
provider over an injected command runner (the commands it issued are compared), enrollment, the device attestor, the enrollment registry, the verifier's
scenarios and its construction refusals. Keys are label seeds; the corpus carries the digest of an extracted key, never the key. Every fn has a handler
and the totals are asserted; a reference refusal needs a native exception."""
import hashlib
import os

import pytest

from atlas_pca import attest_puf as P
from atlas_pca.pca import unb64u
from base_oracle import HERE, canon, load, run

COUNT, CASES = load("attest-puf", os.path.join(HERE, "testdata", "ref-attest-puf.json.gz"))


def _sim(spec):
    return P.create_simulated_puf({"id": spec["id"], "seed": unb64u(spec["seed"]), "length": spec["length"], "flip": spec.get("flip")})


def _rnd(pair):
    calls = iter(pair)
    return lambda n: next(calls)[:n]


def _fe_out(r):
    return {"keySha256": hashlib.sha256(r["key"]).hexdigest(), "helper": r["helper"]}


def _fuzzy_enroll(bits, params, rand):
    return _fe_out(P.fuzzy_enroll(bits, params, _rnd(rand)))


def _fuzzy_reproduce(bits, helper):
    return {"keySha256": hashlib.sha256(P.fuzzy_reproduce(bits, helper)).hexdigest()}


def _tpm(a):
    calls = []
    spec = a["run"]

    def runner(cmd, args):
        calls.append([cmd, list(args)])
        if spec == "undefined":
            return None
        if isinstance(spec, dict) and "$throws" in spec:
            raise RuntimeError(spec["$throws"])
        return spec

    try:
        p = P.TpmEkPufProvider(None if a["opts"] is None else dict(a["opts"], run=runner))
        out = {"ok": True, "value": p.read_ek_public() if a["op"] == "readEkPublic" else p.response(a.get("challenge", CH))}
    except Exception as e:  # noqa: BLE001 - the refusal text is part of the corpus
        out = {"ok": False, "error": str(e)}
    out["calls"] = calls
    return out


CH = hashlib.sha256(b"attest-puf-oracle-randomness/challenge").digest()


def _enroll(spec, challenge, opts, rand):
    return P.enroll_puf(_sim(spec), challenge, dict(opts, randomBytes=_rnd(rand)))


def _attest(spec, enrollment, claims):
    return P.create_puf_attestor(_sim(spec), enrollment).attest(claims)


def _registry(sc):
    r = P.create_puf_enrollment_registry(sc["enrollments"])
    out = []
    for op in sc["ops"]:
        k = next(iter(op))
        if k == "register":
            r.register(op[k])
            out.append(None)
        elif k == "lookup":
            out.append(r.lookup(op[k]))
        elif k == "revoke":
            r.revoke(op[k])
            out.append(None)
        else:
            out.append(r.is_revoked(op[k]))
    return out


def _verifier_cfg(sc, resolve_enrollment=True):
    cfg_in = sc["config"]
    policy = {"measurements": cfg_in["policy"]["measurements"]}
    if cfg_in["policy"].get("weightsMeasurements") is not None:
        policy["weightsMeasurements"] = cfg_in["policy"]["weightsMeasurements"]
    if cfg_in["policy"].get("identity") == "custom":
        policy["deriveIdentity"] = lambda st, enr: {"model_id": "m-custom", "weights_digest": st.get("weights_digest", ""), "weights_measured": True,
                                                    "runtime_measurement": st.get("measurement"), "operator": enr["providerId"]}
    by_id = {}
    for e in sc.get("enrollments") or []:
        by_id[e["providerId"]] = e
    cfg = {"policy": policy}
    if "requirePq" in cfg_in:
        cfg["requirePq"] = cfg_in["requirePq"]
    if not cfg_in.get("noResolveEnrollment"):
        cfg["resolveEnrollment"] = lambda pid, *_: by_id.get(pid)
    if not cfg_in.get("noEvidenceSeam"):
        cfg["resolveEvidence"] = lambda *_: sc["evidence"]
    if sc.get("revoked") is not None:
        cfg["isRevoked"] = lambda pid: pid in sc["revoked"]
    return cfg


def _verify(sc):
    inp = {"document": {}, "ctx": {}, "nowMs": sc["input"]["nowMs"]}
    if "expected" in sc["input"]:
        inp["expected"] = sc["input"]["expected"]
    return P.create_puf_verifier(_verifier_cfg(sc)).verify(inp)


def _build_verifier(cfg):
    live = {}
    if "policy" in cfg:
        live["policy"] = cfg["policy"]
    if not cfg.get("noResolveEnrollment"):
        live["resolveEnrollment"] = lambda *_: None
    P.create_puf_verifier(live)
    return {"built": True}


HANDLERS = {
    "constants": lambda: {"PUF_EXTRACT_INFO": P.PUF_EXTRACT_INFO, "PUF_ATTEST_DOMAIN": P.PUF_ATTEST_DOMAIN, "PUF_KEY_BYTES": P.PUF_KEY_BYTES,
                          "TPM_EK_PUF_DOMAIN": P.TPM_EK_PUF_DOMAIN},
    "repetitionCorrectionBound": P.repetition_correction_bound,
    "simulatedPufResponse": lambda spec, ch: _sim(spec).response(ch),
    "fuzzyEnroll": _fuzzy_enroll,
    "fuzzyReproduce": _fuzzy_reproduce,
    "tpmEk": _tpm,
    "enrollPuf": _enroll,
    "pufAttest": _attest,
    "registry": _registry,
    "verifyPuf": _verify,
    "buildVerifier": _build_verifier,
}
TOTALS = {"constants": 1, "repetitionCorrectionBound": 12, "simulatedPufResponse": 30, "fuzzyEnroll": 23, "fuzzyReproduce": 80, "tpmEk": 30,
          "enrollPuf": 13, "pufAttest": 22, "registry": 10, "verifyPuf": 52, "buildVerifier": 5}


def _same(got, out, _case):
    """The oracle wraps some results as {"ok": true, "value": v}: the same value either way."""
    if isinstance(out, dict) and out.get("ok") is True and set(out) == {"ok", "value"}:
        out = out["value"]
    return canon(got) == canon(out)


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 278 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_puf_replay(fn):
    assert run(CASES[fn], HANDLERS[fn], compare=_same) == (TOTALS[fn], 0)
