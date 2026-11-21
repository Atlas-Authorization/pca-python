"""Replays the TS-reference oracle of the zk compliance modules (testdata/ref-zk.json.gz, 1429 cases): commitments, the attested-VM
prover and verifier hook, the canonical Groth16 envelope gate, struct hashes, action quantisation, context pins, Policy VM proof
verification on BN254 and BLS12-381, the SNARK backends with their assurance labels, circuit versions and the ceremony checks. Every fn of
the corpus has a handler (an unhandled fn fails) and the case total is asserted. Conventions: {"$bigint"} an integer, {"$num"} a
non-finite double, {"$bytes": {"$seed": label}} the secret sha256("atlas-pca-conformance/" + label), {"$expectThunk": X} a function
returning X ("throw": one that raises), "$absent" an argument not given; a reference throw must be a native raise.

The pairing check is libpcazk (atlas_pca.zk_native). Without it the cases that reach the pairing are not replayed and the test reports
a skip after checking every other case; ATLAS_PCA_LIBPCAZK_REQUIRED=1 makes its absence a failure. No case is skipped: a null options object is passed as
``**None`` (a native TypeError, as the reference throws), and a null expectation is passed as None (it matches nothing)."""
import base64
import math
import os
import re

import pytest

from atlas_pca import zk as Z
from atlas_pca import zk_ceremony as C
from atlas_pca import zk_native
from atlas_pca.authorize import assurance_label_of
from base_oracle import HERE, canon, load

COUNT, CASES = load("zk", os.path.join(HERE, "testdata", "ref-zk.json.gz"))
_PAIRING = []  # one entry per pairing check attempted without the library
if not zk_native.available():
    def _no_library(*_a, **_k):
        _PAIRING.append(1)
        raise zk_native.ZkBackendMissing("libpcazk is not available")
    zk_native.verify = _no_library


def test_library_present_when_required():
    if os.environ.get("ATLAS_PCA_LIBPCAZK_REQUIRED") == "1":
        zk_native._load()
        assert zk_native.version()


# ---- argument revival ----------------------------------------------------------------------------------------------------------------

def _rv(v):
    if isinstance(v, dict):
        if set(v) == {"$bigint"}:
            return int(v["$bigint"])
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        if set(v) == {"$bytes"} and isinstance(v["$bytes"], str):
            return base64.urlsafe_b64decode(v["$bytes"] + "=" * (-len(v["$bytes"]) % 4))
        return {k: _rv(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_rv(x) for x in v]
    return v


def _raise_thunk():
    raise RuntimeError("thunk")


def _expect(e):
    if isinstance(e, dict) and "$expectThunk" in e:
        x = e["$expectThunk"]
        return _raise_thunk if x == "throw" else (lambda: x)
    return e


def _kw(opts, table):
    """The reference option names of `opts` as this module's keywords (an unknown name fails the case)."""
    return {table[k]: v for k, v in (opts or {}).items()}


def _options(a, table):
    """The second argument as keywords: absent = none; null stays None, so ``**None`` refuses as the reference does."""
    return _kw(_rv(a[1]), table) if len(a) > 1 and a[1] is not None else None if len(a) > 1 else {}


def _big(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return {"$bigint": str(v)}
    if isinstance(v, (list, tuple)):
        return [_big(x) for x in v]
    if isinstance(v, dict):
        return {k: _big(x) for k, x in v.items()}
    return v


def _present(v):
    """Members the reference leaves undefined are absent from its JSON."""
    return {k: _present(x) for k, x in v.items() if x is not None} if isinstance(v, dict) else v


# ---- handlers --------------------------------------------------------------------------------------------------------------------------

_CATALOG = {"verbCodes": "verb_codes", "resourceCodes": "resource_codes", "strictCatalog": "strict_catalog", "paramScalarField": "param_scalar_field"}
_VERIFY = {"verificationKey": "verification_key", "expect": "expect", "expectRiskHash": "expect_risk_hash"}
_GROTH16 = {"verificationKey": "verification_key", "ceremony": "ceremony"}
_BACKEND = {**_GROTH16, "expect": "expect", "expectActionHash": "expect_action_hash", "expectPolicyHash": "expect_policy_hash",
            "expectPlanHash": "expect_plan_hash"}
_BOUND = {**_BACKEND, "expectRiskHash": "expect_risk_hash"}
_TABLE = {"groth16": _GROTH16, "policyvm": _BACKEND, "policyvm-bls": _BACKEND, "policyvm-bound": _BOUND}
_MAKE = {"groth16": Z.create_groth16_snark_backend, "policyvm": Z.create_policy_vm_snark_backend,
         "policyvm-bls": Z.create_policy_vm_snark_backend_bls12381, "policyvm-bound": Z.create_policy_vm_bound_snark_backend}
_PATHS = ("DEFAULT_VKEY_PATH", "DEFAULT_WASM_PATH", "DEFAULT_ZKEY_PATH", "POLICYVM_VKEY_PATH", "POLICYVM_SAMPLE_PROOF_PATH", "POLICYVM_WASM_PATH",
          "POLICYVM_ZKEY_PATH", "POLICYVM_BLS12381_VKEY_PATH", "POLICYVM_BLS12381_SAMPLE_PROOF_PATH", "POLICYVM_BOUND_VKEY_PATH",
          "POLICYVM_BOUND_SAMPLE_PROOF_PATH", "POLICYVM_BOUND_WASM_PATH", "POLICYVM_BOUND_ZKEY_PATH")


def _constants():
    base = os.path.dirname(Z.circuits_dir())
    return {
        "ZK_PROVER_BINDING_REF": Z.ZK_PROVER_BINDING_REF,
        "POLICYVM_PUBLIC_SIGNAL": Z.POLICYVM_PUBLIC_SIGNAL, "POLICYVM_PUBLIC_SIGNAL_COUNT": Z.POLICYVM_PUBLIC_SIGNAL_COUNT,
        "POLICYVM_BOUND_PUBLIC_SIGNAL": Z.POLICYVM_BOUND_PUBLIC_SIGNAL, "POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT": Z.POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT,
        "POLICYVM_BOUND_RISK_FIELDS": list(Z.POLICYVM_BOUND_RISK_FIELDS), "POLICYVM_REVERSIBILITY_ORDER": list(Z.POLICYVM_REVERSIBILITY_ORDER),
        "paths": {n: os.path.relpath(getattr(Z, n)(), base).replace(os.sep, "/") for n in _PATHS},
    }


def _quantize(fn):
    return lambda *a: _big(fn(*_rv(list(a[:1])), **_options(a, _CATALOG)))


def _context(ps, expect, layout=None):
    args = [ps] if expect == "$absent" else [ps, _expect(expect)]
    return Z.policy_vm_context_matches(*args, **({"layout": Z.POLICYVM_BOUND_PUBLIC_SIGNAL} if layout == "bound" else {}))


def _verify(env, opts):
    kw = _kw(_rv(opts), _VERIFY)
    if "expect" in kw:
        kw["expect"] = _expect(kw["expect"])
    return Z.verify_policy_vm_proof(env, **kw)


def _backend(make, table=None):
    def run(opts, inp):
        kw = _kw(_rv(opts), table or _BACKEND)
        if "expect" in kw:
            kw["expect"] = _expect(kw["expect"])
        b = make(**kw)
        return {"verified": b.verify(inp.get("proof"), inp.get("publicInputs"), inp.get("ctx")), "label": assurance_label_of(b)}
    return run


def _zk_verifier(spec, ctx):
    s = _rv(spec)
    snark = _MAKE[s["snark"]["kind"]](**_kw(s["snark"].get("opts"), _TABLE[s["snark"]["kind"]])) if s.get("snark") else None
    hook = Z.create_zk_verifier(s.get("trustedProverKeys"), policy_commitments=s.get("policyCommitments"),
                                revoked_prover_keys=s.get("revokedProverKeys"), clock_skew_ms=s.get("clockSkewMs"), now=lambda: s["nowMs"],
                                snark_backend=snark)
    result = hook(ctx)
    if isinstance(result.get("reason"), str):
        result["reason"] = re.sub(r"(zk verification error \(fail closed\)): .*$", r"\1", result["reason"], flags=re.S)
    return {"result": result, "label": assurance_label_of(hook)}


def _prover(secret, po):
    p = Z.create_attested_compliance_prover(_rv(secret), allow_insecure_signer=True)
    return {"publicKey": p.public_key, "statement": p.prove(po.get("pcactn"), po.get("decideInput"), po.get("issued_at"), po.get("expires_at"))}


def _provenance(a):
    return C.circuit_provenance(**_kw(a, {"circuit": "circuit", "sourceSha256": "source_sha256", "r1csSha256": "r1cs_sha256", "vkey": "vkey"}))


def _check_provenance(prov, e):
    return C.check_circuit_provenance(prov, **_kw(e, {"circuit": "circuit", "sourceSha256": "source_sha256", "r1csSha256": "r1cs_sha256", "vkey": "vkey"}))


def _check_transcript(t, opts=None):
    return C.check_transcript(t, **_kw(opts, {"minContributions": "min_contributions", "r1csSha256": "r1cs_sha256", "circuit": "circuit"}))


HANDLERS = {
    "constants": _constants,
    "policyCommitment": Z.policy_commitment, "pinnedPolicyCommitment": Z.pinned_policy_commitment, "actionCommitment": Z.action_commitment,
    "proverKeyBinding": Z.prover_key_binding, "commitmentField": Z.commitment_field,
    "isCanonicalGroth16Envelope": Z.is_canonical_groth16_envelope,
    "policyVmStructHash": lambda f: Z.policy_vm_struct_hash(_rv(f)), "policyVmRiskHash": lambda f: Z.policy_vm_risk_hash(_rv(f)),
    "quantizeActionStruct": _quantize(Z.quantize_action_struct), "quantizePlanStruct": _quantize(Z.quantize_plan_struct),
    "quantizePolicyStruct": _quantize(Z.quantize_policy_struct), "quantizePolicyVmInputs": _quantize(Z.quantize_policy_vm_inputs),
    "policyVmCommitmentFromAction": lambda *a: Z.policy_vm_commitment_from_action(*_rv(list(a[:1])), **_options(a, _CATALOG)),
    "decodePolicyVmPublic": lambda ps: _present(Z.decode_policy_vm_public(ps)),
    "decodePolicyVmBoundPublic": lambda ps: _present(Z.decode_policy_vm_bound_public(ps)),
    "policyVmContextMatches": _context,
    "verifyPolicyVmProof": _verify,
    "createGroth16SnarkBackend": _backend(Z.create_groth16_snark_backend, _GROTH16),
    "createPolicyVmSnarkBackend": _backend(Z.create_policy_vm_snark_backend),
    "createPolicyVmSnarkBackendBls12381": _backend(Z.create_policy_vm_snark_backend_bls12381),
    "createPolicyVmBoundSnarkBackend": _backend(Z.create_policy_vm_bound_snark_backend, _BOUND),
    "createZkVerifier": _zk_verifier,
    "createAttestedComplianceProver": _prover,
    "circuitVersion": Z.circuit_version,
    "vkId": C.vk_id, "circuitProvenance": _provenance, "checkCircuitProvenance": _check_provenance, "transcriptSha256": C.transcript_sha256,
    "checkTranscript": _check_transcript, "ceremonyOf": C.ceremony_of,
}
CONTRACT = "provePolicyVmCompliance"  # one case: what proving the sample witness must give (see test_prover_contract)


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 1429
    assert set(CASES) == set(HANDLERS) | {CONTRACT}, sorted(set(CASES) ^ (set(HANDLERS) | {CONTRACT}))


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_zk_replay(fn):
    bad, unreplayed = [], 0
    for c in CASES[fn]:
        out, before = c["out"], len(_PAIRING)
        threw = isinstance(out, dict) and "$throws" in out
        try:
            got = HANDLERS[fn](*c["args"])
        except Exception as e:  # noqa: BLE001 - a native refusal, compared against the reference
            if len(_PAIRING) > before:
                unreplayed += 1
            elif not threw:
                bad.append("%s\n    native raised %s: %s\n    ref:    %s" % (c["name"], type(e).__name__, e, canon(out)[:400]))
            continue
        if len(_PAIRING) > before:
            unreplayed += 1
        elif threw or canon(got) != canon(out):
            bad.append("%s\n    native: %s\n    ref:    %s" % (c["name"], canon(got)[:400], canon(out)[:400]))
    assert not bad, "%d of %d differ from the reference:\n  %s" % (len(bad), len(CASES[fn]), "\n  ".join(bad[:25]))
    if unreplayed:
        pytest.skip("libpcazk not available: %d pairing case(s) of %s not replayed" % (unreplayed, fn))


def test_strict_mode_refuses_what_only_the_reference_verifier_accepts():
    """The quirk-* keys (protocol "plonk", nPublic 14, extra IC entries) verify in the default mode, as in the reference; strict refuses."""
    if not zk_native.available():
        pytest.skip("libpcazk not available")
    quirks = [c for c in CASES["verifyPolicyVmProof"] if "/quirk-" in c["name"]]
    assert len(quirks) == 6
    for c in quirks:
        env, opts = c["args"]
        assert c["out"] is True and Z.verify_policy_vm_proof(env, verification_key=opts["verificationKey"]) is True, c["name"]
        assert Z.verify_policy_vm_proof(env, verification_key=opts["verificationKey"], strict=True) is False, c["name"]


def test_prover_contract():
    """The corpus records what proving the committed sample witness must give. The struct hashes of the witness are checked always; the
    proof itself only where the build products exist (the proving key is not in any repository): ATLAS_PCA_CIRCUITS_DIR."""
    (case,) = CASES[CONTRACT]
    (w,), want = case["args"], case["out"]["publicSignals"]
    structs = (("verb", "resource", "reversibility", "paramScalar"),
               ("wAlpha", "wBeta", "wGamma", "wDelta", "wEpsilon", "wZeta", "theta1", "theta2", "kappa", "budgetB", "policyVerb", "policyResource",
                "policyParamBound", "expiresAt", "notBefore", "maxBlast", "maxDepth", "revMax", "rateMax", "allocParent"),
               ("planVerb", "planResource", "semanticDist", "planSalt"))
    for i, names in enumerate(structs):
        h = Z.policy_vm_struct_hash([w[n] for n in names])
        assert [h["hi"], h["lo"]] == want[2 * i:2 * i + 2]
    if not (os.path.isfile(Z.POLICYVM_WASM_PATH()) and os.path.isfile(Z.POLICYVM_ZKEY_PATH())):
        pytest.skip("no proving key: the struct hashes of the sample witness were checked, the proof was not made")
    env = Z.prove_policy_vm_compliance(w, seed=bytes(32))
    assert env["publicSignals"] == want and env["circuit"] == case["out"]["sampleProofCircuit"]
    assert Z.verify_policy_vm_proof(env) is True


def test_key_curve_aliases_are_read_by_the_library():
    """snarkjs names the curve through getCurveFromName, so the key may spell it "alt_bn128", "BN-254", "Bn-128": the default mode defers to the
    library (no name mapping here), a name it does not know is a refusal and a key that names the other curve is refused."""
    if not zk_native.available():
        pytest.skip("libpcazk not available")
    case = next(c for c in CASES["verifyPolicyVmProof"] if c["out"] is True and c["args"][1].get("verificationKey", {}).get("curve") == "bn128")
    env, opts = case["args"]
    key = opts["verificationKey"]
    for alias in ("bn128", "BN254", "alt_bn128", "ALT_BN128", "Bn-128", "bn-254"):
        assert Z.verify_policy_vm_proof(env, verification_key=dict(key, curve=alias)) is True, alias
    for other in ("bls12381", "BLS12-381", "secp256k1", "", "---"):
        assert Z.verify_policy_vm_proof(env, verification_key=dict(key, curve=other)) is False, other
    assert Z.verify_policy_vm_proof(env, verification_key=dict(key, curve="alt_bn128"), strict=True) is False
