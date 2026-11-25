"""Homomorphic evaluation of PCA's risk gate, the PCA layer (the TypeScript ``pca-fhe``): fixed-point helpers, the public gate policy, the
binding of an encrypted risk claim to one PCActn and the ORIGIN AUTHENTICATION of the claim (Ed25519-signed claim, replay guard, signed
verdict attestation). The BFV primitives (keygen, encrypt, blind evaluation, decrypt) are in :mod:`atlas_pca.fhe_seal` and need the native
SEAL library.

BFV gives confidentiality only: the encryption key is public, so anyone holding it can mint a ciphertext. The signed claim adds who produced
it, for which grant context, action binding and gate policy, exactly once. It hides nothing (context, binding, signer and policy are in the
clear) and does not stop a malicious evaluator from returning wrong gate ciphertexts. Records are dicts with the reference's member names
(``encInputs``, ``weightsScaled``, ``claimDigest``, ...)."""
import math
from ._fin import fin
import os
from typing import Any, Dict, List, Optional

from .pca import _verify_b64u, b64u, canonical_bytes_strict, decode_b64u_strict, hash_canonical, sha256
from .risk import cost, risk_score

__all__ = ["DEFAULT_SCALE", "RISK_DIM", "transformed_inputs", "weight_vector", "quantize_risk_inputs", "fhe_risk_policy",
           "risk_inputs_from_pcactn", "binding_from_pcactn", "plaintext_verdict", "create_fhe_context", "sign_risk_claim",
           "encrypted_risk_claim", "signed_claim_digest", "memory_nonce_guard", "verify_signed_risk_claim", "eval_signed_risk_claim",
           "attest_verdict", "verify_verdict_attestation"]

DEFAULT_SCALE = 1000
RISK_DIM = 6
_SIGNED_BOUND = 1_073_692_673 // 2
CLAIM_DOMAIN = "atlas-pca-fhe/signed-claim/v1\x00"
VERDICT_DOMAIN = "atlas-pca-fhe/verdict-attestation/v1\x00"
_NONCE_BYTES = 16
_MAX_CONTEXT_LEN = 512
_INPUT_FIELDS = ("semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age")


def _fin(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x)


def _clamp01(x: float) -> float:
    return 0 if x < 0 else 1 if x > 1 else x


def _unit(x: Any, worst: int) -> float:
    return _clamp01(x) if _fin(x) else worst


def _wt(x: Any) -> float:
    return x if _fin(x) and x > 0 else 0


def _js_round(x: float) -> int:
    return int(math.floor(x + 0.5))


def transformed_inputs(i: Dict[str, Any]) -> List[float]:
    """The transformed risk-input vector the risk score weights: ``[d, 1-rev, bl, taint, 1-conf, age]``, each through the clamp with the
    score's worst case (non-finite = worst). Reals in [0, 1]."""
    return [_unit(i.get("semanticDistance"), 1), 1 - _unit(i.get("reversibility"), 0), _unit(i.get("blastRadius"), 1),
            _unit(i.get("taint"), 1), 1 - _unit(i.get("confidence"), 0), _unit(i.get("age"), 1)]


def weight_vector(w: Dict[str, Any]) -> List[float]:
    """The weight vector of the risk score in canonical order, its clamp applied."""
    return [_wt(w.get(k)) for k in ("alpha", "beta", "gamma", "delta", "epsilon", "zeta")]


def quantize_risk_inputs(i: Dict[str, Any], scale: int = DEFAULT_SCALE) -> List[int]:
    """The integer vector the agent encrypts: ``round(x * S)`` for each transformed input (the only source of divergence from the
    plaintext score, at most RISK_DIM / (2 S) in r)."""
    if isinstance(scale, bool) or not isinstance(scale, int) or scale <= 0:
        raise ValueError("scale must be a positive integer")
    return [_js_round(x * scale) for x in transformed_inputs(i)]


def fhe_risk_policy(core: Dict[str, Any], budget: float, scale: int = DEFAULT_SCALE) -> Dict[str, Any]:
    """The public gate policy from a core risk policy and the trust budget: fixed-point weights, the kappa-weighted weights and the budget
    bound at S^2. Raises when a scaled product could wrap the plain modulus."""
    if isinstance(scale, bool) or not isinstance(scale, int) or scale <= 0:
        raise ValueError("scale must be a positive integer")
    if not (_fin(budget) and budget >= 0):
        raise ValueError("budget must be finite and >= 0")
    kappa = core["kappa"]
    if not (_fin(kappa) and kappa > 0):
        raise ValueError("policy.kappa must be finite and > 0")
    w = weight_vector(core["weights"])
    ws = [_js_round(v * scale) for v in w]
    kws = [_js_round(kappa * v * scale) for v in w]
    bs = _js_round(budget * scale * scale)
    biggest = max(sum(ws) * scale, sum(kws) * scale, bs)
    if biggest >= _SIGNED_BOUND:
        raise ValueError("policy/scale overflow the plain modulus: max |value| %d must be < SIGNED_BOUND %d. Lower the scale or the weights/budget."
                         % (biggest, _SIGNED_BOUND))
    return {"scale": scale, "dim": RISK_DIM, "weightsScaled": ws, "kappaWeightsScaled": kws, "budgetScaled": bs, "kappa": kappa}


def risk_inputs_from_pcactn(p: Dict[str, Any]) -> Dict[str, float]:
    """The six normalized risk inputs of a PCActn's ``risk_claim.inputs``; a missing or non-numeric field is NaN (the clamp maps it to its
    fail-closed worst case, as the plaintext verifier does)."""
    src = p["risk_claim"]["inputs"]
    return {k: float(src[k]) if _fin(src.get(k)) else float("nan") for k in _INPUT_FIELDS}


def binding_from_pcactn(p: Dict[str, Any]) -> Dict[str, Any]:
    """The replay binding of a signed PCActn: ``{"aud", "actionRef", "counter", "nonce"?}``."""
    out = {"aud": p["aud"], "actionRef": p["action"]["params_digest"], "counter": p["counter"]}
    if p.get("nonce") is not None:
        out["nonce"] = p["nonce"]
    return out


def plaintext_verdict(inputs: Dict[str, Any], core: Dict[str, Any], budget: float) -> Dict[str, Any]:
    """The plaintext reference verdict ``{"r", "admit"}``: ``admit`` iff ``cost(r, kappa) <= budget``."""
    r = risk_score(inputs, core["weights"])
    return {"r": r, "admit": cost(r, core["kappa"]) <= budget}


class _Context:
    def __init__(self, scope: Any, ctx: Any) -> None:
        self._scope, self._ctx = scope, ctx
        self.slot_count = ctx.slots

    def dispose(self) -> None:
        """Release the native objects this context owns."""
        self._scope.__exit__(None, None, None)


def create_fhe_context() -> _Context:
    """Build the deterministic BFV context (needs the native SEAL library). The caller disposes it."""
    from .fhe_seal import _Ctx, _Scope
    s = _Scope()
    try:
        return _Context(s, _Ctx(s))
    except Exception:
        s.__exit__(None, None, None)
        raise


def _bytes_digest(s: str) -> str:
    return b64u(sha256(s.encode("utf-8")))


def _statement(domain: str, body: Any) -> bytes:
    return domain.encode("utf-8") + canonical_bytes_strict(body)


def _claim_statement(c: Dict[str, Any]) -> bytes:
    return _statement(CLAIM_DOMAIN, {"v": 1, "context": c["context"], "nonce": c["nonce"], "signer": c["signer"], "binding": c["claim"]["binding"],
                                     "policy": hash_canonical(c["claim"]["policy"]), "enc_inputs": _bytes_digest(c["claim"]["encInputs"])})


def signed_claim_digest(s: Dict[str, Any]) -> str:
    """Content address of a signed claim (signature included): what a verdict attestation binds to."""
    return hash_canonical(s)


def sign_risk_claim(claim: Dict[str, Any], signer: Any, context: str) -> Dict[str, Any]:
    """Sign an already-built encrypted claim (``{"binding", "encInputs", "policy"}``). `signer` is the encryptor's
    :class:`atlas_pca.agent.KeyPair`; its public key is embedded and must be pinned by the evaluator."""
    if not isinstance(context, str) or len(context) == 0 or len(context) > _MAX_CONTEXT_LEN:
        raise ValueError("context must be a non-empty string of at most %d characters" % _MAX_CONTEXT_LEN)
    nonce = os.urandom(_NONCE_BYTES)
    if not any(nonce):
        raise RuntimeError("signRiskClaim: random source returned all zeros (RNG failure)")
    body = {"claim": claim, "context": context, "nonce": b64u(nonce), "signer": signer.public}
    return {**body, "sig": b64u(signer.sign(_claim_statement(body)))}


def encrypted_risk_claim(actn: Dict[str, Any], public_key: str, policy: Dict[str, Any], signer: Any, context: str) -> Dict[str, Any]:
    """Agent / encryptor side: read the PCActn's risk inputs, quantize, encrypt under the public key, bind the ciphertext to the action and
    SIGN it. The plaintext inputs never leave this call."""
    from .fhe_seal import encrypt_risk_inputs
    if not isinstance(policy, dict):
        raise ValueError("policy must be an object")
    enc = encrypt_risk_inputs(public_key, quantize_risk_inputs(risk_inputs_from_pcactn(actn), policy["scale"]))
    return sign_risk_claim({"binding": binding_from_pcactn(actn), "encInputs": enc, "policy": policy}, signer, context)


class _MemoryNonceGuard:
    def __init__(self, max_entries: int) -> None:
        self._seen: set = set()
        self._max = max_entries

    def claim(self, key: str) -> bool:
        """Record `key`: True the first time, False when it was already used or the guard is full."""
        if key in self._seen or len(self._seen) >= self._max:
            return False
        self._seen.add(key)
        return True


def memory_nonce_guard(max_entries: int = 100_000) -> Any:
    """In-memory single-use tracking for claim nonces. FAILS CLOSED when `max_entries` is reached (it never evicts: eviction would re-open
    replay)."""
    return _MemoryNonceGuard(max_entries)


def _fail(reason: str) -> Dict[str, Any]:
    return {"ok": False, "reason": reason}


def verify_signed_risk_claim(s: Any, expect: Dict[str, Any]) -> Dict[str, Any]:
    """Verify a signed claim; never raises. `expect`: ``trustedSigners``, ``context``, ``binding``, ``policy``, ``nonces`` (a guard with
    ``claim(key)``). Order: shape, pinned signer, signature, context / binding / policy equality, and only then the nonce is consumed (so
    unauthenticated junk cannot burn nonces). Returns ``{"ok": True, "claim", "digest"}`` or ``{"ok": False, "reason"}``."""
    try:
        if not isinstance(s, dict):
            return _fail("claim is not signed: malformed envelope")
        cl = s.get("claim")
        if (not all(isinstance(s.get(k), str) for k in ("context", "nonce", "signer", "sig")) or not isinstance(cl, dict)
                or not isinstance(cl.get("encInputs"), str) or not isinstance(cl.get("binding"), dict) or not isinstance(cl.get("policy"), dict)):
            return _fail("claim is not signed: malformed envelope")
        if decode_b64u_strict(s["nonce"], _NONCE_BYTES) is None:
            return _fail("malformed nonce")
        if decode_b64u_strict(s["signer"], 32) is None or decode_b64u_strict(s["sig"], 64) is None:
            return _fail("malformed signer key or signature")
        if s["signer"] not in expect["trustedSigners"]:
            return _fail("signer is not a trusted encryptor")
        if not _verify_b64u(s["signer"], _claim_statement({"claim": cl, "context": s["context"], "nonce": s["nonce"], "signer": s["signer"]}), s["sig"]):
            return _fail("signature does not verify (ciphertext, binding, policy, context or nonce was altered, or wrong signer)")
        if s["context"] != expect["context"]:
            return _fail("context mismatch: claim was signed for a different grant/policy")
        if hash_canonical(cl["binding"]) != hash_canonical(expect["binding"]):
            return _fail("binding mismatch: claim is bound to a different action")
        if hash_canonical(cl["policy"]) != hash_canonical(expect["policy"]):
            return _fail("policy mismatch: claim was signed for a different gate policy")
        if not expect["nonces"].claim("%s:%s" % (s["signer"], s["nonce"])):
            return _fail("replay: nonce already used (or the replay window is full)")
        return {"ok": True, "claim": cl, "digest": signed_claim_digest(s)}
    except Exception:  # noqa: BLE001
        return _fail("claim could not be verified (malformed)")


def eval_signed_risk_claim(eval_keys: Any, signed: Any, expect: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluator: verify the signed claim, then run the gate. The ciphertext is not loaded into SEAL unless the signature, signer, context,
    binding, policy and nonce all check out. `eval_keys` has ``publicKey`` and ``galoisKeys`` (a dict or an ``FheKeyset``). Returns
    ``{"ok": True, "gate", "claimDigest"}`` or ``{"ok": False, "reason"}``."""
    chk = verify_signed_risk_claim(signed, expect)
    if not chk["ok"]:
        return chk
    try:
        from .fhe_seal import FheRiskPolicy, eval_risk_gate
        p = chk["claim"]["policy"]
        pol = FheRiskPolicy(p["scale"], p["dim"], p["weightsScaled"], p["kappaWeightsScaled"], p["budgetScaled"], p.get("kappa", 1.0))
        pk = eval_keys["publicKey"] if isinstance(eval_keys, dict) else eval_keys.public_key
        gk = eval_keys["galoisKeys"] if isinstance(eval_keys, dict) else eval_keys.galois_keys
        gate = eval_risk_gate(pk, gk, chk["claim"]["encInputs"], pol)
        return {"ok": True, "gate": {"encRiskRaw": gate.enc_risk_raw, "encSlack": gate.enc_slack}, "claimDigest": chk["digest"]}
    except Exception as e:  # noqa: BLE001
        return _fail("evaluation failed: %s" % (str(e) or "unknown error"))


def _verdict_statement(a: Dict[str, Any]) -> bytes:
    return _statement(VERDICT_DOMAIN, {"v": 1, "claim": a["claimDigest"], "gate": a["gateDigest"], "admit": a["admit"], "holder": a["holder"]})


def attest_verdict(holder: Any, signed: Dict[str, Any], gate: Dict[str, str], admit: bool) -> Dict[str, Any]:
    """Key-holder side, after decrypting: sign the decision. `holder` is the holder's Ed25519 :class:`KeyPair` (distinct from the FHE secret
    key). Only ``admit`` is signed, never the slack or r. `gate` is ``{"encRiskRaw", "encSlack"}``."""
    body = {"claimDigest": signed_claim_digest(signed),
            "gateDigest": {"encRiskRaw": _bytes_digest(gate["encRiskRaw"]), "encSlack": _bytes_digest(gate["encSlack"])},
            "admit": bool(admit), "holder": holder.public}
    return {**body, "sig": b64u(holder.sign(_verdict_statement(body)))}


def verify_verdict_attestation(a: Any, expect: Dict[str, Any]) -> Dict[str, Any]:
    """Relying-party side: the attestation is by a pinned holder, over exactly this claim and (optionally) this gate output. Never raises.
    `expect`: ``trustedHolders``, ``claimDigest``, ``gate``?. Returns ``{"ok": True, "admit"}`` or ``{"ok": False, "reason"}``."""
    try:
        gd = a.get("gateDigest") if isinstance(a, dict) else None
        if (not isinstance(a, dict) or not all(isinstance(a.get(k), str) for k in ("claimDigest", "holder", "sig")) or not isinstance(a.get("admit"), bool)
                or not isinstance(gd, dict) or not isinstance(gd.get("encRiskRaw"), str) or not isinstance(gd.get("encSlack"), str)):
            return _fail("malformed attestation")
        if a["holder"] not in expect["trustedHolders"]:
            return _fail("attestation holder is not trusted")
        if decode_b64u_strict(a["holder"], 32) is None or decode_b64u_strict(a["sig"], 64) is None:
            return _fail("malformed holder key or signature")
        if not _verify_b64u(a["holder"], _verdict_statement({"claimDigest": a["claimDigest"], "gateDigest": gd, "admit": a["admit"], "holder": a["holder"]}), a["sig"]):
            return _fail("attestation signature does not verify")
        if a["claimDigest"] != expect["claimDigest"]:
            return _fail("attestation is for a different claim")
        g = expect.get("gate")
        if g is not None and (gd["encRiskRaw"] != _bytes_digest(g["encRiskRaw"]) or gd["encSlack"] != _bytes_digest(g["encSlack"])):
            return _fail("attestation is for a different gate output")
        return {"ok": True, "admit": a["admit"]}
    except Exception:  # noqa: BLE001
        return _fail("attestation could not be verified (malformed)")
