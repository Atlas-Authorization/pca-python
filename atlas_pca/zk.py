"""Zero-knowledge proof of compliance: the resource server learns "authorized", not the policy, the plan or the reasoning.

Two realisations, both checked against COMMITMENTS only:

* the attested-VM statement (``create_attested_compliance_prover`` / ``create_zk_verifier``): an attested VM runs the Policy VM and signs
  a statement that it released the action. Same privacy, weaker trust (the verifier trusts the prover key, optionally bound to hardware
  evidence), no native library needed;
* real Groth16 proofs made by snarkjs / circom: ``pca-compliance-v1`` (BN254), the full Policy VM circuit ``pca-policyvm-v1`` (BN254
  and BLS12-381, verifying keys bundled) and the risk-bound ``pca-policyvm-v2`` (BN254, no bundled key). The pairing check and the
  prover are the opt-in native module ``atlas_pca.zk_native`` (libpcazk); everything else here is pure Python: the canonical envelope
  gate, the context pins, the struct hashes and the deterministic action quantisation that binds a proof to the action in hand.

Envelopes, statements, verifying keys, pins and the quantisable action / plan / policy are plain dicts with the reference member names
(``publicSignals``, ``action_commit``, ``delegationDepth``, ``budgetB``, ...); function options are keyword arguments. A missing
libpcazk raises ``zk_native.ZkBackendMissing``: it is never reported as an invalid proof."""
from __future__ import annotations

from ._fin import fin
import copy
import hashlib
import json
import math
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import _zk_bundled, ed25519 as _ed, zk_native
from .authorize import assurance_label_of, set_assurance_label
from .pca import b64u, canonical_bytes_strict, hash_canonical, unb64u, utf8, verify_b64u
from .zk_ceremony import ceremony_of

_DOMAIN = b"atlas-pca/zk-compliance/v1\0"
ZK_PROVER_BINDING_REF = "atlas-pca/zk-prover/v1"

_BN254_FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
_BN254_FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583
_BLS12381_FQ = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
_BLS12381_FR = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
_CANON_DEC = re.compile(r"0|[1-9][0-9]*")
_DIGITS = re.compile(r"[0-9]+")
_U64 = 1 << 64
_SAFE = 9007199254740991
_WS = "\t\n\v\f\r                  　﻿"
# members every object inherits in the reference runtime: a param named like one of them is not a number there, so it is refused here too
_INHERITED = frozenset(("constructor", "__proto__", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString", "toString",
                        "valueOf", "__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__"))


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _finite(v: Any) -> bool:
    return _num(v) and (isinstance(v, int) or fin(v))


def _integral(v: Any) -> bool:
    return _num(v) and (isinstance(v, int) or v.is_integer())


def _truthy(v: Any) -> bool:
    return not (v is None or v is False or (isinstance(v, (int, float, str)) and (not v or v != v)))


def _bigint(v: Any) -> int:
    """An integer from a number, a boolean or integer text (decimal with a sign, or 0x / 0o / 0b; surrounding space ignored, empty = 0)."""
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        if not _integral(v):
            raise ValueError("not an integer")
        return int(v)
    if not isinstance(v, str):
        raise TypeError("cannot convert to an integer")
    s = v.strip(_WS)
    if s == "":
        return 0
    if len(s) > 2 and s[0] == "0" and s[1] in "xXoObB":
        digits = {"x": "0123456789abcdefABCDEF", "o": "01234567", "b": "01"}[s[1].lower()]
        if all(ch in digits for ch in s[2:]):
            return int(s[2:], {"x": 16, "o": 8, "b": 2}[s[1].lower()])
    elif re.fullmatch(r"[+-]?[0-9]+", s):
        return int(s)
    raise ValueError("cannot convert %r to an integer" % s)


# ---- commitments and the attested-VM statement ---------------------------------------------------------------------------------------

def policy_commitment(grant: Any) -> str:
    """Commitment to the policy: the grant's content address (what a verifier may KNOW about the grant without reading it)."""
    return grant["id"] if isinstance(grant, dict) and isinstance(grant.get("id"), str) else hash_canonical(grant)


def pinned_policy_commitment(grant: Any) -> str:
    """The policy commitment a verifier pins when it is not allowed to read the grant's plaintext."""
    return policy_commitment(grant)


def action_commitment(pcactn: Any) -> str:
    """Commitment to the action: content address of the PCActn's action descriptor."""
    return hash_canonical(pcactn.get("action") if isinstance(pcactn, dict) else None)


def _plan_commit(pcactn: Any) -> str:
    plan = pcactn.get("plan") if isinstance(pcactn, dict) else None
    root = plan.get("root") if isinstance(plan, dict) else None
    return root if isinstance(root, str) else ""


def _statement_message(body: dict) -> bytes:
    return _DOMAIN + canonical_bytes_strict(body)


class AttestedComplianceProver:
    """The attested-VM stand-in for a SNARK prover: signs that the Policy VM released the action. Only commitments enter the statement."""

    def __init__(self, attestor_secret: bytes, allow_insecure_signer: bool = False):
        self._secret = bytes(attestor_secret)
        self._allow_insecure = allow_insecure_signer
        self.public_key = b64u(_ed.public_key(self._secret))

    def __repr__(self) -> str:  # never print the secret
        return "AttestedComplianceProver(public_key=%r)" % self.public_key

    def prove(self, pcactn: Any, decide_input: dict, issued_at: Any, expires_at: Any) -> dict:
        """The signed statement for `pcactn`, IFF the Policy VM releases it under `decide_input`; raises ValueError otherwise (a false
        statement cannot be proven)."""
        from .policy_vm import decide  # deferred: the verifier side does not need the Policy VM
        decision = decide(decide_input)
        if not _truthy(decision.get("releaseGuardianShare")):
            raise ValueError("createAttestedComplianceProver: action is not compliant, nothing to prove (%s)" % "; ".join(decision.get("reasons") or []))
        body = {"v": 1, "mode": "attested-vm", "action_commit": action_commitment(pcactn), "policy_commit": policy_commitment(decide_input.get("grant")),
                "plan_commit": _plan_commit(pcactn), "released": True, "r": decision["r"], "issued_at": issued_at, "expires_at": expires_at,
                "prover": self.public_key}
        return {**body, "sig": b64u(_ed.sign_secret(self._secret, _statement_message(body), self._allow_insecure))}


def create_attested_compliance_prover(attestor_secret: bytes, allow_insecure_signer: bool = False) -> AttestedComplianceProver:
    """The attested-VM reference prover for the 32-byte Ed25519 secret of the VM. Signing needs ``cryptography`` unless
    `allow_insecure_signer` permits the built-in signer (tests, throwaway keys)."""
    return AttestedComplianceProver(attestor_secret, allow_insecure_signer)


def prover_key_binding(prover_public_key: str, epoch: Any, nonce: str) -> dict:
    """The binding a prover VM's hardware quote must carry so that the quote vouches for ITS key (another key, epoch or nonce does not bind)."""
    return {"holderPub": prover_public_key, "grantRef": ZK_PROVER_BINDING_REF, "epoch": epoch, "nonce": nonce}


def _unique(xs: Any) -> list:
    """The distinct scalars of a list, in order (containers are kept: they never equal anything)."""
    out: list = []
    for x in xs if isinstance(xs, (list, tuple)) else []:
        if isinstance(x, (list, dict)) or not any(type(x) is type(y) and x == y for y in out):
            out.append(x)
    return out


def create_zk_verifier(trusted_prover_keys: Sequence[str], *, policy_commitments: Optional[Sequence[str]] = None, snark_backend: Any = None,
                       revoked_prover_keys: Optional[Sequence[str]] = None, prover_attestation: Optional[dict] = None,
                       now: Optional[Callable[[], float]] = None, clock_skew_ms: Any = None) -> Callable[[dict], dict]:
    """The zk hook: ``hook({"pcactn": ..., "grant": ...}) -> {"enforced": True, "ok": bool, "reason"?: str}`` over the proof carried in
    ``pcactn["zk_compliance"]``. It fails closed and uses commitments only.

    With `snark_backend` the proof is opaque: the hook binds the public inputs (action / policy / plan commitments) to this PCActn and
    delegates. Otherwise the proof is an attested-VM statement: well-formed, signed by one of `trusted_prover_keys` and none of
    `revoked_prover_keys`, fresh (`now` in epoch ms, `clock_skew_ms`), bound to this action and plan, and committing to one of
    `policy_commitments` (default: the commitment derived from ``ctx["grant"]``).

    `prover_attestation` (attested-VM mode only) additionally requires hardware evidence for the prover key:
    ``{"hardware_verifier": <verifier labelled hardware or multi_root>, "expected_binding": f(prover_key) -> binding,
    "measurements": [allowlisted runtime measurements]}``. The configuration is copied at construction."""
    trusted = [k for k in _unique(copy.deepcopy(trusted_prover_keys)) if isinstance(k, str)]
    revoked = [k for k in _unique(copy.deepcopy(revoked_prover_keys)) if isinstance(k, str)]
    expected_policy = _unique(copy.deepcopy(policy_commitments)) if isinstance(policy_commitments, (list, tuple)) else None
    skew = max(0, clock_skew_ms) if _finite(clock_skew_ms) else 0
    clock = now if now is not None else (lambda: time.time() * 1000)
    pa = None if snark_backend is not None else prover_attestation
    measurements: List[str] = []
    hw_label = None
    if pa is not None:
        hw_label = assurance_label_of(pa.get("hardware_verifier"))
        if hw_label is None or hw_label["level"] not in ("hardware", "multi_root"):
            raise TypeError("createZkVerifier: proverAttestation.hardwareVerifier must carry a hardware or multi_root assurance label")
        ms = pa.get("measurements")
        if not isinstance(ms, list) or len(ms) == 0 or any(not isinstance(m, str) or m == "" for m in ms):
            raise TypeError("createZkVerifier: proverAttestation.measurements must be a non-empty allowlist")
        if not callable(pa.get("expected_binding")):
            raise TypeError("createZkVerifier: proverAttestation.expectedBinding must be a function")
        measurements = list(ms)
        hw_verifier, expected_binding = pa["hardware_verifier"], pa["expected_binding"]

    def fail(reason: str) -> dict:
        return {"enforced": True, "ok": False, "reason": reason}

    def check(ctx: Any) -> dict:
        pcactn = ctx.get("pcactn") if isinstance(ctx, dict) else None
        proof = pcactn.get("zk_compliance") if isinstance(pcactn, dict) else None
        if proof is None:
            return fail("no zk_compliance proof present")
        grant = ctx.get("grant")
        action_commit = action_commitment(pcactn)
        plan_commit = _plan_commit(pcactn)
        want_policy = expected_policy if expected_policy is not None else [policy_commitment(grant)]

        if snark_backend is not None:  # the proof is opaque: bind the public inputs to THIS action and plan, then delegate
            policy_commit = expected_policy[0] if expected_policy is not None and len(expected_policy) == 1 else policy_commitment(grant)
            ok = snark_backend.verify(proof, {"action_commit": action_commit, "policy_commit": policy_commit, "plan_commit": plan_commit}, ctx)
            return {"enforced": True, "ok": True} if _truthy(ok) else fail("snark backend rejected the proof")

        st = proof if isinstance(proof, dict) else {}
        if not (_num(st.get("v")) and st["v"] == 1) or st.get("mode") != "attested-vm" or not isinstance(st.get("mode"), str):
            return fail("unrecognized compliance statement")
        if st.get("released") is not True:
            return fail("statement does not assert release")
        prover = st.get("prover")
        if not isinstance(prover, str) or prover not in trusted:
            return fail("prover key is not trusted")
        if prover in revoked:
            return fail("prover key is revoked")
        sig = st.get("sig")
        if not isinstance(sig, str) or not verify_b64u(prover, _statement_message({k: v for k, v in st.items() if k != "sig"}), sig):
            return fail("compliance statement signature does not verify")
        issued, expires = st.get("issued_at"), st.get("expires_at")
        if not _finite(issued) or not _finite(expires) or expires < issued:
            return fail("malformed statement validity window")
        now_ms = clock()
        if not _finite(now_ms):
            return fail("compliance statement cannot be dated: the clock is not a finite number")
        if now_ms + skew < issued:
            return fail("compliance statement not yet valid")
        if now_ms - skew > expires:
            return fail("compliance statement expired")
        # commitment binding: these hashes are the only policy / plan knowledge the verifier needs
        if st.get("action_commit") != action_commit or not isinstance(st.get("action_commit"), str):
            return fail("statement does not bind to this action")
        if st.get("plan_commit") != plan_commit or not isinstance(st.get("plan_commit"), str):
            return fail("statement does not bind to this plan commitment")
        policy_commit = st.get("policy_commit")
        if not isinstance(policy_commit, str) or not any(isinstance(w, str) and w == policy_commit for w in want_policy):
            return fail("statement policy commitment is not an expected policy")
        if pa is not None:  # last: the expensive check. Anything but a bound, measured, allowlisted identity denies
            req = {"document": {"attestor": prover, "mode": "hardware"}, "ctx": ctx, "nowMs": now_ms, "expected": expected_binding(prover)}
            hw = hw_verifier.verify(req) if hasattr(hw_verifier, "verify") else hw_verifier(req)
            if not isinstance(hw, dict) or hw.get("ok") is not True:
                return fail("prover hardware evidence invalid: %s" % ((hw.get("reason") if hw.get("reason") is not None else "no reason given")
                                                                     if isinstance(hw, dict) else "no result"))
            if hw.get("bound") is not True:
                return fail("prover hardware evidence does not bind the prover key")
            measured = hw.get("measured")
            if not isinstance(measured, dict) or not isinstance(measured.get("runtime_measurement"), str):
                return fail("prover hardware evidence carries no measured identity")
            if measured["runtime_measurement"] not in measurements:
                return fail("prover VM measurement is not allowlisted")
        return {"enforced": True, "ok": True}

    def hook(ctx: Any) -> dict:
        try:
            return check(ctx)
        except Exception as e:  # noqa: BLE001 - fail closed
            return fail("zk verification error (fail closed): %s" % (str(e) or "unknown"))

    if snark_backend is not None:
        label = assurance_label_of(snark_backend) or {"level": "unknown"}
    elif hw_label is not None:
        label = {"level": "attested_vm_hw", "vendor": "hardware-bound:%s" % (hw_label.get("vendor") or hw_label["level"])}
    else:
        label = {"level": "attested_vm"}
    return set_assurance_label(hook, label["level"], vendor=label.get("vendor"), awaiting_audit=label.get("awaiting_audit"), ceremony=label.get("ceremony"))


# ---- binding tag and the canonical envelope gate ---------------------------------------------------------------------------------------

def commitment_field(b64u_commit: str) -> str:
    """A base64url commitment as a BN254 scalar-field element (decimal): the circuit's public binding tag. Bytes of any length are reduced
    mod the field (at most 6 commitments of 32 bytes share a tag; a binding tag, not a hiding commitment)."""
    return str(int.from_bytes(unb64u(b64u_commit), "big") % _BN254_FR)


def _canon_dec_below(v: Any, bound: int) -> bool:
    return isinstance(v, str) and len(v) <= 120 and _CANON_DEC.fullmatch(v) is not None and int(v) < bound


def is_canonical_groth16_envelope(env: Any, curve: str) -> bool:
    """True iff `env` is exactly the one canonical Groth16 envelope for `curve` ("bn254" | "bls12-381"): the exact member sets, canonical
    decimals below the field modulus, z == 1. A valid proof has many other encodings (x + p, leading zeros, hex, extra members) that
    the pairing check alone would accept; this gate refuses them all."""
    if not isinstance(env, dict) or set(env) != {"system", "circuit", "proof", "publicSignals"}:
        return False
    bn = isinstance(curve, str) and curve == "bn254"
    fq, fr = (_BN254_FQ, _BN254_FR) if bn else (_BLS12381_FQ, _BLS12381_FR)
    ps = env["publicSignals"]
    if not isinstance(ps, list) or not all(_canon_dec_below(x, fr) for x in ps):
        return False
    pr = env["proof"]
    if not isinstance(pr, dict) or set(pr) != {"pi_a", "pi_b", "pi_c", "protocol", "curve"}:
        return False
    if not _is(pr["protocol"], "groth16") or not _is(pr["curve"], "bn128" if bn else "bls12381"):
        return False

    def g1(a: Any) -> bool:
        return isinstance(a, list) and len(a) == 3 and _canon_dec_below(a[0], fq) and _canon_dec_below(a[1], fq) and _is(a[2], "1")

    b = pr["pi_b"]
    if not g1(pr["pi_a"]) or not g1(pr["pi_c"]) or not isinstance(b, list) or len(b) != 3:
        return False
    for row in b[:2]:
        if not isinstance(row, list) or len(row) != 2 or not _canon_dec_below(row[0], fq) or not _canon_dec_below(row[1], fq):
            return False
    return isinstance(b[2], list) and len(b[2]) == 2 and _is(b[2][0], "1") and _is(b[2][1], "0")


def _is(v: Any, text: str) -> bool:
    return isinstance(v, str) and v == text


# ---- fixture locations ---------------------------------------------------------------------------------------------------------------
# The Policy VM verifying keys (BN254 and BLS12-381) and the circuit versions are bundled in the package. Every other artifact (the
# compliance and risk-bound keys, witness wasm files, proving keys) is a build product read from this directory.

def circuits_dir() -> str:
    """Where circuit build products are read from: ``ATLAS_PCA_CIRCUITS_DIR``, else ``circuits`` beside the package."""
    return os.environ.get("ATLAS_PCA_CIRCUITS_DIR") or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "circuits")


def _path(*parts: str) -> Callable[[], str]:
    return lambda: os.path.join(circuits_dir(), *parts)


DEFAULT_VKEY_PATH = _path("build", "verification_key.json")
DEFAULT_WASM_PATH = _path("build", "compliance_js", "compliance.wasm")
DEFAULT_ZKEY_PATH = _path("build", "compliance_final.zkey")
POLICYVM_VKEY_PATH = _path("policyvm_vkey.json")
POLICYVM_SAMPLE_PROOF_PATH = _path("policyvm_sample_proof.json")
POLICYVM_WASM_PATH = _path("build", "policyvm_js", "policyvm.wasm")
POLICYVM_ZKEY_PATH = _path("build", "policyvm_final.zkey")
POLICYVM_BLS12381_VKEY_PATH = _path("policyvm_bls12381_vkey.json")
POLICYVM_BLS12381_SAMPLE_PROOF_PATH = _path("policyvm_bls12381_sample_proof.json")
POLICYVM_BOUND_VKEY_PATH = _path("build", "policyvm_bound_vkey.json")
POLICYVM_BOUND_SAMPLE_PROOF_PATH = _path("build", "policyvm_bound_sample_proof.json")
POLICYVM_BOUND_WASM_PATH = _path("build", "policyvm_bound_js", "policyvm_bound.wasm")
POLICYVM_BOUND_ZKEY_PATH = _path("build", "policyvm_bound_final.zkey")


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _vkey(explicit: Any, path: Optional[str], bundled: Optional[str], default_path: Callable[[], str]) -> Any:
    """An explicit key, else the file at `path`, else the bundled key (when the circuit has one), else the build product."""
    if explicit is not None:
        return explicit
    if path is None and bundled is not None:
        return json.loads(bundled)
    return _read_json(path if path is not None else default_path())


def circuit_version(circuit_id: str) -> dict:
    """The committed version of a circuit id (``pca-compliance-v1``, ``pca-policyvm-v1``, ``pca-policyvm-v2``): the SHA-256 over its whole
    source set and the pinned compiler. Raises ValueError on an unknown id."""
    v = json.loads(_zk_bundled.CIRCUIT_VERSIONS_JSON)
    c = v["circuits"].get(circuit_id) if isinstance(circuit_id, str) else None
    if c is None:
        raise ValueError("circuitVersion: unknown circuit %s" % json.dumps(circuit_id))
    return {"circuit": circuit_id, "sourceSha256": c["source_sha256"], "circom": v["circom"], "circomlib": v["circomlib"]}


# ---- pairing check ---------------------------------------------------------------------------------------------------------------------

def _groth16_verify(vkey: Any, public_signals: list, proof: Any, strict: bool = False) -> bool:
    """The pairing check of the reference verifier: the curve is the one the KEY names, read by the library itself in the default (snarkjs-compatible)
    mode (a name it does not know is a refusal, not an error). Strict mode names the curve explicitly (the library then accepts only the exact
    names "bn128" / "bls12381"). A missing libpcazk raises ZkBackendMissing."""
    if not strict:
        return zk_native.verify(zk_native.CURVE_FROM_KEY, vkey, proof, public_signals, strict)
    name = "".join(re.findall(r"[A-Za-z0-9]+", vkey["curve"].upper()))
    if name in ("BN128", "BN254", "ALTBN128"):
        curve = zk_native.CURVE_BN254
    elif name == "BLS12381":
        curve = zk_native.CURVE_BLS12_381
    else:
        raise ValueError("unknown curve %r" % (vkey["curve"],))
    return zk_native.verify(curve, vkey, proof, public_signals, strict)


def _label(level: str, ceremony: str, vendor: Optional[str] = None) -> dict:
    return {"level": level, "ceremony": ceremony, **({"vendor": vendor} if vendor is not None else {})}


class SnarkBackend:
    """A proof-system backend for ``create_zk_verifier``: ``verify(proof, public_inputs, ctx=None) -> bool`` where `proof` is the opaque
    value carried in ``pcactn["zk_compliance"]`` and `public_inputs` the three commitments. It carries an assurance label."""

    def __init__(self, verify: Callable[[Any, dict, Any], bool], label: dict):
        self._verify = verify
        set_assurance_label(self, label["level"], vendor=label.get("vendor"), ceremony=label.get("ceremony"))

    def verify(self, proof: Any, public_inputs: Optional[dict] = None, ctx: Any = None) -> bool:
        return self._verify(proof, public_inputs, ctx)


def _ceremony(verification_key: Any, ceremony: Any, circuit: str) -> str:
    """``multi-party`` only for an explicit verifying key backed by pinned ceremony evidence; the bundled keys are single-party."""
    return ceremony_of(verification_key, {**ceremony, "circuit": circuit} if isinstance(ceremony, dict) and ceremony else None)


class _Lazy:
    def __init__(self, load: Callable[[], Any]):
        self._load, self._value = load, None

    def __call__(self) -> Any:
        if self._value is None:
            self._value = self._load()
        return self._value


# ---- first circuit: pca-compliance-v1 (BN254) -------------------------------------------------------------------------------------------
# Public signals: [0] policyCommit [1] planCommit [2] actionCommit (Poseidon openings), [3] shaPolicy [4] shaPlan [5] shaAction (binding
# tags), [6] allow.

def create_groth16_snark_backend(*, verification_key: Any = None, verification_key_path: Optional[str] = None, ceremony: Optional[dict] = None,
                                 strict: bool = False) -> SnarkBackend:
    """The Groth16 backend of ``pca-compliance-v1``: a well-formed envelope, allow == 1, binding tags equal to
    ``commitment_field`` of the verifier's own commitments, the canonical encoding, then the pairing check. There is no bundled key."""
    key = _Lazy(lambda: _vkey(verification_key, verification_key_path, None, DEFAULT_VKEY_PATH))

    def verify(proof: Any, public_inputs: Any, _ctx: Any) -> bool:
        env = proof
        if not isinstance(env, dict) or not _is(env.get("system"), "groth16-bn254") or not _is(env.get("circuit"), "pca-compliance-v1"):
            return False
        ps = env.get("publicSignals")
        if not isinstance(ps, list) or len(ps) != 7 or env.get("proof") is None or not _is(ps[6], "1"):
            return False
        for index, member in ((3, "policy_commit"), (4, "plan_commit"), (5, "action_commit")):
            if not _is(ps[index], commitment_field(public_inputs[member])):
                return False
        if not is_canonical_groth16_envelope(env, "bn254"):
            return False
        return _groth16_verify(key(), ps, env["proof"], strict)

    return SnarkBackend(verify, _label("groth16", _ceremony(verification_key, ceremony, "pca-compliance-v1")))


def _witness_text(v: Any) -> str:
    if isinstance(v, bool) or not isinstance(v, (int, float, str)):
        raise TypeError("a witness value is an integer or its decimal text")
    return v if isinstance(v, str) else str(v) if isinstance(v, int) else str(int(v)) if v.is_integer() else repr(v)


def _prove(circuit_input: Dict[str, str], wasm_path: str, zkey_path: str, circuit: str, seed: Optional[bytes]) -> dict:
    with open(wasm_path, "rb") as fh:
        wasm = fh.read()
    with open(zkey_path, "rb") as fh:
        zkey = fh.read()
    out = zk_native.prove(zk_native.CURVE_BN254, wasm, zkey, circuit_input, seed)
    return {"system": "groth16-bn254", "circuit": circuit, "proof": out["proof"], "publicSignals": out["publicSignals"]}


def prove_groth16_compliance(inp: dict, *, wasm_path: Optional[str] = None, zkey_path: Optional[str] = None, seed: Optional[bytes] = None) -> dict:
    """A ``pca-compliance-v1`` proof from the private witness ``{action_commit, policy_commit, plan_commit, verb, resource, planVerb,
    policySalt, planSalt, actionSalt, risk, budget}``. Raises on a non-compliant witness (verb mismatch or risk > budget): a false
    statement is unprovable. `seed` is for tests only."""
    circuit_input = {k: _witness_text(inp[k]) for k in ("verb", "resource", "planVerb", "policySalt", "planSalt", "actionSalt", "risk", "budget")}
    circuit_input.update(shaPolicy=commitment_field(inp["policy_commit"]), shaPlan=commitment_field(inp["plan_commit"]),
                         shaAction=commitment_field(inp["action_commit"]), allow="1")
    return _prove(circuit_input, wasm_path or DEFAULT_WASM_PATH(), zkey_path or DEFAULT_ZKEY_PATH(), "pca-compliance-v1", seed)


# ---- the Policy VM circuits -----------------------------------------------------------------------------------------------------------

POLICYVM_PUBLIC_SIGNAL = {"actionHi": 0, "actionLo": 1, "policyHi": 2, "policyLo": 3, "planHi": 4, "planLo": 5, "r": 6, "t": 7, "admit": 8,
                          "allow": 9, "now": 10, "blast": 11, "delegationDepth": 12, "recentCount": 13, "allocChild": 14}
POLICYVM_PUBLIC_SIGNAL_COUNT = 15
POLICYVM_BOUND_PUBLIC_SIGNAL = {"actionHi": 0, "actionLo": 1, "policyHi": 2, "policyLo": 3, "planHi": 4, "planLo": 5, "r": 6, "t": 7, "admit": 8,
                                "riskHi": 9, "riskLo": 10, "allow": 11, "now": 12, "blast": 13, "delegationDepth": 14, "recentCount": 15,
                                "allocChild": 16}
POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT = 17
POLICYVM_BOUND_RISK_FIELDS = ("revScore", "taint", "conf", "age", "rFloorIn")
POLICYVM_REVERSIBILITY_ORDER = ("reversible", "rate_limited", "irreversible")


def policy_vm_struct_hash(fields: Sequence[Any]) -> dict:
    """``{"hi", "lo"}``: SHA-256 of the fields laid out as the circuit does (each an unsigned 64-bit big-endian integer), split into the two
    128-bit halves the circuit exposes, as decimal strings. Raises on a field outside 0 .. 2^64 - 1."""
    if not isinstance(fields, (list, tuple)):
        raise TypeError("policyVmStructHash: fields must be a list")
    data = bytearray()
    for f in fields:
        v = _bigint(f)
        if v < 0 or v >= _U64:
            raise ValueError("policyVmStructHash: field out of uint64 range")
        data += v.to_bytes(8, "big")
    digest = hashlib.sha256(bytes(data)).digest()
    return {"hi": str(int.from_bytes(digest[:16], "big")), "lo": str(int.from_bytes(digest[16:], "big"))}


def policy_vm_risk_hash(fields: Sequence[Any]) -> dict:
    """The risk commitment of ``pca-policyvm-v2`` (riskHi / riskLo): the five risk magnitudes in ``POLICYVM_BOUND_RISK_FIELDS`` order."""
    if not isinstance(fields, (list, tuple)) or len(fields) != len(POLICYVM_BOUND_RISK_FIELDS):
        raise ValueError("policyVmRiskHash: need exactly 5 risk fields")
    return policy_vm_struct_hash(fields)


def _decode(public_signals: Any, layout: dict, risk: bool) -> dict:
    if not isinstance(public_signals, list):
        raise TypeError("public signals must be a list")
    s = lambda name: public_signals[layout[name]] if layout[name] < len(public_signals) else None  # noqa: E731
    out = {"actionHash": {"hi": s("actionHi"), "lo": s("actionLo")}, "policyHash": {"hi": s("policyHi"), "lo": s("policyLo")},
           "planHash": {"hi": s("planHi"), "lo": s("planLo")}}
    if risk:
        out["riskHash"] = {"hi": s("riskHi"), "lo": s("riskLo")}
    for name in ("r", "t", "admit", "allow", "now", "blast", "delegationDepth", "recentCount", "allocChild"):
        out[name] = s(name)
    return out


def decode_policy_vm_public(public_signals: List[str]) -> dict:
    """The proven statement of a ``pca-policyvm-v1`` proof: the three struct hashes, risk, threshold, admit, allow and the context. A signal
    the list is too short for is None."""
    return _decode(public_signals, POLICYVM_PUBLIC_SIGNAL, False)


def decode_policy_vm_bound_public(public_signals: List[str]) -> dict:
    """As ``decode_policy_vm_public`` for ``pca-policyvm-v2``, plus the risk commitment ``riskHash``."""
    return _decode(public_signals, POLICYVM_BOUND_PUBLIC_SIGNAL, True)


# ---- deterministic action quantisation (binds a proof to the action in hand) -----------------------------------------------------------

def _content_address(domain: str, value: str) -> int:
    return int.from_bytes(hashlib.sha256(utf8("atlas-pca/policyvm-quantize/%s:%s" % (domain, value))).digest()[:8], "big")


def _u64(v: Any, what: str) -> int:
    if isinstance(v, bool) or not _integral(v) or not 0 <= v < _U64:
        raise ValueError("policyvm quantize: %s is not a uint64" % what)
    return int(v)


def _code(domain: str, value: Any, codes: Any, strict: bool) -> int:
    if not isinstance(value, str):
        raise ValueError("policyvm quantize: %s must be a string" % domain)
    if isinstance(codes, dict) and value in codes:
        return _u64(codes[value], "%s code" % domain)
    if strict:
        raise ValueError('policyvm quantize: %s "%s" is not in the catalog (strict)' % (domain, value))
    return _content_address(domain, value)


def _param_scalar(params: Any, field: Any) -> int:
    if not field:
        return 0
    if isinstance(params, dict) and field not in params and field in _INHERITED:
        raise ValueError("policyvm quantize: paramScalar is not a non-negative integer")
    v = params.get(field) if isinstance(params, dict) else None
    if v is None:
        return 0
    if _num(v):
        if not _integral(v) or v < 0 or (isinstance(v, float) and math.copysign(1.0, v) < 0):
            raise ValueError("policyvm quantize: paramScalar must be a non-negative integer")
        return _u64(v, "paramScalar")
    if isinstance(v, str) and _DIGITS.fullmatch(v):
        return _u64(int(v), "paramScalar")
    raise ValueError("policyvm quantize: paramScalar is not a non-negative integer")


def _reversibility(rc: Any, what: str) -> int:
    if not isinstance(rc, str) or rc not in POLICYVM_REVERSIBILITY_ORDER:
        raise ValueError('policyvm quantize: unknown %s class "%s"' % (what, rc))
    return POLICYVM_REVERSIBILITY_ORDER.index(rc)


def quantize_action_struct(action: Any, *, verb_codes: Optional[dict] = None, resource_codes: Optional[dict] = None, strict_catalog: bool = False,
                           param_scalar_field: Optional[str] = None) -> Tuple[int, int, int, int]:
    """The live action ``{verb, resource, reversibility_class?, params?}`` as the circuit's 4-field struct: (verb code, resource code,
    reversibility-class index, param scalar). Codes come from the shared catalogs `verb_codes` / `resource_codes`; a string absent from
    them is content-addressed (first 8 bytes of a domain-tagged SHA-256) unless `strict_catalog`. The scalar is the non-negative integer
    in ``params[param_scalar_field]`` (0 when unset). MUST equal the map the prover used. Raises (fail closed) on anything that cannot be
    quantised."""
    if not isinstance(action, dict):
        raise ValueError("policyvm quantize: action is missing")
    strict = strict_catalog is True
    rc = action.get("reversibility_class")
    return (_code("verb", action.get("verb"), verb_codes, strict), _code("resource", action.get("resource"), resource_codes, strict),
            _reversibility("reversible" if rc is None else rc, "reversibility"), _param_scalar(action.get("params"), param_scalar_field))


def quantize_plan_struct(plan: Any, *, verb_codes: Optional[dict] = None, resource_codes: Optional[dict] = None,
                         strict_catalog: bool = False) -> Tuple[int, int, int, int]:
    """The plan node ``{verb, resource, semanticDist, planSalt}`` as the circuit's 4-field plan struct. The salt is the prover's: a
    verifier binds the ACTION."""
    if not isinstance(plan, dict):
        raise ValueError("policyvm quantize: plan is missing")
    strict = strict_catalog is True
    return (_code("verb", plan.get("verb"), verb_codes, strict), _code("resource", plan.get("resource"), resource_codes, strict),
            _u64(plan.get("semanticDist"), "semanticDist"), _u64(plan.get("planSalt"), "planSalt"))


def quantize_policy_struct(policy: Any, *, verb_codes: Optional[dict] = None, resource_codes: Optional[dict] = None,
                           strict_catalog: bool = False) -> List[int]:
    """The policy ``{weights: {alpha .. zeta}, theta1, theta2, kappa, budgetB, policyVerb, policyResource, policyParamBound, expiresAt,
    notBefore, maxBlast, maxDepth, revMax, rateMax, allocParent}`` as the circuit's 20-field struct (the policy's own fixed-point integers)."""
    if not isinstance(policy, dict) or not isinstance(policy.get("weights"), dict):
        raise ValueError("policyvm quantize: policy or its weights are missing")
    strict = strict_catalog is True
    w = policy["weights"]
    g = policy.get
    return [
        _u64(w.get("alpha"), "wAlpha"), _u64(w.get("beta"), "wBeta"), _u64(w.get("gamma"), "wGamma"), _u64(w.get("delta"), "wDelta"),
        _u64(w.get("epsilon"), "wEpsilon"), _u64(w.get("zeta"), "wZeta"), _u64(g("theta1"), "theta1"), _u64(g("theta2"), "theta2"),
        _u64(g("kappa"), "kappa"), _u64(g("budgetB"), "budgetB"), _code("verb", g("policyVerb"), verb_codes, strict),
        _code("resource", g("policyResource"), resource_codes, strict), _u64(g("policyParamBound"), "policyParamBound"),
        _u64(g("expiresAt"), "expiresAt"), _u64(g("notBefore"), "notBefore"), _u64(g("maxBlast"), "maxBlast"), _u64(g("maxDepth"), "maxDepth"),
        _reversibility(g("revMax"), "revMax"), _u64(g("rateMax"), "rateMax"), _u64(g("allocParent"), "allocParent"),
    ]


def quantize_policy_vm_inputs(inp: Any, **catalog: Any) -> dict:
    """``{"action": ..., "plan"?: ..., "policy"?: ...}``: the action struct always, the plan and policy structs when ``inp`` carries them.
    Takes the catalog keywords of ``quantize_action_struct``."""
    if not isinstance(inp, dict):
        raise ValueError("policyvm quantize: action is missing")
    shared = {k: v for k, v in catalog.items() if k != "param_scalar_field"}
    out: dict = {"action": quantize_action_struct(inp.get("action"), **catalog)}
    if _truthy(inp.get("plan")):
        out["plan"] = quantize_plan_struct(inp["plan"], **shared)
    if _truthy(inp.get("policy")):
        out["policy"] = quantize_policy_struct(inp["policy"], **shared)
    return out


def policy_vm_commitment_from_action(action: Any, **catalog: Any) -> dict:
    """The circuit's action commitment (actionHi / actionLo) recomputed from the LIVE action. Requiring a proof's halves to equal it binds
    the proof to this action: a proof minted for another action mismatches. Takes the keywords of ``quantize_action_struct``."""
    return policy_vm_struct_hash(quantize_action_struct(action, **catalog))


# ---- context pins ----------------------------------------------------------------------------------------------------------------------

_UNSET: Any = type("_NotGiven", (), {"__repr__": lambda self: "<not given>"})()  # None is a value here: a null expectation matches nothing


def _pin(v: Any) -> Optional[int]:
    try:
        if isinstance(v, float) and not (_integral(v) and abs(v) <= _SAFE):  # a double is exact only in the safe-integer range
            return None
        return _bigint(v)
    except (TypeError, ValueError):
        return None


def _signal_matches(signal: Any, pin: Any) -> bool:
    if not isinstance(signal, str) or _CANON_DEC.fullmatch(signal) is None:
        return False
    x = int(signal)
    if pin is None:
        raise TypeError("a pin is a value or a {min, max} window, not null")
    if isinstance(pin, (dict, list)):
        lo, hi = (_pin(pin.get("min")), _pin(pin.get("max"))) if isinstance(pin, dict) else (None, None)
        return lo is not None and hi is not None and lo <= x <= hi
    want = _pin(pin)
    return want is not None and x == want


def policy_vm_context_matches(public_signals: List[str], expect: Any = _UNSET, layout: Optional[dict] = None) -> bool:
    """Do the public signals satisfy `expect`? `expect` is a dict (or a function returning one, evaluated at each call so ``now`` can
    track a live clock) pinning ``now``, ``blast``, ``delegationDepth``, ``recentCount``, ``allocChild``, ``r``, ``t`` to an exact value
    or an inclusive ``{"min", "max"}`` window, plus ``requireAdmit`` / ``requireTier1``. Even with no pins, a context signal that is not
    a canonical decimal below 2^64 is refused (the circuit's comparators run on un-range-checked inputs: a field-negative ``now`` would
    otherwise pass ``now < expiresAt``). A verifier that serves real traffic should pin at least ``now`` and ``recentCount``. Leave
    `expect` out for no pins: an explicit None (or a function returning None) matches nothing."""
    if not isinstance(public_signals, list):
        raise TypeError("public signals must be a list")
    layout = POLICYVM_PUBLIC_SIGNAL if layout is None else layout
    at = lambda name: public_signals[layout[name]] if layout[name] < len(public_signals) else None  # noqa: E731
    for name in ("now", "blast", "delegationDepth", "recentCount", "allocChild"):
        sig = at(name)
        if not isinstance(sig, str) or _CANON_DEC.fullmatch(sig) is None or int(sig) >= _U64:
            return False
    if expect is _UNSET:
        return True
    if callable(expect):
        try:
            expect = expect()
        except Exception:  # noqa: BLE001 - an expectation that cannot be evaluated matches nothing
            return False
    if expect is None:
        return False
    if isinstance(expect, list):
        expect = {}
    if not isinstance(expect, dict):
        return False
    for name in ("now", "blast", "delegationDepth", "recentCount", "allocChild", "r", "t"):
        if name in expect and not _signal_matches(at(name), expect[name]):
            return False
    if _truthy(expect.get("requireAdmit")) and not _is(at("admit"), "1"):
        return False
    if _truthy(expect.get("requireTier1")) and not _is(at("t"), "1"):
        return False
    return True


# ---- verification ----------------------------------------------------------------------------------------------------------------------

def verify_policy_vm_proof(env: Any, *, verification_key: Any = None, verification_key_path: Optional[str] = None, expect: Any = _UNSET,
                           expect_risk_hash: Optional[dict] = None, strict: bool = False) -> bool:
    """Verify a Policy VM Groth16 proof offline: ``{"system": "groth16-bn254" | "groth16-bls12-381", "circuit": "pca-policyvm-v1" |
    "pca-policyvm-v2", "proof", "publicSignals"}``. False (fail closed) on anything malformed.

    Order: shape, circuit and system tags (the risk-bound circuit is BN254 only), signal count, allow == 1, the risk-hash pin
    (`expect_risk_hash`, v2 only), the canonical envelope gate, the context pins (`expect`, see ``policy_vm_context_matches``), then the
    pairing check under `verification_key` (default: the bundled key of the proof's curve; the risk-bound circuit has none and reads
    ``POLICYVM_BOUND_VKEY_PATH``). `strict` also refuses a key whose protocol, nPublic or IC length disagree with the proof."""
    if not isinstance(env, dict):
        return False
    bound = _is(env.get("circuit"), "pca-policyvm-v2")
    if not bound and not _is(env.get("circuit"), "pca-policyvm-v1"):
        return False
    bls = _is(env.get("system"), "groth16-bls12-381")
    if not _is(env.get("system"), "groth16-bn254") and not (bls and not bound):
        return False
    layout = POLICYVM_BOUND_PUBLIC_SIGNAL if bound else POLICYVM_PUBLIC_SIGNAL
    ps = env.get("publicSignals")
    if not isinstance(ps, list) or len(ps) != (POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT if bound else POLICYVM_PUBLIC_SIGNAL_COUNT) or env.get("proof") is None:
        return False
    if not _is(ps[layout["allow"]], "1"):
        return False
    if expect_risk_hash is not None and not (bound and _halves_match(ps, layout, "risk", expect_risk_hash)):
        return False
    if not is_canonical_groth16_envelope(env, "bls12-381" if bls else "bn254"):
        return False
    if not policy_vm_context_matches(ps, expect, layout):
        return False
    bundled = None if bound else _zk_bundled.POLICYVM_BLS12381_VKEY_JSON if bls else _zk_bundled.POLICYVM_VKEY_JSON
    vkey = _vkey(verification_key, verification_key_path, bundled, POLICYVM_BOUND_VKEY_PATH)
    try:
        return _groth16_verify(vkey, ps, env["proof"], strict)
    except zk_native.ZkBackendMissing:
        raise
    except Exception:  # noqa: BLE001 - a key or proof the check cannot read is a refusal
        return False


def _halves_match(ps: list, layout: dict, name: str, want: Any) -> bool:
    """The two 128-bit halves of one commitment equal the expected digest (or no expectation was set)."""
    if not _truthy(want):
        return True
    hi, lo = layout[name + "Hi"], layout[name + "Lo"]
    return isinstance(want, dict) and lo < len(ps) and _is(want.get("hi"), ps[hi]) and _is(want.get("lo"), ps[lo]) and isinstance(ps[hi], str)


def _policy_vm_backend(bundled: str, default_path: Callable[[], str], verification_key: Any, verification_key_path: Optional[str], expect: Any,
                       ceremony: Any, hashes: Dict[str, Any], strict: bool) -> SnarkBackend:
    key = _Lazy(lambda: _vkey(verification_key, verification_key_path, bundled, default_path))

    def verify(proof: Any, _public_inputs: Any, _ctx: Any) -> bool:
        if not isinstance(proof, dict) or not _is(proof.get("circuit"), "pca-policyvm-v1"):
            return False
        ps = proof.get("publicSignals")
        if isinstance(ps, list) and not all(_halves_match(ps, POLICYVM_PUBLIC_SIGNAL, n, w) for n, w in hashes.items()):
            return False
        return verify_policy_vm_proof(proof, verification_key=key(), expect=expect, strict=strict)

    cer = _ceremony(verification_key, ceremony, "pca-policyvm-v1")
    return SnarkBackend(verify, _label("policyvm_snark", cer) if all(_truthy(w) for w in hashes.values()) else _label("unknown", cer, "policyvm-unbound"))


def create_policy_vm_snark_backend(*, verification_key: Any = None, verification_key_path: Optional[str] = None, expect: Any = _UNSET,
                                   ceremony: Optional[dict] = None, expect_action_hash: Optional[dict] = None,
                                   expect_policy_hash: Optional[dict] = None, expect_plan_hash: Optional[dict] = None,
                                   strict: bool = False) -> SnarkBackend:
    """A backend over the full Policy VM circuit (BN254 key bundled). It verifies the proof and allow == 1 and, when given, binds the
    proof's public struct-hash halves to `expect_action_hash` / `expect_policy_hash` / `expect_plan_hash` (``{"hi", "lo"}`` from
    ``policy_vm_struct_hash`` / ``policy_vm_commitment_from_action``). It does NOT bind the canonical-JSON commitments of the hook: the
    circuit commits to a fixed-layout struct. The label is ``policyvm_snark`` only with all three pinned; otherwise a valid proof may be
    for another compliant action and the label is ``unknown``."""
    return _policy_vm_backend(_zk_bundled.POLICYVM_VKEY_JSON, POLICYVM_VKEY_PATH, verification_key, verification_key_path, expect, ceremony,
                              {"action": expect_action_hash, "policy": expect_policy_hash, "plan": expect_plan_hash}, strict)


def create_policy_vm_snark_backend_bls12381(*, verification_key: Any = None, verification_key_path: Optional[str] = None, expect: Any = _UNSET,
                                            ceremony: Optional[dict] = None, expect_action_hash: Optional[dict] = None,
                                            expect_policy_hash: Optional[dict] = None, expect_plan_hash: Optional[dict] = None,
                                            strict: bool = False) -> SnarkBackend:
    """The BLS12-381 (128-bit) counterpart of ``create_policy_vm_snark_backend``: same binding and verification, BLS12-381 key bundled."""
    return _policy_vm_backend(_zk_bundled.POLICYVM_BLS12381_VKEY_JSON, POLICYVM_BLS12381_VKEY_PATH, verification_key, verification_key_path, expect,
                              ceremony, {"action": expect_action_hash, "policy": expect_policy_hash, "plan": expect_plan_hash}, strict)


def create_policy_vm_bound_snark_backend(*, verification_key: Any = None, verification_key_path: Optional[str] = None, expect: Any = _UNSET,
                                         ceremony: Optional[dict] = None, expect_action_hash: Optional[dict] = None,
                                         expect_policy_hash: Optional[dict] = None, expect_plan_hash: Optional[dict] = None,
                                         expect_risk_hash: Optional[dict] = None, strict: bool = False) -> SnarkBackend:
    """A backend over the risk-bound circuit (``pca-policyvm-v2``, BN254): the checks of ``create_policy_vm_snark_backend`` plus the risk
    commitment `expect_risk_hash` (``policy_vm_risk_hash`` over the attested magnitudes). ``policyvm_snark`` only with all four pinned.
    There is no bundled key: pass `verification_key` / `verification_key_path`, or ``POLICYVM_BOUND_VKEY_PATH`` is read."""
    key = _Lazy(lambda: _vkey(verification_key, verification_key_path, None, POLICYVM_BOUND_VKEY_PATH))
    hashes = {"action": expect_action_hash, "policy": expect_policy_hash, "plan": expect_plan_hash, "risk": expect_risk_hash}

    def verify(proof: Any, _public_inputs: Any, _ctx: Any) -> bool:
        if not isinstance(proof, dict) or not _is(proof.get("circuit"), "pca-policyvm-v2") or not isinstance(proof.get("publicSignals"), list):
            return False
        ps = proof["publicSignals"]
        if not all(_halves_match(ps, POLICYVM_BOUND_PUBLIC_SIGNAL, n, w) for n, w in hashes.items()):
            return False
        return verify_policy_vm_proof(proof, verification_key=key(), expect=expect, expect_risk_hash=expect_risk_hash, strict=strict)

    cer = _ceremony(verification_key, ceremony, "pca-policyvm-v2")
    return SnarkBackend(verify, _label("policyvm_snark", cer) if all(_truthy(w) for w in hashes.values()) else _label("unknown", cer, "policyvm-unbound"))


def prove_policy_vm_compliance(witness: Dict[str, Any], *, wasm_path: Optional[str] = None, zkey_path: Optional[str] = None,
                               seed: Optional[bytes] = None) -> dict:
    """A ``pca-policyvm-v1`` proof (BN254) from the complete fixed-point witness (every circuit input, the division witnesses included).
    Raises on a non-compliant witness. Needs the witness wasm and the proving key (build products; the bundled verifying key is enough
    to VERIFY). `seed` is for tests only."""
    return _prove({k: _witness_text(v) for k, v in witness.items()}, wasm_path or POLICYVM_WASM_PATH(), zkey_path or POLICYVM_ZKEY_PATH(),
                  "pca-policyvm-v1", seed)


def prove_policy_vm_bound_compliance(witness: Dict[str, Any], *, wasm_path: Optional[str] = None, zkey_path: Optional[str] = None,
                                     seed: Optional[bytes] = None) -> dict:
    """A risk-bound ``pca-policyvm-v2`` proof; same witness inputs as ``prove_policy_vm_compliance``. Raises on a non-compliant witness."""
    return _prove({k: _witness_text(v) for k, v in witness.items()}, wasm_path or POLICYVM_BOUND_WASM_PATH(),
                  zkey_path or POLICYVM_BOUND_ZKEY_PATH(), "pca-policyvm-v2", seed)


__all__ = [
    "ZK_PROVER_BINDING_REF", "policy_commitment", "pinned_policy_commitment", "action_commitment", "AttestedComplianceProver",
    "create_attested_compliance_prover", "prover_key_binding", "create_zk_verifier", "commitment_field", "is_canonical_groth16_envelope",
    "circuits_dir", "DEFAULT_VKEY_PATH", "DEFAULT_WASM_PATH", "DEFAULT_ZKEY_PATH", "POLICYVM_VKEY_PATH", "POLICYVM_SAMPLE_PROOF_PATH",
    "POLICYVM_WASM_PATH", "POLICYVM_ZKEY_PATH", "POLICYVM_BLS12381_VKEY_PATH", "POLICYVM_BLS12381_SAMPLE_PROOF_PATH", "POLICYVM_BOUND_VKEY_PATH",
    "POLICYVM_BOUND_SAMPLE_PROOF_PATH", "POLICYVM_BOUND_WASM_PATH", "POLICYVM_BOUND_ZKEY_PATH", "circuit_version", "SnarkBackend",
    "create_groth16_snark_backend", "prove_groth16_compliance", "POLICYVM_PUBLIC_SIGNAL", "POLICYVM_PUBLIC_SIGNAL_COUNT",
    "POLICYVM_BOUND_PUBLIC_SIGNAL", "POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT", "POLICYVM_BOUND_RISK_FIELDS", "POLICYVM_REVERSIBILITY_ORDER",
    "policy_vm_struct_hash", "policy_vm_risk_hash", "decode_policy_vm_public", "decode_policy_vm_bound_public", "quantize_action_struct",
    "quantize_plan_struct", "quantize_policy_struct", "quantize_policy_vm_inputs", "policy_vm_commitment_from_action",
    "policy_vm_context_matches", "verify_policy_vm_proof", "create_policy_vm_snark_backend", "create_policy_vm_snark_backend_bls12381",
    "create_policy_vm_bound_snark_backend", "prove_policy_vm_compliance", "prove_policy_vm_bound_compliance",
]
