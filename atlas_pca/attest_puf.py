"""The PUF (physical unclonable function) attestation root: an unclonable-device identity. A code-offset secure sketch over a repetition code plus an
HKDF-SHA256 extractor (the fuzzy extractor), a simulated PUF for tests, a TPM endorsement-key provider over an injected command runner, enrollment
(the device key is the extracted secret: Ed25519 or ML-DSA), the device attestor, the enrollment registry and the verifier. A port of the reference
``attest-puf`` module. A PUF response is ``bytes`` with ONE 0/1 value per bit. Honest scope: the PUF roots a device identity, not a measurement of the
weights (``weights_measured`` is always False) and a simulated PUF is clonable. Synchronous; the verifier is a hardware-verifier object
(``verify(input) -> dict``) usable as a root of :func:`atlas_pca.attestation_soft.create_multi_root_verifier`."""
from __future__ import annotations

from ._fin import fin
import hashlib
import math
import os
import subprocess
from typing import Any, Callable, Dict, Optional

from ._hkdf import hkdf_sha256
from .agent import KeyPair, generate_pq_keypair, sign_with_suite
from .attest_common import attestation_binding
from .attest_pq_software import _has_pq
from .attestation_soft import _member, _need, _truthy, attestation_binding_b64u
from .intent_v2 import _UNDEF
from .intent_wb import _js_str
from .pca import _SIG_SUITES, b64u, canonical_bytes_strict, hash_canonical, unb64u, verify_leaf_suite

__all__ = ["PUF_EXTRACT_INFO", "PUF_ATTEST_DOMAIN", "PUF_KEY_BYTES", "TPM_EK_PUF_DOMAIN", "repetition_correction_bound", "fuzzy_enroll", "fuzzy_reproduce",
           "create_simulated_puf", "default_tpm_command_runner", "TpmEkPufProvider", "enroll_puf", "create_puf_attestor", "create_puf_enrollment_registry",
           "create_puf_verifier"]

PUF_EXTRACT_INFO = "atlas-pca/puf-extract/v1"
PUF_ATTEST_DOMAIN = "atlas-pca/attest-puf/v1\0"
PUF_KEY_BYTES = 32
TPM_EK_PUF_DOMAIN = "atlas-pca/puf-tpm-ek/v1"
_PUF_SUITES = {"ed25519": None, "ml-dsa-65": "ML-DSA-65", "ml-dsa-87": "ML-DSA-87"}


def _is_int(x: Any) -> bool:
    """Number.isInteger: an integral number (a bool is not one)."""
    return not isinstance(x, bool) and (isinstance(x, int) or (isinstance(x, float) and fin(x) and x == math.floor(x)))


# ---- fuzzy extractor ----

def repetition_correction_bound(rep: Any) -> int:
    """The per-block Hamming correction bound of a repetition code: floor((rep - 1) / 2)."""
    return math.floor((rep - 1) / 2)


def _assert_bits(b: bytes, where: str) -> None:
    if any(v > 1 for v in b):
        raise ValueError("%s: response must be a 0/1 bit array" % where)


def _xor_bits(a: bytes, b: bytes) -> bytes:
    return bytes((x ^ y) & 1 for x, y in zip(a, b))


def _rep_encode(message: bytes, rep: int) -> bytes:
    return bytes((m & 1) for m in message for _ in range(rep))


def _rep_decode(code: bytes, rep: int) -> bytes:
    k = len(code) // rep
    return bytes(1 if sum(code[i * rep + j] & 1 for j in range(rep)) * 2 > rep else 0 for i in range(k))  # strict majority; a tie (even rep) is 0


def _pack_bits(bits: bytes) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b & 1:
            out[i >> 3] |= 1 << (i & 7)
    return bytes(out)


def _unpack_bits(packed: bytes, n: int) -> bytes:
    return bytes((packed[i >> 3] >> (i & 7)) & 1 for i in range(n))


def _extract_key(response_bits: bytes, salt: bytes) -> bytes:
    return hkdf_sha256(_pack_bits(response_bits), salt, PUF_EXTRACT_INFO.encode("utf-8"), PUF_KEY_BYTES)


def fuzzy_enroll(response_bits: bytes, params: dict, random_bytes: Callable[[int], bytes]) -> Dict[str, Any]:
    """Enroll a response: ``{"key": 32 bytes, "helper": {sketch, salt, rep, messageBits, n}}``. ``random_bytes`` is asked first for ``messageBits``
    bytes (the codeword message, low bit used) and then for 32 salt bytes. Raises ValueError on a malformed response or parameters."""
    rep, mb = params.get("rep"), params.get("messageBits")
    if not _is_int(rep) or rep < 1 or rep % 2 == 0:
        raise ValueError("fuzzyEnroll: rep must be an odd positive integer")
    if not _is_int(mb) or mb < 1:
        raise ValueError("fuzzyEnroll: messageBits must be a positive integer")
    rep, mb = int(rep), int(mb)
    n = rep * mb
    response_bits = bytes(response_bits)
    if len(response_bits) != n:
        raise ValueError("fuzzyEnroll: response length %d != rep*messageBits %d" % (len(response_bits), n))
    _assert_bits(response_bits, "fuzzyEnroll")
    mr = bytes(random_bytes(mb))
    m = bytes((mr[i] & 1) if i < len(mr) else 0 for i in range(mb))
    sketch = _xor_bits(_rep_encode(m, rep), response_bits)  # C xor W
    salt = bytes(random_bytes(32))
    key = _extract_key(response_bits, salt)
    return {"key": key, "helper": {"sketch": b64u(_pack_bits(sketch)), "salt": b64u(salt), "rep": rep, "messageBits": mb, "n": n}}


def fuzzy_reproduce(response_bits: bytes, helper: Any) -> bytes:
    """The key from a noisy response and the public helper data: identical to enrollment within the per-block bound, a DIFFERENT key beyond it
    (fail closed: the signature then fails). Raises ValueError only for a structurally malformed helper or response."""
    h = helper if isinstance(helper, dict) else None
    if h is None or not _is_int(h.get("rep")) or not _is_int(h.get("messageBits")) or h["rep"] < 1 or h["rep"] % 2 == 0:
        raise ValueError("fuzzyReproduce: malformed helper params")
    n = int(h["rep"]) * int(h["messageBits"])
    if h.get("n") != n:
        raise ValueError("fuzzyReproduce: helper.n inconsistent with rep*messageBits")
    response_bits = bytes(response_bits)
    if len(response_bits) != n:
        raise ValueError("fuzzyReproduce: response length %d != %d" % (len(response_bits), n))
    _assert_bits(response_bits, "fuzzyReproduce")
    if not isinstance(h.get("sketch"), str) or not isinstance(h.get("salt"), str):
        raise ValueError("fuzzyReproduce: helper data missing sketch or salt")
    try:
        packed, salt = unb64u(h["sketch"]), unb64u(h["salt"])
    except ValueError:
        raise ValueError("fuzzyReproduce: helper sketch or salt is not canonical base64url") from None
    if len(packed) != (n + 7) // 8:
        raise ValueError("fuzzyReproduce: helper sketch has the wrong length")
    if len(salt) != 32:
        raise ValueError("fuzzyReproduce: helper salt has the wrong length")
    sketch = _unpack_bits(packed, n)
    rep = int(h["rep"])
    m_hat = _rep_decode(_xor_bits(response_bits, sketch), rep)
    return _extract_key(_xor_bits(_rep_encode(m_hat, rep), sketch), salt)


# ---- providers ----

def _bits_of(stream: bytes, length: int) -> bytes:
    return bytes((stream[i >> 3] >> (i & 7)) & 1 for i in range(length))


class _SimulatedPuf:
    def __init__(self, pid: str, seed: bytes, length: int, flip: Any):
        self.id, self._seed, self._length, self._flips = pid, bytes(seed), length, set(flip or ())

    def response(self, challenge: bytes) -> bytes:
        need = (self._length + 7) // 8
        stream = b"".join(hashlib.sha256(self._seed + bytes(challenge) + blk.to_bytes(4, "big")).digest() for blk in range((need + 31) // 32))
        bits = bytearray(_bits_of(stream, self._length))
        for pos in self._flips:
            if 0 <= pos < len(bits):
                bits[pos] ^= 1
        return bytes(bits)


def create_simulated_puf(opts: dict) -> Any:
    """A deterministic simulated PUF (``id``, ``seed`` bytes, ``length`` bits, ``flip`` positions to toggle): FOR TESTS ONLY, trivially clonable.
    Returns an object with ``id`` and ``response(challenge) -> bytes``."""
    return _SimulatedPuf(opts["id"], opts["seed"], opts["length"], opts.get("flip"))


def default_tpm_command_runner(command: str, args: Any) -> Dict[str, Any]:
    """Run a ``tpm2-tools`` command synchronously: ``{"status", "stdout", "stderr"?, "error"?}``. A tool or TPM failure never raises (status None plus
    ``error`` when the tool cannot be spawned), so the provider fails closed. shortcut: no 1 MiB output cap, add one if a tool can flood stdout."""
    try:
        p = subprocess.run([command, *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    except subprocess.TimeoutExpired as e:
        return {"status": None, "stdout": e.stdout or b"", "stderr": None, "error": "%s: ETIMEDOUT" % command}
    except OSError as e:
        return {"status": None, "stdout": b"", "stderr": None, "error": "%s: %s" % (command, e.__class__.__name__)}
    return {"status": p.returncode, "stdout": p.stdout, "stderr": p.stderr.decode("utf-8", "replace") or None}


def _js_status(v: Any) -> str:
    return "null" if v is None else _js_str(v)


class TpmEkPufProvider:
    """A PUF provider backed by a TPM 2.0 endorsement key: ``response`` derives a stable, device-unique bit response from the EK public area read
    through an injected command runner ``run(command, args) -> {"status", "stdout", "stderr"?, "error"?}`` (default: tpm2-tools). Fails closed."""

    def __init__(self, opts: dict):
        if not isinstance(opts, dict) or not isinstance(opts.get("id"), str) or not opts["id"]:
            raise TypeError("TpmEkPufProvider: id must be a non-empty string")
        if not _is_int(opts.get("length")) or opts["length"] < 1:
            raise ValueError("TpmEkPufProvider: length must be a positive integer (= enrolled rep*messageBits)")
        mn = opts.get("minEkBytes")
        if mn is not None and (not _is_int(mn) or mn < 1):
            raise ValueError("TpmEkPufProvider: minEkBytes must be a positive integer")
        self.id, self._length = opts["id"], int(opts["length"])
        self._run = opts.get("run") or default_tpm_command_runner
        tool = opts.get("tool")
        self._tool = tool if isinstance(tool, str) and tool else "tpm2_readpublic"
        handle = opts.get("ekHandle")
        handle = handle if isinstance(handle, str) and handle else "0x81010001"
        args = opts.get("args")
        self._args = list(args) if args is not None else ["-c", handle, "-f", "der", "-o", "/dev/stdout", "-Q"]
        self._min = 64 if mn is None else int(mn)

    def read_ek_public(self) -> bytes:
        try:
            res = self._run(self._tool, list(self._args))
        except Exception as e:  # noqa: BLE001
            raise RuntimeError("TpmEkPufProvider: tpm2-tools invocation threw (fail closed): %s" % (str(e) or "unknown")) from None
        if not isinstance(res, dict):
            raise RuntimeError("TpmEkPufProvider: command runner returned no result (fail closed)")
        if isinstance(res.get("error"), str) and res["error"]:
            raise RuntimeError("TpmEkPufProvider: tpm2-tools unavailable (fail closed): %s" % res["error"])
        if res.get("status") != 0 or isinstance(res.get("status"), bool):
            err = res.get("stderr")
            raise RuntimeError("TpmEkPufProvider: '%s' exited with status %s (fail closed)%s"
                               % (self._tool, _js_status(res.get("status")), (": " + err.strip()) if isinstance(err, str) and err else ""))
        ek = res.get("stdout")
        if not isinstance(ek, (bytes, bytearray)) or len(ek) < self._min:
            raise RuntimeError("TpmEkPufProvider: EK public too short (%d < %d bytes) \u2014 TPM unavailable or wrong handle (fail closed)"
                               % (len(ek) if isinstance(ek, (bytes, bytearray)) else 0, self._min))
        return bytes(ek)

    def response(self, challenge: bytes) -> bytes:
        secret = hkdf_sha256(self.read_ek_public(), TPM_EK_PUF_DOMAIN.encode("utf-8"), bytes(challenge), 32)
        need = (self._length + 7) // 8
        stream = b"".join(hashlib.sha256(secret + blk.to_bytes(4, "big")).digest() for blk in range(max(1, (need + 31) // 32)))
        return _bits_of(stream, self._length)


# ---- enrollment, attestor ----

def _assert_puf_suite(alg: Any) -> str:
    if isinstance(alg, str) and alg in _PUF_SUITES:
        return alg
    raise ValueError("PUF root: unsupported derived suite '%s' (use ed25519, ml-dsa-65 or ml-dsa-87)" % _js_str(alg))


class _Signer:
    def __init__(self, alg: str, seed: bytes):
        family = _PUF_SUITES[alg]
        self._alg = alg
        if family is None:
            self._ed, self._pq = KeyPair(seed, allow_insecure_signer=True), None
            self.public_key = self._ed.public
        else:
            self._ed, self._pq = None, generate_pq_keypair(family, seed)
            self.public_key = self._pq.public

    def sign(self, msg: bytes) -> Dict[str, str]:
        return sign_with_suite(self._alg, self._ed, self._pq, msg)


def _statement_message(body: dict) -> bytes:
    return PUF_ATTEST_DOMAIN.encode("utf-8") + canonical_bytes_strict(body)


def enroll_puf(provider: Any, challenge: bytes, opts: dict) -> Dict[str, Any]:
    """Enroll a PUF device under ``challenge``: ``opts`` = ``{"rep", "messageBits", "alg"? (default ml-dsa-65), "randomBytes"? (default os.urandom)}``.
    Returns the PUBLIC enrollment (provider id, challenge, suite, public key, helper, helper commitment); the key is re-derived on the device."""
    alg = _assert_puf_suite(opts.get("alg") if opts.get("alg") is not None else "ml-dsa-65")
    rb = opts.get("randomBytes") or os.urandom
    fe = fuzzy_enroll(provider.response(challenge), {"rep": opts.get("rep"), "messageBits": opts.get("messageBits")}, rb)
    return {"providerId": provider.id, "challenge": b64u(bytes(challenge)), "alg": alg, "publicKey": _Signer(alg, fe["key"]).public_key,
            "helper": fe["helper"], "helperCommitment": hash_canonical(fe["helper"])}


def create_puf_attestor(provider: Any, enrollment: dict) -> Any:
    """A device-side attestor: every ``attest(claims)`` reproduces the key from a fresh (noisy) reading, so only the real device signs a statement
    that verifies under the enrolled public key. ``claims`` = measurement, holder_pub, grant_ref, epoch, nonce and optionally weights_digest."""
    alg = _assert_puf_suite(enrollment.get("alg"))
    challenge = unb64u(enrollment.get("challenge"))

    class _Attestor:
        @staticmethod
        def attest(claims: dict) -> Dict[str, Any]:
            key = fuzzy_reproduce(provider.response(challenge), enrollment.get("helper"))
            signer = _Signer(alg, key)
            binding = attestation_binding_b64u({"holderPub": claims.get("holder_pub"), "grantRef": claims.get("grant_ref"), "epoch": claims.get("epoch"),
                                                "nonce": claims.get("nonce")})
            body: Dict[str, Any] = {"provider_id": provider.id, "measurement": _need(claims, "measurement"), "binding": binding, "alg": alg}
            if "weights_digest" in claims:
                body["weights_digest"] = claims["weights_digest"]
            return dict(body, **signer.sign(_statement_message(body)))

    return _Attestor()


class _Registry:
    def __init__(self, enrollments: Any):
        self._by_id: Dict[str, Any] = {}
        self._revoked: set = set()
        for e in enrollments if isinstance(enrollments, list) else []:
            self.register(e)

    def register(self, e: Any) -> None:
        if isinstance(e, dict) and isinstance(e.get("providerId"), str):
            self._by_id[e["providerId"]] = e

    def lookup(self, provider_id: str) -> Any:
        return None if provider_id in self._revoked else self._by_id.get(provider_id)

    def revoke(self, provider_id: str) -> None:
        self._revoked.add(provider_id)

    def is_revoked(self, provider_id: str) -> bool:
        return provider_id in self._revoked


def create_puf_enrollment_registry(enrollments: Any = None) -> Any:
    """An in-memory enrollment registry (``register``, ``lookup``, ``revoke``, ``is_revoked``): a later duplicate overwrites, a revoked id looks up
    as nothing and re-registering does not un-revoke it, malformed entries are skipped."""
    return _Registry(enrollments)


def _default_identity(st: dict, _enr: dict) -> Dict[str, Any]:
    return {"model_id": "", "weights_digest": st["weights_digest"] if isinstance(st.get("weights_digest"), str) else "", "weights_measured": False,
            "runtime_measurement": st.get("measurement"), "operator": ""}


def create_puf_verifier(opts: dict) -> Any:
    """A hardware-verifier root over PUF statements. Options: ``resolveEnrollment(provider_id, document, ctx) -> enrollment | None`` (required),
    ``policy`` ({"measurements" (non-empty), "weightsMeasurements"?, "deriveIdentity"?}), ``requirePq``, ``isRevoked(provider_id)`` and
    ``resolveEvidence(document, ctx) -> statement | None``. The signature is checked under the ENROLLED public key only. Construction refusals raise
    TypeError."""
    policy = opts.get("policy") if isinstance(opts, dict) else None
    if not isinstance(policy, dict) or not isinstance(policy.get("measurements"), list) or len(policy["measurements"]) == 0:
        raise TypeError("createPufVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)")
    if not callable(opts.get("resolveEnrollment")):
        raise TypeError("createPufVerifier: resolveEnrollment is required")
    measurements = list(policy["measurements"])
    wm = policy.get("weightsMeasurements")
    weights_measurements = list(wm) if isinstance(wm, list) else None
    require_pq = opts.get("requirePq") is True
    derive = policy.get("deriveIdentity") or _default_identity
    resolve_enrollment, resolve_evidence, is_revoked = opts["resolveEnrollment"], opts.get("resolveEvidence"), opts.get("isRevoked")

    class _Verifier:
        @staticmethod
        def verify(inp: dict) -> Dict[str, Any]:
            def fail(reason: str) -> Dict[str, Any]:
                return {"ok": False, "reason": reason}
            try:
                if not resolve_evidence:
                    return fail("no PUF evidence resolver configured (fail closed)")
                st = resolve_evidence(inp.get("document"), inp.get("ctx"))
                if not isinstance(st, dict) or not isinstance(st.get("provider_id"), str) or not isinstance(st.get("alg"), str):
                    return fail("no PUF attestation statement for this action")
                pid = st["provider_id"]
                if is_revoked and is_revoked(pid):
                    return fail("PUF enrollment for provider '%s' is revoked" % pid)
                enr = resolve_enrollment(pid, inp.get("document"), inp.get("ctx"))
                if not enr:
                    return fail("no PUF enrollment registered for provider '%s'" % pid)
                not_after = enr.get("notAfter", _UNDEF)
                if not_after is not _UNDEF and not (not_after is not None and inp.get("nowMs") < not_after):
                    return fail("PUF enrollment has expired")
                if not isinstance(enr.get("helperCommitment"), str) or enr["helperCommitment"] != hash_canonical(enr.get("helper")):
                    return fail("PUF enrollment helper commitment mismatch (helper tampered)")
                alg = st["alg"]
                if alg != enr.get("alg"):
                    return fail("PUF statement suite '%s' does not match the enrolled suite '%s'" % (alg, _js_str(enr.get("alg"))))
                suite = _SIG_SUITES.get(alg)
                if suite is None:
                    return fail("PUF statement declares an unknown signature alg '%s'" % alg)
                if require_pq and not _has_pq(suite):
                    return fail("PQ required: PUF-derived suite '%s' is classical" % alg)
                body = {k: v for k, v in st.items() if k not in ("sig", "pq_sig")}
                p: Dict[str, Any] = {"alg": alg, "sig": st.get("sig")}
                if suite[1]:
                    p["pq_pk"] = enr.get("publicKey")
                if "pq_sig" in st:
                    p["pq_sig"] = st["pq_sig"]
                if not isinstance(st.get("sig"), str) or not verify_leaf_suite(p, enr.get("publicKey"), _statement_message(body)):
                    return fail("PUF statement signature does not verify under the enrolled public key (wrong/cloned device or excessive noise)")
                expected = inp.get("expected")
                if not _truthy(expected):
                    return fail("no expected attestation binding supplied")
                try:
                    expected_b64u = b64u(attestation_binding(expected))
                except Exception as e:  # noqa: BLE001
                    return fail("binding not constructible: %s" % (str(e) or "invalid"))
                if not isinstance(st.get("binding"), str) or st["binding"] != expected_b64u:
                    return fail("PUF statement binding mismatch (holder/grant/epoch/nonce)")
                if not _member(measurements, st.get("measurement", _UNDEF)):
                    return fail("measurement not in policy allowlist")
                if weights_measurements:
                    if not isinstance(st.get("weights_digest"), str) or not _member(weights_measurements, st["weights_digest"]):
                        return fail("measured weights digest not in policy allowlist")
                return {"ok": True, "bound": True, "measured": derive(st, enr), "hostAsserted": {"provider_id": pid, "suite": alg}}
            except Exception as e:  # noqa: BLE001
                return fail("puf verification error (fail closed): %s" % (str(e) or "unknown"))

    return _Verifier()
