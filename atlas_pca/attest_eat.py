"""Per-session attestation freshness and channel binding for PCA: a port of the TypeScript reference (@atlasauth/pca-attest-eat).

Emits attestation evidence as an Entity Attestation Token (RFC 9711, a compact JWS with the ``eat+jwt`` typ), binds it to a live
channel and a fresh nonce (IETF SEAT / RA-TLS), and appraises it with the RATS (RFC 9334) split of evidence, reference values
and endorsements into a trust tier. The AMD SEV-SNP hardware root is delegated to ``attest_amd``; this layer adds freshness,
channel binding, EAT emission and appraisal, and the AMD root stays a classical ECDSA/RSA chain (labelled, never upgraded).

Options and results are plain dicts with the reference's member names (``maxAgeMs``, ``expectedNonce``, ``reasons`` ...), so a
claim set or verdict is JSON-identical to the reference. Keys: EdDSA uses a 32-byte Ed25519 seed (signing) or public key
(verifying); ES256 uses a ``cryptography`` P-256 key object. ``cryptography`` is needed for ES256 and for Ed25519 signing
(``pip install 'atlas-pca[attest]'``). ``verify_fresh_attested_eat`` is synchronous here (the reference is async only for I/O-free
awaits); the post-quantum co-signature lives in ``attest_eat_pqcosign`` and admission / artifact provenance in
``attest_eat_admission``, re-exported below.
"""
from ._fin import fin
import hashlib
import math
import os
import re
from typing import Any, Dict, List, Optional

from . import ed25519
from .attest_amd import (
    AMD_ARK_SPKI_SHA384,
    SEV_SNP_POLICY_DEBUG_BIT,
    parse_sev_snp_report,
    verify_genuine_sev_snp_report,
)
from .attest_common import crypto, ecdsa_verify_raw, js_num_str, js_trim, pem_blocks, pem_to_der, to_hex
from .attest_eat_common import G, U, ct_eq, has, is_finite, is_number, js_includes, js_json, js_string, msg_of, now_ms, utf8
from .dpop import assert_canonical_compact_jws
from .pca import b64u, decode_b64u_strict

__all__ = [
    "EAT_TYP", "DEFAULT_EAT_ALG", "SUPPORTED_ALGS", "DEFAULT_MAX_AGE_MS", "CHANNEL_BINDING_DOMAIN", "AMD_SEV_SNP_SIGNED_REGION_END",
    "AMD_SEV_SNP_HARDWARE_ROOT_LABEL", "KNOWN_AMD_ARK_SPKI_SHA384", "AMD_MILAN_ARK_SPKI_SHA384", "KNOWN_REPORT_VERSIONS",
    "generate_eat_key_pair", "verify_key_from_jwk", "issue_nonce", "evidence_from_report", "measured_from_report",
    "parse_report_tolerant", "derive_channel_cnf", "bind_channel", "build_eat", "verify_eat", "verify_freshness",
    "verify_channel_binding", "appraise", "verify_amd_attestation", "verify_fresh_attested_eat",
]

EAT_TYP = "eat+jwt"
DEFAULT_EAT_ALG = "EdDSA"
SUPPORTED_ALGS = ("EdDSA", "ES256")
DEFAULT_MAX_AGE_MS = 5 * 60_000
CHANNEL_BINDING_DOMAIN = "atlas-pca/eat-channel/v1"
AMD_SEV_SNP_SIGNED_REGION_END = 0x2A0
AMD_SEV_SNP_HARDWARE_ROOT_LABEL = "amd-sev-snp/ecdsa-p384 (VCEK\u2192ASK\u2192ARK; classical hardware root, not post-quantum)"
KNOWN_AMD_ARK_SPKI_SHA384: Dict[str, str] = dict(AMD_ARK_SPKI_SHA384)
AMD_MILAN_ARK_SPKI_SHA384 = AMD_ARK_SPKI_SHA384["milan"]
KNOWN_REPORT_VERSIONS = (2, 3, 5)
_MAX_EAT_BYTES = 1 << 20


def _normalize_typ(typ: str) -> str:
    # RFC 7515 4.1.9: a typ without a slash is the application/ form
    t = typ.lower()
    return t if "/" in t else "application/" + t


def _is_record(v: Any) -> bool:
    return isinstance(v, dict)


def _is_supported_alg(v: Any) -> bool:
    return isinstance(v, str) and v in SUPPORTED_ALGS


# ---------------------------------------------------------------------------------------------------------------- keys + JWS


def generate_eat_key_pair(alg: str = DEFAULT_EAT_ALG) -> Dict[str, Any]:
    """A fresh signing key pair: EdDSA -> {publicKey: 32 bytes, privateKey: 32-byte seed}; ES256 -> `cryptography` P-256 keys."""
    if alg == "EdDSA":
        seed = os.urandom(32)
        return {"publicKey": ed25519.public_key(seed), "privateKey": seed}
    if alg == "ES256":
        c = crypto()
        priv = c.ec.generate_private_key(c.ec.SECP256R1())
        return {"publicKey": priv.public_key(), "privateKey": priv}
    raise ValueError("generateEatKeyPair: unsupported alg '%s'" % js_string(alg))


def verify_key_from_jwk(jwk: Dict[str, Any]) -> Any:
    """A verify key from a JWK: OKP / Ed25519 -> the 32 raw public-key bytes, EC / P-256 -> a `cryptography` public key."""
    kty, crv = G(jwk, "kty"), G(jwk, "crv")
    if kty == "OKP" and crv == "Ed25519":
        x = decode_b64u_strict(G(jwk, "x"), 32)
        if x is None:
            raise ValueError("verifyKeyFromJwk: bad Ed25519 public key")
        return x
    if kty == "EC" and crv == "P-256":
        x, y = decode_b64u_strict(G(jwk, "x"), 32), decode_b64u_strict(G(jwk, "y"), 32)
        if x is None or y is None:
            raise ValueError("verifyKeyFromJwk: bad P-256 public key")
        c = crypto()
        return c.ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), c.ec.SECP256R1()).public_key()
    raise ValueError("verifyKeyFromJwk: unsupported key (OKP Ed25519 and EC P-256 only)")


def _ed_seed(key: Any) -> Optional[bytes]:
    if isinstance(key, (bytes, bytearray)) and len(key) == 32:
        return bytes(key)
    return None


class InvalidDigestError(TypeError):
    """The reference runtime's OpenSSL error for a digest an Ed25519 key cannot take (ERR_OSSL_INVALID_DIGEST)."""
    code = "ERR_OSSL_INVALID_DIGEST"


def _is_ed25519_key(c: Any, key: Any, private: bool) -> bool:
    """An Ed25519 key in any form this module takes (raw bytes, or a `cryptography` key object)."""
    if isinstance(key, (bytes, bytearray)):
        return True
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed
    except ImportError:
        return False
    return isinstance(key, _ed.Ed25519PrivateKey if private else _ed.Ed25519PublicKey)


def _sign_jws(alg: str, key: Any, signing_input: str) -> str:
    data = utf8(signing_input)
    if alg == "EdDSA":
        seed = _ed_seed(key)
        if seed is not None:
            return b64u(ed25519.sign_secret(seed, data))
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:
            raise TypeError("EdDSA signing needs a 32-byte Ed25519 seed") from None
        if isinstance(key, Ed25519PrivateKey):
            return b64u(key.sign(data))
        raise TypeError("an EdDSA token is signed with an Ed25519 key")
    # ES256: ECDSA P-256 over SHA-256, JWS wants raw r || s
    c = crypto()
    if _is_ed25519_key(c, key, private=True):
        raise InvalidDigestError("error:1C80007A:Provider routines::invalid digest")
    if not isinstance(key, c.ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise TypeError("an ES256 token is signed with a P-256 key")
    r, s = c.utils.decode_dss_signature(key.sign(data, c.ec.ECDSA(c.hashes.SHA256())))
    return b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _verify_jws(alg: str, key: Any, signing_input: str, sig_b64u: str) -> bool:
    data = utf8(signing_input)
    sig = decode_b64u_strict(sig_b64u) or b""
    if alg == "EdDSA":
        if isinstance(key, (bytes, bytearray)):
            return ed25519.verify(bytes(key), data, sig)
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            raise TypeError("EdDSA verification needs the 32 raw Ed25519 public-key bytes") from None
        if isinstance(key, Ed25519PublicKey):
            return ed25519.verify(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), data, sig)
        raise TypeError("an EdDSA token verifies under an Ed25519 key")
    c = crypto()
    if _is_ed25519_key(c, key, private=False):
        raise InvalidDigestError("error:1C80007A:Provider routines::invalid digest")
    if not isinstance(key, c.ec.EllipticCurvePublicKey):
        raise TypeError("an ES256 token verifies under an EC key")
    return ecdsa_verify_raw(key, sig, data, "sha256")


# ---------------------------------------------------------------------------------------------------------------- nonce


def _base36(n: int) -> str:
    if n == 0:
        return "0"
    digits, neg, n = "0123456789abcdefghijklmnopqrstuvwxyz", n < 0, abs(n)
    out = []
    while n:
        n, r = divmod(n, 36)
        out.append(digits[r])
    return ("-" if neg else "") + "".join(reversed(out))


def issue_nonce(opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """A fresh single-use challenge: ``b64u(random) + "." + base36(now)``. `bytes` is the random length (min 16, default 32).
    shortcut: a non-integral `now` is refused (the reference prints base-36 fractions), the clock is always integral."""
    opts = opts or {}
    now = opts.get("now")
    now = now if is_finite(now) else now_ms()
    if isinstance(now, float):
        if not now.is_integer():
            raise ValueError("issueNonce: now must be an integral millisecond count")
        now = int(now)
    n = opts.get("bytes")
    n = 32 if n is None else n
    if not is_finite(n):
        raise ValueError("issueNonce: bytes must be a finite number")
    n = max(16, int(math.floor(n)))
    return {"value": "%s.%s" % (b64u(os.urandom(n)), _base36(now)), "issuedAt": now}


# ---------------------------------------------------------------------------------------------------------------- evidence projection


def evidence_from_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Project a parsed SEV-SNP report (``parse_sev_snp_report``) into the JSON-safe evidence an EAT carries."""
    return {
        "version": report["version"],
        "measurement": to_hex(report["measurement"]),
        "reported_tcb": str(report["reported_tcb"]),
        "guest_svn": report["guest_svn"],
        "chip_id": to_hex(report["chip_id"]),
        "debug": (report["policy"] & SEV_SNP_POLICY_DEBUG_BIT) != 0,
    }


def measured_from_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """The measured identity of a report: runtime_measurement = hex(MEASUREMENT), operator = hex(CHIP_ID); no weights field."""
    return {
        "model_id": "",
        "weights_digest": "",
        "weights_measured": False,
        "runtime_measurement": to_hex(report["measurement"]),
        "operator": to_hex(report["chip_id"]),
    }


# ---------------------------------------------------------------------------------------------------------------- tolerant parse

_OFF_VERSION, _OFF_GUEST_SVN, _OFF_POLICY, _OFF_MEASUREMENT, _OFF_REPORTED_TCB, _OFF_CHIP_ID = 0x000, 0x004, 0x008, 0x090, 0x180, 0x1A0
_FULL_REPORT_MIN_LEN = 0x2E8 + 72


def _u32(b: bytes, off: int) -> Optional[int]:
    return None if off + 4 > len(b) else int.from_bytes(b[off:off + 4], "little")


def _u64(b: bytes, off: int) -> Optional[int]:
    return None if off + 8 > len(b) else int.from_bytes(b[off:off + 8], "little")


def _slice(b: bytes, off: int, n: int) -> Optional[bytes]:
    return None if off + n > len(b) else b[off:off + n]


def parse_report_tolerant(raw: Any) -> Dict[str, Any]:
    """Parse an SEV-SNP report across format versions, degrading to the version-stable header instead of raising.
    A known version with a complete buffer gets the full parse (``report`` + ``evidence``, ``degraded`` False)."""
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        return {"ok": False, "version": 0, "known": False, "degraded": True, "notes": ["input is not a Uint8Array"]}
    b = bytes(raw)
    notes: List[str] = []
    version = _u32(b, _OFF_VERSION)
    if version is None:
        return {"ok": False, "version": 0, "known": False, "degraded": True, "notes": ["buffer too short to read the report version"]}
    known = version in KNOWN_REPORT_VERSIONS
    if known and len(b) >= _FULL_REPORT_MIN_LEN:
        try:
            report = parse_sev_snp_report(b)
            return {"ok": True, "version": report["version"], "known": True, "degraded": False, "notes": notes, "report": report,
                    "evidence": evidence_from_report(report)}
        except Exception as e:  # noqa: BLE001 - degrade, as the reference
            notes.append("full parse failed, falling back to the stable header: %s" % msg_of(e))
    elif not known:
        notes.append("unknown report version %d \u2014 parsing version-stable header fields only (newer firmware, e.g. GCP 2025-10-27, "
                     "may relocate version-specific fields)" % version)
    else:
        notes.append("buffer length %d < full report %d \u2014 degraded header-only parse" % (len(b), _FULL_REPORT_MIN_LEN))

    measurement = _slice(b, _OFF_MEASUREMENT, 48)
    if measurement is None:
        return {"ok": False, "version": version, "known": known, "degraded": True,
                "notes": notes + ["buffer too short to read the launch measurement"]}
    evidence: Dict[str, Any] = {"version": version, "measurement": to_hex(measurement), "degraded": True}
    guest_svn = _u32(b, _OFF_GUEST_SVN)
    if guest_svn is not None:
        evidence["guest_svn"] = guest_svn
    policy = _u64(b, _OFF_POLICY)
    if policy is not None:
        evidence["debug"] = (policy & SEV_SNP_POLICY_DEBUG_BIT) != 0
    tcb = _u64(b, _OFF_REPORTED_TCB)
    if tcb is not None:
        evidence["reported_tcb"] = str(tcb)
    chip = _slice(b, _OFF_CHIP_ID, 64)
    if chip is not None:
        evidence["chip_id"] = to_hex(chip)
    return {"ok": True, "version": version, "known": known, "degraded": True, "notes": notes, "evidence": evidence}


# ---------------------------------------------------------------------------------------------------------------- channel binding


def derive_channel_cnf(channel_id: Any, holder_key_thumbprint: Any = None) -> Dict[str, str]:
    """``cnf.tls_exporter`` = ``b64u(sha256(DOMAIN || channelId))`` (RA-TLS), plus ``jkt`` when a thumbprint is given."""
    if not isinstance(channel_id, str) or len(channel_id) == 0:
        raise ValueError("deriveChannelCnf: channelId is required")
    cnf = {"tls_exporter": b64u(hashlib.sha256(utf8(CHANNEL_BINDING_DOMAIN) + utf8(channel_id)).digest())}
    if isinstance(holder_key_thumbprint, str) and len(holder_key_thumbprint) > 0:
        cnf["jkt"] = holder_key_thumbprint
    return cnf


def bind_channel(evidence: Any, channel_id: Any, nonce: Any) -> Dict[str, Any]:
    """Bind evidence to a TLS channel id and a per-session freshness nonce (the inputs of ``build_eat``)."""
    if not isinstance(nonce, str) or len(nonce) == 0:
        raise ValueError("bindChannel: a per-session nonce is required for freshness")
    return {"evidence": evidence, "nonce": nonce, "cnf": derive_channel_cnf(channel_id)}


# ---------------------------------------------------------------------------------------------------------------- build / verify


def _resolve_cnf(args: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if has(args, "channelId"):
        derived = derive_channel_cnf(args["channelId"])
        out["tls_exporter"] = derived["tls_exporter"]
    if has(args, "channelBinding"):
        cb = args["channelBinding"]
        te, jkt = G(cb, "tls_exporter"), G(cb, "jkt")
        if isinstance(te, str):
            out["tls_exporter"] = te
        if isinstance(jkt, str):
            out["jkt"] = jkt
    return out


def build_eat(args: Dict[str, Any]) -> str:
    """A signed EAT (compact JWS, typ ``eat+jwt``) over the evidence: ``iss``, ``iat``, ``eat_nonce``, ``cnf`` and the optional
    measured identity / sevsnp evidence / measurements / ueid / sueid / dbgstat / oemid claims. It needs a nonce AND a channel
    binding: an unbound EAT would re-open the replay gap. `key` is an Ed25519 seed (EdDSA) or a P-256 key (ES256)."""
    issuer, nonce = G(args, "issuer"), G(args, "nonce")
    if not isinstance(issuer, str) or len(issuer) == 0:
        raise ValueError("buildEAT: issuer is required")
    if not isinstance(nonce, str) or len(nonce) == 0:
        raise ValueError("buildEAT: nonce (eat_nonce) is required for freshness")
    alg = args.get("alg")
    alg = DEFAULT_EAT_ALG if alg is None else alg
    if not _is_supported_alg(alg):
        raise ValueError("buildEAT: unsupported alg '%s'" % js_string(alg))
    cnf = _resolve_cnf(args)
    if "tls_exporter" not in cnf and "jkt" not in cnf:
        raise ValueError("buildEAT: a channel binding (channelId or channelBinding with a TLS exporter / holder-key thumbprint) "
                         "is required (RA-TLS) \u2014 refusing to emit unbound evidence")
    now = args.get("now")
    iat_ms = now if is_finite(now) else now_ms()
    claims: Dict[str, Any] = {"iss": issuer, "iat": math.floor(iat_ms / 1000) if isinstance(iat_ms, float) else iat_ms // 1000,
                              "eat_nonce": nonce, "cnf": cnf}
    for k in ("ueid", "sueid", "oemid", "dbgstat", "measurements", "measured", "sevsnp"):
        if k in args:
            claims[k] = args[k]
    header = {"alg": alg, "typ": EAT_TYP}
    signing_input = "%s.%s" % (b64u(utf8(js_json(header))), b64u(utf8(js_json(claims))))
    return "%s.%s" % (signing_input, _sign_jws(alg, args.get("key"), signing_input))


def _parse_cnf(v: Any) -> Optional[Dict[str, str]]:
    if not _is_record(v):
        return None
    out: Dict[str, str] = {}
    if isinstance(v.get("tls_exporter"), str):
        out["tls_exporter"] = v["tls_exporter"]
    if isinstance(v.get("jkt"), str):
        out["jkt"] = v["jkt"]
    return out or None


def _parse_measurements(v: Any) -> Optional[List[Dict[str, str]]]:
    if not isinstance(v, list):
        return None
    out = [{"type": e["type"], "value": e["value"]} for e in v if _is_record(e) and isinstance(e.get("type"), str) and isinstance(e.get("value"), str)]
    return out or None


def _parse_tcb_version(v: Any) -> Any:
    if is_finite(v):
        return v
    if isinstance(v, str):
        return v
    if _is_record(v):
        return {k: v[k] for k in ("bootloader", "tee", "snp", "microcode") if is_number(v.get(k))}
    return U


def _parse_measured(v: Any) -> Optional[Dict[str, Any]]:
    if not _is_record(v):
        return None
    if not all(isinstance(v.get(k), str) for k in ("model_id", "weights_digest", "runtime_measurement", "operator")):
        return None
    out: Dict[str, Any] = {"model_id": v["model_id"], "weights_digest": v["weights_digest"],
                           "runtime_measurement": v["runtime_measurement"], "operator": v["operator"]}
    if isinstance(v.get("weights_measured"), bool):
        out["weights_measured"] = v["weights_measured"]
    if isinstance(v.get("system_prompt_digest"), str):
        out["system_prompt_digest"] = v["system_prompt_digest"]
    if isinstance(v.get("tool_manifest_digest"), str):
        out["tool_manifest_digest"] = v["tool_manifest_digest"]
    return out


def _parse_sevsnp(v: Any) -> Optional[Dict[str, Any]]:
    if not _is_record(v) or not is_number(v.get("version")) or not isinstance(v.get("measurement"), str):
        return None
    out: Dict[str, Any] = {"version": v["version"], "measurement": v["measurement"]}
    tcb = _parse_tcb_version(v.get("reported_tcb"))
    if tcb is not U:
        out["reported_tcb"] = tcb
    if is_number(v.get("guest_svn")):
        out["guest_svn"] = v["guest_svn"]
    if isinstance(v.get("chip_id"), str):
        out["chip_id"] = v["chip_id"]
    if isinstance(v.get("debug"), bool):
        out["debug"] = v["debug"]
    if isinstance(v.get("degraded"), bool):
        out["degraded"] = v["degraded"]
    return out


_DBGSTAT_VALUES = ("enabled", "disabled", "disabled-since-boot", "disabled-permanently", "disabled-fully-and-permanently")


def verify_eat(eat: Any, verify_key: Any, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Verify an EAT's signature and typ / iss and parse it into claims. Raises on an invalid signature, wrong key, failed iss / typ
    check, unsupported alg, or a missing iss / iat. A claim of the wrong type is dropped, so a later check fails closed. This
    proves AUTHENTICITY only: freshness, channel binding and appraisal are separate steps."""
    opts = {} if opts is None else opts
    if not isinstance(eat, str):
        raise ValueError("EAT invalid: token is not a string")
    try:
        parsed = assert_canonical_compact_jws(eat, max_bytes=_MAX_EAT_BYTES)  # one accepted spelling per EAT
    except Exception as e:  # noqa: BLE001
        raise ValueError("EAT invalid: %s" % msg_of(e)) from None
    h, p, s = parsed["segments"]
    header, payload = parsed["header"], parsed["payload"]
    if not _is_supported_alg(header.get("alg")):
        raise ValueError("EAT invalid: missing or unsupported `alg` header")
    allowed = opts.get("algorithms")
    allowed = SUPPORTED_ALGS if allowed is None else allowed
    if isinstance(allowed, str):
        alg_ok = header["alg"] in allowed
    elif isinstance(allowed, (list, tuple)):
        alg_ok = js_includes(allowed, header["alg"])
    else:
        raise TypeError("allowed.includes is not a function")
    if not alg_ok:
        raise ValueError("EAT invalid: alg %s not in the allowed set" % header["alg"])
    if opts.get("requireTyp") is not False:
        want = opts.get("typ")
        want = EAT_TYP if want is None else want
        typ = header.get("typ", U)
        if not isinstance(typ, str) or _normalize_typ(typ) != _normalize_typ(want):
            raise ValueError("EAT invalid: typ %s is not %s" % (js_string(typ), js_string(want)))
    if not _verify_jws(header["alg"], verify_key, "%s.%s" % (h, p), s):
        raise ValueError("EAT invalid: signature does not verify")
    iss, iat = payload.get("iss"), payload.get("iat")
    if not isinstance(iss, str):
        raise ValueError("EAT invalid: missing or non-string `iss`")
    if not is_finite(iat):
        raise ValueError("EAT invalid: missing or non-numeric `iat`")
    if "issuer" in opts:
        want_iss = opts["issuer"]
        if not js_includes(want_iss if isinstance(want_iss, list) else [want_iss], iss):
            raise ValueError("EAT invalid: iss %s is not an accepted issuer" % iss)
    claims: Dict[str, Any] = {"iss": iss, "iat": iat}
    if isinstance(payload.get("eat_nonce"), str):
        claims["eat_nonce"] = payload["eat_nonce"]
    cnf = _parse_cnf(payload.get("cnf"))
    if cnf is not None:
        claims["cnf"] = cnf
    if isinstance(payload.get("ueid"), str):
        claims["ueid"] = payload["ueid"]
    if isinstance(payload.get("sueid"), str):
        claims["sueid"] = payload["sueid"]
    measurements = _parse_measurements(payload.get("measurements"))
    if measurements is not None:
        claims["measurements"] = measurements
    if isinstance(payload.get("dbgstat"), str) and payload["dbgstat"] in _DBGSTAT_VALUES:
        claims["dbgstat"] = payload["dbgstat"]
    if isinstance(payload.get("oemid"), str):
        claims["oemid"] = payload["oemid"]
    measured = _parse_measured(payload.get("measured"))
    if measured is not None:
        claims["measured"] = measured
    sevsnp = _parse_sevsnp(payload.get("sevsnp"))
    if sevsnp is not None:
        claims["sevsnp"] = sevsnp
    return claims


# ---------------------------------------------------------------------------------------------------------------- freshness + channel


def verify_freshness(eat: Any, opts: Dict[str, Any]) -> Dict[str, Any]:
    """ANTI-REPLAY FRESHNESS: the ``eat_nonce`` must equal the server-issued challenge and ``iat`` must lie in
    ``[now - maxAgeMs, now]`` (plus ``clockSkewMs``). Absent / mismatched nonce, future iat or a stale token fail closed.
    A present clockSkewMs that is not a finite number (NaN, Infinity, a string, null) is refused: it would disable the age window."""
    now = G(opts, "now")
    now = now if is_finite(now) else now_ms()
    skew = G(opts, "clockSkewMs")
    if skew is not U and not is_finite(skew):
        return {"ok": False, "reason": "invalid clockSkewMs (must be a finite number)"}
    skew = 0 if skew is U else max(0, skew)
    expected = G(opts, "expectedNonce")
    if not isinstance(expected, str) or len(expected) == 0:
        return {"ok": False, "reason": "no expected (server-issued) nonce supplied (fail closed)"}
    nonce = G(eat, "eat_nonce")
    if not isinstance(nonce, str) or len(nonce) == 0:
        return {"ok": False, "reason": "EAT carries no eat_nonce \u2014 cannot establish freshness (replayable)"}
    if not ct_eq(nonce, expected):
        return {"ok": False, "reason": "eat_nonce does not match the server-issued challenge (replayed or relayed evidence)"}
    iat = G(eat, "iat")
    if not is_finite(iat):
        return {"ok": False, "reason": "EAT has no valid iat (cannot establish age)"}
    max_age = G(opts, "maxAgeMs")
    if not is_finite(max_age) or max_age <= 0:
        return {"ok": False, "reason": "invalid maxAgeMs"}
    iat_ms = iat * 1000
    if not (iat_ms - skew <= now):
        return {"ok": False, "reason": "EAT iat is in the future"}
    if not (now - iat_ms <= max_age + skew):
        return {"ok": False, "reason": "EAT is stale (iat older than maxAgeMs) \u2014 expired/replayed attestation"}
    return {"ok": True}


def verify_channel_binding(eat: Any, opts: Dict[str, Any]) -> Dict[str, Any]:
    """CHANNEL BINDING (RA-TLS): every field of the expected cnf (derived from ``channelId`` and / or an explicit ``expectedCnf``) must
    be present and equal in the token's ``cnf``. No cnf, or one bound to another channel / key, fails closed."""
    exp: Dict[str, str] = {}
    channel_id = G(opts, "channelId")
    if isinstance(channel_id, str) and len(channel_id) > 0:
        exp["tls_exporter"] = derive_channel_cnf(channel_id)["tls_exporter"]
    if has(opts, "expectedCnf"):
        e = opts["expectedCnf"]
        te, jkt = G(e, "tls_exporter"), G(e, "jkt")
        if isinstance(te, str):
            exp["tls_exporter"] = te
        if isinstance(jkt, str):
            exp["jkt"] = jkt
    if not exp:
        return {"ok": False, "reason": "no expected channel binding supplied (fail closed)"}
    cnf = G(eat, "cnf")
    c_te = G(cnf, "tls_exporter") if cnf not in (None, U, "", 0, False) else U
    c_jkt = G(cnf, "jkt") if cnf not in (None, U, "", 0, False) else U
    if c_te is U and c_jkt is U:
        return {"ok": False, "reason": "EAT carries no channel/key binding (cnf) \u2014 evidence is not bound to a live channel (RA-TLS)"}
    if "tls_exporter" in exp and (c_te is U or not ct_eq(c_te, exp["tls_exporter"])):
        return {"ok": False, "reason": "TLS-exporter channel binding mismatch (evidence lifted to another channel?)"}
    if "jkt" in exp and (c_jkt is U or not ct_eq(c_jkt, exp["jkt"])):
        return {"ok": False, "reason": "holder-key thumbprint (cnf.jkt) mismatch"}
    return {"ok": True}


# ---------------------------------------------------------------------------------------------------------------- RATS appraisal

_TRUSTWORTHY_TIERS = ("affirming-hw-rooted", "affirming", "warning")


def _is_nonempty_list(v: Any) -> bool:
    return isinstance(v, (list, tuple)) and len(v) > 0


def _pack_tcb(v: Any) -> Optional[int]:
    """A TCB version as a comparable integer, or None for an unknown shape (fail closed)."""
    if is_number(v):
        return int(math.floor(v)) if is_finite(v) and v >= 0 else None
    if isinstance(v, str):
        t = js_trim(v)
        return int(t) if re.fullmatch(r"[0-9]+", t) else None  # unknown / non-numeric format: fail closed
    if not isinstance(v, dict):
        return None  # true / [] / null are not a TCB version

    def comp(x: Any) -> Optional[int]:
        if x is U:
            return 0
        if not is_number(x):
            return None
        if isinstance(x, float):
            if not fin(x) or x != math.floor(x) or (x == 0 and math.copysign(1.0, x) < 0):
                return None
            x = int(x)
        return x if 0 <= x <= 255 else None

    parts = [comp(G(v, k)) for k in ("bootloader", "tee", "snp", "microcode")]
    if any(c is None for c in parts):
        return None
    bl, tee, snp, uc = parts
    return bl | (tee << 8) | (snp << 48) | (uc << 56)  # type: ignore[operator]


def _lc(s: Any) -> str:
    if not isinstance(s, str):
        raise TypeError("s.toLowerCase is not a function")
    return s.lower()


def _find(lst: Any, pred: Any) -> Any:
    """`lst?.find(pred)`: undefined for an absent list, a TypeError for a value without `find`."""
    if lst is U or lst is None:
        return U
    if not isinstance(lst, list):
        raise TypeError("eat.measurements?.find is not a function")
    for e in lst:
        if pred(e):
            return e
    return U


def _launch_measurement(eat: Any) -> Any:
    measured, sevsnp = G(eat, "measured"), G(eat, "sevsnp")
    if measured not in (None, U, "", 0, False):
        rm = G(measured, "runtime_measurement")
        if isinstance(rm, str) and len(rm) > 0:
            return rm
    if sevsnp not in (None, U, "", 0, False):
        m = G(sevsnp, "measurement")
        if isinstance(m, str):
            return m
    hit = _find(G(eat, "measurements"), lambda e: G(e, "type") in ("launch", "measurement"))
    return U if hit is U else G(hit, "value")


def _weights_measurement(eat: Any) -> Any:
    measured = G(eat, "measured")
    if measured not in (None, U, "", 0, False):
        wd = G(measured, "weights_digest")
        if isinstance(wd, str) and len(wd) > 0:
            return wd
    hit = _find(G(eat, "measurements"), lambda e: G(e, "type") == "weights")
    return U if hit is U else G(hit, "value")


def _is_debug_disabled(eat: Any) -> Optional[bool]:
    """True / False when the debug status is known, else None (the caller fails closed).
    shortcut: a dbgstat that is not one of the RFC 9711 values is unknown (the reference reads any value other than 'enabled' as
    disabled); a malformed claim never lifts a debug requirement."""
    dbg = G(eat, "dbgstat")
    if dbg is not U:
        if isinstance(dbg, str) and dbg in _DBGSTAT_VALUES:
            return dbg != "enabled"
        return None
    sevsnp = G(eat, "sevsnp")
    if sevsnp not in (None, U, "", 0, False) and isinstance(G(sevsnp, "debug"), bool):
        return G(sevsnp, "debug") is False
    return None


def appraise(evidence: Any, reference_values: Any = U, endorsements: Any = U, extras: Any = U) -> Dict[str, Any]:
    """APPRAISE an EAT's evidence against RATS reference values and endorsements (RFC 9334), kept as separate inputs.
    Tiers: ``affirming-hw-rooted`` > ``affirming`` > ``warning`` (acceptable); ``contraindicated`` (the measured state is
    actively bad) and ``rejected`` (empty policy, or a required input absent / in an unknown format) fail closed.
    Endorsements gate WHO (mismatch -> rejected); reference values gate WHAT (bad -> contraindicated, absent -> rejected).
    An omitted argument defaults to {}; an explicit None is dereferenced and raises, as in the reference."""
    rv = {} if reference_values is U else reference_values
    en = {} if endorsements is U else endorsements
    reasons: List[str] = []

    def result(tier: str, reason: str) -> Dict[str, Any]:
        return {"tier": tier, "trustworthy": tier in _TRUSTWORTHY_TIERS, "reasons": reasons + [reason]}

    en_issuers, en_oemids, en_operators = G(en, "issuers"), G(en, "oemids"), G(en, "operators")
    has_endorsements = _is_nonempty_list(en_issuers) or _is_nonempty_list(en_oemids) or _is_nonempty_list(en_operators)
    rv_meas, rv_models, rv_weights = G(rv, "measurements"), G(rv, "models"), G(rv, "weightsMeasurements")
    rv_min_tcb, rv_min_svn = G(rv, "minTcb"), G(rv, "minGuestSvn")
    has_reference_values = (_is_nonempty_list(rv_meas) or _is_nonempty_list(rv_models) or _is_nonempty_list(rv_weights)
                            or G(rv, "requireMeasuredWeights") is True or rv_min_tcb is not U or is_number(rv_min_svn)
                            or G(rv, "requireDebugDisabled") is True)
    if not has_endorsements and not has_reference_values:
        return {"tier": "rejected", "trustworthy": False,
                "reasons": ["empty appraisal policy: no endorsements or reference values to appraise against (fail closed)"]}

    iss = G(evidence, "iss")
    # Endorsements (WHO) -> rejected on mismatch.
    if _is_nonempty_list(en_issuers):
        if not js_includes(en_issuers, iss):
            return result("rejected", "issuer %s is not an endorsed attester" % js_string(iss))
        reasons.append("issuer endorsed")
    if _is_nonempty_list(en_oemids):
        oemid = G(evidence, "oemid")
        if not isinstance(oemid, str) or not js_includes(en_oemids, oemid):
            return result("rejected", "oemid absent or not endorsed (fail closed)")
        reasons.append("oemid endorsed")
    if _is_nonempty_list(en_operators):
        measured = G(evidence, "measured")
        op = G(measured, "operator") if measured not in (None, U) else U
        if not isinstance(op, str) or len(op) == 0 or not js_includes(en_operators, op):
            return result("rejected", "hardware operator absent or not endorsed (fail closed)")
        reasons.append("operator endorsed")

    # Reference values (WHAT): bad value -> contraindicated; absent / unknown required -> rejected.
    if _is_nonempty_list(rv_meas):
        m = _launch_measurement(evidence)
        if m is U:
            return result("rejected", "no launch measurement in evidence to compare against reference values (fail closed)")
        lowered = [_lc(x) for x in rv_meas]
        if _lc(m) not in lowered:
            return result("contraindicated", "launch measurement not in reference values")
        reasons.append("launch measurement matches a reference value")
    if _is_nonempty_list(rv_models):
        measured = G(evidence, "measured")
        model = G(measured, "model_id") if measured not in (None, U) else U
        if not isinstance(model, str) or len(model) == 0:
            return result("rejected", "no model id in evidence (fail closed)")
        if not js_includes(rv_models, model):
            return result("contraindicated", "model id not in reference values (model swap?)")
        reasons.append("model id matches a reference value")
    if G(rv, "requireMeasuredWeights") is True:
        measured = G(evidence, "measured")
        wm = G(measured, "weights_measured") if measured not in (None, U) else U
        if wm is not True:
            return result("contraindicated", "weights digest is not hardware-measured (require_measured_weights: "
                                             "self-asserted or host-asserted weights rejected)")
        reasons.append("weights digest is hardware-measured")
    if _is_nonempty_list(rv_weights):
        w = _weights_measurement(evidence)
        if w is U or (isinstance(w, str) and len(w) == 0):
            return result("rejected", "no measured-weights digest in evidence (fail closed)")
        lowered = [_lc(x) for x in rv_weights]
        if _lc(w) not in lowered:
            return result("contraindicated", "weights measurement not in reference values (model swap / fine-tune?)")
        reasons.append("weights measurement matches a reference value")
    if rv_min_tcb is not U:
        minimum = _pack_tcb(rv_min_tcb)
        if minimum is None:
            return result("rejected", "reference minTcb is not a comparable TCB version")
        sevsnp = G(evidence, "sevsnp")
        raw_tcb = G(sevsnp, "reported_tcb") if sevsnp not in (None, U) else U
        got = None if raw_tcb is U else _pack_tcb(raw_tcb)
        if got is None:
            return result("rejected", "evidence TCB version is absent or an unknown format \u2014 failing closed "
                                      "(see 2025-10-27 GCP firmware drift)")
        if got < minimum:
            return result("contraindicated", "reported TCB is below the reference minimum (downgrade / rollback)")
        reasons.append("TCB at or above reference minimum")
    if is_number(rv_min_svn):
        sevsnp = G(evidence, "sevsnp")
        svn = G(sevsnp, "guest_svn") if sevsnp not in (None, U) else U
        if not is_finite(svn):
            return result("rejected", "guest_svn absent (fail closed)")
        if svn < rv_min_svn:
            return result("contraindicated", "guest_svn %s below reference minimum %s" % (js_num_str(svn), js_num_str(rv_min_svn)))
        reasons.append("guest_svn at or above reference minimum")
    if G(rv, "requireDebugDisabled") is True:
        disabled = _is_debug_disabled(evidence)
        if disabled is None:
            return result("rejected", "debug status unknown \u2014 failing closed")
        if not disabled:
            return result("contraindicated", "debug is enabled (host can inspect the guest \u2014 no confidentiality)")
        reasons.append("debug disabled")

    # All checks passed: degraded evidence -> warning; a verified AMD signature -> the hardware-rooted tier.
    sevsnp = G(evidence, "sevsnp")
    if sevsnp not in (None, U) and G(sevsnp, "degraded") is True:
        return {"tier": "warning", "trustworthy": True, "reasons": reasons + ["evidence came from a degraded (version-tolerant) parse \u2014 review"]}
    ex = {} if extras is U else extras
    if G(ex, "hardwareVerified") is True:
        label = G(ex, "hardwareRootLabel")
        label = AMD_SEV_SNP_HARDWARE_ROOT_LABEL if label is U or label is None else label
        return {"tier": "affirming-hw-rooted", "trustworthy": True,
                "reasons": reasons + ["AMD SEV-SNP report signature + VCEK\u2192ASK\u2192ARK chain verified \u2014 %s" % js_string(label)]}
    return {"tier": "affirming", "trustworthy": True, "reasons": reasons}


# ---------------------------------------------------------------------------------------------------------------- AMD delegation


def _cert_to_der(inp: Any) -> bytes:
    if isinstance(inp, (bytes, bytearray, memoryview)):
        return bytes(inp)
    if not isinstance(inp, str):
        raise TypeError("a certificate is DER bytes or a PEM string")
    blocks = pem_blocks(inp)
    if len(blocks) != 1:
        raise ValueError("expected exactly one PEM certificate, found %d" % len(blocks))
    return pem_to_der(blocks[0])


def _der_to_pem(der: bytes) -> str:
    import base64
    b64 = re.sub(r"(.{64})", "\\1\n", base64.b64encode(der).decode("ascii"))
    return "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % b64


def verify_amd_attestation(raw_report: Any, opts: Dict[str, Any]) -> Dict[str, Any]:
    """Compose the AMD SEV-SNP hardware root of trust into one verdict by delegating to ``verify_genuine_sev_snp_report`` (per-family ARK
    pin, exact ASK-then-ARK bundle, validity against the verifier clock ``nowMs``, report signature, VCEK binding), then project the
    verified report into EAT evidence and a measured identity. Fails closed on any failure and never raises. Supply exactly one of
    ``family`` (milan | genoa | turin) or ``trustAnchorArkSpkiSha384``; the root is never inferred from the evidence."""
    root = AMD_SEV_SNP_HARDWARE_ROOT_LABEL
    try:
        has_family, has_pin = has(opts, "family"), has(opts, "trustAnchorArkSpkiSha384")
        if has_family == has_pin:
            return {"ok": False, "reason": "exactly one of family or trustAnchorArkSpkiSha384 must be supplied (the ARK pin is never inferred)",
                    "hardwareRoot": root}
        if has_family:
            fam = opts["family"]
            if not (isinstance(fam, str) and fam in KNOWN_AMD_ARK_SPKI_SHA384):
                return {"ok": False, "reason": "unknown AMD family %s (expected milan | genoa | turin)" % js_string(fam), "hardwareRoot": root}
            pin = KNOWN_AMD_ARK_SPKI_SHA384[fam]
        else:
            pin = opts["trustAnchorArkSpkiSha384"]
        try:
            vcek_der = _cert_to_der(G(opts, "vcek"))
            ask_ark_pem = _der_to_pem(_cert_to_der(G(opts, "ask"))) + _der_to_pem(_cert_to_der(G(opts, "ark")))
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "reason": "certificate parse failed: %s" % msg_of(e), "hardwareRoot": root}
        try:
            report: Any = parse_sev_snp_report(raw_report)
        except Exception:  # noqa: BLE001 - the verifier reports the parse failure with its own reason
            report = None
        expected = G(opts, "expectedMeasurement")
        measurements = [expected] if isinstance(expected, str) and len(expected) > 0 else []
        skew = G(opts, "clockSkewMs")
        verdict = verify_genuine_sev_snp_report(
            raw_report, vcek_der, ask_ark_pem, pin, G(opts, "nowMs") if G(opts, "nowMs") is not U else None,
            None if skew is U else skew, None, {"measurements": measurements, "allowDebug": G(opts, "allowDebug") is True})
        if not verdict.get("ok") or verdict.get("report") is None:
            out: Dict[str, Any] = {"ok": False, "reason": verdict.get("reason") or "AMD SEV-SNP verification failed", "hardwareRoot": root}
            if report is not None:
                out["report"] = report
            return out
        return {"ok": True, "hardwareRoot": root, "report": verdict["report"], "evidence": evidence_from_report(verdict["report"]),
                "measured": measured_from_report(verdict["report"])}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": "AMD attestation verification error (fail closed): %s" % msg_of(e), "hardwareRoot": root}


# ---------------------------------------------------------------------------------------------------------------- composition


def verify_fresh_attested_eat(eat: Any, opts: Dict[str, Any]) -> Dict[str, Any]:
    """The end-to-end check a resource server runs: verify the EAT's signature, then FRESHNESS (nonce + iat), CHANNEL BINDING (cnf vs
    the live channel) and APPRAISAL against the RATS policy. The first failing gate stops the pipeline and names the reason. With
    ``opts["amd"]`` the AMD report signature and chain are verified here (success lifts the tier to ``affirming-hw-rooted``, failure
    is ``contraindicated``). Options: verifyKey, nonce, channelId | channelBinding, policy, now, maxAgeMs, clockSkewMs, issuer,
    algorithms, typ, requireTyp, amd."""
    reasons: List[str] = []
    try:
        claims = verify_eat(eat, G(opts, "verifyKey"), {k: opts[k] for k in ("issuer", "algorithms", "typ", "requireTyp") if k in opts})
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reasons": ["EAT signature/claims invalid: %s" % msg_of(e)]}
    reasons.append("signature + typ/iss verified")

    now = G(opts, "now")
    now = now if is_finite(now) else now_ms()
    max_age = G(opts, "maxAgeMs")
    fopts: Dict[str, Any] = {"expectedNonce": G(opts, "nonce"), "maxAgeMs": DEFAULT_MAX_AGE_MS if max_age is U or max_age is None else max_age,
                             "now": now}
    if has(opts, "clockSkewMs"):
        fopts["clockSkewMs"] = opts["clockSkewMs"]
    fresh = verify_freshness(claims, fopts)
    if not fresh["ok"]:
        return {"ok": False, "reasons": reasons + [fresh.get("reason") or "not fresh"], "claims": claims}
    reasons.append("fresh (nonce + iat within window)")

    copts: Dict[str, Any] = {}
    if has(opts, "channelId"):
        copts["channelId"] = opts["channelId"]
    if has(opts, "channelBinding"):
        copts["expectedCnf"] = opts["channelBinding"]
    chan = verify_channel_binding(claims, copts)
    if not chan["ok"]:
        return {"ok": False, "reasons": reasons + [chan.get("reason") or "channel binding failed"], "claims": claims}
    reasons.append("channel-bound (cnf matches live channel)")

    extras: Dict[str, Any] = {}
    if has(opts, "amd"):
        amd = opts["amd"]
        expected = G(amd, "expectedMeasurement")
        if expected is U or expected is None:
            expected = _launch_measurement(claims)
        aopts: Dict[str, Any] = {"vcek": G(amd, "vcek"), "ask": G(amd, "ask"), "ark": G(amd, "ark"), "nowMs": now}
        for k in ("family", "trustAnchorArkSpkiSha384", "clockSkewMs", "allowDebug"):
            if has(amd, k):
                aopts[k] = amd[k]
        if expected is not U:
            aopts["expectedMeasurement"] = expected
        hw = verify_amd_attestation(G(amd, "rawReport"), aopts)
        if not hw["ok"]:
            return {"ok": False, "tier": "contraindicated",
                    "reasons": reasons + ["AMD hardware root verification failed: %s" % (hw.get("reason") or "unknown")], "claims": claims}
        reasons.append("AMD SEV-SNP hardware root verified (%s)" % hw["hardwareRoot"])
        extras = {"hardwareVerified": True, "hardwareRootLabel": hw["hardwareRoot"]}

    policy = G(opts, "policy")
    rvs, ens = G(policy, "referenceValues"), G(policy, "endorsements")
    app = appraise(claims, {} if rvs is U or rvs is None else rvs, {} if ens is U or ens is None else ens, extras)
    return {"ok": app["trustworthy"], "tier": app["tier"], "reasons": reasons + app["reasons"], "claims": claims}


# Re-export the rest of the reference's surface (the TypeScript index re-exports these modules).
from .attest_eat_pqcosign import *  # noqa: E402,F401,F403
from .attest_eat_admission import *  # noqa: E402,F401,F403
from .attest_eat_pqcosign import __all__ as _pq_all  # noqa: E402
from .attest_eat_admission import __all__ as _adm_all  # noqa: E402

__all__ = list(__all__) + list(_pq_all) + list(_adm_all)
