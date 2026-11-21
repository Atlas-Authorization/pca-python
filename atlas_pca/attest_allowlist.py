"""Signed, versioned, expiring measurement-allowlist manifests (domain ``pca-attest-allowlist/v1\\n``): verify (issuer keys, suite, validity window,
rollback floor), durable verify (a version high-water mark in a key/value store), create, sign, revoke an entry, and the projection to per-vendor
policy fields (Azure MAA, Intel DCAP, SEV-SNP, GCP Confidential Space, NVIDIA CC). A port of the reference ``attest-allowlist`` module; its durable
decision is the proved one (the high-water mark only ever moves up). Manifests, bodies and entries are dicts in the reference's member names."""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional

from ._fin import fin
from .agent import KeyPair, sign_with_suite
from .intent_v2 import _UNDEF
from .pca import _SIG_SUITES, canonical_bytes_strict, hash_canonical, verify_leaf_suite

__all__ = ["ALLOWLIST_KINDS", "verify_allowlist_manifest", "verify_allowlist_durable", "create_allowlist_manifest", "sign_allowlist_manifest",
           "revoke_allowlist_entry", "driver_version_slot_hex", "project_allowlist", "azure_maa_policy_fields", "intel_dcap_policy_fields",
           "sev_snp_policy_fields", "gcp_cs_policy_fields", "nvidia_cc_policy_fields"]

ALLOWLIST_KINDS = ["tdx-mrtd", "tdx-rtmr", "sev-snp-measurement", "gcp-image-digest", "nvidia-measurement", "nvidia-driver-version", "maa-signing-spki",
                   "maa-chain-root-spki", "maa-chain-intermediate-spki", "attest-corroboration"]
_DOMAIN = "pca-attest-allowlist/v1\n"
_HEX96, _HEX64 = re.compile(r"[0-9a-f]{96}"), re.compile(r"[0-9a-f]{64}")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_DRIVER_VERSION = re.compile(r"[0-9]{1,6}(\.[0-9]{1,6}){1,3}")
_CORROBORATION_LABEL = re.compile(r"vantages=[1-9][0-9]{0,2};method=[\x20-\x7e]{1,150}")
_ISSUER_URL = re.compile(r"https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?")
_B64U43 = re.compile(r"[A-Za-z0-9_-]{43}")
_BODY_KEYS = ("version", "issuedAt", "notBefore", "expiresAt", "entries")
_ENTRY_KEYS = ("kind", "value", "label", "notAfter", "revoked")
_MANIFEST_KEYS = ("body", "issuer", "alg", "sig", "pq_sig")
_MAX_ENTRIES = 10_000
_MAX_SAFE = 9007199254740991
_PQ_PK_MEMBER = {"ML-DSA-65": "mlDsaPub", "SLH-DSA-SHA2-128f": "slhDsaPub", "ML-DSA-87": "mlDsa87Pub", "SLH-DSA-SHA2-256s": "slhDsa256sPub",
                 "FN-DSA-512": "fnDsa512Pub", "FN-DSA-1024": "fnDsa1024Pub", "LESS-cat1": "lessCat1Pub"}
_PQ_SECRET_MEMBER = {"ML-DSA-65": "mlDsa", "SLH-DSA-SHA2-128f": "slhDsa", "ML-DSA-87": "mlDsa87", "SLH-DSA-SHA2-256s": "slhDsa256s"}


def _is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _safe_int(x: Any) -> bool:
    return _is_num(x) and fin(x) and x == math.floor(x) and abs(x) <= _MAX_SAFE


def _is_epoch(x: Any) -> bool:
    return _safe_int(x) and x >= 0 and not (isinstance(x, float) and math.copysign(1, x) < 0)


def _only_keys(r: dict, allowed: tuple) -> bool:
    return all(k in allowed for k in r)


def _has_control_char(s: str) -> bool:
    return any(c <= 0x1F or c == 0x7F for c in (int.from_bytes(b, "big") for b in _units(s)))


def _units(s: str) -> List[bytes]:
    raw = s.encode("utf-16-be", "surrogatepass")
    return [raw[i:i + 2] for i in range(0, len(raw), 2)]


def _length(s: str) -> int:
    return len(s.encode("utf-16-be", "surrogatepass")) // 2


def _value_error(kind: str, value: str, label: str) -> Optional[str]:
    if kind in ("tdx-mrtd", "tdx-rtmr", "sev-snp-measurement", "nvidia-measurement"):
        return None if _HEX96.fullmatch(value) else "%s must be 96 lowercase hex chars" % kind
    if kind == "gcp-image-digest":
        return None if _IMAGE_DIGEST.fullmatch(value) else "gcp-image-digest must be sha256:<64 lowercase hex>"
    if kind == "nvidia-driver-version":
        return None if _DRIVER_VERSION.fullmatch(value) and len(value) <= 16 else "nvidia-driver-version must be a dotted version of at most 16 chars"
    if kind == "maa-signing-spki":
        if not _HEX64.fullmatch(value):
            return "maa-signing-spki must be 64 lowercase hex chars"
        return None if _ISSUER_URL.fullmatch(label) else "maa-signing-spki label must be the https issuer URL (no path, no trailing slash)"
    if kind in ("maa-chain-root-spki", "maa-chain-intermediate-spki"):
        return None if _HEX64.fullmatch(value) else "%s must be 64 lowercase hex chars" % kind
    if not _HEX64.fullmatch(value):
        return "attest-corroboration must be a 64 lowercase hex evidence digest"
    return None if _CORROBORATION_LABEL.fullmatch(label) else "attest-corroboration label must be vantages=<n>;method=<text>"


def _parse_body(x: Any) -> Dict[str, Any]:
    if not isinstance(x, dict) or not _only_keys(x, _BODY_KEYS):
        raise TypeError("body must be an object with exactly version/issuedAt/notBefore/expiresAt/entries")
    version, issued, not_before, expires, entries = (x.get(k, _UNDEF) for k in _BODY_KEYS)
    if not _safe_int(version) or version < 1:
        raise TypeError("version must be a positive integer")
    if not _is_epoch(issued) or not _is_epoch(not_before) or not _is_epoch(expires):
        raise TypeError("issuedAt/notBefore/expiresAt must be integer epoch ms")
    if not not_before < expires:
        raise TypeError("notBefore must be before expiresAt")
    if not issued <= expires:
        raise TypeError("issuedAt must not be after expiresAt")
    if not isinstance(entries, list) or len(entries) > _MAX_ENTRIES:
        raise TypeError("entries must be an array (bounded)")
    seen = set()
    out = []
    for i, e in enumerate(entries):
        if not isinstance(e, dict) or not _only_keys(e, _ENTRY_KEYS):
            raise TypeError("entry %d: unexpected shape" % i)
        kind, value, label = e.get("kind", _UNDEF), e.get("value", _UNDEF), e.get("label", _UNDEF)
        if not isinstance(kind, str) or kind not in ALLOWLIST_KINDS:
            raise TypeError("entry %d: unknown kind" % i)
        if not isinstance(value, str) or not isinstance(label, str):
            raise TypeError("entry %d: value and label must be strings" % i)
        if _length(label) < 1 or _length(label) > 200 or _has_control_char(label):
            raise TypeError("entry %d: label must be 1..200 printable chars" % i)
        ve = _value_error(kind, value, label)
        if ve:
            raise TypeError("entry %d: %s" % (i, ve))
        if "notAfter" in e and not _is_epoch(e["notAfter"]):
            raise TypeError("entry %d: notAfter must be integer epoch ms" % i)
        if "revoked" in e and e["revoked"] is not True:
            raise TypeError("entry %d: revoked, when present, must be true" % i)
        dup = "%s\0%s%s" % (kind, ("%s\0" % label) if kind == "maa-signing-spki" else "", value)
        if dup in seen:
            raise TypeError("entry %d: duplicate %s value" % (i, kind))
        seen.add(dup)
        item: Dict[str, Any] = {"kind": kind, "value": value, "label": label}
        if "notAfter" in e:
            item["notAfter"] = e["notAfter"]
        if e.get("revoked") is True:
            item["revoked"] = True
        out.append(item)
    return {"version": version, "issuedAt": issued, "notBefore": not_before, "expiresAt": expires, "entries": out}


def _signed_bytes(body: dict) -> bytes:
    return _DOMAIN.encode("utf-8") + canonical_bytes_strict(body)


def _fail(code: str, reason: str) -> Dict[str, Any]:
    return {"ok": False, "code": code, "reason": reason}


def _signature_ok(alg: str, keys: Any, msg: bytes, sig: str, pq_sig: Any) -> bool:
    suite = _SIG_SUITES[alg]
    _, needs_pk, _hybrid, key_type, _n = suite
    keys = keys if isinstance(keys, dict) else {}
    p: Dict[str, Any] = {"sig": sig} if alg == "ed25519" else {"alg": alg, "sig": sig}
    if needs_pk:
        pk = keys.get(_PQ_PK_MEMBER.get(key_type, ""))
        if pk is None:
            return False
        p["pq_pk"] = pk
    if pq_sig is not _UNDEF:
        p["pq_sig"] = pq_sig
    return verify_leaf_suite(p, keys.get("edPub"), msg)


def verify_allowlist_manifest(manifest: Any, opts: Any) -> Dict[str, Any]:
    """Verify a signed manifest: ``{"ok": True, body, issuer, alg, version, digest}`` or ``{"ok": False, code, reason}``. Options: issuerKeys
    ({issuer: {alg, keys, notAfter?}}), nowMs, minVersion?, lastSeenVersion?, lastSeenDigest?, clockSkewMs?, maxLifetimeMs?. Codes: malformed,
    unknown-issuer, issuer-expired, alg-mismatch, bad-signature, not-yet-valid, expired, rollback, below-min-version, conflict, lifetime-too-long."""
    try:
        if not isinstance(manifest, dict) or not _only_keys(manifest, _MANIFEST_KEYS):
            return _fail("malformed", "manifest has an unexpected shape")
        o = opts if isinstance(opts, dict) else {}
        if not _safe_int(o.get("nowMs")):
            return _fail("malformed", "nowMs must be an integer")
        issuer, alg, sig = manifest.get("issuer", _UNDEF), manifest.get("alg", _UNDEF), manifest.get("sig", _UNDEF)
        pq_sig = manifest.get("pq_sig", _UNDEF)
        if not isinstance(issuer, str) or len(issuer) == 0 or _length(issuer) > 200:
            return _fail("malformed", "issuer must be a string")
        if not isinstance(alg, str) or alg not in _SIG_SUITES:
            return _fail("malformed", "unknown signature alg")
        if not isinstance(sig, str):
            return _fail("malformed", "sig must be a string")
        if pq_sig is not _UNDEF and not isinstance(pq_sig, str):
            return _fail("malformed", "pq_sig must be a string")
        if (not _SIG_SUITES[alg][2]) != (pq_sig is _UNDEF):
            return _fail("malformed", "pq_sig presence does not match the suite")
        try:
            body = _parse_body(manifest.get("body", _UNDEF))
        except Exception as e:  # noqa: BLE001
            return _fail("malformed", str(e) or "invalid body")
        issuer_keys = o["issuerKeys"]
        if issuer not in issuer_keys:
            return _fail("unknown-issuer", "issuer '%s' is not registered" % issuer)
        reg = issuer_keys[issuer]
        if reg.get("alg") != alg:
            return _fail("alg-mismatch", "issuer is registered for '%s', manifest claims '%s'" % (reg.get("alg"), alg))
        if reg.get("notAfter") is not None and not (fin(o["nowMs"]) and o["nowMs"] <= reg["notAfter"]):
            return _fail("issuer-expired", "issuer key is past its notAfter")
        if not _signature_ok(alg, reg.get("keys"), _signed_bytes(body), sig, pq_sig):
            return _fail("bad-signature", "signature does not verify under the registered issuer key")
        skew_o, life_o, minv, last = (o.get(k) for k in ("clockSkewMs", "maxLifetimeMs", "minVersion", "lastSeenVersion"))
        if "clockSkewMs" in o and not (_is_num(skew_o) and fin(skew_o)):
            return _fail("malformed", "clockSkewMs must be a finite number")
        if "maxLifetimeMs" in o and not (_is_num(life_o) and fin(life_o)):
            return _fail("malformed", "maxLifetimeMs must be a finite number")
        if "minVersion" in o and not _safe_int(minv):
            return _fail("malformed", "minVersion must be an integer")
        if "lastSeenVersion" in o and not _safe_int(last):
            return _fail("malformed", "lastSeenVersion must be an integer")
        skew = max(0, skew_o) if skew_o is not None else 0
        now = o["nowMs"]
        if not (fin(now) and now + skew >= body["notBefore"]):
            return _fail("not-yet-valid", "manifest is not yet valid")
        if not (now - skew <= body["expiresAt"]):
            return _fail("expired", "manifest has expired")
        if "maxLifetimeMs" in o and not (body["expiresAt"] - body["notBefore"] <= life_o):
            return _fail("lifetime-too-long", "manifest lifetime exceeds maxLifetimeMs")
        if "minVersion" in o and body["version"] < minv:
            return _fail("below-min-version", "version %s < minVersion %s" % (body["version"], minv))
        digest = hash_canonical(body)
        if "lastSeenVersion" in o:
            if body["version"] < last:
                return _fail("rollback", "version %s is older than last seen %s" % (body["version"], last))
            if body["version"] == last and "lastSeenDigest" in o and o["lastSeenDigest"] != digest:
                return _fail("conflict", "same version as last seen but a different body")
        return {"ok": True, "body": body, "issuer": issuer, "alg": alg, "version": body["version"], "digest": digest}
    except Exception as e:  # noqa: BLE001
        return _fail("malformed", str(e) or "verification error")


def _parse_hw(x: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(x, dict) or not _safe_int(x.get("version")) or (isinstance(x["version"], float) and math.copysign(1, x["version"]) < 0 and x["version"] == 0):
        return None
    if not isinstance(x.get("digest"), str) or not _B64U43.fullmatch(x["digest"]):
        return None
    return {"version": x["version"], "digest": x["digest"]}


def verify_allowlist_durable(manifest: Any, opts: dict, kv: Any) -> Dict[str, Any]:
    """Verify a manifest against the persisted high-water mark of its issuer (key ``allowlist/<issuer>`` = {version, digest}) and advance it. The
    mark only ever moves up: an older version is a rollback, the same version with another body a conflict, a corrupt persisted mark is refused."""
    try:
        issuer = manifest.get("issuer") if isinstance(manifest, dict) else None
        if not isinstance(issuer, str) or _length(issuer) > 200:
            return _fail("malformed", "issuer must be a string")
        key = "allowlist/%s" % issuer
        raw = kv.get(key)
        stored_null = raw is None and callable(getattr(kv, "keys", None)) and key in set(kv.keys())  # a stored null is a corrupt mark, an absent key is none
        prior = None if raw is None else _parse_hw(raw)
        if (raw is not None or stored_null) and prior is None:
            return _fail("malformed", "persisted allowlist high-water mark is corrupt")
        o = dict(opts)
        if prior is not None:
            o.update(lastSeenVersion=prior["version"], lastSeenDigest=prior["digest"])
        v = verify_allowlist_manifest(manifest, o)
        if not v["ok"]:
            return v
        seen: Dict[str, Any] = {}

        def update(cur: Any) -> Any:
            seen["cur"] = cur
            c = None if cur is None else _parse_hw(cur)
            if cur is not None and c is None:
                return None  # corrupt: left alone
            return None if c is not None and c["version"] >= v["version"] else {"version": v["version"], "digest": v["digest"]}

        stored = kv.update(key, update)
        if "cur" not in seen:
            now_kv = _parse_hw(stored)
            if now_kv is None:
                return _fail("rollback", "a newer manifest was accepted concurrently")
        else:
            cur = seen["cur"]
            now_kv = None if cur is None else _parse_hw(cur)
            if cur is not None and now_kv is None:
                return _fail("rollback", "a newer manifest was accepted concurrently")  # a corrupt mark is never overwritten
        if now_kv is not None and now_kv["version"] >= v["version"]:
            after = now_kv
        else:
            after = {"version": v["version"], "digest": v["digest"]}
        if after["version"] > v["version"]:
            return _fail("rollback", "a newer manifest was accepted concurrently")
        if after["version"] == v["version"] and after["digest"] != v["digest"]:
            return _fail("conflict", "same version as the stored high-water mark but a different body")
        return v
    except Exception as e:  # noqa: BLE001
        return _fail("malformed", str(e) or "durable verification error")


def create_allowlist_manifest(body: Any) -> Dict[str, Any]:
    """Validate and normalise a manifest body (raises on any violation)."""
    return _parse_body(body)


def sign_allowlist_manifest(body: Any, issuer: str, alg: str, secrets: dict) -> Dict[str, Any]:
    """Sign a validated body: ``{"body", "issuer", "alg", "sig", "pq_sig"?}``. ``secrets``: edSecret (32 bytes) and the PQ key of the suite's family
    (mlDsa, mlDsa87, slhDsa, slhDsa256s: PqKeyPair)."""
    clean = _parse_body(body)
    suite = _SIG_SUITES.get(alg)
    if suite is None:
        raise ValueError("unknown signature alg %r" % (alg,))
    ed = KeyPair(bytes(secrets["edSecret"]), allow_insecure_signer=True) if isinstance(secrets.get("edSecret"), (bytes, bytearray)) else None
    pq = secrets.get(_PQ_SECRET_MEMBER.get(suite[3], ""))
    out = {"body": clean, "issuer": issuer, "alg": alg}
    out.update(sign_with_suite(alg, ed, pq, _signed_bytes(clean)))
    return out


def revoke_allowlist_entry(prev: dict, rev: dict, times: dict) -> Dict[str, Any]:
    """The next manifest body (version + 1, new times) with the entry marked revoked, or a new revoked entry when none matches."""
    entries = [dict(e) for e in prev["entries"]]
    hit = next((e for e in entries if e["kind"] == rev["kind"] and e["value"] == rev["value"]
                and (rev["kind"] != "maa-signing-spki" or e["label"] == rev.get("label"))), None)
    if hit is not None:
        hit["revoked"] = True
    else:
        entries.append({"kind": rev["kind"], "value": rev["value"], "label": rev.get("label") if rev.get("label") is not None else "revoked", "revoked": True})
    return _parse_body(dict({"version": prev["version"] + 1}, **times, entries=entries))


def driver_version_slot_hex(version: Any) -> str:
    """The 16-byte slot of an NVIDIA driver version string as 32 hex chars (ASCII, zero padded)."""
    if not isinstance(version, str) or not _DRIVER_VERSION.fullmatch(version) or len(version) > 16:
        raise TypeError("invalid driver version")
    return version.encode("ascii").hex().ljust(32, "0")


def project_allowlist(verified: dict, now_ms: Any) -> Dict[str, Any]:
    """The per-vendor lists of the entries that are live at ``now_ms`` (not revoked, not denied by a revocation of the same kind and value, not
    past their own ``notAfter``), plus the revoked and expired entries."""
    body = verified["body"]
    out: Dict[str, Any] = {"tdxMrtds": [], "tdxRtmrs": [], "sevSnpMeasurements": [], "imageDigests": [], "nvidiaMeasurements": [],
                           "nvidiaDriverVersions": [], "nvidiaCcDriverVersions": [], "maaSigningSpkis": {}, "maaChainRootSpkis": [],
                           "maaChainIntermediateSpkis": [], "corroboration": [], "revoked": [], "expired": [], "version": body["version"],
                           "manifestExpiresAt": body["expiresAt"]}
    denied = set()
    for e in body["entries"]:
        if e.get("revoked") is True:
            denied.add("%s\0%s" % (e["kind"], e["value"]))
            out["revoked"].append({"kind": e["kind"], "value": e["value"], "label": e["label"]})
    for e in body["entries"]:
        if e.get("revoked") is True or "%s\0%s" % (e["kind"], e["value"]) in denied:
            continue
        if e.get("notAfter") is not None and not (fin(now_ms) and now_ms <= e["notAfter"]):
            out["expired"].append({"kind": e["kind"], "value": e["value"], "label": e["label"]})
            continue
        k, v = e["kind"], e["value"]
        if k == "tdx-mrtd":
            out["tdxMrtds"].append(v)
        elif k == "tdx-rtmr":
            out["tdxRtmrs"].append(v)
        elif k == "sev-snp-measurement":
            out["sevSnpMeasurements"].append(v)
        elif k == "gcp-image-digest":
            out["imageDigests"].append(v)
        elif k == "nvidia-measurement":
            out["nvidiaMeasurements"].append(v)
        elif k == "nvidia-driver-version":
            out["nvidiaDriverVersions"].append(v)
            out["nvidiaCcDriverVersions"].append(driver_version_slot_hex(v))
        elif k == "maa-signing-spki":
            out["maaSigningSpkis"].setdefault(e["label"], []).append(v)
        elif k == "maa-chain-root-spki":
            out["maaChainRootSpkis"].append(v)
        elif k == "maa-chain-intermediate-spki":
            out["maaChainIntermediateSpkis"].append(v)
        elif k == "attest-corroboration":
            out["corroboration"].append({"value": v, "label": e["label"]})
    return out


def azure_maa_policy_fields(p: dict) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for dst, src in (("tdxMrtds", "tdxMrtds"), ("sevSnpMeasurements", "sevSnpMeasurements"), ("tdxRtmrs", "tdxRtmrs")):
        if p[src]:
            out[dst] = list(p[src])
    return out


def intel_dcap_policy_fields(p: dict) -> Dict[str, Any]:
    out: Dict[str, Any] = {"mrtds": list(p["tdxMrtds"])}
    if p["tdxRtmrs"]:
        out["rtmrs"] = list(p["tdxRtmrs"])
    return out


def sev_snp_policy_fields(p: dict) -> Dict[str, Any]:
    return {"measurements": list(p["sevSnpMeasurements"])}


def gcp_cs_policy_fields(p: dict) -> Dict[str, Any]:
    return {"imageDigests": list(p["imageDigests"])}


def nvidia_cc_policy_fields(p: dict) -> Dict[str, Any]:
    out: Dict[str, Any] = {"measurements": list(p["nvidiaMeasurements"])}
    if p["nvidiaCcDriverVersions"]:
        out["driverVersions"] = list(p["nvidiaCcDriverVersions"])
    return out
