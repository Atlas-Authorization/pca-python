"""Trusted-setup bookkeeping for the Groth16 circuits (pure: no file or process access).

A verifying key is only as trustworthy as the ceremony that made it. ``ceremony_of`` answers "was this key produced by a multi-party
ceremony we can check?": ``multi-party`` ONLY when the caller supplies a transcript, pins its SHA-256 (published out of band by the
coordinator), the transcript is well-formed (two or more distinct contributions chained from the initial key, a public random beacon applied
last) and names exactly this verifying key. Everything else is ``single-party``. The cryptographic check of the contributions themselves is
the ceremony tool's job; nothing here claims more than the pinned transcript says.

Transcripts and provenance records are plain dicts with the reference member names (``r1csSha256``, ``contributions``, ``vkId``, ...)."""
from __future__ import annotations

import hashlib
import re
from typing import Any, Optional

from .pca import canonical_bytes_strict

_H64 = re.compile(r"[0-9a-f]{64}")
_VK_ID = re.compile(r"vk_[0-9a-f]{64}")
_SAFE = 9007199254740991


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _safe_int(v: Any) -> bool:
    return _num(v) and v == v and abs(v) <= _SAFE and float(v).is_integer()


def _is_h64(v: Any) -> bool:
    return isinstance(v, str) and _H64.fullmatch(v) is not None


def _same(a: Any, b: Any) -> bool:
    """Strict equality of two JSON scalars; containers and mixed types never match."""
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return _num(a) and _num(b) and a == b


def _falsy(v: Any) -> bool:
    return v is None or v is False or (isinstance(v, (int, float, str)) and not v)


def _count(n: Any) -> str:
    return str(int(n)) if float(n).is_integer() else repr(float(n))


def vk_id(vkey: Any) -> str:
    """Id of a verifying key: ``vk_`` + SHA-256 of its canonical JSON. A re-setup always yields a new id."""
    return "vk_" + hashlib.sha256(canonical_bytes_strict(vkey)).hexdigest()


def circuit_provenance(circuit: Any, source_sha256: Any, r1cs_sha256: Any, vkey: Any) -> dict:
    """What a verifying key was built from: circuit id, SHA-256 of its source set, SHA-256 of the compiled constraint system, key id."""
    if not _is_h64(source_sha256) or not _is_h64(r1cs_sha256) or circuit == "":
        raise ValueError("circuitProvenance: bad circuit id or hash")
    return {"circuit": circuit, "sourceSha256": source_sha256, "r1csSha256": r1cs_sha256, "vkId": vk_id(vkey)}


def check_circuit_provenance(prov: Any, circuit: Any, source_sha256: Any, vkey: Any, r1cs_sha256: Optional[str] = None) -> Optional[str]:
    """First reason `prov` does not describe `vkey` built from the expected sources and constraint system, or None."""
    if isinstance(prov, list):
        prov = {}  # an array is an object with none of the members
    if not isinstance(prov, dict):
        return "not a provenance record"
    if not _same(prov.get("circuit"), circuit):
        return "record is for another circuit"
    if not _same(prov.get("sourceSha256"), source_sha256):
        return "circuit sources differ from the pinned version"
    if not _is_h64(prov.get("r1csSha256")) or (r1cs_sha256 is not None and prov["r1csSha256"] != r1cs_sha256):
        return "constraint system differs"
    if not _same(prov.get("vkId"), vk_id(vkey)):
        return "verifying key is not the recorded one"
    return None


def transcript_sha256(transcript: Any) -> str:
    return hashlib.sha256(canonical_bytes_strict(transcript)).hexdigest()


def check_transcript(t: Any, min_contributions: Optional[float] = None, r1cs_sha256: Optional[str] = None,
                     circuit: Optional[str] = None) -> Optional[str]:
    """The first problem with a transcript, or None when it is well-formed. Fails closed on any odd shape."""
    if not isinstance(t, dict) or not (_num(t.get("version")) and t["version"] == 1):
        return "not a version-1 transcript"
    if not isinstance(t.get("circuit"), str) or t["circuit"] == "":
        return "no circuit id"
    if circuit is not None and t["circuit"] != circuit:
        return "transcript is for another circuit"
    if not isinstance(t.get("curve"), str) or t["curve"] not in ("bn128", "bls12-381"):
        return "unknown curve"
    for k in ("r1csSha256", "ptauSha256", "initZkeySha256"):
        if not _is_h64(t.get(k)):
            return "%s is not a SHA-256" % k
    if r1cs_sha256 is not None and t["r1csSha256"] != r1cs_sha256:
        return "transcript is for a different constraint system"
    own = t.get("minContributions")
    need = max(2, 2 if min_contributions is None else min_contributions, own if _safe_int(own) else 2)
    cs = t.get("contributions")
    if not isinstance(cs, list) or len(cs) < need:
        return "fewer than %s contributions" % _count(need)
    names, keys = set(), set()
    prev = t["initZkeySha256"]
    for i, c in enumerate(cs):
        index = c.get("index") if isinstance(c, dict) else None
        # the index is the number i itself: not a string, not a boolean, not negative zero
        if not (_num(index) and index == i and str(index)[0] != "-") or not isinstance(c.get("name"), str) or c["name"] == "":
            return "contribution %d is malformed" % i
        if not _is_h64(c.get("zkeySha256")) or not _same(c.get("prevZkeySha256"), prev):
            return "contribution %d does not chain from the previous key" % i
        if c["name"] in names or c["zkeySha256"] in keys:
            return "contribution %d repeats a name or key" % i
        names.add(c["name"])
        keys.add(c["zkeySha256"])
        prev = c["zkeySha256"]
    b = t.get("beacon")
    if not isinstance(b, dict) or not _is_h64(b.get("hashHex")) or not _safe_int(b.get("iterationsExp")) or not 10 <= b["iterationsExp"] <= 63:
        return "no valid random beacon"
    if not _same(b.get("prevZkeySha256"), prev) or not _is_h64(b.get("zkeySha256")):
        return "beacon is not applied after the last contribution"
    if not _same(t.get("finalZkeySha256"), b["zkeySha256"]):
        return "final key is not the beacon output"
    if not isinstance(t.get("vkId"), str) or _VK_ID.fullmatch(t["vkId"]) is None:
        return "no verifying-key id"
    return None


def ceremony_of(vkey: Any, evidence: Any = None) -> str:
    """``multi-party`` only when ``evidence["sha256"]`` equals the transcript's hash, the transcript is well-formed and names `vkey`.
    `evidence` is ``{"transcript", "sha256", "r1csSha256"?, "circuit"?}``. Anything else, including an error, is ``single-party``."""
    try:
        if _falsy(vkey) or _falsy(evidence):
            return "single-party"
        t = evidence.get("transcript")
        if check_transcript(t, r1cs_sha256=evidence.get("r1csSha256"), circuit=evidence.get("circuit")) is not None:
            return "single-party"
        if not _same(transcript_sha256(t), evidence.get("sha256")) or t["vkId"] != vk_id(vkey):
            return "single-party"
        return "multi-party"
    except Exception:  # noqa: BLE001 - fail closed to the weaker label
        return "single-party"


__all__ = ["vk_id", "circuit_provenance", "check_circuit_provenance", "transcript_sha256", "check_transcript", "ceremony_of"]
