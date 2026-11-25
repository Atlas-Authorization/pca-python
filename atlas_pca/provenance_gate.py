"""Build provenance as a K1 discharge (track K9): a port of packages/pca/src/provenance-gate.ts (contracts C-520..C-526).

The policy half of a Sigstore / SLSA provenance check, pure so every verifier runs the same gates: RFC 9162 inclusion,
``provenance_gate`` (facts against the verifier's pinned signer-builder pairs) and ``provenance_caveat`` (the
``needs_discharge`` caveat with ``issuer_class: "artifact"``). Total: malformed input is a refusal, never an exception.
"""
import hashlib
import re
from typing import Any, Dict, List, Optional

from .intent_wb import _closed_members, _is_bounded_string, _is_safe_int, _utf8_len

__all__ = [
    "SLSA_PROVENANCE_V1", "INTOTO_STATEMENT_V1", "rfc9162_leaf_hash", "verify_rfc9162_inclusion", "provenance_facts_error",
    "provenance_policy_error", "provenance_gate", "provenance_caveat",
]

SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
INTOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"


def rfc9162_leaf_hash(data: bytes) -> bytes:
    """RFC 9162 section 2.1.1: SHA-256(0x00 || data)."""
    return hashlib.sha256(b"\x00" + bytes(data)).digest()


def _node(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + l + r).digest()


def _b32(v: Any) -> bool:
    return isinstance(v, (bytes, bytearray)) and len(v) == 32


def verify_rfc9162_inclusion(leaf_hash: Any, index: Any, size: Any, proof: Any, root: Any) -> bool:
    """RFC 9162 section 2.1.3.2. ``proof`` runs from the leaf level up. False on any malformed input."""
    try:
        if not (_is_safe_int(index) and _is_safe_int(size) and index >= 0 and size >= 1 and index < size):
            return False
        if not (_b32(leaf_hash) and _b32(root)):
            return False
        if not isinstance(proof, (list, tuple)) or len(proof) > 64 or not all(_b32(p) for p in proof):
            return False
        fn, sn, r = int(index), int(size) - 1, bytes(leaf_hash)
        for p in proof:
            p = bytes(p)
            if sn == 0:
                return False
            if fn & 1 == 1 or fn == sn:
                r = _node(p, r)
                if fn & 1 == 0:
                    while fn & 1 == 0 and fn != 0:
                        fn >>= 1
                        sn >>= 1
            else:
                r = _node(r, p)
            fn >>= 1
            sn >>= 1
        return sn == 0 and r == bytes(root)
    except Exception:  # total by contract
        return False


_HEX = {"sha256": re.compile(r"[0-9a-f]{64}"), "sha512": re.compile(r"[0-9a-f]{128}")}


def _str(v: Any, mx: int = 2048) -> bool:
    return _is_bounded_string(v, mx)


def _level(v: Any) -> bool:
    return _is_safe_int(v) and v in (1, 2, 3)


def _utf16_len(s: str) -> int:
    # JS String.length counts UTF-16 code units
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _subject_error(s: Any) -> bool:
    if not isinstance(s, dict) or _closed_members(s, ("alg", "digest")) is not None:
        return True
    alg, d = s["alg"], s["digest"]
    return not (isinstance(alg, str) and alg in _HEX and isinstance(d, str) and _HEX[alg].fullmatch(d) is not None)


def provenance_facts_error(f: Any) -> Optional[str]:
    """None when well-formed (closed members, bounded strings)."""
    if not isinstance(f, dict):
        return "facts must be an object"
    e = _closed_members(f, ("v", "predicate_type", "build_type", "builder_id", "subjects", "identity", "oidc_issuer", "integrated_time", "rekor_log_index"),
                        ("source_repo", "source_ref", "source_digest", "provenance_source"), "facts")
    if e:
        return e
    if not (_is_safe_int(f["v"]) and f["v"] == 1):
        return "facts.v must be 1"
    for k in ("predicate_type", "build_type", "builder_id", "identity", "oidc_issuer"):
        if not _str(f[k]):
            return "facts.%s must be a non-empty string" % k
    for k in ("source_repo", "source_ref", "source_digest"):
        if k in f and not _str(f[k]):
            return "facts.%s must be a non-empty string" % k
    s = f["subjects"]
    if not isinstance(s, list) or not 1 <= len(s) <= 64 or any(_subject_error(x) for x in s):
        return "facts.subjects must be 1..64 {alg, digest}"
    if not (_is_safe_int(f["integrated_time"]) and f["integrated_time"] >= 0):
        return "facts.integrated_time must be a non-negative integer"
    if not (_is_safe_int(f["rekor_log_index"]) and f["rekor_log_index"] >= 0):
        return "facts.rekor_log_index must be a non-negative integer"
    if "provenance_source" in f:
        p = f["provenance_source"]
        if not isinstance(p, dict) or _closed_members(p, ("uri",), ("git_commit",)) is not None or not _str(p["uri"]) or ("git_commit" in p and not _str(p["git_commit"])):
            return "facts.provenance_source is malformed"
    return None


def provenance_policy_error(p: Any) -> Optional[str]:
    """None when well-formed."""
    if not isinstance(p, dict):
        return "policy must be an object"
    e = _closed_members(p, ("roots", "min_level"), ("source_repo", "source_ref", "source_ref_prefix", "build_types", "max_age_s", "require_runtime"), "policy")
    if e:
        return e
    roots = p["roots"]
    if not isinstance(roots, list) or not 1 <= len(roots) <= 32:
        return "policy.roots must hold 1..32 pairs"
    for r in roots:
        if not isinstance(r, dict) or _closed_members(r, ("oidc_issuer", "builder_id", "level"), ("identity", "identity_prefix")) is not None:
            return "policy root is malformed"
        if not _str(r["oidc_issuer"]) or not _str(r["builder_id"]):
            return "policy root needs oidc_issuer and builder_id"
        if ("identity" in r) == ("identity_prefix" in r):
            return "policy root needs exactly one of identity and identity_prefix"
        if "identity" in r and not _str(r["identity"]):
            return "policy root identity is malformed"
        # a prefix must at least name a scheme and a host; an empty-ish prefix would pin nothing
        if "identity_prefix" in r and not (_str(r["identity_prefix"]) and _utf16_len(r["identity_prefix"]) >= 10):
            return "policy root identity_prefix must be at least 10 characters"
        if not _level(r["level"]):
            return "policy root level must be 1, 2 or 3"
    if not _level(p["min_level"]):
        return "policy.min_level must be 1, 2 or 3"
    if "source_repo" in p and not _str(p["source_repo"]):
        return "policy.source_repo is malformed"
    if "source_ref" in p and "source_ref_prefix" in p:
        return "policy takes source_ref or source_ref_prefix, not both"
    if "source_ref" in p and not _str(p["source_ref"]):
        return "policy.source_ref is malformed"
    if "source_ref_prefix" in p and not _str(p["source_ref_prefix"]):
        return "policy.source_ref_prefix is malformed"
    if "build_types" in p:
        b = p["build_types"]
        if not (isinstance(b, list) and 1 <= len(b) <= 16 and all(_str(x) for x in b)):
            return "policy.build_types must hold 1..16 strings"
    if "max_age_s" in p and not (_is_safe_int(p["max_age_s"]) and p["max_age_s"] >= 1):
        return "policy.max_age_s must be a positive integer"
    if "require_runtime" in p and not isinstance(p["require_runtime"], bool):
        return "policy.require_runtime must be a boolean"
    return None


def provenance_gate(inp: Any) -> Dict[str, Any]:
    """The provenance gates in the reference order. Returns {ok: True, level, claims} or {ok: False, code}. Total."""
    def no(code: str) -> Dict[str, Any]:
        return {"ok": False, "code": code}
    try:
        if not isinstance(inp, dict):
            return no("malformed_facts")
        f, p, now = inp.get("facts"), inp.get("policy"), inp.get("now")
        if provenance_policy_error(p) is not None:
            return no("malformed_policy")
        if provenance_facts_error(f) is not None:
            return no("malformed_facts")
        if not (_is_safe_int(now) and now >= 0):
            return no("malformed_facts")
        has_rt = "runtime" in inp
        rt = inp.get("runtime")
        if has_rt and _subject_error(rt):
            return no("malformed_runtime")
        if f["predicate_type"] != SLSA_PROVENANCE_V1:
            return no("predicate_type")
        if f["integrated_time"] > now:
            return no("future")
        if "max_age_s" in p and now - f["integrated_time"] > p["max_age_s"]:
            return no("stale")
        level = 0
        for r in p["roots"]:
            if r["oidc_issuer"] != f["oidc_issuer"] or r["builder_id"] != f["builder_id"]:
                continue
            if r["identity"] != f["identity"] if "identity" in r else not f["identity"].startswith(r["identity_prefix"]):
                continue
            level = max(level, int(r["level"]))
        if level == 0:
            return no("no_root")
        if level < p["min_level"]:
            return no("level")
        ps = f.get("provenance_source")
        if ps is not None:
            if "git_commit" in ps and "source_digest" in f and ps["git_commit"] != f["source_digest"]:
                return no("source_mismatch")
            if "source_repo" in f and not (ps["uri"] == "git+" + f["source_repo"] or ps["uri"].startswith("git+" + f["source_repo"] + "@")):
                return no("source_mismatch")
        if "source_repo" in p and f.get("source_repo") != p["source_repo"]:
            return no("source_repo")
        if "source_ref" in p and f.get("source_ref") != p["source_ref"]:
            return no("source_ref")
        if "source_ref_prefix" in p and not ("source_ref" in f and f["source_ref"].startswith(p["source_ref_prefix"])):
            return no("source_ref")
        if "build_types" in p and f["build_type"] not in p["build_types"]:
            return no("build_type")
        bound = False
        if has_rt:
            hit = next((s for s in f["subjects"] if s["alg"] == rt["alg"] and s["digest"] == rt["digest"]), None)
            if hit is None:
                return no("runtime_mismatch")
            subject, bound = hit, True
        else:
            if p.get("require_runtime") is True:
                return no("runtime_required")
            if len(f["subjects"]) != 1:
                return no("subject_ambiguous")
            subject = f["subjects"][0]
        claims: Dict[str, Any] = {
            "subject_alg": subject["alg"], "subject_digest": subject["digest"], "slsa_level": level, "builder_id": f["builder_id"],
            "build_type": f["build_type"], "oidc_issuer": f["oidc_issuer"], "identity": f["identity"],
        }
        for k in ("source_repo", "source_ref", "source_digest"):
            if k in f:
                claims[k] = f[k]
        claims["rekor_log_index"] = int(f["rekor_log_index"])
        claims["runtime_bound"] = bound
        if any(isinstance(v, str) and _utf8_len(v) > 256 for v in claims.values()):
            return no("claim_too_long")
        return {"ok": True, "level": level, "claims": claims}
    except Exception:  # total by contract
        return no("malformed_facts")


def provenance_caveat(issuer: str, min_level: int, id: Optional[str] = None, source_repo: Optional[str] = None,
                      builder_ids: Optional[List[str]] = None, oidc_issuer: Optional[str] = None, require_runtime: bool = True,
                      bind: Optional[str] = None, ttl_ms: Optional[int] = None) -> Dict[str, Any]:
    """A ``needs_discharge`` caveat that asks the pinned ``artifact`` verifier for provenance claims."""
    req: List[Dict[str, Any]] = [{"claim": "slsa_level", "op": "gte", "value": min_level}]
    if source_repo is not None:
        req.append({"claim": "source_repo", "op": "eq", "value": source_repo})
    if builder_ids is not None:
        req.append({"claim": "builder_id", "op": "in", "value": builder_ids})
    if oidc_issuer is not None:
        req.append({"claim": "oidc_issuer", "op": "eq", "value": oidc_issuer})
    if require_runtime is not False:
        req.append({"claim": "runtime_bound", "op": "eq", "value": True})
    return {"type": "needs_discharge", "id": "provenance" if id is None else id, "issuer": issuer, "issuer_class": "artifact",
            "bind": "action" if bind is None else bind, "ttl_ms": 300_000 if ttl_ms is None else ttl_ms, "require": req}
