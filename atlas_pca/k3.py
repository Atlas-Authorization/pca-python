"""Operational-plane artifacts (verification only): signed policy bundles, the decision log (record commits, signed heads,
inclusion, batches), list-authorized receipts and cursors, and grant-management signatures (amend / revoke / need approval).

Every signature is Ed25519 (STRICT verify) over ``domain || strict-canonical-JSON(body)``; the NUL byte at the end of a
domain string is part of it. Every verifier is total: malformed input returns the failure value, never raises. The six
digest functions (``bundle_digest``, ``record_commit``, ``objects_digest``, ``list_bind``, ``authority_digest``) have no
failure value and raise ``TypeError`` on a value outside the strict canonical profile, like ``hash_canonical``.

Verdicts are plain dicts with the wire spelling of the shared vectors (``lastCommit``, ``resourceType`` ...)."""
import json
import math
import re
from typing import Any, Dict, List, Optional

from .pca import (
    _is_safe_int,
    _verify_b64u,
    canonical_bytes_strict,
    decode_b64u_strict,
    hash_canonical,
    verify_inclusion,
)

BUNDLE_DOMAIN = "atlas-pca/policy-bundle/v1\0"
BUNDLE_REF_DOMAIN = "atlas-pca/policy-bundle-ref/v1"
RECORD_DOMAIN = "atlas-pca/decision-record/v1"
LOG_HEAD_DOMAIN = "atlas-pca/decision-log-head/v1\0"
LIST_RECEIPT_DOMAIN = "atlas-pca/list-receipt/v1\0"
LIST_CURSOR_DOMAIN = "atlas-pca/list-cursor/v1\0"
GRANT_AMEND_DOMAIN = "atlas-pca/grant-amend/v1\0"
GRANT_REVOKE_DOMAIN = "atlas-pca/grant-revoke/v1\0"
NEED_APPROVE_DOMAIN = "atlas-pca/need-approve/v1\0"

_MAX_LIST = 4096


# ---- shared helpers (the TypeScript sig.ts) ----------------------------------------------------------------------------

def u16len(s: str) -> int:
    """JS ``String.length``: UTF-16 code units."""
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def u16key(s: str) -> bytes:
    """Sort key giving JS ``Array.prototype.sort`` order (UTF-16 code-unit order)."""
    return s.encode("utf-16-be", "surrogatepass")


def is_obj(x: Any) -> bool:
    return isinstance(x, dict)


def is_uint(n: Any) -> bool:
    """A non-negative safe integer."""
    return _is_safe_int(n) and n >= 0


def is_str(x: Any, mx: int = 512) -> bool:
    return isinstance(x, str) and 0 < u16len(x) <= mx


def is_one(x: Any) -> bool:
    """JS ``x === 1``."""
    return isinstance(x, (int, float)) and not isinstance(x, bool) and x == 1


def _num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and not (isinstance(x, float) and not math.isfinite(x))


def _jsnum(x: Any) -> str:
    """A number spelled like JS ``${n}`` for the integral values these messages carry."""
    return str(int(x)) if isinstance(x, float) and x == math.trunc(x) else str(x)


def verify_body(domain: str, body: Any, signer: Any, sig: Any) -> bool:
    """True iff ``sig`` is a canonical 64-byte b64u Ed25519 signature by ``signer`` over exactly ``domain || canonical(body)``."""
    try:
        return isinstance(sig, str) and decode_b64u_strict(sig, 64) is not None and \
            _verify_b64u(signer, domain.encode("utf-8") + canonical_bytes_strict(body), sig)
    except Exception:
        return False


def _without(o: dict, *drop: str) -> dict:
    return {k: v for k, v in o.items() if k not in drop}


# ---- policy bundles ----------------------------------------------------------------------------------------------------

_VERSION_RE = re.compile(r"[0-9]{1,6}(?:\.[0-9]{1,6}){0,3}")


def bundle_digest(b: dict) -> str:
    return hash_canonical({"d": BUNDLE_REF_DOMAIN, "b": _without(b, "sigs")})


def compare_version(a: str, b: str) -> int:
    """-1 / 0 / 1 over dotted numeric versions. A version that is not dotted digits compares as OLDER than any other
    (fail closed; the TypeScript reference compares such a string as newer)."""
    if not (isinstance(a, str) and isinstance(b, str) and re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", a) and re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", b)):
        return -1
    pa, pb = [int(x) for x in a.split(".")], [int(x) for x in b.split(".")]
    for i in range(max(len(pa), len(pb))):
        d = (pa[i] if i < len(pa) else 0) - (pb[i] if i < len(pb) else 0)
        if d != 0:
            return -1 if d < 0 else 1
    return 0


def bundle_shape_error(b: Any) -> Optional[str]:
    if not is_obj(b) or not is_one(b.get("v")) or b.get("kind") != "pca-policy-bundle":
        return "not a policy bundle"
    if not is_uint(b.get("revision")) or b["revision"] < 1 or not is_uint(b.get("issued_at")):
        return "bad revision or time"
    if ("prev" in b) if b["revision"] == 1 else not is_str(b.get("prev"), 128):
        return "prev must be absent at revision 1 and present after"
    for k, msg in (("grants", "bad grants"), ("template_digests", "bad template_digests")):
        v = b.get(k)
        if not isinstance(v, list) or len(v) > _MAX_LIST or not all(is_str(g, 128) for g in v):
            return msg
    for k in ("schema_digest", "constitution_digest", "flow_rules_digest"):
        if k in b and not is_str(b[k], 128):
            return "bad " + k
    mv = b.get("min_verifier_version")
    if not isinstance(mv, str) or _VERSION_RE.fullmatch(mv) is None:
        return "bad min_verifier_version"
    return None


def verify_bundle(b: Any, signers: Any, threshold: Any, verifier_version: Any, last: Any = None) -> dict:
    """k-of-n pinned signatures, shape, verifier version, rollback and chaining. ``last`` is ``{revision, digest}`` or None."""
    try:
        e = bundle_shape_error(b)
        if e:
            return {"ok": False, "code": "malformed", "reason": e}
        sigs = b.get("sigs")
        if not isinstance(sigs, list) or len(sigs) > 64 or not _is_safe_int(threshold) or threshold < 1 or not isinstance(signers, list):
            return {"ok": False, "code": "malformed", "reason": "bad sigs or threshold"}
        pinned = {s for s in signers if isinstance(s, str)}
        body = _without(b, "sigs")
        good: List[str] = []
        for s in sigs:
            if is_obj(s) and isinstance(s.get("signer"), str) and s["signer"] in pinned and s["signer"] not in good \
                    and verify_body(BUNDLE_DOMAIN, body, s["signer"], s.get("sig")):
                good.append(s["signer"])
        if len(good) < threshold:
            return {"ok": False, "code": "below_threshold", "reason": "%d valid pinned signature(s), need %d" % (len(good), threshold)}
        if compare_version(verifier_version, b["min_verifier_version"]) < 0:
            return {"ok": False, "code": "verifier_too_old", "reason": "needs verifier >= %s" % b["min_verifier_version"]}
        if last is not None:
            rev, lrev = b["revision"], last["revision"]
            if rev < lrev:
                return {"ok": False, "code": "rollback", "reason": "revision %s < accepted %s" % (_jsnum(rev), _jsnum(lrev))}
            if rev == lrev and bundle_digest(b) != last["digest"]:
                return {"ok": False, "code": "broken_chain", "reason": "same revision, different content"}
            if rev == lrev + 1 and b.get("prev") != last["digest"]:
                return {"ok": False, "code": "broken_chain", "reason": "prev does not chain to the accepted revision"}
        return {"ok": True, "revision": b["revision"], "digest": bundle_digest(b), "signers": good}
    except Exception:
        return {"ok": False, "code": "malformed", "reason": "malformed"}


# ---- decision log ------------------------------------------------------------------------------------------------------

def record_commit(r: dict) -> str:
    return hash_canonical({"d": RECORD_DOMAIN, "r": r})


def verify_log_head(h: Any, signer: Any) -> bool:
    try:
        if not is_obj(h) or not is_one(h.get("v")) or h.get("signer") != signer or not is_uint(h.get("size")) \
                or not is_uint(h.get("issued_at")) or not isinstance(h.get("root"), str) or not isinstance(h.get("last_commit"), str):
            return False
        return verify_body(LOG_HEAD_DOMAIN, _without(h, "sig"), signer, h.get("sig"))
    except Exception:
        return False


def verify_record_inclusion(rec: Any, proof: Any, head: Any, signer: Any) -> bool:
    """Offline: ``rec`` is in the log the signed ``head`` commits to, and the head is by the pinned ``signer``."""
    try:
        return verify_log_head(head, signer) and verify_inclusion(head["root"], proof, record_commit(rec))
    except Exception:
        return False


def verify_batch(b: Any, state: Any, signer: Any) -> dict:
    """Receiver side of the stream: contiguous sequence, intact hash chain from ``state`` (``{next, lastCommit}``), head
    signature and size / last-commit agreement. Returns the new cursor in the same shape."""
    try:
        if not (_num(b["from"]) and b["from"] == state["next"]):
            return {"ok": False, "reason": "gap or replay: batch starts at %s, expected %s" % (_jsnum(b["from"]), _jsnum(state["next"]))}
        head = b["head"]
        if not verify_log_head(head, signer):
            return {"ok": False, "reason": "head not signed by the pinned log signer"}
        last, n = state["lastCommit"], state["next"]
        for r in b["records"]:
            if not (_num(r["seq"]) and r["seq"] == n and r["prev"] == last):
                return {"ok": False, "reason": "chain broken at seq %s" % _jsnum(r["seq"])}
            last = record_commit(r)
            n += 1
        if n > head["size"]:
            return {"ok": False, "reason": "batch is longer than the signed head"}
        if n == head["size"] and last != head["last_commit"]:
            return {"ok": False, "reason": "batch end does not match the signed head"}
        return {"ok": True, "next": n, "lastCommit": last}
    except Exception:
        return {"ok": False, "reason": "malformed batch"}


# ---- list-authorized ---------------------------------------------------------------------------------------------------

def objects_digest(objects: List[str]) -> str:
    return hash_canonical({"d": "atlas-pca/list-objects/v1", "o": objects})


def verify_list_receipt(r: Any, signer: Any, objects: Optional[List[str]] = None) -> bool:
    """Signed by ``signer`` over exactly its content; with ``objects``, also that they are the returned ids in order."""
    try:
        if not is_obj(r) or not is_one(r.get("v")) or r.get("signer") != signer or not is_str(r.get("subject")) \
                or not is_str(r.get("resource_type")) or not is_uint(r.get("count")) or not is_uint(r.get("issued_at")):
            return False
        if not verify_body(LIST_RECEIPT_DOMAIN, _without(r, "sig"), signer, r.get("sig")):
            return False
        return objects is None or (isinstance(objects, list) and len(objects) == r["count"] and objects_digest(objects) == r.get("objects_digest"))
    except Exception:
        return False


def list_bind(a: dict) -> str:
    """What a page cursor is bound to: ``{subject, resourceType, filterId, policyDigest, limit, relation?: {relation}}``."""
    rel = a.get("relation")
    rname = rel.get("relation") if isinstance(rel, dict) else None
    return hash_canonical({"s": a["subject"], "t": a["resourceType"], "f": a["filterId"], "p": a["policyDigest"], "r": rname, "l": a["limit"]})


def _no_const(name: str) -> Any:
    raise ValueError(name)


def verify_list_cursor(tok: Any, signer: Any, bind: Optional[dict] = None) -> dict:
    """Shape, signature by ``signer`` and (when ``bind`` is given) that the cursor was issued for exactly those inputs."""
    if not isinstance(tok, str):
        return {"ok": False, "reason": "malformed"}
    parts = tok.split(".")
    p, s, extra = parts[0], (parts[1] if len(parts) > 1 else None), (parts[2] if len(parts) > 2 else None)
    try:
        raw = decode_b64u_strict(p) if p else None
        text = raw.decode("utf-8", "replace") if raw is not None else None
        c = json.loads(text[1:] if text and text[0] == "﻿" else text, parse_constant=_no_const) if text is not None else None
    except Exception:
        return {"ok": False, "reason": "malformed"}
    if extra is not None or not s or not is_obj(c) or not is_one(c.get("v")) or not isinstance(c.get("bind"), str) \
            or not is_uint(c.get("skip")) or ("inner" in c and not isinstance(c["inner"], str)):
        return {"ok": False, "reason": "malformed"}
    if c.get("signer") != signer or not verify_body(LIST_CURSOR_DOMAIN, c, signer, s):
        return {"ok": False, "reason": "signature"}
    if bind is not None:
        try:
            if c["bind"] != list_bind(bind):
                return {"ok": False, "reason": "bind"}
        except Exception:
            return {"ok": False, "reason": "bind"}
    out: Dict[str, Any] = {"ok": True}
    if "inner" in c:
        out["inner"] = c["inner"]
    out["skip"] = int(c["skip"])
    return out


# ---- grant management --------------------------------------------------------------------------------------------------

def _res_covers(p: str, r: str) -> bool:
    return r.startswith(p[:-1]) if p.endswith("*") else p == r


def _res_subset(small: List[str], big: List[str]) -> bool:
    return all(any(_res_covers(b, s) and (b.endswith("*") or b == s if s.endswith("*") else True) for b in big) for s in small)


def _limits(a: dict) -> dict:
    lim = a.get("limits")
    return lim if lim is not None else {}


def _expiry(a: dict) -> float:
    e = a.get("expires_at")
    return math.inf if e is None else e


def _authority_le(a: dict, b: dict) -> bool:
    """Everything ``a`` allows, ``b`` allows."""
    if not all(v in b["verbs"] for v in a["verbs"]) or not _res_subset(a["resources"], b["resources"]):
        return False
    for k, v in _limits(a).items():
        if k in _limits(b) and not v <= _limits(b)[k]:
            return False
    for k in _limits(b):
        if k not in _limits(a):
            return False
    return _expiry(a) <= _expiry(b)


def compare_authority(o: dict, n: dict) -> str:
    """``narrower`` / ``equal`` / ``wider`` / ``incomparable`` (``incomparable`` also for an authority that cannot be compared)."""
    try:
        nle, ole = _authority_le(n, o), _authority_le(o, n)
        return "equal" if nle and ole else "narrower" if nle else "wider" if ole else "incomparable"
    except Exception:
        return "incomparable"


def authority_digest(a: dict) -> str:
    return hash_canonical({"d": "atlas-pca/authority/v1", "a": {**a, "verbs": sorted(a["verbs"], key=u16key), "resources": sorted(a["resources"], key=u16key)}})


def _limit_ok(v: Any) -> bool:
    return _num(v) and v >= 0


def authority_ok(a: Any) -> bool:
    try:
        return (is_obj(a) and isinstance(a.get("verbs"), list) and len(a["verbs"]) <= 256 and all(is_str(v, 128) for v in a["verbs"])
                and isinstance(a.get("resources"), list) and len(a["resources"]) <= 1024 and all(is_str(v, 512) for v in a["resources"])
                and ("limits" not in a or (is_obj(a["limits"]) and all(_limit_ok(v) for v in a["limits"].values())))
                and ("expires_at" not in a or is_uint(a["expires_at"])))
    except Exception:
        return False


def _union(a: List[str], b: List[str]) -> List[str]:
    return list(dict.fromkeys([*a, *b]))


def merge_authority(a: dict, d: dict) -> dict:
    """Union. A ceiling or expiry is only ever RAISED by the delta; one the delta omits is kept."""
    limits = {k: max(v, _limits(d).get(k, v)) for k, v in _limits(a).items()}
    out: Dict[str, Any] = {"verbs": _union(a["verbs"], d["verbs"]), "resources": _union(a["resources"], d["resources"])}
    if limits:
        out["limits"] = limits
    if a.get("expires_at") is not None:
        de = d.get("expires_at")
        out["expires_at"] = max(a["expires_at"], a["expires_at"] if de is None else de)
    return out


def amend_message(g: dict, action: str, authority: dict) -> dict:
    return {"grant": g["id"], "rev": g["rev"], "action": action, "authority": authority_digest(authority)}


def grant_revoke_message(gid: Any, scope: str) -> dict:
    return {"grant": gid, "scope": scope}


def need_approve_message(nr: dict, rev: Any, approved: Any) -> dict:
    return {"need": nr["id"], "grant": nr["grant_id"], "rev": rev, "approved": approved}


def verify_amendment(cur: dict, req: Any, step_up_ok: bool) -> dict:
    """Decide an amendment against the current grant facts (normative check order: request shape, authority shape, grant
    active, classification, signature, step-up). Success: ``{ok, widens, next}``; failure: ``{ok: False, code}``."""
    try:
        if not is_obj(req) or req.get("action") not in ("narrow", "merge", "replace"):
            return {"ok": False, "code": "bad_request"}
        if not authority_ok(req.get("authority")):
            return {"ok": False, "code": "bad_request"}
        if cur["status"] != "active":
            return {"ok": False, "code": "not_active"}
        action, auth = req["action"], req["authority"]
        nxt = merge_authority(cur["authority"], auth) if action == "merge" else auth
        order = compare_authority(cur["authority"], nxt)
        widens = order in ("wider", "incomparable")
        if (not widens and action == "narrow" and order == "equal") or (widens and action == "narrow"):
            return {"ok": False, "code": "not_narrower"}
        signed_by = req.get("signed_by")
        if not isinstance(req.get("sig"), str) or signed_by not in ("holder", "principal"):
            return {"ok": False, "code": "signature_required"}
        if widens and signed_by != "principal":
            return {"ok": False, "code": "signature_required"}
        who = cur["principal"] if signed_by == "principal" else cur["agent"]
        if not verify_body(GRANT_AMEND_DOMAIN, amend_message(cur, action, auth), who, req["sig"]):
            return {"ok": False, "code": "bad_signature"}
        if widens and not step_up_ok:
            return {"ok": False, "code": "step_up_required"}
        return {"ok": True, "widens": widens, "next": nxt}
    except Exception:
        return {"ok": False, "code": "bad_request"}


def verify_revoke_signature(root: dict, scope: Any, sig: Any) -> dict:
    """The principal's signature over ``(grant id, scope)``. Host admin authority is not a wire fact and is not decided here."""
    try:
        if scope not in ("grant", "agent", "subtree"):
            return {"ok": False, "code": "bad_request"}
        if not verify_body(GRANT_REVOKE_DOMAIN, grant_revoke_message(root["id"], scope), root["principal"], sig):
            return {"ok": False, "code": "bad_signature"}
        return {"ok": True, "scope": scope}
    except Exception:
        return {"ok": False, "code": "bad_request"}


def verify_need_approval(nr: dict, g: dict, approved: Any, sig: Any, step_up_ok: bool) -> dict:
    """Principal signature over ``(need, grant, rev, approved)``, same count, same verb / resource, amounts only LOWERED and
    only when ``adjustable``, then step-up. Success: ``{ok, authority}`` (the merged authority)."""
    try:
        if nr["status"] != "pending":
            return {"ok": False, "code": "conflict"}
        if not verify_body(NEED_APPROVE_DOMAIN, need_approve_message(nr, g["rev"], approved), g["principal"], sig):
            return {"ok": False, "code": "bad_signature"}
        if not isinstance(approved, list) or len(approved) != len(nr["needs"]):
            return {"ok": False, "code": "need_not_lowered_only"}
        verbs: List[str] = []
        resources: List[str] = []
        limits: Dict[str, Any] = {}
        for a, want in zip(approved, nr["needs"]):
            if a["verb"] != want["verb"] or a["resource"] != want["resource"]:
                return {"ok": False, "code": "need_not_lowered_only"}
            for k, v in (a.get("limits") or {}).items():
                w = (want.get("limits") or {}).get(k)
                if w is None or v > w:
                    return {"ok": False, "code": "need_not_lowered_only"}
                if v < w and not want.get("adjustable"):
                    return {"ok": False, "code": "need_not_adjustable"}
            verbs.append(a["verb"])
            resources.append(a["resource"])
            # a limit the need names but the principal omitted is not granted at all
            for k, v in (a.get("limits") or {}).items():
                limits[k] = max(limits.get(k, 0), v)
        if not step_up_ok:
            return {"ok": False, "code": "step_up_required"}
        delta: Dict[str, Any] = {"verbs": verbs, "resources": resources}
        if limits:
            delta["limits"] = limits
        return {"ok": True, "authority": merge_authority(g["authority"], delta)}
    except Exception:
        return {"ok": False, "code": "bad_request"}
