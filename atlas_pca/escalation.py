"""Escalation on the wire: a port of packages/pca/src/escalation.ts (security contract C-51). A verifier decision of
``escalate`` is admitted only with a principal-signed answer bound to (policy digest, action digest, history head), spent by the
replay counter, never upgrading a deny. Every signature suite this verifier implements is accepted (Ed25519, ML-DSA, SLH-DSA,
FN-DSA and the hybrids; ``supported_suites()``) under the TypeScript pin rules: the principal is pinned by its Ed25519 key
(a bare string, or ``{"pk": ..., "pq_pk": ...}``), and a post-quantum / hybrid answer verifies only against the PQ key pinned
for that principal. A suite this verifier cannot run is refused (``unsupported_suite``).
Total: every function returns a result, never raises."""
from typing import Any, Dict, List, Optional

from .decision import _safe_int as _dec_safe_int
from .intent_wb import artifact_suite_error, verify_artifact_sig
from .pca import decode_b64u_strict, hash_canonical

__all__ = [
    "ESCALATION_ANSWER_DOMAIN", "ESCALATION_MAX_LIFETIME_MS", "escalation_policy_digest", "escalation_action_digest",
    "escalation_history_head", "build_escalation_request", "escalation_reasons_wire", "escalation_answer_shape_error", "verify_escalation_answer",
]

ESCALATION_ANSWER_DOMAIN = "atlas-pca/escalation-answer/v1\0"
ESCALATION_MAX_LIFETIME_MS = 86_400_000
_REQUIRED = ("v", "kind", "principal", "policy_digest", "action_digest", "history_head", "decision", "iat", "expires_at", "nonce", "sig")
_OPTIONAL = ("alg", "pq_pk", "pq_sig", "render_digest")


def escalation_policy_digest(grant: Any) -> str:
    return hash_canonical({"d": "atlas-pca/escalation-policy/v1", "grant": grant})


def escalation_action_digest(pcactn: Any) -> str:
    return hash_canonical({"d": "atlas-pca/escalation-action/v1", "pcactn": pcactn})


def escalation_history_head(last_counter: Optional[int]) -> str:
    return hash_canonical({"d": "atlas-pca/escalation-history/v1", "last_counter": last_counter})


def _utf16_prefix(s: str, n: int) -> str:
    """`s.slice(0, n)` of a JavaScript string: at most ``n`` UTF-16 code units. A cut inside a surrogate pair keeps the LONE high
    surrogate, as the reference does (a Python ``str`` can hold it; ``escalation_reasons_wire`` writes it as ``\\udXXX``)."""
    return s.encode("utf-16-le", "surrogatepass")[:2 * n].decode("utf-16-le", "surrogatepass")


_JSON_SHORT = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def escalation_reasons_wire(request: Any) -> str:
    """`JSON.stringify(request.reasons)`: strings escaped as the reference writes them (quote, backslash, controls, a lone
    surrogate as ``\\udXXX``; everything else, non-ASCII included, raw)."""
    def one(s: str) -> str:
        out = []
        for ch in s:
            o = ord(ch)
            if ch in _JSON_SHORT:
                out.append(_JSON_SHORT[ch])
            elif o < 0x20 or 0xD800 <= o <= 0xDFFF:
                out.append("\\u%04x" % o)
            else:
                out.append(ch)
        return '"' + "".join(out) + '"'
    return "[" + ",".join(one(r) for r in request["reasons"]) + "]"


def build_escalation_request(*, aud: Any, grant: Any, pcactn: Any, last_counter: Optional[int], reasons: List[str],
                             now: int, ttl_ms: int = 3_600_000, render_digest: Optional[str] = None) -> Dict[str, Any]:
    action = pcactn.get("action") if isinstance(pcactn, dict) else None
    action = action if isinstance(action, dict) else {}
    req = {
        "v": 1, "kind": "pca-escalation-request", "aud": aud if isinstance(aud, str) else "",
        "policy_digest": escalation_policy_digest(grant), "action_digest": escalation_action_digest(pcactn),
        "history_head": escalation_history_head(last_counter),
        "verb": str(action.get("verb")), "resource": str(action.get("resource")),
        "reasons": [_utf16_prefix(str(r), 512) for r in reasons[:16]], "expires_at": now + (ttl_ms if ttl_ms > 0 else 3_600_000),
    }
    if render_digest is not None:
        req["render_digest"] = render_digest
    return req


def _safe_int(v: Any) -> bool:
    """`Number.isSafeInteger(v) && !Object.is(v, -0)`: a parsed JSON `2.0` or `1e3` is the integer 2 / 1000."""
    return _dec_safe_int(v)


def escalation_answer_shape_error(a: Any) -> Optional[str]:
    if not isinstance(a, dict):
        return "not an object"
    for k in a:
        if k not in _REQUIRED and k not in _OPTIONAL:
            return "unknown member 'answer.%s'" % k
    for k in _REQUIRED:
        if k not in a:
            return "missing member 'answer.%s'" % k
    if a["v"] != 1 or isinstance(a["v"], bool) or a["kind"] != "pca-escalation-answer":
        return "not a pca-escalation-answer v1"
    if not isinstance(a["principal"], str) or decode_b64u_strict(a["principal"], 32) is None:
        return "principal must be canonical base64url (32 bytes)"
    for k in ("policy_digest", "action_digest", "history_head"):
        if decode_b64u_strict(a[k], 32) is None:
            return "%s must be canonical base64url (32 bytes)" % k
    if a["decision"] not in ("allow", "deny"):
        return "decision must be 'allow' or 'deny'"
    iat, exp = a["iat"], a["expires_at"]
    if not (_safe_int(iat) and iat >= 0 and _safe_int(exp) and exp >= 0):
        return "iat and expires_at must be non-negative safe integers"
    if not exp > iat:
        return "expires_at must be greater than iat"
    if exp - iat > ESCALATION_MAX_LIFETIME_MS:
        return "an answer lives at most %d ms" % ESCALATION_MAX_LIFETIME_MS
    if "render_digest" in a and not (isinstance(a["render_digest"], str) and decode_b64u_strict(a["render_digest"], 32) is not None):
        return "render_digest must be canonical base64url (32 bytes)"
    nb = decode_b64u_strict(a["nonce"]) if isinstance(a["nonce"], str) else None
    if nb is None or len(nb) < 16:
        return "nonce must be canonical base64url of at least 16 bytes"
    if not isinstance(a["sig"], str):
        return "sig must be a string"
    return artifact_suite_error(a)


def verify_escalation_answer(answer: Any, principals: Any, bind: Any, now: Any) -> Dict[str, Any]:
    def no(r: str) -> Dict[str, Any]:
        return {"ok": False, "reason": r}

    try:
        if not _safe_int(now):
            return no("the verifier clock is not a safe integer (fail closed)")
        e = escalation_answer_shape_error(answer)
        if e:
            return no("malformed escalation answer: " + e)
        if not isinstance(principals, (list, tuple)) or len(principals) == 0:
            return no("no principal is pinned for escalation answers")
        pin = None
        for p in principals:  # the first pin naming the principal decides (as the reference's find)
            cand = {"pk": p} if isinstance(p, str) else p
            if isinstance(cand, dict) and cand.get("pk") == answer["principal"]:
                pin = cand
                break
        if pin is None:
            return no("the answering principal is not pinned by this verifier")
        if not verify_artifact_sig(ESCALATION_ANSWER_DOMAIN, answer, pin):
            return no("escalation answer signature invalid")
        if answer["policy_digest"] != bind.get("policy_digest"):
            return no("the answer is bound to another policy")
        if answer["action_digest"] != bind.get("action_digest"):
            return no("the answer is bound to another action")
        if answer["history_head"] != bind.get("history_head"):
            return no("the answer is bound to another state of the history")
        want_render = bind.get("render_digest")
        if want_render is not None:
            if "render_digest" not in answer:
                return no("the answer is not bound to the canonical approval render")
            if answer["render_digest"] != want_render:
                return no("the answer was given for another approval render")
        elif "render_digest" in answer:
            return no("the answer carries an approval render this verifier did not recompute")
        if now < answer["iat"]:
            return no("the answer is from the future")
        if now > answer["expires_at"]:
            return no("the answer has expired")
        return {"ok": True, "principal": answer["principal"], "decision": answer["decision"]}
    except Exception as err:  # noqa: BLE001
        return no("escalation answer error (fail closed): %s" % type(err).__name__)
