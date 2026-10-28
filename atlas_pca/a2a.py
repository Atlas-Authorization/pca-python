"""The A2A binding (verification side): typed needs (``pca_need``), per-hop chain extension, the pure gate of AUTH_REQUIRED
resumption, push-token binding and signed task-update receipts. Total functions. Results are dicts shaped like the shared vectors
(``a2a-vectors.json``). Per-hop PCActn verification itself is the ordinary verifier's job; this module is what surrounds it."""
from typing import Any, Dict, List, Optional, Sequence

from .k3 import is_obj, is_str, is_uint, verify_body
from .pca import decode_b64u_strict, hash_canonical, strict_parse
from .pca_grant import chain_digest

NEED_MAX_ENCODED = 2048
NEED_DOMAIN = "atlas-pca/need/v1"
_KINDS = ("scope", "grant", "discharge", "escalate")
_NEED_MEMBERS = frozenset(("v", "kind", "verb", "resource", "scopes", "grant_ref", "limits", "discharges", "tier", "policy_digest"))
RECEIPT_DOMAIN = "atlas-pca/a2a-receipt/v1\0"
_RECEIPT_REF = "atlas-pca/a2a-receipt-ref/v1"
_TERMINAL = ("TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED")
_STATES = _TERMINAL + ("TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED")


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def validate_need(x: Any) -> Dict[str, Any]:
    if not is_obj(x):
        return {"ok": False, "code": "bad_shape"}
    if any(k not in _NEED_MEMBERS for k in x):
        return {"ok": False, "code": "unknown_member"}
    if not (_is_int(x.get("v")) and x["v"] == 1) and not (isinstance(x.get("v"), float) and x["v"] == 1):
        return {"ok": False, "code": "bad_version"}
    if not isinstance(x.get("kind"), str) or x["kind"] not in _KINDS:
        return {"ok": False, "code": "bad_kind"}
    bad = {"ok": False, "code": "bad_field"}
    if not is_str(x.get("verb"), 128) or not is_str(x.get("resource"), 512):
        return bad
    if "scopes" in x:
        sc = x["scopes"]
        if not (isinstance(sc, list) and len(sc) <= 16 and all(is_str(s, 128) and not any(c.isspace() for c in s) for s in sc)):
            return bad
    for k in ("grant_ref", "policy_digest"):
        if k in x and not is_str(x[k], 128):
            return bad
    if "tier" in x and not (_is_int(x["tier"]) and x["tier"] in (2, 3)):
        return bad
    if "limits" in x:
        lim = x["limits"]
        if not is_obj(lim) or len(lim) > 16:
            return bad
        for k, v in lim.items():
            if not is_str(k, 64) or not _num(v) or v < 0 or v != v or v in (float("inf"),):
                return bad
    if "discharges" in x:
        d = x["discharges"]
        if not isinstance(d, list) or len(d) > 16:
            return bad
        for e in d:
            if not is_obj(e) or any(k not in ("issuer", "claim") for k in e) or not is_str(e.get("issuer"), 512) or not is_str(e.get("claim"), 256):
                return bad
    if "tier" in x and x["kind"] != "escalate":
        return bad
    if x["kind"] == "escalate" and "tier" not in x:
        return bad
    return {"ok": True, "need": x}


def decode_need(value: Any) -> Dict[str, Any]:
    if not isinstance(value, str) or value == "":
        return {"ok": False, "code": "bad_base64"}
    if len(value) > NEED_MAX_ENCODED:
        return {"ok": False, "code": "too_long"}
    raw = decode_b64u_strict(value)
    if raw is None:
        return {"ok": False, "code": "bad_base64"}
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"ok": False, "code": "bad_utf8"}
    try:
        parsed = strict_parse(text)
    except Exception:
        return {"ok": False, "code": "bad_json"}
    return validate_need(parsed)


def need_digest(need: dict) -> str:
    return hash_canonical({"d": NEED_DOMAIN, "need": need})


def check_chain_extension(chains: Any) -> Dict[str, Any]:
    prev: Optional[list] = None
    for i, ids in enumerate(chains):
        if not isinstance(ids, list) or len(ids) == 0:
            return {"ok": False, "failedHop": i, "reason": "no_chain"}
        if prev is not None and (len(ids) < len(prev) or any(ids[k] != prev[k] for k in range(len(prev)))):
            return {"ok": False, "failedHop": i, "reason": "chain_does_not_extend_previous_hop"}
        prev = ids
    return {"ok": True}


def resume_gate(state: Any, need_encoded: Any, answer_need_digest: Any, proof_action: Any) -> Optional[str]:
    if state not in ("TASK_STATE_AUTH_REQUIRED", "auth-required"):
        return "task_not_auth_required"
    need = None if need_encoded is None else decode_need(need_encoded)
    if need is None or not need["ok"]:
        return "no_valid_need"
    if answer_need_digest != need_digest(need["need"]):
        return "answer_not_bound_to_need"
    if proof_action is None:
        return "no_proof"
    if proof_action.get("verb") != need["need"]["verb"] or proof_action.get("resource") != need["need"]["resource"]:
        return "action_mismatch"
    return None


def push_token(task_id: str, chain_ids: Sequence[str], salt: Any) -> Optional[str]:
    """None where the reference throws (a salt shorter than 16 characters)."""
    if not isinstance(salt, str) or len(salt) < 16:
        return None
    return hash_canonical({"d": "atlas-pca/a2a-push/v1", "task_id": task_id, "chain": chain_digest(list(chain_ids)), "salt": salt})


def check_push(task_id: str, chain_ids: Sequence[str], salt: str, token: Any, payload: Any) -> Dict[str, Any]:
    if not isinstance(token, str) or token == "":
        return {"ok": False, "reason": "no_token"}
    want = push_token(task_id, chain_ids, salt)
    if want is None or token != want:
        return {"ok": False, "reason": "token_mismatch"}
    p = payload if is_obj(payload) else {}
    found = None
    for key, field in (("task", "id"), ("statusUpdate", "taskId"), ("artifactUpdate", "taskId")):
        c = p.get(key)
        v = c.get(field) if is_obj(c) else None
        if v is not None:
            found = v
            break
    return {"ok": True} if found == task_id else {"ok": False, "reason": "task_mismatch"}


def receipt_digest(r: dict) -> str:
    return hash_canonical({"d": _RECEIPT_REF, "r": r})


def verify_receipt(r: Any, signer: str) -> bool:
    try:
        if not is_obj(r) or not (_is_int(r.get("v")) and r["v"] == 1) or r.get("signer") != signer:
            return False
        if not isinstance(r.get("task_id"), str) or r["task_id"] == "" or r.get("state") not in _STATES:
            return False
        if not is_uint(r.get("seq")) or not is_uint(r.get("issued_at")) or not isinstance(r.get("chain"), str) or decode_b64u_strict(r["chain"], 32) is None:
            return False
        prev = r.get("prev")
        if not (prev is None or (isinstance(prev, str) and decode_b64u_strict(prev, 32) is not None)) or (r["seq"] == 0) != (prev is None):
            return False
        if not isinstance(r.get("sig"), str):
            return False
        body = {k: r[k] for k in ("v", "task_id", "state", "seq", "prev", "chain", "issued_at", "signer")}
        return verify_body(RECEIPT_DOMAIN, body, signer, r["sig"])
    except Exception:
        return False


def check_receipt_chain(receipts: Sequence[Any], signer: str, task_id: str, chain_ids: Sequence[str]) -> Dict[str, Any]:
    if not isinstance(receipts, (list, tuple)) or len(receipts) == 0:
        return {"ok": False, "code": "empty"}
    chain = chain_digest(list(chain_ids))
    prev: Optional[dict] = None
    for i, r in enumerate(receipts):
        if not verify_receipt(r, signer):
            return {"ok": False, "code": "bad_receipt", "at": i}
        if r["task_id"] != task_id:
            return {"ok": False, "code": "wrong_task", "at": i}
        if r["chain"] != chain:
            return {"ok": False, "code": "wrong_chain", "at": i}
        if prev is None:
            if r["seq"] != 0:
                return {"ok": False, "code": "bad_start", "at": i}
        else:
            if prev["state"] in _TERMINAL:
                return {"ok": False, "code": "after_terminal", "at": i}
            if r["seq"] != prev["seq"] + 1 or r["prev"] != receipt_digest(prev):
                return {"ok": False, "code": "broken_link", "at": i}
        prev = r
    assert prev is not None
    return {"ok": True, "terminal": prev["state"] in _TERMINAL, "last_state": prev["state"]}


def may_trigger_next(receipts: Sequence[Any], signer: str, task_id: str, chain_ids: Sequence[str]) -> bool:
    r = check_receipt_chain(receipts, signer, task_id, chain_ids)
    return bool(r["ok"]) and r["last_state"] == "TASK_STATE_COMPLETED"
