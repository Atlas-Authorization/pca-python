"""The A2A binding (verification side): typed needs (``pca_need``), per-hop chain extension, the pure gate of AUTH_REQUIRED
resumption, push-token binding and signed task-update receipts. Total functions. Results are dicts shaped like the shared vectors
(``a2a-vectors.json``). Per-hop PCActn verification itself is the ordinary verifier's job; this module is what surrounds it."""
from ._fin import fin
import hmac
import math
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import ed25519 as _ed
from .a2a_card import PCA_A2A_EXTENSION_URI, UNDEFINED, spread
from .attest_common import JS_WS
from .k3 import is_obj, is_str, is_uint, u16len, verify_body
from .pca import b64u, canonical_bytes_strict, decode_b64u_strict, hash_canonical, strict_parse
from .pca_grant import chain_digest, parse_details
from .sdjwt_jws import truthy

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
        if not (isinstance(sc, list) and len(sc) <= 16 and all(is_str(s, 128) and not any(c in JS_WS for c in s) for s in sc)):
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
            if not is_str(k, 64) or not _num(v) or v < 0 or not fin(v):
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


def _same(a: Any, b: Any) -> bool:
    """JavaScript ``===`` on JSON values (containers compare by reference, never equal across two parsed documents)."""
    if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
        return a is b
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if a is None or b is None:
        return a is b
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    return a == b


def chain_extends(prev: Sequence[Any], nxt: Sequence[Any]) -> bool:
    """Does ``nxt`` (capability ids, root first) extend ``prev``? Attenuation only appends hops, so the earlier chain is a prefix."""
    return len(nxt) >= len(prev) and all(_same(nxt[k], id_) for k, id_ in enumerate(prev))


def check_chain_extension(chains: Any) -> Dict[str, Any]:
    prev: Optional[list] = None
    for i, ids in enumerate(chains):
        if not isinstance(ids, list) or len(ids) == 0:
            return {"ok": False, "failedHop": i, "reason": "no_chain"}
        if prev is not None and not chain_extends(prev, ids):
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
    if not isinstance(salt, str) or u16len(salt) < 16:
        return None
    return hash_canonical({"d": "atlas-pca/a2a-push/v1", "task_id": task_id, "chain": chain_digest(list(chain_ids)), "salt": salt})


def check_push(task_id: str, chain_ids: Sequence[str], salt: str, token: Any, payload: Any) -> Dict[str, Any]:
    if not isinstance(token, str) or token == "":
        return {"ok": False, "reason": "no_token"}
    want = push_token(task_id, chain_ids, salt)
    if want is None or not hmac.compare_digest(token.encode("utf-8", "surrogatepass"), want.encode("utf-8")):
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
        if not isinstance(r.get("task_id"), str) or r["task_id"] == "" or u16len(r["task_id"]) > 4096 or r.get("state") not in _STATES:
            return False
        if not _uint(r.get("seq")) or not _uint(r.get("issued_at")) or not isinstance(r.get("chain"), str) or decode_b64u_strict(r["chain"], 32) is None:
            return False
        prev = r.get("prev")
        if "prev" not in r or not (prev is None or (isinstance(prev, str) and decode_b64u_strict(prev, 32) is not None)) or (r["seq"] == 0) != (prev is None):
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


# ==== the rest of the binding: tasks, AUTH_REQUIRED mapping, delegation, mandate envelope, receipts =========================
# Dict options use the TypeScript option names (``expectedRootIssuer``, ``requireChecks``, ``humanSignerSet`` ...); the snake_case
# spellings are accepted too. Where the reference awaits, these functions are synchronous.

TASK_STATE_AUTH_REQUIRED = "TASK_STATE_AUTH_REQUIRED"
TASK_STATE_INPUT_REQUIRED = "TASK_STATE_INPUT_REQUIRED"
NEED_KEY = PCA_A2A_EXTENSION_URI + "#need"
RECEIPT_KEY = PCA_A2A_EXTENSION_URI + "#receipt"
A2A_RECEIPT_DOMAIN = RECEIPT_DOMAIN
A2A_AP2_CONTEXT = ("https://www.w3.org/2018/credentials/v1", "https://ap2-protocol.org/context/v0.2")
_PARAM_KEYS = frozenset(("aud", "suites", "grants", "policy_digest"))


class A2aAuthorityError(Exception):
    """A verifier configured without any authority (``grant`` or ``expectedRootIssuer``): a chain is never its own authority."""
    code = "authority_required"

    def __init__(self) -> None:
        super().__init__("pca-a2a: pass `grant` (from your store) or `expectedRootIssuer`; a chain is never its own authority")


def _opt(o: Any, camel: str, snake: str) -> Any:
    if not isinstance(o, dict):
        return UNDEFINED
    return o[camel] if camel in o else o.get(snake, UNDEFINED)


def _get(o: Any, k: str) -> Any:
    """``o.k`` in JavaScript: a TypeError for null / undefined, undefined for a missing member or a non-object."""
    if o is None or o is UNDEFINED:
        raise TypeError("Cannot read properties of %s (reading '%s')" % ("null" if o is None else "undefined", k))
    return o.get(k, UNDEFINED) if isinstance(o, dict) else UNDEFINED


def _nullish(v: Any, default: Any) -> Any:
    return default if v is None or v is UNDEFINED else v


def _defined(v: Any) -> Any:
    return None if v is UNDEFINED else v


def _uint(n: Any) -> bool:
    """``Number.isSafeInteger(n) && n >= 0 && !Object.is(n, -0)``."""
    return is_uint(n) and not _neg_zero(n)


def _safe_int(v: Any) -> bool:
    """``Number.isSafeInteger`` (so -0 passes)."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    return (v == v and abs(v) <= 9007199254740991 and v == math.floor(v)) if isinstance(v, float) else abs(v) <= 9007199254740991


def _neg_zero(v: Any) -> bool:
    return isinstance(v, float) and v == 0 and math.copysign(1.0, v) < 0


def iso_from_ms(now: Any) -> str:
    """``new Date(now).toISOString()``: RangeError (ValueError) for a non-number or an out-of-range time."""
    if isinstance(now, bool) or not isinstance(now, (int, float)) or now != now or abs(now) > 8.64e15:
        raise ValueError("Invalid time value")
    t = int(now)
    days, ms = divmod(t, 86400000)
    z = days + 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + 3 if mp < 10 else mp - 9
    y += 1 if m <= 2 else 0
    ys = "%04d" % y if 0 <= y <= 9999 else ("+" if y > 0 else "-") + "%06d" % abs(y)
    return "%s-%02d-%02dT%02d:%02d:%02d.%03dZ" % (ys, m, d, ms // 3600000, ms // 60000 % 60, ms // 1000 % 60, ms % 1000)


# ---- proof-carrying tasks -----------------------------------------------------------------------------------------------

def _with_pca(metadata: Any, pca: Any) -> Dict[str, Any]:
    out = spread(_nullish(metadata, {}))
    out[PCA_A2A_EXTENSION_URI] = pca
    return out


def _read_pca(metadata: Any) -> Any:
    v = metadata.get(PCA_A2A_EXTENSION_URI) if isinstance(metadata, dict) else None
    return v if isinstance(v, dict) else None


def attach_pca_to_a2a_task(task: Any, pca: Any) -> Dict[str, Any]:
    """A copy of the task with the PCActn on its metadata (the input is not mutated)."""
    out = spread(task)
    out["metadata"] = _with_pca(_get(task, "metadata"), pca)
    return out


def attach_pca_to_a2a_message(message: Any, pca: Any) -> Dict[str, Any]:
    return attach_pca_to_a2a_task(message, pca)


def extract_pca(task: Any) -> Optional[dict]:
    """The PCActn a task carries: its metadata, then the status message, then the most recent history message; None if none."""
    if not isinstance(task, dict):
        return None
    on_task = _read_pca(task.get("metadata"))
    if on_task is not None:
        return on_task
    status = task.get("status")
    msg = status.get("message") if isinstance(status, dict) else None
    on_status = _read_pca(msg.get("metadata")) if isinstance(msg, dict) else None
    if on_status is not None:
        return on_status
    history = task.get("history")
    if isinstance(history, list):
        for m in reversed(history):
            on_msg = _read_pca(m.get("metadata")) if isinstance(m, dict) else None
            if on_msg is not None:
                return on_msg
    return None


def extract_pca_from_message(message: Any) -> Optional[dict]:
    return _read_pca(message.get("metadata")) if isinstance(message, dict) else None


def _assert_authority(opts: Any) -> None:
    grant = _opt(opts, "grant", "grant")
    issuer = _opt(opts, "expectedRootIssuer", "expected_root_issuer")
    if not (isinstance(grant, (dict, list)) or (isinstance(issuer, str) and issuer != "")):
        raise A2aAuthorityError()


#: The reference's stateless required checks (server verify DEFAULT_REQUIRED_CHECKS): without a revocation hook a task is refused.
DEFAULT_REQUIRED_CHECKS = ("counter_format", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound")


def _core_verifier(p: Any, grant: Any, opts: dict, context: dict, pq_pins: Any) -> Dict[str, Any]:
    """The default verdict source: the core PCActn verifier (signature, audience, validity, chain, plan inclusion, ...). Replay,
    revocation and budget state belong to the caller's ``verify`` hook (for example one that wraps ``authorize``)."""
    from .pca import verify_pcactn_core
    plan = context.get("plan") if isinstance(context.get("plan"), dict) else {}
    authorized = context.get("planAuthorized") is True or context.get("plan_authorized") is True
    roots = [plan["root"]] if authorized and isinstance(plan.get("root"), str) else []
    suites = _opt(opts, "allowedSuites", "allowed_suites")
    v = verify_pcactn_core(p, grant, now=_defined(_opt(opts, "now", "now")), audience=opts.get("aud"),
                           allowed_suites=_defined(suites), authorized_plan_roots=roots, pq_pins=pq_pins)
    checks = dict(v.checks)
    # revocation is a caller hook in the reference (`hooks.revocation(ctx)` -> {enforced, ok, reason}); absent = not enforced
    hooks = opts.get("hooks") if isinstance(opts.get("hooks"), dict) else {}
    rev, reasons = hooks.get("revocation"), list(v.reasons or ([v.reason] if v.reason else []))
    allow = bool(v.allow)
    try:
        res = rev({"pcactn": p, "grant": grant, "context": context}) if callable(rev) else None
    except Exception as exc:  # noqa: BLE001 - a failing revocation hook is a failed check
        res = {"enforced": True, "ok": False, "reason": "revocation hook failed: %s" % exc}
    if isinstance(res, dict) and res.get("enforced") is True:
        checks["revocation"] = "pass" if res.get("ok") is True else "fail"
        if res.get("ok") is not True:
            allow = False
            reasons.append(str(res.get("reason") or "rejected"))
    else:
        checks["revocation"] = "not-enforced"
    params, action = context.get("params"), p.get("action") if isinstance(p, dict) else None
    if isinstance(params, dict) and isinstance(action, dict):
        try:
            from .pca import params_digest
            checks["params_digest"] = params_digest(params) == action.get("params_digest")
        except Exception:  # noqa: BLE001 - params with no canonical form do not open the digest
            checks["params_digest"] = False
    return {"allow": allow, "checks": checks, "reasons": reasons}


def _verify_pca(p: Any, opts: dict, extra_required: Sequence[str] = ()) -> Dict[str, Any]:
    """PCActn authorization shared by the task and payment-mandate surfaces, under a known authority: the stored grant, or the
    chain root only when its issuer is the expected principal. ``opts['verify']`` (a callable ``(pcactn, grant, opts, context)`` ->
    verdict dict with ``allow``/``reasons``/``checks``) replaces the default core verifier."""
    _assert_authority(opts)
    if p is None or not isinstance(p, (dict, list)):
        return {"ok": False, "reason": "PCActn is not an object"}
    chain = _get(p, "cap_chain")
    root = chain[0] if isinstance(chain, list) and chain else UNDEFINED
    if root is UNDEFINED or not truthy(root):
        return {"ok": False, "reason": "PCActn carries no capability chain", "pcActn": p}
    expected = _opt(opts, "expectedRootIssuer", "expected_root_issuer")
    if expected is not UNDEFINED and not _same(_get(root, "issuer"), expected):
        return {"ok": False, "reason": "chain root issuer does not match the expected principal", "pcActn": p}
    grant = _opt(opts, "grant", "grant")
    grant = _nullish(grant, root)  # without a stored grant the root is admitted only under the pinned principal
    pins = _opt(opts, "pqPins", "pq_pins")
    pq_pins = (_defined(pins) or {}) if _opt(opts, "grant", "grant") is UNDEFINED else _defined(pins)
    ctx = opts.get("context")
    context = _nullish(ctx(p) if callable(ctx) else ctx, {})
    hook = opts.get("verify")
    verdict = hook(p, grant, opts, context) if callable(hook) else _core_verifier(p, grant, opts, context, pq_pins)
    require = _opt(opts, "requireChecks", "require_checks")
    # default-deny like the reference: these checks must PASS unless the caller names its own list
    names = list(DEFAULT_REQUIRED_CHECKS) if require is UNDEFINED or require is None else list(require)
    names += [n for n in extra_required if n not in names]
    checks = verdict.get("checks", {})
    allow = bool(verdict.get("allow")) and all(checks.get(n) in (True, "pass") for n in names)
    reasons = [r for r in verdict.get("reasons", []) if r]
    reason = None if allow else ("; ".join(reasons) or "PCActn verification failed")
    result = dict(verdict, allow=allow)
    if reason is not None:
        result["reason"] = reason
    return {"ok": True, "result": result, "pcActn": p} if allow else {"ok": False, "reason": reason, "result": result, "pcActn": p}


def verify_a2a_task(task: Any, opts: Any = None) -> Dict[str, Any]:
    """Verify the proof-carrying action on a task. Fail closed: no PCActn, or one that does not verify, is refused."""
    _assert_authority(opts)
    p = extract_pca(task)
    if p is None:
        return {"ok": False, "reason": "no proof-carrying action attached to this task"}
    return _verify_pca(p, opts)


def pca_a2a_middleware(opts: Any = None) -> Callable[[Any], Dict[str, Any]]:
    """A per-task guard. ``require`` (default True): a task with no proof is refused; with False it passes, but a task that DOES
    carry a proof must still verify."""
    _assert_authority(opts)
    require = _nullish(opts.get("require"), True)

    def guard(task: Any) -> Dict[str, Any]:
        p = extract_pca(task)
        if p is None:
            return {"ok": False, "reason": "proof-carrying action required but none attached to task"} if truthy(require) else {"ok": True}
        return _verify_pca(p, opts)
    return guard


# ---- extension declaration ----------------------------------------------------------------------------------------------

def pca_extension_declaration(params: dict, required: bool = True) -> Dict[str, Any]:
    return {"uri": PCA_A2A_EXTENSION_URI, "description": "Per-action proofs of authority (PCActn) on tasks and messages",
            "required": required, "params": params}


def read_pca_extension(card: Any) -> Dict[str, Any]:
    """Read and validate the PCA extension from an Agent Card. A malformed declaration is a refusal, never a guess."""
    caps = card.get("capabilities") if is_obj(card) else None
    exts = caps.get("extensions") if is_obj(caps) else None
    if not isinstance(exts, list):
        return {"ok": False, "code": "not_declared"}
    found = [e for e in exts if is_obj(e) and e.get("uri") == PCA_A2A_EXTENSION_URI]
    if not found:
        return {"ok": False, "code": "not_declared"}
    if len(found) > 1:
        return {"ok": False, "code": "bad_declaration"}
    e = found[0]
    if "required" in e and not isinstance(e["required"], bool):
        return {"ok": False, "code": "bad_declaration"}
    p = e.get("params")
    if not is_obj(p) or any(k not in _PARAM_KEYS for k in p) or not isinstance(p.get("aud"), str) or not 0 < u16len(p["aud"]) <= 512:
        return {"ok": False, "code": "bad_params"}
    if "suites" in p and not (isinstance(p["suites"], list) and len(p["suites"]) <= 16 and all(isinstance(s, str) and 0 < u16len(s) <= 64 for s in p["suites"])):
        return {"ok": False, "code": "bad_params"}
    if "policy_digest" in p and not (isinstance(p["policy_digest"], str) and 0 < u16len(p["policy_digest"]) <= 128):
        return {"ok": False, "code": "bad_params"}
    grants: list = []
    if "grants" in p:
        g = parse_details(p["grants"])
        if not g["ok"]:
            return {"ok": False, "code": "bad_grants"}
        grants = g["details"]
    return {"ok": True, "required": e.get("required") is True, "params": p, "grants": grants}


def client_opts_into_pca(header: Any) -> bool:
    """True iff the ``A2A-Extensions`` service parameter lists the PCA extension (exact URI in a comma-separated list)."""
    return isinstance(header, str) and any(u.strip(JS_WS) == PCA_A2A_EXTENSION_URI for u in header.split(","))


# ---- AUTH_REQUIRED mapping ----------------------------------------------------------------------------------------------

def is_auth_required(state: Any) -> bool:
    return isinstance(state, str) and state in (TASK_STATE_AUTH_REQUIRED, "auth-required")


def encode_pca_need(need: Any) -> str:
    """The unpadded base64url of a need's strict canonical JSON. Raises on a malformed need or an over-long value."""
    v = validate_need(need)
    if not v["ok"]:
        raise ValueError("encodePcaNeed: malformed need (%s)" % v["code"])
    enc = b64u(canonical_bytes_strict(need))
    if len(enc) > NEED_MAX_ENCODED:
        raise ValueError("encodePcaNeed: the need is too large for a header")
    return enc


def auth_required_status(need: Any, o: dict) -> Dict[str, Any]:
    """The TaskStatus an agent sets to ask for authority: AUTH_REQUIRED plus a message carrying the typed need. Raises on a need the
    codec would refuse."""
    enc = encode_pca_need(need)
    text = _opt(o, "text", "text")
    stamp = iso_from_ms(_opt(o, "now", "now"))
    mid = _opt(o, "messageId", "message_id")
    msg: Dict[str, Any] = {
        "role": "agent",
        "parts": [{"kind": "text", "text": "Authority needed: %s on %s" % (need["verb"], need["resource"]) if text is UNDEFINED or text is None else text}],
        "extensions": [PCA_A2A_EXTENSION_URI],
        "metadata": {NEED_KEY: enc},
    }
    if mid is not UNDEFINED:
        msg["messageId"] = mid
    return {"state": TASK_STATE_AUTH_REQUIRED, "timestamp": stamp, "message": msg}


def read_auth_required_need(task: Any) -> Optional[Dict[str, Any]]:
    """The need parked in a task status message, decoded (None when there is none)."""
    status = task.get("status") if is_obj(task) else None
    msg = status.get("message") if is_obj(status) else None
    md = msg.get("metadata") if is_obj(msg) else None
    if not is_obj(md) or NEED_KEY not in md:
        return None
    return decode_need(md[NEED_KEY])


def answer_message(need: Any, pca: Any, message_id: Any) -> Dict[str, Any]:
    """The answer message: a PCActn for exactly the parked need, plus the need's digest."""
    return {"role": "user", "messageId": message_id, "parts": [{"kind": "text", "text": "authority provided"}],
            "metadata": {PCA_A2A_EXTENSION_URI: pca, NEED_KEY: need_digest(need)}}


def resume_gate_obj(o: dict) -> Optional[str]:
    """``resume_gate`` over the reference's option object ``{state, needEncoded, answerNeedDigest, proofAction}``: an absent
    ``proofAction`` is no proof, a null one raises (as the reference does)."""
    if not is_auth_required(o.get("state")):
        return "task_not_auth_required"
    need = None if "needEncoded" not in o else decode_need(o["needEncoded"])
    if need is None or not need["ok"]:
        return "no_valid_need"
    if not _same(o.get("answerNeedDigest", UNDEFINED), need_digest(need["need"])):
        return "answer_not_bound_to_need"
    if "proofAction" not in o:
        return "no_proof"
    action = o["proofAction"]
    if action is None:
        raise TypeError("Cannot read properties of null (reading 'verb')")
    if not _same(_get(action, "verb"), need["need"]["verb"]) or not _same(_get(action, "resource"), need["need"]["resource"]):
        return "action_mismatch"
    return None


def resume_auth_required(task: Any, answer: Any, opts: dict) -> Dict[str, Any]:
    """Resume a Task parked in AUTH_REQUIRED. Allowed only when the task is in AUTH_REQUIRED, its status carries a decodable need,
    the answer cites that need's digest, the answer carries a PCActn for the need's exact verb and resource, and that PCActn passes
    the verifier for THIS agent. The state change alone, or a proof for another action, resumes nothing."""
    status = task.get("status") if is_obj(task) else None
    smsg = status.get("message") if is_obj(status) else None
    status_md = smsg["metadata"] if is_obj(smsg) and is_obj(smsg.get("metadata")) else {}
    md = answer["metadata"] if is_obj(answer) and is_obj(answer.get("metadata")) else {}
    p = extract_pca_from_message(answer)
    gate: Dict[str, Any] = {}
    if is_obj(status) and "state" in status:
        gate["state"] = status["state"]
    if NEED_KEY in status_md:
        gate["needEncoded"] = status_md[NEED_KEY]
    if NEED_KEY in md:
        gate["answerNeedDigest"] = md[NEED_KEY]
    if p is not None and "action" in p:
        gate["proofAction"] = p["action"]
    refusal = resume_gate_obj(gate)
    if refusal is not None:
        return {"ok": False, "reason": refusal}
    v = verify_a2a_task({"id": task.get("id"), "status": {"state": "TASK_STATE_WORKING"}, "metadata": {PCA_A2A_EXTENSION_URI: p}}, opts)
    return {"ok": True, "verification": v} if v["ok"] else {"ok": False, "reason": v.get("reason") or "proof_rejected"}


# ---- per-hop delegation -------------------------------------------------------------------------------------------------

def verify_a2a_delegation(hops: Sequence[dict]) -> Dict[str, Any]:
    """Verify a chain of delegated tasks, one per A2A hop, each on its own (its own PCActn, audience and authority); the capability
    chain must EXTEND the previous hop's. Stops at the first failure; empty input is refused."""
    chains: List[list] = []
    if len(hops) == 0:
        return {"ok": False, "reason": "no_hops", "chains": chains}
    for i, h in enumerate(hops):
        v = verify_a2a_task(h["task"], h["opts"])
        if not v["ok"]:
            return {"ok": False, "failedHop": i, "reason": v.get("reason") or "rejected", "chains": chains}
        p = extract_pca(h["task"])
        ids = [_get(c, "id") for c in p["cap_chain"]] if p is not None and isinstance(p.get("cap_chain"), list) else None
        if ids is None:
            return {"ok": False, "failedHop": i, "reason": "no_chain", "chains": chains}
        if chains and not chain_extends(chains[-1], ids):
            return {"ok": False, "failedHop": i, "reason": "chain_does_not_extend_previous_hop", "chains": chains}
        chains.append(ids)
    return {"ok": True, "chains": chains}


# ---- push notifications and anti-enumeration ----------------------------------------------------------------------------

def pca_push_token(task_id: str, chain_ids: Sequence[str], salt: Any) -> str:
    """The per-task push token. Raises ValueError on a salt shorter than 16 characters (``push_token`` returns None there)."""
    t = push_token(task_id, chain_ids, salt)
    if t is None:
        raise ValueError("pcaPushToken: the salt must be a secret of at least 16 characters")
    return t


def check_push_notification(expected: dict, delivered: dict) -> Dict[str, Any]:
    """Receiver-side check of a delivered push notification: the token must be the one recomputed from the task, the chain and the
    salt, and the payload must be about that task. Raises on a salt shorter than 16 characters."""
    token = delivered.get("token")
    if not isinstance(token, str) or token == "":
        return {"ok": False, "reason": "no_token"}
    want = pca_push_token(expected["taskId"], expected["chainIds"], expected["salt"])
    if not hmac.compare_digest(token.encode("utf-8", "surrogatepass"), want.encode("utf-8")):
        return {"ok": False, "reason": "token_mismatch"}
    p = delivered.get("payload")
    p = p if is_obj(p) else {}
    found = UNDEFINED
    for key, field in (("task", "id"), ("statusUpdate", "taskId"), ("artifactUpdate", "taskId")):
        c = p.get(key)
        v = c.get(field) if is_obj(c) else None
        if v is not None:
            found = v
            break
    return {"ok": True} if _same(found, expected["taskId"]) else {"ok": False, "reason": "task_mismatch"}


def uniform_task_not_found() -> Dict[str, str]:
    """The one error servers return for "no such task" and "not yours" alike (no existence leak)."""
    return {"code": "TaskNotFoundError", "message": "task not found"}


# ---- payment mandate envelope -------------------------------------------------------------------------------------------

def _human_present(p: Any, signer_set: Any) -> bool:
    """True only when the PCActn's threshold shares verify at t=3 (agent, guardian and principal) under ``signer_set``. The agent
    role may be satisfied by the leaf signature only for an Ed25519 leaf and an Ed25519-only agent registration; anything else
    must carry an explicit agent share. Never raises."""
    try:
        from .pca import THRESHOLD_ROLES, _signer_registry, threshold_message, verify_leaf_suite, verify_threshold_share
        reg = _signer_registry(signer_set)
        if reg is None or set(reg) != set(THRESHOLD_ROLES) or not isinstance(p, dict):
            return False
        msg = threshold_message(p)
        shares = p["threshold"]["shares"] if isinstance(p.get("threshold"), dict) and isinstance(p["threshold"].get("shares"), list) else []
        ok_roles = set()
        for sh in shares:
            if isinstance(sh, dict) and verify_threshold_share({"role": sh.get("role"), "t": 3, "share": sh, "threshold_message": b64u(msg), "signer_set": signer_set}):
                ok_roles.add(sh["role"])
        if "agent" not in ok_roles and reg["agent"][1] is None and p.get("alg") in (None, "ed25519"):
            chain = p.get("cap_chain")
            leaf = chain[-1] if isinstance(chain, list) and chain else None
            if isinstance(leaf, dict) and leaf.get("holder") == reg["agent"][0] and isinstance(p.get("sig"), str) \
                    and verify_leaf_suite(p, leaf["holder"], msg):
                ok_roles.add("agent")
        return ok_roles == set(THRESHOLD_ROLES)
    except Exception:  # noqa: BLE001 - totality: an unverifiable claim is no claim
        return False


def a2a_payment_mandate_from_pca(pca: Any, opts: dict) -> Dict[str, Any]:
    """Map a PCActn to an AP2 payment-mandate envelope whose authority is carried BY REFERENCE (``x_pca.pcactn_digest``).
    ``opts``: ``amount`` (integer minor units), ``paymentMethod``, ``merchant``, ``humanPresent``, ``humanSignerSet``,
    ``issuerPublic``, ``now``. Raises on anything the envelope cannot honestly carry."""
    chain = _get(pca, "cap_chain")
    leaf_obj = chain[-1] if isinstance(chain, list) and chain else UNDEFINED
    leaf = _get(leaf_obj, "holder") if leaf_obj is not None and leaf_obj is not UNDEFINED else UNDEFINED
    issuer = _nullish(_opt(opts, "issuerPublic", "issuer_public"), leaf)
    if issuer is UNDEFINED:
        raise ValueError("a2aPaymentMandateFromPca: no issuerPublic given and the PCActn has no capability chain")
    amount = _get(opts, "amount")
    value = _get(amount, "value")
    if not _safe_int(value) or value < 0:
        raise ValueError("a2aPaymentMandateFromPca: amount.value must be a non-negative integer in minor units")
    hp = _opt(opts, "humanPresent", "human_present")
    signer_set = _opt(opts, "humanSignerSet", "human_signer_set")
    if hp is None or hp is UNDEFINED:
        hp = _human_present(pca, signer_set) if truthy(_defined(signer_set)) else False
    now = _nullish(_opt(opts, "now", "now"), int(time.time() * 1000))
    action = _get(pca, "action")
    x_pca: Dict[str, Any] = {"pcactn_digest": hash_canonical(pca)}
    for k, v in (("aud", _get(pca, "aud")), ("verb", _get(action, "verb")), ("resource", _get(action, "resource")),
                 ("params_digest", _get(action, "params_digest")), ("grant_ref", _get(pca, "grant_ref"))):
        if v is not UNDEFINED:
            x_pca[k] = v
    x_pca["leaf_holder"] = _nullish(leaf, issuer)
    contents: Dict[str, Any] = {"amount": spread(amount), "payment_method": spread(_defined(_opt(opts, "paymentMethod", "payment_method"))),
                                "human_present": hp}
    merchant = _opt(opts, "merchant", "merchant")
    if merchant is not UNDEFINED:
        contents["merchant"] = merchant
    contents["x_pca"] = x_pca
    return {"@context": list(A2A_AP2_CONTEXT), "type": ["VerifiableCredential", "PaymentMandate"], "issuer": issuer,
            "issuanceDate": iso_from_ms(now), "credentialSubject": contents}


def pca_binding_from_a2a_payment_mandate(mandate: Any) -> Dict[str, Any]:
    """The PCA binding read back out of a payment mandate (the round trip of ``x_pca``)."""
    return spread(_get(_get(mandate, "credentialSubject"), "x_pca"))


def _own(o: Any, k: str) -> bool:
    return isinstance(o, dict) and k in o


def _mandate_binding_error(m: Any, p: Any, params: dict, opts: dict) -> Optional[str]:
    x = _get(m, "x_pca")
    if not is_obj(x):
        return "payment mandate carries no x_pca binding"
    chain = _get(p, "cap_chain")
    leaf = chain[-1] if isinstance(chain, list) and chain else None
    action = _get(p, "action")
    bound = [("aud", _get(p, "aud")), ("verb", _get(action, "verb") if action is not None and action is not UNDEFINED else UNDEFINED),
             ("resource", _get(action, "resource") if action is not None and action is not UNDEFINED else UNDEFINED),
             ("params_digest", _get(action, "params_digest") if action is not None and action is not UNDEFINED else UNDEFINED),
             ("grant_ref", _get(p, "grant_ref")), ("leaf_holder", leaf.get("holder", UNDEFINED) if is_obj(leaf) else UNDEFINED)]
    for k, v in bound:
        if not _own(x, k) or not isinstance(x[k], str) or not _same(x[k], v):
            return "payment mandate x_pca.%s is not the PCActn's" % k
    amt = m.get("amount", UNDEFINED) if is_obj(m) else UNDEFINED
    if not is_obj(amt) or not _safe_int(amt.get("value")) or amt["value"] < 0 or _neg_zero(amt["value"]) or not isinstance(amt.get("currency"), str):
        return "payment mandate amount is malformed (value must be a non-negative integer in minor units)"
    if not _own(params, "amount") or not _safe_int(params["amount"]) or params["amount"] < 0 or _neg_zero(params["amount"]):
        return "the PCActn params carry no integer minor-unit amount to bind the mandate amount to"
    if not _own(params, "currency") or not isinstance(params["currency"], str):
        return "the PCActn params carry no currency to bind the mandate currency to"
    if amt["value"] != params["amount"] or amt["currency"] != params["currency"]:
        return "payment mandate amount / currency differ from the authorized PCActn params"
    merchant = m["merchant"] if _own(m, "merchant") else UNDEFINED
    p_merchant = params["merchant"] if _own(params, "merchant") else UNDEFINED
    if not _same(merchant, p_merchant):
        return "payment mandate merchant differs from the authorized PCActn params"
    if _own(params, "payment_method"):
        try:
            same = hash_canonical(m.get("payment_method", UNDEFINED)) == hash_canonical(params["payment_method"])
        except Exception:  # noqa: BLE001 - no canonical form means no match
            same = False
        if not same:
            return "payment mandate payment_method differs from the authorized PCActn params"
    hp = m.get("human_present", UNDEFINED) if is_obj(m) else UNDEFINED
    if not isinstance(hp, bool):
        return "payment mandate human_present must be a boolean"
    hs = _opt(opts, "humanSignerSet", "human_signer_set")
    if hp and not (isinstance(hs, list) and _human_present(p, hs)):
        return "payment mandate claims human_present but no verified principal co-signature backs it (pass humanSignerSet)"
    return None


def verify_a2a_payment_mandate(mandate: Any, pca: Any, opts: Any = None) -> Dict[str, Any]:
    """Verify a payment mandate against the PCActn it references. The mandate is NOT signed: every field a payer acts on must be
    authorized by the PCActn (digest and ``x_pca`` fields, the opened params' amount, currency, merchant and payment method, a
    verified t=3 co-signature for ``human_present``), and the PCActn itself must verify, with ``params_digest`` required."""
    _assert_authority(opts)
    try:
        bound = _get(_get(_get(mandate, "credentialSubject"), "x_pca"), "pcactn_digest")
        digest = hash_canonical(pca)
    except Exception as e:  # noqa: BLE001 - a malformed mandate or a PCActn with no canonical form is a refusal
        return {"ok": False, "reason": "malformed payment mandate or PCActn: %s" % e}
    if not _same(bound, digest):
        return {"ok": False, "reason": "payment mandate is not bound to this PCActn (pcactn_digest mismatch)", "pcActn": pca}
    if pca is None or not isinstance(pca, (dict, list)):
        return {"ok": False, "reason": "PCActn is not an object"}
    ctx = opts.get("context")
    context = _nullish(ctx(pca) if callable(ctx) else ctx, {})
    params = _get(context, "params")
    if not is_obj(params):
        return {"ok": False, "reason": "context.params (the PCActn params plaintext) is required to bind the payment mandate", "pcActn": pca}
    why = _mandate_binding_error(mandate["credentialSubject"], pca, params, opts)
    if why is not None:
        return {"ok": False, "reason": why, "pcActn": pca}
    return _verify_pca(pca, dict(opts, context=context), ("params_digest",))


# ---- signed task-update receipts ----------------------------------------------------------------------------------------

def sign_task_receipt(secret: bytes, o: dict) -> Dict[str, Any]:
    """Sign a receipt (``o``: ``taskId``, ``state``, ``chainIds``, ``issuedAt``, optional ``prev``, the previous receipt of the same
    task). Raises on malformed input, a ``prev`` of another task or one already terminal."""
    task_id, state, issued = o.get("taskId"), o.get("state"), o.get("issuedAt")
    ids = o["chainIds"]
    if not isinstance(task_id, str) or task_id == "" or u16len(task_id) > 256 or state not in _STATES or not _uint(issued) or len(ids) == 0:
        raise ValueError("signTaskReceipt: malformed input")
    prev = o.get("prev")
    if truthy(prev) and (_get(prev, "task_id") != task_id or _get(prev, "state") in _TERMINAL):
        raise ValueError("signTaskReceipt: prev is for another task or already terminal")
    base: Dict[str, Any] = {"v": 1, "task_id": task_id, "state": state, "seq": prev["seq"] + 1 if truthy(prev) else 0,
                            "prev": receipt_digest(prev) if truthy(prev) else None, "chain": chain_digest(list(ids)),
                            "issued_at": issued, "signer": b64u(_ed.public_key(secret))}
    msg = RECEIPT_DOMAIN.encode("utf-8") + canonical_bytes_strict(base)
    return dict(base, sig=b64u(_ed.sign_secret(secret, msg)))


def check_receipt_chain_result(receipts: Any, signer: str, task_id: str, chain_ids: Sequence[str]) -> Dict[str, Any]:
    """``check_receipt_chain`` with the reference's result shape: on success the last receipt itself (``last``) and ``terminal``."""
    r = check_receipt_chain(receipts, signer, task_id, chain_ids)
    if not r["ok"]:
        return r
    return {"ok": True, "last": receipts[-1], "terminal": r["terminal"]}


def attach_receipt(carrier: Any, receipt: Any) -> Dict[str, Any]:
    """A copy of a status update or message with the receipt on its metadata."""
    out = spread(carrier)
    md = spread(_nullish(_get(carrier, "metadata"), {}))
    md[RECEIPT_KEY] = receipt
    out["metadata"] = md
    return out


def receipt_of_payload(payload: Any) -> Any:
    """The (unverified) receipt a push or stream payload carries (``statusUpdate``, ``task`` or ``message`` metadata), else None."""
    if not is_obj(payload):
        return None
    for k in ("statusUpdate", "task", "message"):
        c = payload.get(k)
        md = c.get("metadata") if is_obj(c) else None
        if is_obj(md) and RECEIPT_KEY in md:
            return md[RECEIPT_KEY]
    return None
