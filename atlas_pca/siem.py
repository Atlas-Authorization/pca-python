"""SIEM export of PCA authorization decisions: OCSF 1.x Authorize Session, ArcSight CEF and Elastic Common Schema events
plus fail-safe sinks. Port of the TypeScript reference (@atlasauth/pca-siem); outputs are byte-identical, including the
JavaScript string / number / Date quirks (UTF-16 lengths, number formatting, toISOString).

Everything is pure over plain dicts: a decision record is {pcactn, verify, decision?, now?, session?}. Shipping an event to a
SIEM never raises into the caller: sink errors are caught, scrubbed of credentials, reported through on_error and returned.
"""
from __future__ import annotations

from ._fin import fin
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .pca import hash_canonical
from .sdjwt_jws import js_json, js_num, js_to_string

OCSF_SCHEMA_VERSION = "1.1.0"
ECS_VERSION = "8.11.0"
SECURITY_CHECKS = ("wire", "version", "audience", "validity", "cap_chain", "plan_inclusion", "leaf_signature",
                   "counter_format", "replay")

_U: Any = object()  # JS `undefined` (None is JSON null)

_SEV_INFO = (1, "Informational", 1)
_SEV_LOW = (2, "Low", 3)
_SEV_MEDIUM = (3, "Medium", 5)
_SEV_HIGH = (4, "High", 8)  # (OCSF id, OCSF label, CEF/ECS 0-10 scale)


# ---------------------------------------------------------------------------------------------------- JS helpers
def _get(o: Any, k: str) -> Any:
    return o.get(k, _U) if isinstance(o, dict) else _U


def _nullish(v: Any) -> bool:
    return v is None or v is _U


def _truthy(v: Any) -> bool:
    if v is None or v is _U or v is False:
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v == v and v != 0
    return v != ""


def _str(v: Any, fallback: str) -> str:
    return v if isinstance(v, str) and len(v) > 0 else fallback


def _finite(v: Any) -> Any:
    if isinstance(v, (int, float)) and not isinstance(v, bool) and fin(v):
        return v
    return _U


def _u16(s: str) -> bytes:
    return s.encode("utf-16-le", "surrogatepass")


def _u16len(s: str) -> int:
    return len(_u16(s)) // 2


def _u16slice(s: str, n: int) -> str:
    return _u16(s)[: 2 * n].decode("utf-16-le", "surrogatepass")


def _entries(x: Any) -> List[Tuple[str, Any]]:
    """Object.entries over any JSON value."""
    if isinstance(x, dict):
        return [(str(k), v) for k, v in x.items()]
    if isinstance(x, list):
        return [(str(i), v) for i, v in enumerate(x)]
    if isinstance(x, str):
        b = _u16(x)
        return [(str(i), b[2 * i: 2 * i + 2].decode("utf-16-le", "surrogatepass")) for i in range(len(b) // 2)]
    return []


def _iso(ms: Any) -> str:
    """new Date(ms).toISOString(), or the epoch when ms is not a valid time value."""
    epoch = "1970-01-01T00:00:00.000Z"
    if not isinstance(ms, (int, float)) or isinstance(ms, bool) or not fin(ms) or abs(ms) > 8.64e15:
        return epoch
    t = int(ms)  # truncation toward zero, like TimeClip
    days, rem = divmod(t, 86400000)
    z = days + 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + 3 if mp < 10 else mp - 9
    if m <= 2:
        y += 1
    ys = "%04d" % y if 0 <= y <= 9999 else ("-" if y < 0 else "+") + "%06d" % abs(y)
    h, rem = divmod(rem, 3600000)
    mi, rem = divmod(rem, 60000)
    s, milli = divmod(rem, 1000)
    return "%s-%02d-%02dT%02d:%02d:%02d.%03dZ" % (ys, m, d, h, mi, s, milli)


def _now_ms(now: Any) -> Any:
    if callable(now):
        return now()
    if isinstance(now, (int, float)) and not isinstance(now, bool):
        return now
    return int(time.time() * 1000)


def _prune(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not _U}


def _short_key(key: Any, n: int = 12) -> str:
    if not isinstance(key, str) or len(key) == 0:
        return "(none)"
    return key if _u16len(key) <= n + 1 else _u16slice(key, n) + "…"


def _safe_digest(p: Any) -> str:
    if p is _U:
        return "(undigestible)"
    try:
        return hash_canonical(p)
    except Exception:  # noqa: BLE001 - an out-of-profile body has no digest
        return "(undigestible)"


# ---------------------------------------------------------------------------------------------------- normalization
def _first_reason_or(decision: Any, fallback: str) -> str:
    rs = _get(decision, "reasons")
    first = rs[0] if isinstance(rs, list) and len(rs) > 0 else _U
    return first if isinstance(first, str) and len(first) > 0 else fallback


def _resolve_outcome(verify: Any, decision: Any) -> Tuple[str, str]:
    if not _truthy(verify) or _get(verify, "allow") is not True:
        return "deny", _str(_get(verify, "reason"), "proof failed verification")
    if not _truthy(decision):
        return "allow", "proof verified; no policy decision supplied"
    if _truthy(_get(decision, "admit")):
        return "allow", _first_reason_or(decision, "auto-admitted within policy and budget")
    if _truthy(_get(decision, "releaseGuardianShare")):
        return "step-up", _first_reason_or(decision, "policy satisfied but a co-signature is required")
    return "deny", _first_reason_or(decision, "policy did not release authority (default-deny)")


def _build_hops(chain: List[Any]) -> List[Dict[str, Any]]:
    hops: List[Dict[str, Any]] = []
    for i, cap in enumerate(chain):
        if not _truthy(cap):
            continue
        parent = chain[i - 1] if i > 0 else _U
        pc = _get(parent, "caveats") if _truthy(parent) else _U
        parent_len = len(pc) if isinstance(pc, list) else 0
        oc = _get(cap, "caveats")
        own_len = len(oc) if isinstance(oc, list) else 0
        added = own_len if i == 0 else max(0, own_len - parent_len)
        hops.append({"index": i, "isRoot": i == 0, "issuer": _str(_get(cap, "issuer"), "(none)"),
                     "holder": _str(_get(cap, "holder"), "(none)"), "addedCaveats": added})
    return hops


def _read_override(threshold: Any, threshold_check: Any) -> Dict[str, Any]:
    shares = _get(threshold, "shares") if _truthy(threshold) else _U
    shares = shares if isinstance(shares, list) else []
    # threshold sits outside the signed body: its shares prove nothing until a threshold verifier passed
    if threshold_check != "pass":
        return {"humanApproved": False, "approvers": [], "guardianCosigners": [], "roles": []}
    approvers: List[Any] = []
    guardians: List[Any] = []
    roles: List[Any] = []
    for s in shares:
        role = _get(s, "role")
        if not _truthy(s) or not isinstance(role, str):
            continue
        roles.append(role)
        pk = _get(s, "publicKey")
        if role == "principal" and isinstance(pk, str):
            approvers.append(pk)
        if role == "guardian" and isinstance(pk, str):
            guardians.append(pk)
    return {"humanApproved": len(approvers) > 0, "approvers": approvers, "guardianCosigners": guardians, "roles": roles}


def _severity_for(outcome: str, checks: Any, tier: Any) -> Tuple[int, str, int]:
    if outcome == "deny":
        return _SEV_HIGH if any(_get(checks, k) == "fail" for k in SECURITY_CHECKS) else _SEV_MEDIUM
    if outcome == "step-up":
        return _SEV_MEDIUM
    return _SEV_MEDIUM if tier == 3 and tier is not True else _SEV_LOW if tier == 2 and tier is not True else _SEV_INFO


def _shown_signature(sig: str, mode: Any) -> str:
    if mode == "full":
        return sig
    if mode == "omit":
        return "(omitted)"
    return sig if _u16len(sig) <= 16 else _u16slice(sig, 16) + "…"


def _normalize(record: Any, opts: Any, now: Any) -> Dict[str, Any]:
    """One total pass over the record, shared by the three exporters."""
    if record is None:
        raise TypeError("record is required")
    p = _get(record, "pcactn")
    v = _get(record, "verify")
    verify: Any = {"allow": False, "checks": {}} if _nullish(v) else v
    c = _get(verify, "checks")
    checks: Any = {} if _nullish(c) else c
    n_now = _finite(_get(record, "now"))
    if n_now is _U:
        n_now = _now_ms(now)
    cc = _get(p, "cap_chain")
    chain: List[Any] = cc if isinstance(cc, list) else []
    hops = _build_hops(chain)
    leaf = chain[-1] if chain else _U
    root = chain[0] if chain else _U

    decision = _get(record, "decision")
    outcome, reason = _resolve_outcome(verify, decision)
    rt = _get(decision, "requiredThreshold")
    tier = _get(rt, "t")
    override = _read_override(_get(p, "threshold"), _get(checks, "threshold"))

    grant_ref = _str(_get(p, "grant_ref"), "(none)")
    agent_holder = _str(_get(leaf, "holder"), "(none)")
    ri = _get(root, "issuer")
    principal = ri if isinstance(ri, str) and len(ri) > 0 else None
    chain_string = " -> ".join(_short_key(k) for k in [principal if principal is not None else "(principal?)"] + [h["holder"] for h in hops])

    action = _get(p, "action")
    nonce = _get(p, "nonce")
    bond = _get(p, "bond_ref")
    sev = _severity_for(outcome, checks, tier)
    return {
        "now": n_now, "outcome": outcome, "reason": reason,
        "cryptographicallyVerifiable": _get(checks, "wire") == "pass" and _get(checks, "leaf_signature") == "pass",
        "checks": checks, "agentHolder": agent_holder, "principal": principal,
        "session": _str(_get(record, "session"), grant_ref), "hops": hops, "depth": len(hops) - 1 if hops else 0,
        "chainString": chain_string,
        "verb": _str(_get(action, "verb"), "(unknown verb)"),
        "resource": _str(_get(action, "resource"), "(unknown resource)"),
        "paramsDigest": _str(_get(action, "params_digest"), "(none)"),
        "reversibilityClass": _str(_get(action, "reversibility_class"), "(unknown)"),
        "grantRef": grant_ref,
        "counter": -1 if _finite(_get(p, "counter")) is _U else _get(p, "counter"),
        "nonce": nonce if isinstance(nonce, str) else _U,
        "planRoot": _str(_get(_get(p, "plan"), "root"), "(none)"),
        "signatureSuite": _str(_get(p, "alg"), "ed25519"),
        "leafSignature": _shown_signature(_str(_get(p, "sig"), "(unsigned)"), _get(opts, "signature")),
        "proofDigest": _safe_digest(p),
        "riskScore": _finite(_get(decision, "r")), "tier": tier, "proofStrength": _get(rt, "proof"),
        "caution": _finite(_get(p, "caution")), "bondRef": bond if isinstance(bond, str) else _U,
        "humanApproved": override["humanApproved"], "approvers": override["approvers"],
        "guardianCosigners": override["guardianCosigners"], "roles": override["roles"],
        "severity": sev,
        "iat": n_now if _finite(_get(p, "iat")) is _U else _get(p, "iat"),
        "exp": n_now if _finite(_get(p, "exp")) is _U else _get(p, "exp"),
    }


def _hop_wire(h: Dict[str, Any]) -> Dict[str, Any]:
    return {"index": h["index"], "is_root": h["isRoot"], "issuer": h["issuer"], "holder": h["holder"],
            "added_caveats": h["addedCaveats"]}


def _human_override(n: Dict[str, Any]) -> Any:
    if not n["humanApproved"]:
        return _U
    return {"human_approved": True, "approvers": n["approvers"], "guardian_cosigners": n["guardianCosigners"], "roles": n["roles"]}


def _pca_extensions(n: Dict[str, Any]) -> Dict[str, Any]:
    return _prune({
        "proof_digest": n["proofDigest"], "leaf_signature": n["leafSignature"], "signature_suite": n["signatureSuite"],
        "cryptographically_verifiable": n["cryptographicallyVerifiable"], "plan_root": n["planRoot"],
        "params_digest": n["paramsDigest"], "grant_ref": n["grantRef"], "counter": n["counter"], "nonce": n["nonce"],
        "reversibility_class": n["reversibilityClass"], "risk_score": n["riskScore"], "risk_tier": n["tier"],
        "required_proof": n["proofStrength"], "caution": n["caution"], "bond_ref": n["bondRef"],
        "delegation_depth": n["depth"], "delegation_chain": [_hop_wire(h) for h in n["hops"]], "checks": n["checks"],
        "human_override": _human_override(n),
    })


def _narrative(n: Dict[str, Any]) -> str:
    word = "ALLOWED" if n["outcome"] == "allow" else "DENIED" if n["outcome"] == "deny" else "STEP-UP"
    return ("Agent %s %s to %s on %s (%d-hop chain rooted at principal %s; %s%s). %s" % (
        _short_key(n["agentHolder"]), word, n["verb"], n["resource"], len(n["hops"]), _short_key(n["principal"]),
        "cryptographically verifiable proof" if n["cryptographicallyVerifiable"] else "proof not cryptographically verifiable",
        "; human-signed step-up" if n["humanApproved"] else "", n["reason"]))


# ---------------------------------------------------------------------------------------------------- OCSF
_OCSF_ACTIVITY = {"allow": (1, "Allow"), "deny": (2, "Deny"), "step-up": (3, "Step-Up")}
_OCSF_ACTION = {"allow": (1, "Allowed"), "deny": (2, "Denied"), "step-up": (99, "Other")}


def to_ocsf_event(record: Any, opts: Any = None, now: Any = None) -> Dict[str, Any]:
    """OCSF 1.x Authorize Session (category 3, class 3003); `unmapped` carries the proof digest, tier and delegation chain."""
    n = _normalize(record, opts, now)
    aid, aname = _OCSF_ACTIVITY[n["outcome"]]
    actid, actname = _OCSF_ACTION[n["outcome"]]
    if n["outcome"] == "allow":
        status = (1, "Success", n["reason"])
    elif n["outcome"] == "deny":
        status = (2, "Failure", n["reason"])
    else:
        status = (99, "Other", "step-up / co-signature required: " + n["reason"])
    class_name = "Authorize Session"
    principal = n["principal"] if n["principal"] is not None else "(none)"
    return {
        "activity_id": aid, "activity_name": aname, "category_uid": 3, "category_name": "Identity & Access Management",
        "class_uid": 3003, "class_name": class_name, "type_uid": 3003 * 100 + aid, "type_name": "%s: %s" % (class_name, aname),
        "action_id": actid, "action": actname, "severity_id": n["severity"][0], "severity": n["severity"][1],
        "status_id": status[0], "status": status[1], "status_detail": status[2], "time": n["iat"],
        "actor": {
            "user": {"type_id": 99, "type": "Agent", "uid": n["agentHolder"], "name": _short_key(n["agentHolder"])},
            "invoked_by": principal,
            "session": _prune({"uid": n["session"], "issuer": _U if n["principal"] is None else n["principal"]}),
            "app_name": "PCA",
        },
        "user": {"type_id": 1, "type": "User", "uid": principal, "name": _short_key(n["principal"])},
        "resources": [{"type": "pca.resource", "name": n["resource"], "uid": n["resource"]}],
        "api": {"operation": n["verb"], "service": {"name": "PCA"}},
        "metadata": {
            "version": OCSF_SCHEMA_VERSION, "product": {"name": "PCA", "vendor_name": "Atlas", "version": OCSF_SCHEMA_VERSION},
            "logged_time": n["now"], "uid": n["proofDigest"],
            "labels": ["pca", "outcome:" + n["outcome"], "suite:" + n["signatureSuite"]],
        },
        "observables": [
            {"name": "actor.user.uid", "type": "User Name", "type_id": 4, "value": n["agentHolder"]},
            {"name": "pca.proof.digest", "type": "Hash", "type_id": 8, "value": n["proofDigest"]},
            {"name": "resources.uid", "type": "Resource UID", "type_id": 10, "value": n["resource"]},
        ],
        "count": 1, "message": _narrative(n), "unmapped": _pca_extensions(n),
    }


# ---------------------------------------------------------------------------------------------------- CEF
def _cef_header_escape(s: str) -> str:
    return re.sub(r"[\r\n]+", " ", s.replace("\\", "\\\\").replace("|", "\\|"))


def _cef_ext_value_escape(s: str) -> str:
    return re.sub(r"\r\n|\r|\n", lambda _m: "\\n", s.replace("\\", "\\\\").replace("=", "\\="))


def _cef_str(v: Any) -> str:
    return js_to_string(v)


def to_cef(record: Any, opts: Any = None, now: Any = None) -> str:
    """One ArcSight CEF line: standard keys where they fit, the proof digest in cs1 and the delegation chain in cs2."""
    n = _normalize(record, opts, now)
    wire_ver = _finite(_get(_get(record, "pcactn"), "ver"))
    device_version = js_num(wire_ver) if wire_ver is not _U else "2"
    header = "|".join([
        "CEF:0", _cef_header_escape("Atlas"), _cef_header_escape("PCA"), _cef_header_escape(device_version),
        _cef_header_escape("pca-authz-" + n["outcome"]),
        _cef_header_escape("PCA authorization %s: %s on %s" % (n["outcome"], n["verb"], n["resource"])),
        str(n["severity"][2]),
    ])
    principal = n["principal"] if n["principal"] is not None else "(none)"
    pairs: List[Tuple[str, Any]] = [
        ("act", n["outcome"]), ("outcome", n["outcome"]), ("suser", principal), ("suid", principal),
        ("duser", n["agentHolder"]), ("duid", n["agentHolder"]), ("destinationServiceName", n["verb"]),
        ("rt", n["now"]), ("start", n["iat"]), ("end", n["exp"]),
        ("externalId", n["nonce"] if n["nonce"] is not _U else js_num(n["counter"])),
        ("request", n["resource"]), ("requestMethod", n["verb"]),
        ("cs1Label", "pcaProofDigest"), ("cs1", n["proofDigest"]),
        ("cs2Label", "pcaDelegationChain"), ("cs2", n["chainString"]),
        ("cs3Label", "pcaProofStrength"), ("cs3", "n/a" if _nullish(n["proofStrength"]) else n["proofStrength"]),
        ("cs4Label", "pcaSignatureSuite"), ("cs4", n["signatureSuite"]),
        ("cs5Label", "pcaVerifyChecks"), ("cs5", ";".join("%s:%s" % (k, _cef_str(v)) for k, v in _entries(n["checks"]))),
        ("cs6Label", "pcaGrantRef"), ("cs6", n["grantRef"]),
        ("cn1Label", "pcaRiskScore"), ("cn1", "" if n["riskScore"] is _U else n["riskScore"]),
        ("cn2Label", "pcaDelegationDepth"), ("cn2", n["depth"]),
        ("cn3Label", "pcaRiskTier"), ("cn3", "" if _nullish(n["tier"]) else n["tier"]),
        ("flexString1Label", "pcaHumanApproved"), ("flexString1", "true" if n["humanApproved"] else "false"),
        ("cat", "authorization"), ("msg", n["reason"]),
    ]
    ext = " ".join("%s=%s" % (k, _cef_ext_value_escape(_cef_str(v))) for k, v in pairs)
    return "%s|%s" % (header, ext)


# ---------------------------------------------------------------------------------------------------- ECS
_ECS_EVENT_TYPE = {"allow": ["allowed"], "deny": ["denied"], "step-up": ["info"]}
_ECS_OUTCOME = {"allow": "success", "deny": "failure", "step-up": "unknown"}


def _dedupe(xs: List[Any]) -> List[Any]:
    out: List[Any] = []
    for x in xs:
        if x not in out:
            out.append(x)
    return out


def to_ecs(record: Any, opts: Any = None, now: Any = None) -> Dict[str, Any]:
    """Elastic Common Schema event; the PCA edge lives under `pca.*`."""
    n = _normalize(record, opts, now)
    related_users = _dedupe([n["agentHolder"]] + ([n["principal"]] if n["principal"] else []) + n["approvers"])
    related_hashes = _dedupe([n["proofDigest"], n["leafSignature"]])
    event: Dict[str, Any] = {
        "kind": "event", "category": ["iam"], "type": _ECS_EVENT_TYPE[n["outcome"]], "action": n["verb"],
        "outcome": _ECS_OUTCOME[n["outcome"]], "module": "pca", "dataset": "pca.authorization", "provider": "pca",
        "id": n["proofDigest"], "severity": n["severity"][2], "reason": n["reason"],
    }
    if n["riskScore"] is not _U:
        event["risk_score"] = n["riskScore"]
    principal = n["principal"] if n["principal"] is not None else "(none)"
    return {
        "@timestamp": _iso(n["iat"]), "ecs.version": ECS_VERSION, "event": event,
        "user": {"id": n["agentHolder"], "name": _short_key(n["agentHolder"]), "roles": ["agent"],
                 "effective": {"id": principal, "name": _short_key(n["principal"])}},
        "service": {"name": "pca", "type": "authorization"},
        "related": {"user": related_users, "hash": related_hashes},
        "message": _narrative(n),
        "pca": _prune({
            "outcome": n["outcome"],
            "proof": _prune({"digest": n["proofDigest"], "leaf_signature": n["leafSignature"],
                             "signature_suite": n["signatureSuite"],
                             "cryptographically_verifiable": n["cryptographicallyVerifiable"],
                             "plan_root": n["planRoot"], "params_digest": n["paramsDigest"]}),
            "risk": _prune({"score": n["riskScore"], "tier": n["tier"], "required_proof": n["proofStrength"],
                            "caution": n["caution"]}),
            "delegation": {"depth": n["depth"], "chain": n["chainString"], "hops": n["hops"]},
            "grant_ref": n["grantRef"], "counter": n["counter"], "nonce": n["nonce"],
            "reversibility_class": n["reversibilityClass"], "bond_ref": n["bondRef"], "checks": n["checks"],
            "human_override": _human_override(n),
        }),
    }


# ---------------------------------------------------------------------------------------------------- sinks
_CONTENT_TYPE = {"ocsf": "application/x-ndjson", "ecs": "application/x-ndjson", "cef": "text/plain; charset=utf-8"}

_WS = "\\t\\n\\x0b\\x0c\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"  # the JavaScript \s class
_FL = re.I | re.A  # ASCII-only \w, \b and case folding, as in a non-unicode JavaScript regex
_SCRUB = [
    (re.compile(r"([a-z][a-z0-9+.-]*://)[^%s/@]*:[^%s/@]*@" % (_WS, _WS), _FL), r"\g<1>[redacted]@"),
    (re.compile(r"\b(authorization[\"']?[%s]*[:=][%s]*)[^\n\"']*" % (_WS, _WS), _FL), r"\g<1>[redacted]"),
    (re.compile(r"\b(Bearer|Basic|Splunk|Token)[%s]+[\w.~+/=-]{6,}" % _WS, _FL), r"\g<1> [redacted]"),
    (re.compile(r"\b((?:token|secret|password|passwd|pwd|api[_-]?key|dd-api-key|key|signature|sig|credential)[\"']?[%s]*[:=][%s]*)"
                r"(\"[^\"]*\"|'[^']*'|[^%s\"'&,;]+)" % (_WS, _WS, _WS), _FL), r"\g<1>[redacted]"),
    (re.compile(r"[A-Za-z0-9_-]{32,}"), "[redacted]"),
]


def scrub_error(message: Any) -> str:
    """Remove credentials from an error message: URL userinfo, token= style pairs, bearer credentials, long token-like runs."""
    t = message if isinstance(message, str) else js_to_string(message)
    for rx, rep in _SCRUB:
        t = rx.sub(rep, t)
    return _u16slice(t, 300) + "..." if _u16len(t) > 300 else t


class SiemSink:
    """A SIEM destination: `format` is the schema it expects, deliver(events) -> {"ok": bool, "error"?: str}."""

    def __init__(self, name: str, fmt: Any, deliver: Callable[[List[Dict[str, Any]]], Dict[str, Any]]) -> None:
        self.name = name
        self.format = fmt
        self.deliver = deliver


def format_decision(record: Any, fmt: Any, opts: Any = None, now: Any = None) -> Dict[str, Any]:
    """{format, object?, line}: CEF is a bare line; any format other than cef / ocsf yields ECS."""
    if fmt == "cef":
        return {"format": fmt, "line": to_cef(record, opts, now)}
    obj = to_ocsf_event(record, opts, now) if fmt == "ocsf" else to_ecs(record, opts, now)
    return {"format": fmt, "object": obj, "line": js_json(obj)}


def _err_text(e: BaseException) -> str:
    return str(e) if str(e) else type(e).__name__


def _urllib_fetch(url: str, init: Dict[str, Any]) -> Dict[str, Any]:
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, data=init["body"].encode("utf-8"), headers=init["headers"], method=init["method"])
    try:
        with urllib.request.urlopen(req, timeout=init.get("timeout")) as r:  # noqa: S310 - caller-chosen collector URL
            return {"ok": 200 <= r.status < 300, "status": r.status, "statusText": r.reason}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "statusText": e.reason}


def http_sink(url: str, fmt: Any, headers: Optional[Dict[str, str]] = None, fetch: Optional[Callable[..., Any]] = None,
              content_type: Optional[str] = None, name: Optional[str] = None, timeout_ms: Any = None) -> SiemSink:
    """One POST per batch: NDJSON for OCSF / ECS, raw CEF lines for CEF. fetch(url, init) returns {ok, status, statusText?};
    init carries method / headers / body and a threading.Event `signal` set on timeout. Delivery never raises."""
    def deliver(events: List[Dict[str, Any]]) -> Dict[str, Any]:
        try:
            do_fetch = fetch or _urllib_fetch
            body = "\n".join(e["line"] for e in events)
            hdrs: Dict[str, str] = {}
            ct = content_type if content_type is not None else _CONTENT_TYPE.get(fmt)
            if ct is not None:
                hdrs["content-type"] = ct
            hdrs.update(headers or {})
            tm = 10000 if timeout_ms is None else timeout_ms
            secs = (tm if isinstance(tm, (int, float)) and not isinstance(tm, bool) and fin(tm) and tm > 0 else 10000) / 1000.0
            signal = threading.Event()
            box: Dict[str, Any] = {}

            def run() -> None:
                try:
                    box["res"] = do_fetch(url, {"method": "POST", "headers": hdrs, "body": body, "signal": signal, "timeout": secs})
                except BaseException as e:  # noqa: BLE001 - reported as a delivery failure
                    box["err"] = e

            th = threading.Thread(target=run, daemon=True)
            th.start()
            th.join(secs)
            if th.is_alive():
                signal.set()
                return {"ok": False, "error": "delivery timed out"}
            if "err" in box:
                raise box["err"]
            res = box["res"]
            if _truthy(_resp(res, "ok")):
                return {"ok": True}
            st = _resp(res, "statusText")
            return {"ok": False, "error": scrub_error("HTTP %s%s" % (js_to_string(_resp(res, "status")), " " + st if _truthy(st) else ""))}
        except Exception as e:  # noqa: BLE001 - delivery never raises
            return {"ok": False, "error": scrub_error(_err_text(e))}

    return SiemSink(name if name is not None else "http:%s" % fmt, fmt, deliver)


def _resp(res: Any, k: str) -> Any:
    if isinstance(res, dict):
        return res.get(k)
    return getattr(res, k, None)


def console_sink(fmt: Any = None, logger: Optional[Callable[[str], None]] = None, name: Optional[str] = None) -> SiemSink:
    """Writes each event's serialized line to a logger (default print). Never raises."""
    f = "ocsf" if fmt is None else fmt
    log = logger or print

    def deliver(events: List[Dict[str, Any]]) -> Dict[str, Any]:
        try:
            for e in events:
                log(e["line"])
            return {"ok": True}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": scrub_error(_err_text(e))}

    return SiemSink(name if name is not None else "console:%s" % f, f, deliver)


# ---------------------------------------------------------------------------------------------------- export
def _safe_on_error(on_error: Optional[Callable[..., Any]], error: Exception, sink: str, count: int) -> None:
    if on_error is None:
        return
    try:
        on_error(error, {"sink": sink, "count": count})
    except Exception:  # noqa: BLE001 - an on_error that raises must never reach the auth path
        pass


def export_batch(records: List[Any], sink: Any, on_error: Optional[Callable[..., Any]] = None, serialize: Any = None,
                 now: Any = None) -> Dict[str, Any]:
    """Export decisions in ONE delivery. Fail-safe: any serialization or delivery error is scrubbed, reported through
    on_error(error, {sink, count}) and returned as {ok: False, error}; nothing is raised."""
    fmt = getattr(sink, "format", None)
    count = 0
    try:
        events: List[Dict[str, Any]] = []
        skipped = 0
        for r in records:
            try:
                events.append(format_decision(r, fmt, serialize, now))
            except Exception as e:  # noqa: BLE001 - one bad record must not take the others' audit trail
                skipped += 1
                _safe_on_error(on_error, Exception(scrub_error("record could not be serialized: %s" % _err_text(e))), sink.name, 1)
        count = len(events)
        if not events and skipped > 0:
            return {"ok": False, "delivered": 0, "format": fmt, "error": "no record could be serialized", "skipped": skipped}
        res = sink.deliver(events)
        extra = {"skipped": skipped} if skipped > 0 else {}
        if _truthy(_resp(res, "ok")):
            return dict({"ok": True, "delivered": len(events), "format": fmt}, **extra)
        er = _resp(res, "error")
        err = Exception(scrub_error("sink reported a delivery failure" if _nullish(er) else er))
        _safe_on_error(on_error, err, sink.name, len(events))
        return dict({"ok": False, "delivered": 0, "format": fmt, "error": str(err)}, **extra)
    except Exception as e:  # noqa: BLE001
        err = Exception(scrub_error(_err_text(e)))
        _safe_on_error(on_error, err, getattr(sink, "name", "(unknown sink)"), count)
        return {"ok": False, "delivered": 0, "format": fmt, "error": str(err)}


def export_decision(record: Any, sink: Any, on_error: Optional[Callable[..., Any]] = None, serialize: Any = None,
                    now: Any = None) -> Dict[str, Any]:
    return export_batch([record], sink, on_error, serialize, now)
