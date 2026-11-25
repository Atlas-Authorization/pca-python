"""Auditor-ready compliance evidence from PCA proofs and decision records, pre-mapped to the control language auditors use: EU AI
Act Art. 12 / Art. 50, ISO/IEC 42001 clauses and SOC 2 CC6, plus the console-activity framework report (EU AI Act, SOC 2, GDPR).
Port of the TypeScript reference (@atlasauth/pca-compliance).

Everything here is pure and read-only, and total where the reference is: a malformed record degrades to a best-effort one. HONEST
SCOPE: an evidence mapping, not a legal certification; `satisfied` means the cryptographic evidence a control asks for is present
in the supplied records. Inputs are the reference's JSON shapes (dicts / lists); property reads follow JavaScript semantics (a
missing member is `undefined`, reading through null raises) so reports match the reference text for text."""
from __future__ import annotations

from ._fin import fin
import math
import time
from typing import Any, Dict, List, Optional

from .notary import _to_number
from .pca import hash_canonical, _js_keys
from .predicates import _UNDEF, _js_number_string, _js_string
from .sdjwt_jws import _js_str as _json_string, js_num

COMPLIANCE_FRAMEWORKS = ("eu-ai-act", "iso-42001", "soc2")
_UNSET: Any = object()
_MAX_SAFE = 2 ** 53


# ---- JavaScript semantics ---------------------------------------------------------------------------------------------

def _own(o: Any, k: str) -> Any:
    return o.get(k, _UNDEF) if isinstance(o, dict) else _UNDEF


def _prop(o: Any, k: str) -> Any:
    """`o.k`: raises when `o` is null / undefined, like the reference."""
    if o is None or o is _UNDEF:
        raise TypeError("Cannot read properties of %s (reading '%s')" % ("null" if o is None else "undefined", k))
    return _own(o, k)


def _qprop(o: Any, k: str) -> Any:
    """`o?.k`."""
    return _UNDEF if o is None or o is _UNDEF else _own(o, k)


def _nullish(v: Any) -> bool:
    return v is None or v is _UNDEF


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _finite(v: Any) -> bool:
    """`Number.isFinite` (no coercion)."""
    return _is_num(v) and fin(v)


def _truthy(v: Any) -> bool:
    if v is None or v is _UNDEF or v is False or v == "":
        return False
    if _is_num(v):
        return not (v == 0 or v != v)
    return True


def _num(v: Any) -> float:
    """JavaScript ToNumber for the operands the reference compares."""
    return math.nan if v is _UNDEF else _to_number(v)


def _gt(a: Any, b: Any) -> bool:
    """`a > b`: two strings compare by UTF-16 order, anything else numerically."""
    if isinstance(a, str) and isinstance(b, str):
        return a.encode("utf-16-be", "surrogatepass") > b.encode("utf-16-be", "surrogatepass")
    return _num(a) > _num(b)


def _num_str(v: Any) -> str:
    """ECMAScript Number::toString for a JSON number."""
    if isinstance(v, int):
        return str(v) if abs(v) <= _MAX_SAFE else _js_number_string(float(v))
    return _js_number_string(v)


def _js_round(v: float) -> int:
    """`Math.round`: halves round toward +Infinity."""
    r = math.floor(v)
    return r + 1 if v - r >= 0.5 else r


def _is_integer(v: Any) -> bool:
    return _is_num(v) and fin(v) and v == math.floor(v)


def _u16(s: str) -> bytes:
    return s.encode("utf-16-le", "surrogatepass")


def _length(v: Any) -> Any:
    """`v.length` (string: UTF-16 units; array: items); raises on null / undefined; undefined for any other value."""
    if v is None or v is _UNDEF:
        raise TypeError("Cannot read properties of %s (reading 'length')" % ("null" if v is None else "undefined"))
    if isinstance(v, str):
        return len(_u16(v)) // 2
    if isinstance(v, list):
        return len(v)
    return _UNDEF


class _JsSet:
    """A `Set` with SameValueZero identity: primitives by value, objects (dicts / lists) each distinct."""

    def __init__(self) -> None:
        self._keys: set = set()
        self._n = 0

    def add(self, v: Any) -> None:
        if isinstance(v, bool):
            k: Any = ("b", v)
        elif _is_num(v):
            k = ("n", "nan" if v != v else float(v) + 0.0)
        elif isinstance(v, str):
            k = ("s", v)
        elif v is None or v is _UNDEF:
            k = ("z", v is None)
        else:
            self._n += 1
            k = ("o", self._n)
        self._keys.add(k)

    @property
    def size(self) -> int:
        return len(self._keys)


def _stringify(v: Any) -> str:
    """`JSON.stringify(v)` (compact; JS key order and number formatting)."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _json_string(v)
    if _is_num(v):
        return js_num(v)
    if isinstance(v, list):
        return "[" + ",".join("null" if x is _UNDEF else _stringify(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(_json_string(k) + ":" + _stringify(v[k]) for k in _js_keys(v) if v[k] is not _UNDEF) + "}"
    raise TypeError("stringify: unsupported type %s" % type(v).__name__)


def _pretty(v: Any, base: str = "") -> str:
    """`JSON.stringify(v, null, 2)`."""
    if isinstance(v, list):
        if not v:
            return "[]"
        ind = base + "  "
        return "[\n" + ",\n".join(ind + ("null" if x is _UNDEF else _pretty(x, ind)) for x in v) + "\n" + base + "]"
    if isinstance(v, dict):
        keys = [k for k in _js_keys(v) if v[k] is not _UNDEF]
        if not keys:
            return "{}"
        ind = base + "  "
        return "{\n" + ",\n".join(ind + _json_string(k) + ": " + _pretty(v[k], ind) for k in keys) + "\n" + base + "}"
    return _stringify(v)


def _civil(days: int):
    """(year, month, day) of a day count since 1970-01-01 (proleptic Gregorian)."""
    z = days + 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + 3 if mp < 10 else mp - 9
    return (y + 1 if m <= 2 else y), m, d


def _iso_string(ms: Any) -> str:
    """`new Date(ms).toISOString()`; raises ValueError for an invalid / unrepresentable time (RangeError there)."""
    if not _is_num(ms) or not fin(ms) or abs(ms) > 8.64e15:
        raise ValueError("Invalid time value")
    t = int(ms)
    days, rem = divmod(t, 86400000)
    y, mo, d = _civil(days)
    ys = "%04d" % y if 0 <= y <= 9999 else ("+" if y > 0 else "-") + "%06d" % abs(y)
    return "%s-%02d-%02dT%02d:%02d:%02d.%03dZ" % (ys, mo, d, rem // 3600000, rem // 60000 % 60, rem // 1000 % 60, rem % 1000)


def _iso(ms: Any) -> str:
    if not _finite(ms):
        return "(unknown time)"
    try:
        return _iso_string(ms)
    except ValueError:
        return "(unrepresentable time)"


def _ts(ms: Any) -> Dict[str, Any]:
    return {"epochMs": ms, "iso": _iso(ms)}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _short(key: Any, n: int = 12) -> str:
    """Abbreviate a long key for display (UTF-16 units, like the reference)."""
    if not isinstance(key, str) or len(key) == 0:
        return "(none)"
    b = _u16(key)
    if len(b) // 2 <= n + 1:
        return key
    return b[:n * 2].decode("utf-16-le", "surrogatepass") + "…"


def _numstr(x: Any) -> str:
    if not _is_num(x) or not fin(x):
        return _js_string(x)
    if _is_integer(x):
        return _num_str(x)
    return _js_number_string(_js_round(float(x) * 1e4) / 1e4)


def _tpl(v: Any) -> str:
    """A value interpolated into a template literal."""
    return _js_string(v)


# ---- AuditEvent -------------------------------------------------------------------------------------------------------

def _is_budget_alloc(cv: Any) -> bool:
    return (isinstance(cv, dict) and cv.get("type") == "budget_alloc" and _finite(cv.get("limit")) and cv["limit"] >= 0)


def describe_caveat(cv: Any) -> str:
    """A bounded, human-readable rendering of one caveat."""
    if not isinstance(cv, dict) or not isinstance(cv.get("type"), str):
        return "(malformed caveat)"
    if cv["type"] == "envelope":
        preds, inner = cv.get("predicates"), cv.get("caveats")
        return "policy envelope (%d predicate(s), %d caveat(s))" % (len(preds) if isinstance(preds, list) else 0, len(inner) if isinstance(inner, list) else 0)
    if _is_budget_alloc(cv):
        return "budget allocation ≤ %s" % _numstr(cv["limit"])
    parts: List[str] = []
    for k in _js_keys(cv)[:8]:
        if k == "type":
            continue
        v = cv[k]
        parts.append("%s=%s" % (k, _stringify(v) if isinstance(v, (dict, list)) else _numstr(v)))
    return "%s(%s)" % (cv["type"], ", ".join(parts)) if parts else cv["type"]


def build_delegation_hops(chain: Any) -> List[Dict[str, Any]]:
    """The delegation hops: issuer -> holder and the caveats each hop ADDED (append-only diff against its parent)."""
    safe = chain if isinstance(chain, list) else []
    hops: List[Dict[str, Any]] = []
    for i, cap in enumerate(safe):
        if not _truthy(cap):
            continue
        is_root = i == 0
        parent = safe[i - 1] if i > 0 else None
        pcv = _own(parent, "caveats") if _truthy(parent) else _UNDEF
        parent_len = len(pcv) if isinstance(pcv, list) else 0
        own_cv = _own(cap, "caveats")
        own = own_cv if isinstance(own_cv, list) else []
        added = own if is_root else (own[parent_len:] if len(own) >= parent_len else [])
        scope = [describe_caveat(c) for c in added]
        budget_cv = next((c for c in added if _is_budget_alloc(c)), None)
        issuer, holder = _own(cap, "issuer"), _own(cap, "holder")
        joined = "; ".join(scope)
        if is_root:
            narrative = "Principal %s granted authority to %s%s." % (_short(issuer), _short(holder), (" under: " + joined) if scope else "")
        else:
            narrative = "%s delegated to %s%s." % (_short(issuer), _short(holder), (", narrowing scope: " + joined) if scope else " (rebind only, no new constraints)")
        hop: Dict[str, Any] = {"index": i, "isRoot": is_root, "scope": scope, "caveats": added, "narrative": narrative}
        if issuer is not _UNDEF:
            hop["issuer"] = issuer
        if holder is not _UNDEF:
            hop["holder"] = holder
        if budget_cv is not None:
            hop["budgetAlloc"] = budget_cv["limit"]
        hops.append(hop)
    return hops


def build_human_override(threshold: Any, required_tier: Any, threshold_check: Any) -> Optional[Dict[str, Any]]:
    """The signed co-signature (human override) of a PCActn's threshold signature, if any."""
    sh = _own(threshold, "shares") if _truthy(threshold) else _UNDEF
    shares = sh if isinstance(sh, list) else []
    if len(shares) == 0:
        return None
    # `threshold` is outside the signed body: never report a signed approval (or name approvers) from unverified shares.
    if threshold_check != "pass":
        return {"humanApproved": False, "approvers": [], "guardianCosigners": [], "roles": [], "requiredTier": required_tier,
                "narrative": "%d co-signature share(s) were presented but NOT verified (threshold check: %s); no human approval is recorded."
                             % (len(shares), "absent" if _nullish(threshold_check) else _tpl(threshold_check))}
    approvers: List[Any] = []
    guardians: List[Any] = []
    roles: List[Any] = []
    for s in shares:
        if not _truthy(s) or not isinstance(_own(s, "role"), str):
            continue
        roles.append(s["role"])
        pk = s.get("publicKey")
        if s["role"] == "principal" and isinstance(pk, str):
            approvers.append(pk)
        if s["role"] == "guardian" and isinstance(pk, str):
            guardians.append(pk)
    approved = len(approvers) > 0
    if approved:
        narrative = "Step-up approved by a signed human co-signature from principal %s%s at tier t=%s." % (
            _short(approvers[0]), (" (plus %d guardian co-sign)" % len(guardians)) if guardians else "", _tpl(required_tier))
    else:
        narrative = "Co-signed by %d guardian share(s) at tier t=%s (no human principal signature present)." % (len(guardians), _tpl(required_tier))
    return {"humanApproved": approved, "approvers": approvers, "guardianCosigners": guardians, "roles": roles, "requiredTier": required_tier,
            "narrative": narrative}


def _first_reason_or(decision: Any, fallback: str) -> Any:
    rs = _own(decision, "reasons")
    rs = rs if isinstance(rs, list) else []
    return rs[0] if len(rs) > 0 and isinstance(rs[0], str) else fallback


def resolve_outcome(verify: Any, decision: Any) -> Dict[str, Any]:
    """The auditor-facing outcome from the proof's verification and the Policy-VM decision."""
    if not _truthy(verify) or _own(verify, "allow") is not True:
        r = _qprop(verify, "reason")
        return {"outcome": "deny", "reason": "proof failed verification" if _nullish(r) else r}
    if not _truthy(decision):
        return {"outcome": "allow", "reason": "proof verified; no policy decision supplied"}
    if _truthy(_own(decision, "admit")):
        return {"outcome": "allow", "reason": _first_reason_or(decision, "auto-admitted within policy and budget")}
    if _truthy(_own(decision, "releaseGuardianShare")):
        return {"outcome": "step-up", "reason": _first_reason_or(decision, "policy satisfied but a co-signature is required")}
    return {"outcome": "deny", "reason": _first_reason_or(decision, "policy did not release authority (default-deny)")}


def _safe_digest(p: Any) -> str:
    if p is _UNDEF:
        return "(undigestible)"
    try:
        return hash_canonical(p)
    except Exception:  # noqa: BLE001
        return "(undigestible)"


def to_audit_event(inp: Any) -> Dict[str, Any]:
    """A normalized AuditEvent from a PCActn, the core verifier's result and the Policy-VM decision. `inp` is
    ``{pcactn, verify, decision?, now?, session?}``; `now` (epoch ms) defaults to the clock."""
    p = _prop(inp, "pcactn")
    verify = _own(inp, "verify")
    if _nullish(verify):
        verify = {"allow": False, "checks": {}}
    decision = _own(inp, "decision")
    now = _own(inp, "now")
    if _nullish(now):
        now = _now_ms()
    cc = _qprop(p, "cap_chain")
    chain = cc if isinstance(cc, list) else None
    hops = build_delegation_hops(chain)
    leaf = chain[-1] if chain is not None and len(chain) > 0 else _UNDEF
    root = chain[0] if chain is not None and len(chain) > 0 else _UNDEF
    res = resolve_outcome(verify, decision)
    outcome, reason = res["outcome"], res["reason"]
    tier = _qprop(_qprop(decision, "requiredThreshold"), "t")
    required_tier = 1 if _nullish(tier) else tier
    checks_raw = _own(verify, "checks")
    human = build_human_override(_qprop(p, "threshold"), required_tier, _qprop(checks_raw, "threshold"))
    checks = {} if _nullish(checks_raw) else checks_raw
    crypto_ok = _own(checks, "wire") == "pass" and _own(checks, "leaf_signature") == "pass"

    action = _qprop(p, "action")
    verb_v, res_v = _qprop(action, "verb"), _qprop(action, "resource")
    verb = verb_v if isinstance(verb_v, str) else "(unknown verb)"
    resource = res_v if isinstance(res_v, str) else "(unknown resource)"
    gr = _qprop(p, "grant_ref")
    grant_ref = gr if isinstance(gr, str) else "(none)"
    sig, alg, plan_root = _qprop(p, "sig"), _qprop(p, "alg"), _qprop(_qprop(p, "plan"), "root")
    pd, counter, nonce = _qprop(action, "params_digest"), _qprop(p, "counter"), _qprop(p, "nonce")
    evidence: Dict[str, Any] = {
        "pcactnDigest": _safe_digest(p),
        "leafSignature": sig if isinstance(sig, str) else "(unsigned)",
        "signatureSuite": alg if isinstance(alg, str) else "ed25519",
        "planRoot": plan_root if isinstance(plan_root, str) else "(none)",
        "paramsDigest": pd if isinstance(pd, str) else "(none)",
        "grantRef": grant_ref,
        "counter": counter if _is_num(counter) else -1,
        "cryptographicallyVerifiable": crypto_ok,
    }
    if isinstance(nonce, str):
        evidence["nonce"] = nonce

    risk: Dict[str, Any] = {}
    if _truthy(decision):
        rt = _own(decision, "requiredThreshold")
        for key, val in (("r", _own(decision, "r")), ("tier", _qprop(rt, "t")), ("proof", _qprop(rt, "proof")), ("budget", _own(decision, "budget"))):
            if val is not _UNDEF:
                risk[key] = val

    word = "ALLOWED" if outcome == "allow" else "DENIED" if outcome == "deny" else "STEP-UP"
    narrative = ("Agent %s %s to %s on %s (%d-hop chain rooted at principal %s; %s%s). %s" % (
        _short(_qprop(leaf, "holder")), word, verb, resource, len(hops), _short(_qprop(root, "issuer")),
        "cryptographically verifiable proof" if crypto_ok else "proof not cryptographically verifiable",
        "; human-signed step-up" if human is not None and human["humanApproved"] else "", _tpl(reason)))

    holder = _qprop(leaf, "holder")
    principal = _qprop(root, "issuer")
    sess = _own(inp, "session")
    rc = _qprop(action, "reversibility_class")
    iat, exp = _qprop(p, "iat"), _qprop(p, "exp")
    agent: Dict[str, Any] = {"holder": holder if isinstance(holder, str) else "(none)", "session": grant_ref if _nullish(sess) else sess}
    if isinstance(principal, str):
        agent["principal"] = principal
    event: Dict[str, Any] = {
        "schema": "atlas-pca/audit-event/v1",
        "recordedAt": _ts(now),
        "agent": agent,
        "delegation": {"depth": max(0, len(hops) - 1), "hops": hops},
        "action": {"verb": verb, "resource": resource, "paramsDigest": evidence["paramsDigest"],
                   "reversibilityClass": rc if isinstance(rc, str) else "(unknown)", "summary": "%s on %s" % (verb, resource)},
        "decision": {"outcome": outcome, "reason": reason, "proofVerified": _own(verify, "allow") is True, "checks": checks},
        "risk": risk,
        "timestamps": {"issuedAt": _ts(iat if _is_num(iat) else math.nan), "expiresAt": _ts(exp if _is_num(exp) else math.nan)},
        "evidence": evidence,
        "narrative": narrative,
    }
    if human is not None:
        event["humanOverride"] = human
    return event


# ---- control mappings -------------------------------------------------------------------------------------------------

CONTROL_MAPPINGS = [
    {
        'framework': 'eu-ai-act',
        'controlId': 'eu-ai-act:art-12',
        'controlTitle': 'Record-keeping — automatic, traceable logging of events',
        'clause': 'EU AI Act, Article 12',
        'requirement': 'High-risk AI systems must automatically record events ("logs") over their lifetime, enabling traceability of the system\'s functioning.',
        'pcaEvidence': 'Every action is a signed PCActn; each log entry CITES its proof (the PCActn digest + the verifying leaf signature), so the record is tamper-evident and cannot be back-dated or fabricated.',
        'evidenceFields': ['evidence.pcactnDigest', 'evidence.leafSignature', 'evidence.cryptographicallyVerifiable', 'timestamps.issuedAt'],
    },
    {
        'framework': 'eu-ai-act',
        'controlId': 'eu-ai-act:art-50',
        'controlTitle': 'Transparency — disclosure of automated decisions and the acting agent',
        'clause': 'EU AI Act, Article 50',
        'requirement': 'Providers/deployers must ensure natural persons are informed that they are interacting with / affected by an AI system; interactions and automated decisions must be disclosed.',
        'pcaEvidence': 'Each entry discloses the acting AGENT identity (leaf holder), the PRINCIPAL it acts for (root issuer), the exact action, and the automated decision outcome + reason — a complete, attributable disclosure per action.',
        'evidenceFields': ['agent.holder', 'agent.principal', 'action.summary', 'decision.outcome', 'decision.reason'],
    },
    {
        'framework': 'iso-42001',
        'controlId': 'iso-42001:A.6.2.8',
        'controlTitle': 'Reasoning trace — AI system event logging',
        'clause': 'ISO/IEC 42001 Annex A.6.2.8 (AI system event logs / recording)',
        'requirement': 'The organization shall record events produced by the AI system so that its decisions can be examined and explained after the fact.',
        'pcaEvidence': 'Each entry carries the Policy-VM decision with its decisive reason, the risk score r, the required tier and the trust-budget state — a complete, machine-checked reasoning trace, not a free-text note.',
        'evidenceFields': ['decision.reason', 'risk.r', 'risk.tier', 'risk.budget', 'decision.checks'],
    },
    {
        'framework': 'iso-42001',
        'controlId': 'iso-42001:A.9.2',
        'controlTitle': 'Delegation & authorization chain',
        'clause': 'ISO/IEC 42001 Annex A.9.2 (authorization / responsible use of AI systems)',
        'requirement': 'Use of the AI system must be authorized; the authority under which an automated action is taken must be identifiable and bounded.',
        'pcaEvidence': 'The delegation chain is EXPLICIT: each hop records issuer → holder and the scope (caveats) it narrowed, rooted at the principal — authority is attenuated and provable, never ambient.',
        'evidenceFields': ['delegation.hops', 'delegation.depth', 'agent.principal', 'delegation.hops[].scope'],
    },
    {
        'framework': 'iso-42001',
        'controlId': 'iso-42001:A.9.3',
        'controlTitle': 'Human oversight of AI systems',
        'clause': 'ISO/IEC 42001 Annex A.9.3 (human oversight)',
        'requirement': 'Mechanisms for human oversight of the AI system must exist and be exercised for higher-impact decisions.',
        'pcaEvidence': 'Human oversight is a SIGNED CO-SIGNATURE: a step-up is approved by a principal threshold share naming the human approver (cryptographic, not a free-text "approved by"); denials and step-up requirements show the oversight boundary being enforced.',
        'evidenceFields': ['humanOverride.humanApproved', 'humanOverride.approvers', 'decision.outcome', 'risk.tier'],
    },
    {
        'framework': 'iso-42001',
        'controlId': 'iso-42001:A.6.2.2',
        'controlTitle': 'Intended use — action bound to a committed plan',
        'clause': 'ISO/IEC 42001 Annex A.6.2.2 (AI system requirements / intended purpose)',
        'requirement': 'The AI system must operate within its intended purpose; actions outside the specified scope must be prevented.',
        'pcaEvidence': 'Every action proves inclusion in a committed plan (the signed plan root): an off-plan action fails verification. The plan root in each entry binds the action to its intended, pre-committed purpose.',
        'evidenceFields': ['evidence.planRoot', 'action.verb', 'action.resource', 'decision.checks'],
    },
    {
        'framework': 'soc2',
        'controlId': 'soc2:CC6.1',
        'controlTitle': 'Logical access security — least privilege',
        'clause': 'SOC 2 CC6.1',
        'requirement': 'The entity implements logical access controls to protect against unauthorized access, enforcing least privilege.',
        'pcaEvidence': 'Access is deny-by-default: actions are constrained by signed predicates and capability attenuation. Denied entries evidence the control actively refusing out-of-scope access.',
        'evidenceFields': ['decision.outcome', 'delegation.hops[].scope', 'decision.checks', 'evidence.cryptographicallyVerifiable'],
    },
    {
        'framework': 'soc2',
        'controlId': 'soc2:CC6.2',
        'controlTitle': 'Registration & authorization of credentials / identities',
        'clause': 'SOC 2 CC6.2',
        'requirement': 'Prior to issuing access, the entity registers and authorizes new identities; access is traceable to an authorizing principal.',
        'pcaEvidence': 'Each agent identity (leaf holder) is bound into a delegation chain rooted at an authorizing principal, with every hop signed — access is always traceable to who authorized it.',
        'evidenceFields': ['agent.principal', 'agent.holder', 'delegation.hops', 'evidence.grantRef'],
    },
    {
        'framework': 'soc2',
        'controlId': 'soc2:CC6.3',
        'controlTitle': 'Access modification & removal (attenuation / revocation)',
        'clause': 'SOC 2 CC6.3',
        'requirement': 'The entity modifies and removes access based on roles/need; access rights are narrowed or withdrawn appropriately.',
        'pcaEvidence': 'Delegation is append-only attenuation: a child hop can only narrow scope, never widen it. Narrowing caveats per hop (and denied actions) evidence access being bounded and withdrawn.',
        'evidenceFields': ['delegation.hops[].scope', 'delegation.hops[].budgetAlloc', 'decision.outcome'],
    },
]


def _assert_framework(framework: Any) -> None:
    if not (isinstance(framework, str) and framework in COMPLIANCE_FRAMEWORKS):
        raise ValueError("pca-compliance: unknown framework '%s' (have: %s)" % (_tpl(framework), ", ".join(COMPLIANCE_FRAMEWORKS)))


def control_mappings(framework: Any = _UNSET) -> List[Dict[str, Any]]:
    """The control mappings for a framework (the whole table when none is given)."""
    if framework is _UNSET:
        return list(CONTROL_MAPPINGS)
    _assert_framework(framework)
    return [m for m in CONTROL_MAPPINGS if m["framework"] == framework]


# ---- ComplianceReport -------------------------------------------------------------------------------------------------

def _compute_stats(events: List[Any]) -> Dict[str, Any]:
    agents, principals = _JsSet(), _JsSet()
    sample: Any = _UNDEF
    verifiable = denied = step_up = allowed = human = with_chain = with_plan = 0
    max_depth: Any = 0
    for e in events:
        if not _truthy(e):
            continue
        if _truthy(_prop(_prop(e, "evidence"), "cryptographicallyVerifiable")):
            verifiable += 1
        outcome = _prop(_prop(e, "decision"), "outcome")
        if outcome == "deny":
            denied += 1
        elif outcome == "step-up":
            step_up += 1
        else:
            allowed += 1
        if _truthy(_qprop(_own(e, "humanOverride"), "humanApproved")):
            human += 1
        hops_len = _length(_prop(_prop(e, "delegation"), "hops"))
        if hops_len is not _UNDEF and hops_len > 0:
            with_chain += 1
        if _prop(_prop(e, "evidence"), "planRoot") != "(none)":
            with_plan += 1
        depth = _prop(_prop(e, "delegation"), "depth")
        if _gt(depth, max_depth):
            max_depth = depth
        agents.add(_prop(_prop(e, "agent"), "holder"))
        principal = _prop(_prop(e, "agent"), "principal")
        if principal is not _UNDEF:
            principals.add(principal)
        digest = _prop(_prop(e, "evidence"), "pcactnDigest")
        if sample is _UNDEF and digest != "(undigestible)":
            sample = digest
    return {"total": len(events), "verifiable": verifiable, "denied": denied, "stepUp": step_up, "allowed": allowed, "humanOverrides": human,
            "withChain": with_chain, "withPlanRoot": with_plan, "maxDepth": max_depth, "agents": agents.size, "principals": principals.size,
            "sampleDigest": sample}


def _evaluate_control(control_id: str, s: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[str] = []
    total = s["total"]
    digest_note = "" if s["sampleDigest"] is _UNDEF else " (e.g. %s)" % _short(s["sampleDigest"], 16)
    if total == 0:
        return {"status": "not-evidenced", "evidence": "no actions in the reporting period", "findings": ["no events supplied — nothing to evidence"]}
    if control_id == "eu-ai-act:art-12":
        status = "satisfied" if s["verifiable"] == total else "partial"
        if s["verifiable"] < total:
            findings.append("%d of %d entries are not cryptographically verifiable" % (total - s["verifiable"], total))
        return {"status": status, "evidence": "%d actions logged; %d/%d cite a cryptographically verifiable proof%s" % (total, s["verifiable"], total, digest_note),
                "findings": findings}
    if control_id == "eu-ai-act:art-50":
        return {"status": "satisfied", "evidence": "%d actions each disclose the acting agent, the principal (%d distinct) and the automated decision outcome" % (total, s["principals"]),
                "findings": findings}
    if control_id == "iso-42001:A.6.2.8":
        return {"status": "satisfied", "evidence": "%d actions each carry a decision reason + risk/tier/budget reasoning trace" % total, "findings": findings}
    if control_id == "iso-42001:A.9.2":
        wc = s["withChain"]
        status = "satisfied" if wc == total else "partial" if wc > 0 else "not-evidenced"
        if wc < total:
            findings.append("%d entries have no delegation chain" % (total - wc))
        return {"status": status, "evidence": "%d/%d actions carry an explicit delegation chain (max depth %s, %d authorizing principal(s))" % (wc, total, _tpl(s["maxDepth"]), s["principals"]),
                "findings": findings}
    if control_id == "iso-42001:A.9.3":
        if s["humanOverrides"] > 0:
            status = "satisfied"
            evidence = "%d step-up(s) approved by a signed human co-signature; %d step-up(s) and %d denial(s) show oversight enforced" % (s["humanOverrides"], s["stepUp"], s["denied"])
        elif s["stepUp"] > 0 or s["denied"] > 0:
            status = "partial"
            evidence = "oversight boundary enforced (%d step-up(s), %d denial(s)) but no signed human co-signature observed in the period" % (s["stepUp"], s["denied"])
            findings.append("no human step-up co-signature was exercised in this period")
        else:
            status = "partial"
            evidence = "all actions were auto-admitted within policy; no oversight event was triggered in the period"
            findings.append("no higher-impact action required human oversight in this period")
        return {"status": status, "evidence": evidence, "findings": findings}
    if control_id == "iso-42001:A.6.2.2":
        wp = s["withPlanRoot"]
        status = "satisfied" if wp == total else "partial" if wp > 0 else "not-evidenced"
        if wp < total:
            findings.append("%d entries are not bound to a committed plan root" % (total - wp))
        return {"status": status, "evidence": "%d/%d actions are bound to a committed plan root (intended-use binding)" % (wp, total), "findings": findings}
    if control_id == "soc2:CC6.1":
        if s["denied"] > 0:
            findings.append("%d out-of-scope action(s) denied — access control actively enforced" % s["denied"])
        return {"status": "satisfied", "evidence": "deny-by-default access over %d actions (%d allowed, %d step-up, %d denied); all gated by signed predicates + attenuation"
                % (total, s["allowed"], s["stepUp"], s["denied"]), "findings": findings}
    if control_id == "soc2:CC6.2":
        wc = s["withChain"]
        status = "satisfied" if wc == total else "partial" if wc > 0 else "not-evidenced"
        if wc < total:
            findings.append("%d entries are not traceable to an authorizing principal" % (total - wc))
        return {"status": status, "evidence": "%d agent identit(ies) traceable to %d authorizing principal(s) via signed delegation chains" % (s["agents"], s["principals"]),
                "findings": findings}
    if control_id == "soc2:CC6.3":
        narrowed = _num(s["maxDepth"]) >= 1
        status = "satisfied" if narrowed or s["denied"] > 0 else "partial"
        if not narrowed and s["denied"] == 0:
            findings.append("no attenuating hop or denial observed in the period")
        return {"status": status, "evidence": "access narrowed by attenuation (max delegation depth %s) and %d denied action(s)" % (_tpl(s["maxDepth"]), s["denied"]),
                "findings": findings}
    return {"status": "not-evidenced", "evidence": "no evaluator for this control", "findings": ["unmapped control"]}


def to_compliance_report(events: Any, opts: Any) -> Dict[str, Any]:
    """A structured ComplianceReport for `opts["framework"]` from AuditEvents: per-control status + evidence, the PCA-unique
    assurances and a coverage summary. `opts["now"]` (epoch ms) defaults to the clock."""
    framework = _prop(opts, "framework")
    _assert_framework(framework)
    lst = [e for e in events if _truthy(e)] if isinstance(events, list) else []
    now = _own(opts, "now")
    if _nullish(now):
        now = _now_ms()
    s = _compute_stats(lst)
    items = []
    for m in CONTROL_MAPPINGS:
        if m["framework"] != framework:
            continue
        r = _evaluate_control(m["controlId"], s)
        items.append({"controlId": m["controlId"], "controlTitle": m["controlTitle"], "clause": m["clause"], "framework": m["framework"],
                      "status": r["status"], "pcaEvidence": m["pcaEvidence"], "evidence": r["evidence"], "findings": r["findings"]})
    satisfied = len([i for i in items if i["status"] == "satisfied"])
    partial = len([i for i in items if i["status"] == "partial"])
    not_evidenced = len([i for i in items if i["status"] == "not-evidenced"])
    total = len(items)
    fraction = satisfied / total if total > 0 else 0
    iats = [x for x in (_prop(_prop(_prop(e, "timestamps"), "issuedAt"), "epochMs") for e in lst) if _finite(x)]
    frm = min(iats) if iats else 0
    to = max(iats) if iats else 0
    st = s["total"]
    assurances = {
        "cryptographicallyVerifiable": st > 0 and s["verifiable"] == st,
        "explicitDelegationChain": st > 0 and s["withChain"] == st,
        "signedHumanOverrides": s["humanOverrides"] > 0,
        "narrative": "No events in scope." if st == 0 else
        "%d/%d entries cite a cryptographically verifiable proof; %d/%d carry an explicit delegation chain; %d step-up(s) carry a signed human co-signature."
        % (s["verifiable"], st, s["withChain"], st, s["humanOverrides"]),
    }
    summary = "%s: %d/%d controls satisfied%s%s over %d action(s)." % (
        framework, satisfied, total, (", %d partial" % partial) if partial > 0 else "", (", %d not evidenced" % not_evidenced) if not_evidenced > 0 else "", st)
    return {
        "schema": "atlas-pca/compliance-report/v1",
        "framework": framework,
        "generatedAt": _ts(now),
        "period": {"from": _ts(frm), "to": _ts(to)},
        "eventCount": st,
        "assurances": assurances,
        "items": items,
        "coverage": {"total": total, "satisfied": satisfied, "partial": partial, "notEvidenced": not_evidenced, "satisfiedFraction": fraction,
                     "satisfiedPercent": _js_round(fraction * 100)},
        "summary": summary,
    }


# ---- renderers --------------------------------------------------------------------------------------------------------

_STATUS_GLYPH = {"satisfied": "✓", "partial": "◐", "not-evidenced": "·"}


def render_json(report: Any) -> str:
    """The report as stable, pretty JSON (`JSON.stringify(report, null, 2)`)."""
    return _pretty(report)


def _upper(v: Any) -> str:
    if not isinstance(v, str):
        raise TypeError("toUpperCase is not a function")
    return v.upper()


def _glyph(status: Any) -> str:
    return _STATUS_GLYPH[status] if isinstance(status, str) and status in _STATUS_GLYPH else "undefined"


def render_markdown(report: Any) -> str:
    """The report as an auditor-facing Markdown document (admissibility assurances, coverage, control table and detail)."""
    r = report
    g = lambda *path: _walk(r, path)  # noqa: E731
    lines: List[str] = []
    lines.append("# PCA compliance evidence — %s" % _tpl(g("framework")))
    lines.append("")
    lines.append("Generated %s · %s action(s) · coverage: %s/%s satisfied (%s%%)" % (
        _tpl(g("generatedAt", "iso")), _tpl(g("eventCount")), _tpl(g("coverage", "satisfied")), _tpl(g("coverage", "total")), _tpl(g("coverage", "satisfiedPercent"))))
    if _gt(g("eventCount"), 0):
        lines.append("")
        lines.append("Reporting period: %s → %s" % (_tpl(g("period", "from", "iso")), _tpl(g("period", "to", "iso"))))
    lines.append("")
    lines.append("## Why this trail is admissible (what PCA uniquely provides)")
    lines.append("")
    lines.append("- **Cryptographically verifiable** — %s: every log entry cites its proof (the PCActn digest + the verifying leaf signature), so it is tamper-evident and cannot be back-dated."
                 % ("YES" if _truthy(g("assurances", "cryptographicallyVerifiable")) else "PARTIAL"))
    lines.append("- **Explicit delegation chain** — %s: each action records who authorized what scope, hop by hop, rooted at a principal."
                 % ("YES" if _truthy(g("assurances", "explicitDelegationChain")) else "PARTIAL"))
    lines.append("- **Signed human-overrides** — %s: a step-up approval is a principal threshold co-signature naming the human approver, not a free-text note."
                 % ("YES" if _truthy(g("assurances", "signedHumanOverrides")) else "none in period"))
    lines.append("")
    lines.append("> %s" % _tpl(g("assurances", "narrative")))
    lines.append("")
    lines.append("## Coverage summary")
    lines.append("")
    lines.append("| Satisfied | Partial | Not evidenced | Total |")
    lines.append("| --- | --- | --- | --- |")
    lines.append("| %s | %s | %s | %s |" % (_tpl(g("coverage", "satisfied")), _tpl(g("coverage", "partial")), _tpl(g("coverage", "notEvidenced")), _tpl(g("coverage", "total"))))
    lines.append("")
    lines.append("## Controls")
    lines.append("")
    lines.append("| Control | Clause | Status | Evidence in period |")
    lines.append("| --- | --- | --- | --- |")
    items = g("items")
    if not isinstance(items, list):
        raise TypeError("items is not iterable")
    for i in items:
        lines.append("| %s (`%s`) | %s | %s %s | %s |" % (_tpl(_prop(i, "controlTitle")), _tpl(_prop(i, "controlId")), _tpl(_prop(i, "clause")),
                                                       _glyph(_prop(i, "status")), _upper(_prop(i, "status")), _tpl(_prop(i, "evidence"))))
    lines.append("")
    lines.append("## Control detail")
    lines.append("")
    for i in items:
        lines.append("### %s — %s" % (_tpl(_prop(i, "controlId")), _tpl(_prop(i, "controlTitle"))))
        lines.append("")
        lines.append("- Clause: %s" % _tpl(_prop(i, "clause")))
        lines.append("- Status: %s %s" % (_glyph(_prop(i, "status")), _upper(_prop(i, "status"))))
        lines.append("- PCA evidence basis: %s" % _tpl(_prop(i, "pcaEvidence")))
        lines.append("- Evidence in period: %s" % _tpl(_prop(i, "evidence")))
        n = _length(_prop(i, "findings"))
        if n is not _UNDEF and n > 0:
            lines.append("- Findings:")
            for f in _prop(i, "findings"):
                lines.append("  - %s" % _tpl(f))
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("_Evidence mapping, not a legal certification: a `satisfied` status means the cryptographic evidence the control asks for is present in the supplied records._")
    return "\n".join(lines)


def _walk(o: Any, path: Any) -> Any:
    for k in path:
        o = _prop(o, k)
    return o


# ---- framework report (console activity stream) ------------------------------------------------------------------------

_FRAMEWORK_IDS = ("eu-ai-act", "soc2", "gdpr")


def _safety_bound(p: Any) -> Any:
    kappa, b_max = _prop(p, "kappa"), _prop(p, "bMax")
    if not _gt(kappa, 0):
        return 0
    b = _num(b_max)
    return (math.nan if b != b else max(0.0, b)) / _num(kappa)


def _base_summary(inp: Any) -> Dict[str, Any]:
    events = _prop(inp, "events")
    if not isinstance(events, list):
        raise TypeError("e.filter is not a function")
    p = _prop(_prop(inp, "policy"), "riskPolicy")
    decisions = _qprop(inp, "decisions")
    dlen = 0 if _nullish(decisions) else _length(decisions)
    taint = 0.0
    for x in events:
        t = _prop(x, "taint")
        v = 0.0 if t is _UNDEF else (float(t) if _finite(t) else math.inf)
        taint = max(taint, v)
    agents = _JsSet()
    for x in events:
        agents.add(_prop(x, "agent"))
    return {
        "totalActions": len(events),
        "autonomous": len([x for x in events if _prop(x, "outcome") in ("auto", "executed")]),
        "humanOverseen": len([x for x in events if _prop(x, "outcome") == "step_up"]) + (0 if dlen is _UNDEF else dlen),
        "denied": len([x for x in events if _prop(x, "outcome") == "deny"]),
        "attributableAgents": agents.size,
        "autonomousBound": _safety_bound(p) * _num(_prop(p, "kappa")),
        "maxTaintObserved": taint,
    }


def _period(events: List[Any]) -> Dict[str, Any]:
    ats = [a for a in (_prop(e, "at") for e in events) if _finite(a)]
    return {"from": min(ats) if ats else 0, "to": max(ats) if ats else 0}


def _ctl(cid: str, name: str, status: str, evidence: str) -> Dict[str, Any]:
    return {"id": cid, "name": name, "status": status, "evidence": evidence}


def _eu_ai_act_controls(inp: Any, s: Dict[str, Any]) -> List[Dict[str, Any]]:
    logged = s["totalActions"] > 0
    bound = s["autonomousBound"]
    oversight = s["humanOverseen"] > 0 or _finite(bound)
    goal = _truthy(_own(inp, "hasGoalCommitment"))
    return [
        _ctl("art12-record-keeping", "Automatic logging of events", "pass" if logged else "warn", "%d attributable actions recorded" % s["totalActions"]),
        _ctl("art14-human-oversight", "Human oversight", "pass" if oversight else "warn", "%d human-reviewed actions; autonomous bound %s" % (s["humanOverseen"], _num_str(bound))),
        _ctl("art15-robustness", "Bounded autonomy (accuracy/robustness)", "pass" if _finite(bound) else "fail", "machine-checked safety bound = %s between human co-signs" % _num_str(bound)),
        _ctl("art13-transparency", "Transparency / traceability", "pass" if goal else "warn",
             "every action binds to a signed goal commitment (lineage)" if goal else "no goal commitment supplied"),
    ]


def _soc2_controls(inp: Any, s: Dict[str, Any]) -> List[Dict[str, Any]]:
    preds = _qprop(_own(inp, "policy"), "predicates")
    constrained = isinstance(preds, list) and len(preds) > 0
    return [
        _ctl("cc6.1-access", "Logical access — least privilege", "pass" if constrained else "warn",
             "actions constrained by signed predicates + capability attenuation (deny by default)" if constrained else "the supplied policy lists no predicates"),
        _ctl("cc7.2-monitoring", "Monitoring of anomalies", "pass" if s["totalActions"] > 0 else "warn", "%d denied + %d escalated actions captured" % (s["denied"], s["humanOverseen"])),
        _ctl("cc7.3-audit-trail", "Audit trail", "pass" if s["totalActions"] > 0 else "warn", "%d content-addressed actions across %d agents" % (s["totalActions"], s["attributableAgents"])),
        _ctl("cc8.1-change", "Change management (policy integrity)", "pass" if constrained else "warn",
             "policy is signed into the grant; tampering breaks verification" if constrained else "the supplied policy lists no predicates"),
    ]


def _gdpr_controls(inp: Any, s: Dict[str, Any]) -> List[Dict[str, Any]]:
    goal = _truthy(_own(inp, "hasGoalCommitment"))
    erasure = _truthy(_own(inp, "erasureSupported"))
    return [
        _ctl("art5-purpose", "Purpose limitation", "pass" if goal else "warn", "actions bound to a committed goal/purpose" if goal else "no goal commitment supplied"),
        _ctl("art5-minimization", "Data minimisation", "pass" if s["totalActions"] > 0 else "warn", "taint-gated data flows; max taint observed = %s" % _num_str(s["maxTaintObserved"])),
        _ctl("art5-accountability", "Accountability", "pass" if s["attributableAgents"] > 0 else "warn", "%d attributable agent identities" % s["attributableAgents"]),
        _ctl("art17-erasure", "Right to erasure", "pass" if erasure else "warn", "erasure path wired" if erasure else "erasure path not asserted"),
    ]


_BUILDERS = {"eu-ai-act": _eu_ai_act_controls, "soc2": _soc2_controls, "gdpr": _gdpr_controls}


def framework_report(framework: Any, inp: Any, now: Any = _UNSET) -> Dict[str, Any]:
    """A compliance evidence report for a framework from the console activity stream: ``inp`` is
    ``{policy, events, decisions?, hasGoalCommitment?, erasureSupported?}``. `now` (epoch ms) defaults to the clock when omitted."""
    summary = _base_summary(inp)
    if not (isinstance(framework, str) and framework in _FRAMEWORK_IDS):
        raise ValueError("frameworkReport: unknown framework '%s' (have: %s)" % (_tpl(framework), ", ".join(_FRAMEWORK_IDS)))
    controls = _BUILDERS[framework](inp, summary)
    return {"framework": framework, "generatedAt": _now_ms() if now is _UNSET else now, "period": _period(inp["events"]), "summary": summary,
            "controls": controls, "pass": all(c["status"] != "fail" for c in controls)}


def _date_iso(v: Any) -> str:
    """`new Date(v).toISOString()` for a number (null is the epoch); raises for an invalid time."""
    return _iso_string(0 if v is None else int(v) if isinstance(v, bool) else v)


def framework_report_to_markdown(r: Any) -> str:
    """A short Markdown block of a framework report, for an audit package."""
    summary = _prop(r, "summary")
    controls = _prop(r, "controls")
    if not isinstance(controls, list):
        raise TypeError("r.controls.map is not a function")
    lines = [
        "# PCA compliance evidence — %s" % _tpl(_prop(r, "framework")),
        "",
        "Generated %s · %s actions · %s agents · overall: %s" % (_date_iso(_prop(r, "generatedAt")), _tpl(_prop(summary, "totalActions")),
                                                              _tpl(_prop(summary, "attributableAgents")), "PASS" if _truthy(_prop(r, "pass")) else "FAIL"),
        "",
        "| Control | Status | Evidence |",
        "| --- | --- | --- |",
        *["| %s (%s) | %s | %s |" % (_tpl(_prop(c, "name")), _tpl(_prop(c, "id")), _upper(_prop(c, "status")), _tpl(_prop(c, "evidence"))) for c in controls],
        "",
        "_Evidence mapping, not a legal certification._",
    ]
    return "\n".join(lines)
