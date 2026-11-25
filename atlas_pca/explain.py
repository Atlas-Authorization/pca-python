"""Self-explaining PCA decisions: the verifier's per-check result, the Policy VM decision and a delegation chain become precise,
human-readable explanations plus renderers. Port of @atlasauth/pca-explain of the TypeScript reference.

Everything here is pure and read-only: it consumes the real shapes of the core (a PCActn, a verify result, a decision, a chain),
never re-authorizes anything, and degrades a malformed input to a best-effort explanation. Explanations are plain dicts with
exactly the members of the reference's explanation objects (an absent member is a JS `undefined`); the `*_to_text` functions
render them. Inputs are JSON values (dicts, lists, str, numbers, bools, None), and the reference's JavaScript value semantics
(String(x), JSON.stringify, Number(x), relational comparison, truthiness, property reads on any value) are reproduced where an
untrusted field reaches them, so a hostile shape produces the same text or the same refusal (an exception) as the reference.
`now` and the decision context use the reference's camelCase keys (`blastRadius`, `delegationDepth`, ...).
"""
from __future__ import annotations

import math
from ._fin import fin
import re
from typing import Any, Dict, List, Optional

from .authorize import evaluate_agent_caveats
from .pca import MAX_LIFETIME_MS, MAX_SKEW_MS, PCACTN_VERSION, hash_canonical, verify_chain
from .predicates import _UNDEF, _js_number_string, _js_string, evaluate_predicates
from .risk import cost as _budget_cost
from .sdjwt_jws import js_json

MAX_TEXT = 400
PCACTN_MAX_LIFETIME_MS = MAX_LIFETIME_MS
PCACTN_MAX_SKEW_MS = MAX_SKEW_MS

VERIFY_CHECK_ORDER = ["wire", "version", "audience", "validity", "cap_chain", "grant_ref_bound", "plan_inclusion", "leaf_signature",
                      "counter_format"]

CHECK_TITLE = {
    "wire": "wire format", "version": "version", "audience": "audience binding", "validity": "freshness window",
    "cap_chain": "capability chain", "grant_ref_bound": "grant reference binding", "plan_inclusion": "plan inclusion",
    "leaf_signature": "leaf signature", "counter_format": "counter format", "counter": "counter format", "replay": "replay",
    "plan_root_authorized": "plan-root authorization", "taint_gate": "taint gate", "attestation": "agent attestation",
    "threshold": "threshold signature", "revocation": "revocation", "zk_compliance": "zk compliance", "bond": "bond",
    "malformed": "structure",
}

_NAN = float("nan")
_OPTS = object()  # "argument omitted": the reference defaults it to {}, while an explicit null stays null

# ---- JavaScript value semantics --------------------------------------------------------------------------------------------

# JS \s / String.trim() whitespace
_WS = "\t\n\u000b\u000c\r       　﻿" + "".join(chr(c) for c in range(0x2000, 0x200B))
_WSC = "\t\n\u000b\u000c\r    -     　﻿"
_IDX = re.compile(r"(0|[1-9][0-9]*)")


def _len16(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _slice16(s: str, a: int, b: Optional[int] = None) -> str:
    u = s.encode("utf-16-le", "surrogatepass")
    return u[2 * a:(None if b is None else 2 * b)].decode("utf-16-le", "surrogatepass")


def _u16key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def _trim(s: str) -> str:
    return s.strip(_WS)


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _is_fin(v: Any) -> bool:
    return _is_num(v) and fin(v)


def _is_obj(v: Any) -> bool:
    return isinstance(v, (dict, list))


def _numstr(x: float) -> str:
    return _js_number_string(float(x))


def _truthy(v: Any) -> bool:
    if v is _UNDEF or v is None or v is False:
        return False
    if v is True:
        return True
    if _is_num(v):
        return not (v == 0 or v != v)
    if isinstance(v, str):
        return len(v) > 0
    return True


def _nn(a: Any, b: Any) -> Any:
    """`a ?? b`."""
    return b if a is None or a is _UNDEF else a


def _get(o: Any, k: str) -> Any:
    """`o[k]` without throwing: _UNDEF for an absent member or a value without members."""
    if isinstance(o, dict):
        return o[k] if k in o else _UNDEF
    if isinstance(o, list):
        if k == "length":
            return len(o)
        if _IDX.fullmatch(k) and int(k) < len(o):
            return o[int(k)]
        return _UNDEF
    if isinstance(o, str):
        if k == "length":
            return _len16(o)
        if _IDX.fullmatch(k) and int(k) < _len16(o):
            return _slice16(o, int(k), int(k) + 1)
    return _UNDEF


def _opt(o: Any, k: str) -> Any:
    """`o?.[k]`."""
    return _UNDEF if o is None or o is _UNDEF else _get(o, k)


def _rd(o: Any, k: str) -> Any:
    """`o[k]` where o must not be null or undefined (a TypeError otherwise)."""
    if o is None or o is _UNDEF:
        raise TypeError("cannot read '%s' of %s" % (k, "null" if o is None else "undefined"))
    return _get(o, k)


def _keys(o: Any) -> List[str]:
    """Object.keys: array-index keys ascending first, then the rest in insertion order."""
    if isinstance(o, dict):
        idx = sorted((k for k in o if isinstance(k, str) and _IDX.fullmatch(k) and int(k) < 4294967295), key=int)
        seen = set(idx)
        return idx + [k for k in o if k not in seen]
    if isinstance(o, list):
        return [str(i) for i in range(len(o))]
    if isinstance(o, str):
        return [str(i) for i in range(_len16(o))]
    return []


def _put(d: Dict[str, Any], k: str, v: Any) -> None:
    if v is not _UNDEF:
        d[k] = v


def _str_to_num(s: str) -> float:
    t = _trim(s)
    if t == "":
        return 0.0
    if t in ("Infinity", "+Infinity"):
        return math.inf
    if t == "-Infinity":
        return -math.inf
    m = re.fullmatch(r"0([xX][0-9a-fA-F]+|[bB][01]+|[oO][0-7]+)", t)
    if m:
        return float(int(t[2:], {"x": 16, "b": 2, "o": 8}[t[1].lower()]))
    if re.fullmatch(r"[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?", t):
        return float(t)
    return _NAN


def _to_num(v: Any) -> float:
    """Number(v) for a JSON value (an object is NaN, an array goes through its string form)."""
    if v is _UNDEF:
        return _NAN
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if _is_num(v):
        try:
            return float(v)
        except OverflowError:
            return math.inf if v > 0 else -math.inf
    if isinstance(v, str):
        return _str_to_num(v)
    if isinstance(v, list):
        return _str_to_num(_js_string(v))
    return _NAN


def _prim(v: Any) -> Any:
    return _js_string(v) if isinstance(v, list) else "[object Object]" if isinstance(v, dict) else v


def _lt(a: Any, b: Any) -> bool:
    """JS `a < b` (false when either side is NaN)."""
    a, b = _prim(a), _prim(b)
    if isinstance(a, str) and isinstance(b, str):
        return _u16key(a) < _u16key(b)
    return _to_num(a) < _to_num(b)


def _le(a: Any, b: Any) -> bool:
    a, b = _prim(a), _prim(b)
    if isinstance(a, str) and isinstance(b, str):
        return not _u16key(b) < _u16key(a)
    return _to_num(a) <= _to_num(b)


def _gt(a: Any, b: Any) -> bool:
    return _lt(b, a)


def _add(a: Any, n: int) -> Any:
    """JS `a + n` for a number n: a string or array on the left makes it a concatenation."""
    a = _prim(a)
    return a + str(n) if isinstance(a, str) else _to_num(a) + n


def _jstr(v: Any) -> str:
    """`${JSON.stringify(v)}`: undefined stringifies to the text "undefined"."""
    return "undefined" if v is _UNDEF else js_json(v)


def _iter(v: Any) -> List[Any]:
    """The values `for (const x of v)` visits: an array's items or a string's code points; anything else throws."""
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        return list(v)
    raise TypeError("not iterable")


def _slice_from(v: Any, n: int) -> Any:
    if isinstance(v, list):
        return v[n:]
    if isinstance(v, str):
        return _slice16(v, n)
    raise TypeError("slice is not a function")


def _pad_end(s: str, n: int) -> str:
    return s + " " * max(0, n - _len16(s))


# ---- cleanText -------------------------------------------------------------------------------------------------------------

_W = "A-Za-z0-9_"
_NB = "(?<![%s])" % _W  # JS \b in front of a word character
_FLAGS = re.IGNORECASE | re.ASCII
_RE_JWT = re.compile(_NB + r"eyJ[%s-]{5,}\.[%s-]{5,}\.[%s-]*" % (_W, _W, _W))
_RE_BEARER = re.compile(_NB + r"(Bearer|Basic|Token)[%s]+[%s.~+/=-]{6,}" % (_WSC, _W), _FLAGS)
_RE_USERINFO = re.compile(r"([a-z][a-z0-9+.-]*://)[^%s/@]*:[^%s/@]*@" % (_WSC, _WSC), _FLAGS)
_RE_PAIR = re.compile(
    _NB + r"""((?:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|authorization|auth)["']?[%s]*[:=][%s]*)("[^"]*"|'[^']*'|[^%s"'&,;]+)"""
    % (_WSC, _WSC, _WSC), _FLAGS)
_RE_RUN = re.compile(r"[%s-]{40,}" % _W)


def clean_text(text: Any) -> str:
    """Remove what looks like a credential from text built out of untrusted fields (JWTs, bearer credentials, URL userinfo,
    `token=` style pairs, long unbroken token runs); the result is cut to 400 characters. A net, not a proof."""
    t = _js_string(text)
    t = _RE_JWT.sub("[redacted]", t)
    t = _RE_BEARER.sub(lambda m: m.group(1) + " [redacted]", t)
    t = _RE_USERINFO.sub(lambda m: m.group(1) + "[redacted]@", t)
    t = _RE_PAIR.sub(lambda m: m.group(1) + "[redacted]", t)
    t = _RE_RUN.sub("[redacted]", t)
    return _slice16(t, 0, MAX_TEXT) + "..." if _len16(t) > MAX_TEXT else t


# ---- shared helpers --------------------------------------------------------------------------------------------------------

def _short(key: Any, n: int = 10) -> str:
    """Abbreviate a long b64u key for display: the first `n` characters and an ellipsis."""
    if not isinstance(key, str) or len(key) == 0:
        return "<none>"
    return key if _len16(key) <= n + 1 else _slice16(key, 0, n) + "…"


def _round_js(y: float) -> float:
    f = math.floor(y)
    return f + 1 if y - f >= 0.5 else f


def _num(x: Any) -> str:
    """Compact number: integers stay integers, fractions round to 4 dp; anything else prints as String(x)."""
    if not _is_fin(x):
        return _js_string(x)
    if float(x) == math.floor(x):
        return _numstr(x)
    return _numstr(_round_js(x * 1e4) / 1e4)


def _value_summary(rest: Dict[str, Any]) -> str:
    parts = []
    for k in _keys(rest)[:6]:
        v = rest[k]
        parts.append("%s=%s" % (k, js_json(v) if _is_obj(v) else _num(v)))
    return ", ".join(parts)


def _caveat_type(cv: Any) -> str:
    t = _opt(cv, "type")
    return t if isinstance(t, str) else "<malformed>"


def _caveat_rest(cv: Any) -> Dict[str, Any]:
    rest: Dict[str, Any] = {}
    if _is_obj(cv):
        for k in _keys(cv):
            if k != "type":
                rest[k] = _get(cv, k)
    return rest


def _cond_to_text(c: Any, depth: int = 0) -> str:
    if not _is_obj(c):
        return "<malformed>"
    if depth > 6:
        return "…"
    if isinstance(c, dict):
        if "all_of" in c and isinstance(c["all_of"], list):
            return "(" + " AND ".join(_cond_to_text(x, depth + 1) for x in c["all_of"]) + ")"
        if "any_of" in c and isinstance(c["any_of"], list):
            return "(" + " OR ".join(_cond_to_text(x, depth + 1) for x in c["any_of"]) + ")"
        if "not" in c:
            return "NOT " + _cond_to_text(c["not"], depth + 1)
    ref = _get(c, "ref")
    operand = "→" + _js_string(ref) if ref is not _UNDEF else _num(c["value"]) if isinstance(c, dict) and "value" in c else ""
    return _trim("%s %s %s" % (_js_string(_get(c, "field")), _js_string(_get(c, "op")), operand))


def _where_summary(where: Any) -> str:
    if not isinstance(where, list) or len(where) == 0:
        return "any (no where-bound)"
    return " AND ".join(_cond_to_text(c) for c in where)


# ---- explainVerification ---------------------------------------------------------------------------------------------------

def _reason_tail(name: str, verify_result: Any) -> Optional[str]:
    r = _get(verify_result, "reason")
    if not isinstance(r, str):
        return None
    pre = name + ": "
    return r[len(pre):] if r.startswith(pre) else None


def _validity_pinpoint(p: Any, now: Any) -> Dict[str, str]:
    exp, iat = _get(p, "exp"), _get(p, "iat")
    lifetime = _to_num(exp) - _to_num(iat)
    if not _gt(exp, iat):
        return {"detail": "exp %s ≤ iat %s: empty validity window" % (_js_string(exp), _js_string(iat)),
                "remedy": "set exp strictly greater than iat."}
    if lifetime > PCACTN_MAX_LIFETIME_MS:
        return {"detail": "lifetime %sms exceeds the %dms maximum" % (_numstr(lifetime), PCACTN_MAX_LIFETIME_MS),
                "remedy": "shorten the window to ≤ %dms (buildPCActn ttlMs)." % PCACTN_MAX_LIFETIME_MS}
    if now is not _UNDEF:
        if not _le(iat, _add(now, PCACTN_MAX_SKEW_MS)):
            return {"detail": "iat %s is %sms in the future (> %dms clock-skew allowance)"
                    % (_js_string(iat), _numstr(_to_num(iat) - _to_num(now)), PCACTN_MAX_SKEW_MS),
                    "remedy": "fix the signer clock; do not pre-date actions."}
        if not _le(now, exp):
            return {"detail": "expired %sms ago (exp %s, now %s)" % (_numstr(_to_num(now) - _to_num(exp)), _js_string(exp), _js_string(now)),
                    "remedy": "build a fresh action — a PCActn lifetime is short by design."}
    return {"detail": "validity window invalid", "remedy": "build a fresh action with a valid iat/exp window."}


_HOP_RE = re.compile(r"hop ([0-9]+)")


def _cap_chain_pinpoint(p: Any) -> Dict[str, Any]:
    chain = _get(p, "cap_chain")
    if isinstance(chain, list):
        ok, why = verify_chain(chain)
        reason = "chain root is not the grant this verifier expects" if ok else _nn(why, "capability chain invalid")
    else:
        reason = "cap_chain is not an array"
    m = _HOP_RE.search(reason)
    remedy = "rebuild the chain: each hop must be signed by the parent’s bound holder and may only APPEND caveats."
    if "root issuer" in reason or "not the grant" in reason:
        remedy = "root the chain at the principal key that minted the grant."
    elif "widens" in reason:
        remedy = "a child budget_alloc may not exceed its parent’s carried allocation; lower the sub-allocation."
    elif "caveat" in reason:
        remedy = "attenuation is append-only: never drop, reorder or edit a parent caveat."
    elif "signature" in reason:
        remedy = "re-sign that hop with the parent holder’s secret key (and matching alg/pq_pk for a PQ suite)."
    out: Dict[str, Any] = {"detail": reason, "remedy": remedy}
    if m:
        out["hop"] = int(m.group(1))
    return out


def _leaf_sig_pinpoint(p: Any) -> Dict[str, Any]:
    chain = _get(p, "cap_chain")
    idx = len(chain) - 1 if isinstance(chain, list) else -1
    leaf = chain[idx] if idx >= 0 else _UNDEF
    alg = _nn(_get(p, "alg"), "ed25519")
    remedy = ("sign thresholdMessage(body) with the LEAF holder’s secret key; for a PQ/hybrid suite set alg + pq_pk/pq_sig to "
              "match the holder.")
    if not _truthy(leaf):
        return {"detail": "no leaf capability to check the signature against (empty/invalid chain)", "remedy": remedy}
    out: Dict[str, Any] = {"detail": "leaf hop #%d signature (holder %s, suite %s) does not verify"
                           % (idx, _short(_get(leaf, "holder")), _js_string(alg)), "remedy": remedy}
    if idx >= 0:
        out["hop"] = idx
    return out


def _pinpoint(name: str, p: Any, verify_result: Any, now: Any) -> Dict[str, Any]:
    """The decisive (first failing) check with a concrete detail and remedy."""
    tail = _reason_tail(name, verify_result)
    action, plan = _opt(p, "action"), _opt(p, "plan")
    if name == "wire":
        return {"detail": _nn_str(tail, "wire structure / strict-canonical-form check failed"),
                "remedy": "do not hand-edit the wire JSON; re-encode via encodePCActn with the current SDK."}
    if name == "version":
        return {"detail": _nn_str(tail, "unsupported ver %s (verifier requires %d)" % (_num(_get(p, "ver")), PCACTN_VERSION)),
                "remedy": "re-mint the action at wire version %d." % PCACTN_VERSION}
    if name == "audience":
        return {"detail": _nn_str(tail, "aud %s does not match this resource server / instance" % _jstr(_get(p, "aud"))),
                "remedy": "build the action with aud = this verifier’s instance id (or verify with audience:null to accept any)."}
    if name == "validity":
        v = _validity_pinpoint(p, now)
        return {"detail": _nn_str(tail, v["detail"]), "remedy": v["remedy"]}
    if name == "cap_chain":
        c = _cap_chain_pinpoint(p)
        out = {"detail": _nn_str(tail, c["detail"]), "remedy": c["remedy"]}
        if "hop" in c:
            out["hop"] = c["hop"]
        return out
    if name == "grant_ref_bound":
        return {"detail": _nn_str(tail, "grant_ref %s is not the id of the root capability in cap_chain" % _short(_get(p, "grant_ref"))),
                "remedy": "set grant_ref to the id of the chain root (cap_chain[0].id); buildPCActn does this from the grant."}
    if name == "plan_inclusion":
        return {"detail": _nn_str(tail, "action (verb %s on %s) is not node %s of committed plan %s"
                                  % (_jstr(_opt(action, "verb")), _jstr(_opt(action, "resource")), _jstr(_opt(plan, "node_id")),
                                     _short(_opt(plan, "root")))),
                "remedy": "rebuild the PCActn from a committed plan node whose verb/resource/params match (buildPCActn)."}
    if name == "leaf_signature":
        l = _leaf_sig_pinpoint(p)
        out = {"detail": _nn_str(tail, l["detail"]), "remedy": l["remedy"]}
        if "hop" in l:
            out["hop"] = l["hop"]
        return out
    if name in ("counter", "counter_format"):
        return {"detail": _nn_str(tail, "counter %s is missing or not a non-negative safe integer" % _num(_get(p, "counter"))),
                "remedy": "use a strictly increasing per-holder counter; a repeated counter is a replay."}
    if name == "malformed":
        return {"detail": _nn_str(tail, "the PCActn is structurally malformed"),
                "remedy": "rebuild the action with the SDK; do not construct the wire object by hand."}
    return {"detail": _nn_str(tail, "%s check failed" % name),
            "remedy": "satisfy the %s requirement (supply the corresponding verifier hook / proof)." % name}


def _nn_str(tail: Optional[str], default: str) -> str:
    return default if tail is None else tail


def _pass_detail(name: str, p: Any) -> str:
    """What held, for a pass."""
    if name == "wire":
        return "wire structure + strict canonical form valid"
    if name == "version":
        return "ver %s supported" % _num(_get(p, "ver"))
    if name == "audience":
        return "aud %s matches this resource server" % _jstr(_get(p, "aud"))
    if name == "validity":
        return "fresh: iat/exp window valid (lifetime %ss)" % _num((_to_num(_get(p, "exp")) - _to_num(_get(p, "iat"))) / 1000)
    if name == "cap_chain":
        chain = _get(p, "cap_chain")
        n = len(chain) if isinstance(chain, list) else 0
        root = chain[0] if n > 0 else _UNDEF
        return "%d-hop chain verifies; root issuer %s" % (n, _short(_opt(root, "issuer")))
    if name == "grant_ref_bound":
        return "grant_ref %s is the id of the chain root" % _short(_get(p, "grant_ref"))
    if name == "plan_inclusion":
        plan = _opt(p, "plan")
        return "action is node %s of committed plan %s" % (_jstr(_opt(plan, "node_id")), _short(_opt(plan, "root")))
    if name == "leaf_signature":
        chain = _get(p, "cap_chain")
        leaf = chain[-1] if isinstance(chain, list) and chain else _UNDEF
        return "leaf holder %s signature valid (suite %s)" % (_short(_opt(leaf, "holder")), _js_string(_nn(_get(p, "alg"), "ed25519")))
    if name in ("counter", "counter_format"):
        return "counter %s well-formed" % _num(_get(p, "counter"))
    return "ok"


def _clean_check(c: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(c)
    out["detail"] = clean_text(c["detail"])
    return out


def _verification(verdict: str, allow: bool, checks: List[Dict[str, Any]], decisive: Optional[Dict[str, Any]], summary: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "kind": "verification", "verdict": verdict, "allow": allow, "checks": checks,
        "passed": [c["name"] for c in checks if c["status"] == "pass"],
        "failed": [c["name"] for c in checks if c["status"] == "fail"],
        "notEnforced": [c["name"] for c in checks if c["status"] == "not-enforced"],
    }
    if decisive is not None:
        out["decisive"] = decisive
    out["summary"] = summary
    return out


def _denied_verification(why: str) -> Dict[str, Any]:
    e = {"name": "malformed", "status": "fail", "title": CHECK_TITLE["malformed"], "detail": why,
         "remedy": "pass the PCActn and the verifier result you verified.", "decisive": True}
    return _verification("deny", False, [e], e, "Denied: " + why)


def explain_verification(pca_actn: Any, verify_result: Any, opts: Any = _OPTS) -> Dict[str, Any]:
    """Walk the normative checks of an offline verification in order: summarize what held for each pass and pinpoint the first
    failing check (which hop, which audience mismatch, which validity sub-case, ...) with a concrete remedy. `opts` may carry
    `now` (epoch ms) to tell "expired" from "clock skew" precisely."""
    if not _is_obj(pca_actn) or not _is_obj(verify_result):
        return _denied_verification("the PCActn or the verifier result is missing")
    try:
        return _explain_verification_inner(pca_actn, verify_result, {} if opts is _OPTS else opts)
    except Exception:  # noqa: BLE001 - never throws: a malformed input is a denial
        return _denied_verification("the PCActn or the verifier result is malformed")


def _explain_verification_inner(p: Any, vr: Any, opts: Any) -> Dict[str, Any]:
    statuses = _nn(_get(vr, "checks"), {})
    ordered = list(VERIFY_CHECK_ORDER)
    seen = set(ordered)
    for n in _keys(statuses):  # later-milestone / extra checks appended
        if n not in seen:
            ordered.append(n)
    decisive_name: Optional[str] = None
    for n in ordered:
        if _get(statuses, n) == "fail":
            decisive_name = n
            break
    checks: List[Dict[str, Any]] = []
    decisive: Optional[Dict[str, Any]] = None
    for name in ordered:
        status = _nn(_get(statuses, name), "skipped")
        title = CHECK_TITLE.get(name, name)
        remedy: Optional[str] = None
        hop: Optional[int] = None
        if status == "fail":
            pin = _pinpoint(name, p, vr, _rd(opts, "now"))
            detail, remedy, hop = pin["detail"], pin["remedy"], pin.get("hop")
        elif status == "pass":
            detail = _pass_detail(name, p)
        elif status == "not-enforced":
            detail = "not enforced by this verifier (no hook / opt-out)"
        elif status == "unsupported":
            detail = "the PCActn carries a feature this verifier does not implement (never a pass)"
        else:
            detail = "not reached (a terminal earlier check stopped evaluation)"
        entry: Dict[str, Any] = {"name": name, "status": status, "title": title, "detail": detail}
        if remedy is not None:
            entry["remedy"] = remedy
        if hop is not None:
            entry["hop"] = hop
        if name == decisive_name:
            entry["decisive"] = True
            decisive = entry
        checks.append(entry)

    # Allow only on an explicit `allow: true` that no check contradicts and that carries per-check statuses.
    has_checks = isinstance(_get(vr, "checks"), dict)
    allow_claimed = _get(vr, "allow") is True
    claimed = allow_claimed and has_checks
    contradicted = claimed and decisive_name is not None
    verdict = "allow" if claimed and not contradicted else "deny"
    if verdict == "allow":
        summary = "All %d evaluated checks passed (no check failed)." % sum(1 for c in checks if c["status"] == "pass")
    elif allow_claimed and not has_checks:
        summary = "Denied: the verifier result carries no per-check statuses (an allow without evidence is treated as a denial)."
    elif contradicted:
        summary = ("Denied: the verifier result says allow but the \"%s\" check failed (inconsistent result, treated as a denial)."
                   % (decisive["title"] if decisive is not None else decisive_name))
    elif decisive is not None:
        summary = "Denied at the \"%s\" check: %s" % (decisive["title"], decisive["detail"])
    else:
        reason = _get(vr, "reason")
        summary = "Denied: %s" % (reason if isinstance(reason, str) else "a check failed")
    return _verification(verdict, verdict == "allow", [_clean_check(c) for c in checks],
                         _clean_check(decisive) if decisive is not None else None, clean_text(summary))


_GLYPH = {"pass": "✓", "fail": "✗", "not-enforced": "·", "unsupported": "?", "skipped": "–"}


def verification_to_text(e: Dict[str, Any]) -> str:
    """Render a verification explanation."""
    lines = ["PCA verification — %s" % _js_string(e["verdict"]).upper(), _js_string(e["summary"]), ""]
    for c in e["checks"]:
        mark = " ◀ DECISIVE" if _truthy(_get(c, "decisive")) else ""
        st = c["status"]
        glyph = _GLYPH.get(st, "undefined") if isinstance(st, str) else "undefined"
        lines.append("  %s %s %s%s" % (glyph, _pad_end(_js_string(c["name"]), 16), _js_string(c["detail"]), mark))
        if _truthy(_get(c, "decisive")) and _truthy(_get(c, "remedy")):
            lines.append("      ↳ fix: %s" % _js_string(c["remedy"]))
    return "\n".join(lines)


# ---- explainDecision -------------------------------------------------------------------------------------------------------

def _caveat_remedy(type_: str, rest: Dict[str, Any]) -> str:
    g = lambda k: rest.get(k, _UNDEF)  # noqa: E731
    if type_ == "expires":
        return "the grant expired at %s (epoch ms); obtain a fresh grant or re-mint with a later 'expires'." % _num(g("at"))
    if type_ == "not_before":
        return "the grant is not valid until %s (epoch ms); retry after that time." % _num(g("at"))
    if type_ == "rate":
        return "rate limit %s/%ss reached; wait for the window to clear or raise the 'rate' caveat." % (_num(g("max")), _num(g("per_secs")))
    if type_ == "max_blast_radius":
        return "the action's blast radius exceeds the caveat max %s; narrow the action or raise 'max_blast_radius'." % _num(g("max"))
    if type_ == "reversibility_max":
        return "the action is more severe than the allowed class '%s'; only that class or lower is permitted." % _js_string(g("class"))
    if type_ == "delegation_depth":
        return "delegation depth exceeds max %s; act from a shallower hop or raise 'delegation_depth'." % _num(g("max"))
    return "caveat '%s' is not satisfied; check its parameters against the action/context." % type_


def _caveat_detail(type_: str, rest: Dict[str, Any], satisfied: Any) -> str:
    bound = _value_summary(rest)
    verb = "held" if _truthy(satisfied) else "NARROWED/DENIED"
    return "%s(%s) %s" % (type_, bound, verb) if len(bound) > 0 else "%s %s" % (type_, verb)


_FAILED_CAVEATS = re.compile(r"caveat\(s\) not satisfied: ([^\n\r  ]+)\Z")


def _failed_caveat_types(reasons: List[Any]) -> set:
    out: set = set()
    for r in reasons:
        m = _FAILED_CAVEATS.search(_js_string(r))
        if m:
            for t in m.group(1).split(","):
                if _trim(t):
                    out.add(_trim(t))
    return out


def _risk_band(r: Any, theta1: Any, theta2: Any, tier: Any) -> str:
    if theta1 is _UNDEF or theta2 is _UNDEF:
        return "effective tier t=%s" % _js_string(tier)
    if _le(r, theta1):
        return "r %s ≤ θ1 %s → claim band (t=1)" % (_num(r), _num(theta1))
    if _le(r, theta2):
        return "θ1 %s < r %s ≤ θ2 %s → standard band (t=2)" % (_num(theta1), _num(r), _num(theta2))
    return "r %s > θ2 %s → strong band (t=3)" % (_num(r), _num(theta2))


def _no_decision(reason: str) -> Dict[str, Any]:
    return {"admit": False, "needStepUp": False, "releaseGuardianShare": False, "r": 1,
            "requiredThreshold": {"t": 3, "proof": "human", "optimisticAllowed": False},
            "budget": {"B": 0, "tau": 0, "asOf": 0}, "reasons": [reason]}


def explain_decision(pca_actn: Any, decision: Any, opts: Any = _OPTS) -> Dict[str, Any]:
    """Explain a Policy-VM decision: which predicate granted the (verb, resource) and under what `where` bound, which caveat
    narrowed or denied (type and offending value), the risk band and the admission path; for anything short of auto-admit the
    single decisive reason and remedy. `opts` may carry `envelope` and `context` ({action, caveat, chain}) to pinpoint precisely;
    without them it falls back to the decision's own `reasons`. A missing or malformed decision is a denial, never an allow."""
    o = {} if opts is _OPTS else opts
    if not _is_obj(decision) or not _is_obj(_get(decision, "requiredThreshold")):
        return _explain_decision_inner(_no_decision("no policy decision supplied (default-deny)"), o)
    try:
        return _explain_decision_inner(decision, o)
    except Exception:  # noqa: BLE001
        return _explain_decision_inner(_no_decision("the policy decision could not be explained (default-deny)"), {})


def _includes(r: Any, needle: str) -> bool:
    if not isinstance(r, str):
        raise TypeError("includes is not a function")
    return needle in r


def _length(v: Any) -> Any:
    return len(v) if isinstance(v, list) else _len16(v) if isinstance(v, str) else _UNDEF


def _eval_caveat(cv: Any, caveat_ctx: Any, action_ctx: Any) -> bool:
    """`evaluateAgentCaveats([cv], caveatCtx, actionCtx).ok`: the reference's camelCase context mapped onto this evaluator's."""
    inner = _get(action_ctx, "action")
    inner = inner if isinstance(inner, dict) else {}
    c: Dict[str, Any] = {}
    for src, dst in (("now", "now"), ("delegationDepth", "delegation_depth"), ("blastRadius", "blast_radius"),
                     ("reversibilityClass", "reversibility_class"), ("recentActionTimes", "recent_action_times")):
        v = _get(caveat_ctx, src)
        if v is not _UNDEF:
            c[dst] = v
    c["action"] = inner
    verb, params, binding = _get(inner, "verb"), _get(inner, "params"), _get(action_ctx, "toolBinding")
    tool: Dict[str, Any] = {"tool": verb if isinstance(verb, str) else "", "args": params if isinstance(params, dict) else {}}
    if isinstance(binding, str):
        tool["toolSignatureDigest"] = binding
    return evaluate_agent_caveats([cv], c, action_ctx if isinstance(action_ctx, dict) else {}, tool)[0]


def _explain_decision_inner(decision: Any, opts: Any) -> Dict[str, Any]:
    env = _rd(opts, "envelope")
    ctx = _nn(_get(opts, "context"), {})
    reasons_raw = _get(decision, "reasons")
    reasons: List[Any] = reasons_raw if isinstance(reasons_raw, list) else []

    admitted = _get(decision, "admit") is True  # strict: a truthy non-boolean is not an admission
    rgs = _get(decision, "releaseGuardianShare")
    disposition = "auto-admit" if admitted else "step-up" if rgs is True else "denied"
    verdict = "allow" if admitted else "deny"

    # authority: the granting predicate
    grant: Dict[str, Any] = {}
    _put(grant, "granted", rgs)
    chain = _get(ctx, "chain")
    root_cap = _opt(chain, "0")
    if _truthy(root_cap):
        _put(grant, "capabilityId", _get(root_cap, "id"))
    ctx_action, ctx_caveat = _get(ctx, "action"), _get(ctx, "caveat")
    has_env = _truthy(env)
    if has_env and _truthy(ctx_action):
        preds = _get(env, "predicates")
        pr = evaluate_predicates(preds if isinstance(preds, list) else None, ctx_action)
        if pr.get("allowed") and pr.get("matched") is not None:
            matched = pr["matched"]
            grant["granted"] = True
            grant["predicate"] = matched
            grant["predicateIndex"] = next(i for i, x in enumerate(preds) if x is matched)
            grant["where"] = _where_summary(_get(matched, "where"))
        else:
            grant["granted"] = False
            grant["reason"] = _nn(pr.get("reason"), "no predicate permits this action")
    elif not _truthy(rgs):
        for r in reasons:
            if _includes(r, "predicate") or _includes(r, "not permitted"):
                grant["reason"] = r
                break

    # caveats: per-caveat outcome
    caveats: List[Dict[str, Any]] = []
    failed_from_reasons = _failed_caveat_types(reasons)
    can_eval = env is not _UNDEF and ctx_caveat is not _UNDEF and ctx_action is not _UNDEF
    grant_caveats = _nn(_opt(env, "caveats"), [])
    chain0 = _opt(chain, "0")
    root_count = 0
    if chain0 is not _UNDEF and chain0 is not None:
        cv0 = _rd(chain0, "caveats")
        if cv0 is _UNDEF or cv0 is None:
            raise TypeError("cannot read 'length' of undefined")
        n0 = _length(cv0)
        root_count = 0 if n0 is _UNDEF else n0
    delegated: Any = []
    if isinstance(chain, list) and len(chain) > 1:
        delegated = _slice_from(_nn(_opt(chain[-1], "caveats"), []), root_count)
    def classify(cv: Any, is_delegated: bool) -> Dict[str, Any]:
        type_, rest = _caveat_type(cv), _caveat_rest(cv)
        if can_eval and _truthy(ctx_caveat) and _truthy(ctx_action):
            satisfied: Any = _eval_caveat(cv, ctx_caveat, ctx_action)
        else:
            satisfied = False if type_ in failed_from_reasons else rgs
        out: Dict[str, Any] = {"type": type_}
        _put(out, "satisfied", satisfied)
        out["value"] = rest
        out["detail"] = _caveat_detail(type_, rest, satisfied)
        out["delegated"] = is_delegated
        if not _truthy(satisfied):
            out["remedy"] = _caveat_remedy(type_, rest)
        return out

    for cv in _iter(grant_caveats):
        caveats.append(classify(cv, False))
    for cv in _iter(delegated):
        caveats.append(classify(cv, True))

    # risk / tier
    rt = _get(decision, "requiredThreshold")
    r = _get(decision, "r")
    env_nn = env is not _UNDEF and env is not None
    risk_policy: Any = _UNDEF
    if env_nn:
        risk_policy = _rd(env, "risk_policy")
        if risk_policy is _UNDEF or risk_policy is None:
            raise TypeError("cannot read properties of undefined")
    theta1, theta2 = _opt(risk_policy, "theta1"), _opt(risk_policy, "theta2")
    tier, proof, optimistic = _get(rt, "t"), _get(rt, "proof"), _get(rt, "optimisticAllowed")
    risk: Dict[str, Any] = {}
    _put(risk, "r", r)
    _put(risk, "tier", tier)
    _put(risk, "proof", proof)
    _put(risk, "optimisticAllowed", optimistic)
    risk["band"] = _risk_band(r, theta1, theta2, tier)
    if has_env:
        _put(risk, "theta1", theta1)
        _put(risk, "theta2", theta2)

    # admission / budget
    kappa = _get(risk_policy, "kappa") if env_nn else _UNDEF
    cost_val = _budget_cost(None if r is _UNDEF else r, kappa) if kappa is not _UNDEF else None
    budget_depleted = any(_includes(x, "budget depleted") for x in reasons)
    if admitted:
        path = "auto-admitted at t=%s (%s); metered" % (_js_string(tier), _js_string(proof))
    elif not _truthy(rgs):
        path = "guardian share withheld — policy not satisfied (no autonomous or guardian path)"
    elif budget_depleted:
        path = "trust budget cannot cover the cost — step-up to t=3 (human recharge) required"
    else:
        path = "step-up to t=%s (%s) co-signature required" % (_js_string(tier), _js_string(proof))
    admission: Dict[str, Any] = {"admit": admitted}
    _put(admission, "needStepUp", _get(decision, "needStepUp"))
    _put(admission, "releaseGuardianShare", rgs)
    _put(admission, "budget", _get(decision, "budget"))
    admission["path"] = path
    if cost_val is not None:
        admission["cost"] = cost_val
    if kappa is not _UNDEF:
        admission["kappa"] = kappa

    # the single decisive reason
    decisive: Optional[Dict[str, Any]] = None
    if not admitted:
        if not _truthy(grant.get("granted", _UNDEF)):
            decisive = {"reason": _nn(grant.get("reason", _UNDEF), "action not permitted by the envelope predicates (default-deny)"),
                        "remedy": "grant a predicate that permits this verb+resource (and satisfies its where bound)."}
        else:
            first_failed = next((c for c in caveats if not _truthy(c.get("satisfied", _UNDEF))), None)
            if first_failed is not None:
                decisive = {"reason": "caveat '%s' narrowed the authority away: %s" % (first_failed["type"], first_failed["detail"])}
                if _truthy(first_failed.get("remedy", _UNDEF)):
                    decisive["remedy"] = first_failed["remedy"]
            elif budget_depleted:
                decisive = {"reason": "risk %s is admissible but the trust budget cannot cover cost κ·r%s"
                            % (_num(r), "=" + _num(cost_val) if cost_val is not None else ""),
                            "remedy": "recharge the budget with a human co-sign, or lower the action risk."}
            else:
                decisive = {"reason": "risk %s exceeds the auto threshold → step-up to t=%s (%s)" % (_num(r), _js_string(tier), _js_string(proof)),
                            "remedy": "obtain a human step-up co-signature." if _is_num(tier) and tier == 3
                            else "obtain the guardian/principal co-signature for this tier."}

    if admitted:
        summary = ("Auto-admitted: %s grants it, all caveats held, risk r=%s is in the t=%s band and the budget covers it."
                   % ("predicate #%s" % _js_string(grant.get("predicateIndex", _UNDEF)) if _truthy(grant.get("predicate", _UNDEF)) else "policy",
                      _num(r), _js_string(tier)))
    elif decisive is not None:
        summary = "%s: %s" % ("Denied" if verdict == "deny" and disposition == "denied" else "Needs step-up", _js_string(decisive["reason"]))
    else:
        summary = "Not auto-admitted (t=%s)." % _js_string(tier)

    cleaned_caveats = [dict(c, detail=clean_text(c["detail"])) for c in caveats]
    cleaned_decisive = dict(decisive, reason=clean_text(decisive["reason"])) if decisive is not None else None
    out: Dict[str, Any] = {"kind": "decision", "verdict": verdict, "disposition": disposition, "grant": grant, "caveats": cleaned_caveats,
                           "risk": risk, "admission": admission}
    if cleaned_decisive is not None:
        out["decisive"] = cleaned_decisive
    out["reasons"] = [clean_text(x) for x in reasons]
    out["summary"] = clean_text(summary)
    return out


def decision_to_text(e: Dict[str, Any]) -> str:
    """Render a decision explanation."""
    lines = ["PCA decision — %s (%s)" % (_js_string(e["verdict"]).upper(), _js_string(e["disposition"])), _js_string(e["summary"]), ""]
    gr = e["grant"]
    pred = _get(gr, "predicate")
    if _truthy(_get(gr, "granted")) and _truthy(pred):
        pv = _get(pred, "verb")
        verbs = "|".join("" if x is None else _js_string(x) for x in pv) if isinstance(pv, list) else _js_string(pv)
        lines.append("  authority : predicate #%s of grant %s grants %s on %s"
                     % (_js_string(_get(gr, "predicateIndex")), _short(_get(gr, "capabilityId")), verbs, _js_string(_nn(_get(pred, "resource"), "*"))))
        lines.append("              where %s" % _js_string(_get(gr, "where")))
    else:
        lines.append("  authority : NOT granted — %s" % _js_string(_nn(_get(gr, "reason"), "no predicate permits this action")))
    if len(e["caveats"]) == 0:
        lines.append("  caveats   : none")
    else:
        for c in e["caveats"]:
            mark = "✓" if _truthy(_get(c, "satisfied")) else "✗"
            src = " [delegated]" if _truthy(_get(c, "delegated")) else ""
            lines.append("  caveat %s  : %s%s" % (mark, _js_string(c["detail"]), src))
            if not _truthy(_get(c, "satisfied")) and _truthy(_get(c, "remedy")):
                lines.append("              ↳ fix: %s" % _js_string(c["remedy"]))
    risk = e["risk"]
    lines.append("  risk      : %s; proof=%s, optimistic=%s" % (_js_string(_get(risk, "band")), _js_string(_get(risk, "proof")),
                                                            _js_string(_get(risk, "optimisticAllowed"))))
    a = e["admission"]
    cost = _get(a, "cost")
    cost_str = ", cost κ·r=%s (κ=%s)" % (_num(cost), _num(_get(a, "kappa"))) if cost is not _UNDEF else ""
    lines.append("  budget    : %s%s; B after=%s" % (_js_string(_get(a, "path")), cost_str, _num(_rd(_get(a, "budget"), "B"))))
    dec = _get(e, "decisive")
    if _truthy(dec):
        lines.append("")
        lines.append("  ◀ DECISIVE: %s" % _js_string(_get(dec, "reason")))
        if _truthy(_get(dec, "remedy")):
            lines.append("      ↳ fix: %s" % _js_string(_get(dec, "remedy")))
    return "\n".join(lines)


# ---- explainChain ----------------------------------------------------------------------------------------------------------

def _is_budget_alloc(cv: Any) -> bool:
    if not _is_obj(cv) or _get(cv, "type") != "budget_alloc":
        return False
    lim = _get(cv, "limit")
    return _is_fin(lim) and lim >= 0


def budget_alloc_nodes(chain: Any) -> List[Dict[str, Any]]:
    """The per-node budget subtree carried by a chain: one node per well-formed `budget_alloc` caveat, in delegation order. Reads
    the append-only caveat lineage; it does not verify signatures (run `verify_chain` first)."""
    out: List[Dict[str, Any]] = []
    if not isinstance(chain, list) or len(chain) == 0:
        return out
    leaf = chain[-1]
    leaf_cvs = _rd(leaf, "caveats")
    if not isinstance(leaf_cvs, list):
        return out
    hop = 0
    for ci, cv in enumerate(leaf_cvs):
        while hop < len(chain) - 1:
            n = _length(_rd(chain[hop], "caveats"))
            if (0 if n is _UNDEF else n) <= ci:
                hop += 1
            else:
                break
        if not _is_budget_alloc(cv):
            continue
        introducing = chain[hop]
        cap_id = _rd(introducing, "id")
        if cap_id is _UNDEF:
            raise TypeError("canonicalize: undefined member")
        node: Dict[str, Any] = {"nodePath": hash_canonical({"d": "atlas-pca/budget-node/v1", "cap": cap_id, "i": ci})}
        _put(node, "capId", cap_id)
        _put(node, "holder", _rd(introducing, "holder"))
        node["depth"] = hop
        node["caveatIndex"] = ci
        node["limit"] = cv["limit"]
        out.append(node)
    return out


def _hop_narrowed_summary(is_root: bool, added: List[Any]) -> str:
    bits = []
    for cv in added:
        type_, rest = _caveat_type(cv), _caveat_rest(cv)
        if type_ == "envelope":
            preds, inner = rest.get("predicates"), rest.get("caveats")
            bits.append("envelope (%d predicate(s), %d caveat(s))" % (len(preds) if isinstance(preds, list) else 0,
                                                                       len(inner) if isinstance(inner, list) else 0))
        elif _is_budget_alloc(cv):
            bits.append("budget_alloc(B_sub=%s)" % _num(cv["limit"]))
        else:
            bound = _value_summary(rest)
            bits.append("+%s(%s)" % (type_, bound) if bound else "+" + type_)
    if not bits:
        return "root grant (no caveats)" if is_root else "rebind only (no new caveats)"
    return ("grants " if is_root else "narrows: ") + ", ".join(bits)


def _explain_chain_inner(chain: Any) -> Dict[str, Any]:
    safe = chain if isinstance(chain, list) else []
    hops = []
    for i, cap in enumerate(safe):
        if not _truthy(cap):
            continue
        is_root = i == 0
        parent = safe[i - 1] if i > 0 else _UNDEF
        pc = _get(parent, "caveats") if _truthy(parent) else _UNDEF
        parent_len = len(pc) if isinstance(pc, list) else 0
        oc = _get(cap, "caveats")
        own = oc if isinstance(oc, list) else []
        added = own if is_root else own[parent_len:] if len(own) >= parent_len else []
        budget_cv = next((cv for cv in added if _is_budget_alloc(cv)), None)
        hop: Dict[str, Any] = {"index": i, "isRoot": is_root}
        _put(hop, "issuer", _get(cap, "issuer"))
        _put(hop, "holder", _get(cap, "holder"))
        hop["issuerShort"] = _short(_get(cap, "issuer"))
        hop["holderShort"] = _short(_get(cap, "holder"))
        hop["alg"] = _nn(_get(cap, "alg"), "ed25519")
        hop["addedCaveats"] = list(added)
        hop["addedCaveatTypes"] = [_caveat_type(cv) for cv in added]
        hop["narrowed"] = clean_text(_hop_narrowed_summary(is_root, added))
        if budget_cv is not None:
            hop["budgetAlloc"] = budget_cv["limit"]
        hops.append(hop)
    root = safe[0] if safe else _UNDEF
    leaf = safe[-1] if safe else _UNDEF
    nodes = budget_alloc_nodes(safe)
    summary = ("empty chain (no authority)" if not safe else
               "%s (principal) delegated through %d hop(s) to the acting holder %s; %d budget node(s)."
               % (_short(_opt(root, "issuer")), len(safe) - 1, _short(_opt(leaf, "holder")), len(nodes)))
    out: Dict[str, Any] = {"kind": "chain", "depth": len(safe), "hops": hops}
    _put(out, "rootIssuer", _opt(root, "issuer"))
    _put(out, "leafHolder", _opt(leaf, "holder"))
    out["budgetNodes"] = nodes
    out["summary"] = summary
    return out


def explain_chain(chain: Any, opts: Any = _OPTS) -> Dict[str, Any]:
    """Render a delegation chain as an ordered attenuation trace: issuer to holder per hop and what each hop narrowed. With
    `opts["verify"] is True` the chain is also checked (`opts["expectedRootIssuer"]` pins the root issuer); otherwise the trace
    shows only what the chain claims."""
    o = {} if opts is _OPTS else opts
    out = _explain_chain_inner(chain)
    if _rd(o, "verify") is not True:
        return out
    ok, reason = False, "chain is not an array"  # type: Any
    try:
        if isinstance(chain, list):
            exp = _get(o, "expectedRootIssuer")
            ok, why = verify_chain(chain, None if exp is _UNDEF else exp)
            reason = None if ok else why
    except Exception:  # noqa: BLE001
        ok, reason = False, "chain could not be verified"
    v: Dict[str, Any] = {"ok": bool(ok)}
    if reason is not None:
        v["reason"] = clean_text(reason)
    res = dict(out)
    res["verification"] = v
    return res


def chain_to_text(e: Dict[str, Any]) -> str:
    """Render a chain explanation."""
    lines = ["PCA delegation chain — %s hop(s) (attenuation trace)" % _js_string(e["depth"])]
    v = _get(e, "verification")
    if v is _UNDEF:
        lines.append("UNVERIFIED: this trace shows what the chain claims; no signature or link was checked.")
    elif v["ok"] is True:
        lines.append("verified: signatures, links and caveat rules hold.")
    else:
        lines.append("NOT VALID: %s" % _js_string(_nn(_get(v, "reason"), "the chain failed verification")))
    lines.append(_js_string(e["summary"]))
    lines.append("")
    for h in e["hops"]:
        tag = "root " if h["isRoot"] else "deleg"
        lines.append("  #%s %s %s ──▶ %s   %s" % (_js_string(h["index"]), tag, _js_string(h["issuerShort"]),
                                                              _js_string(h["holderShort"]), _js_string(h["narrowed"])))
    if len(e["budgetNodes"]) > 0:
        tree = " → ".join("depth %s B_sub=%s" % (_js_string(n["depth"]), _num(n["limit"])) for n in e["budgetNodes"])
        lines.append("")
        lines.append("  budget subtree: %s" % tree)
    return "\n".join(lines)
