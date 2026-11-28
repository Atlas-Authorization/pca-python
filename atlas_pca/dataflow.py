"""The capability-tagged, positive data-flow model (CaMeL style), the trace rules that lower "never B after A" guardrails to
derive caveats, the lethal-trifecta lint, and the vendor detector adapters that turn guardrail responses into signed,
tighten-only receipts. Port of @atlasauth/pca-dataflow (and the core model it re-exports) of the TypeScript reference.

Differences from the reference that come from the language: a Tagged value can only be made by this module (the constructor
needs a private token, so `is_tagged` is true only for values it minted); capability sets are frozensets; sinks are dicts
`{"id": str, "accepts": {"external", "require_trusted", "allowed_sources", "denied_sources"}}`; the sink resolver of
`check_action` is an object with `sink_for(action)` or a plain callable; Python has no sparse-array holes, so a `None` entry in
the tagged-argument list is the "an argument was not tagged" refusal.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, Iterable, List, Optional

from .agent import KeyPair, sign_artifact
from .caveat_lang import DERIVE_MAX_WINDOW_MS, derive_error
from .intent_wb import _closed_members, _is_bounded_string, _is_digest, _is_safe_int, artifact_suite_error
from .pca import hash_canonical

# ---- provenance + tagged values ------------------------------------------------------------------------------------------

TRUSTED_QUERY = "trusted-query"


def tool_provenance(name: str) -> str:
    return "tool:" + name


def _u16(s: Any) -> bytes:
    # JS Array.prototype.sort() on strings orders by UTF-16 code unit
    return str(s).encode("utf-16-be", "surrogatepass")


def _sorted(xs: Iterable[Any]) -> List[Any]:
    return sorted(xs, key=_u16)


class Capability:
    """sources (lineage), is_trusted (true only if every source is trusted), readers (optional allow-list of sink ids)."""

    __slots__ = ("sources", "is_trusted", "readers")

    def __init__(self, sources: Any, is_trusted: Any, readers: Any = None):
        object.__setattr__(self, "sources", sources)
        object.__setattr__(self, "is_trusted", is_trusted)
        object.__setattr__(self, "readers", readers)

    def __setattr__(self, k: str, v: Any) -> None:
        raise TypeError("capabilities are immutable")


_MINT = object()


class Tagged:
    """A value carrying its capability. Only this module can construct one (`is_tagged` is false for a look-alike)."""

    __slots__ = ("value", "cap")

    def __init__(self, value: Any, cap: Capability, _token: Any = None):
        if _token is not _MINT:
            raise TypeError("a Tagged value is made by tag(), from_trusted_query(), from_tool_output(), from_source() or derive()")
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "cap", cap)

    def __setattr__(self, k: str, v: Any) -> None:
        raise TypeError("tagged values are immutable")


def is_tagged(x: Any) -> bool:
    return isinstance(x, Tagged)


def _freeze(sources: Any, is_trusted: bool, readers: Any) -> Capability:
    return Capability(frozenset(sources), is_trusted, None if readers is None else frozenset(readers))


def tag(value: Any, cap: Any) -> Tagged:
    """Tag a raw value with an explicit capability (escape hatch; prefer the boundary constructors)."""
    if not isinstance(cap, Capability) or not isinstance(cap.sources, (set, frozenset)) or not isinstance(cap.is_trusted, bool):
        raise TypeError("tag: a capability needs a set of sources and a boolean isTrusted")
    if cap.readers is not None and not isinstance(cap.readers, (set, frozenset)):
        raise TypeError("tag: readers must be a Set when given")
    if cap.is_trusted:
        if len(cap.sources) == 0:
            raise TypeError("tag: a trusted capability needs at least one source")
        for src in cap.sources:
            if isinstance(src, str) and src.startswith("tool:"):
                raise TypeError("tag: tool output can never be trusted")
    return Tagged(value, _freeze(cap.sources, cap.is_trusted, cap.readers), _MINT)


def from_trusted_query(value: Any, readers: Optional[Iterable[str]] = None) -> Tagged:
    return tag(value, Capability(frozenset([TRUSTED_QUERY]), True, None if readers is None else frozenset(readers)))


def from_tool_output(name: str, value: Any, readers: Optional[Iterable[str]] = None) -> Tagged:
    return tag(value, Capability(frozenset([tool_provenance(name)]), False, None if readers is None else frozenset(readers)))


def from_source(source: str, value: Any, is_trusted: bool = False, readers: Optional[Iterable[str]] = None) -> Tagged:
    """Untrusted unless the caller vouches (is_trusted is True) at the boundary."""
    return tag(value, Capability(frozenset([source]), is_trusted is True, None if readers is None else frozenset(readers)))


def union_sources(caps: Iterable[Capability]) -> frozenset:
    out: set = set()
    for c in caps:
        out.update(c.sources)
    return frozenset(out)


def combine_caps(caps: Iterable[Capability]) -> Capability:
    """sources = union, is_trusted = AND over a non-empty list, readers = intersection of the inputs that restrict readers."""
    caps = list(caps)
    sources = union_sources(caps)
    trusted = len(caps) > 0 and all(c.is_trusted for c in caps)
    readers: Optional[set] = None
    for c in caps:
        if c.readers is None:
            continue
        readers = set(c.readers) if readers is None else {r for r in readers if r in c.readers}
    return _freeze(sources, trusted, readers)


def derive(inputs: Any, combine: Callable[..., Any]) -> Tagged:
    """A new tagged value whose capability is combine_caps over the inputs: trust can only be lost."""
    if not isinstance(inputs, (list, tuple)) or not all(is_tagged(t) for t in inputs):
        raise TypeError("derive: every input must be a tagged value made by this module")
    value = combine(*[t.value for t in inputs])
    return Tagged(value, combine_caps([t.cap for t in inputs]), _MINT)


# ---- sinks + the policy interpreter ----------------------------------------------------------------------------------------

def _sorted_sources(cap: Capability) -> List[Any]:
    return _sorted(cap.sources)


def classify_flow(value: Any, sink: Any) -> Dict[str, Any]:
    """One value -> sink flow: {outcome: allow|step_up|deny, reason?, path?}. Order: value readers, denied sources, allow-list,
    external sink, sensitive sink."""
    if not is_tagged(value):
        return {"outcome": "deny", "reason": "value carries no provenance tag made by this module (fail closed)", "path": []}
    if (not isinstance(sink, dict) or not isinstance(sink.get("id"), str) or len(sink["id"]) == 0
            or not isinstance(sink.get("accepts"), dict)):
        return {"outcome": "deny", "reason": "the sink is not a valid sink (fail closed)", "path": _sorted_sources(value.cap)}
    cap = value.cap
    p = sink["accepts"]
    sid = sink["id"]
    if cap.readers is not None and sid not in cap.readers:
        return {"outcome": "deny",
                "reason": "value's readers capability [%s] does not include sink '%s'" % (", ".join(_sorted(cap.readers)) or "∅", sid),
                "path": _sorted_sources(cap)}
    denied = p.get("denied_sources")
    if denied is not None:
        bad = [s for s in _sorted_sources(cap) if s in denied]
        if bad:
            return {"outcome": "deny", "reason": "provenance [%s] is forbidden at sink '%s'" % (", ".join(bad), sid), "path": bad}
    allowed = p.get("allowed_sources")
    if allowed is not None:
        bad = [s for s in _sorted_sources(cap) if s not in allowed]
        if bad:
            return {"outcome": "deny", "reason": "provenance [%s] is not in the allow-list of sink '%s'" % (", ".join(bad), sid), "path": bad}
    if p.get("external") is True and not cap.is_trusted:
        return {"outcome": "deny",
                "reason": "untrusted value (provenance [%s]) may not flow to external-send sink '%s' — exfiltration / prompt-injection path"
                % (", ".join(_sorted_sources(cap)), sid),
                "path": _sorted_sources(cap)}
    if p.get("require_trusted") is True and not cap.is_trusted:
        return {"outcome": "step_up",
                "reason": "sink '%s' requires trusted provenance; value provenance [%s] is untrusted — needs human review"
                % (sid, ", ".join(_sorted_sources(cap))),
                "path": _sorted_sources(cap)}
    return {"outcome": "allow"}


def can_flow(value: Any, sink: Any) -> Dict[str, Any]:
    """ok is true only for a clean allow (a step_up is not ok without a human)."""
    d = classify_flow(value, sink)
    out: Dict[str, Any] = {"ok": d["outcome"] == "allow"}
    if "reason" in d:
        out["reason"] = d["reason"]
    return out


_SEVERITY = {"allow": 0, "step_up": 1, "deny": 2}


def check_action(action: Any, tagged_args: Any, policy: Any, expected_args: Optional[int] = None) -> Dict[str, Any]:
    """Gate an action by data flow: every tagged argument is checked against the sink it dispatches to; the worst outcome wins."""
    try:
        resolver = getattr(policy, "sink_for", None) or policy
        sink = resolver(action)
    except Exception:  # noqa: BLE001 - the resolver is caller code: any failure refuses
        return {"outcome": "deny", "sink": "(unresolved)", "reason": "the sink for this action could not be resolved (fail closed)"}
    if not isinstance(sink, dict) or not isinstance(sink.get("id"), str) or len(sink["id"]) == 0:
        return {"outcome": "deny", "sink": "(unresolved)", "reason": "the sink for this action is not a valid sink (fail closed)"}
    sid = sink["id"]
    if not isinstance(tagged_args, (list, tuple)):
        return {"outcome": "deny", "sink": sid, "reason": "the tagged arguments are not a list (fail closed)"}
    if expected_args is not None and len(tagged_args) != expected_args:
        return {"outcome": "deny", "sink": sid,
                "reason": "expected %s tagged argument(s), got %d (fail closed)" % (_num(expected_args), len(tagged_args))}
    worst: Dict[str, Any] = {"outcome": "allow", "sink": sid}
    for i, arg in enumerate(tagged_args):
        if arg is None:
            worst = {"outcome": "deny", "sink": sid, "arg": i, "reason": "an argument was not tagged (fail closed)"}
            break
        d = classify_flow(arg, sink)
        if _SEVERITY[d["outcome"]] > _SEVERITY[worst["outcome"]]:
            worst = {"outcome": d["outcome"], "sink": sid, "arg": i}
            if "reason" in d:
                worst["reason"] = d["reason"]
            if "path" in d:
                worst["path"] = d["path"]
    return worst


def _num(n: Any) -> str:
    return str(int(n)) if isinstance(n, float) and n.is_integer() else str(n)


def dual_context(query: Any, plan: Callable[[Any], Any], quarantine: Callable[[Any], Any]) -> Dict[str, Any]:
    """Privileged planner sees only the TRUSTED query value; the quarantined handler returns a tagged result."""
    if not is_tagged(query):
        raise TypeError("dualContext: the query must be a tagged value made by this module")
    if not query.cap.is_trusted:
        raise ValueError("dualContext: the privileged planner may only run on a TRUSTED query; got provenance [%s]"
                         % ", ".join(_sorted_sources(query.cap)))
    p = plan(query.value)
    result = quarantine(p)
    if not is_tagged(result):
        raise TypeError("dualContext: the quarantined handler must return a tagged value made by this module")
    return {"plan": p, "result": result}


def external_send_sink(id: str) -> Dict[str, Any]:
    return {"id": id, "accepts": {"external": True}}


def sensitive_sink(id: str) -> Dict[str, Any]:
    return {"id": id, "accepts": {"require_trusted": True}}


def level_of(value: Any) -> str:
    """The label in the provenance lattice of the default gate: trusted, tool (every source a tool output) or agent."""
    if not is_tagged(value):
        return "agent"
    cap = value.cap
    if cap.is_trusted:
        return "trusted"
    srcs = list(cap.sources)
    return "tool" if srcs and all(isinstance(s, str) and s.startswith("tool:") for s in srcs) else "agent"


# ---- trace rules ---------------------------------------------------------------------------------------------------------

class TraceRuleError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


MAX_TRACE_CAVEATS = 64
_B_CHUNK = 8  # 7 + 3k expression nodes <= DERIVE_MAX_NODES (32)
_RULE_ID_RE = re.compile(r"[a-z][a-z0-9_]{0,39}")
_VERB_RE = re.compile(r"[A-Za-z0-9_.:/-]{1,256}")
# JS \s / String.trim() whitespace, `.` (no line terminators) and \S, which differ from Python's
_WS = "\t\n\u000b\u000c\r    -     　﻿"
_S, _NS, _DOT = "[%s]" % _WS, "[^%s]" % _WS, "[^\n\r  ]"
_RULE_RE = re.compile(r"%s*never%s+(%s+?)%s+after%s+(%s+?)%s+within%s+(%s+)%s*" % (_S, _S, _DOT, _S, _S, _DOT, _S, _S, _NS, _S))
_DUR_RE = re.compile(r"([1-9][0-9]{0,9})(ms|s|m|h|d)")
_HEAD_RE = re.compile(r"raise%s+(?:\"([^\"]*)\"|'([^']*)')%s+if:" % (_S, _S))
_FLOW_RE = re.compile(r"\(([A-Za-z0-9_]+):%s*(ToolCall|ToolOutput|Message)\)%s*->%s*\(([A-Za-z0-9_]+):%s*(ToolCall|ToolOutput|Message)\)" % (_S, _S, _S, _S))
_COND_RE = re.compile(r"([A-Za-z0-9_]+)%s+is%s+tool:([A-Za-z0-9_.:/-]+)(\(%s*\))?" % (_S, _S, _DOT))
_UNIT = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}


def _fail(code: str, m: str) -> Any:
    raise TraceRuleError(code, m)


_TRIM = "\t\n\u000b\u000c\r \u00a0\u1680\u2028\u2029\u202f\u205f\u3000\ufeff" + "".join(chr(c) for c in range(0x2000, 0x200B))


def _trim(s: str) -> str:
    return s.strip(_TRIM)


def _utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _duration(t: Any) -> int:
    m = _DUR_RE.fullmatch(t) if isinstance(t, str) else None
    if not m:
        return _fail("duration", "'%s' is not a duration like 10m, 2h or 7d" % t)
    ms = int(m.group(1)) * _UNIT[m.group(2)]
    if ms > DERIVE_MAX_WINDOW_MS:
        _fail("window", "a window of %s exceeds the 30-day history the verifier keeps" % t)
    return ms


def _selector(text: str, side: str) -> Dict[str, Any]:
    s: Dict[str, Any] = {"tools": [], "traits": [], "resources": [], "any": False}
    for raw in text.split(","):
        a = _trim(raw)
        if a == "any":
            s["any"] = True
        elif a.startswith("tool:") and _VERB_RE.fullmatch(a[5:]):
            s["tools"].append(a[5:])
        elif a.startswith("trait:") and _VERB_RE.fullmatch(a[6:]):
            s["traits"].append(a[6:])
        elif a.startswith("resource:") and 9 < _utf16_len(a) <= 9 + 256:
            if side == "never":
                _fail("resource_on_effect", "a resource selector can only name the earlier action (the check reads the current verb)")
            s["resources"].append(a[9:])
        else:
            _fail("selector", "'%s' is not tool:<verb>, trait:<id>, resource:<prefix> or any" % a)
    return s


def _check_id(id: Any) -> None:
    if not isinstance(id, str) or not _RULE_ID_RE.fullmatch(id):
        _fail("id", "rule id '%s' must match %s" % (id, "^[a-z][a-z0-9_]{0,39}$"))


def parse_trace_rule(id: str, text: str, reason: Optional[str] = None) -> Dict[str, Any]:
    """Parse `never <B> after <A> within <duration>`. Raises TraceRuleError."""
    _check_id(id)
    m = _RULE_RE.fullmatch(text) if isinstance(text, str) else None
    if not m:
        return _fail("syntax", "expected 'never <selector> after <selector> within <duration>', got '%s'" % text)
    rule = {"id": id, "never": _selector(m.group(1), "never"), "after": _selector(m.group(2), "after"), "within_ms": _duration(m.group(3))}
    if reason is not None:
        rule["reason"] = reason
    return rule


def parse_invariant_rule(id: str, text: str, horizon: Any = None, drop_unsupported: bool = False) -> Dict[str, Any]:
    """Import the Invariant subset `raise "<msg>" if: (x: ToolCall|ToolOutput) -> (y: ToolCall)` plus `x is tool:<name>` lines.
    `horizon` is required. Returns {rule, dropped}."""
    _check_id(id)
    if not isinstance(horizon, str):
        _fail("horizon", "an Invariant rule has no window: pass the horizon explicitly")
    within_ms = _duration(horizon)
    lines = [l for l in (_trim(x) for x in text.split("\n")) if len(l) > 0 and not l.startswith("#")]
    head = _HEAD_RE.fullmatch(lines[0] if lines else "")
    if not head:
        _fail("syntax", 'the first line must be raise "<message>" if:')
    flow = _FLOW_RE.fullmatch(lines[1] if len(lines) > 1 else "")
    if not flow:
        _fail("unsupported", "the second line must be one flow '(x: ToolCall|ToolOutput) -> (y: ToolCall)' (chains of three and other patterns are not supported)")
    a, ta, b, tb = flow.group(1), flow.group(2), flow.group(3), flow.group(4)
    if ta == "Message" or tb != "ToolCall":
        _fail("unsupported", "only a tool call or tool output followed by a tool call can be compiled")
    if a == b:
        _fail("syntax", "the two events need distinct names")
    tools: Dict[str, List[str]] = {a: [], b: []}
    dropped: List[str] = []
    for l in lines[2:]:
        m = _COND_RE.fullmatch(l)
        if m and m.group(1) in tools and m.group(3) is None:
            tools[m.group(1)].append(m.group(2))
            continue
        if drop_unsupported is True:
            # `x is tool:name({args})` keeps the tool and drops the argument pattern: a wider match, so more refusals
            if m and m.group(1) in tools:
                tools[m.group(1)].append(m.group(2))
            dropped.append(l)
            continue
        _fail("unsupported", "'%s' is outside the compilable subset (x is tool:<name>); pass dropUnsupported to refuse more instead" % l)
    for v in (a, b):
        if len(tools[v]) > 1:
            _fail("unsatisfiable", "'%s' is constrained to two different tools, so the rule can never fire" % v)

    def sel(v: str) -> Dict[str, Any]:
        return {"tools": tools[v], "traits": [], "resources": [], "any": len(tools[v]) == 0}

    reason = head.group(1) if head.group(1) is not None else (head.group(2) if head.group(2) is not None else "")
    return {"rule": {"id": id, "never": sel(b), "after": sel(a), "within_ms": within_ms, "reason": reason}, "dropped": dropped}


def _expand(s: Dict[str, Any], table: Dict[str, Any], what: str) -> List[str]:
    verbs = _sorted(table.keys())
    out: set = set()
    if s["any"]:
        out.update(verbs)
    for t in s["tools"]:
        if t not in table:
            _fail("unknown_tool", "%s: tool '%s' is not an action in the verb table" % (what, t))
        out.add(t)
    for tr in s["traits"]:
        hit = [v for v in verbs if tr in table[v]["traits"]]
        if not hit:
            _fail("empty_selector", "%s: trait '%s' matches no action" % (what, tr))
        out.update(hit)
    return _sorted(out)


def compile_trace_rules(rules: Any, table: Dict[str, Any]) -> Dict[str, Any]:
    """Lower rules to derive caveats over the verifier's history. Raises TraceRuleError on anything not expressible."""
    caveats: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    ids: set = set()
    for r in rules:
        rid = r["id"]
        if not isinstance(rid, str) or not _RULE_ID_RE.fullmatch(rid) or rid in ids:
            _fail("id", "rule id '%s' is malformed or repeated" % rid)
        ids.add(rid)
        w = r["within_ms"]
        if not (_is_safe_int(w) and 1 <= w <= DERIVE_MAX_WINDOW_MS):
            _fail("window", "rule '%s': within_ms must be 1..30 days" % rid)
        w = int(w)
        if len(r["never"]["resources"]) > 0:
            _fail("resource_on_effect", "rule '%s': a resource selector cannot name the later action" % rid)
        bs = _expand(r["never"], table, "rule '%s' never" % rid)
        as_: List[Dict[str, Any]] = [{"verb": v} for v in _expand(r["after"], table, "rule '%s' after" % rid)]
        as_ += [{"resource_prefix": p} for p in _sorted(set(r["after"]["resources"]))]
        if len(bs) == 0 or len(as_) == 0:
            _fail("empty_selector", "rule '%s': a side matches nothing" % rid)
        n = 0
        for a in as_:
            for i in range(0, len(bs), _B_CHUNK):
                chunk = bs[i:i + _B_CHUNK]
                is_b = {"op": "or", "args": [{"op": "eq", "a": {"ref": "verb"}, "b": {"const": v}} for v in chunk]}
                seen = {"name": "seen", "kind": "count", "window_ms": w}
                seen.update(a)
                c = {
                    "type": "derive",
                    "id": "trace.%s.%d" % (rid, n),
                    "defs": [seen, {"name": "verb", "kind": "action", "field": "verb"}, {"name": "is_b", "kind": "expr", "expr": is_b}],
                    # refused iff an A happened within the window AND this action is a B; unknown (no history, no verb) refuses too
                    "check": {"op": "not", "arg": {"op": "and", "args": [{"op": "gt", "a": {"ref": "seen"}, "b": {"const": 0}}, {"ref": "is_b"}]}},
                }
                n += 1
                e = derive_error(c)
                if e:
                    _fail("internal", "rule '%s' compiled to an invalid caveat: %s" % (rid, e))
                caveats.append(c)
                if len(caveats) > MAX_TRACE_CAVEATS:
                    _fail("too_large", "more than %d caveats: split the rule set or narrow the selectors" % MAX_TRACE_CAVEATS)
            for v in bs:
                frm = {"tool": a["verb"]} if "verb" in a else {"resource": a["resource_prefix"]}
                edges.append({"rule": rid, "from": frm, "to": v, "within_ms": w})
    return {"caveats": caveats, "edges": edges, "digest": hash_canonical({"d": "atlas-pca/trace-rules/v1", "caveats": caveats})}


# ---- lethal trifecta lint ------------------------------------------------------------------------------------------------

PRIVATE_READ_TRAITS = ["pca.pii_access", "pca.financial_data_read", "pca.credential_access", "pca.regulated_data"]
EXTERNAL_SEND_TRAITS = ["pca.external_communication", "pca.network_egress", "pca.data_export", "pca.public_exposure"]


def lethal_trifecta(table: Dict[str, Any], edges: Any, untrusted: Optional[Iterable[str]] = None,
                    untrusted_traits: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Private data, untrusted content and a way out in one action set; a send is cut off when every untrusted read, or every
    private read, has an edge rule to it. A lint: it reports, it does not enforce."""
    verbs = _sorted(table.keys())
    untrusted = list(untrusted or [])
    untrusted_traits = list(untrusted_traits or [])

    def has(v: str, ts: List[str]) -> bool:
        return any(t in ts for t in table[v]["traits"])

    def read_only(v: str) -> bool:
        eff = table[v].get("effects") or []
        return len(eff) > 0 and all(e == "read" for e in eff)

    priv = [v for v in verbs if has(v, PRIVATE_READ_TRAITS)]
    untr = [v for v in verbs if v in untrusted or has(v, untrusted_traits) or (read_only(v) and "pca.network_egress" in table[v]["traits"])]
    sends = [v for v in verbs if has(v, EXTERNAL_SEND_TRAITS) and not read_only(v)]
    findings: List[Dict[str, Any]] = []
    if priv and untr and sends:
        def ruled(frm: str, to: str) -> bool:
            return any("tool" in e["from"] and e["from"]["tool"] == frm and e["to"] == to for e in edges)

        for s in sends:
            fu = [u for u in untr if not ruled(u, s)]
            fp = [p for p in priv if not ruled(p, s)]
            if fu and fp:
                findings.append({"send": s, "from_untrusted": fu, "from_private": fp})
    return {"private_reads": priv, "untrusted_reads": untr, "sends": sends, "findings": findings}


# ---- detector receipts + adapters ----------------------------------------------------------------------------------------

DETECTOR_RECEIPT_DOMAIN = "atlas-pca/detector-receipt/v1\x00"
DETECTOR_RECEIPT_REF_DOMAIN = "atlas-pca/detector-receipt-ref/v1"
DETECTOR_VERDICTS = ("suspicious", "no_finding")
_ID_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")


def detector_input_digest(content: Any) -> str:
    """b64u(sha256(strictCanonical({d, content}))): the digest a receipt binds."""
    return hash_canonical({"d": "atlas-pca/detector-input/v1", "content": content})


def detector_receipt_ref(r: Any) -> str:
    return hash_canonical({"d": DETECTOR_RECEIPT_REF_DOMAIN, "receipt": r})


def detector_receipt_shape_error(r: Any) -> Optional[str]:
    """None when well-formed."""
    if not isinstance(r, dict):
        return "receipt must be an object"
    e = _closed_members(r, ["v", "kind", "detector", "version", "input_digest", "verdict", "categories", "iat", "sig"],
                        ["session", "calibration_ref", "alg", "pq_pk", "pq_sig"], "receipt")
    if e:
        return e
    v = r["v"]
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v != 1 or r["kind"] != "pca-detector-receipt":
        return "not a pca-detector-receipt v1"
    if not isinstance(r["detector"], str) or not _ID_RE.fullmatch(r["detector"]):
        return "detector id is malformed"
    if not _is_bounded_string(r["version"], 64):
        return "version must be 1..64 bytes"
    if not _is_digest(r["input_digest"]):
        return "input_digest must be a b64u 32-byte digest"
    if not isinstance(r["verdict"], str) or r["verdict"] not in DETECTOR_VERDICTS:
        return "verdict must be 'suspicious' or 'no_finding'"
    c = r["categories"]
    if not isinstance(c, list) or len(c) > 8 or not all(isinstance(x, str) and _ID_RE.fullmatch(x) for x in c):
        return "categories must be 0..8 ids"
    for i in range(1, len(c)):
        if not c[i - 1] < c[i]:
            return "categories must be sorted and distinct"
    if r["verdict"] == "no_finding" and len(c) > 0:
        return "a no_finding receipt carries no categories"
    if not (_is_safe_int(r["iat"]) and r["iat"] >= 0):
        return "iat must be a non-negative integer"
    if "session" in r and not _is_digest(r["session"]):
        return "session must be a b64u 32-byte id"
    if "calibration_ref" in r and not _is_bounded_string(r["calibration_ref"], 256):
        return "calibration_ref must be 1..256 bytes"
    if not isinstance(r["sig"], str):
        return "sig must be a string"
    return artifact_suite_error(r)


def sign_detector_receipt(body: Dict[str, Any], key: Any, alg: Optional[str] = None, pq: Any = None) -> Dict[str, Any]:
    """Sign a receipt with the detector gateway's key (a KeyPair or a 32-byte Ed25519 seed). Raises on a malformed body."""
    ed = key if isinstance(key, KeyPair) else KeyPair(key)
    signed = sign_artifact(DETECTOR_RECEIPT_DOMAIN, body, ed, alg, pq)
    e = detector_receipt_shape_error(signed)
    if e:
        raise ValueError("signDetectorReceipt: %s" % e)
    return signed


def _is_obj(v: Any) -> bool:
    return isinstance(v, dict)


def category_id(s: Any) -> str:
    """Vendor category text to a receipt category id (lowercase, non-alphanumerics to `_`); unusable text becomes `other`."""
    if not isinstance(s, str):
        return "other"
    c = re.sub(r"^_+|_+$", "", re.sub(r"[^a-z0-9]+", "_", s.lower()))
    c = re.sub(r"^([0-9])", r"c_\1", c)[:64]
    return c if _ID_RE.fullmatch(c) else "other"


def _receipt(ctx: Dict[str, Any], suspicious: bool, categories: Iterable[str]) -> Dict[str, Any]:
    """ctx: {detector, version, content, secret_key, now, session?, calibration_ref?}."""
    cats = sorted(set(categories), key=_u16)[:8] if suspicious else []
    body: Dict[str, Any] = {
        "v": 1,
        "kind": "pca-detector-receipt",
        "detector": ctx["detector"],
        "version": ctx["version"],
        "input_digest": detector_input_digest(ctx["content"]),
        "verdict": "suspicious" if suspicious else "no_finding",
        "categories": cats,
        "iat": ctx["now"],
    }
    if ctx.get("session") is not None:
        body["session"] = ctx["session"]
    if ctx.get("calibration_ref") is not None:
        body["calibration_ref"] = ctx["calibration_ref"]
    return sign_detector_receipt(body, ctx["secret_key"])


def _error_receipt(ctx: Dict[str, Any]) -> Dict[str, Any]:
    return _receipt(ctx, True, ["detector_error"])


def lakera_receipt(response: Any, ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Lakera Guard v2 `/guard` response."""
    if not _is_obj(response) or not isinstance(response.get("flagged"), bool):
        return _error_receipt(ctx)
    cats: set = set()
    if "breakdown" in response:
        if not isinstance(response["breakdown"], list):
            return _error_receipt(ctx)
        for b in response["breakdown"]:
            if not _is_obj(b) or not isinstance(b.get("detected"), bool):
                return _error_receipt(ctx)
            if b["detected"]:
                cats.add(category_id(b.get("detector_type")))
    suspicious = response["flagged"] or len(cats) > 0
    if suspicious and not cats:
        cats.add("flagged")
    return _receipt(ctx, suspicious, cats)


def prompt_security_receipt(response: Any, ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Prompt Security `/api/protect` response (both published integration shapes accepted; clean only when no action is
    block or modify and no violation is listed)."""
    r = response["result"] if _is_obj(response) and _is_obj(response.get("result")) else None
    if r is None:
        return _error_receipt(ctx)
    p = r.get("prompt")
    if "prompt" in r and not _is_obj(p):
        return _error_receipt(ctx)
    actions = [r["action"]] if "action" in r else []
    if _is_obj(p) and "action" in p:
        actions.append(p["action"])
    if not actions or not all(isinstance(a, str) for a in actions):
        return _error_receipt(ctx)
    violations = p.get("violations") if _is_obj(p) and "violations" in p else None
    if _is_obj(p) and "violations" in p and not isinstance(violations, list):
        return _error_receipt(ctx)
    cats = {category_id(v) for v in (violations or [])}
    if "block" in actions:
        cats.add("blocked")
    if "modify" in actions:
        cats.add("modified")
    return _receipt(ctx, len(cats) > 0, cats)


def generic_receipt(response: Any, ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Any detector that answers `{flagged, categories?}`."""
    if not _is_obj(response) or not isinstance(response.get("flagged"), bool):
        return _error_receipt(ctx)
    if "categories" in response and not isinstance(response["categories"], list):
        return _error_receipt(ctx)
    cats = {category_id(c) for c in (response.get("categories") or [])}
    if not response["flagged"] and cats:
        return _error_receipt(ctx)  # categories on a clean answer: ambiguous
    if response["flagged"] and not cats:
        cats.add("flagged")
    return _receipt(ctx, response["flagged"], cats)
