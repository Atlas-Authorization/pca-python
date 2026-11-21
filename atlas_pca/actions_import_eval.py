"""Measure the suggestion rules against a labeled corpus (native port of import/eval.ts of the TypeScript reference @atlasauth/pca-actions).
Every corpus entry is turned into a source document of its own kind, run through the real importer and the real suggestion engine, and the
traits the system flags are compared with the labels: precision and recall per trait, with an exact Clopper-Pearson bound on each. These are
heuristic numbers on a reviewed corpus, published as what they are, never as a safety guarantee."""
import json
import re
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Dict, List, Optional

from .actions import CORE_REGISTRY, _u16key, closure, hint_traits
from .actions_import_pipeline import import_actions
from .actions_import_suggest import apply_suggestion, default_rules, suggest_with_rules
from .intent_clopper import clopper_pearson_upper
from .intent_wb import _UNDEF

LABEL_SHORT = {
    "money": "money_moving", "destr": "destructive", "comm": "external_communication", "priv": "privilege_change", "exp": "data_export", "exec": "code_execution",
    "cred": "credential_access", "bulk": "bulk", "pii": "pii_access", "pub": "public_exposure", "pers": "persistence", "infra": "infra_mutation", "cost": "cost_incurring",
    "legal": "legal_binding", "imp": "impersonation", "egress": "network_egress", "fin": "financial_data_read", "reg": "regulated_data", "sched": "scheduled", "spawn": "agent_spawning",
}
from .actions import _JS_WS  # noqa: E402


def parse_hand_tsv(text: str) -> List[dict]:
    out: List[dict] = []
    n = 0
    for line in text.split("\n"):
        if len(line.strip(_JS_WS)) == 0 or line.startswith("#"):
            continue
        c = line.split("\t")
        if len(c) < 6:
            raise ValueError("hand corpus line needs 6 columns: %s" % line[:80])
        kind, name, loc, params, labels, description = c[:6]
        n += 1
        e = {"id": "hand-%04d" % n, "src": "hand", "kind": kind, "name": name, "params": [] if params == "-" else params.split(","),
             "labels": [] if labels == "-" else [LABEL_SHORT.get(x, x) for x in labels.split(",")], "description": description}
        if kind == "openapi":
            parts = loc.split(" ")
            e["method"] = parts[0]
            e["path"] = " ".join(parts[1:])
        for x in e["labels"]:
            if x not in LABEL_SHORT.values():
                raise ValueError("unknown label '%s' in %s" % (x, name))
        out.append(e)
    return out


def _no_constant(c: str):
    raise ValueError("not JSON: " + c)


def parse_corpus_jsonl(text: str) -> List[dict]:
    return [json.loads(l, parse_constant=_no_constant) for l in text.split("\n") if len(l.strip(_JS_WS)) > 0]


# ---- entries -> source documents -----------------------------------------------------------------------------------------------

_SPEC_RE = re.compile(r"[^:]+:([a-z]+)(?::([^\n\r  ]+))?\Z")
_TYPE_RE = re.compile(r"[^:]+:([a-z]+)")


def _schema_of(spec: str) -> dict:
    m = _SPEC_RE.match(spec)
    typ, fmt = (m.group(1), m.group(2)) if m else (None, None)
    if typ == "array":
        return {"type": "array", "items": {"type": "string"}}
    return {"type": "number" if typ == "number" else (typ if typ is not None else "string"), **({"format": fmt} if fmt else {})}


def _pname(spec: str) -> str:
    i = spec.find(":")
    return spec[:i] if i >= 0 else spec[:-1]  # slice(0, indexOf(':')) with indexOf -1 drops the last character


_READ_FIRST = frozenset(("get", "list", "find", "search", "count", "describe", "show", "lookup", "check", "validate", "preview", "calculate", "estimate", "convert", "format",
                         "compare", "summarize", "sort", "filter", "read", "fetch", "query", "view", "browse", "open"))


def _first_word(n: str) -> str:
    m = re.match(r"[A-Za-z][a-z0-9]*", n)
    return (m.group(0) if m else n).lower()


def _openapi_doc(es: List[dict]) -> dict:
    paths: Dict[str, dict] = {}
    for e in es:
        method = (e.get("method") if e.get("method") is not None else "get").lower()
        body = method in ("post", "put", "patch")
        props = {_pname(p): _schema_of(p) for p in e["params"]}
        path_params = [{"name": m.group(1), "in": "path", "required": True, "schema": {"type": "string"}} for m in re.finditer(r"\{([^}]+)\}", e.get("path") or "")]
        op: dict = {}
        if e["name"]:
            op["operationId"] = e["name"]
        if e["description"]:
            op["summary"] = e["description"]
        op["parameters"] = [*path_params, *([] if body else [{"name": _pname(p), "in": "query", "schema": _schema_of(p)} for p in e["params"] if not any(q["name"] == _pname(p) for q in path_params)])]
        if body and len(e["params"]) > 0:
            op["requestBody"] = {"content": {"application/json": {"schema": {"type": "object", "properties": props, "required": []}}}}
        paths.setdefault(e["path"] if e.get("path") is not None else "undefined", {})[method] = op
    return {"openapi": "3.0.3", "info": {"title": "corpus", "version": "1"}, "paths": paths}


_GQL = {"string": "String", "integer": "Int", "boolean": "Boolean", "array": "[String]"}
_PROTO = {"string": "string", "integer": "int64", "boolean": "bool", "array": "repeated string"}


def _type_word(spec: str) -> str:
    m = _TYPE_RE.match(spec)
    return m.group(1) if m else "string"


def _graphql_sdl(es: List[dict]) -> str:
    q: List[str] = []
    m: List[str] = []
    for e in es:
        args = "(%s)" % ", ".join("%s: %s" % (_pname(p), _GQL.get(_type_word(p), "String")) for p in e["params"]) if e["params"] else ""
        target = q if (_first_word(e["name"]) in _READ_FIRST or re.fullmatch(r"[a-z]+s?", e["name"])) else m
        target.append('  "%s"\n  %s%s: String' % (e["description"].replace('"', "'"), e["name"], args))
    return ("type Query {\n%s\n}\n" % "\n".join(q) if q else "") + ("type Mutation {\n%s\n}\n" % "\n".join(m) if m else "")


def _proto_text(es: List[dict]) -> str:
    svcs: Dict[str, List[dict]] = {}
    for e in es:
        svcs.setdefault(e["name"].split("/")[0], []).append(e)
    msgs = ["message Empty {}"]
    out: List[str] = []
    for s, lst in svcs.items():
        rpcs = []
        for e in lst:
            mname = e["name"].split("/")[1]
            msgs.append("message %sRequest {\n%s\n}" % (mname, "\n".join("  %s %s = %d;" % (_PROTO.get(_type_word(p), "string"), _pname(p), i + 1) for i, p in enumerate(e["params"]))))
            rpcs.append("  rpc %s(%sRequest) returns (Empty);" % (mname, mname))
        out.append("service %s {\n%s\n}" % (s, "\n".join(rpcs)))
    return 'syntax = "proto3";\npackage corpus;\n%s\n%s\n' % ("\n".join(msgs), "\n".join(out))


def _async_doc(es: List[dict]) -> dict:
    channels = {e["name"]: {"publish": {"summary": e["description"], "message": {"payload": {"type": "object", "properties": {_pname(p): _schema_of(p) for p in e["params"]}}}}} for e in es}
    return {"asyncapi": "2.6.0", "info": {"title": "corpus", "version": "1"}, "channels": channels}


def _mcp_doc(es: List[dict]) -> list:
    return [{"name": e["name"], "description": e["description"], "inputSchema": {"type": "object", "properties": {_pname(p): _schema_of(p) for p in e["params"]}}} for e in es]


def _key_of(e: dict) -> str:
    return "%s %s" % ((e.get("method") if e.get("method") is not None else "GET").upper(), e.get("path")) if e["kind"] == "openapi" else e["name"]


def _def_key(d: dict) -> str:
    b = d.get("bindings") or {}
    oa, gq, gr, aa, mc = b.get("openapi"), b.get("graphql"), b.get("grpc"), b.get("asyncapi"), b.get("mcp")
    cands = [
        "%s %s" % (oa["method"], oa["path"]) if oa and oa.get("path") else None,
        oa.get("operationId") if oa else None,
        mc.get("tool") if mc else None,
        gq.get("field") if gq else None,
        "%s/%s" % (gr["service"].split(".")[-1], gr["method"]) if gr else None,
        aa.get("channel") if aa else None,
    ]
    return next((c for c in cands if c is not None), "")


def import_corpus(entries: List[dict]) -> dict:
    """Import every entry with the real importer of its kind: the drafts by entry id (an entry whose def was not emitted is absent)."""
    defs: Dict[str, dict] = {}
    todo = 0
    groups: Dict[str, List[dict]] = {}
    for e in entries:
        groups.setdefault("%s|%s" % (e["kind"], e["spec"] if e.get("spec") is not None else ""), []).append(e)
    for g, es in groups.items():
        kind = g.split("|")[0]
        src = _openapi_doc(es) if kind == "openapi" else _mcp_doc(es) if kind == "mcp" else _graphql_sdl(es) if kind == "graphql" else _proto_text(es) if kind == "grpc" else _async_doc(es)
        r = import_actions(kind, src, {"ns": "corpus", "limits": {"max_ops": 50_000, "max_nodes": 20_000_000, "max_bytes": 200_000_000}})
        todo += len(r["todo"])
        by_key = {_def_key(d): d for d in r["defs"]}
        for e in es:
            d = by_key.get(_key_of(e))
            if d:
                defs[e["id"]] = d
    return {"defs": defs, "todo": todo}


# ---- scoring -----------------------------------------------------------------------------------------------------------------

def real_split(spec: Optional[str] = None) -> str:
    """Deterministic split of the real corpus by specification: rules are tuned on `tune` specs only; `holdout` specs are never looked at."""
    h = 2166136261
    for ch in spec or "":
        o = ord(ch)
        unit = o if o <= 0xFFFF else 0xD800 + ((o - 0x10000) >> 10)  # charCodeAt(0) of a code point: its first UTF-16 unit
        h = ((h ^ unit) * 16777619) & 0xFFFFFFFF
    return "tune" if (h >> 7) % 2 == 0 else "holdout"


def _source_of(e: dict) -> str:
    return "real/%s" % real_split(e.get("spec")) if e["src"] == "real" else e["src"]


def _stat(trait: str, rows: List[tuple], alpha: float) -> dict:
    tp = fp = fn = 0
    for actual, predicted in rows:
        if actual and predicted:
            tp += 1
        elif predicted:
            fp += 1
        elif actual:
            fn += 1
    pos, pred = tp + fn, tp + fp
    return {
        "trait": trait, "positives": pos, "predicted": pred, "tp": tp, "fp": fp, "fn": fn,
        "precision": None if pred == 0 else tp / pred,
        "recall": None if pos == 0 else tp / pos,
        "recall_lower": None if pos == 0 else 1 - clopper_pearson_upper(fn, pos, alpha),
        # the exact bound costs O(n * k) big-integer products: affordable for recall (few misses), not for precision over thousands of flags
        "precision_lower": None if pred == 0 or pred > 600 else 1 - clopper_pearson_upper(fp, pred, alpha),
    }


def eval_suggest(entries: List[dict], rules: Optional[dict] = None, registry: Optional[dict] = None, alpha: Optional[float] = None) -> dict:
    rules = rules or default_rules()
    registry = registry or CORE_REGISTRY
    alpha = 0.05 if alpha is None else alpha
    defs = import_corpus(entries)["defs"]
    trait_names = sorted((re.sub(r"^pca\.", "", t) for t in registry if t not in ("pca.unreviewed", "pca.irreversible")), key=_u16key)
    flagged: Dict[str, set] = {}
    added: Dict[str, set] = {}
    for e in entries:
        d = defs.get(e["id"])
        if not d:
            continue
        s = suggest_with_rules(d, rules, registry)
        sd = apply_suggestion(d, s, {"rules": {"version": rules["version"], "digest": "", "fired": s["fired"]}})
        flagged[e["id"]] = {re.sub(r"^pca\.", "", t) for t in closure(registry, hint_traits(sd)) if t != "pca.unreviewed"}
        added[e["id"]] = {re.sub(r"^pca\.", "", t) for t in s["traits"]}

    def score(es: List[dict], pred: Dict[str, set]) -> List[dict]:
        stats = [_stat(t, [(t in e["labels"], t in pred.get(e["id"], ())) for e in es], alpha) for t in trait_names]
        return [s for s in stats if s["positives"] > 0 or s["predicted"] > 0]

    sources = sorted({*(_source_of(e) for e in entries), *(["real"] if any(e["src"] == "real" for e in entries) else [])}, key=_u16key)
    by_source = {}
    for s in sources:
        es = [e for e in entries if (e["src"] == "real" if s == "real" else _source_of(e) == s)]
        by_source[s] = {"entries": len(es), "flagged": score(es, flagged)}
    return {"alpha": alpha, "entries": len(entries), "mapped": len(defs), "rules_version": rules["version"], "flagged": score(entries, flagged),
            "suggested": score(entries, added), "by_source": by_source}


def _pct(x: Optional[float]) -> str:
    if x is None:
        return "-"
    return "%s%%" % Decimal(x * 100).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)  # Number.prototype.toFixed(1)


def render_eval_markdown(r: dict) -> str:
    def table(stats: List[dict]) -> str:
        return "\n".join(["| trait | labeled | flagged | recall | recall lower bound | precision | missed | false alarms |", "|---|---:|---:|---:|---:|---:|---:|---:|",
                          *("| %s | %d | %d | %s | %s | %s | %d | %d |" % (s["trait"], s["positives"], s["predicted"], _pct(s["recall"]), _pct(s["recall_lower"]), _pct(s["precision"]), s["fn"], s["fp"]) for s in stats)])

    lines = [
        "# Suggestion rules %s: measured on a labeled corpus" % r["rules_version"],
        "",
        "%d labeled operations (%d imported). Lower bounds are one-sided exact Clopper-Pearson at alpha = %s." % (r["entries"], r["mapped"], _js_num(r["alpha"])),
        "These are heuristic numbers on a reviewed corpus. They are not a safety guarantee: an unreviewed action is always held at the most restrictive floor.",
        "",
        "## What a reviewer is shown (importer facts plus suggestions)", "", table(r["flagged"]), "",
        "## What the suggestion rules added", "", table(r["suggested"]), "",
    ]
    for s, v in r["by_source"].items():
        lines += ["## Source: %s (%d operations)" % (s, v["entries"]), "", table(v["flagged"]), ""]
    return "\n".join(lines)


def _js_num(v: Any) -> str:
    from .sdjwt_jws import js_num
    return js_num(v)


def floor_failures(r: dict, f: dict) -> List[str]:
    """Empty when the report meets the floors; else one line per failure."""
    out: List[str] = []
    real = r["by_source"].get("real/holdout")
    if not real or real["entries"] < f["real"]["min_entries"]:
        out.append("the real-spec hold-out has %d operations, fewer than the required %d" % (real["entries"] if real else 0, f["real"]["min_entries"]))
    if r["mapped"] < r["entries"]:
        out.append("%d corpus operations were not imported" % (r["entries"] - r["mapped"]))
    for t, floor in f["real"]["recall_lower"].items():
        s = next((x for x in real["flagged"] if x["trait"] == t), None) if real else None
        need = f["real"]["min_positives"].get(t, 0)
        if not s or s["positives"] < need:
            out.append("%s: %d real labeled positives, fewer than the %d the floor needs" % (t, s["positives"] if s else 0, need))
        elif s["recall_lower"] is None or s["recall_lower"] < floor:
            out.append("%s: hold-out recall lower bound %s is below the recorded floor %s" % (t, _pct(s["recall_lower"]), _pct(floor)))
    syn = r["by_source"].get("syn")
    for t, floor in f["regression"]["recall_lower"].items():
        s = next((x for x in syn["flagged"] if x["trait"] == t), None) if syn else None
        if not s or s["recall_lower"] is None or s["recall_lower"] < floor:
            out.append("%s: regression-set recall lower bound %s is below %s" % (t, _pct(s["recall_lower"] if s else None), _pct(floor)))
    return out
