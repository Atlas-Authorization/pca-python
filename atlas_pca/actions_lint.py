"""The 24 stable lint rules over action definitions, SARIF output and the digest of the rule list (native port of lint.ts of the
TypeScript reference @atlasauth/pca-actions). Pure: defs in, findings out, deterministic order. A def that fails validate_def is
reported as LD-000 and not linted further."""
import re
from typing import Any, Callable, Dict, List, Optional

from .actions import (
    CONTEXT_KEYS, CORE_REGISTRY, EFFECTS, SENSITIVITY_RANK, _JS_WS, _is_context_key, _u16key, def_digest, effective_param_sensitivity,
    extend_registry, is_format, is_read_only, is_role, normalize, traits_digest, validate_def,
)
from .actions_effective import effective_with, prules_violations
from .actions_undo import compensation_shape, may_be_reversible
from .intent_wb import _js_str, _utf16_len
from .pca import hash_canonical

LINT_RULES = (
    ("LD-001", "error", "a destroy-like verb whose effects do not delete"),
    ("LD-002", "error", "a money parameter without a currency, or a currency without the iso_currency format"),
    ("LD-003", "error", "a numeric parameter without min and max"),
    ("LD-004", "error", "a money-moving action without idempotency"),
    ("LD-005", "error", "personal data can leave without the matching effect"),
    ("LD-006", "error", "a declared reversibility or blast below the effective floor"),
    ("LD-007", "error", "an unknown trait, role, format, effect or context key, or an invalid custom trait"),
    ("LD-008", "error", "resource id '*' with scope one"),
    ("LD-009", "error", "a duplicate verb or alias collision"),
    ("LD-010", "error", "a write marked reversible with no compensating action in the pack"),
    ("LD-011", "error", "review state confirmed without a valid attestation for this digest"),
    ("LD-012", "error", "a structural param rule that the effective traits require is violated"),
    ("LD-013", "error", "a read-only action that can mutate or handles credentials"),
    ("LD-014", "error", "one binding in two defs"),
    ("LW-001", "warning", "description missing or too long, or title not imperative"),
    ("LW-002", "warning", "a string parameter without max_len"),
    ("LW-003", "warning", "free text flows into an outbound action without the free_text_outbound tag"),
    ("LW-004", "warning", "an unreviewed def in a stable pack"),
    ("LW-005", "warning", "a dismissed suggested trait without a reason"),
    ("LW-006", "warning", "an array parameter without max_items"),
    ("LW-007", "warning", "a critical parameter without provenance_min"),
    ("LW-008", "warning", "verb naming inconsistent with its siblings or with the file namespace"),
    ("LW-009", "warning", "a money-moving, destructive or privilege-changing action without an example"),
    ("LW-010", "warning", "since is missing"),
)
_SEVERITY = {r[0]: r[1] for r in LINT_RULES}
NOTE_RULE = ("LN-001", "note", "an informational note from the loader")
STRUCTURE_RULE = ("LD-000", "error", "the def is not well formed and cannot be loaded")
LINT_RULES_DIGEST_DOMAIN = "atlas-pca/action-lint-rules/v1"

_DESTROY_RE = re.compile(r"(?:delete|destroy|remove|purge|drop|erase|wipe|revoke|terminate|truncate)(?:_|\Z)")
_SEND_RE = re.compile(r"(?:send|email|notify|sms|message|post_to|broadcast|invite)(?:_|\Z)")
_EXPORT_RE = re.compile(r"(?:export|download|dump|backup|extract)(?:_|\Z)")
_WS_SPLIT = re.compile("[" + re.escape(_JS_WS) + "]+")
_NAME_GROUPS = (("create_", "new_", "add_", "make_"), ("delete_", "remove_", "destroy_"))


def lint_rules_digest() -> str:
    """The digest pca-policy-ci pins: the ordered (id, severity, title) list."""
    return hash_canonical({"d": LINT_RULES_DIGEST_DOMAIN, "rules": [{"id": r[0], "severity": r[1], "title": r[2]} for r in LINT_RULES]})


def _u8(s: str) -> int:
    return len(s.encode("utf-8", "surrogatepass"))


def _last_seg(verb: str) -> str:
    return verb.split(".")[-1]


def _binding_keys(d: dict) -> List[str]:
    b = d.get("bindings") or {}
    out: List[str] = []
    if b.get("mcp"):
        out.append("mcp:%s" % _js_str(b["mcp"].get("tool")))
    if b.get("openapi"):
        out.append("openapi:%s" % _js_str(b["openapi"].get("operationId")))
    if b.get("http"):
        out.append("http:%s %s" % (b["http"]["method"].upper(), b["http"]["path"]))
    if b.get("graphql"):
        out.append("graphql:%s.%s" % (b["graphql"]["op"], b["graphql"]["field"]))
    if b.get("grpc"):
        out.append("grpc:%s/%s" % (b["grpc"]["service"], b["grpc"]["method"]))
    if b.get("asyncapi"):
        out.append("asyncapi:%s %s" % (b["asyncapi"]["op"], b["asyncapi"]["channel"]))
    return out


def _vocabulary_issues(x: Any, reg: Dict[str, dict]) -> List[str]:
    """Vocabulary problems of a raw def (LD-007). Reads only what a malformed def can still be asked."""
    if not isinstance(x, dict):
        return []
    out: List[str] = []
    if isinstance(x.get("effects"), list):
        for e in x["effects"]:
            if not (isinstance(e, str) and e in EFFECTS):
                out.append("unknown effect '%s'" % _js_str(e))
    if isinstance(x.get("params"), dict):
        for n, q in x["params"].items():
            if not isinstance(q, dict):
                continue
            if "role" in q and not is_role(q["role"]):
                out.append("%s: unknown role '%s'" % (n, _js_str(q["role"])))
            if "format" in q and not is_format(q["format"]):
                out.append("%s: unknown format '%s'" % (n, _js_str(q["format"])))
    if isinstance(x.get("context"), list):
        for c in x["context"]:
            if not _is_context_key(c):
                out.append("unknown context key '%s' (known: %s, session_taint_max:<level>)" % (_js_str(c), ", ".join(CONTEXT_KEYS)))
    if isinstance(x.get("traits"), list):
        for t in x["traits"]:
            if isinstance(t, str) and t not in reg:
                out.append("unknown trait '%s'" % t)
    return out


def lint_defs(raw: List[Any], opts: Optional[dict] = None, attestation_verified: Optional[Callable[[dict], Any]] = None) -> List[dict]:
    """Lint a pack's defs (raw values, so a malformed one is still reported). opts: {customTraits, stability, ns}. Findings are sorted by
    verb, rule, param, message. Errors fail CI; warnings fail under strict."""
    opts = opts or {}
    out: List[dict] = []

    def add(rule: str, d: Optional[dict], message: str, param: Optional[str] = None) -> None:
        f: Dict[str, Any] = {"rule": rule, "severity": "error" if rule == STRUCTURE_RULE[0] else _SEVERITY[rule]}
        if d is not None and d.get("verb") is not None:
            f["verb"] = d["verb"]
        if param is not None:
            f["param"] = param
        f["message"] = message
        out.append(f)

    reg = CORE_REGISTRY
    ct = opts.get("customTraits")
    if ct:
        try:
            reg = extend_registry(CORE_REGISTRY, ct)
        except Exception as e:  # noqa: BLE001
            add("LD-007", None, "invalid custom traits: %s" % e)

    defs: List[dict] = []
    for x in raw:
        verb = x["verb"] if isinstance(x, dict) and isinstance(x.get("verb"), str) else None
        vocab = _vocabulary_issues(x, reg)
        if vocab:
            for v in vocab:
                add("LD-007", {"verb": verb}, v)
            continue
        bad = validate_def(x)
        if bad:
            add(STRUCTURE_RULE[0], {"verb": verb}, bad)
            continue
        defs.append(x)

    # ---- pack-level rules
    by_verb: Dict[str, dict] = {}
    names: Dict[str, str] = {}
    for d in defs:
        if d["verb"] in by_verb:
            add("LD-009", d, "verb '%s' is defined twice" % d["verb"])
        by_verb[d["verb"]] = d
    for d in defs:
        for n in [d["verb"]] + list(d.get("aliases") or []):
            owner = names.get(n)
            if owner is not None and owner != d["verb"]:
                add("LD-009", d, "'%s' is also a name of '%s'" % (n, owner))
            elif n not in names:
                names[n] = d["verb"]
    bound: Dict[str, str] = {}
    for d in defs:
        for k in _binding_keys(d):
            owner = bound.get(k)
            if owner is not None and owner != d["verb"]:
                add("LD-014", d, "binding %s is also bound by '%s'" % (k, owner))
            else:
                bound[k] = d["verb"]
    for grp in _NAME_GROUPS:
        used: Dict[str, int] = {}
        for d in defs:
            g = next((p for p in grp if _last_seg(d["verb"]).startswith(p)), None)
            if g:
                used[g] = used.get(g, 0) + 1
        if len(used) > 1:
            win = sorted(used.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
            for d in defs:
                g = next((p for p in grp if _last_seg(d["verb"]).startswith(p)), None)
                if g and g != win:
                    add("LW-008", d, "uses '%s' where its siblings use '%s'" % (g, win))
    if opts.get("ns") is not None:
        for d in defs:
            if d["verb"].split(".")[0] != opts["ns"]:
                add("LW-008", d, "verb namespace '%s' differs from the file namespace '%s'" % (d["verb"].split(".")[0], opts["ns"]))

    # ---- per-def rules
    for d in defs:
        n = normalize(d)
        pnames = sorted(n["params"], key=_u16key)
        eff = effective_with(d, reg, attestation_verified)
        tset = set(eff["hint"]["traits"])
        cl = set(eff["hint"]["closure"])
        effects = d["effects"]

        def params(pred) -> List[str]:
            return [k for k in pnames if pred(n["params"][k])]

        if _DESTROY_RE.match(_last_seg(d["verb"])) and "delete" not in effects:
            add("LD-001", d, "the verb says '%s' but effects do not include delete" % _last_seg(d["verb"]))
        for k in params(lambda q: q.get("role") in ("money.amount", "money.fee")):
            u = n["params"][k].get("unit")
            if not u or u["kind"] != "money":
                add("LD-002", d, "a money parameter needs a unit of kind money with a currency", k)
            elif not isinstance(u["ccy"], str):
                c = n["params"].get(u["ccy"]["from"])
                if not c or c.get("role") != "money.currency" or c.get("format") != "iso_currency":
                    add("LD-002", d, "the currency parameter '%s' needs role money.currency and format iso_currency" % u["ccy"]["from"], k)
        for k in params(lambda q: q.get("role") == "money.currency"):
            if n["params"][k].get("format") != "iso_currency":
                add("LD-002", d, "a currency parameter needs the iso_currency format", k)
        for k in params(lambda q: q["type"] in ("integer", "duration")):
            q = n["params"][k]
            if q.get("role") is not None and q["role"].startswith("id."):
                continue
            if q.get("role") == "count.limit" and "max" in q:
                continue
            if "min" not in q or "max" not in q:
                add("LD-003", d, "a numeric parameter needs both min and max (has %s, %s)" % ("no min" if "min" not in q else "min", "no max" if "max" not in q else "max"), k)
        if ("pay" in effects or "pca.money_moving" in tset) and n["idempotency"]["mode"] == "none":
            add("LD-004", d, "a money-moving action needs idempotency key_param or natural")
        pii = params(lambda q: "pii" in (q.get("tags") or []) or (q.get("role") is not None and (q["role"].startswith("contact.") or q["role"].startswith("person."))))
        if pii:
            expected = set()
            for s in d.get("side_effects") or []:
                if s["kind"] in ("send", "export"):
                    expected.add(s["kind"])
            if _SEND_RE.match(_last_seg(d["verb"])):
                expected.add("send")
            if _EXPORT_RE.match(_last_seg(d["verb"])):
                expected.add("export")
            for e in sorted(expected):
                if e not in effects:
                    add("LD-005", d, "personal data can %s (%s) but effects do not include %s" % ("be sent" if e == "send" else "be exported", ", ".join(pii), e))
        for c in eff["clamps"]:
            add("LD-006", d, "declared %s %s is below the floor %s" % ("reversibility" if c["field"] == "rev" else "blast", _js_str(c["declared"]), _js_str(c["floor"])))
        if n["resource"]["id"] == "*" and n["resource"]["scope"] == "one":
            add("LD-008", d, "resource id '*' with scope one names every resource at once")
        if not is_read_only(effects) and may_be_reversible(d):
            if d.get("compensates") is None:
                add("LD-010", d, "a write declared reversible must name its compensating action (compensates)")
            elif d["compensates"] not in by_verb:
                add("LD-010", d, "compensates '%s', which is not in the pack" % d["compensates"])
            else:
                s = compensation_shape(d, by_verb[d["compensates"]])
                if not s["ok"]:
                    add("LD-010", d, "compensates '%s', which cannot undo it: %s" % (d["compensates"], s["reason"]))
        review = d["review"]
        if review["state"] == "confirmed":
            a = review.get("attestation")
            if a is None:
                add("LD-011", d, "confirmed without an attestation")
            elif a.get("def_digest") != def_digest(d):
                add("LD-011", d, "the attestation covers a different digest of this def")
            elif a.get("traits_digest") != traits_digest(reg):
                add("LD-011", d, "the attestation was made against a different trait registry")
            elif (not attestation_verified(d)) if attestation_verified else "sig" not in a:
                add("LD-011", d, "the attestation is not signed by a pinned reviewer")
        dismissed = (review.get("attestation") or {}).get("dismissed") or [] if review["state"] == "confirmed" else []
        dismissed_names = {x["trait"] for x in dismissed}
        for t in (review.get("provenance") or {}).get("union") or []:
            if t not in cl and t not in dismissed_names:
                add("LD-011", d, "the union-added trait %s was removed without a signed dismissal" % t)
        own = ("money_has_currency", "money_amount_bounded", "pay_has_idempotency")
        for r in prules_violations(d, eff["hint"]["eff"]["prules"]):
            if r not in own:
                add("LD-012", d, "structural rule %s is required by the action's traits and violated" % r)
        if is_read_only(effects):
            enforced = "sandbox_attested" in (d.get("context") or [])
            for k in params(lambda q: q.get("role") in ("code.command", "query.sql")):
                if not enforced:
                    add("LD-013", d, "a read-only action takes code or a query it cannot prove read-only (declare context sandbox_attested)", k)
            for k in params(lambda q: "credential" in (q.get("tags") or [])):
                add("LD-013", d, "a read-only action handles a credential", k)

        # ---- warnings
        if "description" not in d:
            add("LW-001", d, "description is missing")
        elif _u8(d["description"]) > 400:
            add("LW-001", d, "description is longer than 400 bytes")
        first = _WS_SPLIT.split(d["title"])[0].lower()
        if re.search(r"(?:ing|ed)\Z", first) or (re.search(r"[^s]s\Z", first) and not re.search(r"(?:us|is)\Z", first)) or first in ("a", "an", "the"):
            add("LW-001", d, "title '%s' is not imperative" % d["title"])
        for k in params(lambda q: q["type"] == "string" and "max_len" not in q and "values" not in q):
            add("LW-002", d, "a string parameter without max_len (the default is 1024; say it)", k)
        if "pca.external_communication" in cl:
            for k in params(lambda q: q["type"] == "string" and "values" not in q and "format" not in q and (q.get("role") is None or q["role"].startswith("text.")) and "free_text_outbound" not in (q.get("tags") or [])):
                if k != n["idempotency"].get("param"):
                    add("LW-003", d, "free text flows into an outbound action without tags: [free_text_outbound]", k)
        if opts.get("stability") == "stable" and review["state"] in ("unreviewed", "suggested"):
            add("LW-004", d, "a %s def in a stable pack" % review["state"])
        for x in (review.get("attestation") or {}).get("dismissed") or []:
            if _utf16_len(x["reason"].strip(_JS_WS)) < 5:
                add("LW-005", d, "dismissed trait %s has no reason" % x["trait"])
        for k in params(lambda q: q["type"] == "array" and q.get("max_items") is None):
            add("LW-006", d, "an array parameter without max_items", k)
        for k in params(lambda q: SENSITIVITY_RANK[effective_param_sensitivity(q)] >= SENSITIVITY_RANK["critical"] and "provenance_min" not in q):
            add("LW-007", d, "a critical parameter without provenance_min", k)
        if ("pca.money_moving" in tset or "pca.destructive" in tset or "pca.privilege_change" in tset) and len(d.get("examples") or []) == 0:
            add("LW-009", d, "no example for a money-moving, destructive or privilege-changing action")
        if "since" not in d:
            add("LW-010", d, "since is missing")

    def key(f: dict):
        return (_u16key(f.get("verb") or ""), _u16key(f["rule"]), _u16key(f.get("param") or ""), _u16key(f["message"]))

    return sorted(out, key=key)


def lint_fails(fs: List[dict], strict: bool = False) -> bool:
    """Does the run fail? Errors always; warnings under `strict`."""
    return any(f["severity"] == "error" or (strict and f["severity"] == "warning") for f in fs)


def lint_text(fs: List[dict]) -> str:
    """Plain text, one line per finding."""
    if not fs:
        return "0 errors, 0 warnings"
    e = sum(1 for f in fs if f["severity"] == "error")
    w = sum(1 for f in fs if f["severity"] == "warning")
    lines = []
    for f in fs:
        loc = ""
        if f.get("file"):
            loc = "%s%s: " % (f["file"], ":%s:%s" % (_js_str(f["line"]), _js_str(f.get("column") if f.get("column") is not None else 1)) if f.get("line") is not None else "")
        v, p = f.get("verb"), f.get("param")
        lines.append("%s %s  %s%s%s%s%s" % (f["severity"].ljust(7), f["rule"], loc, v or "", " [%s]" % p if p else "", ": " if v or p else "", f["message"]))
    notes = len(fs) - e - w
    return "%s\n%d error%s, %d warning%s%s" % ("\n".join(lines), e, "" if e == 1 else "s", w, "" if w == 1 else "s",
                                               ", %d note%s" % (notes, "" if notes == 1 else "s") if notes > 0 else "")


def to_sarif(fs: List[dict], tool: Optional[dict] = None) -> dict:
    """SARIF 2.1.0, so findings appear as pull request annotations."""
    tool = tool or {}
    rules = [STRUCTURE_RULE, NOTE_RULE] + list(LINT_RULES)

    def level(s: str) -> str:
        return "error" if s == "error" else "warning" if s == "warning" else "note"

    driver: Dict[str, Any] = {"name": tool["name"] if tool.get("name") is not None else "pca actions lint"}
    if tool.get("version"):
        driver["version"] = tool["version"]
    driver["rules"] = [{"id": r[0], "shortDescription": {"text": r[2]}, "defaultConfiguration": {"level": level(r[1])}} for r in rules]
    results = []
    for f in fs:
        loc: Dict[str, Any] = {}
        if f.get("file"):
            pl: Dict[str, Any] = {"artifactLocation": {"uri": f["file"]}}
            if f.get("line") is not None:
                pl["region"] = {"startLine": f["line"], "startColumn": f["column"] if f.get("column") is not None else 1}
            loc["physicalLocation"] = pl
        if f.get("verb"):
            loc["logicalLocations"] = [{"name": f["verb"], "kind": "member"}]
        prefix = "%s%s: " % (f["verb"], " [%s]" % f["param"] if f.get("param") else "") if f.get("verb") else ""
        results.append({"ruleId": f["rule"], "level": level(f["severity"]), "message": {"text": prefix + f["message"]}, "locations": [loc]})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": driver}, "results": results}]}
