"""Run every def's executable examples through the real pipeline in process (native port of test-runner.ts of the TypeScript reference
@atlasauth/pca-actions): derive the schema, conform the params, expand the floors, decide; plus the generic property checks of the pack:
monotonicity over trait additions and subsets, one digest across the JSON and YAML forms, and the schema round trip (the example conforms;
every mutation of it is refused). The example policy (`under`) is a small allow selector evaluated here; it can only pre-authorize.
The YAML form of the digest property needs a YAML emitter and loader, which this package does not carry: pass `yaml_load(def) -> load result`
(the caller's emit-and-load round trip) to check it; without one the check runs over the value form of the same document."""
import json
from typing import Any, Callable, Dict, List, Optional

from .actions import (
    CAVEAT_KINDS, ActionKitError, _u16key, def_digest, floor_decision, floor_of, leq,
)
from .actions_author import load_actions_text, load_actions_value
from .actions_derive import flatten_params, operation_of, to_schema_doc
from .actions_effective import eff_with_trait, effective_with
from .intent_v2 import conform_action
from .intent_wb import _UNDEF

_META = {"site": "https://example.invalid", "aud": "example", "version": "0"}
_SEL_KEYS = ("trait", "verb", "where", "caveats", "context")


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _hint_of(d: dict, reg: dict) -> dict:
    """Examples and property checks describe the action AS REVIEWED (its hint view): authoring tests, not enforcement."""
    e = effective_with(d, reg)
    return {**e, **e["hint"], "confirmed": True}


def _core_trait_ids() -> List[str]:
    from .actions import CORE_TRAIT_DEFS
    return [t["id"] for t in CORE_TRAIT_DEFS]


def _parse_under(under: Any):
    if under is _UNDEF:
        return []
    if not isinstance(under, dict) or any(k != "allow" for k in under):
        return "under must be {allow: selector | [selector]}"
    allow = under.get("allow")
    out = []
    for s in (allow if isinstance(allow, list) else [allow]):
        if not isinstance(s, dict) or any(k not in _SEL_KEYS for k in s):
            return "an allow selector has trait, verb, where, caveats, context"
        if ("trait" not in s) == ("verb" not in s):
            return "an allow selector names exactly one of trait and verb"
        if "where" in s and not isinstance(s["where"], dict):
            return "where must be an object"
        if "caveats" in s and (not isinstance(s["caveats"], list) or not all(c in CAVEAT_KINDS for c in s["caveats"])):
            return "caveats must be known caveat kinds"
        out.append(s)
    return out


def _domain_of(v: str) -> str:
    return v[v.rfind("@") + 1:].lower()


def _grant_of(sel: dict, d: dict, flat: dict, eff: dict) -> Optional[List[str]]:
    """The caveats of the grant a matching allow selector stands for, or None when it does not match this call."""
    if "trait" in sel and (sel["trait"] if "." in sel["trait"] else "pca." + sel["trait"]) not in eff["closure"]:
        return None
    if "verb" in sel and sel["verb"] != d["verb"]:
        return None
    caveats: Dict[str, None] = dict.fromkeys(sel.get("caveats") or [])
    for key, cond in (sel.get("where") or {}).items():
        dom = key.endswith(".domain")
        name = key[:-len(".domain")] if dom else key
        pd = d["params"].get(name)
        if not pd:
            return None
        if name not in flat:
            return None
        v = flat[name]
        if isinstance(cond, list):
            if not isinstance(v, str) or (_domain_of(v) if dom else v) not in cond:
                return None
        elif isinstance(cond, dict):
            if not _is_num(v) or ("max" in cond and v > cond["max"]) or ("min" in cond and v < cond["min"]):
                return None
        else:
            return None
        role = pd.get("role") or ""
        if role.startswith("contact.") or role == "party.payee":
            caveats["recipient_scope"] = None
        elif role == "money.amount":
            caveats["amount_cap"] = None
        elif role == "count.limit":
            caveats["count_cap"] = None
        elif role.startswith("id."):
            caveats["resource_scope"] = None
    return list(caveats)


def decide_example(d: dict, ex: dict, reg: dict, defs: List[dict]) -> dict:
    """Decide one example: {got, why}."""
    doc = to_schema_doc(defs, reg, _META)
    flat = flatten_params(ex["params"])
    c = conform_action(doc, d["verb"], flat)
    if not c["ok"]:
        return {"got": "deny", "why": "schema_violation %s%s" % (c.get("code"), " (%s)" % c["path"] if c.get("path") else "")}
    op = operation_of(d, {"params": ex["params"]})
    if not op["ok"]:
        return {"got": "deny", "why": op["reason"]}
    sels = _parse_under(ex.get("under", _UNDEF))
    if isinstance(sels, str):
        return {"got": "deny", "why": "bad example policy: %s" % sels}
    eff = _hint_of(d, reg)
    call_ctx: Dict[str, None] = {}
    idem = d.get("idempotency")
    if idem and idem.get("mode") == "natural":
        call_ctx["idempotency"] = None
    if idem and idem.get("mode") == "key_param" and idem.get("param") is not None and idem["param"] in flat:
        call_ctx["idempotency"] = None
    grant_caveats: List[str] = []
    pre = 0
    for s in sels:
        g = _grant_of(s, d, flat, eff)
        if g is None:
            continue
        pre = 3
        grant_caveats = list(dict.fromkeys([*grant_caveats, *g]))
        for k in s.get("context") or []:
            call_ctx[k] = None
    got = floor_decision({"caveats": grant_caveats, "max_esc": 3, "preauth_esc": pre}, {"context": list(call_ctx)}, eff["eff"])
    if got == "allow":
        why = "floor satisfied"
    else:
        need = ", ".join([*[k for k in eff["eff"]["caveats"] if k not in grant_caveats], *[k for k in eff["eff"]["context"] if k not in call_ctx]])
        why = "floor needs %s" % (need or "escalation tier %s" % eff["eff"]["esc"])
    return {"got": got, "why": why}


def _mutations(d: dict, flat: dict) -> List[dict]:
    out = [{"name": "extra param", "params": {**flat, "zz_undeclared": "x"}}]
    for k in sorted(flat, key=_u16key):
        pd = d["params"].get(k)
        if not pd:
            continue
        if pd.get("required") is not False:
            out.append({"name": "missing %s" % k, "params": {x: y for x, y in flat.items() if x != k}})
        v = flat[k]
        out.append({"name": "type swap %s" % k, "params": {**flat, k: 12345 if isinstance(v, str) else "x" if _is_num(v) or isinstance(v, bool) else {}}})
        if _is_num(v) and pd["type"] == "integer":
            if pd.get("max") is not None:
                out.append({"name": "above max %s" % k, "params": {**flat, k: pd["max"] + 1}})
            if pd.get("min") is not None:
                out.append({"name": "below min %s" % k, "params": {**flat, k: pd["min"] - 1}})
        if isinstance(v, str) and pd["type"] == "string":
            if pd.get("values"):
                out.append({"name": "outside values %s" % k, "params": {**flat, k: "not_a_listed_value_zz"}})
            if pd.get("max_len") is not None:
                out.append({"name": "too long %s" % k, "params": {**flat, k: "x" * (pd["max_len"] + 1)}})
    return out


def _yaml_form(d: dict) -> dict:
    """The def through real YAML text (written by defs_to_yaml, read by the YAML loader); without ruamel.yaml, the value form."""
    from .actions_yaml_emit import stringify
    ns = d["verb"].split(".")[0]
    r = load_actions_text(stringify({"ns": ns, "actions": [d]}), "yaml")
    if len(r["errors"]) == 1 and r["errors"][0]["message"].startswith("YAML needs ruamel.yaml"):
        return load_actions_value({"ns": ns, "actions": [d]})
    return r


def run_def_tests(defs: List[dict], reg: dict, prop_limit: Optional[int] = None, yaml_load: Optional[Callable[[dict], dict]] = None) -> dict:
    """Run examples and property checks for a set of defs (one pack). `prop_limit` bounds the trait subsets tried per def."""
    examples: List[dict] = []
    props: List[dict] = []
    limit = 256 if prop_limit is None else prop_limit
    for d in defs:
        for index, ex in enumerate(d.get("examples") or []):
            r = decide_example(d, ex, reg, defs)
            examples.append({"verb": d["verb"], "index": index, "expect": ex["expect"], "got": r["got"], "ok": r["got"] == ex["expect"], "why": r["why"]})

        # T2: adding any core trait never lowers the effective profile
        eff = _hint_of(d, reg)
        lowered = [t for t in _core_trait_ids() if not leq(eff["eff"], eff_with_trait(d, t, reg))]
        props.append({"verb": d["verb"], "name": "adding a trait never lowers the profile", "ok": len(lowered) == 0, "detail": ", ".join(lowered)})

        # T2 over subsets of the def's own traits (bounded): F(S) <= F(T)
        ts = eff["traits"]
        bad = 0
        total = min(2 ** min(len(ts), 20), limit)
        top = floor_of(reg, ts)
        for mask in range(total):
            sub = [t for i, t in enumerate(ts) if (mask >> (i % 32)) & 1]  # 32-bit shift counts, as in the reference
            if not leq(floor_of(reg, sub), top):
                bad += 1
        props.append({"verb": d["verb"], "name": "floors are monotone over trait subsets", "ok": bad == 0, "detail": "%d subsets, %d violations" % (total, bad)})

        # one digest across the JSON and YAML forms
        want = def_digest(d)
        via_json = load_actions_text(json.dumps(d), "json")
        via_yaml = yaml_load(d) if yaml_load else _yaml_form(d)
        ok_j = len(via_json["errors"]) == 0 and len(via_json["defs"]) > 0 and def_digest(via_json["defs"][0]) == want
        ok_y = len(via_yaml["errors"]) == 0 and len(via_yaml["defs"]) > 0 and def_digest(via_yaml["defs"][0]) == want
        props.append({"verb": d["verb"], "name": "one digest across JSON and YAML forms", "ok": ok_j and ok_y,
                      "detail": "" if ok_j and ok_y else "json %s; yaml %s" % ("ok" if ok_j else (via_json["errors"][0]["message"] if via_json["errors"] else "digest differs"),
                                                                              "ok" if ok_y else (via_yaml["errors"][0]["message"] if via_yaml["errors"] else "digest differs"))})

        # schema round trip: each example conforms, every mutation is refused
        if len(d.get("examples") or []) == 0:
            props.append({"verb": d["verb"], "name": "schema round trip", "ok": True, "detail": "skipped: no examples"})
            continue
        doc = to_schema_doc(defs, reg, _META)
        accepted: List[str] = []
        tried = 0
        for ex in d["examples"]:
            flat = flatten_params(ex["params"])
            if not conform_action(doc, d["verb"], flat)["ok"]:
                continue  # a deliberately non-conforming example is a deny example
            for m in _mutations(d, flat):
                tried += 1
                if conform_action(doc, d["verb"], m["params"])["ok"]:
                    accepted.append(m["name"])
        props.append({"verb": d["verb"], "name": "schema round trip", "ok": len(accepted) == 0,
                      "detail": "%d mutations refused" % tried if not accepted else "accepted: %s" % ", ".join(dict.fromkeys(accepted))})
    return {"examples": examples, "props": props, "ok": all(e["ok"] for e in examples) and all(q["ok"] for q in props)}


def test_text(r: dict) -> str:
    lines: List[str] = []
    for e in r["examples"]:
        lines.append("%s  %s example %d: expected %s, got %s (%s)" % ("PASS" if e["ok"] else "FAIL", e["verb"], e["index"] + 1, e["expect"], e["got"], e["why"]))
    for q in r["props"]:
        lines.append("%s  %s %s%s" % ("PASS" if q["ok"] else "FAIL", q["verb"], q["name"], ": %s" % q["detail"] if q["detail"] else ""))
    f = len([l for l in lines if l.startswith("FAIL")])
    lines.append("%d passed, %d failed" % (len(lines) - f, f))
    return "\n".join(lines)
