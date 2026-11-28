"""Everything an ActionDef yields (native port of derive.ts and explain.ts of the TypeScript reference @atlasauth/pca-actions):
the signed schema verb and document, the operation binding, risk inputs, policy predicates, ontology terms, the policy card, the
escalation tier, MCP annotations and the plain-language explanation. Rule 22's integrity half (schema_verb_floor_error,
schema_floor_error, registry_of_schema) lives in actions.py. `attestation_verified` is the caller's confirmation verifier."""
import copy
import math
from ._fin import fin
from typing import Any, Callable, Dict, List, Optional

from .actions import (
    SCOPE_BLAST, ActionKitError, closure, def_digest, is_read_only, normalize, traits_digest, worst_reversibility, _u16key, _is_safe_int,
)
from .actions_effective import effective_with
from .actions_idpattern import id_matches

MAX_PARAM_PATH_DEPTH = 3
ESC_TIERS = ("auto", "confirm", "cosign", "stepup")
RISK_NAMES = ("low", "elevated", "high", "critical")
REVERSIBILITY_SCORE = {"reversible": 1, "rate_limited": 0.4, "irreversible": 0}
_CORE_NAMESPACE = "pca."
Verifier = Optional[Callable[[dict], Any]]


# ---- flattened params + role lookup ------------------------------------------------------------------------------------------

def flatten_params(params: dict) -> dict:
    """Nested plain objects become dotted keys (up to 3 segments); arrays and scalars are leaves; a deeper object stays a leaf."""
    out: Dict[str, Any] = {}

    def walk(prefix: str, depth: int, v: Any) -> None:
        if isinstance(v, dict) and depth < MAX_PARAM_PATH_DEPTH and len(v) > 0:
            for k, x in v.items():
                walk(k if prefix == "" else "%s.%s" % (prefix, k), depth + 1, x)
        else:
            out[prefix] = v

    for k, v in params.items():
        walk(k, 1, v)
    return out


def param_by_role(d: dict, role: str) -> str:
    """The unique param carrying `role`, or raises no_param / ambiguous_param."""
    hits = sorted((n for n in d["params"] if d["params"][n].get("role") == role), key=_u16key)
    if not hits:
        raise ActionKitError("no_param", "'%s' has no parameter with role %s" % (d["verb"], role))
    if len(hits) > 1:
        raise ActionKitError("ambiguous_param", "'%s' has several parameters with role %s" % (d["verb"], role))
    return hits[0]


def effect_class(d: dict) -> str:
    """The one adapter to the Goal IR's 4 classes: read | reversible | external_send | irreversible."""
    n = normalize(d)
    if is_read_only(n["effects"]):
        return "read"
    if worst_reversibility(n["reversibility"], n["params"]) == "irreversible":
        return "irreversible"
    if any(e in ("send", "publish", "export") for e in n["effects"]):
        return "external_send"
    return "reversible"


# ---- signed schema (v2) ------------------------------------------------------------------------------------------------------

def _unit_id(p: dict) -> Optional[str]:
    u = p.get("unit")
    if u is None:
        return None
    if u["kind"] != "money":
        return u["kind"]
    return "money." + u["ccy"].lower() if isinstance(u.get("ccy"), str) else None


def _unit_decl(p: dict) -> Optional[dict]:
    u = p.get("unit")
    if u is None:
        return None
    if u["kind"] != "money":
        return {"kind": u["kind"]}
    if not isinstance(u.get("ccy"), str):
        return None
    out = {"kind": "money", "currency": u["ccy"]}
    if "exp" in u:
        out["exponent"] = u["exp"]
    return out


def _to_param_decl(n: dict) -> dict:
    d = {"type": n["type"], "semantic": n["role"] if n.get("role") is not None else "generic." + n["type"], "sensitivity": n["sensitivity"]}
    if not n["required"]:
        d["required"] = False
    if "values" in n:
        d["values"] = list(n["values"])
    for k in ("min", "max", "max_len", "items", "min_items", "max_items", "format", "provenance_min", "default", "principal_neutral_default", "description"):
        if k in n:
            d[k] = copy.deepcopy(n[k])
    uid = _unit_id(n)
    if uid is not None:
        d["unit"] = uid
    if "accumulates" in n:
        d["accumulates_into"] = list(n["accumulates"])
    if "role" in n:
        d["role"] = n["role"]
    if "tags" in n:
        d["tags"] = list(n["tags"])
    return d


def to_schema_verb(d: dict, reg: Dict[str, dict], attestation_verified: Verifier = None) -> dict:
    """{verb, units}: the signed v2 verb declaration of a def (effects, traits, def digest, materialized floors) and the units it needs."""
    n = normalize(d)
    eff = effective_with(d, reg, attestation_verified)
    params: Dict[str, dict] = {}
    units: Dict[str, dict] = {}
    for name in n["params"]:
        p = n["params"][name]
        params["action.params." + name] = _to_param_decl(p)
        uid = _unit_id(p)
        if uid is not None:
            units[uid] = _unit_decl(p)
    v: Dict[str, Any] = {
        "verb": n["verb"], "kind": "read" if is_read_only(n["effects"]) else "write", "params": params, "effects": list(n["effects"]),
        "traits": eff["traits"], "def": def_digest(d), "floors": eff["eff"],
    }
    att = (d.get("review") or {}).get("attestation")
    if eff["confirmed"] and isinstance(att, dict) and "sig" in att:
        v["confirmation"] = att
    r = n["reversibility"]
    if isinstance(r, str):
        v["reversibility"] = r
    else:
        by = {"param": "action.params." + r["by"], "map": dict(r["map"])}
        if "default" in r:
            by["default"] = r["default"]
        v["reversibility_by"] = by
    b = n["bindings"]
    if b.get("mcp") is not None:
        v["mcp"] = {"tool": b["mcp"]["tool"]} if "tool" in b["mcp"] else {}
    if b.get("openapi") is not None:
        v["openapi"] = {"operationId": b["openapi"]["operationId"]} if "operationId" in b["openapi"] else {}
    if "description" in n:
        v["description"] = n["description"]
    return {"verb": v, "units": units}


def to_schema_doc(defs: List[dict], reg: Dict[str, dict], meta: dict, attestation_verified: Verifier = None) -> dict:
    """The unsigned v2 schema document of a set of defs (verbs sorted; units merged, a conflicting redefinition refused)."""
    verbs: List[dict] = []
    units: Dict[str, dict] = {}
    seen = set()
    for d in sorted(defs, key=lambda x: _u16key(x["verb"])):
        if d["verb"] in seen:
            raise ActionKitError("duplicate_verb", "verb '%s' appears twice" % d["verb"])
        seen.add(d["verb"])
        o = to_schema_verb(d, reg, attestation_verified)
        verbs.append(o["verb"])
        for uid, u in o["units"].items():
            prev = units.get(uid)
            if prev is not None and (prev.get("kind") != u.get("kind") or prev.get("currency") != u.get("currency") or prev.get("exponent") != u.get("exponent")):
                raise ActionKitError("unit_conflict", "unit '%s' is declared with two different definitions" % uid)
            units[uid] = u
    custom = sorted((t for t in reg.values() if not t["id"].startswith(_CORE_NAMESPACE)), key=lambda t: _u16key(t["id"]))
    doc: Dict[str, Any] = {"v": 2, "kind": "pca-action-schema", "site": meta["site"], "aud": meta["aud"], "version": meta["version"]}
    if units:
        doc["units"] = units
    doc["verbs"] = verbs
    doc["traits_digest"] = traits_digest(reg)
    if custom:
        doc["trait_defs"] = custom
    if meta.get("pack") is not None:
        doc["pack"] = meta["pack"]
    return doc


# ---- operation binding -------------------------------------------------------------------------------------------------------

def operation_of(d: dict, call: dict) -> dict:
    """{ok: True, op: {verb, resource, params}} or {ok: False, reason}: refuses (never guesses) a missing or non-matching id."""
    flat = flatten_params(call["params"])
    declared = sorted(d["params"], key=_u16key)
    params = {k: flat[k] for k in declared if k in flat}
    rtype, rid, scope = d["resource"]["type"], d["resource"]["id"], d["resource"]["scope"]
    if not (isinstance(rid, str) and rid == "*") and "exact" in rid:
        resource = "%s:%s" % (rtype, rid["exact"])
    else:
        id_param = next((n for n in declared if d["params"][n].get("role") == "id." + rtype), None)
        val = params.get(id_param) if id_param is not None else None
        if isinstance(val, str):
            if not id_matches(rid, val):
                return {"ok": False, "reason": "the id '%s' does not match the resource pattern of %s" % (val, d["verb"])}
            resource = "%s:%s" % (rtype, val)
        elif scope != "one":
            resource = "%s:*" % rtype
        else:
            return {"ok": False, "reason": "%s needs a parameter with role id.%s to name its resource" % (d["verb"], rtype)}
    return {"ok": True, "op": {"verb": d["verb"], "resource": resource, "params": params}}


# ---- risk --------------------------------------------------------------------------------------------------------------------

def _unit01(x: float) -> float:
    return min(1, max(0, x))


def _is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def risk_of(d: dict, eff: dict, params: Optional[dict] = None, opts: Optional[dict] = None) -> dict:
    """Risk inputs for a call: reversibility score and blast from the effective profile; a money.amount param makes the blast
    amount/kappa from the signed kappa (missing or invalid: 1, the worst case). Reads nothing the agent claims."""
    opts = opts or {}
    blast = _unit01(eff["eff"]["blast_ppm"] / 1_000_000)
    money = sorted((n for n in d["params"] if d["params"][n].get("role") == "money.amount"), key=_u16key)
    if money:
        flat = flatten_params(params) if params else {}
        amount = flat.get(money[0])
        kappa = opts.get("kappa")
        blast = _unit01(amount / kappa) if _is_num(amount) and fin(amount) and amount >= 0 and _is_num(kappa) and fin(kappa) and kappa > 0 else 1
    out = {"reversibility": REVERSIBILITY_SCORE[eff["eff"]["rev"]], "blastRadius": blast, "confidence": 1}
    t = opts.get("taint")
    if _is_num(t) and fin(t):
        out["taint"] = _unit01(t)
    return out


# ---- predicates --------------------------------------------------------------------------------------------------------------

def resource_matcher(d: dict) -> str:
    """`<type>:<prefix>*`, `<type>:<exact>` or `<type>:*`."""
    rtype, rid = d["resource"]["type"], d["resource"]["id"]
    if isinstance(rid, str) and rid == "*":
        return rtype + ":*"
    return "%s:%s" % (rtype, rid["exact"]) if "exact" in rid else "%s:%s*" % (rtype, rid["prefix"])


def predicates_of(d: dict, limits: Optional[dict] = None) -> dict:
    """The policy predicate scaffold; a money limit on a def with no money.amount parameter raises (never silently unbounded)."""
    limits = limits or {}
    out: Dict[str, Any] = {"verb": d["verb"], "resource": resource_matcher(d)}
    if "max_amount" in limits:
        m = limits["max_amount"]
        if not _is_safe_int(m) or m < 0:
            raise ActionKitError("bad_limit", "max_amount must be a non-negative safe integer")
        name = param_by_role(d, "money.amount")
        out["where"] = [{"field": "action.params." + name, "op": "lte", "value": m}, {"field": "action.params." + name, "op": "gte", "value": 0}]
    return out


# ---- Goal IR ontology terms --------------------------------------------------------------------------------------------------

def _sorted_u16(xs) -> list:
    return sorted(xs, key=_u16key)


def _ont_param(d: dict, p: dict) -> dict:
    u = p.get("unit")
    if u is not None:
        if u["kind"] == "money":
            c = u["ccy"]
            if isinstance(c, str):
                return {"kind": "money", "ccys": [c]}
            cp = d["params"].get(c["from"])
            return {"kind": "money", "ccys": _sorted_u16(cp["values"]) if cp is not None and cp.get("values") is not None else []}
        return {"kind": "duration" if u["kind"] == "duration" else "bytes" if u["kind"] == "bytes" else "ratio" if u["kind"] == "ratio" else "count"}
    role, fmt = p.get("role"), p.get("format")
    if role is not None and role.startswith("id."):
        return {"kind": "id", "of": role[3:]}
    if fmt is not None and fmt.startswith("id:"):
        return {"kind": "id", "of": fmt[3:]}
    t = p["type"]
    if t == "duration":
        return {"kind": "duration"}
    if t in ("datetime", "date"):
        return {"kind": "instant"}
    if t == "integer":
        return {"kind": "count"}
    if t == "boolean":
        return {"kind": "enum", "values": ["false", "true"]}
    if t == "set":
        return {"kind": "enum", "values": _sorted_u16(p.get("values") or [])}
    if t == "string":
        return {"kind": "enum", "values": _sorted_u16(p["values"])} if p.get("values") is not None else {"kind": "text"}
    return {"kind": "text"}


def to_ontology(defs: List[dict], reg: Dict[str, dict], attestation_verified: Verifier = None) -> dict:
    """Ontology terms for a set of defs; `effect` is derived (effect_class), never overridden."""
    types: Dict[str, str] = {}
    units: Dict[str, dict] = {}
    verbs: List[dict] = []
    aliases: Dict[str, str] = {}
    traits: Dict[str, List[str]] = {}
    for d in sorted(defs, key=lambda x: _u16key(x["verb"])):
        rid = d["resource"]["id"]
        prefix = "" if (isinstance(rid, str) and rid == "*") or "exact" in rid else rid["prefix"]
        if d["resource"]["type"] not in types:
            types[d["resource"]["type"]] = prefix
        params: Dict[str, dict] = {}
        for name in _sorted_u16(d["params"]):
            params[name] = _ont_param(d, d["params"][name])
            u = d["params"][name].get("unit")
            if u is not None and u["kind"] == "money" and isinstance(u.get("ccy"), str):
                units[u["ccy"]] = {"kind": "money", **({"exponent": u["exp"]} if "exp" in u else {})}
            elif u is not None and u["kind"] != "money":
                units[u["kind"]] = {"kind": u["kind"]}
        verbs.append({"id": d["verb"], "effect": effect_class(d), "resource_type": d["resource"]["type"], "params": params})
        for a in d.get("aliases") or []:
            if a in aliases and aliases[a] != d["verb"]:
                raise ActionKitError("alias_collision", "alias '%s' names two verbs" % a)
            aliases[a] = d["verb"]
        traits[d["verb"]] = effective_with(d, reg, attestation_verified)["traits"]
    return {"types": [{"id": i, "id_prefix": p} for i, p in types.items()], "units": units, "verbs": verbs, "aliases": aliases, "traits": traits}


# ---- policy card + escalation + MCP annotations ------------------------------------------------------------------------------

def _sentence(s: str) -> str:
    return s if s != "" and s[-1] in ".!?" else s + "."


def _list(xs: List[str]) -> str:
    return (xs[0] if xs else "") if len(xs) <= 1 else ", ".join(xs[:-1]) + " and " + xs[-1]


def card_of(d: dict, eff: dict, reg: Dict[str, dict]) -> dict:
    """The deterministic policy card: the title and the phrases of the trait closure, riskiest first."""
    ordered = sorted((reg[i] for i in closure(reg, eff["traits"])), key=lambda t: (-t["floor"]["risk"], _u16key(t["id"])))
    phrases = list(dict.fromkeys(t["card_phrase"] for t in ordered))
    e = eff["eff"]
    if eff["confirmed"]:
        second = "This action %s." % _list(phrases) if phrases else "This action only reads."
    else:
        second = "This action has not been reviewed by a person, so it is treated as the most dangerous kind of action: it %s." % _list(phrases)
    return {"verb": d["verb"], "title": d["title"], "text": _sentence(d["title"]) + " " + second, "risk": RISK_NAMES[e["risk"]],
            "escalation": ESC_TIERS[e["esc"]], "reversibility": e["rev"], "blast_ppm": e["blast_ppm"], "needs": list(e["caveats"]), "context": list(e["context"])}


def escalation_of(eff: dict) -> dict:
    """The minimum escalation tier of the effective profile."""
    return {"tier": eff["eff"]["esc"], "name": ESC_TIERS[eff["eff"]["esc"]]}


def mcp_annotations_of(d: dict, eff: dict) -> dict:
    """Advisory MCP tool annotations; an unreviewed def's own claim of safety is never advertised."""
    cl = set(eff["closure"])
    idem = (d.get("idempotency") or {}).get("mode", "none")
    ro = is_read_only(d["effects"])
    return {"readOnlyHint": eff["confirmed"] and ro, "destructiveHint": "pca.destructive" in cl,
            "idempotentHint": eff["confirmed"] and (idem != "none" or ro),
            "openWorldHint": "pca.network_egress" in cl or "pca.external_communication" in cl}


# ---- explain.ts --------------------------------------------------------------------------------------------------------------

def _blast_text(ppm: int) -> str:
    return "%dk" % (ppm // 1000) if ppm % 1000 == 0 else "%dppm" % ppm


def explain_def(d: dict, reg: Dict[str, dict], attestation_verified: Verifier = None) -> str:
    """The plain-language profile of one def: card, effective profile, what a grant must carry, traits and review state."""
    eff = effective_with(d, reg, attestation_verified)
    card = card_of(d, eff, reg)
    e = eff["eff"]
    rev = "irreversible" if e["rev"] == "irreversible" else "rate limited" if e["rev"] == "rate_limited" else "reversible"
    lines = [card["text"], "effective: risk %d, %s, blast %s, escalation: %s" % (e["risk"], rev, _blast_text(e["blast_ppm"]), card["escalation"]),
             "grant must carry: " + (", ".join(card["needs"]) if card["needs"] else "nothing")]
    if card["context"]:
        lines.append("call must carry: " + ", ".join(card["context"]))
    lines.append("traits: " + (", ".join(eff["closure"]) or "none"))
    lines.append("review: " + (d["review"]["state"] if eff["confirmed"] else "%s, not confirmed by a signed review" % d["review"]["state"]))
    if not eff["confirmed"]:
        h = eff["hint"]
        lines.append("until a reviewer signs it this action is treated as the most dangerous kind of action; as written it would be: risk %d, escalation tier %d, traits: %s"
                     % (h["eff"]["risk"], h["eff"]["esc"], ", ".join(h["closure"]) or "none"))
    return "\n".join(lines)
