"""The outcome space derived from a site's signed action schema: dimensions only for parameters whose effective
sensitivity (after the wallet floor) is material or critical, canonical projections for boolean / set / array parameters,
and default sets for silent parameters. Native port of the TypeScript reference (@atlasauth/pca-intent)."""
from __future__ import annotations

import functools
from typing import Any, Dict, List, Optional

from .intent_omega import OTHER, derive_omega
from .intent_v2 import _js_string, compare_utf8
from .pca import canonicalize_strict

WALLET_FLOOR_PREFIXES = ("money.", "party.", "contact.", "person.", "credential.")
WALLET_FLOOR_EXACT = ("text.message",)
_REV = ("reversible", "rate_limited", "irreversible")
_UTF8 = functools.cmp_to_key(compare_utf8)


def _floor_applies(semantic: str, floor: Optional[dict]) -> bool:
    floor = floor or {}
    pre = floor.get("prefixes") if floor.get("prefixes") is not None else WALLET_FLOOR_PREFIXES
    ex = floor.get("exact") if floor.get("exact") is not None else WALLET_FLOOR_EXACT
    return semantic in ex or any(semantic.startswith(p) for p in pre)


def effective_sensitivity(d: dict, floor: Optional[dict] = None) -> str:
    """A site `free` on a floored semantic type becomes `material`."""
    return "material" if d.get("sensitivity") == "free" and _floor_applies(d["semantic"], floor) else d.get("sensitivity")


def verb_reversibility(v: dict) -> str:
    """rev(v) = max over outcomes of the declared reversibility (the conservative projection)."""
    rb = v.get("reversibility_by")
    if not rb:
        return v.get("reversibility") or ("reversible" if v.get("kind") == "read" else "irreversible")
    d = v["params"].get(rb["param"])
    mapped = list(rb["map"].values())
    dtype = d.get("type") if d else None
    domain = ["true", "false"] if dtype == "boolean" else d.get("values") if dtype == "string" and d.get("values") else None
    covered = domain is not None and all(x in rb["map"] for x in domain)
    items = mapped if covered else mapped + [rb.get("default") or "irreversible"]
    return max(items, key=lambda r: _REV.index(r) if r in _REV else -1) if items else "reversible"


def wallet_floor_overrides(doc: dict, floor: Optional[dict] = None) -> List[dict]:
    """Every override the wallet floor makes on a schema."""
    out = []
    for v in doc["verbs"]:
        for path in sorted(v["params"], key=_UTF8):
            d = v["params"][path]
            eff = effective_sensitivity(d, floor)
            if eff != d.get("sensitivity"):
                out.append({"verb": v["verb"], "path": path, "semantic": d["semantic"], "declared": d.get("sensitivity"), "effective": eff})
    return out


def _canon_path(param_path: str) -> str:
    return "env.canon." + param_path[len("action.params."):]


def _uses_canon(d: dict) -> bool:
    return d.get("type") in ("boolean", "set", "array")


def canon_value(d: dict, x: Any) -> str:
    """The canonical text a value of a canon-projected parameter has."""
    if d.get("type") == "boolean":
        return "true" if x is True else "false"
    if d.get("type") == "set":
        return canonicalize_strict(sorted(list(x), key=_UTF8))
    return canonicalize_strict(x)


def _is_safe_int_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and float(x).is_integer() and abs(x) <= 9007199254740991


def derive_omega_from_schema(o: dict) -> Dict[str, Any]:
    """Derive the schema outcome space: {omega, overrides, defaults, canonOf}."""
    schema_verbs = o["schema"]["verbs"]
    slots = o.get("slots")
    if o.get("verbs") is not None:
        verb_names = list(o["verbs"])
    else:
        verb_names = list(dict.fromkeys([v["verb"] for v in schema_verbs if v.get("kind") == "write"] + list((slots or {}).get("verbs") or [])))
    base = derive_omega({"policies": o.get("policies") or [], "slots": slots, "extraVerbs": verb_names})
    defaults: List[dict] = []
    canon_of: Dict[str, str] = {}
    verbs: List[dict] = []
    confirmed = o.get("confirmed") or {}
    floor = o.get("floor")
    for verb in sorted(verb_names, key=_UTF8):
        decl = next((v for v in schema_verbs if v["verb"] == verb), None)
        if decl is None:
            continue
        lits = next((v for v in base["verbs"] if v["verb"] == verb), None)
        dims: List[dict] = [d for d in (lits["dims"] if lits else []) if not d["path"].startswith("action.params.")]
        for path in sorted(decl["params"], key=_UTF8):
            pd = decl["params"][path]
            if effective_sensitivity(pd, floor) == "free":
                continue
            lit = next((d for d in lits["dims"] if d["path"] == path), None) if lits else None
            silent = lit is None
            conf = list(confirmed.get(path) or [])
            neutral = [pd["default"]] if pd.get("principal_neutral_default") is True and "default" in pd else []
            default_set = conf + neutral
            if pd.get("type") == "integer":
                cuts = list(lit["cuts"]) if lit is not None and lit["kind"] == "num" else []
                for x in default_set:
                    if _is_safe_int_num(x) and x not in cuts:
                        cuts.append(int(x))
                srt = sorted(set(cuts))
                max_cut = srt[-1] if srt else 0
                dom = (o.get("domains") or {}).get(path)
                lo = dom["lo"] if dom and dom.get("lo") is not None else pd["min"] if pd.get("min") is not None else min(0, srt[0] - 1 if srt else 0)
                hi = dom["hi"] if dom and dom.get("hi") is not None else pd["max"] if pd.get("max") is not None else max(10, 2 * max_cut, max_cut + 10)
                dims.append({"kind": "num", "path": path, "lo": lo, "hi": hi, "cuts": [c for c in srt if lo <= c <= hi],
                             "dist": "loguniform" if lo >= 0 else "uniform"})
                nums = [x for x in default_set if isinstance(x, (int, float)) and not isinstance(x, bool)]
                if silent and len(nums) == 1:
                    defaults.append({"verb": verb, "path": path, "min": nums[0], "max": nums[0]})
                continue
            canon = _uses_canon(pd)
            dim_path = _canon_path(path) if canon else path
            if canon:
                canon_of[dim_path] = path
            exacts: Dict[str, None] = {}
            prefixes: Dict[str, None] = {}
            if lit is not None and lit["kind"] == "cat":
                for v in lit["values"]:
                    if v["kind"] == "exact":
                        exacts[v["value"]] = None
                    elif v["kind"] == "prefix":
                        prefixes[v["value"]] = None
            if pd.get("type") == "string" and pd.get("values"):
                for v in pd["values"]:
                    exacts[v] = None
            if pd.get("type") == "boolean":
                exacts["false"] = None
                exacts["true"] = None
            def_texts = [canon_value(pd, x) if canon else _js_string(x) for x in default_set]
            for t in def_texts:
                exacts[t] = None
            values = [{"kind": "exact", "value": v} for v in sorted(exacts, key=_UTF8)]
            values += [{"kind": "prefix", "value": v} for v in sorted(prefixes, key=_UTF8)]
            values.append({"kind": "other", "value": OTHER})
            dims.append({"kind": "cat", "path": dim_path, "values": values})
            if silent and len(def_texts) > 0:
                defaults.append({"verb": verb, "path": dim_path, "oneOf": sorted(set(def_texts), key=_UTF8)})
        dims.sort(key=lambda d: _UTF8(d["path"]))
        verbs.append({"verb": verb, "reversibility": verb_reversibility(decl), "weight": 0, "dims": dims})
    for v in verbs:
        v["weight"] = 1 / (len(verbs) or 1)
    overrides = wallet_floor_overrides({"verbs": [v for v in schema_verbs if v["verb"] in verb_names]}, floor)
    return {"omega": {"v": 1, "verbs": verbs, "approximate": base["approximate"]}, "overrides": overrides, "defaults": defaults, "canonOf": canon_of}
