"""Semantic diff of two versions of one ActionDef (native port of diff.ts and defdiff.ts of the TypeScript reference
@atlasauth/pca-actions). diff_defs is the grant-pin form (equal|narrow|widen|incomparable, never optimistic); diff_defs_authoring
and diff_packs are the authoring-CLI form."""
import json
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .actions import (
    CORE_REGISTRY, PROVENANCE_LEVELS, REV_RANK, ROLE_SENSITIVITY_FLOOR, SENSITIVITY_RANK, ActionKitError, closure, def_digest,
    effective_param_sensitivity, leq, normalize, worst_reversibility,
)
from .actions_effective import effective_with, profile_eq
from .actions_idpattern import id_pattern_contains
from .intent_wb import _UNDEF, _js_str

_INF = float("inf")
_DEFAULT_MAX_LEN = 1024
_DEFAULT_MAX_ITEMS = 64
_SCOPE_RANK = {"one": 0, "set": 1, "tenant": 2, "global": 3}
_IDEM_RANK = {"none": 0, "natural": 1, "key_param": 2}


def _g(o: dict, k: str, default: Any) -> Any:
    """`o[k] ?? default`: an absent or null member takes the default."""
    v = o.get(k)
    return default if v is None else v


def _sorted_keys(v: Any) -> Any:
    """Object keys sorted recursively (list order kept): the reference compares JSON after this, so key order never matters."""
    if isinstance(v, list):
        return [_sorted_keys(x) for x in v]
    if isinstance(v, dict):
        return {k: _sorted_keys(v[k]) for k in sorted(v, key=lambda k: k.encode("utf-16-be", "surrogatepass"))}
    return v


def _js(v: Any) -> str:
    return json.dumps(_sorted_keys(v), separators=(",", ":"), ensure_ascii=False)


def _sj(o: dict, k: str) -> str:
    """JSON.stringify(sortKeys(o[k])) (an absent member is 'undefined')."""
    return _js(o[k]) if k in o else "undefined"


def _set_rel(old: Sequence[Any], new: Sequence[Any]) -> str:
    o, n = set(old), set(new)
    added = any(x not in o for x in n)
    removed = any(x not in n for x in o)
    return "inc" if added and removed else "narrow" if added else "widen" if removed else "eq"


def _rank_rel(o: float, n: float) -> str:
    """More restrictive = larger."""
    return "eq" if n == o else "narrow" if n > o else "widen"


def _domain_contains(outer: dict, inner: dict) -> bool:
    """Is every value of inner's domain also a value of outer's? Same declared type required. Sound, not complete."""
    t = outer["type"]
    if t != inner["type"]:
        return False
    if t in ("string", "object_ref"):
        if _g(inner, "max_len", _DEFAULT_MAX_LEN) > _g(outer, "max_len", _DEFAULT_MAX_LEN):
            return False
        if outer.get("values") is not None and (inner.get("values") is None or not all(v in outer["values"] for v in inner["values"])):
            return False
        return outer.get("format") is None or inner.get("format") == outer["format"]
    if t == "integer":
        return _g(inner, "min", -_INF) >= _g(outer, "min", -_INF) and _g(inner, "max", _INF) <= _g(outer, "max", _INF)
    if t == "duration":
        return max(_g(inner, "min", 0), 0) >= max(_g(outer, "min", 0), 0) and _g(inner, "max", _INF) <= _g(outer, "max", _INF)
    if t == "set":
        ov = outer.get("values") or []
        iv = inner.get("values") or []
        if not all(v in ov for v in iv):
            return False
        o_max = min(_g(outer, "max_items", len(ov)), len(ov))
        i_max = min(_g(inner, "max_items", len(iv)), len(iv))
        return _g(inner, "min_items", 0) >= _g(outer, "min_items", 0) and i_max <= o_max
    if t == "array":
        if _g(outer, "items", "string") != _g(inner, "items", "string"):
            return False
        if _g(inner, "min_items", 0) < _g(outer, "min_items", 0) or _g(inner, "max_items", _DEFAULT_MAX_ITEMS) > _g(outer, "max_items", _DEFAULT_MAX_ITEMS):
            return False
        if outer.get("items") == "integer":
            return _g(inner, "min", -_INF) >= _g(outer, "min", -_INF) and _g(inner, "max", _INF) <= _g(outer, "max", _INF)
        return _g(inner, "max_len", _DEFAULT_MAX_LEN) <= _g(outer, "max_len", _DEFAULT_MAX_LEN)
    return True  # boolean, date, datetime: no domain members


def _calls_contained(outer: dict, inner: dict) -> bool:
    """Is every call conforming to `inner` also conforming to `outer`? Closed world, required members, domains."""
    for name, ip in inner.items():
        op = outer.get(name)
        if op is None or not _domain_contains(op, ip):
            return False
    for name, op in outer.items():
        if not op.get("required"):
            continue
        ip = inner.get(name)
        if ip is None or not ip.get("required"):
            return False
    return True


def _call_set_rel(old_p: dict, new_p: dict) -> str:
    sub = _calls_contained(old_p, new_p)
    sup = _calls_contained(new_p, old_p)
    return "eq" if sub and sup else "narrow" if sub else "widen" if sup else "inc"


def _prov_rank(p: Any) -> int:
    return len(PROVENANCE_LEVELS) - 1 if p is None else PROVENANCE_LEVELS.index(p)


def _param_attr_rels(o: dict, n: dict) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if o.get("role") != n.get("role"):
        out.append(("role", "inc"))
    out.append(("sensitivity", _rank_rel(SENSITIVITY_RANK[o["sensitivity"]], SENSITIVITY_RANK[n["sensitivity"]])))
    out.append(("tags", _set_rel(o.get("tags") or [], n.get("tags") or [])))
    out.append(("provenance_min", _rank_rel(-_prov_rank(o.get("provenance_min")), -_prov_rank(n.get("provenance_min")))))
    if _sj(o, "unit") != _sj(n, "unit"):
        out.append(("unit", "inc"))
    out.append(("accumulates", _set_rel(o.get("accumulates") or [], n.get("accumulates") or [])))
    if _sj(o, "default") != _sj(n, "default") or o.get("principal_neutral_default", _UNDEF) != n.get("principal_neutral_default", _UNDEF):
        out.append(("default", "inc"))
    return out


def _text_differs(o: dict, n: dict) -> bool:
    return any(o.get(k, _UNDEF) != n.get(k, _UNDEF) for k in ("title", "description", "compensates"))


def diff_defs(prev: dict, nxt: dict, reg: Optional[Dict[str, dict]] = None, attestation_verified: Optional[Callable[[dict], Any]] = None) -> dict:
    """The semantic diff of `nxt` against `prev` (two versions of one verb): {class, reasons}. Raises diff_verb for two different verbs."""
    reg = CORE_REGISTRY if reg is None else reg
    if prev["verb"] != nxt["verb"]:
        raise ActionKitError("diff_verb", "diff compares two versions of one verb, not '%s' and '%s'" % (prev["verb"], nxt["verb"]))
    o, n = normalize(prev), normalize(nxt)
    rels: List[Tuple[str, str]] = []
    text = _text_differs(o, n)
    rels.append(("effects", _set_rel(o["effects"], n["effects"])))
    rels.append(("params.accepted_calls", _call_set_rel(o["params"], n["params"])))
    for name in sorted(o["params"]):
        if name in n["params"]:
            for k, r in _param_attr_rels(o["params"][name], n["params"][name]):
                rels.append(("params.%s.%s" % (name, k), r))
    eo = effective_with(prev, reg, attestation_verified)
    en = effective_with(nxt, reg, attestation_verified)

    def prof_rel(a: dict, b: dict) -> str:
        return ("eq" if leq(b, a) else "narrow") if leq(a, b) else ("widen" if leq(b, a) else "inc")

    rels.append(("traits", _set_rel(closure(reg, eo["hint"]["traits"]), closure(reg, en["hint"]["traits"]))))
    rels.append(("profile", prof_rel(eo["hint"]["eff"], en["hint"]["eff"])))
    rels.append(("confirmation", _rank_rel(0 if eo["confirmed"] else 1, 0 if en["confirmed"] else 1)))
    rels.append(("effective.traits", _set_rel(closure(reg, eo["traits"]), closure(reg, en["traits"]))))
    rels.append(("effective.profile", prof_rel(eo["eff"], en["eff"])))
    rels.append(("reversibility", _rank_rel(REV_RANK[worst_reversibility(o["reversibility"], o["params"])], REV_RANK[worst_reversibility(n["reversibility"], n["params"])])))
    rels.append(("blast", _rank_rel(o["blast"]["ppm"], n["blast"]["ppm"])))
    oi, ni = o["idempotency"], n["idempotency"]
    idem = "inc" if oi["mode"] == "key_param" and ni["mode"] == "key_param" and oi.get("param") != ni.get("param") else _rank_rel(_IDEM_RANK[oi["mode"]], _IDEM_RANK[ni["mode"]])
    rels.append(("idempotency", idem))
    rels.append(("context", _set_rel(o["context"], n["context"])))
    rels.append(("side_effects", _set_rel(["%s|%s" % (s["target"], s["kind"]) for s in o["side_effects"]], ["%s|%s" % (s["target"], s["kind"]) for s in n["side_effects"]])))
    orr, nrr = o["resource"], n["resource"]
    if _js(orr["id"]) == _js(nrr["id"]):
        res_id = "eq"
    elif id_pattern_contains(orr["id"], nrr["id"]):
        res_id = "narrow"
    elif id_pattern_contains(nrr["id"], orr["id"]):
        res_id = "widen"
    else:
        res_id = "inc"
    rels.append(("resource.id", "inc" if orr["type"] != nrr["type"] else res_id))
    rels.append(("resource.scope", _rank_rel(-_SCOPE_RANK[orr["scope"]], -_SCOPE_RANK[nrr["scope"]])))
    ar = _set_rel(o["aliases"], n["aliases"])  # new aliases widen what natural language can reach
    rels.append(("aliases", "widen" if ar == "narrow" else "narrow" if ar == "widen" else ar))
    rels.append(("bindings", "eq" if _js(o["bindings"]) == _js(n["bindings"]) else "inc"))

    diffs = [(d, r) for d, r in rels if r != "eq"]
    reasons = sorted("%s: %s" % (d, "incomparable" if r == "inc" else r) for d, r in diffs)
    if text:
        reasons.append("text: title, description or compensates changed")
    reasons.sort()

    def has(r: str) -> bool:
        return any(x == r for _, x in diffs)

    cls = "incomparable" if has("inc") or (has("narrow") and has("widen")) else "widen" if has("widen") else "narrow" if has("narrow") else "equal"
    return {"class": cls, "reasons": reasons}


def diff_is_free(c: str) -> bool:
    """Does a pin follow this change on its own (no principal)?"""
    return c in ("equal", "narrow")


# ---- the authoring diff (defdiff.ts) ----------------------------------------------------------------------------------------

def _num_str(v: Any) -> str:
    return _js_str(_UNDEF if v is None else v)


def _param_diff(k: str, x: dict, y: dict, wide: list, narrow: list, incomp: list) -> None:
    def num(f: str, lower_is_wider: bool) -> None:
        o, n = x.get(f), y.get(f)
        if o == n:
            return

        def rank(v: Any) -> float:
            return (-_INF if lower_is_wider else _INF) if v is None else v

        wider_new = rank(n) < rank(o) if lower_is_wider else rank(n) > rank(o)
        (wide if wider_new else narrow).append("param %s: %s %s to %s" % (k, f, _num_str(o), _num_str(n)))

    if x["type"] != y["type"]:
        incomp.append("param %s: type changed" % k)
    num("min", True); num("max", False); num("max_len", False); num("max_items", False); num("min_items", True)
    if json.dumps(x.get("unit"), separators=(",", ":")) != json.dumps(y.get("unit"), separators=(",", ":")):
        incomp.append("param %s: unit changed" % k)
    vo, vn = x.get("values"), y.get("values")
    if vo is not None or vn is not None:
        if vo is None:
            narrow.append("param %s: values restricted" % k)
        elif vn is None:
            wide.append("param %s: values unrestricted" % k)
        else:
            added = [v for v in vn if v not in vo]
            removed = [v for v in vo if v not in vn]
            if added:
                wide.append("param %s: values added (%s)" % (k, ", ".join(_js_str(v) for v in added)))
            if removed:
                narrow.append("param %s: values removed (%s)" % (k, ", ".join(_js_str(v) for v in removed)))
    if x["required"] is True and y["required"] is False:
        wide.append("param %s: required to optional" % k)
    if x["required"] is False and y["required"] is True:
        narrow.append("param %s: optional to required" % k)

    def pl(v: Any) -> int:
        return len(PROVENANCE_LEVELS) if v is None else (PROVENANCE_LEVELS.index(v) if v in PROVENANCE_LEVELS else -1)

    if pl(y.get("provenance_min")) > pl(x.get("provenance_min")):
        wide.append("param %s: provenance_min loosened" % k)
    elif pl(y.get("provenance_min")) < pl(x.get("provenance_min")):
        narrow.append("param %s: provenance_min tightened" % k)
    sx = SENSITIVITY_RANK[effective_param_sensitivity(x)]
    sy = SENSITIVITY_RANK[effective_param_sensitivity(y)]
    if sy < sx:
        wide.append("param %s: sensitivity lowered" % k)
    elif sy > sx:
        narrow.append("param %s: sensitivity raised" % k)
    if x.get("role") != y.get("role"):
        def f(r: Any) -> int:
            return SENSITIVITY_RANK[ROLE_SENSITIVITY_FLOOR[r]] if r is not None and r in ROLE_SENSITIVITY_FLOOR else 0

        if f(y.get("role")) < f(x.get("role")):
            wide.append("param %s: role changed to a lower-floor role" % k)
        elif f(y.get("role")) > f(x.get("role")):
            narrow.append("param %s: role changed to a higher-floor role" % k)
        else:
            incomp.append("param %s: role changed" % k)


def diff_defs_authoring(a: dict, b: dict, reg: Dict[str, dict]) -> dict:
    """{class, breaking, reasons}: anything not shown to be no wider is widening. A renamed verb is a breaking widen."""
    if a["verb"] != b["verb"]:
        return {"class": "widen", "breaking": True, "reasons": ["verb renamed: removed + added (grants on the old verb do not follow)"]}
    wide: List[str] = []
    narrow: List[str] = []
    incomp: List[str] = []
    breaking = False
    na, nb = normalize(a), normalize(b)
    ea = effective_with(a, reg)["hint"]
    eb = effective_with(b, reg)["hint"]
    if not leq(ea["eff"], eb["eff"]):
        wide.append("the effective profile is not at least the old one")
    elif not profile_eq(ea["eff"], eb["eff"]):
        narrow.append("the effective profile rose")
    for e in na["effects"]:
        if e not in nb["effects"]:
            wide.append("effect %s removed" % e)
    for e in nb["effects"]:
        if e not in na["effects"]:
            narrow.append("effect %s added" % e)
    for t in na["traits"]:
        if t not in nb["traits"]:
            wide.append("declared trait %s removed" % t)
    for t in nb["traits"]:
        if t not in na["traits"]:
            narrow.append("declared trait %s added" % t)
    ra = worst_reversibility(na["reversibility"], na["params"])
    rb = worst_reversibility(nb["reversibility"], nb["params"])
    if REV_RANK[rb] < REV_RANK[ra]:
        wide.append("reversibility lowered (%s to %s)" % (ra, rb))
    elif REV_RANK[rb] > REV_RANK[ra]:
        narrow.append("reversibility raised (%s to %s)" % (ra, rb))
    if nb["blast"]["ppm"] < na["blast"]["ppm"]:
        wide.append("blast lowered")
    elif nb["blast"]["ppm"] > na["blast"]["ppm"]:
        narrow.append("blast raised")

    def idem(m: str) -> int:
        return 0 if m == "none" else 1

    if idem(nb["idempotency"]["mode"]) < idem(na["idempotency"]["mode"]):
        wide.append("idempotency loosened")
    elif idem(nb["idempotency"]["mode"]) > idem(na["idempotency"]["mode"]):
        narrow.append("idempotency added")
    if na["resource"]["type"] != nb["resource"]["type"]:
        incomp.append("resource type changed")
    if _SCOPE_RANK[nb["resource"]["scope"]] > _SCOPE_RANK[na["resource"]["scope"]]:
        wide.append("resource scope widened")
    elif _SCOPE_RANK[nb["resource"]["scope"]] < _SCOPE_RANK[na["resource"]["scope"]]:
        narrow.append("resource scope narrowed")
    in_old = id_pattern_contains(na["resource"]["id"], nb["resource"]["id"])
    in_new = id_pattern_contains(nb["resource"]["id"], na["resource"]["id"])
    if not in_old:
        wide.append("the resource id pattern is not contained in the old one")
    elif not in_new:
        narrow.append("the resource id pattern is narrower")
    for k in na["params"]:
        x = na["params"][k]
        y = nb["params"].get(k)
        if not y:
            narrow.append("param %s removed" % k)
            breaking = True
            continue
        _param_diff(k, x, y, wide, narrow, incomp)
        if x["required"] is False and y["required"] is True:
            breaking = True
    for k in nb["params"]:
        if k in na["params"]:
            continue
        if nb["params"][k]["required"]:
            narrow.append("required param %s added" % k)
            breaking = True
        else:
            wide.append("optional param %s added" % k)
    if a["review"]["state"] == "confirmed" and b["review"]["state"] != "confirmed":
        narrow.append("review state left confirmed")
    cls = "incomparable" if incomp or (wide and narrow) else "widen" if wide else "narrow" if narrow else "equal"
    cmp_eq = cls == "equal" and def_digest(a) != def_digest(b)
    reasons = ["widen: " + r for r in wide] + ["narrow: " + r for r in narrow] + ["incomparable: " + r for r in incomp] + (["equal: only title or description changed"] if cmp_eq else [])
    return {"class": cls, "breaking": breaking, "reasons": reasons}


def diff_packs(olds: Sequence[dict], news: Sequence[dict], reg: Dict[str, dict]) -> List[dict]:
    """Per-verb diff of two sets of defs. A removed verb is `removed`; a new verb is `added`."""
    o = {d["verb"]: d for d in olds}
    n = {d["verb"]: d for d in news}
    out: List[dict] = []
    for v in sorted(set(o) | set(n)):
        x, y = o.get(v), n.get(v)
        if x is None:
            out.append({"verb": v, "class": "added", "breaking": False, "reasons": []})
        elif y is None:
            out.append({"verb": v, "class": "removed", "breaking": True, "reasons": ["verb removed"]})
        else:
            d = diff_defs_authoring(x, y, reg)
            e = {"verb": v}
            e.update(d)
            out.append(e)
    return out
