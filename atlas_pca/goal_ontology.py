"""The intent-fidelity ontology: the signed authoring vocabulary (aliases, templates, units), its projection onto the IR ontology,
its well-formedness checker, template instantiation, slot typing and locale-aware amount parsing (the TypeScript reference is
@atlasauth/pca-goal `ontology`). Ontologies, goals and slot values are the parsed-JSON trees of the reference."""
import re
import unicodedata
from functools import cmp_to_key
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from .analyzer_js import UNDEF, includes, jget, js_str, key_order, oget as oc, req_list, strict_eq, truthy, u16key
from .attest_common import JS_WS, js_trim
from .goal_codec import _safe_int
from .goal_digests import nl_digest
from .goal_examples import allow_witness
from .goal_normalize import canonicalize_goal
from .goal_sign import sign_payload, verify_payload
from .pca import hash_canonical

__all__ = [
    "EFFECT_CLASSES", "ontology_digest", "sign_ontology", "verify_ontology", "resolve_verb", "goal_ccy", "to_ir_ontology", "ontology_for_goal",
    "goal_anchors", "check_ontology", "slot_lits", "instantiate_template", "parse_human_amount", "parse_money",
]

EFFECT_CLASSES = ["read", "reversible", "external_send", "irreversible"]
_INVIS = "​-‏⁠﻿"
_INVIS_RE = re.compile("[%s]" % _INVIS)
_FOREVER = 9007199254740991


def _hk(x: Any) -> Any:
    """A hashable key with JavaScript Set semantics: objects and arrays by identity."""
    return ("\0obj", id(x)) if isinstance(x, (dict, list)) else x


class _JSSet:
    def __init__(self, items: Any = ()):
        self._s = set(_hk(i) for i in items)

    def add(self, x: Any) -> None:
        self._s.add(_hk(x))

    def __contains__(self, x: Any) -> bool:
        return _hk(x) in self._s

    def __len__(self) -> int:
        return len(self._s)


def ontology_digest(o: Any) -> str:
    return hash_canonical({"d": "atlas-pca/goal-intent-ontology/v1", "ontology": o})


def sign_ontology(o: Any, secret: Any, alg: Optional[str] = None, pq: Any = None) -> dict:
    return sign_payload("ontology", o, secret, alg, pq)


def verify_ontology(s: Any, pins: Sequence[Any]) -> bool:
    return verify_payload(s, "ontology", pins)


def _norm(s: str) -> str:
    return _INVIS_RE.sub("", unicodedata.normalize("NFKC", s).lower())


def _entries(o: Any) -> list:
    """Object.entries(o): a dict's members in JavaScript key order; null throws; other primitives have none."""
    if o is None or o is UNDEF:
        raise TypeError("cannot convert undefined or null to object")
    if isinstance(o, dict):
        return [(k, o[k]) for k in key_order(o)]
    if isinstance(o, (list, tuple)):
        return [(str(i), x) for i, x in enumerate(o)]
    if isinstance(o, str):
        return [(str(i), c) for i, c in enumerate(_u16(o))]
    return []


def _u16(s: str) -> list:
    b = s.encode("utf-16-le", "surrogatepass")
    return [b[i:i + 2].decode("utf-16-le", "surrogatepass") for i in range(0, len(b), 2)]


def _iter(x: Any) -> Any:
    """`for (const e of x)`: an array's elements or a string's code points; anything else throws."""
    if isinstance(x, (list, tuple, str)):
        return list(x)
    raise TypeError("not iterable")


def _values(o: Any) -> list:
    return [v for _, v in _entries(o)]


def _find(xs: Any, pred: Callable[[Any], Any]) -> Any:
    for x in req_list(xs):
        if truthy(pred(x)):
            return x
    return UNDEF


def _own(o: Any, k: Any) -> Any:
    """o[k] for an own member of a plain object, else undefined (the reference reads a null object and throws)."""
    if o is None or o is UNDEF:
        raise TypeError("cannot read properties of null")
    return o[k] if isinstance(o, dict) and isinstance(k, str) and k in o else UNDEF


def _len_pos(x: Any) -> bool:
    """`!x?.length` is false: x is a non-empty array / string."""
    return isinstance(x, (list, tuple, str)) and len(x) > 0


def resolve_verb(o: Any, word: str) -> Optional[str]:
    """The canonical verb id of an id or declared alias; case and homoglyph variants are NOT guessed."""
    if not isinstance(word, str):
        raise TypeError("word.trim is not a function")
    w = js_trim(word)
    if any(strict_eq(jget(v, "id"), w) for v in req_list(jget(o, "verbs"))):
        return w
    al = jget(o, "aliases")
    hit = _own(al, w)
    return None if hit is UNDEF else hit


def goal_ccy(g: Any) -> Optional[str]:
    """The currency a goal is written in: the first money quantity in its conditions or bound caps (None without money)."""
    found: List[Any] = [UNDEF]

    def t(x: Any) -> None:
        if jget(x, "k") != "lit":
            return
        v = jget(x, "v")
        for i in (req_list(jget(v, "items")) if jget(v, "k") == "set" else [v]):
            if found[0] is UNDEF and jget(i, "k") == "q" and jget(jget(jget(i, "q"), "u"), "k") == "money":
                found[0] = jget(jget(jget(i, "q"), "u"), "ccy")

    def c(x: Any) -> None:
        k = jget(x, "k")
        if k == "cmp":
            t(jget(x, "l"))
            t(jget(x, "r"))
        elif k == "and" or k == "or":
            c(jget(x, "a"))
            c(jget(x, "b"))
        elif k == "not":
            c(jget(x, "c"))

    for gr in req_list(jget(g, "grants")):
        c(jget(gr, "cond"))
    for p in req_list(jget(g, "prohibits")):
        c(jget(p, "cond"))
    for x in req_list(jget(g, "escalateOn")):
        c(x)
    for b in req_list(jget(g, "bounds")):
        cap = jget(b, "cap")
        if found[0] is UNDEF and jget(jget(cap, "u"), "k") == "money":
            found[0] = jget(jget(cap, "u"), "ccy")
    return None if found[0] is UNDEF else found[0]


def _param_ty(p: Any, ccy: Any) -> Dict[str, Any]:
    kind = jget(p, "kind")
    if kind == "id" or kind == "enum" or kind == "text":
        return {"k": "s"}
    if kind == "money":
        ccys = jget(p, "ccys")
        if ccy is not None and ccy is not UNDEF and ccys is not UNDEF and includes(ccys, ccy):
            c = ccy
        elif ccys is not UNDEF and includes(ccys, "USD"):
            c = "USD"
        else:
            c = req_list(ccys)[0] if len(req_list(ccys)) else UNDEF
        return {"k": "q", "u": {"k": "money", "ccy": c}}
    return {"k": "q", "u": {"k": kind}}


def to_ir_ontology(o: Any, opts: Optional[dict] = None) -> Dict[str, Any]:
    """T1's `Ontology` (verbs with effect class and typed parameters, relation tables) for an intent ontology. `opts`: {ccy?, rels?}."""
    opts = opts or {}
    verbs = []
    for v in req_list(jget(o, "verbs")):
        params = jget(v, "params")
        verbs.append({"verb": jget(v, "id"), "cls": jget(v, "effect"),
                      "params": [{"path": path, "ty": _param_ty(_own(params, path), opts.get("ccy"))}
                                 for path in sorted([k for k, _ in _entries(params)], key=u16key)]})
    rels = opts.get("rels")
    return {"verbs": verbs, "rels": [] if rels is None else rels}


def ontology_for_goal(o: Any, g: Any, rels: Optional[list] = None) -> Dict[str, Any]:
    """The IR ontology a goal is typed and decided against: money parameters in the goal's own currency."""
    ccy = goal_ccy(g)
    opts: Dict[str, Any] = {"rels": [] if rels is None else rels}
    if ccy is not None:
        opts["ccy"] = ccy
    return to_ir_ontology(o, opts)


def goal_anchors(g: Any) -> List[Dict[str, Any]]:
    """Relation anchors a goal mentions, declared with no members (typing needs them; facts come per case)."""
    out: Dict[str, Dict[str, Any]] = {}

    def sel(s: Any) -> None:
        k = jget(s, "k")
        if k == "related":
            out[jget(s, "rel") + "\0" + jget(s, "anchor")] = {"rel": jget(s, "rel"), "anchor": jget(s, "anchor"), "members": []}
        elif k == "all_of":
            for p in req_list(jget(s, "parts")):
                sel(p)

    for gr in req_list(jget(g, "grants")):
        sel(jget(gr, "res"))
    for p in req_list(jget(g, "prohibits")):
        sel(jget(p, "res"))

    def cmp(a: dict, b: dict) -> int:
        return -1 if u16key(a["rel"] + "\0" + a["anchor"]) < u16key(b["rel"] + "\0" + b["anchor"]) else 1
    return sorted(out.values(), key=cmp_to_key(cmp))


def _refs_res(s: Any) -> List[str]:
    def d(x: Any) -> List[str]:
        return [x[1:]] if x.startswith("$") else []
    k = jget(s, "k")
    if k == "exact":
        return d(jget(s, "id"))
    if k == "oneof":
        return [y for i in req_list(jget(s, "ids")) for y in d(i)]
    if k == "related":
        return d(jget(s, "anchor"))
    if k == "all_of":
        return [y for p in req_list(jget(s, "parts")) for y in _refs_res(p)]
    return []


def _refs_term(x: Any) -> List[str]:
    return [jget(x, "slot")] if jget(x, "k") == "slot" else []


def _refs_cond(c: Any) -> List[str]:
    k = jget(c, "k")
    if k == "cmp":
        return _refs_term(jget(c, "l")) + _refs_term(jget(c, "r"))
    if k == "and" or k == "or":
        return _refs_cond(jget(c, "a")) + _refs_cond(jget(c, "b"))
    if k == "not":
        return _refs_cond(jget(c, "c"))
    return []


def _refs_grant(g: Any) -> List[str]:
    return _refs_res(jget(g, "res")) + _refs_cond(jget(g, "cond"))


def _refs_bound(b: Any) -> List[str]:
    return [jget(b, "cap_slot")] if truthy(jget(b, "cap_slot")) else []


def _slot_refs(t: Any) -> List[str]:
    return ([y for g in req_list(jget(t, "grants")) for y in _refs_grant(g)] + [y for p in req_list(jget(t, "prohibits")) for y in _refs_grant(p)]
            + [y for b in req_list(jget(t, "bounds")) for y in _refs_bound(b)])


def check_ontology(o: Any) -> List[Dict[str, str]]:
    """Well-formedness checker: every defect as `{code, where, msg}`; an empty list means well formed."""
    I: List[Dict[str, str]] = []

    def bad(code: Any, where: Any, msg: Any) -> None:
        I.append({k: v for k, v in (("code", code), ("where", where), ("msg", msg)) if v is not UNDEF})

    type_ids = _JSSet()
    prefixes = _JSSet()
    for t in _iter(jget(o, "types")):
        tid = jget(t, "id")
        if tid in type_ids:
            bad("dup_type", tid, "duplicate type id")
        type_ids.add(tid)
        pre = jget(t, "id_prefix")
        if not truthy(pre) or pre in prefixes:
            bad("dup_prefix", tid, "id prefix empty or reused")
        prefixes.add(pre)
    units = jget(o, "units")
    for u, d in _entries(units):
        exp = jget(d, "exponent")
        if jget(d, "kind") == "money" and not (_is_integer(exp) and exp >= 0 and exp <= 4):
            bad("unit_exponent", u, "money unit needs an integer exponent 0..4")
        if jget(d, "kind") != "money" and exp is not UNDEF:
            bad("unit_exponent", u, "only money units carry an exponent")
    rel_ids = _JSSet()
    for r in _iter(jget(o, "relations")):
        rid = jget(r, "id")
        if rid in rel_ids:
            bad("dup_relation", rid, "duplicate relation")
        rel_ids.add(rid)
        if jget(r, "from") not in type_ids or jget(r, "to") not in type_ids:
            bad("relation_type", rid, "relation endpoint type is not declared")
    verb_ids = _JSSet()
    verbs: Dict[Any, Any] = {}
    for v in _iter(jget(o, "verbs")):
        vid = jget(v, "id")
        if vid in verb_ids:
            bad("dup_verb", vid, "duplicate verb")
        verb_ids.add(vid)
        verbs[_hk(vid)] = v
        if not includes(EFFECT_CLASSES, jget(v, "effect")):
            bad("no_effect_class", vid, "verb has no valid effect class")
        if jget(v, "resource_type") not in type_ids:
            bad("verb_resource_type", vid, "resource type is not declared")
        for p, pt in _entries(jget(v, "params")):
            kind = jget(pt, "kind")
            w = "%s.%s" % (js_str(vid), p)
            if kind == "money":
                ccys = jget(pt, "ccys")
                if not _len_pos(ccys):
                    bad("param_ccy", w, "money parameter lists no currency")
                for c in ([] if ccys is UNDEF or ccys is None else _iter(ccys)):
                    if oc(_own(units, c) if isinstance(c, str) else UNDEF, "kind") != "money":
                        bad("unit_unknown", w, "currency %s is not a declared money unit" % js_str(c))
            elif kind == "enum":
                if not _len_pos(jget(pt, "values")):
                    bad("param_enum", w, "enum parameter has no values")
            elif kind == "id":
                of = jget(pt, "of")
                if not truthy(of) or of not in type_ids:
                    bad("param_type", w, "id parameter type is not declared")
            elif kind != "text":
                if not any(strict_eq(jget(u, "kind"), kind) for u in _values(units)):
                    bad("unit_unknown", w, "no declared unit of kind %s" % js_str(kind))
    seen: Dict[str, str] = {}
    aliases = jget(o, "aliases")
    for k, target in _entries(aliases):
        if k != _norm(k) or (re.search("[^\x20-\x7e]", k) and k != unicodedata.normalize("NFKC", k)):
            bad("alias_key", k, "alias key is not in normalized form")
        if _INVIS_RE.search(k):
            bad("alias_key", k, "alias key contains invisible characters")
        n = _norm(k)
        if n in seen and seen[n] != k:
            bad("alias_collision", k, "collides with %s after normalization" % seen[n])
        seen[n] = k
        if target not in verb_ids:
            bad("alias_target", k, "alias target is not a canonical verb")
        if isinstance(target, str) and isinstance(aliases, dict) and target in aliases:
            bad("alias_chain", k, "alias target is itself an alias (chain or cycle)")
        if k in verb_ids and k != target:
            bad("alias_shadow", k, "alias shadows a canonical verb")
    tids = _JSSet()
    for t in req_list(jget(o, "templates")):
        tid = jget(t, "id")
        w = "template:%s" % js_str(tid)
        if tid in tids:
            bad("dup_template", w, "duplicate template id")
        tids.add(tid)
        slots = req_list(jget(t, "slots"))
        slot_names = _JSSet(jget(s, "name") for s in slots)
        if len(slot_names) != len(slots):
            bad("dup_slot", w, "duplicate slot")
        for r in _slot_refs(t):
            if r not in slot_names:
                bad("slot_undeclared", w, "slot %s is used but not declared" % js_str(r))
        for s in slots:
            sw = "%s.%s" % (w, js_str(jget(s, "name")))
            sk = jget(s, "kind")
            if sk == "id" or sk == "id_list":
                of = jget(s, "of")
                if not truthy(of) or of not in type_ids:
                    bad("slot_type", sw, "id slot type is not declared")
            if sk == "money":
                ccy = jget(s, "ccy")
                if oc(_own(units, ccy if ccy is not UNDEF else "") if (ccy is UNDEF or isinstance(ccy, str)) else UNDEF, "kind") != "money":
                    bad("slot_ccy", sw, "money slot currency is not a declared unit")
            if (sk == "enum" or sk == "enum_list") and not _len_pos(jget(s, "values")):
                bad("slot_enum", sw, "enum slot has no values")
            if not truthy(jget(s, "mandatory")) and jget(s, "default") is UNDEF:
                bad("slot_default", sw, "optional slot needs a default (an unfilled slot must be a hole or a default)")
            if jget(s, "name") not in _slot_refs(t):
                bad("slot_unused", sw, "declared slot is never used")
        tgrants = req_list(jget(t, "grants"))
        tbounds = req_list(jget(t, "bounds"))
        if len(tgrants) == 0:
            bad("empty_allow", w, "template has no grant (empty Allow set)")
        gids = _JSSet(jget(g, "gid") for g in tgrants)
        if len(gids) != len(tgrants):
            bad("dup_gid", w, "duplicate grant id")
        for g in tgrants:
            v = verbs.get(_hk(jget(g, "verb")))
            gw = "%s.%s" % (w, js_str(jget(g, "gid")))
            if v is None:
                bad("grant_verb", gw, "grant verb is not in the ontology")
                continue
            _check_resource(o, jget(g, "res"), v, gw, bad)
            _check_cond(jget(g, "cond"), v, t, gw, bad)
            res = jget(g, "res")
            if jget(res, "k") == "any" and not (jget(v, "effect") == "read" and len(tbounds) > 0):
                bad("unbounded", gw, "wildcard resource in a template")
            if jget(v, "effect") != "read" and jget(res, "k") == "related" and len(tbounds) == 0:
                bad("unbounded", gw, "non-read grant on a related set needs an aggregate bound")
        for p in req_list(jget(t, "prohibits")):
            tg = jget(p, "target")
            pw = "%s.%s" % (w, js_str(jget(p, "pid")))
            if jget(tg, "k") == "verb" and _hk(jget(tg, "verb")) not in verbs:
                bad("prohibit_verb", pw, "prohibit verb is not in the ontology")
            if jget(tg, "k") == "effect" and not includes(EFFECT_CLASSES, jget(tg, "cls")):
                bad("prohibit_effect", pw, "unknown effect class")
        for b in tbounds:
            bw = "%s.%s" % (w, js_str(jget(b, "bid")))
            over = jget(b, "over")
            if not strict_eq(over, "all") and any(x not in gids for x in req_list(over)):
                bad("bound_over", bw, "bound selects an unknown grant")
            cs_name = jget(b, "cap_slot")
            if truthy(cs_name) and cs_name not in slot_names:
                bad("slot_undeclared", w, "cap slot %s is not declared" % js_str(cs_name))
            if truthy(cs_name):
                cs = _find(slots, lambda x: strict_eq(jget(x, "name"), cs_name))
                if cs is not UNDEF:
                    csk, agg = jget(cs, "kind"), jget(b, "agg")
                    if not (csk == "money" or csk == "count"):
                        bad("bound_cap", bw, "cap slot must be money or count")
                    if agg == "count" and csk != "count":
                        bad("bound_cap", bw, "count bound needs a count slot")
                    if agg == "sum" and csk != "money":
                        bad("bound_cap", bw, "sum bound over money needs a money slot")
            if jget(b, "agg") == "sum" and not truthy(jget(b, "param")):
                bad("bound_value", bw, "sum bound has no value parameter")
        # non-empty and bounded after instantiation with the declared example
        g = instantiate_template(o, tid, jget(t, "example"), {"principal": "p", "nl": ""})
        if len(g["holes"]) > 0:
            bad("example_holes", w, "example leaves holes: %s" % ",".join(h["hid"] for h in g["holes"]))
        elif len(g["grants"]) != len(tgrants):
            bad("empty_allow", w, "example instantiation dropped a grant")
        elif not _has_allow_witness(o, g):
            bad("empty_allow", w, "instantiated template has an empty Allow set")
    return I


def _is_integer(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and float(x).is_integer()


def _check_resource(o: Any, s: Any, v: Any, w: str, bad: Callable[[str, str, str], None]) -> None:
    rt = jget(v, "resource_type")
    ty = _find(jget(o, "types"), lambda t: strict_eq(jget(t, "id"), rt))
    prefix = oc(ty, "id_prefix")

    def id_ok(i: Any, pre: Any) -> bool:
        return i.startswith("$") or (pre is not UNDEF and i.startswith(pre))

    k = jget(s, "k")
    if k == "exact" and not id_ok(jget(s, "id"), prefix):
        bad("resource_type", w, "exact resource id has the wrong type prefix")
    elif k == "oneof":
        ids = req_list(jget(s, "ids"))
        if len(ids) == 0:
            bad("resource_empty", w, "one_of is empty")
        for i in ids:
            if not id_ok(i, prefix):
                bad("resource_type", w, "one_of member has the wrong type prefix")
    elif k == "related":
        rel = jget(s, "rel")
        r = _find(jget(o, "relations"), lambda x: strict_eq(jget(x, "id"), rel))
        if r is UNDEF:
            bad("relation_unknown", w, "relation %s is not declared" % js_str(rel))
        else:
            if jget(r, "to") != rt:
                bad("relation_type", w, "relation target type differs from the verb resource type")
            rf = jget(r, "from")
            anchor_pre = oc(_find(jget(o, "types"), lambda t: strict_eq(jget(t, "id"), rf)), "id_prefix")
            if not id_ok(jget(s, "anchor"), anchor_pre):
                bad("resource_type", w, "relation anchor has the wrong type prefix")
    elif k == "all_of":
        parts = req_list(jget(s, "parts"))
        if len(parts) < 2:
            bad("all_of_arity", w, "all_of needs at least two parts")
        for x in parts:
            _check_resource(o, x, v, w, bad)


def _check_cond(c: Any, v: Any, t: Any, w: str, bad: Callable[[str, str, str], None]) -> None:
    k = jget(c, "k")
    if k == "and" or k == "or":
        _check_cond(jget(c, "a"), v, t, w, bad)
        _check_cond(jget(c, "b"), v, t, w, bad)
        return
    if k == "not":
        _check_cond(jget(c, "c"), v, t, w, bad)
        return
    if k != "cmp":
        return
    l = jget(c, "l")
    p = _own(jget(v, "params"), jget(l, "path")) if jget(l, "k") == "param" else UNDEF
    if jget(l, "k") != "param" or not truthy(p):
        bad("cond_param", w, "left side of a comparison must be a declared parameter of the verb")
        return
    op = jget(c, "op")
    pk = jget(p, "kind")
    if (op in ("lt", "lte", "gt", "gte")) and (pk == "text" or pk == "enum" or pk == "id"):
        bad("cond_order", w, "ordering on a text/enum/id parameter")
    x = jget(c, "r")
    xk = jget(x, "k")
    if xk == "slot":
        sn = jget(x, "slot")
        s = _find(jget(t, "slots"), lambda q: strict_eq(jget(q, "name"), sn))
        if s is UNDEF:
            return
        sk = jget(s, "kind")
        if pk == "money":
            ok_kind = sk == "money"
        else:
            ok_kind = (pk == sk or (pk == "enum" and (sk == "enum" or sk == "enum_list")) or (pk == "id" and (sk == "id" or sk == "id_list"))
                       or (pk == "text" and sk == "text_list"))
        if not ok_kind:
            bad("cond_type", w, "slot %s (%s) does not type-check against parameter kind %s" % (js_str(jget(s, "name")), js_str(sk), js_str(pk)))
        ccys = jget(p, "ccys")
        scc = jget(s, "ccy")
        if pk == "money" and sk == "money" and not (ccys is not UNDEF and includes(ccys, "" if scc is UNDEF else scc)):
            bad("cond_unit", w, "slot currency is not accepted by the parameter")
        lst = sk == "id_list" or sk == "enum_list" or sk == "text_list"
        if lst != (op == "in" or op == "nin"):
            bad("cond_type", w, "list slots pair with in/nin and scalar slots with the other operators")
    elif xk == "lit":
        lv = jget(x, "v")
        if jget(lv, "k") == "set":
            items = req_list(jget(lv, "items"))
            if len(items) == 0:
                bad("cond_type", w, "empty literal list")
            for i in items:
                _lit_check(i, p, w, bad)
            if op != "in" and op != "nin":
                bad("cond_type", w, "a literal set pairs with in/nin")
        else:
            _lit_check(lv, p, w, bad)
            if op == "in" or op == "nin":
                bad("cond_type", w, "in/nin needs a list")
    else:
        bad("cond_term", w, "unsupported right-hand term")


def _lit_check(l: Any, p: Any, w: str, bad: Callable[[str, str, str], None]) -> None:
    pk = jget(p, "kind")
    k = jget(l, "k")
    if k == "q":
        u = jget(jget(l, "q"), "u")
        if jget(u, "k") != pk:
            bad("cond_type", w, "literal kind differs from the parameter kind")
        ccys = jget(p, "ccys")
        if jget(u, "k") == "money" and not (ccys is not UNDEF and includes(ccys, jget(u, "ccy"))):
            bad("cond_unit", w, "literal currency is not accepted by the parameter")
    elif k == "s":
        if pk != "enum" and pk != "id" and pk != "text":
            bad("cond_type", w, "literal kind differs from the parameter kind")
        vals = jget(p, "values")
        if pk == "enum" and not (vals is not UNDEF and includes(vals, jget(l, "s"))):
            bad("cond_enum", w, "enum literal is not a member")
    else:
        bad("cond_type", w, "nested literal set")


def _has_allow_witness(o: Any, g: dict) -> bool:
    """A cheap Allow witness for the checker: build an action from the grant's selector and conditions."""
    ont = ontology_for_goal(o, g)
    return all(allow_witness(g, gr, ont) is not None for gr in g["grants"])


def _quantity_of(s: Any, v: Any) -> Optional[Dict[str, Any]]:
    if isinstance(v, (str, list, tuple)):
        return None
    if not isinstance(v, dict):
        raise TypeError("cannot use 'in' operator on a non-object")
    kind = jget(s, "kind")

    def ok(n: Any, signed: bool) -> bool:
        return _safe_int(n) and (signed or n >= 0) and not (isinstance(n, float) and n == 0 and str(n).startswith("-"))
    if "minor" in v and kind == "money" and strict_eq(v.get("ccy"), jget(s, "ccy")) and ok(v["minor"], False):
        return {"u": {"k": "money", "ccy": v["ccy"]}, "n": v["minor"]}
    if "n" in v and kind == "count" and ok(v["n"], False):
        return {"u": {"k": "count"}, "n": v["n"]}
    if "ms" in v and kind == "duration" and ok(v["ms"], False):
        return {"u": {"k": "duration"}, "n": v["ms"]}
    if "epoch_ms" in v and kind == "instant" and ok(v["epoch_ms"], True):
        return {"u": {"k": "instant"}, "n": v["epoch_ms"]}
    return None


def _sv(s: str) -> Dict[str, Any]:
    return {"k": "s", "s": s}


_ID_RE = re.compile(r"[A-Za-z0-9_-]+")


def _utf16_len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def slot_lits(o: Any, s: Any, v: Any = UNDEF) -> Union[List[Dict[str, Any]], str, None]:
    """Typed value(s) of a slot, or a reason string when it is missing / invalid (the slot then becomes a Hole)."""
    if v is UNDEF:
        return "missing"
    kind = jget(s, "kind")
    if kind in ("money", "count", "duration", "instant"):
        q = _quantity_of(s, v)
        if q is None:
            return "ill-typed"
        mx = jget(s, "max")
        if mx is not UNDEF and (0 if kind == "instant" else q["n"]) > mx:
            return "above the template maximum"
        return [{"k": "q", "q": q}]
    if kind == "id" or kind == "id_list":
        of = jget(s, "of")
        pre = oc(_find(jget(o, "types"), lambda t: strict_eq(jget(t, "id"), of)), "id_prefix")
        if kind == "id":
            return [_sv(v)] if (isinstance(v, str) and truthy(pre) and v.startswith(pre) and _utf16_len(v) > _utf16_len(pre) and _ID_RE.fullmatch(v)) else "ill-typed"
        if isinstance(v, (list, tuple)) and len(v) > 0 and all(truthy(pre) and x.startswith(pre) and _ID_RE.fullmatch(x) for x in v):
            return [_sv(x) for x in v]
        return "ill-typed"
    vals = jget(s, "values")
    if kind == "enum":
        return [_sv(v)] if (isinstance(v, str) and vals is not UNDEF and includes(vals, v)) else "ill-typed"
    if kind == "enum_list":
        if isinstance(v, (list, tuple)) and len(v) > 0 and all(vals is not UNDEF and includes(vals, x) for x in v):
            return [_sv(x) for x in v]
        return "ill-typed"
    if kind == "text_list":
        if isinstance(v, (list, tuple)) and len(v) > 0 and all(
                isinstance(x, str) and len(x) > 0 and x == unicodedata.normalize("NFKC", x) and not _INVIS_RE.search(x) for x in v):
            return [_sv(x) for x in v]
        return "ill-typed"
    return None  # the reference switch has no default


def _is_list_slot(t: Any, name: Any) -> bool:
    s = _find(jget(t, "slots"), lambda x: strict_eq(jget(x, "name"), name))
    k = "" if s is UNDEF or jget(s, "kind") is UNDEF else jget(s, "kind")
    return isinstance(k, str) and k.endswith("_list")


def instantiate_template(o: Any, template_id: Any, values: Any, opts: Any) -> Dict[str, Any]:
    """Template -> Goal (IR, canonical order). Mandatory slots that are missing or ill-typed become Holes; every clause depending on a
    hole is dropped (the most restrictive completion); a prohibition that depends on a hole widens to every resource. Limits become
    IR bounds over the surviving grants (admitting grant, lifetime window, session scope)."""
    t = _find(jget(o, "templates"), lambda x: strict_eq(jget(x, "id"), template_id))
    if t is UNDEF:
        raise ValueError("unknown template %s" % js_str(template_id))
    bound: Dict[Any, Any] = {}
    holes: List[Dict[str, Any]] = []
    for s in req_list(jget(t, "slots")):
        name = jget(s, "name")
        v = _own(values, name)
        r = slot_lits(o, s, jget(s, "default") if v is UNDEF or v is None else v)
        if isinstance(r, str):
            ccy = jget(s, "ccy")
            holes.append({"hid": name, "q": "What is the %s (%s%s)? (%s)" % (js_str(name).replace("_", " "), js_str(jget(s, "kind")),
                                                                         " " + js_str(ccy) if truthy(ccy) else "", r),
                          "domain": [], "affects": [], "global": False})
        else:
            bound[name] = r

    def deps(refs: List[Any]) -> bool:
        return all(r in bound for r in refs)

    def single(name: Any) -> Any:
        return bound[name][0]

    def sub(i: str) -> str:
        return single(i[1:])["s"] if i.startswith("$") else i

    def sub_part(r: Any) -> Any:
        k = jget(r, "k")
        if k == "exact":
            return {"k": "exact", "id": sub(jget(r, "id"))}
        if k == "oneof":
            return {"k": "oneof", "ids": [sub(i) for i in req_list(jget(r, "ids"))]}
        return dict(r, anchor=sub(jget(r, "anchor")))

    def sub_res(r: Any) -> Any:
        k = jget(r, "k")
        if k == "any":
            return r
        if k == "all_of":
            return {"k": "all_of", "parts": [sub_part(p) for p in req_list(jget(r, "parts"))]}
        return sub_part(r)

    verb_of: Dict[Any, Any] = {}
    for v in req_list(jget(o, "verbs")):
        verb_of.setdefault(jget(v, "id"), v)

    def ty_of(verb: Any, path: Any, ccy: Any) -> Any:
        p = _own(jget(verb_of[verb], "params"), path) if verb is not None and verb in verb_of else UNDEF
        if p is UNDEF:
            p = next((x for x in (_own(jget(v, "params"), path) for v in req_list(jget(o, "verbs"))) if x is not UNDEF), UNDEF)
        if p is UNDEF:
            raise ValueError("parameter %s is not declared by any verb" % js_str(path))
        return _param_ty(p, ccy)

    def lit(x: Any) -> Any:
        k = jget(x, "k")
        if k == "slot":
            l = bound[jget(x, "slot")]
            return {"k": "lit", "v": {"k": "set", "items": l} if _is_list_slot(t, jget(x, "slot")) else l[0]}
        return {"k": "lit", "v": jget(x, "v")} if k == "lit" else None

    def ccy_of(x: Any) -> Any:
        if x is not None and jget(x, "k") == "lit" and jget(jget(x, "v"), "k") == "q" and jget(jget(jget(jget(x, "v"), "q"), "u"), "k") == "money":
            return jget(jget(jget(jget(x, "v"), "q"), "u"), "ccy")
        return None

    def sub_cond(c: Any, verb: Any) -> Any:
        k = jget(c, "k")
        if k == "true":
            return c
        if k == "and" or k == "or":
            return {"k": k, "a": sub_cond(jget(c, "a"), verb), "b": sub_cond(jget(c, "b"), verb)}
        if k == "not":
            return {"k": "not", "c": sub_cond(jget(c, "c"), verb)}
        lv, rv = lit(jget(c, "l")), lit(jget(c, "r"))
        hint = ccy_of(lv)
        if hint is None:
            hint = ccy_of(rv)

        def term(x: Any, v: Any) -> Any:
            if v is not None:
                return v
            path = jget(x, "path")
            return {"k": "param", "path": path, "ty": ty_of(verb, path, hint)}
        return {"k": "cmp", "op": jget(c, "op"), "l": term(jget(c, "l"), lv), "r": term(jget(c, "r"), rv)}

    dropped: set = set()
    grants: List[Dict[str, Any]] = []
    t_bounds = req_list(jget(t, "bounds"))
    t_grants = req_list(jget(t, "grants"))
    keep_bound = [b for b in t_bounds if deps(_refs_bound(b))]
    for b in t_bounds:
        if not any(b is kb for kb in keep_bound):
            for g in t_grants:
                over = jget(b, "over")
                if strict_eq(over, "all") or includes(over, jget(g, "gid")):
                    dropped.add(jget(g, "gid"))
    for g in t_grants:
        if jget(g, "gid") in dropped or not deps(_refs_grant(g)):
            dropped.add(jget(g, "gid"))
        else:
            grants.append({"gid": jget(g, "gid"), "verb": jget(g, "verb"), "res": sub_res(jget(g, "res")), "cond": sub_cond(jget(g, "cond"), jget(g, "verb"))})
    prohibits: List[Dict[str, Any]] = []
    for p in req_list(jget(t, "prohibits")):
        tg = jget(p, "target")
        if jget(tg, "k") == "verb":
            verb = jget(tg, "verb")
        else:
            fv = _find(jget(o, "verbs"), lambda v: strict_eq(jget(v, "effect"), jget(tg, "cls")))
            verb = oc(fv, "id")
            verb = None if verb is UNDEF else verb
        if deps(_refs_grant(p)):
            prohibits.append({"pid": jget(p, "pid"), "target": tg, "res": sub_res(jget(p, "res")), "cond": sub_cond(jget(p, "cond"), verb)})
        else:
            prohibits.append({"pid": jget(p, "pid"), "target": tg, "res": {"k": "any", "reason": "hole"}, "cond": {"k": "true"}})
    kept = set(g["gid"] for g in grants)
    bounds: List[Dict[str, Any]] = []
    for b in keep_bound:
        over = jget(b, "over")
        gids = [g["gid"] for g in grants] if strict_eq(over, "all") else [x for x in req_list(over) if x in kept]
        if len(gids) == 0:
            continue
        cs = jget(b, "cap_slot")
        cap_lit = single(cs) if truthy(cs) else None
        cap = jget(cap_lit, "q") if cap_lit is not None and jget(cap_lit, "k") == "q" else jget(b, "cap")
        verb = next(g for g in grants if g["gid"] == gids[0])["verb"]
        agg = jget(b, "agg")
        capu = jget(cap, "u")
        bounds.append({
            "bid": jget(b, "bid"), "sel": {"k": "gids", "gids": gids}, "agg": agg,
            "value": ({"k": "param", "path": jget(b, "param"), "ty": ty_of(verb, jget(b, "param"), jget(capu, "ccy") if jget(capu, "k") == "money" else None)}
                      if agg == "sum" else {"k": "lit", "v": {"k": "q", "q": {"u": {"k": "count"}, "n": 1}}}),
            "key": "", "window": {"k": "lifetime"}, "scope": {"k": "session"}, "cap": cap, "onExceed": jget(b, "onExceed")})
    srcs = jget(opts, "sources")
    return canonicalize_goal({
        "v": 1, "principal": jget(opts, "principal"), "ontDigest": ontology_digest(o), "nlDigest": nl_digest(jget(opts, "nl")),
        "sources": list(req_list(srcs)) if srcs is not UNDEF and srcs is not None else [],
        "grants": grants, "prohibits": prohibits, "bounds": bounds,
        "validity": {"notBefore": 0, "notAfter": _FOREVER, "maxIdle": 0}, "deleg": {"maxDepth": 0, "narrowOnly": True, "mayTouch": []},
        "escalateOn": [], "wildcardAck": [], "holes": holes})


# ---- locale-aware human number parsing (interpreter front end only; the IR has no locale) -----------------------------------

_NUM_RE = re.compile(r"[0-9][0-9.,]*")


def parse_human_amount(text: str, exponent: int, locale: Optional[str] = None) -> Dict[str, Any]:
    """"1,000.50", "1.000,50", "$20", "20 dollars". Ambiguous literals ("1,000" with no locale hint, "1.000") are NOT guessed: they
    yield a failure and become a Hole. `locale` 'en' reads ',' as thousands, 'de' reads '.' as thousands."""
    if not isinstance(text, str):
        raise TypeError("text.normalize is not a function")
    t = re.sub("[^0-9.,]", "", js_trim(unicodedata.normalize("NFKC", text)))
    if not _NUM_RE.fullmatch(t) or re.search("[.,]{2}", t):
        return {"ok": False, "reason": "not a number"}
    last_dot, last_comma = t.rfind("."), t.rfind(",")
    dec = thou = None
    if last_dot >= 0 and last_comma >= 0:
        dec = "." if last_dot > last_comma else ","
        thou = "," if dec == "." else "."
    elif last_dot >= 0 or last_comma >= 0:
        sep = "." if last_dot >= 0 else ","
        parts = t.split(sep)
        group_like = len(parts) > 2 or len(parts[-1]) == 3
        if not group_like:
            dec = sep
        elif len(parts) > 2:
            thou = sep
        elif locale:
            if (locale == "en") == (sep == ","):
                thou = sep
            else:
                dec = sep
        else:
            return {"ok": False, "reason": "ambiguous separator"}
    int_part, frac = t, ""
    if dec:
        i = t.rfind(dec)
        int_part, frac = t[:i], t[i + 1:]
    if thou:
        groups = int_part.split(thou)
        if any(len(g) != 3 for g in groups[1:]) or len(groups[0]) == 0 or len(groups[0]) > 3:
            return {"ok": False, "reason": "malformed grouping"}
        int_part = "".join(groups)
    if len(frac) > exponent:
        return {"ok": False, "reason": "more decimals than the currency allows"}
    minor = int(int_part + frac.ljust(exponent, "0"))
    return {"ok": True, "minor": minor} if minor <= _FOREVER else {"ok": False, "reason": "out of range"}


def parse_money(text: Any, exponent: int, locale: Optional[str]) -> Dict[str, Any]:
    """The strict front-end contract over `parse_human_amount`: only digits, '.' and ',' after one optional leading currency symbol; with
    a locale, a decimal separator that contradicts it is refused; without one, a repeated or ambiguous separator is a Hole, not a guess."""
    t = re.sub("^[$€£][%s]*" % re.escape(JS_WS), "", js_trim(js_str(text)))
    if not _NUM_RE.fullmatch(t):
        return {"error": "BAD_NUMBER"}
    both = "." in t and "," in t
    if locale is not None and both and t[max(t.rfind("."), t.rfind(","))] != ("." if locale == "en" else ","):
        return {"error": "BAD_NUMBER"}
    if locale is None and not both and len(re.findall("[.,]", t)) > 1:
        return {"hole": "AMBIGUOUS_NUMBER"}
    r = parse_human_amount(t, exponent, locale)
    if r["ok"]:
        return {"minor": r["minor"]}
    return {"hole": "AMBIGUOUS_NUMBER"} if r["reason"] == "ambiguous separator" else {"error": "BAD_NUMBER"}
