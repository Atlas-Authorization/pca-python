"""The trusted question card and agent-initiated clarification of the wallet (the PCA Intent Layer v2): a deterministic render
from the wallet's own outcome space, the cell coordinates, the verified site identity, the principal's own signed statement and a
closed-enum reason (no field for agent-authored text), its digest, the "Partly..." and typed-value checks, and the structured
clarification request with max-information cell selection. A port of the TypeScript reference (@atlasauth/pca-wallet).

The input is a dict with the reference's member names (omega, verb, coords, site, statementText, reversibility, units, action,
friction, kind, reason, locale, catalog)."""
import math
import re
from typing import Any, Dict, List, Optional

from ._fin import fin
from .facade import BUILTIN_ACTIONS, _Catalog
from .pca import hash_canonical
from .predicates import _UNDEF, _js_string
from .wallet import (_entries, _g, _plain, _truthy, bin_ent, cat_label, cell_key, cell_of_action, flat_index,
                     friction_rank, is_obj, resolve_coords, worst_provenance)
from .wallet_omega import DEFAULT_HARM, HarmModel, cell_stats, is_number, is_safe_int, label_of, num_cells, u16len, u16slice

__all__ = [
    "CARD_DOMAIN", "CLARIFY_REASONS", "REASON_LABELS", "MAX_CANDIDATES", "clean_text", "last4", "format_number", "render_card",
    "card_digest", "card_digest_matches", "card_text", "partial_error", "normalize_typed", "expected_typed",
    "parse_clarify_request", "information_gain", "plan_clarification",
]

CARD_DOMAIN = "atlas-pca/intent-card/v2"
CLARIFY_REASONS = ("ambiguous_parameter", "multiple_options", "price_changed", "constraint_conflict", "missing_value", "other")
REASON_LABELS = {
    "ambiguous_parameter": "Your agent found a detail your request did not settle.",
    "multiple_options": "Your agent found several options that match.",
    "price_changed": "Your agent found that a price changed.",
    "constraint_conflict": "Your agent found that two parts of your request conflict.",
    "missing_value": "Your agent needs a value your request did not give.",
    "other": "Your agent needs a decision before it continues.",
}
MAX_CANDIDATES = 8
_MAX_VALUES = 64
_MAX_STRING = 256
_PATH_RE = re.compile(r"[a-z][a-z0-9_]*(\.[a-z0-9_]+)*", re.I | re.ASCII)
_DEFAULT_CATALOG = _Catalog(BUILTIN_ACTIONS)

# JavaScript's \s and String.prototype.trim whitespace set
_WS = "\t\n\x0b\x0c\r    -     　﻿"
_CTRL = re.compile("[\u0000-\u001f\u007f-\u009f​-‏ -‮⁦-⁩]")
_WS_RUN = re.compile("[" + _WS + "]+")
_WS_EDGE = re.compile("^[" + _WS + "]+|[" + _WS + "]+$")


def clean_text(s: Any, mx: int) -> str:
    """Strip control characters, collapse whitespace, cap length (for the principal's own words and the site's name)."""
    if not isinstance(s, str):
        raise TypeError("s.replace is not a function")
    t = _WS_EDGE.sub("", _WS_RUN.sub(" ", _CTRL.sub(" ", s)))
    return t if u16len(t) <= mx else u16slice(t, 0, mx - 1) + "…"


def last4(s: str) -> str:
    """The last four letters/digits of a string (all a card ever shows of a string the outcome space does not name)."""
    return re.sub("[^A-Za-z0-9]", "", s)[-4:].upper()


def _group(n: int) -> str:
    return re.sub(r"\B(?=(\d{3})+(?!\d))", ",", str(n), flags=re.ASCII)


_CURRENCY_SYMBOL = {"USD": "$", "EUR": "€", "GBP": "£", "JPY": "¥"}


def _to_number(v: Any) -> float:
    """JavaScript ToNumber for the values a JSON document can hold (undefined is NaN)."""
    if v is _UNDEF:
        return math.nan
    if v is None or v is False:
        return 0.0
    if v is True:
        return 1.0
    if is_number(v):
        return float(v)
    if isinstance(v, str):
        t = _WS_EDGE.sub("", v)
        if t == "":
            return 0.0
        return float(t) if re.fullmatch(r"[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?", t, re.ASCII) else math.nan
    if isinstance(v, list):
        return _to_number(_js_string(v))
    return math.nan


def _exponent(unit: Any) -> int:
    e = _to_number(_g(unit, "exponent"))
    if e != e:
        raise ValueError("NaN exponent")
    return int(max(0, min(6, math.floor(e)))) if e not in (math.inf, -math.inf) else (6 if e > 0 else 0)


def _is_money(unit: Any) -> bool:
    return isinstance(unit, dict) and unit.get("kind") == "money"


def format_number(x: Any, unit: Any = None) -> str:
    """Thousands grouping with commas, independent of any locale data (cards render identically anywhere)."""
    if _is_money(unit):
        try:
            e = _exponent(unit)
        except ValueError:
            return _nan_money(x, unit)
        neg = x < 0
        a = abs(int(x))
        div = 10 ** e
        whole = _group(a // div)
        frac = "." + str(a % div).rjust(e, "0") if e > 0 else ""
        cur = _g(unit, "currency")
        sym = _CURRENCY_SYMBOL.get(cur) if isinstance(cur, str) else None
        if sym is None:
            sym = _js_string(cur) + " "
        return "%s%s%s%s" % ("-" if neg else "", sym, whole, frac)
    return "%s%s" % ("-" if x < 0 else "", _group(abs(int(x))))


def _nan_money(x: Any, unit: Any) -> str:
    # an exponent that is not a number: the reference computes with NaN, rendering "NaN" for the whole part and no fraction
    cur = _g(unit, "currency")
    sym = _CURRENCY_SYMBOL.get(cur) if isinstance(cur, str) else None
    if sym is None:
        sym = _js_string(cur) + " "
    return "%s%sNaN" % ("-" if x < 0 else "", sym)


_ACC = re.compile(r"env\.acc\.([A-Za-z0-9_.-]+)\.post")
_WORLD = re.compile(r"env\.world\.([A-Za-z0-9_.-]+)")
_MON = re.compile(r"env\.mon\.([A-Za-z0-9_.-]+)\.state")


def _dim_label(path: str) -> str:
    m = _ACC.fullmatch(path)
    if m:
        return "%s (running total for this task)" % re.sub("[_.]", " ", m.group(1))
    m = _WORLD.fullmatch(path)
    if m:
        return "%s (from a signed fact)" % re.sub("[_.]", " ", m.group(1))
    m = _MON.fullmatch(path)
    if m:
        return "state of %s" % re.sub("[_.]", " ", m.group(1))
    return label_of(path)


def _is_prov_path(p: str) -> bool:
    return p.startswith("env.prov.")


def _num_fact(d: Dict[str, Any], ids: List[int], unit: Any, action_value: Any) -> str:
    cells = num_cells(d)
    lo = cells[ids[0]]["lo"]
    hi = cells[ids[-1]]["hi"]
    if lo == hi:
        rng = "exactly %s" % format_number(lo, unit)
    elif lo == d["lo"] and hi == d["hi"]:
        rng = "any value"
    elif hi == d["hi"]:
        rng = "%s or more" % format_number(lo, unit)
    elif lo == d["lo"]:
        rng = "up to %s" % format_number(hi, unit)
    else:
        rng = "%s – %s" % (format_number(lo, unit), format_number(hi, unit))
    ex = " (this action: %s)" % format_number(action_value, unit) if is_number(action_value) and fin(action_value) else ""
    return rng + ex


def _cat_value_text(d: Dict[str, Any], i: int) -> str:
    v = d["values"][i]
    if v["kind"] == "exact":
        return '"%s"' % clean_text(v["value"], 64)
    if v["kind"] == "prefix":
        return 'anything starting with "%s"' % clean_text(v["value"], 64)
    return "a value not named in your request"


def _cat_fact(d: Dict[str, Any], ids: List[int], action_value: Any) -> str:
    parts = [_cat_value_text(d, i) for i in ids]
    if len(parts) == 1:
        st = parts[0]
    else:
        st = "%s or %s" % (", ".join(parts[:-1]), parts[-1] if parts else "undefined")
    if not isinstance(action_value, str):
        return st
    named = any(v["kind"] == "exact" and v["value"] == action_value for v in d["values"])
    return '%s (this action: %s)' % (st, '"%s"' % clean_text(action_value, 64) if named else 'a value ending in "%s"' % last4(action_value))


def _banner_for(path: str, levels: List[str]) -> Optional[str]:
    w = worst_provenance(levels)
    label = _dim_label(path)
    if w == "web":
        return "This %s was suggested by content on a web page, not by you." % label
    if w == "tool":
        return "This %s came from a tool result, not from you." % label
    if w == "agent":
        return "This %s was chosen by your agent, not taken from your request or from the site." % label
    return None


def _prov_levels(d: Dict[str, Any], ids: List[int]) -> List[str]:
    out: List[str] = []
    for i in ids:
        out.extend(re.split("[|,]", cat_label(d, i)))
    return out


def _vget(values: Any, path: str) -> Any:
    """`action.values[path]` for a value that may be any JSON: a missing or null `values` throws, a non-object has no members."""
    if values is None or values is _UNDEF:
        raise TypeError("Cannot read properties of undefined")
    return values.get(path) if isinstance(values, dict) else None


def _typed_target(vs: Dict[str, Any], action: Any, units: Any) -> Optional[Dict[str, Any]]:
    if not _truthy(action):
        return None
    values = _g(action, "values")
    dims = [d for d in vs["dims"] if not _is_prov_path(d["path"])]
    nums = [d for d in dims if d["kind"] == "num" and is_number(_vget(values, d["path"]))]
    money = next((d for d in nums if _is_money(_g(units, d["path"]) if isinstance(units, dict) else None)), None)
    pick = money if money is not None else (nums[0] if nums else None)
    if pick is not None:
        return {"path": pick["path"], "mode": "number", "prompt": "To allow it, type the %s of this action shown above." % _dim_label(pick["path"])}
    cat = next((d for d in dims if d["kind"] == "cat" and isinstance(_vget(values, d["path"]), str) and len(last4(_vget(values, d["path"]))) == 4), None)
    if cat is not None:
        return {"path": cat["path"], "mode": "last4", "prompt": "To allow it, type the last 4 letters or digits of the %s." % _dim_label(cat["path"])}
    return None


_ANSWERS = {
    "tap": [{"id": "no", "label": "No"}, {"id": "partly", "label": "Partly…"}, {"id": "yes", "label": "Yes"}],
    "hold": [{"id": "no", "label": "No"}, {"id": "partly", "label": "Partly…"}, {"id": "yes", "label": "Press and hold to allow"}],
    "typed": [{"id": "no", "label": "No"}, {"id": "partly", "label": "Partly…"}, {"id": "yes", "label": "Yes, type the value to confirm"}],
    "device": [{"id": "no", "label": "No"}, {"id": "partly", "label": "Partly…"}, {"id": "yes", "label": "Yes, confirm with your security key"}],
}
_REV_TEXT = {"reversible": "that can be undone", "rate_limited": "that is rate-limited", "irreversible": "that cannot be undone"}


def _answers_of(friction: Any) -> Optional[List[Dict[str, str]]]:
    # ANSWERS[friction]: a property key, so a one-element array of a tier name selects that tier too
    key = friction if isinstance(friction, str) else (friction[0] if isinstance(friction, list) and len(friction) == 1 and isinstance(friction[0], str) else None)
    return _ANSWERS.get(key) if key is not None else None


def _lower_first(s: str) -> str:
    return s if not s or s[0] in "\n\r  " else s[0].lower() + s[1:]


def render_card(inp: Dict[str, Any]) -> Dict[str, Any]:
    """Render the trusted question card: {ok: True, card} or {ok: False, reason}."""
    loc = _g(inp, "locale")
    if loc is _UNDEF or loc is None:
        loc = "en"
    if loc != "en":
        raise_loc = _g(inp, "locale")
        return {"ok": False, "reason": "unsupported locale %s" % _js_string(raise_loc)}
    kind = _g(inp, "kind")
    reason = _g(inp, "reason")
    if kind == "clarification" and reason is _UNDEF:
        return {"ok": False, "reason": "a clarification card needs a reason"}
    if reason is not _UNDEF and not (isinstance(reason, str) and reason in CLARIFY_REASONS):
        return {"ok": False, "reason": "unknown clarification reason"}
    verb = _g(inp, "verb")
    r = resolve_coords(inp["omega"], verb, _g(inp, "coords"))
    if not r["ok"]:
        return r
    vs, box = r["vs"], r["box"]
    action = _g(inp, "action")
    if _truthy(action) and _g(action, "verb") != verb:
        return {"ok": False, "reason": "the action is for another verb"}
    cat = inp.get("catalog")
    catalog = _DEFAULT_CATALOG if cat is None else cat
    site = inp["site"]
    site_name = clean_text(site["name"], 64) or clean_text(site["origin"], 64)
    said = clean_text(inp["statementText"], 280) if "statementText" in inp else ""
    if kind == "clarification":
        header = 'Your agent needs a decision for your request "%s"' % said if said else "Your agent needs a decision"
    else:
        header = '%s asks on behalf of your request "%s"' % (site_name, said) if said else "%s asks for your confirmation" % site_name
    spec = catalog.get(verb)
    if spec:
        what = _lower_first(re.sub(r"\.\Z", "", spec["description"]))
    else:
        what = 'the action "%s" on %s' % (clean_text(verb, 64), site_name)
    rev = inp.get("reversibility")
    if rev is None:
        rev = vs["reversibility"]
    sentence = "Allow %s, %s, with:" % (what, _REV_TEXT.get(rev, "undefined") if isinstance(rev, str) else "undefined")
    units = inp.get("units")
    facts: List[Dict[str, str]] = []
    banners: List[str] = []
    partial: List[Dict[str, Any]] = []
    for k, d in enumerate(vs["dims"]):
        ids = box[k]
        if _is_prov_path(d["path"]):
            if d["kind"] != "cat":
                continue
            b = _banner_for(d["path"][len("env.prov."):], _prov_levels(d, ids))
            if b:
                banners.append(b)
            continue
        av = None
        if action is not None and action is not _UNDEF:
            av = _vget(_g(action, "values"), d["path"])
        unit = _g(units, d["path"]) if isinstance(units, dict) else None
        unit = None if unit is _UNDEF else unit
        if d["kind"] == "num":
            facts.append({"key": d["path"], "label": _dim_label(d["path"]), "text": _num_fact(d, ids, unit, av)})
            cells = num_cells(d)
            partial.append({"path": d["path"], "kind": "num", "lo": cells[ids[0]]["lo"], "hi": cells[ids[-1]]["hi"]})
        else:
            facts.append({"key": d["path"], "label": _dim_label(d["path"]), "text": _cat_fact(d, ids, av)})
            options = [d["values"][i]["value"] for i in ids if d["values"][i]["kind"] == "exact"]
            if len(options) > 1:
                partial.append({"path": d["path"], "kind": "cat", "options": options})
    friction = _g(inp, "friction")
    typed = _typed_target(vs, action, units) if friction_rank(friction) >= friction_rank("typed") else None
    body: Dict[str, Any] = {
        "v": 2, "verb": verb, "coords": _plain(inp["coords"]), "locale": "en",
        "site": {"origin": clean_text(site["origin"], 256), "name": site_name},
        "header": header,
    }
    if kind is not _UNDEF:
        body["kind"] = kind
    if reason is not _UNDEF:
        body["reason_label"] = REASON_LABELS[reason]
    body["sentence"] = sentence
    body["facts"] = facts
    body["banners"] = banners
    if friction is not _UNDEF:
        body["friction"] = friction
    answers = _answers_of(friction)
    if answers is not None:
        body["answers"] = answers
    if typed:
        body["typed"] = typed
    body["partial"] = partial
    out = dict(body)
    out["rendered_digest"] = card_digest(body)
    return {"ok": True, "card": out}


def card_digest(body: Dict[str, Any]) -> str:
    """The content address of a card body (everything but `rendered_digest`)."""
    return hash_canonical({"d": CARD_DOMAIN, "c": _plain(body)})


def card_digest_matches(card: Dict[str, Any]) -> bool:
    """Recompute a card's digest and compare: an auditor's check that the stored card is the one that was hashed."""
    body = {k: v for k, v in card.items() if k != "rendered_digest"}
    return card_digest(body) == card.get("rendered_digest", _UNDEF)


def card_text(card: Dict[str, Any]) -> str:
    """The plain text of a card, line by line (what a screen reader or a text channel shows)."""
    lines = [card["header"]]
    if _truthy(card.get("reason_label")):
        lines.append(card["reason_label"])
    lines.append(card["sentence"])
    lines.extend("- %s: %s" % (f["label"], f["text"]) for f in card["facts"])
    lines.extend(card["banners"])
    if _truthy(card.get("typed")):
        lines.append(card["typed"]["prompt"])
    lines.append(" ".join("[%s]" % a["label"] for a in card["answers"]))
    return "\n".join(lines)


def partial_error(card: Dict[str, Any], p: Dict[str, Any]) -> Optional[str]:
    """Validate a "Partly..." answer against the card: a structured restriction of the shown ranges and values only."""
    slot = next((s for s in card["partial"] if s["path"] == p.get("path")), None)
    if slot is None:
        return "the card has no field %s" % _js_string(p.get("path", _UNDEF))

    if slot["kind"] == "num":
        def in_range(x: Any) -> bool:
            return is_number(x) and float(x).is_integer() and not (isinstance(x, float) and x == 0 and math.copysign(1.0, x) < 0) and x >= slot["lo"] and x <= slot["hi"]
        if "upTo" in p:
            return None if in_range(p["upTo"]) and p["upTo"] < slot["hi"] else "upTo must be an integer in [%d, %d]" % (slot["lo"], slot["hi"] - 1)
        if "from" in p:
            return None if in_range(p["from"]) and p["from"] > slot["lo"] else "from must be an integer in [%d, %d]" % (slot["lo"] + 1, slot["hi"])
        if "except" in p:
            return None if len(p["except"]) > 0 and all(in_range(x) for x in p["except"]) else "except values must be integers in [%d, %d]" % (slot["lo"], slot["hi"])
        return "a numeric partly answer needs upTo, from or except"
    if "notFor" not in p:
        return "a categorical partly answer needs notFor"
    vals = list(dict.fromkeys(p["notFor"]))
    if len(vals) == 0 or not all(v in slot["options"] for v in vals):
        return "notFor must name values shown on the card"
    if len(vals) == len(slot["options"]):
        return 'excluding every value is a "No"'
    return None


_TYPED_STRIP = re.compile("[" + _WS + ",$€£¥]")


def normalize_typed(inp: str, mode: str, unit: Any = None) -> Optional[str]:
    """Normalize what the human typed for comparison with the action value (digits for numbers, minor units for money)."""
    if mode == "last4":
        t = re.sub("[^A-Za-z0-9]", "", inp).upper()
        return t if len(t) == 4 else None
    t = re.sub("^[A-Za-z]{3}", "", _TYPED_STRIP.sub("", inp))
    m = re.fullmatch("(-?)([0-9]+)(?:\\.([0-9]+))?", t)
    if not m:
        return None
    e = _exponent(unit) if _is_money(unit) else 0
    frac = m.group(3) or ""
    if len(frac) > e:
        return None
    minor = int(m.group(2)) * 10 ** e + (int(frac.ljust(e, "0")) if frac else 0)
    return "%s%d" % ("-" if m.group(1) == "-" and minor != 0 else "", minor)


def expected_typed(card: Dict[str, Any], action: Dict[str, Any]) -> Optional[str]:
    """The normalized value the human must type for this card and action (what a site or auditor recomputes)."""
    if not _truthy(card.get("typed")):
        return None
    v = _vget(action["values"] if "values" in action else _UNDEF, card["typed"]["path"])
    if card["typed"]["mode"] == "last4":
        return last4(v) if isinstance(v, str) and len(last4(v)) == 4 else None
    return str(int(v)) if is_number(v) and is_safe_int(v) and not (isinstance(v, float) and v == 0 and math.copysign(1.0, v) < 0) else None


# ---- agent-initiated clarification (clarify.ts) -----------------------------------------------------------------------------------

def parse_clarify_request(body: Any) -> Dict[str, Any]:
    """Strict parse of a clarification body: {ok: True, request} or {ok: False, error}. Never raises."""
    if not is_obj(body):
        return {"ok": False, "error": "body must be an object"}
    for k in body:
        if k != "candidates" and k != "reason":
            return {"ok": False, "error": 'unknown member "%s" (clarifications carry no text)' % k}
    if not isinstance(body.get("reason"), str) or body["reason"] not in CLARIFY_REASONS:
        return {"ok": False, "error": "reason must be one of %s" % ", ".join(CLARIFY_REASONS)}
    cands = body.get("candidates")
    if not isinstance(cands, list) or len(cands) == 0 or len(cands) > MAX_CANDIDATES:
        return {"ok": False, "error": "candidates must be 1..%d structured actions" % MAX_CANDIDATES}
    out: List[Dict[str, Any]] = []
    for i, c in enumerate(cands):
        if not is_obj(c):
            return {"ok": False, "error": "candidates[%d] must be an object" % i}
        for k in c:
            if k != "verb" and k != "values":
                return {"ok": False, "error": 'candidates[%d] has an unknown member "%s"' % (i, k)}
        verb = c.get("verb")
        if not isinstance(verb, str) or u16len(verb) == 0 or u16len(verb) > 128:
            return {"ok": False, "error": "candidates[%d].verb must be a non-empty string" % i}
        if not is_obj(c.get("values")):
            return {"ok": False, "error": "candidates[%d].values must be an object" % i}
        entries = _entries(c["values"])
        if len(entries) > _MAX_VALUES:
            return {"ok": False, "error": "candidates[%d] has too many values" % i}
        values: Dict[str, Any] = {}
        for p, v in entries:
            if _PATH_RE.fullmatch(p) is None:
                return {"ok": False, "error": "candidates[%d] has a malformed path" % i}
            if not (p == "action.resource" or p.startswith("action.params.")):
                return {"ok": False, "error": "candidates[%d].values may only name action.params.* or action.resource" % i}
            if is_number(v):
                if not is_safe_int(v) or (isinstance(v, float) and v == 0 and math.copysign(1.0, v) < 0):
                    return {"ok": False, "error": "candidates[%d].values.%s must be a safe integer" % (i, p)}
            elif not isinstance(v, str) or u16len(v) > _MAX_STRING:
                return {"ok": False, "error": "candidates[%d].values.%s must be a string (≤ %d) or an integer" % (i, p, _MAX_STRING)}
            values[p] = v
        out.append({"verb": verb, "values": values})
    return {"ok": True, "request": {"candidates": out, "reason": body["reason"]}}


def information_gain(p: float, eta_pos: float, eta_neg: float) -> float:
    """Expected information gain of asking a cell with acceptance p under asymmetric noise (bits)."""
    py = p * (1 - eta_neg) + (1 - p) * eta_pos
    return bin_ent(py) - (p * bin_ent(eta_neg) + (1 - p) * bin_ent(eta_pos))


def plan_clarification(inp: Dict[str, Any]) -> Dict[str, Any]:
    """Dry-run verdicts for each candidate and the one cell worth asking, if any. `inp` carries omega, view (a dict of callables
    p, vetoed and outsideCeiling over (verb, idx)), candidates, an optional lift callable, asked (a set of `verb|i,j,..` keys),
    etaPos, etaNeg and an optional harm model."""
    omega = inp["omega"]
    view = inp["view"]
    lift = inp.get("lift")
    harm = inp.get("harm") or DEFAULT_HARM
    verdicts: List[Dict[str, Any]] = []
    best: Optional[Dict[str, Any]] = None
    seen = set()
    for index, cand in enumerate(inp["candidates"]):
        at = cell_of_action(omega, lift(cand) if lift else cand)
        if not at:
            verdicts.append({"index": index, "verdict": "outside"})
            continue
        vs, idx = at["vs"], at["idx"]
        if view["outsideCeiling"](vs["verb"], idx) or view["vetoed"](vs["verb"], idx):
            verdicts.append({"index": index, "verdict": "denied"})
            continue
        p = view["p"](vs["verb"], idx)
        if p <= 0:
            verdicts.append({"index": index, "verdict": "denied"})
            continue
        if p >= 1:
            verdicts.append({"index": index, "verdict": "admitted"})
            continue
        key = cell_key(vs["verb"], idx)
        if key in inp["asked"]:
            verdicts.append({"index": index, "verdict": "asked"})
            continue
        verdicts.append({"index": index, "verdict": "uncertain"})
        if key in seen:
            continue
        seen.add(key)
        ig = information_gain(p, inp["etaPos"], inp["etaNeg"])
        s = cell_stats(vs, idx, harm)
        c2 = {"index": index, "verb": vs["verb"], "idx": idx, "p": p, "ig": ig, "weight": s["mass"] * s["harm"], "flat": flat_index(vs, idx)}
        if (best is None or c2["ig"] > best["ig"] + 1e-12
                or (abs(c2["ig"] - best["ig"]) <= 1e-12 and (c2["weight"] > best["weight"] or (c2["weight"] == best["weight"] and c2["flat"] < best["flat"])))):
            best = c2
    ask = None if best is None else {"index": best["index"], "verb": best["verb"], "idx": best["idx"], "p": best["p"], "ig": best["ig"]}
    return {"verdicts": verdicts, "ask": ask}
