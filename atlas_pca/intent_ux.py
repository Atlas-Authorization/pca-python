"""Question cards for human studies: a deterministic, structured form of a cell question, and the parser that turns card
input into the learner's answer. Native port of the TypeScript reference (@atlasauth/pca-intent)."""
from __future__ import annotations

from ._fin import fin
import math
import re
from typing import Any, Dict, List

from .intent_omega import _at, num_cells, rep_value
from .intent_render import label_of, render_question
from .intent_v2 import _UNDEF, _js_string
from .pca import hash_canonical

_FIELD_RE = re.compile(r"(action\.params\.[a-z_][a-z0-9_]*|action\.resource)")


def _fact_of(d: dict, i: int) -> dict:
    label = label_of(d["path"])
    if d["kind"] == "num":
        c = _at(num_cells(d), i)
        text = "exactly %s" % _js_string(c["lo"]) if c["lo"] == c["hi"] else \
            "any value from %s to %s (for example %s)" % (_js_string(c["lo"]), _js_string(c["hi"]), _js_string(rep_value(d, i)))
        return {"path": d["path"], "label": label, "text": text}
    v = _at(d["values"], i)
    text = '"%s"' % v["value"] if v["kind"] == "exact" else 'anything under "%s" not named elsewhere' % v["value"] if v["kind"] == "prefix" \
        else "any value not named anywhere in the grant or your request"
    return {"path": d["path"], "label": label, "text": text}


def question_card(omega: dict, q: dict, catalog: Any = None) -> dict:
    vs = next((v for v in omega["verbs"] if v["verb"] == q["verb"]), None)
    if vs is None:
        raise ValueError("questionCard: no verb %s" % q["verb"])
    facts = [_fact_of(d, q["cell"][k]) for k, d in enumerate(vs["dims"])]
    partial: List[dict] = []
    for k, d in enumerate(vs["dims"]):
        if d["kind"] == "num":
            c = _at(num_cells(d), q["cell"][k])
            partial.append({"path": d["path"], "kind": "num", "lo": c["lo"], "hi": c["hi"]})
        else:
            partial.append({"path": d["path"], "kind": "cat", "options": [v["value"] for v in d["values"] if v["kind"] == "exact"]})
    body = {"v": 1, "verb": q["verb"], "cell": list(q["cell"]), "sentence": render_question(vs, q["cell"], catalog), "facts": facts,
            "reversibility": vs["reversibility"], "answers": ["yes", "no", "partly"], "partial": partial}
    return {**body, "digest": hash_canonical({"d": "atlas-pca/intent-card/v1", "c": body})}


def _strings(x: Any) -> List[str]:
    """[...new Set(x.filter(nonempty string))]: x must be an array (the reference throws on anything else)."""
    if not isinstance(x, list):
        raise TypeError("input.notFor.filter is not a function")
    out: List[str] = []
    for v in x:
        if isinstance(v, str) and len(v) > 0 and v not in out:
            out.append(v)
    return out


def _is_int_not_neg0(x: Any) -> bool:
    if isinstance(x, bool):
        return False
    if isinstance(x, int):
        return True
    return isinstance(x, float) and fin(x) and x.is_integer() and not (x == 0 and math.copysign(1.0, x) < 0)


def _set_of(x: Any) -> List[Any]:
    """[...new Set(x)]: null/undefined give the empty set, a string its characters, an array its items; else a TypeError."""
    if x is None or x is _UNDEF:
        return []
    if isinstance(x, str):
        x = list(x)
    if not isinstance(x, list):
        raise TypeError("object is not iterable")
    out: List[Any] = []
    for v in x:
        if v not in out:
            out.append(v)
    return out


def parse_card_answer(card: dict, inp: dict) -> dict:
    if inp.get("answer", _UNDEF) != "partly":
        return {"ok": True, "answer": 1 if inp.get("answer", _UNDEF) == "yes" else 0}
    if "newField" in inp:
        nf = inp["newField"]
        if not (isinstance(nf, str) and _FIELD_RE.fullmatch(nf)):
            return {"ok": False, "error": "unknown field %s" % _js_string(nf)}
        if any(s["path"] == nf for s in card["partial"]):
            return {"ok": False, "error": "%s is already on the card; answer partly for it directly" % nf}
        vals = _strings(inp.get("notFor", _UNDEF))
        if len(vals) == 0:
            return {"ok": False, "error": "name at least one value"}
        return {"ok": True, "answer": {"kind": "partial", "path": nf,
                                       "newDim": {"kind": "cat", "path": nf, "values": [{"kind": "exact", "value": v} for v in vals] + [{"kind": "other", "value": "⊥"}]},
                                       "parts": [{"values": vals, "y": 0}, {"other": True, "y": 1}]}}
    path = inp.get("path", _UNDEF)
    slot = next((s for s in card["partial"] if s["path"] == path), None)
    if slot is None:
        return {"ok": False, "error": "the card has no field %s" % _js_string(path)}
    if slot["kind"] == "num":
        lo, hi = slot["lo"], slot["hi"]

        def in_range(x: Any) -> bool:
            return _is_int_not_neg0(x) and x >= lo and x <= hi
        if "upTo" in inp:
            x = inp["upTo"]
            if not in_range(x) or x == hi:
                return {"ok": False, "error": "upTo must be an integer in [%s, %s]" % (_js_string(lo), _js_string(hi - 1))}
            return {"ok": True, "answer": {"kind": "partial", "path": slot["path"], "cuts": [x],
                                           "parts": [{"lo": lo, "hi": x, "y": 1}, {"lo": x + 1, "hi": hi, "y": 0}]}}
        if "from" in inp:
            x = inp["from"]
            if not in_range(x) or x == lo:
                return {"ok": False, "error": "from must be an integer in [%s, %s]" % (_js_string(lo + 1), _js_string(hi))}
            return {"ok": True, "answer": {"kind": "partial", "path": slot["path"], "cuts": [x],
                                           "parts": [{"lo": lo, "hi": x - 1, "y": 0}, {"lo": x, "hi": hi, "y": 1}]}}
        if "except" in inp:
            ex = _set_of(inp["except"])
            if all(_is_int_not_neg0(v) for v in ex):
                ex = sorted(ex)
            if len(ex) == 0 or not all(in_range(v) for v in ex):
                return {"ok": False, "error": "except values must be integers in [%s, %s]" % (_js_string(lo), _js_string(hi))}
            return {"ok": True, "answer": {"kind": "partial", "path": slot["path"], "cuts": ex,
                                           "parts": [{"lo": x, "hi": x, "y": 0} for x in ex] + [{"lo": lo, "hi": hi, "y": 1}]}}
        return {"ok": False, "error": "a numeric partly answer needs upTo, from or except"}
    if "notFor" not in inp:
        return {"ok": False, "error": "a categorical partly answer needs notFor"}
    vals = _strings(inp["notFor"])
    if len(vals) == 0:
        return {"ok": False, "error": "name at least one value"}
    return {"ok": True, "answer": {"kind": "partial", "path": slot["path"], "values": vals, "parts": [{"values": vals, "y": 0}, {"other": True, "y": 1}]}}
