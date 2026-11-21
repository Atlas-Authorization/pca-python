"""Round-trip checks (the TypeScript reference is @atlasauth/pca-goal `roundtrip`): the lossless card tape, semantic widening
mutations and the explainer + comparator detector, measured by mutation and tighten-only (it can only escalate). An explainer is an
object with `explain(prose_lines) -> str`; a comparator an object with `equivalent(goal_text, explanation) -> {equivalent, reason?}`."""
import copy
import re
from typing import Any, Dict, List, Optional, Sequence

from .analyzer_js import UNDEF, includes, jget, js_json, js_str, req_list, strict_eq, truthy
from .goal_card import render_card
from .goal_codec import decode_goal, encode_goal
from .goal_interpret import extract_candidates
from .goal_normalize import canonicalize_goal, stable

__all__ = ["card_round_trips", "round_trip", "deterministic_explainer", "lexical_comparator", "MUTATION_KINDS", "mutate_goal", "measure_detection"]

MUTATION_KINDS = ["widen_cap", "widen_where", "drop_prohibit", "drop_bound", "swap_resource", "add_grant"]


def card_round_trips(g: Any) -> bool:
    """decode(encode(goal)) equals the goal: nothing the goal says is lost on the card tape."""
    return stable(decode_goal(encode_goal(g))) == stable(g)


def round_trip(goal: Any, goal_text: str, explainer: Any, comparator: Any) -> str:
    """The explainer sees ONLY the compiled card lines, never the goal text or the model's reasoning."""
    try:
        e = explainer.explain(render_card(goal)["lines"])
        return "ok" if truthy(comparator.equivalent(goal_text, e)["equivalent"]) else "escalate"
    except Exception:  # noqa: BLE001
        return "escalate"


class _Det:
    id = "card-prose"

    def explain(self, p: Sequence[str]) -> str:
        return "\n".join(p)


deterministic_explainer = _Det()
_MINOR = re.compile("(\\d+) ([A-Z]{3}) minor units", re.ASCII)


class _Lexical:
    id = "lexical"
    family = "rule"

    def __init__(self, o: Any):
        self.o = o

    def equivalent(self, text: str, explanation: str) -> Dict[str, Any]:
        a, b = extract_candidates(text, self.o), extract_candidates(explanation, self.o)
        b_amounts = [{"ccy": m.group(2), "minor": float(m.group(1))} for m in _MINOR.finditer(explanation)]  # Number(): huge values are doubles
        ids = lambda x: ",".join(sorted(dict.fromkeys(x), key=lambda s: s.encode("utf-16-be", "surrogatepass")))  # noqa: E731
        if ids(a["ids"]) != ids(b["ids"]):
            return {"equivalent": False, "reason": "ids differ"}
        # every amount stated in the policy must be one the principal wrote (the principal may write extras only as decoys)
        wrote = set("%s%s" % (m["ccy"], js_str(m["minor"])) for m in a["amounts"])
        for m in b_amounts:
            if "%s%s" % (m["ccy"], js_str(m["minor"])) not in wrote:
                return {"equivalent": False, "reason": "amount %s %s not stated by the principal" % (m["ccy"], js_str(m["minor"]))}
        if len(a["amounts"]) > 0 and len(b_amounts) == 0:
            return {"equivalent": False, "reason": "no amount in the policy"}
        return {"equivalent": True}


def lexical_comparator(o: Any) -> Any:
    """Offline reference comparator: the card lines judged lexically (ids, amounts)."""
    return _Lexical(o)


def _scale(x: Any, f: int) -> Any:
    k = jget(jget(x, "u"), "k")
    return dict(x, n=jget(x, "n") * f) if (k == "money" or k == "count") else x


def _map_lits(c: Any, f: Any) -> Any:
    k = jget(c, "k")
    if k == "cmp":
        r = jget(c, "r")
        hit = jget(r, "k") == "lit" and jget(jget(r, "v"), "k") == "q" and (jget(c, "op") == "lte" or jget(c, "op") == "lt")
        return dict(c, r={"k": "lit", "v": {"k": "q", "q": f(jget(jget(r, "v"), "q"))}} if hit else r)
    if k == "and" or k == "or":
        return dict(c, a=_map_lits(jget(c, "a"), f), b=_map_lits(jget(c, "b"), f))
    return c


def mutate_goal(g: Any, kind: str, ontology: Any) -> Optional[Dict[str, Any]]:
    """Semantic mutations that WIDEN the policy (or leave it equal); None when the goal has nothing to mutate."""
    x = copy.deepcopy(g)
    if kind == "widen_cap":
        if not x["bounds"]:
            return None
        x["bounds"][0]["cap"] = _scale(x["bounds"][0]["cap"], 10)
        return x
    if kind == "widen_where":
        gr = next((y for y in x["grants"] if js_json(_map_lits(y["cond"], lambda z: _scale(z, 10))) != js_json(y["cond"])), None)
        if gr is None:
            return None
        gr["cond"] = _map_lits(gr["cond"], lambda z: _scale(z, 10))
        return x
    if kind == "drop_prohibit":
        if len(x["prohibits"]) == 0:
            return None
        x["prohibits"].pop()
        return x
    if kind == "drop_bound":
        if len(x["bounds"]) == 0:
            return None
        x["bounds"].pop()
        return x
    if kind == "swap_resource":
        gr = next((y for y in x["grants"] if y["res"]["k"] == "exact"), None)
        if gr is None:
            return None
        gr["res"] = {"k": "exact", "id": gr["res"]["id"] + "9"}
        return x
    if kind == "add_grant":
        have = set(y["verb"] for y in x["grants"])
        v = next((y for y in req_list(jget(ontology, "verbs"))
                  if jget(y, "effect") != "read" and jget(y, "id") not in have
                  and not any(p["target"]["k"] == "verb" and p["target"]["verb"] == jget(y, "id") for p in x["prohibits"])), None)
        if v is None:
            return None
        x["grants"].append({"gid": "injected", "verb": jget(v, "id"), "res": {"k": "any", "reason": "injected"}, "cond": {"k": "true"}})
        x["wildcardAck"].append("injected")
        return canonicalize_goal(x)
    return None


def measure_detection(cases: Sequence[Any], ontology: Any, explainer: Any, comparator: Any) -> List[Dict[str, Any]]:
    """Fraction of semantic widenings the explainer + comparator pair flags (they can only escalate; this is a measured detector)."""
    out = []
    for kind in MUTATION_KINDS:
        applied = detected = 0
        for c in cases:
            m = mutate_goal(c["goal"], kind, ontology)
            if not m:
                continue
            applied += 1
            if round_trip(m, c["text"], explainer, comparator) == "escalate":
                detected += 1
        out.append({"kind": kind, "applied": applied, "detected": detected, "rate": detected / applied if applied else 0})
    return out
