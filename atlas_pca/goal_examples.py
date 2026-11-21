"""Boundary examples and signed GoalTests over the Goal IR and its reference semantics (the TypeScript reference is
@atlasauth/pca-goal `examples`). An action is classified per coordinate (verb, resource, relation bits, each parameter) against the
literals of the policy; `cells` enumerates one representative per decision cell. A `Case` is `{act, rels}`: an action plus the
relation facts it is decided under. A `Space` is `{verbs, resources, rels, q, d}` with `q` param -> unit key -> sorted numbers
and `d` param -> sorted discrete literals."""
from ._fin import fin
import math
from functools import cmp_to_key
from typing import Any, Callable, Dict, List, Optional, Sequence

from .analyzer_js import UNDEF, includes, jget, js_str, req_list, strict_eq, truthy, u16key
from .goal_digests import goal_digest
from .goal_normalize import stable
from .goal_refsem import ref_explain
from .goal_sign import sign_payload, verify_payload
from .pca import hash_canonical

__all__ = [
    "EMPTY_HIST", "MAX_CELLS", "decision_of", "rank_of", "mk_act", "decide_case", "replay", "build_space", "cell_key", "cells",
    "allow_witness", "boundary_examples", "review_set", "expected_decision", "tests_digest", "make_goal_tests", "sign_goal_tests",
    "check_goal_tests", "sign_pin", "check_pin",
]

EMPTY_HIST = {"adms": [], "last": -1, "aggs": {}}
MAX_CELLS = 40_000
_OTHER = "\u0000other"


def decision_of(d: int) -> str:
    return "allow" if d == 2 else ("escalate" if d == 1 else "deny")


def rank_of(d: str) -> int:
    return 0 if d == "allow" else (1 if d == "escalate" else 2)


def mk_act(verb: str, res: str, params: Optional[dict] = None, over: Optional[dict] = None) -> Dict[str, Any]:
    """An action with the fixed envelope the examples use (one session, one principal, no delegation, time 0)."""
    a = {"verb": verb, "res": res, "params": {} if params is None else params, "t": 0, "sess": "s", "prin": "p", "org": "o", "agent": "a", "depth": 0}
    a.update(over or {})
    return a


def _fresh_hist() -> Dict[str, Any]:
    return {"adms": [], "last": -1, "aggs": {}}


def decide_case(g: Any, ont: Any, c: Any) -> Dict[str, Any]:
    """The reference decision of a goal for `{act, hist?, rels?}`: `{decision, witness, prohibited}`."""
    rels = jget(c, "rels")
    hist = jget(c, "hist")
    ont2 = dict(ont, rels=rels) if truthy(rels) else ont
    x = ref_explain(g, ont2, jget(c, "act"), _fresh_hist() if hist is None or hist is UNDEF else hist)
    return {"decision": decision_of(x["d"]), "witness": x["witness"], "prohibited": x["prohibit"] < 2}


def replay(g: Any, ont: Any, acts: Sequence[Any], rels: Any) -> Dict[str, Any]:
    """The history of the admitted prefix of `acts` (an action the goal refuses is not recorded)."""
    h = _fresh_hist()
    for act in req_list(acts):
        v = decide_case(g, ont, {"act": act, "hist": h, "rels": rels})
        if v["decision"] == "allow" and v["witness"] is not None:
            h["adms"].append({"gid": v["witness"], "act": act})
            h["last"] = jget(act, "t")
    return h


def _qkey(q: Any) -> str:
    u = jget(q, "u")
    return "money:" + js_str(jget(u, "ccy")) if jget(u, "k") == "money" else js_str(jget(u, "k"))


def _unit_of_key(key: str) -> Dict[str, Any]:
    return {"k": "money", "ccy": key[6:]} if key.startswith("money:") else {"k": key}


def _dkey(v: Any) -> Optional[str]:
    return "s:" + js_str(jget(v, "s")) if jget(v, "k") == "s" else None


def _walk_cond(c: Any, f: Callable[[str, Any], None]) -> None:
    k = jget(c, "k")
    if k == "cmp":
        l, r = jget(c, "l"), jget(c, "r")
        p = jget(l, "path") if jget(l, "k") == "param" else (jget(r, "path") if jget(r, "k") == "param" else None)
        other = r if jget(l, "k") == "param" else l
        if p is None or jget(other, "k") != "lit":
            return
        v = jget(other, "v")
        if jget(v, "k") == "set":
            for i in req_list(jget(v, "items")):
                f(p, i)
        else:
            f(p, v)
    elif k == "and" or k == "or":
        _walk_cond(jget(c, "a"), f)
        _walk_cond(jget(c, "b"), f)
    elif k == "not":
        _walk_cond(jget(c, "c"), f)


def _parts(s: Any) -> list:
    k = jget(s, "k")
    return req_list(jget(s, "parts")) if k == "all_of" else ([] if k == "any" else [s])


def _rel_cmp(a: dict, b: dict) -> int:
    x, y = u16key(a["rel"] + a["anchor"]), u16key(b["rel"] + b["anchor"])
    return -1 if x < y else 1


def build_space(goals: Sequence[Any], extra_verbs: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    verbs: Dict[str, None] = dict.fromkeys(extra_verbs or [])
    resources: Dict[str, None] = {}
    rels: Dict[str, Dict[str, str]] = {}
    q: Dict[str, Dict[str, set]] = {}
    d: Dict[str, set] = {}

    def lit(p: str, v: Any) -> None:
        if jget(v, "k") == "q":
            m = q.setdefault(p, {})
            m.setdefault(_qkey(jget(v, "q")), set()).add(jget(jget(v, "q"), "n"))
        else:
            k = _dkey(v)
            if k is not None:
                d.setdefault(p, set()).add(k)

    def res(s: Any) -> None:
        for x in _parts(s):
            k = jget(x, "k")
            if k == "exact":
                resources[jget(x, "id")] = None
            elif k == "oneof":
                for i in req_list(jget(x, "ids")):
                    resources[i] = None
            else:
                rels[jget(x, "rel") + "\0" + jget(x, "anchor")] = {"rel": jget(x, "rel"), "anchor": jget(x, "anchor")}

    for g in req_list(goals):
        for gr in req_list(jget(g, "grants")):
            verbs[jget(gr, "verb")] = None
            res(jget(gr, "res"))
            _walk_cond(jget(gr, "cond"), lit)
        for p in req_list(jget(g, "prohibits")):
            t = jget(p, "target")
            if jget(t, "k") == "verb":
                verbs[jget(t, "verb")] = None
            res(jget(p, "res"))
            _walk_cond(jget(p, "cond"), lit)
        for c in req_list(jget(g, "escalateOn")):
            _walk_cond(c, lit)
        for b in req_list(jget(g, "bounds")):
            v = jget(b, "value")
            if jget(b, "agg") == "sum" and jget(v, "k") == "param":
                lit(jget(v, "path"), {"k": "q", "q": jget(b, "cap")})  # reps around the cap so witnesses carry the summed param
    return {
        "verbs": sorted(verbs, key=u16key), "resources": sorted(resources, key=u16key), "rels": sorted(rels.values(), key=cmp_to_key(_rel_cmp)),
        "q": {p: {k: sorted(s) for k, s in m.items()} for p, m in q.items()},
        "d": {p: sorted(s, key=u16key) for p, s in d.items()},
    }


def _classify_lit(sp: dict, p: str, l: Any) -> str:
    if l is UNDEF:
        return "missing"
    if jget(l, "k") == "set":
        return "missing"
    groups, ds = sp["q"].get(p), sp["d"].get(p)
    if jget(l, "k") == "q":
        key = _qkey(jget(l, "q"))
        g = groups.get(key) if groups is not None else None
        if g is None:
            return "unit" if (groups is not None or ds is not None) else "any"
        v = jget(jget(l, "q"), "n")
        i = next((j for j, x in enumerate(g) if x == v), -1)
        if i >= 0:
            return "%s=%d" % (key, i)
        pos = 0
        while pos < len(g) and g[pos] < v:
            pos += 1
        return "%s@%d" % (key, pos)  # strictly between literal pos-1 and pos
    k = _dkey(l)
    if ds is None:
        return "unit" if groups is not None else "any"
    return k if k in ds else "other"


def _rel_bit(c: Any, rel: str, anchor: str) -> int:
    for x in req_list(jget(c, "rels")):
        if strict_eq(jget(x, "rel"), rel) and strict_eq(jget(x, "anchor"), anchor):
            return 1 if includes(jget(x, "members"), jget(jget(c, "act"), "res")) else 0
    return 0


def _params_of(sp: dict) -> List[str]:
    return sorted(dict.fromkeys(list(sp["q"]) + list(sp["d"])), key=u16key)


def cell_key(sp: dict, c: Any) -> str:
    """The decision cell of a case under a space (canonical string; the unit of precedents)."""
    act = jget(c, "act")
    params = jget(act, "params")
    return stable({
        "v": jget(act, "verb") if includes(sp["verbs"], jget(act, "verb")) else "*",
        "r": jget(act, "res") if includes(sp["resources"], jget(act, "res")) else "*",
        "l": [_rel_bit(c, x["rel"], x["anchor"]) for x in sp["rels"]],
        "p": {p: _classify_lit(sp, p, params.get(p, UNDEF) if isinstance(params, dict) else UNDEF) for p in _params_of(sp)},
    })


def _param_options(sp: dict, p: str) -> list:
    out: list = [None]  # None = the parameter is absent
    seen = set()

    def add(v: Any) -> None:
        k = stable(v)
        if k not in seen:
            seen.add(k)
            out.append(v)

    for key, vals in sp["q"].get(p, {}).items():
        is_instant = key == "instant"
        for v in vals:
            for x in (v - 1, v, v + 1):
                if x >= 0 or is_instant:
                    add({"k": "q", "q": {"u": _unit_of_key(key), "n": x}})
        if key.startswith("money:"):
            add({"k": "q", "q": {"u": {"k": "money", "ccy": "ZZZ"}, "n": 0}})  # unit mismatch -> Unknown
    for k in sp["d"].get(p, []):
        add({"k": "s", "s": k[2:]})
    if p in sp["d"]:
        add({"k": "s", "s": _OTHER})
    return out


def cells(sp: dict, opts: Optional[dict] = None) -> Dict[str, Any]:
    """One representative per decision cell. `complete` is False when the grid exceeded MAX_CELLS (then it is a subset)."""
    opts = opts or {}
    vs = opts.get("verbs")
    verbs = vs if vs is not None else list(sp["verbs"]) + ["\u0000other-verb"]
    resources = list(sp["resources"]) + ["\u0000other-resource"]
    params = _params_of(sp)
    p_opts = [_param_options(sp, p) for p in params]
    rel_bits = len(sp["rels"])
    total = len(verbs) * len(resources) * 2 ** rel_bits
    for o in p_opts:
        total *= len(o)
    complete = total <= MAX_CELLS
    out: List[dict] = []
    seen = set()

    def push(c: dict) -> None:
        k = cell_key(sp, c)
        if k not in seen:
            seen.add(k)
            out.append(c)

    def build(verb: str, resource: str, bits: int, choice: list) -> dict:
        pr = {p: choice[i] for i, p in enumerate(params) if choice[i] is not None}
        return {"act": mk_act(verb, resource, pr),
                "rels": [{"rel": x["rel"], "anchor": x["anchor"], "members": [resource] if bits & (1 << i) else []} for i, x in enumerate(sp["rels"])]}

    if complete:
        for verb in verbs:
            for res in resources:
                for bits in range(2 ** rel_bits):
                    idx = [0] * len(params)
                    while True:
                        push(build(verb, res, bits, [p_opts[i][j] for i, j in enumerate(idx)]))
                        k = 0
                        while k < len(idx):
                            idx[k] += 1
                            if idx[k] != len(p_opts[k]):
                                break
                            idx[k] = 0
                            k += 1
                        if k == len(idx):
                            break
    else:
        def base_choice() -> list:
            return [o[min(2, len(o) - 1)] for o in p_opts]

        for verb in verbs:
            push(build(verb, resources[0], 0, base_choice()))
            for res in resources:
                for bits in range(2 ** rel_bits):
                    push(build(verb, res, bits, base_choice()))
            for i, o in enumerate(p_opts):
                for l in o:
                    ch = base_choice()
                    ch[i] = l
                    push(build(verb, resources[0], 0, ch))
    return {"cases": out, "complete": complete}


def _magnitude(a: Any) -> float:
    s: float = 0
    for v in jget(a, "params").values():
        s += abs(jget(jget(v, "q"), "n")) if jget(v, "k") == "q" else 0
    return s


def allow_witness(g: Any, gr: Any, ont: Any) -> Optional[Dict[str, Any]]:
    """The smallest-magnitude case the grant admits (a minimal Allow witness), or None if its Allow set is empty."""
    sp = build_space([g])
    best = None
    for c in cells(sp, {"verbs": [jget(gr, "verb")]})["cases"]:
        v = decide_case(g, ont, c)
        if v["decision"] == "allow" and v["witness"] == jget(gr, "gid") and (best is None or _magnitude(c["act"]) < _magnitude(best["act"])):
            best = c
    return best


def _fdiv_floor(a: Any, b: Any) -> Any:
    """Math.floor(a / b) with JavaScript division (x / 0 is +-Infinity, 0 / 0 is NaN)."""
    if b == 0:
        return math.nan if a == 0 else (math.inf if a > 0 else -math.inf)
    return math.floor(a / b)


def boundary_examples(g: Any, opts: dict) -> Dict[str, Any]:
    """The full example set: decision-cell representatives, cap sequences and unmentioned-dimension probes."""
    ont = opts["ont"]
    goals = [g] + list(opts.get("extra") or [])
    sp = build_space(goals, opts.get("verbs") or [])
    c = cells(sp)
    out: List[dict] = []

    def add(kind: str, why: str, cs: dict, hist: Optional[dict] = None) -> None:
        h = _fresh_hist() if hist is None else hist
        out.append({"id": "%s:%s" % (kind, hash_canonical({"act": cs["act"], "hist": h, "rels": cs["rels"]})[:12]), "kind": kind, "why": why,
                    "act": cs["act"], "hist": h, "rels": cs["rels"], "decision": decide_case(g, ont, {"act": cs["act"], "hist": h, "rels": cs["rels"]})["decision"]})

    for cs in c["cases"]:
        v = decide_case(g, ont, cs)
        add("prohibit_trigger" if v["prohibited"] and v["decision"] == "deny" else ("member" if v["decision"] == "allow" else "boundary"), "cell " + v["decision"], cs)
    for gr in req_list(jget(g, "grants")):
        w = allow_witness(g, gr, ont)
        if w:
            add("allow_witness", "minimal Allow witness of grant " + js_str(jget(gr, "gid")), w)
    for b in req_list(jget(g, "bounds")):
        sel = jget(b, "sel")
        gids = jget(sel, "gids") if jget(sel, "k") == "gids" else []
        gr = next((x for x in req_list(jget(g, "grants")) if includes(gids, jget(x, "gid"))), None)
        w = allow_witness(g, gr, ont) if gr is not None else None
        if not w:
            continue
        cap_n = jget(jget(b, "cap"), "n")
        if jget(b, "agg") == "count":
            per: Any = 1
        else:
            val = jget(b, "value")
            v = w["act"]["params"].get(jget(val, "path"), UNDEF) if jget(val, "k") == "param" else UNDEF
            per = jget(jget(v, "q"), "n") if v is not UNDEF and truthy(v) and jget(v, "k") == "q" else 0
        if jget(b, "agg") == "sum" and per <= 0:
            continue
        n = _fdiv_floor(cap_n, per)
        if n > 60:
            continue  # sequence too long to review; the aggregate theorem (not examples) covers it
        count = int(n) if isinstance(n, int) or (isinstance(n, float) and fin(n)) else 0
        add("cap_sequence", "reach the %s cap with %s action(s), then one more" % (js_str(jget(b, "bid")), js_str(n)), w,
            replay(g, ont, [w["act"]] * max(count, 0), w["rels"]))
    for gr in req_list(jget(g, "grants")):  # unmentioned-dimension probes: extreme amount, other resource, other relation anchor
        w = allow_witness(g, gr, ont)
        if not w:
            continue
        for p, l in w["act"]["params"].items():
            if jget(l, "k") == "q" and jget(jget(jget(l, "q"), "u"), "k") == "money":
                act = dict(w["act"], params=dict(w["act"]["params"], **{p: {"k": "q", "q": dict(l["q"], n=1_000_000_000)}}))
                add("probe", "extreme " + p, dict(w, act=act))
        nothing = [dict(r, members=[]) for r in w["rels"]]
        add("probe", "other resource", {"act": dict(w["act"], res="\u0000other-resource"), "rels": nothing})
        add("probe", "other customer/anchor", {"act": w["act"], "rels": nothing})
    seen = set()
    res: List[dict] = []
    for e in out:
        if e["id"] not in seen:
            seen.add(e["id"])
            res.append(e)
    return {"examples": res, "complete": c["complete"]}


_KIND_W = {"probe": 0, "cap_sequence": 1, "allow_witness": 2, "prohibit_trigger": 3, "member": 4, "boundary": 5}


def review_set(examples: Sequence[Any], cap: int) -> list:
    """Cap examples, riskiest-looking first (Allow of the unmentioned, then Allow, then boundary), stable."""
    def cmp(a: Any, b: Any) -> int:
        r = rank_of(a["decision"]) - rank_of(b["decision"]) or _KIND_W[a["kind"]] - _KIND_W[b["kind"]]
        if r:
            return r
        x, y = u16key(a["id"]), u16key(b["id"])
        return -1 if x < y else 1
    return sorted(examples, key=cmp_to_key(cmp))[:cap]


def expected_decision(a: str) -> str:
    return "allow" if a == "allow" else ("deny" if a == "deny" else "escalate")


def tests_digest(tests: Sequence[Any]) -> str:
    """Order-independent digest of a test list."""
    def cmp(a: Any, b: Any) -> int:
        x, y = u16key(a["id"]), u16key(b["id"])
        return -1 if x < y else (1 if x > y else 0)
    return hash_canonical({"d": "atlas-pca/goal-tests/v1", "tests": sorted(tests, key=cmp_to_key(cmp))})


def make_goal_tests(g: Any, confirmed: Sequence[Any]) -> Dict[str, Any]:
    tests = [{"id": c["example"]["id"], "act": c["example"]["act"], "hist": c["example"]["hist"], "rels": c["example"]["rels"], "answer": c["answer"]}
             for c in confirmed]
    return {"goal_digest": goal_digest(g), "ontology_digest": jget(g, "ontDigest"), "tests": tests, "tests_digest": tests_digest(tests)}


def sign_goal_tests(s: dict, secret: Any, alg: Optional[str] = None, pq: Any = None) -> dict:
    return sign_payload("goal-tests", s, secret, alg, pq)


def check_goal_tests(s: Any, pins: Sequence[Any], decide_fn: Callable[[dict], str]) -> Dict[str, Any]:
    """Recompile check: any recompile must reproduce every confirmed test or the policy is refused."""
    if not verify_payload(s, "goal-tests", pins):
        return {"ok": False, "reason": "signature", "failures": []}
    pl = s["payload"]
    if tests_digest(pl["tests"]) != pl["tests_digest"]:
        return {"ok": False, "reason": "tests_digest", "failures": []}
    failures = []
    for t in pl["tests"]:
        got = decide_fn(t)
        if got != expected_decision(t["answer"]):
            failures.append({"id": t["id"], "expected": expected_decision(t["answer"]), "got": got})
    return {"ok": False, "reason": "test_regression", "failures": failures} if failures else {"ok": True, "failures": failures}


def sign_pin(p: dict, secret: Any, alg: Optional[str] = None, pq: Any = None) -> dict:
    """The pin: the policy version cannot silently change under a signed test set."""
    return sign_payload("policy-pin", p, secret, alg, pq)


def check_pin(pin: Any, pins: Sequence[Any], cur: Any) -> Dict[str, Any]:
    if not verify_payload(pin, "policy-pin", pins):
        return {"ok": False, "reason": "signature"}
    p = pin["payload"]
    goal, tests = jget(cur, "goal"), jget(cur, "tests")
    if p["goal_digest"] != goal_digest(goal):
        return {"ok": False, "reason": "goal changed under the pin"}
    if p["policy_digest"] != jget(cur, "policy_digest"):
        return {"ok": False, "reason": "policy changed under the pin"}
    if p["tests_digest"] != jget(tests, "tests_digest") or p["tests_digest"] != tests_digest(jget(tests, "tests")):
        return {"ok": False, "reason": "tests changed under the pin"}
    if p["ontology_digest"] != jget(goal, "ontDigest"):
        return {"ok": False, "reason": "ontology changed under the pin"}
    return {"ok": True}
