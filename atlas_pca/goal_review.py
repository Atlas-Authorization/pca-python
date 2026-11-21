"""Principal review and signing for a Goal IR (the TypeScript reference is @atlasauth/pca-goal `review`).

PolicyCard: a deterministic, template-only rendering of the WHOLE Goal from the same phrase table as the plain text card, with exact
numbers. Lossless-or-refuse: a clause that cannot be rendered and digested makes the card fail; the card is never truncated. The
reviewer-fatigue limits (REVIEW_LIMITS) are hard caps that REFUSE a goal or diff that is too large to read; callers may only tighten
them. Semantic diff: clause-level, widenings first; anything not PROVEN narrower counts as a widening. GoalApproval: a pinned reviewer
signs the digests of goal, compiled policy, card, ontology, tests, instruction and model set; `load_approved_goal` trusts nothing the
submission claims about itself (recomputes every digest, recompiles, re-renders, re-runs the confirmed examples) and never raises.

The compiler is injected as a `ReviewKernel` (the proved compiler is not native): `compile(goal, ont)`, `policy_digest(policy)`, and
optionally `analyze(policy)`, `decide(goal, ont, act, hist)` and `newly_allowed(prev, next, ont, limit)`."""
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

from ._fin import fin
from .analyzer_js import UNDEF, includes, jget, js_str, req_list, strict_eq, truthy
from .goal_card import bound_line, cond as cond_text, delegation_line, escalate_line, grant_line, hole_line, prohibit_line, quantity as quantity_text, res as res_text, validity_line
from .goal_codec import _safe_int
from .goal_digests import goal_digest, model_set_digest, nl_digest
from .goal_examples import expected_decision, tests_digest
from .goal_sign import sign_goal_artifact, signer_id, verify_goal_artifact
from .pca import canonical_bytes, canonicalize, hash_canonical, intent_goal_v3

__all__ = [
    "ReviewKernel", "REVIEW_LIMITS", "effective_limits", "ReviewError", "GOAL_APPROVAL_KIND", "MAX_GOAL_APPROVAL_TTL_MS", "render_policy_card",
    "card_digest", "card_to_text", "diff_goals", "diff_to_text", "GOAL_APPROVAL_SIGNED_FIELDS", "approve_goal", "load_approved_goal",
]


class ReviewKernel:
    """The compiler and decision entry points this flow needs (injected). Pure and total."""

    def __init__(self, compile: Callable[[Any, Any], Dict[str, Any]], policy_digest: Callable[[Any], str], analyze: Optional[Callable[[Any], List[str]]] = None,
                 decide: Optional[Callable[[Any, Any, Any, Any], str]] = None, newly_allowed: Optional[Callable[[Any, Any, Any, int], Dict[str, Any]]] = None):
        self.compile, self.policy_digest, self.analyze, self.decide, self.newly_allowed = compile, policy_digest, analyze, decide, newly_allowed


REVIEW_LIMITS = {"max_grants": 32, "max_prohibits": 64, "max_bounds": 32, "max_escalate_on": 32, "max_examples": 40, "max_card_lines": 200,
                 "max_card_bytes": 24_576, "max_diff_changes": 60, "max_diff_widenings": 12, "max_witnesses": 20}


def effective_limits(o: Optional[dict] = None) -> Dict[str, int]:
    """Caller overrides may only TIGHTEN a limit (a larger number is ignored)."""
    out = dict(REVIEW_LIMITS)
    if o:
        for k in list(out):
            v = o.get(k) if isinstance(o, dict) else None
            if _safe_int(v) and v >= 0 and v < out[k]:
                out[k] = int(v)
    return out


class ReviewError(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__("goal review: %s: %s" % (code, detail))
        self.code = code


_D_CARD = "atlas-pca/policy-card/v1"
_D_CLAUSE = "atlas-pca/goal-clause/v1"
GOAL_APPROVAL_KIND = "goal-approval"
MAX_GOAL_APPROVAL_TTL_MS = 24 * 3_600_000
_DEFAULT_TTL_MS = 3_600_000


def _json_of(v: Any) -> str:
    try:
        return canonicalize(v)
    except Exception:  # noqa: BLE001
        raise ReviewError("unrenderable", "a clause has no canonical form (float, undefined or cycle)")


def _is_obj(v: Any) -> bool:
    return isinstance(v, dict)


def _line(id: Any, kind: str, text: str, clause: Any, severity: str = "info") -> Dict[str, Any]:
    return {"id": id, "kind": kind, "severity": severity, "text": text, "clause_digest": hash_canonical({"d": _D_CLAUSE, "kind": kind, "clause": clause})}


def _safe_text(f: Callable[[], str], clause: Any) -> str:
    """Clause text through the shared phrase table; an unknown clause shape is shown as its canonical JSON, never dropped."""
    try:
        t = f()
        if "undefined" in t:
            raise ValueError("unknown clause shape")
        return t
    except Exception:  # noqa: BLE001
        return _json_of(clause)


def _go(goal: Any) -> str:
    try:
        return goal_digest(goal)
    except Exception:  # noqa: BLE001
        raise ReviewError("unrenderable", "the Goal has no canonical form (float, undefined or cycle)")


def render_policy_card(goal: Any, tests: Optional[Sequence[Any]] = None, opts: Optional[dict] = None) -> Dict[str, Any]:
    """Render the card. Deterministic, no model, no locale. Raises ReviewError: `holes` (a draft is not reviewable for signing),
    `wildcard_unacknowledged`, `card_too_large` (a fatigue cap), `unrenderable`. `opts.allowHoles` renders a DRAFT for display."""
    tests = [] if tests is None else tests
    opts = opts or {}
    L = effective_limits(opts.get("limits"))

    def big(what: str, n: int, mx: int) -> None:
        if n > mx:
            raise ReviewError("card_too_large", "%d %s exceed the cap of %d: split the goal into smaller goals" % (n, what, mx))

    if not (_is_obj(goal) and all(isinstance(goal.get(k), list) for k in ("grants", "prohibits", "bounds", "escalateOn", "holes"))
            and _is_obj(goal.get("validity")) and _is_obj(goal.get("deleg"))):
        raise ReviewError("unrenderable", "not a Goal IR")
    big("grants", len(goal["grants"]), L["max_grants"])
    big("prohibitions", len(goal["prohibits"]), L["max_prohibits"])
    big("bounds", len(goal["bounds"]), L["max_bounds"])
    big("escalation triggers", len(goal["escalateOn"]), L["max_escalate_on"])
    big("boundary examples", len(tests), L["max_examples"])
    big("card lines", 4 + len(goal["grants"]) + len(goal["prohibits"]) + len(goal["bounds"]) + len(goal["escalateOn"]) + len(goal["holes"]) + len(tests), L["max_card_lines"])
    if len(goal["holes"]) > 0 and not opts.get("allowHoles"):
        raise ReviewError("holes", "%d unresolved question(s): a goal with holes is a draft and cannot be signed" % len(goal["holes"]))
    wa = goal.get("wildcardAck")
    ack = wa if isinstance(wa, list) else []
    lines: List[Dict[str, Any]] = []
    lines.append(_line("principal", "meta", "Acting for principal %s. Nothing outside this card is allowed (default deny)." % _json_of(goal.get("principal", UNDEF)), goal.get("principal", UNDEF)))
    for g in goal["grants"]:
        wild = jget(jget(g, "res"), "k") == "any" if jget(g, "res") is not None and jget(g, "res") is not UNDEF else False
        if wild and not includes(ack, jget(g, "gid")):
            raise ReviewError("wildcard_unacknowledged", "grant %s allows ANY resource without a wildcard acknowledgement" % _json_of(jget(g, "gid")))
        lines.append(_line(jget(g, "gid"), "grant", _safe_text(lambda g=g, wild=wild: "%s.%s" % (grant_line(g), " WILDCARD acknowledged by the principal." if wild else ""), g), g, "red" if wild else "info"))
    for p in goal["prohibits"]:
        pr = jget(p, "res")
        lines.append(_line(jget(p, "pid"), "prohibit", _safe_text(lambda p=p: "%s." % prohibit_line(p), p), p,
                           "red" if pr is not None and pr is not UNDEF and jget(pr, "k") == "any" else "info"))
    for b in goal["bounds"]:
        lines.append(_line(jget(b, "bid"), "bound", _safe_text(lambda b=b: "%s." % bound_line(b), b), b))
    lines.append(_line("validity", "validity", _safe_text(lambda: "%s." % validity_line(goal["validity"]), goal["validity"]), goal["validity"]))
    lines.append(_line("delegation", "delegation", _safe_text(lambda: "%s." % delegation_line(goal["deleg"]), goal["deleg"]), goal["deleg"],
                       "info" if truthy(goal["deleg"].get("narrowOnly", UNDEF)) else "red"))
    for i, c in enumerate(goal["escalateOn"]):
        lines.append(_line("escalate_on[%d]" % i, "escalate", _safe_text(lambda c=c: "%s." % escalate_line(c), c), c))
    for i, h in enumerate(goal["holes"]):
        lines.append(_line("hole[%d]" % i, "hole", _safe_text(lambda h=h: "%s. Everything depending on it is dropped." % hole_line(h), h), h, "red"))
    for t in tests:
        act = jget(t, "act")
        n = len(jget(jget(t, "hist"), "adms"))
        ans = jget(t, "answer")
        lines.append(_line("example:%s" % js_str(jget(t, "id")), "example",
                           "EXAMPLE you confirmed: %s on %s with %s%s must be %s." % (
                               _json_of(jget(act, "verb")), _json_of(jget(act, "res")), _json_of(jget(act, "params")),
                               " after %d earlier admitted action(s)" % n if n > 0 else "",
                               "ASKED about" if ans == "ask" else ("ALLOWED" if ans == "allow" else "DENIED")), t))
    big("card lines", len(lines), L["max_card_lines"])
    card = {"v": 1, "goal_digest": _go(goal), "ontology_digest": goal.get("ontDigest", UNDEF), "nl_digest": goal.get("nlDigest", UNDEF),
            "principal": goal.get("principal", UNDEF), "lines": lines}
    card = {k: v for k, v in card.items() if v is not UNDEF}
    big("bytes of card", len(canonical_bytes(card)), L["max_card_bytes"])
    return card


def card_digest(card: Any) -> str:
    return hash_canonical({"d": _D_CARD, "card": card})


def card_to_text(card: Any) -> str:
    """Plain-text form of a card for any console or terminal. Red lines are prefixed `!!`."""
    return "\n".join("%s%s" % ("!! " if l["severity"] == "red" else "   ", l["text"]) for l in card["lines"])


# ---- semantic diff ---------------------------------------------------------------------------------------------------------------

def _same(a: Any, b: Any) -> bool:
    return _json_of(a) == _json_of(b)


def _conjuncts(c: Any) -> list:
    k = jget(c, "k")
    return _conjuncts(jget(c, "a")) + _conjuncts(jget(c, "b")) if k == "and" else ([] if k == "true" else [c])


def _where_no_wider(old_w: Any, new_w: Any) -> bool:
    have = set(_json_of(c) for c in _conjuncts(new_w))
    return all(_json_of(c) in have for c in _conjuncts(old_w))


def _grant_dir(o: Any, n: Any) -> str:
    if _same(o, n):
        return "neutral"
    return "narrow" if strict_eq(jget(o, "verb"), jget(n, "verb")) and _same(jget(o, "res"), jget(n, "res")) and _where_no_wider(jget(o, "cond"), jget(n, "cond")) else "unknown"


def _prohibit_dir(o: Any, n: Any) -> str:
    if _same(o, n):
        return "neutral"
    # A prohibition that triggers on MORE (old.cond is a conjunction containing new.cond) is a narrowing of the allow set.
    return "narrow" if _same(jget(o, "target"), jget(n, "target")) and _same(jget(o, "res"), jget(n, "res")) and _where_no_wider(jget(n, "cond"), jget(o, "cond")) else "unknown"


def _bound_dir(o: Any, n: Any) -> str:
    if _same(o, n):
        return "neutral"
    rest = lambda b: dict(b, cap=None)  # noqa: E731
    if not _same(rest(o), rest(n)) or not _same(jget(jget(o, "cap"), "u"), jget(jget(n, "cap"), "u")):
        return "unknown"
    on, nn = jget(jget(o, "cap"), "n"), jget(jget(n, "cap"), "n")
    return "narrow" if nn < on else ("widen" if nn > on else "neutral")


def _idle(x: Any) -> float:
    return float("inf") if x == 0 else x


def _validity_dir(o: Any, n: Any) -> str:
    if _same(o, n):
        return "neutral"
    nb, na, ni = jget(n, "notBefore"), jget(n, "notAfter"), _idle(jget(n, "maxIdle"))
    ob, oa, oi = jget(o, "notBefore"), jget(o, "notAfter"), _idle(jget(o, "maxIdle"))
    nar = nb >= ob and na <= oa and ni <= oi
    wid = nb <= ob and na >= oa and ni >= oi
    return "narrow" if nar else ("widen" if wid else "unknown")


def _delegation_dir(o: Any, n: Any) -> str:
    if _same(o, n):
        return "neutral"
    touch_o, touch_n = list(req_list(jget(o, "mayTouch"))), list(req_list(jget(n, "mayTouch")))
    sub = all(includes(touch_o, x) for x in touch_n)
    sup = all(includes(touch_n, x) for x in touch_o)
    on, nn = truthy(jget(o, "narrowOnly")), truthy(jget(n, "narrowOnly"))
    nar = jget(n, "maxDepth") <= jget(o, "maxDepth") and sub and (nn or not on)
    wid = jget(n, "maxDepth") >= jget(o, "maxDepth") and sup and (on or not nn)
    return "narrow" if nar else ("widen" if wid else "unknown")


def _pairs(prev: list, nxt: list, kind: str, added: str, removed: str, changed: Callable[[Any, Any], str], text: Callable[[Any, Any], str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    pm: Dict[Any, Any] = {}
    for k, v in prev:
        pm[k] = v
    nm = set(k for k, _ in nxt)
    for id_, v in nxt:
        if id_ not in pm:
            out.append({"change": "added", "kind": kind, "id": id_, "direction": added, "text": "ADDED %s" % text(id_, v)})
        elif not _same(pm[id_], v):
            out.append({"change": "changed", "kind": kind, "id": id_, "direction": changed(pm[id_], v), "text": "CHANGED %s (was: %s)" % (text(id_, v), text(id_, pm[id_]))})
    for id_, v in prev:
        if id_ not in nm:
            out.append({"change": "removed", "kind": kind, "id": id_, "direction": removed, "text": "REMOVED %s" % text(id_, v)})
    return out


def diff_goals(prev: Any, nxt: Any, kernel: Optional[ReviewKernel] = None, opts: Optional[dict] = None) -> Dict[str, Any]:
    """Clause-level semantic diff between the goal a principal approved before and the one now proposed. Widenings first. Raises ReviewError
    `diff_too_large` / `too_many_widenings` past the fatigue caps: a diff a human cannot read is not offered as one."""
    opts = opts or {}
    L = effective_limits(opts.get("limits"))

    def gl(id_: Any, g: Any) -> str:
        return "grant %s: %s on %s when %s" % (_json_of(id_), _json_of(jget(g, "verb")), res_text(jget(g, "res")), cond_text(jget(g, "cond")))

    def pl(id_: Any, p: Any) -> str:
        t = jget(p, "target")
        tgt = _json_of(jget(t, "verb")) if jget(t, "k") == "verb" else "effect class %s" % _json_of(jget(t, "cls"))
        return "prohibition %s: %s on %s when %s" % (_json_of(id_), tgt, res_text(jget(p, "res")), cond_text(jget(p, "cond")))

    changes: List[Dict[str, Any]] = (
        _pairs([(jget(g, "gid"), g) for g in req_list(jget(prev, "grants"))], [(jget(g, "gid"), g) for g in req_list(jget(nxt, "grants"))], "grant", "widen", "narrow", _grant_dir, gl)
        + _pairs([(jget(p, "pid"), p) for p in req_list(jget(prev, "prohibits"))], [(jget(p, "pid"), p) for p in req_list(jget(nxt, "prohibits"))], "prohibit", "narrow", "widen", _prohibit_dir, pl)
        + _pairs([(jget(b, "bid"), b) for b in req_list(jget(prev, "bounds"))], [(jget(b, "bid"), b) for b in req_list(jget(nxt, "bounds"))], "bound", "narrow", "widen", _bound_dir,
                 lambda id_, b: "bound %s: %s (%s)" % (_json_of(id_), bound_line(b), quantity_text(jget(b, "cap"))))
        + _pairs([(_json_of(c), c) for c in req_list(jget(prev, "escalateOn"))], [(_json_of(c), c) for c in req_list(jget(nxt, "escalateOn"))], "escalate", "narrow", "widen",
                 lambda a, b: "unknown", lambda _id, c: "escalation when %s" % cond_text(c)))
    pv, nv = jget(prev, "validity"), jget(nxt, "validity")
    if not _same(pv, nv):
        changes.append({"change": "changed", "kind": "validity", "id": "validity", "direction": _validity_dir(pv, nv), "text": "CHANGED validity: %s (was: %s)" % (_json_of(nv), _json_of(pv))})
    pd, nd = jget(prev, "deleg"), jget(nxt, "deleg")
    if not _same(pd, nd):
        changes.append({"change": "changed", "kind": "delegation", "id": "delegation", "direction": _delegation_dir(pd, nd), "text": "CHANGED delegation: %s (was: %s)" % (_json_of(nd), _json_of(pd))})
    # Identity of the actor, the vocabulary and the wildcard acknowledgements are never "neutral": a swap can widen.
    if not strict_eq(jget(prev, "principal"), jget(nxt, "principal")):
        changes.append({"change": "changed", "kind": "meta", "id": "principal", "direction": "unknown", "text": "CHANGED principal: %s (was: %s)" % (_json_of(jget(nxt, "principal")), _json_of(jget(prev, "principal")))})
    if not strict_eq(jget(prev, "ontDigest"), jget(nxt, "ontDigest")):
        changes.append({"change": "changed", "kind": "meta", "id": "ontology", "direction": "unknown",
                        "text": "CHANGED ontology: every term now means what the new vocabulary says (was %s, now %s)" % (_json_of(jget(prev, "ontDigest")), _json_of(jget(nxt, "ontDigest")))})
    if not _same(jget(prev, "wildcardAck"), jget(nxt, "wildcardAck")):
        changes.append({"change": "changed", "kind": "meta", "id": "wildcard_ack", "direction": "unknown",
                        "text": "CHANGED wildcard acknowledgements: %s (was: %s)" % (_json_of(jget(nxt, "wildcardAck")), _json_of(jget(prev, "wildcardAck")))})
    if not strict_eq(jget(prev, "nlDigest"), jget(nxt, "nlDigest")):
        changes.append({"change": "changed", "kind": "meta", "id": "instruction", "direction": "neutral", "text": "CHANGED the instruction text the goal was interpreted from"})

    def is_wide(c: dict) -> bool:
        return c["direction"] == "widen" or c["direction"] == "unknown"
    widenings = len([c for c in changes if is_wide(c)])
    if len(changes) > L["max_diff_changes"]:
        raise ReviewError("diff_too_large", "%d changes exceed the cap of %d: review the new goal as a whole instead" % (len(changes), L["max_diff_changes"]))
    if widenings > L["max_diff_widenings"]:
        raise ReviewError("too_many_widenings", "%d widenings exceed the cap of %d per review" % (widenings, L["max_diff_widenings"]))
    na = None
    ont = opts.get("ontology")
    if ont and kernel is not None and kernel.newly_allowed is not None:
        na = kernel.newly_allowed(prev, nxt, ont, L["max_witnesses"])
    return {"v": 1, "from_goal_digest": _go(prev), "to_goal_digest": _go(nxt),
            "newly_allowed": list(na["witnesses"])[:L["max_witnesses"]] if na else [],
            "newly_allowed_complete": bool(na["complete"] and len(na["witnesses"]) <= L["max_witnesses"]) if na else False,
            "changes": [c for c in changes if is_wide(c)] + [c for c in changes if not is_wide(c)], "widenings": widenings}


def diff_to_text(d: Any) -> str:
    head = ["!! NEWLY ALLOWED: %s on %s with %s" % (_json_of(w["verb"]), _json_of(w["res"]), _json_of(w["params"])) for w in d["newly_allowed"]]
    if not d["newly_allowed_complete"]:
        head.append("!! The list of newly allowed actions is incomplete or unavailable: read every widening below.")
    return "\n".join(head + ["%s%s" % ("!! " if c["direction"] in ("widen", "unknown") else "   ", c["text"]) for c in d["changes"]])


# ---- GoalApproval -----------------------------------------------------------------------------------------------------------------

GOAL_APPROVAL_SIGNED_FIELDS = ["v", "goal_digest", "policy_digest", "card_digest", "ontology_digest", "tests_digest", "nl_digest", "model_set_digest", "reviewer",
                               "approved_at", "expires_at"]
_FIELD_REASON = [("goal_digest", "goal_digest_mismatch"), ("policy_digest", "policy_digest_mismatch"), ("ontology_digest", "ontology_mismatch"),
                 ("tests_digest", "tests_digest_mismatch"), ("nl_digest", "nl_digest_mismatch"), ("model_set_digest", "model_set_digest_mismatch"),
                 ("card_digest", "card_digest_mismatch")]


def _derive(sub: Any, kernel: ReviewKernel, limits: Optional[dict]) -> Dict[str, Any]:
    def bad(reason: str) -> Dict[str, Any]:
        return {"ok": False, "reason": reason}
    if (not _is_obj(sub) or not _is_obj(sub.get("goal")) or not _is_obj(sub.get("ontology")) or not isinstance(sub.get("instruction"), str)
            or not isinstance(sub.get("model_set"), list) or any(not isinstance(m, str) for m in sub["model_set"])
            or ("tests" in sub and not isinstance(sub["tests"], list))):
        return bad("malformed_submission")
    tests = sub.get("tests", [])
    try:
        card = render_policy_card(sub["goal"], tests, {} if limits is None else {"limits": limits})
    except ReviewError as e:
        return bad(e.code)
    except Exception:  # noqa: BLE001
        return bad("malformed_goal")
    try:
        gd = goal_digest(sub["goal"])
        nl = nl_digest(sub["instruction"])
        ts = tests_digest(tests)
        ms = model_set_digest(sub["model_set"])
    except Exception:  # noqa: BLE001
        return bad("malformed_goal")
    if not isinstance(sub["goal"].get("nlDigest"), str) or nl != sub["goal"]["nlDigest"]:
        return bad("instruction_mismatch")
    try:
        compiled = kernel.compile(sub["goal"], sub["ontology"])
    except Exception:  # noqa: BLE001
        return bad("compile_error")
    if not compiled["ok"]:
        return bad("compile_error")
    try:
        found = kernel.analyze(compiled["policy"]) if kernel.analyze is not None else []
        if len(found if found is not None else []) > 0:
            return bad("analyzer_error")
        pd = kernel.policy_digest(compiled["policy"])
    except Exception:  # noqa: BLE001
        return bad("analyzer_error")
    if len(tests) > 0:
        if kernel.decide is None:
            return bad("tests_unverifiable")
        # Regression pin: the principal's confirmed examples must be reproduced by the policy we just compiled.
        for t in tests:
            try:
                got = kernel.decide(sub["goal"], dict(sub["ontology"], rels=t["rels"]) if truthy(jget(t, "rels")) else sub["ontology"], t["act"], t["hist"])
            except Exception:  # noqa: BLE001
                return bad("tests_unverifiable")
            if got != expected_decision(t["answer"]):
                return bad("tests_contradicted")
    return {"ok": True, "policy": compiled["policy"], "digests": {
        "goal_digest": gd, "policy_digest": pd, "card_digest": card_digest(card), "ontology_digest": sub["goal"].get("ontDigest"),
        "tests_digest": ts, "nl_digest": nl, "model_set_digest": ms}}


def approve_goal(sub: Any, reviewer_secret: Any, opts: Optional[dict] = None) -> Dict[str, Any]:
    """The human step: sign the exact goal. Re-derives everything the loader will; raises when the goal is not signable (holes, wildcard
    without ack, card or diff over the fatigue caps, compile or analyzer failure, a test the compiled policy contradicts, an instruction
    that does not match `nlDigest`). `opts`: kernel (required), now, ttlMs, limits, base, alg, pq."""
    opts = opts or {}
    now = opts.get("now")
    now = int(time.time() * 1000) if now is None else now
    ttl = opts.get("ttlMs")
    ttl = _DEFAULT_TTL_MS if ttl is None else ttl
    if not _safe_int(now) or not _safe_int(ttl) or ttl <= 0 or ttl > MAX_GOAL_APPROVAL_TTL_MS:
        raise ValueError("approveGoal: invalid time or ttl")
    kernel = opts.get("kernel")
    if kernel is None:
        raise ValueError("approveGoal: a review kernel is required (the proved compiler is not native)")
    d = _derive(sub, kernel, opts.get("limits"))
    if not d["ok"]:
        raise ValueError("approveGoal: %s" % d["reason"])
    if opts.get("base") is not None:
        diff_goals(opts["base"], sub["goal"], None, {"limits": opts.get("limits")})
    body = dict(d["digests"], v=1, reviewer=signer_id(reviewer_secret), approved_at=int(now), expires_at=int(now) + int(ttl))
    return sign_goal_artifact(GOAL_APPROVAL_KIND, body, reviewer_secret, opts.get("alg"), opts.get("pq"))


def _fail(reason: str) -> Dict[str, Any]:
    return {"ok": False, "reason": reason}


def load_approved_goal(sub: Any, approval: Any, opts: dict) -> Dict[str, Any]:
    """The only door from a submitted goal to an enforceable one. Recomputes the goal digest, recompiles the policy, re-renders the card and
    re-derives the tests, instruction and model-set digests from the submission; trusts nothing the submission or the approval says about
    itself. Never raises. `opts`: kernel (required), reviewers (pinned), ontology_digest, now, limits."""
    try:
        now = opts.get("now")
        now = int(time.time() * 1000) if now is None else now
        reviewers = opts.get("reviewers")
        if not isinstance(reviewers, list) or len(reviewers) == 0:
            return _fail("no_reviewers_pinned")
        a = approval
        if (not _is_obj(a) or not (_safe_int(a.get("v")) and a.get("v") == 1) or not isinstance(a.get("sig"), str) or not isinstance(a.get("reviewer"), str)
                or not _safe_int(a.get("approved_at")) or not _safe_int(a.get("expires_at")) or any(not isinstance(a.get(f), str) for f, _ in _FIELD_REASON)):
            return _fail("malformed_approval")
        kernel = opts.get("kernel")
        if kernel is None:
            return _fail("malformed_approval")
        d = _derive(sub, kernel, opts.get("limits"))
        if not d["ok"]:
            return d
        od = opts.get("ontology_digest")
        if od is not None and not strict_eq(sub["goal"].get("ontDigest"), od):
            return _fail("ontology_mismatch")
        for f, reason in _FIELD_REASON:
            if a[f] != d["digests"][f]:
                return _fail(reason)
        if not any((p if isinstance(p, str) else jget(p, "pk")) == a["reviewer"] for p in reviewers):
            return _fail("reviewer_not_pinned")
        if a["expires_at"] - a["approved_at"] <= 0 or a["expires_at"] - a["approved_at"] > MAX_GOAL_APPROVAL_TTL_MS:
            return _fail("ttl_too_long")
        if not (fin(now) and a["approved_at"] <= now):
            return _fail("not_yet_valid")
        if not (fin(now) and now < a["expires_at"]):
            return _fail("expired")
        if not verify_goal_artifact(GOAL_APPROVAL_KIND, a, "reviewer", reviewers):
            return _fail("bad_signature")
        ref = {"goal_digest": d["digests"]["goal_digest"], "policy_digest": d["digests"]["policy_digest"]}
        return {"ok": True, "approved": {"goal": sub["goal"], "ontology": sub["ontology"], "policy": d["policy"], "ref": ref, "goal_string": intent_goal_v3(ref),
                                         "intent_policy": {"approved_goal": ref}, "instruction": sub["instruction"], "reviewer": a["reviewer"], "expires_at": a["expires_at"]}}
    except Exception:  # noqa: BLE001 - never raises
        return _fail("malformed_approval")
