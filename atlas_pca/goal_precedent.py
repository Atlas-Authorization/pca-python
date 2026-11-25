"""Progressive authorization (the TypeScript reference is @atlasauth/pca-goal `precedent`). Widening is only by an escalation request
answered by a principal-signed escalation answer. A verified answer becomes an append-only hash-chained precedent bound to (policy
digest, decision cell, the answered action's exact quantities as a ceiling). A recorded cell decision is never flipped except by a
principal-signed revocation. P1 the allow set grows only by cells with a valid principal signature bound to the policy digest; P2 no
replay of an answer onto another policy digest, cell or beyond the signed ceiling; P3 a Deny is never turned into Allow (precedents
act only on Escalate); P4 Escalate never becomes Allow implicitly. NOT covered by any signature: the relation facts (`rels`) and the
log itself (the integrity of the head is the verifier's to anchor)."""
from typing import Any, Dict, List, Optional, Sequence

from .analyzer_js import UNDEF, jget, js_json, js_str, req_list
from .escalation import (ESCALATION_ANSWER_DOMAIN, escalation_action_digest, escalation_answer_shape_error, escalation_history_head,
                         escalation_policy_digest, verify_escalation_answer)
from .goal_examples import build_space, cell_key, decide_case, mk_act
from .goal_sign import sign_payload, verify_payload
from .intent_wb import verify_artifact_sig
from .pca import hash_canonical, params_digest

__all__ = ["ceilings_of", "sign_revocation", "answer_body_for", "PrecedentLog", "authorize_with_precedents"]

GENESIS = "0" * 64


def _unit_key(q: Any) -> str:
    u = jget(q, "u")
    return "money:%s" % js_str(jget(u, "ccy")) if jget(u, "k") == "money" else js_str(jget(u, "k"))


def ceilings_of(params: Any) -> Dict[str, Any]:
    """Ceilings are keyed by parameter AND unit (kind + currency): a EUR answer never covers a GBP action."""
    out: Dict[str, Any] = {}
    for k, v in params.items():
        if jget(v, "k") == "q":
            out["%s|%s" % (k, _unit_key(jget(v, "q")))] = jget(jget(v, "q"), "n")
    return out


def _case_of(a: Any) -> Dict[str, Any]:
    act = jget(jget(a, "pcactn"), "action")
    return {"act": mk_act(jget(act, "verb"), jget(act, "resource"), jget(a, "params")), "rels": jget(a, "rels")}


def sign_revocation(p: dict, secret: Any) -> dict:
    return sign_payload("precedent-revocation", p, secret)


def answer_body_for(req: Any, o: Any) -> Dict[str, Any]:
    """The answer body for a request: bind it to the request's exact (policy, action, history head); sign it as an escalation answer."""
    return {"v": 1, "kind": "pca-escalation-answer", "principal": jget(o, "principal"), "policy_digest": jget(req, "policy_digest"),
            "action_digest": jget(req, "action_digest"), "history_head": jget(req, "history_head"), "decision": jget(o, "decision"),
            "iat": jget(o, "iat"), "expires_at": jget(o, "expires_at"), "nonce": jget(o, "nonce")}


def _nz(x: Any) -> Any:
    return None if x is None or x is UNDEF else x


def _entry_digest(e: Any) -> str:
    answered = _nz(e.get("answered"))
    return hash_canonical({
        "d": "atlas-pca/goal-precedent-entry/v1", "seq": e.get("seq"), "prev": e.get("prev"), "kind": e.get("kind"), "answer": _nz(e.get("answer")),
        "answered": dict(answered, lastCounter=_nz(answered.get("lastCounter"))) if answered else None, "cell": _nz(e.get("cell")),
        "ceilings": _nz(e.get("ceilings")), "revocation": _nz(e.get("revocation"))})


def _jstr(x: Any) -> Any:
    return UNDEF if x is UNDEF else js_json(x)


class PrecedentLog:
    def __init__(self, principals: Sequence[Any]):
        """`principals`: the pinned signers allowed to answer and revoke (the verifier's own list)."""
        self.entries: List[Dict[str, Any]] = []
        self._principals = principals

    def head(self) -> str:
        return self.entries[-1]["digest"] if self.entries else GENESIS

    def _pin_for(self, pk: Any) -> Any:
        for p in self._principals:
            if (p if isinstance(p, str) else jget(p, "pk")) == pk:
                return p
        return None

    def _answer_fault(self, answer: Any, answered: Any) -> Optional[str]:
        """Everything about an answer that does not depend on the clock: shape, pinned signature, bindings, params digest."""
        if escalation_answer_shape_error(answer) is not None:
            return "malformed answer"
        pin = self._pin_for(answer["principal"])
        if pin is None or not verify_artifact_sig(ESCALATION_ANSWER_DOMAIN, answer, pin):
            return "bad signature"
        pcactn = answered["pcactn"]
        if answer["action_digest"] != escalation_action_digest(pcactn):
            return "answer is bound to another action"
        if answer["history_head"] != escalation_history_head(_nz(answered.get("lastCounter"))):
            return "answer is bound to another history state"
        if params_digest(answered["params"]) != pcactn["action"]["params_digest"]:
            return "params do not match the signed action"
        return None

    def verify_chain(self, space: Any) -> bool:
        """Recompute the whole chain (append-only integrity), every signature and binding, and every derived cell and ceiling."""
        try:
            prev = GENESIS
            for i, e in enumerate(self.entries):
                if e.get("seq") != i or e.get("prev") != prev or _entry_digest(e) != e.get("digest"):
                    return False
                if e.get("kind") == "answer":
                    if not e.get("answer") or not e.get("answered") or self._answer_fault(e["answer"], e["answered"]) is not None:
                        return False
                    if e.get("cell") != cell_key(space, _case_of(e["answered"])) or _jstr(e.get("ceilings", UNDEF)) != _jstr(ceilings_of(e["answered"]["params"])):
                        return False
                elif not (e.get("revocation") and verify_payload(e["revocation"], "precedent-revocation", self._principals)):
                    return False
                prev = e["digest"]
            return True
        except Exception:  # noqa: BLE001 - total
            return False

    def _live(self, policy: Any, cell: Any, now: Any) -> Optional[Dict[str, Any]]:
        revoked = [e["revocation"]["payload"]["target_entry"] for e in self.entries if e.get("kind") == "revocation"]
        for e in reversed(self.entries):
            if e.get("kind") == "answer" and e["answer"]["policy_digest"] == policy and e.get("cell") == cell and e["answer"]["expires_at"] > now and e["digest"] not in revoked:
                return e
        return None

    def append(self, answer: Any, answered: Any, grant: Any, space: Any, now: Any) -> Dict[str, Any]:
        """Verify the answer (pinned signer, bound to this grant's policy digest and this exact action and history, unexpired) and record it."""
        v = verify_escalation_answer(answer, self._principals, {
            "policy_digest": escalation_policy_digest(grant), "action_digest": escalation_action_digest(answered["pcactn"]),
            "history_head": escalation_history_head(_nz(answered.get("lastCounter")))}, now)
        if not v["ok"]:
            return {"ok": False, "reason": v["reason"]}
        fault = self._answer_fault(answer, answered)
        if fault:
            return {"ok": False, "reason": fault}
        cell = cell_key(space, _case_of(answered))
        existing = self._live(answer["policy_digest"], cell, now)
        if existing is not None and existing["answer"]["decision"] != answer["decision"]:
            return {"ok": False, "reason": "conflicts with a recorded decision; revoke it first"}
        return {"ok": True, "entry": self._push({"kind": "answer", "answer": answer, "answered": answered, "cell": cell, "ceilings": ceilings_of(answered["params"])})}

    def revoke(self, rev: Any) -> Dict[str, Any]:
        if not verify_payload(rev, "precedent-revocation", self._principals):
            return {"ok": False, "reason": "bad signature"}
        p = rev["payload"]
        if not any(e.get("kind") == "answer" and e["digest"] == p["target_entry"] and e["answer"]["policy_digest"] == p["policy_digest"] and e.get("cell") == p["cell"]
                   for e in self.entries):
            return {"ok": False, "reason": "no such precedent"}
        return {"ok": True, "entry": self._push({"kind": "revocation", "revocation": rev})}

    def _push(self, e: Dict[str, Any]) -> Dict[str, Any]:
        base = dict({"seq": len(self.entries), "prev": self.head()}, **{k: v for k, v in e.items() if v is not UNDEF})
        entry = dict(base, digest=_entry_digest(base))
        self.entries.append(entry)
        return entry

    def lookup(self, policy_digest: Any, space: Any, c: Any, now: Any) -> Optional[Dict[str, Any]]:
        """The recorded decision covering this case under this policy, if any (cell match, ceilings respected, unexpired, unrevoked)."""
        e = self._live(policy_digest, cell_key(space, c), now)
        if e is None:
            return None
        ceil = e["ceilings"]
        now2 = ceilings_of(jget(jget(c, "act"), "params"))
        for k, v in now2.items():
            if v > (ceil[k] if k in ceil else float("-inf")):
                return None  # beyond the signed ceiling
        for k in ceil:
            if k not in now2:
                return None  # same parameters and units as the signed witness
        return {"decision": e["answer"]["decision"], "entry": e}


def authorize_with_precedents(goal: Any, ont: Any, policy_digest: str, log: PrecedentLog, c: Any, now: Any) -> Dict[str, Any]:
    """Policy decision refined by precedents. Precedents act only on Escalate (P3, P4); a tampered log fails closed."""
    base = decide_case(goal, ont, c)["decision"]
    if base != "escalate":
        return {"decision": base, "via": "policy"}
    space = build_space([goal])
    if not log.verify_chain(space):
        return {"decision": "escalate", "via": "policy"}
    hit = log.lookup(policy_digest, space, c, now)
    if hit is None:
        return {"decision": "escalate", "via": "policy"}
    return {"decision": "allow" if hit["decision"] == "allow" else "deny", "via": "precedent", "precedent": hit["entry"]}
