"""Shadow policy rollout (port of the TypeScript reference, @atlasauth/pca-grants): run candidate policy bundles beside the enforced one,
record every divergence as a verifier-signed diff, and gate promotion on zero unexplained widenings. The enforced decision is computed
first and returned untouched, so a candidate that raises, returns junk or mutates its input cannot change the answer. Nothing here
decides an action; it is analysis and rollout tooling.

``decide`` hooks are plain callables returning ``"allow"``, ``"deny"`` or ``"escalate"``; ``GateOptions`` is a dict with the reference's
member names (``shadow_digest``, ``enforced_digest``, ``minSamples``, ``principals``, ``explanations``, ``surface``, ``approval``)."""
from __future__ import annotations

import copy
from typing import Any, Callable, Dict, List, Optional, Sequence

from .grants import _RANK, _gt, _rank, _without, sign_body, signer_of
from .k3 import bundle_digest, is_obj, is_one, is_str, is_uint, u16key, verify_body

SHADOW_DIFF_DOMAIN = "atlas-pca/shadow-diff/v1\0"
WIDENING_EXPLANATION_DOMAIN = "atlas-pca/shadow-widening-explanation/v1\0"
PROMOTION_APPROVAL_DOMAIN = "atlas-pca/shadow-promotion-approval/v1\0"


def _is_kind(x: Any) -> bool:
    return isinstance(x, str) and x in _RANK


def run_shadow(input_: Any, enforced: Callable[[Any], Any], candidates: Sequence[dict]) -> dict:
    """The enforced decision, plus what each candidate (``{digest, decide}``) would have said: ``{decision, shadow: [outcome]}``
    with outcome ``{digest, decision | "error", diverged, widening}``. The returned ``decision`` is the enforced one, always."""
    decision = enforced(input_)
    shadow = []
    for c in candidates:
        try:
            d = c["decide"](copy.deepcopy(input_))
            if not _is_kind(d):
                shadow.append({"digest": c["digest"], "decision": "error", "diverged": False, "widening": False})
            else:
                shadow.append({"digest": c["digest"], "decision": d, "diverged": d != decision, "widening": _gt(_rank(d), _rank(decision))})
        except Exception:  # noqa: BLE001 - a failing candidate is an error outcome, never an answer
            shadow.append({"digest": c["digest"], "decision": "error", "diverged": False, "widening": False})
    return {"decision": decision, "shadow": shadow}


def shadow_record_field(outcomes: Sequence[dict]) -> List[dict]:
    """The ``shadow`` member of a decision record, from the outcomes."""
    return [{"digest": o["digest"], "decision": o["decision"], "diverged": o["diverged"]} for o in outcomes]


_DIFF_KEYS = ("v", "shadow_digest", "enforced_digest", "action_digest", "enforced", "shadow", "widening", "at", "signer")


def _diff_body(d: dict) -> dict:
    return {k: d[k] for k in _DIFF_KEYS}


def verify_shadow_diff(d: Any, signer: Optional[str] = None) -> bool:
    """A well formed diff signed by its own ``signer`` (and by ``signer`` when given). Never raises."""
    try:
        if not is_obj(d) or not is_one(d.get("v")) or not (is_str(d.get("shadow_digest"), 128) and is_str(d.get("enforced_digest"), 128)
                                                           and is_str(d.get("action_digest"), 128)) \
                or not _is_kind(d.get("enforced")) or not _is_kind(d.get("shadow")) or not isinstance(d.get("widening"), bool) \
                or not is_uint(d.get("at")) or not is_str(d.get("signer"), 128):
            return False
        if d["enforced"] == d["shadow"] or d["widening"] != _gt(_rank(d["shadow"]), _rank(d["enforced"])):
            return False
        if signer is not None and d["signer"] != signer:
            return False
        return verify_body(SHADOW_DIFF_DOMAIN, _diff_body(d), d["signer"], d.get("sig"))
    except Exception:
        return False


def _zero_stats() -> Dict[str, int]:
    return {"total": 0, "diverged": 0, "widened": 0, "tightened": 0, "errors": 0}


class ShadowLog:
    """Collects the signed diffs and counters per candidate. In memory: persist ``diffs()`` to the decision log for the audit trail."""

    def __init__(self, secret: bytes) -> None:
        self._secret = secret
        self._stat: Dict[str, Dict[str, int]] = {}
        self._list: Dict[str, List[dict]] = {}

    @property
    def signer(self) -> str:
        return signer_of(self._secret)

    def observe(self, enforced_digest: str, action_digest: str, enforced: str, outcome: dict, at: Any) -> Optional[dict]:
        """Count one observation; sign and keep a diff when the candidate diverged."""
        s = self._stat.get(outcome["digest"]) or _zero_stats()
        self._stat[outcome["digest"]] = s
        s["total"] += 1
        if outcome["decision"] == "error":
            s["errors"] += 1
            return None
        if not outcome["diverged"]:
            return None
        s["diverged"] += 1
        s["widened" if outcome["widening"] else "tightened"] += 1
        base = {"v": 1, "shadow_digest": outcome["digest"], "enforced_digest": enforced_digest, "action_digest": action_digest,
                "enforced": enforced, "shadow": outcome["decision"], "widening": outcome["widening"], "at": at, "signer": self.signer}
        diff = {**base, "sig": sign_body(SHADOW_DIFF_DOMAIN, _diff_body(base), self._secret)}
        self._list.setdefault(outcome["digest"], []).append(diff)
        return diff

    def stats(self, digest: str) -> Dict[str, int]:
        return dict(self._stat.get(digest) or _zero_stats())

    def diffs(self, digest: str) -> List[dict]:
        return list(self._list.get(digest, []))


def _exp_body(e: dict) -> dict:
    return {k: e[k] for k in ("v", "shadow_digest", "action_digest", "reason_digest", "principal")}


def sign_widening_explanation(secret: bytes, e: dict) -> dict:
    """A principal states that this widening is intended (``reason_digest`` binds the display-only reason text)."""
    base = {"v": 1, **e, "principal": signer_of(secret)}
    return {**base, "sig": sign_body(WIDENING_EXPLANATION_DOMAIN, _exp_body(base), secret)}


def _verify_explanation(e: Any) -> bool:
    try:
        if not is_obj(e) or not is_one(e.get("v")) or not (is_str(e.get("shadow_digest"), 128) and is_str(e.get("action_digest"), 128)
                                                           and is_str(e.get("reason_digest"), 128) and is_str(e.get("principal"), 128)):
            return False
        return verify_body(WIDENING_EXPLANATION_DOMAIN, _exp_body(e), e["principal"], e.get("sig"))
    except Exception:
        return False


def _ap_body(a: dict) -> dict:
    return {k: a[k] for k in ("v", "shadow_digest", "enforced_digest", "at", "principal")}


def sign_promotion_approval(secret: bytes, a: dict) -> dict:
    base = {"v": 1, **a, "principal": signer_of(secret)}
    return {**base, "sig": sign_body(PROMOTION_APPROVAL_DOMAIN, _ap_body(base), secret)}


def _verify_approval(a: Any) -> bool:
    try:
        if not is_obj(a) or not is_one(a.get("v")) or not (is_str(a.get("shadow_digest"), 128) and is_str(a.get("enforced_digest"), 128)) \
                or not is_uint(a.get("at")) or not is_str(a.get("principal"), 128):
            return False
        return verify_body(PROMOTION_APPROVAL_DOMAIN, _ap_body(a), a["principal"], a.get("sig"))
    except Exception:
        return False


def promotion_gate(log: ShadowLog, o: dict) -> dict:
    """May this candidate be promoted? Enough samples, no candidate failures, every diff verifies, zero unexplained widenings, and a
    principal-signed approval when the static verdict on the declared surfaces is ``wider`` or ``unknown``. Fails closed."""
    def no(code: str, reason: str, unexplained: Optional[list] = None) -> dict:
        return {"ok": False, "code": code, "reason": reason, **({"unexplained": unexplained} if unexplained else {})}

    try:
        principals = o.get("principals")
        if not is_str(o.get("shadow_digest"), 128) or not is_str(o.get("enforced_digest"), 128) or not is_uint(o.get("minSamples")) \
                or o["minSamples"] < 1 or not isinstance(principals, list) or o.get("surface") not in ("narrower", "equal", "wider", "unknown"):
            return no("bad_input", "bad gate options")
        sd, ed = o["shadow_digest"], o["enforced_digest"]
        s = log.stats(sd)
        if s["total"] < o["minSamples"]:
            return no("too_few_samples", "%d observation(s), need %s" % (s["total"], _num(o["minSamples"])))
        if s["errors"] > 0:
            return no("shadow_errors", "%d observation(s) where the candidate failed" % s["errors"])
        diffs = log.diffs(sd)
        if not all(verify_shadow_diff(d, log.signer) and d["shadow_digest"] == sd and d["enforced_digest"] == ed for d in diffs) or len(diffs) != s["diverged"]:
            return no("bad_diff", "a recorded diff does not verify, belongs to another pair, or is missing")
        explained = set()
        exps = o.get("explanations")
        if exps is None:
            exps = []
        if isinstance(exps, dict):
            raise TypeError("explanations is not iterable")
        for e in exps:
            if _verify_explanation(e) and e["principal"] in principals and e["shadow_digest"] == sd:
                explained.add(e["action_digest"])
        unexplained = sorted({d["action_digest"] for d in diffs if d["widening"] and d["action_digest"] not in explained}, key=u16key)
        if unexplained:
            return no("unexplained_widening", "%d widening(s) without a principal's explanation" % len(unexplained), unexplained)
        if o["surface"] in ("wider", "unknown"):
            a = o.get("approval")
            if not _verify_approval(a) or a["principal"] not in principals or a["shadow_digest"] != sd or a["enforced_digest"] != ed:
                return no("advisory_wider", "the analyzer reports the candidate %s on the declared surfaces: a principal-signed approval is required"
                          % ("wider" if o["surface"] == "wider" else "not provably narrower"))
        return {"ok": True, "samples": s["total"], "widenings": len([d for d in diffs if d["widening"]]), "surface": o["surface"]}
    except Exception:
        return no("bad_input", "evaluation error (fail closed)")


def _num(x: Any) -> str:
    return str(int(x)) if isinstance(x, float) and x == int(x) else str(x)


def promote_shadow(enforced: dict, candidate: dict, gate: dict, now: Any) -> dict:
    """The body of the bundle revision that makes the candidate the enforced policy: its content at revision + 1, chained to the
    enforced revision, with the shadow list cleared. Needs a passing gate for this candidate, and the candidate must be listed in the
    enforced revision's ``shadow``. Sign it with ``sign_bundle`` / ``assemble_bundle`` like any revision."""
    digest = bundle_digest(candidate)
    if not gate.get("ok"):
        raise ValueError("promoteShadow: the gate did not pass (%s)" % gate.get("code"))
    if digest not in (enforced.get("shadow") if enforced.get("shadow") is not None else []):
        raise ValueError("promoteShadow: the candidate is not listed in the enforced revision's shadow")
    if not is_uint(now):
        raise ValueError("promoteShadow: bad time")
    rest = _without(candidate, "sigs", "shadow", "prev")
    return {**rest, "revision": enforced["revision"] + 1, "prev": bundle_digest(enforced), "issued_at": now}
