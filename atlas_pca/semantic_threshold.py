"""Semantic-judge threshold: an ensemble of independently keyed judges each sign a verdict (faithful, score) bound to the action digest and the goal
commitment; the action passes when at least ``k`` DISTINCT trusted judges agree it is faithful at one quantised score, optionally above a
conformally calibrated cutoff, and (optionally) only judges with a verified TEE attestation count. A port of the reference ``semantic-threshold``
module. Scores are quantised to parts per million before they are signed or counted, so every language computes the same integers. Fails closed; the
legacy unbound-PQ opt-out is not offered (a PQ or hybrid verdict counts only under a pinned key)."""
from __future__ import annotations

from ._fin import fin
import math
from functools import cmp_to_key
from typing import Any, Callable, Dict, List, Optional

from .agent import KeyPair
from .attestation_soft import _truthy, match_agent_binding
from .intent_v2 import _UNDEF, _bind_suite_fields, _pinned_suite_error, compare_utf8, suite_capability_error
from .intent_wb import _js_str
from .pca import b64u, canonical_bytes_strict, decode_b64u_strict, hash_canonical
from .pq_suites import sign_suite_artifact, suite_pq_public_key

__all__ = ["SEMANTIC_JUDGE_DOMAIN", "SCORE_SCALE", "quantize_score", "statement_of", "semantic_judge_message", "action_digest", "verdict_digest",
           "sign_judge_verdict", "verify_judge_verdict", "verify_judge_attestation", "conformal_threshold", "empirical_false_allow_rate",
           "verify_semantic_threshold", "create_semantic_verifier", "semantic_risk_contribution"]

SEMANTIC_JUDGE_DOMAIN = "atlas-pca/semantic-judge/v1\0"
SCORE_SCALE = 1_000_000
_MIN_VALUE = 5e-324  # Number.MIN_VALUE


def _is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _fin(x: Any) -> bool:
    return _is_num(x) and fin(x)


def _js_round(x: float) -> float:
    """``Math.round``: halves go toward +Infinity."""
    f = math.floor(x)
    return f + 1 if x - f >= 0.5 else f


def quantize_score(score: Any) -> int:
    """The score in parts per million, clamped to [0, 1e6]; a non-finite score is 0."""
    if not _fin(score):
        return 0
    q = int(_js_round(score * SCORE_SCALE))
    return 0 if q < 0 else SCORE_SCALE if q > SCORE_SCALE else q


def statement_of(v: dict) -> Dict[str, Any]:
    """The signed statement of a verdict: the digests, ``faithful`` (=== true), the quantised score and the judge measurement (``alg`` and ``pq_pk``
    bound in for a non-Ed25519 suite)."""
    jm = v.get("judgeMeasurement")
    base = {"v": 1, "actionDigest": v.get("actionDigest", _UNDEF), "goalCommitment": v.get("goalCommitment", _UNDEF), "faithful": v.get("faithful") is True,
            "score_ppm": quantize_score(v.get("score")), "judgeMeasurement": "" if jm is None else _js_str(jm)}
    base = {k: x for k, x in base.items() if x is not _UNDEF}
    alg, pk = v.get("alg", _UNDEF), v.get("pq_pk", _UNDEF)
    try:
        return _bind_suite_fields(base, alg, pk)
    except TypeError:  # a non-Ed25519 suite without pq_pk: the statement carries pq_pk undefined, which the canonical encoder refuses when it is signed
        return {**_bind_suite_fields(base, alg, ""), "pq_pk": _UNDEF}


def semantic_judge_message(statement: Any) -> bytes:
    """The signed bytes: the domain, then the strict canonical JSON of the statement (a non-integer, negative-zero or non-finite member raises)."""
    return SEMANTIC_JUDGE_DOMAIN.encode("utf-8") + canonical_bytes_strict(statement)


def action_digest(action: Any) -> str:
    """The digest a verdict binds: the content hash of the PCActn's action."""
    return hash_canonical(action)


def verdict_digest(v: Any) -> str:
    return hash_canonical(v)


def sign_judge_verdict(secret_key: Any, v: dict, suite: Optional[dict] = None) -> Dict[str, Any]:
    """A judge's signed verdict; ``suite`` = ``{"alg"?, "pq"?}``. Raises on an unknown alg."""
    if "actionDigest" not in v or "goalCommitment" not in v:  # an absent member has no canonical form: the reference refuses to sign it
        raise TypeError("canonicalize: unsupported type undefined")
    jm = "" if v.get("judgeMeasurement") is None else _js_str(v["judgeMeasurement"])
    alg = (suite or {}).get("alg")
    if alg is not None and suite_capability_error(alg) is not None:
        raise ValueError("signJudgeVerdict: unknown signature alg '%s'" % _js_str(alg))
    ed = KeyPair(bytes(secret_key), allow_insecure_signer=True)
    pq = (suite or {}).get("pq")
    pq_pk = suite_pq_public_key(alg, pq)
    non_ed = alg is not None and alg != "ed25519"
    statement = statement_of(dict(v, judgeMeasurement=jm, **({"alg": alg} if non_ed else {}), **({"pq_pk": pq_pk} if pq_pk is not None and non_ed else {})))
    fields = sign_suite_artifact(alg, ed, pq, semantic_judge_message(statement))
    out = {"judge": ed.public, "actionDigest": v["actionDigest"], "goalCommitment": v["goalCommitment"], "faithful": v.get("faithful") is True,
           "score": v["score"], "judgeMeasurement": jm}
    out.update(fields)
    return out


def verify_judge_verdict(v: Any, expected: dict, pin: Optional[dict] = None) -> bool:
    """One verdict: the judge key, the bindings to the expected action and goal, the typed members, and the signature under its suite (a PQ or hybrid
    suite only under ``pin["pqPins"]``). Total: anything malformed is False."""
    if not isinstance(v, dict):
        return False
    j = v.get("judge")
    if not isinstance(j, str) or decode_b64u_strict(j, 32) is None:
        return False
    if not isinstance(v.get("actionDigest"), str) or not isinstance(v.get("goalCommitment"), str):
        return False
    if v["actionDigest"] != expected.get("actionDigest") or v["goalCommitment"] != expected.get("goalCommitment"):
        return False
    if not isinstance(v.get("faithful"), bool):
        return False
    s = v.get("score")
    if not _fin(s) or s < 0 or s > 1:
        return False
    if not isinstance(v.get("judgeMeasurement"), str) or not isinstance(v.get("sig"), str):
        return False
    alg = v.get("alg", _UNDEF)
    if suite_capability_error(alg) is not None:
        return False  # an unknown suite fails closed
    try:
        msg = semantic_judge_message(statement_of(v))
        pins = pin.get("pqPins") if isinstance(pin, dict) else None
        return _pinned_suite_error(alg, j, v.get("pq_pk", _UNDEF), msg, v["sig"], v.get("pq_sig", _UNDEF), pins) is None
    except Exception:  # noqa: BLE001 - e.g. a post-quantum verdict with no pq_pk: refused, never thrown
        return False


def verify_judge_attestation(judge_measurement: Any, attestation: Any, approved: Any = None) -> Dict[str, Any]:
    """A judge's hardware attestation: verified, bound to a TEE report, carrying a measured identity whose runtime measurement equals the signed
    ``judgeMeasurement`` and satisfying the approved agent binding: ``{"ok", "reason"?, "measured"?}``."""
    if not isinstance(attestation, dict) or attestation.get("ok") is not True:
        r = attestation.get("reason") if isinstance(attestation, dict) else None
        return {"ok": False, "reason": r if r is not None else "no verified attestation for this judge (fail-closed)"}
    if attestation.get("bound") is not True:
        return {"ok": False, "reason": "judge attestation not bound to a TEE report (report_data binding unconfirmed)"}
    measured = attestation.get("measured")
    if not isinstance(measured, (dict, list)):
        return {"ok": False, "reason": "judge attestation carries no measured identity"}
    if not isinstance(judge_measurement, str) or len(judge_measurement) == 0:
        return {"ok": False, "reason": "verdict carries no judgeMeasurement to bind to the attested identity"}
    if (measured.get("runtime_measurement") if isinstance(measured, dict) else None) != judge_measurement:
        return {"ok": False, "reason": "attested enclave measurement does not match the signed judgeMeasurement"}
    appraisal = match_agent_binding(measured, approved)
    if appraisal:
        return {"ok": False, "reason": appraisal}
    return {"ok": True, "measured": measured}


def _clamp_alpha(alpha: Any) -> float:
    if not _fin(alpha):
        return 1
    if alpha <= 0:
        return _MIN_VALUE
    return 1 if alpha > 1 else alpha


def _unfaithful_scores(samples: Any) -> List[float]:
    return [s["score"] for s in (samples if isinstance(samples, list) else [])
            if isinstance(s, dict) and s.get("faithful") is False and _fin(s.get("score"))]


def conformal_threshold(calibration: Any) -> float:
    """The cutoff a score must EXCEED: the (1 - alpha) conformal quantile of the unfaithful samples' scores; +Infinity when there are too few."""
    cal = calibration if isinstance(calibration, dict) else {}
    alpha = _clamp_alpha(cal.get("alpha"))
    unfaithful = _unfaithful_scores(cal.get("samples"))
    m = len(unfaithful)
    if m == 0:
        return math.inf
    rank = math.ceil((m + 1) * (1 - alpha))
    if rank > m:
        return math.inf
    unfaithful.sort()
    return unfaithful[max(rank, 1) - 1]


def empirical_false_allow_rate(samples: Any, cutoff: Any) -> float:
    """The fraction of unfaithful samples whose score exceeds ``cutoff`` (0 with none)."""
    scores = _unfaithful_scores(samples)
    if not scores:
        return 0
    allowed = sum(1 for s in scores if s > cutoff)
    return allowed / len(scores)


def verify_semantic_threshold(verdicts: Any, opts: Any) -> Dict[str, Any]:
    """``{"ok", "agreeCount", "aggregateScore", "cutoff"?, "reason"?}``. Options: judgeKeys, k, goalCommitment, actionDigest, calibration?, pqPins?,
    attestation? ({"resolve"(verdict) -> hardware result, "require", "approved"?}). A judge counts once, only when every one of its verdicts verifies
    and they all agree (faithful at one quantised score); a judge that contradicts itself does not count."""
    o = opts if isinstance(opts, dict) else {}
    k = o.get("k", _UNDEF)
    allow = {key for key in (o["judgeKeys"] if isinstance(o.get("judgeKeys"), list) else []) if isinstance(key, str) and decode_b64u_strict(key, 32) is not None}
    if not isinstance(o.get("actionDigest"), str) or not isinstance(o.get("goalCommitment"), str):
        return {"ok": False, "agreeCount": 0, "aggregateScore": 0, "reason": "missing action/goal binding"}
    if not _is_num(k) or not fin(k) or k != math.floor(k) or k < 1:
        return {"ok": False, "agreeCount": 0, "aggregateScore": 0, "reason": "invalid quorum k=%s" % _js_str(k)}
    att = o.get("attestation")
    by_judge: Dict[str, Dict[str, set]] = {}
    for v in verdicts if isinstance(verdicts, list) else []:
        if not isinstance(v, dict) or not isinstance(v.get("judge"), str) or v["judge"] not in allow:
            continue
        if not verify_judge_verdict(v, {"actionDigest": o["actionDigest"], "goalCommitment": o["goalCommitment"]}, o):
            continue
        if att and att.get("require") is True and not verify_judge_attestation(v.get("judgeMeasurement"), att["resolve"](v), att.get("approved"))["ok"]:
            continue  # an unattested, wrong-measurement or unapproved judge: the vote does not count
        g = by_judge.setdefault(v["judge"], {"faithful": set(), "score": set()})
        g["faithful"].add(v.get("faithful") is True)
        g["score"].add(quantize_score(v.get("score")))
    agreeing = [(j, next(iter(g["score"]))) for j, g in by_judge.items() if g["faithful"] == {True} and len(g["score"]) == 1]
    agreeing.sort(key=cmp_to_key(lambda a, b: compare_utf8(a[0], b[0])))
    n = len(agreeing)
    aggregate = 0 if n == 0 else sum_in_order([q / SCORE_SCALE for _, q in agreeing]) / n
    if n < k:
        return {"ok": False, "agreeCount": n, "aggregateScore": aggregate, "reason": "only %d distinct trusted judge(s) agree, need %s" % (n, _js_str(k))}
    cal = o.get("calibration")
    if _truthy(cal):
        cutoff = conformal_threshold(cal)
        if not aggregate > cutoff:
            return {"ok": False, "agreeCount": n, "aggregateScore": aggregate, "cutoff": cutoff,
                    "reason": "aggregateScore %s does not exceed calibrated cutoff %s" % (_js_str(aggregate), _js_str(cutoff))}
        return {"ok": True, "agreeCount": n, "aggregateScore": aggregate, "cutoff": cutoff}
    return {"ok": True, "agreeCount": n, "aggregateScore": aggregate}


def sum_in_order(xs: List[float]) -> float:
    """A left-to-right floating-point sum starting from 0 (the reference's ``reduce``; ``sum`` would compensate)."""
    acc = 0.0
    for x in xs:
        acc += x
    return acc


def create_semantic_verifier(opts: dict) -> Callable[[Any], Dict[str, Any]]:
    """The semantic hook: ``hook(ctx)`` -> ``{"enforced", "ok"?, "reason"?}``. Options: judgeKeys, k, calibration?, ``verdicts(ctx)``,
    ``goalCommitment(ctx)``, ``actionDigest(ctx)`` (default: the content hash of ``ctx["pcactn"]["action"]``), ``optionalWhenAbsent``,
    ``attestation(ctx)``. With no ensemble the hook is closed unless ``optionalWhenAbsent``."""
    digest_of = opts.get("actionDigest") or (lambda ctx: action_digest(ctx["pcactn"]["action"]))

    def hook(ctx: Any) -> Dict[str, Any]:
        goal = opts["goalCommitment"](ctx)
        verdicts = opts["verdicts"](ctx)
        if not isinstance(goal, str) or verdicts is None:
            if opts.get("optionalWhenAbsent"):
                return {"enforced": False}
            return {"enforced": True, "ok": False, "reason": "no semantic ensemble available for this action (fail-closed)"}
        att = opts["attestation"](ctx) if opts.get("attestation") else None
        o = {"judgeKeys": opts.get("judgeKeys"), "k": opts.get("k"), "goalCommitment": goal, "actionDigest": digest_of(ctx), "calibration": opts.get("calibration")}
        if att:
            o["attestation"] = att
        res = verify_semantic_threshold(verdicts, o)
        return {"enforced": True, "ok": True} if res["ok"] else {"enforced": True, "ok": False, "reason": res.get("reason") or "semantic threshold not met"}
    return hook


def semantic_risk_contribution(aggregate_score: Any) -> float:
    """The risk the semantic ensemble contributes: ``1 - aggregateScore`` clamped to [0, 1]; a non-finite score is the worst case, 1."""
    if not _fin(aggregate_score):
        return 1
    r = 1 - aggregate_score
    return 0 if r < 0 else 1 if r > 1 else r
