"""The confirmation flow and signed review attestations (native port of import/review.ts of the TypeScript reference @atlasauth/pca-actions):
the attestation verdict with its reasons, review status, the review queue and view, and the producer side (confirm_def). A def WITHOUT a valid
attestation has the top of the registry as its effective traits; one counts only when a key pinned with the reviewer role signed this exact
def digest. Signing needs the `cryptography` package (as KeyPair.sign does)."""
import json
from typing import Any, Dict, List, Optional

from .actions import (
    _TRAIT_ID_RE, ActionKitError, _JS_WS, _blank_reason, _sort_uniq, _u16key, _verify_b64u, closure, def_digest, facts_digest,
    normalize, review_message, reviewer_pins_error, traits_digest, validate_def,
)
from .actions_confirmation import sign_review
from .actions_derive import card_of, to_schema_verb
from .actions_effective import effective_with, implied_traits
from .agent import KeyPair
from .intent_wb import _UNDEF, _utf16_len

_SUSPECT = ("pca.money_moving", "pca.privilege_change", "pca.code_execution", "pca.destructive", "pca.external_communication")
_NEXT = ("pca.credential_access", "pca.data_export", "pca.regulated_data", "pca.public_exposure", "pca.infra_mutation", "pca.legal_binding", "pca.impersonation", "pca.persistence")


def _fail(reason: str, detail: str) -> dict:
    return {"ok": False, "reason": reason, "detail": detail}


def verify_attestation_verdict(d: Any, reg: Dict[str, dict], pins: Any) -> dict:
    """{ok: True, kid} iff the confirmation is valid, else {ok: False, reason, detail}. Never raises."""
    try:
        pe = reviewer_pins_error(pins)
        if pe:
            return _fail("bad_pins", pe)
        review = d.get("review") if isinstance(d, dict) else None
        if (review or {}).get("state") != "confirmed":
            return _fail("not_confirmed", "review.state is not confirmed")
        a = review.get("attestation", _UNDEF)
        if a is _UNDEF:
            return _fail("no_attestation", "a confirmed def carries an attestation")
        if a is not None and not isinstance(a, dict):
            a = {}  # a scalar or array has no members: unsigned
        if not isinstance(a.get("sig"), str):
            return _fail("no_signature", "the attestation is unsigned")
        if not isinstance(a.get("facts_digest"), str):
            return _fail("malformed", "the attestation facts_digest must be a string")
        ft, dis = a.get("final_traits"), a.get("dismissed")
        if (not isinstance(ft, list) or not all(isinstance(t, str) for t in ft) or not isinstance(dis, list)
                or not all(isinstance(x, dict) and isinstance(x.get("trait"), str) and isinstance(x.get("reason"), str) for x in dis)
                or not _is_nonneg_or_neg(a.get("ts")) or not isinstance(a.get("reviewer_kid"), str)):
            return _fail("malformed", "the attestation final_traits, dismissed, ts or reviewer_kid is malformed")
        if a.get("def_digest") != def_digest(d):
            return _fail("digest_mismatch", "the def changed after it was reviewed")
        accepted = {traits_digest(reg)} | set(pins.get("traits_digests") or [])
        if a.get("traits_digest") not in accepted:
            return _fail("traits_digest_mismatch", "the trait registry changed since the review")
        if json.dumps(_sort_uniq(ft)) != json.dumps(_sort_uniq(d.get("traits"))):
            return _fail("final_traits_mismatch", "the attested final traits are not the def's declared traits")
        fin = set(ft)
        if any(x["trait"] in fin or _blank_reason(x["reason"]) for x in dis):
            return _fail("dismissed_conflict", "a dismissed trait is also final, or has no reason")
        key = next((k for k in pins["keys"] if k["kid"] == a["reviewer_kid"]), None)
        if key is None:
            return _fail("unknown_reviewer", "no pinned key '%s'" % a["reviewer_kid"])
        if "reviewer" not in key["roles"]:
            return _fail("not_a_reviewer", "key '%s' does not hold the reviewer role" % key["kid"])
        if ("not_before" in key and a["ts"] < key["not_before"]) or ("not_after" in key and a["ts"] > key["not_after"]):
            return _fail("outside_validity", "the attestation time is outside the key validity")
        body = {k: v for k, v in a.items() if k != "sig"}
        if _verify_b64u(key["pk"], review_message(body), a["sig"]):
            return {"ok": True, "kid": key["kid"]}
        return _fail("bad_signature", "the attestation signature is invalid")
    except Exception as e:  # noqa: BLE001
        return _fail("malformed", str(e))


def _is_nonneg_or_neg(v: Any) -> bool:
    """Number.isSafeInteger(v) and not -0 (any sign: a negative ts is judged later by the key validity)."""
    import math
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    if isinstance(v, float) and (not math.isfinite(v) or not v.is_integer() or (v == 0 and math.copysign(1, v) < 0)):
        return False
    return abs(v) <= 9007199254740991


def attestation_verifier(reg: Dict[str, dict], pins: Any):
    """The callback the algebra takes: a confirmed def counts only if the attestation verdict is ok."""
    return lambda d: verify_attestation_verdict(d, reg, pins)["ok"]


def review_status(d: dict, reg: Dict[str, dict], pins: Any) -> str:
    """The state that counts: a `confirmed` def with an invalid attestation is `stale` (it behaves as unreviewed)."""
    if d["review"]["state"] != "confirmed":
        return d["review"]["state"]
    return "confirmed" if verify_attestation_verdict(d, reg, pins)["ok"] else "stale"


def revert_stale(d: dict, reg: Dict[str, dict], pins: Any) -> dict:
    """Defs whose confirmation no longer holds go back to `unreviewed` (the attestation is dropped)."""
    if review_status(d, reg, pins) != "stale":
        return d
    rest = {k: v for k, v in d["review"].items() if k != "attestation"}
    return {**d, "review": {**rest, "state": "unreviewed"}}


def _intrinsic(d: dict, reg: Dict[str, dict]) -> dict:
    return effective_with(d, reg)["hint"]


def review_priority(d: dict, reg: Dict[str, dict]) -> int:
    """0 = a core suspect trait (money, privilege, code, destructive, outbound communication), 1 = other risky, 2 = the rest."""
    cl = set(_intrinsic(d, reg)["closure"])
    if any(t in cl for t in _SUSPECT):
        return 0
    if any(t in cl for t in _NEXT):
        return 1
    return 2


def review_queue_order(defs: List[dict], reg: Dict[str, dict]) -> List[dict]:
    """Defs in review order: suspect traits first, then by risk (highest first), then by verb."""
    rows = [(review_priority(d, reg), _intrinsic(d, reg)["eff"]["risk"], d) for d in defs]
    rows.sort(key=lambda x: (x[0], -x[1], _u16key(x[2]["verb"])))
    return [r[2] for r in rows]


def _sj(o: dict, k: str) -> str:
    return json.dumps(o[k], separators=(",", ":"), ensure_ascii=False) if k in o else "undefined"


def prepare_review(d: dict, reg: Dict[str, dict], previous: Optional[dict] = None) -> dict:
    """What the reviewer is shown: the def's facts, the traits it would carry once signed, the policy card and (with `previous`) what changed."""
    eff = effective_with(d, reg)
    shown = {**eff, **eff["hint"], "confirmed": True}
    sb = d["review"].get("suggested_by") or {}
    changes: List[str] = []
    if previous is not None:
        skip = ("review", "examples", "source", "since")
        a = {k: v for k, v in previous.items() if k not in skip}
        b = {k: v for k, v in d.items() if k not in skip}
        changes = sorted((k for k in set(a) | set(b) if _sj(a, k) != _sj(b, k)), key=_u16key)
    return {
        "verb": d["verb"], "def_digest": def_digest(d), "state": d["review"]["state"], "declared_traits": _sort_uniq(d.get("traits")),
        "implied_traits": implied_traits(normalize(d)), "suggested": sb.get("added") if sb.get("added") is not None else {"traits": [], "roles": {}, "tags": {}},
        "effective": eff, "card": card_of(d, shown, reg), "changes": changes, "priority": review_priority(d, reg),
    }


def confirm_def(d: dict, o: dict) -> dict:
    """Review one def: validate the decision, write the final traits, sign an attestation over the resulting digest, return the confirmed def.
    o: {registry, reviewer: {kid, secret}, pins?, finalTraits, dismissed?, ts}. Raises bad_confirm / undismissed_suggestion / not_reviewer."""
    reg = o["registry"]
    ts = o.get("ts")
    if not _is_nonneg_or_neg(ts) or ts < 0:
        raise ActionKitError("bad_confirm", "ts must be a non-negative integer")
    final = _sort_uniq(o["finalTraits"])
    if len(final) != len(o["finalTraits"]):
        raise ActionKitError("bad_confirm", "final traits must be distinct")
    for t in final:
        if _TRAIT_ID_RE.fullmatch(t) is None or t not in reg:
            raise ActionKitError("bad_confirm", "unknown trait '%s'" % t)
        if t == "pca.unreviewed":
            raise ActionKitError("bad_confirm", "'pca.unreviewed' is the review marker, not a final trait")
    dismissed = [{"trait": x["trait"], "reason": x["reason"]} for x in (o.get("dismissed") or [])]
    dset = set()
    for x in dismissed:
        if not isinstance(x["reason"], str) or len(x["reason"].strip(_JS_WS)) == 0 or _utf16_len(x["reason"]) > 256:
            raise ActionKitError("bad_confirm", "dismissed trait '%s' needs a reason (1..256 characters)" % x["trait"])
        if x["trait"] in dset:
            raise ActionKitError("bad_confirm", "trait '%s' is dismissed twice" % x["trait"])
        dset.add(x["trait"])
        if x["trait"] in final:
            raise ActionKitError("bad_confirm", "trait '%s' is both final and dismissed" % x["trait"])
    sb = d["review"].get("suggested_by") or {}
    shown = _sort_uniq(list(d.get("traits") or []) + list((sb.get("added") or {}).get("traits") or []))
    covered = set(closure(reg, _sort_uniq(final + implied_traits(normalize(d)))))
    for t in shown:
        if t in final or t in covered:
            continue
        if t not in dset:
            raise ActionKitError("undismissed_suggestion", "trait '%s' was suggested and is not in the final set: record it as dismissed with a reason" % t)
    for t in dset:
        if t not in shown:
            raise ActionKitError("bad_confirm", "trait '%s' was never suggested; nothing to dismiss" % t)
    rv = o["reviewer"]
    if o.get("pins"):
        pe = reviewer_pins_error(o["pins"])
        if pe:
            raise ActionKitError("bad_confirm", pe)
        key = next((k for k in o["pins"]["keys"] if k["kid"] == rv["kid"]), None)
        if key is None or "reviewer" not in key["roles"]:
            raise ActionKitError("not_reviewer", "key '%s' is not pinned with the reviewer role" % rv["kid"])
        if key["pk"] != KeyPair(bytes(rv["secret"])).public:
            raise ActionKitError("not_reviewer", "the secret does not belong to the pinned key '%s'" % rv["kid"])
    body = {**d, "traits": final}
    if not final:
        del body["traits"]
    digest = def_digest(body)
    att = sign_review({"def_digest": digest, "traits_digest": traits_digest(reg), "facts_digest": facts_digest(to_schema_verb(body, reg)["verb"]), "final_traits": final,
                       "dismissed": dismissed, "reviewer_kid": rv["kid"], "ts": ts}, rv["secret"])
    out = {**body, "review": {**d["review"], "state": "confirmed", "attestation": att}}
    bad = validate_def(out)
    if bad is not None:
        raise ActionKitError("bad_confirm", "the confirmed def is invalid: %s" % bad)
    return out
