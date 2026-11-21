"""`verify_evidence_bundle`: deterministic replay of a dispute evidence bundle (Intent Layer v2). Every finding is RECOMPUTED from the signed
artifacts; nothing the bundle claims about itself (the canary summary, the accumulator posts, the verdicts) is taken on trust. The output is a
findings report whose text comes from fixed templates, so two readers of the same bundle with the same trust inputs get byte-identical reports
(`report_digest`). Three statuses, never mixed: `pass` (re-verified here), `fail` (re-verification refuted it), `unverified` (this verifier had
no way to check it: no verifier for the format, an unopened map, a missing trust key); `complete` is False whenever one is present.

Port of @atlasauth/pca-evidence (verifyEvidenceBundle) of the TypeScript reference. Never raises on a malformed bundle: it is a report with a failed
`shape` finding, and a fault inside the replay is a failed `shape` finding too (fail closed). A `trust["verifiers"][name]` port is a callable
`(artifact, bundle) -> {"ok": bool, "reason"?: str}` that OVERRIDES the core default of that artifact."""
from __future__ import annotations

from ._fin import fin
import functools
from typing import Any, Callable, Dict, List, Optional

from .evidence import (EVIDENCE_REPORT_DOMAIN, acc_trust_error, anchor_commit, bundle_shape_error, cap_of, evidence_digest,
                       normalize_bundle, principals_trust_error)
from .explain import _UNDEF, _truthy
from .intent_history import acc_key_of, acc_pre_state, monitor_state
from .intent_v2 import (RECEIPT_SKEW_MS, acc_value_of, action_schema_digest, check_session_revocation, delta_revocation_id, map_revocation_id,
                        pcactn_reservation_digest, receipt_arithmetic_ok, session_revocation_id, session_root_digest, sequencer_key_set_digest,
                        verify_action_schema, verify_receipt_against_holder, verify_sequencer_key_set, verify_session_root)
from .intent_jit import intent_action_digest
from .intent_mapkit import intent_map_digest, verify_intent_map
from .intent_statement import intent_ref, verify_intent
from .intent_wb import (FACT_DOMAIN, INTENT_CLASSIFIER_DOMAIN, OFFER_SET_DOMAIN, validate_classifier_verdict_wire, validate_fact_wire,
                        validate_offer_set_wire, verify_artifact_sig, verify_labels)
from .ledger import verify_ledger_inclusion, verify_tree_head
from .pca import grant_session_caveat, hash_canonical, intent_session_caveat_error, params_digest, ts_check_name, ts_reason, unb64u, verify_chain, verify_pcactn_core
from .predicates import _js_string
from .wallet import answer_ref, device_challenge, friction_rank, typed_digest, verify_intent_answer
from .webauthn import verify_assertion

__all__ = ["verify_evidence_bundle", "INTENT_ANCHOR_LOG", "DEFAULT_REVOCATION_MAX_AGE_S"]

INTENT_ANCHOR_LOG = "pca-intent:v1"
DEFAULT_REVOCATION_MAX_AGE_S = {"payment": 60, "default": 300}

_TEMPLATES = {
    "shape": "The bundle is well formed (pca-intent-evidence v1, closed members)",
    "principal.pinned": "Every session-root key that signs in this bundle is a principal key pinned by the reader (attribution)",
    "trust.principals": "The pinned principal keys (trust.principals) are well formed",
    "statement.commit": "The session root commits to the intent statement the bundle names",
    "statement.opening": "The opened statement is signed by a principal and hashes to the committed ref",
    "session_root.signature": "The session root is signed by one of its principal keys",
    "schema.signature": "The action schema is signed by a site key",
    "schema.digest": "The session root binds this action schema",
    "schema.anchor": "The action schema is anchored in a transparency log",
    "map.replay": "The task map replays to its committed digest",
    "root_grant": "The root intent grant G_0 is principal-signed and bound to the session",
    "delta.signature": "The delta grant is a root capability signed by a principal of the session",
    "delta.chain": "The delta grant chains to the session (session, seq, prev, root)",
    "delta.backed": 'Every delta grant is backed by a principal "yes" answer',
    "answer.signature": "The answer is signed by a principal of the session, for this session",
    "answer.map": "The answer refers to a map version in the bundle",
    "answer.tier": "The answer meets the site minimum friction tier for the verb",
    "answer.typed": "The typed-tier value re-derives the signed typed digest",
    "answer.device": "The device-tier WebAuthn assertion verifies with user verification",
    "canaries.summary": "The canary summary equals the one recomputed from the signed canary answers",
    "pcactn.verify": "The PCActn verifies (signature, chain, audience, validity at its issue time)",
    "pcactn.root": "The PCActn's root capability is G_0 or a bundled delta grant",
    "pcactn.session": "The PCActn's signed intent_session member matches the session, its root grant and the accumulator events",
    "subject.present": "The subject PCActn is in the bundle",
    "jit.consent": "The irreversible subject action carries a principal JIT consent bound to its exact action digest",
    "accumulator.declared": "The accumulator is declared in the session root",
    "accumulator.arithmetic": "The accumulator posts are the running values of the counted events",
    "accumulator.cap": "Every accumulator post is within the admitting grant's cap",
    "accumulator.receipts": "The sequencer reservation receipt verifies and is consistent",
    "acc.keysets.equivocation": "No two different sequencer key sets share one root and version",
    "acc.keysets": "The sequencer key set is signed by the session's pinned sequencer root and its version never rolls back",
    "trust.acc": "The verifier freshness configuration (trust.acc) is well formed",
    "effect.binding": "The effect record is bound to the PCActn's signed params",
    "effect.charged": "The charged amount is within the confirmed value",
    "effect.frame": "No monitored state outside the write set changed",
    "effect.signature": "The effect record is signed by the site",
    "verdict.signature": "The site verdict record verifies",
    "fact.signature": "The oracle fact verifies under a pinned oracle key",
    "classifier.signature": "The classifier verdict verifies under a pinned judge key",
    "offer_set.signature": "The offer set is signed by a site key, for this session",
    "labels.signature": "The label receipt is signed by a pinned site key, for this session",
    "settlement.signature": "The settlement record verifies",
    "revocation.history": "The bundled revocation epoch extends its predecessor (one append-only chain by the session revocation authority)",
    "revocation.epoch": "A fresh revocation epoch shows the session, its maps and its deltas unrevoked at the action time",
    "anchor.inclusion": "The anchored artifact is included under a guardian-signed head of the intent log",
}
_STATUS_TEXT = {"pass": "verified", "fail": "REFUTED", "unverified": "not verified here"}
_NOT_PROVEN = [
    "That the principal understood the question: the bundle proves only that a deterministic card with the recorded digest was shown and answered at the recorded friction tier.",
    "That the site's signed schema describes what its endpoints really do (SCH).",
    "That the site's effect records and any oracle facts are true (EFF, ORC).",
    "Acceptance of this bundle by any card network, court or regulator.",
]
_V2_CHECKS = ("schema", "intent_session", "accumulators")


# ---- JavaScript value helpers ----------------------------------------------------------------------------------------------------

def _u16(s: Any) -> bytes:
    """UTF-16 code-unit order of a string (JS `<` and the default `Array.sort`)."""
    return str(s).encode("utf-16-be", "surrogatepass")


def _n(v: Any) -> str:
    """String(v) for a JSON value (an integral float prints without a fraction)."""
    return _js_string(v)


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and fin(v)


def _is_obj(v: Any) -> bool:
    return isinstance(v, dict)


def _se(a: Any, b: Any) -> bool:
    """`a === b` over JSON scalars."""
    if a is _UNDEF or b is _UNDEF:
        return a is b
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return a is b or (a is None and b is None)


def _pg(o: Any, k: str) -> Any:
    """`o?.[k]` without throwing: undefined for a missing member or a non-object."""
    return o[k] if isinstance(o, dict) and k in o else _UNDEF


def _num_or0(x: Any, k: str) -> float:
    """`Number(x?.[k]) || 0`."""
    v = _pg(x, k)
    if v is _UNDEF or v is None:
        return 0
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, (int, float)):
        return 0 if v != v else v
    if isinstance(v, str):
        try:
            r = float(v.strip()) if v.strip() else 0.0
        except ValueError:
            return 0
        return 0 if r != r else r
    return 0


def _sign(a: float) -> int:
    return -1 if a < 0 else 1 if a > 0 else 0


# ---- findings --------------------------------------------------------------------------------------------------------------------

class _Findings:
    def __init__(self) -> None:
        self.list: List[Dict[str, Any]] = []

    def add(self, code: str, status: str, refs: Optional[List[str]] = None, detail: Any = None) -> None:
        text = "%s: %s%s." % (_TEMPLATES[code], _STATUS_TEXT[status], " (%s)" % detail if _truthy(detail) else "")
        self.list.append({"code": code, "status": status, "text": text, "refs": list(refs or [])})

    def verdict(self, code: str, v: Any, refs: Optional[List[str]] = None) -> None:
        if v.get("ok"):
            self.add(code, "pass", refs)
        else:
            self.add(code, "fail", refs, v.get("reason"))

    def check(self, code: str, port: Optional[Callable[..., Any]], core: Optional[Callable[[], Any]], artifact: Any, bundle: Any, refs: List[str],
              what: str) -> None:
        """Run `port` if supplied, else the core default; with neither, the artifact stays unverified."""
        try:
            v = port(artifact, bundle) if port else core() if core else None
        except Exception as e:  # noqa: BLE001 - a throwing verifier is a refutation
            v = {"ok": False, "reason": "verifier threw: %s" % e}
        if v is None:
            self.add(code, "unverified", refs, "no verifier for %s" % what)
        else:
            self.verdict(code, v, refs)


def _nul(e: Optional[str]) -> dict:
    return {"ok": True} if e is None else {"ok": False, "reason": e}


def _empty_summary() -> Dict[str, Any]:
    return {"admitted_under": None, "principal_keys": [], "answers": {"total": 0, "yes": 0, "no": 0, "partial": 0, "canaries": 0}, "refusals": [],
            "consent": None, "charged": None, "canary_accuracy": {"correct": 0, "asked": 0}, "attribution": {"pinned": False, "keys_to_check": []},
            "proven": [], "not_proven": list(_NOT_PROVEN)}


def _finish(f: _Findings, digest: Optional[str], summary: Dict[str, Any]) -> Dict[str, Any]:
    findings = sorted(f.list, key=lambda x: (_u16(x["code"]), _u16(",".join(x["refs"])), _u16(x["status"]), _u16(x["text"])))
    consistent = len(findings) > 0 and not any(x["status"] == "fail" for x in findings)
    pinned = [x for x in findings if x["code"] == "principal.pinned"]
    attributed = any(x["status"] == "pass" for x in pinned) and not any(x["status"] != "pass" for x in pinned)
    ok = consistent and attributed
    complete = not any(x["status"] == "unverified" for x in findings)
    if consistent and not attributed and summary["attribution"]["keys_to_check"]:
        summary["not_proven"].insert(0, "The bundle is internally consistent but NOT attributed to any known principal: verify these session-root keys out of band: %s."
                                     % ", ".join(summary["attribution"]["keys_to_check"]))
    unverified = sorted({x["code"] for x in findings if x["status"] == "unverified"}, key=_u16)
    if unverified:
        summary["not_proven"].append("Checked only through a supplied verifier, or not at all: %s." % ", ".join(unverified))
    body = {"ok": ok, "consistent": consistent, "attributed": attributed, "complete": complete, "digest": digest, "findings": findings, "summary": summary}
    return dict(body, report_digest=hash_canonical({"d": EVIDENCE_REPORT_DOMAIN, "r": body}))


def verify_evidence_bundle(bundle: Any, trust: Optional[dict] = None) -> Dict[str, Any]:
    """Replay a bundle against the reader's trust inputs (`trust`: siteKeys, principals, sessionRootDigest, minTier, jitTier, typedValues,
    credentials, canaryLabels, oracleKeys, judges, labelKeys, anchorGuardian, acc, verifiers; all optional). Returns the findings report
    {ok, consistent, attributed, complete, digest, findings, summary, report_digest}."""
    trust = {} if trust is None else trust
    if not isinstance(trust, dict):
        raise TypeError("trust must be an object")
    f = _Findings()
    summary = _empty_summary()
    te = acc_trust_error(trust.get("acc", _UNDEF))
    if te:
        f.add("trust.acc", "fail", [], te)
        return _finish(f, None, summary)
    pe = principals_trust_error(trust.get("principals", _UNDEF))
    if pe:
        f.add("trust.principals", "fail", [], pe)
        return _finish(f, None, summary)
    bad = bundle_shape_error(bundle)
    if bad:
        f.add("shape", "fail", [], bad)
        return _finish(f, None, summary)
    try:
        b = normalize_bundle(bundle)
        digest = evidence_digest(b)
    except Exception as e:  # noqa: BLE001
        f.add("shape", "fail", [], "not canonicalizable: %s" % e)
        return _finish(f, None, summary)
    f.add("shape", "pass")
    try:
        _replay(b, digest, trust, f, summary)
    except Exception as e:  # noqa: BLE001 - a fault inside the replay refutes the shape (fail closed)
        f.add("shape", "fail", [], "replay aborted: %s" % e)
    return _finish(f, digest, summary)


def _acc_context_for(S: dict, history: List[dict], params: dict, t: Any, schema: Any) -> Dict[str, Any]:
    """The verifier context (`intentV2.acc`) for a candidate action: pre-states of the site-local accumulators and monitor states."""
    state: Dict[str, Any] = {}
    for a in S["accumulators"]:
        if a["holder"]["kind"] != "site_local":
            continue
        if a["key"] is not None and acc_key_of(a, params) is None:
            continue  # the verifier fails the claim (missing key)
        state[a["id"]] = acc_pre_state(a, history, params, t, schema)
    return {"state": state, "monitors": {m["id"]: monitor_state(m, history) for m in S["monitors"]}}


def _replay(b: dict, digest: str, trust: dict, f: _Findings, summary: Dict[str, Any]) -> None:
    S = b["session_root"]
    session = b["subject"]["session"]
    aud = b["subject"]["aud"]
    doc = b["schema"]["doc"]
    # Consistency is checked against the keys the session root names; ATTRIBUTION (below) against the reader's pins.
    principals = sorted((p["key"] for p in S["principals"]), key=_u16)
    summary["principal_keys"] = principals
    s_ref = trust["sessionRootDigest"] if trust.get("sessionRootDigest") is not None else session_root_digest(S)
    ports = trust.get("verifiers") if trust.get("verifiers") is not None else {}
    # The reader's PQ pins (trust.principals[].pq_pk, out of band; NEVER the bundle's own S.principals).
    pq_pins = {p["key"]: p["pq_pk"] for p in (trust.get("principals") or []) if isinstance(p.get("pq_pk"), str)}
    site_keys = trust.get("siteKeys")

    # -- session root -------------------------------------------------------------------------------------------------------
    if S["session"] != session:
        f.add("session_root.signature", "fail", ["session_root"], "session root is for another session")
    else:
        f.check("session_root.signature", ports.get("sessionRoot"), lambda: verify_session_root(S, pq_pins), S, b, ["session_root"], "the session root")

    # -- statement ----------------------------------------------------------------------------------------------------------
    f.add("statement.commit", "pass" if S["intent_ref"] == b["statement"]["commit"] else "fail", ["statement"])
    opening = b["statement"].get("opening", _UNDEF)
    if opening is _UNDEF:
        f.add("statement.opening", "unverified", ["statement"], "the statement was not opened (it stays a commitment)")
    else:
        v = verify_intent(opening)
        if not v["ok"]:
            f.add("statement.opening", "fail", ["statement"], v.get("reason"))
        elif intent_ref(opening) != b["statement"]["commit"]:
            f.add("statement.opening", "fail", ["statement"], "the opening does not hash to the commitment")
        elif opening["principal"] not in principals:
            f.add("statement.opening", "fail", ["statement"], "signed by a key that is not a principal of the session")
        else:
            f.add("statement.opening", "pass", ["statement"])

    # -- schema -------------------------------------------------------------------------------------------------------------
    f.check("schema.signature", ports.get("schema"), (lambda: verify_action_schema(doc, site_keys)) if site_keys is not None else None, doc, b,
            ["schema"], "the action schema (no site keys supplied)")
    schema_digest = action_schema_digest(doc)
    f.add("schema.digest", "pass" if S["schema"]["digest"] == schema_digest and S["schema"]["aud"] == aud else "fail", ["schema"])

    # -- maps ---------------------------------------------------------------------------------------------------------------
    map_commits = {m["commit"] for m in b["maps"]}
    for m in b["maps"]:
        ref = ["map:%s" % _n(m["seq"])]
        if not _truthy(m.get("map", _UNDEF)):
            f.add("map.replay", "unverified", ref, "committed map not revealed")
            continue
        r = verify_intent_map(m["map"])
        if not r["ok"]:
            f.add("map.replay", "fail", ref, "; ".join(r["problems"][:3]))
        elif intent_map_digest(m["map"]) != m["commit"]:
            f.add("map.replay", "fail", ref, "the revealed map does not hash to its commit")
        else:
            f.add("map.replay", "pass", ref)

    # -- grants: G_0 and the delta chain (core intent_session caveat) -------------------------------------------------------
    grants: Dict[str, Dict[str, Any]] = {}
    g0 = b["root_grant"]
    cv = grant_session_caveat(g0)
    ok, why = verify_chain([g0], g0["issuer"], pq_pins=pq_pins)
    if not ok:
        f.add("root_grant", "fail", ["G_0"], why)
    elif g0["issuer"] not in principals:
        f.add("root_grant", "fail", ["G_0"], "not signed by a principal of the session")
    elif cv is None or intent_session_caveat_error(cv) is not None:
        f.add("root_grant", "fail", ["G_0"], (intent_session_caveat_error(cv) or "") if cv is not None else "no intent_session caveat")
    elif cv["session"] != session or not _se(cv["seq"], 0) or cv["root"] != s_ref:
        f.add("root_grant", "fail", ["G_0"], "intent_session caveat does not bind seq 0 of this session root")
    else:
        f.add("root_grant", "pass", ["G_0"])
        grants[g0["id"]] = {"cap": g0, "seq": 0}
    prev_id = g0["id"]
    for i, d in enumerate(b["deltas"]):
        want = i + 1
        ref = ["D_%d" % want]
        ok, why = verify_chain([d], d["issuer"], pq_pins=pq_pins)
        if not ok or d["issuer"] not in principals or "parent" in d:
            f.add("delta.signature", "fail", ref, why if not ok else "not a principal-signed root capability")
            continue
        f.add("delta.signature", "pass", ref)
        cv = grant_session_caveat(d)
        n_cv = sum(1 for k in d["caveats"] if _pg(k, "type") == "intent_session")
        why2: Optional[str] = None
        if cv is None or n_cv != 1:
            why2 = "no single intent_session caveat"
        elif intent_session_caveat_error(cv) is not None:
            why2 = intent_session_caveat_error(cv)
        elif cv["session"] != session:
            why2 = "bound to another session"
        elif cv["root"] != s_ref:
            why2 = "bound to another session root"
        elif not _se(cv["seq"], want):
            why2 = "seq %s where %d was expected (gap, duplicate or reorder)" % (_n(cv["seq"]), want)
        elif cv.get("prev", _UNDEF) != prev_id:
            why2 = "prev does not name the previous grant"
        if why2:
            f.add("delta.chain", "fail", ref, why2)
        else:
            f.add("delta.chain", "pass", ref)
            grants[d["id"]] = {"cap": d, "seq": want}
        prev_id = d["id"]

    # -- answers ------------------------------------------------------------------------------------------------------------
    verified: List[dict] = []
    for a in b["answers"]:
        qid = _pg(a, "question_id")
        ref = ["answer:%s" % _n(qid)]
        v = verify_intent_answer(a, principals)
        if not v["ok"]:
            f.add("answer.signature", "fail", ref, v.get("reason"))
            continue
        if a["session"] != session:
            f.add("answer.signature", "fail", ref, "answer for another session")
            continue
        f.add("answer.signature", "pass", ref)
        verified.append(a)
        f.add("answer.map", "pass" if a["map_digest"] in map_commits else "fail", ref)
        ux = a["ux"]
        if _truthy(ux.get("canary", _UNDEF)) or not _se(a["y"], 1):
            continue
        mn = (trust.get("minTier") or {}).get(a["verb"]) if isinstance(trust.get("minTier"), dict) else None
        if mn is not None:
            f.add("answer.tier", "pass" if friction_rank(ux["tier"]) >= friction_rank(mn) else "fail", ref, "%s vs minimum %s" % (_n(ux["tier"]), _n(mn)))
        if ux["tier"] == "typed":
            tv = (trust.get("typedValues") or {}).get(qid) if isinstance(trust.get("typedValues"), dict) else None
            if tv is None:
                f.add("answer.typed", "unverified", ref, "the typed value is not known to this verifier")
            else:
                f.add("answer.typed", "pass" if typed_digest(qid, tv) == ux.get("typed_digest", _UNDEF) else "fail", ref)
        if ux["tier"] == "device":
            wa = ux.get("webauthn")
            creds = trust.get("credentials")
            cred = creds.get(wa["credential_id"]) if _truthy(wa) and isinstance(creds, dict) else None
            if not _truthy(wa) or cred is None:
                f.add("answer.device", "unverified", ref, "unknown authenticator")
            else:
                r = verify_assertion(
                    {"authenticator_data": unb64u(wa["authenticator_data"]), "client_data_json": unb64u(wa["client_data_json"]), "signature": unb64u(wa["signature"]),
                     "public_key": cred["publicKey"]},
                    {"expected_challenge": device_challenge(qid, ux["rendered_digest"], a["y"], ux.get("action_digest")), "rp_id": cred.get("rpId"),
                     "origins": cred.get("origins"), "require_uv": True,
                     "stored_sign_count": cred["signCount"] if cred.get("signCount") is not None else 0})
                f.add("answer.device", "pass" if r["ok"] else "fail", ref, None if r["ok"] else r.get("reason"))
    real = [a for a in verified if not _truthy(a["ux"].get("canary", _UNDEF))]
    canaries = [a for a in verified if _truthy(a["ux"].get("canary", _UNDEF))]
    summary["answers"] = {"total": len(real), "yes": sum(1 for a in real if _se(a["y"], 1) and "partial" not in a), "no": sum(1 for a in real if _se(a["y"], 0)),
                          "partial": sum(1 for a in real if "partial" in a), "canaries": len(canaries)}
    summary["refusals"] = sorted((a["question_id"] for a in real if _se(a["y"], 0)), key=_u16)
    yes_count = sum(1 for a in real if _se(a["y"], 1))
    f.add("delta.backed", "pass" if yes_count >= len(b["deltas"]) else "fail", [], "%d delta(s), %d principal yes answer(s)" % (len(b["deltas"]), yes_count))

    # -- canaries: recomputed, the claimed summary is never trusted --------------------------------------------------------------
    labels = {c["question_id"]: c["label"] for c in b["canary_labels"]}
    false_yes = false_no = missing = 0
    canary_labels = trust.get("canaryLabels") if isinstance(trust.get("canaryLabels"), dict) else {}
    for a in canaries:
        label = canary_labels.get(a["question_id"])
        if label is None:
            label = labels.get(a["question_id"])
        if label is None:
            missing += 1
        elif _se(label, 0) and _se(a["y"], 1):
            false_yes += 1
        elif _se(label, 1) and _se(a["y"], 0):
            false_no += 1
    summary["canary_accuracy"] = {"correct": len(canaries) - missing - false_yes - false_no, "asked": len(canaries)}
    c = b["canaries"]
    if missing > 0:
        f.add("canaries.summary", "fail", [], "%d canary answer(s) without a known label" % missing)
    elif not _se(c["asked"], len(canaries)) or not _se(c["false_yes"], false_yes) or not _se(c["false_no"], false_no):
        f.add("canaries.summary", "fail", [], "claimed %s/%s/%s, recomputed %d/%d/%d" % (_n(c["asked"]), _n(c["false_yes"]), _n(c["false_no"]), len(canaries), false_yes, false_no))
    else:
        f.add("canaries.summary", "pass", [], "%d asked, %d false yes, %d false no" % (len(canaries), false_yes, false_no))

    # -- sequencer key sets (rule 15): replayed per root in issue order, versions monotone like core keyset_versions ------------
    acc_trust = trust.get("acc")

    def freshness(ks: dict) -> dict:
        out: Dict[str, Any] = {}
        if acc_trust is not None and acc_trust.get("max_receipt_age_s") is not None:
            out["max_receipt_age_ms"] = acc_trust["max_receipt_age_s"] * 1000
        if acc_trust is not None and acc_trust.get("max_keyset_age_s") is not None:
            out["max_keyset_age_ms"] = acc_trust["max_keyset_age_s"] * 1000
        if ks["tracked"] is not None:
            out["tracked"] = ks["tracked"]
        elif ks["minV"] is not None:
            out["min_keyset_version"] = ks["minV"]
        return out

    root_holders: Dict[str, dict] = {}
    for a in S["accumulators"]:
        if a["holder"]["kind"] == "sequenced":
            root_holders[a["holder"]["root"]] = a["holder"]
    accepted: List[dict] = []
    verified_sets: List[dict] = []  # signed under a pinned root and not a rollback (equivocating sets included): the tracked-version history
    equivocated: set = set()
    seqkeys = b["accumulator"].get("sequencer_keys")
    raw = list(seqkeys) if seqkeys is not None else []

    def cmp_sets(x: Any, y: Any) -> int:
        for k in ("issued_at", "version"):
            d = _sign(_num_or0(x, k) - _num_or0(y, k))
            if d:
                return d
        hx, hy = hash_canonical(x), hash_canonical(y)
        return -1 if _u16(hx) < _u16(hy) else 1 if _u16(hx) > _u16(hy) else 0

    sets = sorted(raw, key=functools.cmp_to_key(cmp_sets))
    tracked: Dict[str, Any] = {}
    by_version: Dict[str, dict] = {}
    for i, k in enumerate(sets):
        ref = "keyset#%d:%s" % (i, _n(k.get("version", _UNDEF)) if _is_obj(k) else "?")
        holder = root_holders.get(k["sequencer"]) if _is_obj(k) and isinstance(k.get("sequencer"), str) else None
        if holder is None:
            f.add("acc.keysets", "fail", [ref], "not signed by a sequencer root the session root pins")
            continue
        if not verify_sequencer_key_set(k, holder["root"], holder.get("root_pq_pk")):
            f.add("acc.keysets", "fail", [ref], "the key set does not verify under its pinned root")
            continue
        prev = tracked.get(holder["root"])
        if prev is not None and k["version"] < prev:
            f.add("acc.keysets", "fail", [ref], "version %s rolls back the tracked version %s" % (_n(k["version"]), _n(prev)))
            continue
        # Equivocation (core rule 15): two DIFFERENT sets under one root and version are both refused; an identical duplicate is not.
        slot = "%s#%s" % (holder["root"], _n(k["version"]))
        kd = sequencer_key_set_digest(k)
        seen = by_version.get(slot)
        if seen is not None and seen["digest"] != kd:
            equivocated.add(slot)
            verified_sets.append(k)
            f.add("acc.keysets.equivocation", "fail", [seen["ref"], ref], "two different key sets under version %s of one sequencer root" % _n(k["version"]))
            continue
        if seen is None:
            by_version[slot] = {"digest": kd, "ref": ref}
        verified_sets.append(k)
        tracked[holder["root"]] = max(prev if prev is not None else 0, k["version"])
        accepted.append(k)
        f.add("acc.keysets", "pass", [ref])
    accepted = [k for k in accepted if "%s#%s" % (k["sequencer"], _n(k["version"])) not in equivocated]

    def key_sets_at(root: str, t: Any) -> Dict[str, Any]:
        """In force = accepted sets of the root issued by admission (+ the core skew); the tracked state is the newest VERIFIED set issued by then."""
        own = [k for k in accepted if k["sequencer"] == root]
        newest = None
        for k in verified_sets:
            if k["sequencer"] == root and k["issued_at"] <= t and (newest is None or k["version"] > newest["version"]):
                newest = k
        poisoned = newest is not None and "%s#%s" % (root, _n(newest["version"])) in equivocated
        floor = newest["version"] if newest is not None else 0
        return {"sets": [k for k in own if k["issued_at"] <= t + RECEIPT_SKEW_MS and k["version"] >= floor],
                "minV": newest["version"] if newest is not None else None,
                "tracked": {"version": newest["version"], "digest": sequencer_key_set_digest(newest)} if newest is not None and not poisoned else None}

    # -- PCActns ------------------------------------------------------------------------------------------------------------
    by_digest: Dict[str, dict] = {}
    root_seq: Dict[str, int] = {}

    def effect_of(d: Any) -> Any:
        return next((e for e in b["effects"] if e.get("pcactn_digest") == d), None)

    def digest_of(p: Any) -> Optional[str]:
        try:
            return hash_canonical(p)
        except Exception:  # noqa: BLE001
            return None

    grants_by_seq = [g["cap"] for g in sorted(grants.values(), key=lambda g: g["seq"])]

    def epoch_idx_at(t: Any) -> int:
        """Index of the epoch in force at t (the last one issued at or before t, in issue order), or -1."""
        idx = -1
        for i, r in enumerate(b["revocation_epochs"]):
            if r["epoch"]["issued_at"] <= t:
                idx = i
        return idx

    # The admitted history, as the site's store held it: one event per accumulator-bearing PCActn, in event order.
    history: List[dict] = []
    for ev in b["accumulator"]["events"]:
        if any(h["id"] == ev["pcactn_digest"] for h in history):
            continue
        p = next((x for x in b["pcactns"] if digest_of(x) == ev["pcactn_digest"]), None)
        eff = effect_of(ev["pcactn_digest"])
        params = eff.get("params") if isinstance(eff, dict) else None
        if p is not None and _truthy(params if params is not None else _UNDEF):
            status = ev.get("status")
            history.append({"id": ev["pcactn_digest"], "verb": p["action"]["verb"], "resource": p["action"]["resource"], "params": params, "t": p["iat"],
                            "status": "committed" if status is None else status})

    def v2_context(p: dict, d: str, seq: Optional[int]) -> Optional[dict]:
        """The verifier state `decide_intent_v2` reads, rebuilt from the bundle (None when the bundle lacks the plaintext params)."""
        eff = effect_of(d)
        params = eff.get("params") if isinstance(eff, dict) else None
        if not _truthy(params if params is not None else _UNDEF) or seq is None:
            return None
        idx = next((i for i, h in enumerate(history) if h["id"] == d), -1)
        before = history[:idx] if idx >= 0 else [h for h in history if h["t"] <= p["iat"]]
        acc = _acc_context_for(S, before, params, p["iat"], {"verbs": doc["verbs"]})
        ri = epoch_idx_at(p["iat"])
        rev = b["revocation_epochs"][ri] if ri >= 0 else None
        rev_last = b["revocation_epochs"][ri - 1] if ri > 0 else None
        kv = {root: key_sets_at(root, p["iat"])["tracked"] for root in root_holders}
        session_ctx: Dict[str, Any] = {"root": S, "grants": grants_by_seq[:seq], "pq_pins": pq_pins}
        if rev is not None:
            session_ctx["revocation"] = rev
        if rev_last is not None:
            session_ctx["revocation_last"] = rev_last
        ctx: Dict[str, Any] = {
            "params": params, "schema": {"docs": [doc], "keys": site_keys if site_keys is not None else []}, "session": session_ctx,
            "acc": dict(acc, receipts=b["accumulator"].get("receipts") if b["accumulator"].get("receipts") is not None else [],
                        sequencer_keys=[k for root in root_holders for k in key_sets_at(root, p["iat"])["sets"]],
                        keyset_versions={root: t for root, t in kv.items() if t is not None}),
        }
        if acc_trust is not None:
            ctx["policy"] = {"acc": acc_trust}
        return ctx

    for p in b["pcactns"]:
        d = digest_of(p)
        if d is None:
            f.add("pcactn.verify", "fail", ["pcactn:?"], "not canonicalizable")
            continue
        by_digest[d] = p
        ref = ["pcactn:%s" % d]
        chain = p.get("cap_chain") if isinstance(p, dict) else None
        root = chain[0] if isinstance(chain, list) and len(chain) > 0 else None
        if not _truthy(root if root is not None else _UNDEF):
            f.add("pcactn.verify", "fail", ref, "empty capability chain")
            continue
        rid = root.get("id") if isinstance(root, dict) else None
        g = grants.get(rid) if isinstance(rid, str) else None
        same_root = g is not None and hash_canonical(g["cap"]) == hash_canonical(root)
        is_ = p.get("intent_session", _UNDEF)
        ctx = v2_context(p, d, g["seq"]) if is_ is not _UNDEF and same_root else None
        # The root's authority is pcactn.root (byte-equal to G_0 / a verified delta) plus principal.pinned (trust.principals): a non-Ed25519
        # root verifies only under the reader's pins, else it is refused.
        r = verify_pcactn_core(p, root, now=p["iat"], audience=aud, insecure_skip_plan_root_check=True, grant_from_artifact=True, pq_pins=pq_pins,
                               **({"intent_v2": ctx} if ctx is not None else {}))
        failed = sorted((ts_check_name(k) for k, st in r.checks.items() if st is False), key=_u16)
        v1f = [k for k in failed if k not in _V2_CHECKS]
        v2f = [k for k in failed if k in _V2_CHECKS]
        f.add("pcactn.verify", "fail" if v1f else "pass", ref, "%s: %s" % (", ".join(v1f), ts_reason(r.reason) or "") if v1f else None)
        if same_root:
            f.add("pcactn.root", "pass", ref, "G_0" if g["seq"] == 0 else "D_%d" % g["seq"])
            root_seq[d] = g["seq"]
        else:
            f.add("pcactn.root", "fail", ref, "rooted at a grant that is not G_0 or a verified delta of this session")
        if is_ is not _UNDEF:
            why: Optional[str] = None
            if _pg(is_, "session") != session:
                why = "another session"
            elif _pg(is_, "root") != s_ref:
                why = "another session root"
            elif _pg(is_, "schema") != schema_digest:
                why = "another schema"
            elif g is not None and not _se(_pg(is_, "seq"), g["seq"]):
                why = "seq %s but rooted at seq %d" % (_n(_pg(is_, "seq")), g["seq"])
            else:
                claims = _pg(is_, "acc")
                if claims is _UNDEF or claims is None:
                    claims = []
                if not isinstance(claims, list):
                    raise TypeError("is_.acc is not iterable")
                for cl in claims:
                    ev = next((e for e in b["accumulator"]["events"] if e["pcactn_digest"] == d and e["acc"] == _pg(cl, "id")), None)
                    if ev is None or not _se(ev["post"], _pg(cl, "post")):
                        why = "the signed claim %s.post = %s has no matching accumulator event" % (_n(_pg(cl, "id")), _n(_pg(cl, "post")))
            if why is None and v2f:
                why = "core v2 checks failed: %s" % ", ".join(v2f)
            if why is not None:
                f.add("pcactn.session", "fail", ref, why)
            elif ctx is None:
                f.add("pcactn.session", "unverified", ref, "the core v2 checks need the plaintext params of the effect record")
            else:
                f.add("pcactn.session", "pass", ref)
    subject = by_digest.get(b["subject"]["pcactn_digest"])
    f.add("subject.present", "pass" if subject is not None else "fail", ["pcactn:%s" % b["subject"]["pcactn_digest"]])
    s_seq = root_seq.get(b["subject"]["pcactn_digest"])
    summary["admitted_under"] = None if s_seq is None else "G_0" if s_seq == 0 else "D_%d" % s_seq

    # -- effects (no core format yet: signature through the port) ----------------------------------------------------------------
    for e in b["effects"]:
        ref = ["effect:%s" % _n(e["pcactn_digest"])]
        p = by_digest.get(e["pcactn_digest"])
        if p is None:
            f.add("effect.binding", "fail", ref, "no such PCActn in the bundle")
            continue
        if "params" not in e:
            f.add("effect.binding", "unverified", ref, "no raw params to bind")
        else:
            f.add("effect.binding", "pass" if params_digest(e["params"]) == p["action"]["params_digest"] else "fail", ref)
        charged = e.get("charged", _UNDEF)
        if _truthy(charged):
            cref = _pg(charged, "ref")
            name = cref[len("action.params."):] if isinstance(cref, str) and cref.startswith("action.params.") else None
            params = e.get("params", _UNDEF)
            bound = params.get(name, _UNDEF) if name is not None and _truthy(params) and isinstance(params, dict) else _UNDEF
            amount = _pg(charged, "amount")
            if not _is_num(bound) or not _is_num(amount):
                f.add("effect.charged", "unverified", ref, "no numeric %s to compare" % _n(cref))
            else:
                f.add("effect.charged", "pass" if amount <= bound else "fail", ref, "%s vs %s" % (_n(amount), _n(bound)))
                if e["pcactn_digest"] == b["subject"]["pcactn_digest"]:
                    summary["charged"] = {"amount": amount, "bound": bound}
        if "frame_violations" in e:
            fv = e["frame_violations"]
            f.add("effect.frame", "pass" if len(fv) == 0 else "fail", ref, ", ".join(sorted((_n(x) for x in fv), key=_u16)) if len(fv) else None)
        f.check("effect.signature", ports.get("effect"), None, e, b, ref, "effect records (no core format yet)")

    # -- JIT consent for an irreversible subject action (core action digest) -----------------------------------------------------
    if subject is not None and subject["action"].get("reversibility_class") == "irreversible":
        ref = ["pcactn:%s" % b["subject"]["pcactn_digest"]]
        ad = intent_action_digest(subject["action"])
        need = trust["jitTier"] if trust.get("jitTier") is not None else "typed"
        cons = next((a for a in real if _se(a["y"], 1) and a["ux"].get("consent_for_action") is True and a["ux"].get("action_digest", _UNDEF) == ad
                     and friction_rank(a["ux"]["tier"]) >= friction_rank(need)), None)
        if cons is not None:
            f.add("jit.consent", "pass", ref, "question %s, %s tier" % (_n(cons["question_id"]), _n(cons["ux"]["tier"])))
            summary["consent"] = {"question_id": cons["question_id"], "tier": cons["ux"]["tier"], "signer": cons["signer"]}
        else:
            f.add("jit.consent", "fail", ref, "no principal yes at %s tier or above bound to this action digest" % _n(need))

    # -- accumulators (core declarations and value rule) -------------------------------------------------------------------------
    decls = {a["id"]: a for a in S["accumulators"]}
    schema_verbs = {"verbs": doc["verbs"]}

    def value_of(decl: dict, d: str) -> Any:
        p = by_digest.get(d)
        eff = effect_of(d)
        params = eff.get("params") if isinstance(eff, dict) else None
        if p is None or not _truthy(params if params is not None else _UNDEF):
            return None
        v = acc_value_of(decl, p["action"]["verb"], params, schema_verbs)
        return v["val"] if v["ok"] else None

    running: Dict[str, Any] = {}
    for i, ev in enumerate(b["accumulator"]["events"]):
        ref = ["acc:%s#%d" % (ev["acc"], i)]
        decl = decls.get(ev["acc"])
        if decl is None:
            f.add("accumulator.declared", "fail", ref)
            continue
        p = by_digest.get(ev["pcactn_digest"])
        counted = ev.get("status") != "released" and ev.get("status") != "reverted"
        prev = running.get(ev["acc"], 0)
        expected: Any = None
        if not counted:
            expected = prev
        elif decl["agg"] == "count":
            expected = prev + 1
        elif decl["agg"] in ("sum", "max"):
            val = value_of(decl, ev["pcactn_digest"])
            if val is not None:
                expected = prev + val if decl["agg"] == "sum" else max(prev, val)
        if p is None:
            f.add("accumulator.arithmetic", "fail", ref, "event names a PCActn that is not in the bundle")
        elif expected is None:
            f.add("accumulator.arithmetic", "unverified" if ev["post"] >= prev else "fail", ref, "contribution not recomputable" if ev["post"] >= prev else "post decreased")
        else:
            f.add("accumulator.arithmetic", "pass" if ev["post"] == expected else "fail", ref,
                  None if ev["post"] == expected else "post %s, recomputed %s" % (_n(ev["post"]), _n(expected)))
        running[ev["acc"]] = ev["post"] if counted else prev
        if not counted:
            continue
        seq = root_seq.get(ev["pcactn_digest"]) if p is not None else None
        delta = ev.get("delta", _UNDEF)
        if delta is not _UNDEF and seq is not None and delta != seq:
            f.add("accumulator.cap", "fail", ref, "the event names a different admitting grant from the PCActn root")
            continue
        want_seq = seq if seq is not None else delta
        grant = next((g for g in grants.values() if _se(g["seq"], want_seq)), None)
        caps = [x for x in (cap_of(grant["cap"], ev["acc"], p["action"]["verb"]) if grant is not None and p is not None else None,
                            decl.get("domain_max") if _is_num(decl.get("domain_max")) else None, decl.get("cap") if _is_num(decl.get("cap")) else None)
                if x is not None]
        if not caps:
            f.add("accumulator.cap", "unverified", ref, "no cap stated for this accumulator")
        else:
            cap = min(caps)
            f.add("accumulator.cap", "pass" if ev["post"] <= cap else "fail", ref, "post %s, cap %s" % (_n(ev["post"]), _n(cap)))
    receipts = b["accumulator"].get("receipts") if b["accumulator"].get("receipts") is not None else []
    if b["accumulator"]["holder"] == "sequenced" and len(receipts) == 0:
        f.add("accumulator.receipts", "fail", ["accumulator"], "a sequenced accumulator without receipts")
    for i, r in enumerate(receipts):
        def core(r: Any = r) -> Optional[dict]:
            # None = the signature and freshness held but the contribution cannot be recomputed (params withheld): unverified.
            decl = decls.get(r["acc"])
            if decl is None or decl["holder"]["kind"] != "sequenced":
                return {"ok": False, "reason": "the receipt names an accumulator that is not sequenced in the session root"}
            holder = decl["holder"]
            if r["session"] != session or r["aud"] != aud:
                return {"ok": False, "reason": "receipt for another session or audience"}
            d = next((dd for dd, pp in by_digest.items() if pcactn_reservation_digest(pp) == r["pcactn_digest"]), None)
            if d is None:
                return {"ok": False, "reason": "the receipt reserves for a PCActn that is not in the bundle"}
            # Rule 15 freshness is judged at ADMISSION time (the reserved PCActn's iat), never at bundle-verification time.
            admitted_at = by_digest[d]["iat"]
            ks = key_sets_at(holder["root"], admitted_at)
            if not verify_receipt_against_holder(r, holder, ks["sets"], admitted_at, **freshness(ks)):
                return {"ok": False, "reason": "not signed by a key the pinned sequencer root listed, or not fresh, at admission time"}
            if not admitted_at <= r["expires_at"]:
                return {"ok": False, "reason": "the receipt had expired when the action was admitted"}
            val = value_of(decl, d)
            if val is None:
                return None
            if not receipt_arithmetic_ok(decl, r, val):
                return {"ok": False, "reason": "pre + delta does not give post for the reserved value"}
            return {"ok": True}
        rs = _pg(r, "seq")
        f.check("accumulator.receipts", ports.get("receipt"), core, r, b, ["receipt:%s#%s" % (_n(_pg(r, "acc")), _n(i if rs is _UNDEF or rs is None else rs))], "the reserved contribution (the effect params were withheld)")

    # -- W-B artifacts: facts, classifier verdicts, offer sets, label receipts ------------------------------------------------------
    oracle_keys = trust.get("oracleKeys")
    for i, x in enumerate(b.get("facts") or []):
        pk = oracle_keys.get(x["oracle"]) if _is_obj(x) and isinstance(x.get("oracle"), str) and isinstance(oracle_keys, dict) else None

        def fact_core(x: Any = x, pk: Any = pk) -> dict:
            w = validate_fact_wire(x)
            if w:
                return {"ok": False, "reason": w}
            return {"ok": True} if verify_artifact_sig(FACT_DOMAIN, x, pk) else {"ok": False, "reason": "bad oracle signature"}
        f.check("fact.signature", ports.get("fact"), fact_core if pk is not None else None, x, b, ["fact:%d" % i], "this fact (oracle key not pinned)")
    judges = trust.get("judges") if trust.get("judges") is not None else []
    for i, x in enumerate(b.get("classifier") or []):
        judge = x["judge"] if _is_obj(x) and isinstance(x.get("judge"), str) else None

        def cls_core(x: Any = x, judge: Any = judge) -> dict:
            w = validate_classifier_verdict_wire(x)
            if w:
                return {"ok": False, "reason": w}
            if x["session"] != session:
                return {"ok": False, "reason": "verdict for another session"}
            return {"ok": True} if verify_artifact_sig(INTENT_CLASSIFIER_DOMAIN, x, judge) else {"ok": False, "reason": "bad judge signature"}
        f.check("classifier.signature", ports.get("classifier"), None if judge is None or judge not in judges else cls_core, x, b, ["classifier:%d" % i],
                "this classifier verdict (judge not pinned)")
    for i, x in enumerate(b.get("offer_sets") or []):
        key = next((k for k in (site_keys or []) if _is_obj(x) and _pg(k, "kid") == x.get("kid", _UNDEF) and _pg(k, "alg") == "ed25519"), None)

        def offer_core(x: Any = x, key: Any = key) -> dict:
            w = validate_offer_set_wire(x)
            if w:
                return {"ok": False, "reason": w}
            if x["session"] != session:
                return {"ok": False, "reason": "offer set for another session"}
            return {"ok": True} if verify_artifact_sig(OFFER_SET_DOMAIN, x, key["pk"]) else {"ok": False, "reason": "bad site signature"}
        f.check("offer_set.signature", ports.get("offerSet"), offer_core if key is not None else None, x, b, ["offer_set:%d" % i], "this offer set (site key not pinned)")
    label_keys = trust["labelKeys"] if trust.get("labelKeys") is not None else [
        {"site": doc["site"], "kid": k["kid"], "pk": k["pk"]} for k in (site_keys or []) if k["alg"] == "ed25519"]
    for i, x in enumerate(b.get("labels") or []):
        def labels_core(x: Any = x) -> dict:
            e = verify_labels(x, label_keys)
            if e is None and _pg(x, "session") != session:
                return {"ok": False, "reason": "label receipt for another session"}
            return _nul(e)
        f.check("labels.signature", ports.get("labels"), labels_core if len(label_keys) > 0 else None, x, b, ["labels:%d" % i], "this label receipt (no site keys)")

    # -- ported artifacts with no core format --------------------------------------------------------------------------------------
    for v in b["verdicts"]:
        f.check("verdict.signature", ports.get("verdict"), None, v, b, ["verdict:%s" % _n(_pg(v, "pcactn_digest"))], "site verdicts (no core format yet)")
    for i, x in enumerate(b.get("settlements") or []):
        f.check("settlement.signature", ports.get("settlement"), None, x, b, ["settlement:%d" % i], "settlement records (no core format yet)")

    # -- revocation (core check_session_revocation, rule 13 step 7) ------------------------------------------------------------------
    # The bundle's epochs, in issue order, must form ONE append-only chain signed by the session's dedicated revocation authority: every
    # epoch is checked as of its own issue time with its predecessor as the tracked `last`; the epoch in force at the action time decides.
    epochs = b["revocation_epochs"]
    rev = S.get("revocation", _UNDEF)
    if len(epochs) == 0:
        f.add("revocation.epoch", "unverified", [], "no revocation epoch in the bundle")
    elif not _truthy(rev):
        f.add("revocation.epoch", "fail", [], "the session root names no revocation authority")
    else:
        authority = rev["key"]
        max_age = rev.get("max_age_s")
        max_age_ms = (DEFAULT_REVOCATION_MAX_AGE_S["default"] if max_age is None else max_age) * 1000
        pin = {authority: rev["pq_pk"]} if rev.get("pq_pk", _UNDEF) is not _UNDEF else None

        def rcheck(ev: dict, ids: list, now: Any, last: Any) -> dict:
            kw: Dict[str, Any] = {}
            if pin is not None:
                kw["pq_pins"] = pin
            if last is not None:
                kw["last"] = last
            return check_session_revocation(ev, session=session, authority=authority, ids=ids, now=now, max_age_ms=max_age_ms, **kw)

        history_ok = True
        for i, ev in enumerate(epochs):
            v = rcheck(ev, [], ev["epoch"]["issued_at"], epochs[i - 1] if i > 0 else None)
            if not v["ok"]:
                history_ok = False
            f.verdict("revocation.history", v, ["epoch#%d:%s" % (i, _n(ev["epoch"]["epoch"]))])
        if subject is None:
            f.add("revocation.epoch", "unverified", [], "no subject action time")
        else:
            ids = [session_revocation_id(session)] + [map_revocation_id(m["commit"]) for m in b["maps"]] + [delta_revocation_id(d["id"]) for d in b["deltas"]]
            idx = epoch_idx_at(subject["iat"])
            ev = epochs[idx] if idx >= 0 else None
            if ev is None:
                f.add("revocation.epoch", "fail", [], "every epoch was issued after the action")
            elif not history_ok:
                f.add("revocation.epoch", "fail", ["epoch:%s" % _n(ev["epoch"]["epoch"])], "the bundled epochs are not one append-only chain")
            else:
                f.verdict("revocation.epoch", rcheck(ev, ids, subject["iat"], epochs[idx - 1] if idx > 0 else None), ["epoch:%s" % _n(ev["epoch"]["epoch"])])

    # -- anchors ------------------------------------------------------------------------------------------------------------
    if _truthy(b["schema"].get("anchor", _UNDEF)):
        f.add("schema.anchor", "unverified", ["schema"], "the anchor names a log position without an inclusion proof")

    def anchorable(kind: Any, d: Any) -> bool:
        if kind == "evidence":
            return d == digest
        if kind == "statement":
            return d == b["statement"]["commit"]
        if kind == "map":
            return isinstance(d, str) and d in map_commits
        if kind == "schema":
            return d == schema_digest
        if kind == "observation":
            return any(answer_ref(a) == d for a in verified)
        return False

    if not any(a["kind"] == "evidence" for a in b["anchors"]):
        f.add("anchor.inclusion", "unverified", ["anchor:evidence"], "the bundle is not anchored")
    for a in b["anchors"]:
        ref = ["anchor:%s:%s" % (_n(a["kind"]), _n(a["index"]))]
        if not anchorable(a["kind"], a["digest"]):
            f.add("anchor.inclusion", "fail", ref, "the anchor names an artifact that is not this one")
            continue
        g = trust.get("anchorGuardian")
        if not _truthy(g if g is not None else _UNDEF):
            f.add("anchor.inclusion", "unverified", ref, "no anchor-log guardian key supplied")
            continue
        h = a["signed_tree_head"]
        okk = (h["principal"] == INTENT_ANCHOR_LOG and h["instance_id"] == g["instance"] and verify_tree_head(h, g["public"])
               and _se(a["proof"]["index"], a["index"]) and _se(a["proof"]["size"], h["size"])
               and verify_ledger_inclusion(h["root"], a["proof"], anchor_commit(a["kind"], a["digest"])))
        f.add("anchor.inclusion", "pass" if okk else "fail", ref)

    # -- attribution: the session-root keys that sign in this bundle must be pinned by the reader --------------------------------------
    # Everything above verifies against keys the bundle's own self-signed session root names, so it proves internal consistency only.
    # The revocation authority and the sequencer roots are named inside S, so they are attributed transitively once S's signer is pinned.
    signing = [S.get("signer", _UNDEF), g0["issuer"]] + [d["issuer"] for d in b["deltas"]] + [a["signer"] for a in b["answers"]]
    if _truthy(opening):
        signing.append(opening["principal"])
    keys = sorted({k for k in signing if isinstance(k, str)}, key=_u16)
    summary["attribution"]["keys_to_check"] = keys
    pins_in = trust.get("principals")
    if pins_in is None:
        f.add("principal.pinned", "unverified", keys, "no pinned principal keys: the bundle names its own principals; verify these keys out of band")
    else:
        pins = {p["key"]: p for p in pins_in}
        unpinned = [k for k in keys if k not in pins]

        def pq_mismatch(k: str) -> bool:
            pin = pins.get(k)
            sp = next((x for x in S["principals"] if x["key"] == k), None)
            return pin is not None and pin.get("pq_pk") != (sp.get("pq_pk") if sp is not None else None)
        mism = [k for k in keys if pq_mismatch(k)]
        if unpinned:
            f.add("principal.pinned", "fail", unpinned, "signing keys that are not pinned principals")
        elif mism:
            f.add("principal.pinned", "fail", mism, "the session root binds a different PQ key than the pin")
        else:
            f.add("principal.pinned", "pass", keys)
            summary["attribution"]["pinned"] = True

    # -- plain-language facts (only what passed) -------------------------------------------------------------------------------------
    proven: List[str] = []

    def passed(code: str) -> bool:
        return any(x["code"] == code and x["status"] == "pass" for x in f.list) and not any(x["code"] == code and x["status"] == "fail" for x in f.list)

    if summary["admitted_under"] and passed("pcactn.verify"):
        proven.append("The subject action was signed by the agent under %s, a grant signed by the session principal%s."
                      % (summary["admitted_under"], " (pinned)" if summary["attribution"]["pinned"] else " (NOT pinned)"))

    def who(k: str) -> str:
        return ("Pinned principal key %s" % k) if summary["attribution"]["pinned"] else "Session-root key %s (NOT pinned: not attributed to a known principal)" % k

    if summary["consent"]:
        proven.append('%s signed a %s-tier "yes" bound to this exact action (question %s).' % (who(summary["consent"]["signer"]), summary["consent"]["tier"], summary["consent"]["question_id"]))
    ch = summary["charged"]
    if ch and ch["amount"] <= ch["bound"]:
        proven.append("The charged amount %s is within the confirmed value %s." % (_n(ch["amount"]), _n(ch["bound"])))
    if summary["refusals"]:
        proven.append("The principal refused %d question(s): %s." % (len(summary["refusals"]), ", ".join(summary["refusals"])))
    if summary["canary_accuracy"]["asked"]:
        proven.append("Canary accuracy %d/%d." % (summary["canary_accuracy"]["correct"], summary["canary_accuracy"]["asked"]))
    if passed("accumulator.cap"):
        proven.append("Every accumulator post is within the cap of the grant that admitted it.")
    if passed("effect.frame"):
        proven.append("The site reports no change to monitored state outside the write set.")
    summary["proven"] = proven
