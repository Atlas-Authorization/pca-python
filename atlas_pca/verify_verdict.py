"""The resource-server verifier with the FULL verdict (the reference's ``verifyPCActn``): one call reports ``allow``, the recomputed risk ``r``,
the ``requiredThreshold``, every check as ``pass`` | ``fail`` | ``not-enforced`` | ``unsupported`` (the reference's check names: ``cap_chain``,
``freshness``, ...), the reasons in order, the budget after the decision and, when asked for, the per-check assurance report. It never raises:
any internal error becomes a fail-closed verdict.

``verify_pcactn_verdict(pcactn, opts, k1=None)``: ``pcactn`` is the object or its JSON text; ``opts`` is the reference's options object (an
absent key is "not given"; ``None`` under ``audience`` is the explicit opt-out): ``grant`` (the verifier's OWN stored grant, required), ``now``,
``audience``, ``insecureSkipPlanRootCheck``, ``context`` {params, subject, env, plan, planAuthorized, reversibilityClass, risk, budget,
recentActionTimes, revocationEpoch, beacon}, ``require`` (default :data:`DEFAULT_REQUIRED_CHECKS`), ``allowedSuites``, ``pqPins``, ``operation``,
``intent`` (the policy, snake_case keys as the reference: ``require``, ``min_fidelity_ppm``, ...; any other key is ignored), ``intentV2`` / ``freshAt`` (the Python-native state dicts of ``decide_intent_v2`` / ``decide_fresh_at``),
``enforce`` {taint, freshness, attestation {verifier, required}}, ``requireRiskInputs``, ``assurance``, ``requireAssurance``,
``allowUnsupported`` and ``hooks`` {attestation, threshold, revocation, zk}: callables ``f({"pcactn", "grant", "nowEpoch"}) -> {"enforced",
"ok"?, "reason"?, "t"?}``. ``k1`` is the caveat-language input of ``evaluate_k1``.

The legacy unbound-PQ opt-out (``allowUnboundPq``) is not offered: a pure-PQ or hybrid signer is always checked against its ``holder_pq``."""
from ._fin import fin
import math
import time
from typing import Any, Callable, Dict, List, Optional

from . import pca as _pca
from .authorize import assurance_report, evaluate_agent_caveats, read_envelope, refresh_assurance, unmet_assurance, _v2_env, LEGACY_POLARITY_DEGRADED
from .attestation_soft import requires_attestation
from .beacon import beacon_ref, verify_liveness_beacon
from .caveat_lang import discharge_action_digest, evaluate_k1, is_k1_caveat
from .decision import decision_of, fold_v2_reasons, model_paths_read
from .fresh_at import ABSENT as _FA_ABSENT, decide_fresh_at
from .intent_v2 import _UNDEF, _js_strict_eq, check_revocation_epoch, decide_intent_v2
from .policy_vm import decide, resolve_reversibility_class
from .predicates import _js_string
from .revocation_staleness import class_rank
from .taint import taint_gate

__all__ = ["verify_pcactn_verdict", "DEFAULT_REQUIRED_CHECKS"]

#: The minimum enforcement profile of the stateless verifier: it allows only when every one of these passed.
DEFAULT_REQUIRED_CHECKS = ("counter_format", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound")
_NO_BUDGET = "budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge"
_UNSUPPORTED_WHY = ": unsupported: the PCActn carries a feature this verifier does not implement (list it in allowUnsupported to accept it)"
_PLAN_DEFAULT_DENY = "default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)"
_ZK_NO_VERIFIER = ("zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not "
                   "present a proof")
_DEFAULT_EPOCH_MS = 60_000
_MAX_SAFE = 9007199254740991


class _Throw(Exception):
    """A fault the reference raises as an exception (it becomes a fail-closed verdict)."""


def _s(v: Any) -> str:
    return "undefined" if v is _UNDEF else _js_string(v)


def _truthy(v: Any) -> bool:
    if v is None or v is _UNDEF or v is False:
        return False
    if isinstance(v, (int, float)):
        return v != 0 and v == v
    return v != "" if isinstance(v, str) else True


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _fin(v: Any) -> bool:
    return _num(v) and fin(v)


def _get(d: Any, k: str) -> Any:
    return d.get(k, _UNDEF) if isinstance(d, dict) else _UNDEF


def _msg(e: BaseException) -> str:
    return str(e)


def _fail_closed(reason: str, checks: Optional[dict] = None) -> dict:
    c = dict(checks or {})
    c["malformed"] = "fail"
    return {"allow": False, "r": 1, "requiredThreshold": {"t": 3, "proof": "strong", "optimisticAllowed": False}, "checks": c, "reasons": [reason]}


def _wants_assurance(o: dict) -> bool:
    return o.get("assurance") is True or "requireAssurance" in o


def _assurance(p: Any, checks: dict, *, hooks: Optional[dict] = None, attestation_hook: Any = None, threshold_t: Any = None,
               degraded: Optional[dict] = None) -> dict:
    # the reference reports `unsupported` only for the checks' own status and a carried bond_ref: no backend probing, no bare-report rules
    return assurance_report(p if isinstance(p, dict) else None, checks, degraded, hooks=hooks if hooks is not None else {}, attestation_hook=attestation_hook,
                            threshold_t=threshold_t, allow_unbound_pq=False, unsupported_suites=False)


def verify_pcactn_verdict(pcactn: Any, opts: Optional[dict] = None, k1: Optional[dict] = None) -> dict:
    """The full verdict of the flagship ``verifyPCActn`` (see the module doc). Total."""
    o = opts if isinstance(opts, dict) else {}
    try:
        v = _run(pcactn, o, k1)
    except Exception as e:  # noqa: BLE001 - totality: any internal error is a fail-closed verdict
        v = _fail_closed("verifier error (fail closed): %s" % _msg(e))
    # a verdict that stopped before the checks ran (undecodable, wire, verifier error) still reports its outcomes when asked
    if _wants_assurance(o) and "assurance" not in v:
        v["assurance"] = _assurance(None, v["checks"])
    return v


def _decode(text: Any) -> "tuple[Any, Optional[str]]":
    if _pca.artifact_too_large(text):
        return None, _pca.ARTIFACT_SIZE_REASON
    try:
        v = _pca.strict_parse(text)
    except Exception as e:  # noqa: BLE001
        return None, _msg(e)
    if not isinstance(v, dict):
        return None, "decodePCActn: not an object"
    return v, None


def _run_hook(st: dict, name: str, hook: Any, hctx: dict, fail: Callable[[str, str], None]) -> bool:
    """The hook seam: no hook reports not-enforced; a hook that raises (or answers null) denies as malformed. True iff the hook enforced."""
    res = hook(hctx) if hook is not None else {}
    if res is None:
        raise _Throw("Cannot read properties of null (reading 'enforced')")
    res = res if isinstance(res, dict) else {}
    if not _truthy(res.get("enforced")):
        st[name] = "not-enforced"
        return False
    if _truthy(res.get("ok")):
        st[name] = "pass"
    else:
        why = res.get("reason")
        fail(name, "rejected" if why is None else _s(why))
    return True


def _core(p: dict, grant: dict, o: dict, now: Any, hooks: dict, enforce: dict, v2: Any, fresh_at: Any):
    """The core verifier with the reference's statuses and reason texts. ``plan_root_authorized`` is reported not-enforced here (the server
    decides it from its own plan context). Returns ``(checks, first_failure_reason)``."""
    st: Dict[str, str] = {}
    first: List[Optional[str]] = [None]

    def fail(name: str, why: str) -> None:
        st[name] = "fail"
        if first[0] is None:
            first[0] = "%s: %s" % (name, why)

    allowed = o.get("allowedSuites") if isinstance(o.get("allowedSuites"), list) else None
    try:
        st["wire"] = "pass"
        if _js_strict_eq(p.get("ver", _UNDEF), _pca.PCACTN_VERSION):
            st["version"] = "pass"
        else:
            fail("version", "unsupported ver %s (this verifier requires %d)" % (_s(p.get("ver", _UNDEF)), _pca.PCACTN_VERSION))

        # audience: the signed aud must equal this verifier's audience; None is the explicit opt-out; absent fails closed
        has_aud = isinstance(p.get("aud"), str) and p["aud"] != ""
        if "audience" not in o:
            if has_aud:
                fail("audience", "PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or audience: null to accept any)")
            else:
                st["audience"] = "not-enforced"
        elif o["audience"] is None:
            st["audience"] = "not-enforced"
        elif _js_strict_eq(p.get("aud", _UNDEF), o["audience"]):
            st["audience"] = "pass"
        else:
            fail("audience", "aud does not match this resource server / instance")

        iat, exp = p["iat"], p["exp"]
        if not _pca._is_safe_int(now):
            fail("validity", "the verifier clock is not a safe integer epoch-ms")
        elif not exp > iat:
            fail("validity", "exp must be greater than iat")
        elif exp - iat > _pca.MAX_LIFETIME_MS:
            fail("validity", "lifetime exceeds %d ms" % _pca.MAX_LIFETIME_MS)
        elif iat > now + _pca.MAX_SKEW_MS:
            fail("validity", "iat is in the future (clock skew)")
        elif now > exp:
            fail("validity", "the PCActn has expired")
        else:
            st["validity"] = "pass"

        # the capability chain: non-empty, rooted at the grant, then the walk
        chain = p.get("cap_chain") if isinstance(p.get("cap_chain"), list) else []
        if not chain:
            fail("cap_chain", "empty chain")
        elif _pca.cap_hash(chain[0]) != _pca.cap_hash(grant):
            fail("cap_chain", "chain root is not the grant")
        else:
            ok, why = _pca.verify_chain(chain, grant.get("issuer"), allowed, trusted_root=grant)
            if ok:
                st["cap_chain"] = "pass"
            else:
                fail("cap_chain", why or "invalid")

        # grant_ref_bound (normative): the signed grant_ref is the id of the ROOT capability of the presented chain
        root = chain[0] if chain and isinstance(chain[0], dict) else None
        root_id = root.get("id") if root is not None else None
        gref = p.get("grant_ref")
        if isinstance(gref, str) and gref != "" and isinstance(root_id, str) and gref == root_id:
            st["grant_ref_bound"] = "pass"
        else:
            fail("grant_ref_bound", "grant_ref is not the id of the root capability in cap_chain")

        # plan inclusion: the leaf is recomputed from the action itself
        plan = p["plan"]
        cond = plan.get("conditions_digest")
        if cond is None:
            cond = _pca.conditions_digest()
        if _pca.verify_inclusion(plan["root"], plan["inclusion_proof"], _pca._plan_leaf(plan["node_id"], p["action"], cond)):
            st["plan_inclusion"] = "pass"
        else:
            fail("plan_inclusion", "action is not a node of the committed plan")
        st["plan_root_authorized"] = "not-enforced"

        # the leaf-holder signature over the canonical body, dispatched by `alg`
        if chain:
            leaf_cap = chain[-1]
            alg = p.get("alg")
            shown = "ed25519" if alg is None else alg
            if allowed is not None and not (isinstance(shown, str) and shown in allowed):
                err = "signature suite '%s' is not allowed by this verifier's suite policy" % _s(shown)
            else:
                err = _pca.pq_binding_error(alg, p.get("pq_pk"), leaf_cap.get("holder_pq"), "leaf")
            if err is not None:
                fail("leaf_signature", err)
            elif isinstance(p.get("sig"), str) and _pca._verify_suite(
                    p, leaf_cap.get("holder"), _pca.threshold_message(p),
                    _pca._resolve_pq_key(leaf_cap.get("holder"), p.get("pq_pk"), holder_pq=leaf_cap.get("holder_pq"))):
                st["leaf_signature"] = "pass"
            else:
                fail("leaf_signature", "signature does not verify under the leaf holder key / suite")
        else:
            fail("leaf_signature", "signature does not verify under the leaf holder key / suite")

        c = p.get("counter")
        if _pca._is_safe_int(c) and c >= 0:
            st["counter_format"] = "pass"
        else:
            fail("counter_format", "missing or not a non-negative safe integer")

        # Intent Layer M2: reported iff the PCActn carries `intent` or the policy is active
        sess = p.get("intent_session")
        sess = sess if isinstance(sess, dict) else {}
        status, why = _pca.decide_intent_binding(p.get("intent"), grant, o.get("intent"), sess.get("session"), sess.get("map_form"))
        if status == "pass":
            st["intent"] = "pass"
        elif status == "fail":
            fail("intent", why)
        # Intent Layer v2
        for cc in decide_intent_v2(p, grant, v2, now)["checks"]:
            if cc["ok"]:
                st[cc["name"]] = "pass"
            else:
                fail(cc["name"], cc.get("reason") if cc.get("reason") is not None else "rejected")
        # consistency token
        fa = decide_fresh_at(p["fresh_at"] if "fresh_at" in p else _FA_ABSENT, fresh_at, now)
        if fa["status"] == "pass":
            st["fresh_at"] = "pass"
        elif fa["status"] == "fail":
            fail("fresh_at", fa["reason"])

        # M1 taint gate
        tg_cfg = enforce.get("taint")
        if _truthy(tg_cfg):
            try:
                tg_cfg = tg_cfg if isinstance(tg_cfg, dict) else {}
                tg = taint_gate(p.get("provenance"), tg_cfg.get("registry"), tg_cfg.get("resourceGraph", tg_cfg.get("resource_graph")),
                                tg_cfg.get("maxTaint", tg_cfg.get("max_taint")))
            except Exception as e:  # noqa: BLE001
                tg = {"ok": False, "reason": "taint gate error (fail closed): %s" % _msg(e)}
            if tg["ok"]:
                st["taint_gate"] = "pass"
            else:
                fail("taint_gate", tg["reason"])
        else:
            st["taint_gate"] = "not-enforced"

        # M3 freshness gate: its check is named `freshness`
        g = enforce.get("freshness")
        if _truthy(g):
            g = g if isinstance(g, dict) else {}
            epoch_ms = g.get("epochMs")
            epoch_ms = _DEFAULT_EPOCH_MS if epoch_ms is None else epoch_ms
            fnow = g.get("now")
            fnow = now if fnow is None else fnow
            skew = max(0, g["clockSkewMs"]) if _fin(g.get("clockSkewMs")) else 0
            max_age = g.get("maxAgeMs")
            fr = p.get("freshness")
            fr = fr if isinstance(fr, dict) else {}
            if not (_num(epoch_ms) and epoch_ms > 0) or not _fin(max_age) or max_age < 0:
                fail("freshness", "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)")
            elif not isinstance(fr.get("beacon_ref"), str) or fr["beacon_ref"] == "" or not _pca._is_safe_int(fr.get("epoch")) or fr["epoch"] <= 0:
                fail("freshness", "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)")
            else:
                anchor = fr["epoch"] * epoch_ms
                if anchor > fnow + skew:
                    fail("freshness", "freshness anchor is in the future")
                elif fnow - anchor > max_age:
                    fail("freshness", "freshness anchor is stale (older than %s ms)" % _s(max_age))
                else:
                    st["freshness"] = "pass"

        hctx = {"pcactn": p, "grant": grant, "nowEpoch": now}
        # M5 attestation: the gate's verifier takes the slot; with the gate on, a not-enforced result fails closed unless not required
        gate = enforce.get("attestation")
        gate = gate if _truthy(gate) else None
        att = gate.get("verifier") if isinstance(gate, dict) else None
        att = att if att is not None else hooks.get("attestation")
        _run_hook(st, "attestation", att, hctx, fail)
        required_gate = gate.get("required") if isinstance(gate, dict) else None
        if gate is not None and _truthy(True if required_gate is None else required_gate) and st.get("attestation") == "not-enforced":
            fail("attestation", "attestation required but the verifier reported not-enforced / no document (fail closed)")
        _run_hook(st, "threshold", hooks.get("threshold"), hctx, fail)
        _run_hook(st, "revocation", hooks.get("revocation"), hctx, fail)
        # a carried zk proof that no zk verifier enforced is never silently accepted
        if "zk_compliance" in p:
            _run_hook(st, "zk_compliance", hooks.get("zk"), hctx, fail)
            if st.get("zk_compliance") == "not-enforced":
                st["zk_compliance"] = "fail"
                if first[0] is None:
                    first[0] = _ZK_NO_VERIFIER
        if "bond_ref" in p:
            st["bond"] = "not-enforced"
    except Exception as e:  # noqa: BLE001 - malformed input never raises; it simply denies
        st["malformed"] = "fail"
        if first[0] is None:
            first[0] = "malformed PCActn: %s" % _msg(e)
    return st, first[0]


class _State:
    """The verdict combinator: ordered checks and ordered reasons."""

    def __init__(self) -> None:
        self.checks: Dict[str, str] = {}
        self.reasons: List[str] = []

    def fail(self, name: str, why: str) -> None:
        self.checks[name] = "fail"
        self.reasons.append("%s: %s" % (name, why))

    def fail_raw(self, name: str, reason: str) -> None:
        self.checks[name] = "fail"
        self.reasons.append(reason)

    def has_fail(self) -> bool:
        return "fail" in self.checks.values()


def _hook_int(h: Any) -> Optional[float]:
    """The threshold a hook reported as the verified core reads it: floor, NaN / non-number unreported, the infinities clamped to the safe-integer extremes."""
    if not _num(h) or h != h:
        return None
    if h >= _MAX_SAFE:
        return _MAX_SAFE
    if h <= -_MAX_SAFE:
        return -_MAX_SAFE
    return math.floor(h)


def _needs_model_rules(grant: Any) -> bool:
    env = read_envelope(grant)
    return env is not None and (any(k in env for k in ("units", "tighten", "model_polarity", "actions")) or len(model_paths_read([env.get("predicates")])) > 0)


def _unmet(report: dict, req: Any) -> Optional[str]:
    """The reference's ``unmetAssurance`` over a requirement given as JSON: the one ``unmet_assurance``, which refuses an unknown key or value
    (a ``threshold`` that is not a list included) fail closed."""
    if not isinstance(req, dict):
        return None
    return unmet_assurance(report, req)


def _run(pcactn: Any, o: dict, k1: Optional[dict]) -> dict:
    p0 = pcactn
    if isinstance(pcactn, (str, bytes, bytearray)):
        p0, why = _decode(pcactn)
        if why is not None:
            return _fail_closed("undecodable PCActn: " + why)
    if not isinstance(p0, (dict, list)):
        return _fail_closed("PCActn is not an object")

    now = o.get("now")
    if now is None:
        now = int(time.time() * 1000)
    grant_o = o.get("grant", _UNDEF)
    grant = grant_o if isinstance(grant_o, dict) else None
    op = o.get("operation") if isinstance(o.get("operation"), dict) else None
    ctx_in = o.get("context") if isinstance(o.get("context"), dict) else {}
    ctx = dict(ctx_in)
    # the operation's params are the action params (predicates, caveats, digest); a context that disagrees is flagged below
    ctx_params = ctx_in.get("params", _UNDEF)
    if op is not None and "params" in op:
        ctx["params"] = op["params"]
    hooks_in = o.get("hooks") if isinstance(o.get("hooks"), dict) else {}
    hooks = dict(hooks_in)
    enforce = o.get("enforce") if isinstance(o.get("enforce"), dict) else {}

    # F-1: remember the threshold the hook says it enforced, so it can be compared with the SERVER-derived t below
    hook_t: List[Any] = [_UNDEF]
    user_threshold = hooks_in.get("threshold")
    if _truthy(user_threshold):
        def threshold(hctx: dict) -> Any:
            r = user_threshold(hctx)
            if isinstance(r, dict) and _truthy(r.get("enforced")):
                hook_t[0] = r.get("t", _UNDEF)
            return r
        hooks["threshold"] = threshold

    # Rules 20 and 21 read the signed envelope of the stored grant: when it carries any, the v2 pipeline needs the plaintext params and the host env
    needs_model = grant is not None and _needs_model_rules(grant)
    v2: Any = None
    if _truthy(o.get("intentV2")) or needs_model:
        v2 = dict(o["intentV2"]) if isinstance(o.get("intentV2"), dict) else {}
        for k in ("params", "env"):
            if v2.get(k) is None:
                if k in ctx:
                    v2[k] = ctx[k]
                else:
                    v2.pop(k, None)
    fresh_at = o.get("freshAt")

    # a wire-form failure is terminal: nothing else is evaluated on a malformed object
    wire = _pca.validate_wire_v2(p0)
    if wire is not None:
        return _fail_closed("wire: " + wire, {"wire": "fail"})
    p: dict = p0
    if grant is None:
        raise _Throw("Cannot read properties of %s (reading 'id')" % ("null" if grant_o is None else "undefined"))
    core_st, core_reason = _core(p, grant, o, now, hooks, enforce, v2, fresh_at)

    vs = _State()
    vs.checks.update(core_st)
    unsupported: List[str] = []
    if "bond_ref" in p and vs.checks.get("bond") == "not-enforced":
        unsupported.append("bond")
    core_allow = "fail" not in core_st.values()
    if not core_allow and core_reason is not None:
        vs.reasons.append(core_reason)
    v2d = None
    if "intent_session" in p or needs_model:
        v2d = decide_intent_v2(p, grant, v2, now)
        # the core keeps only its FIRST failure reason; the v2 checks are the escalate-class ones, so every failed one is reported
        vs.reasons = fold_v2_reasons(vs.reasons, v2d["checks"])

    # server-side PQ pin for a non-Ed25519 grant (fail closed: no pin for the issuer, or a different key, denies)
    pq_pins = o.get("pqPins") if isinstance(o.get("pqPins"), dict) else None
    if pq_pins is not None:
        alg = grant.get("alg")
        alg = "ed25519" if alg is None else alg
        issuer = grant.get("issuer")
        has_pin = isinstance(issuer, str) and issuer in pq_pins
        pin = pq_pins[issuer] if has_pin else None
        if alg == "ed25519":
            if has_pin:
                vs.fail("pq_pin", "the grant issuer is pinned to a post-quantum key; a classical grant is refused")
            else:
                vs.checks["pq_pin"] = "pass"
        elif isinstance(pin, str) and isinstance(grant.get("pq_pk"), str) and pin == grant["pq_pk"]:
            vs.checks["pq_pin"] = "pass"
        elif not has_pin:
            vs.fail("pq_pin", "no server-side PQ pin for the grant issuer (suite %s)" % _s(alg))
        else:
            vs.fail("pq_pin", "the grant pq_pk does not match the server-side pin")

    # grant_ref binds the object to this grant
    if isinstance(p.get("grant_ref"), str) and _js_strict_eq(p["grant_ref"], grant.get("id", _UNDEF)):
        vs.checks["grant_ref"] = "pass"
    else:
        vs.fail("grant_ref", "does not reference the supplied grant")

    action = p.get("action") if isinstance(p.get("action"), dict) else {}
    signed_digest = action.get("params_digest", _UNDEF)

    # the proof must be for the operation the server will execute: verb, resource and (when given) the exact params
    if op is not None:
        ov, orr = op.get("verb"), op.get("resource")
        signed = "%s on %s" % (_s(action.get("verb", _UNDEF)), _s(action.get("resource", _UNDEF)))
        if not isinstance(ov, str) or not isinstance(orr, str):
            vs.fail("operation", "the server operation has no verb / resource (fail closed)")
        elif not _js_strict_eq(action.get("verb", _UNDEF), ov) or not _js_strict_eq(action.get("resource", _UNDEF), orr):
            vs.fail("operation", "the proof is for %s, but this operation is %s on %s" % (signed, ov, orr))
        elif "params" in op and not _js_strict_eq(_pca.hash_canonical(op["params"]), signed_digest):
            vs.fail("operation", "the proof's params_digest does not match the params of this %s operation" % ov)
        elif "params" in op and ctx_params is not _UNDEF and _pca.hash_canonical(ctx_params) != _pca.hash_canonical(op["params"]):
            vs.fail("operation", "context.params differ from the operation params")
        else:
            vs.checks["operation"] = "pass"

    # params plaintext must open the committed digest
    if "params" in ctx:
        if _js_strict_eq(_pca.hash_canonical(ctx["params"]), signed_digest):
            vs.checks["params_digest"] = "pass"
        else:
            vs.fail("params_digest", "supplied params do not hash to action.params_digest")
    else:
        vs.checks["params_digest"] = "not-enforced"

    # the verifier's own copy of the plan must be the committed one
    plan_o = ctx.get("plan", _UNDEF)
    plan_supplied = _truthy(plan_o)
    plan_wire = p.get("plan") if isinstance(p.get("plan"), dict) else {}
    plan_nodes: Optional[list] = None
    root_matches = False
    if plan_supplied:
        if not isinstance(plan_o, list):
            raise _Throw("ctx.plan.map is not a function")
        plan_nodes = plan_o
        root_matches = _js_strict_eq(_pca.merkle_root([_pca.plan_node_leaf(n) for n in plan_o]), plan_wire.get("root", _UNDEF))
    skip = o.get("insecureSkipPlanRootCheck") is True
    auth = ctx.get("planAuthorized", _UNDEF)
    if not plan_supplied:
        if skip:
            vs.checks["plan_root_authorized"] = "not-enforced"
        else:
            vs.fail("plan_root_authorized", _PLAN_DEFAULT_DENY)
    elif not root_matches:
        vs.fail("plan_root_authorized", "known plan does not match plan.root")
    elif auth is True:
        vs.checks["plan_root_authorized"] = "pass"
    elif auth is False:
        vs.fail("plan_root_authorized", "the plan root has not been authorized by the principal")
    elif skip:
        vs.checks["plan_root_authorized"] = "not-enforced"
    else:
        vs.fail("plan_root_authorized", _PLAN_DEFAULT_DENY)

    # the guardian-signed revocation epoch (reported as `freshness`)
    if _truthy(ctx.get("revocationEpoch")):
        re_ = ctx["revocationEpoch"] if isinstance(ctx["revocationEpoch"], dict) else {}
        fr = p.get("freshness") if isinstance(p.get("freshness"), dict) else {}
        last = re_.get("lastAcceptedEpoch")
        r = check_revocation_epoch(
            re_.get("epoch"), re_.get("guardianPublic", _UNDEF), now, grant.get("id", _UNDEF), _UNDEF if last is None else last,
            fr.get("epoch", _UNDEF), None, re_["maxAgeMs"] if re_.get("maxAgeMs") is not None else _UNDEF)
        # an `enforce.freshness` failure from the core stands (a passing epoch never overwrites it)
        if r["ok"]:
            if vs.checks.get("freshness") != "fail":
                vs.checks["freshness"] = "pass"
        else:
            vs.fail("freshness", r.get("reason") or "revocation epoch rejected")
    elif "freshness" not in vs.checks:
        vs.checks["freshness"] = "not-enforced"

    # the dead-man liveness beacon
    bc = ctx.get("beacon")
    if _truthy(bc):
        bc = bc if isinstance(bc, dict) else {}
        b = bc.get("beacon")
        r = verify_liveness_beacon(b, bc.get("issuers"), now, bc.get("instance"), grant.get("id"), bc.get("pqPins") if _truthy(bc.get("pqPins")) else None)
        last = bc.get("lastAcceptedSeq")
        replayed = bool(r["ok"] and last is not None and _num(b.get("seq")) and _num(last) and b["seq"] < last)
        fr = p.get("freshness") if isinstance(p.get("freshness"), dict) else {}
        ref_binds = bool(r["ok"] and not replayed and isinstance(fr.get("beacon_ref"), str) and fr["beacon_ref"] == beacon_ref(b))
        if not r["ok"]:
            vs.fail("beacon", r.get("reason") or "beacon rejected")
        elif replayed:
            vs.fail("beacon", "beacon seq %s is older than the last accepted %s (replay)" % (_s(b.get("seq", _UNDEF)), _s(last)))
        elif not ref_binds:
            vs.fail("beacon", "PCActn freshness.beacon_ref does not bind the presented beacon")
        else:
            vs.checks["beacon"] = "pass"
    else:
        vs.checks["beacon"] = "not-enforced"

    # require-when-bound: a grant whose agent_binding constrains the model / measurement / operator / weights REQUIRES a bound attestation
    env = read_envelope(grant)
    if env is not None and requires_attestation(env.get("agent_binding")) and vs.checks.get("attestation") != "pass":
        vs.fail("attestation", "the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED")

    chain = p.get("cap_chain") if isinstance(p.get("cap_chain"), list) else []
    depth = max(0, len(chain) - 1)
    # fail-closed default: an ABSENT budget becomes a DENY-METERED budget (B=0)
    budget_given = "budget" in ctx
    budget_ctx = ctx.get("budget")
    budget_in = budget_ctx if budget_ctx is not None else {"B": 0, "tau": now, "asOf": now}
    vs.checks["budget"] = "pass" if _truthy(budget_ctx) else "not-enforced"
    if not budget_given:
        vs.reasons.append(_NO_BUDGET)

    # taint: ONLY a verifier-supplied value counts (the agent's own provenance.taint_level can only lower risk)
    risk = dict(ctx["risk"]) if isinstance(ctx.get("risk"), dict) else {}
    req_inputs = o.get("requireRiskInputs")
    if isinstance(req_inputs, list) and req_inputs:
        missing = [k if isinstance(k, str) else _s(k) for k in req_inputs
                   if not (isinstance(k, str) and _fin(risk.get(k))) and not (k == "semanticDistance" and "plan" in ctx)]
        if missing:
            vs.fail("risk_inputs", "required risk input(s) not supplied by the server: %s" % ", ".join(missing))
        else:
            vs.checks["risk_inputs"] = "pass"

    # reversibility: the verifier's authoritative class wins; the agent may only be STRICTER
    declared = action.get("reversibility_class", _UNDEF)
    reversibility = declared
    server_class = ctx.get("reversibilityClass")
    if server_class is not None:
        dr, sr = class_rank(None if declared is _UNDEF else declared), class_rank(server_class)
        if dr < sr:
            vs.fail("reversibility", "declared class '%s' is less restrictive than the authoritative '%s'" % (_s(declared), _s(server_class)))
        else:
            vs.checks["reversibility"] = "pass"
        reversibility = declared if dr > sr else server_class
    inner: Dict[str, Any] = {"verb": action.get("verb"), "resource": action.get("resource")}
    if "params" in ctx:
        inner["params"] = ctx["params"]
    if reversibility is not _UNDEF and reversibility is not None:
        inner["reversibility_class"] = reversibility
    action_ctx: Dict[str, Any] = {"action": inner}
    if ctx.get("subject") is not None:
        action_ctx["subject"] = ctx["subject"]
    pred_env = _v2_env(p, grant, v2, now, ctx.get("env")) if "intent_session" in p else ctx.get("env")
    if pred_env is not None:
        action_ctx["env"] = pred_env
    # signed `tool_binding` (D): binds the semantic firewall (tool_schema caveats) to the tool the agent signed
    if isinstance(p.get("tool_binding"), str):
        action_ctx["toolBinding"] = p["tool_binding"]

    din: Dict[str, Any] = {"grant": grant, "trustedRoot": grant, "action": action_ctx, "risk": risk, "budget": budget_in, "now": now,
                           "caveatContext": {"delegationDepth": depth}}
    if pq_pins is not None:
        din["pqPins"] = pq_pins
    if isinstance(plan_o, list):
        din["plan"] = plan_o
    if "node_id" in plan_wire:
        din["nodeId"] = plan_wire["node_id"]
    if ctx.get("recentActionTimes") is not None:
        din["caveatContext"]["recentActionTimes"] = ctx["recentActionTimes"]
    if k1 is not None:
        din["k1"] = {kk: vv for kk, vv in k1.items() if kk != "narrow"}
        din["k1"]["action_digest"] = discharge_action_digest(p)
    if _num(p.get("caution")):
        din["rFloor"] = p["caution"]
    d = decide(din)
    release = d.get("releaseGuardianShare") is True

    # caveats added by delegation hops (beyond the root's) are conjunctive too
    k1_bound: Optional[list] = None
    if chain:
        gcs = grant.get("caveats")
        if not isinstance(gcs, list):
            raise _Throw("Cannot read properties of undefined (reading 'length')")
        lcs = chain[-1].get("caveats") if isinstance(chain[-1], dict) else None
        if not isinstance(lcs, list):
            raise _Throw("Cannot read properties of undefined (reading 'slice')")
        extra = lcs[len(gcs):]
        # K1 caveat types (and the caveats of a verified narrow block) are evaluated over the whole chain
        use_k1 = any(is_k1_caveat(c) for c in lcs) or (k1 is not None and "narrow" in k1)
        k1r = None
        if use_k1:
            ki = None if k1 is None else dict(k1, action_digest=discharge_action_digest(p))
            k1r = evaluate_k1(grant, chain, ki, {"now": now, "action": inner})
            k1_bound = k1r["bound"]
        cctx: Dict[str, Any] = {"now": now, "action": inner, "delegation_depth": depth}
        if risk.get("blastRadius") is not None:
            cctx["blast_radius"] = risk["blastRadius"]
        # the SAME class decide() used for the envelope caveats: the action's own, else the signed plan node's
        rev_class = resolve_reversibility_class(action_ctx, plan_nodes, plan_wire.get("node_id"))
        if rev_class is not None:
            cctx["reversibility_class"] = rev_class
        if ctx.get("recentActionTimes") is not None:
            cctx["recent_action_times"] = ctx["recentActionTimes"]
        tc: Dict[str, Any] = {"tool": inner["verb"] if isinstance(inner["verb"], str) else "", "args": inner["params"] if isinstance(inner.get("params"), dict) else {}}
        if isinstance(action_ctx.get("toolBinding"), str):
            tc["toolSignatureDigest"] = action_ctx["toolBinding"]
        cv_ok, failed = evaluate_agent_caveats([c for c in extra if not is_k1_caveat(c)] + (k1r["plain"] if k1r else []), cctx, action_ctx, tc)
        if cv_ok and (k1r is None or k1r["ok"]):
            vs.checks["delegated_caveats"] = "pass"
        else:
            all_failed = list(failed) + (list(k1r["failed"]) if k1r else [])
            tail = " (%s)" % "; ".join(k1r["reasons"]) if k1r and not k1r["ok"] else ""
            vs.fail("delegated_caveats", "delegation caveat(s) not satisfied: %s%s" % (", ".join(all_failed), tail))

    # policy: the check mirrors the Policy VM's release decision; its reasons (also the informational ones when released) are kept in order
    vs.checks["policy"] = "pass" if release else "fail"
    for x in d.get("reasons") or []:
        vs.reasons.append("policy: " + _s(x))

    # threshold: t > 1 needs a proof only an enforced threshold hook gives, and the hook must report at least the SERVER-derived t (F-1)
    rt = d["requiredThreshold"]
    t_req = int(rt["t"])
    if t_req > 1 and release:
        th = vs.checks.get("threshold")
        if th == "pass":
            hi = _hook_int(hook_t[0])
            if not (hi is not None and hi >= t_req):
                vs.fail_raw("threshold", "threshold: threshold hook enforced t=%s but the server requires t=%d (below the server-derived threshold; derive t from server-held data)"
                            % ("unreported" if hook_t[0] is _UNDEF else _s(hook_t[0]), t_req))
        elif th == "fail":
            vs.fail_raw("threshold", "threshold: t=%d required and the threshold proof was rejected" % t_req)
        else:
            vs.fail_raw("threshold", "threshold: t=%d (%s) required but no threshold verifier is enforced" % (t_req, rt.get("proof")))

    required: List[str] = list(DEFAULT_REQUIRED_CHECKS)
    if o.get("require") is not None:
        if not isinstance(o["require"], list):
            raise _Throw("required.map is not a function")
        required = [x if isinstance(x, str) else _s(x) for x in o["require"]]
    want_assurance = _wants_assurance(o)
    gate_att = enforce.get("attestation")
    att_hook = gate_att.get("verifier") if isinstance(gate_att, dict) and gate_att.get("verifier") is not None else hooks_in.get("attestation")
    a_hooks = {k: hooks_in[k] for k in ("attestation", "zk", "threshold", "revocation") if hooks_in.get(k) is not None}
    t_val = hook_t[0] if hook_t[0] is not _UNDEF else None
    degraded = {"tighten": LEGACY_POLARITY_DEGRADED} if v2d is not None and v2d.get("legacy_model_polarity") is True else None

    def report(checks: dict) -> dict:
        return _assurance(p, checks, hooks=a_hooks, attestation_hook=att_hook, threshold_t=t_val, degraded=degraded)

    if _truthy(o.get("requireAssurance")):
        unmet = _unmet(report(dict(vs.checks)), o["requireAssurance"])
        if unmet is None:
            vs.checks["assurance"] = "pass"
        else:
            vs.fail_raw("assurance", unmet)

    allow = not vs.has_fail() and release and core_allow
    checks = dict(vs.checks)
    for n in unsupported:
        if checks.get(n) == "not-enforced":
            checks[n] = "unsupported"

    def enforce_required(allow_in: bool, reasons: List[str]) -> "tuple[bool, dict, List[str]]":
        out = dict(checks)
        rs = list(reasons)
        # the old check name `counter` meant the format check statelessly and the replay check with a store
        names = [("replay" if "replay" in checks else "counter_format") if n == "counter" and "counter" not in checks else n for n in required]
        for name in names:
            was = out.get(name)
            if was == "pass":
                continue
            allow_in = False
            if was == "fail":
                continue
            rs.append("%s: required check is %s (default-deny: not enforced by this resource server)" % (name, was if was is not None else "absent"))
            out[name] = "fail"
        return allow_in, out, rs

    def finish(out: dict, final_checks: dict) -> dict:
        if want_assurance:
            out["assurance"] = refresh_assurance(report(checks), final_checks)
        return out

    # a feature the PCActn carries but this verifier does not implement is never a pass, and denies unless allowed
    allow_unsupported = o.get("allowUnsupported")
    listed = [x if isinstance(x, str) else _s(x) for x in allow_unsupported] if isinstance(allow_unsupported, list) else []
    refused = [n for n in unsupported if n not in listed]
    if refused:
        ev_allow, ev_checks, ev_reasons = enforce_required(False, vs.reasons + [n + _UNSUPPORTED_WHY for n in refused])
        return finish({"allow": ev_allow, "r": d["r"], "requiredThreshold": rt, "checks": ev_checks, "reasons": ev_reasons}, ev_checks)
    ev_allow, ev_checks, ev_reasons = enforce_required(allow, vs.reasons)
    out: Dict[str, Any] = {"allow": ev_allow, "r": d["r"], "requiredThreshold": rt, "checks": ev_checks, "reasons": ev_reasons}
    if allow and _truthy(budget_ctx):
        out["budget"] = d["budget"]
    if k1_bound and any(isinstance(b, dict) and isinstance(b.get("caveat"), dict) and b["caveat"].get("type") == "max_uses" for b in k1_bound):
        out["k1Bound"] = k1_bound
    # an escalation keeps the post-decision budget: an answered escalation is admitted with it, never free
    if not ev_allow and _truthy(budget_ctx) and decision_of({"allow": False, "checks": ev_checks, "reasons": ev_reasons}) == "escalate":
        out["budget"] = d["budget"]
    if not ev_allow and not ev_reasons:
        out["reasons"] = ["denied"]
    return finish(out, ev_checks)
