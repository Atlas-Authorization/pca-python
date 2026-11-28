"""Payments for PCA: a payment mandate as a Root Intent Grant, the charge decision, the charge PCActn, Shared Payment Token
limits, spend rails (card limits, a real-time authorization callback, settlement reconciliation), the Stripe Issuing
adapter and agent network tokens.

Mirrors the TypeScript reference (@atlasauth/pca-payments). Values are the reference's JSON shapes (camelCase members); inputs
follow JavaScript semantics where the reference does (missing members, truthiness, coercing arithmetic), so a hostile mandate
or charge is refused or priced exactly as the reference does. This package carries no policy engine: the charge decision takes
the PCA policy decision function as an injected callable `decide(decide_input) -> policy_decision`, and secrets are signed
through `cryptography` (or after `atlas_pca.ed25519.allow_insecure_signer()` / the `allow_insecure_signer` argument).
HTTP is injected too: a partner transport is a callable `post(path, body) -> dict`."""
from __future__ import annotations

import hashlib
import hmac
import math
import re
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FutureTimeout
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote

from . import ed25519
from ._fin import fin
from . import sdjwt_jws as J
from .agent import KeyPair, build_pcactn, mint_grant
from .authorize import read_envelope
from .pca import b64u, decode_b64u_strict, hash_canonical
from .ratchet import _to_number
from .risk import cost as budget_cost

UNDEF = object()  # a JSON member that is absent (distinct from null)

CHARGE_REVERSIBILITY_CLASS = "reversible"
CHARGE_VERB = "charge"
AMOUNT_NOT_MINOR_UNITS = "amount_not_integer_minor_units"
MERCHANT_INVALID = "merchant_invalid"
STRIPE_WEBHOOK_TOLERANCE_SEC = 300
STRIPE_API_VERSION = "2025-03-31.basil"
NETWORK_TOKEN_BINDING_KIND = "pca.network_token_binding"
MCC_TRAIT_RE = re.compile(r"mcc\.c([0-9]{4})")

_JS_WS = "\t\n\v\f\r    -     　﻿"
_JS_WS_CHARS = "\t\n\v\f\r       　﻿" + "".join(chr(c) for c in range(0x2000, 0x200B))
_MAX_CAS_ATTEMPTS = 8


# ---- JS-semantics helpers ---------------------------------------------------------------------------------------------------

def _isnum(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _isfinite(v: Any) -> bool:
    return _isnum(v) and fin(v)


def _safe_int(v: Any) -> bool:
    return _isnum(v) and fin(v) and v == math.floor(v) and abs(v) <= 2 ** 53 - 1


def _truthy(v: Any) -> bool:
    return False if v is UNDEF else J.truthy(v)


def _prop(o: Any, k: str) -> Any:
    """`o.k`: TypeError for null / undefined, UNDEF for a missing member or a primitive."""
    if o is None or o is UNDEF:
        raise TypeError("Cannot read properties of %s (reading '%s')" % ("null" if o is None else "undefined", k))
    return o.get(k, UNDEF) if isinstance(o, dict) else UNDEF


def _optprop(o: Any, k: str) -> Any:
    return UNDEF if o is None or o is UNDEF else _prop(o, k)


def _nullish(v: Any) -> bool:
    return v is None or v is UNDEF


def _len16(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _length(v: Any) -> Any:
    """`v.length`: TypeError for null / undefined, UNDEF when there is none."""
    if v is None or v is UNDEF:
        raise TypeError("Cannot read properties of undefined (reading 'length')")
    if isinstance(v, str):
        return _len16(v)
    if isinstance(v, list):
        return len(v)
    if isinstance(v, dict):
        return v.get("length", UNDEF)
    return UNDEF


def _gt0(v: Any) -> bool:
    n = _to_number(v)
    return n > 0


def _spread_list(v: Any) -> List[Any]:
    if isinstance(v, list):
        return list(v)
    if isinstance(v, str):
        return list(v)
    raise TypeError("object is not iterable")


def _spread_obj(v: Any) -> Dict[str, Any]:
    if isinstance(v, dict):
        return dict(v)
    if isinstance(v, (list, str)):
        return {str(i): c for i, c in enumerate(v)}
    return {}


def _tostr(v: Any) -> str:
    """String(v) as a template literal renders it."""
    if v is UNDEF:
        return "undefined"
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return v
    if _isnum(v):
        return J.js_num(v)
    if isinstance(v, list):
        return ",".join("" if (x is None or x is UNDEF) else _tostr(x) for x in v)
    return "[object Object]"


def _js_div(a: float, b: float) -> float:
    if b == 0:
        if a == 0 or a != a:
            return math.nan
        neg = (a < 0) != (math.copysign(1.0, b) < 0)
        return -math.inf if neg else math.inf
    return a / b


def _js_round(x: float) -> float:
    if x != x or math.isinf(x):
        return x
    r = math.floor(x)
    return float(r + 1) if x - r >= 0.5 else float(r)


def _js_floor(x: float) -> float:
    return x if (x != x or math.isinf(x)) else float(math.floor(x))


def _js_min(a: Any, b: Any) -> float:
    x, y = _to_number(a), _to_number(b)
    return math.nan if (x != x or y != y) else min(x, y)


def _js_max(a: Any, b: Any) -> float:
    x, y = _to_number(a), _to_number(b)
    return math.nan if (x != x or y != y) else max(x, y)


def _num(v: Any) -> Any:
    """An integral float is returned as an int so a whole number serialises as one."""
    return int(v) if isinstance(v, float) and fin(v) and v == math.floor(v) and abs(v) < 2 ** 63 else v


def _js_gt(a: Any, b: Any) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a.encode("utf-16-be", "surrogatepass") > b.encode("utf-16-be", "surrogatepass")
    return _to_number(a) > _to_number(b)


def _seq(a: Any, b: Any) -> bool:
    """JS strict equality for JSON values."""
    if a is UNDEF or b is UNDEF:
        return a is b
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if _isnum(a) and _isnum(b):
        return a == b
    return type(a) is type(b) and a == b


def _js_trim(s: str) -> str:
    return s.strip(_JS_WS_CHARS)


def _utf8(s: str) -> bytes:
    return s.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")


def _drop(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not UNDEF}


def _hash(v: Any) -> str:
    if v is UNDEF:
        raise TypeError("canonicalize: unsupported type undefined")
    return hash_canonical(v)


# ---- mandate ----------------------------------------------------------------------------------------------------------------

_CONTROL_OR_STAR = re.compile("[*\u0000-\u001f\u007f]")


def is_plain_id(x: Any) -> bool:
    """A merchant id that cannot act as a resource pattern: no `*`, no control characters."""
    return isinstance(x, str) and len(x) > 0 and _CONTROL_OR_STAR.search(x) is None


def is_minor_units(x: Any) -> bool:
    """A non-negative safe integer (amounts are integer minor units)."""
    return _safe_int(x) and x >= 0 and not (isinstance(x, float) and x == 0 and math.copysign(1.0, x) < 0)


def _validate(p: Any) -> None:
    g = lambda k: _prop(p, k)  # noqa: E731
    # -0 is a number the strict canonicalizer refuses (grantDigestOf, hashCanonical): refuse it here too instead of signing it
    for k in ("perTransactionCap", "autoApproveThreshold", "cumulativeCap", "replenishPerCosign", "periodMs", "maxTransactionsPerPeriod", "periodStart", "now"):
        v = g(k)
        if isinstance(v, float) and v == 0 and math.copysign(1.0, v) < 0:
            raise ValueError("buildPaymentMandate: %s must not be negative zero" % k)
    strict = g("strictMinorUnits")
    if strict is not False:
        rep = g("replenishPerCosign")
        for k, v in (("perTransactionCap", g("perTransactionCap")), ("autoApproveThreshold", g("autoApproveThreshold")),
                     ("cumulativeCap", g("cumulativeCap")), ("replenishPerCosign", 0 if _nullish(rep) else rep)):
            if not _safe_int(v):
                raise ValueError("buildPaymentMandate: %s must be a safe integer in minor units (strictMinorUnits)" % k)
    m = g("merchants")
    if not isinstance(m, list) or len(m) == 0:
        raise ValueError("buildPaymentMandate: at least one allowlisted merchant is required")
    if any(not isinstance(x, str) or len(x) == 0 for x in m):
        raise ValueError("buildPaymentMandate: merchant ids must be non-empty strings")
    if any(not is_plain_id(x) for x in m):
        raise ValueError("buildPaymentMandate: merchant ids must not contain `*` or control characters")
    cur = g("currency")
    if not isinstance(cur, str) or len(cur) == 0:
        raise ValueError("buildPaymentMandate: currency is required")
    x_, y_, cap = g("perTransactionCap"), g("autoApproveThreshold"), g("cumulativeCap")
    if not _isfinite(x_) or x_ <= 0:
        raise ValueError("buildPaymentMandate: perTransactionCap (X) must be a finite number > 0")
    if not _isfinite(y_) or y_ < 0 or y_ > x_:
        raise ValueError("buildPaymentMandate: autoApproveThreshold (Y) must satisfy 0 ≤ Y ≤ X")
    if not _isfinite(cap) or cap < x_:
        raise ValueError("buildPaymentMandate: cumulativeCap must be a finite number ≥ perTransactionCap (X)")
    pm = g("periodMs")
    if pm is not UNDEF and (not _isfinite(pm) or pm <= 0):
        raise ValueError("buildPaymentMandate: periodMs must be a finite number > 0 when given")
    mx = g("maxTransactionsPerPeriod")
    if mx is not UNDEF and (not _safe_int(mx) and not (_isnum(mx) and fin(mx) and mx == math.floor(mx)) or mx <= 0):
        raise ValueError("buildPaymentMandate: maxTransactionsPerPeriod must be a positive integer when given")
    rep = g("replenishPerCosign")
    if rep is not UNDEF and (not _isfinite(rep) or rep < 0):
        raise ValueError("buildPaymentMandate: replenishPerCosign must be a finite number ≥ 0 when given")


def _cond(field: str, op: str, value: Any) -> Dict[str, Any]:
    return _drop({"field": field, "op": op, "value": value})


def mandate_predicates(terms: Any) -> List[Dict[str, Any]]:
    """One predicate per merchant, each carrying the currency, category and hard-ceiling guards."""
    merchants = _prop(terms, "merchants")
    if not isinstance(merchants, list):
        raise TypeError("terms.merchants.map is not a function")
    out = []
    for m in merchants:
        conds = [_cond("action.params.amount", "lte", _prop(terms, "perTransactionCap")),
                 _cond("action.params.currency", "eq", _prop(terms, "currency")),
                 _cond("action.params.amount", "gte", 0)]
        cats = _prop(terms, "categories")
        n = _length(cats)
        if n is not UNDEF and n > 0:
            conds.append(_cond("action.params.category", "in", cats))
        out.append({"verb": "charge", "resource": "merchant:" + _tostr(m), "where": conds})
    return out


def mandate_caveats(terms: Any) -> List[Dict[str, Any]]:
    """The envelope caveats: period window, velocity cap, and the bonded / refundable reversibility floor."""
    cv: List[Dict[str, Any]] = []
    ps = _prop(terms, "periodStart")
    if _gt0(ps):
        cv.append({"type": "not_before", "at": ps})
    pe = _prop(terms, "periodEnd")
    if pe is not UNDEF:
        cv.append({"type": "expires", "at": pe})
    mx = _prop(terms, "maxTransactionsPerPeriod")
    if mx is not UNDEF and pe is not UNDEF:
        per = _js_max(1, _js_round(_js_div(_to_number(pe) - _to_number(ps), 1000.0)))
        cv.append({"type": "rate", "max": mx, "per_secs": _num(per)})
    cv.append({"type": "reversibility_max", "class": "reversible"})
    return cv


def mandate_risk_policy(terms: Any, replenish_per_cosign: Any) -> Dict[str, Any]:
    """The risk policy that makes "spend = risk" exact: only blast radius weighs, theta1 = theta2 = Y/X, kappa = X, bMax = cap."""
    a, x = _prop(terms, "autoApproveThreshold"), _prop(terms, "perTransactionCap")
    th = _js_div(_to_number(a), _to_number(x))
    return _drop({"weights": {"alpha": 0, "beta": 0, "gamma": 1, "delta": 0, "epsilon": 0, "zeta": 0},
                  "theta1": th, "theta2": th, "kappa": x, "lambda": 0, "rho": replenish_per_cosign,
                  "bMax": _prop(terms, "cumulativeCap")})


def auto_spend_bound(mandate: Any) -> float:
    """The most an agent can spend autonomously between two human co-signs: safetyBound * kappa (equals cumulativeCap)."""
    p = _prop(mandate, "policy")
    kappa, b_max = _prop(p, "kappa"), _prop(p, "bMax")
    bound = _js_div(_js_max(0, b_max), _to_number(kappa)) if _to_number(kappa) > 0 else 0
    return _num(bound * _to_number(kappa))


def build_payment_mandate(params: Dict[str, Any], allow_insecure_signer: bool = False) -> Dict[str, Any]:
    """Encode the params as a PCA Root Intent Grant envelope plus the initial trust budget. `principalSecret` is the 32-byte
    Ed25519 seed that signs the grant."""
    _validate(params)
    g = lambda k: _prop(params, k)  # noqa: E731
    now = g("now") if _isfinite(g("now")) else int(time.time() * 1000)
    period_start = g("periodStart") if _isfinite(g("periodStart")) else now
    cats = g("categories")
    terms: Dict[str, Any] = {
        "merchants": list(g("merchants")), "categories": _spread_list(cats) if _truthy(cats) else [], "currency": g("currency"),
        "perTransactionCap": g("perTransactionCap"), "autoApproveThreshold": g("autoApproveThreshold"),
        "cumulativeCap": g("cumulativeCap"), "periodStart": period_start,
    }
    if g("periodMs") is not UNDEF:
        terms["periodEnd"] = period_start + g("periodMs")
    if g("maxTransactionsPerPeriod") is not UNDEF:
        terms["maxTransactionsPerPeriod"] = g("maxTransactionsPerPeriod")
    rep = g("replenishPerCosign")
    policy = mandate_risk_policy(terms, terms["cumulativeCap"] if _nullish(rep) else rep)
    goal = g("goal")
    if _nullish(goal):
        goal = "spend ≤ %s %s autonomously / ≤ %s with co-sign, ≤ %s cumulative, at [%s]" % (
            _tostr(terms["autoApproveThreshold"]), terms["currency"], _tostr(terms["perTransactionCap"]),
            _tostr(terms["cumulativeCap"]), ", ".join(terms["merchants"]))
    principal = KeyPair(g("principalSecret"), allow_insecure_signer)
    if g("principalPublic") != principal.public:
        raise ValueError("buildPaymentMandate: principalPublic is not the public key of principalSecret")
    salt = g("goalSalt")
    minted = mint_grant(principal, g("agentPublic"),
                        {"predicates": mandate_predicates(terms), "caveats": mandate_caveats(terms), "agent_binding": {},
                         "risk_policy": policy}, goal, None if salt is UNDEF else salt)
    return {"grant": minted["grant"], "policy": policy, "budget": {"B": terms["cumulativeCap"], "tau": now, "asOf": now},
            "terms": terms, "goalCommit": minted["goal_commit"], "goalSalt": minted["goal_salt"]}


# ---- charge decision --------------------------------------------------------------------------------------------------------

class MandateGrantError(Exception):
    """code: verified_grant_required | mandate_grant_mismatch | mandate_terms_mismatch."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class ChargeStoreError(Exception):
    pass


def _charge_params(mandate: Any, charge: Any) -> Dict[str, Any]:
    cur = _prop(charge, "currency")
    p = {"amount": _prop(charge, "amount"),
         "currency": _prop(_prop(mandate, "terms"), "currency") if cur is UNDEF else cur}
    cat = _prop(charge, "category")
    if cat is not UNDEF:
        p["category"] = cat
    return _drop(p)


def charge_params(mandate: Any, charge: Any) -> Dict[str, Any]:
    """The charge params committed in both the plan node and the PCActn action. Only an ABSENT currency defaults to the mandate's."""
    return _charge_params(mandate, charge)


def charge_action_context(mandate: Any, charge: Any) -> Dict[str, Any]:
    """The action a charge denotes: the verb / resource / params the predicates and risk read."""
    return {"action": {"verb": CHARGE_VERB, "resource": "merchant:" + _tostr(_prop(charge, "merchant")),
                       "params": _charge_params(mandate, charge), "reversibility_class": CHARGE_REVERSIBILITY_CLASS}}


def _bind_to_verified_grant(mandate: Any, verified_grant: Any) -> Dict[str, Any]:
    if verified_grant is None or verified_grant is UNDEF or not isinstance(verified_grant, (dict, list)):
        raise MandateGrantError("verified_grant_required",
                                "a verified (or stored) grant is required; the mandate's own grant is never the authority")
    if mandate is None or not isinstance(mandate, (dict, list)) or _hash(_prop(mandate, "grant")) != _hash(verified_grant):
        raise MandateGrantError("mandate_grant_mismatch", "the mandate grant is not the verified grant")
    env = read_envelope(verified_grant)

    def same(a: Any, b: Any) -> bool:
        return _hash(a) == _hash(b)

    terms, policy = _prop(mandate, "terms"), _prop(mandate, "policy")
    if (env is None or not _truthy(terms) or not _truthy(policy) or not same(env["predicates"], mandate_predicates(terms))
            or not same(env["caveats"], mandate_caveats(terms)) or not same(env["risk_policy"], policy)):
        raise MandateGrantError("mandate_terms_mismatch",
                                "the mandate terms / policy are not the ones signed into the verified grant")
    b_max = env["risk_policy"]["bMax"]
    budget = _optprop(mandate, "budget")
    b = _optprop(budget, "B") if budget is not UNDEF else UNDEF
    bb = max(0, min(b, b_max)) if _isfinite(b) else 0
    out = _spread_obj(mandate)
    out["grant"] = verified_grant
    nb = _spread_obj(budget)
    nb["B"] = bb
    out["budget"] = nb
    return out


def charge_decide_input(mandate0: Any, charge: Any, now: Any, verified_grant: Any) -> Dict[str, Any]:
    """The decide input for a charge: risk collapses to the normalised amount (spend = risk). A mandate whose grant, terms or
    policy differ from `verified_grant` is refused (MandateGrantError)."""
    mandate = _bind_to_verified_grant(mandate0, verified_grant)
    x = _prop(_prop(mandate, "terms"), "perTransactionCap")
    amount = _prop(charge, "amount")
    amount = amount if _isfinite(amount) else math.inf
    blast = _js_div(amount, _to_number(x)) if _to_number(x) > 0 else 1
    ctx: Dict[str, Any] = {"reversibilityClass": CHARGE_REVERSIBILITY_CLASS}
    recent = _prop(charge, "recentChargeTimes")
    if recent is not UNDEF:
        ctx["recentActionTimes"] = recent
    return {"grant": verified_grant, "action": charge_action_context(mandate, charge),
            "risk": {"semanticDistance": 0, "reversibility": 1, "blastRadius": blast, "taint": 0, "confidence": 1, "age": 0},
            "budget": mandate["budget"], "now": now, "caveatContext": ctx}


def authorize_charge(mandate0: Any, charge: Any, verified_grant: Any, decide: Callable[[Dict[str, Any]], Dict[str, Any]]) -> Dict[str, Any]:
    """Run a charge through the PCA decision against the grant you VERIFIED (or loaded from your own store). Pure: reads the
    mandate budget (clamped to the signed bMax) and returns the next one in `budgetAfter`. `decide` is the PCA policy engine."""
    mandate = _bind_to_verified_grant(mandate0, verified_grant)
    now = _prop(charge, "now")
    now = now if _isfinite(now) else int(time.time() * 1000)
    raw = decide(charge_decide_input(mandate, charge, now, verified_grant))
    amount, merchant = _prop(charge, "amount"), _prop(charge, "merchant")
    refusal = AMOUNT_NOT_MINOR_UNITS if not is_minor_units(amount) else MERCHANT_INVALID if not is_plain_id(merchant) else None
    if refusal is None:
        decision = raw
    else:
        decision = dict(raw, admit=False, releaseGuardianShare=False, reasons=[refusal] + list(raw["reasons"]), budget=mandate["budget"])
    if not decision["releaseGuardianShare"]:
        outcome = "deny"
    elif decision["admit"]:
        outcome = "auto"
    else:
        outcome = "step_up"
    policy, terms, budget = mandate["policy"], mandate["terms"], mandate["budget"]
    exact = (outcome == "auto" and is_minor_units(amount) and _seq(policy["kappa"], terms["perTransactionCap"])
             and _safe_int(budget.get("B", UNDEF)))
    cost = 0 if outcome != "auto" else (amount if exact else budget_cost(decision["r"], policy["kappa"]))
    return {"outcome": outcome, "t": decision["requiredThreshold"]["t"], "r": decision["r"],
            "requiredThreshold": decision["requiredThreshold"], "cost": cost, "budgetBefore": budget,
            "budgetAfter": dict(decision["budget"], B=budget["B"] - amount) if exact else decision["budget"],
            "reasons": decision["reasons"], "decision": decision}


def settle_charge(mandate: Dict[str, Any], decision: Dict[str, Any]) -> Dict[str, Any]:
    """Advance the mandate's budget after a decision (functional)."""
    return dict(_spread_obj(mandate), budget=_prop(decision, "budgetAfter"))


def _nz(x: Any) -> Any:
    return x if _isfinite(x) and x > 0 else 0


def _recharge(b: Any, rho: Any, b_max: Any, now: Any) -> Dict[str, Any]:
    bb = _prop(b, "B")
    total = (bb + J.js_num(_nz(rho))) if isinstance(bb, str) else _to_number(bb) + _nz(rho)
    return {"B": _num(_js_min(_nz(b_max), total)), "tau": now, "asOf": now}


def apply_human_cosign(mandate: Any, now: Any, opts: Any = UNDEF) -> Dict[str, Any]:
    """Apply a human co-sign: restore autonomous budget by `rho`, or fully re-confirm to `bMax` with {"full": True}. The only
    way the budget goes up."""
    opts = {} if opts is UNDEF else opts
    full = _truthy(_prop(opts, "full"))
    policy = _prop(mandate, "policy")
    if full:
        budget = {"B": _nz(_prop(policy, "bMax")), "tau": now, "asOf": now}
    else:
        budget = _recharge(_prop(mandate, "budget"), _prop(policy, "rho"), _prop(policy, "bMax"), now)
    return dict(_spread_obj(mandate), budget=budget)


def _valid_record(r: Any) -> bool:
    if not isinstance(r, dict):
        return False
    v, b = r.get("version"), r.get("budget")
    return (_safe_int(v) and not (isinstance(v, float) and v == 0 and math.copysign(1.0, v) < 0) and isinstance(b, dict)
            and _isfinite(b.get("B")) and _isfinite(b.get("tau")) and _isfinite(b.get("asOf")))


def _check_store(store: Any) -> None:
    if not store or not callable(getattr(store, "get", None)) or not callable(getattr(store, "compare_and_set", None)):
        raise ChargeStoreError("a ChargeBudgetStore with get and compare_and_set is required")


def authorize_charge_atomic(mandate: Any, charge: Any, verified_grant: Any, store: Any, decide: Callable[[Dict[str, Any]], Dict[str, Any]],
                            key: Optional[str] = None) -> Dict[str, Any]:
    """authorize_charge against the DURABLE cumulative budget in `store` (get(key) -> {budget, version} | None;
    compare_and_set(key, expected_version | None, budget) -> bool). An auto debit is committed with a compare-and-set before it
    is returned; losing the race re-reads and re-decides; persistent contention returns a deny."""
    _check_store(store)
    key = hash_canonical(verified_grant) if key is None else key
    for _ in range(_MAX_CAS_ATTEMPTS):
        rec = store.get(key)
        if rec is not None and not _valid_record(rec):
            raise ChargeStoreError("the store returned a malformed budget record")
        m = dict(_spread_obj(mandate), budget=rec["budget"]) if rec else mandate
        d = authorize_charge(m, charge, verified_grant, decide)
        if d["outcome"] != "auto":
            return d
        if store.compare_and_set(key, rec["version"] if rec else None, d["budgetAfter"]):
            return d
    d = authorize_charge(mandate, charge, verified_grant, decide)
    return dict(d, outcome="deny", t=3, cost=0, budgetAfter=d["budgetBefore"], reasons=["budget_store_conflict"] + list(d["reasons"]))


def apply_human_cosign_atomic(mandate: Any, verified_grant: Any, store: Any, now: Any, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """apply_human_cosign against the DURABLE budget, committed with a compare-and-set so a co-sign racing a charge is never
    lost or applied twice. Call it only after verifying the human co-sign; persistent contention raises."""
    _check_store(store)
    opts = opts or {}
    key = opts.get("key") if opts.get("key") is not None else hash_canonical(verified_grant)
    for _ in range(_MAX_CAS_ATTEMPTS):
        rec = store.get(key)
        if rec is not None and not _valid_record(rec):
            raise ChargeStoreError("the store returned a malformed budget record")
        bound = _bind_to_verified_grant(dict(_spread_obj(mandate), budget=rec["budget"]) if rec else mandate, verified_grant)
        nxt = apply_human_cosign(bound, now, {"full": opts.get("full") is True})["budget"]
        if store.compare_and_set(key, rec["version"] if rec else None, nxt):
            return nxt
    raise ChargeStoreError("could not commit the co-sign: the budget record kept changing")


# ---- charge as a proof-carrying action ----------------------------------------------------------------------------------------

def charge_plan_node(mandate: Any, charge: Any, id_: str) -> Dict[str, Any]:
    """The committed plan node for a charge; params_digest is pinned to the charge params so the leaf reconciles with the PCActn."""
    return {"id": id_, "verb": CHARGE_VERB, "resource": "merchant:" + _tostr(_prop(charge, "merchant")),
            "reversibility_class": CHARGE_REVERSIBILITY_CLASS, "params_digest": hash_canonical(_charge_params(mandate, charge))}


def charge_to_pcactn(mandate: Any, charge: Any, opts: Dict[str, Any], allow_insecure_signer: bool = False) -> Dict[str, Any]:
    """A signed PCActn for a charge: {pcactn, node}. opts: signerSecret (32-byte seed), aud, counter, optional chain, nodeId, now."""
    if not is_minor_units(_prop(charge, "amount")):
        raise ValueError("chargeToPCActn: amount must be a non-negative integer in minor units")
    node_id = opts.get("nodeId")
    node_id = "charge:%s:%s" % (_tostr(_prop(charge, "merchant")), _tostr(opts.get("counter", UNDEF))) if node_id is None else node_id
    node = charge_plan_node(mandate, charge, node_id)
    x = _prop(_prop(mandate, "terms"), "perTransactionCap")
    amount = _prop(charge, "amount")
    amount = amount if _isfinite(amount) else x
    r = _js_div(amount, x) if x > 0 else 1
    r = 0 if r < 0 else 1 if r > 1 else r
    params = _charge_params(mandate, charge)
    chain = opts.get("chain")
    chain = [mandate["grant"]] if chain is None else chain
    pcactn = build_pcactn(chain[0], chain, [node], node_id, opts.get("counter"), KeyPair(opts.get("signerSecret"), allow_insecure_signer),
                          opts.get("aud"), params=params, now=opts.get("now"),
                          risk_claim={"r": _num(r), "inputs": dict(params, blastRadius=_num(r))})
    return {"pcactn": pcactn, "node": node}


# ---- Shared Payment Token limits, rails -------------------------------------------------------------------------------------

def shared_payment_token_limits(mandate: Any, now: Any) -> Dict[str, Any]:
    """The usage_limits of a Stripe Shared Payment Token that fits what the mandate lets an agent spend WITHOUT a co-sign: at most
    the auto-approve threshold and the remaining autonomous budget, lowercase currency, expiring with the mandate period."""
    if not _isfinite(now):
        raise TypeError("sharedPaymentTokenLimits: now must be an epoch-ms time")
    t = _prop(mandate, "terms")
    budget = _js_floor(_to_number(_prop(_prop(mandate, "budget"), "B")))
    mx = _js_min(_prop(t, "autoApproveThreshold"), budget)
    if not _safe_int(mx) or mx <= 0:
        raise ValueError("sharedPaymentTokenLimits: no autonomous spend capacity is left; a human co-sign is needed")
    pe = _prop(t, "periodEnd")
    if pe is not UNDEF and not _isfinite(pe):  # an infinite period end would serialize as expires_at: null, read as no expiry
        raise TypeError("sharedPaymentTokenLimits: periodEnd must be an epoch-ms time")
    if pe is not UNDEF and not (_to_number(now) < _to_number(pe)):
        raise ValueError("sharedPaymentTokenLimits: the mandate period has ended")
    out = {"currency": _prop(t, "currency").lower(), "max_amount": int(mx)}
    if pe is not UNDEF:
        out["expires_at"] = _num(_js_floor(_js_div(_to_number(pe), 1000.0)))
    return out


def categories_from_traits(traits: Any) -> List[str]:
    """Action-kit convention: a trait `mcc.c5734` says the verb may spend in MCC 5734. Traits only narrow."""
    out = set()
    for t in traits:
        m = MCC_TRAIT_RE.fullmatch(t) if isinstance(t, str) else None
        if m:
            out.add(m.group(1))
    return sorted(out)


def rail_limits(mandate: Any, now: Any, opts: Any = UNDEF) -> Dict[str, Any]:
    """The limits an instrument for this mandate may carry (amounts from shared_payment_token_limits; categories are the
    mandate's allowlist narrowed by the action's mcc traits). opts: actionTraits, allowAnyCategory."""
    opts = {} if opts is UNDEF else opts
    spt = shared_payment_token_limits(mandate, now)
    total = _num(_js_floor(_to_number(_prop(_prop(mandate, "budget"), "B"))))
    t = _prop(mandate, "terms")
    from_mandate = _spread_list(_prop(t, "categories"))
    traits = _prop(opts, "actionTraits")
    from_traits = categories_from_traits([] if _nullish(traits) or traits is UNDEF else traits)
    if from_mandate and from_traits:
        cats = sorted(c for c in from_mandate if c in from_traits)
        if not cats:
            raise ValueError("railLimits: the action traits and the mandate categories do not intersect; nothing may be spent")
    else:
        cats = sorted(from_mandate if from_mandate else from_traits)
    if not cats and _prop(opts, "allowAnyCategory") is not True:
        raise ValueError("railLimits: no category control (mandate categories or mcc.* traits); pass allowAnyCategory to accept any merchant category")
    out = {"currency": _prop(t, "currency").upper(), "perAuthorizationMax": spt["max_amount"], "totalMax": total,
           "categories": cats, "merchants": _spread_list(_prop(t, "merchants"))}
    if "expires_at" in spt:
        out["expiresAt"] = spt["expires_at"] * 1000
    return out


def _decline(*reasons: str) -> Dict[str, Any]:
    return {"approved": False, "reasons": list(reasons)}


def create_rail_authorizer(opts: Dict[str, Any]) -> Callable[[Any], Dict[str, Any]]:
    """A real-time authorization callback that answers from authorize_charge_atomic inside a latency budget. Total: a step-up,
    a deny, an unknown card, a timeout, an exception are all declines. opts: instruments(instrument_id) -> {mandate, grant,
    budgetKey?} | None, store, decide, latencyBudgetMs (default 1500), now() -> ms, onStepUp(a, decision)."""
    budget_ms = opts.get("latencyBudgetMs")
    budget_ms = 1500 if budget_ms is None else budget_ms
    if not _isfinite(budget_ms) or budget_ms <= 0:
        raise ValueError("createRailAuthorizer: latencyBudgetMs must be positive")
    clock = opts.get("now") or (lambda: int(time.time() * 1000))

    def decide_one(a: Any) -> Dict[str, Any]:
        if (not isinstance(a, dict) or not isinstance(a.get("id"), str) or not isinstance(a.get("instrumentId"), str)
                or len(a["id"]) == 0):
            return _decline("malformed_authorization")
        amount = a.get("amount")
        if not _safe_int(amount) or amount <= 0:
            return _decline("amount_not_positive_minor_units")
        if not isinstance(a.get("currency"), str) or len(a["currency"]) == 0:
            return _decline("currency_missing")
        if not isinstance(a.get("merchantId"), str) or len(a["merchantId"]) == 0:
            return _decline("merchant_unknown")
        inst = opts["instruments"](a["instrumentId"])
        if inst is None:
            return _decline("instrument_unknown")
        charge = {"merchant": a["merchantId"], "amount": amount, "currency": a["currency"].upper(), "now": clock()}
        if "mcc" in a:
            charge["category"] = a["mcc"]
        d = authorize_charge_atomic(inst["mandate"], charge, inst["grant"], opts["store"], opts["decide"], inst.get("budgetKey"))
        if d["outcome"] == "auto":
            return {"approved": True, "reasons": [], "decision": d}
        if d["outcome"] == "step_up":
            try:
                if opts.get("onStepUp"):
                    opts["onStepUp"](a, d)
            except Exception:  # noqa: BLE001 - a failing notifier must not change the answer
                pass
            return {"approved": False, "reasons": ["step_up_required"] + list(d["reasons"]), "decision": d}
        return {"approved": False, "reasons": list(d["reasons"]) if d["reasons"] else ["denied"], "decision": d}

    def authorize(a: Any) -> Dict[str, Any]:
        ex = ThreadPoolExecutor(max_workers=1)
        try:
            # a decision that finishes after the timeout may still have debited the budget (an under-spend, the safe direction)
            return ex.submit(decide_one, a).result(timeout=budget_ms / 1000.0)
        except _FutureTimeout:
            return _decline("latency_budget_exceeded")
        except Exception:  # noqa: BLE001
            return _decline("authorizer_error")
        finally:
            ex.shutdown(wait=False)

    return authorize


def reconcile_settlement(approved: Any, s: Any) -> Dict[str, Any]:
    """Compare what settled with what PCA approved: commit only on an exact fit; anything else says freeze the grant."""
    reasons: List[str] = []
    if not _seq(_prop(s, "authorizationId"), _prop(approved, "id")):
        reasons.append("authorization_id_mismatch")
    if _js_gt(_prop(s, "amount"), _prop(approved, "amount")):
        reasons.append("settled_more_than_approved")
    sc, ac = _prop(s, "currency"), _prop(approved, "currency")
    if not isinstance(sc, str):
        raise TypeError("s.currency.toUpperCase is not a function")
    if sc.upper() != ac.upper():
        reasons.append("currency_mismatch")
    if not _seq(_prop(s, "merchantId"), _prop(approved, "merchantId")):
        reasons.append("merchant_mismatch")
    if _js_gt(_prop(s, "captures"), 1):
        reasons.append("second_capture")
    return {"ok": True} if not reasons else {"ok": False, "reasons": reasons, "action": "freeze_grant"}


# ---- Stripe Issuing adapter -------------------------------------------------------------------------------------------------

def stripe_card_params(limits: Dict[str, Any], opts: Dict[str, Any]) -> Dict[str, str]:
    """The form parameters for POST /v1/issuing/cards (virtual, active) that carry the rail limits. opts: categoryNames
    (MCC -> Stripe category), cardholder, metadata. Raises when an MCC has no Stripe category name."""
    p = {"cardholder": opts["cardholder"], "type": "virtual", "status": "active", "currency": limits["currency"].lower(),
         "spending_controls[spending_limits][0][amount]": _tostr(limits["perAuthorizationMax"]),
         "spending_controls[spending_limits][0][interval]": "per_authorization",
         "spending_controls[spending_limits][1][amount]": _tostr(limits["totalMax"]),
         "spending_controls[spending_limits][1][interval]": "all_time"}
    names = opts["categoryNames"]
    for i, mcc in enumerate(limits["categories"]):
        name = names.get(mcc) if isinstance(names, dict) else None
        if name is None:
            raise ValueError("stripeCardParams: no Stripe category name for MCC %s" % mcc)
        p["spending_controls[allowed_categories][%d]" % i] = name
    for k, v in (opts.get("metadata") or {}).items():
        p["metadata[%s]" % k] = v
    return p


def sign_stripe_payload(raw_body: str, secret: str, t_sec: Any) -> str:
    t = _tostr(t_sec)
    return "t=%s,v1=%s" % (t, hmac.new(_utf8(secret), _utf8("%s.%s" % (t, raw_body)), hashlib.sha256).hexdigest())


_STRIPE_T = re.compile("[0-9]{1,12}")
_STRIPE_SIG = re.compile("[0-9a-f]{64}")


def verify_stripe_signature(raw_body: str, header: Any, secret: Any, now_sec: Any,
                            tolerance_sec: Any = STRIPE_WEBHOOK_TOLERANCE_SEC) -> bool:
    """Verify a `Stripe-Signature` header over the RAW body. Total: False on anything malformed, stale or mismatched."""
    try:
        if not isinstance(header, str) or not isinstance(secret, str) or len(secret) == 0 or not (fin(tolerance_sec) and tolerance_sec > 0):
            return False
        t: Optional[str] = None
        v1: List[str] = []
        for part in header.split(","):
            i = part.find("=")
            if i < 0:
                continue
            k, v = _js_trim(part[:i]), _js_trim(part[i + 1:])
            if k == "t":
                t = v
            elif k == "v1":
                v1.append(v)
        if t is None or _STRIPE_T.fullmatch(t) is None or not v1:
            return False
        if not (abs(now_sec - int(t)) <= tolerance_sec):
            return False
        want = hmac.new(_utf8(secret), _utf8("%s.%s" % (t, raw_body)), hashlib.sha256).digest()
        return any(_STRIPE_SIG.fullmatch(s) is not None and hmac.compare_digest(bytes.fromhex(s), want) for s in v1)
    except Exception:  # noqa: BLE001
        return False


def stripe_authorization_from_event(event: Any) -> Optional[Dict[str, Any]]:
    """Normalise an `issuing_authorization.request` event; None when it is not a well-formed request with a pending amount."""
    if not isinstance(event, dict) or event.get("type") != "issuing_authorization.request":
        return None
    data = event.get("data")
    a = data.get("object") if isinstance(data, dict) else None
    a = a if isinstance(a, dict) else None
    pending = a.get("pending_request") if a else None
    pending = pending if isinstance(pending, dict) else None
    card = a.get("card") if a else None
    card = card if isinstance(card, dict) else None
    merchant = a.get("merchant_data") if a else None
    merchant = merchant if isinstance(merchant, dict) else None
    if a is None or pending is None or not isinstance(a.get("id"), str) or not isinstance(card.get("id") if card else None, str):
        return None
    amount, currency = pending.get("amount"), pending.get("currency")
    if not _isnum(amount) or not isinstance(currency, str):
        return None
    out: Dict[str, Any] = {"id": a["id"], "instrumentId": card["id"], "amount": amount, "currency": currency}
    nid = merchant.get("network_id") if merchant else None
    if isinstance(nid, str) and len(nid) > 0:
        out["merchantId"] = nid
    cc = merchant.get("category_code") if merchant else None
    if isinstance(cc, str):
        out["mcc"] = cc
    return out


def _reply(status: int, body: Any, version: str) -> Dict[str, Any]:
    return {"status": status, "headers": {"Stripe-Version": version, "Content-Type": "application/json"}, "body": J.js_json(body)}


def create_stripe_issuing_webhook(opts: Dict[str, Any]) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """The HTTP handler body for the `issuing_authorization.request` endpoint. Bad signature: 400 (nothing is decided). A request
    event gets 200 {approved} from the PCA decision; any other event type gets 200 {}. `amount` is never sent. opts: secret,
    authorize(RailAuthorization) -> verdict, stripeVersion, nowSec() , toleranceSec. REQUIRED OPERATOR SETTING: set the Issuing
    authorization timeout response to DECLINE and turn Autopilot off."""
    version = opts.get("stripeVersion") or STRIPE_API_VERSION
    now_sec = opts.get("nowSec") or (lambda: int(time.time()))

    def handle(req: Dict[str, Any]) -> Dict[str, Any]:
        raw, sig = req["rawBody"], req.get("signature")
        tol = opts.get("toleranceSec")
        if not verify_stripe_signature(raw, sig, opts["secret"], now_sec(), STRIPE_WEBHOOK_TOLERANCE_SEC if tol is None else tol):
            return _reply(400, {"error": "bad_signature"}, version)
        try:
            event = J.js_json_parse_no_duplicates(raw)  # a repeated member is refused (JSON.parse keeps the last); numbers stay as written
        except (ValueError, RecursionError):
            return _reply(400, {"error": "bad_json"}, version)
        if not isinstance(event, dict) or event.get("type") != "issuing_authorization.request":
            return _reply(200, {}, version)
        auth = stripe_authorization_from_event(event)
        if auth is None:
            return _reply(200, {"approved": False}, version)
        v = opts["authorize"](auth)
        return _reply(200, {"approved": v.get("approved") is True}, version)

    return handle


def stripe_settlement_from_transaction(txn: Any) -> Optional[Dict[str, Any]]:
    """Normalise an `issuing_transaction.created` capture into a settlement (a capture's amount is negative in Stripe's ledger)."""
    if not isinstance(txn, dict):
        return None
    m = txn.get("merchant_data")
    m = m if isinstance(m, dict) else None
    if (txn.get("type") != "capture" or not isinstance(txn.get("authorization"), str) or not _isnum(txn.get("amount"))
            or not isinstance(txn.get("currency"), str)):
        return None
    out: Dict[str, Any] = {"authorizationId": txn["authorization"], "amount": _num(-txn["amount"]), "currency": txn["currency"]}
    if m is not None and isinstance(m.get("network_id"), str):
        out["merchantId"] = m["network_id"]
    out["captures"] = 1
    return out


# ---- agent network tokens ---------------------------------------------------------------------------------------------------

_REF_RE = re.compile("[A-Za-z0-9_.:-]{8,128}")
_WS_DASH = re.compile("[" + _JS_WS + "-]")
_DIGITS = re.compile("[0-9]+")


def _luhn(d: str) -> bool:
    total, dbl = 0, False
    for ch in reversed(d):
        n = ord(ch) - 48
        if dbl:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        dbl = not dbl
    return total % 10 == 0


def looks_like_pan(s: str) -> bool:
    """True when a maximal digit run (spaces and hyphens removed) is 13..19 long and Luhn-valid. Whole runs only."""
    return any(13 <= len(r) <= 19 and _luhn(r) for r in _DIGITS.findall(_WS_DASH.sub("", s)))


def token_ref_error(ref: Any) -> Optional[str]:
    if not isinstance(ref, str) or _REF_RE.fullmatch(ref) is None:
        return "token_ref_malformed"
    if looks_like_pan(ref):
        return "token_ref_looks_like_pan"
    return None


def _body_of(b: Any) -> Dict[str, Any]:
    body = {"kind": NETWORK_TOKEN_BINDING_KIND, "v": 1, "provider": _prop(b, "provider"), "token_ref": _prop(b, "token_ref"),
            "grant_digest": _prop(b, "grant_digest"), "issuer_nonce": _prop(b, "issuer_nonce"), "holder": _prop(b, "holder")}
    if any(v is UNDEF for v in body.values()):
        raise TypeError("canonicalize: unsupported type undefined")
    return body


def binding_message(b: Any) -> bytes:
    """The exact bytes the holder signs: utf8 of the canonical-JSON digest of the binding body."""
    return hash_canonical(_body_of(b)).encode("utf-8")


def bind_network_token(opts: Dict[str, Any], allow_insecure_signer: bool = False) -> Dict[str, Any]:
    """Tie a grant holder to an OPAQUE network-token reference (never a PAN). opts: provider, tokenRef, grant, issuerNonce,
    holderSecret (32-byte seed), holderPublic (32 bytes)."""
    e = token_ref_error(opts.get("tokenRef"))
    if e is not None:
        raise ValueError("bindNetworkToken: %s" % e)
    n = _length(opts.get("issuerNonce"))
    if n is not UNDEF and n < 16:
        raise ValueError("bindNetworkToken: issuer nonce must be at least 16 chars")
    core = {"provider": opts.get("provider", UNDEF), "token_ref": opts["tokenRef"], "grant_digest": _hash(opts.get("grant", UNDEF)),
            "issuer_nonce": opts["issuerNonce"], "holder": b64u(bytes(opts["holderPublic"]))}
    proof = ed25519.sign_secret(bytes(opts["holderSecret"]), binding_message(core), allow_insecure_signer)
    return dict({"kind": NETWORK_TOKEN_BINDING_KIND}, **core, binding_proof=b64u(proof))


def verify_network_token_binding(b: Any, expect: Any) -> Optional[str]:
    """Total. None = valid. `expect`: grant (the one the caller verified), holder (b64u), issuerNonce, optional provider."""
    try:
        if b is None or not isinstance(b, (dict, list)) or _prop(b, "kind") != NETWORK_TOKEN_BINDING_KIND:
            return "binding_malformed"
        e = token_ref_error(_prop(b, "token_ref"))
        if e is not None:
            return e
        prov, exp_prov = _prop(b, "provider"), _prop(expect, "provider")
        if not isinstance(prov, str) or len(prov) == 0 or (exp_prov is not UNDEF and not _seq(prov, exp_prov)):
            return "provider_mismatch"
        if not _seq(_prop(b, "grant_digest"), _hash(_prop(expect, "grant"))):
            return "grant_digest_mismatch"
        if not _seq(_prop(b, "holder"), _prop(expect, "holder")):
            return "holder_mismatch"
        if not _seq(_prop(b, "issuer_nonce"), _prop(expect, "issuerNonce")):
            return "issuer_nonce_mismatch"
        pk, sg = decode_b64u_strict(_prop(b, "holder")), decode_b64u_strict(_prop(b, "binding_proof"))
        if pk is None or sg is None:
            return "binding_malformed"
        return None if ed25519.verify(pk, binding_message(b), sg) else "binding_proof_invalid"
    except Exception:  # noqa: BLE001
        return "binding_malformed"


def controls_from_limits(limits: Dict[str, Any], grant: Any) -> Dict[str, Any]:
    """The network-side controls: always an upper-bounded copy of the rail limits."""
    c = {"currency": limits["currency"], "perAuthorizationMax": limits["perAuthorizationMax"], "totalMax": limits["totalMax"],
         "categories": list(limits["categories"]), "merchants": list(limits["merchants"])}
    if limits.get("expiresAt") is not None:
        c["expiresAt"] = limits["expiresAt"]
    c["metadata"] = {"grant_digest": hash_canonical(grant)}
    return c


def settlement_metadata(b: Dict[str, Any], pcactn_digest: str) -> Dict[str, str]:
    return {"pca_grant": b["grant_digest"], "pca_pcactn": pcactn_digest, "pca_token_ref": b["token_ref"]}


def reconcile_network_settlement(expected: Dict[str, Any], record: Any) -> Dict[str, Any]:
    """A network settlement record joins the ledger entry only if all three echoed values match exactly."""
    md = _optprop(record, "metadata") if record is not None else UNDEF
    m = {} if _nullish(md) else md
    reasons: List[str] = []
    ped = _prop(m, "pca_pcactn")
    if not isinstance(ped, str) or len(ped) == 0 or _length(_prop(expected, "pcactnDigest")) == 0:
        reasons.append("pcactn_digest_missing")
    if not _seq(_prop(m, "pca_grant"), _prop(expected, "grantDigest")):
        reasons.append("grant_digest_mismatch")
    if not _seq(ped, _prop(expected, "pcactnDigest")):
        reasons.append("pcactn_digest_mismatch")
    if not _seq(_prop(m, "pca_token_ref"), _prop(expected, "tokenRef")):
        reasons.append("token_ref_mismatch")
    return {"ok": True} if not reasons else {"ok": False, "reasons": reasons}


def charge_with_network_token(binding: Dict[str, Any], mandate: Any, charge: Any, opts: Dict[str, Any],
                              allow_insecure_signer: bool = False) -> Dict[str, Any]:
    """Build the PCActn for the charge and return the metadata for the network request, derived from THAT PCActn's digest:
    there is no way to carry a digest that is not of a PCActn this call built."""
    if token_ref_error(_prop(binding, "token_ref")) is not None:
        raise ValueError("chargeWithNetworkToken: bad binding")
    if not _seq(_prop(binding, "grant_digest"), _hash(_prop(mandate, "grant"))):
        raise ValueError("chargeWithNetworkToken: binding is for another grant")
    built = charge_to_pcactn(mandate, charge, opts, allow_insecure_signer)
    digest = hash_canonical(built["pcactn"])
    return {"pcactn": built["pcactn"], "node": built["node"], "metadata": settlement_metadata(binding, digest), "pcactnDigest": digest}


# ---- partner adapters (no network calls of their own: the transport is injected) -----------------------------------------------

class NetworkTokenProvider:
    def __init__(self, id_: str, issue: Callable[[Dict[str, Any]], Dict[str, str]], suspend: Callable[[str, str], None]):
        self.id, self.issue, self.suspend = id_, issue, suspend


def _partner_adapter(id_: str, scope_key: str) -> Callable[[Callable[[str, Dict[str, Any]], Dict[str, Any]]], NetworkTokenProvider]:
    def make(post: Callable[[str, Dict[str, Any]], Dict[str, Any]]) -> NetworkTokenProvider:
        def issue(req: Dict[str, Any]) -> Dict[str, str]:
            c = req["controls"]
            scope = {"currency": c["currency"], "per_authorization_max": c["perAuthorizationMax"], "total_max": c["totalMax"],
                     "merchant_categories": c["categories"], "merchants": c["merchants"]}
            if c.get("expiresAt") is not None:
                scope["expires_at"] = c["expiresAt"]
            r = post("/tokens", {"agent_id": req["agentId"], scope_key: scope, "metadata": c["metadata"]})
            ref = r.get("token_ref")
            e = token_ref_error(ref)
            if e is not None:
                raise ValueError("%s: provider returned %s" % (id_, e))
            return {"token_ref": ref}

        def suspend(token_ref: str, reason: str) -> None:
            post("/tokens/%s/suspend" % quote(token_ref, safe="-_.!~*'()"), {"reason": reason})

        return NetworkTokenProvider(id_, issue, suspend)

    return make


# Generic mappings of PCA controls onto a neutral control shape; the partner wire formats are access-gated.
visa_intelligent_commerce_adapter = _partner_adapter("visa_ic", "instructions")
mastercard_agent_pay_adapter = _partner_adapter("mastercard_agent_pay", "session_scope")


def issue_bound_network_token(opts: Dict[str, Any], allow_insecure_signer: bool = False) -> Dict[str, Any]:
    """Issuance gate: issue a token whose controls equal the rail limits, then bind it to the grant holder. opts: provider,
    limits, grant, agentId, holderSecret, holderPublic, issuerNonce."""
    controls = controls_from_limits(opts["limits"], opts["grant"])
    ref = opts["provider"].issue({"controls": controls, "agentId": opts["agentId"]})["token_ref"]
    binding = bind_network_token({"provider": opts["provider"].id, "tokenRef": ref, "grant": opts["grant"],
                                  "issuerNonce": opts["issuerNonce"], "holderSecret": opts["holderSecret"],
                                  "holderPublic": opts["holderPublic"]}, allow_insecure_signer)
    return {"binding": binding, "controls": controls}


def suspend_on_revoke(provider: NetworkTokenProvider, binding: Dict[str, Any]) -> None:
    """Grant revoked => suspend. Provider errors propagate (a failed suspend is not a success)."""
    provider.suspend(binding["token_ref"], "grant_revoked")


def open_charge_bond(pcactn: Any, opts: Dict[str, Any], signer_secret: bytes, allow_insecure_signer: bool = False) -> Dict[str, Any]:
    """Open the optimistic bonded claim for a charge (the dispute / refund window): a signed, bonded claim of compliance a watchtower can
    challenge. Thin wrapper over `optimistic.open_optimistic`; refuses an irreversible charge. `opts`: bondRef, claimedR, challengeWindowMs?,
    issuedAt?, serverNow?, windowPolicy?."""
    from .optimistic import open_optimistic  # deferred: keeps the payments import graph unchanged
    return open_optimistic(pcactn, opts, signer_secret, allow_insecure_signer)


class _MemoryChargeBudgetStore:
    def __init__(self) -> None:
        self._m: Dict[str, dict] = {}

    def get(self, key: str) -> Optional[dict]:
        return self._m.get(key)

    def compare_and_set(self, key: str, expected: Optional[int], budget: dict) -> bool:
        cur = self._m.get(key)
        if (cur["version"] if cur else None) != expected:
            return False
        self._m[key] = {"budget": budget, "version": (expected or 0) + 1}
        return True


def memory_charge_budget_store() -> Any:
    """A single-process reference ChargeBudgetStore for tests (``get`` and ``compare_and_set``); production needs a durable store with a
    conditional write."""
    return _MemoryChargeBudgetStore()
