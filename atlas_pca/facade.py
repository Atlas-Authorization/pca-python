"""The high-level agent facade: compile a principal's human-level inputs (permissions, limits) into a signed grant, and act.

    from atlas_pca import create_agent, keypair_from_seed

    a = create_agent(principal=principal_key, goal="reconcile refunds for October",
                     permissions={"stripe": ["refund"], "gmail": ["send"]}, limits={"refund": "$500/day"},
                     aud="https://api.example.com")
    r = a.act("stripe.refund", "charge:ch_123", {"amount": 42, "currency": "usd"})
    requests.post(url, json=body, headers=r["headers"])      # PCA-Action + PCA-Provenance

`create_agent` compiles the permissions into predicates, caveats and a risk policy (`compile_policy`), creates the
provenance recorder whose key the grant's signed envelope names, and mints the root grant. `act` builds a signed PCActn per
tool call with its provenance bundle; `dry_run` is a local, NON-authoritative pre-check. Nothing here authorizes anything:
the resource server's verifier decides. Same compile and wire as the TypeScript reference's `agent()`.

Keep the provenance recorder in the harness, out of the model's reach (never expose `agent.provenance` as a tool).
"""
import math
import re
import time
from typing import Any, Dict, List, Optional, Sequence

from .agent import KeyPair, build_pcactn, delegate, generate_keypair, mint_grant, pca_headers
from .arg_provenance import ProvenanceRecorder, create_provenance_recorder
from .pca import REVERSIBILITY_ORDER, canonicalize, evaluate_caveats, params_digest
from .predicates import _js_number_string, _js_string, evaluate_predicates
from .risk import DEFAULT_RISK_POLICY, admit, safety_bound, validate_risk_policy

__all__ = ["create_agent", "compile_policy", "parse_limit", "AgentHandle", "MAX_LIMIT_LENGTH", "BUILTIN_ACTIONS"]

# ---- limit parsing ----------------------------------------------------------------------------------------------------------

PERIODS = {
    "s": 1000, "sec": 1000, "second": 1000, "seconds": 1000,
    "m": 60_000, "min": 60_000, "minute": 60_000, "minutes": 60_000,
    "h": 3_600_000, "hr": 3_600_000, "hour": 3_600_000, "hours": 3_600_000,
    "d": 86_400_000, "day": 86_400_000, "days": 86_400_000,
    "w": 604_800_000, "week": 604_800_000, "weeks": 604_800_000,
    "mo": 2_592_000_000, "month": 2_592_000_000, "months": 2_592_000_000,
}
MAX_LIMIT_LENGTH = 64
# ECMAScript WhiteSpace + LineTerminator (what String.prototype.trim and \s cover)
_JS_WS = "\t\n\x0b\x0c\r                  　﻿"
_S = "[" + re.escape(_JS_WS) + "]*"
_LIMIT_RE = re.compile(r"(\$)?" + _S + r"([0-9]+(?:\.[0-9]+)?)" + _S + r"(?:/" + _S + r"([a-zA-Z]+))?")
_MAX_SAFE = 9007199254740991


# The built-in connector actions the facade compiles permissions against: the reference catalog (effective reversibility and
# blast radius). Generated data, do not edit by hand; test_catalog_builtin.py checks it against the reference source.
BUILTIN_ACTIONS = [
    {"connector": "stripe", "action": "charge", "verb": "stripe.charge", "reversibility": "irreversible", "blastRadius": 0.9, "amountField": "amount", "description": "Charge a customer. Refundable in practice, but a charge is treated as final.", "aliases": ["bill", "charge_customer"], "traits": ["pca.irreversible", "pca.money_moving"]},
    {"connector": "stripe", "action": "refund", "verb": "stripe.refund", "reversibility": "irreversible", "blastRadius": 0.9, "amountField": "amount", "description": "Returns money for a charge to the customer.", "aliases": ["issue_refund", "refund", "refund_charge", "reimburse"], "traits": ["pca.irreversible", "pca.money_moving"]},
    {"connector": "stripe", "action": "payout", "verb": "stripe.payout", "reversibility": "irreversible", "blastRadius": 0.9, "amountField": "amount", "description": "Moves funds from a Stripe balance to a bank account.", "aliases": ["pay_out", "payout"], "traits": ["pca.irreversible", "pca.money_moving"]},
    {"connector": "stripe", "action": "create_customer", "verb": "stripe.create_customer", "reversibility": "rate_limited", "blastRadius": 0.2, "description": "Creates a customer record.", "traits": ["pca.pii_access"]},
    {"connector": "gmail", "action": "send", "verb": "gmail.send", "reversibility": "irreversible", "blastRadius": 0.8, "description": "Sends an email to people outside your organisation.", "aliases": ["send_email"], "traits": ["pca.external_communication", "pca.irreversible", "pca.pii_access"]},
    {"connector": "gmail", "action": "draft", "verb": "gmail.draft", "reversibility": "reversible", "blastRadius": 0.2, "description": "Saves an email draft without sending it.", "traits": ["pca.pii_access"]},
    {"connector": "gmail", "action": "delete", "verb": "gmail.delete", "reversibility": "irreversible", "blastRadius": 0.8, "description": "Permanently deletes a message.", "traits": ["pca.destructive", "pca.irreversible"]},
    {"connector": "github", "action": "read", "verb": "github.read", "reversibility": "reversible", "blastRadius": 0.05, "description": "Reads files from a repository.", "traits": []},
    {"connector": "github", "action": "create_pr", "verb": "github.create_pr", "reversibility": "irreversible", "blastRadius": 0.2, "description": "Opens a pull request, which is visible to everyone with access to the repository.", "traits": ["pca.external_communication", "pca.irreversible"]},
    {"connector": "github", "action": "comment", "verb": "github.comment", "reversibility": "irreversible", "blastRadius": 0.2, "description": "Posts a comment, visible to everyone with access to the repository.", "traits": ["pca.external_communication", "pca.irreversible"]},
    {"connector": "github", "action": "merge_pr", "verb": "github.merge_pr", "reversibility": "irreversible", "blastRadius": 0.5, "description": "Merges a pull request, which can trigger deploys and other downstream effects.", "traits": ["pca.irreversible"]},
    {"connector": "github", "action": "delete_repo", "verb": "github.delete_repo", "reversibility": "irreversible", "blastRadius": 0.8, "description": "Deletes a repository and everything in it.", "traits": ["pca.destructive", "pca.irreversible"]},
    {"connector": "slack", "action": "post_message", "verb": "slack.post_message", "reversibility": "irreversible", "blastRadius": 0.5, "description": "Posts a message that members of the channel can read.", "traits": ["pca.bulk", "pca.external_communication", "pca.irreversible"]},
    {"connector": "slack", "action": "read", "verb": "slack.read", "reversibility": "reversible", "blastRadius": 0.05, "description": "Reads the message history of a channel.", "traits": []},
    {"connector": "calendar", "action": "create_event", "verb": "calendar.create_event", "reversibility": "irreversible", "blastRadius": 0.2, "description": "Creates an event and sends invitations to its attendees.", "traits": ["pca.external_communication", "pca.irreversible", "pca.pii_access"]},
    {"connector": "calendar", "action": "delete_event", "verb": "calendar.delete_event", "reversibility": "rate_limited", "blastRadius": 0.5, "description": "Deletes a calendar event.", "traits": ["pca.destructive"]},
    {"connector": "files", "action": "read", "verb": "files.read", "reversibility": "reversible", "blastRadius": 0.05, "description": "Reads files.", "traits": ["pca.bulk"]},
    {"connector": "files", "action": "write", "verb": "files.write", "reversibility": "rate_limited", "blastRadius": 0.5, "description": "Writes or overwrites files.", "traits": ["pca.bulk"]},
    {"connector": "files", "action": "delete", "verb": "files.delete", "reversibility": "irreversible", "blastRadius": 0.8, "description": "Deletes files.", "traits": ["pca.bulk", "pca.destructive", "pca.irreversible"]},
    {"connector": "http", "action": "get", "verb": "http.get", "reversibility": "reversible", "blastRadius": 0.05, "description": "Fetches a URL.", "traits": ["pca.bulk", "pca.network_egress"]},
    {"connector": "http", "action": "post", "verb": "http.post", "reversibility": "rate_limited", "blastRadius": 0.5, "description": "Posts a body to a URL.", "traits": ["pca.bulk", "pca.network_egress"]},
]


def _u16len(s: str) -> int:
    return sum(2 if ord(c) > 0xFFFF else 1 for c in s)


def _js_num(text: str) -> Any:
    v = float(text)
    return int(v) if v.is_integer() and abs(v) <= _MAX_SAFE else v


def parse_limit(s: Any) -> Dict[str, Any]:
    """Parse "$500/day", "$500", "10/hour", "10" into {"amount", "unit": "usd" | "count", "periodMs"?}. Raises ValueError on
    anything malformed or longer than 64 characters."""
    if not isinstance(s, str) or len(s.strip(_JS_WS)) == 0:
        raise ValueError("parseLimit: empty limit")
    if _u16len(s) > MAX_LIMIT_LENGTH:
        raise ValueError("parseLimit: limit is longer than %d characters" % MAX_LIMIT_LENGTH)
    m = _LIMIT_RE.fullmatch(s.strip(_JS_WS))
    if not m:
        raise ValueError("parseLimit: cannot parse limit '%s'" % s)
    amount = _js_num(m.group(2))
    if not math.isfinite(amount) or amount < 0:
        raise ValueError("parseLimit: bad amount in '%s'" % s)
    out: Dict[str, Any] = {"amount": amount, "unit": "usd" if m.group(1) == "$" else "count"}
    if m.group(3) is not None:
        p = PERIODS.get(m.group(3).lower())
        if p is None:
            raise ValueError("parseLimit: unknown period '%s' in '%s'" % (m.group(3), s))
        out["periodMs"] = p
    return out


# ---- catalog ----------------------------------------------------------------------------------------------------------------

class _Catalog:
    def __init__(self, actions: Sequence[dict]):
        self._by_verb: Dict[str, dict] = {}
        for a in actions:
            self._by_verb[a["verb"]] = a  # later specs override earlier ones

    def get(self, verb: str) -> Optional[dict]:
        return self._by_verb.get(verb)

    def resolve(self, connector: str, action: str) -> Optional[dict]:
        exact = self._by_verb.get(connector + "." + action)
        if exact:
            return exact
        hits = [a for a in self._by_verb.values() if a.get("connector") == connector and action in (a.get("aliases") or [])]
        return hits[0] if len(hits) == 1 else None


def _spec_for(catalog: _Catalog, verb: str) -> dict:
    s = catalog.get(verb)
    if s:
        return s
    dot = verb.find(".")
    if dot > 0:  # an alias of exactly one action of the connector; never a guess
        via = catalog.resolve(verb[:dot], verb[dot + 1:])
        if via:
            return via
    parts = verb.split(".")
    # an uncatalogued verb counts as irreversible with a high blast radius
    return {"connector": parts[0], "action": ".".join(parts[1:]) or verb, "verb": verb, "reversibility": "irreversible",
            "blastRadius": 0.8, "description": "(uncatalogued) %s" % verb}


def _sev(cls: Any) -> int:
    return REVERSIBILITY_ORDER.index(cls) if cls in REVERSIBILITY_ORDER else -1


def _catalog_of(catalog: Optional[Sequence[dict]]) -> _Catalog:
    return _Catalog(BUILTIN_ACTIONS if catalog is None else catalog)


# ---- compile ----------------------------------------------------------------------------------------------------------------

def compile_policy(permissions: Dict[str, Sequence[str]], limits: Optional[Dict[str, str]] = None,
                   catalog: Optional[Sequence[dict]] = None, budget_model: Optional[str] = None,
                   risk_policy: Optional[Dict[str, Any]] = None, now: Optional[int] = None) -> Dict[str, Any]:
    """Compile permissions ({connector: [actions]}) and limits ({action or connector.action: "$N[/period]" | "N[/period]"})
    into {predicates, caveats, riskPolicy, actions, budgetModel, limits, inputLimits, approximations}. Pure: no keys.

    A money limit becomes a per-call ceiling on the action's amount field; a period becomes the grant lifetime (`expires`);
    each count limit with a period becomes one `rate` caveat; `reversibility_max` is the strictest granted class. A money
    limit on a verb without an amount field is refused (it could not be enforced)."""
    cat = _catalog_of(catalog)
    at = now if now is not None else int(time.time() * 1000)
    raw_limits = limits if limits is not None else {}
    if not isinstance(permissions, dict):
        raise ValueError("compilePolicy: permissions must be an object")
    actions: List[dict] = []
    for connector, acts in permissions.items():
        if not isinstance(acts, list):
            raise ValueError("compilePolicy: permissions.%s must be an array" % connector)
        for action in acts:
            actions.append(_spec_for(cat, "%s.%s" % (connector, _js_string(action))))
    if not actions:
        raise ValueError("compilePolicy: no permissions granted")

    def own(key: Any) -> Any:  # own keys only; a JSON null is no limit
        return raw_limits.get(key) if isinstance(raw_limits, dict) and isinstance(key, str) else None

    parsed: Dict[str, dict] = {}

    def limit_for(s: dict) -> Optional[dict]:
        raw = own(s["verb"])
        if raw is None:
            raw = own(s.get("action"))
        for a in s.get("aliases") or []:
            if raw is None:
                raw = own(a)
        if raw is None:
            return None
        lim = parse_limit(raw)
        parsed[s["verb"]] = lim
        return lim

    predicates = []
    for s in actions:
        where = []
        lim = limit_for(s)
        if lim and lim["unit"] == "usd" and not s.get("amountField"):
            raise ValueError("compilePolicy: '$' limit on '%s' but the catalog gives that verb no amount field, so the limit "
                             "could not be enforced" % s["verb"])
        if lim and lim["unit"] == "usd":
            where.append({"field": "action.params.%s" % s["amountField"], "op": "lte", "value": lim["amount"]})
            where.append({"field": "action.params.%s" % s["amountField"], "op": "gte", "value": 0})
        p: Dict[str, Any] = {"verb": s["verb"], "resource": s.get("resource") or "*"}
        if where:
            p["where"] = where
        predicates.append(p)

    caveats: List[dict] = []
    strictest = "reversible"
    for s in actions:
        if _sev(s.get("reversibility")) > _sev(strictest):
            strictest = s["reversibility"]
    caveats.append({"type": "reversibility_max", "class": strictest})
    periods = [l["periodMs"] for l in parsed.values() if "periodMs" in l]
    if periods:
        caveats.append({"type": "expires", "at": at + min(periods)})
    for l in parsed.values():  # one rate caveat per count limit: a second limit can only narrow
        if l["unit"] == "count" and l.get("periodMs"):
            caveats.append({"type": "rate", "max": l["amount"], "per_secs": max(1, int(math.floor(l["periodMs"] / 1000 + 0.5)))})

    dollars = [l for l in parsed.values() if l["unit"] == "usd"]
    model = "dollars" if budget_model == "dollars" else "risk" if budget_model == "risk" else ("dollars" if dollars else "risk")
    irreversible = any(s.get("reversibility") == "irreversible" for s in actions)
    if model == "dollars" and dollars:
        kappa = max(l["amount"] for l in dollars)
        b_max: Any = 0
        for l in dollars:
            b_max = b_max + l["amount"]
        rp: Dict[str, Any] = {
            "weights": {"alpha": 0, "beta": 0, "gamma": 1, "delta": 0, "epsilon": 0, "zeta": 0},
            # within-cap actions auto-approve only when nothing granted is irreversible
            "theta1": DEFAULT_RISK_POLICY["theta1"] if irreversible else 1,
            "theta2": DEFAULT_RISK_POLICY["theta2"] if irreversible else 1,
            "kappa": kappa if kappa > 0 else 1,
            "lambda": 0,
            "rho": DEFAULT_RISK_POLICY["rho"],
            "bMax": b_max if b_max > 0 else 1,
        }
    else:
        rp = dict(DEFAULT_RISK_POLICY, weights=dict(DEFAULT_RISK_POLICY["weights"]))
    if risk_policy:
        w = dict(rp["weights"])
        w.update(risk_policy.get("weights") or {})
        rp = dict(rp, **risk_policy)
        rp["weights"] = w
    bad = validate_risk_policy(rp)
    if bad:
        raise ValueError("compilePolicy: derived risk policy invalid: %s" % bad)
    approximations = ["%s: $%s/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap"
                      % (v, _js_number_string(float(l["amount"]))) for v, l in parsed.items()
                      if l["unit"] == "usd" and "periodMs" in l]
    # member names are the reference's (riskPolicy, budgetModel, periodMs, inputLimits) so a compiled policy is the same JSON
    return {"predicates": predicates, "caveats": caveats, "riskPolicy": rp, "actions": actions, "budgetModel": model,
            "limits": parsed, "inputLimits": dict(raw_limits), "approximations": approximations}


# ---- the agent handle -------------------------------------------------------------------------------------------------------

_NUM_RE = re.compile(r"[+-]?(?:Infinity|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)")
_RADIX = ((re.compile(r"0[xX][0-9a-fA-F]+"), 16), (re.compile(r"0[oO][0-7]+"), 8), (re.compile(r"0[bB][01]+"), 2))


def _string_to_number(s: str) -> float:
    t = s.strip(_JS_WS)
    if t == "":
        return 0.0
    for rx, base in _RADIX:
        if rx.fullmatch(t):
            return float(int(t[2:], base))
    if _NUM_RE.fullmatch(t):
        return float(t.replace("Infinity", "inf"))
    return math.nan


def _to_number(params: Optional[dict], field: str) -> float:
    """ECMAScript Number(params[field])."""
    if not isinstance(params, dict) or field not in params:
        return math.nan
    v = params[field]
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, (str, list)):
        return _string_to_number(_js_string(v))
    return math.nan


def _clamp01(x: Any) -> Any:
    return x if x != x else max(0, min(1, x))


def _risk_for(policy: dict, spec: dict, params: Optional[dict], override: Any = None) -> Any:
    if isinstance(override, (int, float)) and not isinstance(override, bool):
        return _clamp01(override)
    if policy["budgetModel"] == "dollars" and spec.get("amountField"):
        amt = _to_number(params, spec["amountField"])
        if math.isfinite(amt) and policy["riskPolicy"]["kappa"] > 0:
            return _clamp01(amt / policy["riskPolicy"]["kappa"])
    return _clamp01(spec["blastRadius"])


class AgentHandle:
    """What `create_agent` returns: the signed grant and chain, the compiled policy, the holder key, the starting trust
    budget, and `act` / `dry_run` / `sub_agent` / `encode_grant`. `provenance` is the session's recorder: record the
    principal's message and every tool, retrieval or web result entering the model's context; `act` appends the action."""

    def __init__(self, grant: dict, chain: List[dict], goal_salt: str, policy: dict, holder: KeyPair, principal_public: str,
                 catalog: _Catalog, default_aud: Optional[str], start_now: int, provenance: Optional[ProvenanceRecorder]):
        self.grant, self.chain, self.goal_salt, self.policy = grant, chain, goal_salt, policy
        self.holder, self.principal_public, self.provenance = holder, principal_public, provenance
        self._catalog, self._aud, self._start_now = catalog, default_aud, start_now
        self.counter = 0
        rp = policy["riskPolicy"]
        self.budget = {"B": rp["bMax"], "tau": start_now, "asOf": start_now}
        self.autonomy_bound = safety_bound(rp) * rp["kappa"]

    def dry_run(self, verb: str, resource: str, params: Optional[dict] = None, now: Optional[int] = None) -> Dict[str, Any]:
        """Local, NON-authoritative pre-check of the grant's own predicates and caveats: {"allowed", "reason"?, "t"?} where `t`
        is the risk tier the compiled policy would assign (1 automatic, 2, 3 human co-sign)."""
        spec = _spec_for(self._catalog, verb)
        at = now if now is not None else int(time.time() * 1000)
        ctx = {"action": {"verb": verb, "resource": resource, "params": params if params is not None else {},
                          "reversibility_class": spec["reversibility"]}}
        pred = evaluate_predicates(self.policy["predicates"], ctx)
        if not pred["allowed"]:
            return {"allowed": False, "reason": pred.get("reason") or "no predicate matched"}
        ok, failed = evaluate_caveats(self.policy["caveats"], {
            "now": at, "blast_radius": spec["blastRadius"], "reversibility_class": spec["reversibility"],
            "delegation_depth": len(self.chain) - 1,
            # the local handle has no admitted-action history (the server meters it)
            "recent_action_times": []})
        if not ok:
            return {"allowed": False, "reason": "caveat(s) failed: %s" % ", ".join(failed)}
        adm = admit(_risk_for(self.policy, spec, params), self.budget, self.policy["riskPolicy"])
        return {"allowed": True, "t": adm["t"]}

    def act(self, verb: str, resource: str, params: Optional[dict] = None, counter: Optional[int] = None,
            aud: Optional[str] = None, now: Optional[int] = None, ttl_ms: Optional[int] = None, nonce: Optional[str] = None,
            caution: Optional[float] = None, risk: Optional[float] = None) -> Dict[str, Any]:
        """Build a proof-carrying action (it does NOT authorize). Returns {"pcactn", "encoded", "headers", "dry_run",
        "provenance"}: POST with `headers` (PCA-Action, and PCA-Provenance when the bundle fits a header; else send
        `provenance` as the body member `pca_provenance`). The counter auto-increments; no nonce unless given."""
        a = aud if aud is not None else self._aud
        if not a:
            raise ValueError("act: aud (resource-server / instance id) is required (pass aud= here or to create_agent)")
        spec = _spec_for(self._catalog, verb)
        # the node commits the SAME params digest the action carries, else plan inclusion fails
        node = {"id": "n0", "verb": verb, "resource": resource, "reversibility_class": spec["reversibility"],
                "params_digest": params_digest(params)}
        r = _risk_for(self.policy, spec, params, risk)
        if counter is None:
            self.counter += 1
            use = self.counter
        else:
            use = counter
            self.counter = max(self.counter, counter)
        kw: Dict[str, Any] = {}
        if ttl_ms is not None:
            kw["ttl_ms"] = ttl_ms
        pcactn = build_pcactn(self.grant, self.chain, [node], "n0", use, self.holder, a, params=params, now=now, nonce=nonce,
                              caution=caution, risk_claim={"r": r, "inputs": {"blastRadius": r}}, **kw)
        bundle = self.provenance.for_action({"verb": verb, "resource": resource,
                                             "params": params if params is not None else {}}) if self.provenance else None
        return {"pcactn": pcactn, "encoded": canonicalize(pcactn), "headers": pca_headers(pcactn, provenance=bundle),
                "dry_run": self.dry_run(verb, resource, params, now), "provenance": bundle}

    def sub_agent(self, holder: Optional[KeyPair] = None, added_caveats: Sequence[dict] = ()) -> "AgentHandle":
        """A new handle for a sub-agent (a fresh Ed25519 holder unless given) whose chain has one more, narrower hop signed
        by this holder. It shares the policy, catalog and provenance recorder."""
        sub = holder if holder is not None else generate_keypair()
        child = delegate(self.chain[-1], self.holder, sub.public, added_caveats)
        return AgentHandle(self.grant, self.chain + [child], self.goal_salt, self.policy, sub, self.principal_public,
                           self._catalog, self._aud, self._start_now, self.provenance)

    def encode_grant(self) -> str:
        """The grant as JSON text (canonical) for transport or inspection."""
        return canonicalize(self.grant)


def create_agent(principal: KeyPair, goal: str, permissions: Dict[str, Sequence[str]], limits: Optional[Dict[str, str]] = None,
                 holder: Optional[KeyPair] = None, agent_binding: Optional[dict] = None,
                 risk_policy: Optional[Dict[str, Any]] = None, budget_model: Optional[str] = None,
                 catalog: Optional[Sequence[dict]] = None, aud: Optional[str] = None, now: Optional[int] = None,
                 goal_salt: Optional[str] = None, provenance: Optional[Dict[str, Any]] = None) -> AgentHandle:
    """Compile the principal's inputs into a signed root grant for `holder` (generated when omitted) and return the handle.

    `limits` keys are a bare action ("refund"), a full verb ("stripe.refund") or an alias. `budget_model` "dollars" makes
    spend = risk exact when limits are monetary ("auto", the default, picks it iff a "$" limit is present). `provenance`
    overrides the recorder's options (mediator "agent-harness", kid "k1", secret_key, session, now, alg, pq); its key is
    named in the grant's signed envelope (`provenance.mediators`). `goal_salt` fixes the goal commitment's salt."""
    cat = _catalog_of(catalog)
    at = now if now is not None else int(time.time() * 1000)
    h = holder if holder is not None else generate_keypair()
    policy = compile_policy(permissions, limits, catalog, budget_model, risk_policy, at)
    opts: Dict[str, Any] = {"mediator": "agent-harness", "kid": "k1"}
    opts.update(provenance or {})
    recorder = create_provenance_recorder(**opts)
    minted = mint_grant(principal, h.public, {
        "predicates": policy["predicates"], "caveats": policy["caveats"],
        "agent_binding": agent_binding if agent_binding is not None else {}, "risk_policy": policy["riskPolicy"],
        # the principal designates the harness's mediator key: a verifier trusts its labels with no extra configuration
        "provenance": {"mediators": [recorder.pin]}}, goal, salt=goal_salt)
    grant = minted["grant"]
    return AgentHandle(grant, [grant], minted["goal_salt"], policy, h, principal.public, cat, aud, at, recorder)
