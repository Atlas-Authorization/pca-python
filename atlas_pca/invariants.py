"""Property-based machine-checking of PCA's core safety invariants: attenuation monotonicity, budget soundness, fail-closed
behaviour and determinism, run against the real atlas_pca core (nothing is re-implemented). Port of @atlasauth/pca-invariants of
the TypeScript reference.

The arbitraries are stdlib generators over a `random.Random` (the reference uses a property-testing library with its own
generator and shrinking; neither is reproduced, so a given seed explores different cases than the reference). A property is a
callable `prop(rng) -> bool`; `check_invariants` runs each one `num_runs` times from a fixed seed and reports a failing case's
seed so it can be replayed.
"""
from __future__ import annotations

from ._fin import fin
import copy
import math
import random
from typing import Any, Callable, Dict, List, Optional

from . import ed25519 as _ed
from . import prohibitions
from .agent import KeyPair, delegate, mint_root
from .forbid_certificate import decide_clauses
from .pca import _caveat_satisfied, allocations_monotone, b64u, evaluate_caveats, hash_canonical, verify_chain
from .predicates import evaluate_condition, evaluate_condition_tri, evaluate_predicates
from .risk import admit, cost, required_threshold, risk_score, safety_bound, validate_risk_policy

DEFAULT_SEED = 20260108
DEFAULT_NUM_RUNS = 1000
_EPS = 1e-9

Prop = Callable[[random.Random], bool]


# ---- primitive generators ------------------------------------------------------------------------------------------------

def _int(rng: random.Random, lo: int, hi: int) -> int:
    return rng.randint(lo, hi)


def _dbl(rng: random.Random, lo: float, hi: float) -> float:
    """A double in [lo, hi], the endpoints included on purpose."""
    r = rng.random()
    if r < 0.08:
        return lo
    if r < 0.16:
        return hi
    return lo + (hi - lo) * rng.random()


def _string(rng: random.Random, lo: int = 0, hi: int = 10) -> str:
    return "".join(chr(rng.randint(0x20, 0x7E)) for _ in range(rng.randint(lo, hi)))


def _array(rng: random.Random, gen: Callable[[random.Random], Any], lo: int, hi: int) -> list:
    return [gen(rng) for _ in range(rng.randint(lo, hi))]


def arb_seed32(rng: random.Random) -> bytes:
    """32 random bytes: a reproducible Ed25519 secret seed."""
    return bytes(rng.getrandbits(8) for _ in range(32))


def key_pair_from_seed(seed: bytes) -> Dict[str, Any]:
    """{secret_key, public_key, pub (b64u), signer}: any 32 bytes is a valid Ed25519 secret. `signer` falls back to the built-in
    (non constant-time) signer when `cryptography` is absent, which is fine for generated test keys."""
    signer = KeyPair(seed, allow_insecure_signer=True)
    return {"secret_key": seed, "public_key": _ed.public_key(seed), "pub": signer.public, "signer": signer}


# ---- predicates, actions, caveat contexts ----------------------------------------------------------------------------------

_VERBS = ["read", "write", "delete", "transfer", "list", "admin"]
_RESOURCES = ["/acct/a", "/acct/b", "/docs/1", "/docs/2", "/x/y", "/"]
_LEAF_OPS = ["eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists"]
_LEAF_FIELDS = ["subject.role", "subject.tier", "env.ip", "action.verb", "action.resource", "action.params.amount"]


def arb_verb(rng: random.Random) -> str:
    return rng.choice(_VERBS)


def arb_resource(rng: random.Random) -> str:
    return rng.choice(_RESOURCES) if rng.random() < 0.5 else _string(rng)


def arb_leaf_condition(rng: random.Random) -> Dict[str, Any]:
    pick = rng.randint(0, 3)
    value: Any = (_string(rng) if pick == 0 else _int(rng, -10, 10) if pick == 1 else rng.random() < 0.5 if pick == 2
                  else _array(rng, _string, 0, 3))
    return {"field": rng.choice(_LEAF_FIELDS), "op": rng.choice(_LEAF_OPS), "value": value}


arb_condition = arb_leaf_condition


def arb_predicate(rng: random.Random) -> Dict[str, Any]:
    k = rng.randint(0, 2)
    verb: Any = arb_verb(rng) if k == 0 else _array(rng, arb_verb, 1, 3) if k == 1 else "*"
    rk = rng.randint(0, 3)
    p: Dict[str, Any] = {"verb": verb}
    if rk == 1:
        p["resource"] = "*"
    elif rk == 2:
        p["resource"] = rng.choice(["/acct/*", "/docs/*"])
    elif rk == 3:
        p["resource"] = arb_resource(rng)
    if rng.random() < 0.5:
        p["where"] = _array(rng, arb_condition, 0, 2)
    return p


def arb_predicate_list(rng: random.Random) -> List[Dict[str, Any]]:
    return _array(rng, arb_predicate, 1, 4)


def arb_action_context(rng: random.Random) -> Dict[str, Any]:
    action: Dict[str, Any] = {"verb": arb_verb(rng), "resource": arb_resource(rng)}
    if rng.random() < 0.5:
        params: Dict[str, Any] = {}
        for key in rng.sample(["amount", "target", "reason"], rng.randint(0, 3)):
            r = rng.randint(0, 2)
            params[key] = _string(rng) if r == 0 else _int(rng, -5, 100) if r == 1 else rng.random() < 0.5
        action["params"] = params
    ctx: Dict[str, Any] = {"action": action}
    role, tier, ip = rng.choice(["admin", "user", "guest"]), _int(rng, 0, 5), _string(rng)
    if rng.random() < 0.5:
        ctx["subject"] = {"role": role, "tier": tier}
    if rng.random() < 0.5:
        ctx["env"] = {"ip": ip}
    return ctx


_REVERSIBILITY = ["reversible", "rate_limited", "irreversible", "teleport"]


def arb_caveat_context(rng: random.Random) -> Dict[str, Any]:
    """The caveat evaluation context, with this package's snake_case keys."""
    ctx: Dict[str, Any] = {"now": _int(rng, 0, 10_000_000)}
    if rng.random() < 0.5:
        ctx["blast_radius"] = _dbl(rng, 0, 1)
    if rng.random() < 0.5:
        ctx["reversibility_class"] = rng.choice(_REVERSIBILITY)
    if rng.random() < 0.5:
        ctx["delegation_depth"] = _int(rng, 0, 20)
    if rng.random() < 0.5:
        ctx["recent_action_times"] = _array(rng, lambda r: _int(r, 0, 10_000_000), 0, 6)
    return ctx


def arb_eval_point(rng: random.Random) -> Dict[str, Any]:
    """An action + caveat context together: one point at which to probe a chain's effective authority."""
    return {"action": arb_action_context(rng), "cav_ctx": arb_caveat_context(rng)}


# ---- attenuating delegation chains -----------------------------------------------------------------------------------------

def arb_caveat_spec(rng: random.Random) -> Dict[str, Any]:
    k = rng.randint(0, 6)
    if k == 0:
        return {"k": "expires", "at": _int(rng, 0, 10_000_000)}
    if k == 1:
        return {"k": "not_before", "at": _int(rng, 0, 10_000_000)}
    if k == 2:
        return {"k": "rate", "max": _int(rng, 1, 10), "per_secs": _int(rng, 1, 3600)}
    if k == 3:
        # quantized to 3 decimals so the limit is canonical-wire-safe
        return {"k": "max_blast_radius", "max": _int(rng, 0, 1000) / 1000}
    if k == 4:
        return {"k": "reversibility_max", "cls": rng.choice(["reversible", "rate_limited", "irreversible"])}
    if k == 5:
        return {"k": "delegation_depth", "max": _int(rng, 0, 20)}
    return {"k": "budget_frac", "frac": _dbl(rng, 0, 1)}


_BUDGET_ALLOC_BASE = 1_000_000


def _spec_to_caveat(spec: Dict[str, Any], alloc: Dict[str, float]) -> Dict[str, Any]:
    k = spec["k"]
    if k in ("expires", "not_before"):
        return {"type": k, "at": spec["at"]}
    if k == "rate":
        return {"type": "rate", "max": spec["max"], "per_secs": spec["per_secs"]}
    if k == "max_blast_radius":
        return {"type": "max_blast_radius", "max": spec["max"]}
    if k == "reversibility_max":
        return {"type": "reversibility_max", "class": spec["cls"]}
    if k == "delegation_depth":
        return {"type": "delegation_depth", "max": spec["max"]}
    if k == "budget_frac":
        base = alloc["running"] if fin(alloc["running"]) else _BUDGET_ALLOC_BASE
        # frac in [0,1] and base a non-negative integer: an integer <= the previous allocation (monotone, canonical-wire-safe)
        limit = math.floor(base * spec["frac"])
        alloc["running"] = limit
        return {"type": "budget_alloc", "limit": limit}
    raise ValueError("unknown caveat spec %r" % (k,))


def build_chain(m: Dict[str, Any]) -> Dict[str, Any]:
    """A signed, legally-attenuating chain from a model {principal_seed, holder0_seed, root_specs, hops: [{holder_seed,
    added_specs}], predicates}. Returns {caps, predicates, root_issuer, holders}."""
    alloc = {"running": math.inf}
    principal = key_pair_from_seed(m["principal_seed"])
    holder0 = key_pair_from_seed(m["holder0_seed"])
    root = mint_root(principal["signer"], holder0["pub"], [_spec_to_caveat(s, alloc) for s in m["root_specs"]])
    caps = [root]
    holders = [holder0["pub"]]
    prev = root
    signer = holder0["signer"]  # the next hop is signed by the key the parent is bound to
    for hop in m["hops"]:
        to = key_pair_from_seed(hop["holder_seed"])
        cap = delegate(prev, signer, to["pub"], [_spec_to_caveat(s, alloc) for s in hop["added_specs"]])
        caps.append(cap)
        holders.append(to["pub"])
        prev = cap
        signer = to["signer"]
    return {"caps": caps, "predicates": m["predicates"], "root_issuer": principal["pub"], "holders": holders}


def arb_chain(rng: random.Random) -> Dict[str, Any]:
    return build_chain({
        "principal_seed": arb_seed32(rng),
        "holder0_seed": arb_seed32(rng),
        "root_specs": _array(rng, arb_caveat_spec, 1, 4),
        "hops": _array(rng, lambda r: {"holder_seed": arb_seed32(r), "added_specs": _array(r, arb_caveat_spec, 0, 3)}, 0, 5),
        "predicates": arb_predicate_list(rng),
    })


# ---- risk policy / inputs / budget -----------------------------------------------------------------------------------------

def arb_risk_weights(rng: random.Random) -> Dict[str, float]:
    return {k: _dbl(rng, 0, 2) for k in ("alpha", "beta", "gamma", "delta", "epsilon", "zeta")}


def arb_risk_policy(rng: random.Random) -> Dict[str, Any]:
    """A well-formed risk policy: kappa > 0, 0 <= theta1 <= theta2, the rest finite >= 0."""
    theta1 = _dbl(rng, 0, 1)
    return {"weights": arb_risk_weights(rng), "theta1": theta1, "theta2": theta1 + _dbl(rng, 0, 1), "kappa": _dbl(rng, 0.001, 5),
            "lambda": _dbl(rng, 0, 0.01), "rho": _dbl(rng, 0, 2), "bMax": _dbl(rng, 0, 10)}


def arb_risk_inputs(rng: random.Random) -> Dict[str, float]:
    return {k: _dbl(rng, 0, 1) for k in ("semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age")}


def arb_trust_budget(rng: random.Random) -> Dict[str, Any]:
    b: Dict[str, Any] = {"B": _dbl(rng, 0, 10), "tau": _int(rng, 0, 10_000_000)}
    if rng.random() < 0.5:
        b["asOf"] = _int(rng, 0, 10_000_000)
    return b


def arb_risk_deltas(rng: random.Random) -> Dict[str, float]:
    return {k: _dbl(rng, 0, 1) for k in ("dSem", "dBlast", "dTaint", "dAge", "dRev", "dConf")}


def _clamp01(x: float) -> float:
    return 0 if x < 0 else 1 if x > 1 else x


def worsen(base: Dict[str, float], d: Dict[str, float]) -> Dict[str, float]:
    """A risk input that is >= `base` in every risk-increasing axis and <= in every protective axis."""
    return {
        "semanticDistance": _clamp01(base["semanticDistance"] + d["dSem"]),
        "blastRadius": _clamp01(base["blastRadius"] + d["dBlast"]),
        "taint": _clamp01(base["taint"] + d["dTaint"]),
        "age": _clamp01(base["age"] + d["dAge"]),
        "reversibility": _clamp01(base["reversibility"] - d["dRev"]),
        "confidence": _clamp01(base["confidence"] - d["dConf"]),
    }


# ---- 1. attenuation monotonicity -------------------------------------------------------------------------------------------

def _auth_allowed(caveats: list, predicates: list, pt: Dict[str, Any]) -> bool:
    if not evaluate_predicates(predicates, pt["action"])["allowed"]:
        return False
    return evaluate_caveats(caveats, pt["cav_ctx"])[0]


def _alloc_limits(caveats: list) -> list:
    return [cv["limit"] for cv in caveats if isinstance(cv, dict) and cv.get("type") == "budget_alloc"
            and isinstance(cv.get("limit"), (int, float)) and not isinstance(cv.get("limit"), bool)]


def attenuation_monotonicity_property() -> Prop:
    """A legal chain verifies; each hop's caveats extend its parent's append-only; budget_alloc limits never grow; and at every probe
    point the per-hop verdict is monotone non-increasing root to leaf (a delegate step can only shrink or preserve authority)."""
    def prop(rng: random.Random) -> bool:
        chain = arb_chain(rng)
        points = _array(rng, arb_eval_point, 1, 5)
        caps = chain["caps"]
        if not verify_chain(caps, chain["root_issuer"])[0]:
            return False
        for i in range(1, len(caps)):
            parent, child = caps[i - 1]["caveats"], caps[i]["caveats"]
            if len(child) < len(parent):
                return False
            for j in range(len(parent)):
                if hash_canonical(child[j]) != hash_canonical(parent[j]):
                    return False
        leaf = caps[-1]
        if not allocations_monotone(leaf["caveats"])[0]:
            return False
        limits = _alloc_limits(leaf["caveats"])
        for i in range(1, len(limits)):
            if limits[i] > limits[i - 1]:
                return False
        for pt in points:
            ancestor_allowed = True
            for cap in caps:
                allowed = _auth_allowed(cap["caveats"], chain["predicates"], pt)
                if allowed and not ancestor_allowed:  # a true after a false would be a widening
                    return False
                ancestor_allowed = allowed
        return True
    return prop


# ---- 2. budget soundness ---------------------------------------------------------------------------------------------------

def risk_monotone_property() -> Prop:
    """r is clamped to [0, 1] and a pointwise-worse input never yields a lower r."""
    def prop(rng: random.Random) -> bool:
        policy, inputs, deltas = arb_risk_policy(rng), arb_risk_inputs(rng), arb_risk_deltas(rng)
        r = risk_score(inputs, policy["weights"])
        if not (0 <= r <= 1):
            return False
        r_worse = risk_score(worsen(inputs, deltas), policy["weights"])
        if not (0 <= r_worse <= 1):
            return False
        return r_worse + _EPS >= r
    return prop


def admission_soundness_property() -> Prop:
    """Whenever `admit` lets an action proceed without a human, the admitted cost kappa*r is covered by the budget; and
    `safety_bound` is exactly bMax/kappa."""
    def prop(rng: random.Random) -> bool:
        policy, inputs, budget = arb_risk_policy(rng), arb_risk_inputs(rng), arb_trust_budget(rng)
        if validate_risk_policy(policy) is not None:
            return False
        r = risk_score(inputs, policy["weights"])
        c = cost(r, policy["kappa"])
        adm = admit(r, budget, policy)
        if adm["metered"]:
            if adm["t"] >= 3:
                return False
            if not budget["B"] + _EPS >= c:
                return False
        if adm["admit"]:
            if adm["t"] != 1 or not adm["metered"]:
                return False
            if not budget["B"] + _EPS >= c:
                return False
        expected = max(0, policy["bMax"]) / policy["kappa"] if policy["kappa"] > 0 else 0
        return abs(safety_bound(policy) - expected) <= _EPS
    return prop


def cumulative_budget_bound_property() -> Prop:
    """From a full budget, any sequence of machine-only actions debiting kappa*r never drives B negative and the total admitted risk
    obeys Sum(r) <= bMax/kappa."""
    def prop(rng: random.Random) -> bool:
        policy = arb_risk_policy(rng)
        seq = _array(rng, arb_risk_inputs, 1, 40)
        bound = safety_bound(policy)
        b = max(0, policy["bMax"])
        sum_r = 0.0
        for inputs in seq:
            r = risk_score(inputs, policy["weights"])
            adm = admit(r, {"B": b, "tau": 0, "asOf": 0}, policy)
            if adm["metered"] and adm["t"] < 3:
                c = cost(r, policy["kappa"])
                if not b + _EPS >= c:
                    return False
                b = max(0, b - c)
                sum_r += r
                if b < -_EPS:
                    return False
                if not policy["kappa"] * sum_r <= policy["bMax"] + 1e-6:
                    return False
                if not sum_r <= bound + 1e-6:
                    return False
        return True
    return prop


# ---- 3. fail-closed --------------------------------------------------------------------------------------------------------

_KNOWN_CAVEAT_TYPES = {"expires", "not_before", "rate", "max_blast_radius", "reversibility_max", "delegation_depth", "budget_alloc",
                       "max_spend", "intent_session"}

_UNDECIDABLES = [
    lambda f: {"field": f + ".definitely_absent", "op": "eq", "value": "x"},  # missing field
    lambda f: {"field": f, "op": "lt", "value": 5},  # string field vs number: incomparable
    lambda f: {"field": f, "op": "in", "value": "not-an-array"},  # non-array operand
    lambda f: {"field": f, "op": "eq"},  # no value and no ref
    lambda f: {"field": f, "op": "member_of", "value": "g", "collection": "env.no_such_collection"},  # missing collection
]


def undecidable_leaf_fails_closed_property() -> Prop:
    """Every structurally undecidable leaf evaluates to 'unknown' (never 'true'), so a predicate carrying it never grants."""
    def prop(rng: random.Random) -> bool:
        make = rng.choice(_UNDECIDABLES)
        verb, resource = rng.choice(["read", "write", "delete"]), "/x"
        ctx = {"action": {"verb": verb, "resource": resource}, "subject": {"role": "admin"}}
        leaf = make("subject.role")
        if evaluate_condition_tri(leaf, ctx) == "true":
            return False
        if evaluate_condition(leaf, ctx) is not False:
            return False
        return evaluate_predicates([{"verb": verb, "resource": resource, "where": [leaf]}], ctx)["allowed"] is False
    return prop


def undecidable_groups_fail_closed_property() -> Prop:
    """not / all_of / any_of over undecidable or empty children fail closed (never 'true')."""
    def prop(rng: random.Random) -> bool:
        ctx = {"action": {"verb": "read", "resource": "/x"}, "subject": {"role": "admin"}}
        child = {"field": "subject.role", "op": "lt", "value": 5}
        for c in ({"not": child}, {"all_of": []}, {"any_of": []}, {"all_of": [child]}, {"any_of": [child]}):
            if evaluate_condition_tri(c, ctx) == "true":
                return False
        return True
    return prop


def member_of_cycle_safe_property() -> Prop:
    """`member_of` over a cyclic adjacency terminates with a correct verdict and fails closed on an unreachable target."""
    def prop(rng: random.Random) -> bool:
        target = rng.choice(["a", "b", "c", "z"])
        rel = {"a": ["b"], "b": ["a", "c"]}  # a -> b -> a is a cycle; c hangs off b; z is absent
        ctx = {"action": {"verb": "read", "resource": "/x"}, "subject": {"g": "a"}, "env": {"rel": rel}}
        tri = evaluate_condition_tri({"field": "subject.g", "op": "member_of", "value": target, "collection": "env.rel"}, ctx)
        return tri == ("true" if target in ("a", "b", "c") else "false")
    return prop


def unknown_caveat_type_denies_property() -> Prop:
    """An unknown caveat type is never satisfied, so a caveat set containing it is never ok."""
    def prop(rng: random.Random) -> bool:
        t = _string(rng, 1, 12)
        while t in _KNOWN_CAVEAT_TYPES:
            t = _string(rng, 1, 12)
        cav, ctx = {"type": t}, {"now": _int(rng, 0, 10_000_000)}
        if _caveat_satisfied(cav, ctx) is not False:
            return False
        return evaluate_caveats([cav], ctx)[0] is False
    return prop


_ALL_MUTATIONS = ["tamper-caveat", "drop-leaf-caveat", "swap-holder", "break-parent", "bad-sig", "wrong-root-issuer", "suite-mismatch",
                  "break-id", "append-forged-hop"]


def forged_chain_rejected_property() -> Prop:
    """A legal chain mutated by one of nine attacks (tampered or dropped caveat, swapped holder, broken parent link, bad signature,
    wrong root issuer, mismatched suite, broken id, appended unsigned hop) never verifies."""
    def prop(rng: random.Random) -> bool:
        chain = arb_chain(rng)
        mutation = rng.choice(_ALL_MUTATIONS)
        pick = _int(rng, 0, 1_000_000)
        aux_seed = arb_seed32(rng)
        caps, root = chain["caps"], chain["root_issuer"]
        if not verify_chain(caps, root)[0]:
            return False
        n = len(caps)
        idx = pick % n if n > 0 else 0
        aux = key_pair_from_seed(aux_seed)

        def rejects(m: list) -> bool:
            return verify_chain(m, root)[0] is False

        if mutation == "tamper-caveat":
            m = copy.deepcopy(caps)
            m[idx]["caveats"] = m[idx]["caveats"] + [{"type": "expires", "at": 999}]
            return rejects(m)
        if mutation == "drop-leaf-caveat":
            m = copy.deepcopy(caps)
            if len(m[n - 1]["caveats"]) == 0:
                return True  # inapplicable: trivially pass
            m[n - 1]["caveats"] = m[n - 1]["caveats"][:-1]
            return rejects(m)
        if mutation == "swap-holder":
            m = copy.deepcopy(caps)
            m[idx]["holder"] = aux["pub"]  # changes the signed body: digest mismatch
            return rejects(m)
        if mutation == "break-parent":
            if n < 2:
                return True
            m = copy.deepcopy(caps)
            m[max(1, idx)]["parent"] = hash_canonical({"bogus": len(aux_seed), "tag": "not-a-real-parent"})
            return rejects(m)
        if mutation == "bad-sig":
            m = copy.deepcopy(caps)
            m[idx]["sig"] = b64u(aux["signer"].sign(bytes([1, 2, 3, 4])))  # well-formed but wrong: other bytes, other key
            return rejects(m)
        if mutation == "wrong-root-issuer":
            if aux["pub"] == root:
                return True
            return verify_chain(caps, aux["pub"])[0] is False
        if mutation == "suite-mismatch":
            m = copy.deepcopy(caps)
            m[idx]["alg"] = "ml-dsa-65"  # the suite fields are bound into body_digest, so this must be rejected
            return rejects(m)
        if mutation == "break-id":
            m = copy.deepcopy(caps)
            m[idx]["id"] = hash_canonical({"not": "the-body-digest", "n": idx})
            return rejects(m)
        # append-forged-hop: issued as if from the leaf, but signed by a key that is not the leaf's holder
        forged = delegate(caps[n - 1], aux["signer"], aux["pub"], [])
        return rejects(caps + [forged])
    return prop


def _arb_unsigned_capability(rng: random.Random) -> Dict[str, Any]:
    return {"id": _string(rng), "issuer": _string(rng), "holder": _string(rng),
            "caveats": _array(rng, lambda r: {"type": _string(r)}, 0, 3), "body_digest": _string(rng), "sig": _string(rng)}


def garbage_chain_rejected_property() -> Prop:
    """Arbitrary never-signed chains (including the empty chain) never verify."""
    def prop(rng: random.Random) -> bool:
        return verify_chain(_array(rng, _arb_unsigned_capability, 0, 4))[0] is False
    return prop


# ---- 4. determinism --------------------------------------------------------------------------------------------------------

def determinism_property() -> Prop:
    """verify_chain, evaluate_predicates, evaluate_caveats, risk_score, required_threshold and admit are deterministic."""
    def prop(rng: random.Random) -> bool:
        chain, pt, preds = arb_chain(rng), arb_eval_point(rng), arb_predicate_list(rng)
        policy, inputs, budget = arb_risk_policy(rng), arb_risk_inputs(rng), arb_trust_budget(rng)
        if verify_chain(chain["caps"], chain["root_issuer"]) != verify_chain(chain["caps"], chain["root_issuer"]):
            return False
        p1, p2 = evaluate_predicates(preds, pt["action"]), evaluate_predicates(preds, pt["action"])
        if p1["allowed"] != p2["allowed"] or p1.get("reason") != p2.get("reason"):
            return False
        leaf = chain["caps"][-1]
        c1, c2 = evaluate_caveats(leaf["caveats"], pt["cav_ctx"]), evaluate_caveats(leaf["caveats"], pt["cav_ctx"])
        if c1[0] != c2[0] or "|".join(c1[1]) != "|".join(c2[1]):
            return False
        r1, r2 = risk_score(inputs, policy["weights"]), risk_score(inputs, policy["weights"])
        if r1 != r2:
            return False
        if required_threshold(r1, policy) != required_threshold(r1, policy):
            return False
        return admit(r1, budget, policy) == admit(r1, budget, policy)
    return prop


def forbid_monotone_property() -> Prop:
    """Forbid-wins is monotone and order-independent: adding a forbid clause can only move a decision down, a forbid that matches
    always denies whatever the permits say, and the decision does not depend on the clause order."""
    ranks = {"deny": 0, "escalate": 1, "allow": 2}

    def mk(kind: str, ps: list, tag: str) -> list:
        return [{"id": "%s%d" % (tag, i), "kind": kind, "when": w} for i, w in enumerate(ps)]

    def prop(rng: random.Random) -> bool:
        permits, forbids, extra = arb_predicate_list(rng), arb_predicate_list(rng), arb_predicate_list(rng)
        pt, rot = arb_eval_point(rng), _int(rng, 0, 5)
        base = mk("permit", permits, "p") + mk("escalate", extra, "e")
        with_forbid = base + mk("forbid", forbids, "f")
        before = decide_clauses(base, pt["action"])["decision"]
        after = decide_clauses(with_forbid, pt["action"])["decision"]
        if ranks[after] > ranks[before]:
            return False  # adding a forbid must never grow the admit set
        if any(prohibitions.when_matches(w, pt["action"]) for w in forbids) and after != "deny":
            return False  # a matching forbid beats every permit
        k = rot % len(with_forbid)
        return decide_clauses(with_forbid[k:] + with_forbid[:k], pt["action"])["decision"] == after
    return prop


# ---- runner / registry -----------------------------------------------------------------------------------------------------

def _assert_property(prop: Prop, num_runs: int, seed: int) -> None:
    rng = random.Random(seed)
    for i in range(num_runs):
        case_seed = rng.getrandbits(64)
        if prop(random.Random(case_seed)) is not True:
            raise AssertionError("property failed after %d run(s) (seed %d, case seed %d)" % (i + 1, seed, case_seed))


class Invariant:
    """A named invariant whose `run(num_runs, seed)` executes its property-based check (raises on a counterexample)."""

    def __init__(self, name: str, make: Callable[[], Prop]):
        self.name = name
        self._make = make

    def run(self, num_runs: int, seed: int) -> None:
        _assert_property(self._make(), num_runs, seed)


INVARIANTS: List[Invariant] = [
    Invariant("attenuation-monotonicity", attenuation_monotonicity_property),
    Invariant("risk-wellformed-and-monotone", risk_monotone_property),
    Invariant("admission-soundness", admission_soundness_property),
    Invariant("cumulative-budget-bound", cumulative_budget_bound_property),
    Invariant("fail-closed:undecidable-leaf", undecidable_leaf_fails_closed_property),
    Invariant("fail-closed:undecidable-groups", undecidable_groups_fail_closed_property),
    Invariant("fail-closed:member-of-cycle-safe", member_of_cycle_safe_property),
    Invariant("fail-closed:unknown-caveat-type", unknown_caveat_type_denies_property),
    Invariant("fail-closed:forged-chain-rejected", forged_chain_rejected_property),
    Invariant("fail-closed:garbage-chain-rejected", garbage_chain_rejected_property),
    Invariant("forbid-monotone", forbid_monotone_property),
    Invariant("determinism", determinism_property),
]


def _safe_int(v: Any) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return abs(v) <= 2 ** 53 - 1
    return isinstance(v, float) and fin(v) and v == math.floor(v) and abs(v) <= 2 ** 53 - 1


def check_invariants(num_runs: Optional[int] = None, seed: Optional[int] = None, bail: bool = False) -> List[Dict[str, Any]]:
    """Machine-check every invariant. Returns one {name, ok, numRuns, seed, error?} per invariant; ok False with an error is a
    surfaced counterexample (a candidate core bug). Raises ValueError on a non-positive run count or a non-integer seed (a check
    that runs zero cases would pass vacuously)."""
    runs = DEFAULT_NUM_RUNS if num_runs is None else num_runs
    sd = DEFAULT_SEED if seed is None else seed
    if not _safe_int(runs) or runs < 1:
        raise ValueError("checkInvariants: numRuns must be a positive integer")
    if not _safe_int(sd):
        raise ValueError("checkInvariants: seed must be an integer")
    runs, sd = int(runs), int(sd)
    results: List[Dict[str, Any]] = []
    for inv in INVARIANTS:
        try:
            inv.run(runs, sd)
            results.append({"name": inv.name, "ok": True, "numRuns": runs, "seed": sd})
        except Exception as e:  # noqa: BLE001 - a counterexample or a core fault is reported, not raised
            results.append({"name": inv.name, "ok": False, "numRuns": runs, "seed": sd, "error": str(e)})
            if bail:
                break
    return results
