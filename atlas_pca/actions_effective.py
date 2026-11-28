"""From an ActionDef to T(d), decl(d) and eff_R(d) with a caller-supplied confirmation verifier, plus the structural param rules
(native port of effective.ts of the TypeScript reference @atlasauth/pca-actions). actions.effective() is the pinned-key form of the same."""
from typing import Any, Callable, Dict, List, Optional, Sequence

from .actions import (
    PARAM_RULE_IDS, REV_RANK, decl_profile, floor_of, closure, hint_traits, implied_from_facts, join, leq, normalize, top_traits,
    worst_reversibility,
)

Verifier = Optional[Callable[[dict], Any]]


def profile_eq(p: dict, q: dict) -> bool:
    return leq(p, q) and leq(q, p)


def implied_traits(n: dict) -> List[str]:
    """Traits implied by a NORMALIZED def's own facts."""
    return implied_from_facts(n["effects"], list(n["params"].values()), n["resource"]["scope"], worst_reversibility(n["reversibility"], n["params"]))


def is_confirmed(d: dict, attestation_verified: Verifier = None) -> bool:
    """True iff the caller's verifier says the def carries a valid signed review. Absent => never."""
    return attestation_verified is not None and attestation_verified(d) is True


def traits_of_with(d: dict, reg: Dict[str, dict], attestation_verified: Verifier = None) -> List[str]:
    return hint_traits(d) if is_confirmed(d, attestation_verified) else top_traits(reg)


def effective_with(d: dict, reg: Dict[str, dict], attestation_verified: Verifier = None) -> dict:
    """{confirmed, traits, closure, floor, eff, decl, hint:{traits,closure,floor,eff}, clamps}; the verifier replaces the pinned keys."""
    decl = decl_profile(d)

    def view(traits: List[str]) -> dict:
        floor = floor_of(reg, traits)
        return {"traits": traits, "closure": closure(reg, traits), "floor": floor, "eff": join(decl, floor)}

    hint = view(hint_traits(d))
    confirmed = is_confirmed(d, attestation_verified)
    main = hint if confirmed else view(top_traits(reg))
    clamps = []
    if "reversibility" in d and REV_RANK[decl["rev"]] < REV_RANK[hint["floor"]["rev"]]:
        clamps.append({"field": "rev", "declared": decl["rev"], "floor": hint["floor"]["rev"]})
    if "blast" in d and decl["blast_ppm"] < hint["floor"]["blast_ppm"]:
        clamps.append({"field": "blast_ppm", "declared": decl["blast_ppm"], "floor": hint["floor"]["blast_ppm"]})
    out = dict(main)
    out.update({"confirmed": confirmed, "decl": decl, "hint": hint, "clamps": clamps})
    return out


def eff_with_trait(d: dict, t: str, reg: Dict[str, dict]) -> dict:
    """The hint profile after adding trait `t` to the declared traits (never lower). Analysis only."""
    d2 = dict(d)
    d2["traits"] = list(d.get("traits") or []) + [t]
    return effective_with(d2, reg)["hint"]["eff"]


def prules_violations(d: dict, ids: Sequence[str] = PARAM_RULE_IDS) -> List[str]:
    """Structural param rules (among `ids`) the def violates. A def violating a rule its traits require is not loadable."""
    n = normalize(d)
    ps = list(n["params"].values())

    def with_role(pred) -> list:
        return [p for p in ps if p.get("role") is not None and pred(p["role"])]

    def money_ok(p: dict) -> bool:
        u = p.get("unit")
        if not u or u.get("kind") != "money":
            return False
        ccy = u.get("ccy")
        if isinstance(ccy, str):
            return True
        c = n["params"].get(ccy["from"]) if isinstance(ccy, dict) else None
        return c is not None and c.get("role") == "money.currency" and c.get("format") == "iso_currency"

    bad = []
    for rid in ids:
        ok = True
        if rid == "money_has_currency":
            ok = all(money_ok(p) for p in with_role(lambda r: r in ("money.amount", "money.fee")))
        elif rid == "money_amount_bounded":
            ok = all(p["type"] == "integer" and "min" in p and "max" in p for p in with_role(lambda r: r == "money.amount"))
        elif rid == "id_not_wildcard":
            ok = not (n["resource"]["id"] == "*" and n["resource"]["scope"] == "one")
        elif rid == "recipient_param_declared":
            ok = n.get("audience") == "resource" or len(with_role(lambda r: r == "party.payee" or r.startswith("contact."))) > 0
        elif rid == "array_bounded":
            ok = all(p.get("max_items") is not None for p in ps if p["type"] == "array")
        elif rid == "export_bounded":
            ok = n["resource"]["scope"] == "one" or any("max" in p for p in with_role(lambda r: r == "count.limit"))
        elif rid == "secret_not_logged":
            ok = all("secret" in (p.get("tags") or []) for p in with_role(lambda r: r.startswith("credential.")))
        elif rid == "pay_has_idempotency":
            ok = "pay" not in n["effects"] or n["idempotency"]["mode"] != "none"
        if not ok:
            bad.append(rid)
    return bad


def required_prules_violated(d: dict, eff: dict) -> List[str]:
    """Rules the effective profile requires but the def does not satisfy (the load-time check)."""
    return prules_violations(d, eff["prules"])
