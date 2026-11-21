"""Approval-render wrappers, the facade view of a def and the provenance-gate facts (native port of the wrapper half of
approval-render.ts, facade-spec.ts and provenance.ts of the TypeScript reference @atlasauth/pca-actions). The render itself is
approval.render_approval. `attestation_verified` is the caller's confirmation verifier (absent: nothing is confirmed)."""
from typing import Any, Callable, Dict, List, Optional

from .actions import CORE_REGISTRY, ActionKitError, normalize
from .actions_derive import param_by_role
from .actions_effective import effective_with, is_confirmed, traits_of_with
from .approval import _jtruthy, approval_render_digest, render_approval
from .pca import params_digest

Verifier = Optional[Callable[[dict], Any]]


def render_approval_with(d: dict, params: Any, attestation_verified: Verifier = None) -> dict:
    """render_approval, with the confirmation decided by the verifier (asked only after the render itself succeeded)."""
    r = render_approval(d, params, False)
    r["unreviewed"] = not is_confirmed(d, attestation_verified)
    return r


def render_digest_for_action(d: dict, params: Any, pcactn: dict, attestation_verified: Verifier = None) -> str:
    """H(R) for an executed action; refuses unless the params are the ones the PCActn signed and the verb is the PCActn's verb."""
    if pcactn["action"]["verb"] != d["verb"]:
        raise ActionKitError("render_verb_mismatch", "the PCActn is for '%s', the definition for '%s'" % (pcactn["action"]["verb"], d["verb"]))
    if pcactn["action"].get("params_digest") != params_digest(params):
        raise ActionKitError("render_params_mismatch", "the supplied params are not the params the PCActn signed")
    return approval_render_digest(render_approval_with(d, params, attestation_verified))


def approver_render_check(d: dict, params: Any, requested_render_digest: str, attestation_verified: Verifier = None) -> str:
    """The approver client's check before it signs: re-render from the pinned def and require the requested digest. Returns the digest to sign."""
    dg = approval_render_digest(render_approval_with(d, params, attestation_verified))
    if dg != requested_render_digest:
        raise ActionKitError("render_mismatch", "the approval request commits to a render this definition and these params do not produce")
    return dg


def single_tap_allowed(r: dict) -> bool:
    """Single-tap (one-gesture) approval is allowed only for a confirmed definition."""
    return not _jtruthy(r.get("unreviewed"))


def renderers_from_defs(defs: List[dict], attestation_verified: Verifier = None) -> Callable[[str, str, Optional[dict]], dict]:
    """The step-up renderer derived from the pinned defs (found by verb or alias); an unknown verb raises, which makes the review a deny."""
    by_verb: Dict[str, dict] = {}
    for d in defs:
        by_verb[d["verb"]] = d
        for a in d.get("aliases") or []:
            by_verb.setdefault(a, d)

    def render(verb: str, _resource: str, params: Optional[dict]) -> dict:
        d = by_verb.get(verb)
        if d is None:
            raise ActionKitError("render_unknown_verb", "no pinned action definition for '%s'" % verb)
        return render_approval_with(d, {} if params is None else params, attestation_verified)

    return render


# ---- facade-spec.ts ----------------------------------------------------------------------------------------------------------

def spec_of_def(d: dict, reg: Optional[Dict[str, dict]] = None, attestation_verified: Verifier = None, reviewed: bool = False) -> dict:
    """One def to one facade row: reversibility and blast are the EFFECTIVE values; `reviewed` prices the def as reviewed (release-attested catalog only)."""
    reg = CORE_REGISTRY if reg is None else reg
    full = effective_with(d, reg, attestation_verified)
    e = full["hint"] if reviewed is True else full
    parts = d["verb"].split(".")
    try:
        amount = param_by_role(d, "money.amount")
    except ActionKitError:
        amount = None
    out: Dict[str, Any] = {"connector": parts[0], "action": ".".join(parts[1:]), "verb": d["verb"], "reversibility": e["eff"]["rev"],
                           "blastRadius": e["eff"]["blast_ppm"] / 1_000_000}
    if amount is not None:
        out["amountField"] = amount
    out["description"] = d["description"] if d.get("description") is not None else d["title"]
    if d.get("aliases"):
        out["aliases"] = sorted(d["aliases"], key=lambda s: s.encode("utf-16-be", "surrogatepass"))
    out["traits"] = e["closure"]
    return out


def facade_specs(defs: List[dict], reg: Optional[Dict[str, dict]] = None, attestation_verified: Verifier = None, reviewed: bool = False) -> List[dict]:
    return [spec_of_def(d, reg, attestation_verified, reviewed) for d in defs]


# ---- provenance.ts -----------------------------------------------------------------------------------------------------------

def provenance_info_of(d: dict, reg: Optional[Dict[str, dict]] = None, attestation_verified: Verifier = None) -> dict:
    """The gate facts of one def. Unconfirmed means maximally dangerous: no effects, the top trait set, provenance relaxations ignored."""
    reg = CORE_REGISTRY if reg is None else reg
    traits = traits_of_with(d, reg, attestation_verified)
    if not is_confirmed(d, attestation_verified):
        return {"effects": [], "traits": traits}
    n = normalize(d)
    params = {name: p["provenance_min"] for name, p in n["params"].items() if "provenance_min" in p}
    out: Dict[str, Any] = {"effects": list(n["effects"]), "traits": traits}
    if params:
        out["params"] = params
    return out


def provenance_actions(defs: List[dict], reg: Optional[Dict[str, dict]] = None, attestation_verified: Verifier = None) -> Callable[[dict], Optional[dict]]:
    """The `provenance.actions` resolver: the facts of the def whose verb (or alias) is the operation's verb, None for an unknown verb. Two defs claiming one name raise."""
    reg = CORE_REGISTRY if reg is None else reg
    by_verb: Dict[str, dict] = {}
    for d in defs:
        n = normalize(d)
        info = provenance_info_of(d, reg, attestation_verified)
        for v in [n["verb"]] + list(n["aliases"]):
            if v in by_verb:
                raise ValueError("provenanceActions: two definitions claim the verb '%s'" % v)
            by_verb[v] = info
    return lambda op: by_verb.get(op["verb"])
