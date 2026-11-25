"""The built-in connector defs, the domain-vocabulary defs and bindings, and how the built-ins become confirmed (native port of builtin.ts,
builtin-review.ts and domain.ts of the TypeScript reference @atlasauth/pca-actions). The data is generated from the reference
(actions_builtin_data.py). Without a release signing step the built-ins carry no attestation: unconfirmed, maximally dangerous."""
from typing import Any, Dict, List, Optional

from .actions import CORE_REGISTRY, ActionKitError
from .actions_builtin_data import DATA
from .actions_derive import effect_class, to_ontology

BUILTIN_DEFS: List[dict] = DATA["builtin"]
DOMAIN_DEFS: List[dict] = DATA["domain"]
LEGACY_CATALOG: Dict[str, dict] = DATA["legacyCatalog"]
LEGACY_ONTOLOGY_EFFECT: Dict[str, str] = DATA["legacyOntologyEffect"]
RESOLUTIONS: List[dict] = DATA["resolutions"]
DOMAIN_VERBS: Dict[str, List[dict]] = DATA["domainVerbs"]
CORE_PACK_DEFS: List[dict] = BUILTIN_DEFS + DOMAIN_DEFS

# No pinned release reviewer key and no attestation until a release run signs the built-ins.
BUILTIN_RELEASE: Dict[str, Any] = {"pins": None, "attestations": {}}


def released_builtin_defs(defs: Optional[List[dict]] = None) -> List[dict]:
    """The built-in defs with their release attestation attached where the package carries one (others stay unconfirmed)."""
    out = []
    for d in (BUILTIN_DEFS if defs is None else defs):
        a = BUILTIN_RELEASE["attestations"].get(d["verb"])
        out.append(d if a is None else {**d, "review": {**d["review"], "state": "confirmed", "attestation": a}})
    return out


def sign_builtins(kid: str, secret: bytes, ts: int, registry: Optional[Dict[str, dict]] = None, defs: Optional[List[dict]] = None) -> List[dict]:
    """Release step: confirm (sign) every built-in def with the release reviewer key. The secret is the caller's; it is never stored."""
    from .actions import _sort_uniq
    from .actions_review import confirm_def
    reg = CORE_REGISTRY if registry is None else registry
    return [confirm_def(d, {"registry": reg, "reviewer": {"kid": kid, "secret": secret}, "finalTraits": _sort_uniq(d.get("traits") or []), "ts": ts})
            for d in (BUILTIN_DEFS if defs is None else defs)]


def builtin_reviewer_pins() -> Optional[dict]:
    """The pinned release reviewer keys; None before the first release signing (then pass pins=None: nothing is confirmed)."""
    return BUILTIN_RELEASE["pins"]


# ---- domain.ts: the Goal IR domain vocabularies derived from the defs ------------------------------------------------------

def _def_of(verb: str) -> dict:
    d = next((x for x in CORE_PACK_DEFS if x["verb"] == verb), None)
    if d is None:
        raise ValueError("domain binding names unknown def '%s'" % verb)
    return d


def domain_verbs(domain: str, reg: Optional[Dict[str, dict]] = None) -> dict:
    """The `verbs` and `aliases` of a domain ontology, derived from the defs (effect class derived, never assigned)."""
    reg = CORE_REGISTRY if reg is None else reg
    bindings = DOMAIN_VERBS[domain]
    onto = to_ontology([_def_of(b["verb"]) for b in bindings], reg)
    verbs: List[dict] = []
    aliases: Dict[str, str] = {}
    for b in bindings:
        d = _def_of(b["verb"])
        if b["id"] not in (d.get("aliases") or []):
            raise ValueError("domain binding '%s' is not an alias of '%s'" % (b["id"], b["verb"]))
        ov = next(v for v in onto["verbs"] if v["id"] == b["verb"])
        params: Dict[str, dict] = {}
        for nl, dp in b["params"].items():
            p = ov["params"].get(dp)
            if not p:
                raise ValueError("domain binding '%s' surfaces unknown parameter '%s'" % (b["id"], dp))
            params[nl] = {"kind": "money", "ccys": list(b["ccys"])} if p["kind"] == "money" and b.get("ccys") is not None else p
        verbs.append({"id": b["id"], "effect": effect_class(d), "resource_type": b["resourceType"], "params": params})
        for a in d.get("aliases") or []:
            if a != b["id"]:
                aliases[a] = b["id"]
    return {"verbs": verbs, "aliases": aliases}


def domain_roles(domain: str) -> Dict[str, Dict[str, List[str]]]:
    """The role map of a domain verb for the selector layer: role -> NL parameter names carrying it."""
    out: Dict[str, Dict[str, List[str]]] = {}
    for b in DOMAIN_VERBS[domain]:
        d = _def_of(b["verb"])
        roles: Dict[str, List[str]] = {}
        for nl, dp in b["params"].items():
            pd = d["params"].get(dp)
            r = pd.get("role") if pd is not None else None
            if r is not None:
                roles.setdefault(r, []).append(nl)
        out[b["id"]] = roles
    return out


def builtin_review_opts(reg: Optional[Dict[str, dict]] = None) -> Any:
    """The confirmation verifier under which the released built-ins count as confirmed (a signature by the pinned release key, nothing else);
    None before the first release signing (then nothing is confirmed)."""
    from .actions import CORE_REGISTRY
    from .actions_hosted import review_opts_of
    return review_opts_of(builtin_reviewer_pins(), CORE_REGISTRY if reg is None else reg)
