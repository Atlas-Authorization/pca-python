"""Undo windows over action definitions, the structural and planning half (native port of the definition-level functions of undo.ts of
the TypeScript reference @atlasauth/pca-actions). The window state machine, tokens and receipts are in undo.py."""
import copy
import math
from typing import Any, Callable, Dict, List, Optional

from .actions import CORE_REGISTRY, def_digest, is_read_only, normalize, _u16key
from .actions_effective import effective_with, is_confirmed
from .actions_review import attestation_verifier
from .approval import approval_render_digest, render_approval
from .intent_wb import _is_safe_int


def reversibility_for(d: dict, params: dict) -> str:
    """The class of a reversibility declaration for concrete params (an unmapped or absent value takes `default`, else irreversible)."""
    r = normalize(d)["reversibility"]
    if isinstance(r, str):
        return r
    v = params.get(r["by"]) if r["by"] in params else None
    if isinstance(v, str):
        k = v
    elif isinstance(v, bool):
        k = "true" if v else "false"
    elif isinstance(v, (int, float)) and _is_safe_int(v) and not (isinstance(v, float) and v == 0 and math.copysign(1, v) < 0):
        k = str(int(v))
    else:
        k = None
    return r["map"][k] if k is not None and k in r["map"] else r.get("default", "irreversible")


def may_be_reversible(d: dict) -> bool:
    """True when some value of the declaration is `reversible` (a fixed class, a map value or the default)."""
    r = d.get("reversibility")
    if r is None:
        return False
    if isinstance(r, str):
        return r == "reversible"
    return "reversible" in r["map"].values() or r.get("default") == "reversible"


def _same_type(a: Optional[dict], b: dict) -> bool:
    return a is not None and a["type"] == b["type"] and a.get("items") == b.get("items")


def compensation_shape(orig: dict, comp: dict) -> dict:
    """Can `comp` undo `orig` without the agent's help? {ok: True, shape: {copied, target?}} or {ok: False, reason}. Structural only."""
    if is_read_only(comp["effects"]):
        return {"ok": False, "reason": "the compensating action %s only reads" % comp["verb"]}
    if comp["resource"]["type"] != orig["resource"]["type"]:
        return {"ok": False, "reason": "the compensating action %s acts on %s, not %s" % (comp["verb"], comp["resource"]["type"], orig["resource"]["type"])}
    nc = normalize(comp)
    copied: List[str] = []
    target = None
    idem = nc["idempotency"].get("param") if nc["idempotency"]["mode"] == "key_param" else None
    for name, p in sorted(nc["params"].items(), key=lambda kv: _u16key(kv[0])):
        if name == idem:
            continue
        if _same_type(orig["params"].get(name), p):
            copied.append(name)
            continue
        if not p["required"]:
            continue
        if p.get("role") == "id." + comp["resource"]["type"] and target is None:
            target = name
            continue
        return {"ok": False, "reason": "the compensating action %s needs '%s', which neither the original call nor its result supplies" % (comp["verb"], name)}
    shape: Dict[str, Any] = {"copied": copied}
    if target is not None:
        shape["target"] = target
    return {"ok": True, "shape": shape}


def undo_engine(defs: List[dict], pins: Any, registry: Optional[Dict[str, dict]] = None) -> Callable[[dict], Optional[dict]]:
    """plan(op) -> {def_digest, compensation, render, render_digest} or None. Answers only from CONFIRMED definitions (a valid signed review
    by a pinned reviewer key; no pins: nothing is undoable), exact verb match only. Never raises: anything undecidable is not undoable."""
    reg = registry or CORE_REGISTRY
    by_verb: Dict[str, dict] = {}
    for d in defs:
        by_verb.setdefault(d["verb"], d)

    review = None if pins is None else attestation_verifier(reg, pins)

    def confirmed(d: dict) -> bool:
        try:
            return is_confirmed(d, review)
        except Exception:  # noqa: BLE001
            return False

    def plan(op: dict) -> Optional[dict]:
        try:
            d = by_verb.get(op["verb"])
            params = op.get("params") or {}
            if d is None or not confirmed(d) or is_read_only(d["effects"]) or d.get("compensates") is None:
                return None
            if effective_with(d, reg, review)["eff"]["rev"] != "reversible" or reversibility_for(d, params) != "reversible":
                return None
            c = by_verb.get(d["compensates"])
            if c is None or not confirmed(c):
                return None
            s = compensation_shape(d, c)
            if not s["ok"]:
                return None
            cparams: Dict[str, Any] = {}
            nc = normalize(c)
            for k in s["shape"]["copied"]:
                if k in params:
                    cparams[k] = copy.deepcopy(params[k])
                elif nc["params"][k]["required"]:
                    return None
            render = render_approval(d, params, True)
            comp: Dict[str, Any] = {"verb": c["verb"], "params": cparams, "def_digest": def_digest(c)}
            if "target" in s["shape"]:
                comp["target_param"] = s["shape"]["target"]
            return {"def_digest": def_digest(d), "compensation": comp, "render": render, "render_digest": approval_render_digest(render)}
        except Exception:  # noqa: BLE001
            return None

    return plan
