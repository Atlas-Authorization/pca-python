"""Lazy just-in-time elicitation: the ordered per-visit decision, the cell coordinates carried by a signed
`pca-intent-required`, its wallet-side body, and the delta cells between two answers. Native port of the TypeScript
reference (@atlasauth/pca-intent). A "learner" exposes .omega, .is_vetoed(o), .acceptance(o) and (for deltas) .cells();
signing / verifying the required notice and minting the signed delta grant belong to the core."""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from .intent_omega import cell_of, encode_cell, verb_cell_count
from .pca import hash_canonical

INTENT_ACTION_DOMAIN = "atlas-pca/intent-action/v1"


def decide_visit(i: dict) -> dict:
    """The ordered lazy-elicitation decision: schema violation, ceiling, denied, admit, or intent_required."""
    conform = i["conform"]
    if not conform["ok"]:
        return {"kind": "schema_violation", "reason": "%s: %s" % (conform["code"], conform["reason"])}
    learner = i["learner"]
    lifted = i["lifted"]
    vs = next((v for v in learner.omega["verbs"] if v["verb"] == lifted["verb"]), None)
    cell = cell_of(vs, lifted) if vs else None
    if vs is None or cell is None:
        return {"kind": "schema_violation", "reason": "the lifted action lies outside \u03a9\u0303"}
    for ceiling in i.get("ceilings") or []:
        if not ceiling(vs, lifted):
            return {"kind": "ceiling"}
    vetoed = learner.is_vetoed(lifted)
    p = learner.acceptance(lifted)
    if vetoed or p <= 0:
        return {"kind": "intent_denied", "vetoed": vetoed}
    if i["inEffective"]:
        return {"kind": "admit", "cell": cell}
    return {"kind": "intent_required", "cell": cell, "p": p}


def cell_coords(vs: dict, cell: List[int]) -> Dict[str, list]:
    """The coordinates of one cell (numeric: [i, i]; categorical: the cell's value). Never text about the value."""
    out: Dict[str, list] = {}
    for k, d in enumerate(vs["dims"]):
        out[d["path"]] = [cell[k], cell[k]] if d["kind"] == "num" else [d["values"][cell[k]]["value"]]
    return out


def cell_from_coords(vs: dict, coords: Any) -> Optional[List[int]]:
    """Coordinates -> per-dimension cell indices (the inverse of cell_coords for one cell), or None."""
    if not isinstance(coords, dict) or len(coords) != len(vs["dims"]):
        return None
    out: List[int] = []
    for d in vs["dims"]:
        c = coords.get(d["path"])
        if c is None or not isinstance(c, list):
            return None
        if d["kind"] == "num":
            if len(c) < 2 or not isinstance(c[0], (int, float)) or isinstance(c[0], bool) or c[0] != c[1]:
                return None
            out.append(c[0])
        else:
            if len(c) != 1 or not isinstance(c[0], str):
                return None
            i = next((k for k, v in enumerate(d["values"]) if v["value"] == c[0]), -1)
            if i < 0:
                return None
            out.append(i)
    return out


def intent_action_digest(action: dict) -> str:
    """The action digest a JIT consent is bound to."""
    return hash_canonical({"d": INTENT_ACTION_DOMAIN, "action": {k: action[k] for k in ("verb", "resource", "params_digest", "reversibility_class")}})


def intent_required_body(i: dict) -> dict:
    """The site's `pca-intent-required` body for a visited uncertain cell (sign it with the core)."""
    return {"v": 1, "kind": "pca-intent-required", "session": i["session"], "map_digest": i["mapDigest"], "schema": i["schemaDigest"],
            "pcactn_digest": hash_canonical(i["pcactn"]), "action_digest": intent_action_digest(i["pcactn"]["action"]),
            "cell": {"verb": i["vs"]["verb"], "coords": cell_coords(i["vs"], i["cell"])}, "reason": "uncertain", "question_id": i["questionId"],
            "friction": i["friction"], "delivered_to": i["deliveredTo"], "expires_at": i["expiresAt"]}


def wallet_check_intent_required(body: dict, w: dict, verify: Callable[[Any, Any, Any], dict]) -> dict:
    """The wallet's check of an intent_required: the injected verifier checks the site signature under its keys and the expiry
    (verify(body, keys, now) -> {ok, reason?}); the session, map, action and the cell are then re-derived from the wallet's own
    space. Any disagreement refuses the question."""
    v = verify(body, w["keys"], w["now"])
    if not v["ok"]:
        return v
    if body.get("session") != w["session"] or body.get("map_digest") != w["mapDigest"]:
        return {"ok": False, "reason": "the question is for another session or map"}
    if body.get("pcactn_digest") != hash_canonical(w["pcactn"]) or body.get("action_digest") != intent_action_digest(w["pcactn"]["action"]):
        return {"ok": False, "reason": "the question is about another action"}
    lifted = w["lifted"]
    vs = next((x for x in w["omegaTilde"]["verbs"] if x["verb"] == lifted["verb"]), None)
    mine = cell_of(vs, lifted) if vs else None
    if vs is None or mine is None or body["cell"]["verb"] != vs["verb"]:
        return {"ok": False, "reason": "the wallet cannot place the action in \u03a9\u0303"}
    theirs = cell_from_coords(vs, body["cell"]["coords"])
    if theirs is None or any(x != mine[k] for k, x in enumerate(theirs)):
        return {"ok": False, "reason": "the site cell differs from the cell the wallet derives"}
    return {"ok": True, "vs": vs, "cell": mine}


def delta_cells(prev: Any, nxt: Any) -> Dict[str, List[int]]:
    """Per verb, the cells the next learner's grant adds over the previous one's (as 0/1 arrays over the flat cell index)."""
    out: Dict[str, List[int]] = {}
    prev_in = {"%s|%s" % (c["verb"], ",".join(str(i) for i in c["cell"])) for c in prev.cells() if c["inGrant"]}
    for vs in nxt.omega["verbs"]:
        a = [0] * verb_cell_count(vs)
        any_ = False
        for c in nxt.cells():
            if c["verb"] != vs["verb"] or not c["inGrant"] or "%s|%s" % (c["verb"], ",".join(str(i) for i in c["cell"])) in prev_in:
                continue
            a[encode_cell(vs, c["cell"])] = 1
            any_ = True
        if any_:
            out[vs["verb"]] = a
    return out


def delta_predicates(omega_tilde: dict, delta: Dict[str, List[int]]) -> List[dict]:
    """The predicates of a delta (one maximal box per covered region, per verb)."""
    from .intent_learner import boxes_to_predicates
    out: List[dict] = []
    for vs in omega_tilde["verbs"]:
        if vs["verb"] in delta:
            out.extend(boxes_to_predicates(vs, delta[vs["verb"]]))
    return out


def mint_delta(prev: Any, nxt: Any, prev_grant: dict, principal: Any, holder: str, session: str, seq: int, root: str,
               map_digest: str, prev_id: Optional[str] = None, **kw: Any) -> Optional[Dict[str, Any]]:
    """Mint D_k from the k-th answer: None when the answer added no cell. `principal` is the PRINCIPAL key (the wallet holds
    it; the agent's key never signs a grant); `kw` are the remaining mint_session_grant arguments (map_form, caveats, ...)."""
    from .signers_more import mint_session_grant
    delta = delta_cells(prev, nxt)
    cells = sum(sum(v) for v in delta.values())
    if cells == 0:
        return None
    if prev_id is not None and prev_id != prev_grant["id"]:
        raise ValueError("mintDelta: prev must be the id of the previous session grant")
    r = mint_session_grant(principal, holder, session, seq, root, map_digest, delta_predicates(nxt.omega, delta), prev=prev_grant["id"], **kw)
    return {**r, "cells": cells}
