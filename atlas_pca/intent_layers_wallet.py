"""Wallet-side layered intent lattice and quorum-signed layer approvals: ceiling admitters, the lattice view of a task
learner, owner risk, layer cell sets and k-of-n approvals of a shared-layer widening. Native port of the TypeScript
reference (@atlasauth/pca-intent); the verifier-side layer checks live in intent_layers."""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from . import ed25519
from .intent_layers import LAYER_CEILINGS
from .intent_multi import normalize_rule, rule_admits
from .intent_omega import DEFAULT_HARM, cell_rep, cell_stats, decode_cell, encode_cell, verb_cell_count
from .intent_policy import admitter
from .intent_v2 import _UNDEF, _js_strict_eq
from .pca import _verify_b64u, b64u, canonical_bytes_strict, decode_b64u_strict

LAYER_APPROVAL_DOMAIN = "atlas-pca/intent-layer-approval/v1\0"


def ceiling_admitters(layers: Any) -> Dict[str, Any]:
    """Compile ceiling layers into admitters. ABSENT = no ceiling; a ceiling present as null or not an object is malformed."""
    out: Dict[str, Any] = {}
    for k in LAYER_CEILINGS:
        l = layers.get(k, _UNDEF) if isinstance(layers, dict) else _UNDEF
        if l is _UNDEF:
            out[k] = None
            continue
        if l is None or not isinstance(l, dict):
            raise ValueError("ceilingAdmitters: the %s ceiling is malformed (null or not an object)" % k)
        out[k] = admitter(l)
    return out


def ceiling_of(c: Dict[str, Any], vs: dict, o: dict) -> Optional[str]:
    """The first ceiling that excludes the outcome (None when every ceiling admits it)."""
    for k in LAYER_CEILINGS:
        a = c.get(k)
        if a and not a.admits(vs, o):
            return k
    return None


def lattice_view(task: Any, ceilings: Dict[str, Any]) -> dict:
    """The lattice of a task learner under ceiling layers (the learner exposes omega, cells() and tau)."""
    out: Dict[str, List[dict]] = {"effective": [], "uncertain": [], "ceiling": []}
    by_verb = {v["verb"]: v for v in task.omega["verbs"]}
    for c in task.cells():
        vs = by_verb[c["verb"]]
        layer = ceiling_of(ceilings, vs, cell_rep(vs, c["cell"]))
        if layer:
            out["ceiling"].append({"verb": c["verb"], "cell": c["cell"], "layer": layer})
            continue
        if c["vetoed"]:
            continue
        if c["inGrant"]:
            out["effective"].append({"verb": c["verb"], "cell": c["cell"]})
        elif c["p"] > 1e-12 and c["p"] < task.tau - 1e-12:
            out["uncertain"].append({"verb": c["verb"], "cell": c["cell"]})
    return out


def decide_outcome_layers(task: Any, ceilings: Dict[str, Any], o: dict) -> dict:
    vs = next((v for v in task.omega["verbs"] if v["verb"] == o["verb"]), None)
    if vs is None:
        return {"decision": "intent_denied"}
    layer = ceiling_of(ceilings, vs, o)
    if layer:
        return {"decision": "ceiling", "layer": layer}
    if task.is_vetoed(o) or task.acceptance(o) <= 1e-12:
        return {"decision": "intent_denied"}
    if task.admits_outcome(o):
        return {"decision": "admit", "by": 0}
    return {"decision": "intent_required"}


def _key(c: dict) -> str:
    return "%s|%s" % (c["verb"], ",".join(str(i) for i in c["cell"]))


def assert_askable(view: dict, c: dict) -> None:
    """A question may only be about a cell of U_k (inside every ceiling); raises otherwise."""
    key = _key(c)
    if not any(_key(u) == key for u in view["uncertain"]):
        raise ValueError("layers: cell %s is not an uncertain cell inside every ceiling (never a question)" % key)


def owner_risk(omega: dict, cells: List[dict], acceptability: Callable[[dict, dict], float], harm: Any = DEFAULT_HARM) -> float:
    """Layer owner's own risk measure of a set of cells: sum of mu(c) (1 - a(c)) E[h | c]."""
    r = 0.0
    by_verb = {v["verb"]: v for v in omega["verbs"]}
    for c in cells:
        vs = by_verb.get(c["verb"])
        if vs is None:
            continue
        st = cell_stats(vs, c["cell"], harm)
        r += st["mass"] * (1 - acceptability(vs, cell_rep(vs, c["cell"]))) * st["harm"]
    return r


def layer_cells(omega: dict, a: Any) -> List[dict]:
    """Every cell of the outcome space an admitter admits."""
    out = []
    for vs in omega["verbs"]:
        for f in range(verb_cell_count(vs)):
            cell = decode_cell(vs, f)
            if a.admits(vs, cell_rep(vs, cell)):
                out.append({"verb": vs["verb"], "cell": cell})
    return out


def cell_key_of(omega: dict, c: dict) -> str:
    vs = next((v for v in omega["verbs"] if v["verb"] == c["verb"]), None)
    return "%s|%s" % (c["verb"], encode_cell(vs, c["cell"]) if vs else ",".join(str(i) for i in c["cell"]))


# ---- quorum-signed layer approvals --------------------------------------------------------------------------------

_STATEMENT_KEYS = ("layer", "session", "seq", "map_digest", "prev")


def _statement_of(a: Any) -> Dict[str, Any]:
    g = (lambda k: a.get(k, _UNDEF)) if isinstance(a, dict) else (lambda k: _UNDEF)
    return {"v": 1, "kind": "pca-intent-layer-approval", **{k: g(k) for k in _STATEMENT_KEYS}}


def _approval_message(s: dict) -> bytes:
    return LAYER_APPROVAL_DOMAIN.encode("utf-8") + canonical_bytes_strict(_statement_of(s))


def sign_layer_approval(s: dict, secret_key: bytes) -> dict:
    """Sign an approval of a shared-layer widening (an Ed25519 seed)."""
    st = _statement_of(s)
    return {**st, "signer": b64u(ed25519.public_key(secret_key)), "sig": b64u(ed25519.sign_secret(secret_key, _approval_message(st)))}


def verify_quorum_approvals(approvals: Any, members: Any, rule: Any, expected: Any) -> dict:
    """An approval counts iff its signer is a member, it is that member's first, its statement equals `expected` field by
    field and its signature verifies; the rule is the multi-principal one over member keys."""
    ignored: List[dict] = []
    if not isinstance(approvals, list) or not isinstance(members, list) or expected is None or not isinstance(expected, (dict, list)):
        return {"ok": False, "signers": [], "ignored": [{"index": -1, "reason": "approvals and members must be arrays and expected an object"}]}
    if (any(not isinstance(m, str) for m in members) or len(set(members)) != len(members)
            or any(decode_b64u_strict(m, 32) is None for m in members)):
        return {"ok": False, "signers": [], "ignored": [{"index": -1, "reason": "members must be distinct 32-byte keys"}]}
    try:
        n = normalize_rule(rule, list(members))
    except Exception as e:  # noqa: BLE001 - the refusal text is reported
        return {"ok": False, "signers": [], "ignored": [{"index": -1, "reason": str(e)}]}
    want = _statement_of(expected)
    counted: set = set()
    for i, a in enumerate(approvals):
        if a is None or a is False or a == 0 or a == "" or not isinstance(a, (dict, list)):
            ignored.append({"index": i, "reason": "not an object"})
            continue
        signer = a.get("signer", _UNDEF) if isinstance(a, dict) else _UNDEF
        if not (isinstance(signer, str) and signer in members):
            ignored.append({"index": i, "reason": "signer is not a member"})
            continue
        if signer in counted:
            ignored.append({"index": i, "reason": "second approval from the same member"})
            continue
        st = _statement_of(a)
        same = (all(_js_strict_eq(st[k], want[k]) for k in want) and _js_strict_eq(a.get("v", _UNDEF), 1)
                and _js_strict_eq(a.get("kind", _UNDEF), "pca-intent-layer-approval"))
        if not same:
            ignored.append({"index": i, "reason": "approval is for another (layer, session, seq, map_digest, prev)"})
            continue
        try:
            sig = a.get("sig", _UNDEF)
            ok = isinstance(sig, str) and bool(_verify_b64u(signer, _approval_message(st), sig))
        except Exception:  # noqa: BLE001
            ok = False
        if not ok:
            ignored.append({"index": i, "reason": "bad signature"})
            continue
        counted.add(signer)
    signers = [m for m in members if m in counted]
    return {"ok": rule_admits(n, [m in counted for m in members]), "signers": signers, "ignored": ignored}


def org_layer_from_maps(maps: List[dict], rule: dict) -> Dict[str, Any]:
    """An org layer that is itself a LEARNED map over a shared omega: the joint grant of the org approvers' maps under the
    org's rule. Its uncertain cells go to the org's approvers; a widening needs an org delta with a quorum of signatures."""
    from .intent_multi_agg import aggregate_intent_maps
    m = aggregate_intent_maps(maps, rule)
    return {"map": m, "policy": m["grant"]}
