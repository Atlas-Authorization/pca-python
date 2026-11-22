"""Least privilege from observed behaviour: propose a narrower grant from what its holder really did (proven subsumed by the
original, never applied), unused-permission findings, and signed access requests. Port of the TypeScript reference
(@atlasauth/pca-analyzer)."""
import math
from typing import Any, Dict, List

from . import ed25519
from .analyzer_core import admits_concrete, subsumes, to_model
from .analyzer_exposure import diff_policies, resolve_action
from .analyzer_js import UNDEF, fin, includes, is_num, jget, js_str, jsnum, nn, num_str, own, req_list, spread, strict_eq, truthy, u16key
from .analyzer_residual import policy_digest_of
from .pca import REVERSIBILITY_ORDER, b64u, decode_b64u_strict, hash_canonical, sha256
from .predicates import predicate_matches

ACCESS_REQUEST_SIG_DOMAIN = "atlas-pca/access-request/v1\0"


def _rev_weight(r: Any) -> int:
    return REVERSIBILITY_ORDER.index(r) + 1 if isinstance(r, str) and r in REVERSIBILITY_ORDER else 0


def _is_obj(x: Any) -> bool:
    return isinstance(x, dict)


def _common_prefix(rs: List[str]) -> str:
    p = rs[0] if rs else ""
    for r in rs:
        i = 0
        while i < len(p) and i < len(r) and p[i] == r[i]:
            i += 1
        p = p[:i]
    cut = p.rfind("/")
    return p[:cut + 1] if cut >= 0 else ""


def _is_integer(v: Any) -> bool:
    return is_num(v) and float(jsnum(v)).is_integer()


def _upper_bound_of(where: Any, path: str) -> float:
    ub = math.inf
    for c in req_list(nn(where, [])):
        if isinstance(c, dict) and "field" in c and c["field"] == path and c.get("op") in ("lte", "lt") and is_num(c.get("value", UNDEF)):
            ub = min(ub, jsnum(c["value"]))
    return ub


def _ctx_of(a: Any) -> Dict[str, Any]:
    params = jget(a, "params")
    return {"action": {"verb": jget(a, "verb"), "resource": jget(a, "resource"), "params": {} if params is UNDEF or params is None else params}}


def _matches(p: Any, a: Any) -> bool:
    return predicate_matches(p, _ctx_of(a))


def _params_of(a: Any) -> Any:
    return nn(jget(a, "params"), {})


def _join_verbs(verbs: List[Any]) -> str:
    return ", ".join("" if v is None else js_str(v) for v in verbs)


def suggest_narrowing(policy: Any, observed: Any, o: Any = None) -> Dict[str, Any]:
    """Propose a narrower replacement for `policy` from the ledger-sourced `observed` actions, plus unused-permission findings
    and access requests for refused attempts. Result: {used, rejected, denied, proposal?, reason?, coversObserved, diff?,
    findings, accessRequests, taskBinding?}. Never applies anything."""
    o = {} if o is None else o
    margin = nn(jget(o, "margin"), 0.1)
    min_samples = nn(jget(o, "minSamples"), 5)
    enum_limit = nn(jget(o, "enumLimit"), 8)
    catalog = jget(o, "catalog")
    model = to_model(policy)
    digest = policy_digest_of(model)
    observed = req_list(observed)

    trusted = [x for x in observed if jget(x, "source") == "ledger" and jget(x, "outcome") != "denied"]
    rejected = len([x for x in observed if jget(x, "source") != "ledger"])
    refused = [x for x in observed if jget(x, "source") == "ledger" and jget(x, "outcome") == "denied"]

    findings: List[Dict[str, Any]] = []
    pp = jget(policy, "predicates")
    base = pp if isinstance(pp, list) else []

    def build(narrow_resources: bool) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for p in base:
            hits = [a for a in trusted if _matches(p, a)]
            if not hits:
                continue
            verbs = sorted({jget(h, "verb"): None for h in hits}, key=u16key)
            resources = sorted({jget(h, "resource"): None for h in hits}, key=u16key)
            nxt: Dict[str, Any] = {"verb": verbs[0] if len(verbs) == 1 else verbs}
            if narrow_resources:
                if len(resources) == 1:
                    nxt["resource"] = resources[0]
                else:
                    pre = _common_prefix(resources)
                    if len(pre) > 1:
                        nxt["resource"] = pre + "*"
                    elif jget(p, "resource") is not UNDEF:
                        nxt["resource"] = jget(p, "resource")
            elif jget(p, "resource") is not UNDEF:
                nxt["resource"] = jget(p, "resource")
            where: List[Any] = list(req_list(nn(jget(p, "where"), [])))
            names: Dict[str, None] = {}
            for h in hits:
                for k in spread(_params_of(h)):
                    names[k] = None
            for name in sorted(names, key=u16key):
                path = "action.params.%s" % name
                vals = [own(_params_of(h), name) for h in hits]
                if len(vals) < min_samples or any(v is UNDEF for v in vals):
                    continue
                if all(is_num(v) and fin(v) is not None for v in vals):
                    mx = max(jsnum(v) for v in vals)
                    v = mx * (1 + margin)
                    ceil = math.ceil(v) if all(_is_integer(x) for x in vals) else v
                    if ceil < _upper_bound_of(jget(p, "where"), path):
                        where.append({"field": path, "op": "lte", "value": ceil})
                elif all(isinstance(v, str) for v in vals):
                    st = sorted(set(vals), key=u16key)
                    if len(st) <= enum_limit:
                        where.append({"field": path, "op": "in", "value": st})
            if where:
                nxt["where"] = where
            out.append(nxt)
        return out

    for i, p in enumerate(base):
        hit = any(_matches(p, a) for a in trusted)
        pv = jget(p, "verb")
        verbs = [pv] if isinstance(pv, str) else list(pv) if isinstance(pv, list) else []
        if not hit:
            v = verbs[0] if verbs and verbs[0] is not None else "*"
            s = resolve_action(catalog, "unknown.any" if v == "*" else v)["spec"]
            findings.append({
                "kind": "unused-predicate", "predicate": i, "verb": v,
                "detail": "no observed action used predicate %d (%s)" % (i, _join_verbs(verbs) or "*"),
                "blastRadius": s["blastRadius"], "reversibility": s["reversibility"], "rank": s["blastRadius"] * _rev_weight(s["reversibility"]),
            })
            continue
        for v in verbs:
            if v == "*":
                continue
            if not any(strict_eq(jget(a, "verb"), v) and _matches(p, a) for a in trusted):
                s = resolve_action(catalog, v)["spec"]
                findings.append({
                    "kind": "unused-verb", "predicate": i, "verb": v, "detail": "verb %s is granted by predicate %d but never used" % (v, i),
                    "blastRadius": s["blastRadius"], "reversibility": s["reversibility"], "rank": s["blastRadius"] * _rev_weight(s["reversibility"]),
                })
        for c in req_list(nn(jget(p, "where"), [])):
            if (_is_obj(c) and isinstance(c.get("field"), str) and c.get("op") in ("lte", "lt") and is_num(c.get("value", UNDEF))
                    and c["field"].startswith("action.params.")):
                name = c["field"][len("action.params."):]
                vals = [x for x in (own(_params_of(a), name) for a in trusted if _matches(p, a)) if is_num(x)]
                if len(vals) >= min_samples and max(jsnum(x) for x in vals) < jsnum(c["value"]) / 2:
                    v0 = verbs[0] if verbs else UNDEF
                    s = resolve_action(catalog, v0 if v0 is not UNDEF and v0 is not None else "unknown.any")["spec"]
                    f: Dict[str, Any] = {"kind": "unreached-cap", "predicate": i}
                    if truthy(v0):
                        f["verb"] = v0
                    f.update({
                        "detail": "%s <= %s but the largest observed value is %s" % (name, num_str(jsnum(c["value"])), num_str(max(jsnum(x) for x in vals))),
                        "blastRadius": s["blastRadius"], "reversibility": s["reversibility"], "rank": s["blastRadius"] * _rev_weight(s["reversibility"]),
                    })
                    findings.append(f)
    findings.sort(key=lambda f: (-f["rank"], f["predicate"]))

    groups: Dict[str, Dict[str, Any]] = {}
    for a in refused:
        k = "%s\u0000%s" % (js_str(jget(a, "verb")), js_str(jget(a, "resource")))
        g = groups.get(k)
        if g is not None:
            g["denied_count"] += 1
        else:
            r: Dict[str, Any] = {
                "v": 1, "kind": "pca-access-request", "verb": jget(a, "verb"), "resource": jget(a, "resource"),
                "example_params": spread(_params_of(a)), "denied_count": 1, "policy_digest": digest,
            }
            if truthy(jget(o, "taskBinding")):
                r["task_binding"] = jget(o, "taskBinding")
            groups[k] = r
    access_requests = sorted(groups.values(), key=lambda g: (-g["denied_count"], u16key(g["verb"])))

    res: Dict[str, Any] = {"used": len(trusted), "rejected": rejected, "denied": len(refused), "coversObserved": False, "findings": findings, "accessRequests": access_requests}
    if truthy(jget(o, "taskBinding")):
        res["taskBinding"] = jget(o, "taskBinding")

    caveats = list(nn(model.get("caveats"), []))
    decay = jget(o, "decay")
    if truthy(decay):
        caveats.append({"type": "expires", "at": jget(decay, "nowSec") + jget(decay, "expiresInSecs")})
    original = policy
    for narrow in (True, False):
        proposal = {"predicates": build(narrow), "caveats": caveats, "vetoes": model["vetoes"], "tighten": model["tighten"]}
        if len(proposal["predicates"]) == 0:
            res["reason"] = "no ledger observation matches any predicate"
            return res
        proof = subsumes(original, proposal)
        if proof["subsumes"] is not True or proof.get("approximate") is True:
            res["reason"] = proof.get("reason", "the proposal could not be proven narrower than the original")
            continue
        res.pop("reason", None)
        res["proposal"] = proposal
        res["coversObserved"] = all(
            admits_concrete(proposal, {"verb": jget(a, "verb"), "resource": jget(a, "resource"), "params": _params_of(a)}) for a in trusted)
        res["diff"] = diff_policies(original, proposal)
        return res
    return res


# ---- access requests ------------------------------------------------------------------------------------------------------------


def _request_message(r: Any) -> bytes:
    return ACCESS_REQUEST_SIG_DOMAIN.encode("utf-8") + sha256(hash_canonical(r).encode("utf-8"))


def sign_access_request(r: Any, secret: bytes, signer_public: str) -> Dict[str, Any]:
    """The holder's signed ask (a request for a human to read; nothing here turns it into authority). `secret` is the Ed25519 seed."""
    return {"request": r, "signer": signer_public, "sig": b64u(ed25519.sign(secret, _request_message(r)))}


def verify_access_request(s: Any, expected_signer: Any = None) -> bool:
    """Verify a signed access request (optionally against an expected signer public key); any failure is False."""
    try:
        if not _is_obj(s) or not _is_obj(s.get("request")) or s["request"].get("kind") != "pca-access-request" or not strict_eq(s["request"].get("v", UNDEF), 1):
            return False
        if expected_signer is not None and not strict_eq(s.get("signer", UNDEF), expected_signer):
            return False
        sig = s.get("sig")
        if not isinstance(sig, str):
            return False
        pk = decode_b64u_strict(s.get("signer"), 32)
        sg = decode_b64u_strict(sig, 64)
        if pk is None or sg is None:
            return False
        return bool(ed25519.verify(pk, _request_message(s["request"]), sg))
    except Exception:  # noqa: BLE001 - any failure is a refusal
        return False
