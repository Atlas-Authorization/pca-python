"""Differential replay of the GNAP bridge (atlas_pca.gnap) against the TypeScript reference (@atlasauth/pca-gnap): access rights,
holders, grant requests -> capability chains, action authorization, bound tokens, jwsd proofs (sign / verify / replay store), the
step-up continuation, and the interaction modes (hash, validation, the AS state machine as scripted scenarios)."""
import re

import pytest

pytest.importorskip("cryptography")

from atlas_pca import gnap as G
from base_oracle import b64d, canon, load_ref, run

COUNT, CASES = load_ref("gnap")


def _snake(opts, names):
    """Option dict with the reference's camelCase names mapped to snake_case; a present key stays present (even None)."""
    return {names[k]: v for k, v in (opts or {}).items() if k in names}


G2C_NAMES = {"issuerPublic": "issuer_public", "parent": "parent", "issuerChain": "issuer_chain", "clampToIssuer": "clamp_to_issuer", "holder": "holder",
             "interacted": "interacted", "now": "now", "goal": "goal", "riskPolicy": "risk_policy", "agentBinding": "agent_binding", "salt": "salt"}
CHAIN_NAMES = {"expectedRootIssuer": "expected_root_issuer", "pqPins": "pq_pins"}
RESP_NAMES = {"expiresIn": "expires_in", "bearer": "bearer", "instanceId": "instance_id", "manageUri": "manage_uri", "continue": "continue"}
HASH_NAMES = {"clientNonce": "client_nonce", "asNonce": "as_nonce", "interactRef": "interact_ref", "grantEndpoint": "grant_endpoint", "hashMethod": "hash_method"}


def _grant_request_to_capability(req, opts):
    o = _snake(opts, G2C_NAMES)
    if isinstance(opts, dict) and "issuerSecret" in opts:
        o["issuer_secret"] = b64d(opts["issuerSecret"]) if isinstance(opts["issuerSecret"], str) else opts["issuerSecret"]
    r = G.grant_request_to_capability(req, o)
    return {"grant": r["grant"], "chain": r["chain"], "holder": r["holder"], "grantedAccess": r["granted_access"],
            "droppedAccess": r["dropped_access"], "provenance": r["provenance"]}


def _authorize(chain, action, opts=None):
    return G.authorize_gnap_action(chain, action, _snake(opts, CHAIN_NAMES))


def _verify_token(value, opts=None):
    return G.verify_gnap_token(value, _snake(opts, CHAIN_NAMES))


def _sign_request(a):
    args = {"key": {"secret_key": b64d(a["key"]["secretKey"]), "public_key": b64d(a["key"]["publicKey"])}}
    for k, n in (("body", "body"), ("htm", "htm"), ("uri", "uri"), ("created", "created"), ("kid", "kid"), ("accessTokenValue", "access_token_value")):
        if k in a:
            args[n] = a[k]
    r = G.sign_gnap_request(args)
    return {"detachedJws": r["detached_jws"], "header": r["header"], "holder": r["holder"]}


def _verify_request(a):
    seen = []
    args = {}
    for k, n in (("detachedJws", "detached_jws"), ("body", "body"), ("holder", "holder"), ("htm", "htm"), ("uri", "uri"), ("maxAgeSec", "max_age_sec"),
                 ("now", "now"), ("accessTokenValue", "access_token_value"), ("replayCheck", "replay_check")):
        if k in a:
            args[n] = a[k]
    mode = a.get("seenProofMode")
    if mode in ("fresh", "replayed", "throws", "undefined"):
        def store(proof_id, expires):
            seen.append([proof_id, expires])
            if mode == "throws":
                raise RuntimeError("store down")
            return {"fresh": False, "replayed": True}.get(mode)
        args["seen_proof"] = store
    result = G.verify_gnap_request(args)
    if isinstance(result.get("reason"), str):
        result = dict(result, reason=re.sub(r"(bad-json) \(.*\)$", r"\1", result["reason"], flags=re.S))
    return {"result": result, "seen": seen}


def _step_up(req, opts=None):
    o = {}
    for k, n in (("issuerChain", "issuer_chain"), ("tier", "tier")):
        if opts is not None and k in opts:
            o[n] = opts[k]
    return G.gnap_request_requires_step_up(req, o)


def _begin(a):
    args = {}
    for k, n in (("signerSet", "signer_set"), ("t", "t"), ("tier", "tier"), ("continueUri", "continue_uri"), ("continueToken", "continue_token"),
                 ("wait", "wait"), ("reason", "reason")):
        if k in a:
            args[n] = a[k]
    r = G.begin_gnap_continuation(args)
    s = r["step_up"]
    return {"response": r["response"], "stepUp": {"tier": s["tier"], "t": s["t"], "signerSet": s["signer_set"], "reason": s["reason"], "continueToken": s["continue_token"]}}


def _complete(a):
    args = {"agent_leaf_secret": b64d(a["agentLeafSecret"])}
    for k, n in (("grant", "grant"), ("chain", "chain"), ("plan", "plan"), ("nodeId", "node_id"), ("params", "params"), ("counter", "counter"),
                 ("aud", "aud"), ("now", "now"), ("ttlMs", "ttl_ms"), ("signerSet", "signer_set"), ("t", "t")):
        if k in a:
            args[n] = a[k]
    if "cosignSecrets" in a:
        args["cosign_secrets"] = [{"role": c["role"], "secret": b64d(c["secret"])} for c in a["cosignSecrets"]]
    return G.complete_gnap_continuation(args)


def _accept_finish(cb, ctx):
    return G.accept_finish(cb, _snake(ctx, HASH_NAMES))


# ---- the interaction server, scripted ------------------------------------------------------------------------------------------

def _redact(v, pairs):
    if isinstance(v, str):
        for k, t in pairs:
            if k:
                v = v.replace(k, t)
        return v
    if isinstance(v, list):
        return [_redact(x, pairs) for x in v]
    if isinstance(v, dict):
        return {k: _redact(x, pairs) for k, x in v.items()}
    return v


def _scenario(s):
    clock = [1000]
    opts = s["opts"]
    ge = opts.get("grantEndpoint", "https://as.example/tx")
    o = {"grant_endpoint": ge, "supports": opts["supports"], "redirect_uri": lambda i: "https://as.example/i/%s" % i, "now": lambda: clock[0]}
    if opts.get("app"):
        o["app_uri"] = lambda i: "app://as/%s" % i
    if opts.get("userCodeUri"):
        o["user_code_uri"] = opts["userCodeUri"]
    if "ttlSec" in opts:
        o["ttl_sec"] = opts["ttlSec"]
    srv = G.InteractionServer(o)
    v = {}
    last = {}

    def sub(x):
        if isinstance(x, str) and x.startswith("$"):
            code = v.get("code") or ""
            if x == "$code:lower":
                return code.lower()
            if x == "$code:spaced":
                return code[:4] + " - " + code[4:]
            return v.get(x[1:], x)
        return x
    trace = []
    for st in s["steps"]:
        try:
            op = st["op"]
            if op == "start":
                last["req"] = st["req"]
                r = srv.start(st["req"])
                it = r["interaction"]
                v["id"], v["code"], v["asnonce"] = it.id, it.user_code or "", (it.finish["as_nonce"] if it.finish else "")
                v.setdefault("ids", []).append(it.id)
                value = {"interaction": it.as_dict(), "response": r["response"]}
            elif op == "lookup":
                it = srv.lookup_user_code(sub(st["code"]))
                value = it.as_dict() if it else None
            elif op == "approve":
                r = srv.approve(sub(st["id"]))
                v["ref"] = r["interact_ref"]
                it = srv.get(v["id"])
                fin = r.get("finish")
                if fin and fin["method"] == "push":
                    m = fin["body"]["hash"]
                elif fin and fin.get("url"):
                    mm = re.search(r"[?&]hash=([^&]+)", fin["url"])
                    m = mm.group(1) if mm else None
                else:
                    m = None
                v["hash"] = m if m is not None else ""
                expected = None
                if it is not None and it.finish is not None:
                    f = it.finish
                    expected = G.interaction_hash({"client_nonce": f["client_nonce"], "as_nonce": f["as_nonce"], "interact_ref": r["interact_ref"],
                                                   "grant_endpoint": it.grant_endpoint, "hash_method": f["hash_method"]})
                result = {"interactRef": r["interact_ref"]}
                if fin:
                    result["finish"] = fin
                value = {"result": result, "hashOk": m == expected}
            elif op == "consume":
                value = srv.consume(sub(st["ref"])).as_dict()
            elif op == "finalize":
                srv.finalize(sub(st["id"]))
                value = None
            elif op == "get":
                it = srv.get(sub(st["id"]))
                value = it.as_dict() if it else None
            elif op == "advance":
                clock[0] += st["sec"]
                value = clock[0]
            else:
                fin = last["req"]["finish"]
                ctx = {"client_nonce": fin["nonce"], "as_nonce": v.get("asnonce"), "grant_endpoint": ge}
                if fin.get("hash_method"):
                    ctx["hash_method"] = fin["hash_method"]
                value = G.accept_finish({"hash": sub(st["hash"]), "interact_ref": sub(st["ref"])}, ctx)
            pairs = [(v.get("ref"), "<REF>"), (v.get("hash"), "<HASH>"), (v.get("asnonce"), "<ASNONCE>"), (v.get("id"), "<ID>"), (v.get("code"), "<CODE>")]
            pairs = [(i, "<ID:%d>" % n) for n, i in enumerate(v.get("ids", [])[:-1])] + pairs  # an earlier interaction's id keeps its index
            trace.append({"op": op, "ok": True, "value": _redact(value, pairs)})
        except Exception as e:  # noqa: BLE001
            trace.append({"op": st["op"], "ok": False, "code": e.code if isinstance(e, G.InteractionError) else "other"})
    return trace


MAP = {
    "constants": lambda: {"GNAP_GRANT_CAVEAT": G.GNAP_GRANT_CAVEAT, "GNAP_ACCESS_CAVEAT": G.GNAP_ACCESS_CAVEAT, "MAX_DETACHED_JWS_CHARS": G.MAX_DETACHED_JWS_CHARS,
                          "START_MODES": list(G.START_MODES), "FINISH_METHODS": list(G.FINISH_METHODS), "HASH_METHODS": list(G.HASH_METHODS)},
    "AGENT_GNAP_PROFILE": lambda: G.AGENT_GNAP_PROFILE,
    "gnapActionResource": G.gnap_action_resource,
    "normalizeAccess": G.normalize_access,
    "accessToPredicates": G.access_to_predicates,
    "accessContains": G.access_contains,
    "accessWithin": G.access_within,
    "clampAccess": G.clamp_access,
    "resolveHolder": G.resolve_holder,
    "holderJwk": G.holder_jwk,
    "grantRequestToCapability": _grant_request_to_capability,
    "grantedAccessOf": G.granted_access_of,
    "authorizeGnapAction": _authorize,
    "encodeBoundToken": G.encode_bound_token,
    "capabilityToGrantResponse": lambda chain, opts=None: G.capability_to_grant_response(chain, _snake(opts, RESP_NAMES)),
    "verifyGnapToken": _verify_token,
    "gnapContentDigest": lambda body: G.gnap_content_digest(body),
    "gnapContentDigestAbsent": lambda: G.gnap_content_digest(),
    "signGnapRequest": _sign_request,
    "verifyGnapRequest": _verify_request,
    "gnapRequestRequiresStepUp": _step_up,
    "beginGnapContinuation": _begin,
    "gnapStepUpShare": lambda body, role, secret, signer_set, t: G.gnap_step_up_share(body, role, b64d(secret), signer_set, t),
    "completeGnapContinuation": _complete,
    "callbackUriOk": G.callback_uri_ok,
    "validateInteractRequest": G.validate_interact_request,
    "interactionHash": lambda a: G.interaction_hash(_snake(a, HASH_NAMES)),
    "verifyInteractionHash": lambda received, a: G.verify_interaction_hash(received, _snake(a, HASH_NAMES)),
    "acceptFinish": _accept_finish,
    "newUserCode": G.new_user_code,
    "accessToNeeds": G.access_to_needs,
    "interactionScenario": _scenario,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in CASES.values()) and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
