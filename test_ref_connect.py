"""Differential replay of the outbound token vault (atlas_pca.connect: oauth_scope caveats, token refresh, the proxy-mode request
extractor, signed release receipts, the envelope-encrypted store, TokenVault release and proxy scenarios) against vectors generated
from the TypeScript reference (@atlasauth/pca-connect). A reference throw requires the port to raise. Envelope encryption needs the
optional `cryptography` package."""
import pytest

from atlas_pca import connect as C, connect_replay as R, ed25519
from atlas_pca.pca import unb64u
from base_oracle import load_ref, run

ed25519.allow_insecure_signer()
COUNT, CASES = load_ref("connect")


def u16(s):
    return s.encode("utf-16-be")


def granted(chain, provider):
    r = C.granted_oauth_scopes(chain, provider)
    return None if r is None else sorted(r, key=u16)


def err_out(e):
    if isinstance(e, C.VaultError):
        out = {"ok": False, "name": type(e).__name__, "code": e.code}
        if e.code != "not_authorized":
            out["message"] = e.message
        if getattr(e, "status", None) is not None:
            out["status"] = e.status
        if getattr(e, "missing", None):
            out["missing"] = list(e.missing)
        return out
    return {"ok": False, "name": "Error"}


class Resp:
    def __init__(self, r):
        self.ok, self.status, self._r = r["ok"], r["status"], r

    def json(self):
        if self._r.get("jsonThrows"):
            raise ValueError("bad json")
        return self._r.get("json")

    def text(self):
        if self._r.get("textThrows"):
            raise ValueError("bad text")
        return self._r.get("text", "")


def transport(script, log):
    if script is None:
        return None
    n = [0]

    def fetch(url, init):
        log.append({"url": url, "method": init["method"], "headers": init["headers"], "body": init["body"]})
        r = script[min(n[0], len(script) - 1)]
        n[0] += 1
        if "throws" in r:
            raise RuntimeError(r["throws"])
        return Resp(r)

    return fetch


def refresh(c):
    log = []
    try:
        v = C.refresh_connection(c["connection"], c.get("config"), c["refreshToken"], c["requested"], transport(c.get("script"), log), c["now"],
                                 c["defaultTokenLifetimeMs"])
        return {"ok": True, "value": v, "calls": log}
    except Exception as e:  # noqa: BLE001
        return {**err_out(e), "calls": log}


def decrypt(c):
    inner = C.InMemoryConnectionStore()
    inner.set(c["record"])
    w = C.LocalKeyWrapper({k: unb64u(v) for k, v in c["ring"].items()}, c["active"])
    store = C.EncryptedConnectionStore(inner, w)
    try:
        r = store.get(c["key"])
        return {"ok": True, "value": None if r is None else C.clone_connection(r)}
    except Exception as e:  # noqa: BLE001
        return err_out(e)


def vault(s):
    now = {"v": s["nowMs"]}
    store = C.InMemoryConnectionStore()
    fetch_log, proxy_log, receipts = [], [], []
    op = s.get("opts") or {}
    table = s.get("actionsTable")
    pi = [0]
    kw = {"strict": False, "store": store, "now": lambda: now["v"], "fetch": transport(s.get("fetchScript"), fetch_log)}
    simple = {"insecureBearerRelease": "insecure_bearer_release", "insecureSkipPlanRootCheck": "insecure_skip_plan_root_check",
              "authorizedPlanRoots": "authorized_plan_roots", "audience": "audience", "expiryLeewayMs": "expiry_leeway_ms",
              "defaultTokenLifetimeMs": "default_token_lifetime_ms", "requireActionBinding": "require_action_binding",
              "defaultConnectionId": "default_connection_id", "providers": "providers", "pqPins": "pq_pins",
              "maxProxyResponseBytes": "max_proxy_response_bytes"}
    for k, v in simple.items():
        if k in op and op[k] is not None and op[k] is not False:
            kw[v] = op[k]
        elif k in op and op[k] is False and k == "requireActionBinding":
            kw[v] = False
    if "useVerb" in op:
        kw["use_verb"] = op["useVerb"]
    if op.get("replay"):
        kw["replay"] = R.InMemoryReplayStore()
    if op.get("revoked"):
        def is_revoked(_p):
            if op["revoked"] == "throws":
                raise RuntimeError("src down")
            return op["revoked"] == "yes"
        kw["is_revoked"] = is_revoked
    if table:
        def actions(verb):
            t = table.get(verb)
            if t is None:
                return None
            a = {"verb": t["verb"], "def_digest": t["def_digest"], "confirmed": t["confirmed"], "upstream": t["upstream"]}
            if t.get("extract"):
                a["extract"] = C.http_extractor(t["extract"])
            return a
        kw["actions"] = actions
    if op.get("proxy"):
        def proxy_fetch(req):
            proxy_log.append({"method": req["method"], "url": req["url"], "headers": req["headers"], "body": req.get("body"), "redirect": req["redirect"]})
            r = s["proxyScript"][min(pi[0], len(s["proxyScript"]) - 1)]
            pi[0] += 1
            if r.get("throws"):
                raise RuntimeError("net")
            return {"status": r["status"], "headers": r["headers"], "body": r["body"]}
        kw["proxy_fetch"] = proxy_fetch
    if op.get("receiptSeed"):
        def sink(r):
            receipts.append(r)
            if op.get("failingSink"):
                raise RuntimeError("sink")
        kw["receipts"] = {"secret_key": unb64u(op["receiptSeed"]), "sink": sink}
    v = C.TokenVault(**kw)
    results = []

    def rec(f):
        try:
            results.append({"ok": True, "value": f()})
        except Exception as e:  # noqa: BLE001
            results.append(err_out(e))

    for c in s["calls"]:
        if c["op"] == "put":
            a = c["args"]
            rec(lambda a=a: v.put_connection(a.get("agentId"), a.get("provider"), a.get("accessToken"), a.get("expiresAt"), a.get("scopes"),
                                             a.get("authority"), a.get("connectionId"), a.get("refreshToken")))
        elif c["op"] == "get":
            a = c["args"]
            rec(lambda c=c, a=a: v.get_connection_token(c["pcActn"], a["provider"], a.get("connectionId"), a.get("scopes")))
        elif c["op"] == "proxy":
            a = c["args"]
            rec(lambda c=c, a=a: v.proxy_call(c["pcActn"], c["request"], a["provider"], a.get("connectionId"), a.get("scopes")))
        elif c["op"] == "delete":
            rec(lambda c=c: v.delete_connection(c["agentId"], c["provider"], c.get("connectionId")))
        elif c["op"] == "now":
            now["v"] = c["now"]
    out = []
    for k in s.get("watch") or []:
        g = store.get(k)
        out.append(None if g is None else C.clone_connection(g))
    return {"results": results, "store": out, "receipts": receipts, "fetchCalls": fetch_log, "proxyCalls": proxy_log}


MAP = {
    "oauthScopeCaveat": C.oauth_scope_caveat, "isOAuthScopeCaveat": C.is_oauth_scope_caveat, "grantedOAuthScopes": granted,
    "httpExtractor": lambda spec, req: C.http_extractor(spec)(req), "checkProxyHeaders": C.check_proxy_headers,
    "DEFAULT_PROXY_HEADERS": lambda: list(C.DEFAULT_PROXY_HEADERS), "outboundRequestDigest": C.outbound_request_digest,
    "signReleaseReceipt": lambda b, seed: C.sign_release_receipt(b, unb64u(seed)), "verifyReleaseReceipt": C.verify_release_receipt,
    "receiptActionDigest": C.receipt_action_digest, "refreshConnection": refresh, "decryptRecord": decrypt, "vault": vault,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in CASES.values()) and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    if fn == "decryptRecord":
        pytest.importorskip("cryptography")
    run(CASES[fn], MAP[fn])
