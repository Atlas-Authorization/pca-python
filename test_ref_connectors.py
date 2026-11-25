"""Differential replay of the connector catalog (atlas_pca.connectors: manifest validation and digests, the provider registry,
authorize URL / PKCE / URL variables, access-token placement, code exchange and refresh into the vault, manifest-to-vault-provider
mapping) against vectors generated from the TypeScript reference (@atlasauth/pca-connectors). Errors are compared as data (class
name and message); a failure that is not a connector error is the generic "Error". A reference throw requires the port to raise."""
import pytest

from atlas_pca import connect as V, connectors as C, ed25519
from base_oracle import load_ref, run

ed25519.allow_insecure_signer()
COUNT, CASES = load_ref("connectors")


def err_out(e):
    if isinstance(e, C.ConnectorError):
        out = {"ok": False, "name": type(e).__name__, "message": e.message}
        if getattr(e, "issues", None):
            out["issues"] = list(e.issues)
        return out
    return {"ok": False, "name": "Error"}


def guard(f):
    def g(*a):
        try:
            return {"ok": True, "value": f(*a)}
        except Exception as e:  # noqa: BLE001
            return err_out(e)
    return g


def with_reg(customs):
    r = C.create_default_registry()
    for m in customs or []:
        r.register(m)
    return r


def build_authorize(pid, opts, customs):
    return guard(lambda: C.build_authorize_url(pid, {**opts, "registry": with_reg(customs)}))()


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


def token_run(which):
    def run_case(c):
        log = []
        store = V.InMemoryConnectionStore()
        vault = V.TokenVault(strict=False, insecure_skip_plan_root_check=True, store=store, now=lambda: c["now"])
        bind = c["bind"]
        rest = {k: v for k, v in c.items() if k not in ("bind", "script", "customs")}
        authority = {"principal": bind["principal"]}
        for k in ("scopes", "audience"):
            if k in bind:
                authority[k] = bind[k]
        args = {**rest, "fetch": transport(c.get("script"), log), "registry": with_reg(c.get("customs")),
                "bind": {"vault": vault, "agentId": bind["agentId"], "authority": authority}}
        if "connectionId" in bind:
            args["bind"]["connectionId"] = bind["connectionId"]
        try:
            result = {"ok": True, "value": which(args)}
        except Exception as e:  # noqa: BLE001
            result = err_out(e)
        g = store.get({"agentId": bind["agentId"], "provider": c["providerId"], "connectionId": bind.get("connectionId", "default")})
        return {"result": result, "fetchCalls": log, "stored": None if g is None else V.clone_connection(g)}
    return run_case


def registry(s):
    r = C.ProviderRegistry() if s.get("empty") else C.create_default_registry()
    out = []
    for op in s["ops"]:
        try:
            k = op["op"]
            if k == "register":
                v = r.register(op["manifest"], op.get("opts"))
            elif k == "get":
                v = r.get(op["id"])
            elif k == "require":
                v = r.require(op["id"])
            elif k == "has":
                v = r.has(op["id"])
            elif k == "list":
                v = r.list()
            elif k == "ids":
                v = r.ids()
            else:
                v = C.catalog_digest(r)
            out.append({"ok": True, "value": v})
        except Exception as e:  # noqa: BLE001
            out.append(err_out(e))
    return out


def catalog():
    return {"ids": [m["id"] for m in C.list_providers()], "manifests": C.list_providers(), "digest": C.catalog_digest(),
            "google": C.get_provider("google"), "nope": C.get_provider("nope")}


MAP = {
    "validateManifest": C.validate_manifest, "assertManifest": guard(C.assert_manifest), "manifestDigest": C.manifest_digest, "catalog": catalog,
    "registry": registry, "substituteVars": guard(lambda u, v: C.substitute_vars(u, v)), "pkceChallenge": guard(C.pkce_challenge),
    "buildAuthorizeUrl": build_authorize, "applyAccessToken": guard(C.apply_access_token),
    "manifestToProviderConfig": guard(lambda i, creds: C.manifest_to_provider_config(C.get_provider(i), creds)),
    "buildVaultProviders": guard(lambda c: C.build_vault_providers(c)), "exchange": token_run(C.exchange_code), "refresh": token_run(C.refresh),
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in CASES.values()) and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
