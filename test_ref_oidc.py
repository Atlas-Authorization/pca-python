"""Differential replay of the OIDC bridge (atlas_pca.oidc) against vectors generated from the TypeScript reference
(@atlasauth/pca-oidc): discovery, ID-token verification across algorithms, the caching JWKS resolver, principal mapping."""
import importlib.util
import json
import re

import pytest

from atlas_pca import oidc
from base_oracle import load_ref, run

COUNT, CASES = load_ref("oidc")


def _snake(o):
    """Top-level camelCase option names -> snake_case (member values keep their JSON names)."""
    if not isinstance(o, dict):
        return o
    return {re.sub(r"([A-Z])", lambda m: "_" + m.group(1).lower(), k): v for k, v in o.items()}


def _fetch(spec, urls=None):
    state = {"i": 0}

    def fetch(url, headers, timeout_ms):
        if urls is not None:
            urls.append(url)
        r = spec["responses"][min(state["i"], len(spec["responses"]) - 1)]
        state["i"] += 1
        if r.get("throws"):
            raise RuntimeError("boom")
        return {"status": r["status"], "body": r.get("body", ""), "headers": r.get("headers") or {}}

    return fetch


def _adapt(opts):
    a = _snake(opts)
    if not isinstance(a, dict):
        return a
    k = a.get("key")
    if isinstance(k, dict) and "jwks" in k:
        a["key"] = oidc.create_local_jwk_set(k["jwks"])
    elif isinstance(k, dict) and "resolver" in k:
        r = _snake(k["resolver"])
        a["key"] = oidc.create_oidc_jwks(dict(r, fetch=_fetch(r["fetch"])))
    if isinstance(a.get("fetch"), dict):
        a["fetch"] = _fetch(a["fetch"])
    return a


def _adapt_discover(opts):
    a = _snake(opts)
    if isinstance(a, dict) and isinstance(a.get("fetch"), dict):
        a["fetch"] = _fetch(a["fetch"])
    return a


def _pick(jwk):
    return {k: jwk[k] for k in ("kty", "crv", "x", "y", "n", "e") if k in jwk}


def _err(e):
    return {"err": "keys" if isinstance(e, oidc.OidcVerificationError) and e.code == "keys" else "other"}


def _discover_calls(issuer, opts):
    urls = []
    try:
        oidc.discover_oidc(issuer, dict(_snake(opts), fetch=_fetch(opts["fetch"], urls)))
        outcome = "ok"
    except Exception:  # noqa: BLE001
        outcome = "error"
    return {"urls": urls, "outcome": outcome}


def _jwks_sequence(s):
    clock = {"t": 0}
    fetches = [0]
    inner = _fetch(s["fetch"])

    def fetch(url, headers, timeout_ms):
        fetches[0] += 1
        return inner(url, headers, timeout_ms)

    r = oidc.create_oidc_jwks(dict(_snake(s.get("opts") or {}), jwks_uri=s.get("jwksUri"), fetch=fetch, now=lambda: clock["t"]))
    steps = []
    for st in s["steps"]:
        clock["t"] = st["atMs"]
        try:
            steps.append({"ok": _pick(r(st["header"], None))})
        except Exception as e:  # noqa: BLE001
            steps.append(_err(e))
    return {"steps": steps, "fetches": fetches[0]}


def _jwks_from_issuer(s):
    urls = []
    r = oidc.create_oidc_jwks_from_issuer(s["issuer"], dict(_snake(s.get("opts") or {}), fetch=_fetch(s["fetch"], urls)))
    try:
        out = {"ok": _pick(r(s["header"], None))}
    except Exception as e:  # noqa: BLE001
        out = _err(e)
    return {"out": out, "urls": urls}


_P_OUT = {"principal_id": "principalId", "subject_caveat": "subjectCaveat", "principal_public": "principalPublic",
          "email_verified": "emailVerified", "preferred_username": "preferredUsername", "auth_time": "authTime"}


def _principal(claims, *opts):
    if opts and opts[0] is None:
        # the reference reads a null options argument and throws; Python's None means "omitted"
        raise TypeError("opts is null")
    p = oidc.oidc_principal(claims, _snake(opts[0]) if opts else None)
    return {_P_OUT.get(k, k): v for k, v in p.items()}


def _constants():
    return {"DEFAULT_ID_TOKEN_ALGS": list(oidc.DEFAULT_ID_TOKEN_ALGS), "DEFAULT_MAX_DISCOVERY_BYTES": oidc.DEFAULT_MAX_DISCOVERY_BYTES,
            "DEFAULT_JWKS_TIMEOUT_MS": oidc.DEFAULT_JWKS_TIMEOUT_MS, "OIDC_SUBJECT_CAVEAT": oidc.OIDC_SUBJECT_CAVEAT}


MAP = {
    "verifyIdToken": lambda t, o: oidc.verify_id_token(t, _adapt(o)),
    "discoveryUrl": oidc.discovery_url,
    "discoverOidc": lambda i, o: oidc.discover_oidc(i, _adapt_discover(o)),
    "discoverOidcCalls": _discover_calls,
    "createOidcJwks": _jwks_sequence,
    "createOidcJwksFromIssuer": _jwks_from_issuer,
    "oidcPrincipal": _principal,
    "isOidcSubjectCaveat": oidc.is_oidc_subject_caveat,
    "constants": _constants,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in CASES.values()) and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    # RSA / EC keys and RS* / PS* / ES* signatures need `cryptography`; the dependency-free job skips just those cases
    no_crypto = importlib.util.find_spec("cryptography") is None
    skip = (lambda c: "needs cryptography" if re.search(r"RSA|\bEC\b|(?:RS|PS|ES)(?:256|384|512)", c["name"] + json.dumps(c["args"])) else None) \
        if no_crypto else None
    ran, skipped = run(CASES[fn], MAP[fn], skip=skip)
    assert ran > 0 and (no_crypto or skipped == 0)
