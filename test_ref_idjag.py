"""Differential replay of the ID-JAG bridge (atlas_pca.idjag) against vectors generated from the TypeScript reference
(@atlasauth/pca-idjag): verification, principal / capability projection, caveat guards and readers, XAA request shapes."""
import re

import pytest

from atlas_pca import idjag as J, oidc
from base_oracle import load_ref, run

COUNT, CASES = load_ref("idjag")


def _snake(o):
    """Top-level camelCase option names -> snake_case (member values keep their JSON names)."""
    if not isinstance(o, dict):
        return o
    return {re.sub(r"([A-Z])", lambda m: "_" + m.group(1).lower(), k): v for k, v in o.items()}


def _fetch(spec):
    state = {"i": 0}

    def fetch(url, headers, timeout_ms):
        r = spec["responses"][min(state["i"], len(spec["responses"]) - 1)]
        state["i"] += 1
        if r.get("throws"):
            raise RuntimeError("boom")
        return {"status": r["status"], "body": r.get("body", ""), "headers": r.get("headers") or {}}

    return fetch


def _consume(spec):
    def consume(jti, exp):
        if spec["mode"] == "throw":
            raise RuntimeError("store down")
        return True if spec["mode"] == "fresh" else 1 if spec["mode"] == "truthy" else False

    return consume


def _adapt(opts):
    a = _snake(opts)
    if not isinstance(a, dict):
        return a
    if isinstance(a.get("consume_jti"), dict) and "mode" in a["consume_jti"]:
        a["consume_jti"] = _consume(a["consume_jti"])
    if isinstance(a.get("key"), dict) and "jwks" in a["key"]:
        a["key"] = oidc.create_local_jwk_set(a["key"]["jwks"])
    if isinstance(a.get("fetch"), dict):
        a["fetch"] = _fetch(a["fetch"])
    return a


_P_OUT = {"principal_id": "principalId", "subject_caveat": "subjectCaveat", "principal_public": "principalPublic",
          "email_verified": "emailVerified", "preferred_username": "preferredUsername", "auth_time": "authTime"}


def _rename(d, names):
    return {names.get(k, k): v for k, v in d.items()}


def _grant_in(g):
    return _rename(g, {"oidcClaims": "oidc_claims"}) if isinstance(g, dict) else g


def _grant_out(g):
    return _rename(g, {"oidc_claims": "oidcClaims"})


def _principal_out(p):
    return _rename(p, _P_OUT)


def _verify(jwt, opts):
    return _grant_out(J.verify_id_jag(jwt, _adapt(opts)))


def _principal(g, *opts):
    return _principal_out(J.id_jag_to_pca_principal(_grant_in(g), _snake(opts[0]) if opts else None))


def _capability(g, opts):
    r = J.id_jag_to_capability(_grant_in(g), _snake(opts))
    return {"capability": r["capability"], "principal": _principal_out(r["principal"]), "scopes": r["scopes"]}


def _bearer(opts):
    return _rename(J.jwt_bearer_assertion(_snake(opts)), {"grant_type": "grantType"})


def _constants():
    return {n: getattr(J, n) for n in ("MAX_ID_JAG_CHARS", "IDJAG_AUTHORITY_CAVEAT", "IDJAG_PROVENANCE_CAVEAT",
                                       "GRANT_TYPE_TOKEN_EXCHANGE", "GRANT_TYPE_JWT_BEARER", "TOKEN_TYPE_ID_JAG",
                                       "TOKEN_TYPE_ID_TOKEN", "TOKEN_TYPE_ACCESS_TOKEN", "TOKEN_TYPE_JWT",
                                       "CLIENT_ASSERTION_TYPE_JWT_BEARER")}


MAP = {
    "verifyIdJag": _verify,
    "idJagToPcaPrincipal": _principal,
    "idJagToCapability": _capability,
    "isIdJagAuthorityCaveat": J.is_id_jag_authority_caveat,
    "isIdJagProvenanceCaveat": J.is_id_jag_provenance_caveat,
    "readIdJagAuthority": J.read_id_jag_authority,
    "readIdJagProvenance": J.read_id_jag_provenance,
    "tokenExchangeRequest": lambda o: J.token_exchange_request(_snake(o)),
    "jwtBearerAssertion": _bearer,
    "constants": _constants,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in CASES.values()) and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    ran, skipped = run(CASES[fn], MAP[fn])
    assert ran > 0 and skipped == 0
