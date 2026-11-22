"""ID-JAG / OAuth Cross-App-Access bridge for Proof-Carrying Authority, a native port of the TypeScript reference
(@atlasauth/pca-idjag).

An ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant) is a JWT the enterprise IdP mints so one app may act, for a named
user, against ANOTHER app: ``sub`` is the human, ``act.sub`` the agent, ``aud`` the single resource app, ``scope`` the authority.
``verify_id_jag`` checks one (reusing ``atlas_pca.oidc.verify_id_token``), ``id_jag_to_capability`` projects it onto a signed
root capability, and ``token_exchange_request`` / ``jwt_bearer_assertion`` build the two XAA request shapes.

Options are dicts with snake_case keys; the ``consume_jti`` single-use store is a plain callable returning True for a fresh jti.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from . import oidc as _oidc
from .agent import KeyPair, mint_root
from .attest_common import decode_canonical_b64url
from .pca import strict_parse

__all__ = [
    "IdJagVerificationError", "MAX_ID_JAG_CHARS", "verify_id_jag", "id_jag_to_pca_principal", "IDJAG_AUTHORITY_CAVEAT",
    "IDJAG_PROVENANCE_CAVEAT", "id_jag_to_capability", "is_id_jag_authority_caveat", "is_id_jag_provenance_caveat",
    "read_id_jag_authority", "read_id_jag_provenance", "GRANT_TYPE_TOKEN_EXCHANGE", "GRANT_TYPE_JWT_BEARER", "TOKEN_TYPE_ID_JAG",
    "TOKEN_TYPE_ID_TOKEN", "TOKEN_TYPE_ACCESS_TOKEN", "TOKEN_TYPE_JWT", "CLIENT_ASSERTION_TYPE_JWT_BEARER",
    "token_exchange_request", "jwt_bearer_assertion",
]

MAX_ID_JAG_CHARS = 16384
IDJAG_AUTHORITY_CAVEAT = "idjag_authority"
IDJAG_PROVENANCE_CAVEAT = "idjag_provenance"
GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
TOKEN_TYPE_ID_JAG = "urn:ietf:params:oauth:token-type:id-jag"
TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"
CLIENT_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# JavaScript's \s (not Python's, which differs at U+001C-U+001F, U+0085 and U+FEFF)
_JS_WS = re.compile("[\t\n\v\f\r    -     　﻿]+")


class IdJagVerificationError(Exception):
    """Any ID-JAG verification failure; ``code`` is an OIDC code (config, invalid_token, signature, issuer, audience, expired,
    issued_at, not_before, nonce, azp, keys, claims, ...) or one of actor, scope, grant."""

    def __init__(self, code: str, message: str, cause: Optional[BaseException] = None) -> None:
        super().__init__(message)
        self.code = code
        self.__cause__ = cause


def _as_actor(v: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(v, dict):
        return None
    sub = v.get("sub")
    if not isinstance(sub, str) or sub == "":
        return None
    return dict(v)


def _clean_strings(xs: Any) -> List[str]:
    return [s for s in xs if isinstance(s, str) and len(s) > 0]


def _parse_scopes(scope: Any, scopes: Any) -> Optional[List[str]]:
    if isinstance(scope, str):
        return [s for s in _JS_WS.split(scope) if len(s) > 0]
    if isinstance(scope, list):
        return _clean_strings(scope)
    if isinstance(scopes, list):
        return _clean_strings(scopes)
    return None


def verify_id_jag(jwt: str, opts: Dict[str, Any]) -> Dict[str, Any]:
    """Verify an ID-JAG and return the grant (``iss, sub, actor, agent, audience, scopes, iat, exp, jti?, nonce?, cnf?,
    oidc_claims``). Fails closed with IdJagVerificationError. Strict draft mode (default) also needs ``client_id`` and
    ``consume_jti``; pass ``strict_draft=False`` to opt out. opts: issuer, audience, nonce, required_scopes,
    clock_tolerance_sec, max_token_age_sec, algorithms, key | jwks_uri | discover (+ fetch), strict_draft, client_id,
    consume_jti, now (epoch seconds)."""
    if not isinstance(jwt, str) or len(jwt) == 0:
        raise IdJagVerificationError("invalid_token", "verifyIdJag: jwt must be a non-empty string")
    if len(jwt) > MAX_ID_JAG_CHARS:
        raise IdJagVerificationError("invalid_token", "verifyIdJag: jwt exceeds the size limit")
    if not isinstance(opts, dict):
        raise IdJagVerificationError("config", "verifyIdJag: opts is required")
    if not isinstance(opts.get("issuer"), str) or opts["issuer"] == "":
        raise IdJagVerificationError("config", "verifyIdJag: opts.issuer is required")
    audience = opts.get("audience")
    if not isinstance(audience, str) or audience == "":
        raise IdJagVerificationError("config", "verifyIdJag: opts.audience is required (ID-JAG is single-audience)")

    strict = opts.get("strict_draft") is not False
    if strict and not callable(opts.get("consume_jti")):
        raise IdJagVerificationError("config", "verifyIdJag: strictDraft requires opts.consume_jti (single-use store)")
    if strict and (not isinstance(opts.get("client_id"), str) or opts["client_id"] == ""):
        raise IdJagVerificationError(
            "config", "verifyIdJag: strictDraft requires opts.client_id (the client authenticated at the token endpoint)")

    # every crypto + registered-claim check is the OIDC verifier's; its code is kept so callers see one error family
    base_opts = {k: opts[k] for k in ("nonce", "clock_tolerance_sec", "max_token_age_sec", "algorithms", "key", "jwks_uri",
                                      "discover", "fetch", "now") if opts.get(k) is not None}
    base_opts["issuer"], base_opts["audience"] = opts["issuer"], audience
    try:
        base = _oidc.verify_id_token(jwt, base_opts)
    except _oidc.OidcVerificationError as e:
        raise IdJagVerificationError(e.code, str(e), e) from e
    except ImportError:
        raise
    except Exception as e:  # noqa: BLE001 - e.g. a failed discovery: one error family
        raise IdJagVerificationError("invalid_token", "ID-JAG verification failed", e) from e

    aud = base["aud"]
    aud_list = aud if isinstance(aud, list) else [aud]
    if len(aud_list) != 1 or aud_list[0] != audience:
        raise IdJagVerificationError(
            "audience", "ID-JAG must carry exactly one audience equal to the resource app (single-audience grant)")

    # the signature is verified, so the payload is authentic: read the claims the OIDC projection does not surface
    try:
        segs = jwt.split(".")
        header = strict_parse(decode_canonical_b64url(segs[0]).decode("utf-8"))
        raw = strict_parse(decode_canonical_b64url(segs[1]).decode("utf-8"))
        if not isinstance(raw, dict) or not isinstance(header, dict):
            raise ValueError("not an object")
    except Exception as e:  # noqa: BLE001
        raise IdJagVerificationError("invalid_token", "ID-JAG payload could not be decoded", e) from e

    actor = _as_actor(raw.get("act"))
    if actor is None:
        raise IdJagVerificationError("actor", 'ID-JAG is missing a well-formed "act" (agent) claim with a string "sub"')
    scopes = _parse_scopes(raw.get("scope"), raw.get("scopes"))
    if scopes is None:
        raise IdJagVerificationError("scope", 'ID-JAG is missing the "scope" (or "scopes") claim')
    if isinstance(opts.get("required_scopes"), list):
        for req in opts["required_scopes"]:
            if req not in scopes:
                raise IdJagVerificationError("scope", 'ID-JAG does not grant the required scope "%s"' % req)

    jti = raw["jti"] if isinstance(raw.get("jti"), str) and raw["jti"] != "" else None

    if strict:
        def fail(m: str) -> None:
            raise IdJagVerificationError("grant", m)

        if header.get("typ") != "oauth-id-jag+jwt":
            fail('ID-JAG header typ must be "oauth-id-jag+jwt"')
        if not isinstance(raw.get("client_id"), str) or raw["client_id"] == "":
            fail('ID-JAG is missing "client_id"')
        if raw["client_id"] != opts["client_id"]:
            fail("ID-JAG client_id does not match the expected client")
        if jti is None:
            fail('ID-JAG is missing "jti"')
        try:
            fresh = opts["consume_jti"](jti, base["exp"]) is True
        except Exception:  # noqa: BLE001 - a failing store is never a pass
            fresh = False
        if not fresh:
            fail("ID-JAG jti was already used or the single-use store failed")

    grant: Dict[str, Any] = {"iss": base["iss"], "sub": base["sub"], "actor": actor, "agent": actor["sub"], "audience": audience,
                             "scopes": scopes, "iat": base["iat"], "exp": base["exp"]}
    if jti is not None:
        grant["jti"] = jti
    if "nonce" in base:
        grant["nonce"] = base["nonce"]
    if "cnf" in base:
        grant["cnf"] = base["cnf"]
    grant["oidc_claims"] = base
    return grant


def id_jag_to_pca_principal(grant: Dict[str, Any], opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The PCA principal of a verified grant (``atlas_pca.oidc.oidc_principal`` over its ``oidc_claims``)."""
    if not isinstance(grant, dict):
        raise TypeError("idJagToPcaPrincipal: grant is required")
    return _oidc.oidc_principal(grant.get("oidc_claims"), opts or {})


def id_jag_to_capability(grant: Dict[str, Any], opts: Dict[str, Any]) -> Dict[str, Any]:
    """Project a verified grant onto a signed ROOT capability (authority = scopes, holder = the agent key, subject = the human,
    plus a provenance caveat). Returns ``{"capability", "principal", "scopes"}``. opts: ``principal_secret`` (32-byte Ed25519
    seed or a KeyPair), ``principal_public`` (b64u; must equal the key's public key and any cnf-bound key), ``holder`` (b64u),
    optional ``alg`` / ``pq`` (the root hop's suite, as ``mint_root``), ``extra_caveats``, ``allow_insecure_signer``."""
    if not isinstance(grant, dict):
        raise TypeError("idJagToCapability: grant is required")
    if not isinstance(opts, dict):
        raise TypeError("idJagToCapability: opts is required")
    secret = opts.get("principal_secret")
    if not isinstance(secret, (bytes, bytearray, KeyPair)):
        raise TypeError("idJagToCapability: opts.principalSecret must be bytes")
    if not isinstance(opts.get("principal_public"), str) or opts["principal_public"] == "":
        raise TypeError("idJagToCapability: opts.principalPublic is required")
    if not isinstance(opts.get("holder"), str) or opts["holder"] == "":
        raise TypeError("idJagToCapability: opts.holder (the agent key) is required")

    principal = id_jag_to_pca_principal(grant, {"principal_public": opts["principal_public"]})
    scopes = list(grant["scopes"])
    authority = {"type": IDJAG_AUTHORITY_CAVEAT, "scopes": list(scopes), "aud": grant["audience"]}
    provenance: Dict[str, Any] = {"type": IDJAG_PROVENANCE_CAVEAT, "iss": grant["iss"], "sub": grant["sub"], "agent": grant["agent"],
                                  "aud": grant["audience"], "iat": grant["iat"], "exp": grant["exp"]}
    if grant.get("jti") is not None:
        provenance["jti"] = grant["jti"]
    extra = opts.get("extra_caveats")
    caveats = [authority, provenance, principal["subject_caveat"]] + (list(extra) if extra is not None else [])

    kp = secret if isinstance(secret, KeyPair) else KeyPair(bytes(secret), bool(opts.get("allow_insecure_signer")))
    if kp.public != opts["principal_public"]:
        raise ValueError("idJagToCapability: opts.principalSecret does not belong to opts.principalPublic")
    capability = mint_root(kp, opts["holder"], caveats, alg=opts.get("alg"), pq=opts.get("pq"))
    return {"capability": capability, "principal": principal, "scopes": list(scopes)}


def is_id_jag_authority_caveat(cv: Any) -> bool:
    return (isinstance(cv, dict) and cv.get("type") == IDJAG_AUTHORITY_CAVEAT and isinstance(cv.get("scopes"), list)
            and all(isinstance(s, str) for s in cv["scopes"]) and isinstance(cv.get("aud"), str) and cv["aud"] != "")


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def is_id_jag_provenance_caveat(cv: Any) -> bool:
    return (isinstance(cv, dict) and cv.get("type") == IDJAG_PROVENANCE_CAVEAT
            and all(isinstance(cv.get(k), str) for k in ("iss", "sub", "agent", "aud"))
            and _is_num(cv.get("iat")) and _is_num(cv.get("exp")))


def _find_caveat(cap: Any, typ: str) -> Any:
    if not isinstance(cap, dict) or cap.get("caveats") is None:
        return None
    cavs = cap["caveats"]
    if not isinstance(cavs, list):
        raise TypeError("caveats.find is not a function")
    for c in cavs:
        if isinstance(c, dict) and c.get("type") == typ:
            return c
    return None


def read_id_jag_authority(cap: Any) -> Optional[Dict[str, Any]]:
    """The authority caveat of a root capability, or None when absent or malformed."""
    cv = _find_caveat(cap, IDJAG_AUTHORITY_CAVEAT)
    return cv if cv is not None and is_id_jag_authority_caveat(cv) else None


def read_id_jag_provenance(cap: Any) -> Optional[Dict[str, Any]]:
    """The provenance caveat of a root capability, or None when absent or malformed."""
    cv = _find_caveat(cap, IDJAG_PROVENANCE_CAVEAT)
    return cv if cv is not None and is_id_jag_provenance_caveat(cv) else None


# ------------------------------------------------------------------------------------------------ XAA request shapes


def _usv(s: str) -> str:
    return "".join("�" if 0xD800 <= ord(c) <= 0xDFFF else c for c in s)


def _form_encode(s: str) -> str:
    """application/x-www-form-urlencoded byte serializer (URLSearchParams): alphanumerics and ``*-._`` stay, space is ``+``."""
    out = []
    for b in _usv(s).encode("utf-8"):
        if (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122) or b in b"*-._":
            out.append(chr(b))
        elif b == 32:
            out.append("+")
        else:
            out.append("%%%02X" % b)
    return "".join(out)


def _js_key_order(keys: List[str]) -> List[str]:
    """Object property order: canonical array-index keys ascending first, then the rest in insertion order."""
    idx = [k for k in keys if re.fullmatch(r"0|[1-9][0-9]{0,9}", k) and int(k) < 4294967295]
    return sorted(idx, key=int) + [k for k in keys if k not in set(idx)]


def _form_request(url: str, params: Dict[str, Any]) -> Dict[str, Any]:
    clean = {k: v for k, v in params.items() if isinstance(v, str) and len(v) > 0}
    order = _js_key_order(list(clean))
    clean = {k: clean[k] for k in order}
    return {"url": url, "method": "POST",
            "headers": {"content-type": "application/x-www-form-urlencoded", "accept": "application/json"},
            "params": clean, "body": "&".join("%s=%s" % (_form_encode(k), _form_encode(v)) for k, v in clean.items())}


def _scope_param(scope: Any) -> Optional[str]:
    if scope is None:
        return None
    if isinstance(scope, list):
        parts = scope
    elif isinstance(scope, str):
        parts = _JS_WS.split(scope)
    else:
        raise TypeError("scope.split is not a function")
    parts = [s for s in parts if isinstance(s, str) and len(s) > 0]
    return " ".join(parts) if parts else None


def _spread(extra: Any) -> Dict[str, Any]:
    """`...extra` of a JS object spread: an object's members, an array's / string's indexed elements, nothing for the rest."""
    if isinstance(extra, dict):
        return dict(extra)
    if isinstance(extra, (list, str)):
        return {str(i): v for i, v in enumerate(extra)}
    return {}


def token_exchange_request(opts: Dict[str, Any]) -> Dict[str, Any]:
    """The RFC 8693 token-exchange POST that OBTAINS an ID-JAG from the IdP. opts: token_endpoint, subject_token (required);
    subject_token_type, actor_token, actor_token_type, audience, resource, scope (str | list), requested_token_type,
    client_id, extra. Returns ``{url, method, headers, params, body}``."""
    if not isinstance(opts, dict):
        raise TypeError("tokenExchangeRequest: opts is required")
    if not isinstance(opts.get("token_endpoint"), str) or opts["token_endpoint"] == "":
        raise TypeError("tokenExchangeRequest: opts.tokenEndpoint is required")
    if not isinstance(opts.get("subject_token"), str) or opts["subject_token"] == "":
        raise TypeError("tokenExchangeRequest: opts.subjectToken is required")
    actor = opts.get("actor_token")
    has_actor = isinstance(actor, str) and len(actor) > 0

    def dflt(k: str, d: str) -> Any:
        return d if opts.get(k) is None else opts[k]

    params: Dict[str, Any] = {
        "grant_type": GRANT_TYPE_TOKEN_EXCHANGE, "subject_token": opts["subject_token"],
        "subject_token_type": dflt("subject_token_type", TOKEN_TYPE_ID_TOKEN),
        "requested_token_type": dflt("requested_token_type", TOKEN_TYPE_ID_JAG),
    }
    if opts.get("audience") is not None:
        params["audience"] = opts["audience"]
    if opts.get("resource") is not None:
        params["resource"] = opts["resource"]
    scope = _scope_param(opts.get("scope"))
    if scope is not None:
        params["scope"] = scope
    if has_actor:
        params["actor_token"] = actor
        params["actor_token_type"] = dflt("actor_token_type", TOKEN_TYPE_JWT)
    if opts.get("client_id") is not None:
        params["client_id"] = opts["client_id"]
    params.update(_spread(opts.get("extra")))
    return _form_request(opts["token_endpoint"], params)


def jwt_bearer_assertion(opts: Dict[str, Any]) -> Dict[str, Any]:
    """The RFC 7523 jwt-bearer form of an ID-JAG being REDEEMED at the target app. opts: token_endpoint, assertion (required);
    scope, client_id, client_assertion, extra. Returns ``{grant_type, assertion, scope?, request}``."""
    if not isinstance(opts, dict):
        raise TypeError("jwtBearerAssertion: opts is required")
    if not isinstance(opts.get("token_endpoint"), str) or opts["token_endpoint"] == "":
        raise TypeError("jwtBearerAssertion: opts.tokenEndpoint is required")
    if not isinstance(opts.get("assertion"), str) or opts["assertion"] == "":
        raise TypeError("jwtBearerAssertion: opts.assertion is required")
    scope = _scope_param(opts.get("scope"))
    ca = opts.get("client_assertion")
    params: Dict[str, Any] = {"grant_type": GRANT_TYPE_JWT_BEARER, "assertion": opts["assertion"]}
    if scope is not None:
        params["scope"] = scope
    if opts.get("client_id") is not None:
        params["client_id"] = opts["client_id"]
    if isinstance(ca, str) and len(ca) > 0:
        params["client_assertion_type"] = CLIENT_ASSERTION_TYPE_JWT_BEARER
        params["client_assertion"] = ca
    params.update(_spread(opts.get("extra")))
    out: Dict[str, Any] = {"grant_type": GRANT_TYPE_JWT_BEARER, "assertion": opts["assertion"]}
    if scope is not None:
        out["scope"] = scope
    out["request"] = _form_request(opts["token_endpoint"], params)
    return out
