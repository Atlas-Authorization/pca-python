"""A2A 1.0 Agent Card helpers: RFC 8785 canonical bytes (``jcs_bytes``), the AgentCard schema check (``validate_agent_card1``),
signed cards (``issue_signed_agent_card`` / ``verify_agent_card``, JWS over the canonical card minus ``signatures``) and the
extended card derived from a residual policy (``extended_agent_card``). Cards are plain dicts; results are dicts shaped like the
TypeScript reference (``@atlasauth/pca-a2a``). EdDSA needs nothing extra; ES256 and RSA keys need ``cryptography``."""
import base64
from typing import Any, Callable, Dict, List, Optional

from .k3 import u16key
from .oidc import create_local_jwk_set
from .sdjwt_jws import (JoseError, assert_canonical_jws_segments, js_json_bytes, js_json_parse, js_num, jws_sign,
                        jws_verify, node_b64url_decode, public_key_from_jwk, truthy, _js_str)
from . import ed25519 as _ed

PCA_A2A_EXTENSION_URI = "https://atlasauth.net/a2a/ext/pca/v2"
PCA_PASSPORT_HEADER = "pca_passport"
_MAX_DEPTH = 64
_PREFIX = "pca-verb:"


class _Undefined:
    """JavaScript ``undefined`` where it must stay distinct from ``null`` (a dict member that is present but undefined)."""

    def __repr__(self) -> str:
        return "undefined"


UNDEFINED = _Undefined()


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def spread(v: Any) -> Dict[str, Any]:
    """The own enumerable members JavaScript object spread ``{...v}`` copies: a dict as is, a list or string by index."""
    if isinstance(v, dict):
        return dict(v)
    if isinstance(v, list):
        return {str(i): x for i, x in enumerate(v)}
    if isinstance(v, str):
        units = v.encode("utf-16-le", "surrogatepass")
        return {str(i): chr(int.from_bytes(units[2 * i:2 * i + 2], "little")) for i in range(len(units) // 2)}
    return {}


# ---- RFC 8785 --------------------------------------------------------------------------------------------------------

def _lone(s: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def _jcs(v: Any, depth: int) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf"))):
            raise TypeError("jcs: non-finite number")
        return js_num(v)
    if isinstance(v, str):
        if _lone(v):
            raise TypeError("jcs: lone surrogate in string")
        return _js_str(v)
    if not isinstance(v, (list, dict)):
        raise TypeError("jcs: unsupported type %s" % ("undefined" if v is UNDEFINED else type(v).__name__))
    if depth > _MAX_DEPTH:
        raise TypeError("jcs: nesting too deep")
    if isinstance(v, list):
        return "[" + ",".join(_jcs(x, depth + 1) for x in v) + "]"
    out = []
    for k in sorted(v, key=u16key):
        if _lone(k):
            raise TypeError("jcs: lone surrogate in key")
        out.append(_js_str(k) + ":" + _jcs(v[k], depth + 1))
    return "{" + ",".join(out) + "}"


def jcs_bytes(value: Any) -> bytes:
    """RFC 8785 canonical UTF-8 bytes of a JSON value. Raises TypeError for a value with no JSON form."""
    return _jcs(value, 1).encode("utf-8")


# ---- A2A 1.0 AgentCard message ---------------------------------------------------------------------------------------

def _str(v: Any) -> bool:
    return isinstance(v, str)


def validate_agent_card1(card: Any) -> List[str]:
    """The problems found in an object checked against the A2A 1.0 ``AgentCard`` message, each with a JSON path (empty = valid)."""
    p: List[str] = []
    if not isinstance(card, dict):
        return ["$: the agent card must be an object"]

    def req_str(o: dict, k: str, at: str) -> None:
        if not _str(o.get(k)) or o[k] == "":
            p.append("%s.%s: required non-empty string" % (at, k))

    def opt_str(o: dict, k: str, at: str) -> None:
        if k in o and not _str(o[k]):
            p.append("%s.%s: must be a string" % (at, k))

    def opt_bool(o: dict, k: str, at: str) -> None:
        if k in o and not isinstance(o[k], bool):
            p.append("%s.%s: must be a boolean" % (at, k))

    def str_array(v: Any, at: str, non_empty: bool) -> None:
        if not isinstance(v, list) or not all(_str(x) for x in v):
            p.append("%s: must be an array of strings" % at)
        elif non_empty and len(v) == 0:
            p.append("%s: must not be empty" % at)

    def obj_array(o: dict, k: str, at: str, required: bool, non_empty: bool, each: Callable[[dict, str], None]) -> None:
        if k not in o:
            if required:
                p.append("%s.%s: required array" % (at, k))
            return
        v = o[k]
        if not isinstance(v, list):
            p.append("%s.%s: must be an array" % (at, k))
            return
        if non_empty and len(v) == 0:
            p.append("%s.%s: must not be empty" % (at, k))
        for i, e in enumerate(v):
            if isinstance(e, dict):
                each(e, "%s.%s[%d]" % (at, k, i))
            else:
                p.append("%s.%s[%d]: must be an object" % (at, k, i))

    req_str(card, "name", "$")
    req_str(card, "description", "$")
    req_str(card, "version", "$")
    opt_str(card, "documentationUrl", "$")
    opt_str(card, "iconUrl", "$")

    def iface(e: dict, at: str) -> None:
        req_str(e, "url", at)
        req_str(e, "protocolBinding", at)
        req_str(e, "protocolVersion", at)
        opt_str(e, "tenant", at)

    obj_array(card, "supportedInterfaces", "$", True, True, iface)
    if "provider" in card:
        if not isinstance(card["provider"], dict):
            p.append("$.provider: must be an object")
        else:
            req_str(card["provider"], "url", "$.provider")
            req_str(card["provider"], "organization", "$.provider")
    if not isinstance(card.get("capabilities"), dict):
        p.append("$.capabilities: required object")
    else:
        c = card["capabilities"]
        opt_bool(c, "streaming", "$.capabilities")
        opt_bool(c, "pushNotifications", "$.capabilities")
        opt_bool(c, "extendedAgentCard", "$.capabilities")

        def ext(e: dict, at: str) -> None:
            opt_str(e, "uri", at)
            opt_str(e, "description", at)
            opt_bool(e, "required", at)
            if "params" in e and not isinstance(e["params"], dict):
                p.append("%s.params: must be an object" % at)

        obj_array(c, "extensions", "$.capabilities", False, False, ext)
    if "securitySchemes" in card and not isinstance(card["securitySchemes"], dict):
        p.append("$.securitySchemes: must be an object")
    if "securityRequirements" in card and not isinstance(card["securityRequirements"], list):
        p.append("$.securityRequirements: must be an array")
    for k in ("defaultInputModes", "defaultOutputModes"):
        if k not in card:
            p.append("$.%s: required array of strings" % k)
        else:
            str_array(card[k], "$." + k, True)

    def skill(e: dict, at: str) -> None:
        req_str(e, "id", at)
        req_str(e, "name", at)
        req_str(e, "description", at)
        if "tags" not in e:
            p.append("%s.tags: required array of strings" % at)
        else:
            str_array(e["tags"], at + ".tags", False)
        for k in ("examples", "inputModes", "outputModes"):
            if k in e:
                str_array(e[k], "%s.%s" % (at, k), False)
        if "securityRequirements" in e and not isinstance(e["securityRequirements"], list):
            p.append("%s.securityRequirements: must be an array" % at)

    obj_array(card, "skills", "$", True, False, skill)

    def sig(e: dict, at: str) -> None:
        req_str(e, "protected", at)
        req_str(e, "signature", at)
        if "header" in e and not isinstance(e["header"], dict):
            p.append("%s.header: must be an object" % at)

    obj_array(card, "signatures", "$", False, False, sig)
    return p


# ---- signed cards ----------------------------------------------------------------------------------------------------

def _is_jwk(k: Any) -> bool:
    return isinstance(k, dict) and "kty" in k


def _card_bytes(card: dict) -> bytes:
    return jcs_bytes({k: v for k, v in card.items() if k != "signatures"})  # RFC 8785, A2A 1.0 section 8.4


class JwkKeyError(JoseError):
    """A private JWK Node cannot import (its ERR_CRYPTO_INVALID_JWK)."""
    code = "ERR_CRYPTO_INVALID_JWK"


def _signing_key(key: Any, alg: str) -> Any:
    """importJWK for a signing key: Ed25519 JWKs pass through (jws_sign reads ``d``), EC JWKs become a cryptography key."""
    if not _is_jwk(key):
        return key
    if key.get("kty") == "EC" and isinstance(key.get("d"), str):
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
        except ImportError:
            raise JoseError("this algorithm needs the 'cryptography' package (pip install cryptography)") from None
        curve = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}.get(key.get("crv"))
        if curve is None:
            raise JoseError("unsupported EC curve")
        return ec.derive_private_key(int.from_bytes(node_b64url_decode(key["d"]), "big"), curve())
    if key.get("kty") == "OKP":
        if "d" in key:
            try:
                ok = isinstance(key["d"], str) and len(node_b64url_decode(key["d"])) == 32
            except Exception:  # noqa: BLE001
                ok = False
            if not ok:
                raise JwkKeyError("Invalid JWK OKP key")
        return key
    raise JoseError("Invalid key for this operation: unsupported private JWK")


def issue_signed_agent_card(card: dict, signing_key: Any, opts: Optional[dict] = None) -> dict:
    """The card with a signature appended: the passport reference is embedded (and put in the signed protected header) before
    signing. ``opts``: ``alg`` (default EdDSA), ``passport``, ``kid``, ``profile`` (``pca-detached`` default, or ``a2a-1.0``, which
    needs a ``kid``) and ``schema`` (``a2a-1.0``: refuse a card that does not match the schema). Raises on any refusal."""
    o = opts or {}
    if not isinstance(card, dict):
        raise TypeError("issue_signed_agent_card: the card must be an object")
    alg = o["alg"] if o.get("alg") is not None else "EdDSA"
    if truthy(o.get("passport")):
        pp = o["passport"]
        passport: Any = {"id": pp["id"] if isinstance(pp, dict) and "id" in pp else UNDEFINED}
        if isinstance(pp, dict) and pp.get("uri", UNDEFINED) is not UNDEFINED and "uri" in pp:
            passport["uri"] = pp["uri"]
    else:
        passport = card.get("pcaPassport")
    to_sign = dict(card)
    if truthy(passport):
        to_sign["pcaPassport"] = passport
    if o.get("schema") == "a2a-1.0":
        problems = validate_agent_card1(to_sign)
        if problems:
            raise ValueError("issue_signed_agent_card: the card does not match the A2A 1.0 schema: " + "; ".join(problems))
    payload = _card_bytes(to_sign)
    key = _signing_key(signing_key, alg)
    a2a10 = o.get("profile") == "a2a-1.0"
    if a2a10 and (not isinstance(o.get("kid"), str) or o["kid"] == ""):
        raise ValueError("issue_signed_agent_card: the 'a2a-1.0' profile requires a kid")
    header: Dict[str, Any] = {"alg": alg}
    if a2a10:
        header["typ"] = "JOSE"
    else:
        header["b64"] = False
        header["crit"] = ["b64"]
    if "kid" in o:
        header["kid"] = o["kid"]
    if truthy(passport):
        pid = passport.get("id", UNDEFINED) if isinstance(passport, dict) else UNDEFINED
        if pid is not UNDEFINED:
            header[PCA_PASSPORT_HEADER] = pid
    prot = _b64u(js_json_bytes(header))
    body = payload if not a2a10 else _b64u(payload).encode("ascii")
    sig = _b64u(jws_sign(alg, key, prot.encode("ascii") + b"." + body))
    existing = to_sign.get("signatures")
    if existing is None:
        prior: List[Any] = []
    elif isinstance(existing, list):
        prior = list(existing)
    elif isinstance(existing, str):
        prior = list(spread(existing).values())
    else:
        raise TypeError("existing is not iterable")
    out = dict(to_sign)
    out["signatures"] = prior + [{"protected": prot, "signature": sig}]
    return out


_BAD = object()  # a key that imports but cannot verify (symmetric, or a curve this verifier does not support)


def _import_verify_key(key: Any, alg: str) -> Any:
    """importJWK for a verification key. Raises JoseError where the import itself fails; a private JWK yields its public key."""
    if not _is_jwk(key):
        return key
    kty = key.get("kty")
    if kty == "oct":
        if not isinstance(key.get("k"), str) or not key["k"]:
            raise JoseError("missing k")
        return _BAD
    if kty == "OKP":
        if key.get("crv") != "Ed25519":
            return _BAD
        if truthy(key.get("d")):
            seed = node_b64url_decode(key["d"]) if isinstance(key["d"], str) else b""
            if len(seed) != 32:
                raise JoseError("invalid Ed25519 private key")
            return _ed.public_key(seed)
        return public_key_from_jwk(key, alg)
    if kty in ("EC", "RSA"):
        if truthy(key.get("d")):
            if kty == "EC":
                pub = _signing_key(key, alg).public_key()
                return pub
            return _BAD
        return public_key_from_jwk(key, alg)
    raise JoseError('Unsupported "kty" (Key Type) Parameter value')


def _flattened_verify(prot: str, payload: Any, signature: str, key: Any, resolver: bool) -> dict:
    """jose flattenedVerify for a card signature; ``payload`` is bytes (detached raw) or the base64url text. Raises on refusal."""
    parsed = js_json_parse(node_b64url_decode(prot).decode("utf-8", "replace")) if prot else {}
    if not isinstance(parsed, dict):
        raise JoseError("JWS Protected Header is invalid")
    b64 = True
    if "crit" in parsed:
        crit = parsed["crit"]
        if not isinstance(crit, list) or not crit or any(not isinstance(c, str) or c == "" for c in crit):
            raise JoseError('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present')
        for c in crit:
            if c != "b64":
                raise JoseError('Extension Header Parameter "%s" is not recognized' % c)
        b64 = parsed.get("b64")
        if not isinstance(b64, bool):
            raise JoseError('The "b64" (base64url-encode payload) Header Parameter must be a boolean')
    alg = parsed.get("alg")
    if not isinstance(alg, str) or not alg:
        raise JoseError('JWS "alg" (Algorithm) Header Parameter missing or invalid')
    if b64 and not isinstance(payload, str):
        raise JoseError("JWS Payload must be a string")
    if resolver:
        jwk = key(parsed, None)
        key = _import_verify_key(jwk, alg) if _is_jwk(jwk) else jwk
    if key is _BAD:
        raise JoseError("Invalid key for this operation")
    data = prot.encode("utf-8") + b"." + (payload.encode("utf-8") if isinstance(payload, str) else payload)
    if not jws_verify(alg, key, node_b64url_decode(signature), data):
        raise JoseError("signature verification failed")
    return parsed


def verify_agent_card(card: Any, opts: dict) -> Dict[str, Any]:
    """Validate a card against its signature(s). Fail closed: no signatures, an unresolvable key or ANY signature that does not
    verify over the canonical card (minus ``signatures``) refuses. ``opts``: ``jwks``, ``key`` (a JWK or key object), ``alg``
    (default EdDSA, used to import a JWK ``key``), ``schema`` (``a2a-1.0``). On success the result names the passport id the
    signature commits to (``passportRef``) and the one embedded in the card (``passport``)."""
    if card is None or not isinstance(card, (dict, list)):
        return {"ok": False, "reason": "agent card is not an object"}
    signatures = card.get("signatures") if isinstance(card, dict) else None
    if not isinstance(signatures, list) or len(signatures) == 0:
        return {"ok": False, "reason": "agent card carries no signatures"}
    if opts.get("schema") == "a2a-1.0":
        problems = validate_agent_card1(card)
        if problems:
            return {"ok": False, "reason": "agent card does not match the A2A 1.0 schema: " + "; ".join(problems)}
    resolver = False
    try:
        if truthy(opts.get("jwks")):
            key: Any = create_local_jwk_set(opts["jwks"])
            resolver = True
        elif "key" in opts:
            k = opts["key"]
            key = _import_verify_key(k, opts["alg"] if opts.get("alg") is not None else "EdDSA") if _is_jwk(k) else k
        else:
            return {"ok": False, "reason": "no verification key or JWKS supplied"}
    except Exception as e:  # noqa: BLE001 - an unusable key is a refusal, with the library's own words
        return {"ok": False, "reason": "could not resolve verification key: %s" % e}
    try:
        payload = _card_bytes(card)
    except TypeError as e:
        return {"ok": False, "reason": "agent card has no canonical form: %s" % e}
    passport_ref: Optional[str] = None
    for i, sig in enumerate(signatures):
        if not isinstance(sig, dict) or not isinstance(sig.get("protected"), str) or not isinstance(sig.get("signature"), str):
            return {"ok": False, "reason": "signature %d is malformed" % i}
        try:
            assert_canonical_jws_segments(sig["protected"], sig["signature"])  # canonical-spelling gate BEFORE the signature check
            header = _payload_header(sig["protected"])
            body: Any = payload if header.get("b64") is False else _b64u(payload)
            verified = _flattened_verify(sig["protected"], body, sig["signature"], key, resolver)
        except Exception as e:  # noqa: BLE001 - every refusal reads the same
            return {"ok": False, "reason": "signature %d did not verify: %s" % (i, e)}
        ref = verified.get(PCA_PASSPORT_HEADER)
        if isinstance(ref, str) and passport_ref is None:
            passport_ref = ref
    out: Dict[str, Any] = {"ok": True}
    if passport_ref is not None:
        out["passportRef"] = passport_ref
    if isinstance(card, dict) and truthy(card.get("pcaPassport")):
        out["passport"] = card["pcaPassport"]
    return out


def _payload_header(prot: str) -> dict:
    try:
        h = js_json_parse(node_b64url_decode(prot).decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - an unparsable header is refused by the verify step
        return {}
    return h if isinstance(h, dict) else {}


# ---- extended card ---------------------------------------------------------------------------------------------------

def _key(v: Any) -> Any:
    """SameValueZero identity of a JSON value (for sets and maps keyed by it)."""
    if v is UNDEFINED:
        return ("u",)
    if v is None:
        return ("z",)
    if isinstance(v, bool):
        return ("b", v)
    if isinstance(v, (int, float)):
        return ("n", float(v))
    if isinstance(v, str):
        return ("s", v)
    return ("o", id(v))


def _member(o: Any, k: str) -> Any:
    """``o.k`` in JavaScript: undefined for a missing member or a non-object, a TypeError for null."""
    if o is None or o is UNDEFINED:
        raise TypeError("Cannot read properties of %s (reading '%s')" % ("null" if o is None else "undefined", k))
    return o.get(k, UNDEFINED) if isinstance(o, dict) else UNDEFINED


def _default_verb_of(s: Any) -> Any:
    tags = _member(s, "tags")
    if tags is None or tags is UNDEFINED:
        tags = []
    if not isinstance(tags, list):
        raise TypeError("tags.find is not a function")
    for t in tags:
        if isinstance(t, str) and t.startswith(_PREFIX):
            return t[len(_PREFIX):]
    return UNDEFINED


def extended_agent_card(public_card: Any, o: dict) -> dict:
    """The card a caller may see after authenticating: hidden skills are revealed only when their verb's envelope is
    ``autonomous`` or ``needs-approval`` (no envelope or ``denied`` reveals nothing), all envelopes must come from one policy (its
    digest is recorded in the PCA extension params). ``o``: ``authenticated``, ``hiddenSkills``, ``envelopes``, optional ``verbOf``.
    The result is unsigned; discovery only, attempting a skill still needs its PCActn."""
    if o.get("authenticated") is not True:
        raise ValueError("extendedAgentCard: the caller must be authenticated (A2A 13.3)")
    envs = o["envelopes"]
    digests: Dict[Any, Any] = {}
    for e in envs:
        digests.setdefault(_key(_member(e, "policyDigest")), _member(e, "policyDigest"))
    if len(digests) > 1:
        raise ValueError("extendedAgentCard: envelopes were computed against different policies")
    by_verb: Dict[Any, Any] = {}
    for e in envs:
        by_verb[_key(_member(e, "verb"))] = e
    verb_of = o.get("verbOf") or _default_verb_of
    revealed: List[dict] = []
    for s in o["hiddenSkills"]:
        verb = verb_of(s)
        env = UNDEFINED if verb is UNDEFINED or verb is None else by_verb.get(_key(verb), UNDEFINED)
        if env is UNDEFINED or _member(env, "status") == "denied":
            continue
        tags = _member(s, "tags")
        sk = spread(s)
        sk["tags"] = (list(tags) if isinstance(tags, list) else []) + ["pca:autonomous" if _member(env, "status") == "autonomous" else "pca:needs-approval"]
        revealed.append(sk)
    if public_card is None:
        raise TypeError("Cannot destructure 'publicCard' as it is null.")
    rest = {k: v for k, v in spread(public_card).items() if k != "signatures"}
    caps_raw = rest.get("capabilities")
    caps = spread(caps_raw if caps_raw is not None else {})
    exts_raw = _member(caps_raw, "extensions") if caps_raw is not None else UNDEFINED
    exts = exts_raw if isinstance(exts_raw, list) else []
    policy_digest = next(iter(digests.values())) if digests else UNDEFINED
    if policy_digest is UNDEFINED:
        next_exts = exts
    else:
        next_exts = []
        for e in exts:
            if _member(e, "uri") == PCA_A2A_EXTENSION_URI:
                ne = spread(e)
                params = spread(_member(e, "params"))
                params["policy_digest"] = policy_digest
                ne["params"] = params
                next_exts.append(ne)
            else:
                next_exts.append(e)
    skills = rest.get("skills") if isinstance(rest.get("skills"), list) else []
    caps["extensions"] = next_exts
    out = dict(rest)
    out["capabilities"] = caps
    out["skills"] = list(skills) + revealed
    return out
