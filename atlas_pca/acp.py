"""Agentic Commerce Protocol (ACP) and x402 for PCA: delegated one-time payment tokens minted FROM a PCActn (the proof's spend cap,
merchant and category allowlists and human-present requirement gate issuance), their settlement-time verification, the x402 v1
challenge and the injectable settle flow, x402 v2 (requirements, headers, negotiation), its HTTP transport and Stripe Shared Payment
Granted Tokens. Total functions over dicts shaped like the TypeScript reference (``@atlasauth/pca-acp``); no network is performed:
the verifier, settler and single-use store are injected (a store is any object with ``claim(jti, expires_at_ms) -> bool``).

Where the reference awaits, these functions are synchronous. A settle step that returns ``None`` yields no receipt. A token or
proof refused at mint raises ``AcpAuthorityError``; x402 header and ``parse_stripe_spt`` problems raise ``TypeError``."""
from ._fin import fin
import base64
import math
import re
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import a2a_card as _card
from .a2a import iso_from_ms
from .a2a_card import UNDEFINED, spread
from .k3 import u16key, u16len
from .oauth import _parse_url
from .pca import hash_canonical, verify_pcactn_core
from .sdjwt_jws import (JoseError, assert_canonical_compact_jws, js_json, js_json_bytes, js_json_parse, js_num, js_to_string, jws_sign,
                        jws_verify, node_b64url_decode, truthy)
from .attest_common import JS_WS

ACP_DELEGATED_TOKEN_VERSION = 1
ACP_DELEGATED_TOKEN_TYPE = "acp-delegated-payment"
SPEND_CAP_CAVEAT = "max_amount"
MERCHANT_ALLOW_CAVEAT = "merchant_allow"
MERCHANT_CATEGORY_CAVEAT = "merchant_category"
HUMAN_PRESENT_CAVEAT = "human_present"
X402_VERSION_1 = 1
X402_VERSION_2 = 2
X402_SUPPORTED_VERSIONS = (2, 1)
X402_V2_PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"
X402_PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"
X402_PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE"
X402_HTTP_STATUS = {"payment_required": 402, "malformed": 400, "failed": 402, "internal_error": 500, "settled": 200}
STRIPE_SPT_OBJECT = "shared_payment.granted_token"
_MAX_SAFE = 9007199254740991


class AcpAuthorityError(Exception):
    """A delegated payment token cannot be minted because the request exceeds the proof's authority (or the input is malformed)."""


# ---- JavaScript value semantics ------------------------------------------------------------------------------------------

def _s(v: Any) -> str:
    """``String(v)`` for a JSON value or undefined."""
    return "undefined" if v is UNDEFINED else js_to_string(v)


def _get(o: Any, k: str) -> Any:
    """``o.k``: a TypeError for null / undefined, undefined for a missing member or a non-object."""
    if o is None or o is UNDEFINED:
        raise TypeError("Cannot read properties of %s (reading '%s')" % ("null" if o is None else "undefined", k))
    return o.get(k, UNDEFINED) if isinstance(o, dict) else UNDEFINED


def _is_obj(v: Any) -> bool:
    return isinstance(v, dict)


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _finite(v: Any) -> bool:
    return _is_num(v) and fin(v)


def _safe_int(v: Any) -> bool:
    """``Number.isSafeInteger`` (so -0 passes)."""
    if not _is_num(v):
        return False
    if isinstance(v, float):
        return v == v and abs(v) <= _MAX_SAFE and v == math.floor(v)
    return abs(v) <= _MAX_SAFE


def _neg_zero(v: Any) -> bool:
    return isinstance(v, float) and v == 0 and math.copysign(1.0, v) < 0


def _is_amount(v: Any) -> bool:
    """Integer minor units: floats, NaN, zero, negatives and unsafe integers are refused."""
    return _safe_int(v) and v > 0


def _is_int(v: Any) -> bool:
    return _safe_int(v) and not _neg_zero(v)


_NUM = re.compile(r"[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")


def _to_number(v: Any) -> float:
    """``Number(v)`` for a JSON value or undefined (NaN where the reference yields it)."""
    if v is UNDEFINED:
        return math.nan
    if v is None or v is False:
        return 0.0
    if v is True:
        return 1.0
    if _is_num(v):
        return float(v)
    if isinstance(v, (list, dict)):
        return _to_number(_s(v))
    s = str(v).strip(JS_WS)
    if s == "":
        return 0.0
    if s in ("Infinity", "+Infinity"):
        return math.inf
    if s == "-Infinity":
        return -math.inf
    if len(s) > 2 and s[0] == "0" and s[1] in "xXoObB":
        try:
            return float(int(s[2:], {"x": 16, "o": 8, "b": 2}[s[1].lower()]))
        except ValueError:
            return math.nan
    return float(s) if _NUM.fullmatch(s) else math.nan


def _gt(a: Any, b: Any) -> bool:
    """``a > b`` where ``a`` is a number and ``b`` may be any value (coerced by ToNumber, so NaN compares false)."""
    return float(a) > _to_number(b)


# ---- caveat vocabulary ---------------------------------------------------------------------------------------------------

def spend_cap_caveat(max_amount: Any, currency: Any = UNDEFINED) -> Dict[str, Any]:
    out: Dict[str, Any] = {"type": SPEND_CAP_CAVEAT, "max": max_amount}
    if currency is not UNDEFINED:
        out["currency"] = currency
    return out


def merchant_allow_caveat(merchants: Sequence[Any]) -> Dict[str, Any]:
    return {"type": MERCHANT_ALLOW_CAVEAT, "merchants": list(merchants)}


def merchant_category_caveat(categories: Sequence[Any]) -> Dict[str, Any]:
    return {"type": MERCHANT_CATEGORY_CAVEAT, "categories": list(categories)}


def human_present_caveat(required: bool = True) -> Dict[str, Any]:
    return {"type": HUMAN_PRESENT_CAVEAT, "required": required}


def _string_array(v: Any, label: str) -> list:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise AcpAuthorityError("malformed %s caveat: expected a string[] (fail closed)" % label)
    return v


def extract_payment_authority(caveats: Any) -> Dict[str, Any]:
    """Collapse a leaf capability's cumulative caveats into its effective payment authority: the tightest cap, intersected
    allowlists, a sticky human-present requirement. A malformed PAYMENT caveat raises (fail closed); other caveat types are ignored."""
    if caveats is None or caveats is UNDEFINED or not isinstance(caveats, (list, str)):
        raise TypeError("caveats is not iterable")
    max_amount: Any = UNDEFINED
    currency: Any = UNDEFINED
    merchants: Optional[list] = None
    categories: Optional[list] = None
    human = False
    for c in caveats:
        typ = _get(c, "type")
        if typ == SPEND_CAP_CAVEAT:
            mx = c.get("max", UNDEFINED)
            if not _is_num(mx) or not _safe_int(mx) or mx < 0 or _neg_zero(mx):
                raise AcpAuthorityError("malformed max_amount caveat: max must be an integer >= 0 in minor units (fail closed)")
            max_amount = mx if max_amount is UNDEFINED else min(max_amount, mx)
            cur = c.get("currency", UNDEFINED)
            if cur is not UNDEFINED:
                if not isinstance(cur, str) or len(cur) == 0:
                    raise AcpAuthorityError("malformed max_amount caveat: currency must be a non-empty string (fail closed)")
                if currency is not UNDEFINED and currency != cur:
                    raise AcpAuthorityError('conflicting spend-cap currencies "%s" vs "%s" (fail closed)' % (currency, cur))
                currency = cur
        elif typ == MERCHANT_ALLOW_CAVEAT:
            lst = _string_array(c.get("merchants", UNDEFINED), "merchant_allow")
            merchants = list(dict.fromkeys(lst)) if merchants is None else [m for m in merchants if m in lst]
        elif typ == MERCHANT_CATEGORY_CAVEAT:
            lst = _string_array(c.get("categories", UNDEFINED), "merchant_category")
            categories = list(dict.fromkeys(lst)) if categories is None else [m for m in categories if m in lst]
        elif typ == HUMAN_PRESENT_CAVEAT:
            req = c.get("required", UNDEFINED)
            if not isinstance(req, bool):
                raise AcpAuthorityError("malformed human_present caveat: required must be a boolean (fail closed)")
            human = human or req
    out: Dict[str, Any] = {}
    if max_amount is not UNDEFINED:
        out["maxAmount"] = max_amount
    if currency is not UNDEFINED:
        out["currency"] = currency
    out.update({"merchants": merchants, "categories": categories, "humanPresentRequired": human})
    return out


def check_payment_authority(authority: dict, request: dict) -> Dict[str, Any]:
    """Check a concrete purchase request against a payment authority. Pure and fail-closed: an over-cap amount, a forbidden
    currency, a merchant or category outside the allowlist or a missing human-present signal returns ``{"ok": False, ...}``."""
    amount, currency, merchant = _get(request, "amount"), _get(request, "currency"), _get(request, "merchant")
    if not _is_amount(amount):
        return {"ok": False, "reason": "amount must be a positive integer in minor units"}
    if not isinstance(currency, str) or len(currency) == 0:
        return {"ok": False, "reason": "currency must be a non-empty string"}
    if not isinstance(merchant, str) or len(merchant) == 0:
        return {"ok": False, "reason": "merchant must be a non-empty string"}
    a_cur = authority.get("currency", UNDEFINED)
    if a_cur is not UNDEFINED and a_cur != currency:
        return {"ok": False, "reason": 'currency "%s" is not the authorized currency "%s"' % (currency, _s(a_cur))}
    cap = authority.get("maxAmount", UNDEFINED)
    if cap is not UNDEFINED and not (_is_int(cap) and cap >= 0):  # a present cap is a non-negative safe integer; absent is the way to say unbounded
        return {"ok": False, "reason": "authorized spend cap is not a non-negative integer (fail closed)"}
    if cap is not UNDEFINED and _gt(amount, cap):
        return {"ok": False, "reason": "amount %s exceeds the authorized spend cap %s" % (js_num(amount), _s(cap))}
    merchants = authority.get("merchants")
    if merchants is not None and merchant not in merchants:
        return {"ok": False, "reason": 'merchant "%s" is not in the authorized allowlist' % merchant}
    categories = authority.get("categories")
    if categories is not None:
        category = request.get("category", UNDEFINED)
        if category is UNDEFINED:
            return {"ok": False, "reason": "the proof constrains merchant categories but no category was supplied"}
        if not any(isinstance(x, str) and x == category for x in categories):
            return {"ok": False, "reason": 'category "%s" is not in the authorized allowlist' % _s(category)}
    if authority.get("humanPresentRequired") and request.get("humanPresent") is not True:
        return {"ok": False, "reason": "the proof requires a human-present charge but humanPresent was not asserted"}
    return {"ok": True}


# ---- delegated payment token ---------------------------------------------------------------------------------------------

def _leaf_capability(pca: Any) -> Any:
    chain = _get(pca, "cap_chain")
    if not isinstance(chain, list) or len(chain) == 0:
        raise AcpAuthorityError("PCActn carries no capability chain (fail closed)")
    return chain[-1]


def _authority_ref(pca: Any) -> Dict[str, Any]:
    leaf = _leaf_capability(pca)
    action = _get(pca, "action")
    ref = {"digest": hash_canonical(pca), "aud": _get(pca, "aud"), "grant_ref": _get(pca, "grant_ref"), "leaf_holder": _get(leaf, "holder"),
           "verb": _get(action, "verb"), "resource": _get(action, "resource"), "params_digest": _get(action, "params_digest")}
    return {k: v for k, v in ref.items() if v is not UNDEFINED}


def _opt(o: Any, k: str) -> Any:
    """``o.k`` for an options object: a TypeError for null, undefined for a missing member or a non-object."""
    return _get(o, k)


def _nullish(v: Any, default: Any) -> Any:
    return default if v is None or v is UNDEFINED else v


def mint_delegated_payment_token(pca: Any, opts: dict) -> str:
    """Mint a one-time ACP delegated payment token (a compact EdDSA JWS) FROM a PCActn, bound to session, merchant, amount,
    currency and expiry, carrying the proof's authority BY REFERENCE (``pca.digest``). The proof's caveats gate issuance and an
    over-authority request, an expiry in the past or one that would outlive the proof raises ``AcpAuthorityError``.
    ``opts``: ``amount``, ``currency``, ``merchant``, ``session``, ``expiresAt``, ``paymentMethod``, ``signingKey`` (a private JWK or key
    object), ``alg``, ``category``, ``humanPresent``, ``issuer``, ``kid``, ``jti``, ``now``."""
    now_o = _opt(opts, "now")
    now = now_o if _finite(now_o) else _now_ms_default()
    authority = extract_payment_authority(_get(_leaf_capability(pca), "caveats"))
    req: Dict[str, Any] = {"amount": _opt(opts, "amount"), "currency": _opt(opts, "currency"), "merchant": _opt(opts, "merchant")}
    for k in ("category", "humanPresent"):
        if _opt(opts, k) is not UNDEFINED:
            req[k] = opts[k]
    check = check_payment_authority(authority, {k: v for k, v in req.items() if v is not UNDEFINED})
    if not check["ok"]:
        raise AcpAuthorityError("refused: %s" % (check.get("reason") or "request exceeds the proof authority"))
    exp_at = _opt(opts, "expiresAt")
    if not _finite(exp_at):
        raise AcpAuthorityError("refused: expiresAt must be a finite epoch-ms timestamp")
    if not (exp_at > now):
        raise AcpAuthorityError("refused: expiresAt is not in the future")
    pca_exp = _get(pca, "exp")
    if not (_finite(pca_exp) and exp_at <= pca_exp):
        raise AcpAuthorityError("refused: token expiry %s would outlive the proof's exp %s" % (js_num(exp_at), _s(_get(pca, "exp"))))
    session = _opt(opts, "session")
    if not truthy(None if session is UNDEFINED else session):
        raise AcpAuthorityError("refused: a session id is required")
    ref = _authority_ref(pca)
    jti = _opt(opts, "jti")
    if jti is None or jti is UNDEFINED:
        seed = dict(pca, nonce="acp:%s:%s:%s:%s:%s:%s" % (_s(session), _s(_opt(opts, "merchant")), _s(_opt(opts, "amount")),
                                                           _s(_opt(opts, "currency")), _s(exp_at), ref["digest"]))
        jti = hash_canonical(seed)
    claims: Dict[str, Any] = {"typ": ACP_DELEGATED_TOKEN_TYPE, "ver": ACP_DELEGATED_TOKEN_VERSION, "jti": jti, "session": session,
                              "merchant": _opt(opts, "merchant"), "amount": _opt(opts, "amount"), "currency": _opt(opts, "currency"),
                              "iat": now, "exp": exp_at, "paymentMethod": spread(_opt(opts, "paymentMethod")),
                              "humanPresent": _opt(opts, "humanPresent") is True}
    if _opt(opts, "category") is not UNDEFINED:
        claims["category"] = opts["category"]
    if _opt(opts, "issuer") is not UNDEFINED:
        claims["iss"] = opts["issuer"]
    claims["pca"] = ref
    claims = {k: v for k, v in claims.items() if v is not UNDEFINED}
    alg_o = _opt(opts, "alg")
    alg = "EdDSA" if alg_o is None or alg_o is UNDEFINED else alg_o
    key = _card._signing_key(_opt(opts, "signingKey"), alg) if _card._is_jwk(_opt(opts, "signingKey")) else _opt(opts, "signingKey")
    header: Dict[str, Any] = {"alg": alg, "typ": ACP_DELEGATED_TOKEN_TYPE}
    if _opt(opts, "kid") is not UNDEFINED:
        header["kid"] = opts["kid"]
    prot = _card._b64u(js_json_bytes(header))
    body = _card._b64u(js_json_bytes(claims))
    return prot + "." + body + "." + _card._b64u(jws_sign(alg, key, (prot + "." + body).encode("ascii")))


def _is_payment_method(v: Any) -> bool:
    return isinstance(v, dict) and isinstance(v.get("type"), str)


def _parse_claims(payload: bytes) -> Optional[dict]:
    try:
        parsed = js_json_parse(payload.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        return None
    if not isinstance(parsed, dict):
        return None
    c = parsed
    if c.get("typ") != ACP_DELEGATED_TOKEN_TYPE or not _is_num(c.get("ver")) or c["ver"] != ACP_DELEGATED_TOKEN_VERSION:
        return None
    if (not isinstance(c.get("jti"), str) or not isinstance(c.get("session"), str) or not isinstance(c.get("merchant"), str)
            or not _is_amount(c.get("amount")) or not isinstance(c.get("currency"), str) or not _finite(c.get("iat")) or not _finite(c.get("exp"))
            or c["jti"] == "" or c["session"] == "" or c["merchant"] == "" or c["currency"] == ""
            or not isinstance(c.get("humanPresent"), bool) or not _is_payment_method(c.get("paymentMethod"))):
        return None
    p = c.get("pca")
    if not isinstance(p, dict) or any(not isinstance(p.get(k), str) for k in ("digest", "aud", "grant_ref", "leaf_holder", "verb", "resource", "params_digest")):
        return None
    return parsed


def _compact_verify(token: Any, key: Any, algorithms: list) -> bytes:
    """jose compactVerify: header rules, the allowed algorithms, the signature; returns the payload bytes. Raises on refusal."""
    parts = token.split(".")
    prot, pay, sig = parts
    header = js_json_parse(node_b64url_decode(prot).decode("utf-8", "replace")) if prot else {}
    if not isinstance(header, dict):
        raise JoseError("JWS Protected Header is invalid")
    b64 = True
    if "crit" in header:
        crit = header["crit"]
        if not isinstance(crit, list) or not crit or any(not isinstance(c, str) or c == "" for c in crit):
            raise JoseError('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present')
        for c in crit:
            if c != "b64":
                raise JoseError('Extension Header Parameter "%s" is not recognized' % c)
        b64 = header.get("b64")
        if not isinstance(b64, bool):
            raise JoseError('The "b64" (base64url-encode payload) Header Parameter must be a boolean')
    alg = header.get("alg")
    if not isinstance(alg, str) or not alg:
        raise JoseError('JWS "alg" (Algorithm) Header Parameter missing or invalid')
    if not isinstance(algorithms, list) or any(not isinstance(a, str) for a in algorithms):
        raise TypeError('"algorithms" option must be an array of strings')
    if alg not in algorithms:
        raise JoseError('"alg" (Algorithm) Header Parameter value not allowed')
    if not jws_verify(alg, key, node_b64url_decode(sig), (prot + "." + pay).encode("utf-8")):
        raise JoseError("signature verification failed")
    return node_b64url_decode(pay) if b64 else pay.encode("utf-8")


def _verify_binding(token: Any, opts: dict) -> Dict[str, Any]:
    alg_o = _opt(opts, "alg")
    alg = "EdDSA" if alg_o is None or alg_o is UNDEFINED else alg_o
    now_o = _opt(opts, "now")
    now = now_o if _finite(now_o) else _now_ms_default()
    try:
        assert_canonical_compact_jws(token)  # canonical-spelling gate BEFORE the signature check
        vk = _opt(opts, "verifyKey")
        key = _card._import_verify_key(vk, alg) if _card._is_jwk(vk) else (None if vk is UNDEFINED else vk)
        if key is _card._BAD:
            raise JoseError("Invalid key for this operation")
        claims = _parse_claims(_compact_verify(token, key, [alg]))
    except Exception as e:  # noqa: BLE001 - every refusal reads the same, with the library's own words
        return {"ok": False, "reason": "token signature did not verify: %s" % e}
    if claims is None:
        return {"ok": False, "reason": "token payload is not a well-formed delegated payment token"}
    em = _opt(opts, "expectedMerchant")
    if claims["merchant"] != em or not isinstance(em, str):
        return {"ok": False, "reason": 'token merchant "%s" does not match expected "%s"' % (claims["merchant"], _s(em)), "claims": claims}
    amount = _opt(opts, "amount")
    if not _is_amount(amount):
        return {"ok": False, "reason": "settlement amount must be a positive integer in minor units", "claims": claims}
    if amount > claims["amount"]:
        return {"ok": False, "reason": "settlement amount %s exceeds the token's authorized amount %s" % (js_num(amount), js_num(claims["amount"])), "claims": claims}
    if now > claims["exp"]:
        return {"ok": False, "reason": "the delegated payment token has expired", "claims": claims}
    es = _opt(opts, "expectedSession")
    if es is not UNDEFINED and (not isinstance(es, str) or claims["session"] != es):
        return {"ok": False, "reason": 'token session "%s" does not match expected "%s"' % (claims["session"], _s(es)), "claims": claims}
    ec = _opt(opts, "expectedCurrency")
    if ec is not UNDEFINED and (not isinstance(ec, str) or claims["currency"] != ec):
        return {"ok": False, "reason": 'token currency "%s" does not match expected "%s"' % (claims["currency"], _s(ec)), "claims": claims}
    grant, pca = _opt(opts, "grant"), _opt(opts, "pcActn")
    if grant is not UNDEFINED and pca is UNDEFINED:
        return {"ok": False, "reason": "a grant was supplied without the pcActn to re-verify (fail closed)", "claims": claims}
    if pca is not UNDEFINED:
        if hash_canonical(pca) != claims["pca"]["digest"]:
            return {"ok": False, "reason": "pcactn_digest mismatch: the supplied proof is not the one that minted this token", "claims": claims}
        if grant is not UNDEFINED:
            roots = _opt(opts, "authorizedPlanRoots")
            v = verify_pcactn_core(pca, grant, now=now, audience=_defined(_opt(opts, "audience")),
                                   authorized_plan_roots=None if roots is UNDEFINED else roots,
                                   insecure_skip_plan_root_check=_opt(opts, "insecureSkipPlanRootCheck") is True)
            result = {"allow": bool(v.allow), "checks": dict(v.checks), "reason": v.reason}
            if not v.allow:
                return {"ok": False, "reason": "bound proof failed to verify: %s" % (v.reason or "denied"), "claims": claims, "pcaResult": result}
            return {"ok": True, "claims": claims, "pcaResult": result}
    return {"ok": True, "claims": claims}


def _defined(v: Any) -> Any:
    return None if v is UNDEFINED else v


def _now_ms_default() -> int:
    return int(time.time() * 1000)


def verify_delegated_payment_token(token: Any, opts: dict) -> Dict[str, Any]:
    """Verify a delegated payment token at settlement: the signature, then merchant, amount, expiry, session and currency bindings
    and, with a ``pcActn``, the proof's digest (end to end with a ``grant``). Strict by default: a ``singleUse`` store and an
    ``expectedCurrency`` are required, and after every other check the token's ``jti`` is claimed once. Fails CLOSED on every
    mismatch, an already redeemed token or an unavailable store."""
    su = _opt(opts, "singleUse")
    if _opt(opts, "strict") is not False:
        if not truthy(None if su is UNDEFINED else su) or not callable(getattr(su, "claim", None)):
            return {"ok": False, "reason": "strict settlement requires a singleUse store (fail closed)"}
        cur = _opt(opts, "expectedCurrency")
        if not isinstance(cur, str) or len(cur) == 0:
            return {"ok": False, "reason": "strict settlement requires expectedCurrency (fail closed)"}
    res = _verify_binding(token, opts)
    if not res["ok"] or su is UNDEFINED:
        return res
    claims = res["claims"]
    try:
        first = su.claim(claims["jti"], claims["exp"]) is True
    except Exception:  # noqa: BLE001 - a store that is down never admits a token
        return {"ok": False, "reason": "single-use store unavailable (fail closed)", "claims": claims}
    return res if first else {"ok": False, "reason": "the delegated payment token was already redeemed", "claims": claims}


# ---- x402 v1 -------------------------------------------------------------------------------------------------------------

def x402_challenge(resource: Any, opts: dict) -> Dict[str, Any]:
    """The HTTP 402 challenge for a protected resource (x402 v1 ``accepts`` entry and body). Raises ``TypeError`` on anything the
    v1 wire would make invalid (a non-positive-integer amount, no payTo or asset, a bad timeout)."""
    amount = _opt(opts, "amount")
    if not _is_amount(amount):
        raise TypeError("x402Challenge: amount must be a positive integer in atomic/minor units")
    pay_to, currency = _opt(opts, "payTo"), _opt(opts, "currency")
    if not isinstance(pay_to, str) or len(pay_to) == 0:
        raise TypeError("x402Challenge: payTo is required")
    if not isinstance(currency, str) or len(currency) == 0:
        raise TypeError("x402Challenge: currency (the x402 asset) is required")
    timeout = _nullish(_opt(opts, "maxTimeoutSeconds"), 60)
    if not _safe_int(timeout) or timeout <= 0:
        raise TypeError("x402Challenge: maxTimeoutSeconds must be a positive integer")
    requirement = {"maxTimeoutSeconds": timeout, "scheme": _nullish(_opt(opts, "scheme"), "exact"), "network": _nullish(_opt(opts, "network"), "base-sepolia"),
                   "maxAmountRequired": js_num(amount), "resource": resource,
                   "description": _nullish(_opt(opts, "description"), "Payment required for %s" % _s(resource)), "payTo": pay_to, "asset": currency,
                   "mimeType": _nullish(_opt(opts, "mimeType"), "application/json")}
    return {"status": 402, "headers": {"Content-Type": "application/json"},
            "body": {"x402Version": 1, "error": _nullish(_opt(opts, "error"), "X-PAYMENT header is required"), "accepts": [requirement]}}


def x402_settle(payload: Any, opts: dict) -> Dict[str, Any]:
    """Gate an x402 settlement on a verified, PCActn-bound payment. ``opts["verify"]`` (payload -> ``{ok, reason?, claims?}``) is
    required; on a refusal the answer is a fresh 402 (fail closed), otherwise the optional ``opts["settle"]`` step
    (payload, claims -> receipt) runs and its non-None return value becomes the receipt."""
    norm = normalize_x402_payload(payload)
    if not norm["ok"]:
        return {"settled": False, "status": 402, "reason": norm["reason"]}
    v = opts["verify"](payload)
    if not truthy(v.get("ok")):
        out = {"settled": False, "status": 402, "reason": _nullish(v.get("reason"), "payment verification failed")}
        if truthy(v.get("claims")):
            out["claims"] = v["claims"]
        return out
    if "claims" not in v:
        return {"settled": False, "status": 402, "reason": "verifier admitted the payment but returned no claims (fail closed)"}
    receipt = opts["settle"](payload, v["claims"]) if truthy(opts.get("settle")) else None
    out = {"settled": True, "status": 200, "claims": v["claims"]}
    if receipt is not None:
        out["receipt"] = receipt
    return out


def acp_x402_verifier(opts: dict) -> Callable[[Any], Dict[str, Any]]:
    """Adapt ``verify_delegated_payment_token`` into the ``verify`` step of ``x402_settle``: it reads the token from the payload of
    either version and verifies its binding and bound proof. Strict by default: ``expectedMerchant`` and ``amount`` must come from
    the server (the payload's own are never read) and a store and currency are required."""
    def verify(payload: Any) -> Dict[str, Any]:
        norm = normalize_x402_payload(payload)
        if not norm["ok"]:
            return {"ok": False, "reason": norm["reason"]}
        offered = _opt(opts, "offered")
        if norm["version"] == 2 and offered is not UNDEFINED and not x402_accepted_matches(offered, norm.get("accepted")):
            return {"ok": False, "reason": "x402 v2 payload.accepted is not one of the requirements this server offered"}
        em, amt = _opt(opts, "expectedMerchant"), _opt(opts, "amount")
        if _opt(opts, "strict") is not False and (em is UNDEFINED or amt is UNDEFINED):
            return {"ok": False, "reason": "strict settlement requires the server to supply expectedMerchant and amount (fail closed)"}
        merchant = _nullish(em, norm.get("merchant", UNDEFINED))
        if not isinstance(merchant, str) or len(merchant) == 0:
            return {"ok": False, "reason": "x402 payload has no merchant to check the token against"}
        amount = _nullish(amt, norm.get("amount", UNDEFINED))
        if not _is_num(amount) or not _is_amount(amount):
            return {"ok": False, "reason": "x402 payload has no amount to check the token against"}
        o2: Dict[str, Any] = {"expectedMerchant": merchant, "amount": amount, "verifyKey": _opt(opts, "verifyKey")}
        for k in ("alg", "now", "expectedSession", "expectedCurrency", "pcActn", "grant", "audience", "authorizedPlanRoots",
                  "insecureSkipPlanRootCheck", "singleUse", "strict"):
            if _opt(opts, k) is not UNDEFINED:
                o2[k] = opts[k]
        res = verify_delegated_payment_token(norm["token"], o2)
        out: Dict[str, Any] = {"ok": res["ok"]}
        if res.get("reason") is not None:
            out["reason"] = res["reason"]
        if truthy(res.get("claims")):
            out["claims"] = res["claims"]
        return out
    return verify


def to_acp_allowance(claims: dict) -> Dict[str, Any]:
    """Map VERIFIED token claims to the ACP delegate_payment ``allowance``; raises ``AcpAuthorityError`` when a claim cannot be
    expressed in the ACP shape (currency not three letters, merchant over 256 characters, expiry not a date)."""
    if not _is_amount(_get(claims, "amount")):
        raise AcpAuthorityError("allowance: amount must be a positive integer in minor units")
    cur = claims.get("currency")
    currency = cur.lower() if isinstance(cur, str) else ""
    if re.fullmatch(r"[a-z]{3}", currency) is None:
        raise AcpAuthorityError("allowance: currency must be a three-letter ISO-4217 code")
    merchant, session = claims.get("merchant"), claims.get("session")
    if not isinstance(merchant, str) or len(merchant) == 0 or u16len(merchant) > 256:
        raise AcpAuthorityError("allowance: merchant_id must be 1 to 256 characters")
    if not isinstance(session, str) or len(session) == 0:
        raise AcpAuthorityError("allowance: checkout_session_id is required")
    exp = claims.get("exp")
    if not _finite(exp):
        raise AcpAuthorityError("allowance: expiry is not a valid time")
    try:
        at = iso_from_ms(exp)
    except ValueError:
        raise AcpAuthorityError("allowance: expiry is not a valid time") from None
    return {"reason": "one_time", "max_amount": claims["amount"], "currency": currency, "checkout_session_id": session,
            "merchant_id": merchant, "expires_at": at}


# ---- x402 v2 -------------------------------------------------------------------------------------------------------------

_CAIP2 = re.compile(r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}")
_PRINTABLE = re.compile(r"[\x20-\x7e]*")
_ATOMIC = re.compile(r"0|[1-9][0-9]*")
_B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")


def _non_empty(v: Any) -> bool:
    return isinstance(v, str) and len(v) > 0


def _absolute_http(u: Any) -> bool:
    if not isinstance(u, str):
        return False
    r = _parse_url(u)
    return r is not None and r["scheme"] in ("http", "https")


def resource_info_problems(r: Any) -> List[str]:
    """Problems with a ``ResourceInfo`` (empty = valid)."""
    if not _is_obj(r):
        return ["resource must be an object"]
    p: List[str] = []
    if not _absolute_http(r.get("url")):
        p.append("resource.url must be an absolute http(s) URL")
    for k in ("description", "mimeType"):
        if k in r and not isinstance(r[k], str):
            p.append("resource.%s must be a string" % k)
    sn = r.get("serviceName", UNDEFINED)
    if sn is not UNDEFINED and not (isinstance(sn, str) and u16len(sn) <= 32 and _PRINTABLE.fullmatch(sn)):
        p.append("resource.serviceName must be printable ASCII up to 32 characters")
    tags = r.get("tags", UNDEFINED)
    if tags is not UNDEFINED and not (isinstance(tags, list) and len(tags) <= 5 and all(isinstance(t, str) and u16len(t) <= 32 and _PRINTABLE.fullmatch(t) for t in tags)):
        p.append("resource.tags must be up to 5 printable ASCII strings of up to 32 characters")
    icon = r.get("iconUrl", UNDEFINED)
    if icon is not UNDEFINED and not (_absolute_http(icon) and u16len(icon) <= 2048):
        p.append("resource.iconUrl must be an absolute http(s) URL up to 2048 characters")
    return p


def requirement_v2_problems(q: Any) -> List[str]:
    """Problems with one v2 ``PaymentRequirements`` (empty = valid)."""
    if not _is_obj(q):
        return ["requirements must be an object"]
    p: List[str] = []
    if not _non_empty(q.get("scheme")):
        p.append("scheme is required")
    if not isinstance(q.get("network"), str) or _CAIP2.fullmatch(q["network"]) is None:
        p.append("network must be a CAIP-2 identifier")
    if not isinstance(q.get("amount"), str) or _ATOMIC.fullmatch(q["amount"]) is None or q["amount"] == "0":
        p.append("amount must be a positive decimal string of atomic units")
    if not _non_empty(q.get("asset")):
        p.append("asset is required")
    if not _non_empty(q.get("payTo")):
        p.append("payTo is required")
    t = q.get("maxTimeoutSeconds")
    if not _is_num(t) or not _safe_int(t) or t <= 0:
        p.append("maxTimeoutSeconds must be a positive integer")
    if "extra" in q and not _is_obj(q["extra"]):
        p.append("extra must be an object")
    return p


def payment_required_v2_problems(pr: Any) -> List[str]:
    """Problems with a v2 ``PaymentRequired`` (empty = valid)."""
    if not _is_obj(pr):
        return ["PaymentRequired must be an object"]
    p: List[str] = []
    v = pr.get("x402Version")
    if not _is_num(v) or v != 2:
        p.append("x402Version must be 2")
    if "error" in pr and not isinstance(pr["error"], str):
        p.append("error must be a string")
    p.extend(resource_info_problems(pr.get("resource")))
    acc = pr.get("accepts")
    if not isinstance(acc, list) or len(acc) == 0:
        p.append("accepts must be a non-empty array")
    else:
        for i, q in enumerate(acc):
            p.extend("accepts[%d].%s" % (i, m) for m in requirement_v2_problems(q))
    if "extensions" in pr:
        ex = pr["extensions"]
        if not _is_obj(ex):
            p.append("extensions must be an object")
        else:
            for k, v in ex.items():
                if not _is_obj(v) or not _is_obj(v.get("info")) or not _is_obj(v.get("schema")):
                    p.append("extensions.%s needs info and schema objects" % k)
    return p


def _b64_encode(obj: Any) -> str:
    return base64.b64encode(js_json_bytes(obj)).decode("ascii")


def _b64_decode(value: Any, name: str) -> Any:
    """Decode a header value like Node's ``Buffer.from(v, 'base64')`` behind the shape gate, then ``JSON.parse`` it."""
    if not isinstance(value, str) or _B64.fullmatch(value) is None:
        raise TypeError("x402: %s is not base64" % name)
    s = value.rstrip("=")
    if len(s) % 4 == 1:
        s = s[:-1]
    try:
        return js_json_parse(base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        raise TypeError("x402: %s is not JSON" % name) from None


def encode_payment_required_header(pr: Any) -> str:
    """Encode a ``PaymentRequired`` for the ``PAYMENT-REQUIRED`` header (validates first; raises ``TypeError``)."""
    problems = payment_required_v2_problems(pr)
    if problems:
        raise TypeError("x402: " + "; ".join(problems))
    return _b64_encode(pr)


def decode_payment_required_header(value: Any) -> Dict[str, Any]:
    """Decode and validate a ``PAYMENT-REQUIRED`` header value; raises ``TypeError`` on bad base64, bad JSON or an invalid object."""
    doc = _b64_decode(value, "PAYMENT-REQUIRED")
    problems = payment_required_v2_problems(doc)
    if problems:
        raise TypeError("x402: " + "; ".join(problems))
    return doc


def x402_challenge_v2(resource: Any, opts: dict) -> Dict[str, Any]:
    """The v2 402 challenge: JSON body plus the base64 ``PAYMENT-REQUIRED`` header; refuses anything the v2 spec makes invalid."""
    amount = _opt(opts, "amount")
    if not _is_num(amount) or not _safe_int(amount) or amount <= 0:
        raise TypeError("x402Challenge: amount must be a positive integer in atomic units")
    info = {"url": resource} if isinstance(resource, str) else spread(resource)
    req: Dict[str, Any] = {"scheme": _nullish(_opt(opts, "scheme"), "exact"), "network": _opt(opts, "network"), "amount": js_num(amount),
                           "asset": _opt(opts, "asset"), "payTo": _opt(opts, "payTo"),
                           "maxTimeoutSeconds": _nullish(_opt(opts, "maxTimeoutSeconds"), 60)}
    if _opt(opts, "extra") is not UNDEFINED:
        req["extra"] = opts["extra"]
    body: Dict[str, Any] = {"x402Version": 2, "error": _nullish(_opt(opts, "error"), "PAYMENT-SIGNATURE header is required"), "resource": info,
                            "accepts": [{k: v for k, v in req.items() if v is not UNDEFINED}]}
    if _opt(opts, "extensions") is not UNDEFINED:
        body["extensions"] = opts["extensions"]
    header = encode_payment_required_header(body)
    return {"status": 402, "headers": {"Content-Type": "application/json", X402_V2_PAYMENT_REQUIRED_HEADER: header}, "body": body}


def _includes(lst: Any, v: int) -> bool:
    return any(_is_num(x) and x == v for x in lst)


def x402_negotiate(offered: Any = UNDEFINED, supported: Sequence[Any] = X402_SUPPORTED_VERSIONS) -> Optional[int]:
    """The highest x402 version both sides speak, or None (answer 402 v1 with an error, never guess). ``offered`` is what the client
    says it speaks (None or empty means ``[1]`` only for an omitted value; a null raises, as the reference does)."""
    mine = [v for v in supported if _is_num(v) and v in (1, 2)]
    if offered is None:
        raise TypeError("Cannot read properties of null (reading 'length')")
    theirs = [1] if offered is UNDEFINED or len(offered) == 0 else offered
    for v in sorted(mine, reverse=True):
        if _includes(theirs, v):
            return int(v)
    return None


def _stable(v: Any) -> str:
    if not isinstance(v, (list, dict)):
        return js_json(v)
    if isinstance(v, list):
        return "[" + ",".join(_stable(x) for x in v) + "]"
    return "{" + ",".join("%s:%s" % (js_json(k), _stable(v[k])) for k in sorted(v, key=u16key)) + "}"


def x402_accepted_matches(offered: Sequence[Any], accepted: Any) -> bool:
    """True when ``accepted`` (echoed by the client in its v2 payload) is exactly one of the requirements the server offered."""
    if requirement_v2_problems(accepted):
        return False
    a = _stable(accepted)
    return any(_stable(o) == a for o in offered)


def normalize_x402_payload(raw: Any) -> Dict[str, Any]:
    """Read a client payload of either version. v1: the token, merchant and amount are top-level members. v2: the token is
    ``payload.token`` and the echoed ``accepted`` must be a valid v2 requirement (the merchant is never read from a v2 payload and
    the amount only from ``accepted.amount``)."""
    if not _is_obj(raw):
        return {"ok": False, "reason": "x402 payment payload is not an object"}
    ver = raw.get("x402Version", UNDEFINED)
    if _is_num(ver) and ver == 2:
        inner = raw.get("payload")
        if not _is_obj(inner) or not isinstance(inner.get("token"), str) or len(inner["token"]) == 0:
            return {"ok": False, "reason": "x402 v2 payload is missing payload.token"}
        problems = requirement_v2_problems(raw.get("accepted"))
        if problems:
            return {"ok": False, "reason": "x402 v2 payload.accepted is invalid: " + "; ".join(problems)}
        accepted = raw["accepted"]
        out: Dict[str, Any] = {"ok": True, "version": 2, "token": inner["token"], "accepted": accepted}
        amount = float(accepted["amount"])
        if _safe_int(amount):
            out["amount"] = int(amount)
        return out
    if ver is not UNDEFINED and not (_is_num(ver) and ver == 1):
        return {"ok": False, "reason": "unsupported x402Version %s" % _s(ver)}
    if not isinstance(raw.get("token"), str):
        return {"ok": False, "reason": "x402 payment payload is missing a token"}
    out = {"ok": True, "version": 1, "token": raw["token"]}
    if isinstance(raw.get("merchant"), str):
        out["merchant"] = raw["merchant"]
    if _is_num(raw.get("amount")):
        out["amount"] = raw["amount"]
    return out


# ---- x402 v2 HTTP transport ----------------------------------------------------------------------------------------------

def payment_payload_v2_problems(p: Any) -> List[str]:
    """Problems with a v2 ``PaymentPayload`` (empty = valid)."""
    if not _is_obj(p):
        return ["PaymentPayload must be an object"]
    out: List[str] = []
    v = p.get("x402Version")
    if not _is_num(v) or v != 2:
        out.append("x402Version must be 2")
    if "resource" in p:
        out.extend(resource_info_problems(p["resource"]))
    out.extend("accepted.%s" % m for m in requirement_v2_problems(p.get("accepted")))
    if not _is_obj(p.get("payload")):
        out.append("payload must be an object")
    if "extensions" in p and not _is_obj(p["extensions"]):
        out.append("extensions must be an object")
    return out


def settlement_response_problems(r: Any) -> List[str]:
    """Problems with a ``SettlementResponse`` (empty = valid). A success must not carry an ``errorReason``; a failure must."""
    if not _is_obj(r):
        return ["SettlementResponse must be an object"]
    out: List[str] = []
    success, tx, net = r.get("success", UNDEFINED), r.get("transaction", UNDEFINED), r.get("network", UNDEFINED)
    er = r.get("errorReason", UNDEFINED)
    if not isinstance(success, bool):
        out.append("success must be a boolean")
    if not isinstance(tx, str):
        out.append("transaction must be a string")
    elif success is True and tx == "":
        out.append("a successful settlement needs a transaction")
    if not isinstance(net, str) or _CAIP2.fullmatch(net) is None:
        out.append("network must be a CAIP-2 identifier")
    if er is not UNDEFINED and not isinstance(er, str):
        out.append("errorReason must be a string")
    if success is True and er is not UNDEFINED:
        out.append("errorReason must be omitted on success")
    if success is False and (not isinstance(er, str) or er == ""):
        out.append("errorReason is required on failure")
    if "payer" in r and not isinstance(r["payer"], str):
        out.append("payer must be a string")
    if "amount" in r and not (isinstance(r["amount"], str) and _ATOMIC.fullmatch(r["amount"])):
        out.append("amount must be a decimal string of atomic units")
    if "extensions" in r and not _is_obj(r["extensions"]):
        out.append("extensions must be an object")
    return out


def _encode_header(obj: Any, problems: List[str]) -> str:
    if problems:
        raise TypeError("x402: " + "; ".join(problems))
    return _b64_encode(obj)


def encode_payment_signature_header(p: Any) -> str:
    """Encode a ``PaymentPayload`` for the ``PAYMENT-SIGNATURE`` request header (validates first; raises ``TypeError``)."""
    return _encode_header(p, payment_payload_v2_problems(p))


def decode_payment_signature_header(value: Any) -> Dict[str, Any]:
    """Decode and validate a ``PAYMENT-SIGNATURE`` header value; raises ``TypeError`` on bad base64, bad JSON or an invalid object."""
    doc = _b64_decode(value, "PAYMENT-SIGNATURE")
    problems = payment_payload_v2_problems(doc)
    if problems:
        raise TypeError("x402: " + "; ".join(problems))
    return doc


def encode_payment_response_header(r: Any) -> str:
    """Encode a ``SettlementResponse`` for the ``PAYMENT-RESPONSE`` response header."""
    return _encode_header(r, settlement_response_problems(r))


def decode_payment_response_header(value: Any) -> Dict[str, Any]:
    doc = _b64_decode(value, "PAYMENT-RESPONSE")
    problems = settlement_response_problems(doc)
    if problems:
        raise TypeError("x402: " + "; ".join(problems))
    return doc


def read_payment_signature(headers: dict) -> Dict[str, Any]:
    """Server side: read the client's ``PAYMENT-SIGNATURE`` header (case-insensitive, first value of a list). A missing header is
    402 (answer with a ``PAYMENT-REQUIRED`` challenge); a present but undecodable or invalid one is 400. Never raises."""
    v: Any = UNDEFINED
    for k, val in headers.items():
        if k.lower() == X402_PAYMENT_SIGNATURE_HEADER.lower():
            v = (val[0] if val else UNDEFINED) if isinstance(val, list) else val
            break
    if v is UNDEFINED or v == "":
        return {"ok": False, "status": X402_HTTP_STATUS["payment_required"], "reason": "PAYMENT-SIGNATURE header is required"}
    try:
        return {"ok": True, "payload": decode_payment_signature_header(v)}
    except Exception as e:  # noqa: BLE001 - never raises: any failure is a malformed header
        return {"ok": False, "status": X402_HTTP_STATUS["malformed"], "reason": str(e)}


def x402_settlement_response(outcome: dict, network: Any) -> Dict[str, Any]:
    """Server side: the status and ``PAYMENT-RESPONSE`` header for a settlement outcome (a success is 200 and needs the transaction;
    a failure is 402 with ``success: false``, the reason and an empty transaction unless one was broadcast). Raises ``TypeError``
    if the response would be invalid."""
    body: Dict[str, Any]
    settled = truthy(_get(outcome, "settled") if "settled" in outcome else None)
    if settled:
        body = {"success": True, "transaction": outcome.get("transaction", UNDEFINED), "network": network}
        for k in ("payer", "amount"):
            if k in outcome:
                body[k] = outcome[k]
    else:
        tx = outcome.get("transaction", UNDEFINED)
        body = {"success": False, "errorReason": outcome.get("reason", UNDEFINED), "transaction": "" if tx is None or tx is UNDEFINED else tx, "network": network}
        if "payer" in outcome:
            body["payer"] = outcome["payer"]
    body = {k: v for k, v in body.items() if v is not UNDEFINED}
    status = X402_HTTP_STATUS["settled"] if settled else X402_HTTP_STATUS["failed"]
    return {"status": status, "headers": {X402_PAYMENT_RESPONSE_HEADER: encode_payment_response_header(body)}}


def x402_payment_signature_headers(p: Any) -> Dict[str, str]:
    """Client side: the request header to attach on the retry, from a payload built for an offered requirement."""
    return {X402_PAYMENT_SIGNATURE_HEADER: encode_payment_signature_header(p)}


# ---- Stripe Shared Payment Granted Tokens --------------------------------------------------------------------------------

_SPT_REASONS = ("consumed", "expired", "resolved", "revoked")
_SPT_ID = re.compile(r"spt_[A-Za-z0-9_]+")
_LOWER3 = re.compile(r"[a-z]{3}")


def _is_currency(v: Any) -> bool:
    return isinstance(v, str) and _LOWER3.fullmatch(v) is not None


def stripe_spt_problems(t: Any) -> List[str]:
    """Problems with a Shared Payment Granted Token object (empty = well formed)."""
    if not _is_obj(t):
        return ["the token must be an object"]
    p: List[str] = []
    if t.get("object") != STRIPE_SPT_OBJECT:
        p.append('object must be "%s"' % STRIPE_SPT_OBJECT)
    if not isinstance(t.get("id"), str) or _SPT_ID.fullmatch(t["id"]) is None:
        p.append("id must be an spt_ identifier")
    if not _is_int(t.get("created")):
        p.append("created must be an integer timestamp")
    if not isinstance(t.get("livemode"), bool):
        p.append("livemode must be a boolean")
    da = t.get("deactivated_at", UNDEFINED)
    if da is not None and not _is_int(da):
        p.append("deactivated_at must be null or an integer timestamp")
    dr = t.get("deactivated_reason", UNDEFINED)
    if dr is not None and not (isinstance(dr, str) and dr in _SPT_REASONS):
        p.append("deactivated_reason must be null or one of consumed, expired, resolved, revoked")
    u = t.get("usage_limits")
    if not _is_obj(u):
        p.append("usage_limits is required")
    else:
        if not _is_currency(u.get("currency")):
            p.append("usage_limits.currency must be a lowercase three-letter code")
        if not _is_int(u.get("max_amount")) or u["max_amount"] < 0:
            p.append("usage_limits.max_amount must be a non-negative integer in minor units")
        ea = u.get("expires_at")
        if ea is not None and not _is_int(ea):
            p.append("usage_limits.expires_at must be an integer timestamp")
    ud = t.get("usage_details")
    if ud is not None:
        c = ud.get("amount_captured") if _is_obj(ud) else None
        if not _is_obj(c) or not _is_int(c.get("value")) or c["value"] < 0 or not _is_currency(c.get("currency")):
            p.append("usage_details.amount_captured needs a non-negative integer value and a lowercase currency")
    for k in ("payment_method_details", "agent_details", "shared_metadata"):
        if t.get(k) is not None and not _is_obj(t[k]):
            p.append("%s must be null or an object" % k)
    pmd = t.get("payment_method_details")
    if _is_obj(pmd) and not isinstance(pmd.get("type"), str):
        p.append("payment_method_details.type must be a string")
    return p


def parse_stripe_spt(t: Any) -> Dict[str, Any]:
    """Parse a Shared Payment Granted Token; raises ``TypeError`` listing every problem."""
    problems = stripe_spt_problems(t)
    if problems:
        raise TypeError("stripe spt: " + "; ".join(problems))
    return t


def stripe_spt_usable(t: Any, use: dict) -> Dict[str, Any]:
    """Can this token still be used for this capture? Refuses a malformed token, a deactivated or expired one, the wrong mode, a
    different currency, a non-integer amount and one above ``max_amount`` minus what was already captured."""
    problems = stripe_spt_problems(t)
    if problems:
        return {"ok": False, "reason": "malformed token: %s" % problems[0]}
    now, amount = _get(use, "now"), _get(use, "amount")
    if not _is_int(now) or not _is_int(amount) or amount <= 0:
        return {"ok": False, "reason": "now and amount must be integers and the amount positive"}
    lm = _nullish(use.get("livemode", UNDEFINED), True)
    if not isinstance(lm, bool) or lm != t["livemode"]:
        return {"ok": False, "reason": "the token is in the wrong mode"}
    if t["deactivated_reason"] is not None:
        return {"ok": False, "reason": "the token is deactivated (%s)" % t["deactivated_reason"]}
    if t["deactivated_at"] is not None and t["deactivated_at"] <= now:
        return {"ok": False, "reason": "the token is deactivated"}
    lim = t["usage_limits"]
    if _is_num(lim.get("expires_at")) and now >= lim["expires_at"]:
        return {"ok": False, "reason": "the token has expired"}
    cur = use.get("currency")
    if lim["currency"] != cur.lower():
        return {"ok": False, "reason": "the capture currency differs from the token currency"}
    captured = t["usage_details"].get("amount_captured") if _is_obj(t.get("usage_details")) else None
    if captured is not None and captured["currency"] != lim["currency"]:
        return {"ok": False, "reason": "the captured amount is in another currency"}
    remaining = lim["max_amount"] - (captured["value"] if captured is not None else 0)
    if amount > remaining:
        return {"ok": False, "reason": "the amount %s exceeds the remaining %s" % (js_num(amount), js_num(remaining))}
    return {"ok": True}


def stripe_usage_limits_for(authority: dict) -> Dict[str, Any]:
    """The ``usage_limits`` to request for a PCA authority: lowercase currency, integer minor units, expiry in whole seconds
    (rounded down). Raises ``TypeError`` on anything invalid."""
    ma, cur, exp = _get(authority, "maxAmount"), authority.get("currency"), authority.get("expiresAtMs", UNDEFINED)
    if not _is_int(ma) or ma <= 0:
        raise TypeError("stripe spt: maxAmount must be a positive integer in minor units")
    if not isinstance(cur, str) or re.fullmatch(r"[A-Za-z]{3}", cur) is None:
        raise TypeError("stripe spt: currency must be a three-letter code")
    if exp is not UNDEFINED and not (_finite(exp) and exp > 0):
        raise TypeError("stripe spt: expiresAtMs must be a positive epoch-ms time")
    out: Dict[str, Any] = {"currency": cur.lower(), "max_amount": ma}
    if exp is not UNDEFINED:
        out["expires_at"] = math.floor(exp / 1000)
    return out


def stripe_spt_within_claims(t: Any, claims: dict) -> Dict[str, Any]:
    """A Shared Payment Token may be no wider than the delegated payment token (and so the PCA proof) it serves: same currency,
    ``max_amount`` not above the delegated amount, and an expiry present and not after the delegated token's."""
    problems = stripe_spt_problems(t)
    if problems:
        return {"ok": False, "reason": "malformed token: %s" % problems[0]}
    lim = t["usage_limits"]
    amount, exp = _get(claims, "amount"), _get(claims, "exp")
    if lim["currency"] != _get(claims, "currency").lower():
        return {"ok": False, "reason": "the token currency differs from the delegated currency"}
    if not (_finite(amount) and lim["max_amount"] <= amount):  # the negation of the positive condition: a missing or non-number amount never admits
        return {"ok": False, "reason": "max_amount %s exceeds the delegated amount %s" % (js_num(lim["max_amount"]), _s(amount))}
    if not _is_num(lim.get("expires_at")):
        return {"ok": False, "reason": "the token has no expiry"}
    if not (_finite(exp) and lim["expires_at"] * 1000 <= exp):
        return {"ok": False, "reason": "the token outlives the delegated payment token"}
    return {"ok": True}
