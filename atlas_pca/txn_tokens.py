"""OAuth chain-of-custody profile of a PCA capability chain: the RFC 8693 section 4.1 nested `act` claim, and Transaction Tokens
(typ txntoken+jwt, draft-11; or the legacy txn_token+jwt shape) signed with Ed25519. The token is an interop envelope, not a
credential: authority still rests on the PCActn's signed capability chain. Mirrors the TypeScript reference
(@atlasauth/pca-txn-tokens). Options are dicts keyed in snake_case."""
from __future__ import annotations
from ._fin import fin

import time
import uuid
from typing import Any, Dict, List, Optional

from . import ed25519
from .dpop import _js_len, _now_sec, _utf8, assert_canonical_compact_jws, jws_verify_compact, jwt_claims_check
from .oauth import _js_json, _truthy
from .pca import b64u, decode_b64u_strict

TXN_TOKEN_TYP = "txn_token+jwt"
TXN_TOKEN_TYP_DRAFT_11 = "txntoken+jwt"
DEFAULT_TTL_SEC = 120
MAX_TOKEN_CHARS = 16384
_PCA_ACTION_KEYS = ("verb", "resource", "aud")
_UNDEF = object()


class TxnTokenError(Exception):
    """A verifier configured without a required security component; `code` is replay_store_required."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _get(x: Any, k: str) -> Any:
    """JavaScript property read: a missing member (or a non-object) is undefined, null raises."""
    if x is None:
        raise TypeError("cannot read properties of null")
    return x.get(k, _UNDEF) if isinstance(x, dict) else _UNDEF


def _nonempty_str(x: Any) -> bool:
    return isinstance(x, str) and len(x) > 0


def sub_act_chain(chain: Any) -> Dict[str, Any]:
    """Project a capability chain into `{sub, act}`: `sub` is the root principal, then one nested `act` per hop, root to leaf."""
    if not isinstance(chain, list) or len(chain) == 0:
        raise TypeError("subActChain: chain must be a non-empty CapabilityChain")
    root = chain[0]
    act: Optional[Dict[str, Any]] = None
    for i in range(len(chain) - 1, -1, -1):
        holder = _get(chain[i], "holder")
        if not _nonempty_str(holder):
            raise TypeError("subActChain: hop %d has no holder" % i)
        act = {"sub": holder, "act": act} if act else {"sub": holder}
    issuer = _get(root, "issuer")
    if not _nonempty_str(issuer):
        raise TypeError("subActChain: root hop has no issuer (principal)")
    return {"sub": issuer, "act": act} if act else {"sub": issuer}


def act_depth(claim: Any) -> int:
    """The number of nested `act` levels (one per delegation hop); the top-level `sub` does not count."""
    if not isinstance(claim, (dict, list)):
        raise TypeError("actDepth: expected a sub/act claim object")
    depth = 0
    cur = _get(claim, "act")
    while _truthy(cur) and cur is not _UNDEF:
        depth += 1
        cur = _get(cur, "act")
    return depth


def to_rfc8693_act(claim: Any) -> Dict[str, Any]:
    """The RFC 8693 order of an `act` chain, the most recent actor outermost (the projection above descends root first)."""
    actors: List[Any] = []
    c = _get(claim, "act")
    while c is not _UNDEF and _truthy(c):
        actors.append(_get(c, "sub"))
        c = _get(c, "act")
    act: Optional[Dict[str, Any]] = None
    for sub in actors:
        node: Dict[str, Any] = {} if sub is _UNDEF else {"sub": sub}
        if act is not None:
            node["act"] = act
        act = node
    out: Dict[str, Any] = {}
    sub = _get(claim, "sub")
    if sub is not _UNDEF:
        out["sub"] = sub
    if act is not None:
        out["act"] = act
    return out


def _signing_seed(key: Any) -> bytes:
    if isinstance(key, (bytes, bytearray)):
        if len(key) != 32:
            raise TypeError("toTransactionToken: a raw Ed25519 secret key must be 32 bytes")
        return bytes(key)
    if isinstance(key, dict) and key.get("kty") == "OKP" and key.get("crv") == "Ed25519":
        seed = decode_b64u_strict(key.get("d"), 32)
        if seed is not None:
            return seed
    raise TypeError("toTransactionToken: the issuer key must be a 32-byte Ed25519 seed or a private OKP / Ed25519 JWK")


def _verification_key(key: Any) -> bytes:
    if isinstance(key, (bytes, bytearray)):
        if len(key) != 32:
            raise TypeError("fromTransactionToken: a raw Ed25519 public key must be 32 bytes")
        return bytes(key)
    if isinstance(key, dict) and key.get("kty") == "OKP" and key.get("crv") == "Ed25519":
        pub = decode_b64u_strict(key.get("x"), 32)
        if pub is not None:
            return pub
    raise TypeError("fromTransactionToken: the verify key must be a 32-byte Ed25519 key or a public OKP / Ed25519 JWK")


def to_transaction_token(args: Dict[str, Any]) -> str:
    """Mint a signed Transaction Token carrying the chain of custody (`sub` / `act`) and the action as `tctx`.
    Args (snake_case): chain, action {verb, resource, aud}, issuer_key (32-byte seed or private JWK), issuer, profile
    ('draft-11' default or 'legacy'), scope, req_wl, txn, trust_domain, ttl_sec (default 120), now_sec (default the clock)."""
    chain, action, issuer = args.get("chain"), args.get("action"), args.get("issuer")
    if not _nonempty_str(issuer):
        raise TypeError("toTransactionToken: `issuer` is required")
    if not isinstance(action, dict) or not all(isinstance(action.get(k), str) for k in _PCA_ACTION_KEYS):
        raise TypeError("toTransactionToken: `action` must have string verb, resource and aud")
    custody = sub_act_chain(chain)
    ttl = DEFAULT_TTL_SEC if args.get("ttl_sec") is None else args["ttl_sec"]
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not fin(ttl) or ttl <= 0:
        raise ValueError("toTransactionToken: ttlSec must be > 0")
    now = _now_sec(args.get("now_sec")) if args.get("now_sec") is not None else int(time.time())
    seed = _signing_seed(args.get("issuer_key"))
    profile = args.get("profile")
    draft = profile is None or profile == "draft-11"
    if profile is not None and profile != "legacy" and not draft:
        raise TypeError("toTransactionToken: profile must be legacy or draft-11")
    tctx = {"verb": action["verb"], "resource": action["resource"], "aud": action["aud"]}
    if draft:
        scope, req_wl = args.get("scope"), args.get("req_wl")
        if not _nonempty_str(scope):
            raise TypeError("toTransactionToken: draft-11 requires `scope`")
        if not _nonempty_str(req_wl):
            raise TypeError("toTransactionToken: draft-11 requires `reqWl`")
        td = args.get("trust_domain")
        td = action["aud"] if td is None else td
        if not _nonempty_str(td):
            raise TypeError("toTransactionToken: draft-11 requires a non-empty trust domain (aud)")
        txn = args.get("txn")
        payload: Dict[str, Any] = {"tctx": tctx}
        if custody.get("act"):
            payload["act"] = custody["act"]
        payload.update({"txn": str(uuid.uuid4()) if txn is None else txn, "scope": scope, "req_wl": req_wl, "iat": now, "iss": issuer,
                        "sub": custody["sub"], "aud": td, "exp": now + ttl})
        header = {"alg": "EdDSA", "typ": TXN_TOKEN_TYP_DRAFT_11}
    else:
        payload = {"tctx": tctx}
        if custody.get("act"):
            payload["act"] = custody["act"]
        payload.update({"iat": now, "iss": issuer, "sub": custody["sub"], "aud": action["aud"], "exp": now + ttl, "jti": str(uuid.uuid4())})
        header = {"alg": "EdDSA", "typ": TXN_TOKEN_TYP}
    signing_input = "%s.%s" % (b64u(_utf8(_js_json(header))), b64u(_utf8(_js_json(payload))))
    return "%s.%s" % (signing_input, b64u(ed25519.sign_secret(seed, signing_input.encode("ascii"))))


def _normalize_act(parent: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if "act" not in parent:
        return None
    node = parent["act"]
    if not isinstance(node, dict):
        raise ValueError("transaction token: malformed `act` claim")
    if not _nonempty_str(node.get("sub")):
        raise ValueError("transaction token: `act.sub` must be a non-empty string")
    inner = _normalize_act(node)
    return {"sub": node["sub"], "act": inner} if inner else {"sub": node["sub"]}


def _read_tctx(raw: Any, draft: bool) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("transaction token: missing or malformed `tctx`")
    uses_pca = any(k in raw for k in _PCA_ACTION_KEYS)
    if not draft or uses_pca:
        if not all(isinstance(raw.get(k), str) for k in _PCA_ACTION_KEYS):
            raise ValueError("transaction token: missing or malformed `tctx`")
        return {"tctx": raw, "action": {k: raw[k] for k in _PCA_ACTION_KEYS}}
    return {"tctx": raw, "action": None}


def from_transaction_token(jwt: Any, verify_key: Any, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Verify a Transaction Token's EdDSA signature and read out the custody chain, the action and the claims. Raises on a bad
    signature, key, lifetime or claim set. Options (snake_case): profile ('draft-11' default, or 'legacy'), audience (required
    for draft-11), clock_tolerance_sec, now (a datetime or epoch seconds), seen_txn (callable(id, exp) -> True when already seen;
    required unless replay_check == 'unchecked')."""
    o = {} if opts is None else opts
    profile = o.get("profile")
    draft = profile is None or profile == "draft-11"
    if profile is not None and profile != "legacy" and not draft:
        raise TypeError("fromTransactionToken: profile must be legacy or draft-11")
    audience = o.get("audience")
    if draft and not _nonempty_str(audience):
        raise TypeError("fromTransactionToken: draft-11 requires opts.audience (the trust domain this verifier serves)")
    seen_txn = o.get("seen_txn")
    if not callable(seen_txn) and o.get("replay_check") != "unchecked":
        raise TxnTokenError("replay_store_required", "fromTransactionToken: supply opts.seen_txn (a replay store) or set opts.replay_check to 'unchecked'")
    if isinstance(jwt, str) and _js_len(jwt) > MAX_TOKEN_CHARS:
        raise ValueError("transaction token: token exceeds the size limit")
    parsed = assert_canonical_compact_jws(jwt)
    pub = _verification_key(verify_key)
    jws_verify_compact(jwt, parsed, ("EdDSA",), lambda alg, header: (lambda data, sig: ed25519.verify(pub, data, sig)))
    required = ("iat", "exp", "aud", "sub", "txn", "scope", "req_wl") if draft else ("exp",)
    payload = jwt_claims_check(parsed["header"], parsed["payload"], typ=TXN_TOKEN_TYP_DRAFT_11 if draft else TXN_TOKEN_TYP, required=required,
                               audience=audience, clock_tolerance=o.get("clock_tolerance_sec"), now=o.get("now"))
    if draft:
        for k in ("txn", "scope", "req_wl"):
            if not _nonempty_str(payload.get(k)):
                raise ValueError("transaction token: `%s` must be a non-empty string" % k)
    if not _nonempty_str(payload.get("sub")):
        raise ValueError("transaction token: missing `sub` (root principal)")
    t = _read_tctx(payload.get("tctx"), draft)
    if draft and "rctx" in payload and not isinstance(payload["rctx"], dict):
        raise ValueError("transaction token: malformed `rctx`")
    act = _normalize_act(payload)
    if seen_txn is not None and callable(seen_txn):
        ident = payload.get("txn") if draft else payload.get("jti")
        if not _nonempty_str(ident):
            raise ValueError("transaction token: no transaction identifier to check for replay")
        if seen_txn(ident, payload.get("exp")):
            raise ValueError("transaction token: replayed (transaction identifier already seen)")
    chain = {"sub": payload["sub"], "act": act} if act else {"sub": payload["sub"]}
    return {"chain": chain, "action": t["action"], "tctx": t["tctx"], "claims": payload}
