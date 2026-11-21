"""ERC-7715 (``wallet_requestExecutionPermissions``) for PCA grants: the mapping of a grant's money envelope to a permission
request, the filter against a wallet's supported permissions and the fail-closed check of what the wallet actually granted (it
may narrow, never widen). Pure mapping and verification: no chain access and no redemption. Dicts shaped like the TypeScript
reference (``@atlasauth/pca-erc7715``); a chain id is a Python ``int`` (the reference takes a BigInt).

The EIP defines no permission ``type`` data beyond ``native-token-allowance`` {allowance}; for ``erc20-token-allowance`` the data
{tokenAddress, allowance} is a PCA profile to confirm against the target wallet's permission ERC. There is no price oracle: the
caller states the exact integer ratio ``baseUnitsPerMinor``. Fail strict: an unknown permission or rule type, any widening, a
missing expiry or an unexpected chain, account or manager is refused."""
import math
import re
from typing import Any, Callable, Dict, List, Optional

from .a2a_card import UNDEFINED
from .attest_common import JS_WS
from .pca import hash_canonical
from .sdjwt_jws import js_to_string

_HEX_ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
_HEX_QTY = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)")
_HEX_CTX = re.compile(r"0x[0-9a-fA-F]+")
_DEC = re.compile(r"0|[1-9][0-9]*")
_MAX_SAFE = 9007199254740991


def _s(v: Any) -> str:
    """``String(v)``."""
    return "undefined" if v is UNDEFINED else js_to_string(v)


def _m(o: Any, k: str) -> Any:
    """``o.k``: a TypeError for null / undefined, undefined for a missing member or a non-object."""
    if o is None or o is UNDEFINED:
        raise TypeError("Cannot read properties of %s (reading '%s')" % ("null" if o is None else "undefined", k))
    return o.get(k, UNDEFINED) if isinstance(o, dict) else UNDEFINED


def _lower(v: Any) -> str:
    if not isinstance(v, str):
        raise TypeError("toLowerCase is not a function")
    return v.lower()


def _test(rx: "re.Pattern[str]", v: Any) -> bool:
    """``RegExp.test(v)``: the value is coerced to its string first."""
    return rx.fullmatch(_s(v)) is not None


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _safe_int(v: Any) -> bool:
    """``Number.isSafeInteger``."""
    if not _num(v):
        return False
    if isinstance(v, float):
        return v == v and abs(v) <= _MAX_SAFE and v == math.floor(v)
    return abs(v) <= _MAX_SAFE


def _neg_zero(v: Any) -> bool:
    return isinstance(v, float) and v == 0 and math.copysign(1.0, v) < 0


def _seq(a: Any, b: Any) -> bool:
    """``a === b`` for JSON values (containers by reference)."""
    if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
        return a is b
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if a is None or b is None or a is UNDEFINED or b is UNDEFINED:
        return a is b
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    return a == b


def _bigint(v: Any) -> int:
    """``BigInt(v)``: raises ValueError (SyntaxError / RangeError) or TypeError where the reference throws."""
    if v is None or v is UNDEFINED:
        raise TypeError("Cannot convert %s to a BigInt" % _s(v))
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        if v != v or v in (math.inf, -math.inf) or v != math.floor(v):
            raise ValueError("not an integer")
        return int(v)
    if isinstance(v, (list, dict)):
        v = _s(v)
    s = v.strip(JS_WS)
    if s == "":
        return 0
    if len(s) > 2 and s[0] == "0" and s[1] in "xXoObB":
        try:
            return int(s[2:], {"x": 16, "o": 8, "b": 2}[s[1].lower()]) if re.fullmatch(r"[0-9a-fA-F]+", s[2:]) else _bad(s)
        except ValueError:
            return _bad(s)
    if re.fullmatch(r"[+-]?[0-9]+", s) is None:
        return _bad(s)
    return int(s)


def _bad(s: str) -> int:
    raise ValueError("Cannot convert %s to a BigInt" % s)


def _hex(n: int) -> str:
    return "0x%x" % n


def grant_to_permission_request(g: Any, o: Any) -> Dict[str, Any]:
    """The ERC-7715 request for a grant's money envelope ``{grantDigest, capMinor, expiresAtSec}``. ``o``: ``chainId`` (int),
    ``sessionAccount``, ``baseUnitsPerMinor`` (decimal string), ``tokenAddress`` (absent: the native token), ``from``,
    ``isAdjustmentAllowed``. The allowance is ``capMinor * baseUnitsPerMinor`` in hex; the grant's end becomes the ``expiry`` rule.
    Raises ValueError on a bad envelope, address, ratio or chain."""
    cap, exp = _m(g, "capMinor"), _m(g, "expiresAtSec")
    if not _safe_int(cap) or cap <= 0 or not _safe_int(exp) or exp <= 0:
        raise ValueError("grantToPermissionRequest: bad envelope")
    session, frm, token = _m(o, "sessionAccount"), _m(o, "from"), _m(o, "tokenAddress")
    if not _test(_HEX_ADDR, session) or (frm is not UNDEFINED and not _test(_HEX_ADDR, frm)) or (token is not UNDEFINED and not _test(_HEX_ADDR, token)):
        raise ValueError("grantToPermissionRequest: bad address")
    ratio = _m(o, "baseUnitsPerMinor")
    if not _test(_DEC, ratio) or (isinstance(ratio, str) and ratio == "0"):
        raise ValueError("grantToPermissionRequest: baseUnitsPerMinor must be a positive integer string")
    chain = _m(o, "chainId")
    if isinstance(chain, int) and not isinstance(chain, bool) and chain <= 0:
        raise ValueError("grantToPermissionRequest: bad chain")
    if not isinstance(chain, int) or isinstance(chain, bool):
        raise TypeError("chainId must be an integer")
    allowance = _hex(int(cap) * _bigint(ratio))
    adj = _m(o, "isAdjustmentAllowed")
    adj = True if adj is None or adj is UNDEFINED else adj
    out: Dict[str, Any] = {"chainId": _hex(chain)}
    if frm is not UNDEFINED:
        out["from"] = frm
    out["to"] = session
    if token is not UNDEFINED:
        out["permission"] = {"type": "erc20-token-allowance", "isAdjustmentAllowed": adj, "data": {"tokenAddress": token, "allowance": allowance}}
    else:
        out["permission"] = {"type": "native-token-allowance", "isAdjustmentAllowed": adj, "data": {"allowance": allowance}}
    out["rules"] = [{"type": "expiry", "data": {"timestamp": exp}}]
    return out


def supports_request(supported: Any, req: Any) -> bool:
    """A ``wallet_getSupportedExecutionPermissions`` result filtered to what a grant could use (the caller made the RPC): the
    permission type is listed, the chain id is among its ``chainIds`` and every rule type is among its ``ruleTypes`` (the draft also
    spells it ``rulesTypes``). Never raises."""
    try:
        s = _m(supported, _s(_m(_m(req, "permission"), "type")))
        if s is UNDEFINED:
            return False
        chains = _m(s, "chainIds")
        if not isinstance(chains, list):
            return False
        lowered = [_lower(c) for c in chains]
        if _lower(_m(req, "chainId")) not in lowered:
            return False
        rt = _m(s, "ruleTypes")
        if rt is None or rt is UNDEFINED:
            rt = _m(s, "rulesTypes")
        rules = _m(req, "rules")
        if rules is None or rules is UNDEFINED:
            rules = []
        if not isinstance(rules, list):
            return False
        for r in rules:
            if not isinstance(rt, list):
                return False
            t = _m(r, "type")
            if not any(_seq(x, t) for x in rt):
                return False
        return True
    except Exception:  # noqa: BLE001 - anything unreadable is unsupported
        return False


def revoke_params(context: Any = UNDEFINED) -> Dict[str, Any]:
    """The ``wallet_revokeExecutionPermission`` parameters for a permission context."""
    return {} if context is UNDEFINED else {"permissionContext": context}


def verify_granted_permission(g: Any, sent: Any, got: Any, o: Any) -> Optional[str]:
    """Verify what the wallet actually granted against the request sent and the grant. None when the permission is within the grant,
    else a reason. A wallet may NARROW (when ``isAdjustmentAllowed``); a larger amount, a later expiry or a different token, chain,
    recipient or manager is refused. ``o``: ``allowedManagers`` (lower-case compare) and an optional ``contextOwner`` callable
    mapping a context handle to the grant digest it is bound to (None when unbound). Never raises."""
    try:
        return _verify_granted(g, sent, got, o)
    except Exception:  # noqa: BLE001 - totality: anything unreadable is a malformed response
        return "response_malformed"


def _verify_granted(g: Any, sent: Any, got: Any, o: Any) -> Optional[str]:
    r = got
    if r is None or not isinstance(r, (dict, list)):
        return "response_malformed"
    perm = _m(r, "permission")
    if not isinstance(perm, (dict, list)):
        return "response_malformed"
    ctx = _m(r, "context")
    if not isinstance(ctx, str) or _HEX_CTX.fullmatch(ctx) is None:
        return "context_malformed"
    owner_fn = _m(o, "contextOwner")
    owner = owner_fn(ctx) if callable(owner_fn) else None
    if owner is not None and not _seq(owner, _m(g, "grantDigest")):
        return "context_bound_to_other_grant"
    mgr = _m(r, "delegationManager")
    if not isinstance(mgr, str) or _HEX_ADDR.fullmatch(mgr) is None:
        return "delegation_manager_not_allowed"
    managers = _m(o, "allowedManagers")
    if not isinstance(managers, list):
        raise TypeError("allowedManagers.map is not a function")
    if _lower(mgr) not in [_lower(m) for m in managers]:
        return "delegation_manager_not_allowed"
    if _lower(_s(_m(r, "chainId"))) != _lower(_m(sent, "chainId")):
        return "chain_mismatch"
    if _lower(_s(_m(r, "to"))) != _lower(_m(sent, "to")):
        return "recipient_mismatch"
    sfrom = _m(sent, "from")
    if sfrom is not UNDEFINED and _lower(_s(_m(r, "from"))) != _lower(sfrom):
        return "from_mismatch"
    ptype, stype = _m(perm, "type"), _m(_m(sent, "permission"), "type")
    if not _seq(ptype, stype) or not (_seq(ptype, "native-token-allowance") or _seq(ptype, "erc20-token-allowance")):
        return "permission_type_mismatch"
    d, sd = _m(perm, "data"), _m(_m(sent, "permission"), "data")
    dtok, sdtok = _m(d, "tokenAddress"), _m(sd, "tokenAddress")
    if _lower(_s("" if dtok is None or dtok is UNDEFINED else dtok)) != _lower(_s("" if sdtok is None or sdtok is UNDEFINED else sdtok)):
        return "token_mismatch"
    allowance = _m(d, "allowance")
    if not isinstance(allowance, str) or _HEX_QTY.fullmatch(allowance) is None:
        return "amount_malformed"
    if _bigint(allowance) > _bigint(_m(sd, "allowance")):
        return "amount_widened"
    adj, sadj = _m(perm, "isAdjustmentAllowed"), _m(_m(sent, "permission"), "isAdjustmentAllowed")
    if not _seq(adj, sadj) and adj is True:
        return "adjustment_widened"
    rules = _m(r, "rules")
    if not isinstance(rules, list):
        return "expiry_missing"
    expiry: Any = UNDEFINED
    for rule in rules:
        if rule is None or rule is UNDEFINED or not _seq(_m(rule, "type"), "expiry"):
            return "unknown_rule_type"
        if expiry is not UNDEFINED:
            return "duplicate_expiry"
        expiry = _m(_m(rule, "data"), "timestamp")
        if not _safe_int(expiry) or _neg_zero(expiry):
            return "expiry_malformed"
    if expiry is UNDEFINED:
        return "expiry_missing"
    exp_sec = _m(g, "expiresAtSec")
    if exp_sec is None or isinstance(exp_sec, bool):
        exp_sec = int(bool(exp_sec))  # JavaScript compares null as 0 and a boolean as 0 / 1
    if _num(exp_sec) and expiry > exp_sec:
        return "expiry_extended"
    return None


def grant_digest_of(grant: Any) -> str:
    """``hashCanonical(grant)``; raises TypeError on a value with no strict canonical form."""
    return hash_canonical(grant)
