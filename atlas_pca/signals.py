"""Shared Signals Framework / CAEP for PCA: Security Event Tokens (RFC 8417), the subscriber-side revocation state, the
fail-closed SET receiver, the SSF stream health / verification / poll / push bookkeeping and the SSF management API.

Mirrors the TypeScript reference (@atlasauth/pca-signals). Asynchronous reference functions are synchronous here; function and
store options are plain callables / objects. JSON-shaped inputs follow JavaScript semantics where the reference does
(truthiness, missing members, member order), so a hostile input is refused or accepted exactly as the reference does."""
from __future__ import annotations

import copy
import math
import re
import secrets
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import sdjwt_jws as J
from ._fin import fin
from .pca import _js_keys

SET_TYP = "secevent+jwt"
SET_ALG = "EdDSA"
EVENT_TYPES = {
    "sessionRevoked": "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
    "credentialChange": "https://schemas.openid.net/secevent/caep/event-type/credential-change",
    "grantRevoked": "https://atlasauth.net/caep/grant-revoked",
    "killSwitch": "https://atlasauth.net/caep/kill-switch",
    "intentRevoked": "https://atlasauth.net/caep/intent-revoked",
    "verification": "https://schemas.openid.net/secevent/ssf/event-type/verification",
    "riskLevelChange": "https://schemas.openid.net/secevent/caep/event-type/risk-level-change",
    "assuranceLevelChange": "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change",
}
RISC_EVENT_TYPES = {
    "sessionsRevoked": "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked",
    "accountDisabled": "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
    "accountPurged": "https://schemas.openid.net/secevent/risc/event-type/account-purged",
    "credentialCompromise": "https://schemas.openid.net/secevent/risc/event-type/credential-compromise",
}
SET_INMEMORY_MAX_ENTRIES = 100_000
DELIVERY_PUSH = "urn:ietf:rfc:8935"
DELIVERY_POLL = "urn:ietf:rfc:8936"
STREAM_STATUSES = ["enabled", "paused", "disabled"]

UNDEF = object()  # a JSON member that is absent (distinct from null)
_DEFAULT = object()


class SignalsError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class SetVerifyError(Exception):
    """A JOSE-level refusal. `code` is the JOSE error code (None for the package's own `SET invalid:` errors)."""

    def __init__(self, message: str, code: Optional[str] = None):
        super().__init__(message)
        self.code = code


# ---- JS-semantics helpers ---------------------------------------------------------------------------------------------------

def _isrec(v: Any) -> bool:
    return isinstance(v, dict)


def _isnum(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _prop(o: Any, k: str) -> Any:
    """`o.k`: TypeError for null / undefined, UNDEF for a missing member or a primitive."""
    if o is None or o is UNDEF:
        raise TypeError("Cannot read properties of %s (reading '%s')" % ("null" if o is None else "undefined", k))
    return o.get(k, UNDEF) if isinstance(o, dict) else UNDEF


def _optprop(o: Any, k: str) -> Any:
    return UNDEF if o is None or o is UNDEF else _prop(o, k)


def _entries(x: Any) -> List[Tuple[str, Any]]:
    """Object.entries(x)."""
    if x is None or x is UNDEF:
        raise TypeError("Cannot convert undefined or null to object")
    if isinstance(x, dict):
        return [(k, x[k]) for k in _js_keys(x)]
    if isinstance(x, list):
        return [(str(i), v) for i, v in enumerate(x)]
    if isinstance(x, str):
        return [(str(i), c) for i, c in enumerate(x)]
    return []


def _safe_int(v: Any) -> bool:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    if isinstance(v, float) and (not fin(v) or v != math.floor(v)):
        return False
    return abs(v) <= 2 ** 53 - 1


def _nonneg_safe_int(v: Any) -> bool:
    return _safe_int(v) and v >= 0 and not (isinstance(v, float) and v == 0 and math.copysign(1.0, v) < 0)


def _str_ne(x: Any) -> bool:
    return isinstance(x, str) and len(x) > 0


# ---- SET build / verify -----------------------------------------------------------------------------------------------------

def build_set(events: Any, issuer: Any, audience: Any, key: Any, subject: Any = None, now: Optional[int] = None,
              jti: Optional[str] = None) -> str:
    """Build a signed SET. `key` is a 32-byte Ed25519 seed; `subject` None omits sub / sub_id."""
    if not isinstance(events, (dict, list)) or len(events) == 0:
        raise ValueError("buildSET: at least one event is required in the `events` map (RFC 8417 §2.2)")
    payload: Dict[str, Any] = {"events": events}
    if subject is not None:
        payload["sub_id"] = {"format": "opaque", "id": subject}
    payload["iss"] = issuer
    payload["iat"] = int(time.time()) if now is None else now
    payload["jti"] = jti if jti is not None else str(uuid.uuid4())
    payload["aud"] = audience
    if subject is not None:
        payload["sub"] = subject
    return J.sign_jwt(payload, {"alg": SET_ALG, "typ": SET_TYP}, key)


def _norm_typ(v: str) -> str:
    v = v.lower()
    return v[len("application/"):] if v.startswith("application/") else v


def _jose_verify(jwt: str, key: Any, opts: Dict[str, Any], typ: Optional[str]) -> Tuple[dict, dict]:
    """jose 5 jwtVerify with the claim checks and their order, for an already canonical compact JWS."""
    prot, pay, sig = jwt.split(".")
    header = J.js_json_parse(J.node_b64url_decode(prot).decode("utf-8", "replace")) if prot else {}
    if not isinstance(header, dict):
        header = {}
    b64 = True
    if "crit" in header:
        crit = header["crit"]
        if not isinstance(crit, list) or not crit or any(not _str_ne(c) for c in crit):
            raise SetVerifyError('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present',
                                 "ERR_JWS_INVALID")
        for p in crit:
            if p != "b64":
                raise SetVerifyError('Extension Header Parameter "%s" is not recognized' % p, "ERR_JOSE_NOT_SUPPORTED")
        b64 = header.get("b64")
        if not isinstance(b64, bool):
            raise SetVerifyError('The "b64" (base64url-encode payload) Header Parameter must be a boolean', "ERR_JWS_INVALID")
    alg = header.get("alg")
    if not _str_ne(alg):
        raise SetVerifyError('JWS "alg" (Algorithm) Header Parameter missing or invalid', "ERR_JWS_INVALID")
    if alg != SET_ALG:
        raise SetVerifyError('"alg" (Algorithm) Header Parameter value not allowed', "ERR_JOSE_ALG_NOT_ALLOWED")
    try:
        ok = J.jws_verify(alg, key, J.node_b64url_decode(sig), (prot + "." + pay).encode("utf-8"))
    except J.JoseError as e:
        raise SetVerifyError(str(e)) from None
    if not ok:
        raise SetVerifyError("signature verification failed", "ERR_JWS_SIGNATURE_VERIFICATION_FAILED")
    if not b64:
        raise SetVerifyError("JWTs MUST NOT use unencoded payload", "ERR_JWT_INVALID")
    try:
        payload = J.js_json_parse(J.node_b64url_decode(pay).decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        payload = None
    if not isinstance(payload, dict):
        raise SetVerifyError("JWT Claims Set must be a top-level JSON object", "ERR_JWT_INVALID")
    claim = "ERR_JWT_CLAIM_VALIDATION_FAILED"
    if typ and (not isinstance(header.get("typ"), str) or _norm_typ(header["typ"]) != _norm_typ(typ)):
        raise SetVerifyError('unexpected "typ" JWT header value', claim)
    has_iss, has_aud = "issuer" in opts, "audience" in opts
    issuer, audience = opts.get("issuer"), opts.get("audience")
    for c in (["iss"] if has_iss else []) + (["aud"] if has_aud else []):
        if c not in payload:
            raise SetVerifyError('missing required "%s" claim' % c, claim)
    if J.truthy(issuer) and payload.get("iss") not in (issuer if isinstance(issuer, list) else [issuer]):
        raise SetVerifyError('unexpected "iss" claim value', claim)
    if J.truthy(audience):
        aud_opt = [audience] if isinstance(audience, str) else audience
        if not isinstance(aud_opt, list):
            raise TypeError("audience option must be a string or an array")
        ap = payload.get("aud")
        if isinstance(ap, str):
            good = ap in aud_opt
        elif isinstance(ap, list):
            good = any(a in ap for a in aud_opt)
        else:
            good = False
        if not good:
            raise SetVerifyError('unexpected "aud" claim value', claim)
    tol_opt = opts.get("clockTolerance", UNDEF)
    if tol_opt is UNDEF:
        tol: float = 0
    elif isinstance(tol_opt, str):
        tol = J.secs(tol_opt)
    elif _isnum(tol_opt):
        tol = tol_opt
    else:
        raise TypeError("Invalid clockTolerance option type")
    now = math.floor(time.time()) if "currentDate" not in opts else J.epoch_of_ms(opts["currentDate"])
    if "iat" in payload and not _isnum(payload["iat"]):
        raise SetVerifyError('"iat" claim must be a number', claim)
    if "nbf" in payload:
        if not _isnum(payload["nbf"]):
            raise SetVerifyError('"nbf" claim must be a number', claim)
        if payload["nbf"] > now + tol:
            raise SetVerifyError('"nbf" claim timestamp check failed', claim)
    if "exp" in payload:
        if not _isnum(payload["exp"]):
            raise SetVerifyError('"exp" claim must be a number', claim)
        if payload["exp"] <= now - tol:
            raise SetVerifyError('"exp" claim timestamp check failed', "ERR_JWT_EXPIRED")
    return payload, header


def _parse_events(raw: Any) -> Dict[str, Any]:
    if not _isrec(raw):
        raise ValueError("SET invalid: `events` claim is missing or not a JSON object (RFC 8417 §2.2)")
    if not raw:
        raise ValueError("SET invalid: `events` claim is empty (RFC 8417 §2.2)")
    for k in _js_keys(raw):
        if not _isrec(raw[k]):
            raise ValueError("SET invalid: event payload for `%s` is not a JSON object (RFC 8417 §2.2)" % k)
    return raw


def verify_set(set_: Any, verify_key: Any, opts: Any = _DEFAULT) -> Dict[str, Any]:
    """Verify a SET (EdDSA; `verify_key` is the 32-byte public key) and parse it: {events, iss, jti, sub?, payload}.
    opts: issuer, audience, clockTolerance, currentDate (epoch ms), typ, requireTyp. Raises on any invalid token."""
    if opts is _DEFAULT:
        opts = {}
    if opts is None:
        raise TypeError("Cannot read properties of null (reading 'issuer')")
    J.assert_canonical_compact_jws(set_)
    typ = None if opts.get("requireTyp") is False else (opts.get("typ") if opts.get("typ") is not None else SET_TYP)
    payload, _ = _jose_verify(set_, verify_key, opts, typ)
    if not isinstance(payload.get("iss"), str):
        raise ValueError("SET invalid: missing or non-string `iss`")
    if not isinstance(payload.get("jti"), str):
        raise ValueError("SET invalid: missing or non-string `jti` (RFC 8417 §2.2 requires it)")
    events = _parse_events(payload.get("events"))
    out = {"events": events, "iss": payload["iss"], "jti": payload["jti"], "payload": payload}
    if isinstance(payload.get("sub"), str):
        out["sub"] = payload["sub"]
    return out


# ---- subscriber-side revocation state ---------------------------------------------------------------------------------------

class RevocationState:
    def __init__(self) -> None:
        self.revoked_grants: Dict[str, float] = {}
        self.killed_agents: Dict[str, float] = {}
        self.revoked_intent_ids: Optional[Dict[str, float]] = None


def create_revocation_state() -> RevocationState:
    return RevocationState()


def _record_max(m: Dict[str, float], key: str, ts: float) -> None:
    prev = m.get(key)
    if prev is None or ts > prev:
        m[key] = ts


def _ts(ev: Any) -> float:
    t = _prop(ev, "event_timestamp")
    return t if _isnum(t) else 0


def apply_set(state: RevocationState, parsed: Any) -> RevocationState:
    """Fold one verified SET into the state: monotone, each key keeps the max event_timestamp."""
    for typ, ev in _entries(_prop(parsed, "events")):
        if ev is UNDEF:
            continue
        ts = _ts(ev)
        if typ == EVENT_TYPES["grantRevoked"]:
            ref = _prop(ev, "grant_ref")
            if _str_ne(ref):
                _record_max(state.revoked_grants, ref, ts)
        elif typ == EVENT_TYPES["killSwitch"]:
            agent, ref = _prop(ev, "agent"), _prop(ev, "grant_ref")
            if _str_ne(agent):
                _record_max(state.killed_agents, agent, ts)
            if _str_ne(ref):
                _record_max(state.revoked_grants, ref, ts)
        elif typ == EVENT_TYPES["intentRevoked"]:
            ids = _prop(ev, "ids")
            if isinstance(ids, list):
                for i in ids:
                    if isinstance(i, str) and i.startswith("pca-intent:"):
                        if state.revoked_intent_ids is None:
                            state.revoked_intent_ids = {}
                        _record_max(state.revoked_intent_ids, i, ts)
    return state


def is_intent_revoked(state: RevocationState, id_: str) -> bool:
    return state.revoked_intent_ids is not None and id_ in state.revoked_intent_ids


def is_revoked(state: RevocationState, grant_ref: str, agent: Any = None) -> bool:
    if grant_ref in state.revoked_grants:
        return True
    return agent is not None and agent in state.killed_agents


def _set_timestamp(p: Any) -> float:
    m = math.inf
    for _, ev in _entries(_prop(p, "events")):
        if ev is not UNDEF:
            t = _prop(ev, "event_timestamp")
            if _isnum(t) and t < m:
                m = t
    return m if fin(m) else 0


def stream_processor(parsed_sets: Any, state: Optional[RevocationState] = None) -> RevocationState:
    """Fold verified SETs in event_timestamp order (stable), so delivery order cannot matter."""
    if not isinstance(parsed_sets, list):
        raise TypeError("parsedSets is not iterable")
    state = state if state is not None else create_revocation_state()
    keyed = [(_set_timestamp(p), p) for p in parsed_sets]
    for _, p in sorted(keyed, key=lambda kp: kp[0]):
        apply_set(state, p)
    return state


# ---- replay store, receiver -------------------------------------------------------------------------------------------------

class InMemorySetReplayStore:
    def __init__(self, max_entries: int) -> None:
        self._max = max_entries
        self._seen: Dict[str, float] = {}

    def add_if_absent(self, jti: str, expires_at_sec: float, now_sec: float) -> bool:
        if not (fin(now_sec) and fin(expires_at_sec)):
            return False  # a non-finite clock or expiry never records or releases an entry
        held = self._seen.get(jti)
        if held is not None and not (now_sec >= held):
            return False
        if held is None and len(self._seen) >= self._max:
            for k in [k for k, exp in self._seen.items() if now_sec >= exp]:
                del self._seen[k]
            if len(self._seen) >= self._max:
                raise RuntimeError("replay store is full")
        self._seen[jti] = expires_at_sec
        return True


def create_in_memory_set_replay_store(opts: Any = _DEFAULT) -> InMemorySetReplayStore:
    """Bounded single-process store: when full, a new jti raises (the receiver then refuses) instead of evicting a live entry."""
    if opts is _DEFAULT:
        opts = {}
    mx = _prop(opts, "maxEntries")
    mx = SET_INMEMORY_MAX_ENTRIES if mx is UNDEF or mx is None else mx
    if isinstance(mx, bool) or not _isnum(mx) or not fin(mx) or mx != math.floor(mx) or mx < 1:
        raise SignalsError("misconfigured", "maxEntries must be a positive integer")
    return InMemorySetReplayStore(int(mx))


def run_set_replay_store_conformance(make: Callable[[], Any]) -> List[str]:
    failures: List[str] = []

    def check(ok: bool, name: str) -> None:
        if not ok:
            failures.append(name)

    s = make()
    check(s.add_if_absent("a", 200, 100) is True, "first sight of a jti returns true")
    check(s.add_if_absent("a", 200, 101) is False, "second sight of the same jti returns false")
    check(s.add_if_absent("b", 200, 101) is True, "a different jti is independent")
    check(s.add_if_absent("a", 200, 199) is False, "still seen one second before expiry")
    t = make()
    t.add_if_absent("c", 200, 100)
    check(t.add_if_absent("c", 400, 200) is True, "an expired entry may be added again (nowSec >= expiresAtSec)")
    u = make()
    wins = sum(1 for _ in range(16) if u.add_if_absent("race", 200, 100))
    check(wins == 1, "16 concurrent adds of one jti: exactly one wins (got %d)" % wins)
    return failures


def _fails(code: str, reason: str) -> Dict[str, Any]:
    return {"ok": False, "code": code, "reason": reason}


def receive_set(set_: Any, verify_key: Any, opts: Any) -> Dict[str, Any]:
    """The recommended receive path: size cap, canonical spelling, signature, typ, iss, aud, iat window, atomic jti replay
    guard, then fold into the state. Every refusal is a value; a replay store that raises denies (the SET is not applied)."""
    store = _optprop(opts, "replayStore") if opts else UNDEF
    max_age = opts.get("maxAgeSec", UNDEF) if isinstance(opts, dict) else UNDEF
    if (not opts or opts.get("issuer", UNDEF) is UNDEF or opts.get("audience", UNDEF) is UNDEF
            or not callable(getattr(store, "add_if_absent", None)) or not J.truthy(opts.get("state"))
            or not _isnum(max_age) or not fin(max_age) or max_age <= 0):
        return _fails("misconfigured", "issuer, audience, replayStore, state and a positive maxAgeSec are all required")
    mb = opts.get("maxBytes")
    if not isinstance(set_, str) or len(set_.encode("utf-16-le", "surrogatepass")) // 2 > (16384 if mb is None else mb):
        return _fails("oversize", "SET is not a string or exceeds maxBytes")
    try:
        J.assert_canonical_compact_jws(set_)
    except J.CanonicalJwsError as e:
        return _fails("malformed", str(e))
    now = opts.get("nowSec")
    now = math.floor(time.time()) if now is None else now
    try:
        parsed = verify_set(set_, verify_key, {"issuer": opts["issuer"], "audience": opts["audience"], "currentDate": now * 1000})
    except Exception as e:  # noqa: BLE001 - every verification failure is a refusal value
        return _fails("verify_failed", str(e))
    iat = parsed["payload"].get("iat")
    if not _isnum(iat) or not fin(iat):
        return _fails("iat_missing", "SET has no numeric iat")
    skew = opts.get("clockSkewSec")
    skew = 60 if skew is None else skew
    if not (fin(now) and fin(skew) and iat <= now + skew):
        return _fails("iat_future", "SET iat is in the future")
    if not (now - iat <= max_age):
        return _fails("iat_stale", "SET is older than %ss" % J.js_num(max_age))
    plan = None
    if "standardRevocations" in opts and opts["standardRevocations"] is not None:
        try:
            plan = plan_standard_revocations(parsed, opts["standardRevocations"])
        except Exception as e:  # noqa: BLE001
            return _fails("unmapped_subject", str(e))
    try:
        fresh = opts["replayStore"].add_if_absent(parsed["jti"], iat + max_age + skew, now)
    except Exception as e:  # noqa: BLE001
        return _fails("replay_store_error", str(e))
    if fresh is not True:
        return _fails("replay", "jti '%s' has already been received" % parsed["jti"])
    apply_set(opts["state"], parsed)
    if plan is not None:
        for agent, ts in plan["agents"]:
            _record_max(opts["state"].killed_agents, agent, ts)
    return {"ok": True, "parsed": parsed}


# ---- standard (CAEP / RISC) revocation events -------------------------------------------------------------------------------

def _default_subject_to_agent(subject: Dict[str, Any]) -> Optional[str]:
    i = subject.get("id")
    return i if subject.get("format") == "opaque" and _str_ne(i) else None


def _is_revoking_standard_event(typ: str, ev: Any) -> bool:
    if typ == EVENT_TYPES["sessionRevoked"]:
        return True
    if typ == EVENT_TYPES["credentialChange"]:
        return _prop(ev, "change_type") != "create"  # unknown or absent counts as a change (fail closed)
    return typ in RISC_EVENT_TYPES.values()


def plan_standard_revocations(parsed: Any, opts: Any = None) -> Dict[str, Any]:
    """Decide, without touching any state, which agents the SET's CAEP / RISC revoking events revoke:
    {agents: [[agent, ts]], unmapped: [event types]}. opts: subjectToAgent (callable), failOnUnmapped."""
    opts = {} if opts is None else opts
    to_agent = opts.get("subjectToAgent") or _default_subject_to_agent
    plan: Dict[str, Any] = {"agents": [], "unmapped": []}
    sub_id = _prop(_prop(parsed, "payload"), "sub_id")
    set_subject = sub_id if _isrec(sub_id) else None
    for typ, ev in _entries(_prop(parsed, "events")):
        if ev is UNDEF or not _is_revoking_standard_event(typ, ev):
            continue
        ev_subject = _prop(ev, "subject")
        own = ev_subject if _isrec(ev_subject) else set_subject
        agent = None
        if own is not None and isinstance(own.get("format"), str):
            try:
                agent = to_agent(own)
            except Exception:  # noqa: BLE001 - a mapper that raises names no agent
                agent = None
        if not _str_ne(agent):
            if opts.get("failOnUnmapped") is True:
                raise SignalsError("unmapped_subject", "event '%s' names no mappable agent" % typ)
            plan["unmapped"].append(typ)
            continue
        plan["agents"].append([agent, _ts(ev)])
    return plan


def _assert_state(state: Any) -> None:
    if not isinstance(state, RevocationState):
        raise SignalsError("misconfigured", "state must come from createRevocationState()")


def apply_standard_revocations(state: Any, parsed: Any, opts: Any = None) -> Dict[str, Any]:
    _assert_state(state)
    plan = plan_standard_revocations(parsed, opts)
    for agent, ts in plan["agents"]:
        _record_max(state.killed_agents, agent, ts)
    return plan


# ---- authorize() adapters ---------------------------------------------------------------------------------------------------

def _leaf_holder_agent(ctx: Dict[str, Any]) -> Any:
    chain = _prop(_prop(ctx, "pcactn"), "cap_chain")
    if chain is UNDEF or chain is None:
        raise TypeError("Cannot read properties of undefined (reading 'length')")
    last = chain[-1] if isinstance(chain, list) and chain else None
    h = _optprop(last, "holder") if _isrec(last) else UNDEF
    return None if h is UNDEF else h


def _revocation_reason(state: RevocationState, pcactn: Any, grant: Any, agent_of: Callable[[Any], Any]) -> Optional[str]:
    try:
        ref = _prop(pcactn, "grant_ref")
        if not _str_ne(ref):
            return "grant_ref is missing"
        if ref in state.revoked_grants:
            return "grant revoked by signal"
        gid = _optprop(grant, "id")
        if isinstance(gid, str) and gid in state.revoked_grants:
            return "grant revoked by signal"
        agent = agent_of({"pcactn": pcactn, "grant": grant})
        if not _str_ne(agent):
            return "agent could not be determined"
        if agent in state.killed_agents:
            return "agent killed by signal"
        return None
    except Exception:  # noqa: BLE001
        return "revocation check error (fail closed)"


def create_revocation_hook(state: Any, opts: Any = None) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """A hook for authorize(): reads `state` live, always enforced; a revoked grant, a revoked or undeterminable agent, or
    any error denies. opts: agentOf (callable over {pcactn, grant}), default the leaf holder of the capability chain."""
    _assert_state(state)
    agent_of = (opts or {}).get("agentOf") or _leaf_holder_agent

    def hook(ctx: Dict[str, Any]) -> Dict[str, Any]:
        reason = _revocation_reason(state, _prop(ctx, "pcactn"), _prop(ctx, "grant"), agent_of)
        return {"enforced": True, "ok": True} if reason is None else {"enforced": True, "ok": False, "reason": reason}

    return hook


def create_is_revoked(state: Any, opts: Any = None) -> Callable[[Any, Any], bool]:
    _assert_state(state)
    agent_of = (opts or {}).get("agentOf") or _leaf_holder_agent
    return lambda grant, pcactn: _revocation_reason(state, pcactn, grant, agent_of) is not None


# ---- snapshot / restore -----------------------------------------------------------------------------------------------------

def snapshot_revocation_state(state: Any) -> Dict[str, Any]:
    _assert_state(state)
    return {"v": 1, "grants": [[k, v] for k, v in state.revoked_grants.items()],
            "agents": [[k, v] for k, v in state.killed_agents.items()],
            "intents": [[k, v] for k, v in (state.revoked_intent_ids or {}).items()]}


def _pairs(v: Any, what: str) -> List[Tuple[str, float]]:
    if not isinstance(v, list):
        raise SignalsError("bad_snapshot", "%s is not an array" % what)
    out = []
    for p in v:
        if not isinstance(p, list) or len(p) != 2 or not _str_ne(p[0]) or not _isnum(p[1]) or not fin(p[1]):
            raise SignalsError("bad_snapshot", "%s holds an entry that is not [string, number]" % what)
        out.append((p[0], p[1]))
    return out


def restore_revocation_state(snapshot: Any, into: Any = _DEFAULT) -> RevocationState:
    """Merge a snapshot into `into` (a fresh state by default). Strict: any shape error raises `bad_snapshot` and `into` is
    untouched. Monotone (max timestamp), so restoring never un-revokes."""
    if into is _DEFAULT:
        into = create_revocation_state()
    _assert_state(into)
    if not _isrec(snapshot) or isinstance(snapshot.get("v"), bool) or snapshot.get("v") != 1:
        raise SignalsError("bad_snapshot", "snapshot is not a version 1 object")
    extra = [k for k in _js_keys(snapshot) if k not in ("v", "grants", "agents", "intents")]
    if extra:
        raise SignalsError("bad_snapshot", "snapshot has unknown member '%s'" % extra[0])
    grants = _pairs(snapshot.get("grants"), "grants")
    agents = _pairs(snapshot.get("agents"), "agents")
    intents = _pairs(snapshot.get("intents"), "intents")
    for k, t in grants:
        _record_max(into.revoked_grants, k, t)
    for k, t in agents:
        _record_max(into.killed_agents, k, t)
    for k, t in intents:
        if into.revoked_intent_ids is None:
            into.revoked_intent_ids = {}
        _record_max(into.revoked_intent_ids, k, t)
    return into


# ---- SSF stream configuration and health ------------------------------------------------------------------------------------

_JS_WS = "\t\n\v\f\r    -     　﻿"
_HTTPS_URL = re.compile("https://[^" + _JS_WS + "]+")


def _https_url(v: Any) -> bool:
    return isinstance(v, str) and _HTTPS_URL.fullmatch(v) is not None


def validate_stream_config(c: Any) -> List[str]:
    """SSF 8.1.1 shape checks: the problems found (empty = valid)."""
    if not isinstance(c, dict):
        return ["not an object"]
    e: List[str] = []

    def strs(x: Any) -> bool:
        return isinstance(x, list) and all(_str_ne(i) for i in x)

    aud = c.get("aud")
    if not _str_ne(c.get("stream_id")):
        e.append("stream_id is required")
    if not _str_ne(c.get("iss")):
        e.append("iss is required")
    if not (_str_ne(aud) or (isinstance(aud, list) and len(aud) > 0 and all(_str_ne(i) for i in aud))):
        e.append("aud must be a non-empty string or array")
    delivered, supported = c.get("events_delivered"), c.get("events_supported")
    if not strs(delivered) or len(delivered) == 0:
        e.append("events_delivered must be a non-empty array of event type URIs")
    if "events_supported" in c and not strs(supported):
        e.append("events_supported must be an array of URIs")
    if "events_requested" in c and (not strs(c["events_requested"]) or len(c["events_requested"]) == 0):
        e.append("events_requested must be a non-empty array of URIs")
    if strs(delivered) and strs(supported) and not all(x in supported for x in delivered):
        e.append("events_delivered must be a subset of events_supported")
    d = c.get("delivery")
    if not J.truthy(d) or not isinstance(d, dict) or d.get("method") not in (DELIVERY_PUSH, DELIVERY_POLL):
        e.append("delivery.method must be the RFC 8935 or RFC 8936 URI")
    elif not _https_url(d.get("endpoint_url")):
        e.append("delivery.endpoint_url must be an https URL")
    if "min_verification_interval" in c and not _nonneg_safe_int(c["min_verification_interval"]):
        e.append("min_verification_interval must be a non-negative integer (seconds)")
    return e


class StreamHealth:
    """Receiver-side health of one stream. All times are epoch seconds passed in; a verification state is single use,
    expiring, and only valid if this tracker issued it."""

    def __init__(self, config: Dict[str, Any], options: Optional[Dict[str, Any]] = None) -> None:
        self.config = config
        self._o = options or {}
        self._status = "enabled"
        self._last_event: Optional[float] = None
        self._last_verified: Optional[float] = None
        self._last_requested: Optional[float] = None
        self._fails = 0
        self._rejected = 0
        self._pending: Dict[str, float] = {}

    def _opt(self, k: str, d: Any) -> Any:
        v = self._o.get(k)
        return d if v is None else v

    def set_status(self, s: Any) -> None:
        if not isinstance(s, str) or s not in STREAM_STATUSES:
            raise ValueError("unknown stream status")
        self._status = s

    def record_event(self, now_sec: float) -> None:
        self._last_event = max(0 if self._last_event is None else self._last_event, now_sec)

    def request_verification(self, now_sec: float) -> Optional[str]:
        if self._status != "enabled":
            return None
        if not fin(now_sec):
            return None
        mn = self.config.get("min_verification_interval")
        mn = 0 if mn is None else mn
        if self._last_requested is not None and not (now_sec - self._last_requested >= mn):
            return None
        self._expire(now_sec)
        if len(self._pending) >= self._opt("maxPending", 16):
            return None
        state = secrets.token_urlsafe(16)
        exp = now_sec + self._opt("verifyTimeoutSec", 60)
        if not fin(exp):
            return None  # a NaN or infinite timeout would leave the request pending forever
        self._pending[state] = exp
        self._last_requested = now_sec
        return state

    def ack_verification(self, state: Any, now_sec: float) -> bool:
        if not fin(now_sec):
            self._rejected += 1
            return False
        self._expire(now_sec)
        exp = self._pending.get(state) if isinstance(state, str) else None
        if exp is None:
            self._rejected += 1
            return False
        del self._pending[state]
        self._last_verified = now_sec
        self._last_event = max(0 if self._last_event is None else self._last_event, now_sec)
        self._fails = 0
        return True

    def _expire(self, now_sec: float) -> None:
        for k in [k for k, exp in self._pending.items() if now_sec > exp]:
            del self._pending[k]
            self._fails += 1

    def report(self, now_sec: float) -> Dict[str, Any]:
        self._expire(now_sec)
        reasons: List[str] = []
        within = self._opt("verifiedWithinSec", 300)
        if self._status == "disabled":
            state = "disabled"
            reasons.append("stream is disabled: no events are transmitted or held")
        elif self._status == "paused":
            state = "paused"
            reasons.append("stream is paused: events may be delayed")
        elif not (self._fails < self._opt("failAfter", 3)):
            state = "failing"
            reasons.append("%d consecutive verification requests timed out" % self._fails)
        elif self._last_verified is None:
            state = "unverified"
            reasons.append("no verification round trip has completed")
        elif not (fin(now_sec) and now_sec - self._last_verified <= within):
            state = "degraded"
            reasons.append("last verified %ss ago, over %ss" % (J.js_num(now_sec - self._last_verified), J.js_num(within)))
        else:
            state = "healthy"
        out: Dict[str, Any] = {"state": state, "status": self._status, "reasons": reasons,
                               "pending_verifications": len(self._pending),
                               "consecutive_verification_failures": self._fails, "rejected_verifications": self._rejected}
        if self._last_event is not None:
            out["last_event_at"] = self._last_event
        if self._last_verified is not None:
            out["last_verified_at"] = self._last_verified
        return out

    def revocation_fresh_within(self, max_age_sec: float, now_sec: float) -> bool:
        """May the verifier assume no pushed revocation was missed in the last `max_age_sec`? Only if the stream is enabled
        and a verified round trip completed inside that window; otherwise fall back to the signed epoch pull bound."""
        return self._status == "enabled" and self._last_verified is not None and fin(now_sec) and now_sec - self._last_verified <= max_age_sec


def handle_verification_request(streams: Dict[str, Dict[str, Any]], req: Any, now_sec: float, key: Any) -> Dict[str, Any]:
    """SSF 8.1.4.2: 404 unknown stream, 400 malformed, 429 inside min_verification_interval, else 204 plus the signed SET."""
    sid = req.get("stream_id", UNDEF) if isinstance(req, dict) else UNDEF
    state = req.get("state", UNDEF) if isinstance(req, dict) else UNDEF
    if not isinstance(sid, str) or (state is not UNDEF and not isinstance(state, str)):
        return {"status": 400, "error": "stream_id (string) is required; state must be a string"}
    s = streams.get(sid)
    if s is None:
        return {"status": 404, "error": "no such stream"}
    mn = s["config"].get("min_verification_interval")
    mn = 0 if mn is None else mn
    last = s.get("lastVerification")
    if last is not None and now_sec - last < mn:
        return {"status": 429, "error": "verification requested too soon"}
    s["lastVerification"] = now_sec
    cfg = s["config"]
    s_ev = {"state": state} if state is not UNDEF else {}
    return {"status": 204, "set": build_set({EVENT_TYPES["verification"]: s_ev}, cfg.get("iss"), cfg.get("aud"), key,
                                            subject=cfg.get("stream_id"))}


class PollQueue:
    """RFC 8936 transmitter queue: retains a SET until acknowledged, retransmits unacknowledged ones, records receiver errors."""

    def __init__(self) -> None:
        self._q: Dict[str, str] = {}
        self.errors: List[Dict[str, Any]] = []

    def enqueue(self, jti: str, set_: str) -> None:
        self._q[jti] = set_

    @property
    def depth(self) -> int:
        return len(self._q)

    def poll(self, req: Any) -> Dict[str, Any]:
        mx = _prop(req, "maxEvents")
        if mx is not UNDEF and not _nonneg_safe_int(mx):
            raise ValueError("maxEvents must be a non-negative integer")
        ack = _prop(req, "ack")
        for j in ([] if ack is UNDEF or ack is None else _iter(ack)):
            if isinstance(j, str):
                self._q.pop(j, None)
        errs = _prop(req, "setErrs")
        for jti, e in _entries({} if errs is UNDEF or errs is None else errs):
            if jti in self._q:
                del self._q[jti]
                rec: Dict[str, Any] = {"jti": jti}
                for k in ("err", "description"):
                    v = _prop(e, k)
                    if v is not UNDEF:
                        rec[k] = v
                self.errors.append(rec)
        limit = math.inf if mx is UNDEF or mx is None else mx
        sets: Dict[str, str] = {}
        n = 0
        for jti, s in self._q.items():
            if n >= limit:
                break
            sets[jti] = s
            n += 1
        out: Dict[str, Any] = {"sets": sets}
        if len(self._q) > n:
            out["moreAvailable"] = True
        return out


def _iter(x: Any) -> List[Any]:
    if isinstance(x, (list, str)):
        return list(x)
    raise TypeError("not iterable")


def push_response(r: Any) -> Dict[str, Any]:
    """RFC 8935 receiver status for a receive_set outcome: 202 on success, 400 + {err, description} otherwise."""
    ok = _prop(r, "ok")
    if ok is not UNDEF and J.truthy(ok):  # an absent member is undefined, which is falsy
        return {"status": 202}
    code = _prop(r, "code")
    if code == "verify_failed":
        err = "invalid_key"
    elif code in ("malformed", "oversize"):
        err = "invalid_request"
    elif code in ("misconfigured", "replay_store_error"):
        err = "access_denied"
    else:
        err = "invalid_request"
    body: Dict[str, Any] = {"err": err}
    reason = _prop(r, "reason")
    if reason is not UNDEF:
        body["description"] = reason
    return {"status": 400, "body": body}


def risk_level_change_set(args: Dict[str, Any]) -> str:
    return build_set({EVENT_TYPES["riskLevelChange"]: args["event"]}, args["issuer"], args["audience"], args["key"])


def assurance_level_change_set(args: Dict[str, Any]) -> str:
    """CAEP assurance-level-change; `change_direction` is derived when both levels are in `order`."""
    e = dict(args["event"])
    order = args.get("order")
    if e.get("previous_level", UNDEF) is not UNDEF and e.get("change_direction", UNDEF) is UNDEF and J.truthy(order):
        i = order.index(e["previous_level"]) if e["previous_level"] in order else -1
        j = order.index(e["current_level"]) if e.get("current_level") in order else -1
        if i >= 0 and j >= 0 and i != j:
            e["change_direction"] = "increase" if j > i else "decrease"
    return build_set({EVENT_TYPES["assuranceLevelChange"]: e}, args["issuer"], args["audience"], args["key"])


# ---- SSF stream management API ----------------------------------------------------------------------------------------------

class MemoryStreamStore:
    def __init__(self) -> None:
        self._m: Dict[str, Dict[str, Any]] = {}

    def get(self, id_: str) -> Optional[Dict[str, Any]]:
        r = self._m.get(id_)
        return copy.deepcopy(r) if r is not None else None

    def put(self, id_: str, r: Dict[str, Any]) -> None:
        self._m[id_] = copy.deepcopy(r)

    def delete(self, id_: str) -> None:
        self._m.pop(id_, None)

    def list_by_receiver(self, receiver: str) -> List[List[Any]]:
        return [[i, copy.deepcopy(r)] for i, r in self._m.items() if r.get("receiver") == receiver]


_ENDPOINTS = ["configuration", "status", "add_subject", "remove_subject", "verification"]
_RECEIVER_SUPPLIED = ["events_requested", "delivery", "description"]
_TRANSMITTER_SUPPLIED = ["stream_id", "iss", "aud", "events_supported", "events_delivered", "min_verification_interval"]


def _bad(m: str) -> Dict[str, Any]:
    return {"status": 400, "body": {"error": "invalid_request", "description": m}}


def _utf16_key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def _subject_key(s: Any) -> Optional[str]:
    if not _isrec(s) or not _str_ne(s.get("format")):
        return None
    try:
        ordered = sorted(s.keys(), key=_utf16_key)
        shaped = {k: s[k] for k in ordered}  # JS object semantics: array-index keys come first
        return "{" + ",".join(J.js_json(k) + ":" + J.js_json(shaped[k]) for k in _js_keys(shaped)) + "}"
    except Exception:  # noqa: BLE001
        return None


def _slice16(s: str, n: int) -> str:
    b = s.encode("utf-16-le", "surrogatepass")[: 2 * n]
    return b.decode("utf-16-le", "surrogatepass")


def transmitter_metadata(o: Dict[str, Any], base: str, jwks_uri: Optional[str] = None) -> Dict[str, Any]:
    """SSF 7.1 transmitter configuration metadata (served at /.well-known/ssf-configuration)."""
    dm = o.get("deliveryMethods")
    out: Dict[str, Any] = {"spec_version": "1_0", "issuer": o["issuer"]}
    if J.truthy(jwks_uri):
        out["jwks_uri"] = jwks_uri
    out["delivery_methods_supported"] = [DELIVERY_PUSH, DELIVERY_POLL] if dm is None else dm
    for k, p in (("configuration_endpoint", "configuration"), ("status_endpoint", "status"),
                 ("add_subject_endpoint", "add_subject"), ("remove_subject_endpoint", "remove_subject"),
                 ("verification_endpoint", "verification")):
        out[k] = "%s/ssf/%s" % (base, p)
    out["default_subjects"] = "NONE"
    return out


def ssf_management_handler(o: Dict[str, Any], authenticate: Callable[[Any], Any]) -> Callable[[Any], Dict[str, Any]]:
    """Framework-neutral SSF 8.1 stream management: {method, path, query, body} in, {status, body} out. `authenticate` returns
    the receiver {id, aud} or None (401). A stream belongs to one receiver; anyone else sees 404, never 403.
    Options o: store, issuer, eventsSupported, pollEndpoint(stream_id), signingKey (32-byte seed), deliver(stream, set),
    now(), and optionally deliveryMethods, maxStreamsPerReceiver, maxSubjectsPerStream, newId()."""
    methods = o["deliveryMethods"] if o.get("deliveryMethods") is not None else [DELIVERY_PUSH, DELIVERY_POLL]
    new_id = o.get("newId") or (lambda: secrets.token_urlsafe(12))
    mx = o.get("maxStreamsPerReceiver")
    max_streams = 1 if mx is None else mx
    store = o["store"]
    supported = o["eventsSupported"]

    def own(rcv: Dict[str, Any], id_: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(id_, str):
            return None
        r = store.get(id_)
        return r if r and r.get("receiver") == rcv.get("id") else None

    def delivered(requested: Optional[List[str]]) -> List[str]:
        return list(supported) if requested is None else [e for e in supported if e in requested]

    def requested_ok(v: Any) -> bool:
        return isinstance(v, list) and len(v) > 0 and all(_str_ne(e) for e in v)

    def delivery_for(id_: str, d: Any) -> Tuple[bool, Any]:
        if d is UNDEF:
            if DELIVERY_POLL not in methods:
                return False, "delivery is required: this transmitter does not support poll"
            return True, {"method": DELIVERY_POLL, "endpoint_url": o["pollEndpoint"](id_)}
        if not _isrec(d) or not isinstance(d.get("method"), str) or d["method"] not in methods:
            return False, "delivery.method is not supported by this transmitter"
        if d["method"] == DELIVERY_POLL:
            return True, {"method": DELIVERY_POLL, "endpoint_url": o["pollEndpoint"](id_)}
        if not _https_url(d.get("endpoint_url")):
            return False, "push delivery needs an https endpoint_url"
        return True, {"method": DELIVERY_PUSH, "endpoint_url": d["endpoint_url"]}

    def build(id_: str, rcv: Dict[str, Any], requested: Any, delivery: Any, description: Any) -> Dict[str, Any]:
        cfg = {"stream_id": id_, "iss": o["issuer"], "aud": rcv.get("aud"), "events_supported": list(supported),
               "events_delivered": delivered(requested), "delivery": delivery}
        if description is not None:
            cfg["description"] = _slice16(description, 256)
        return cfg

    nf = {"status": 404, "body": {"error": "not_found"}}
    na = {"status": 405, "body": {"error": "method_not_allowed"}}

    def route(req: Any, rcv: Dict[str, Any]) -> Dict[str, Any]:
        path = _prop(req, "path")
        if not isinstance(path, str):
            raise TypeError("path.split is not a function")
        segs = [x for x in path.split("/") if x]
        seg = segs[-1] if segs else ""
        q = _prop(req, "query")
        q = {} if q is UNDEF or q is None else q
        body = _prop(req, "body")
        b = body if _isrec(body) else None
        method = _prop(req, "method")
        if not isinstance(method, str):
            raise TypeError("toUpperCase is not a function")
        m = method.upper()
        if seg not in _ENDPOINTS:
            return {"status": 404, "body": {"error": "not_found"}}
        qsid = _prop(q, "stream_id")

        if seg == "configuration":
            if m == "POST":
                if b is None:
                    return _bad("a JSON object body is required")
                for k in _js_keys(b):
                    if k not in _RECEIVER_SUPPLIED:
                        return _bad("'%s' is not a receiver-supplied member" % k)
                er = b.get("events_requested", UNDEF)
                if er is not UNDEF and not requested_ok(er):
                    return _bad("events_requested must be a non-empty array of event type URIs")
                if "description" in b and not isinstance(b["description"], str):
                    return _bad("description must be a string")
                if len(store.list_by_receiver(rcv.get("id"))) >= max_streams:
                    return {"status": 409, "body": {"error": "conflict",
                                                     "description": "this receiver already has the maximum number of streams"}}
                id_ = new_id()
                ok, d = delivery_for(id_, b.get("delivery", UNDEF))
                if not ok:
                    return _bad(d)
                req_ev = None if er is UNDEF else er
                if len(delivered(req_ev)) == 0:
                    return _bad("none of events_requested is supported by this transmitter")
                config = build(id_, rcv, req_ev, d, b.get("description"))
                problems = validate_stream_config(config)
                if problems:
                    return _bad("; ".join(problems))
                rec = {"receiver": rcv.get("id"), "config": config}
                if J.truthy(er) and er is not UNDEF:
                    rec["events_requested"] = er
                rec["status"] = "enabled"
                rec["subjects"] = {}
                store.put(id_, rec)
                return {"status": 201, "body": config}
            if m == "GET":
                if qsid is UNDEF:
                    return {"status": 200, "body": [r["config"] for _, r in store.list_by_receiver(rcv.get("id"))]}
                s = own(rcv, qsid)
                return {"status": 200, "body": s["config"]} if s else nf
            if m in ("PATCH", "PUT"):
                if b is None:
                    return _bad("a JSON object body is required")
                s = own(rcv, b.get("stream_id"))
                if not isinstance(b.get("stream_id"), str):
                    return _bad("stream_id is required")
                if not s:
                    return nf
                for k in _js_keys(b):
                    if k not in _RECEIVER_SUPPLIED and k not in _TRANSMITTER_SUPPLIED:
                        return _bad("unknown member '%s'" % k)
                for k in _TRANSMITTER_SUPPLIED:
                    if k not in b:
                        continue
                    exp = s["config"].get(k, UNDEF)
                    if J.js_json(b[k]) != (None if exp is UNDEF else J.js_json(exp)):
                        return _bad("'%s' is transmitter-supplied and does not match" % k)
                er = b.get("events_requested", UNDEF)
                if er is not UNDEF and not requested_ok(er):
                    return _bad("events_requested must be a non-empty array of event type URIs")
                if "description" in b and not isinstance(b["description"], str):
                    return _bad("description must be a string")
                delivery = s["config"]["delivery"]
                if "delivery" in b or m == "PUT":
                    ok, d = delivery_for(s["config"]["stream_id"], b.get("delivery", UNDEF))
                    if not ok:
                        return _bad(d)
                    if d["method"] != s["config"]["delivery"]["method"]:
                        return _bad("delivery.method cannot be changed: create a new stream")
                    delivery = d
                if m == "PUT":
                    requested = None if er is UNDEF else er
                    description = b.get("description")
                else:
                    requested = er if er is not UNDEF else s.get("events_requested")
                    description = b["description"] if "description" in b else s["config"].get("description")
                if len(delivered(requested)) == 0:
                    return _bad("none of events_requested is supported by this transmitter")
                nxt = build(s["config"]["stream_id"], rcv, requested, delivery, description)
                if s["config"].get("min_verification_interval") is not None or "min_verification_interval" in s["config"]:
                    nxt["min_verification_interval"] = s["config"]["min_verification_interval"]
                s["config"] = nxt
                if requested:
                    s["events_requested"] = requested
                else:
                    s.pop("events_requested", None)
                store.put(nxt["stream_id"], s)
                return {"status": 200, "body": nxt}
            if m == "DELETE":
                s = own(rcv, qsid)
                if not s:
                    return nf
                store.delete(qsid)
                return {"status": 204}
            return na

        if seg == "status":
            if m == "GET":
                s = own(rcv, qsid)
                if not s:
                    return _bad("stream_id is required") if qsid is UNDEF else nf
                out = {"stream_id": qsid, "status": s["status"]}
                if s.get("status_reason") is not None:
                    out["reason"] = s["status_reason"]
                return {"status": 200, "body": out}
            if m == "POST":
                if b is None or not isinstance(b.get("stream_id"), str):
                    return _bad("stream_id is required")
                if not isinstance(b.get("status"), str) or b["status"] not in STREAM_STATUSES:
                    return _bad("status must be 'enabled', 'paused' or 'disabled'")
                if "reason" in b and not isinstance(b["reason"], str):
                    return _bad("reason must be a string")
                s = own(rcv, b["stream_id"])
                if not s:
                    return nf
                s["status"] = b["status"]
                if "reason" in b:
                    s["status_reason"] = b["reason"]
                else:
                    s.pop("status_reason", None)
                store.put(b["stream_id"], s)
                out = {"stream_id": b["stream_id"], "status": s["status"]}
                if s.get("status_reason") is not None:
                    out["reason"] = s["status_reason"]
                return {"status": 200, "body": out}
            return na

        if seg in ("add_subject", "remove_subject"):
            if m != "POST":
                return na
            if b is None or not isinstance(b.get("stream_id"), str):
                return _bad("stream_id is required")
            key = _subject_key(b.get("subject"))
            if key is None:
                return _bad("subject must be a Subject Identifier object with a format")
            if "verified" in b and not isinstance(b["verified"], bool):
                return _bad("verified must be a boolean")
            s = own(rcv, b["stream_id"])
            if not s:
                return nf
            if seg == "add_subject":
                cap = o.get("maxSubjectsPerStream")
                if key not in s["subjects"] and len(s["subjects"]) >= (10_000 if cap is None else cap):
                    return {"status": 429, "body": {"error": "too_many_requests", "description": "subject limit reached"}}
                s["subjects"][key] = b["verified"] if "verified" in b else True
                store.put(b["stream_id"], s)
                return {"status": 200}
            s["subjects"].pop(key, None)
            store.put(b["stream_id"], s)
            return {"status": 204}

        if m != "POST":
            return na
        if b is None:
            return _bad("a JSON object body is required")
        s = own(rcv, b.get("stream_id"))
        if not s:
            return nf if isinstance(b.get("stream_id"), str) else _bad("stream_id is required")
        if s["status"] == "disabled":
            return _bad("the stream is disabled")
        entry: Dict[str, Any] = {"config": s["config"]}
        if s.get("lastVerification") is not None:
            entry["lastVerification"] = s["lastVerification"]
        vreq = {"stream_id": b["stream_id"]}
        if "state" in b:
            vreq["state"] = b["state"]
        out = handle_verification_request({s["config"]["stream_id"]: entry}, vreq, o["now"](), o["signingKey"])
        if out["status"] != 204:
            return {"status": out["status"], "body": {"error": "too_many_requests" if out["status"] == 429 else "invalid_request",
                                                       "description": out["error"]}}
        s["lastVerification"] = o["now"]()
        store.put(s["config"]["stream_id"], s)
        o["deliver"](s, out["set"])
        return {"status": 204}

    def handler(req: Any) -> Dict[str, Any]:
        try:
            rcv = authenticate(req)
            if not rcv:
                return {"status": 401, "body": {"error": "unauthenticated"}}
            return route(req, rcv)
        except Exception:  # noqa: BLE001 - a handler never leaks an exception
            return {"status": 500, "body": {"error": "server_error"}}

    return handler
