"""Proof-Carrying Authority gateway: the decision logic of a deny-by-default enforcement point, as pure functions over request
dicts. Port of the TypeScript reference (@atlasauth/pca-gateway).

A request is {method, path, query?, authority?, bodySha256?, body?, headers}. The proof travels as the `PCA-Action` header; the
gateway's own audience and a route -> capability map are configured once. Every step denies by default. The Envoy HTTP and gRPC
ext_authz shapes and the AWS Lambda authorizers are plain functions over event dicts; `gateway_proxy` joins a gateway to an injected
upstream callable. `cloudflare_worker` is the runtime-free logic of the Worker adapter (request, next and respond are injected).

Nothing here authorizes on its own: it extracts the proof, verifies it with the fail-closed offline core, checks the capability the
route maps to, and maps that onto the gateway's contract. Hooks other than `revocation` (attestation / threshold / zk) and the
attestation enforcement gate are not supported by the Python core and are refused at construction.
"""
from __future__ import annotations

import copy
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .authorize import AuthorizeOptions
from .pca import (ARTIFACT_SIZE_REASON, artifact_too_large, decode_pca_header, params_digest, strict_parse,
                  verify_pcactn_core)
from .sdjwt_jws import js_json, js_to_string

PCA_HEADER = "PCA-Action"
PCA_INJECTED_HEADERS = ("x-pca-verdict", "x-pca-verb", "x-pca-grant")
DEFAULT_REQUIRE_CHECKS = ("revocation",)

#: what presented_provenance returns when the request presents none (JSON null is a presented, malformed bundle)
ABSENT: Any = type("Absent", (), {"__repr__": lambda self: "ABSENT"})()

_U: Any = object()


# ---------------------------------------------------------------------------------------------------- JS helpers
def _g(o: Any, k: str) -> Any:
    return o.get(k) if isinstance(o, dict) else None


def _jt(v: Any) -> bool:
    """JavaScript truthiness for JSON values (an empty object or array is truthy)."""
    if v is None or v is False or v == "":
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v == v and v != 0
    return True


def _u16be(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def _err(e: BaseException) -> str:
    return str(e)


# ---------------------------------------------------------------------------------------------------- configuration
@dataclass
class GatewayOptions:
    """Gateway configuration (see the TypeScript reference for each field).

    ``routes``  first matching rule wins: ``{"method"?, "path", "capability": {"verb", "resource"?}}``.
    ``resolve_grant``  ``(grant_ref, pcactn) -> grant | None``.
    ``replay_guard``  an object with ``claim(key, expires_at_ms, now_ms)`` (see :func:`memory_replay_guard`).
    ``bind_request``  None: bind method, path, query and (when supplied) the body hash; ``False``: off; or ``{"authority"?, "body"?}``.
    ``hooks``  ``{"revocation": (ctx) -> {"enforced", "ok"?, "reason"?}}`` with ctx ``{"pcactn", "grant", "nowEpoch"}``.
    ``enforce``  ``{"freshness"?, "taint"?}`` forwarded to the core verifier.
    ``check_proof``  ``(ctx) -> bool | {"allow", "reason"?}``; ctx ``{"pcactn", "grant", "verdict", "request", "required"?}``.
    ``policy``  REQUIRED: ``{"mode": "signature-only"}`` or ``{"mode": "full", "params": "body" | (req) -> dict | None,
    "state_store", "is_revoked", ...}`` (the other keys are :class:`atlas_pca.authorize.AuthorizeOptions` fields, plus ``k1``
    and ``provenance_log``)."""

    audience: str = ""
    routes: List[dict] = field(default_factory=list)
    resolve_grant: Optional[Callable[..., Any]] = None
    authorized_plan_roots: Optional[List[str]] = None
    insecure_skip_plan_root_check: bool = False
    unmatched_route: Optional[str] = None
    replay_guard: Any = None
    bind_request: Any = None
    hooks: Optional[dict] = None
    enforce: Optional[dict] = None
    require_checks: Optional[List[str]] = None
    check_proof: Optional[Callable[[dict], Any]] = None
    path_policy: Optional[str] = None
    now: Optional[Callable[[], Any]] = None
    realm: Optional[str] = None
    policy: Any = None


# ---------------------------------------------------------------------------------------------------- canonical query / binding
def _decode_uri_component(s: str) -> str:
    """JavaScript decodeURIComponent: a '%' without two hex digits, or bytes that are not UTF-8, raise ValueError."""
    def run(m: "re.Match[str]") -> str:
        try:
            return bytes(int(h, 16) for h in re.findall(r"%([0-9a-fA-F]{2})", m.group(0))).decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("URI malformed") from None

    if re.search(r"%(?![0-9a-fA-F]{2})", s):
        raise ValueError("URI malformed")
    return re.sub(r"(?:%[0-9a-fA-F]{2})+", run, s)


def canonical_query(query: Optional[str]) -> str:
    """Strip a leading '?', drop empty pairs, sort the raw pairs (UTF-16 code unit order) and join with '&'. Raises ValueError on
    a query that is ambiguous across upstream parsers: a repeated parameter name (percent-decoded, '+' as space, case-insensitive),
    a ';' separator, or a malformed percent escape in a name (the gateway turns it into a request-mismatch deny)."""
    if query is None:
        return ""
    q = query[1:] if query.startswith("?") else query
    if ";" in q:
        raise ValueError("query contains ';' (parsers disagree on it as a separator)")
    pairs = [x for x in q.split("&") if x != ""]
    seen = set()
    for pair in pairs:
        eq = pair.find("=")
        raw_key = pair if eq < 0 else pair[:eq]
        try:
            key = _decode_uri_component(raw_key.replace("+", " ")).lower()
        except ValueError:
            raise ValueError("query parameter name has a malformed percent escape") from None
        if key in seen:
            raise ValueError("duplicate query parameter '%s'" % key)
        seen.add(key)
    return "&".join(sorted(pairs, key=_u16be))


def request_binding(req: dict, opts: Optional[dict] = None) -> Dict[str, Any]:
    """The canonical binding of a request an agent signs as its action params: upper-cased method, path, canonical query and
    optionally the authority and body hash."""
    opts = opts or {}
    sha = _g(req, "bodySha256")
    if sha is None:
        sha = _g(req, "body_sha256")
    b: Dict[str, Any] = {"v": 2, "method": req["method"].upper(), "path": req["path"], "query": canonical_query(_g(req, "query"))}
    if _jt(opts.get("authority")):
        b["authority"] = (_g(req, "authority") or "").lower()
    body = opts["body"] if "body" in opts else _U
    if body is True or (body is _U and sha is not None):
        b["body_sha256"] = (sha if sha is not None else "").lower()
    return b


def bind_params(params: dict, binding: Optional[dict] = None) -> dict:
    """The params an agent signs for a full-policy gateway: the params plus the request binding as a `binding` member."""
    if binding is None:
        return params
    if "binding" in params:
        raise ValueError("params already have a 'binding' member")
    return dict(params, binding=binding)


def ambiguous_path_reason(path: str) -> Optional[str]:
    """Why `path` is ambiguous for route matching (the upstream may route a different path), or None when canonical."""
    if re.search(r"[\u0000-\u001f\u007f\\]", path):
        return "control character or backslash in path"
    if "//" in path:
        return "repeated slash in path"
    if ";" in path:
        return "path parameter (;) in path"
    if any(seg in (".", "..") for seg in path.split("/")):
        return "dot segment in path"
    for m in re.finditer(r"%([0-9a-fA-F]{2})", path):
        code = int(m.group(1), 16)
        ch = chr(code)
        if code < 0x20 or code == 0x7F:
            return "percent-encoded control character in path"
        if ch in ("/", "\\"):
            return "percent-encoded slash in path"
        if ch == ";":
            return "percent-encoded path parameter delimiter in path"
        if re.fullmatch(r"[A-Za-z0-9\-._~]", ch):
            return "non-canonical percent-encoding in path"
    if re.search(r"%(?![0-9a-fA-F]{2})", path):
        return "malformed percent-encoding in path"
    return None


# ---------------------------------------------------------------------------------------------------- replay guard / provenance log
class MemoryReplayGuard:
    """In-process single-use store. State is per process: use a shared store for more than one instance. A claim stays live
    through its expiry inclusive. Fails closed (raises) when `max_entries` unexpired claims are held."""

    def __init__(self, max_entries: int = 100_000, now: Optional[Callable[[], Any]] = None) -> None:
        self._seen: Dict[str, Any] = {}
        self._max = max_entries
        self._now = now or (lambda: int(time.time() * 1000))

    def claim(self, key: str, expires_at_ms: Any, now_ms: Any = None) -> bool:
        t = now_ms if now_ms is not None else self._now()
        if len(self._seen) >= self._max:
            for k, exp in list(self._seen.items()):
                if exp < t:
                    del self._seen[k]
            if len(self._seen) >= self._max:
                raise RuntimeError("replay guard full")
        existing = self._seen.get(key)
        if existing is not None and existing >= t:
            return False
        self._seen[key] = expires_at_ms
        return True


def memory_replay_guard(max_entries: int = 100_000, now: Optional[Callable[[], Any]] = None) -> MemoryReplayGuard:
    return MemoryReplayGuard(max_entries, now)


def _same(a: Any, b: Any) -> bool:
    """JavaScript `===` over JSON values (objects by identity, no bool/number mixing)."""
    if a is _U or b is _U:
        return a is b
    if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
        return a is b
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return type(a) is type(b) and a == b


class MemoryProvenanceLog:
    """The gateway's per-session record of untrusted content it relayed: at most `max_sessions` sessions (oldest dropped first),
    256 observations each."""

    def __init__(self, max_sessions: int = 10_000) -> None:
        self._m: Dict[str, List[dict]] = {}
        self._max = max_sessions

    def seen(self, session: str) -> List[dict]:
        return [dict(x) for x in self._m.get(session, [])]

    def add(self, session: str, o: dict) -> None:
        cur = self._m.pop(session, [])
        origin, source = _g(o, "origin") if "origin" in o else _U, _g(o, "source") if "source" in o else _U
        if not any(_same(x.get("origin", _U), origin) and _same(x.get("source", _U), source) for x in cur) and len(cur) < 256:
            cur.append({k: v for k, v in (("origin", origin), ("source", source)) if v is not _U})
        self._m[session] = cur
        while len(self._m) > self._max:
            del self._m[next(iter(self._m))]


def memory_provenance_log(max_sessions: int = 10_000) -> MemoryProvenanceLog:
    return MemoryProvenanceLog(max_sessions)


# ---------------------------------------------------------------------------------------------------- headers / extraction
def get_header(headers: Any, name: str) -> Any:
    """Case-insensitive single-value lookup over a header map: the first key that matches; a list reads as its first element."""
    if not isinstance(headers, dict):
        return None
    lower = name.lower()
    for key, v in headers.items():
        if not isinstance(key, str) or key.lower() != lower:
            continue
        if isinstance(v, list):
            return v[0] if v else None
        return v
    return None


def decode_pcactn(text: str) -> dict:
    if artifact_too_large(text):  # FIRST: before any parsing
        raise ValueError(ARTIFACT_SIZE_REASON)
    v = strict_parse(text)
    if not isinstance(v, dict):
        raise TypeError("decodePCActn: not an object")
    return v


def _extract_pcactn(headers: Any) -> dict:
    raw = get_header(headers, PCA_HEADER)
    if raw is None or raw == "":
        return {"code": "no-proof", "reason": "no %s header" % PCA_HEADER}
    try:
        return {"pcactn": decode_pcactn(decode_pca_header(raw))}
    except Exception as e:  # noqa: BLE001 - undecodable is a deny
        return {"code": "invalid-proof", "reason": "undecodable %s header: %s" % (PCA_HEADER, _err(e))}


def _body_object(req: dict) -> Any:
    body = _g(req, "body")
    if isinstance(body, str) and len(body) > 0:
        try:
            b = strict_parse(body)
        except Exception:  # noqa: BLE001 - not JSON: no body form
            return None
        return b if isinstance(b, dict) else None
    return None


def _params_is_fn(policy: Any) -> bool:
    return callable(_g(policy, "params"))


def presented_provenance(req: dict, policy: dict) -> Any:
    """The provenance bundle a request presents: header `PCA-Provenance` (strict base64url JSON), else body member
    `pca_provenance` when the body is not the signed params. ABSENT when none; None when presented but unreadable."""
    try:
        h = get_header(_g(req, "headers"), "pca-provenance")
        if h is not None and h != "":
            return strict_parse(decode_pca_header(h))
    except Exception:  # noqa: BLE001 - presented but malformed: the gate denies it
        return None
    if _params_is_fn(policy):
        b = _body_object(req)
        if b is not None and "pca_provenance" in b:
            return b["pca_provenance"]
    return ABSENT


def presented_artifacts(req: dict, policy: dict) -> Dict[str, Any]:
    """The discharges and narrow block a request presents (headers, then body members when the body is not the signed params)."""
    out: Dict[str, Any] = {}
    headers = _g(req, "headers")
    try:
        d = get_header(headers, "pca-discharges")
        if d is not None and d != "":
            arr = strict_parse(decode_pca_header(d))
            if isinstance(arr, list):
                out["discharges"] = arr
    except Exception:  # noqa: BLE001 - unreadable: no discharges
        pass
    try:
        n = get_header(headers, "pca-narrow")
        if n is not None and n != "":
            out["narrow"] = strict_parse(decode_pca_header(n))
    except Exception:  # noqa: BLE001 - unreadable: no narrow block
        pass
    if _params_is_fn(policy):
        b = _body_object(req)
        if b is not None:
            if "discharges" not in out and isinstance(b.get("pca_discharges"), list):
                out["discharges"] = b["pca_discharges"]
            if "narrow" not in out and "pca_narrow" in b:
                out["narrow"] = b["pca_narrow"]
    return out


# ---------------------------------------------------------------------------------------------------- routes / decisions
def _match_method(rule: dict, method: str) -> bool:
    m = rule.get("method")
    if m is None or m == "*" or m.upper() == "ANY":
        return True
    return m.upper() == method.upper()


def _match_path(pattern: str, path: str) -> bool:
    if pattern in ("*", "/*"):
        return True
    if pattern.endswith("/*"):
        prefix = pattern[:-2]
        return path == prefix or path.startswith(prefix + "/")
    if pattern.endswith("*"):
        return path.startswith(pattern[:-1])
    return path == pattern


def _match_route(routes: List[dict], method: str, path: str) -> Optional[dict]:
    for r in routes:
        if _match_method(r, method) and _match_path(r["path"], path):
            return r
    return None


_ERROR_TOKEN = {
    "no-proof": "missing_proof", "invalid-proof": "invalid_proof", "unknown-grant": "invalid_proof",
    "verify-failed": "invalid_proof", "wrong-audience": "invalid_resource", "insufficient-capability": "insufficient_capability",
    "unmapped-route": "access_denied", "invalid-path": "invalid_request", "replayed-proof": "replayed_proof",
    "replay-guard-unavailable": "temporarily_unavailable", "request-mismatch": "proof_not_bound_to_request",
    "proof-rejected": "access_denied",
}


def _deny(code: str, status: int, reason: str, realm: str, **extra: Any) -> Dict[str, Any]:
    return dict({"allow": False, "status": status, "code": code, "reason": reason,
                 "headers": {"www-authenticate": 'PCA realm="%s", error="%s"' % (realm, _ERROR_TOKEN[code])}},
                **{k: v for k, v in extra.items() if v is not None})


def _allow(reason: str, **extra: Any) -> Dict[str, Any]:
    extra = {k: v for k, v in extra.items() if v is not None}
    headers: Dict[str, str] = {}
    if extra.get("verdict"):
        headers["x-pca-verdict"] = js_json(extra["verdict"])
    if extra.get("pcactn"):
        headers["x-pca-verb"] = extra["pcactn"]["action"]["verb"]
        headers["x-pca-grant"] = extra["pcactn"]["grant_ref"]
    return dict({"allow": True, "status": 200, "code": "allow", "reason": reason, "headers": headers}, **extra)


def _policy_mode(opts: GatewayOptions) -> Any:
    return _g(opts.policy, "mode")


def _missing_text(opts: GatewayOptions, missing: List[str]) -> str:
    mode = _policy_mode(opts)
    return "%s is missing %s" % ("the gateway" if mode is None or mode == "signature-only" else "full policy mode", ", ".join(missing))


def _missing_policy(opts: GatewayOptions) -> List[str]:
    p = opts.policy
    if p is None:
        return ["policy ({ mode: 'full', params, state, isRevoked } or an explicit { mode: 'signature-only' })"]
    mode = _g(p, "mode")
    if mode == "signature-only":
        m: List[str] = []
        if opts.replay_guard is None:
            m.append("replayGuard (signature-only mode needs a single-use guard)")
        rc = DEFAULT_REQUIRE_CHECKS if opts.require_checks is None else opts.require_checks
        if "revocation" in rc and not callable(_g(opts.hooks, "revocation")):
            m.append("hooks.revocation (required by the default requireChecks ['revocation']; pass requireChecks: [] to waive)")
        return m
    if mode != "full":
        return ["a known policy mode (got '%s')" % js_to_string(mode)]
    missing: List[str] = []
    if not isinstance(opts.audience, str) or opts.audience == "":
        missing.append("audience")
    if not callable(opts.resolve_grant):
        missing.append("resolveGrant")
    store = p.get("state_store")
    if store is None or not callable(getattr(store, "claim", None)):
        missing.append("state")
    if not callable(p.get("is_revoked")):
        missing.append("isRevoked")
    if store is not None and callable(getattr(store, "claim", None)) and not (
            callable(getattr(store, "budget", None)) and callable(getattr(store, "claim_budget", None))):
        missing.append("state.claim_budget (the trust budget is decided and debited with the replay claim)")
    if p.get("params") != "body" and not callable(p.get("params")):
        missing.append("params ('body' or a function)")
    return missing


def _signed_params(req: dict, policy: dict, bind: Any) -> Dict[str, Any]:
    """Full-policy mode: the params the agent must have signed for this request ({"params"} or {"error"})."""
    if policy["params"] == "body":
        body = _g(req, "body")
        if not isinstance(body, str):
            return {"error": "full policy mode reads the params from the body, and the request carries none"}
        try:
            params = strict_parse(body)
        except Exception as e:  # noqa: BLE001
            return {"error": "the body is not strict JSON: %s" % _err(e)}
    else:
        params = policy["params"](req)
    if not isinstance(params, dict):
        return {"error": "the request params are not a JSON object"}
    if bind is False:
        return {"params": params}
    b = bind or {}
    if "binding" in params:
        return {"error": "the request params carry a 'binding' member (reserved for the request binding)"}
    if (_jt(b.get("authority")) and not _jt(_g(req, "authority"))) or (b.get("body") is True and not _jt(_g(req, "bodySha256"))):
        return {"error": "request lacks an attribute the proof must bind (authority / body hash)"}
    try:
        # the params carry the body, so its hash is bound only when asked for explicitly (bind_request body: True)
        binding = request_binding(req, dict(({"authority": True} if _jt(b.get("authority")) else {}), body=b.get("body") is True))
        return {"params": dict(params, binding=binding)}
    except Exception as e:  # noqa: BLE001
        return {"error": "the request cannot be bound: %s" % _err(e)}


# ---------------------------------------------------------------------------------------------------- core verification
def _statuses(v: Any, revocation: str, enforce: dict) -> Dict[str, str]:
    """The core verdict's checks in the reference vocabulary: pass / fail / not-enforced."""
    st: Dict[str, str] = {}
    for k, ok in v.checks.items():
        st["cap_chain" if k == "chain" else k] = "pass" if ok else "fail"
    for k in v.not_enforced:
        st[k] = "not-enforced"
    st["attestation"] = "not-enforced"
    st["threshold"] = "not-enforced"
    st["revocation"] = revocation
    if "taint_gate" not in st:
        st["taint_gate"] = "not-enforced"
    return st


def _verify(pcactn: dict, grant: dict, opts: GatewayOptions, now: Any) -> Dict[str, Any]:
    kw: Dict[str, Any] = {}
    if opts.authorized_plan_roots is not None:
        kw["authorized_plan_roots"] = list(opts.authorized_plan_roots)
    if opts.insecure_skip_plan_root_check is True:
        kw["insecure_skip_plan_root_check"] = True
    enf = opts.enforce or {}
    if "freshness" in enf:
        kw["enforce_freshness"] = enf["freshness"]
    if "taint" in enf:
        kw["enforce_taint"] = enf["taint"]
    v = verify_pcactn_core(pcactn, grant, now=now, audience=opts.audience, **kw)
    allow = bool(v.allow)
    reason = v.reason
    revocation = "not-enforced"
    hook = _g(opts.hooks, "revocation")
    if hook is not None and v.checks.get("wire"):
        try:
            res = hook({"pcactn": pcactn, "grant": grant, "nowEpoch": now})
            enforced, ok = bool(_g(res, "enforced")), bool(_g(res, "ok"))
            if not enforced:
                revocation = "not-enforced"
            elif ok:
                revocation = "pass"
            else:
                revocation = "fail"
                if allow or reason is None:
                    rr = _g(res, "reason")
                    reason = "revocation: %s" % (js_to_string(rr) if rr is not None else "rejected")
                allow = False
        except Exception as e:  # noqa: BLE001 - a hook that raises refuses the proof
            revocation = "fail"
            if allow or reason is None:
                reason = "malformed PCActn: %s" % _err(e)
            allow = False
    statuses = _statuses(v, revocation, enf)
    verdict: Dict[str, Any] = {"allow": allow, "checks": statuses}
    if reason is not None:
        verdict["reason"] = reason
    verdict["_wire"] = bool(v.checks.get("wire"))
    verdict["_audience"] = bool(v.checks.get("audience"))
    return verdict


def authorize(req: dict, opts: GatewayOptions) -> Dict[str, Any]:
    """The framework-agnostic core: extract the PCActn, map the request to the capability its route requires, verify (fail
    closed), enforce audience, capability, request binding, required checks, the proof hook, the policy and single use. Returns
    a Decision dict {allow, status, code, reason, headers, verdict?, pcactn?, matched?, policyVerdict?}."""
    realm = opts.realm if opts.realm is not None else opts.audience
    unmatched = opts.unmatched_route or "deny"
    path, method = req["path"], req["method"]

    # 0. an ambiguous request target is never matched against the route map
    if (opts.path_policy or "strict") == "strict":
        bad = ambiguous_path_reason(path)
        if bad is not None:
            return _deny("invalid-path", 400, bad, realm)

    # 1. route -> required capability; an unmapped route follows unmatched_route (default deny)
    rule = _match_route(opts.routes, method, path)
    if rule is None:
        if unmatched == "allow":
            return _allow("route %s %s is unmapped (unmatchedRoute=allow)" % (method, path))
        if unmatched == "deny":
            return _deny("unmapped-route", 403, "no capability mapping for %s %s (deny-by-default)" % (method, path), realm)
    required = rule["capability"] if rule is not None else None

    # 2. the proof (fail closed)
    extracted = _extract_pcactn(_g(req, "headers"))
    if "pcactn" not in extracted:
        return _deny(extracted["code"], 401, extracted["reason"], realm)
    pcactn = extracted["pcactn"]

    # 3. the grant the chain must root in
    grant_ref = pcactn.get("grant_ref")
    grant = opts.resolve_grant(grant_ref, pcactn)
    if not _jt(grant):
        return _deny("unknown-grant", 401, "unknown grant_ref %s" % ("undefined" if "grant_ref" not in pcactn else js_to_string(grant_ref)),
                     realm, pcactn=pcactn)

    # 3b. a configuration with a missing component denies every request (fail closed)
    missing_cfg = _missing_policy(opts)
    if missing_cfg:
        return _deny("proof-rejected", 403, "%s (fail closed)" % _missing_text(opts, missing_cfg), realm, pcactn=pcactn)

    # 4. offline verification, the audience bound to THIS gateway
    now = opts.now() if opts.now is not None else int(time.time() * 1000)
    verdict = _verify(pcactn, grant, opts, now)
    wire_ok, aud_ok = verdict.pop("_wire"), verdict.pop("_audience")
    if not verdict["allow"]:
        audience_failed = wire_ok and not aud_ok
        return _deny("wrong-audience" if audience_failed else "verify-failed", 403 if audience_failed else 401,
                     verdict.get("reason") or "PCActn verification failed", realm, verdict=verdict, pcactn=pcactn)

    # 5. capability enforcement: the verified proof carries the verb (+ resource) the route requires
    action = pcactn["action"]
    if required is not None:
        if action["verb"] != required["verb"]:
            return _deny("insufficient-capability", 403, "route requires capability '%s' but the proof authorizes '%s'"
                         % (required["verb"], action["verb"]), realm, verdict=verdict, pcactn=pcactn, matched=required)
        if required.get("resource") is not None and action["resource"] != required["resource"]:
            return _deny("insufficient-capability", 403, "route is bound to resource '%s' but the proof targets '%s'"
                         % (required["resource"], action["resource"]), realm, verdict=verdict, pcactn=pcactn, matched=required)

    policy = opts.policy if _policy_mode(opts) == "full" else None
    bind = opts.bind_request
    full_params: Optional[dict] = None
    if policy is not None:
        # 5b (full). the agent signed the real params plus the request binding: rebuild them from THIS request
        sp = _signed_params(req, policy, {} if bind is None else bind)
        if "error" in sp:
            return _deny("request-mismatch", 403, sp["error"], realm, verdict=verdict, pcactn=pcactn)
        if action["params_digest"] != params_digest(sp["params"]):
            return _deny("request-mismatch", 403, "the proof is not bound to this request (params/method/path/query/authority)",
                         realm, verdict=verdict, pcactn=pcactn)
        full_params = sp["params"]
    elif bind is not False:
        # 5b. request binding: the signed params digest must be the digest of THIS request
        b = bind or {}
        if (_jt(b.get("authority")) and not _jt(_g(req, "authority"))) or (b.get("body") is True and not _jt(_g(req, "bodySha256"))):
            return _deny("request-mismatch", 403, "request lacks an attribute the proof must bind (authority / body hash)",
                         realm, verdict=verdict, pcactn=pcactn)
        try:
            bound = params_digest(request_binding(req, b))
        except Exception as e:  # noqa: BLE001
            return _deny("request-mismatch", 403, "the request cannot be bound: %s" % _err(e), realm, verdict=verdict, pcactn=pcactn)
        if action["params_digest"] != bound:
            return _deny("request-mismatch", 403, "the proof is not bound to this request (method/path/query/authority/body)",
                         realm, verdict=verdict, pcactn=pcactn)

    # 5c. required checks must have PASSED (not merely "not-enforced"); full mode takes revocation from is_revoked
    for c in (opts.require_checks if opts.require_checks is not None else (DEFAULT_REQUIRE_CHECKS if policy is None else ())):
        if verdict["checks"].get(c) != "pass":
            return _deny("proof-rejected", 403, "required check '%s' is %s" % (c, verdict["checks"].get(c, "absent")), realm,
                         verdict=verdict, pcactn=pcactn)

    # 5d. per-proof policy hook (limits, budgets, revocation lists); a raise denies
    if opts.check_proof is not None:
        try:
            ctx = {"pcactn": pcactn, "grant": grant, "verdict": verdict, "request": req}
            if required is not None:
                ctx["required"] = required
            r = opts.check_proof(ctx)
            ok = r if isinstance(r, bool) else _jt(_g(r, "allow"))
            if not ok:
                why = _g(r, "reason") if isinstance(r, dict) and _jt(_g(r, "reason")) else "rejected by checkProof"
                return _deny("proof-rejected", 403, why, realm, verdict=verdict, pcactn=pcactn)
        except Exception as e:  # noqa: BLE001
            return _deny("proof-rejected", 403, "checkProof failed: %s" % _err(e), realm, verdict=verdict, pcactn=pcactn)

    # 5e. full-policy mode: the grant's limits and caveats, revocation, the replay counter and the trust budget
    policy_verdict: Any = None
    if policy is not None and full_params is not None:
        full = _full_policy(req, opts, policy, pcactn, grant, required, full_params, verdict, realm, now)
        if "decision" in full:
            return full["decision"]
        policy_verdict = full["policy_verdict"]

    # 6. single use, only for a proof that would otherwise be allowed (a denied attempt never burns it)
    if opts.replay_guard is not None:
        try:
            first = opts.replay_guard.claim("%s:%s" % (pcactn["grant_ref"], pcactn["sig"]), pcactn["exp"], now)
        except Exception as e:  # noqa: BLE001
            return _deny("replay-guard-unavailable", 503, "replay guard unavailable: %s" % _err(e), realm, verdict=verdict, pcactn=pcactn)
        if not first:
            return _deny("replayed-proof", 403, "this proof has already been used", realm, verdict=verdict, pcactn=pcactn)

    return _allow("proof-carrying action authorized (full policy)" if policy_verdict else "proof-carrying action verified",
                  verdict=verdict, pcactn=pcactn, matched=required, policyVerdict=policy_verdict)


def _full_policy(req: dict, opts: GatewayOptions, policy: dict, pcactn: dict, grant: dict, required: Optional[dict],
                 full_params: dict, verdict: dict, realm: str, now: Any) -> Dict[str, Any]:
    """Full-policy mode: delegate to the core `authorize` pipeline with the gateway's own audience, grant and clock."""
    k1: Any = None
    k1_opt = policy.get("k1")
    if k1_opt is not None:
        try:
            own = k1_opt(req, pcactn) if callable(k1_opt) else k1_opt
            k1 = {**presented_artifacts(req, policy), **own}
        except Exception as e:  # noqa: BLE001
            return {"decision": _deny("proof-rejected", 403, "k1 input failed: %s (fail closed)" % _err(e), realm,
                                      verdict=verdict, pcactn=pcactn)}
    bundle = presented_provenance(req, policy)
    log_opt = policy.get("provenance_log", _U)
    if log_opt is False:
        log = None
    elif log_opt is _U or log_opt is None:
        log = opts.__dict__.setdefault("_provenance_log", MemoryProvenanceLog())
    else:
        log = log_opt
    chain = pcactn.get("cap_chain")
    leaf = chain[-1].get("holder", _U) if isinstance(chain, list) and chain and isinstance(chain[-1], dict) else _U
    receipts = _g(bundle, "receipts") if bundle is not ABSENT else None
    session = _g(receipts[0], "session") if isinstance(receipts, list) and receipts else None
    log_key = "%s\n%s\n%s" % (js_to_string(pcactn.get("grant_ref")), "undefined" if leaf is _U else js_to_string(leaf),
                              session if isinstance(session, str) else "-")
    try:
        fields = {k: v for k, v in policy.items() if k not in ("mode", "params", "k1", "provenance_log")}
        user_observed = fields.pop("provenance_observed", None)

        def observed(p: dict, op: dict, sess: Any) -> list:
            return [*(user_observed(p, op, sess) if user_observed else []), *(log.seen(log_key) if log else [])]

        if user_observed or log:
            fields["provenance_observed"] = observed
        ao = AuthorizeOptions(k1=k1, **fields)
        action = pcactn["action"]
        operation = {"verb": required["verb"] if required else action["verb"],
                     "resource": required["resource"] if required and required.get("resource") is not None else action["resource"],
                     "params": full_params}
        d = ao.run(pcactn, operation=operation, audience=opts.audience, resolve_grant=lambda _ref: grant, now=now,
                   provenance=None if bundle is ABSENT else bundle)
    except Exception as e:  # noqa: BLE001
        return {"decision": _deny("proof-rejected", 403, "full policy failed: %s (fail closed)" % _err(e), realm, verdict=verdict, pcactn=pcactn)}
    # what this call returns flows back into the agent's context: the session has now seen untrusted content
    if d.allow and log:
        log.add(log_key, {"origin": "tool", "source": action["verb"]})
    if not d.allow:
        checks = d.checks or {}
        code = ("replayed-proof" if checks.get("replay") == "fail" else
                "insufficient-capability" if checks.get("operation") == "fail" else
                "verify-failed" if d.status == 401 else "proof-rejected")
        pv = {"allow": False, "checks": checks, "reason": d.reason}
        return {"decision": _deny(code, d.status, d.reason or "rejected", realm, verdict=verdict, pcactn=pcactn, policyVerdict=pv)}
    return {"policy_verdict": {"allow": True, "checks": d.checks or {}}}


def create_gateway(opts: GatewayOptions) -> Callable[[dict], Dict[str, Any]]:
    """A reusable authorizer bound to one frozen configuration. Raises TypeError when a component is missing, and
    ValueError for a hook or gate this port cannot run (it would otherwise be silently ignored)."""
    missing = _missing_policy(opts)
    if missing:
        raise TypeError("pca-gateway: %s" % _missing_text(opts, missing))
    extra_hooks = [k for k in (opts.hooks or {}) if k != "revocation"]
    if extra_hooks or "attestation" in (opts.enforce or {}):
        raise ValueError("pca-gateway: hooks %s / the attestation gate are not supported by the Python core"
                         % ", ".join(extra_hooks or ["attestation"]))
    frozen = copy.copy(opts)
    frozen.routes = copy.deepcopy(opts.routes)
    if opts.authorized_plan_roots is not None:
        frozen.authorized_plan_roots = list(opts.authorized_plan_roots)
    return lambda req: authorize(req, frozen)


def gateway_proxy(opts: GatewayOptions, upstream: Callable[[dict, Dict[str, Any]], Any]) -> Callable[[dict], Any]:
    """Join a gateway to an injected upstream callable: on allow, `upstream(request, decision)` is called with every
    client-supplied x-pca-* header removed and the decision's headers set; on deny the 401 / 403 response dict is returned
    and the upstream is never called."""
    gateway = create_gateway(opts)

    def handle(req: dict) -> Any:
        d = gateway(req)
        if d["allow"]:
            hdrs = {k: v for k, v in (_g(req, "headers") or {}).items() if not (isinstance(k, str) and k.lower() in PCA_INJECTED_HEADERS)}
            hdrs.update(d["headers"])
            return upstream(dict(req, headers=hdrs), d)
        return _deny_response(d)

    return handle


def _deny_response(d: Dict[str, Any]) -> Dict[str, Any]:
    return {"status": d["status"], "headers": dict({"content-type": "application/json"}, **d["headers"]),
            "body": js_json({"error": d["code"], "reason": d["reason"]})}


# ---------------------------------------------------------------------------------------------------- Envoy HTTP ext_authz
def _query_of_target(target: str) -> str:
    q = target.find("?")
    if q < 0:
        return ""
    rest = target[q + 1:]
    h = rest.find("#")
    return rest[:h] if h >= 0 else rest


def _first(*vs: Any) -> Any:
    for v in vs:
        if v is not None:
            return v
    return None


def _envoy_request(check: dict) -> dict:
    headers = _first(_g(check, "headers"), {})
    method = _first(_g(check, "method"), _g(headers, ":method"), "*")
    target = _first(_g(check, "path"), _g(headers, ":path"), "/")
    m = re.search(r"[?#]", target)
    raw_path = target[: m.start()] if m else target
    path = "/" if raw_path == "" else raw_path
    authority = _first(_g(check, "authority"), _g(headers, ":authority"))
    req: Dict[str, Any] = {"method": method, "path": path, "query": _query_of_target(target), "headers": headers}
    if authority is not None:
        req["authority"] = authority
    if _g(check, "body") is not None:
        req["body"] = check["body"]
    return req


def envoy_ext_authz(opts: GatewayOptions) -> Callable[[dict], Dict[str, Any]]:
    """Envoy HTTP ext_authz handler: 200 plus the verified verdict headers on allow (every injected header is overwritten, the
    unset ones blank), the guard's 401 / 403 with a WWW-Authenticate challenge and a JSON body on deny."""
    gateway = create_gateway(opts)

    def check(c: dict) -> Dict[str, Any]:
        d = gateway(_envoy_request(c))
        if d["allow"]:
            return {"status": 200, "headers": dict({h: "" for h in PCA_INJECTED_HEADERS}, **d["headers"]), "body": ""}
        return _deny_response(d)

    return check


# ---------------------------------------------------------------------------------------------------- Envoy gRPC ext_authz
GRPC_OK = 0
GRPC_UNAUTHENTICATED = 16
GRPC_PERMISSION_DENIED = 7
GRPC_UNAVAILABLE = 14
OVERWRITE_IF_EXISTS_OR_ADD = 2


def _header_options(h: Dict[str, str]) -> List[dict]:
    return [{"header": {"key": k, "value": v}, "appendAction": OVERWRITE_IF_EXISTS_OR_ADD} for k, v in h.items()]


def envoy_grpc_ext_authz(opts: GatewayOptions) -> Callable[[dict], Dict[str, Any]]:
    """Envoy gRPC ext_authz `Check` handler over a decoded CheckRequest dict (camelCase). On allow it also lists every x-pca-*
    header it did not set in `headersToRemove`, so a client cannot smuggle a forged verdict through an unmapped-route allow."""
    gateway = create_gateway(opts)

    def check(c: dict) -> Dict[str, Any]:
        http = _g(_g(_g(c, "attributes"), "request"), "http")
        if not _jt(http):
            return {"status": {"code": GRPC_PERMISSION_DENIED, "message": "no http request attributes"},
                    "deniedResponse": {"status": {"code": 403}, "headers": [],
                                       "body": js_json({"error": "invalid-request", "reason": "CheckRequest carried no HTTP attributes"})}}
        headers = _first(_g(http, "headers"), {})
        req: Dict[str, Any] = {"headers": headers}
        method = _first(_g(http, "method"), _g(headers, ":method"))
        if method is not None:
            req["method"] = method
        path = _first(_g(http, "path"), _g(headers, ":path"))
        if path is not None:
            req["path"] = path
        authority = _first(_g(http, "host"), _g(headers, ":authority"))
        if authority is not None:
            req["authority"] = authority
        if _g(http, "body") is not None:
            req["body"] = http["body"]
        d = gateway(_envoy_request(req))
        if d["allow"]:
            return {"status": {"code": GRPC_OK, "message": ""},
                    "okResponse": {"headers": _header_options(d["headers"]),
                                   "headersToRemove": [h for h in PCA_INJECTED_HEADERS if h not in d["headers"]]}}
        code = GRPC_UNAUTHENTICATED if d["status"] == 401 else GRPC_UNAVAILABLE if d["status"] == 503 else GRPC_PERMISSION_DENIED
        return {"status": {"code": code, "message": d["reason"]},
                "deniedResponse": {"status": {"code": d["status"]},
                                   "headers": _header_options(dict({"content-type": "application/json"}, **d["headers"])),
                                   "body": js_json({"error": d["code"], "reason": d["reason"]})}}

    return check


# ---------------------------------------------------------------------------------------------------- AWS Lambda authorizers
def _encode_uri_component(s: Any) -> str:
    from urllib.parse import quote
    try:
        return quote(js_to_string(s), safe="-_.!~*'()")
    except UnicodeEncodeError:
        raise ValueError("URI malformed") from None


def _lambda_resource(event: dict) -> str:
    return _first(_g(event, "methodArn"), _g(event, "routeArn"), "*")


def _lambda_method_path(event: dict) -> Dict[str, str]:
    http = _g(_g(event, "requestContext"), "http")
    method = _first(_g(http, "method"), _g(event, "httpMethod"))
    path = _first(_g(event, "rawPath"), _g(event, "path"), _g(http, "path"))
    if method is not None and path is not None:
        return {"method": method, "path": path}
    arn = _first(_g(event, "methodArn"), _g(event, "routeArn"))
    if arn is not None:
        parts = ":".join(arn.split(":")[5:]).split("/")
        arn_method = parts[2].split(" ")[0] if len(parts) > 2 else None
        return {"method": _first(method, arn_method, "*"), "path": _first(path, "/" + "/".join(parts[3:]))}
    return {"method": _first(method, "*"), "path": _first(path, "/")}


def _lambda_query(event: dict) -> str:
    raw = _g(event, "rawQueryString")
    if isinstance(raw, str):
        return raw
    multi, single = _g(event, "multiValueQueryStringParameters"), _g(event, "queryStringParameters")
    pairs: List[str] = []
    if _jt(multi) and isinstance(multi, dict):
        for k, vs in multi.items():
            for v in (vs if vs is not None else []):
                pairs.append("%s=%s" % (_encode_uri_component(k), _encode_uri_component(v)))
    elif _jt(single) and isinstance(single, dict):
        for k, v in single.items():
            pairs.append("%s=%s" % (_encode_uri_component(k), _encode_uri_component(v)))
    return "&".join(pairs)


def _lambda_request(event: dict) -> dict:
    mp = _lambda_method_path(event)
    return {"method": mp["method"], "path": mp["path"], "query": _lambda_query(event), "headers": _first(_g(event, "headers"), {})}


def _lambda_context(d: Dict[str, Any]) -> Dict[str, str]:
    if d["allow"]:
        return {"pcaVerdict": js_json(d["verdict"])} if d.get("verdict") else {}
    return {"pcaDenied": "true", "pcaCode": d["code"], "pcaReason": d["reason"], "pcaStatus": str(d["status"])}


def lambda_authorizer(opts: GatewayOptions) -> Callable[[dict], Dict[str, Any]]:
    """AWS API Gateway REQUEST authorizer: an Allow IAM policy (verdict on context.pcaVerdict) on a valid proof, else a Deny
    policy. REST (`methodArn`) and HTTP-API (`routeArn`) payloads."""
    gateway = create_gateway(opts)

    def handle(event: dict) -> Dict[str, Any]:
        d = gateway(_lambda_request(event))
        return {"principalId": _first(_g(d.get("pcactn"), "grant_ref"), "anonymous"),
                "policyDocument": {"Version": "2012-10-17", "Statement": [
                    {"Action": "execute-api:Invoke", "Effect": "Allow" if d["allow"] else "Deny", "Resource": _lambda_resource(event)}]},
                "context": _lambda_context(d)}

    return handle


def lambda_simple_authorizer(opts: GatewayOptions) -> Callable[[dict], Dict[str, Any]]:
    """HTTP-API simple-response variant: {isAuthorized, context} instead of an IAM policy."""
    gateway = create_gateway(opts)

    def handle(event: dict) -> Dict[str, Any]:
        d = gateway(_lambda_request(event))
        return {"isAuthorized": d["allow"], "context": _lambda_context(d)}

    return handle


# ---------------------------------------------------------------------------------------------------- Cloudflare Worker (runtime-free)
_UNSET = object()


def _hdr_get(headers: Any, name: str) -> Any:
    if isinstance(headers, dict):
        return get_header(headers, name)
    g = getattr(headers, "get", None)
    return g(name) if callable(g) else None


def _hdr_items(headers: Any) -> List[Any]:
    """The (name, value) pairs of a header mapping; a get-only object enumerates as empty (a Fetch Headers without forEach)."""
    if isinstance(headers, dict):
        return list(headers.items())
    it = getattr(headers, "items", None)
    return list(it()) if callable(it) else []


def _inbound_pca_headers(request: dict) -> List[str]:
    headers = _g(request, "headers")
    found: List[str] = []
    for k, _v in _hdr_items(headers):
        if isinstance(k, str) and k.lower().startswith("x-pca-") and k.lower() not in found:
            found.append(k.lower())
    for n in PCA_INJECTED_HEADERS:
        if _hdr_get(headers, n) is not None and n not in found:
            found.append(n)
    return found


def _default_rewrite(request: dict, drop: List[str]) -> Optional[dict]:
    headers = _g(request, "headers")
    if not isinstance(headers, dict):
        return None
    return dict(request, headers={k: v for k, v in headers.items() if not (isinstance(k, str) and k.lower() in drop)})


def _path_from_url(url: str) -> Dict[str, str]:
    rest, authority = url, ""
    scheme = rest.find("://")
    if scheme >= 0:
        rest = rest[scheme + 3:]
        slash = rest.find("/")
        if slash >= 0:
            authority, rest = rest[:slash], rest[slash:]
        else:
            authority, rest = rest, "/"
    m = re.search(r"[?#]", rest)
    path = rest[: m.start()] if m else rest
    return {"path": "/" if path == "" else path, "authority": authority, "query": _query_of_target(rest)}


def cloudflare_worker(opts: GatewayOptions, next_: Callable[[dict], Any], respond: Callable[[str, dict], Any],
                      rewrite_request: Any = _UNSET) -> Callable[[dict], Any]:
    """Cloudflare Worker middleware over injected plug points. A request is ``{"method", "url", "headers", "body"?}`` where headers
    is a dict (or an object with ``get`` and optionally ``items``) and ``body`` is the text a full-policy ``params: "body"`` gateway
    reads. On allow, any inbound ``x-pca-*`` header is removed (``rewrite_request(request, drop_names)``; the default rewrites a dict
    request; ``None`` opts out) before ``next_``; when it cannot be removed the request is refused with 400 and never forwarded. On
    deny, ``respond(json_body, {"status", "headers"})`` builds the 401 / 403 with the challenge."""
    gateway = create_gateway(opts)

    def handle(request: dict) -> Any:
        u = _path_from_url(_g(request, "url"))
        headers = _g(request, "headers")
        pca = _hdr_get(headers, PCA_HEADER)
        h: Dict[str, Any] = {} if pca is None else {PCA_HEADER.lower(): pca}
        for n in ("pca-discharges", "pca-narrow"):
            v = _hdr_get(headers, n)
            if v is not None:
                h[n] = v
        req: Dict[str, Any] = {"method": _g(request, "method"), "path": u["path"], "query": u["query"], "authority": u["authority"], "headers": h}
        pol = opts.policy
        if _g(pol, "mode") == "full" and _g(pol, "params") == "body" and _g(request, "body") is not None:
            req["body"] = request["body"]
        d = gateway(req)
        if d["allow"]:
            forged = _inbound_pca_headers(request)
            if not forged:
                return next_(request)
            rw = _default_rewrite if rewrite_request is _UNSET else rewrite_request
            clean = rw(request, forged) if rw is not None else None
            if clean is not None:
                return next_(clean)
            return respond(js_json({"error": "forged-pca-header", "reason": "inbound x-pca-* header cannot be removed"}),
                           {"status": 400, "headers": {"content-type": "application/json"}})
        return respond(js_json({"error": d["code"], "reason": d["reason"]}),
                       {"status": d["status"], "headers": dict({"content-type": "application/json"}, **d["headers"])})

    return handle
