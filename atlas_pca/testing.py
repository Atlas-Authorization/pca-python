"""Testing kit for Proof-Carrying Authority: factories, fakes and assertion helpers so an integrator can unit-test their PCA
wiring with no backend and no network. ``test_agent`` mints a real agent with test defaults, ``make_pcactn`` builds real PCActns
from it and ``fake_verify`` runs the REAL core verifier against them. Mirrors the TypeScript reference (@atlasauth/pca-testing).

Nothing here authorizes anything. ``fake_verify`` stands in for the resource server by rooting the check at the PCActn's own grant
and accepting the PCActn's own audience by default, so a clean round trip verifies; it is the real verifier, not a weakened one,
so tampering is caught exactly as in production. A grant lifted from the artifact is never trusted for a post-quantum root (no
pin exists), as in the reference.

The adapter acceptance matrix (``run_adapter_acceptance``) takes a harness for your own adapter, so every adapter runs the same
scenarios and must equal ``ADAPTER_ACCEPTANCE_EXPECTED``.
"""
from __future__ import annotations

import asyncio
import inspect
import json
from ._fin import fin
import re
from typing import Any, Callable, Dict, List, Optional

from .agent import KeyPair, generate_keypair
from .facade import AgentHandle, create_agent
from .pca import ARTIFACT_SIZE_REASON, Verdict, artifact_too_large, canonicalize, strict_parse, verify_pcactn_core
from .predicates import _js_number_string, _js_string

_UNSET: Any = object()

# ---- factories ------------------------------------------------------------------------------------


def test_agent(permissions: Optional[dict] = None, limits: Optional[dict] = None, goal: Optional[str] = None,
               aud: Optional[str] = None, principal: Optional[KeyPair] = None, holder: Optional[KeyPair] = None) -> AgentHandle:
    """A REAL agent handle with test defaults (permissions {stripe: [refund]}, limits {refund: "$500/day"}, goal "test", aud
    "ins_test", fresh keys). Pass limits={} for no limits."""
    return create_agent(
        principal=principal if principal is not None else generate_keypair(),
        goal=goal if goal is not None else "test",
        permissions=permissions if permissions is not None else {"stripe": ["refund"]},
        limits=limits if limits is not None else {"refund": "$500/day"},
        holder=holder,
        aud=aud if aud is not None else "ins_test",
    )


test_agent.__test__ = False  # type: ignore[attr-defined]  # not a pytest test


def make_pcactn(a: AgentHandle, verb: str, resource: str, params: Optional[dict] = None, counter: Optional[int] = None,
                now: Optional[int] = None) -> Dict[str, Any]:
    """Build a PCActn for one action: {"pcactn", "encoded"} (the local dry-run is dropped; use ``a.act`` if you need it)."""
    res = a.act(verb, resource, params, counter=counter, now=now)
    return {"pcactn": res["pcactn"], "encoded": res["encoded"]}


# ---- fake verifier --------------------------------------------------------------------------------


def _truthy(v: Any) -> bool:
    if v is None or v is False or v == "":
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return not (v == 0 or v != v)
    return True


_NO_GRANT = "fakeVerify: PCActn has an empty cap_chain and no grant was supplied via opts.grant"


def _lift_grant(pcactn: Any) -> Any:
    """``pcactn.cap_chain[0]`` as JavaScript reads it; raises where JavaScript would raise or find nothing."""
    if not isinstance(pcactn, dict):
        raise ValueError(_NO_GRANT)
    chain = pcactn.get("cap_chain")
    first = None
    if isinstance(chain, list) and chain:
        first = chain[0]
    elif isinstance(chain, str) and chain:
        first = chain[0]
    elif isinstance(chain, dict):
        first = chain.get("0")
    if not _truthy(first):
        raise ValueError(_NO_GRANT)
    return first


def fake_verify(pcactn: Any, audience: Any = _UNSET, now: Optional[int] = None, grant: Optional[dict] = None) -> Verdict:
    """Run the real core verifier against ``pcactn``, rooting the check at ``grant`` or the PCActn's own chain root and
    defaulting the verifier audience to the PCActn's own ``aud`` (omit ``audience``; pass None to opt out; a mismatching string
    forces the audience check to fail). ``now`` is epoch ms (wall clock when omitted). Returns the Verdict; raises when there is
    no grant to root at."""
    root = grant if grant is not None else _lift_grant(pcactn)
    lifted = grant is None
    if audience is not _UNSET and audience is not None:
        aud = audience
    else:
        if audience is _UNSET and pcactn is None:
            raise ValueError("fakeVerify: no PCActn")
        own = pcactn.get("aud") if isinstance(pcactn, dict) else None
        aud = own if isinstance(own, str) else None  # opt-out accepts the PCActn's own audience; a non-string one fails the wire check
    if not isinstance(root, dict):
        return Verdict(False, {"wire": False}, "wire: the grant is not an object")
    if lifted and "alg" in root and root["alg"] != "ed25519":
        return Verdict(False, {"cap_chain": False},
                       "cap_chain: root suite needs a verifier-side PQ pin; a grant lifted from the artifact is never trusted for it")
    return verify_pcactn_core(pcactn, root, now=now, audience=aud, insecure_skip_plan_root_check=True)


def _failing(res: Verdict) -> List[str]:
    return [name for name, ok in res.checks.items() if ok is False]


def expect_verifies(pcactn: Any, audience: Any = _UNSET, now: Optional[int] = None, grant: Optional[dict] = None) -> Verdict:
    """Assert that ``pcactn`` verifies: raises AssertionError naming the failing checks and the reason, else returns the Verdict."""
    res = fake_verify(pcactn, audience, now, grant)
    if not res.allow:
        raise AssertionError("expectVerifies: PCActn was denied. failing checks: [%s]%s"
                             % (", ".join(_failing(res)), " — %s" % res.reason if res.reason else ""))
    return res


def expect_denied(pcactn: Any, audience: Any = _UNSET, now: Optional[int] = None, grant: Optional[dict] = None) -> Verdict:
    """The inverse of ``expect_verifies``: raises AssertionError when ``pcactn`` unexpectedly verifies."""
    res = fake_verify(pcactn, audience, now, grant)
    if res.allow:
        raise AssertionError("expectDenied: PCActn verified but was expected to be denied. checks: %s" % json.dumps(res.checks))
    return res


# ---- in-memory state store ------------------------------------------------------------------------


class MemoryStateStore:
    """An in-memory per-holder state store (replay counter, budget): a drop-in budget store for tests. Nothing persists."""

    def __init__(self) -> None:
        self._m: Dict[str, Any] = {}

    def get(self, key: str) -> Optional[Any]:
        return self._m.get(key)

    def put(self, key: str, state: Any) -> None:
        self._m[key] = state


def memory_state_store() -> MemoryStateStore:
    return MemoryStateStore()


# ---- tampering ------------------------------------------------------------------------------------

_JSON_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _json_string(s: str) -> str:
    out = []
    for c in s:
        o = ord(c)
        if c in _JSON_ESC:
            out.append(_JSON_ESC[c])
        elif o < 0x20 or 0xD800 <= o <= 0xDFFF:  # a lone surrogate is escaped, as JSON.stringify does
            out.append("\\u%04x" % o)
        else:
            out.append(c)
    return '"' + "".join(out) + '"'


def _stringify(v: Any) -> str:
    """JSON.stringify of a decoded JSON value (numbers as ECMAScript prints a double; -0 prints 0)."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _json_string(v)
    if isinstance(v, (int, float)):
        return "null" if not fin(v) else _js_number_string(float(v))
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_stringify(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(_json_string(str(k)) + ":" + _stringify(x) for k, x in v.items()) + "}"
    raise TypeError("tamper: unsupported value")


def _decode_pcactn(s: str) -> dict:
    if artifact_too_large(s):  # FIRST: before any parsing
        raise ValueError(ARTIFACT_SIZE_REASON)
    v = strict_parse(s)
    if not isinstance(v, dict):
        raise TypeError("decodePCActn: not an object")
    return v


def tamper(encoded: str, mutate: Callable[[Dict[str, Any]], Any]) -> str:
    """Decode an encoded PCActn (strict profile, size-capped), let ``mutate`` corrupt the dict in place, then re-encode it so a
    test can assert the corruption is caught. A change touching the signed body breaks ``leaf_signature``."""
    rec = dict(_decode_pcactn(encoded))
    mutate(rec)
    return canonicalize(_decode_pcactn(_stringify(rec)))


# ---- adapter acceptance matrix -------------------------------------------------------------------------------------------------

ADAPTER_ACCEPTANCE_AUDIENCE = "payments-rs"


def _outcome(status: int, ran: bool, bound: bool) -> Dict[str, Any]:
    return {"status": status, "handlerRan": ran, "bound": bound}


# The outcome every adapter must produce per scenario: status, whether the handler ran, whether the attached operation matches.
ADAPTER_ACCEPTANCE_EXPECTED: Dict[str, Dict[str, Any]] = {
    **{k: _outcome(403, False, False) for k in ("over_limit_predicate", "over_limit_max_spend", "body_differs", "other_operation",
                                                  "escalate_unanswered", "missing_revocation", "missing_store")},
    "valid_first": _outcome(200, True, True),
    "replay_second": _outcome(403, False, False),
}

_SPECIAL = ("http", "https", "ftp", "ws", "wss", "file")
_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*):")


class InvalidUrlError(ValueError):
    """The reference runtime's URL parser error (ERR_INVALID_URL)."""
    code = "ERR_INVALID_URL"


def _pathname_of(url: str) -> str:
    """The pathname of ``url`` resolved against a base origin as a WHATWG URL parser yields it, for the shapes a request carries
    (absolute and scheme-relative URLs, rooted and relative paths, dot segments, query, fragment). Raises ValueError where the
    parser rejects the URL. shortcut: percent-encoding of the path is not reproduced (an encoded spelling never equals a route),
    upgrade if routes ever contain non-ASCII."""
    s = re.sub(r"\A[\x00-\x20]+|[\x00-\x20]+\Z", "", url)
    s = re.sub(r"[\t\n\r]", "", s)
    cut = len(s)
    for i, ch in enumerate(s):
        if ch in "?#":
            cut = i
            break
    rest = s[:cut]
    sm = _SCHEME.match(rest)
    if sm:
        scheme = sm.group(1).lower()
        rest = rest[sm.end():]
        if scheme not in _SPECIAL:
            if rest.startswith("//"):
                end = rest.find("/", 2)
                path = "" if end < 0 else rest[end:]
            elif rest.startswith("/"):
                path = rest
            else:
                return rest  # opaque path: never a route
        elif scheme == "file":
            rest = rest.replace("\\", "/")
            if rest.startswith("//"):
                end = rest.find("/", 2)
                path = "/" if end < 0 else rest[end:]
            else:
                path = rest if rest.startswith("/") else "/" + rest
        else:
            rest = rest.replace("\\", "/")
            if scheme == "http" and not rest.startswith("//"):  # same scheme as the base: relative
                path = rest if rest.startswith("/") else "/" + rest
            else:
                rest = rest.lstrip("/")
                end = rest.find("/")
                if (rest if end < 0 else rest[:end]) == "":
                    raise InvalidUrlError("Invalid URL")
                path = "/" if end < 0 else rest[end:]
    else:
        rest = rest.replace("\\", "/")
        if rest.startswith("//"):
            t = rest[2:].lstrip("/")
            end = t.find("/")
            if (t if end < 0 else t[:end]) == "":
                raise InvalidUrlError("Invalid URL")
            path = "/" if end < 0 else t[end:]
        else:
            path = rest if rest.startswith("/") else "/" + rest
    if path == "":
        return ""
    out: List[str] = []
    segs = path[1:].split("/")
    for i, seg in enumerate(segs):
        low = seg.lower()
        last = i == len(segs) - 1
        if low in ("..", ".%2e", "%2e.", "%2e%2e"):
            if out:
                out.pop()
            if last:
                out.append("")
        elif low in (".", "%2e"):
            if last:
                out.append("")
        else:
            out.append(seg)
    return "/" + "/".join(out)


def acceptance_operation(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The server's mapping from request to operation: a route table on method + path with the JSON body as params. ``req`` is
    {"method", "url", "body"}. Returns None for an unknown route or a body that is not an object, else {verb, resource, params}."""
    url = req.get("url")
    path = _pathname_of(url) if isinstance(url, str) else ""
    key = _js_string(req.get("method")).upper() + " " + path
    if key == "POST /payments":
        verb = "payments.send"
    elif key == "POST /refunds":
        verb = "payments.refund"
    else:
        return None
    body = req.get("body")
    if not isinstance(body, dict):
        return None
    return {"verb": verb, "resource": "payments", "params": body}


# ---- the matrix runner ----------------------------------------------------------------------------------------

_PROV_KEY = bytes([3]) * 32


def _prov_recorder():
    from .arg_provenance import create_provenance_recorder
    return create_provenance_recorder(mediator="adapter-acceptance", kid="k1", secret_key=_PROV_KEY)


def _fixture(limit: str) -> Dict[str, Any]:
    from .agent import build_pcactn, mint_grant, mint_root, pca_headers
    from .arg_provenance import principal_direct_provenance
    from .authorize import MemoryStateStore
    from .pca import params_digest
    principal, holder = generate_keypair(), generate_keypair()
    where = [{"field": "action.params.amount", "op": "lte", "value": 100}] if limit in ("predicate", "escalate") else []
    envelope: Dict[str, Any] = {
        "predicates": [{"verb": ["payments.send", "payments.refund"], "resource": "payments", "where": where}],
        "caveats": [], "agent_binding": {},
        # "spend = risk": each call is priced at amount / 100 and debits the amount from a far-away budget
        "risk_policy": {"weights": {"alpha": 0, "beta": 0, "gamma": 1, "delta": 0, "epsilon": 0, "zeta": 0}, "theta1": 1,
                        "theta2": 1, "kappa": 100, "lambda": 0, "rho": 0.5, "bMax": 1_000_000},
    }
    if limit == "escalate":  # a payment over 50 asks the principal; with no answer it is refused
        envelope["tighten"] = [{"id": "big_payment", "when": {"field": "action.params.amount", "op": "gt", "value": 50},
                                "signal": "escalate"}]
    grant = mint_grant(principal, holder.public, envelope, "pay invoices")["grant"]
    if limit == "max_spend":  # a ROOT caveat outside the envelope, enforced like a delegated one
        grant = mint_root(principal, holder.public, [*grant["caveats"], {"type": "max_spend", "usd": 100}])
    counter = [0]

    def request(signed: Dict[str, Any], sent: Dict[str, Any]) -> Dict[str, Any]:
        params = {"payee": "acme", "amount": signed["amount"]}
        node = {"id": "n1", "verb": signed["verb"], "resource": "payments", "params_digest": params_digest(params),
                "reversibility_class": "irreversible"}
        counter[0] += 1
        p = build_pcactn(grant, [grant], [node], "n1", counter[0], holder, ADAPTER_ACCEPTANCE_AUDIENCE, params=params)
        prov = principal_direct_provenance(_prov_recorder(), {"verb": signed["verb"], "resource": "payments", "params": params})
        return {"method": "POST", "path": sent["path"], "headers": {**pca_headers(p, provenance=prov), "content-type": "application/json"},
                "body": {"payee": "acme", "amount": sent["amount"]}}

    def options(**over: Any) -> Dict[str, Any]:
        o = {
            "audience": ADAPTER_ACCEPTANCE_AUDIENCE,
            "resolve_grant": lambda ref: grant if ref == grant["id"] else None,
            "state_store": MemoryStateStore(),
            "is_revoked": lambda p, g: False,
            "plan": "single-step",
            "risk": lambda op, g, p: {"blastRadius": min(1, float((op.get("params") or {}).get("amount") or 0) / 100),
                                      "semanticDistance": 0, "reversibility": 0, "taint": 0, "confidence": 1, "age": 0},
            "provenance_mediators": [_prov_recorder().pin],
        }
        o.update(over)
        return o

    return {"request": request, "options": options}


def _resolve(v: Any) -> Any:
    return asyncio.run(v) if inspect.isawaitable(v) else v


def run_adapter_acceptance(harness: Callable[[Dict[str, Any]], Callable[[Dict[str, Any]], Any]]) -> Dict[str, Dict[str, Any]]:
    """Run the matrix through ``harness`` and compare the result with ``ADAPTER_ACCEPTANCE_EXPECTED``.

    ``harness(options)`` builds the adapter ONCE from ``options`` (``authorize`` keyword arguments minus the per-request ones:
    pass them through unchanged) and returns ``send(req)`` for one request ``{"method", "path", "headers", "body"}``; ``send``
    returns ``{"status", "handlerRan", "operation"?}`` (``operation`` = the ``AuthorizedOperation`` an allowed call attached).
    The adapter derives the operation with ``acceptance_operation({"method", "url", "body"})`` and takes the proof from the
    ``PCA-Action`` header and the bundle from ``PCA-Provenance``. ``harness`` and ``send`` may be sync or async."""
    from .authorize import AuthorizeResult, is_authorized_for
    out: Dict[str, Dict[str, Any]] = {}

    def settle(req: Dict[str, Any], o: Dict[str, Any]) -> Dict[str, Any]:
        ran = acceptance_operation({"method": req["method"], "url": req["path"], "body": req["body"]})
        op = o.get("operation")
        bound = bool(op) and bool(ran) and is_authorized_for(
            AuthorizeResult(allow=True, status=200, operation=op, decision="allow"), ran)
        return _outcome(o["status"], o["handlerRan"], bound)

    def send_of(opts: Dict[str, Any]) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
        send = _resolve(harness(opts))
        return lambda req: _resolve(send(req))

    def once(name: str, f: Dict[str, Any], req: Dict[str, Any], **over: Any) -> None:
        out[name] = settle(req, send_of(f["options"](**over))(req))

    def pay(f: Dict[str, Any], verb: str, signed: int, path: str, sent: int) -> Dict[str, Any]:
        return f["request"]({"verb": verb, "amount": signed}, {"path": path, "amount": sent})

    pred = _fixture("predicate")
    spend = _fixture("max_spend")
    esc = _fixture("escalate")
    once("over_limit_predicate", pred, pay(pred, "payments.send", 400, "/payments", 400))
    once("over_limit_max_spend", spend, pay(spend, "payments.send", 400, "/payments", 400))
    once("body_differs", pred, pay(pred, "payments.send", 50, "/payments", 400))
    once("other_operation", pred, pay(pred, "payments.send", 50, "/refunds", 50))
    once("escalate_unanswered", esc, pay(esc, "payments.send", 70, "/payments", 70))
    once("missing_revocation", pred, pay(pred, "payments.send", 50, "/payments", 50), is_revoked=None)
    once("missing_store", pred, pay(pred, "payments.send", 50, "/payments", 50), state_store=None)
    send = send_of(pred["options"]())
    valid = pay(pred, "payments.send", 50, "/payments", 50)
    out["valid_first"] = settle(valid, send(valid))
    out["replay_second"] = settle(valid, send(valid))
    return out


def first_failed_check(checks: Dict[str, str]) -> Optional[str]:
    """The first check (in evaluation order) whose status is ``fail``, or None when none failed."""
    return next((name for name, status in checks.items() if status == "fail"), None)
