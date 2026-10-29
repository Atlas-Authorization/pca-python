"""``authorize()``: the full authorization pipeline for a Python resource server or tool guard (0.5, additive).

``verify_pcactn_core`` answers "is this a validly signed PCActn for this audience". ``authorize`` answers "may THIS
operation run now", in the same order as the TypeScript ``authorize()`` / ``verifyPCActn``:

  1. configuration: ``audience``, ``resolve_grant``, ``state_store`` (with ``claim``) and ``is_revoked`` are REQUIRED,
     and the call must name the ``operation`` it will execute (verb, resource, params). A missing one denies with its
     name; nothing is ever downgraded to "not enforced".
  2. the core checks (``verify_pcactn_core``: wire, version, audience, validity, chain, grant_ref_bound,
     plan_inclusion, leaf_signature, counter format, intent), then ``revocation`` (``is_revoked``), then
     ``zk_compliance`` (a carried proof cannot be verified here: fail closed).
  3. ``operation``: the signed ``action.verb`` / ``action.resource`` equal the operation's, and the signed
     ``action.params_digest`` opens to exactly the operation's params. Those params are what the predicates and caveats
     read, so a $400 operation is judged as $400 even when the agent signed $50 (and then refused for the mismatch).
  4. ``grant_ref``, ``params_digest``, ``plan_root_authorized`` (``plan="single-step"`` or a ``context`` plan),
     ``attestation`` (a grant whose ``agent_binding`` pins the agent needs an attestation verifier this SDK does not
     have: fail closed), ``reversibility`` (when the context names an authoritative class).
  5. policy: the grant's envelope predicates (default deny), the envelope's caveats and the ROOT caveats outside the
     envelope (``policy``), and the caveats delegation hops appended (``delegated_caveats``). ``predicates`` and
     ``tool_schema`` caveats are enforced against the operation; unknown caveat types fail closed.
  6. provenance by default (check ``provenance_flow``, see ``atlas_pca.arg_provenance``): a sensitive action whose choice or
     sink arguments do not derive from the principal is ``escalate`` (a forged provenance bundle is ``deny``). Always on; the
     only opt-out is the grant envelope's signed ``provenance: {"mode": "insecure_off"}``.
  7. replay: only when everything above passes, the counter is consumed through ``state_store.claim(key, counter)``,
     one atomic compare-and-set per action (key = ``<grant id>:<leaf holder>``). A replayed or older counter fails the
     ``replay`` check (the name ``counter`` is accepted as an alias in ``require``).

Not ported from the TypeScript policy VM: the risk score, trust budget and threshold step-up (``risk_policy``). A grant
whose risk policy would make the TypeScript verifier ask for a co-signature is decided here on predicates and caveats
alone.

Never raises: any internal error is a denial.
"""
from __future__ import annotations

import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, NamedTuple, Optional, Sequence, Union

from .intent_v2 import _UNDEF
from .pca import (REGISTERED_SUITES, StrictJsonError, Verdict, _fin, _plan_leaf, artifact_too_large, conditions_digest,
                  evaluate_caveats, hash_canonical, merkle_root, params_digest, strict_parse, suite_available,
                  verify_pcactn_core)
from .predicates import _js_string, evaluate_predicates, predicate_matches
from .decision import decision_of
from .escalation import (build_escalation_request, escalation_action_digest, escalation_history_head, escalation_policy_digest,
                         verify_escalation_answer)
from .safe_regex import with_regex_budget
from .revocation_staleness import (RevocationStaleness, check_revocation_state, class_rank as _class_rank,
                                   effective_reversibility)
from .caveat_lang import discharge_action_digest, evaluate_k1, is_k1_caveat, reserve_max_uses
from .workflow import admit_step
from .arg_provenance import decide_arg_provenance, prov_envelope_error, read_provenance_bundle
from .obligations import obligation_error

ENVELOPE_CAVEAT = "envelope"
_MISSING_EPOCH = _UNDEF  # the PCActn carries no freshness.epoch

#: The checks that must be ``pass`` (not merely "not failed"): the TypeScript ``DEFAULT_REQUIRED_CHECKS`` plus the
#: operation binding and the policy. ``require=`` can add names, never remove these.
DEFAULT_REQUIRED_CHECKS = ("counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound",
                           "operation", "params_digest", "policy")

# A failing one of these is an authentication failure (401), everything else is insufficient authority (403); the same
# split as the TypeScript requirePCA (the Python core names the chain check `chain`, TypeScript `cap_chain`).
_AUTHN_CHECKS = ("wire", "version", "audience", "validity", "chain", "grant_ref_bound", "leaf_signature", "malformed",
                 "grant_ref")

GrantResolver = Callable[[Optional[str]], Optional[dict]]
RevocationCheck = Callable[[dict, dict], bool]


# ---- the replay store ------------------------------------------------------------------------------------------------

class ClaimResult(NamedTuple):
    """What ``StateStore.claim`` returns. ``ok`` is True only when THIS call consumed the counter."""

    ok: bool
    last_counter: Optional[int] = None


def _once_args(key: Any, retain_until: Any, now: Any) -> None:
    for v in (retain_until, now):
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("consume_once: retain_until and now must be integers")
    if not isinstance(key, str) or key == "" or retain_until < now:
        raise ValueError("consume_once: invalid key or retention horizon")


class StateStore:
    """The replay-store protocol: ``claim(key, counter) -> ClaimResult``.

    ONE atomic operation of your backend: if a counter is stored for ``key`` and ``counter`` is not strictly greater,
    return ``ClaimResult(False, stored)``; otherwise store ``counter`` and return ``ClaimResult(True)``. A claim that
    cannot decide must return ``ok=False`` or raise (``authorize`` then denies). Implementations need not subclass this.

    ``last(key) -> Optional[int]`` is REQUIRED when ``escalation_principals`` is set: an escalation answer is bound to the
    holder's history head (the highest admitted counter), so the verifier must be able to read it, as the TypeScript store's
    ``get`` does. ``authorize`` refuses (``authorize_config``) an escalation setup whose store has no ``last``, and
    :class:`AuthorizeOptions` raises at construction.
    """

    def claim(self, key: str, counter: int) -> ClaimResult:  # pragma: no cover - protocol
        raise NotImplementedError

    def last(self, key: str) -> Optional[int]:  # pragma: no cover - protocol
        raise NotImplementedError

    def consume_once(self, key: str, retain_until_ms: int, now_ms: int) -> bool:
        """TTL'd consume-once (K1 ``max_uses`` slots): True iff ``key`` has no live record (``retain_until >= now``); the
        record is then kept at least until ``retain_until_ms`` (the maximum of the horizons seen). Raises ``ValueError``
        for an empty key or ``retain_until_ms < now_ms``, leaving nothing behind. This default has no expiry: it falls back
        to ``claim(key, 1)``; the bundled stores override it."""
        _once_args(key, retain_until_ms, now_ms)
        return bool(self.claim(key, 1).ok)


class MemoryStateStore(StateStore):
    """In-process reference store (one lock). Correct for ONE process only; use :class:`SqliteStateStore` or your
    database for several workers."""

    def __init__(self) -> None:
        self._last: Dict[str, int] = {}
        self._once: Dict[str, int] = {}
        self._lock = threading.Lock()

    def consume_once(self, key: str, retain_until_ms: int, now_ms: int) -> bool:
        _once_args(key, retain_until_ms, now_ms)
        with self._lock:
            until = self._once.get(key)
            if until is not None and until >= now_ms:
                self._once[key] = max(until, retain_until_ms)
                return False
            for k in [k for k, u in self._once.items() if u < now_ms]:  # prune what no longer needs remembering
                del self._once[k]
            self._once[key] = retain_until_ms
            return True

    def last(self, key: str) -> Optional[int]:
        with self._lock:
            return self._last.get(key)

    def claim(self, key: str, counter: int) -> ClaimResult:
        with self._lock:
            last = self._last.get(key)
            if last is not None and not counter > last:
                return ClaimResult(False, last)
            self._last[key] = counter
            return ClaimResult(True)


class SqliteStateStore(StateStore):
    """Durable store on SQLite: one row per counter stream, ``key`` is the PRIMARY KEY (unique constraint).

    The claim is ONE statement, ``INSERT ... ON CONFLICT(key) DO UPDATE ... WHERE excluded.last_counter >
    last_counter``, which SQLite runs under its write lock, so concurrent threads and processes sharing the file can
    never both consume the same counter. Needs SQLite 3.24+.
    """

    TABLE = "pca_replay"
    ONCE_TABLE = "pca_consume_once"

    def __init__(self, path: str, *, timeout: float = 30.0) -> None:
        self._path = path
        self._timeout = timeout
        self._local = threading.local()
        self._conn().execute(
            "CREATE TABLE IF NOT EXISTS %s (key TEXT NOT NULL PRIMARY KEY, last_counter INTEGER NOT NULL)" % self.TABLE)
        self._conn().execute(
            "CREATE TABLE IF NOT EXISTS %s (key TEXT NOT NULL PRIMARY KEY, retain_until INTEGER NOT NULL)" % self.ONCE_TABLE)

    def _conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self._path, timeout=self._timeout, isolation_level=None)  # autocommit: one statement
            self._local.conn = c
        return c

    def consume_once(self, key: str, retain_until_ms: int, now_ms: int) -> bool:
        """ONE statement: insert, or take over the row only when its record has expired (``retain_until < now``)."""
        _once_args(key, retain_until_ms, now_ms)
        c, t = self._conn(), self.ONCE_TABLE
        cur = c.execute(
            "INSERT INTO %s (key, retain_until) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET "
            "retain_until = excluded.retain_until WHERE %s.retain_until < ?" % (t, t), (key, retain_until_ms, now_ms))
        if cur.rowcount == 1:
            c.execute("DELETE FROM %s WHERE retain_until < ?" % t, (now_ms,))
            return True
        c.execute("UPDATE %s SET retain_until = ? WHERE key = ? AND retain_until < ?" % t, (retain_until_ms, key, retain_until_ms))
        return False

    def last(self, key: str) -> Optional[int]:
        row = self._conn().execute("SELECT last_counter FROM %s WHERE key = ?" % self.TABLE, (key,)).fetchone()
        return row[0] if row else None

    def claim(self, key: str, counter: int) -> ClaimResult:
        if not isinstance(key, str) or isinstance(counter, bool) or not isinstance(counter, int):
            return ClaimResult(False)
        c = self._conn()
        cur = c.execute(
            "INSERT INTO %s (key, last_counter) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET "
            "last_counter = excluded.last_counter WHERE excluded.last_counter > %s.last_counter" % (self.TABLE, self.TABLE),
            (key, counter))
        if cur.rowcount == 1:
            return ClaimResult(True)
        row = c.execute("SELECT last_counter FROM %s WHERE key = ?" % self.TABLE, (key,)).fetchone()
        return ClaimResult(False, row[0] if row else None)


def state_key(grant_id: str, leaf_holder: str) -> str:
    """The store key of a holder's counter stream (the TypeScript ``pcaStateKey`` default scope)."""
    return "%s:%s" % (grant_id, leaf_holder)


# ---- the envelope (TypeScript envelope.ts readEnvelope / risk.ts validateRiskPolicy) ---------------------------------

def _validate_risk_policy(p: Any) -> Optional[str]:
    if not isinstance(p, dict):
        return "risk_policy must be an object"
    w = p.get("weights")
    if not isinstance(w, dict):
        return "risk_policy.weights missing"
    for k in ("alpha", "beta", "gamma", "delta", "epsilon", "zeta"):
        v = _fin(w.get(k))
        if v is None or v < 0:
            return "risk_policy.weights.%s must be finite and >= 0" % k
    vals = {}
    for k in ("theta1", "theta2", "kappa", "lambda", "rho", "bMax"):
        vals[k] = _fin(p.get(k))
        if vals[k] is None:
            return "risk_policy.%s must be finite" % k
    if vals["theta1"] < 0 or vals["theta2"] < vals["theta1"]:
        return "risk_policy requires 0 <= theta1 <= theta2"
    if vals["kappa"] <= 0:
        return "risk_policy.kappa must be > 0"
    if vals["lambda"] < 0 or vals["rho"] < 0 or vals["bMax"] < 0:
        return "risk_policy lambda/rho/bMax must be >= 0"
    return None


def read_envelope(grant: Any) -> Optional[dict]:
    """The grant's policy envelope: its FIRST ``envelope`` caveat without ``type``, or None when absent or malformed."""
    try:
        cs = grant.get("caveats") if isinstance(grant, dict) else None
        if not isinstance(cs, list):
            return None
        cv = next((c for c in cs if isinstance(c, dict) and c.get("type") == ENVELOPE_CAVEAT), None)
        if cv is None:
            return None
        e = {k: v for k, v in cv.items() if k != "type"}
        if not isinstance(e.get("goal_commit"), str):
            return None
        if not isinstance(e.get("predicates"), list) or not isinstance(e.get("caveats"), list):
            return None
        if not isinstance(e.get("agent_binding"), (dict, list)):
            return None
        if _validate_risk_policy(e.get("risk_policy")) is not None:
            return None
        return e
    except Exception:
        return None


def root_caveats(grant: Any) -> Any:
    """Every root caveat except the first ``envelope`` one (TypeScript ``rootCaveats``); a non-list is returned as is."""
    cs = grant.get("caveats") if isinstance(grant, dict) else None
    if not isinstance(cs, list):
        return cs
    out = list(cs)
    for i, c in enumerate(out):
        if isinstance(c, dict) and c.get("type") == ENVELOPE_CAVEAT:
            del out[i]
            break
    return out


def _requires_attestation(binding: Any) -> bool:
    """TypeScript ``requiresAttestation``: any agent pin in ``agent_binding`` requires a bound attestation."""
    b = binding if isinstance(binding, dict) else {}
    ne = lambda x: isinstance(x, list) and len(x) > 0  # noqa: E731
    mm = b.get("min_measurement", None) if "min_measurement" in b else _ABSENT
    has_min = mm is not _ABSENT and mm != ""
    return (ne(b.get("model_allowlist")) or has_min or (isinstance(b.get("operator"), str) and b["operator"] != "")
            or ne(b.get("weights_allowlist")) or ne(b.get("system_prompt_allowlist"))
            or ne(b.get("tool_manifest_allowlist")) or b.get("require_hardware") is True
            or b.get("require_measured_weights") is True)


_ABSENT = object()


# ---- the semantic firewall: `tool_schema` caveats (TypeScript agent-native.ts) -----------------------------------------

MAX_SCHEMA_DEPTH = 8
MAX_SCHEMA_NODES = 256
MAX_OBJECT_PROPS = 64
MAX_ENUM_VALUES = 256
DEFAULT_MAX_ARRAY_ITEMS = 256
ABSOLUTE_MAX_ARRAY_ITEMS = 4096
DEFAULT_MAX_STRING_LEN = 65_536
ABSOLUTE_MAX_STRING_LEN = 1_048_576
MAX_VALUE_NODES = 10_000

_SAFE_NAME = re.compile(r"[A-Za-z0-9_]{1,64}")
_SPEC_KEYS = {
    "string": ("type", "enum", "const", "minLength", "maxLength", "prefix"),
    "number": ("type", "enum", "const", "min", "max"),
    "integer": ("type", "enum", "const", "min", "max"),
    "boolean": ("type", "enum", "const"),
    "object": ("type", "props", "required"),
    "array": ("type", "items", "minItems", "maxItems"),
}


def _jslen(s: str) -> int:
    """JavaScript ``string.length`` (UTF-16 code units)."""
    return len(s.encode("utf-16-le")) // 2


def _is_int(x: Any) -> bool:
    f = _fin(x)
    return f is not None and float(f).is_integer()


def _non_neg_int(x: Any, mx: int) -> bool:
    f = _fin(x)
    return f is not None and float(f).is_integer() and 0 <= f <= mx


def _only_keys(o: dict, allowed: Sequence[str]) -> bool:
    return all(k in allowed for k in o)


def _js_eq(a: Any, b: Any) -> bool:
    """JavaScript ``===`` on the scalars a schema can hold (numbers compare as doubles; a bool is never a number)."""
    fa, fb = _fin(a), _fin(b)
    if fa is not None or fb is not None:
        return fa is not None and fb is not None and fa == fb
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return False


def validate_arg_schema(schema: Any) -> Optional[str]:
    """Validate a ``tool_schema`` argument schema (closed; shape, depth, node count, bounds). None when valid."""
    if not isinstance(schema, dict):
        return "schema must be an object"
    if not _only_keys(schema, ("props", "required")):
        return "unknown schema key"
    return _object_schema_error(schema.get("props"), schema.get("required", _ABSENT), 1, {"nodes": 0})


def _object_schema_error(props: Any, required: Any, depth: int, budget: dict) -> Optional[str]:
    if depth > MAX_SCHEMA_DEPTH:
        return "schema too deep"
    budget["nodes"] += 1
    if budget["nodes"] > MAX_SCHEMA_NODES:
        return "schema too large"
    if not isinstance(props, dict):
        return "props must be an object"
    if len(props) > MAX_OBJECT_PROPS:
        return "too many props"
    for n, spec in props.items():
        if not _SAFE_NAME.fullmatch(n):
            return "invalid property name '%s'" % n[:32]
        e = _spec_error(spec, depth + 1, budget)
        if e:
            return "%s: %s" % (n, e)
    if required is not _ABSENT:
        if not isinstance(required, list) or len(required) > MAX_OBJECT_PROPS:
            return "required must be a short array"
        for r in required:
            if not isinstance(r, str) or r not in props:
                return "required names an undeclared property"
    return None


def _spec_error(spec: Any, depth: int, budget: dict) -> Optional[str]:
    if depth > MAX_SCHEMA_DEPTH:
        return "schema too deep"
    budget["nodes"] += 1
    if budget["nodes"] > MAX_SCHEMA_NODES:
        return "schema too large"
    if not isinstance(spec, dict) or not isinstance(spec.get("type"), str) or spec["type"] not in _SPEC_KEYS:
        return "unknown type"
    t = spec["type"]
    if not _only_keys(spec, _SPEC_KEYS[t]):
        return "unknown spec key"
    if t == "object":
        budget["nodes"] -= 1  # counted once by _object_schema_error
        return _object_schema_error(spec.get("props"), spec.get("required", _ABSENT), depth, budget)
    if t == "array":
        if "minItems" in spec and not _non_neg_int(spec["minItems"], ABSOLUTE_MAX_ARRAY_ITEMS):
            return "bad minItems"
        if "maxItems" in spec and not _non_neg_int(spec["maxItems"], ABSOLUTE_MAX_ARRAY_ITEMS):
            return "bad maxItems"
        if "minItems" in spec and "maxItems" in spec and spec["minItems"] > spec["maxItems"]:
            return "minItems > maxItems"
        return _spec_error(spec.get("items"), depth + 1, budget)

    def ok(v: Any) -> bool:
        if t == "string":
            return isinstance(v, str) and _jslen(v) <= 1024
        if t == "boolean":
            return isinstance(v, bool)
        return _fin(v) is not None and (t == "number" or _is_int(v))

    if "const" in spec and not ok(spec["const"]):
        return "bad const"
    if "enum" in spec:
        en = spec["enum"]
        if not isinstance(en, list) or len(en) == 0 or len(en) > MAX_ENUM_VALUES or not all(ok(x) for x in en):
            return "bad enum"
    if t == "string":
        if "minLength" in spec and not _non_neg_int(spec["minLength"], ABSOLUTE_MAX_STRING_LEN):
            return "bad minLength"
        if "maxLength" in spec and not _non_neg_int(spec["maxLength"], ABSOLUTE_MAX_STRING_LEN):
            return "bad maxLength"
        if "minLength" in spec and "maxLength" in spec and spec["minLength"] > spec["maxLength"]:
            return "minLength > maxLength"
        if "prefix" in spec and (not isinstance(spec["prefix"], str) or _jslen(spec["prefix"]) > 512):
            return "bad prefix"
    elif t in ("number", "integer"):
        if "min" in spec and _fin(spec["min"]) is None:
            return "bad min"
        if "max" in spec and _fin(spec["max"]) is None:
            return "bad max"
        if "min" in spec and "max" in spec and _fin(spec["min"]) > _fin(spec["max"]):
            return "min > max"
    return None


def _show(k: str) -> str:
    import json
    return json.dumps(k[:48] + "…" if _jslen(k) > 48 else k, ensure_ascii=False)


def _check_value(spec: dict, v: Any, path: str, depth: int, budget: dict) -> Optional[str]:
    if depth > MAX_SCHEMA_DEPTH + 1:
        return "%s: too deep" % path
    budget["n"] += 1
    if budget["n"] > MAX_VALUE_NODES:
        return "%s: too many values" % path
    t = spec.get("type")
    if t == "object":
        if not isinstance(v, dict):
            return "%s: expected object" % path
        return _check_object(spec["props"], spec.get("required"), v, path, depth, budget)
    if t == "array":
        if not isinstance(v, list):
            return "%s: expected array" % path
        mx = min(spec.get("maxItems", DEFAULT_MAX_ARRAY_ITEMS), ABSOLUTE_MAX_ARRAY_ITEMS)
        if len(v) > mx:
            return "%s: exceeds maxItems" % path
        if "minItems" in spec and len(v) < spec["minItems"]:
            return "%s: below minItems" % path
        for i, x in enumerate(v):
            e = _check_value(spec["items"], x, "%s[%d]" % (path, i), depth + 1, budget)
            if e:
                return e
        return None
    if t == "string":
        if not isinstance(v, str):
            return "%s: wrong type (expected string)" % path
        n = _jslen(v)
        if n > min(spec.get("maxLength", DEFAULT_MAX_STRING_LEN), ABSOLUTE_MAX_STRING_LEN):
            return "%s: exceeds maxLength" % path
        if "minLength" in spec and n < spec["minLength"]:
            return "%s: below minLength" % path
        if "prefix" in spec and not v.startswith(spec["prefix"]):
            return "%s: violates prefix" % path
    elif t in ("number", "integer"):
        f = _fin(v)
        if f is None or (t == "integer" and not float(f).is_integer()):
            return "%s: wrong type (expected %s)" % (path, t)
        if "min" in spec and f < _fin(spec["min"]):
            return "%s: below min" % path
        if "max" in spec and f > _fin(spec["max"]):
            return "%s: above max" % path
    elif t == "boolean":
        if not isinstance(v, bool):
            return "%s: wrong type (expected boolean)" % path
    else:
        return "%s: unknown type" % path
    if "const" in spec and not _js_eq(spec["const"], v):
        return "%s: violates const" % path
    if "enum" in spec and not any(_js_eq(e, v) for e in spec["enum"]):
        return "%s: violates enum" % path
    return None


def _check_object(props: dict, required: Any, obj: dict, path: str, depth: int, budget: dict) -> Optional[str]:
    for k in obj:
        if k not in props:
            return "%s: unexpected argument %s" % (path, _show(k))
    for r in required or []:
        if r not in obj:
            return "%s: missing required argument '%s'" % (path, r)
    for k in obj:
        e = _check_value(props[k], obj[k], "%s.%s" % (path, k), depth + 1, budget)
        if e:
            return e
    return None


def evaluate_tool_schema(caveat: Any, call: Any) -> "tuple[bool, Optional[str]]":
    """Evaluate a tool call ``{"tool", "args", "tool_signature_digest"?}`` against a ``tool_schema`` caveat.
    Returns ``(ok, reason)``. Same rules as the TypeScript ``evaluateToolSchema``. Never raises."""
    try:
        if not isinstance(caveat, dict) or caveat.get("type") != "tool_schema" \
                or not isinstance(caveat.get("tool"), str) or caveat["tool"] == "":
            return False, "malformed tool_schema caveat"
        verr = validate_arg_schema(caveat.get("schema"))
        if verr:
            return False, "malformed tool_schema caveat: %s" % verr
        if hash_canonical(caveat["schema"]) != caveat.get("schema_digest"):
            return False, "schema digest mismatch"
        sig = _js_string(caveat["signature_digest"]) if "signature_digest" in caveat else "undefined"
        if hash_canonical({"tool": caveat["tool"], "signature_digest": sig, "schema": caveat["schema"]}) \
                != caveat.get("binding_digest"):
            return False, "binding digest mismatch"
        if not isinstance(call, dict) or not isinstance(call.get("tool"), str) or not isinstance(call.get("args"), dict):
            return False, "malformed call"
        if call["tool"] != caveat["tool"]:
            return False, "tool %s not authorized" % _show(call["tool"])
        if "tool_signature_digest" in call and call["tool_signature_digest"] != caveat.get("signature_digest"):
            return False, "signed tool_binding differs from the authorized tool signature"
        e = _check_object(caveat["schema"]["props"], caveat["schema"].get("required"), call["args"], "args", 1, {"n": 0})
        return (False, e) if e else (True, None)
    except Exception:
        return False, "evaluation error (fail closed)"


# ---- the agent-native caveat evaluator (TypeScript evaluateAgentCaveats) ----------------------------------------------

def _agent_caveat_satisfied(cv: Any, ctx: dict, action_ctx: dict, tool_call: dict) -> bool:
    try:
        if not isinstance(cv, dict) or not isinstance(ctx, dict):
            return False
        t = cv.get("type")
        if t == "tool_schema":
            return evaluate_tool_schema(cv, tool_call)[0]
        if t == "predicates":
            allow = cv.get("allow")
            if not isinstance(action_ctx, dict) or not isinstance(allow, list):
                return False
            return any(predicate_matches(p, action_ctx) for p in allow)
        # max_spend and the stock types: the 0.4.1 evaluator (unknown types fail closed there)
        ok, _ = evaluate_caveats([cv], ctx)
        return ok
    except Exception:
        return False


def evaluate_agent_caveats(caveats: Any, ctx: Mapping[str, Any], action_ctx: Optional[dict] = None,
                           tool_call: Optional[dict] = None) -> "tuple[bool, list]":
    """Evaluate caveats with the agent-native evaluator: the stock types of :func:`atlas_pca.evaluate_caveats`, plus
    ``predicates`` (``allow``: the action must match one predicate; needs ``action_ctx`` = ``{"action": {...},
    "subject"?, "env"?}``) and ``tool_schema`` (needs ``tool_call`` = ``{"tool", "args", "tool_signature_digest"?}``).
    ``ctx`` is the stock context (``now``, ``action``, ``blast_radius``, ...). Unknown types fail closed. Returns
    ``(ok, failed_types)``. Never raises."""
    def run() -> "tuple[bool, list]":
        if not isinstance(caveats, list):
            return False, ["<malformed caveats>"]
        failed = []
        for cv in caveats:
            if not _agent_caveat_satisfied(cv, dict(ctx), action_ctx or {}, tool_call or {}):
                t = cv.get("type") if isinstance(cv, dict) else None
                failed.append(t if isinstance(t, str) else "<malformed>")
        return not failed, failed
    try:
        return with_regex_budget(run)
    except Exception:
        return False, ["<evaluation error>"]


# ---- authorize ----------------------------------------------------------------------------------------------------------

@dataclass
class AuthorizedOperation:
    """The operation an allowing decision is bound to. ``id`` is the digest of the presented PCActn."""

    verb: str
    resource: str
    params_digest: str
    id: str


@dataclass
class AuthorizeResult:
    """Outcome of :func:`authorize`. ``allow`` is the one thing a caller must branch on.

    ``status`` is 200, 401 (no / undecodable / unauthenticated proof) or 403. ``checks`` maps each check to ``pass``,
    ``fail`` or ``not-enforced``; ``reason`` is the decisive one (an ``operation`` failure first). ``missing`` names
    configuration components that were absent (the call was refused before any verification)."""

    allow: bool
    status: int
    checks: Dict[str, str] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    reason: Optional[str] = None
    operation: Optional[AuthorizedOperation] = None
    pcactn: Optional[dict] = None
    verdict: Optional[Verdict] = None
    missing: Optional[List[str]] = None
    #: Per check: ``{"outcome": pass | fail | not-enforced | unsupported, "level"?, "suites"?, "reason"?}`` (see
    #: :func:`assurance_report`). ``unsupported`` names a feature this SDK does not implement; it is never a pass.
    assurance: Dict[str, dict] = field(default_factory=dict)
    #: The ternary decision: ``allow`` (and ``allow`` is True), ``escalate`` (refused; ``escalation`` is the request to put
    #: to the principal) or ``deny``. ``allow`` is exactly ``decision == "allow"``: an escalate is never an allow.
    decision: str = "deny"
    #: ``decision == "escalate"``: the escalation request; on an allow admitted by an answer: ``{"answered_by": <principal>}``.
    escalation: Optional[dict] = None
    #: an escalation the ``undo_admit`` hook turned into an allow under a veto window: the admission ``{"id", "window_end",
    #: "compensation": {"verb", "resource", ...}}`` (the action runs now; the principal can veto it until ``window_end``)
    undo: Optional[dict] = None
    #: obligations the enforcement point must perform with this allow (``undo_window`` when ``undo`` is set)
    obligations: Optional[List[dict]] = None

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


def _refuse(status: int, check: str, reason: str, *, missing: Optional[List[str]] = None,
            pcactn: Optional[dict] = None) -> AuthorizeResult:
    return AuthorizeResult(allow=False, status=status, checks={check: "fail"}, reasons=[reason], reason=reason,
                           missing=missing, pcactn=pcactn, assurance={check: {"outcome": "fail"}})


# ---- assurance labels (0.5, additive; T8 / B7) ----------------------------------------------------------------------

#: Attestation levels, weakest first. `unknown` = an unlabelled verifier (satisfies nothing).
_ATT_RANK = {"unknown": 0, "software": 1, "hardware": 2, "multi_root": 3}
_ZK_RANK = {"unknown": 0, "attested_vm": 1, "attested_vm_hw": 1, "stark": 2, "zkvm": 2, "groth16": 3, "policyvm_snark": 3}
_ZK_NEED = {"attested_vm": 1, "attested_vm_hardware": 1, "proof": 2, "snark": 3}
_AWAITING_AUDIT_SCHEMES = ("frost", "frost_dkg", "mpc")
_LABEL_ATTR = "__pca_assurance_label__"
_CHAIN_NAMES = ("cap_chain", "chain")  # the reference names the chain check `cap_chain`, this SDK's verdict `chain`


def set_assurance_label(target: Any, level: str, *, vendor: Optional[str] = None, awaiting_audit: Optional[bool] = None,
                        ceremony: Optional[str] = None) -> Any:
    """Attach an assurance label to a verifier hook, a hardware verifier or a SNARK-like backend (any object that takes
    attributes: a function, an instance). Labels come from the VERIFIER'S configuration, never from the presented
    evidence; an unlabelled hook is ``unknown``, which satisfies no requirement. Returns `target`.

    ``level``    attestation: ``software`` | ``hardware`` | ``multi_root``; zk: ``groth16`` | ``policyvm_snark`` | ``stark`` |
                 ``zkvm`` | ``attested_vm`` | ``attested_vm_hw``; threshold: ``multisig`` | ``frost`` | ``frost_dkg`` | ``mpc``.
    ``vendor``   a vendor or root id, e.g. ``amd-sev-snp``.
    ``awaiting_audit``  crypto awaiting audit (not production): FROST, DKG, MPC.
    ``ceremony`` SNARK backends: ``single-party`` | ``multi-party``."""
    label = {"level": level}
    for k, v in (("vendor", vendor), ("awaiting_audit", awaiting_audit), ("ceremony", ceremony)):
        if v is not None:
            label[k] = v
    setattr(target, _LABEL_ATTR, label)
    return target


def assurance_label_of(target: Any) -> Optional[dict]:
    """The label attached to `target` by :func:`set_assurance_label`, if any."""
    lab = getattr(target, _LABEL_ATTR, None)
    return dict(lab) if isinstance(lab, dict) and isinstance(lab.get("level"), str) else None


def is_awaiting_audit_scheme(scheme: Any) -> bool:
    """True for the threshold schemes awaiting audit (FROST, DKG, MPC)."""
    return scheme in _AWAITING_AUDIT_SCHEMES


def multi_root_level(roots: Sequence[Mapping[str, Any]], threshold: Any) -> str:
    """The attestation level a multi-root N-of-M policy guarantees: the fewest hardware roots any accepted subset can
    contain (all required roots, filled up to `threshold` with the weakest optional ones). Two or more => ``multi_root``,
    one => ``hardware``, none => the weakest level among the roots that could make up the quorum. Each root is
    ``{"verifier": <labelled hook>, "required"?: bool}``."""
    def rank(r: Mapping[str, Any]) -> int:
        lab = assurance_label_of(r.get("verifier"))
        return _ATT_RANK.get(lab["level"] if lab else "unknown", 0)

    req = [r for r in roots if r.get("required") is True]
    opt = sorted((r for r in roots if r.get("required") is not True), key=rank)  # stable, like the reference's sort
    chosen = req + opt[:max(0, int(threshold) - len(req))]
    hw = sum(1 for r in chosen if rank(r) >= _ATT_RANK["hardware"])
    if hw >= 2:
        return "multi_root"
    if hw == 1:
        return "hardware"
    return "software" if min((rank(r) for r in chosen), default=_ATT_RANK["software"]) >= _ATT_RANK["software"] else "unknown"


def signature_level(alg: Any) -> str:
    """Classify one signature suite (absent = Ed25519): ``ed25519``, ``hybrid`` (Ed25519 + a PQ suite), ``pq`` (PQ only),
    or ``unknown`` for an unregistered suite."""
    a = "ed25519" if alg is None else alg
    if a == "ed25519":
        return "ed25519"
    if not isinstance(a, str) or a not in REGISTERED_SUITES:
        return "unknown"
    return "hybrid" if a.startswith("hybrid-") else "pq"


_sig_level = signature_level


def _weakest(levels: List[str]) -> str:
    for lv in ("unknown", "ed25519", "hybrid"):
        if lv in levels:
            return lv
    return "pq" if levels else "unknown"


def _unavailable(alg: Any) -> bool:
    a = "ed25519" if alg is None else alg
    return isinstance(a, str) and a in REGISTERED_SUITES and not suite_available(a)


LEGACY_POLARITY_DEGRADED = "model_polarity 'legacy': a grant reads a model-derived value in where (rule 21)"


def assurance_report(p: Optional[dict], checks: Mapping[str, str], degraded: Optional[Mapping[str, str]] = None, *,
                     hooks: Optional[Mapping[str, Any]] = None, attestation_hook: Any = None,
                     threshold_t: Any = None, allow_unbound_pq: bool = False) -> Dict[str, dict]:
    """What each check rests on (the TypeScript ``assuranceReport``). ``degraded`` maps a check name to why a PASSING check
    rests on a compatibility mode (it is then reported ``degraded`` and refused by any high-assurance policy). Signature
    checks carry their suites and level; a carried ``bond_ref`` is ``unsupported`` (never a pass).

    ``hooks``  the verifier's labelled hooks ``{"attestation", "zk", "threshold", "revocation"}`` (see
               :func:`set_assurance_label`): a passing check reports the hook's level, vendor, awaiting-audit flag and (zk) ceremony;
               an unlabelled hook reports ``unknown``. ``attestation_hook`` (the verifier actually used) wins over
               ``hooks["attestation"]``; ``threshold_t`` is the ``t`` the threshold hook enforced; ``allow_unbound_pq``
               reports a PQ suite that was not pinned as ``unbound_pq``.

    Without ``hooks`` (the :func:`authorize` path: this SDK verifies no zk proof, attestation or threshold co-signature
    there) a failed attestation, a carried ``zk_compliance`` / ``threshold`` and a registered suite whose backend is
    missing here are also reported ``unsupported``."""
    out: Dict[str, dict] = {}
    pp = p if isinstance(p, dict) else {}
    have_p = isinstance(p, dict)
    hk = hooks if isinstance(hooks, Mapping) else {}
    chain = pp.get("cap_chain") if isinstance(pp.get("cap_chain"), list) else []
    hop_algs = [(c.get("alg") if isinstance(c, dict) else None) for c in chain]
    for name, st in checks.items():
        e: dict = {"outcome": st}
        if st == "unsupported":
            e["reason"] = "%s is not implemented by this verifier" % name
        if st == "pass":
            hook = (attestation_hook if attestation_hook is not None else hk.get("attestation")) if name == "attestation" else \
                hk.get("zk") if name == "zk_compliance" else hk.get("threshold") if name == "threshold" else \
                hk.get("revocation") if name == "revocation" else None
            label = assurance_label_of(hook) if hook is not None else None
            if name in ("attestation", "zk_compliance") or (name == "threshold" and hook is not None):
                e["level"] = label["level"] if label else "unknown"
                if label and "vendor" in label:
                    e["vendor"] = label["vendor"]
                if name == "zk_compliance" and label and "ceremony" in label:
                    e["ceremony"] = label["ceremony"]
                if (label and label.get("awaiting_audit") is True) or (name == "threshold" and is_awaiting_audit_scheme(e["level"])):
                    e["awaiting_audit"] = True
                if name == "threshold" and isinstance(threshold_t, (int, float)) and not isinstance(threshold_t, bool):
                    e["t"] = threshold_t
            elif label:
                e["level"] = label["level"]
                if "vendor" in label:
                    e["vendor"] = label["vendor"]
                if label.get("awaiting_audit") is True:
                    e["awaiting_audit"] = True
            if name == "leaf_signature" and have_p:
                alg = pp.get("alg")
                alg = "ed25519" if alg is None else alg
                e["suites"] = [str(alg)]
                e["level"] = "unbound_pq" if allow_unbound_pq and alg != "ed25519" else signature_level(alg)
            if name in _CHAIN_NAMES and have_p and isinstance(pp.get("cap_chain"), list):
                algs = ["ed25519" if a is None else a for a in hop_algs]
                e["suites"] = [str(a) for a in algs]
                e["level"] = "unbound_pq" if allow_unbound_pq and any(a != "ed25519" for a in algs) \
                    else _weakest([signature_level(a) for a in algs])
        out[name] = e

    def unsupported(name: str, why: str) -> None:
        out[name] = {"outcome": "unsupported", "reason": why}

    if hooks is None:
        if out.get("leaf_signature", {}).get("outcome") == "fail" and _unavailable(pp.get("alg")):
            unsupported("leaf_signature", "signature suite '%s' has no backend in this runtime" % pp.get("alg"))
        if out.get("chain", {}).get("outcome") == "fail" and any(_unavailable(a) for a in hop_algs):
            unsupported("chain", "a capability suite has no backend in this runtime")
        if "zk_compliance" in pp:
            unsupported("zk_compliance", "zk compliance verification is not implemented by this SDK")
        if out.get("attestation", {}).get("outcome") == "fail":
            unsupported("attestation", "attestation verification is not implemented by this SDK")
        if "threshold" in pp:
            unsupported("threshold", "threshold co-signatures are not verified by this SDK")
    if "bond_ref" in pp:  # a bond is never verified here: reported, never a pass
        unsupported("bond", "bond verification is not implemented by this verifier")
    for name, why in (degraded or {}).items():
        if out.get(name, {}).get("outcome") == "pass":
            out[name] = dict(out[name], degraded=True, reason=why)
    return out


_ASSURANCE_KEYS = ("attestation", "zk", "signature", "threshold", "allow_awaiting_audit", "allowAwaitingAudit", "allowPreview", "allow_preview")


def unmet_assurance(report: Mapping[str, dict], require: Mapping[str, Any]) -> Optional[str]:
    """The TypeScript ``unmetAssurance``: the reason (prefixed ``assurance: ``) of the first unmet dimension of `require`
    (``attestation``: ``software`` < ``hardware`` < ``multi_root``; ``zk``: ``attested_vm`` | ``attested_vm_hardware`` |
    ``proof`` | ``snark``; ``signature="pq"``; ``threshold=[schemes]``; ``allowAwaitingAudit``), or None. Missing, failed,
    not-enforced, unlabelled, weaker, awaiting-audit, ``degraded`` and ``unsupported`` evidence never meets a requirement. An
    unknown requirement key or value is refused (fail closed)."""
    for name, e in report.items():
        if e.get("outcome") == "unsupported":
            return "assurance: unsupported: %s (%s); a high-assurance policy never accepts it" % (name, e.get("reason") or "not implemented")
    for name, e in report.items():
        if e.get("outcome") == "pass" and e.get("degraded") is True:
            return "assurance: %s rests on a degraded compatibility mode (%s); a high-assurance policy never accepts it" % (
                name, e.get("reason") or "degraded")
    if not isinstance(require, Mapping):
        return "assurance: unknown assurance requirement(s): invalid (fail closed)"
    unknown = [k for k in require if k not in _ASSURANCE_KEYS]
    if unknown:
        return "assurance: unknown assurance requirement(s): %s (fail closed)" % ", ".join(sorted(unknown))
    att, zk, sig, thr = (require.get(k) for k in ("attestation", "zk", "signature", "threshold"))
    allow_awaiting_audit = any(require.get(k) is True for k in ("allowAwaitingAudit", "allow_awaiting_audit", "allowPreview", "allow_preview"))
    if att is not None and att not in ("software", "hardware", "multi_root"):
        return "assurance: unknown attestation requirement %r (fail closed)" % (att,)
    if zk is not None and zk not in _ZK_NEED:
        return "assurance: unknown zk requirement %r (fail closed)" % (zk,)
    if sig is not None and sig != "pq":
        return "assurance: unknown signature requirement %r (fail closed)" % (sig,)
    if thr is not None and not (isinstance(thr, (list, tuple)) and all(isinstance(x, str) for x in thr)):
        return "assurance: unknown threshold requirement %r (fail closed)" % (thr,)

    def need(name: str, what: str):
        e = report.get(name)
        if e is None:
            return "assurance: %s required but there is no %s evidence" % (what, name)
        if e.get("outcome") != "pass":
            return "assurance: %s required but the %s check is %s" % (what, name, e.get("outcome"))
        return e

    if att is not None:
        e = need("attestation", "%s attestation" % att)
        if isinstance(e, str):
            return e
        if _ATT_RANK.get(e.get("level", "unknown"), 0) < _ATT_RANK[att]:
            return "assurance: %s attestation required but the evidence is %s" % (att, e.get("level", "unknown"))
    if zk is not None:
        e = need("zk_compliance", "zk compliance (%s)" % zk)
        if isinstance(e, str):
            return e
        if zk == "attested_vm_hardware" and e.get("level") in ("attested_vm", "unknown", None):
            return "assurance: zk compliance (%s) required but the prover key is not bound to hardware evidence" % zk
        if _ZK_RANK.get(e.get("level", "unknown"), 0) < _ZK_NEED[zk]:
            return "assurance: zk compliance (%s) required but the evidence is %s" % (zk, e.get("level", "unknown"))
    if sig == "pq":
        for name in ("leaf_signature", next((n for n in _CHAIN_NAMES if n in report), "cap_chain")):
            e = need(name, "post-quantum signatures")
            if isinstance(e, str):
                return e
            if e.get("level") not in ("pq", "hybrid"):
                return "assurance: post-quantum signatures required but %s is %s" % (name, e.get("level", "unknown"))
    if thr is not None:
        names = " | ".join(thr)
        e = need("threshold", "threshold (%s)" % names)
        if isinstance(e, str):
            return e
        if e.get("level") is None:
            return "assurance: threshold (%s) required but no threshold verifier enforced it" % names
        if e["level"] not in thr:
            return "assurance: threshold (%s) required but the scheme is %s" % (names, e["level"])
    if not allow_awaiting_audit:
        for name, e in report.items():
            if e.get("outcome") != "pass" or e.get("awaiting_audit") is not True and e.get("preview") is not True:
                continue
            if name == "threshold" and thr is not None and e.get("level", "") in thr:
                continue
            return "assurance: %s rests on crypto awaiting audit (%s); set allowAwaitingAudit or list the scheme to accept it" % (name, e.get("level", "unknown"))
    return None


def missing_authorize_components(*, audience: Any, resolve_grant: Any, state_store: Any, is_revoked: Any,
                                 escalation_principals: Any = None) -> List[str]:
    """Names of the required components that are absent (empty = complete). With ``escalation_principals`` the store must
    also expose ``last(key)`` (the history head an answer is bound to)."""
    missing = []
    if not isinstance(audience, str) or audience == "":
        missing.append("audience")
    if not callable(resolve_grant):
        missing.append("resolve_grant")
    if state_store is None or not callable(getattr(state_store, "claim", None)):
        missing.append("state_store")
    if not callable(is_revoked):
        missing.append("is_revoked")
    if escalation_principals and state_store is not None and not callable(getattr(state_store, "last", None)):
        missing.append("state_store.last (required by escalation_principals)")
    return missing


def _needs_model_rules(grant: Any) -> bool:
    from .decision import model_paths_read
    env = read_envelope(grant)
    return env is not None and ("units" in env or "tighten" in env or "model_polarity" in env
                                or len(model_paths_read([env.get("predicates")])) > 0)


def _degraded_of(verdict: Any) -> Optional[Dict[str, str]]:
    """The degraded passing checks of a core verdict: rule 21 under ``model_polarity: "legacy"``."""
    return {"tighten": LEGACY_POLARITY_DEGRADED} if getattr(verdict, "legacy_model_polarity", False) else None


def _valid_operation(op: Any) -> bool:
    if not isinstance(op, Mapping):
        return False
    return (isinstance(op.get("verb"), str) and op["verb"] != "" and isinstance(op.get("resource"), str)
            and op["resource"] != "" and isinstance(op.get("params"), dict))


def _decisive(checks: Dict[str, str], reasons: List[str]) -> str:
    names = sorted(checks, key=lambda n: 0 if n == "operation" else 1)  # stable: a binding failure first
    for n in names:
        if checks[n] != "fail":
            continue
        hit = next((r for r in reasons if r.startswith(n + ":")), None)
        if hit:
            return hit
    return reasons[0] if reasons else "denied"


def _coerce(pcactn: Any) -> "tuple[Optional[dict], Optional[str]]":
    if isinstance(pcactn, dict):
        return pcactn, None
    if isinstance(pcactn, (str, bytes, bytearray)):
        if artifact_too_large(pcactn):
            return None, "undecodable"
        try:
            text = bytes(pcactn).decode("utf-8") if isinstance(pcactn, (bytes, bytearray)) else pcactn
            obj = strict_parse(text)
        except (StrictJsonError, UnicodeDecodeError):
            return None, "undecodable"
        return (obj, None) if isinstance(obj, dict) else (None, "undecodable")
    return None, "absent" if pcactn is None else "undecodable"


def _revocation_ids(policy: RevocationStaleness, p: dict) -> list:
    """Capability ids that need a non-revocation proof: `policy.ids(p)`, else every id in the PCActn's cap_chain. Total
    (an id source that raises or a malformed chain yields None, which the caller's gate cannot satisfy: fail closed)."""
    try:
        if policy.ids is not None:
            return list(policy.ids(p))
        return [c["id"] for c in p["cap_chain"]]
    except Exception:  # noqa: BLE001
        return [None]


def authorize(pcactn: Union[dict, str, bytes, None], *, operation: Mapping[str, Any], audience: str,
              resolve_grant: GrantResolver, state_store: Any, is_revoked: RevocationCheck,
              now: Optional[int] = None, plan: Optional[str] = None,
              context: Optional[Callable[[dict], Optional[dict]]] = None, intent_policy: Optional[dict] = None,
              intent_v2: Any = None, allowed_suites: Any = None, require: Sequence[str] = (),
              require_assurance: Optional[Mapping[str, Any]] = None, escalation_principals: Any = None,
              escalation_answer: Any = None, escalation_request_ttl_ms: int = 3_600_000,
              revocation_staleness: Optional[RevocationStaleness] = None, plans: Any = None,
              k1: Any = None, uses_store: Any = None, fresh_at: Any = None,
              escalation_render: Any = None, insecure_unbound_approval: bool = False,
              workflow: Any = None, workflow_step: Any = None, provenance: Any = None,
              provenance_request: Any = None, provenance_mediators: Sequence[Any] = (),
              provenance_actions: Optional[Callable[[dict], Optional[dict]]] = None,
              provenance_observed: Optional[Callable[..., Any]] = None,
              undo_admit: Optional[Callable[[dict, dict, dict], Optional[dict]]] = None) -> AuthorizeResult:
    """Authorize ONE operation (see the module doc for the pipeline).

    ``pcactn``        the presented PCActn: a parsed object, or its JSON text (strict profile).
    ``operation``     ``{"verb", "resource", "params"}``: what the handler / tool WILL execute, from the server's own
                      routing and parsed input, never from the PCActn. ``params`` must be a dict.
    ``audience``      this resource server's id (the PCActn's signed ``aud`` must equal it).
    ``resolve_grant`` ``(grant_ref) -> grant | None`` from your own store.
    ``state_store``   replay store with an atomic ``claim(key, counter)`` (:class:`MemoryStateStore`,
                      :class:`SqliteStateStore`, or your database).
    ``is_revoked``    ``(pcactn, grant) -> bool``; only ``False`` passes (anything else, or an exception, denies).
    ``now``           epoch milliseconds (default: wall clock).
    ``plan``          ``"single-step"``: accept a one-node plan whose node is exactly this operation. Otherwise
                      ``context`` must return the principal-authorized ``plan`` with ``plan_authorized: True``.
    ``context``       ``(pcactn) -> dict | None`` with optional ``plan``, ``plan_authorized``, ``subject``, ``env``,
                      ``blast_radius``, ``recent_action_times``, ``reversibility_class`` (the server's
                      authoritative class; the agent may only declare a stricter one).
    ``intent_policy`` / ``intent_v2`` / ``allowed_suites``: forwarded to ``verify_pcactn_core`` (``intent_v2`` may be
                      a callable ``(pcactn) -> dict``; its ``params`` default to the operation's).
    ``fresh_at``      consistency-token policy forwarded to ``verify_pcactn_core`` (see ``atlas_pca.fresh_at``): a dict, or a
                      callable ``(pcactn) -> dict | None`` (it raising denies). A stale verifier yields ``decision == "escalate"``.
    ``require``       extra check names that must pass (the defaults always apply).
    ``escalation_principals`` / ``escalation_answer`` a verdict whose every failing check is escalate-class (an unanswered
                      ``intent_required`` question) has ``decision == "escalate"`` and is refused with the request in
                      ``result.escalation``; it is admitted only with ``escalation_answer`` (a principal-signed
                      EscalationAnswer) signed by one of the pinned ``escalation_principals`` and bound to this grant, this
                      PCActn and the holder's history head (the store MUST offer ``last(key)``: without it the call is refused as
                      ``authorize_config``). The replay claim spends it; an answer never upgrades a deny.
    ``k1`` / ``uses_store`` caveat language v2: ``k1`` is the verifier's own K1 input (``pins``, ``discharges``, ``narrow``,
                      ``spiffe_id``, ``history``, ``revoked_discharges``; ``{}`` is configured, None is not); ``action_digest`` is
                      always computed here. A chain carrying a K1 caveat is refused without ``k1``. ``uses_store`` (an atomic
                      ``consume_once(key, retain_until, now)``, e.g. :class:`MemoryStateStore`) spends ``max_uses`` slots after the
                      replay counter was claimed; without it a ``max_uses`` caveat is refused.
    ``workflow`` / ``workflow_step`` workflow admission (K5, C-308). ``workflow`` is the verifier's option ``{"principal", "rs_signer",
                      "required"?}`` (the keys THIS server pinned; ``required`` must be True to refuse a call without a step); a
                      call carrying ``workflow_step`` (``{"commitment", "receipts", "step", "units"?, "goal_digest"?}``) is
                      decided by ``admit_step`` BEFORE the replay claim, so a refusal never spends the counter. A non-allow is a
                      403 whose checks are exactly ``{workflow: fail}`` (an escalate keeps ``decision == "escalate"``).
    ``escalation_request_ttl_ms`` how long an issued EscalationRequest is valid (default one hour).
    ``revocation_staleness`` a :class:`RevocationStaleness` (off when None): the verifier caps how old the revocation
                      state may be, with a stricter window for irreversible actions. The state comes from
                      ``context(pcactn)["revocation_state"]`` (``{"kind": "epoch", "epoch": <guardian-signed epoch>,
                      "root"?, "last_accepted_epoch"?}`` or ``{"kind": "root", "root", "issued_at"}``, see
                      :func:`atlas_pca.check_revocation_state`); ``is_revoked`` still decides revocation. A failing age
                      check fails the ``freshness`` check; an irreversible action with no verifiable (guardian-signed)
                      state is refused unless ``allow_unsigned_root_for_irreversible``.
    ``plans``         a :class:`PlanRegistry` (T10): when ``context`` supplies no ``plan``, the registered plan for the
                      PCActn's ``plan.root`` and its executability (authorized, approval unexpired, nodes still hash to the
                      root) feed ``plan_root_authorized``, and the ``plan_state`` check names the state on a denial. An
                      unknown root is refused (``plan_state``) unless ``plan="single-step"`` applies.
    ``require_assurance`` high-assurance policy, e.g. ``{"signature": "pq"}``: weaker, missing, failed or unsupported
                      evidence fails the ``assurance`` check before any replay state is written. Every result carries
                      ``assurance`` (see :func:`assurance_report`).
    ``provenance``    PROVENANCE BY DEFAULT (always on, check ``provenance_flow``): the provenance bundle for this call (a
                      :class:`atlas_pca.arg_provenance.ProvenanceRecorder` ``for_action`` result). Without it the bundle is read
                      from ``provenance_request`` (``(headers, body)``: header ``PCA-Provenance``, base64url JSON, else the body
                      member ``pca_provenance``; an unreadable header denies). A sensitive action (anything
                      ``provenance_actions`` does not define as read-only, and every unknown action) is ``escalate`` unless its
                      choice and every sink argument derive from the principal: a verified chain from a pinned mediator whose
                      context was the principal's own message, a value the principal typed verbatim, an executable
                      principal-authorized plan from ``plans``, or an admitted ``workflow`` step (choice only). A
                      principal-signed escalation answer admits the escalated call; a forged bundle denies. The ONLY opt-out
                      is the grant envelope's signed member ``provenance: {"mode": "insecure_off"}`` (dangerous).
    ``provenance_mediators`` pinned mediator keys ``[{"mediator", "kid", "pk", "pq_pk"?}]`` (the grant envelope's
                      ``provenance.mediators`` are added). ``provenance_actions`` ``(operation) -> facts | None``: the action's
                      ``{"effects", "traits", "params": {name: floor}}`` from YOUR action definitions (None = unknown =
                      sensitive). ``provenance_observed`` ``(pcactn, operation, session) -> [{"origin", "source"}]``: untrusted
                      content THIS server saw reach the agent's context (raise only). A hook that raises denies.
    ``undo_admit``    optional undo windows: ``(pcactn, grant, operation) -> admission | None``, called ONLY for an
                      unanswered ``escalate`` that is not a provenance escalation (``provenance_flow`` or rule 17
                      ``provenance`` failing never reaches it). The admission ``{"id", "window_end", "compensation": {"verb",
                      ...}}`` must be returned only AFTER the undo coordinator durably opened the window's record (the
                      TypeScript coordinator or the hosted ledger); a hook that raises or returns None leaves the escalation
                      standing. An admission turns the escalation into an allow: the result carries ``undo`` and the
                      ``undo_window`` obligation, which the enforcement point must support.
    """
    try:
        r = _authorize(pcactn, operation, audience, resolve_grant, state_store, is_revoked, now, plan, context,
                       intent_policy, intent_v2, allowed_suites, require, require_assurance, escalation_principals,
                       escalation_answer, escalation_request_ttl_ms, revocation_staleness, plans, k1, uses_store, fresh_at,
                       escalation_render, insecure_unbound_approval, workflow, workflow_step, provenance,
                       provenance_request, provenance_mediators, provenance_actions, provenance_observed, undo_admit)
        if not r.assurance:
            r.assurance = assurance_report(r.pcactn, r.checks, _degraded_of(r.verdict))
        return r
    except Exception as e:  # noqa: BLE001 - never raise: an internal error denies
        return _refuse(403, "authorize", "authorize: error (fail closed): %s" % type(e).__name__)


def _authorize(pcactn, operation, audience, resolve_grant, state_store, is_revoked, now, plan, context, intent_policy,
               intent_v2, allowed_suites, require, require_assurance=None, escalation_principals=None,
               escalation_answer=None, escalation_request_ttl_ms=3_600_000, revocation_staleness=None, plans=None,
               k1=None, uses_store=None, fresh_at=None, escalation_render=None,
               insecure_unbound_approval=False, workflow=None, workflow_step=None, provenance=None,
               provenance_request=None, provenance_mediators=(), provenance_actions=None, provenance_observed=None,
               undo_admit=None) -> AuthorizeResult:
    missing = missing_authorize_components(audience=audience, resolve_grant=resolve_grant, state_store=state_store,
                                           is_revoked=is_revoked, escalation_principals=escalation_principals)
    if revocation_staleness is not None and not isinstance(revocation_staleness, RevocationStaleness):
        missing.append("revocation_staleness (must be a RevocationStaleness)")
    if plan is not None and plan != "single-step":
        missing.append("plan (only 'single-step' or None)")
    if missing:
        return _refuse(403, "authorize_config", "authorize_config: missing required component(s): %s (fail closed)"
                       % ", ".join(missing), missing=missing)
    if not _valid_operation(operation):
        return _refuse(403, "operation", "operation: authorize needs the operation to execute (verb, resource, params) "
                                         "(fail closed)")
    # a private copy: the params that are verified cannot change under the verifier
    op = {"verb": operation["verb"], "resource": operation["resource"],
          "params": strict_parse(_canon_json(operation["params"]))}

    # workflow configured but this call carries no step: refused before the PCActn is read (it needs none)
    if workflow is not None:
        if not isinstance(workflow, Mapping):
            return _refuse(403, "workflow", "workflow: invalid workflow option (fail closed)")
        if workflow_step is None and workflow.get("required") is True:
            return _refuse(403, "workflow", "workflow: this call carries no workflow step (fail closed)")

    p, err = _coerce(pcactn)
    if p is None:
        if err == "absent":
            return _refuse(401, "wire", "wire: no PCActn presented")
        # an undecodable PCActn is never judged by the workflow gate: the pipeline's own refusal comes first
        return _refuse(401, "pcactn", "undecodable PCActn: could not be decoded")
    grant_ref = p.get("grant_ref")
    if not isinstance(grant_ref, str):
        return _refuse(401, "malformed", "malformed: grant_ref is not a string", pcactn=p)
    try:
        grant = resolve_grant(grant_ref)
    except Exception:  # noqa: BLE001
        return _refuse(403, "resolve_grant", "resolve_grant: grant resolution failed (fail closed)", pcactn=p)
    if not isinstance(grant, dict):
        return _refuse(401, "grant_ref", "grant_ref: does not resolve to a known grant", pcactn=p)

    if now is None:
        now = int(time.time() * 1000)
    ctx: dict = {}
    if context is not None:
        try:
            ctx = context(p) or {}
        except Exception:  # noqa: BLE001
            return _refuse(403, "context", "context: the context callback failed (fail closed)", pcactn=p)
        if not isinstance(ctx, dict):
            return _refuse(403, "context", "context: the context callback must return a dict (fail closed)", pcactn=p)

    plan_state: Optional[dict] = None
    # principal commitments for the provenance gate: an executable principal-authorized REGISTRY plan (never a plan the
    # request or the context supplies), an admitted step of the principal-signed workflow (the choice only)
    principal_plan = principal_control = False
    if plans is not None and ctx.get("plan") is None:
        pl0 = p.get("plan") if isinstance(p.get("plan"), dict) else {}
        root0 = pl0.get("root") if isinstance(pl0.get("root"), str) else ""
        try:
            pc = plans.context(grant_ref, root0, now)
        except Exception:  # noqa: BLE001
            return _refuse(403, "plans", "plans: the plan registry failed (fail closed)", pcactn=p)
        if pc is not None:
            ctx = dict(ctx, plan=pc["plan"], plan_authorized=pc["planAuthorized"])
            plan_state = pc["status"]
            principal_plan = pc["planAuthorized"] is True and isinstance(plan_state, dict) and plan_state.get("executable") is True
        elif plan != "single-step":
            plan_state = {"state": "unknown", "executable": False, "reason": "plan %s is unknown to the plan registry" % root0}

    v2 = intent_v2
    if callable(intent_v2):
        try:
            v2 = intent_v2(p)
        except Exception:  # noqa: BLE001
            return _refuse(403, "intent_v2", "intent_v2: verifier state unavailable (fail closed)", pcactn=p)
    # Rules 20 / 21 read the signed envelope of the stored grant: when it carries `units` / `tighten` / `model_polarity` or a
    # grant-side `where` reads a model-derived path, the v2 pipeline needs the plaintext params and the host env even if the
    # host configured no v2 context (TypeScript `needsModelRules`).
    if isinstance(v2, dict) or (v2 is None and _needs_model_rules(grant)):
        v2 = dict(v2 or {})
        if v2.get("params") is None:
            v2["params"] = op["params"]
        if v2.get("env") is None:  # `intentV2.env ?? ctx.env`: a null env is the authorize context's (a non-object one is malformed)
            v2.pop("env", None)
            if ctx.get("env") is not None:
                v2["env"] = ctx["env"]

    fa = fresh_at
    if callable(fresh_at):
        try:
            fa = fresh_at(p)
        except Exception:  # noqa: BLE001
            return _refuse(403, "fresh_at", "fresh_at: verifier state unavailable (fail closed)", pcactn=p)

    # ---- workflow admission (K5, C-308): before the core checks and the replay claim, so a refusal never consumes the counter
    if workflow is not None:
        if workflow_step is not None:
            wf = workflow_step if isinstance(workflow_step, Mapping) else {}
            pl0 = p.get("plan")
            root = pl0.get("root") if isinstance(pl0, dict) and isinstance(pl0.get("root"), str) else None
            units = wf.get("units")
            d = admit_step({"workflow": wf.get("commitment"), "principal": workflow.get("principal"),
                            "rs_signer": workflow.get("rs_signer"), "receipts": wf.get("receipts"), "now": now,
                            "request": {"step": wf.get("step"), "verb": op["verb"], "resource": op["resource"],
                                        "params": op["params"], "units": {} if units is None else units,
                                        "goal_digest": wf.get("goal_digest"), "plan_root": root}})
            if d.get("decision") != "allow":
                r = _refuse(403, "workflow", "workflow: %s%s" % (d.get("code") or "refused",
                                                                " (step %s)" % d["step"] if d.get("step") else ""), pcactn=p)
                if d.get("decision") == "escalate":
                    r.decision = "escalate"
                return r
            principal_control = True

    # ---- 1. the core checks
    core = verify_pcactn_core(p, grant, now=now, audience=audience, allowed_suites=allowed_suites,
                              intent_policy=intent_policy, intent_v2=v2, fresh_at=fa)
    if core.checks.get("wire") is False:
        r = core.reason or "wire: malformed PCActn"
        return AuthorizeResult(allow=False, status=401, checks={"wire": "fail", "malformed": "fail"}, reasons=[r],
                               reason=r, pcactn=p, verdict=core)
    checks: Dict[str, str] = {k: ("pass" if ok else "fail") for k, ok in core.checks.items()}
    reasons: List[str] = [] if core.allow else (list(core.reasons) or ([core.reason] if core.reason else []))

    def mark(name: str, status: str) -> None:
        checks[name] = status

    def fail(name: str, why: str) -> None:
        checks[name] = "fail"
        reasons.append("%s: %s" % (name, why))

    # ---- 2. revocation (required) and a carried zk proof (no verifier here: fail closed)
    try:
        revoked = is_revoked(p, grant)
    except Exception:  # noqa: BLE001
        revoked = None
    if revoked is False:
        mark("revocation", "pass")
    else:
        fail("revocation", "the grant is revoked" if revoked is True else "the revocation check failed (fail closed)")
    accepted_epoch = None
    if revocation_staleness is not None:
        # T9: the revocation state must be recent enough for the action's class (the stricter of the server's and the signed one)
        a0 = p.get("action") if isinstance(p.get("action"), dict) else {}
        state = ctx.get("revocation_state")
        if state is None:
            if effective_reversibility(ctx.get("reversibility_class"), a0.get("reversibility_class")) == "irreversible" \
                    and not revocation_staleness.allow_unsigned_root_for_irreversible:
                fail("freshness", "no verifiable (guardian-signed) revocation state for an irreversible action")
            else:
                mark("freshness", "not-enforced")
        else:
            fr = p.get("freshness")
            st = check_revocation_state(revocation_staleness, state, now=now, grant_ref=grant_ref,
                                        signed_class=a0.get("reversibility_class"), server_class=ctx.get("reversibility_class"),
                                        pcactn_epoch=fr["epoch"] if isinstance(fr, dict) and "epoch" in fr else _MISSING_EPOCH,
                                        ids=_revocation_ids(revocation_staleness, p),
                                        proof_for=(lambda rid: revocation_staleness.proof_for(rid, p))
                                        if revocation_staleness.proof_for is not None else None)
            if st["ok"]:
                mark("freshness", "pass")
                accepted_epoch = st.get("epoch")
            else:
                fail("freshness", st["reason"])
    if "zk_compliance" in p:
        fail("zk_compliance", "PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed)")

    action = p.get("action") if isinstance(p.get("action"), dict) else {}
    signed_digest = action.get("params_digest")
    op_digest = params_digest(op["params"])

    # ---- 3. the operation binding
    if action.get("verb") != op["verb"] or action.get("resource") != op["resource"]:
        fail("operation", "the proof is for %s on %s, but this operation is %s on %s"
             % (_js_string(action.get("verb")), _js_string(action.get("resource")), op["verb"], op["resource"]))
    elif op_digest != signed_digest:
        fail("operation", "the proof's params_digest does not match the params of this %s operation" % op["verb"])
    else:
        mark("operation", "pass")

    # ---- 4. grant_ref, params, plan, attestation, reversibility
    if grant_ref == grant.get("id"):
        mark("grant_ref", "pass")
    else:
        fail("grant_ref", "does not reference the supplied grant")
    if op_digest == signed_digest:
        mark("params_digest", "pass")
    else:
        fail("params_digest", "supplied params do not hash to action.params_digest")

    pl = p.get("plan") if isinstance(p.get("plan"), dict) else {}
    node_id = pl.get("node_id")
    plan_nodes = ctx.get("plan")
    plan_authorized = ctx.get("plan_authorized")
    if plan == "single-step" and plan_nodes is None:
        plan_nodes = [{"id": _js_string(node_id), "verb": op["verb"], "resource": op["resource"],
                       "params_digest": op_digest, "reversibility_class": action.get("reversibility_class")}]
        plan_authorized = True
    if plan_nodes is not None:
        try:
            known = merkle_root([_plan_leaf(n.get("id"), n, conditions_digest(n.get("pre"), n.get("post")))
                                 for n in plan_nodes])
        except Exception:  # noqa: BLE001
            known = None
        if known is None or known != pl.get("root"):
            fail("plan_root_authorized", "known plan does not match plan.root")
        elif plan_authorized is not True:
            fail("plan_root_authorized", "the plan root has not been authorized by the principal")
        else:
            mark("plan_root_authorized", "pass")
    else:
        # K5: default-deny. The opt-out (insecure_skip_plan_root_check) exists only on the lower-level verifiers; authorize never has it.
        fail("plan_root_authorized", "default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecure_skip_plan_root_check)")

    if plan_state is not None:
        if plan_state.get("executable"):
            mark("plan_state", "pass")
        else:
            fail("plan_state", plan_state.get("reason") or "plan is %s" % plan_state.get("state"))

    env = read_envelope(grant)
    if _requires_attestation(env.get("agent_binding") if env else None):
        fail("attestation", "the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED "
                            "(no attestation verifier in this SDK: fail closed)")

    declared = action.get("reversibility_class")
    effective = declared
    server_class = ctx.get("reversibility_class")
    if server_class is not None:
        dr, sr = _class_rank(declared), _class_rank(server_class)
        if dr < sr:
            fail("reversibility", "declared class '%s' is less restrictive than the authoritative '%s'"
                 % (_js_string(declared), server_class))
        else:
            mark("reversibility", "pass")
        effective = declared if dr > sr else server_class

    # ---- 5. policy: envelope predicates + envelope caveats + root caveats; then the delegated caveats
    chain = p.get("cap_chain") if isinstance(p.get("cap_chain"), list) else []
    depth = max(0, len(chain) - 1)
    inner = {"verb": action.get("verb"), "resource": action.get("resource"), "params": op["params"]}
    if effective is not None:
        inner["reversibility_class"] = effective
    action_ctx: dict = {"action": inner}
    if ctx.get("subject") is not None:
        action_ctx["subject"] = ctx["subject"]
    pred_env = _v2_env(p, grant, v2, now, ctx.get("env"))
    if pred_env is not None:
        action_ctx["env"] = pred_env
    tool_call: dict = {"tool": inner["verb"] if isinstance(inner["verb"], str) else "", "args": op["params"]}
    if isinstance(p.get("tool_binding"), str):
        tool_call["tool_signature_digest"] = p["tool_binding"]
    rev_class = effective
    if rev_class is None and isinstance(node_id, str) and isinstance(plan_nodes, list):
        rev_class = next((n.get("reversibility_class") for n in plan_nodes
                          if isinstance(n, dict) and n.get("id") == node_id), None)
    cctx = {"now": now, "action": inner, "delegation_depth": depth}
    if ctx.get("blast_radius") is not None:
        cctx["blast_radius"] = ctx["blast_radius"]
    if rev_class is not None:
        cctx["reversibility_class"] = rev_class
    if ctx.get("recent_action_times") is not None:
        cctx["recent_action_times"] = ctx["recent_action_times"]

    def policy_step() -> List[str]:
        why: List[str] = []
        if env is None:
            return ["grant carries no valid envelope"]
        pr = evaluate_predicates(env["predicates"], action_ctx)
        if not pr.get("allowed"):
            why.append(pr.get("reason") or "action not permitted by envelope predicates")
        ok, failed = evaluate_agent_caveats(env["caveats"], cctx, action_ctx, tool_call)
        if not ok:
            why.append("caveat(s) not satisfied: %s" % ", ".join(failed))
        rc = root_caveats(grant)  # K1 types are evaluated over the whole chain below, never by the stock evaluator
        ok, failed = evaluate_agent_caveats([c for c in rc if not is_k1_caveat(c)] if isinstance(rc, list) else rc,
                                            cctx, action_ctx, tool_call)
        if not ok:
            why.append("root caveat(s) not satisfied: %s" % ", ".join(failed))
        return why

    leaf = chain[-1] if chain and isinstance(chain[-1], dict) else {}
    gcs = grant.get("caveats") if isinstance(grant.get("caveats"), list) else []
    lcs = leaf.get("caveats") if isinstance(leaf.get("caveats"), list) else []
    k1_in = k1 if isinstance(k1, dict) else None
    k1r = None
    k1_bad: List[str] = []
    if any(is_k1_caveat(c) for c in gcs + lcs) or (k1_in is not None and "narrow" in k1_in):
        if chain and any(is_k1_caveat(c) for c in gcs) and lcs[:len(gcs)] != gcs:
            k1_bad.append("a root K1 caveat is not carried by the leaf")
        kin = None if k1_in is None else {**k1_in, "action_digest": discharge_action_digest(p)}
        k1r = evaluate_k1(grant, chain, kin, {"now": now, "action": inner})
    if chain or k1r is not None:
        extra = lcs[len(gcs):] if chain and isinstance(leaf.get("caveats"), list) else ([] if not chain else None)
        if isinstance(extra, list):
            extra = [c for c in extra if not is_k1_caveat(c)] + (k1r["plain"] if k1r else [])
        ok, failed = evaluate_agent_caveats(extra, cctx, action_ctx, tool_call)
        if k1r is not None and not k1r["ok"]:
            failed = list(failed) + k1r["failed"]
        failed = list(failed) + k1_bad
        why = "; ".join(k1r["reasons"]) if k1r is not None and not k1r["ok"] else ""
        if ok and not failed:
            mark("delegated_caveats", "pass")
        else:
            fail("delegated_caveats", "delegation caveat(s) not satisfied: %s%s" % (", ".join(failed), " (%s)" % why if why else ""))

    try:
        policy_why = with_regex_budget(policy_step)
    except Exception:  # noqa: BLE001
        policy_why = ["policy evaluation error (fail closed)"]
    if policy_why:
        checks["policy"] = "fail"
        reasons.extend("policy: %s" % w for w in policy_why)
    else:
        mark("policy", "pass")

    # ---- required checks (default-deny), then the replay counter
    # ``replay`` is tentative until the atomic claim below (a refused claim flips it to fail); the store is present here.
    mark("replay", "pass")
    # the old name ``counter`` is an alias of ``replay`` in a ``require`` list
    for name in list(DEFAULT_REQUIRED_CHECKS) + ["replay" if n == "counter" else n for n in require if isinstance(n, str)]:
        st = checks.get(name)
        if st != "pass" and st != "fail":
            checks[name] = "fail"
            reasons.append("%s: required check is %s (default-deny: not enforced by this resource server)"
                           % (name, st or "absent"))

    # ---- high-assurance policy (before any replay state is written)
    if require_assurance is not None:
        unmet = unmet_assurance(assurance_report(p, checks, _degraded_of(core)), require_assurance if isinstance(require_assurance, Mapping)
                                else {"invalid": True})
        if unmet is None:
            mark("assurance", "pass")
        else:
            checks["assurance"] = "fail"
            reasons.append(unmet)  # already prefixed `assurance: `

    # ---- provenance by default (its own check name: ``provenance`` is the Intent v2 rule 17 check, never overwritten)
    pv_status, pv_reason = _provenance_flow(env, op, p, provenance, provenance_request, provenance_mediators,
                                            provenance_actions, provenance_observed, principal_plan, principal_control)
    checks["provenance_flow"] = pv_status
    if pv_status == "fail":
        reasons.append("provenance_flow: %s" % pv_reason)

    holder = chain[-1].get("holder") if chain and isinstance(chain[-1], dict) else None
    counter = p.get("counter")
    skey = state_key(grant["id"], holder) if isinstance(holder, str) and isinstance(grant.get("id"), str) else None
    esc: dict = {"request": None, "by": None, "undo": None}

    def deny() -> AuthorizeResult:
        status = 401 if any(checks.get(c) == "fail" for c in _AUTHN_CHECKS) else 403
        return AuthorizeResult(allow=False, status=status, checks=checks, reasons=reasons,
                               reason=_decisive(checks, reasons), pcactn=p, verdict=core,
                               decision="escalate" if esc["request"] is not None else "deny", escalation=esc["request"])

    if any(s == "fail" for s in checks.values()):
        if decision_of({"allow": False, "checks": checks, "reasons": reasons}) != "escalate" or skey is None:
            return deny()
        # Ternary decision: every failing check is escalate-class. Never admitted by itself.
        last = None
        head_known = False
        peek = getattr(state_store, "last", None)
        if callable(peek):
            try:
                last = peek(skey)
                head_known = last is None or _is_int(last)
            except Exception:  # noqa: BLE001
                head_known = False
        # K7: the verifier's own recomputation of H(R) from the executed params and its definition (None: none could be derived)
        render_digest = None
        if callable(escalation_render):
            try:
                render_digest = escalation_render(p)
            except Exception:  # noqa: BLE001
                render_digest = None
        esc["request"] = build_escalation_request(aud=audience, grant=grant, pcactn=p, last_counter=last if head_known else None,
                                                  reasons=reasons, now=now, ttl_ms=escalation_request_ttl_ms, render_digest=render_digest)
        if not insecure_unbound_approval and render_digest is None and escalation_principals and escalation_answer is not None:
            reasons.append("escalation: an approval render is required and none could be recomputed (pass escalation_render, or insecure_unbound_approval=True)")
        elif escalation_principals and escalation_answer is not None and head_known:
            bind = {"policy_digest": escalation_policy_digest(grant), "action_digest": escalation_action_digest(p),
                    "history_head": escalation_history_head(last)}
            if render_digest is not None:
                bind["render_digest"] = render_digest
            v = verify_escalation_answer(escalation_answer, escalation_principals, bind, now)
            if v.get("ok") and v.get("decision") == "allow":
                for n, st in list(checks.items()):
                    if st == "fail":
                        checks[n] = "pass"
                checks["escalation"] = "pass"
                reasons.append("escalation: answered allow by principal %s" % v["principal"][:8])
                esc["by"], esc["request"] = v["principal"], None
            else:
                reasons.append("escalation: %s" % ("the principal answered deny" if v.get("ok") else v.get("reason")))
        # Undo window: an unanswered escalation runs now under a veto window instead of waiting for prior approval. Only the
        # escalate-class failures are lifted (exactly what an answer would lift). Never for a provenance escalation:
        # reversibility does not make an action injected content chose safe to run.
        answer_presented = bool(escalation_principals) and escalation_answer is not None
        prov_escalated = checks.get("provenance_flow") == "fail" or checks.get("provenance") == "fail"
        if esc["request"] is not None and undo_admit is not None and not answer_presented and not prov_escalated:
            adm = _undo_admission(undo_admit, p, grant, op)
            if adm is not None:
                for n, st in list(checks.items()):
                    if st == "fail":
                        checks[n] = "pass"
                checks["undo_window"] = "pass"
                reasons.append("undo_window: runs now under a veto window until %s (compensation %s)"
                               % (adm["window_end"], adm["compensation"]["verb"]))
                esc["request"], esc["undo"] = None, adm
        if esc["request"] is not None:
            return deny()

    if not isinstance(holder, str) or not isinstance(grant.get("id"), str):
        fail("replay", "no counter stream for this proof (fail closed)")
        return deny()
    try:
        claimed = state_store.claim(state_key(grant["id"], holder), counter)
    except Exception:  # noqa: BLE001
        claimed = None
    if isinstance(claimed, bool):
        claimed = ClaimResult(claimed)
    if not (isinstance(claimed, tuple) and len(claimed) >= 1 and claimed[0] is True):
        last = claimed[1] if isinstance(claimed, tuple) and len(claimed) > 1 else None
        if claimed is None:
            fail("replay", "the replay store failed (fail closed)")
        elif last is not None:
            fail("replay", "%s is not greater than last seen %s (replay)" % (counter, last))
        else:
            fail("replay", "%s was already claimed (replay)" % (counter,))
        return deny()
    # K1 ``max_uses`` is spent only for an action that is otherwise admitted, after the counter above accepted it
    if k1r is not None and any(b["caveat"].get("type") == "max_uses" for b in k1r["bound"] if isinstance(b["caveat"], dict)):
        if uses_store is None:
            fail("max_uses", "the chain carries a max_uses caveat and this verifier has no uses_store (fail closed)")
            return deny()
        spent = reserve_max_uses(uses_store, k1r["bound"], now)
        if not spent["ok"]:
            fail("max_uses", spent["reason"])
            return deny()
    if accepted_epoch is not None and revocation_staleness.on_epoch_accepted is not None:
        try:
            revocation_staleness.on_epoch_accepted(accepted_epoch, p)
        except Exception:  # noqa: BLE001 - the pin is the host's; the decision is already made
            pass
    adm = esc["undo"]
    return AuthorizeResult(allow=True, status=200, checks=checks, reasons=reasons, pcactn=p, verdict=core, decision="allow",
                           escalation=({"answered_by": esc["by"]} if esc["by"] is not None else None),
                           operation=AuthorizedOperation(verb=op["verb"], resource=op["resource"],
                                                         params_digest=signed_digest, id=hash_canonical(p)),
                           undo=adm, obligations=[_undo_obligation(adm)] if adm is not None else None)


def _undo_obligation(adm: dict) -> dict:
    return {"kind": "undo_window", "params": {"id": adm["id"], "window_end": adm["window_end"]}, "due": adm["window_end"]}


def _undo_admission(hook: Callable[..., Any], p: dict, grant: dict, op: dict) -> Optional[dict]:
    """The undo hook's admission, or None (no admission: the escalation stands). A hook that raises, or returns anything but
    ``{"id", "window_end", "compensation": {"verb", ...}}`` whose ``undo_window`` obligation is well formed, admits nothing."""
    try:
        adm = hook(p, grant, op)
        if not isinstance(adm, dict) or not isinstance(adm.get("compensation"), dict):
            return None
        if not isinstance(adm["compensation"].get("verb"), str) or obligation_error(_undo_obligation(adm)) is not None:
            return None
        return adm
    except Exception:  # noqa: BLE001 - an admission that cannot be decided is no admission
        return None


def _provenance_flow(env: Optional[dict], op: dict, p: dict, bundle: Any, request: Any, mediators: Any, actions: Any,
                     observed: Any, plan: bool, control: bool) -> "tuple[str, Optional[str]]":
    """The provenance gate for one operation: ``(status, reason)``; an escalate reason carries the ``escalate:`` prefix so the
    ternary decision reads it as escalate-class, a deny keeps its code."""
    pe = env.get("provenance", _ABSENT) if isinstance(env, dict) else _ABSENT
    if pe is not _ABSENT:
        e = prov_envelope_error(pe)
        if e:
            return "fail", "the grant's provenance member is malformed: %s" % e
        # the principal's signed, documented-dangerous opt-out
        if pe.get("mode") == "insecure_off":
            return "not-enforced", None
    if not isinstance(op, dict) or not isinstance(op.get("verb"), str) or not isinstance(op.get("resource"), str):
        return "fail", "no operation is bound to this request (fail closed)"
    if bundle is None and request is not None:
        try:
            headers, body = request
            bundle = read_provenance_bundle(headers, body)
        except Exception:  # noqa: BLE001
            return "fail", "the provenance bundle is unreadable (fail closed)"
    o = {"verb": op["verb"], "resource": op["resource"], "params": op.get("params") or {}}
    rs = bundle.get("receipts") if isinstance(bundle, dict) else None
    session = rs[0].get("session") if isinstance(rs, list) and rs and isinstance(rs[0], dict) else None
    try:
        facts = actions(o) if actions is not None else None
        obs = list(observed(p, o, session if isinstance(session, str) else None) or []) if observed is not None else []
    except Exception:  # noqa: BLE001
        return "fail", "the provenance configuration failed (fail closed)"
    pins = list(mediators) if isinstance(mediators, (list, tuple)) else mediators
    if isinstance(pins, list) and isinstance(pe, dict) and isinstance(pe.get("mediators"), list):
        pins = pins + pe["mediators"]
    d_in = {"bundle": bundle, "operation": o, "mediators": pins, "principal_plan": plan, "principal_control": control,
            "observed": obs}
    if facts is not None:
        d_in["action"] = facts
    d = decide_arg_provenance(d_in)
    if d["outcome"] == "pass":
        return "pass", None
    return "fail", ("escalate: %s" % d["reason"]) if d["outcome"] == "escalate" else "%s: %s" % (d["code"], d["reason"])


def _canon_json(v: Any) -> str:
    from .pca import canonicalize
    return canonicalize(v)


def _v2_env(p: dict, grant: dict, v2: Any, now: int, env: Any) -> Any:
    """The predicate ``env``: the host's, with the verifier-computed Intent Layer v2 members (TypeScript ``v2Env``)."""
    if "intent_session" not in p:
        return env
    rest = dict(env) if isinstance(env, dict) else {}
    for k in ("acc", "mon", "canon", "world", "prov", "class"):
        rest.pop(k, None)
    from .intent_v2 import decide_intent_v2  # deferred: intent_v2 imports pca
    d = decide_intent_v2(p, grant, v2, now).get("env") or {}
    for k, v in d.items():
        if v is not None:
            rest[k] = v
    return rest


def is_authorized_for(result: AuthorizeResult, operation: Mapping[str, Any]) -> bool:
    """True only if ``result`` allowed exactly this operation (verb, resource, params digest). Call it where the side
    effect runs, with the values it is about to use."""
    try:
        b = result.operation if isinstance(result, AuthorizeResult) and result.allow else None
        if b is None or not _valid_operation(operation):
            return False
        return (b.verb == operation["verb"] and b.resource == operation["resource"]
                and b.params_digest == params_digest(operation["params"]))
    except Exception:  # noqa: BLE001
        return False


@dataclass
class AuthorizeOptions:
    """The ``authorize`` components a guard adds on top of its ``audience`` / ``resolve_grant`` (the opt-in for
    ``require_pca(authorize=...)``, the FastAPI / Django helpers and the framework adapters)."""

    state_store: Any = None
    is_revoked: Optional[RevocationCheck] = None
    plan: Optional[str] = "single-step"
    context: Optional[Callable[[dict], Optional[dict]]] = None
    require: Sequence[str] = ()
    require_assurance: Optional[Mapping[str, Any]] = None
    #: pinned principals whose EscalationAnswers count: b64u Ed25519 keys, or ``{"pk": ..., "pq_pk": ...}`` pins for a
    #: post-quantum / hybrid suite (None: every escalate is refused). Needs a ``state_store`` with ``last(key)``.
    escalation_principals: Any = None
    #: how long an issued EscalationRequest is valid, in ms (default one hour)
    escalation_request_ttl_ms: int = 3_600_000
    #: K7: ``(pcactn) -> H(R) | None``, the verifier's recomputation of the canonical approval render digest (see ``approval``).
    #: With it the request carries the digest and an answer must be signed over exactly it; an answer carrying a render when this is
    #: not set is refused.
    escalation_render: Any = None
    #: K7: refuse every answer unless a render digest was recomputed
    insecure_unbound_approval: bool = False
    #: verifier-side revocation staleness (off when None), see :class:`RevocationStaleness`
    revocation_staleness: Optional[RevocationStaleness] = None
    #: the plan registry (T10), see :class:`PlanRegistry`
    plans: Any = None
    #: caveat language v2: the verifier's own K1 input (a dict, or a callable ``(pcactn) -> dict``); None = not configured, so a
    #: chain carrying a K1 caveat is refused. Discharges / narrow presented in the request headers are merged under it.
    k1: Any = None
    #: atomic ``consume_once(key, retain_until, now)`` store for ``max_uses`` slots (None: a ``max_uses`` caveat is refused)
    uses_store: Any = None
    #: workflow admission (K5, C-308): ``{"principal", "rs_signer", "required"?}``, the keys this server pinned; None = off
    workflow: Any = None
    #: per-request source of the workflow step for the guards: ``(headers, body) -> step | None``; else the JSON body member ``workflow``
    workflow_step: Optional[Callable[..., Any]] = None
    #: provenance by default (always on, see ``authorize``): pinned mediator keys ``[{"mediator", "kid", "pk", "pq_pk"?}]``
    provenance_mediators: Sequence[Any] = ()
    #: ``(operation) -> {"effects", "traits", "params"} | None``: the action facts from your definitions (None = unknown = sensitive)
    provenance_actions: Optional[Callable[[dict], Optional[dict]]] = None
    #: ``(pcactn, operation, session) -> [{"origin", "source"}]``: untrusted content this server saw reach the agent (raise only)
    provenance_observed: Optional[Callable[..., Any]] = None
    #: undo windows: ``(pcactn, grant, operation) -> admission | None`` (see ``authorize``); None = off
    undo_admit: Optional[Callable[..., Any]] = None

    def __post_init__(self) -> None:
        if self.escalation_principals and self.state_store is not None and not callable(getattr(self.state_store, "last", None)):
            raise ValueError("AuthorizeOptions: escalation_principals needs a state_store with last(key): an escalation "
                             "answer is bound to the holder's history head")

    def run(self, pcactn: Any, *, operation: Any, audience: str, resolve_grant: GrantResolver,
            now: Optional[int] = None, intent_policy: Optional[dict] = None, intent_v2: Any = None,
            escalation_answer: Any = None, presented_k1: Optional[Mapping[str, Any]] = None,
            fresh_at: Any = None, workflow: Any = None, provenance: Any = None, request: Any = None) -> AuthorizeResult:
        """``provenance``: this call's bundle; ``request``: ``(headers, body)`` the bundle is read from otherwise."""
        k1 = self.k1
        try:
            if callable(k1):
                k1 = k1(pcactn)
            # presented discharges / narrow first, the verifier's own input wins; no k1 configured = none at all
            k1 = {**dict(presented_k1 or {}), **k1} if isinstance(k1, dict) else None
        except Exception:  # noqa: BLE001
            k1 = None
        return authorize(pcactn, operation=operation, audience=audience, resolve_grant=resolve_grant,
                         state_store=self.state_store, is_revoked=self.is_revoked, now=now, plan=self.plan,
                         context=self.context, intent_policy=intent_policy, intent_v2=intent_v2, require=self.require,
                         require_assurance=self.require_assurance, escalation_principals=self.escalation_principals,
                         escalation_answer=escalation_answer, escalation_request_ttl_ms=self.escalation_request_ttl_ms,
                         escalation_render=self.escalation_render, insecure_unbound_approval=self.insecure_unbound_approval,
                         revocation_staleness=self.revocation_staleness, plans=self.plans, k1=k1, uses_store=self.uses_store,
                         fresh_at=fresh_at, workflow=self.workflow, workflow_step=workflow, provenance=provenance,
                         provenance_request=request, provenance_mediators=self.provenance_mediators,
                         provenance_actions=self.provenance_actions, provenance_observed=self.provenance_observed,
                         undo_admit=self.undo_admit)


def authorize_tool_call(options: AuthorizeOptions, pcactn: Any, *, verb: Optional[str], resource: Optional[str],
                        params: Optional[Mapping[str, Any]], audience: str, resolve_grant: GrantResolver,
                        now: Optional[int] = None, provenance: Any = None) -> AuthorizeResult:
    """``authorize`` for an agent tool guard: the operation is the capability the tool requires (``verb``,
    ``resource``) with the tool-call arguments as ``params``. A tool that declares no capability, or a call whose
    arguments could not be bound (``params`` None, e.g. positional arguments), is refused (fail closed). ``provenance`` is the
    call's provenance bundle (see ``authorize``; without one a sensitive tool call escalates)."""
    if not isinstance(options, AuthorizeOptions):
        return _refuse(403, "authorize_config", "authorize_config: authorize options are not an AuthorizeOptions "
                                                "(fail closed)", missing=["authorize"])
    missing = missing_authorize_components(audience=audience, resolve_grant=resolve_grant,
                                           state_store=options.state_store, is_revoked=options.is_revoked,
                                           escalation_principals=options.escalation_principals)
    if missing:  # configuration first: a guard built without its store / revocation check names what is missing
        return _refuse(403, "authorize_config", "authorize_config: missing required component(s): %s (fail closed)"
                       % ", ".join(missing), missing=missing)
    if not isinstance(verb, str) or not isinstance(resource, str):
        return _refuse(403, "operation", "operation: the tool declares no capability (verb:resource) to bind the "
                                         "proof to (fail closed)")
    if params is None:
        return _refuse(403, "operation", "operation: the tool-call arguments could not be bound (pass them as "
                                         "keyword arguments) (fail closed)")
    return options.run(pcactn, operation={"verb": verb, "resource": resource, "params": dict(params)},
                       audience=audience, resolve_grant=resolve_grant, now=now, provenance=provenance)
