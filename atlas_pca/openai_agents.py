"""OpenAI Agents SDK (`openai-agents`, package `agents`) guard for Proof-Carrying Authority (the TypeScript reference,
@atlasauth/pca-openai-agents).

Duck-typed: `agents` is never imported at module import time (only inside `PcaGuardrail.as_*` and the guardrail output builders).

* `with_pca_tool` / `pca_tools`: a tool call first REQUIRES a proof-carrying action (found in the run context), VERIFIES it (fail closed:
  `PcaToolDenied`, which the SDK reports to the model as a tool error) and only then runs the original. Works on an SDK `FunctionTool`
  (`on_invoke_tool(ctx, json_text)`), or any object / dict with `execute(input, run_context)`.
  Default mode `"full"`: `authorize=` (an `AuthorizeOptions`) plus `resolve_grant=` run the whole pipeline: the input must hash to the
  signed params, grant limits, revocation and single use. `mode="signature-only"` with `verify=` checks only the signature, chain,
  audience and window, which does NOT prove the grant permits the call.
* `PcaGuardrail` (`pca_input_guardrail`, `pca_tool_guard`): signature-only pre-filters that trip when the run or tool call carries no
  valid proof.
* step-up: `review_tool_call`, `pending_step_ups`, `pca_needs_approval`, `with_approval` map a risky tool to the SDK's `needs_approval`
  so the run interrupts for a guardian / human co-sign.
* `attach_pca`: the agent side, a tool whose every call is signed first (like the other framework adapters).

Differences from the TypeScript reference: the grant-form `verify={"grant": ...}` has no audience opt-out (`audience=None` is refused,
pass a custom `verify` callable to accept any audience) and no `hooks`; the full mode takes `authorize=AuthorizeOptions(...)` and
`resolve_grant=` where the reference takes one options object; `review_tool_call` takes the `review` callable (the agent's review of an
intended action) because the Python agent has no built-in step-up review.
"""
import inspect
import json
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from atlas_pca.adapters import (PcaCall, bridge_tool_call, guard, js_string, provenance_headers, record_input, record_messages,
                                record_principal, with_attrs)
from atlas_pca.authorize import missing_authorize_components
from atlas_pca.gateway import decode_pcactn
from atlas_pca.pca import decode_pca_header, strict_parse, verify_pcactn_core

__all__ = ["PcaToolDenied", "proof_from_run_context", "provenance_from_run_context", "proof_from_input_headers",
           "guardrail_proof_from_context", "with_pca_tool", "pca_tools", "PcaGuardrail", "pca_input_guardrail", "pca_tool_guard",
           "review_tool_call", "pending_step_ups", "pca_needs_approval", "with_approval", "attach_pca", "provenance_from",
           "PcaCall", "bridge_tool_call", "provenance_headers", "record_input", "record_messages", "record_principal"]

_UNSET = object()


class PcaToolDenied(Exception):
    """A guarded tool refused to run. `kind`: missing | malformed | verify | binding | policy | replay | revoked | config."""

    def __init__(self, message: str, verb: Any, kind: str, checks: Optional[Mapping[str, Any]] = None):
        super().__init__("PCA tool denied (%s) for %s: %s" % (kind, js_string(verb), message))
        self.verb, self.kind, self.checks = verb, kind, checks


# ---- proof sources ------------------------------------------------------------------------------------------------------

def _g(o: Any, k: str) -> Any:
    return o.get(k) if isinstance(o, dict) else getattr(o, k, None)


def _is_record(v: Any) -> bool:
    return v is not None and not isinstance(v, (str, bytes, bool, int, float))


def _first(*vals: Any) -> Any:
    for v in vals:
        if v is not None:
            return v
    return None


def _proof_from_bag(bag: Any) -> Optional[str]:
    if not _is_record(bag):
        return None
    direct = _first(_g(bag, "pca"), _g(bag, "pcaProof"), _g(bag, "pca_proof"))
    return direct if isinstance(direct, str) else None


def proof_from_run_context(_input: Any, run_context: Any) -> Optional[str]:
    """The encoded PCActn from `run_context.context` (`pca` / `pcaProof` / `pca_proof`), then from `run_context` itself."""
    inner = _proof_from_bag(_g(run_context, "context"))
    return inner if inner is not None else _proof_from_bag(run_context)


def provenance_from_run_context(_input: Any, run_context: Any) -> Any:
    """The call's provenance bundle: `pcaProvenance` / `pca_provenance` / `PCA-Provenance` on the context, then on the run context."""
    for bag in (_g(run_context, "context"), run_context):
        if not _is_record(bag):
            continue
        v = _first(_g(bag, "pcaProvenance"), _g(bag, "pca_provenance"), _g(bag, "PCA-Provenance"))
        if v is not None:
            return v
    return None


def proof_from_input_headers(field: str = "headers", header: str = "PCA-Action") -> Callable[[Any, Any], Optional[str]]:
    """A proof source reading a `PCA-Action` header value from a headers-like dict on the tool input."""
    def source(input: Any, _run_context: Any = None) -> Optional[str]:
        if not _is_record(input):
            return None
        bag = _g(input, field)
        if not _is_record(bag):
            return None
        v = _g(bag, header)
        return v if isinstance(v, str) else None
    return source


def guardrail_proof_from_context(args: Any) -> Optional[str]:
    """Guardrail default: the proof from the run context passed as `args["context"]`."""
    outer = _g(args, "context")
    inner = _g(outer, "context") if _is_record(outer) else None
    p = _proof_from_bag(inner)
    return p if p is not None else _proof_from_bag(outer)


def provenance_from(v: Any) -> Any:
    """A provenance bundle from an object, a JSON text or a base64url header value; None when it is neither."""
    if v is None:
        return None
    if _is_record(v):
        return v
    if not isinstance(v, str) or v == "":
        return None
    try:
        return strict_parse(v)
    except Exception:  # noqa: BLE001 - try the header form
        try:
            return strict_parse(decode_pca_header(v))
        except Exception:  # noqa: BLE001
            return None


# ---- the proof pipeline -------------------------------------------------------------------------------------------------

async def _aw(x: Any) -> Any:
    return await x if inspect.isawaitable(x) else x


def _to_pcactn(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        raise TypeError("the proof is neither a PCActn object nor encoded text")
    try:
        return decode_pcactn(raw)
    except Exception:  # noqa: BLE001 - a header value is base64url of the JSON
        return decode_pcactn(decode_pca_header(raw))


def _verb_of(p: Any) -> Any:
    return _g(_g(p, "action"), "verb")


async def _run_verify(verify: Any, pcactn: dict, audience: Any) -> Any:
    if callable(verify):
        return await _aw(verify(pcactn))
    if not isinstance(verify, Mapping) or not isinstance(verify.get("grant"), dict):
        return {"allow": False, "checks": {}, "reason": "no verifier configured"}
    now = verify.get("now")
    now = now() if callable(now) else now
    kw = {k: verify[k] for k in ("enforce_freshness", "enforce_taint", "authorized_plan_roots", "allowed_suites", "pq_pins")
          if verify.get(k) is not None}
    return verify_pcactn_core(pcactn, verify["grant"], now=now, audience=audience,
                              insecure_skip_plan_root_check=verify.get("insecure_skip_plan_root_check") is True, **kw)


async def _assert_proof(raw: Any, verify: Any, audience: Any, verb: Optional[str], label: str,
                        full: Optional[Callable[[dict], Any]] = None) -> Dict[str, Any]:
    """Decode, bind to `verb`, then verify (or run the full policy). Returns {"pcactn", "result"} or raises PcaToolDenied."""
    if raw is None:
        raise PcaToolDenied("no proof-carrying action present on the call", label, "missing")
    try:
        pcactn = _to_pcactn(raw)
    except Exception as cause:  # noqa: BLE001
        raise PcaToolDenied("proof could not be decoded: %s" % cause, label, "malformed") from None
    got = _verb_of(pcactn)
    if verb is not None and got != verb:
        raise PcaToolDenied("proof is for '%s', not this tool's '%s'" % (js_string(got), verb), got if got is not None else label, "binding")
    if full is not None:
        d = await _aw(full(pcactn))
        if not d["allow"]:
            raise PcaToolDenied(d["reason"], got if got is not None else label, "verify" if d["kind"] == "authn" else d["kind"], d.get("checks"))
        return {"pcactn": pcactn, "result": {"allow": True, "checks": d.get("checks")}}
    result = await _run_verify(verify, pcactn, audience)
    if not _g(result, "allow"):
        reason = _g(result, "reason")
        raise PcaToolDenied("verification failed" if reason is None else reason, got if got is not None else label, "verify",
                            _g(result, "checks"))
    return {"pcactn": pcactn, "result": result}


def _authorize_execution(authorize: Any, resolve_grant: Any, audience: str, pcactn: dict, op: Mapping[str, Any],
                         now: Any) -> Dict[str, Any]:
    """Binding to the operation, then `authorize` (replay, revocation, limits): the decision `{"allow", "kind", "reason", "checks"}`."""
    from atlas_pca.server_surface import authorize_execution
    return authorize_execution(pcactn, dict(op), authorize, audience=audience, resolve_grant=resolve_grant, now=now)


def _full_policy(options: Mapping[str, Any]) -> Optional[Callable[..., Any]]:
    auth = options.get("authorize")
    mode = options.get("mode")
    mode = "full" if mode is None else mode
    if mode not in ("full", "signature-only"):
        raise TypeError("with_pca_tool: unknown mode '%s'" % js_string(mode))
    if mode == "signature-only":
        if auth is not None:
            raise TypeError("with_pca_tool: `authorize` is the full mode; drop it, or drop mode: 'signature-only'")
        if options.get("verify") is None:
            raise TypeError("with_pca_tool: mode 'signature-only' needs `verify`")
        return None
    if auth is None:
        raise TypeError("with_pca_tool: pass `authorize` (full policy, the default mode), or set mode: 'signature-only' with `verify` to check the signature only")
    if options.get("verify") is not None:
        raise TypeError("with_pca_tool: `verify` checks the signature only: set mode: 'signature-only' to use it, and drop `authorize`")
    audience = options["audience"] if isinstance(options.get("audience"), str) else None
    resolve_grant = options.get("resolve_grant")
    missing = missing_authorize_components(audience=audience, resolve_grant=resolve_grant, state_store=getattr(auth, "state_store", None),
                                           is_revoked=getattr(auth, "is_revoked", None),
                                           escalation_principals=getattr(auth, "escalation_principals", None))
    operation, verb, resource = options.get("operation"), options.get("verb"), options.get("resource")
    if operation is None and (verb is None or resource is None):
        missing.append("operation (or the guard's verb and resource)")
    if not callable(getattr(auth, "run", None)):
        missing.append("authorize.run")
    if missing or audience is None:
        raise TypeError("with_pca_tool: full policy mode is missing %s" % ", ".join(missing))
    prov = options.get("provenance") or provenance_from_run_context
    now = options.get("now")

    def check(pcactn: dict, input: Any, run_context: Any) -> Dict[str, Any]:
        op = dict(operation(input, run_context)) if operation is not None else {"verb": verb, "resource": resource,
                                                                                  "params": input if isinstance(input, dict) else {}}
        if op.get("provenance") is None:
            bundle = provenance_from(prov(input, run_context))
            if bundle is not None:
                op["provenance"] = bundle
        return _authorize_execution(auth, resolve_grant, audience, pcactn, op, now)
    return check


# ---- the execution guard ------------------------------------------------------------------------------------------------

def _parse_args(raw: Any) -> Any:
    if isinstance(raw, (str, bytes, bytearray)):
        try:
            return json.loads(raw)
        except ValueError:
            return None
    return raw


def with_pca_tool(tool: Any, **options: Any) -> Any:
    """A copy of `tool` whose every call first requires and verifies a proof (see the module doc); every other field is kept.

    Options: `mode` (`"full"` default | `"signature-only"`), `verify` (a callable `pcactn -> {allow, reason?, checks?}` or
    `{"grant": ..., "now"?, "authorized_plan_roots"?, "insecure_skip_plan_root_check"?, ...}`), `authorize` (`AuthorizeOptions`) with
    `resolve_grant`, `operation(input, run_context) -> {verb, resource, params}` or the guard's `verb` + `resource`, `audience`
    (a string; `None` accepts any audience with a custom `verify`; omitted refuses), `require(input, run_context)` (proof source),
    `provenance(input, run_context)`, `recorder` (a provenance recorder), `on_deny(error, input)`, `on_verified(result, pcactn, input)`,
    `now`."""
    source = options.get("require") or proof_from_run_context
    label = _first(options.get("verb"), _g(tool, "name"), "(tool)")
    full = _full_policy(options)
    verify = options.get("verify")
    has_audience = "audience" in options
    audience = options.get("audience")
    on_deny, on_verified, recorder = options.get("on_deny"), options.get("on_verified"), options.get("recorder")

    async def guarded(input: Any, run_context: Any, call: Callable[[], Any]) -> Any:
        ctx = {} if run_context is None else run_context
        raw = source(input, ctx)
        try:
            verified = await _assert_proof(raw, verify, audience if has_audience else None, options.get("verb"), label,
                                           (lambda p: full(p, input, ctx)) if full is not None else None)
        except PcaToolDenied as err:
            if on_deny:
                on_deny(err, input)
            raise
        if on_verified:
            on_verified(verified["result"], verified["pcactn"], input)
        out = await _aw(call())
        if recorder is not None:
            v = _verb_of(verified["pcactn"])
            recorder.tool(js_string(v if v is not None else label), out)
        return out

    orig_invoke = _g(tool, "on_invoke_tool")
    if callable(orig_invoke):
        async def on_invoke_tool(ctx: Any, raw: Any = None, *rest: Any, **kw: Any) -> Any:
            return await guarded(_parse_args(raw), ctx, lambda: orig_invoke(ctx, raw, *rest, **kw))
        return _with(tool, on_invoke_tool=on_invoke_tool)

    orig_exec = _g(tool, "execute")

    async def execute(input: Any, run_context: Any = None) -> Any:
        def call() -> Any:
            if not callable(orig_exec):
                raise RuntimeError("with_pca_tool: the wrapped tool has no execute()")
            return orig_exec(input, run_context)
        return await guarded(input, run_context, call)
    return _with(tool, execute=execute)


def _with(tool: Any, **attrs: Any) -> Any:
    return {**tool, **attrs} if isinstance(tool, dict) else with_attrs(tool, **attrs)


def _merge_options(base: Mapping[str, Any], over: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not over:
        return dict(base)
    own_mode = over.get("authorize") is not None
    out: Dict[str, Any] = {}
    if own_mode:  # a per-tool `authorize` or `verify` replaces the shared mode (the two are exclusive)
        src: Mapping[str, Any] = over
        keys = ("authorize", "resolve_grant", "operation")
    elif over.get("verify") is not None:
        src, keys = over, ("verify",)
    else:
        src, keys = base, ("verify", "authorize", "resolve_grant", "operation")
    out.update({k: src[k] for k in keys if src.get(k) is not None})
    mode = over.get("mode")
    mode = mode if mode is not None else (None if own_mode else base.get("mode"))
    if mode is not None:
        out["mode"] = mode
    for k in ("require", "verb", "resource", "on_deny", "on_verified", "provenance", "recorder", "now"):
        v = _first(over.get(k), base.get(k))
        if v is not None:
            out[k] = v
    if "audience" in over:
        out["audience"] = over["audience"]
    elif "audience" in base:
        out["audience"] = base["audience"]
    return out


def pca_tools(tools: Any, *, per: Optional[Mapping[str, Mapping[str, Any]]] = None, only: Optional[Sequence[str]] = None,
              **options: Any) -> Any:
    """Guard a `{name: tool}` dict (or a list of tools, keyed by their `name`) with shared options. `per[name]` overrides them for one
    tool, `only` limits the guarded set; every other tool passes through unchanged (the same object)."""
    only_set = None if only is None else set(only)

    def one(name: Any, t: Any) -> Any:
        if only_set is not None and name not in only_set:
            return t
        return with_pca_tool(t, **_merge_options(options, (per or {}).get(name)))
    if isinstance(tools, Mapping):
        return {k: one(k, t) for k, t in tools.items()}
    return [one(_g(t, "name"), t) for t in tools]


# ---- guardrails -----------------------------------------------------------------------------------------------------------

class PcaGuardrail:
    """A signature-only proof gate. `execute(args)` (async) returns `{"tripwire_triggered", "output_info"}`; `as_input_guardrail()` /
    `as_tool_input_guardrail()` build the SDK's own objects (importing `agents` only then)."""

    def __init__(self, name: str, source: Callable[[Any], Optional[str]], verify: Any, audience: Any, verb: Optional[str], label: str,
                 has_audience: bool):
        self.name, self._source, self._verify, self._audience, self._verb, self._label = name, source, verify, audience, verb, label
        self._has_audience = has_audience

    async def execute(self, args: Any) -> Dict[str, Any]:
        try:
            v = await _assert_proof(self._source(args), self._verify, self._audience if self._has_audience else None, self._verb, self._label)
        except PcaToolDenied as err:
            info: Dict[str, Any] = {"kind": err.kind, "verb": err.verb, "reason": str(err)}
            if err.checks is not None:
                info["checks"] = err.checks
            return {"tripwire_triggered": True, "output_info": info}
        return {"tripwire_triggered": False, "output_info": {"verb": _verb_of(v["pcactn"])}}

    async def input_guardrail_function(self, context: Any, agent: Any, input: Any) -> Any:
        out = await self.execute({"agent": agent, "input": input, "context": context})
        try:
            from agents import GuardrailFunctionOutput  # type: ignore
        except ImportError:
            return out
        return GuardrailFunctionOutput(output_info=out["output_info"], tripwire_triggered=out["tripwire_triggered"])

    async def tool_guardrail_function(self, data: Any) -> Any:
        ctx = _g(data, "context")
        out = await self.execute({"agent": _g(data, "agent"), "input": _g(ctx, "tool_arguments"), "context": ctx})
        try:
            from agents import ToolGuardrailFunctionOutput  # type: ignore
        except ImportError:
            return out
        if out["tripwire_triggered"]:
            return ToolGuardrailFunctionOutput.reject_content(out["output_info"]["reason"], output_info=out["output_info"])
        return ToolGuardrailFunctionOutput.allow(output_info=out["output_info"])

    def as_input_guardrail(self) -> Any:
        from agents import InputGuardrail  # type: ignore
        return InputGuardrail(guardrail_function=self.input_guardrail_function, name=self.name)

    def as_tool_input_guardrail(self) -> Any:
        from agents import ToolInputGuardrail  # type: ignore
        return ToolInputGuardrail(guardrail_function=self.tool_guardrail_function, name=self.name)


def _guardrail(default: str, label: str, verify: Any, require: Any, audience: Any, verb: Optional[str], name: Optional[str]) -> PcaGuardrail:
    return PcaGuardrail(name or default, require or guardrail_proof_from_context, verify, None if audience is _UNSET else audience, verb,
                        verb if verb is not None else label, audience is not _UNSET)


def pca_input_guardrail(*, verify: Any, require: Optional[Callable[[Any], Optional[str]]] = None, audience: Any = _UNSET,
                        verb: Optional[str] = None, name: Optional[str] = None) -> PcaGuardrail:
    """An input guardrail: trips at the top of a run when the run context carries no valid proof (`inputGuardrails=[g.as_input_guardrail()]`)."""
    return _guardrail("pca-input-guardrail", "(run)", verify, require, audience, verb, name)


def pca_tool_guard(*, verify: Any, require: Optional[Callable[[Any], Optional[str]]] = None, audience: Any = _UNSET,
                   verb: Optional[str] = None, name: Optional[str] = None) -> PcaGuardrail:
    """The same gate scoped to a tool call (`as_tool_input_guardrail()`); prefer `with_pca_tool` with `authorize` for the real check."""
    return _guardrail("pca-tool-guard", "(run)", verify, require, audience, verb, name)


# ---- step-up --------------------------------------------------------------------------------------------------------------

def review_tool_call(agent: Any, tool: str, input: Optional[Mapping[str, Any]], *, intent: Callable[..., Optional[Mapping[str, Any]]],
                     review: Optional[Callable[..., Mapping[str, Any]]] = None, standing: Any = None, goal: Optional[str] = None,
                     now: Optional[int] = None, renderer: Any = None, insecure_unbound_approval: Optional[bool] = None) -> Dict[str, Any]:
    """Review one intended tool call: `intent(tool, input)` maps it to `{"verb", "resource", "params"?}` (None = unguarded, `auto`), then
    `review(agent, verb, resource, params, opts)` returns `{"kind": "auto"}`, `{"kind": "deny", "reason"}` or
    `{"kind": "step_up", "request"}`. Returns `{"tool", "review"}`."""
    mapped = intent(tool, input)
    if mapped is None:
        return {"tool": tool, "review": {"kind": "auto"}}
    if review is None:
        raise TypeError("review_tool_call: pass `review`, the agent's review of an intended action")
    params = mapped.get("params")
    opts = {k: v for k, v in (("now", now), ("goal", goal), ("standing", standing), ("renderer", renderer),
                              ("insecure_unbound_approval", insecure_unbound_approval)) if v is not None}
    return {"tool": tool, "review": review(agent, mapped["verb"], mapped["resource"], input if params is None else params, opts)}


def pending_step_ups(reviews: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """The step-up requests among `review_tool_call` results (auto / deny filtered out)."""
    return [{"tool": r["tool"], "request": r["review"]["request"]} for r in reviews if r["review"].get("kind") == "step_up"]


def pca_needs_approval(agent: Any, *, intent: Callable[..., Any], tool_name: Optional[str] = None, approved: Optional[Callable[[Any], Any]] = None,
                       on_step_up: Optional[Callable[[Dict[str, Any]], Any]] = None, deny_needs_approval: bool = True,
                       **review_opts: Any) -> Callable[..., Any]:
    """The SDK's `needs_approval` callback `(run_context, input, call_id=None) -> bool` from risk review: auto -> False; step-up not yet
    co-signed -> `on_step_up({"tool", "request"})` and True (the run interrupts); an already approved step-up -> False; deny -> True
    unless `deny_needs_approval=False` (the approver then rejects it). `review_opts`: `review`, `standing`, `goal`, `now`, `renderer`,
    `insecure_unbound_approval`."""
    name = tool_name if tool_name is not None else "(tool)"

    async def needs_approval(_run_context: Any, input: Any, _call_id: Any = None) -> bool:
        r = review_tool_call(agent, name, input, intent=intent, **review_opts)["review"]
        kind = r.get("kind")
        if kind == "auto":
            return False
        if kind == "deny":
            return deny_needs_approval
        if approved is not None and await _aw(approved(r["request"])):
            return False
        if on_step_up is not None:
            await _aw(on_step_up({"tool": name, "request": r["request"]}))
        return True
    return needs_approval


def with_approval(tool: Any, agent: Any, **opts: Any) -> Any:
    """A copy of `tool` with `needs_approval` from PCA risk review (the tool's name seeds the intent lookup unless `tool_name` is given)."""
    name = opts.pop("tool_name", None)
    name = name if name is not None else (_g(tool, "name") or "(tool)")
    return _with(tool, needs_approval=pca_needs_approval(agent, tool_name=name, **opts))


# ---- agent side -----------------------------------------------------------------------------------------------------------

def attach_pca(agent: Any, verb: str, resource: Any, tool: Any, on_proof: Optional[Callable[[PcaCall, dict], Any]] = None,
               fail_fast: bool = True) -> Any:
    """A copy of an SDK `FunctionTool` whose every call first builds a signed PCActn from its JSON arguments (fast-fail `PcaDenied` on
    a failing dry run), hands it to `on_proof(pca, params)` and runs the original. Arguments that are not a JSON object are refused."""
    orig = tool.on_invoke_tool

    async def on_invoke_tool(ctx: Any, raw: Any = None, *rest: Any, **kw: Any) -> Any:
        params = _parse_args(raw)
        if not isinstance(params, dict):
            raise TypeError("attach_pca: tool arguments must be a JSON object")

        async def run(p: dict, pca: PcaCall) -> Any:
            if on_proof:
                await _aw(on_proof(pca, p))
            return await _aw(orig(ctx, raw, *rest, **kw))
        return await guard(agent, verb, resource, run, fail_fast)(params)
    return with_attrs(tool, on_invoke_tool=on_invoke_tool)
