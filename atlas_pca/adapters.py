"""Agent-side tool-call bridge for AI frameworks (the TypeScript reference's `bridgeToolCall` / `guard` / `PcaDenied`).

Wrap a tool so each call silently builds a signed PCActn and hands it to the tool with ready-to-send headers. Nothing here
authorizes: the resource server's verifier decides, and a bypassed wrapper only produces an action that fails server-side.

Provenance: with `Agent(..., provenance=<ProvenanceRecorder>)` every action carries its provenance bundle (header
`PCA-Provenance`, or the body member `pca_provenance` when it is too large for a header), and the helpers here (`record_principal`,
`record_tool_result`, `record_messages`, `record_input`, `with_principal_input`) feed the recorder the way the TypeScript reference
does: the principal's turns are TRUSTED, tool output UNTRUSTED. Without a recorder they do nothing.

`guard` adds a fast client-side reject: it verifies the action it just built against the agent's own root grant (signature, chain,
audience, validity, predicates and caveats of the chain) and raises `PcaDenied` before the tool runs. That check is offline and
non-authoritative, and fails closed.

Not ported from the TypeScript reference: the per-call `counter` / `now` overrides, because `Agent.act` owns the counter and
clock (set `Agent(clock=...)` instead). The per-call `aud` override is supported (`guard(aud=...)`, `bridge_tool_call(aud=...)`).
"""
from ._fin import fin
import copy
import inspect
import json
import math
import re
import weakref
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Union

from atlas_pca.agent import Agent
from atlas_pca.arg_provenance import PROV_HEADER
from atlas_pca.pca import b64u, canonical_bytes_strict, decode_pca_header, evaluate_caveats, verify_pcactn_core
from atlas_pca.predicates import evaluate_predicates

__all__ = ["PcaDenied", "PcaCall", "bridge_tool_call", "guard", "dry_run", "js_json", "js_string", "with_attrs", "guard_kwargs",
           "PROV_HEADER_MAX", "provenance_headers", "record_principal", "record_tool_result", "message_segments", "record_messages",
           "record_input", "with_principal_input"]

#: Largest bundle carried as a header (base64url characters); a larger one goes in the request body as `pca_provenance`.
PROV_HEADER_MAX = 8192


class PcaDenied(Exception):
    """Raised by `guard` when the local dry run rejects a call before dispatch."""

    def __init__(self, reason: str, verb: str, resource: str):
        super().__init__("PCA denied %s on %s: %s" % (verb, resource, reason))
        self.reason, self.verb, self.resource = reason, verb, resource


@dataclass
class PcaCall:
    """What a guarded dispatch receives: the encoded PCActn JSON, the PCActn and the headers that carry it."""

    encoded: str
    pcactn: dict
    headers: Dict[str, str]
    #: The provenance bundle of this action (send it as body member `pca_provenance` when it is not in `headers`).
    provenance: Optional[dict] = None


def _call_of(action: Any) -> PcaCall:
    return PcaCall(decode_pca_header(action.headers["PCA-Action"]), action.pcactn, action.headers, getattr(action, "provenance", None))


def _envelope_refusal(agent: Agent, action: Any, params: Optional[dict]) -> Optional[str]:
    """The chain check proves signatures and linkage only; scope is the grants' envelopes: every hop must admit the action by its
    predicates and caveats (a hop only narrows). None when all admit, else the first refusal reason."""
    a = action.pcactn["action"]
    act = {"verb": a["verb"], "resource": a["resource"], "params": {} if params is None else params}
    if a.get("reversibility_class"):
        act["reversibility_class"] = a["reversibility_class"]
    now = agent.clock()
    for i, g in enumerate(agent.chain):
        for cv in g.get("caveats") or []:
            if not isinstance(cv, dict) or cv.get("type") != "envelope":
                continue
            pred = evaluate_predicates(cv.get("predicates"), {"action": act})
            if not pred["allowed"]:
                return pred.get("reason") or "no predicate matched"
            ok, failed = evaluate_caveats(cv.get("caveats") or [], {
                "now": now, "reversibility_class": act.get("reversibility_class"), "delegation_depth": i, "recent_action_times": []})
            if not ok:
                return "caveat(s) failed: %s" % ", ".join(failed)
    return None


def dry_run(agent: Agent, action: Any, params: Optional[dict] = None, aud: Optional[str] = None) -> Optional[str]:
    """None when the action verifies against the agent's own root grant AND every hop's envelope predicates and caveats admit it,
    else the refusal reason. Never raises."""
    try:
        v = verify_pcactn_core(action.pcactn, agent.chain[0], now=agent.clock(), audience=agent.aud if aud is None else aud,
                               authorized_plan_roots=[action.pcactn["plan"]["root"]])
        if not v.allow:
            return v.reason or "denied"
        return _envelope_refusal(agent, action, params)
    except Exception as e:  # noqa: BLE001 - fail closed
        return "dry run failed (%s)" % type(e).__name__


def js_json(v: Any) -> str:
    """`JSON.stringify` for plain data: compact separators, raw non-ASCII, integral floats as integers, NaN / Infinity as null."""
    def norm(x: Any) -> Any:
        if isinstance(x, float):
            return None if not fin(x) else (int(x) if x == int(x) and abs(x) < 1e21 else x)
        if isinstance(x, dict):
            return {k: norm(w) for k, w in x.items()}
        if isinstance(x, (list, tuple)):
            return [norm(w) for w in x]
        return x
    out = json.dumps(norm(v), separators=(",", ":"), ensure_ascii=False)
    # well-formed JSON.stringify escapes a lone surrogate (a Python str holds one as its own code point)
    return re.sub("[\ud800-\udfff]", lambda m: "\\u%04x" % ord(m.group()), out)


def js_string(v: Any) -> str:
    """JavaScript `String(v)` for JSON values."""
    if isinstance(v, str):
        return v
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        return "NaN" if v != v else ("Infinity" if v == math.inf else "-Infinity" if v == -math.inf else js_json(v))
    if isinstance(v, int):
        return str(v)
    if isinstance(v, (list, tuple)):
        return ",".join("" if x is None else js_string(x) for x in v)
    return "[object Object]"


def provenance_headers(bundle: Optional[dict]) -> Dict[str, str]:
    """`PCA-Provenance: <base64url canonical JSON>` for a bundle that fits PROV_HEADER_MAX; `{}` otherwise (send it in the body)."""
    if bundle is None:
        return {}
    v = b64u(canonical_bytes_strict(bundle))
    return {PROV_HEADER: v} if len(v) <= PROV_HEADER_MAX else {}


def _recorder(agent: Any) -> Any:
    return getattr(agent, "provenance", None)


def record_principal(agent: Any, text: str) -> None:
    """Record the principal's own message in the agent's provenance chain (TRUSTED)."""
    rec = _recorder(agent)
    if rec is not None:
        rec.principal(text)


def record_tool_result(agent: Any, tool: str, output: Any) -> None:
    """Record a tool result entering the model's context (UNTRUSTED)."""
    rec = _recorder(agent)
    if rec is not None:
        rec.tool(tool, output)


def _get(o: Any, k: str) -> Any:
    return o.get(k) if isinstance(o, dict) else getattr(o, k, None)


def _target_recorder(t: Any) -> Any:
    if t is None:
        return None
    return t if hasattr(t, "for_action") else getattr(t, "provenance", None)


def _role_of(m: Any) -> str:
    if not isinstance(m, dict):
        for g in ("_getType", "getType", "_get_type", "get_type"):
            f = getattr(m, g, None)
            if callable(f):
                try:
                    r = f()
                    if isinstance(r, str):
                        return r
                except Exception:  # noqa: BLE001 - fall through
                    pass
    for k in ("role", "type"):
        r = _get(m, k)
        if isinstance(r, str):
            return r
    return ""


_PRINCIPAL_ROLES = {"user", "human"}
_MODEL_ROLES = {"assistant", "ai", "model", "system", "developer"}


def _first(*vals: Any) -> Any:
    for v in vals:
        if v is not None:
            return v
    return None


def message_segments(m: Any) -> List[Dict[str, Any]]:
    """The context segments a chat message adds, by the conversation's own roles: a user / human turn is the PRINCIPAL; a
    `tool_result` / `tool-result` / `function_call_output` part inside any turn, a `tool` / `function` turn and a turn of an unknown
    role are UNTRUSTED tool output; assistant / system / developer turns add nothing."""
    if m is None or isinstance(m, (str, bool, int, float)):
        return []
    role = _role_of(m).lower()
    if role in _MODEL_ROLES:
        return []
    content = _get(m, "content")

    def tool_name(x: Any) -> str:
        return js_string(_first(*[_get(x, k) for k in ("toolName", "name", "tool_use_id", "toolCallId", "tool_call_id")],
                                _get(m, "name"), _get(m, "tool_call_id"), "tool"))

    if role not in _PRINCIPAL_ROLES:
        return [{"origin": "tool", "source": tool_name(m), "content": content if content is not None else m}]
    if not isinstance(content, (list, tuple)):
        return [{"origin": "principal", "source": "user", "content": content if content is not None else ""}]
    out: List[Dict[str, Any]] = []
    text: List[str] = []
    for part in content:
        if isinstance(part, (dict, list, tuple)) or (part is not None and not isinstance(part, (str, bool, int, float))):
            pt = part
        else:
            pt = {"type": "text", "text": js_string(part)}
        t = _get(pt, "type")
        t = t if isinstance(t, str) else ""
        if t in ("tool_result", "tool-result", "function_call_output"):
            out.append({"origin": "tool", "source": tool_name(pt),
                        "content": _first(_get(pt, "content"), _get(pt, "result"), _get(pt, "output"), pt)})
        elif isinstance(_get(pt, "text"), str):
            text.append(_get(pt, "text"))
        else:
            out.append({"origin": "principal", "source": "user", "content": pt})
    if text:
        out.insert(0, {"origin": "principal", "source": "user", "content": "\n".join(text)})
    return out


_SEEN: "weakref.WeakKeyDictionary[Any, int]" = weakref.WeakKeyDictionary()


def record_messages(target: Any, messages: Any) -> None:
    """Record a conversation's new messages in the agent's provenance chain (call it with the whole list before each model turn;
    messages already recorded are skipped, a shorter list starts over)."""
    rec = _target_recorder(target)
    if rec is None or not isinstance(messages, (list, tuple)):
        return
    seen = _SEEN.get(rec, 0)
    for i in range(0 if len(messages) < seen else seen, len(messages)):
        for seg in message_segments(messages[i]):
            if seg["origin"] == "principal":
                rec.principal(seg["content"] if isinstance(seg["content"], str) else js_json(seg["content"]))
            else:
                rec.tool(seg["source"], seg["content"])
    _SEEN[rec] = len(messages)


def record_input(target: Any, input: Any) -> None:
    """Record what the principal asked for: a string is the principal's message; a message list (or `{"messages": [...]}`) goes
    through `record_messages`; a dict's `input` / `prompt` / `query` / `question` / `message` / `text` string (or message list) is
    the principal's message. Anything else records nothing (the gate then keeps the context at `agent`: fail closed)."""
    rec = _target_recorder(target)
    if rec is None:
        return
    if isinstance(input, str):
        rec.principal(input)
    elif isinstance(input, (list, tuple)):
        record_messages(rec, input)
    elif isinstance(input, dict):
        if isinstance(input.get("messages"), (list, tuple)):
            record_messages(rec, input["messages"])
        for k in ("input", "prompt", "query", "question", "message", "text"):
            v = input.get(k)
            if isinstance(v, str):
                rec.principal(v)
            elif isinstance(v, (list, tuple)):
                record_messages(rec, v)


def with_principal_input(target: Any, fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a framework entry point so its first argument, the principal's request, is recorded before it runs."""
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        record_input(target, args[0] if args else None)
        return fn(*args, **kwargs)
    return wrapper

def bridge_tool_call(agent: Agent, call: Dict[str, Any], mapping: Callable[[Dict[str, Any]], Optional[Dict[str, str]]],
                     aud: Optional[str] = None) -> Optional[PcaCall]:
    """Turn `{"name", "arguments"}` into a PCActn using `mapping(call) -> {"verb", "resource"}`; None when the mapping declines
    the call (an unmapped tool). `aud` signs for another audience than the agent's. No dry run here: an out-of-policy call still yields a signed PCActn and is refused server-side."""
    m = mapping(call)
    if not m:
        return None
    return _call_of(agent.act(m["verb"], m["resource"], call.get("arguments"), **({} if aud is None else {"aud": aud})))


def guard(agent: Agent, verb: str, resource: Union[str, Callable[[dict], str]], run: Callable[..., Any], fail_fast: bool = True,
          aud: Optional[str] = None) -> Callable[..., Any]:
    """Wrap `run(params, pca)`: build a PCActn for each call, raise `PcaDenied` on a failing dry run (unless `fail_fast=False`),
    then run with the proof (`aud` signs and checks for another audience than the agent's). Returns `wrapper(params)`: async when `run` is a coroutine function, sync otherwise."""
    def prepare(params: dict):
        res = resource(params) if callable(resource) else resource
        action = agent.act(verb, res, params, **({} if aud is None else {"aud": aud}))
        if fail_fast:
            why = dry_run(agent, action, params, aud)
            if why is not None:
                raise PcaDenied(why, verb, res)
        return _call_of(action)

    if inspect.iscoroutinefunction(run):
        async def awrapper(params: dict) -> Any:
            out = await run(params, prepare(params))
            record_tool_result(agent, verb, out)  # what the tool returned enters the model's context: untrusted from here on
            return out
        return awrapper

    def wrapper(params: dict) -> Any:
        out = run(params, prepare(params))
        record_tool_result(agent, verb, out)
        return out
    return wrapper


def with_attrs(tool: Any, **attrs: Any) -> Any:
    """A shallow copy of a tool object with `attrs` replaced; everything else keeps its shape. Pydantic-style objects that
    refuse a new attribute get it on the instance directly."""
    out = copy.copy(tool)
    for k, v in attrs.items():
        try:
            setattr(out, k, v)
        except (ValueError, AttributeError, TypeError):
            object.__setattr__(out, k, v)
    return out


def guard_kwargs(agent: Agent, verb: str, resource: Union[str, Callable[[dict], str]], fn: Callable[..., Any],
                 on_proof: Optional[Callable[[PcaCall, dict], Any]] = None, fail_fast: bool = True) -> Callable[..., Any]:
    """`guard` for a tool called as `fn(**arguments)` (LangChain `func`, LlamaIndex `call`): the keyword arguments are the PCActn's
    params. Positional arguments are refused (TypeError): a call whose params cannot be bound is never signed."""
    def run(params: dict, pca: PcaCall) -> Any:
        if on_proof:
            on_proof(pca, params)
        return fn(**params)

    async def arun(params: dict, pca: PcaCall) -> Any:
        if on_proof:
            on_proof(pca, params)
        return await fn(**params)

    g = guard(agent, verb, resource, arun if inspect.iscoroutinefunction(fn) else run, fail_fast)

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if args:
            raise TypeError("a PCA-guarded tool takes keyword arguments only")
        return g(kwargs)
    if inspect.iscoroutinefunction(fn):
        async def awrapper(*args: Any, **kwargs: Any) -> Any:
            if args:
                raise TypeError("a PCA-guarded tool takes keyword arguments only")
            return await g(kwargs)
        return awrapper
    return wrapper
