"""``pca_function_middleware`` — gate *every* tool a Microsoft Agent Framework agent invokes.

The Agent Framework runs function-invocation middleware around each tool call: a middleware receives a
``FunctionInvocationContext`` (carrying ``.function``, the ``AIFunction`` being invoked, and
``.arguments``, its parsed arguments) and a ``next`` callable that actually runs the function. Calling
``next`` lets the function run; *not* calling it short-circuits the call, and setting ``context.result``
supplies the outcome the model sees instead. This module builds such a middleware that verifies a
proof-carrying action for each call and fails closed:

* no proof, or an undecodable one                        -> deny (the function never runs)
* a proof that does not verify under the core verifier   -> deny (bad signature / chain / validity /
  wrong audience / unknown grant / replay counter)
* a valid proof whose authorized action does not satisfy the function's required capability -> deny
* otherwise                                              -> allow (``next`` is called; the tool runs)

On a deny, the default behaviour is to set ``context.result`` to a structured deny result (routed back
to the model, and ``next`` is never called) — or, with ``raise_on_deny=True``, to raise
:class:`~atlas_pca_agent_framework.tool.PcaToolDenied`.

The proof is read from the context var (:func:`atlas_pca_agent_framework.pca_context`), or inline from a
reserved ``pca_action`` key in ``context.arguments`` (stripped before the tool runs). ``audience`` is
this agent's RFC 8707 resource identifier, so a proof minted for another resource server is rejected.

``require`` selects each tool's required capability:

* a ``"verb:resource"`` string applied to every tool;
* a mapping ``{tool_name: "verb:resource"}`` — a tool absent from the map needs only a *valid* proof
  (resource-server-correct), with no specific capability; or
* a callable ``(function) -> "verb:resource" | None`` — ``None`` likewise means "valid proof, no
  capability". The callable receives the ``AIFunction`` object the framework is about to invoke.

``agent_framework`` is imported optionally/duck-typed: when its ``FunctionMiddleware`` base class is
present the middleware subclasses it (so the framework classifies and runs it as function middleware);
otherwise it is a plain object exposing the same ``async process(context, next)`` hook, so the decision
logic is fully testable with the framework absent.
"""
from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Mapping, Optional, Tuple, Union

from ._proof import PCA_ARG, coerce_pcactn, current_proof
from .tool import PcaToolDenied
from .verifier import CoreVerifier, GrantResolver, ToolDecision, Verifier

#: How each tool's required capability is chosen. See the module docstring. The callable form receives
#: the ``AIFunction`` the framework is about to invoke (typed ``object`` — it is a framework value we
#: duck-type, not something this package depends on the concrete type of).
RequireSpec = Union[str, Mapping[str, str], Callable[[object], Optional[str]]]

#: The ``next`` the framework hands a function-invocation middleware: run the rest of the pipeline
#: (ultimately the tool) for this context. Returns an awaitable in the Agent Framework.
NextFn = Callable[[object], Awaitable[None]]


# Base the middleware on the framework's FunctionMiddleware when present, so it is recognised and run as
# function-invocation middleware; otherwise a plain object with the same hook. Static checkers see the
# `object` base (via TYPE_CHECKING), so no type suppression is needed.
if TYPE_CHECKING:
    _FunctionMiddlewareBase = object
else:
    try:  # pragma: no cover - import shape depends on whether agent_framework is installed
        from agent_framework import FunctionMiddleware as _FunctionMiddlewareBase
    except Exception:  # pragma: no cover - the dependency-free path
        _FunctionMiddlewareBase = object


def _require_for(function: object, name: Optional[str], require: RequireSpec) -> Optional[str]:
    if callable(require) and not isinstance(require, Mapping):
        return require(function)
    if isinstance(require, Mapping):
        return require.get(name) if name is not None else None
    return require


def _split_require(spec: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if spec is None:
        return None, None
    if not isinstance(spec, str) or ":" not in spec:
        raise ValueError("require entry must be a 'verb:resource' string, got %r" % (spec,))
    verb, resource = spec.split(":", 1)
    if not verb or not resource:
        raise ValueError("require entry must be a non-empty 'verb:resource' string, got %r" % (spec,))
    return verb, resource


def _function_name(function: object, context: object) -> Optional[str]:
    """The invoked tool's name, from the ``AIFunction`` (``.name`` / ``__name__``) or the context."""
    name = getattr(function, "name", None) or getattr(function, "__name__", None)
    if name is None:
        name = getattr(context, "name", None)
    return str(name) if name is not None else None


def _read_proof(arguments: object, *, arg_name: str) -> Optional[Dict[str, Any]]:
    """Resolve the proof for one call and strip the inline key from ``arguments`` so the tool never
    sees it: an explicit inline ``pca_action`` wins, else the context var. ``None`` fails closed."""
    inline: Any = None
    if isinstance(arguments, dict) and arg_name in arguments:
        inline = arguments.pop(arg_name)
    if inline is not None:
        return coerce_pcactn(inline)
    return coerce_pcactn(current_proof())


def _deny_result(decision: ToolDecision) -> Dict[str, Any]:
    """The tool-result the framework hands back to the model when a call is denied."""
    return {
        "error": decision.reason or "proof-carrying authority required",
        "pca": {"allowed": False, "required": decision.required},
    }


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


class PcaFunctionMiddleware(_FunctionMiddlewareBase):
    """Function-invocation middleware enforcing a PCActn on every tool an agent invokes.

    Construct it with :func:`pca_function_middleware`. The pure decision is :meth:`decide`; :meth:`process`
    is the framework hook (also exposed as ``__call__``) that allows a call by invoking ``next`` and
    denies it by setting ``context.result`` (or raising when ``raise_on_deny`` is set).
    """

    def __init__(self, *, audience: str, require: RequireSpec, verifier: Verifier,
                 raise_on_deny: bool = False, arg_name: str = PCA_ARG) -> None:
        if _FunctionMiddlewareBase is not object:
            super().__init__()
        self._audience = audience
        self._require = require
        self._verifier = verifier
        self._raise_on_deny = raise_on_deny
        self._arg_name = arg_name

    def decide(self, *, function: object = None, name: Optional[str] = None,
               arguments: Optional[Dict[str, Any]] = None) -> ToolDecision:
        """Decide one tool call without any framework types. Pure and fail-closed.

        Note: ``arguments`` is mutated in place to strip the inline ``pca_action`` key, exactly as the
        real call path does, so the tool never receives the proof as one of its own arguments.
        """
        verb, resource = _split_require(_require_for(function, name, self._require))
        pcactn = _read_proof(arguments, arg_name=self._arg_name)
        return self._verifier.verify(pcactn, verb=verb, resource=resource, audience=self._audience)

    async def process(self, context: object, next: NextFn) -> None:
        """Framework hook: verify before the tool runs; allow via ``next``, else deny fail-closed."""
        function = getattr(context, "function", None)
        name = _function_name(function, context)
        arguments = getattr(context, "arguments", None)
        decision = self.decide(function=function, name=name,
                               arguments=arguments if isinstance(arguments, dict) else None)
        if decision.ok:
            await _maybe_await(next(context))
            return
        if self._raise_on_deny:
            raise PcaToolDenied(decision)
        # Deny: do NOT call `next` (the tool never runs) and hand the model a structured result.
        setattr(context, "result", _deny_result(decision))

    async def __call__(self, context: object, next: NextFn) -> None:
        """Allow use as a plain function-style middleware (``middleware(context, next)``)."""
        await self.process(context, next)


def pca_function_middleware(*, audience: str, require: RequireSpec,
                            resolve_grant: Optional[GrantResolver] = None,
                            verifier: Optional[Verifier] = None, now: Optional[int] = None,
                            raise_on_deny: bool = False,
                            arg_name: str = PCA_ARG) -> PcaFunctionMiddleware:
    """Build the Agent Framework function-invocation middleware that gates every tool with PCA.

    ``audience``       — this agent's RFC 8707 resource id; a proof for another audience is rejected.
    ``require``        — a :data:`RequireSpec` choosing each tool's capability (see the module docstring).
    ``resolve_grant``  — ``(grant_ref) -> grant | None``; required unless ``verifier`` is supplied.
    ``verifier``       — a :class:`Verifier`; defaults to :class:`CoreVerifier` built from ``resolve_grant``.
    ``now``            — epoch-ms validity clock (default: wall clock); used only for the default verifier.
    ``raise_on_deny``  — raise :class:`PcaToolDenied` instead of setting a deny result on ``context``.
    ``arg_name``       — the inline proof key in ``arguments`` (default ``"pca_action"``), stripped before the tool runs.

    Wire it in one line::

        from agent_framework import ChatAgent
        from atlas_pca_agent_framework import pca_function_middleware

        agent = ChatAgent(
            chat_client=client,
            tools=[place_order, cancel_order],
            middleware=[pca_function_middleware(
                audience="rs-orders",
                require={"place_order": "write:db/orders"},
                resolve_grant=resolve,
            )],
        )
    """
    if not audience:
        raise ValueError("pca_function_middleware requires a non-empty `audience`")
    if verifier is None:
        if resolve_grant is None:
            raise ValueError("pca_function_middleware requires either `verifier=` or `resolve_grant=`")
        verifier = CoreVerifier(resolve_grant, now=now)
    elif resolve_grant is not None:
        raise ValueError("pass either `verifier=` or `resolve_grant=`, not both")
    return PcaFunctionMiddleware(audience=audience, require=require, verifier=verifier,
                                 raise_on_deny=raise_on_deny, arg_name=arg_name)
