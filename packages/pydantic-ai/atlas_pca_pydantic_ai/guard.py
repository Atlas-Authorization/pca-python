"""Proof-carrying authority for Pydantic AI tools.

A tool call is where an agent's authority turns into a side effect, so :func:`pca_tool` wraps a tool
function to verify a proof-carrying action *before* the tool runs and fail closed otherwise:

* no proof, or an undecodable one                      -> reject (the tool never runs)
* a proof that does not verify under the core verifier -> reject (bad signature / chain / validity /
  wrong audience / unknown grant / replay counter)
* a valid proof whose authorized action does not satisfy the tool's required capability -> reject
* otherwise                                            -> run the real tool

``audience`` is this tool server's RFC 8707 resource identifier: a proof minted for a *different*
audience is rejected by the core verifier's ``audience`` check, so a token for another server cannot be
replayed here (resource-server-correct).

Pydantic AI is imported optionally / duck-typed, so the package imports and the pure decision
(:meth:`PCAGuard.decide`) are testable with ``pydantic_ai`` absent. When it *is* installed, a rejection
is raised as :class:`PCARejected`, which subclasses ``pydantic_ai.ModelRetry`` so the framework surfaces
the reason to the model as a soft error; absent the dependency it is a plain typed exception.
"""
import functools
import inspect
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Dict, Mapping, Optional, TypeVar, Union, cast

from atlas_pca.pca import Verdict

from .capability import Capability, capability_satisfies, parse_capability
from .extract import PCA_KEY, extract_pcactn
from .verifier import CoreVerifier, GrantResolver, Verifier

__all__ = [
    "PCADeps",
    "PCADecision",
    "PCARejected",
    "PCAGuard",
    "pca_tool",
]

PCActn = Dict[str, Any]


@dataclass
class PCADeps:
    """A ready-made :class:`RunContext.deps` carrier for a PCActn.

    Use it directly as an agent's ``deps_type`` when the tool needs no other dependencies, or copy the
    ``pca_action`` field onto your own deps dataclass. It holds the base64url wire form **or** the
    inline PCActn object::

        agent = Agent(model, deps_type=PCADeps)
        agent.run_sync("...", deps=PCADeps(pca_action=proof_b64u))
    """

    pca_action: Optional[Union[str, Mapping[str, Any]]] = None


@dataclass
class PCADecision:
    """The outcome of enforcing one tool call. ``allow`` is the field a caller branches on."""

    allow: bool
    reason: Optional[str] = None
    required: Optional[Capability] = None
    verdict: Optional[Verdict] = None
    pcactn: Optional[PCActn] = None
    tool: Optional[str] = None


# PCARejected subclasses pydantic_ai's ModelRetry when it is installed, so a rejection surfaces to the
# model as a retryable soft error (ModelRetry forwards its message to the model); with pydantic_ai
# absent it is a plain exception. Static checkers always see the Exception base (via TYPE_CHECKING), so
# this stays statically typed with no suppression and no class redefinition — the base is chosen once,
# at import.
if TYPE_CHECKING:
    _RejectBase = Exception
else:
    try:  # pragma: no cover - exercised only when pydantic_ai is installed
        from pydantic_ai import ModelRetry as _RejectBase
    except Exception:  # pragma: no cover - the dependency-free path
        _RejectBase = Exception


class PCARejected(_RejectBase):
    """Raised to reject a tool call. Carries the denying :class:`PCADecision`.

    When ``pydantic_ai`` is installed this *is* a ``ModelRetry``, so raising it inside a tool tells the
    agent run that the call was refused and hands the reason back to the model.
    """

    def __init__(self, decision: "PCADecision") -> None:
        self.decision = decision
        super().__init__(decision.reason or "proof-carrying authority required")


def _resolve_verifier(verifier: Optional[Verifier], resolve_grant: Optional[GrantResolver]) -> Verifier:
    if verifier is None:
        if resolve_grant is None:
            raise ValueError("a pca guard needs a verifier or a resolve_grant callback")
        return CoreVerifier(resolve_grant=resolve_grant)
    if resolve_grant is not None:
        raise ValueError("pass either verifier or resolve_grant, not both")
    return verifier


def _takes_ctx(func: Callable[..., object]) -> bool:
    """True when ``func``'s first parameter is a Pydantic AI ``RunContext`` (an ``@agent.tool``).

    Detected from the annotation (``RunContext`` / ``RunContext[Deps]``, whether a real object or a
    string from ``from __future__ import annotations``), falling back to the conventional first-arg name
    for an un-annotated tool. An ``@agent.tool_plain`` takes no context and returns ``False``.
    """
    try:
        params = list(inspect.signature(func).parameters.values())
    except (TypeError, ValueError):
        return False
    if not params:
        return False
    first = params[0]
    annotation = first.annotation
    if annotation is inspect.Parameter.empty:
        return first.name in ("ctx", "context", "run_context")
    text = annotation if isinstance(annotation, str) else getattr(annotation, "__name__", "") or str(annotation)
    return "RunContext" in text


def _deps_of(takes_ctx: bool, args: "tuple[object, ...]") -> object:
    """The agent dependencies for this call: ``RunContext.deps`` when the tool takes a context."""
    if takes_ctx and args:
        return getattr(args[0], "deps", None)
    return None


class PCAGuard:
    """A reusable guard bound to one audience + verifier, so a whole agent's tools share it.

    Build it once and decorate each tool with :meth:`tool`; it is the helper that registers the guard
    across an agent's tools without repeating the audience/verifier each time::

        guard = PCAGuard(audience="agent://orders", resolve_grant=my_resolver)

        @agent.tool
        @guard.tool("write:db/orders")
        def transfer(ctx: RunContext[PCADeps], amount: int) -> str:
            ...

    The same guard also wraps a bare function for the ``Tool(...)`` constructor::

        agent = Agent(model, tools=[Tool(guard.wrap(transfer, "write:db/orders"))])
    """

    def __init__(
        self,
        *,
        audience: str,
        verifier: Optional[Verifier] = None,
        resolve_grant: Optional[GrantResolver] = None,
        key: str = PCA_KEY,
    ) -> None:
        if not audience:
            raise ValueError("a pca guard requires a non-empty audience (this server's RFC 8707 resource)")
        self.audience = audience
        self.verifier = _resolve_verifier(verifier, resolve_grant)
        self.key = key

    def decide(self, required: Capability, *, deps: object = None, arguments: object = None) -> PCADecision:
        """Decide one tool call without any Pydantic AI types. Pure and fail-closed."""
        pcactn, err = extract_pcactn(deps, arguments, key=self.key)
        if pcactn is None:
            reason = "no PCActn presented" if err == "absent" else "PCActn could not be decoded"
            return PCADecision(allow=False, required=required, reason=reason)

        verdict = self.verifier.verify(pcactn, audience=self.audience)
        if not verdict.allow:
            return PCADecision(
                allow=False, required=required, verdict=verdict, pcactn=pcactn,
                reason=verdict.reason or "proof did not verify",
            )

        action = pcactn.get("action")
        verb = action.get("verb") if isinstance(action, dict) else None
        resource = action.get("resource") if isinstance(action, dict) else None
        if not (isinstance(verb, str) and isinstance(resource, str)
                and capability_satisfies(required, verb, resource)):
            authorized = "%s:%s" % (verb, resource)
            return PCADecision(
                allow=False, required=required, verdict=verdict, pcactn=pcactn,
                reason="insufficient_capability: requires %r, proof authorizes %r" % (str(required), authorized),
            )

        return PCADecision(allow=True, required=required, verdict=verdict, pcactn=pcactn)

    def wrap(self, func: "F", require: Union[str, Capability]) -> "F":
        """Wrap a tool function so it enforces ``require`` before running. Preserves the signature."""
        required = parse_capability(require)
        takes_ctx = _takes_ctx(func)
        tool_name = getattr(func, "__name__", None)

        def evaluate(args: "tuple[object, ...]", kwargs: "Dict[str, object]") -> PCADecision:
            deps = _deps_of(takes_ctx, args)
            decision = self.decide(required, deps=deps, arguments=kwargs)
            decision.tool = tool_name
            return decision

        def clean(kwargs: "Dict[str, object]") -> "Dict[str, object]":
            # Drop a proof carried in the (model-controlled) arguments so it is never forwarded to the
            # real tool, which does not declare it.
            return {k: v for k, v in kwargs.items() if k != self.key}

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: object, **kwargs: object) -> object:
                decision = evaluate(args, kwargs)
                if not decision.allow:
                    raise PCARejected(decision)
                return await func(*args, **clean(kwargs))

            return cast("F", async_wrapper)

        @functools.wraps(func)
        def sync_wrapper(*args: object, **kwargs: object) -> object:
            decision = evaluate(args, kwargs)
            if not decision.allow:
                raise PCARejected(decision)
            return func(*args, **clean(kwargs))

        return cast("F", sync_wrapper)

    def tool(self, require: Union[str, Capability]) -> "Callable[[F], F]":
        """A decorator form of :meth:`wrap`, bound to this guard: ``@guard.tool("write:db/orders")``."""
        def decorator(func: "F") -> "F":
            return self.wrap(func, require)

        return decorator


F = TypeVar("F", bound=Callable[..., object])


def pca_tool(
    require: Union[str, Capability],
    *,
    audience: str,
    verifier: Optional[Verifier] = None,
    resolve_grant: Optional[GrantResolver] = None,
    key: str = PCA_KEY,
) -> Callable[[F], F]:
    """Make one Pydantic AI tool proof-carrying + policy-gated.

    Before the tool runs it requires a valid proof-carrying action (extracted per the ``PCA-Action``
    convention from ``RunContext.deps`` or the tool arguments), verifies it via the shared
    :mod:`atlas_pca` verifier (fail closed on a missing / invalid / wrong-audience / insufficient
    proof), and only then runs. A rejection raises :class:`PCARejected` (a ``pydantic_ai.ModelRetry``
    when that is installed) so Pydantic AI surfaces it.

    ``require``       — the ``"verb:resource"`` capability the proof's ``action`` must satisfy.
    ``audience``      — this tool server's RFC 8707 resource id; the PCActn's signed ``aud`` must equal it.
    ``verifier``      — a :class:`~atlas_pca_pydantic_ai.verifier.Verifier`; omit it and pass
                        ``resolve_grant`` to use the default :class:`CoreVerifier`.
    ``resolve_grant`` — ``grant_ref -> grant | None``, mapping the PCActn's ``grant_ref`` to the root grant.

    Stack it under Pydantic AI's own tool decorator (the signature is preserved either way)::

        @agent.tool
        @pca_tool("write:db/orders", audience="agent://orders", resolve_grant=my_resolver)
        def transfer(ctx: RunContext[PCADeps], amount: int) -> str:
            ...
    """
    guard = PCAGuard(audience=audience, verifier=verifier, resolve_grant=resolve_grant, key=key)
    return guard.tool(require)
