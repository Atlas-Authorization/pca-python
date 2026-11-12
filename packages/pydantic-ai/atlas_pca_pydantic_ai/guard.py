"""Proof-carrying authority for Pydantic AI tools.

A tool call is where an agent's authority turns into a side effect, so :func:`pca_tool` wraps a tool
function to verify a proof-carrying action *before* the tool runs and fail closed otherwise:

* no proof, or an undecodable one                      -> reject (the tool never runs)
* a proof that does not verify under the core verifier -> reject (bad signature / chain / validity /
  wrong audience / unknown grant / malformed counter; the counter is format-checked, not replay-checked)
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
from .extract import PCA_KEY, _coerce, extract_pcactn, provenance_from_deps
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
    #: provenance by default: the bundle your agent harness's recorder returned for the call (object or base64url JSON)
    pca_provenance: Optional[Union[str, Mapping[str, Any]]] = None


@dataclass
class PCADecision:
    """The outcome of enforcing one tool call. ``allow`` is the field a caller branches on."""

    allow: bool
    reason: Optional[str] = None
    required: Optional[Capability] = None
    verdict: Optional[Verdict] = None
    pcactn: Optional[PCActn] = None
    tool: Optional[str] = None
    #: authorize mode: the full ``atlas_pca.AuthorizeResult`` (checks, reasons, bound operation)
    authorization: Any = None


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


def _authorize_options(authorize: Any) -> Any:
    from atlas_pca.authorize import AuthorizeOptions  # atlas-pca 0.5+

    if authorize is None:
        return AuthorizeOptions()  # empty: every call is refused (authorize_config) until a store etc. is supplied
    return AuthorizeOptions(**dict(authorize)) if isinstance(authorize, Mapping) else authorize


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
        # the default (0.5): bind the call arguments, enforce caveats / revocation / replay
        guard = PCAGuard(audience="agent://orders", resolve_grant=my_resolver,
                         authorize=AuthorizeOptions(state_store=store, is_revoked=is_revoked))
        # explicit opt-in to verifying the signature only
        guard = PCAGuard(audience="agent://orders", resolve_grant=my_resolver, signature_only=True)

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
        authorize: Any = None,
        now: Optional[int] = None,
        signature_only: bool = False,
        provenance: Optional[Callable[[Dict[str, Any]], Any]] = None,
        recorder: Any = None,
    ) -> None:
        if not audience:
            raise ValueError("a pca guard requires a non-empty audience (this server's RFC 8707 resource)")
        if signature_only and authorize is not None:
            raise ValueError("signature_only and authorize are mutually exclusive")
        if not signature_only and (verifier is not None or resolve_grant is None):
            raise ValueError("a pca guard runs the full authorize pipeline by default and needs resolve_grant (and no "
                             "verifier); pass signature_only=True to verify the signature only")
        self.audience = audience
        self.verifier = _resolve_verifier(verifier, resolve_grant)
        self.key = key
        self._authorize = None if signature_only else _authorize_options(authorize)
        self._resolve_grant = resolve_grant
        self._now = now
        self._provenance = provenance
        #: the agent session's ``atlas_pca.ProvenanceRecorder`` (or None), see :func:`pca_tool`
        self.recorder = recorder

    def decide(self, required: Capability, *, deps: object = None, arguments: object = None,
               params: Any = None) -> PCADecision:
        """Decide one tool call without any Pydantic AI types. Pure and fail-closed.

        Authorize mode (the default; not ``signature_only``): ``params`` are the call arguments the proof must be bound to; the
        operation is ``required`` (an exact ``verb:resource``; a wildcard capability is refused).
        """
        pcactn, err = extract_pcactn(deps, arguments, key=self.key)
        if pcactn is None:
            reason = "no PCActn presented" if err == "absent" else "PCActn could not be decoded"
            return PCADecision(allow=False, required=required, reason=reason)
        if self._authorize is not None:
            return self._decide_authorized(required, pcactn, params, deps)

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

    def _bundle(self, op: Dict[str, Any], deps: object) -> Any:
        """This call's provenance bundle: ``provenance(op)``, else the one on ``deps``, else ``recorder.for_action(op)``."""
        raw = self._provenance(op) if self._provenance is not None else provenance_from_deps(deps)
        if raw is not None:
            return raw if isinstance(raw, dict) else _coerce(raw)[0]  # the object, or its base64url JSON
        return self.recorder.for_action(op) if self.recorder is not None else None

    def _decide_authorized(self, required: Capability, pcactn: PCActn, params: Any, deps: object = None) -> PCADecision:
        from atlas_pca.authorize import authorize_tool_call  # atlas-pca 0.5+

        exact = "*" not in required.verb and "*" not in required.resource
        bundle = None
        if exact and params is not None:  # otherwise authorize_tool_call refuses the call before the gate
            try:
                bundle = self._bundle({"verb": required.verb, "resource": required.resource, "params": dict(params)},
                                      deps)
            except Exception:  # noqa: BLE001  (fail closed: a bundle source or recorder that fails never lets the call through)
                return PCADecision(allow=False, required=required, pcactn=pcactn,
                                   reason="provenance_flow: the provenance bundle could not be read or recorded "
                                          "(fail closed)")
        r = authorize_tool_call(self._authorize, pcactn, verb=required.verb if exact else None,
                                resource=required.resource if exact else None, params=params,
                                audience=self.audience, resolve_grant=self._resolve_grant, now=self._now,
                                provenance=bundle)
        return PCADecision(allow=r.allow, required=required, verdict=r.verdict, pcactn=pcactn,
                           reason=None if r.allow else r.reason, authorization=r)

    def wrap(self, func: "F", require: Union[str, Capability]) -> "F":
        """Wrap a tool function so it enforces ``require`` before running. Preserves the signature."""
        required = parse_capability(require)
        takes_ctx = _takes_ctx(func)
        tool_name = getattr(func, "__name__", None)

        def evaluate(args: "tuple[object, ...]", kwargs: "Dict[str, object]") -> PCADecision:
            deps = _deps_of(takes_ctx, args)
            if self._authorize is None:
                decision = self.decide(required, deps=deps, arguments=kwargs)
            else:
                # the call arguments (positional ones beyond the RunContext cannot be bound: refused)
                bound = clean(kwargs) if len(args) <= (1 if takes_ctx else 0) else None
                decision = self.decide(required, deps=deps, arguments=kwargs, params=bound)
            decision.tool = tool_name
            return decision

        def clean(kwargs: "Dict[str, object]") -> "Dict[str, object]":
            # Drop a proof carried in the (model-controlled) arguments so it is never forwarded to the
            # real tool, which does not declare it.
            return {k: v for k, v in kwargs.items() if k != self.key}

        def record(out: object) -> None:
            # provenance by default: what the tool returned is untrusted content for every later call
            if self.recorder is not None:
                self.recorder.tool(required.verb, out)

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: object, **kwargs: object) -> object:
                decision = evaluate(args, kwargs)
                if not decision.allow:
                    raise PCARejected(decision)
                out = await func(*args, **clean(kwargs))
                record(out)
                return out

            return cast("F", async_wrapper)

        @functools.wraps(func)
        def sync_wrapper(*args: object, **kwargs: object) -> object:
            decision = evaluate(args, kwargs)
            if not decision.allow:
                raise PCARejected(decision)
            out = func(*args, **clean(kwargs))
            record(out)
            return out

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
    authorize: Any = None,
    now: Optional[int] = None,
    signature_only: bool = False,
    provenance: Optional[Callable[[Dict[str, Any]], Any]] = None,
    recorder: Any = None,
) -> Callable[[F], F]:
    """Make one Pydantic AI tool proof-carrying + policy-gated.

    Before the tool runs it requires a valid proof-carrying action (extracted per the ``PCA-Action``
    convention from ``RunContext.deps`` or the tool arguments), verifies it via the shared
    :mod:`atlas_pca` verifier (fail closed on a missing / invalid / wrong-audience / insufficient
    proof), and only then runs. A rejection raises :class:`PCARejected` (a ``pydantic_ai.ModelRetry``
    when that is installed) so Pydantic AI surfaces it.

    ``require``       — the ``"verb:resource"`` capability the proof's ``action`` must satisfy.
    ``audience``      — this tool server's RFC 8707 resource id; the PCActn's signed ``aud`` must equal it.
    ``verifier``      — a :class:`~atlas_pca_pydantic_ai.verifier.Verifier`; only with ``signature_only=True``.
    ``resolve_grant`` — ``grant_ref -> grant | None``, mapping the PCActn's ``grant_ref`` to the root grant; required.
    ``authorize``     — the full pipeline, the default (0.5): an ``atlas_pca.AuthorizeOptions`` (or a dict of its
                        fields: ``state_store``, ``is_revoked``, ...). The proof must be for exactly this call
                        (``require``, which must be an exact ``verb:resource``, with the keyword arguments as params),
                        and the grant's predicates and caveats, revocation and the replay counter are enforced
                        before the tool runs. Needs ``resolve_grant``. Without ``authorize`` every call is refused
                        (``authorize_config``). ``now`` fixes its clock.
    ``signature_only`` — explicit opt-in to verifying the signature, chain, audience, validity and counter format
                        only (no policy, replay or revocation). Cannot be combined with ``authorize``.
    ``provenance``    — provenance by default (authorize mode): ``(operation) -> bundle | None``, the provenance bundle for
                        this call (the one your agent harness's recorder returned for it). Default: the bundle on
                        ``RunContext.deps`` (``deps.pca_provenance``, see :class:`PCADeps`, or ``deps["PCA-Provenance"]``).
                        It is forwarded to ``authorize``; pin the recording mediator in ``authorize.provenance_mediators``.
                        Never synthesize a principal-direct bundle for a call the model chose: a sensitive call whose
                        choice or arguments do not come from the principal escalates.
    ``recorder``      — the agent session's ``atlas_pca.ProvenanceRecorder``: a call that presents no bundle gets
                        ``recorder.for_action(operation)``, and every result a guarded tool returns is recorded in it as
                        UNTRUSTED tool output.

    Stack it under Pydantic AI's own tool decorator (the signature is preserved either way)::

        @agent.tool
        @pca_tool("write:db/orders", audience="agent://orders", resolve_grant=my_resolver, authorize=options)
        def transfer(ctx: RunContext[PCADeps], amount: int) -> str:
            ...
    """
    guard = PCAGuard(audience=audience, verifier=verifier, resolve_grant=resolve_grant, key=key, authorize=authorize,
                     now=now, signature_only=signature_only, provenance=provenance, recorder=recorder)
    return guard.tool(require)
