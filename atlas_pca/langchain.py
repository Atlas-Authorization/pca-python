"""LangChain adapter: wrap a tool so every call builds a PCActn first (the TypeScript reference, @atlasauth/pca-langchain).

Duck-typed (`langchain_core` is never imported). The copy keeps the tool's shape: whichever of `func` / `coroutine` (called with
keyword arguments, as LangChain calls them) and `invoke` / `ainvoke` (called with a dict of arguments) it has is wrapped, every
other attribute is preserved. Does not authorize; the resource server's verifier decides.
"""
from typing import Any, Callable, Optional, Union

from atlas_pca.adapters import PcaCall, guard, guard_kwargs, provenance_headers, record_input, record_messages, record_principal, with_attrs

__all__ = ["with_pca", "with_pca_agent", "PcaCall", "provenance_headers", "record_input", "record_messages", "record_principal"]


def with_pca(agent: Any, verb: str, resource: Union[str, Callable[[dict], str]], tool: Any,
             on_proof: Optional[Callable[[PcaCall, dict], Any]] = None, fail_fast: bool = True) -> Any:
    """Return a copy of `tool` that fast-fails with `PcaDenied` on a failing dry run, hands the proof to `on_proof(pca, args)` and
    then runs the original. `invoke` / `ainvoke` take a dict of arguments (anything else is a TypeError: it cannot be signed)."""
    wrapped = {}
    for m in ("func", "coroutine"):
        f = getattr(tool, m, None)
        if callable(f):
            wrapped[m] = guard_kwargs(agent, verb, resource, f, on_proof, fail_fast)

    def need_dict(a: Any) -> dict:
        if not isinstance(a, dict):
            raise TypeError("with_pca: tool input must be a dict of arguments")
        return a

    def pass_through(a: dict, pca: PcaCall) -> None:
        if on_proof:
            on_proof(pca, a)

    inv = getattr(tool, "invoke", None)
    if callable(inv):
        def invoke(input: Any, config: Any = None, **kw: Any) -> Any:
            def run(a: dict, pca: PcaCall) -> Any:
                pass_through(a, pca)
                return inv(a, **({} if config is None else {"config": config}), **kw)
            return guard(agent, verb, resource, run, fail_fast)(need_dict(input))
        wrapped["invoke"] = invoke
    ainv = getattr(tool, "ainvoke", None)
    if callable(ainv):
        async def ainvoke(input: Any, config: Any = None, **kw: Any) -> Any:
            async def run(a: dict, pca: PcaCall) -> Any:
                pass_through(a, pca)
                return await ainv(a, **({} if config is None else {"config": config}), **kw)
            return await guard(agent, verb, resource, run, fail_fast)(need_dict(input))
        wrapped["ainvoke"] = ainvoke
    if not wrapped:
        raise TypeError("with_pca: the wrapped tool exposes none of func / coroutine / invoke / ainvoke")
    return with_attrs(tool, **wrapped)


def with_pca_agent(agent: Any, runnable: Any) -> Any:
    """Wrap an agent executor / graph so every `invoke` / `ainvoke` / `stream` / `astream` first records the principal's input (a string,
    `{"input": ...}` or `{"messages": [...]}`: human turns are the principal, tool turns untrusted). With the tools wrapped by `with_pca`
    each PCActn then carries the provenance bundle."""
    def rec(f: Any) -> Any:
        def wrapper(input: Any, *args: Any, **kwargs: Any) -> Any:
            record_input(agent, input)
            return f(input, *args, **kwargs)
        return wrapper
    wrapped = {m: rec(getattr(runnable, m)) for m in ("invoke", "ainvoke", "stream", "astream") if callable(getattr(runnable, m, None))}
    return with_attrs(runnable, **wrapped)
