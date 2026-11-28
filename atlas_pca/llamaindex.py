"""LlamaIndex adapter: wrap a FunctionTool so every `call` / `acall` builds a PCActn first (the TypeScript reference, @atlasauth/pca-llamaindex).

Duck-typed (`llama_index` is never imported): the copy keeps `metadata` and every other attribute. `call` / `acall` are invoked with
keyword arguments, which become the action's params. Does not authorize; the resource server's verifier decides.
"""
from typing import Any, Callable, Optional, Union

from atlas_pca.adapters import PcaCall, guard_kwargs, provenance_headers, record_input, record_messages, record_principal, with_attrs

__all__ = ["with_pca", "with_pca_engine", "PcaCall", "provenance_headers", "record_input", "record_messages", "record_principal"]


def with_pca(agent: Any, verb: str, resource: Union[str, Callable[[dict], str]], tool: Any,
             on_proof: Optional[Callable[[PcaCall, dict], Any]] = None, fail_fast: bool = True) -> Any:
    """Return a copy of `tool` whose `call` (and `acall`, when present) fast-fails with `PcaDenied` on a failing dry run, hands the
    proof to `on_proof(pca, args)` and then runs the original. A tool with neither raises TypeError."""
    wrapped = {}
    for m in ("call", "acall"):
        f = getattr(tool, m, None)
        if callable(f):
            wrapped[m] = guard_kwargs(agent, verb, resource, f, on_proof, fail_fast)
    if not wrapped:
        raise TypeError("with_pca: the wrapped tool exposes neither call() nor acall()")
    return with_attrs(tool, **wrapped)


def with_pca_engine(agent: Any, engine: Any) -> Any:
    """Wrap a chat / query engine or agent so every `chat` / `query` (and `achat` / `aquery`) first records the principal's request
    (the first argument, or `message=` / `query=` ...; `chat_history` user turns are the principal, tool turns untrusted)."""
    def rec(f: Any) -> Any:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            hist = kwargs.get("chat_history", kwargs.get("chatHistory"))
            if isinstance(hist, (list, tuple)):
                record_messages(agent, hist)
            record_input(agent, args[0] if args else kwargs)
            return f(*args, **kwargs)
        return wrapper
    wrapped = {m: rec(getattr(engine, m)) for m in ("chat", "query", "achat", "aquery") if callable(getattr(engine, m, None))}
    return with_attrs(engine, **wrapped)
