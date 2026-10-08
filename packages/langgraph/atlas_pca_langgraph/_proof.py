"""How a PCActn is carried into a LangGraph run, and how it is normalized to an object.

LangGraph nodes and tool calls have no HTTP envelope, so a proof reaches a guarded tool/node one of
four ways, mirroring how ``atlas_pca.server`` carries a proof over the wire (header / body) and how the
sibling CrewAI and Google ADK guards carry it (session state / context var / tool-input convention):

* the graph **state** dict under the key ``"PCA-Action"`` (:data:`PCA_STATE_KEY`) — the
  resource-server-correct channel for a node: state rides every super-step and is not part of a tool's
  own argument schema, so the model cannot forge or omit it. This is the analogue of the MCP ``_meta``
  / the ``PCA-Action`` request header;
* the **config** ``configurable`` dict under the same key (:data:`PCA_CONFIG_KEY`) — a ``RunnableConfig``
  rides every node and tool invocation (``graph.invoke(state, {"configurable": {"PCA-Action": ...}})``),
  the analogue of a request-scoped header, and is what a guarded tool sees from inside a ``ToolNode``;
* a **context var** (:func:`pca_context` / :func:`set_pca_action`) that an orchestration layer sets
  around a graph run or a single node — the analogue of a request-scoped header; or
* a **tool-input convention**: a reserved ``pca_action`` key (:data:`PCA_ARG`) in a tool-call's ``args``
  itself, for clients that can only influence the arguments.

A proof may be a parsed object, a raw JSON string, or the base64url of UTF-8 JSON (the exact
``PCA-Action`` header/meta encoding used across the Atlas PCA SDKs). :func:`coerce_pcactn` normalizes
all of these to a ``dict`` (or ``None``), going through the strict JSON profile of the reference
verifier so nothing here parses JSON more leniently than the verifier itself.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any, Dict, Iterator, Mapping, Optional, Union

from atlas_pca.pca import StrictJsonError, decode_b64u_strict, strict_parse

#: Reserved key a caller may pass in a tool-call's ``args`` to carry the proof inline.
PCA_ARG = "pca_action"

#: Key the proof travels under in the LangGraph **state** dict. Matches the ``PCA-Action`` request
#: header / MCP ``_meta`` key used by the other Atlas PCA SDKs.
PCA_STATE_KEY = "PCA-Action"

#: Key the proof travels under in the ``RunnableConfig`` ``configurable`` dict.
PCA_CONFIG_KEY = "PCA-Action"

#: What a caller may hand us: a parsed PCActn, its JSON text, its base64url, or nothing.
ProofInput = Union[Dict[str, Any], str, bytes, bytearray, None]

_CURRENT: ContextVar[ProofInput] = ContextVar("atlas_pca_action", default=None)


def coerce_pcactn(raw: ProofInput) -> Optional[Dict[str, Any]]:
    """Normalize a carried proof to a PCActn object, or ``None`` when absent/undecodable.

    Accepts a ``dict`` (returned as-is), a base64url string of UTF-8 JSON, a raw JSON string, or raw
    JSON bytes. All text goes through the strict RFC 8259 profile of the reference verifier. Never
    raises: an undecodable value is simply ``None`` (and the guard then fails closed).
    """
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        decoded = decode_b64u_strict(raw)
        if decoded is not None:
            obj = _parse(decoded)
            if obj is not None:
                return obj
        return _parse(raw)
    if isinstance(raw, (bytes, bytearray)):
        return _parse(bytes(raw))
    return None


def _parse(text: Union[str, bytes]) -> Optional[Dict[str, Any]]:
    try:
        obj = strict_parse(text)
    except StrictJsonError:
        return None
    return obj if isinstance(obj, dict) else None


def proof_from_state(state: Any, *, state_key: str = PCA_STATE_KEY) -> ProofInput:
    """The raw proof carried in a LangGraph **state** dict, or ``None``.

    Duck-typed over the graph state: reads ``state[state_key]`` from any ``Mapping`` (a plain ``dict``,
    a ``TypedDict`` instance, ``MessagesState``), or an attribute of the same name on a state object.
    Any missing/odd shape yields ``None`` (the guard then fails closed). The returned value is still
    raw — pass it through :func:`coerce_pcactn` before use.
    """
    if state is None:
        return None
    if isinstance(state, Mapping):
        return state.get(state_key)
    getter = getattr(state, "get", None)
    if callable(getter):
        try:
            value = getter(state_key)
        except Exception:
            value = None
        if value is not None:
            return value
    return getattr(state, state_key, None)


def proof_from_config(config: Any, *, config_key: str = PCA_CONFIG_KEY) -> ProofInput:
    """The raw proof carried in a ``RunnableConfig``'s ``configurable`` dict, or ``None``.

    Duck-typed over LangChain/LangGraph's ``RunnableConfig`` (a ``Mapping`` with a ``"configurable"``
    sub-dict): reads ``config["configurable"][config_key]``. Any missing/odd shape yields ``None``.
    The returned value is still raw — pass it through :func:`coerce_pcactn` before use.
    """
    if not isinstance(config, Mapping):
        return None
    configurable = config.get("configurable")
    if not isinstance(configurable, Mapping):
        return None
    return configurable.get(config_key)


def set_pca_action(pcactn: ProofInput) -> "Token[ProofInput]":
    """Bind a proof to the current context. Returns a token for :func:`reset_pca_action`."""
    return _CURRENT.set(pcactn)


def reset_pca_action(token: "Token[ProofInput]") -> None:
    """Undo a :func:`set_pca_action`, restoring the previously bound proof."""
    _CURRENT.reset(token)


def current_proof() -> ProofInput:
    """The raw proof bound to the current context, or ``None``."""
    return _CURRENT.get()


@contextmanager
def pca_context(pcactn: ProofInput) -> Iterator[None]:
    """Bind ``pcactn`` as the current proof for the duration of the ``with`` block.

    Usage::

        with pca_context(my_pcactn):
            graph.invoke(state)   # every guarded tool / gated node sees this proof
    """
    token = _CURRENT.set(pcactn)
    try:
        yield
    finally:
        _CURRENT.reset(token)


def resolve_proof(inline: ProofInput = None, *, state: Any = None, config: Any = None,
                  state_key: str = PCA_STATE_KEY, config_key: str = PCA_CONFIG_KEY,
                  ) -> Optional[Dict[str, Any]]:
    """The effective proof for one invocation, normalized to an object (``None`` fails closed).

    Precedence, most specific first: an explicit ``inline`` proof (the reserved ``pca_action`` arg),
    then the graph ``state``, then the ``config.configurable``, then the context var. Each candidate is
    normalized through the strict profile; the first that yields an object wins.
    """
    if inline is not None:
        got = coerce_pcactn(inline)
        if got is not None:
            return got
    from_state = proof_from_state(state, state_key=state_key)
    if from_state is not None:
        got = coerce_pcactn(from_state)
        if got is not None:
            return got
    from_config = proof_from_config(config, config_key=config_key)
    if from_config is not None:
        got = coerce_pcactn(from_config)
        if got is not None:
            return got
    return coerce_pcactn(current_proof())
