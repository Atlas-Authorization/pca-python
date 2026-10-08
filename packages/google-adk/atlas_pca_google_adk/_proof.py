"""How a PCActn is carried into a Google ADK tool call, and how it is normalized to an object.

ADK tool calls have no HTTP envelope, so a proof reaches a guarded tool one of three ways, mirroring
how ``atlas_pca.server`` carries a proof over the wire (header / body) and how the sibling CrewAI and
FastMCP guards carry it (context var / tool-input convention):

* the ADK **session state** (``tool_context.state``) under the key ``"PCA-Action"`` — the
  resource-server-correct channel: state rides every tool call in a session and is not part of the
  tool's own argument schema, so the model cannot forge or omit it. This is the analogue of the MCP
  ``_meta`` / the ``PCA-Action`` request header;
* a **context var** (:func:`pca_context` / :func:`set_pca_action`) that an orchestration layer sets
  around an agent run or a single tool call — the analogue of a request-scoped header; or
* a **tool-input convention**: a reserved ``pca_action`` key in the tool-call ``args`` itself, for
  clients that can only influence the arguments.

A proof may be a parsed object, a raw JSON string, or the base64url of UTF-8 JSON (the exact
``PCA-Action`` header/meta encoding used across the Atlas PCA SDKs). :func:`coerce_pcactn` normalizes
all three to a ``dict`` (or ``None``), going through the strict JSON profile of the reference verifier
so nothing here parses JSON more leniently than the verifier itself.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any, Dict, Iterator, Optional, Union

from atlas_pca.pca import StrictJsonError, decode_b64u_strict, strict_parse

#: Reserved key a caller may pass in a tool invocation's ``args`` to carry the proof inline.
PCA_ARG = "pca_action"

#: Key the proof travels under in ADK session state (``tool_context.state``). Matches the
#: ``PCA-Action`` request header / MCP ``_meta`` key used by the other Atlas PCA SDKs.
PCA_STATE_KEY = "PCA-Action"

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


def proof_from_tool_context(tool_context: Any, *, state_key: str = PCA_STATE_KEY) -> ProofInput:
    """The raw proof carried in an ADK ``tool_context``'s session state, or ``None``.

    Duck-typed over ADK's ``ToolContext``: reads ``tool_context.state`` (a dict-like ``State``) under
    ``state_key``. Any missing/odd shape yields ``None`` (the guard then fails closed). The returned
    value is still raw — pass it through :func:`coerce_pcactn` before use.
    """
    if tool_context is None:
        return None
    state = getattr(tool_context, "state", None)
    if state is None:
        return None
    getter = getattr(state, "get", None)
    if callable(getter):
        try:
            value = getter(state_key)
        except Exception:
            value = None
        if value is not None:
            return value
    try:
        return state[state_key]
    except Exception:
        return None


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
            runner.run(...)   # every guarded tool / gated callback sees this proof
    """
    token = _CURRENT.set(pcactn)
    try:
        yield
    finally:
        _CURRENT.reset(token)
