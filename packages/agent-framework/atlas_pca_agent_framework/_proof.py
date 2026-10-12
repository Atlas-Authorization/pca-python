"""How a PCActn is carried into a Microsoft Agent Framework tool call, and how it is normalized.

Agent Framework function (tool) calls have no HTTP envelope, so a proof reaches a guarded tool one of
two ways, mirroring how ``atlas_pca.server`` carries a proof over the wire and how the sibling CrewAI /
Google ADK guards carry it:

* a **context var** (:func:`pca_context` / :func:`set_pca_action`) that an orchestration layer sets
  around an ``agent.run(...)`` (or a single tool call) — the analogue of a request-scoped header, and
  the **recommended** channel: it is out-of-band, so the model cannot forge or omit it and it never
  appears in the tool's JSON schema; or
* a **tool-input convention**: a reserved ``pca_action`` key in the call ``arguments`` itself, for
  callers that can only influence the arguments (it is stripped before the tool runs).

A proof may be a parsed object, a raw JSON string, or the base64url of UTF-8 JSON (the exact
``PCA-Action`` header encoding used across the Atlas PCA SDKs). :func:`coerce_pcactn` normalizes all
three to a ``dict`` (or ``None``), going through the strict JSON profile of the reference verifier so
nothing here parses JSON more leniently than the verifier itself.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any, Dict, Iterator, Optional, Union

from atlas_pca.pca import StrictJsonError, decode_b64u_strict, strict_parse

#: Reserved key a caller may pass in a tool invocation's ``arguments`` to carry the proof inline.
PCA_ARG = "pca_action"

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
            await agent.run("place the order")   # every guarded tool / gated function sees this proof
    """
    token = _CURRENT.set(pcactn)
    try:
        yield
    finally:
        _CURRENT.reset(token)
