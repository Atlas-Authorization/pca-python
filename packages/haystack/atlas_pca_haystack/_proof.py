"""How a PCActn is carried into a Haystack tool call, and how it is normalized to an object.

A Haystack ``Tool.invoke`` / component ``run`` carries only the arguments an LLM produced for the call,
with no HTTP envelope, so a proof reaches a guarded tool one of two ways — mirroring how
``atlas_pca.server`` carries a proof over the wire:

* a **context var** (:func:`pca_context` / :func:`set_pca_action`) that an orchestration layer sets
  around a ``Pipeline.run`` / ``ToolInvoker.run`` or a single ``Tool.invoke`` — the analogue of a
  request-scoped header, and the only channel the invoker-level guard can use because the LLM, not the
  caller, supplies a tool call's arguments; or
* a **tool-input convention**: a reserved ``pca_action`` keyword in a direct ``invoke`` call itself.

A proof may be a parsed object, a raw JSON string, or the base64url of UTF-8 JSON (the exact
``PCA-Action`` header encoding used by ``atlas_pca.server``). :func:`coerce_pcactn` normalizes all
three to a ``dict`` (or ``None``), going through the strict JSON profile of the reference verifier so
nothing here parses JSON more leniently than the verifier itself.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Any, Dict, Iterator, Optional, Union

from atlas_pca.pca import StrictJsonError, decode_b64u_strict, strict_parse

#: Reserved keyword a caller may pass in a direct ``invoke`` to carry the proof inline.
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
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")  # strict_parse decodes identically (no BOM stripping)
        except UnicodeDecodeError:
            return None
    try:
        obj = strict_parse(text)
    except StrictJsonError:
        return None
    return obj if isinstance(obj, dict) else None


def set_pca_action(pcactn: ProofInput) -> Token[ProofInput]:
    """Bind a proof to the current context. Returns a token for :func:`reset_pca_action`."""
    return _CURRENT.set(pcactn)


def reset_pca_action(token: Token[ProofInput]) -> None:
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
            pipeline.run(...)      # every guarded tool the run invokes sees this proof
    """
    token = _CURRENT.set(pcactn)
    try:
        yield
    finally:
        _CURRENT.reset(token)
