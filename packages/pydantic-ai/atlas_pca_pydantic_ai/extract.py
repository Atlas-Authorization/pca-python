"""Pull a PCActn out of a Pydantic AI tool call, per the ``PCA-Action`` convention.

A proof travels in one of two places, checked in order:

1. The agent's dependencies, i.e. ``RunContext.deps`` — the resource-server-correct channel. The host
   sets it out-of-band when it starts the run (``agent.run(..., deps=...)``); the model never sees or
   controls it. It is read as:

   * ``deps.pca_action`` — an attribute on any deps object (use :class:`PCADeps`, or add the field to
     your own deps type), holding the base64url string **or** the inline PCActn object, or
   * ``deps["PCA-Action"]`` — when ``deps`` is a plain mapping.

2. The tool-call ``arguments`` under ``"PCA-Action"`` — a fallback for callers that cannot set deps,
   carrying the same base64url string or inline object. These are model-controlled, so the deps channel
   is preferred.

Decoding reuses the strict base64url + strict-JSON profile from :mod:`atlas_pca`, so a malformed proof
is reported as ``"undecodable"`` (fail-closed), never silently parsed leniently.
"""
from typing import Any, Dict, Mapping, Optional, Tuple

from atlas_pca.pca import StrictJsonError, decode_b64u_strict, strict_parse

PCA_KEY = "PCA-Action"

# ``(pcactn, error)`` — ``error`` is ``"absent"`` or ``"undecodable"`` when ``pcactn`` is ``None``.
Extracted = Tuple[Optional[Dict[str, Any]], Optional[str]]

_MISSING = object()


def _as_mapping(obj: object) -> Optional[Mapping[str, Any]]:
    """Normalise a tool-arguments container (a mapping or a pydantic model) to a plain mapping."""
    if obj is None:
        return None
    if isinstance(obj, Mapping):
        return obj
    dump = getattr(obj, "model_dump", None)
    if callable(dump):
        try:
            result = dump(by_alias=True)
        except TypeError:
            result = dump()
        if isinstance(result, Mapping):
            return result
    return None


def _decode_b64u_pcactn(raw: str) -> Extracted:
    decoded = decode_b64u_strict(raw)
    if decoded is None:
        return None, "undecodable"
    try:
        obj = strict_parse(decoded)
    except StrictJsonError:
        return None, "undecodable"
    if not isinstance(obj, dict):
        return None, "undecodable"
    return obj, None


def _coerce(value: object) -> Extracted:
    """Coerce a carried value to a PCActn: a base64url string or an inline object."""
    if isinstance(value, str):
        return _decode_b64u_pcactn(value)
    if isinstance(value, Mapping):
        return dict(value), None
    return None, "undecodable"


def _from_deps(deps: object, key: str) -> Extracted:
    """Read the proof off ``RunContext.deps``: a ``pca_action`` attribute or a ``key`` mapping entry."""
    if deps is None:
        return None, None
    value: object = getattr(deps, "pca_action", _MISSING)
    if value is _MISSING and isinstance(deps, Mapping):
        value = deps.get(key, _MISSING)
    if value is _MISSING or value is None:
        return None, None  # not carried on deps; the arguments channel is tried next
    return _coerce(value)


def extract_pcactn(
    deps: object = None,
    arguments: object = None,
    *,
    key: str = PCA_KEY,
) -> Extracted:
    """Return ``(pcactn, error)`` for a Pydantic AI tool call.

    ``deps``      — the agent's ``RunContext.deps`` (the primary, host-controlled channel).
    ``arguments`` — the tool-call arguments mapping (the model-controlled fallback channel).
    ``key``       — the key the proof travels under (default ``"PCA-Action"``).
    """
    pcactn, err = _from_deps(deps, key)
    if pcactn is not None or err is not None:
        return pcactn, err

    arg_map = _as_mapping(arguments)
    if arg_map is not None and key in arg_map:
        return _coerce(arg_map[key])

    return None, "absent"
