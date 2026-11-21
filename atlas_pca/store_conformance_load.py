"""Load a store adapter from a Python file (``./my_adapter.py``), an importable module name, or a built-in reference (``builtin:<name>``)
(port of the TypeScript reference, @atlasauth/pca-store-conformance, load.ts). The module may expose the adapter (or a factory
``(options) -> adapter``) as ``default``, ``adapter`` or ``create_adapter``."""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import os
from typing import Any, Dict, Optional

from .store_conformance_runner import REFERENCE_ADAPTERS


def _adapter_like(x: Any) -> bool:
    return callable(x) or (x is not None and callable(getattr(x, "open", None)))


def pick_export(mod: Any) -> Any:
    """The first adapter-like export among ``default``, ``adapter`` and ``create_adapter`` (None when there is none)."""
    for n in ("default", "adapter", "create_adapter"):
        v = getattr(mod, n, None)
        if _adapter_like(v):
            return v
    return None


def _import(spec: str) -> Any:
    if spec.endswith(".py") or os.sep in spec or os.path.exists(spec):
        path = os.path.abspath(spec)
        name = "_pcasc_adapter_" + hashlib.sha256(path.encode()).hexdigest()[:12]
        s = importlib.util.spec_from_file_location(name, path)
        if s is None or s.loader is None:
            raise ImportError("cannot load %s" % spec)
        m = importlib.util.module_from_spec(s)
        s.loader.exec_module(m)
        return m
    return importlib.import_module(spec)


def load_adapter(spec: str, options: Optional[Dict[str, str]] = None) -> Any:
    options = options or {}
    if spec.startswith("builtin:"):
        name = spec[len("builtin:"):]
        if name not in REFERENCE_ADAPTERS:
            raise ValueError("unknown built-in adapter '%s' (known: %s)" % (name, ", ".join(REFERENCE_ADAPTERS)))
        exported: Any = REFERENCE_ADAPTERS[name]
    else:
        exported = pick_export(_import(spec))
    a = exported(options) if callable(exported) and not callable(getattr(exported, "open", None)) else exported
    if a is None or not callable(getattr(a, "open", None)) or not isinstance(getattr(a, "name", None), str):
        raise TypeError("%s: does not export a store adapter (an object with a string 'name' and an 'open()' method, or a factory returning one)" % spec)
    return a


__all__ = ["load_adapter", "pick_export"]
