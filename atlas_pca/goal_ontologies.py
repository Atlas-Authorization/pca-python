"""The shipped intent ontologies and the selector catalog of each domain (the TypeScript reference is @atlasauth/pca-goal
`ontologies`). Derived reference data: they read the action definitions, so the port ships the reference output as JSON
(`goal_ontologies.json`, package data) instead of re-deriving it."""
import json
import os
from typing import Any, Dict, List, Optional

__all__ = ["NAMES", "shipped_ontology", "shipped_catalog", "all_ontologies"]

_DATA: Optional[Dict[str, Any]] = None


def _data() -> Dict[str, Any]:
    global _DATA
    if _DATA is None:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "goal_ontologies.json"), "r", encoding="utf-8") as fh:
            _DATA = json.load(fh)
    return _DATA


NAMES: List[str] = ["calendar_travel", "code_repos", "data_access", "email", "payments"]


def shipped_ontology(name: str) -> Optional[Dict[str, Any]]:
    """The intent ontology of a shipped domain (a fresh copy), or None for an unknown name."""
    o = _data()["ontologies"].get(name) if isinstance(name, str) else None
    return None if o is None else json.loads(json.dumps(o))


def shipped_catalog(name: str) -> Optional[Dict[str, Any]]:
    """The selector catalog `{known, verbs}` of a shipped domain (a fresh copy), or None for an unknown name."""
    c = _data()["catalogs"].get(name) if isinstance(name, str) else None
    return None if c is None else json.loads(json.dumps(c))


def all_ontologies() -> Dict[str, Dict[str, Any]]:
    return {n: shipped_ontology(n) for n in NAMES}  # type: ignore[misc]
