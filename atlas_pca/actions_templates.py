"""Starter packs a platform can begin from (native port of templates.ts of the TypeScript reference @atlasauth/pca-actions): typical actions of
five business types in the authoring YAML form, with custom traits and business rules. Every action is an authored draft: a template never
confirms anything. The data is generated from the reference (actions_templates_data.py); the namespace is substituted into it. The YAML is
returned as text (the Python SDK does not parse YAML natively: parse it and pass the value to actions_author.load_actions_value)."""
import copy
import re
from typing import Any, List, Optional

from .actions import ActionKitError
from .actions_templates_data import MARKER, TEMPLATES

_NS_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")


def check_ns(ns: Any) -> str:
    """The namespace is interpolated into YAML and trait ids: only a plain lowercase identifier, never the reserved `pca`."""
    if not isinstance(ns, str) or _NS_RE.fullmatch(ns) is None:
        raise ActionKitError("bad_ns", "ns must be a lowercase identifier (a-z, 0-9, _; up to 32 characters)")
    if ns == "pca":
        raise ActionKitError("bad_ns", "the namespace 'pca' is reserved for core traits")
    return ns


def _sub(x: Any, ns: str) -> Any:
    if isinstance(x, str):
        return x.replace(MARKER, ns)
    if isinstance(x, list):
        return [_sub(v, ns) for v in x]
    if isinstance(x, dict):
        return {k: _sub(v, ns) for k, v in x.items()}
    return x


class StarterTemplate:
    def __init__(self, raw: dict):
        self.id: str = raw["id"]
        self.title: str = raw["title"]
        self.description: str = raw["description"]
        self.ns: str = raw["ns"]
        self._traits = raw["traits"]
        self._yaml = raw["yaml"]

    def traits(self, ns: str) -> List[dict]:
        """The pack's custom traits under namespace `ns` (ids `<ns>.<name>`)."""
        return _sub(copy.deepcopy(self._traits), check_ns(ns))

    def yaml(self, ns: str) -> str:
        """The authoring YAML under namespace `ns`, with `rules:` blocks and their examples."""
        return self._yaml.replace(MARKER, check_ns(ns))


STARTER_TEMPLATES: List[StarterTemplate] = [StarterTemplate(t) for t in TEMPLATES]


def starter_template(id: str) -> Optional[StarterTemplate]:
    return next((t for t in STARTER_TEMPLATES if t.id == id), None)
