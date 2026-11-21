"""The connector action catalog: resolves a ``permissions`` shorthand (``{"stripe": ["refund"]}``) into the policy primitives a grant is
compiled from: a verb, a resource matcher, a reversibility class, a blast-radius preset and, for a money-moving action, the params field
that carries the amount.

This is data, not enforcement: nothing here authorizes anything. Specs are dicts with the reference member names (``connector``,
``action``, ``verb``, ``reversibility``, ``blastRadius``, ``amountField``, ``resource``, ``description``, ``aliases``, ``traits``). An
unknown verb resolves fail-closed (irreversible, maximum blast radius), and an extension may only make an existing entry more cautious."""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Sequence

from .facade import _JS_WS, BUILTIN_ACTIONS
from .pca import REVERSIBILITY_ORDER, hash_canonical
from .predicates import _js_string as js_string

__all__ = ["BLAST", "BUILTIN_ACTIONS", "Catalog", "DEFAULT_CATALOG", "assert_catalog_pinned", "build_catalog", "catalog_digest",
           "define_action", "extend_catalog", "resolve_action", "uncatalogued_spec"]

#: Blast-radius presets by shape of action: conservative, overridable.
BLAST = {"read": 0.05, "reversibleWrite": 0.2, "rateLimitedWrite": 0.5, "irreversibleWrite": 0.8, "moneyMovement": 0.9}

_BAD_CONNECTOR = re.compile("[" + re.escape(_JS_WS) + ".]")  # the reference's /[\s.]/ (ECMAScript white space)
_MISSING: Any = object()


def _member(s: Any, k: str) -> Any:
    return s.get(k, _MISSING) if isinstance(s, dict) else _MISSING


def define_action(s: Any) -> Dict[str, Any]:
    """Validate one action spec and return it with its ``verb`` (default ``connector + "." + action``; other members survive).
    Raises ValueError on a bad shape."""
    if s is None:
        raise ValueError("defineAction: the spec is null")
    connector, action = _member(s, "connector"), _member(s, "action")
    if not isinstance(connector, str) or not isinstance(action, str) or not connector or not action:
        raise ValueError("defineAction: connector and action are required")
    if _BAD_CONNECTOR.search(connector):
        raise ValueError("defineAction: connector must not contain whitespace or a dot")
    amount = _member(s, "amountField")
    if amount is not _MISSING and (not isinstance(amount, str) or len(amount) == 0):
        raise ValueError("defineAction: amountField must be a non-empty string")
    rev = _member(s, "reversibility")
    if not isinstance(rev, str) or rev not in REVERSIBILITY_ORDER:
        raise ValueError("defineAction: bad reversibility '%s'" % ("undefined" if rev is _MISSING else js_string(rev)))
    blast = _member(s, "blastRadius")
    if isinstance(blast, bool) or not isinstance(blast, (int, float)) or not 0 <= blast <= 1:  # a NaN fails both comparisons
        raise ValueError("defineAction: blastRadius must be in [0,1]")
    out = dict(s)
    if out.get("verb") is None:
        out["verb"] = "%s.%s" % (connector, action)
    return out


class Catalog:
    """An immutable lookup over action specs, keyed by verb. A later spec with the same verb replaces the earlier one in place, so
    ``all()`` and ``for_connector()`` keep the order of first appearance."""

    def __init__(self, actions: Optional[Sequence[Any]] = None):
        self._by_verb: Dict[Any, Any] = {}
        for a in BUILTIN_ACTIONS if actions is None else actions:
            self._by_verb[a.get("verb") if isinstance(a, dict) else None] = a

    def get(self, verb: Any) -> Optional[Dict[str, Any]]:
        """The spec of a verb (``connector.action``), or None."""
        try:
            return self._by_verb.get(verb)
        except TypeError:  # an unhashable key names no verb
            return None

    def for_connector(self, connector: Any) -> List[Dict[str, Any]]:
        """Every action of a connector namespace."""
        return [a for a in self._by_verb.values() if isinstance(a, dict) and isinstance(connector, str) and a.get("connector") == connector]

    def all(self) -> List[Dict[str, Any]]:
        """Every action in the catalog."""
        return list(self._by_verb.values())

    def resolve(self, connector: Any, action: Any) -> Optional[Dict[str, Any]]:
        """``connector`` + ``action`` as a human or a model writes them: the exact verb, else an alias of exactly one action of that
        connector. Absent or ambiguous: None (never a guess)."""
        exact = self._by_verb.get("%s.%s" % (js_string(connector), js_string(action)))
        if exact:
            return exact
        hits = [a for a in self.for_connector(connector) if isinstance(a.get("aliases"), list) and isinstance(action, str) and action in a["aliases"]]
        return hits[0] if len(hits) == 1 else None


def build_catalog(actions: Optional[Sequence[Any]] = None) -> Catalog:
    """A catalog over ``actions`` (default: the built-in actions). The specs are taken as given; validate them with ``define_action``."""
    return Catalog(actions)


#: The default catalog over the built-in actions.
DEFAULT_CATALOG = build_catalog()


def uncatalogued_spec(verb: str) -> Dict[str, Any]:
    """What a verb is treated as when the catalog does not know it: irreversible, maximum blast radius."""
    parts = verb.split(".")
    return {"connector": parts[0], "action": ".".join(parts[1:]) or verb, "verb": verb, "reversibility": "irreversible", "blastRadius": 1,
            "description": "(uncatalogued) %s" % verb}


def resolve_action(catalog: Catalog, verb: str) -> Dict[str, Any]:
    """Resolve a verb, failing closed: ``{"spec", "catalogued"}``; an unknown verb comes back as ``uncatalogued_spec`` with
    ``catalogued`` False."""
    spec = catalog.get(verb)
    return {"spec": spec, "catalogued": True} if spec else {"spec": uncatalogued_spec(verb), "catalogued": False}


def _utf16(s: Any) -> bytes:
    return s.encode("utf-16-be", "surrogatepass") if isinstance(s, str) else b""


def catalog_digest(catalog: Catalog) -> str:
    """A digest of the whole catalog (SHA-256 over the canonical JSON of the specs sorted by verb, in UTF-16 code unit order as the
    reference sorts). Pin it: a deployment can refuse to start when the catalog it reviewed has since changed."""
    return hash_canonical(sorted(catalog.all(), key=lambda a: _utf16(a.get("verb") if isinstance(a, dict) else None)))


def assert_catalog_pinned(catalog: Catalog, expected: str) -> None:
    """Raises ValueError unless ``catalog`` hashes to ``expected``."""
    if not isinstance(expected, str) or catalog_digest(catalog) != expected:
        raise ValueError("catalog does not match the pinned digest")


def _less(a: Any, b: Any) -> bool:
    def num(v: Any) -> bool:
        return isinstance(v, (int, float)) and not isinstance(v, bool) and not (isinstance(v, float) and math.isnan(v))
    return num(a) and num(b) and a < b


def extend_catalog(base: Catalog, extra: Sequence[Dict[str, Any]]) -> Catalog:
    """``base`` plus ``extra``. An extra action may not replace an existing verb with a less cautious one (a lower reversibility class or
    a lower blast radius): ValueError."""
    def sev(c: Any) -> int:
        return REVERSIBILITY_ORDER.index(c) if isinstance(c, str) and c in REVERSIBILITY_ORDER else -1
    for e in extra:
        old = base.get(e["verb"])
        if old and (sev(e.get("reversibility")) < sev(old.get("reversibility")) or _less(e.get("blastRadius"), old.get("blastRadius"))):
            raise ValueError("extendCatalog: '%s' would be less cautious than the existing entry" % e["verb"])
    return build_catalog(list(base.all()) + list(extra))
