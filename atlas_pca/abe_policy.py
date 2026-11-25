"""Access structures over attributes: a monotone boolean formula as a threshold tree.

  {"attr": a}                       leaf, the holder must own the key for attribute a
  {"allOf": [...]}                  AND (n-of-n)
  {"anyOf": [...]}                  OR (1-of-n)
  {"threshold": k, "of": [...]}     k-of-n

The normalised form is {"kind": "leaf", "attr": a} or {"kind": "gate", "t": k, "of": [...]}. Negation is not supported (ABE
access structures are monotone).
"""
from __future__ import annotations

from ._fin import fin
import math
import struct
from typing import Any, Dict, List, Optional

MAX_POLICY_NODES = 1024  # bounds work on untrusted input
# Gate nesting along any root-to-leaf path: the ciphertext header is authenticated as canonical JSON (nesting capped at 32), each
# gate costs three JSON levels and the root sits at level 2, so 10 gates is the most that can be authenticated. Enforcing it here
# makes "encryptable" imply "decryptable".
MAX_POLICY_DEPTH = 10


class Fail(Exception):
    """A refusal carrying the reason."""


def leaf(attr: str) -> dict:
    return {"kind": "leaf", "attr": attr}


def gate(t: int, of: list) -> dict:
    return {"kind": "gate", "t": t, "of": of}


def is_leaf(n: dict) -> bool:
    return n.get("kind") == "leaf"


def num(o: Any) -> Optional[float]:
    """The value of a JSON number as JavaScript reads it (a float), or None when not a number."""
    if isinstance(o, bool) or not isinstance(o, (int, float)):
        return None
    try:
        return float(o)
    except OverflowError:
        return math.inf if o > 0 else -math.inf


def pos_int(o: Any) -> bool:
    """JavaScript typeof x === 'number' && Number.isInteger(x) && x > 0."""
    d = num(o)
    return d is not None and fin(d) and d == math.floor(d) and d > 0


def js_int(d: float) -> str:
    """JavaScript String(n) for a positive integral number."""
    if d < 1e21:
        return str(int(d))
    m, e = repr(d).split("e")
    return "%se%s" % (m[:-2] if m.endswith(".0") else m, e)


def has_lone_surrogate(s: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def normalize(policy: Any) -> Dict[str, Any]:
    """{'ok': True, 'tree': ...} or {'ok': False, 'reason': ...}: validate and normalise an access structure; fails closed with a
    reason on any malformed node or oversized tree."""
    try:
        return {"ok": True, "tree": _walk(policy, "policy", 0, [0])}
    except Fail as e:
        return {"ok": False, "reason": str(e)}
    except RecursionError:
        return {"ok": False, "reason": "policy nested too deeply"}


def _walk(p: Any, path: str, gates: int, nodes: List[int]) -> dict:
    nodes[0] += 1
    if nodes[0] > MAX_POLICY_NODES:
        raise Fail("policy too large (> %d nodes)" % MAX_POLICY_NODES)
    if not isinstance(p, dict):
        raise Fail("%s: not an object" % path)
    if "attr" in p:
        a = p["attr"]
        if not isinstance(a, str) or a == "":
            raise Fail("%s: 'attr' must be a non-empty string" % path)
        if has_lone_surrogate(a):
            raise Fail("%s: 'attr' is not well-formed UTF-16" % path)
        if any(k in p for k in ("allOf", "anyOf", "threshold", "of")):
            raise Fail("%s: a leaf must not mix 'attr' with a gate" % path)
        return leaf(a)
    gate_keys = [k for k in ("allOf", "anyOf", "threshold", "of") if k in p and not (k == "of" and "threshold" in p)]
    if len(gate_keys) > 1:
        raise Fail("%s: ambiguous node (%s); a gate must use exactly one of allOf/anyOf/threshold" % (path, ", ".join(gate_keys)))
    if len(gate_keys) == 1 and gates + 1 > MAX_POLICY_DEPTH:
        raise Fail("%s: policy nested deeper than %d gates" % (path, MAX_POLICY_DEPTH))
    if "allOf" in p:
        kids = _children(p["allOf"], "allOf", path, gates, nodes)
        return gate(len(kids), kids)
    if "anyOf" in p:
        return gate(1, _children(p["anyOf"], "anyOf", path, gates, nodes))
    if "threshold" in p:
        t = p["threshold"]
        if not pos_int(t):
            raise Fail("%s: 'threshold' must be a positive integer" % path)
        kids = _children(p.get("of"), "of", path, gates, nodes)
        d = num(t)
        if d > len(kids):
            raise Fail("%s: threshold %s exceeds the number of branches (%d)" % (path, js_int(d), len(kids)))
        return gate(int(d), kids)
    raise Fail("%s: unknown policy node (expected attr/allOf/anyOf/threshold)" % path)


def _children(raw: Any, key: str, path: str, gates: int, nodes: List[int]) -> list:
    if not isinstance(raw, list) or not raw:
        raise Fail("%s: '%s' must be a non-empty array" % (path, key))
    return [_walk(c, "%s.%s[%d]" % (path, key, i), gates + 1, nodes) for i, c in enumerate(raw)]


def of(n: dict) -> list:
    return n["of"]


def t(n: dict) -> int:
    return int(num(n["t"]))


def satisfies(tree: dict, attrs) -> bool:
    """Non-cryptographic prediction: does the attribute set satisfy the tree? (Enforcement is the cryptography.)"""
    if is_leaf(tree):
        return tree["attr"] in attrs
    return sum(1 for c in of(tree) if satisfies(c, attrs)) >= t(tree)


def js_sort(strs) -> List[str]:
    """JavaScript's default sort order: UTF-16 code units."""
    def key(s: str):
        b = s.encode("utf-16-be", "surrogatepass")
        return struct.unpack(">%dH" % (len(b) // 2), b)

    return sorted(strs, key=key)


def leaves(tree: dict) -> List[str]:
    """Leaf attributes in depth-first order (one span-program row each)."""
    if is_leaf(tree):
        return [tree["attr"]]
    return [a for c in of(tree) for a in leaves(c)]


def policy_attributes(tree: dict) -> List[str]:
    """Every attribute the tree names, sorted (UTF-16 code unit order, as the reference sorts)."""
    return js_sort(list(dict.fromkeys(leaves(tree))))
