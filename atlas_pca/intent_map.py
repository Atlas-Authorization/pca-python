"""Intent Layer v2 rule 19 (V15): the COMMITTED intent map and the Z0 disclosure check `map`.

Mirrors packages/pca/src/intent-map-commit.ts (NORMATIVE; conformance README rule 19): salted, kind-tagged leaves, the
RFC 6962 / 9162 tree with its own node tag, `map_commit = b64u(SHA-256(TAG_COMMIT || u64be(n) || root))`, RFC 9162
§2.1.3.2 audit-path openings, closed and typed leaves, the exact cell of omega (num: a safe integer in its cut cell; cat:
exact > longest prefix > other) and `decide_map_disclosure` (Z0). The builder (`commit_map`, wallet side in the
reference) is ported for tests and hosts. Strict values only: numbers are safe integers (not -0, not a bool), lists are
JSON arrays, keyed reads are own members. Every decide / verify entry point is total.
"""
import hashlib
from typing import Any, Dict, List, Optional

from .pca import (
    _blen, _has_surrogate, _is_safe_int, _js_nonneg_int, b64u, canonical_bytes_strict, decode_b64u_strict,
    params_digest,
)

MAP_TAG_HEADER = "atlas-pca/intent-map/header/v1\x00"
MAP_TAG_CELL = "atlas-pca/intent-map/cell/v1\x00"
MAP_TAG_METRICS = "atlas-pca/intent-map/metrics/v1\x00"
MAP_TAG_LEARNER = "atlas-pca/intent-map/learner/v1\x00"
MAP_TAG_NODE = "atlas-pca/intent-map/node/v1\x00"
MAP_TAG_COMMIT = "atlas-pca/intent-map/commit/v1\x00"
MAP_TAG_SALT = "atlas-pca/intent-map/salt/v1\x00"  # informative: the wallet's per-leaf salt derivation
MAP_FORM_COMMIT = "commit"
MAP_OTHER = "⊥"  # ⊥, the OTHER value of a categorical dimension

MAX_MAP_LEAVES = 1 << 24
MAX_VERB_CELLS = 1 << 20
MAX_MAP_DIMS = 16
MAX_MAP_CUTS = 256
MAX_MAP_VALUES = 256
MAX_MAP_STRING_BYTES = 256
_PPM_ONE = 1_000_000
MAP_METRIC_FIELDS = ("residual_risk_ppm", "burden_ppm", "uncertainty_ppm", "disagreement_ppm", "mean_harm_ppm",
                     "fidelity_est_ppm", "entropy_mbits", "questions", "conflicts")
_TAGS = {"header": MAP_TAG_HEADER, "cell": MAP_TAG_CELL, "metrics": MAP_TAG_METRICS, "learner": MAP_TAG_LEARNER}
_PARAMS = "action.params."
_ABSENT = object()


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _u64be(n: int) -> bytes:
    return int(n).to_bytes(8, "big")


def _u16len(s: str) -> int:
    return sum(2 if ord(c) > 0xFFFF else 1 for c in s)


def _is_str(v: Any, mx: int = MAX_MAP_STRING_BYTES) -> bool:
    """A string without lone surrogates of at most `mx` UTF-8 bytes (may be empty)."""
    return isinstance(v, str) and not _has_surrogate(v) and _blen(v) <= mx


def _closed(o: dict, allowed, required) -> bool:
    return all(k in allowed for k in o) and all(k in o for k in required)


def _is_param_name(name: str) -> bool:
    return 1 <= len(name) <= 64 and all(c.isascii() and (c.isalnum() or c == "_") for c in name)


def _is_dim_path(p: Any) -> bool:
    return p == "action.resource" or (isinstance(p, str) and p.startswith(_PARAMS) and _is_param_name(p[len(_PARAMS):]))


# ---- hashing --------------------------------------------------------------------------------------------------------

def map_leaf_hash(kind: str, salt: bytes, leaf: Any) -> bytes:
    """SHA-256(TAG_kind || salt || strictCanonical(leaf)). Raises on a leaf without a strict canonical form."""
    if len(salt) != 32:
        raise ValueError("map_leaf_hash: the salt is 32 bytes")
    return _sha256(_TAGS[kind].encode("utf-8") + salt + canonical_bytes_strict(leaf))


def map_node_hash(left: bytes, right: bytes) -> bytes:
    return _sha256(MAP_TAG_NODE.encode("utf-8") + left + right)


def map_commit_of(size: int, root: bytes) -> str:
    """map_commit of a tree of `size` leaves with root `root`."""
    return b64u(_sha256(MAP_TAG_COMMIT.encode("utf-8") + _u64be(size) + root))


def map_leaf_salt(secret: bytes, index: int) -> bytes:
    """Informative per-leaf salt derivation (wallet side)."""
    return _sha256(MAP_TAG_SALT.encode("utf-8") + secret + _u64be(index))


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _tree_root(hs: List[bytes]) -> bytes:
    if len(hs) == 1:
        return hs[0]
    k = _split(len(hs))
    return map_node_hash(_tree_root(hs[:k]), _tree_root(hs[k:]))


def _audit_path(hs: List[bytes], idx: int, out: List[bytes]) -> None:
    if len(hs) == 1:
        return
    k = _split(len(hs))
    if idx < k:
        _audit_path(hs[:k], idx, out)
        out.append(_tree_root(hs[k:]))
    else:
        _audit_path(hs[k:], idx - k, out)
        out.append(_tree_root(hs[:k]))


def map_tree_root(hashes: List[bytes]) -> bytes:
    if not hashes:
        raise ValueError("map tree: empty")
    return _tree_root(hashes)


def map_audit_path(hashes: List[bytes], index: int) -> List[str]:
    out: List[bytes] = []
    _audit_path(hashes, index, out)
    return [b64u(h) for h in out]


def map_root_from_path(index: int, size: int, leaf_hash: bytes, path: List[bytes]) -> Optional[bytes]:
    """RFC 9162 §2.1.3.2 inclusion verification with the map node hash: the root the audit path of leaf `index` in a tree
    of `size` leaves recomputes, or None when the path has the wrong length for (index, size). Total."""
    if not (0 <= index < size):
        return None
    fn, sn, r = index, size - 1, leaf_hash
    for p in path:
        if sn == 0:
            return None
        if fn % 2 == 1 or fn == sn:
            r = map_node_hash(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn //= 2
                    sn //= 2
        else:
            r = map_node_hash(r, p)
        fn //= 2
        sn //= 2
    return r if sn == 0 else None


def commit_leaves(leaves: Any) -> str:
    """map_commit of a full leaf list `[{kind, salt, leaf}]` (primitives.intent_map_commit): every leaf hashed with its
    kind's tag and its own salt, the RFC 9162 tree, the size-bound commitment. Raises on a malformed list."""
    if not isinstance(leaves, list) or not leaves:
        raise ValueError("commit_leaves: a non-empty leaf list")
    hashes = []
    for e in leaves:
        if not isinstance(e, dict) or e.get("kind") not in _TAGS:
            raise ValueError("commit_leaves: each entry is {kind, salt, leaf} with a known kind")
        salt = decode_b64u_strict(e.get("salt"), 32)
        if salt is None or "leaf" not in e:
            raise ValueError("commit_leaves: salt must be canonical base64url (32 bytes) and leaf present")
        hashes.append(map_leaf_hash(e["kind"], salt, e["leaf"]))
    return map_commit_of(len(hashes), map_tree_root(hashes))


# ---- leaf shapes (closed and typed) ---------------------------------------------------------------------------------

def map_num_cells(d: dict) -> List[tuple]:
    """The cells of a numeric dimension as inclusive (lo, hi) ranges (empty ranges dropped)."""
    out = []
    cur = d["lo"]
    for c in d["cuts"]:
        if cur <= c - 1:
            out.append((cur, c - 1))
        out.append((c, c))
        cur = c + 1
    if cur <= d["hi"]:
        out.append((cur, d["hi"]))
    return out


def _dim_cells(d: dict) -> int:
    return len(map_num_cells(d)) if d["kind"] == "num" else len(d["values"])


def _dim_error(d: Any, j: int) -> Optional[str]:
    if not isinstance(d, dict):
        return "dims[%d] must be an object" % j
    kind = d.get("kind")
    if kind == "num" and isinstance(kind, str):
        keys = ("kind", "path", "lo", "hi", "cuts")
        if not _closed(d, keys, keys):
            return "dims[%d] must be exactly {kind, path, lo, hi, cuts}" % j
        if not _is_dim_path(d["path"]) or d["path"] == "action.resource":
            return "dims[%d].path must be action.params.<name>" % j
        lo, hi = d["lo"], d["hi"]
        if not _is_safe_int(lo) or not _is_safe_int(hi) or lo > hi:
            return "dims[%d] lo / hi must be safe integers with lo <= hi" % j
        cuts = d["cuts"]
        if not isinstance(cuts, list) or len(cuts) > MAX_MAP_CUTS:
            return "dims[%d].cuts must be an array of at most %d" % (j, MAX_MAP_CUTS)
        prev = None
        for c in cuts:
            if not _is_safe_int(c) or (prev is not None and c <= prev) or c < lo or c > hi:
                return "dims[%d].cuts must be strictly increasing safe integers in [lo, hi]" % j
            prev = c
        return None
    if kind == "cat" and isinstance(kind, str):
        keys = ("kind", "path", "values")
        if not _closed(d, keys, keys):
            return "dims[%d] must be exactly {kind, path, values}" % j
        if not _is_dim_path(d["path"]):
            return "dims[%d].path must be action.resource or action.params.<name>" % j
        vals = d["values"]
        if not isinstance(vals, list) or len(vals) == 0 or len(vals) > MAX_MAP_VALUES:
            return "dims[%d].values must be an array of 1..%d" % (j, MAX_MAP_VALUES)
        seen = set()
        for i, v in enumerate(vals):
            if not isinstance(v, dict) or not _closed(v, ("kind", "value"), ("kind", "value")):
                return "dims[%d].values[%d] must be exactly {kind, value}" % (j, i)
            vk = v["kind"]
            if not (isinstance(vk, str) and vk in ("exact", "prefix", "other")):
                return "dims[%d].values[%d].kind must be exact, prefix or other" % (j, i)
            if not _is_str(v["value"]):
                return "dims[%d].values[%d].value must be a string of at most %d UTF-8 bytes" % (j, i, MAX_MAP_STRING_BYTES)
            if (i != len(vals) - 1 or v["value"] != MAP_OTHER) if vk == "other" else (vk == "prefix" and len(v["value"]) == 0):
                return "dims[%d].values: exactly one other ('%s'), last; prefixes non-empty" % (j, MAP_OTHER)
            key = (vk, v["value"])
            if key in seen:
                return "dims[%d].values must be distinct" % j
            seen.add(key)
        if vals[-1]["kind"] != "other":
            return "dims[%d].values must end with the other value" % j
        return None
    return "dims[%d].kind must be num or cat" % j


def map_header_error(h: Any) -> Optional[str]:
    """Shape of a header leaf (closed, typed; `cells` equals the product of the dimensions' cell counts)."""
    keys = ("verb", "first", "cells", "dims")
    if not isinstance(h, dict) or not _closed(h, keys, keys):
        return "the header leaf must be exactly {verb, first, cells, dims}"
    if not _is_str(h["verb"], 128) or len(h["verb"]) == 0:
        return "header.verb must be a non-empty string of at most 128 UTF-8 bytes"
    if not _js_nonneg_int(h["first"]) or h["first"] >= MAX_MAP_LEAVES:
        return "header.first must be a leaf index"
    if not _is_safe_int(h["cells"]) or h["cells"] < 1 or h["cells"] > MAX_VERB_CELLS:
        return "header.cells must be a safe integer in [1, %d]" % MAX_VERB_CELLS
    dims = h["dims"]
    if not isinstance(dims, list) or len(dims) > MAX_MAP_DIMS:
        return "header.dims must be an array of at most %d" % MAX_MAP_DIMS
    paths = set()
    n = 1
    for j, d in enumerate(dims):
        e = _dim_error(d, j)
        if e:
            return "header." + e
        if d["path"] in paths:
            return "header.dims paths must be distinct"
        paths.add(d["path"])
        n *= _dim_cells(d)
        if n > MAX_VERB_CELLS:
            return "header: too many cells"
    if n != h["cells"]:
        return "header.cells is not the product of the dimensions' cell counts"
    return None


def map_cell_error(c: Any) -> Optional[str]:
    keys = ("verb", "cell", "p_ppm", "in_grant")
    if not isinstance(c, dict) or not _closed(c, keys, keys):
        return "the cell leaf must be exactly {verb, cell, p_ppm, in_grant}"
    if not _is_str(c["verb"], 128) or len(c["verb"]) == 0:
        return "cell.verb must be a non-empty string of at most 128 UTF-8 bytes"
    if not isinstance(c["cell"], list) or len(c["cell"]) > MAX_MAP_DIMS or not all(_js_nonneg_int(x) for x in c["cell"]):
        return "cell.cell must be an array of non-negative safe integers"
    if not _js_nonneg_int(c["p_ppm"]) or c["p_ppm"] > _PPM_ONE:
        return "cell.p_ppm must be a safe integer in [0, 1000000]"
    if not isinstance(c["in_grant"], bool):
        return "cell.in_grant must be a boolean"
    return None


def map_metrics_error(m: Any) -> Optional[str]:
    if not isinstance(m, dict) or not _closed(m, MAP_METRIC_FIELDS + ("log2_vs_mbits",), MAP_METRIC_FIELDS):
        return "the metrics leaf must be exactly {%s, log2_vs_mbits?}" % ", ".join(MAP_METRIC_FIELDS)
    for k in MAP_METRIC_FIELDS + ("log2_vs_mbits",):
        if k == "log2_vs_mbits" and k not in m:
            continue
        if not _js_nonneg_int(m[k]):
            return "metrics.%s must be a non-negative safe integer" % k
    return None


def map_learner_error(lr: Any) -> Optional[str]:
    if not isinstance(lr, dict) or not _closed(lr, ("learner_digest",), ("learner_digest",)):
        return "the learner leaf must be exactly {learner_digest}"
    return None if decode_b64u_strict(lr["learner_digest"], 32) is not None else \
        "learner.learner_digest must be canonical base64url (32 bytes)"


def map_cell_of(header: dict, resource: Any, params: Any) -> dict:
    """Cell of omega under a (well-formed) header: {"cell": [...], "flat": n} or {"error": reason}. `resource` is
    `action.resource`, `params` the plaintext action params (own members). Total for a well-formed header."""
    cell: List[int] = []
    flat = 0
    for d in header["dims"]:
        if d["path"] == "action.resource":
            x = resource
        else:
            x = params.get(d["path"][len(_PARAMS):], _ABSENT) if isinstance(params, dict) else _ABSENT
        i = -1
        if d["kind"] == "num":
            if _is_safe_int(x):
                for k, (lo, hi) in enumerate(map_num_cells(d)):
                    if lo <= x <= hi:
                        i = k
                        break
        elif isinstance(x, str) and not _has_surrogate(x):
            best, best_len = -1, -1
            for k, v in enumerate(d["values"]):
                if v["kind"] == "exact" and v["value"] == x:
                    best = k
                    break
                if v["kind"] == "prefix" and x.startswith(v["value"]) and _u16len(v["value"]) > best_len:
                    best, best_len = k, _u16len(v["value"])
            i = best if best >= 0 else len(d["values"]) - 1
        if i < 0:
            return {"error": "the action's %s lies outside the committed map's dimension" % d["path"]}
        cell.append(i)
        flat = flat * _dim_cells(d) + i
    return {"cell": cell, "flat": flat}


def _entry_shape(e: Any, what: str) -> Optional[str]:
    keys = ("index", "salt", "leaf", "path")
    if not isinstance(e, dict) or not _closed(e, keys, keys):
        return "disclosure.%s must be exactly {index, salt, leaf, path}" % what
    if not _js_nonneg_int(e["index"]):
        return "disclosure.%s.index must be a non-negative safe integer" % what
    if decode_b64u_strict(e["salt"], 32) is None:
        return "disclosure.%s.salt must be canonical base64url (32 bytes)" % what
    p = e["path"]
    if not isinstance(p, list) or len(p) > 64 or not all(decode_b64u_strict(h, 32) is not None for h in p):
        return "disclosure.%s.path must be an array of 32-byte digests" % what
    return None


def map_disclosure_error(d: Any) -> Optional[str]:
    """Shape of a Z0 disclosure (closed, typed). None = well-formed."""
    keys = ("size", "header", "cell", "metrics")
    if not isinstance(d, dict) or not _closed(d, keys, keys):
        return "the disclosure must be exactly {size, header, cell, metrics}"
    if not _is_safe_int(d["size"]) or d["size"] < 4 or d["size"] > MAX_MAP_LEAVES:
        return "disclosure.size must be a safe integer in [4, %d]" % MAX_MAP_LEAVES
    for k in ("header", "cell", "metrics"):
        e = _entry_shape(d[k], k)
        if e:
            return e
    return map_header_error(d["header"]["leaf"]) or map_cell_error(d["cell"]["leaf"]) or map_metrics_error(d["metrics"]["leaf"])


def _opens(kind: str, e: dict, size: int, map_commit: str) -> bool:
    try:
        h = map_leaf_hash(kind, decode_b64u_strict(e["salt"], 32), e["leaf"])
        root = map_root_from_path(e["index"], size, h, [decode_b64u_strict(x, 32) for x in e["path"]])
        return root is not None and map_commit_of(size, root) == map_commit
    except Exception:  # noqa: BLE001
        return False


def decide_map_disclosure(map_commit: Any, action: Any, disclosure: Any, params: Any = _ABSENT,
                          max_residual_risk_ppm: Any = _ABSENT) -> Dict[str, Any]:
    """Z0, the `map` check (rule 19; decideMapDisclosure). First failure wins:
      1. the disclosure is well-formed;
      2. `map_commit` is canonical base64url of 32 bytes;
      3. `params` (ABSENT = {}; present it must be an object) hash to `action.params_digest`;
      4. header.verb == action.verb, header.index < header.first, header.first + header.cells <= size - 2;
      5. the header, cell and metrics leaves each open map_commit (own salt, own tag, audit path, size);
      6. the cell of omega under the header: cell.index == header.first + flat, cell.verb == verb, cell.cell == indices;
      7. cell.in_grant is true;
      8. metrics.index == size - 2 and, when epsilon is given, metrics.residual_risk_ppm <= epsilon.
    Returns {"ok": True, "cell", "p_ppm", "residual_risk_ppm"} or {"ok": False, "reason"}. Never raises."""
    try:
        de = map_disclosure_error(disclosure)
        if de:
            return {"ok": False, "reason": "map disclosure malformed: %s" % de}
        if decode_b64u_strict(map_commit, 32) is None:
            return {"ok": False, "reason": "the PCActn carries no map commitment"}
        if params is not _ABSENT and not isinstance(params, dict):
            return {"ok": False, "reason": "params must be an object"}
        if not isinstance(action, dict):
            raise TypeError("the action must be an object")
        a = action
        if params_digest({} if params is _ABSENT else params) != a.get("params_digest", _ABSENT):
            return {"ok": False, "reason": "the params do not hash to action.params_digest"}
        d = disclosure
        h = d["header"]["leaf"]
        if not (isinstance(a.get("verb"), str) and h["verb"] == a["verb"]):
            return {"ok": False, "reason": "the disclosed header is not the action's verb"}
        if not d["header"]["index"] < h["first"] or not h["first"] + h["cells"] <= d["size"] - 2:
            return {"ok": False, "reason": "the disclosed header does not fit the committed layout"}
        for kind in ("header", "cell", "metrics"):
            if not _opens(kind, d[kind], d["size"], map_commit):
                return {"ok": False, "reason": "the %s leaf does not open the map commitment" % kind}
        w = map_cell_of(h, a.get("resource", _ABSENT), {} if params is _ABSENT else params)
        if "error" in w:
            return {"ok": False, "reason": w["error"]}
        c = d["cell"]["leaf"]
        if d["cell"]["index"] != h["first"] + w["flat"] or c["verb"] != h["verb"] or len(c["cell"]) != len(w["cell"]) \
                or any(x != y for x, y in zip(c["cell"], w["cell"])):
            return {"ok": False, "reason": "the disclosed cell is not the action's cell"}
        if c["in_grant"] is not True:
            return {"ok": False, "reason": "the action's cell is outside the committed grant"}
        if d["metrics"]["index"] != d["size"] - 2:
            return {"ok": False, "reason": "the disclosed metrics leaf is not at its committed position"}
        rr = d["metrics"]["leaf"]["residual_risk_ppm"]
        if max_residual_risk_ppm is not _ABSENT and not rr <= max_residual_risk_ppm:
            return {"ok": False, "reason": "the committed residual risk %d ppm exceeds ε = %s" % (rr, max_residual_risk_ppm)}
        return {"ok": True, "cell": list(c["cell"]), "p_ppm": c["p_ppm"], "residual_risk_ppm": rr}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": "map error (fail closed): %s" % e}


def decide_map_primitive(inp: Any) -> Dict[str, Any]:
    """primitives.intent_map: {map_commit, action, params?, disclosure, max_residual_risk_ppm?} -> the Z0 decision."""
    if not isinstance(inp, dict):
        return {"ok": False, "reason": "input must be an object"}
    kw = {}
    if "params" in inp:
        kw["params"] = inp["params"]
    if "max_residual_risk_ppm" in inp:
        kw["max_residual_risk_ppm"] = inp["max_residual_risk_ppm"]
    return decide_map_disclosure(inp.get("map_commit"), inp.get("action"), inp.get("disclosure"), **kw)


# ---- builder (wallet side in the reference; for hosts and tests) ------------------------------------------------------

def commit_map(headers: List[dict], cells: Dict[str, List[dict]], metrics: dict, learner_digest: str,
               secret: bytes) -> Dict[str, Any]:
    """Build the committed form (rule 19 leaf order) with per-leaf salts from `secret` (32 bytes). Returns
    {"map_commit", "size", "leaves": [{kind, leaf, salt}], "disclose": fn(verb, resource, params) -> disclosure}.
    Raises on a malformed input (the same shapes the verifier checks)."""
    if len(secret) != 32:
        raise ValueError("commit_map: the secret is 32 bytes")
    heads = sorted(headers, key=lambda h: h["verb"].encode("utf-8"))
    for i in range(1, len(heads)):
        if heads[i]["verb"] == heads[i - 1]["verb"]:
            raise ValueError("commit_map: duplicate verb")
    nxt = len(heads)
    full = []
    for h in heads:
        n = 1
        for d in h["dims"]:
            n *= _dim_cells(d)
        full.append({"verb": h["verb"], "first": nxt, "cells": n, "dims": h["dims"]})
        nxt += n
    leaves = [("header", h) for h in full]
    for h in full:
        cs = cells.get(h["verb"])
        if not isinstance(cs, list) or len(cs) != h["cells"]:
            raise ValueError("commit_map: verb %s needs %d cell leaves" % (h["verb"], h["cells"]))
        for c in cs:
            leaves.append(("cell", {"verb": h["verb"], "cell": c["cell"], "p_ppm": c["p_ppm"], "in_grant": c["in_grant"]}))
    leaves += [("metrics", metrics), ("learner", {"learner_digest": learner_digest})]
    check = {"header": map_header_error, "cell": map_cell_error, "metrics": map_metrics_error, "learner": map_learner_error}
    for kind, leaf in leaves:
        e = check[kind](leaf)
        if e:
            raise ValueError("commit_map: " + e)
    size = len(leaves)
    if size < 4 or size > MAX_MAP_LEAVES:
        raise ValueError("commit_map: the map has too few or too many leaves")
    salts = [map_leaf_salt(secret, i) for i in range(size)]
    hashes = [map_leaf_hash(k, salts[i], leaf) for i, (k, leaf) in enumerate(leaves)]
    root = map_tree_root(hashes)

    def entry(i: int) -> dict:
        return {"index": i, "salt": b64u(salts[i]), "leaf": leaves[i][1], "path": map_audit_path(hashes, i)}

    def disclose(verb: str, resource: Any, params: dict) -> dict:
        hi = next((i for i, h in enumerate(full) if h["verb"] == verb), -1)
        if hi < 0:
            raise ValueError("commit_map.disclose: verb %s is not in the map" % verb)
        w = map_cell_of(full[hi], resource, params)
        if "error" in w:
            raise ValueError("commit_map.disclose: " + w["error"])
        return {"size": size, "header": entry(hi), "cell": entry(full[hi]["first"] + w["flat"]), "metrics": entry(size - 2)}

    return {"map_commit": map_commit_of(size, root), "size": size,
            "leaves": [{"kind": k, "leaf": leaf, "salt": b64u(salts[i])} for i, (k, leaf) in enumerate(leaves)],
            "disclose": disclose}

