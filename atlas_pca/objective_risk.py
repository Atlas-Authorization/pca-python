"""The objective risk functional: every input of the heuristic r is a pure function of COMMITTED facts and of the CANONICAL action, never of
what the agent asserts. Canonical action, a committed registry of verified inverses (reversibility), a committed resource graph (blast radius),
native and BYO embedders, goal commitment and distance, split-conformal calibration, harm currency, the composition (:func:`objective_risk`)
and the dispute-game oracle. A port of the reference ``objective-risk`` module: digests are the LENIENT canonical hash (any finite double, printed
as ECMAScript prints it), so they are server-only and never feed a protocol digest. Everything fails CLOSED (r = 1, ``valid`` False).

Data is dicts and lists in the reference's member names; the registry, graph and embedder are objects."""
from __future__ import annotations

from ._fin import fin
import functools
import hashlib
import math
import unicodedata
from typing import Any, Callable, Dict, List, Optional

from .actions_import_common import _lenient as canonicalize_lenient
from .actions_import_common import hash_canonical_lenient
from .attest_common import js_trim
from .intent_v2 import compare_utf8
from .intent_wb import _js_str
from .risk import _js_num, risk_score

__all__ = ["METRIC", "DEFAULT_EPSILON", "NATIVE_SCHEME", "DEFAULT_MAX_PARAM_LEAVES", "DEFAULT_NATIVE_CONFIG", "canonical_action",
           "canonical_action_json", "canonical_action_digest", "InMemoryInverseRegistry", "reversibility", "ResourceGraph", "blast_radius",
           "Embedder", "EmbeddingError", "validate_vector", "native_hash_embedder", "byo_model_id", "byo_embedder", "conformance_check",
           "commit_goal", "verify_goal_commitment", "vector_distance", "committed_distance_checked", "committed_distance", "calibrate",
           "conformal_threshold", "calibration_digest", "harm_report", "objective_risk", "objective_risk_oracle"]

METRIC = "half-chord-v1"
DEFAULT_EPSILON = 1 / 4096
NATIVE_SCHEME = "pca-native-hash-ngram-v1"
DEFAULT_MAX_PARAM_LEAVES = 256
DEFAULT_NATIVE_CONFIG: Dict[str, Any] = {"dims": 256, "ngramMin": 2, "ngramMax": 4, "seed": "pca-native-v1",
                                         "fieldWeights": {"verb": 4, "resource": 2, "param": 1}}
_MAX_SAFE = 9007199254740991
_UTF8 = functools.cmp_to_key(compare_utf8)


class EmbeddingError(Exception):
    """An embedding or vector that breaks the determinism contract."""


def _is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _fin(x: Any) -> bool:
    return _is_num(x) and fin(x)


def _safe_int(x: Any) -> bool:
    return _fin(x) and x == math.floor(x) and abs(x) <= _MAX_SAFE


def _clamp01(x: Any) -> Any:
    return (0 if x < 0 else 1 if x > 1 else x) if _fin(x) else 1


def _u16(s: Any) -> bytes:
    """UTF-16 code-unit order key (the reference's string ``<``)."""
    return s.encode("utf-16-be", "surrogatepass")


def _sorted_u16(items: Any) -> List[Any]:
    return sorted(items, key=_u16)


def _utf8(s: str) -> bytes:
    """TextEncoder: a lone surrogate is U+FFFD."""
    try:
        return s.encode("utf-8")
    except UnicodeEncodeError:
        return s.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")


def _js_min(a: float, b: float) -> float:
    return math.nan if a != a or b != b else min(a, b)


def _js_max(a: float, b: float) -> float:
    return math.nan if a != a or b != b else max(a, b)


def _js_ceil(x: float) -> float:
    return x if not fin(x) else float(math.ceil(x))


def _div(a: float, b: float) -> float:
    if b == 0:
        return math.nan if a == 0 or a != a else math.copysign(math.inf, a) * math.copysign(1, b)
    return a / b


def _get(o: Any, k: str) -> Any:
    """``o.k``: a null object throws (as the reference), a non-object has no members."""
    if o is None:
        raise TypeError("Cannot read properties of null (reading '%s')" % k)
    return o.get(k) if isinstance(o, dict) else None


# ---- canonical action ----

def _norm_value(v: Any) -> Any:
    if isinstance(v, str):
        return unicodedata.normalize("NFC", v)
    if isinstance(v, list):
        return [_norm_value(x) for x in v]
    if isinstance(v, dict):
        out: Dict[str, Any] = {}
        for k, x in v.items():
            nk = unicodedata.normalize("NFC", k)
            if nk in out:
                raise TypeError("canonicalAction: duplicate key after NFC normalization")
            out[nk] = _norm_value(x)
        return out
    return v


def canonical_action(a: Any) -> Dict[str, Any]:
    """Verb trimmed and lower-cased, strings and keys NFC, params validated by the lenient canonicalizer; re-encodings that do not change the
    action collapse to one form. Raises TypeError on anything without a stable encoding."""
    verb_in, res_in = _get(a, "verb") if a is not None else None, _get(a, "resource") if a is not None else None
    if not isinstance(verb_in, str) or not isinstance(res_in, str):
        raise TypeError("canonicalAction: verb/resource must be strings")
    verb = js_trim(unicodedata.normalize("NFC", verb_in)).lower()
    resource = js_trim(unicodedata.normalize("NFC", res_in))
    if not verb or not resource:
        raise TypeError("canonicalAction: empty verb/resource")
    raw = a.get("params")
    params = _norm_value({} if raw is None else raw)
    if not isinstance(params, dict):
        raise TypeError("canonicalAction: params must be an object")
    c = {"verb": verb, "resource": resource, "params": params}
    canonicalize_lenient(c)  # validate
    return c


def canonical_action_json(c: Any) -> str:
    return canonicalize_lenient(c)


def canonical_action_digest(c: Any) -> str:
    return hash_canonical_lenient(c)


# ---- 1. reversibility ----

class InMemoryInverseRegistry:
    """A committed registry of verified inverses; its digest covers all contents and the trusted-verifier set."""

    def __init__(self, trusted_verifiers: Any = ()) -> None:
        self._m: Dict[Any, dict] = {}
        self._trusted = _sorted_u16(set(trusted_verifiers))

    def register(self, verb: Any, e: dict) -> "InMemoryInverseRegistry":
        c = dict(e)
        if e.get("verification"):
            c["verification"] = dict(e["verification"])
        self._m[verb] = c
        return self

    def lookup(self, verb: Any) -> Optional[dict]:
        e = self._m.get(verb)
        return dict(e) if e is not None else None

    def trusted_verifiers(self) -> List[str]:
        return self._trusted

    def digest(self) -> str:
        def row(verb: Any, e: dict) -> dict:
            for k in ("inverseKind", "fidelity"):
                if k not in e:
                    raise TypeError("canonicalize: undefined member %s" % k)
            ver = e.get("verification")
            return {"verb": verb, "inverseKind": e["inverseKind"], "fidelity": e["fidelity"], "verification": None if ver is None else ver}
        entries = [row(v, e) for v, e in sorted(self._m.items(), key=lambda kv: _u16(kv[0]))]
        return hash_canonical_lenient({"v": 1, "trusted": self._trusted, "entries": entries})


def reversibility(action: dict, registry: Any, authorized_kinds: Any) -> Dict[str, Any]:
    """Reversible iff the registry holds an inverse verified by a TRUSTED verifier AND the inverse verb is authorized by the capability;
    anything else is irreversible. ``value``: 1 reversible, 0.5 compensable, 0 irreversible."""
    e = registry.lookup(action["verb"])
    ver = e.get("verification") if e else None
    trusted = isinstance(ver, dict) and ver.get("verifierId") in registry.trusted_verifiers()
    if not e or not trusted or e.get("inverseKind") not in set(authorized_kinds):
        return {"class": "irreversible", "value": 0}
    if e.get("fidelity") == "exact":
        return {"class": "reversible", "value": 1, "inverseKind": e["inverseKind"]}
    return {"class": "compensable", "value": 0.5, "inverseKind": e["inverseKind"]}


# ---- 2. blast radius ----

class ResourceGraph:
    """Adjacency model with a content digest the grant commits."""

    def __init__(self) -> None:
        self._nodes: Dict[Any, dict] = {}
        self._out: Dict[Any, List[dict]] = {}

    def add_node(self, n: dict) -> "ResourceGraph":
        self._nodes[n["id"]] = n
        self._out.setdefault(n["id"], [])
        return self

    def add_edge(self, e: dict) -> "ResourceGraph":
        if e["from"] not in self._nodes or e["to"] not in self._nodes:
            raise ValueError("edge endpoints must exist")
        self._out[e["from"]].append(e)
        return self

    @property
    def size(self) -> int:
        return len(self._nodes)

    def node(self, i: Any) -> Optional[dict]:
        return self._nodes.get(i) if isinstance(i, str) else None

    def reachable(self, start: Any, scope: Optional[dict] = None) -> List[Any]:
        """BFS reachable set (including ``start``), edge-kind and depth restricted, sorted."""
        if not isinstance(start, str) or start not in self._nodes:
            return []
        kinds = set(scope["edgeKinds"]) if scope and scope.get("edgeKinds") is not None else None
        md = scope.get("maxDepth") if scope else None
        max_depth = math.inf if md is None else _js_num(md)
        seen = {start}
        frontier = [start]
        d = 0
        while d < max_depth and frontier:
            nxt = []
            for u in frontier:
                for e in self._out.get(u, []):
                    if (kinds is None or e["kind"] in kinds) and e["to"] not in seen:
                        seen.add(e["to"])
                        nxt.append(e["to"])
            frontier = nxt
            d += 1
        return _sorted_u16(seen)

    def digest(self) -> str:
        n = sorted(({"id": x["id"], "harm": x["harm"] if x.get("harm") is not None else {}} for x in self._nodes.values()), key=lambda x: _u16(x["id"]))
        e = sorted(({"from": x["from"], "to": x["to"], "kind": x["kind"]} for es in self._out.values() for x in es),
                   key=lambda x: _u16("%s\u0000%s\u0000%s" % (x["from"], x["to"], x["kind"])))
        return hash_canonical_lenient({"v": 1, "n": n, "e": e})


def blast_radius(action: dict, graph: ResourceGraph, scope: Optional[dict] = None) -> Dict[str, Any]:
    """{count, reachable, normalized, harm}: count / |graph| in [0, 1]; an unknown resource or empty graph is 1 (fail closed); harm sums only
    finite values > 0 per dimension."""
    reachable = graph.reachable(action["resource"], scope)
    if not reachable or graph.size == 0:
        return {"count": 0, "reachable": reachable, "normalized": 1, "harm": {}}
    harm: Dict[str, Any] = {}
    for i in reachable:
        h = (graph.node(i) or {}).get("harm")
        for d, v in (h if isinstance(h, dict) else {}).items():
            if _fin(v) and v > 0:
                harm[d] = harm.get(d, 0) + v
    return {"count": len(reachable), "reachable": reachable, "normalized": len(reachable) / graph.size, "harm": harm}


# ---- 3. committed embeddings ----

class Embedder:
    """Maps the CANONICAL action to an integer vector (never agent-supplied features). ``model_id`` is a hash of ``config``."""

    def __init__(self, model_id: str, config: Any, dims: Any, embed: Callable[[dict], Any]) -> None:
        self.model_id, self.config, self.dims, self.embed = model_id, config, dims, embed


def validate_vector(v: Any, dims: Any) -> List[int]:
    """Exactly ``dims`` safe integers, each within the range that keeps dot products of two such vectors exact in a double; -0 becomes 0."""
    if not isinstance(v, list) or len(v) != dims:
        raise EmbeddingError("vector must have exactly %s components" % _js_str(dims))
    lim = math.floor(math.sqrt(_MAX_SAFE / (2 * max(1, dims))))
    for x in v:
        if not _safe_int(x):
            raise EmbeddingError("vector components must be safe integers")
        if abs(x) > lim:
            raise EmbeddingError("vector component out of range")
    return [int(x) for x in v]


def _ok_int(x: Any, lo: Any, hi: Any) -> bool:
    return _safe_int(x) and lo <= x <= hi


def _validate_native_config(c: dict) -> None:
    if not _ok_int(c.get("dims"), 8, 65536):
        raise ValueError("native config: dims must be an integer in [8, 65536]")
    if not _ok_int(c.get("ngramMin"), 1, 8) or not _ok_int(c.get("ngramMax"), c["ngramMin"], 8):
        raise ValueError("native config: need 1 <= ngramMin <= ngramMax <= 8")
    if not isinstance(c.get("seed"), str) or not c["seed"]:
        raise ValueError("native config: seed required")
    fw = c["fieldWeights"]
    for k in ("verb", "resource", "param"):
        if not _ok_int(fw.get(k), 0, 1000):
            raise ValueError("native config: fieldWeights.%s must be an integer in [0, 1000]" % k)
    if "maxParamLeaves" in c and not _ok_int(c["maxParamLeaves"], 1, 1_000_000):
        raise ValueError("native config: maxParamLeaves must be an integer in [1, 1000000]")
    if "paramMode" in c and c["paramMode"] not in ("leaves", "digest"):
        raise ValueError("native config: paramMode must be 'leaves' or 'digest'")


def _param_leaves(v: Any, path: str, out: List[str]) -> None:
    if isinstance(v, list):
        for i, x in enumerate(v):
            _param_leaves(x, "%s[%d]" % (path, i), out)
    elif isinstance(v, dict):
        for k in sorted(v, key=_UTF8):
            _param_leaves(v[k], "%s.%s" % (path, k) if path else k, out)
    else:
        out.append("%s=%s" % (path, canonicalize_lenient(v)))


def _is_word_char(c: str) -> bool:
    return unicodedata.category(c)[0] in ("L", "N")


def _text_features(prefix: str, text: str, nmin: int, nmax: int) -> List[str]:
    out: List[str] = []
    cps = list("\u0002%s\u0003" % text)  # code points, with boundary markers
    for n in range(nmin, nmax + 1):
        for i in range(0, len(cps) - n + 1):
            out.append("%sc%d:%s" % (prefix, n, "".join(cps[i:i + n])))
    word: List[str] = []
    for c in text + "\u0000":  # a sentinel that is not a word character flushes the last run
        if _is_word_char(c):
            word.append(c)
        elif word:
            out.append("%sw:%s" % (prefix, "".join(word).lower()))
            word = []
    return out


_UNSET = object()


def native_hash_embedder(config: Any = _UNSET) -> Embedder:
    """Native embedder: code-point n-grams and word tokens of the verb, the resource and each flattened param leaf, each hashed as
    SHA-256(seed 0x1F feature): bucket = big-endian u32 of the first four bytes mod dims, sign = low bit of byte 4, accumulating
    +-fieldWeight. Only SHA-256, UTF-8, integer arithmetic and NFC / code-point iteration are needed."""
    config = DEFAULT_NATIVE_CONFIG if config is _UNSET else config
    _validate_native_config(config)
    cfg = dict(config, fieldWeights=dict(config["fieldWeights"]))
    committed = dict({"scheme": NATIVE_SCHEME}, **cfg)
    model_id = "native:" + hash_canonical_lenient(committed)
    prefix = _utf8(cfg["seed"] + "\u001f")
    dims, fw = cfg["dims"], cfg["fieldWeights"]

    def embed(a: dict) -> List[int]:
        v = [0] * dims

        def add(feat: str, w: int) -> None:
            if w == 0:
                return
            h = hashlib.sha256(prefix + _utf8(feat)).digest()
            b = int.from_bytes(h[:4], "big") % dims
            v[b] += w if (h[4] & 1) == 0 else -w

        for f in _text_features("v:", a["verb"], cfg["ngramMin"], cfg["ngramMax"]):
            add(f, fw["verb"])
        for f in _text_features("r:", a["resource"], cfg["ngramMin"], cfg["ngramMax"]):
            add(f, fw["resource"])
        leaves: List[str] = []
        _param_leaves(a["params"], "", leaves)
        cap = cfg.get("maxParamLeaves", DEFAULT_MAX_PARAM_LEAVES)
        if len(leaves) > cap:  # fail CLOSED on a param-stuffed action
            raise EmbeddingError("param leaf count %d exceeds cap %s" % (len(leaves), _js_str(cap)))
        if cfg.get("paramMode") == "digest":
            add("p#:" + hash_canonical_lenient({"t": "pca-objrisk-params-v1", "params": a["params"]}), fw["param"])
        else:
            for leaf in leaves:
                for f in _text_features("p:", leaf, cfg["ngramMin"], cfg["ngramMax"]):
                    add(f, fw["param"])
        return v

    return Embedder(model_id, committed, dims, embed)


def byo_model_id(d: dict) -> str:
    return "byo:" + hash_canonical_lenient(d)


def byo_embedder(descriptor: dict, infer: Callable[[str], Any], claimed_model_id: Optional[str] = None) -> Embedder:
    """A customer-supplied model that meets the determinism contract: ``modelId`` = ``byo:`` + the descriptor hash, ``infer`` gets the canonical
    action JSON, the output is ``dims`` safe integers within the declared quantization range."""
    dims = descriptor.get("dims")
    if not _safe_int(dims) or dims < 1:
        raise ValueError("byo: dims must be a positive integer")
    q = _get(descriptor, "quantization")
    bits = _get(q, "bits")
    if not _safe_int(bits) or bits < 2 or bits > 31 or not _js_num(q.get("scale")) > 0:
        raise ValueError("byo: invalid quantization")
    if descriptor.get("inputEncoding") != "pca-canonical-action-json-v1":
        raise ValueError("byo: unsupported inputEncoding")
    model_id = byo_model_id(descriptor)
    if claimed_model_id is not None and claimed_model_id != model_id:
        raise ValueError("byo: modelId does not match the committed descriptor")
    qmax = 2 ** (bits - 1) - 1

    def embed(a: dict) -> List[int]:
        v = validate_vector(infer(canonical_action_json(a)), dims)
        for x in v:
            if abs(x) > qmax:
                raise EmbeddingError("byo: component exceeds declared quantization range")
        return v

    return Embedder(model_id, descriptor, dims, embed)


def conformance_check(e: Embedder, cases: Any) -> bool:
    """Run conformance cases ({action, vector}) shipped with a model; True iff all reproduce exactly."""
    try:
        for c in cases:
            v = e.embed(canonical_action(c["action"]))
            if len(v) != len(c["vector"]) or any(x != c["vector"][i] for i, x in enumerate(v)):
                return False
        return True
    except Exception:  # noqa: BLE001
        return False


# ---- goal commitment and distance ----

def _goal_commit_input(g: dict) -> dict:
    return {"embedderModelId": g.get("embedderModelId"), "config": g.get("config"), "goalVector": g.get("goalVector"), "metric": g.get("metric"),
            "epsilon": g.get("epsilon")}


def _eps_ok(e: Any) -> bool:
    n = _js_num(e)
    return n > 0 and n <= 1


def commit_goal(embedder: Embedder, goal_action: Any, epsilon: Any = None) -> Dict[str, Any]:
    """Embed the goal's CANONICAL action and bind it to this embedder; ``epsilon`` None is the default. Raises on invalid input."""
    eps = DEFAULT_EPSILON if epsilon is None else epsilon
    if not _eps_ok(eps):
        raise ValueError("epsilon must be in (0, 1]")
    goal_vector = validate_vector(embedder.embed(canonical_action(goal_action)), embedder.dims)
    g = {"embedderModelId": embedder.model_id, "config": embedder.config, "goalVector": goal_vector, "metric": METRIC, "epsilon": eps}
    return dict(g, commit=hash_canonical_lenient(_goal_commit_input(g)))


def verify_goal_commitment(g: Any, embedder: Embedder) -> Optional[str]:
    """Verifies the commitment hashes AND that it is bound to exactly this embedder (id, config, dims): the first failing reason, else None."""
    try:
        if _get(g, "metric") != METRIC:
            return "unknown metric"
        if not _eps_ok(g.get("epsilon")):
            return "bad epsilon"
        if g.get("commit") != hash_canonical_lenient(_goal_commit_input(g)):
            return "goal commitment hash mismatch"
        if g.get("embedderModelId") != embedder.model_id:
            return "embedder modelId mismatch"
        if hash_canonical_lenient(g.get("config")) != hash_canonical_lenient(embedder.config):
            return "embedder config mismatch"
        validate_vector(g.get("goalVector"), embedder.dims)
        return None
    except Exception as e:  # noqa: BLE001 - the reference returns the message
        return str(e)


def vector_distance(a: List[Any], b: List[Any], epsilon: Any = None) -> float:
    """Integer vectors -> sin(theta / 2) = sqrt((1 - cos) / 2), rounded UP to a multiple of epsilon; only IEEE ``/`` and ``sqrt``, in this
    order (no fused multiply-add)."""
    eps = DEFAULT_EPSILON if epsilon is None else epsilon
    if len(a) != len(b):
        return 1
    dot = na = nb = 0.0
    same = True
    for x, y in zip(a, b):
        fx, fy = float(x), float(y)
        dot += fx * fy
        na += fx * fx
        nb += fy * fy
        if x != y:
            same = False
    if na == 0 or nb == 0:
        return 1
    if same:
        return 0
    cos = _js_max(-1.0, _js_min(1.0, _div(dot, math.sqrt(na * nb))))
    d = math.sqrt((1 - cos) / 2) if cos == cos else math.nan
    if d < 1e-9:  # float noise floor, far below epsilon
        return 0
    e = _js_num(eps)
    return _clamp01(_js_ceil(_div(d, e)) * e)


def committed_distance_checked(action: dict, goal: Any, embedder: Embedder) -> Dict[str, Any]:
    """Distance to the committed goal; ``ok`` False (distance 1) on any commitment or embedding failure."""
    bad = verify_goal_commitment(goal, embedder)
    if bad:
        return {"ok": False, "reason": bad}
    try:
        v = validate_vector(embedder.embed(action), embedder.dims)
        return {"ok": True, "value": vector_distance(v, goal["goalVector"], goal["epsilon"])}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": str(e)}


def committed_distance(action: Any, goal: Any, embedder: Embedder) -> float:
    """Convenience: canonicalizes an agent submission and returns the distance (1 on failure)."""
    try:
        r = committed_distance_checked(canonical_action(action), goal, embedder)
        return r["value"] if r["ok"] else 1
    except Exception:  # noqa: BLE001
        return 1


# ---- 4. split-conformal calibration ----

def calibrate(raw_score: Any, benign_scores: List[Any]) -> float:
    """p = (1 + #{s >= raw}) / (n + 1); calibrated r = 1 - p. An empty set or a non-finite raw score is 1."""
    n = len(benign_scores)
    if n == 0 or not _fin(raw_score):
        return 1
    ge = sum(1 for s in benign_scores if s >= raw_score)
    return 1 - (1 + ge) / (n + 1)


def conformal_threshold(benign_scores: List[Any], alpha: Any) -> Any:
    """Split-conformal quantile (benign raw <= q with probability >= 1 - alpha): +Infinity when n is too small, None where the reference has
    no element (alpha >= 1)."""
    n = len(benign_scores)
    k = _js_ceil((n + 1) * (1 - _js_num(alpha)))
    if n == 0 or k > n:
        return math.inf
    if k != k or k < 1:
        return None
    return sorted(benign_scores)[int(k) - 1]


def calibration_digest(scores: List[Any]) -> str:
    return hash_canonical_lenient({"v": 1, "scores": sorted(scores)})


# ---- 5. harm currency ----

def harm_report(units: dict, denoms: List[dict]) -> Dict[str, Any]:
    """Weighted saturating normalization of the harm units over the denominations, in [0, 1]; 1 when nothing is weighted."""
    num = den = 0.0
    for d in denoms:
        w, ceiling = _js_num(d.get("weight")), _js_num(d.get("ceiling"))
        if not w > 0 or not ceiling > 0:
            continue
        u = units[d["id"]] if d.get("id") in units else 0
        num += w * _js_min(1, _div(_js_max(0, _js_num(u)), ceiling))
        den += w
    return {"units": units, "normalized": 1 if den == 0 else _clamp01(_div(num, den))}


# ---- composition ----

_WORST_INPUTS = {"semanticDistance": 1, "reversibility": 0, "blastRadius": 1, "taint": 1, "confidence": 0, "age": 1}


def _reject(reasons: List[str]) -> Dict[str, Any]:
    return {"r": 1, "valid": False, "reasons": reasons, "raw": 1, "inputs": dict(_WORST_INPUTS), "reversibility": {"class": "irreversible", "value": 0},
            "blast": {"count": 0, "reachable": [], "normalized": 1, "harm": {}}, "harm": {"units": {}, "normalized": 1}, "evidenceDigest": ""}


def objective_risk(submitted: Any, ctx: dict) -> Dict[str, Any]:
    """Pure function of (canonical action, committed context). Any commitment mismatch (registry, graph, goal / embedder binding, calibration
    set) or un-encodable action returns the fail-closed r = 1 with ``valid`` False. ``ctx``: registry, authorizedKinds, graph, scope?, embedder,
    goal, commitments {registryDigest, graphDigest, calibrationDigest?}, denominations, weights, taint, age, attestedUncertainty?, calibration?."""
    try:
        action = canonical_action(submitted)
    except Exception as e:  # noqa: BLE001
        return _reject(["action: %s" % (str(e) or "not canonicalizable")])
    reasons: List[str] = []
    com = ctx["commitments"]
    if ctx["registry"].digest() != com["registryDigest"]:
        reasons.append("registry digest does not match the committed digest")
    if ctx["graph"].digest() != com["graphDigest"]:
        reasons.append("graph digest does not match the committed digest")
    calibration = ctx.get("calibration")
    if calibration is not None:
        if "calibrationDigest" not in com:
            reasons.append("calibration set used without a committed digest")
        elif calibration_digest(calibration) != com["calibrationDigest"]:
            reasons.append("calibration digest does not match the committed digest")
    dist = committed_distance_checked(action, ctx["goal"], ctx["embedder"])
    if not dist["ok"]:
        reasons.append("goal/embedder: %s" % dist["reason"])
    if reasons:
        return _reject(reasons)
    kinds = ctx["authorizedKinds"]
    rev = reversibility(action, ctx["registry"], kinds)
    scope = ctx.get("scope")
    blast = blast_radius(action, ctx["graph"], scope)
    harm = harm_report(blast["harm"], ctx["denominations"])
    au = ctx.get("attestedUncertainty")
    uncertainty = _clamp01(0 if au is None else au)
    inputs = {"semanticDistance": dist["value"], "reversibility": rev["value"],
              "blastRadius": _js_max(blast["normalized"], harm["normalized"] if len(ctx["denominations"]) and len(blast["harm"]) else 0),
              "taint": ctx["taint"] if _fin(ctx.get("taint")) else 1, "confidence": 1 - uncertainty, "age": ctx["age"] if _fin(ctx.get("age")) else 1}
    raw = risk_score(inputs, ctx["weights"])
    r = calibrate(raw, calibration) if calibration is not None else raw
    ek = scope.get("edgeKinds") if scope else None
    md = scope.get("maxDepth") if scope else None
    evidence = hash_canonical_lenient({
        "action": canonical_action_digest(action),
        "scope": {"edgeKinds": _sorted_u16(ek) if ek is not None else None, "maxDepth": md},
        "authorized": _sorted_u16(kinds), "registry": com["registryDigest"], "graph": com["graphDigest"], "goal": ctx["goal"]["commit"],
        "calibration": com.get("calibrationDigest"), "inputs": inputs})
    return {"r": r, "valid": True, "reasons": [], "raw": raw, "inputs": inputs, "reversibility": rev, "blast": blast, "harm": harm, "evidenceDigest": evidence}


# ---- dispute-game oracle ----

class _Oracle:
    def __init__(self, ctx: dict) -> None:
        self._ctx = ctx

    def resolve(self, inp: Any, snapshot: Any) -> Dict[str, Any]:
        """Recompute the disputed input from the COMMITTED facts over the snapshot's canonical action; fails CLOSED (``valid`` False)."""
        try:
            a = ((snapshot.get("action") or {}).get("action") if isinstance(snapshot.get("action"), dict) else None) if isinstance(snapshot, dict) else None
            if not isinstance(a, dict) or not isinstance(a.get("verb"), str) or not isinstance(a.get("resource"), str):
                return {"input": inp, "valid": False, "reason": "snapshot action is missing a canonical verb/resource"}
            params = a.get("params")
            res = objective_risk({"verb": a["verb"], "resource": a["resource"], "params": params if isinstance(params, dict) else {}}, self._ctx)
            if not res["valid"]:
                return {"input": inp, "valid": False, "reason": "; ".join(res["reasons"]) or "objective risk could not be reproduced"}
            if inp == "reversibility_class":
                return {"input": inp, "class": res["reversibility"]["class"], "valid": True}
            if inp in ("reversibility", "blastRadius", "semanticDistance"):
                return {"input": inp, "value": res["inputs"][inp], "valid": True}
            return {"input": inp, "valid": False, "reason": "unknown disputed input: %s" % _js_str(inp)}
        except Exception as e:  # noqa: BLE001
            return {"input": inp, "valid": False, "reason": "objective oracle error (fail closed): %s" % (str(e) or "unknown")}


def objective_risk_oracle(ctx: dict) -> _Oracle:
    """The dispute game's objective oracle backed by the objective risk functional."""
    return _Oracle(ctx)
