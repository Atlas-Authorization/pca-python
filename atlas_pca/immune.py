"""Behavioral immune system: "authorization that gets more paranoid when something is off". Learn each principal's NORMAL risk
distribution from the stream of their agents' actions, detect drift, volatility and violation bursts, and under suspicion PROPOSE a
tightened risk policy for the next epoch (lower theta so more actions need a human, higher kappa so each action costs more budget).
When behavior returns to baseline the proposal relaxes back to the base policy. Mirrors the TypeScript reference (``immune.ts``).

HONEST framing: this PROPOSES a policy; it never mutates a signed grant. The adaptation is a pure, deterministic, REVERSIBLE function of
the current threat score computed from the BASE policy, so it can only make authorization stricter under threat and returns to the
baseline when calm. GUARANTEED (enforced in code): the adapted policy never widens the base (kappa' >= kappa, theta' <= theta, the rest
equal; :func:`assert_no_widen`); score 0 restores the base exactly; a malformed state or score fails CLOSED to the most restrictive
threat level; a tightening proposal is guardian-signed, bound to the base policy and state digests, and applies only with a strictly
higher epoch. NOT guaranteed: the anomaly score is a heuristic (EWMA and z-score over one principal's history); a slow attacker who
drifts the baseline can game it, and it is no proof that an agent is compromised or benign.

An immune state is ``{"baseline": {"n", "mean", "m2"}, "ewma", "stepUps", "denies", "lastAt", "seeded"}``; an observation is
``{"r", "at", "stepUp"?, "denied"?}``. Values are decoded JSON (dicts, lists, ints and floats).
"""
from __future__ import annotations

import copy
import math
from ._fin import fin
from typing import Any, Dict, List, Optional

from . import ed25519
from .actions_import_common import _lenient, _utf8, hash_canonical_lenient, is_safe_integer
from .facade import _string_to_number
from .harness import _to_fixed
from .pca import _verify_b64u, b64u
from .predicates import _UNDEF, _js_string
from .risk import validate_risk_policy

# ---- JavaScript value coercions -------------------------------------------------------------------


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _finite(v: Any) -> bool:
    """Number.isFinite."""
    return _is_num(v) and fin(v)


def _truthy(v: Any) -> bool:
    if v is None or v is False or v == "" or v is _UNDEF:
        return False
    if _is_num(v):
        return not (v == 0 or v != v)
    return True


def _number(v: Any) -> float:
    """ECMAScript Number(v) of a decoded JSON value (_UNDEF is undefined: NaN)."""
    if v is _UNDEF:
        return math.nan
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if _is_num(v):
        return float(v)
    if isinstance(v, (str, list)):
        return _string_to_number(_js_string(v))
    return math.nan


def _get(o: Any, key: str) -> Any:
    """Own-property read ``o[key]`` (a missing member or a non-object is undefined)."""
    return o.get(key, _UNDEF) if isinstance(o, dict) else _UNDEF


def _prop(o: Any, key: str) -> Any:
    """``o[key]`` where the reference throws on a null or undefined ``o``."""
    if o is None or o is _UNDEF:
        raise TypeError("Cannot read properties of %s (reading '%s')" % ("null" if o is None else "undefined", key))
    return _get(o, key)


def _seq(a: Any, b: Any) -> bool:
    """Strict equality (===) of two decoded JSON values (objects and arrays by identity)."""
    if _is_num(a) and _is_num(b):
        return a == b
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    return a is b


def _ge(a: Any, b: Any) -> bool:
    """``a >= b`` (two strings compare as strings, everything else as numbers; NaN is false)."""
    if isinstance(a, str) and isinstance(b, str):
        return a >= b
    return _number(a) >= _number(b)


def _gt(a: Any, b: Any) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a > b
    return _number(a) > _number(b)


def _neg_zero(x: Any) -> bool:
    return _is_num(x) and x == 0 and math.copysign(1.0, x) < 0


def _clamp01(x: float) -> float:
    """Math.max(0, Math.min(1, x)); NaN stays NaN."""
    if x != x:
        return x
    return 0.0 if x < 0 else 1.0 if x > 1 else x


# ---- baseline (Welford running mean and variance) -------------------------------------------------

EMPTY_BASELINE: Dict[str, Any] = {"n": 0, "mean": 0, "m2": 0}


def update_baseline(b: Any, r: Any) -> Dict[str, Any]:
    """Welford update of a baseline with one risk sample (a non-finite sample counts as 0)."""
    x = float(r) if _finite(r) else 0.0
    n = _number(_prop(b, "n")) + 1
    mean0 = _number(_prop(b, "mean"))
    delta = x - mean0
    mean = mean0 + delta / n
    m2 = _number(_get(b, "m2")) + delta * (x - mean)
    return {"n": n, "mean": mean, "m2": m2}


def baseline_std(b: Any) -> float:
    """Population standard deviation of the baseline (0 until at least 2 samples)."""
    n = _number(_prop(b, "n"))
    return math.sqrt(_number(_get(b, "m2")) / n) if n >= 2 else 0


# ---- immune state ---------------------------------------------------------------------------------

# ewma smoothing of the recent signal; half-life (ms) of the step-up / deny counters; drift z-score, step-up rate and deny count at which each signal saturates
DEFAULT_IMMUNE_CONFIG: Dict[str, Any] = {"alpha": 0.3, "halfLifeMs": 3_600_000, "driftZSat": 3, "stepUpSat": 5, "denySat": 3}

INITIAL_IMMUNE_STATE: Dict[str, Any] = {"baseline": EMPTY_BASELINE, "ewma": 0, "stepUps": 0, "denies": 0, "lastAt": 0, "seeded": False}


def initial_state() -> Dict[str, Any]:
    """A fresh copy of the state of a principal with no history."""
    return copy.deepcopy(INITIAL_IMMUNE_STATE)


#: Resolution of the decay: the elapsed time is counted in 1/1024ths of a half-life (rounded down).
DECAY_STEPS_PER_HALF_LIFE = 1024
#: 2^(-1/1024) rounded to the nearest double (a decimal literal parses identically in every language).
_DECAY_STEP = 0.9993233275026507


def _decay(count: float, dt_ms: float, half_life_ms: float) -> float:
    """Exponential decay by a half-life from exactly reproducible operations only (no pow, exp or log, which differ in the last digit between
    libm implementations): u = floor(1024 * dt / halfLife) whole 1/1024ths of a half-life, then the factor is 0.5 multiplied floor(u / 1024)
    times and 0.9993233275026507 multiplied (u mod 1024) times, in that order, one IEEE double multiplication at a time."""
    if dt_ms <= 0 or count == 0:
        return count
    num = float(dt_ms) * DECAY_STEPS_PER_HALF_LIFE
    if half_life_ms == 0:  # JS division by zero: +Infinity (num > 0), NaN for 0 / 0
        q = math.inf if num > 0 else math.nan
    else:
        q = num / float(half_life_ms)
    if q != q:
        return math.nan
    if q == math.inf:
        return count * 0
    u = math.floor(q) if q != -math.inf else -math.inf
    if u == -math.inf:
        return count  # a negative half-life: the reference's loops do not run for k < 0 and m is the full range; unreachable for a valid config
    if u >= DECAY_STEPS_PER_HALF_LIFE * 1100:  # 0.5^1100 underflows
        return count * 0
    k = u // DECAY_STEPS_PER_HALF_LIFE
    m = u - k * DECAY_STEPS_PER_HALF_LIFE
    f = 1.0
    for _ in range(int(k)):
        f *= 0.5
    for _ in range(int(m)):
        f *= _DECAY_STEP
    return count * f


def observe(state: Any, obs: Any, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Fold one observation into the immune state (baseline, recent EWMA, decayed step-up and deny counters). A non-finite timestamp is
    pinned to the last good one (no clock advance), so the counters never turn NaN and read a permanent, fail-open ``calm``."""
    c = cfg if cfg is not None else DEFAULT_IMMUNE_CONFIG
    raw_r = _prop(obs, "r")
    r = max(0.0, min(1.0, float(raw_r) if _finite(raw_r) else 0.0))
    raw_at = _get(obs, "at")
    last_at = _prop(state, "lastAt")
    at = raw_at if _finite(raw_at) else last_at
    seeded = _truthy(_get(state, "seeded"))
    dt = max(0.0, _number(at) - _number(last_at)) if seeded else 0.0
    baseline = update_baseline(_get(state, "baseline"), r)
    ewma = c["alpha"] * r + (1 - c["alpha"]) * _number(_get(state, "ewma")) if seeded else r
    step_ups = _decay(_number(_get(state, "stepUps")), dt, c["halfLifeMs"]) + (1 if _truthy(_get(obs, "stepUp")) else 0)
    denies = _decay(_number(_get(state, "denies")), dt, c["halfLifeMs"]) + (1 if _truthy(_get(obs, "denied")) else 0)
    return {"baseline": baseline, "ewma": ewma, "stepUps": step_ups, "denies": denies, "lastAt": at, "seeded": True}


_MAX_COUNT = 1e9


def _in_range(x: Any, lo: float, hi: float) -> bool:
    return _finite(x) and lo <= x <= hi


def _is_integer(x: Any) -> bool:
    return isinstance(x, int) or (isinstance(x, float) and x.is_integer())


def validate_immune_state(s: Any) -> Optional[str]:
    """The reason a state is malformed (non-finite, negative, out of bound), or None."""
    if not isinstance(s, (dict, list)):
        return "state must be an object"
    b = _get(s, "baseline")
    if not isinstance(b, (dict, list)):
        return "baseline missing"
    n = _get(b, "n")
    if not _in_range(n, 0, _MAX_COUNT) or not _is_integer(n) or _neg_zero(n):
        return "baseline.n must be an integer in [0, 1e9]"
    if not _in_range(_get(b, "mean"), 0, 1):
        return "baseline.mean must be in [0, 1]"
    if not _in_range(_get(b, "m2"), 0, _MAX_COUNT):
        return "baseline.m2 must be finite and >= 0"
    if not _in_range(_get(s, "ewma"), 0, 1):
        return "ewma must be in [0, 1]"
    if not _in_range(_get(s, "stepUps"), 0, _MAX_COUNT):
        return "stepUps must be finite and >= 0"
    if not _in_range(_get(s, "denies"), 0, _MAX_COUNT):
        return "denies must be finite and >= 0"
    if not _in_range(_get(s, "lastAt"), 0, 9007199254740991):
        return "lastAt must be a finite non-negative time"
    if not isinstance(_get(s, "seeded"), bool):
        return "seeded must be a boolean"
    return None


# ---- threat assessment ----------------------------------------------------------------------------


def _threat(level: str, score: float, signals: List[str], drift: float, volatility: float, violation: float) -> Dict[str, Any]:
    return {"level": level, "score": score, "signals": signals,
            "components": {"drift": drift, "volatility": volatility, "violation": violation}}


def assess(state: Any, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The current threat from the immune state: ``{"level": calm | elevated | high, "score", "signals", "components": {drift, volatility,
    violation}}``. The score is the maximum of the drift (recent mean risk above the baseline, in std units), step-up volatility and
    violation (decayed deny count) signals; levels switch at 0.33 and 0.66. A malformed state is the maximal threat."""
    c = cfg if cfg is not None else DEFAULT_IMMUNE_CONFIG
    bad = validate_immune_state(state)
    if bad is not None:
        return _threat("high", 1, ["invalid immune state: " + bad], 1, 1, 1)
    base = state["baseline"]
    std = baseline_std(base)
    signals: List[str] = []
    drift = 0.0
    if base["n"] >= 5 and std > 1e-9:  # only ABOVE-baseline movement is threatening, and it needs a settled baseline
        z = (state["ewma"] - base["mean"]) / std
        drift = _clamp01(z / c["driftZSat"])
        if drift > 0.33:
            signals.append("risk drifted %sσ above baseline" % _to_fixed(z, 1))
    volatility = _clamp01(state["stepUps"] / c["stepUpSat"])
    if volatility > 0.33:
        signals.append("elevated step-up rate (%s)" % _to_fixed(state["stepUps"], 1))
    violation = _clamp01(state["denies"] / c["denySat"])
    if violation > 0.33:
        signals.append("repeated policy violations (%s)" % _to_fixed(state["denies"], 1))
    score = max(drift, volatility, violation)
    return _threat("high" if score >= 0.66 else "elevated" if score >= 0.33 else "calm", score, signals, drift, volatility, violation)


# ---- adaptation (anomaly-gated epoch) -------------------------------------------------------------

# max multiple kappa can be raised to at score 1, and min multiple theta can be lowered to
DEFAULT_ADAPT_CONFIG: Dict[str, Any] = {"maxKappaMult": 3, "minThetaMult": 0.4}


def _adaptation(policy: Any, changed: bool, rationale: str) -> Dict[str, Any]:
    return {"policy": policy, "changed": changed, "rationale": rationale}


def _js_join(items: List[Any]) -> str:
    """Array.prototype.join('; '): null and undefined read as the empty string."""
    return "; ".join("" if x is None or x is _UNDEF else _js_string(x) for x in items)


def adapt(base: Any, assessment: Any, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The adapted policy for a threat assessment, derived from the BASE policy (never compounded): ``{"policy", "changed",
    "rationale"}``. Score 0 gives the base unchanged; higher scores raise kappa toward ``maxKappaMult`` times and lower theta toward
    ``minThetaMult`` times. A non-finite score is the worst case, never calm. The result is re-validated and checked against the no-widen
    invariant; a rejected adaptation keeps the base. Raises TypeError where the reference throws (a null base with a non-zero score)."""
    c = cfg if cfg is not None else DEFAULT_ADAPT_CONFIG
    raw = _prop(assessment, "score")
    s = _clamp01(float(raw)) if _finite(raw) else 1.0
    if s == 0:
        return _adaptation(base, False, "calm — baseline policy")
    if base is None:
        raise TypeError("Cannot read properties of null (reading 'weights')")
    kappa_mult = 1 + (c["maxKappaMult"] - 1) * s
    theta_mult = 1 - (1 - c["minThetaMult"]) * s
    policy: Dict[str, Any] = dict(base) if isinstance(base, dict) else {}
    w = _get(base, "weights")
    policy["weights"] = dict(w) if isinstance(w, dict) else {}
    policy["kappa"] = _number(_get(base, "kappa")) * kappa_mult
    policy["theta1"] = _clamp01(_number(_get(base, "theta1")) * theta_mult)
    policy["theta2"] = _clamp01(_number(_get(base, "theta2")) * theta_mult)
    bad = validate_risk_policy(policy)
    if bad is None:
        bad = no_widen_violation(base, policy)
    if bad is not None:
        return _adaptation(base, False, "adaptation rejected (%s) — kept baseline" % bad)
    signals = _prop(assessment, "signals")
    if signals is _UNDEF or signals is None:
        raise TypeError("Cannot read properties of %s (reading 'length')" % ("null" if signals is None else "undefined"))
    has_signals = len(signals) > 0 if isinstance(signals, (list, str)) else False
    if has_signals and not isinstance(signals, list):
        raise TypeError("assessment.signals.join is not a function")
    why = _js_join(signals) if has_signals else "threat score %s" % _to_fixed(s, 2)
    return _adaptation(policy, True, "%s: %s → κ ×%s, θ ×%s" % (
        _js_string(_get(assessment, "level")), why, _to_fixed(kappa_mult, 2), _to_fixed(theta_mult, 2)))


# ---- the no-widen invariant -----------------------------------------------------------------------


def no_widen_violation(base: Any, adapted: Any) -> Optional[str]:
    """Why ``adapted`` is looser than ``base``, or None when it only tightens (kappa up, thetas down, the rest identical). A value that is
    not a number reads as looser. Raises TypeError where the reference throws (a missing ``weights``)."""
    # null and booleans coerce to numbers in a relational comparison: a value that is not a number is a violation before any comparison
    if not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in (_prop(adapted, "kappa"), _get(adapted, "theta1"), _get(adapted, "theta2"))):
        return "kappa and theta must be numbers"
    if not _ge(_prop(adapted, "kappa"), _prop(base, "kappa")):
        return "kappa decreased"
    if not _ge(_get(base, "theta1"), _get(adapted, "theta1")):
        return "theta1 increased"
    if not _ge(_get(base, "theta2"), _get(adapted, "theta2")):
        return "theta2 increased"
    for k in ("lambda", "rho", "bMax"):
        if not _seq(_get(adapted, k), _get(base, k)):
            return "%s changed" % k
    bw = _get(base, "weights")
    if bw is None or bw is _UNDEF:
        raise TypeError("Cannot convert undefined or null to object")
    if isinstance(bw, dict):
        aw = _get(adapted, "weights")
        for k in list(bw):
            if aw is None or aw is _UNDEF:
                raise TypeError("Cannot read properties of %s (reading '%s')" % ("null" if aw is None else "undefined", k))
            if not _seq(_get(aw, k), bw[k]):
                return "weights.%s changed" % k
    return None


def assert_no_widen(base: Any, adapted: Any) -> None:
    """Raises unless ``adapted`` only tightens ``base``."""
    v = no_widen_violation(base, adapted)
    if v is not None:
        raise ValueError("immune: adaptation widens the policy (%s)" % v)


# ---- signed tightening proposals ------------------------------------------------------------------

TIGHTENING_DOMAIN = "atlas-pca/immune-tightening/v1\0"


def _tightening_message(claim: Any) -> bytes:
    return _utf8(TIGHTENING_DOMAIN) + _utf8(_lenient(claim))


def policy_digest(policy: Any) -> str:
    """base64url(sha256(lenient canonical JSON)) of a risk policy."""
    return hash_canonical_lenient(policy)


def immune_state_digest(state: Any) -> str:
    return hash_canonical_lenient(state)


def issue_tightening_proposal(base: Any, state: Any, epoch: Any, now: Any, guardian_secret: bytes,
                              cfg: Optional[Dict[str, Any]] = None, adapt_cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Derive and sign the tightening for ``state``. Raises ValueError on a malformed base, an epoch that is not an integer >= 1 or a
    non-finite ``now`` (never an unsigned loosening). ``guardian_secret`` is the 32-byte Ed25519 seed; signing needs ``cryptography`` or the
    ed25519 insecure-signer opt-in, as everywhere else in this package. A malformed state is the maximal threat, never a calm one."""
    bad = validate_risk_policy(base)
    if bad is not None:
        raise ValueError("issueTighteningProposal: %s" % bad)
    if not is_safe_integer(epoch) or epoch < 1:
        raise ValueError("issueTighteningProposal: epoch must be an integer >= 1")
    if not _finite(now):
        raise ValueError("issueTighteningProposal: now must be finite")
    ad = adapt(base, assess(state, cfg), adapt_cfg)
    claim = {"v": 1, "base_digest": policy_digest(base), "state_digest": hash_canonical_lenient(state), "epoch": epoch, "issued_at": now,
             "policy": ad["policy"], "rationale": ad["rationale"], "guardian": b64u(ed25519.public_key(guardian_secret))}
    proposal = dict(claim)
    proposal["sig"] = b64u(ed25519.sign_secret(guardian_secret, _tightening_message(claim)))
    return proposal


def _refused(reason: str) -> Dict[str, Any]:
    return {"ok": False, "reason": reason}


def apply_tightening(base: Any, p: Any, o: Any) -> Dict[str, Any]:
    """Verify a proposal and return ``{"ok": True, "policy", "epoch"}`` or ``{"ok": False, "reason"}``; never raises. ``o``: the pinned
    ``guardian`` (b64u, required: an unpinned proposal is refused), ``lastEpoch`` (highest epoch already applied, 0 when none), ``now``,
    ``maxAgeMs`` (older proposals are refused) and optionally ``state`` (the proposal must equal the tightening that state derives).
    Reasons: malformed, guardian, signature, invalid-policy, base, stale, replayed-epoch, widens, state-mismatch."""
    try:
        if not isinstance(p, dict) or not _seq(p.get("v", _UNDEF), 1) or not isinstance(p.get("sig"), str) or not isinstance(p.get("guardian"), str):
            return _refused("malformed")
        pin = _prop(o, "guardian")
        if not isinstance(pin, str) or pin != p["guardian"]:
            return _refused("guardian")
        claim = {k: v for k, v in p.items() if k != "sig"}
        if not _verify_b64u(p["guardian"], _tightening_message(claim), p["sig"]):
            return _refused("signature")
        pol = p.get("policy", _UNDEF)
        if validate_risk_policy(base) is not None or validate_risk_policy(pol) is not None:
            return _refused("invalid-policy")
        if not _seq(p.get("base_digest", _UNDEF), policy_digest(base)):
            return _refused("base")
        now, at = _get(o, "now"), p.get("issued_at", _UNDEF)
        if not _finite(now) or not _finite(at) or not at <= now or not _ge(_get(o, "maxAgeMs"), now - at):
            return _refused("stale")
        epoch = p.get("epoch", _UNDEF)
        if not is_safe_integer(epoch) or _neg_zero(epoch) or not _gt(epoch, _get(o, "lastEpoch")):
            return _refused("replayed-epoch")
        if no_widen_violation(base, pol) is not None:
            return _refused("widens")
        st = _get(o, "state")
        if _truthy(st) and (not _seq(p.get("state_digest", _UNDEF), hash_canonical_lenient(st))
                            or policy_digest(adapt(base, assess(st))["policy"]) != policy_digest(pol)):
            return _refused("state-mismatch")
        return {"ok": True, "policy": pol, "epoch": epoch}
    except Exception:  # noqa: BLE001 - every refusal is a distinct reason; anything unexpected is malformed
        return _refused("malformed")


# ---- durable state --------------------------------------------------------------------------------


class ImmuneStore:
    """Immune state and applied epoch for one subject over an atomic key/value store (:class:`atlas_pca.atomic_kv.MemoryAtomicKv` or
    :class:`SqliteAtomicKv`), so a restart keeps the history and the replay floor. A stored value of ``None`` is an absent key in
    that interface."""

    def __init__(self, kv: Any, subject: str) -> None:
        if kv is None:
            raise ValueError("immune store: kv is required")
        self._kv = kv
        self._s_key = "immune/state/" + subject
        self._e_key = "immune/epoch/" + subject

    def get(self) -> Any:
        """The stored state, or the initial one."""
        v = self._kv.get(self._s_key)
        return initial_state() if v is None else v

    def observe(self, obs: Any, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Folds one observation atomically. Raises when the stored state is malformed (it is never silently reset to calm)."""
        def fold(prev: Any) -> Dict[str, Any]:
            cur = initial_state() if prev is None else prev
            bad = validate_immune_state(cur)
            if bad is not None:
                raise ValueError("immune store: stored state invalid (%s)" % bad)
            return observe(cur, obs, cfg)

        return self._kv.update(self._s_key, fold)

    def last_epoch(self) -> Any:
        v = self._kv.get(self._e_key)
        return v if _is_num(v) else 0

    def apply(self, base: Any, p: Any, o: Any) -> Dict[str, Any]:
        """Verify and apply a proposal (``o`` as for :func:`apply_tightening` without ``lastEpoch``); the epoch floor advances atomically, so
        two racing applies of one epoch cannot both win."""
        out = [_refused("malformed")]

        def advance(prev: Any) -> Any:
            oo = dict(o) if isinstance(o, dict) else {}
            oo["lastEpoch"] = prev if _is_num(prev) else 0
            out[0] = apply_tightening(base, p, oo)
            return out[0]["epoch"] if out[0]["ok"] else None

        self._kv.update(self._e_key, advance)
        return out[0]


def create_immune_store(kv: Any, subject: str) -> ImmuneStore:
    return ImmuneStore(kv, subject)
