"""Proof of progress toward a committed goal: a goal (objective, potential id, embedder, metric, epsilon, exploration budget) is hashed into a
commitment; each step is a hash-chained body binding the goal, the action digest, the before and after state digests, the sequence number and
the previous step; the verifier recomputes the integer potential and the mode (progress, or exploration charged to a budget). Steps can be
Ed25519-signed by the holder, post-states can carry a state source's signed attestation, and the trajectory head can be anchored in the
transparency ledger. A port of the reference ``progress`` module. Hashes here are the STRICT canonical hash (the wire form): a state with a
non-integer of more than 15 significant digits, -0 or a lone surrogate has no digest.

Goals, states and steps are dicts in the reference's member names; potentials are callables ``fn(objective, state)`` returning a non-negative safe
integer (anything else is ``bad-potential``). Sources are synchronous."""
from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, List, Optional

from .actions_import_common import _lenient as _canonicalize_lenient
from ._fin import fin
from .agent import KeyPair
from .intent_v2 import _UNDEF, _bind_suite_fields, _pinned_suite_error, suite_capability_error
from .pca import b64u, canonical_bytes_strict, hash_canonical, verify_b64u
from .pq_suites import sign_suite_artifact, suite_pq_public_key

__all__ = ["PROGRESS_VERSION", "PROGRESS_SIG_DOMAIN", "TRAJECTORY_ANCHOR_DOMAIN", "STATE_ATTESTATION_DOMAIN", "PotentialRegistry",
           "DEFAULT_POTENTIALS", "l1_feature_potential", "dag_remaining_potential", "dag_weighted_potential", "goal_digest", "commit_goal",
           "verify_goal_commitment", "state_digest", "trajectory_head", "progress_step_digest", "trajectory_anchor_commit",
           "verify_trajectory_anchor", "anchor_trajectory_head", "InMemoryStateSource", "verify_state_attestation", "AttestedStateSource",
           "attested_state_verifier", "ProgressTracker", "verify_progress_step", "verify_trajectory", "sign_progress_step",
           "verify_signed_progress_step", "verify_signed_trajectory", "ProgressError"]

PROGRESS_VERSION = 2
PROGRESS_SIG_DOMAIN = "atlas-pca/progress-step/v2"
TRAJECTORY_ANCHOR_DOMAIN = "atlas-pca/trajectory-anchor/v1"
STATE_ATTESTATION_DOMAIN = "atlas-pca/progress-state-attestation/v1\0"
_GENESIS = "genesis"
_MAX_SAFE = 9007199254740991


def _is_num(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _safe_int(x: Any) -> bool:
    import math
    return _is_num(x) and fin(x) and x == math.floor(x) and abs(x) <= _MAX_SAFE


def _assert_int(n: Any, what: str) -> None:
    if not _safe_int(n):
        raise TypeError("%s: safe integer required" % what)


def _is_obj(x: Any) -> bool:
    return isinstance(x, dict)


def _is_str(x: Any) -> bool:
    return isinstance(x, str)


def _prop(o: Any, k: str) -> Any:
    """``o?.k``: an absent or non-object receiver has no member."""
    return o.get(k) if isinstance(o, dict) else None


def _snapshot(v: Any) -> Any:
    """A detached copy through the lenient canonical form (-0 becomes 0, a non-finite number raises)."""
    return json.loads(_canonicalize_lenient(v))


def _u16(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def _setkey(v: Any) -> Any:
    """A JavaScript Set's notion of identity: values of different types never collide, objects are distinct."""
    return (type(v).__name__, v) if isinstance(v, (str, int, float, bool)) or v is None else ("obj", id(v))


# ---- potentials and the registry ----

def l1_feature_potential(objective: Any, state: Any) -> int:
    """The L1 distance between ``objective.target`` and ``state.x`` (equal-length integer arrays)."""
    t, x = _prop(objective, "target"), _prop(state, "x")
    if not isinstance(t, list) or not isinstance(x, list) or len(t) != len(x):
        raise TypeError("l1-feature-v1: bad shape")
    d = 0
    for a, b in zip(t, x):
        _assert_int(a, "target")
        _assert_int(b, "x")
        d += abs(a - b)
        _assert_int(d, "distance")
    return d


def dag_remaining_potential(objective: Any, state: Any) -> int:
    """The summed cost of the tasks that are not yet done."""
    tasks, done = _prop(objective, "tasks"), _prop(state, "done")
    if not isinstance(tasks, list) or not isinstance(done, list):
        raise TypeError("dag-remaining-v1: bad shape")
    ids = {_setkey(_task_field(t, "id")) for t in tasks}
    if len(ids) != len(tasks):
        raise TypeError("dag-remaining-v1: duplicate task id")
    done_set = {_setkey(d): d for d in done}
    for k, d in done_set.items():
        if k not in ids:
            raise TypeError("dag-remaining-v1: unknown task %s" % (d,))
    rem = 0
    for t in tasks:
        cost = _task_field(t, "cost")
        _assert_int(cost, "cost")
        if cost < 0:
            raise TypeError("negative cost")
        if _setkey(_task_field(t, "id")) not in done_set:
            rem += cost
        _assert_int(rem, "remaining")
    return rem


def _task_field(t: Any, k: str) -> Any:
    if t is None:
        raise TypeError("Cannot read properties of null (reading '%s')" % k)
    return t.get(k) if isinstance(t, dict) else None


def dag_weighted_potential(objective: Any, state: Any) -> int:
    """The summed cost of the tasks not yet done over a dependency DAG (cycles, unknown or self dependencies and a done task before its
    dependency are refused)."""
    tasks, done = _prop(objective, "tasks"), _prop(state, "done")
    if not isinstance(tasks, list) or not isinstance(done, list):
        raise TypeError("dag-weighted-v1: bad shape")
    by_id: Dict[str, dict] = {}
    for t in tasks:
        if not _is_obj(t) or not _is_str(t.get("id")) or len(t["id"]) == 0:
            raise TypeError("dag-weighted-v1: bad task")
        if t["id"] in by_id:
            raise TypeError("dag-weighted-v1: duplicate task id")
        _assert_int(t.get("cost"), "cost")
        if t["cost"] < 0:
            raise TypeError("negative cost")
        deps = t.get("deps")
        deps = [] if deps is None else deps
        if not isinstance(deps, list) or not all(_is_str(d) for d in deps):
            raise TypeError("dag-weighted-v1: bad deps")
        by_id[t["id"]] = {"cost": t["cost"], "deps": deps}
    indeg: Dict[str, int] = {}
    rev: Dict[str, List[str]] = {}
    for i, t in by_id.items():
        ds = list(dict.fromkeys(t["deps"]))
        indeg[i] = len(ds)
        for d in ds:
            if d == i or d not in by_id:
                raise TypeError("dag-weighted-v1: bad dependency %s" % d)
            rev[d] = rev.get(d, []) + [i]
    q = [i for i, n in indeg.items() if n == 0]
    seen = 0
    while q:
        i = q.pop()
        seen += 1
        for n in rev.get(i, []):
            indeg[n] -= 1
            if indeg[n] == 0:
                q.append(n)
    if seen != len(by_id):
        raise TypeError("dag-weighted-v1: cycle")
    done_set: Dict[str, bool] = {}
    for d in done:
        if not _is_str(d) or d not in by_id:
            raise TypeError("dag-weighted-v1: unknown task %s" % (d,))
        if d in done_set:
            raise TypeError("dag-weighted-v1: duplicate done")
        done_set[d] = True
    for d in done_set:
        for dep in by_id[d]["deps"]:
            if dep not in done_set:
                raise TypeError("dag-weighted-v1: %s done before dependency %s" % (d, dep))
    rem = 0
    for i, t in by_id.items():
        if i not in done_set:
            rem += t["cost"]
        _assert_int(rem, "remaining")
    return rem


class PotentialRegistry:
    """Potential id -> ``{"fn", "embedder"}``. Ids are 1..128 UTF-16 units; a registered id is never replaced; a frozen registry refuses more."""

    def __init__(self) -> None:
        self._m: Dict[str, dict] = {}
        self._frozen = False

    def register(self, pid: Any, fn: Any, embedder: Any = "") -> "PotentialRegistry":
        if self._frozen:
            raise ValueError("registry is frozen")
        if not _is_str(pid) or len(pid) == 0 or len(_u16(pid)) // 2 > 128:
            raise TypeError("potential id: 1..128 chars")
        if not callable(fn):
            raise TypeError("potential must be a function")
        if not _is_str(embedder):
            raise TypeError("embedder must be a string")
        if pid in self._m:
            raise ValueError("potential %s already registered" % pid)
        self._m[pid] = {"fn": fn, "embedder": embedder}
        return self

    def get(self, pid: Any) -> Optional[dict]:
        return self._m.get(pid) if _is_str(pid) else None

    def has(self, pid: Any) -> bool:
        return _is_str(pid) and pid in self._m

    def ids(self) -> List[str]:
        return sorted(self._m, key=_u16)

    def freeze(self) -> "PotentialRegistry":
        self._frozen = True
        return self

    @staticmethod
    def from_record(rec: Dict[str, Any]) -> "PotentialRegistry":
        r = PotentialRegistry()
        for k, v in rec.items():
            if callable(v):
                r.register(k, v)
            else:
                emb = v.get("embedder")
                r.register(k, v.get("fn"), "" if emb is None else emb)
        return r

    @staticmethod
    def defaults() -> "PotentialRegistry":
        return (PotentialRegistry().register("l1-feature-v1", l1_feature_potential).register("dag-remaining-v1", dag_remaining_potential)
                .register("dag-weighted-v1", dag_weighted_potential))


DEFAULT_POTENTIALS = PotentialRegistry.defaults().freeze()


def _to_registry(r: Any) -> PotentialRegistry:
    if r is None:
        return DEFAULT_POTENTIALS
    return r if isinstance(r, PotentialRegistry) else PotentialRegistry.from_record(r)


# ---- goal commitment ----

def _validate_goal(goal: Any) -> None:
    if not _is_obj(goal):
        raise TypeError("goal must be an object")
    _assert_int(goal.get("epsilon"), "epsilon")
    _assert_int(goal.get("explorationBudget"), "explorationBudget")
    if goal["epsilon"] < 1:
        raise ValueError("epsilon must be >= 1")
    if goal["explorationBudget"] < 0:
        raise ValueError("explorationBudget must be >= 0")
    if not _is_str(goal.get("potential")) or len(goal["potential"]) == 0:
        raise TypeError("potential id required")
    if not _is_str(goal.get("metric")):
        raise TypeError("metric must be a string")
    if "embedder" in goal and not _is_str(goal["embedder"]):
        raise TypeError("embedder must be a string")


def goal_digest(goal: Any) -> str:
    """The commitment of a goal: the strict hash of its members (an absent embedder and ``""`` are the same commitment)."""
    _validate_goal(goal)
    if "objective" not in goal:
        raise TypeError("canonicalize: undefined member objective")
    return hash_canonical({"t": "pca-goal", "v": PROGRESS_VERSION, "objective": goal["objective"], "potential": goal["potential"],
                           "embedder": goal.get("embedder", ""), "metric": goal["metric"], "epsilon": goal["epsilon"],
                           "explorationBudget": goal["explorationBudget"]})


def commit_goal(goal: Any) -> Dict[str, Any]:
    """``{"goal": <detached canonical copy>, "commitment"}``."""
    c = goal_digest(goal)
    return {"goal": _snapshot(goal), "commitment": c}


def verify_goal_commitment(goal: Any, commitment: Any) -> bool:
    """Does ``goal`` hash to ``commitment``? Never raises."""
    try:
        return goal_digest(goal) == commitment
    except Exception:  # noqa: BLE001
        return False


# ---- steps and the trajectory ----

def _step_body_digest(s: Dict[str, Any]) -> str:
    return hash_canonical(dict({"t": "pca-progress-step", "v": PROGRESS_VERSION}, **s))


def state_digest(state: Any) -> str:
    """The strict hash of a state; a state outside the strict profile (-0, a long fraction, a lone surrogate) has none."""
    return hash_canonical({"t": "pca-state", "state": state})


def trajectory_head(steps: List[dict]) -> str:
    """The digest of the last step, ``genesis`` for none."""
    return _prop_strict(steps[-1], "digest") if steps else _GENESIS


def _prop_strict(o: Any, k: str) -> Any:
    """``o.k`` where a null object throws and a missing member is undefined (None here)."""
    if o is None:
        raise TypeError("Cannot read properties of null (reading '%s')" % k)
    return o.get(k) if isinstance(o, dict) else None


def progress_step_digest(step: Any) -> Any:
    """The digest a step carries."""
    return _prop_strict(step, "digest")


def trajectory_anchor_commit(salt: Any, head: Any) -> str:
    """The salted commitment to a trajectory head, appended to the transparency ledger. Raises on an empty salt or head."""
    if not _is_str(salt) or len(salt) == 0 or not _is_str(head) or len(head) == 0:
        raise TypeError("trajectoryAnchorCommit: salt and head must be non-empty strings")
    return hash_canonical({"t": TRAJECTORY_ANCHOR_DOMAIN, "salt": salt, "head": head})


def verify_trajectory_anchor(commit: Any, salt: Any, head: Any) -> bool:
    try:
        return trajectory_anchor_commit(salt, head) == commit
    except Exception:  # noqa: BLE001
        return False


def anchor_trajectory_head(ledger: Any, steps: List[dict], salt: Optional[str] = None) -> Dict[str, Any]:
    """Anchor the head of ``steps`` in ``ledger``: ``{head, salt, commit, index, ledgerHead}`` (a random 16-byte salt when none is given)."""
    head = trajectory_head(steps)
    salt = salt if salt is not None else b64u(os.urandom(16))
    commit = trajectory_anchor_commit(salt, head)
    index = ledger.append_commitment(commit)["index"]
    return {"head": head, "salt": salt, "commit": commit, "index": index, "ledgerHead": ledger.head()}


class ProgressError(Exception):
    """A denial with its ``code`` (unknown-potential, embedder-mismatch, bad-potential, ...)."""

    def __init__(self, code: str, msg: str) -> None:
        self.code = code
        super().__init__(msg)


def _resolve(goal: dict, reg: PotentialRegistry) -> dict:
    spec = reg.get(goal.get("potential"))
    if not spec:
        raise ProgressError("unknown-potential", "unknown potential %s" % goal.get("potential"))
    if (spec.get("embedder") or "") != (goal.get("embedder") or ""):
        raise ProgressError("embedder-mismatch", "embedder mismatch")
    return spec


def _potential_of(goal: dict, reg: PotentialRegistry, state: Any) -> int:
    spec = _resolve(goal, reg)
    try:
        p = spec["fn"](goal.get("objective"), state)
        _assert_int(p, "potential")
    except Exception as e:  # noqa: BLE001
        raise ProgressError("bad-potential", str(e)) from e
    if p < 0:
        raise ProgressError("bad-potential", "potential must be >= 0")
    return int(p)


def _denial_of(e: BaseException) -> str:
    return e.code if isinstance(e, ProgressError) else "bad-potential"


def _classify(pb: int, pa: int, epsilon: int) -> Dict[str, Any]:
    required = pb - epsilon
    if pa <= required or (pa == 0 and pb > 0):
        return {"mode": "progress", "charge": 0}
    charge = pa - required
    try:
        _assert_int(charge, "charge")
    except Exception as e:  # noqa: BLE001
        raise ProgressError("bad-potential", str(e)) from e
    return {"mode": "exploration", "charge": charge}


def _run_guard(g: Callable[[dict], Any], t: dict) -> bool:
    try:
        return g(t) is True  # only the value true allows; a throw or a truthy non-boolean denies
    except Exception:  # noqa: BLE001
        return False


# ---- state sources and attestations ----

class InMemoryStateSource:
    """A state source over an in-process world; its evidence is a counter record."""

    def __init__(self, initial: Any, source_id: str = "in-memory") -> None:
        self.id = source_id
        self._cur = _snapshot(initial)
        self._n = 0
        self.requests: List[dict] = []

    def apply(self, nxt: Any) -> None:
        self._cur = _snapshot(nxt)

    def observe(self, req: dict) -> Dict[str, Any]:
        self.requests.append(req)
        state = _snapshot(self._cur)
        n, self._n = self._n, self._n + 1
        return {"state": state, "state_digest": state_digest(state), "source": self.id,
                "evidence": {"kind": "in-memory", "n": n, "prior": req.get("prior_digest"), "action": req.get("action_digest")}}


def _attestation_message(a: dict, alg: Any = _UNDEF, pq_pk: Any = _UNDEF) -> bytes:
    body = canonical_bytes_strict(_bind_suite_fields({"source": a["source"], "goal_commitment": a["goal_commitment"], "action_digest": a["action_digest"],
                                                      "prior_digest": a["prior_digest"], "state_digest": a["state_digest"]}, alg, pq_pk))
    return STATE_ATTESTATION_DOMAIN.encode("utf-8") + body


def verify_state_attestation(att: Any, trusted_public_key: Any, pin: Optional[dict] = None) -> bool:
    """Verify a state source's signed attestation under its trusted Ed25519 key (a PQ or hybrid suite only under ``pin["pqPins"]``; the
    legacy unbound-PQ opt-out is not offered). Never raises."""
    try:
        if not att or not _is_obj(att) or not _is_str(att.get("sig")) or not _is_str(att.get("source")):
            return False
        if not _is_str(trusted_public_key) or len(trusted_public_key) == 0:
            return False
        alg = att.get("alg", _UNDEF)
        if suite_capability_error(alg) is not None:
            return False
        pins = pin.get("pqPins") if _is_obj(pin) else None
        return _pinned_suite_error(alg, trusted_public_key, att.get("pq_pk", _UNDEF), _attestation_message(att, alg, att.get("pq_pk", _UNDEF)),
                                   att["sig"], att.get("pq_sig", _UNDEF), pins) is None
    except Exception:  # noqa: BLE001
        return False


class AttestedStateSource:
    """A state source that signs an attestation for every observation (deterministic for Ed25519)."""

    def __init__(self, source_id: Any, signer_secret: Any, observe_state: Any, suite: Optional[dict] = None) -> None:
        if not _is_str(source_id) or len(source_id) == 0:
            raise ValueError("AttestedStateSource: id is required")
        if not isinstance(signer_secret, (bytes, bytearray)):
            raise ValueError("AttestedStateSource: signerSecret must be bytes")
        if not callable(observe_state):
            raise ValueError("AttestedStateSource: observeState must be a function")
        alg = (suite or {}).get("alg")
        if alg is not None and suite_capability_error(alg) is not None:
            raise ValueError("AttestedStateSource: unknown signature alg '%s'" % alg)
        self.id = source_id
        self._ed = KeyPair(bytes(signer_secret), allow_insecure_signer=True)
        self.public_key = self._ed.public
        self._observe_state = observe_state
        self._alg = alg
        self._pq = (suite or {}).get("pq")
        self._pq_pk = suite_pq_public_key(alg, self._pq)
        self._attestations: List[dict] = []

    @property
    def attestations(self) -> List[dict]:
        return list(self._attestations)

    def observe(self, req: dict) -> Dict[str, Any]:
        state = _snapshot(self._observe_state(req))
        sd = state_digest(state)
        stmt = {"source": self.id, "goal_commitment": req["goal_commitment"], "action_digest": req["action_digest"],
                "prior_digest": req["prior_digest"], "state_digest": sd}
        alg = _UNDEF if self._alg is None else self._alg
        fields = sign_suite_artifact(self._alg, self._ed, self._pq, _attestation_message(stmt, alg, _UNDEF if self._pq_pk is None else self._pq_pk))
        att = dict(stmt, **fields)
        self._attestations.append(att)
        return {"state": state, "state_digest": sd, "source": self.id, "evidence": att}


def attested_state_verifier(opts: dict) -> Callable[[dict], bool]:
    """A step-attestation hook over the attestations a source produced: the step's source has a trusted key, an attestation for exactly this
    transition names that source, the evidence digest is the hash of the attestation as carried, and the signature verifies."""
    by_key: Dict[str, dict] = {}
    for att in opts.get("attestations") or []:
        if _is_obj(att) and _is_str(att.get("action_digest")) and _is_str(att.get("prior_digest")) and _is_str(att.get("state_digest")):
            by_key["%s\0%s\0%s" % (att["action_digest"], att["prior_digest"], att["state_digest"])] = att

    def verify(step: dict) -> bool:
        try:
            pub = _prop(opts.get("trustedKeys"), step.get("state_source"))
            if not _is_str(pub) or len(pub) == 0:
                return False
            att = by_key.get("%s\0%s\0%s" % (step.get("action_digest"), step.get("before_digest"), step.get("after_digest")))
            if not att or att.get("source") != step.get("state_source"):
                return False
            if hash_canonical({"t": "pca-evidence", "e": att}) != step.get("evidence_digest"):
                return False
            return verify_state_attestation(att, pub, opts)
        except Exception:  # noqa: BLE001
            return False
    return verify


# ---- the tracker ----

class ProgressTracker:
    """The prover side: advances a goal's trajectory step by step, computing the mode and charge and refusing what the budget or the guard
    forbids (an exhausted exploration budget is the only denial with ``stepUp``)."""

    def __init__(self, goal: dict, commitment: str, initial: Any, registry: Any = None, guard: Optional[Callable[[dict], Any]] = None) -> None:
        if not verify_goal_commitment(goal, commitment):
            raise ValueError("goal does not match commitment")
        self.commitment = commitment
        self.goal = _snapshot(goal)
        self._guard = guard
        self._reg = _to_registry(registry)
        self._seq, self._head, self._spent = 0, _GENESIS, 0
        self._cur = _snapshot(initial)
        self._cur_digest = state_digest(self._cur)
        self._log: List[dict] = []
        _potential_of(self.goal, self._reg, self._cur)  # fail fast: unknown id / embedder / bad initial state

    @property
    def spent(self) -> int:
        return self._spent

    @property
    def remaining(self) -> int:
        return self.goal["explorationBudget"] - self._spent

    @property
    def state(self) -> Any:
        return self._cur

    @property
    def current_state_digest(self) -> str:
        return self._cur_digest

    @property
    def reached(self) -> bool:
        return _potential_of(self.goal, self._reg, self._cur) == 0

    @property
    def steps(self) -> List[dict]:
        return list(self._log)

    def step(self, after: Any, action_digest: Any) -> Dict[str, Any]:
        return self._advance(after, action_digest, "", "")

    def step_observed(self, source: Any, action_digest: Any) -> Dict[str, Any]:
        """Advance to the state a source observed (and attested); any mismatch or failure of the source is ``state-source-mismatch``."""
        try:
            obs = source.observe({"action_digest": action_digest, "goal_commitment": self.commitment, "prior_digest": self._cur_digest})
            if not obs or obs.get("source") != source.id or obs.get("state_digest") != state_digest(obs.get("state")):
                return {"ok": False, "reason": "state-source-mismatch", "stepUp": False}
            ev = obs.get("evidence")
            return self._advance(obs["state"], action_digest, source.id, hash_canonical({"t": "pca-evidence", "e": None if ev is None else ev}))
        except Exception:  # noqa: BLE001
            return {"ok": False, "reason": "state-source-mismatch", "stepUp": False}

    def _advance(self, after_in: Any, action_digest: Any, state_source: str, evidence_digest: str) -> Dict[str, Any]:
        if not _is_str(action_digest) or len(action_digest) == 0:
            return {"ok": False, "reason": "malformed", "stepUp": False}
        try:
            after = _snapshot(after_in)
            after_digest = state_digest(after)
            pb = _potential_of(self.goal, self._reg, self._cur)
            pa = _potential_of(self.goal, self._reg, after)
            cls = _classify(pb, pa, self.goal["epsilon"])
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "reason": _denial_of(e), "stepUp": False}
        if self._guard is not None and not _run_guard(self._guard, {"seq": self._seq, "before": self._cur, "after": after, "action_digest": action_digest}):
            return {"ok": False, "reason": "prohibited", "stepUp": False}
        nxt = self._spent + cls["charge"]
        if not _safe_int(nxt) or nxt > self.goal["explorationBudget"]:
            return {"ok": False, "reason": "exploration-exhausted", "stepUp": True}
        body = {"goal_commitment": self.commitment, "seq": self._seq, "before": self._cur, "after": after, "before_digest": self._cur_digest,
                "after_digest": after_digest, "action_digest": action_digest, "mode": cls["mode"], "potential_before": pb, "potential_after": pa,
                "charge": cls["charge"], "state_source": state_source, "evidence_digest": evidence_digest, "prev": self._head}
        step = dict(body, digest=_step_body_digest(body))
        self._log.append(step)
        self._seq += 1
        self._head = step["digest"]
        self._spent = nxt
        self._cur = after
        self._cur_digest = after_digest
        return {"ok": True, "step": step, "spent": self._spent, "remaining": self.remaining}


# ---- verification ----

def _fail(reason: str) -> Dict[str, Any]:
    return {"ok": False, "reason": reason}


def _is_step(s: Any) -> bool:
    return (_is_obj(s) and _is_str(s.get("goal_commitment")) and _safe_int(s.get("seq")) and s["seq"] >= 0 and _is_str(s.get("before_digest"))
            and _is_str(s.get("after_digest")) and _is_str(s.get("action_digest")) and s.get("mode") in ("progress", "exploration")
            and _safe_int(s.get("potential_before")) and _safe_int(s.get("potential_after")) and _safe_int(s.get("charge"))
            and _is_str(s.get("state_source")) and _is_str(s.get("evidence_digest")) and _is_str(s.get("prev")) and _is_str(s.get("digest"))
            and "before" in s and "after" in s)


def verify_progress_step(goal: Any, commitment: Any, step: Any, opts: Optional[dict] = None) -> Dict[str, Any]:
    """Check one step against the goal: ``{"ok": True, "charge"}`` or ``{"ok": False, "reason"}``. Options (the reference's names):
    expectedSeq, expectedPrev, expectedActionDigest, expectedBeforeDigest, expectedAfterDigest, registry, guard, trustedStateSources,
    requireAttestedState (attested state is required by default), attestation. The first failing check wins, in the reference's order."""
    opts = opts or {}
    try:
        if not verify_goal_commitment(goal, commitment):
            return _fail("goal-mismatch")
        if not _is_step(step):
            return _fail("malformed")
        if step["goal_commitment"] != commitment:
            return _fail("goal-mismatch")
        if "expectedSeq" in opts and step["seq"] != opts["expectedSeq"]:
            return _fail("seq-mismatch")
        if "expectedPrev" in opts and step["prev"] != opts["expectedPrev"]:
            return _fail("chain-break")
        if "expectedActionDigest" in opts and step["action_digest"] != opts["expectedActionDigest"]:
            return _fail("action-mismatch")
        if "expectedBeforeDigest" in opts and step["before_digest"] != opts["expectedBeforeDigest"]:
            return _fail("state-mismatch")
        if "expectedAfterDigest" in opts and step["after_digest"] != opts["expectedAfterDigest"]:
            return _fail("state-mismatch")
        body = {k: v for k, v in step.items() if k != "digest"}
        if _step_body_digest(body) != step["digest"]:
            return _fail("digest-mismatch")
        if state_digest(step["before"]) != step["before_digest"] or state_digest(step["after"]) != step["after_digest"]:
            return _fail("state-digest-mismatch")
        reg = _to_registry(opts.get("registry"))
        try:
            pb = _potential_of(goal, reg, step["before"])
            pa = _potential_of(goal, reg, step["after"])
            cls = _classify(pb, pa, goal["epsilon"])
        except Exception as e:  # noqa: BLE001
            return _fail(_denial_of(e))
        if pb != step["potential_before"] or pa != step["potential_after"]:
            return _fail("potential-mismatch")
        if step["mode"] != cls["mode"]:
            return _fail("mode-mismatch")
        if step["charge"] != cls["charge"]:
            return _fail("charge-mismatch")
        trusted = opts.get("trustedStateSources")
        if trusted is not None and step["state_source"] not in trusted:
            return _fail("untrusted-state-source")
        if opts.get("requireAttestedState") is not False and step["state_source"] == "":
            return _fail("untrusted-state-source")
        guard = opts.get("guard")
        if guard and not _run_guard(guard, {"seq": step["seq"], "before": step["before"], "after": step["after"], "action_digest": step["action_digest"]}):
            return _fail("prohibited")
        att = opts.get("attestation")
        if att:
            try:
                ok = att(step) is True
            except Exception:  # noqa: BLE001
                ok = False
            if not ok:
                return _fail("attestation-failed")
        return {"ok": True, "charge": cls["charge"]}
    except Exception:  # noqa: BLE001
        return _fail("malformed")


def verify_trajectory(goal: Any, commitment: Any, steps: Any, opts: Optional[dict] = None) -> Dict[str, Any]:
    """Check a whole trajectory: per step the step check (seq and chain link), then continuity of the state, then the exploration budget.
    ``{"ok": True, spent, remaining, reached, finalPotential, steps, head}`` or ``{"ok": False, reason, at}``. Extra options: initial,
    initialDigest (wins), expectedActionDigests."""
    opts = opts or {}
    if not verify_goal_commitment(goal, commitment):
        return {"ok": False, "reason": "goal-mismatch", "at": -1}
    if not isinstance(steps, list):
        return {"ok": False, "reason": "malformed", "at": -1}
    eads = opts.get("expectedActionDigests")
    if eads is not None and len(eads) != len(steps):
        return {"ok": False, "reason": "action-mismatch", "at": min(len(eads), len(steps))}
    try:
        anchor = opts.get("initialDigest")
        if anchor is None:
            anchor = state_digest(opts["initial"]) if "initial" in opts else None
    except Exception:  # noqa: BLE001
        return {"ok": False, "reason": "malformed", "at": -1}
    prev, spent, final_potential = _GENESIS, 0, -1
    if not steps and "initial" in opts:
        try:
            final_potential = _potential_of(goal, _to_registry(opts.get("registry")), opts["initial"])
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "reason": _denial_of(e), "at": -1}
    for i, s in enumerate(steps):
        so = dict(opts)
        so.pop("expectedActionDigest", None)
        so.update({"expectedSeq": i, "expectedPrev": prev})
        if eads is not None and i < len(eads):
            so["expectedActionDigest"] = eads[i]
        r = verify_progress_step(goal, commitment, s, so)
        if not r["ok"]:
            return {"ok": False, "reason": r["reason"], "at": i}
        if anchor is not None and s["before_digest"] != anchor:
            return {"ok": False, "reason": "discontinuous-state", "at": i}
        spent += r["charge"]
        if not _safe_int(spent) or spent > goal["explorationBudget"]:
            return {"ok": False, "reason": "budget-exceeded", "at": i}
        anchor, prev, final_potential = s["after_digest"], s["digest"], s["potential_after"]
    return {"ok": True, "spent": spent, "remaining": goal["explorationBudget"] - spent, "reached": final_potential == 0,
            "finalPotential": final_potential, "steps": len(steps), "head": prev}


# ---- signed steps ----

def _sig_message(step: dict, holder: str) -> bytes:
    return canonical_bytes_strict({"d": PROGRESS_SIG_DOMAIN, "b": {
        "holder": holder, "goal_commitment": step["goal_commitment"], "action_digest": step["action_digest"], "before_digest": step["before_digest"],
        "after_digest": step["after_digest"], "seq": step["seq"], "prev": step["prev"], "step_digest": step["digest"]}})


def sign_progress_step(step: dict, secret_key: bytes, holder_public_key: str) -> Dict[str, Any]:
    """``{"step", "holder", "sig"}``: Ed25519 over the domain-separated binding of the step to the holder. The key is not checked against
    the holder name."""
    return {"step": step, "holder": holder_public_key,
            "sig": b64u(KeyPair(bytes(secret_key), allow_insecure_signer=True).sign(_sig_message(step, holder_public_key)))}


def _signed_shape(s: Any) -> bool:
    return _is_obj(s) and _is_str(s.get("holder")) and _is_str(s.get("sig")) and _is_step(s.get("step"))


def verify_signed_progress_step(goal: Any, commitment: Any, signed: Any, opts: dict) -> Dict[str, Any]:
    """The holder's signature (shape, holder, action, goal, signature, in this order), then the unsigned step check."""
    try:
        if not _signed_shape(signed):
            return _fail("malformed")
        if signed["holder"] != opts.get("expectedHolder"):  # an absent option is undefined: nothing equals it
            return _fail("holder-mismatch")
        if signed["step"]["action_digest"] != opts.get("expectedActionDigest"):
            return _fail("action-mismatch")
        if signed["step"]["goal_commitment"] != commitment:
            return _fail("goal-mismatch")
        if not verify_b64u(signed["holder"], _sig_message(signed["step"], signed["holder"]), signed["sig"]):
            return _fail("bad-signature")
        return verify_progress_step(goal, commitment, signed["step"], opts)
    except Exception:  # noqa: BLE001
        return _fail("malformed")


def verify_signed_trajectory(goal: Any, commitment: Any, signed: Any, opts: dict) -> Dict[str, Any]:
    """Every signature (shape, holder, action, signature per step), then the trajectory check over the unsigned steps."""
    if not isinstance(signed, list):
        return {"ok": False, "reason": "malformed", "at": -1}
    eads = opts["expectedActionDigests"]
    if len(eads) != len(signed):
        return {"ok": False, "reason": "action-mismatch", "at": min(len(eads), len(signed))}
    for i, sp in enumerate(signed):
        try:
            if not _signed_shape(sp):
                return {"ok": False, "reason": "malformed", "at": i}
            if sp["holder"] != opts["expectedHolder"]:
                return {"ok": False, "reason": "holder-mismatch", "at": i}
            if sp["step"]["action_digest"] != eads[i]:
                return {"ok": False, "reason": "action-mismatch", "at": i}
            if not verify_b64u(sp["holder"], _sig_message(sp["step"], sp["holder"]), sp["sig"]):
                return {"ok": False, "reason": "bad-signature", "at": i}
        except Exception:  # noqa: BLE001
            return {"ok": False, "reason": "malformed", "at": i}
    return verify_trajectory(goal, commitment, [s["step"] for s in signed], {k: v for k, v in opts.items() if k != "expectedHolder"})
