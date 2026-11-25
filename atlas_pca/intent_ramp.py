"""Trust ramp and drift: start narrow, widen only through confirmed behaviour, veto on every negative runtime signal, and
a one-sided Bernoulli CUSUM that freezes widening on drift. Native port of the TypeScript reference
(@atlasauth/pca-intent). A "learner" is any object with .cells(), .admits_outcome(o) and .observe(o, y, source)."""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from .detmath import det_ln
from .intent_omega import js_max


def signal_label(s: Any) -> int:
    return 1 if s == "jit-approve" or s == "principal-confirm" else 0


def narrow_start(omega: dict, slots: dict, opts: Optional[dict] = None) -> dict:
    """The narrow starting configuration for a learner that will be ramped."""
    opts = opts or {}
    slot_mass = opts.get("slotNullMass")
    other_mass = opts.get("otherNullMass")
    null_mass: Dict[str, float] = {}
    for vs in omega["verbs"]:
        if vs["verb"] in slots["verbs"]:
            null_mass[vs["verb"]] = 0.5 if slot_mass is None else slot_mass
        else:
            null_mass[vs["verb"]] = 0.95 if other_mass is None else other_mass
    return {"eta": 0, "tau": 1, "nullMass": null_mass}


def _fresh() -> Dict[str, Any]:
    return {"statistic": 0, "alarm": False, "informative": 0, "divergences": 0}


class DriftDetector:
    def __init__(self, o: Optional[dict] = None):
        o = o or {}
        self.rho0 = 0.02 if o.get("rho0") is None else o["rho0"]
        self.rho1 = 0.25 if o.get("rho1") is None else o["rho1"]
        self.h = det_ln(100) if o.get("h") is None else o["h"]  # det_ln, not math.log: the drift decision (S > h) must not depend on a platform's libm
        if not (0 < self.rho0 < self.rho1 < 1):
            raise ValueError("DriftDetector: need 0 < rho0 < rho1 < 1")
        if not (self.h > 0):
            raise ValueError("DriftDetector: h must be positive")
        self._s = _fresh()

    def update(self, diverged: bool) -> Dict[str, Any]:
        """Feed one signal about an action that was inside the grant: diverged = True for a negative signal."""
        inc = det_ln(self.rho1 / self.rho0) if diverged else det_ln((1 - self.rho1) / (1 - self.rho0))
        statistic = js_max(0, self._s["statistic"] + inc)
        self._s = {"statistic": statistic, "alarm": self._s["alarm"] or statistic >= self.h,
                   "informative": self._s["informative"] + 1, "divergences": self._s["divergences"] + (1 if diverged else 0)}
        return self.state

    @property
    def state(self) -> Dict[str, Any]:
        return dict(self._s)

    def reset(self) -> None:
        self._s = _fresh()


class TrustRamp:
    def __init__(self, learner: Any, drift: Optional[dict] = None):
        self._l = learner
        self.drift = DriftDetector(drift)
        self._queued: List[dict] = []
        self.log: List[dict] = []

    @property
    def learner(self) -> Any:
        return self._l

    @property
    def frozen(self) -> bool:
        """Widening is frozen while a drift alarm stands."""
        return self.drift.state["alarm"]

    @property
    def pending(self) -> List[dict]:
        """Positive signals held back by a freeze (released only by rebase)."""
        return self._queued

    def _grant_size(self) -> int:
        return sum(1 for c in self._l.cells() if c["inGrant"])

    def record(self, o: dict, signal: str) -> dict:
        y = signal_label(signal)
        was_in_grant = self._l.admits_outcome(o)
        before = self._grant_size()
        drift = self.drift.state
        if was_in_grant:
            drift = self.drift.update(y == 0)
        applied = True
        if y == 1 and self.frozen:
            self._queued.append({"o": o, "signal": signal})
            applied = False
        else:
            self._l.observe(o, y, "runtime")
        rec = {"signal": signal, "y": y, "wasInGrant": was_in_grant, "before": before, "after": self._grant_size(), "applied": applied, "drift": drift}
        self.log.append(rec)
        return rec

    def record_observation(self, obs: dict, ctx: dict) -> dict:
        """Record a SIGNED runtime observation: the signature must verify (ctx["verify_observation"] is the core observation
        verifier, returning {ok, reason?}), the signer must be trusted and the observation must be about this map."""
        verify = ctx.get("verify_observation")
        if verify is None:
            return {"ok": False, "reason": "no observation verifier configured"}
        v = verify(obs, ctx.get("verify") or {})
        if not v["ok"]:
            return {"ok": False, "reason": v["reason"]}
        if obs.get("signer") not in ctx["trustedSigners"]:
            return {"ok": False, "reason": "untrusted observation signer"}
        if obs.get("map_digest") != ctx["mapDigest"]:
            return {"ok": False, "reason": "observation is about a different map"}
        if obs.get("source") != "runtime":
            return {"ok": False, "reason": "only runtime observations feed the ramp"}
        sig = "principal-confirm" if obs.get("y") == 1 else "postcondition-violation"
        return {"ok": True, "record": self.record({"verb": obs["verb"], "values": obs["values"]}, sig)}

    def rebase(self, nxt: Any) -> None:
        """Re-base on a new, signed intent statement (the only way to clear an alarm); queued positive signals are discarded."""
        self._l = nxt
        self._queued = []
        self.drift.reset()
