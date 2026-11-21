"""Runtime drift monitoring, tighten-only (the TypeScript reference is @atlasauth/pca-goal `drift`). A monitor compares the action
stream to the goal's expected profile (verbs, resources, magnitude, rate, novelty). Anomalies convert Allow to Escalate; the strike
counter is a ratchet (never decreases); at `lockdown` strikes every Allow becomes Escalate. `apply_drift` never relaxes a decision."""
import hashlib
import hmac
import re
from typing import Any, Dict, List, Optional

from .analyzer_js import UNDEF, includes, jget, js_json, js_str, req_list
from .goal_examples import decide_case

__all__ = ["DEFAULT_DRIFT", "expected_verbs", "DriftMonitor", "apply_drift", "guarded_decide"]

DEFAULT_DRIFT = {"windowMs": 60_000, "maxPerWindow": 20, "maxNovel": 3, "magnitudeFactor": 3, "warmup": 5, "lockdown": 5}


def expected_verbs(g: Any) -> set:
    return set(jget(x, "verb") for x in req_list(jget(g, "grants")))


def _res_ids(s: Any) -> List[Any]:
    k = jget(s, "k")
    if k == "exact":
        return [jget(s, "id")]
    if k == "oneof":
        return list(req_list(jget(s, "ids")))
    if k == "all_of":
        return [y for p in req_list(jget(s, "parts")) for y in _res_ids(p)]
    return []


def _known_resources(g: Any) -> set:
    return set(y for x in req_list(jget(g, "grants")) for y in _res_ids(jget(x, "res")))


def _node_hex(s: str) -> bytes:
    """Node's lenient Buffer.from(s, 'hex'): decoding stops at the first invalid pair."""
    if not isinstance(s, str):
        raise TypeError("the first argument must be a string")
    out = bytearray()
    for i in range(0, len(s) - 1, 2):
        pair = s[i:i + 2]
        if not re.fullmatch("[0-9a-fA-F]{2}", pair):
            break
        out.append(int(pair, 16))
    return bytes(out)


class DriftMonitor:
    def __init__(self, goal: Any, opts: Optional[dict] = None):
        self.goal = goal
        self.o = dict(DEFAULT_DRIFT, **(opts or {}))
        self.st: Dict[str, Any] = {"strikes": 0, "times": [], "novel": [], "seen": {}}

    def observe(self, a: Any, t: Any) -> Dict[str, Any]:
        reasons: List[str] = []
        o = self.o
        verb = jget(a, "verb")
        if not any(verb == v for v in expected_verbs(self.goal)):
            reasons.append("verb %s outside the goal profile" % js_str(verb))
        known = _known_resources(self.goal)
        res = jget(a, "res")
        if len(known) > 0 and res not in known and not includes(self.st["novel"], res):
            self.st["novel"].append(res)
        if len(self.st["novel"]) > o["maxNovel"]:
            reasons.append("novel resources beyond the allowance")
        self.st["times"] = [x for x in self.st["times"] if x > t - o["windowMs"]] + [t]
        if len(self.st["times"]) > o["maxPerWindow"]:
            reasons.append("rate above the profile")
        params = jget(a, "params")
        for p, l in list(params.items()):
            if jget(l, "k") != "q":
                continue
            hist = self.st["seen"].get(p, [])
            v = jget(jget(l, "q"), "n")
            if len(hist) >= o["warmup"]:
                mean = sum(hist) / len(hist) if hist else float("nan")  # warmup 0: 0 / 0 is NaN, never above
                if mean > 0 and v > mean * o["magnitudeFactor"]:
                    reasons.append("%s magnitude %sx above the running mean" % (p, js_str(o["magnitudeFactor"])))
            self.st["seen"][p] = (hist + [v])[-50:]
        if reasons:
            self.st["strikes"] += 1  # ratchet: only ever increases
        return {"anomalous": len(reasons) > 0, "strikes": self.st["strikes"], "lockdown": self.st["strikes"] >= o["lockdown"], "reasons": reasons}

    def state(self) -> Dict[str, Any]:
        return self.st

    def _mac(self, state: Any, key: bytes) -> bytes:
        return hmac.new(bytes(key), js_json(state).encode("utf-8"), hashlib.sha256).digest()

    def seal(self, key: bytes) -> Dict[str, Any]:
        """Sealed state: durable and not agent-writable (the monitor key is held outside the agent)."""
        return {"state": self.st, "mac": self._mac(self.st, key).hex()}

    @staticmethod
    def restore(goal: Any, sealed: Any, key: bytes, opts: Optional[dict] = None) -> "DriftMonitor":
        """Restore; a state that fails its MAC locks down (fail closed)."""
        m = DriftMonitor(goal, opts)
        want = m._mac(jget(sealed, "state"), key)
        got = _node_hex(jget(sealed, "mac"))
        if len(got) == len(want) and hmac.compare_digest(got, want):
            m.st = jget(sealed, "state")
        else:
            m.st = {"strikes": m.o["lockdown"], "times": [], "novel": [], "seen": {}}
        return m


def apply_drift(d: str, s: Any) -> str:
    """Tighten-only: Allow becomes Escalate on an anomaly or lockdown; nothing else changes."""
    return "escalate" if d == "allow" and (jget(s, "anomalous") or jget(s, "lockdown")) else d


def guarded_decide(goal: Any, ont: Any, mon: DriftMonitor, c: Any, t: Any) -> Dict[str, Any]:
    """Decide, observe, tighten."""
    base = decide_case(goal, ont, c)["decision"]
    signal = mon.observe(jget(c, "act"), t)
    return {"decision": apply_drift(base, signal), "signal": signal}
