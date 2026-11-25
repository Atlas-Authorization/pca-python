"""Provenance on the wallet side and within-grant regret: the fixed banner for a tainted value, the provenance friction
floor and the regret report. Native port of the TypeScript reference (@atlasauth/pca-intent). A regret case is a dict
{feasible, chosen, admits, utility} with callables for admits / utility."""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

_FRICTION_ORDER = ["tap", "hold", "typed", "device"]


def provenance_banner(level: Any, what: str = "value") -> Optional[str]:
    """The fixed banner for a tainted value (None for trusted / first-party values)."""
    if level == "web":
        return "This %s was suggested by content on the page, not by you." % what
    if level == "agent":
        return "This %s came from your agent, not from you or the site." % what
    if level == "tool":
        return "This %s came from another service, not from you or this site." % what
    return None


def is_tainted(level: Any) -> bool:
    return level == "tool" or level == "web" or level == "agent"


def provenance_friction(base: Any, sensitivity: Any, level: Any) -> Optional[str]:
    """A tainted critical value is at least typed, a tainted material value at least hold; provenance only raises friction."""
    floor = "tap" if not is_tainted(level) else "typed" if sensitivity == "critical" else "hold"
    ib = _FRICTION_ORDER.index(base) if base in _FRICTION_ORDER else -1
    i = max(ib, _FRICTION_ORDER.index(floor))
    return _FRICTION_ORDER[i] if i >= 0 else None


def within_grant_regret(c: dict) -> Dict[str, Any]:
    """Only options inside the effective grant compete; a chosen option outside it is denied (risk, not regret)."""
    admitted = c["admits"](c["chosen"])
    best = None
    best_u = -math.inf
    for o in c["feasible"]:
        if not c["admits"](o):
            continue
        u = c["utility"](o)
        if u > best_u:
            best_u = u
            best = o
    if not admitted or best is None:
        return {"regret": 0, "best": best, "admitted": admitted}
    d = best_u - c["utility"](c["chosen"])
    return {"regret": d if d != d or d > 0 else 0, "best": best, "admitted": admitted}


def regret_report(cases: List[dict], scale: float = 1) -> Dict[str, Any]:
    admitted = 0
    positive = 0
    s = 0.0
    mx = 0
    for c in cases:
        r = within_grant_regret(c)
        if not r["admitted"]:
            continue
        admitted += 1
        s += r["regret"]
        if r["regret"] > 0:
            positive += 1
        if r["regret"] > mx:
            mx = r["regret"]
    mean = s / admitted if admitted else 0
    return {"cases": len(cases), "admitted": admitted, "positive": positive, "mean": mean, "max": mx,
            "regret_est_ppm": int(math.floor((mean / (scale if scale > 0 else 1)) * 1000000 + 0.5))}
