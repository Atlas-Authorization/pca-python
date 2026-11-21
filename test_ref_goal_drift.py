"""Differential replay of the TypeScript reference (@atlasauth/pca-goal drift and crc): the tighten-only drift monitor (driven through a
step script, as the monitor is stateful), conformal risk control numerics and the fidelity report."""
import copy

import pytest

from atlas_pca import goal_crc as C
from atlas_pca import goal_drift as D
from base_oracle import b64d, load_ref, run

COUNT, BY_FN = load_ref("goal-drift")


def _flow(goal, opts, steps):
    mon = D.DriftMonitor(goal, opts or {})
    last = None
    out = []
    for s in steps:
        op = s["op"]
        if op == "observe":
            out.append(mon.observe(s["act"], s["t"]))
        elif op == "state":
            out.append(copy.deepcopy(mon.state()))
        elif op == "seal":
            last = copy.deepcopy(mon.seal(b64d(s["key"])))
            out.append(last)
        elif op == "restoreLast":
            sealed = copy.deepcopy(last)
            if s.get("mode") == "state":
                sealed["state"]["strikes"] = 0
            if s.get("mode") == "mac":
                sealed["mac"] = ("1" if sealed["mac"][0] == "0" else "0") + sealed["mac"][1:]
            if s.get("mode") == "badmac":
                sealed["mac"] = "zz"
            mon = D.DriftMonitor.restore(goal, sealed, b64d(s["key"]), opts or {})
            out.append(copy.deepcopy(mon.state()))
        elif op == "guarded":
            r = D.guarded_decide(goal, s["ont"], mon, s["case"], s["t"])
            out.append({"decision": r["decision"], "signal": r["signal"]})
    return out


def _calibrate(losses, alpha, gate):
    g = None if gate == "none" else (lambda k, n: C.cp_upper95(k, n) <= float(gate[2:]) / 1e5)
    return C.calibrate(losses, alpha, g)


FNS = {
    "flow": _flow, "applyDrift": D.apply_drift, "alphaOf": C.alpha_of, "calibrate": _calibrate, "assertMonotone": C.assert_monotone,
    "cpUpper95": C.cp_upper95, "renderReportMarkdown": C.render_report_markdown,
}


def test_every_function_is_covered():
    assert set(BY_FN) == set(FNS)


@pytest.mark.parametrize("fn", sorted(FNS))
def test_matches_reference(fn):
    ran, _ = run(BY_FN[fn], FNS[fn])
    assert ran == len(BY_FN[fn])
