"""Specification by example for a fixed grant: boundary, verb and unconstrained witness actions to ask the principal
about. Native port of the TypeScript reference (@atlasauth/pca-intent)."""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Sequence

from .intent_omega import cell_rep, cell_stats, decode_cell, encode_cell, num_cells, u16key, verb_cell_count
from .intent_policy import admitter
from .intent_render import render_question


def boundary_witnesses(grant: Any, omega: dict, catalog: Any = None) -> List[dict]:
    g = admitter(grant)
    out: List[dict] = []
    seen: set = set()

    def push(vs: dict, kind: str, idx: List[int], allows: bool, facet: str) -> None:
        key = "%s|%s" % (vs["verb"], ",".join(str(i) for i in idx))
        if key in seen:
            return
        seen.add(key)
        out.append({"kind": kind, "side": "inside" if allows else "outside", "verb": vs["verb"], "cell": idx,
                    "outcome": cell_rep(vs, idx), "grantAllows": allows, "facet": facet, "question": render_question(vs, idx, catalog)})

    for vs in omega["verbs"]:
        n = verb_cell_count(vs)
        acc = [0] * n
        mass = [0.0] * n
        typical = -1
        typical_out = -1
        for c in range(n):
            idx = decode_cell(vs, c)
            acc[c] = 1 if g.admits(vs, cell_rep(vs, idx)) else 0
            mass[c] = cell_stats(vs, idx)["mass"]
            if acc[c] and (typical < 0 or mass[c] > mass[typical]):
                typical = c
            if typical_out < 0 or mass[c] > mass[typical_out]:
                typical_out = c
        if typical < 0:
            push(vs, "verb", decode_cell(vs, typical_out), False, "%s|verb" % vs["verb"])
            continue
        base = decode_cell(vs, typical)
        push(vs, "verb", base, True, "%s|verb" % vs["verb"])
        best: Dict[str, dict] = {}
        for c in range(n):
            if not acc[c]:
                continue
            idx = decode_cell(vs, c)
            for k, d in enumerate(vs["dims"]):
                nk = len(num_cells(d)) if d["kind"] == "num" else len(d["values"])
                if d["kind"] == "num":
                    neigh = [x for x in (idx[k] - 1, idx[k] + 1) if 0 <= x < nk]
                else:
                    neigh = [x for x in range(nk) if x != idx[k]]
                for x in neigh:
                    j = list(idx)
                    j[k] = x
                    if acc[encode_cell(vs, j)]:
                        continue
                    facet = "%s|%s|%d~%d" % (vs["verb"], d["path"], min(x, idx[k]), max(x, idx[k])) if d["kind"] == "num" \
                        else "%s|%s|%d" % (vs["verb"], d["path"], x)
                    shared = sum(1 for t, v in enumerate(idx) if t != k and v == base[t])
                    score = shared * 10 + mass[c]
                    prev = best.get(facet)
                    if prev is None or score > prev["score"]:
                        best[facet] = {"ins": idx, "outs": j, "score": score}
        for facet in sorted(best, key=u16key):
            b = best[facet]
            push(vs, "boundary", b["ins"], True, facet)
            push(vs, "boundary", b["outs"], False, facet)
        for k, d in enumerate(vs["dims"]):
            nk = len(num_cells(d)) if d["kind"] == "num" else len(d["values"])
            if nk < 2:
                continue
            depends = False
            c = 0
            while c < n and not depends:
                idx = decode_cell(vs, c)
                x = 0
                while x < nk and not depends:
                    j = list(idx)
                    j[k] = x
                    if acc[encode_cell(vs, j)] != acc[c]:
                        depends = True
                    x += 1
                c += 1
            if depends:
                continue
            j = list(base)
            if d["kind"] == "num":
                j[k] = nk - 1
            else:
                j[k] = next((i for i, v in enumerate(d["values"]) if v["kind"] == "other"), -1)
            push(vs, "unconstrained", j, True, "%s|%s|unconstrained" % (vs["verb"], d["path"]))
    return out


def check_witnesses(witnesses: Sequence[dict], oracle: Callable[[dict], bool]) -> dict:
    """Ask an oracle (the principal) about each witness; a mismatch is a place where grant and intent disagree."""
    return {"questions": len(witnesses), "mismatches": [w for w in witnesses if oracle(w) is not w["grantAllows"]]}
