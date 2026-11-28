"""Regions: the part of the outcome space a cell question was about, written in value terms so an observation keeps its
meaning when the space is refined. Native port of the TypeScript reference (@atlasauth/pca-intent)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .intent_omega import _at, cat_cell_of, cat_rep, num_cells, is_number


def region_of_cell(vs: dict, idx: List[int]) -> dict:
    dims: Dict[str, Any] = {}
    for k, d in enumerate(vs["dims"]):
        if d["kind"] == "num":
            c = _at(num_cells(d), idx[k])
            dims[d["path"]] = {"kind": "num", "lo": c["lo"], "hi": c["hi"]}
        else:
            dims[d["path"]] = {"kind": "cat", "values": [dict(v) for v in d["values"]], "cells": [idx[k]]}
    return {"verb": vs["verb"], "dims": dims}


def restrict_region(r: dict, d: dict, part: dict) -> dict:
    dims = dict(r["dims"])
    if d["kind"] == "num" and "lo" in part:
        dims[d["path"]] = {"kind": "num", "lo": part["lo"], "hi": part["hi"]}
    elif d["kind"] == "cat" and "cells" in part:
        dims[d["path"]] = {"kind": "cat", "values": [dict(v) for v in d["values"]], "cells": list(part["cells"])}
    else:
        raise ValueError("restrictRegion: part does not match the kind of %s" % d["path"])
    return {"verb": r["verb"], "dims": dims}


def _ref_dim(path: str, rd: dict) -> dict:
    return {"kind": "cat", "path": path, "values": rd["values"]}


def dim_cells_in(d: dict, rd: Optional[dict], mode: str) -> List[int]:
    """The cells of dimension d covered by the region dimension: 'inner' (wholly inside) or 'outer' (meeting it)."""
    n = len(num_cells(d)) if d["kind"] == "num" else len(d["values"])
    all_ = list(range(n))
    if not rd:
        return all_
    if d["kind"] == "num":
        if rd["kind"] != "num":
            raise ValueError("region: %s is numeric in Ω but categorical in the region" % d["path"])
        cells = num_cells(d)
        out = []
        for i in all_:
            c = cells[i]
            ok = (c["lo"] >= rd["lo"] and c["hi"] <= rd["hi"]) if mode == "inner" else (c["hi"] >= rd["lo"] and c["lo"] <= rd["hi"])
            if ok:
                out.append(i)
        return out
    if rd["kind"] != "cat":
        raise ValueError("region: %s is categorical in Ω but numeric in the region" % d["path"])
    ref = _ref_dim(d["path"], rd)
    in_set = set(rd["cells"])
    return [i for i in all_ if cat_cell_of(ref, cat_rep(d, i)) in in_set]


def region_cells(vs: dict, r: dict, mode: str) -> List[int]:
    """Flat cell indices of vs covered by the region (row-major, last dimension fastest); refuses a restriction the space lacks."""
    if r["verb"] != vs["verb"]:
        raise ValueError("region: verb %s does not match %s" % (r["verb"], vs["verb"]))
    for p in r["dims"]:
        if not any(d["path"] == p for d in vs["dims"]):
            raise ValueError("region: restricts %s, which Ω has no dimension for" % p)
    per = [dim_cells_in(d, r["dims"].get(d["path"]), mode) for d in vs["dims"]]
    if any(len(x) == 0 for x in per):
        return []
    sizes = [len(num_cells(d)) if d["kind"] == "num" else len(d["values"]) for d in vs["dims"]]
    acc = [0]
    for k, cells in enumerate(per):
        acc = [f * sizes[k] + c for f in acc for c in cells]
    return acc


def value_in_region_dim(path: str, rd: dict, x: Any) -> bool:
    if rd["kind"] == "num":
        return is_number(x) and x >= rd["lo"] and x <= rd["hi"]
    return isinstance(x, str) and cat_cell_of(_ref_dim(path, rd), x) in rd["cells"]
