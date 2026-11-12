"""Replay harness for the shared k05 TS-generated differential oracles (testdata/k05-<module>.json.gz; generators in the
flagship tools/pca-audit/k05-oracles). Case = {fn, name, args, out}: bytes are {"$bytes": b64url}, a reference throw is
{"$throws": msg, code?} (the same code is required when present, else any refusal); fn names ending in "@suspect" are
reported, never failed. Each test_k05_*_diff.py maps fn -> the atlas_pca twin and calls run()."""
import base64
import gzip
import json
import os
import warnings
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))


def load(module):
    """(count, {fn: [case, ...]}) of testdata/k05-<module>.json.gz; JSON -0 stays -0.0."""
    with gzip.open(os.path.join(HERE, "testdata", "k05-%s.json.gz" % module), "rt", encoding="utf-8") as fh:
        d = json.load(fh, parse_int=lambda t: -0.0 if t == "-0" else int(t))
    out = defaultdict(list)
    for c in d["cases"]:
        out[c["fn"]].append(c)
    assert len(d["cases"]) == d["count"]
    return d["count"], dict(out)


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b):
    return base64.urlsafe_b64encode(bytes(b)).rstrip(b"=").decode("ascii")


def dec(v):
    """Oracle JSON -> Python: {"$bytes": b64url} -> bytes, recursively."""
    if isinstance(v, dict):
        if len(v) == 1 and "$bytes" in v:
            return b64d(v["$bytes"])
        return {k: dec(x) for k, x in v.items()}
    if isinstance(v, list):
        return [dec(x) for x in v]
    return v


def norm(v):
    """Python result -> the oracle's JSON form: bytes -> {"$bytes"}, tuples/sets -> lists, an integral float -> int (JS has
    one number type), inf/nan -> {"$num"}. Key order is irrelevant (compare() sorts keys)."""
    if isinstance(v, (bytes, bytearray, memoryview)):
        return {"$bytes": b64e(v)}
    if isinstance(v, dict):
        return {str(k): norm(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [norm(x) for x in v]
    if isinstance(v, (set, frozenset)):
        return sorted(norm(x) for x in v)
    if isinstance(v, float):
        if v != v:
            return {"$num": "NaN"}
        if v in (float("inf"), float("-inf")):
            return {"$num": "Infinity" if v > 0 else "-Infinity"}
        if v.is_integer() and abs(v) <= 2 ** 64:
            return int(v)
    return v


def canon(v):
    return json.dumps(norm(v), sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def throws(out):
    return isinstance(out, dict) and "$throws" in out


def clip(v, prefix):
    """Every string starting with `prefix` cut to it (the case's textPrefix: the rest is language-specific error text)."""
    if isinstance(v, str):
        return prefix if v.startswith(prefix) else v
    if isinstance(v, dict):
        return {k: clip(x, prefix) for k, x in v.items()}
    if isinstance(v, list):
        return [clip(x, prefix) for x in v]
    return v


def _fail_closed(v):
    """A caught runtime error's text after "(fail closed): " is the language's own message: compare up to the marker."""
    if isinstance(v, str):
        i = v.find("(fail closed): ")
        return v if i < 0 else v[: i + 15]
    if isinstance(v, dict):
        return {k: _fail_closed(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_fail_closed(x) for x in v]
    return v


def _equal(got, out, c, compare):
    if c.get("cmp") == "code" and isinstance(out, str) and ": " in out:
        # the reference's caught exception text: only the "<code>: " prefix is portable
        return isinstance(got, str) and got.startswith(out[: out.index(": ") + 2])
    got, out = _fail_closed(got), _fail_closed(out)
    if "textPrefix" in c:
        got, out = clip(norm(got), c["textPrefix"]), clip(out, c["textPrefix"])
    return compare(got, out, c) if compare is not None else canon(got) == canon(out)


def run(cases, call, compare=None, refused=None, skip=None, limit=25):
    """Replay `cases` through call(*args) (args already decoded). Exact canonical-JSON equality unless `compare(got, out, case)`
    is given (returns True when equal). A reference throw requires a native exception (with the same `.code` when the case
    has one) or, when `refused(got, case)` is given and true, a refusal value. `skip(case)` -> reason string skips a case.
    Returns (ran, skipped); fails listing up to `limit` mismatches."""
    bad, ran, skipped = [], 0, 0
    for c in cases:
        if skip is not None:
            why = skip(c)
            if why:
                skipped += 1
                continue
        ran += 1
        out = c["out"]
        args = dec(c["args"])
        try:
            got = call(*args)
        except Exception as e:  # noqa: BLE001 - any native refusal is compared against the reference
            if not throws(out):
                bad.append((c["name"], "raised %s: %s" % (type(e).__name__, e), out))
            elif "code" in out and getattr(e, "code", None) != out["code"]:
                bad.append((c["name"], "raised code %r: %s" % (getattr(e, "code", None), e), out))
            continue
        if throws(out):
            if refused is None or not refused(got, c):
                bad.append((c["name"], "returned %s" % canon(got)[:300], out))
            continue
        if not _equal(got, out, c, compare):
            bad.append((c["name"], "got %s" % canon(got)[:400], canon(out)[:400]))
    if c_suspect(cases):
        if bad:
            warnings.warn("@suspect cases differ (reported, not failed): %d, e.g. %r" % (len(bad), bad[:3]))
        return ran, skipped
    assert not bad, "%d of %d differ from the TS reference:\n" % (len(bad), ran) + "\n".join(
        "  %s\n    native: %s\n    ref:    %s" % (n, g, str(o)[:400]) for n, g, o in bad[:limit])
    return ran, skipped


def c_suspect(cases):
    return bool(cases) and cases[0]["fn"].endswith("@suspect")
