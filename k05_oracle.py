"""Replay harness for the shared k05 TS-generated differential oracles (testdata/k05-<module>.json.gz; generators in the
flagship tools/pca-audit/k05-oracles). Case = {fn, name, args, out}: bytes are {"$bytes": b64url}, a reference throw is
{"$throws": msg, code?} (the same code is required when present, else any refusal); fn names ending in "@suspect" are
reported, never failed. Each test_k05_*_diff.py maps fn -> the atlas_pca twin and calls run()."""
from array import array
import base64
import gzip
import json
import os
import re
import warnings
from collections.abc import Mapping, Sequence

HERE = os.path.dirname(os.path.abspath(__file__))


_FN_RE = re.compile(rb'\{"fn":("(?:[^"\\]|\\.)*")')
_SEP = b',"cases":[\n'
_INDEXES = {}  # path -> _Index: the raw text of every case, read once


class _Index:
    """A corpus as it sits on disk: ONE bytes buffer (the cases are the lines of its "cases" array) plus the offsets of each line and the
    case indexes of each fn. Nothing is JSON-decoded here, so a process that imports every test module (the parent of a forking
    mutation runner) holds only the raw text, shared copy-on-write with its children; a case is decoded when a test touches it."""

    def __init__(self, path):
        with gzip.open(path, "rb") as fh:
            buf = fh.read()
        i = buf.find(_SEP)
        assert i >= 0, "%s: no cases array" % path
        self.count = json.loads(buf[:i] + b',"cases":[]}')["count"]
        self.buf, self.starts, self.ends, self.by_fn = buf, array("Q"), array("Q"), {}
        pos, end = i + len(_SEP), len(buf)
        while pos < end and buf[pos] != 0x5D:  # "]" closes the array
            nl = buf.find(b"\n", pos)
            stop = nl if nl >= 0 else end
            e = stop - 1 if buf[stop - 1] == 0x2C else stop  # a line ends with "," except the last one
            m = _FN_RE.match(buf, pos)
            assert m and buf[e - 1] == 0x7D, "%s: case %d is not one line starting with its fn" % (path, len(self.starts))
            self.by_fn.setdefault(json.loads(m.group(1)), array("I")).append(len(self.starts))
            self.starts.append(pos)
            self.ends.append(e)
            pos = stop + 1
        assert len(self.starts) == self.count, "%s: %d cases, count says %d" % (path, len(self.starts), self.count)


class _Cases(Sequence):
    """The cases of one fn, each decoded when it is first indexed. Iterating decodes without caching, so a test that walks 20k cases
    holds one at a time."""

    def __init__(self, corpus, ids):
        self._corpus, self._ids = corpus, ids

    def __len__(self):
        return len(self._ids)

    def __getitem__(self, i):
        if isinstance(i, slice):
            return [self[j] for j in range(*i.indices(len(self)))]
        return self._corpus.case(self._ids[i], keep=True)

    def __iter__(self):
        return (self._corpus.case(j) for j in self._ids)


class _LazyCases(Mapping):
    """{fn: cases} over an _Index with the interface of the dict `load` used to return."""

    def __init__(self, ix):
        self._ix, self._kept = ix, {}

    def case(self, j, keep=False):
        if j in self._kept:
            return self._kept[j]
        ix = self._ix
        c = json.loads(ix.buf[ix.starts[j]:ix.ends[j]], parse_int=lambda t: -0.0 if t == "-0" else int(t))
        if keep:
            self._kept[j] = c
        return c

    def __getitem__(self, fn):
        return _Cases(self, self._ix.by_fn[fn])

    def __iter__(self):
        return iter(self._ix.by_fn)

    def __len__(self):
        return len(self._ix.by_fn)

    def __contains__(self, fn):
        return fn in self._ix.by_fn


def load(module):
    """(count, {fn: [case, ...]}) of testdata/k05-<module>.json.gz; JSON -0 stays -0.0. The corpus is read once and kept as raw text; a
    case is decoded only when a test touches it (see _Index)."""
    path = os.path.join(HERE, "testdata", "k05-%s.json.gz" % module)
    if path not in _INDEXES:
        _INDEXES[path] = _Index(path)
    return _INDEXES[path].count, _LazyCases(_INDEXES[path])


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
