"""Replay harness for the shared base TS-generated differential oracles (testdata/base-<module>.json.gz; generators in the
flagship tools/pca-audit/oracles-base). Case = {fn, name, args, out}: bytes are {"$bytes": b64url}, a reference throw is
{"$throws": msg, code?} (the same code is required when present, else any refusal); fn names ending in "@suspect" are
reported, never failed. Each test_base_*_diff.py maps fn -> the atlas_pca twin and calls run()."""
from array import array
import base64
import decimal
import gzip
import hashlib
import json
import os
import re
import time
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
        head = json.loads(buf[:i] + b',"cases":[]}')  # count and the shared string table sit before the cases
        self.count, self.blobs, self.clock_ms = head["count"], head.get("blobs"), head.get("clockMs")  # clockMs: the generator's frozen clock
        self.clock_cases = frozenset(head.get("clockCases") or ())  # the cases whose expected result depends on that clock
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


def _index(path):
    if path not in _INDEXES:
        _INDEXES[path] = _Index(path)
    return _INDEXES[path]


class _Cases(Sequence):
    """The cases of one fn, each decoded (and seed-expanded) when it is first indexed. Iterating decodes without caching, so a test that
    walks 20k cases holds one at a time."""

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

    def __init__(self, ix, unseed):
        self._ix, self._unseed, self._kept = ix, unseed, {}
        self.clock_ms = ix.clock_ms  # the corpus header's clockMs (None for a corpus generated before the member existed)
        self.clock_cases = ix.clock_cases  # the header's clockCases: case names that must run with the clock set to clockMs

    def case(self, j, keep=False):
        if j in self._kept:
            return self._kept[j]
        ix = self._ix
        c = json.loads(ix.buf[ix.starts[j]:ix.ends[j]], parse_int=lambda t: -0.0 if t == "-0" else int(t))
        if ix.blobs is not None:  # long strings are shared in a top-level table: every {"$blob": id} (args and out) is the string
            c = dict(c, args=_hydrate(c["args"], ix.blobs), out=_hydrate(c["out"], ix.blobs))
        if self._unseed:
            c = _unseed(c)
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


# The reference generator's frozen clock is read from the corpus header's "clockMs" member (see reference_clock_ms). REFERENCE_CLOCK_MS is
# only the fallback for corpora committed before the header carried it; no replay reads it directly.
REFERENCE_CLOCK_MS = 1_700_000_000_000
_CLOCK_META_KEYS = ("clockMs",)  # corpus header member names that carry the frozen clock (epoch ms), tried in order


def reference_clock_ms(meta=None):
    """The frozen clock in epoch ms of the corpus `meta` (a loaded corpus, or a header dict): its "clockMs" when present, else REFERENCE_CLOCK_MS."""
    if not isinstance(meta, dict):
        meta = {"clockMs": getattr(meta, "clock_ms", None)}
    for k in _CLOCK_META_KEYS:
        v = meta.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and abs(v) != float("inf"):
            return v
    return REFERENCE_CLOCK_MS


def near_clock(ms, clock=None, window_ms=120_000):
    """True when `ms` is within two minutes of the wall clock or of the frozen clock of the corpus `clock` (see reference_clock_ms): the reference prints such an instant as "<now>"."""
    return abs(ms - time.time() * 1000) < window_ms or abs(ms - reference_clock_ms(clock)) < window_ms


def load(module, path=None, unseed=True):
    """(count, {fn: [case, ...]}) of testdata/base-<module>.json.gz (or `path`); JSON -0 stays -0.0. The corpus is read once and kept as raw
    text; a case is decoded only when a test touches it (see _Index)."""
    ix = _index(path or os.path.join(HERE, "testdata", "base-%s.json.gz" % module))
    return ix.count, _LazyCases(ix, unseed)


def _hydrate(v, blobs):
    if isinstance(v, dict):
        if set(v) == {"$blob"}:
            return blobs[v["$blob"]]
        return {k: _hydrate(x, blobs) for k, x in v.items()}
    return [_hydrate(x, blobs) for x in v] if isinstance(v, list) else v


def _unseed(v):
    """A corpus carries no private key material: {"$seed": label[, "es256": true]} stands for the key member the generator derived from
    sha256("atlas-pca-conformance/" + label) (an ES256 scalar: the same digest with the top bit of byte 0 cleared)."""
    if isinstance(v, dict):
        if set(v) == {"$utf16"} and isinstance(v["$utf16"], list):  # a string holding a lone surrogate, as its code units
            return "".join(chr(u) for u in v["$utf16"]).encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")
        if "$seed" in v and set(v) <= {"$seed", "es256", "ec", "ed448"}:
            m = re.fullmatch(r"fill:(\d{1,3})", v["$seed"]) if isinstance(v["$seed"], str) else None
            if m and int(m.group(1)) < 256:  # 32 repeated bytes (the generator's Buffer.alloc(32, n)) as raw bytes, the form it stripped: not a sha256 label
                return bytes([int(m.group(1))]) * 32
            pre = ("atlas-pca-conformance/" + v["$seed"]).encode("utf-8")
            h = lambda sfx=b"": hashlib.sha256(pre + sfx).digest()  # noqa: E731
            if v.get("ed448"):
                raw = bytearray(h() + h(b"/2")[:25])
            elif v.get("ec"):  # plain SHA-256 stretch, no bignum: P-384 -> 48 bytes (&0x7F), P-521 -> 66 bytes (&0x01)
                n, mask = (66, 0x01) if v["ec"] == "P-521" else (48, 0x7F)
                raw = bytearray((h() + h(b"/2") + h(b"/3"))[:n])
                raw[0] &= mask
            else:
                raw = bytearray(h())
                if v.get("es256"):
                    raw[0] &= 0x7F
            return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")
        for k, x in v.items():  # in place: a copy of a 100 MB+ tree would double the peak of a decode
            v[k] = _unseed(x)
        return v
    if isinstance(v, list):
        for i, x in enumerate(v):
            v[i] = _unseed(x)
    return v


def load_ref(package, path=None):
    """The 0.6 package oracles: test-data/ref-<package>.json.gz (or `path`), same case format."""
    return load(package, path or os.path.join(HERE, "test-data", "ref-%s.json.gz" % package))


def gen_path(name):
    """Where ref-<name>-gen.json.gz lives: the oracle cases that carry private keys, generated by CI (gen-secret-corpus.sh), never committed."""
    return os.path.join(os.environ.get("PCA_SECRET_CORPUS_DIR") or os.path.join(HERE, "test-data"), "ref-%s-gen.json.gz" % name)


def load_gen(name, unseed=True):
    """(count, {fn: [case, ...]}) of the -gen corpus, or None when it is absent (see require_gen)."""
    p = gen_path(name)
    return load(name, p, unseed) if os.path.exists(p) else None


class _MergedCases(list):
    """The cases of one fn from the committed corpus plus the generated -gen corpus; `clock_by_case` maps each clockCases name of either header to
    that corpus's clockMs, so `run` still freezes the clock for them."""

    clock_by_case: dict = {}


def merge_cases(main, gen):
    clocks = {}
    for corpus in (main, gen[1] if gen else None):
        if corpus is not None and getattr(corpus, "clock_ms", None) is not None:
            clocks.update({n: corpus.clock_ms for n in getattr(corpus, "clock_cases", ())})
    out = {}
    for fn, cs in main.items():
        out[fn] = _MergedCases(cs)
    for fn, cs in (gen[1] if gen else {}).items():
        out.setdefault(fn, _MergedCases()).extend(cs)
    for v in out.values():
        v.clock_by_case = clocks
    return out


def require_gen(name):
    """A missing -gen corpus FAILS when CI is "true"/"1", else skips."""
    import pytest
    msg = "ref-%s-gen.json.gz not found at %s (generate with .github/scripts/gen-secret-corpus.sh or set PCA_SECRET_CORPUS_DIR)" % (name, gen_path(name))
    if os.environ.get("CI") in ("true", "1"):
        pytest.fail(msg)
    pytest.skip(msg)


def covered(cases, gen, mapped):
    """Every corpus fn is mapped; every mapped fn has cases once the -gen corpus is present."""
    return set(cases) <= set(mapped) and (gen is None or set(cases) == set(mapped))


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
        return _js_number(v)
    if isinstance(v, int) and not isinstance(v, bool) and abs(v) > 2 ** 53:
        try:
            return _js_number(float(v))  # a JS number: the double nearest to it, printed with its shortest digits
        except OverflowError:
            return v
    return v


def _js_number(f):
    """The corpus form of a double: an integral value below 1e21 as the integer of its shortest digits (what JSON.stringify prints), else the float."""
    if f.is_integer() and abs(f) < 1e21:
        return int(decimal.Decimal(repr(f)))
    return f


def canon(v):
    return json.dumps(norm(v), sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def throws(out):
    return isinstance(out, dict) and "$throws" in out


# JS-engine crash text the reference records on hostile input (one shared rule for every lane): a case whose expected throw message matches passes iff the
# native call refuses (raises, or returns a refusal), never when it returns a value; the message itself is not compared
_ENGINE_CRASH = re.compile(r"Cannot read propert(y|ies) of (null|undefined)|is not a function|is not iterable|Cannot convert undefined or null to object|"
                           r"Cannot destructure|Cannot use 'in' operator|Cannot create property|Reduce of empty array|is not an object|Cannot mix BigInt|"
                           r"Do not know how to serialize a BigInt|Converting circular structure|Invalid array length|Maximum call stack")
_REFUSAL_FLAGS = ("ok", "valid", "verified", "allowed", "allow", "admit", "accepted", "success")


def engine_crash(out):
    return throws(out) and isinstance(out["$throws"], str) and _ENGINE_CRASH.search(out["$throws"]) is not None


def refusal_like(got):
    """A native refusal returned as a value: None, a falsy verdict flag, an error member or a deny / refuse decision."""
    if got is None:
        return True
    if isinstance(got, dict):
        if any(got.get(k) is False for k in _REFUSAL_FLAGS) or got.get("error") or got.get("err") is not None:
            return True
        d = got.get("decision")
        return isinstance(d, str) and d in ("deny", "refuse", "refused")
    return False


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


class _frozen_clock:
    """Run a case with the wall clock set to `ms` (epoch milliseconds): the reference ran its clockCases under exactly this clock."""

    def __init__(self, ms):
        self._ms = ms

    def __enter__(self):
        self._saved = (time.time, time.time_ns)
        ms = self._ms
        time.time = lambda: ms / 1000
        time.time_ns = lambda: int(ms * 1_000_000)
        return self

    def __exit__(self, *_a):
        time.time, time.time_ns = self._saved
        return False


def _clock_of(cases, case):
    """The frozen clock a case must run under (the corpus header's clockMs when the case is named in clockCases), else None."""
    by_case = getattr(cases, "clock_by_case", None)
    if by_case is not None:
        return by_case.get(case.get("name"))
    corpus = getattr(cases, "_corpus", None)
    if corpus is not None and case.get("name") in getattr(corpus, "clock_cases", ()):
        return corpus.clock_ms
    return None


def case_clock(cases, case):
    """A context manager for a replay that loops over cases itself: the frozen clock for a clockCases case, else a no-op."""
    import contextlib
    ms = _clock_of(cases, case)
    return contextlib.nullcontext() if ms is None else _frozen_clock(ms)


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
        if isinstance(args, dict):  # a case recorded with one object argument instead of an argument list
            args = [args]
        clock = _clock_of(cases, c)
        try:
            if clock is None:
                got = call(*args)
            else:
                with _frozen_clock(clock):
                    got = call(*args)
        except Exception as e:  # noqa: BLE001 - any native refusal is compared against the reference
            if not throws(out):
                bad.append((c["name"], "raised %s: %s" % (type(e).__name__, e), out))
            elif "code" in out and getattr(e, "code", None) != out["code"]:
                bad.append((c["name"], "raised code %r: %s" % (getattr(e, "code", None), e), out))
            continue
        if throws(out):
            if (refused is None or not refused(got, c)) and not (engine_crash(out) and refusal_like(got)):
                bad.append((c["name"], "returned %s" % canon(got)[:300], out))
            continue
        if not _equal(got, out, c, compare):
            cg, co = canon(got), canon(out)
            k = max(0, next((i for i in range(min(len(cg), len(co))) if cg[i] != co[i]), 0) - 150)  # window on the first difference
            bad.append((c["name"], "got %s%s" % ("@%d " % k if k else "", cg[k:k + 400]), "%s%s" % ("@%d " % k if k else "", co[k:k + 400])))
    if c_suspect(cases):
        if bad:
            warnings.warn("@suspect cases differ (reported, not failed): %d, e.g. %r" % (len(bad), bad[:3]))
        return ran, skipped
    # ascii-escaped: a mismatch text holding a lone surrogate cannot cross the xdist channel (it killed the whole session instead of naming the test)
    assert not bad, ("%d of %d differ from the TS reference:\n" % (len(bad), ran) + "\n".join(
        "  %s\n    native: %s\n    ref:    %s" % (n, g, str(o)[:560]) for n, g, o in bad[:limit])).encode("ascii", "backslashreplace").decode("ascii")
    return ran, skipped


def c_suspect(cases):
    return bool(cases) and cases[0]["fn"].endswith("@suspect")
