"""Replays the TS-reference oracle of the entropy module (testdata/ref-entropy.json.gz, 562 cases): QRNG sources, the SP 800-90B health tests,
the HKDF combiner, secure_seed and the Ed25519 key-pair helper. Every fn of the corpus has a handler (an unhandled fn fails) and the case total
is asserted. The local CSPRNG, every source and the HTTP transport are injected by the case; no key material is in the corpus (a key pair is
compared by its public key and the SHA-256 of its secret). Messages that start with "QRNG", "HttpQrngSource", "mixEntropy" or "secureSeed" are
compared exactly, other error texts belong to the reference runtime. No case is skipped. DEVIATIONS names the two cases where Python
differs on purpose, each with its reason and the native result that is asserted instead of the reference's."""
import hashlib
import math
import os
import threading

import pytest

from atlas_pca import entropy as E
from base_oracle import HERE, canon, load

COUNT, CASES = load("entropy", os.path.join(HERE, "testdata", "ref-entropy.json.gz"))
EXACT = ("QRNG", "HttpQrngSource", "mixEntropy", "secureSeed")
_BY_NAME = {c["name"]: c for cs in CASES.values() for c in cs}
DEVIATIONS = {  # name: (why, the native result)
    "mixEntropy/ctx-null": ("None is the absent context (the reference throws on a null one)", _BY_NAME["mixEntropy/opts-empty"]["out"]),
    "httpQrng/throw-string": ("a Python exception always carries its text; the reference prints 'unknown error' for a thrown non-error",
                              dict(_BY_NAME["httpQrng/throw-string"]["out"], **{"$throws": "QRNG: fetch failed (strange)"})),
}


class _BareString(Exception):
    """Stands for the reference's rejection with a bare string (not an error object): the hook record's class is "string"."""


def _dec(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}[v["$num"]]
        if set(v) == {"$bytes"}:
            s = v["$bytes"]
            return __import__("base64").urlsafe_b64decode(s + "=" * (-len(s) % 4))
        return {k: _dec(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_dec(x) for x in v]
    return v


def _cls(e):
    if isinstance(e, _BareString):
        return "string"
    return "EntropyError" if isinstance(e, E.EntropyError) else "TypeError" if isinstance(e, TypeError) else \
        "RangeError" if isinstance(e, ValueError) else "Error"


def _err(e):
    out = {"cls": _cls(e), "message": str(e)}
    if isinstance(e, E.EntropyError):
        out["code"] = e.code
    return out


def _thrown(e, **more):
    r = _err(e)
    r["$throws"] = r.pop("message")
    r.update(more)
    return r


def _same(got, out):
    if not (isinstance(out, dict) and "$throws" in out):
        return canon(got) == canon(out)
    if not (isinstance(got, dict) and "$throws" in got):
        return False
    g, o = dict(got), dict(out)
    gm, om = g.pop("$throws"), o.pop("$throws")
    if om.startswith(EXACT) and gm != om.replace("a Uint8Array", "bytes"):
        return False
    gc, oc = g.pop("cls", None), o.pop("cls", None)
    if o.get("code") == "ERR_INVALID_URL":  # the reference URL parser's error; here Ada's ValueError
        del o["code"]
        oc = "RangeError"
    if oc == "SyntaxError":  # the transport's json() failure, re-raised unchanged (a ValueError in Python)
        oc = "RangeError"
    if oc is not None and gc != oc:
        return False
    return canon(g) == canon(o)


# ---- injected parts ----------------------------------------------------------------------------------------------------------------

class _Source:
    def __init__(self, spec, log):
        self.name = spec.get("name", "test-src")
        self._spec, self._log = spec, log

    def fetch(self, n):
        self._log.append(n)
        kind = self._spec["kind"]
        if kind == "bytes":
            return self._spec["value"]
        if kind == "nonbytes":
            return "not-bytes"
        if kind in ("reject", "throwSync"):
            raise RuntimeError(self._spec["message"])
        if kind == "rejectString":
            raise _BareString(self._spec["message"])
        raise AssertionError("source spec %r" % kind)


def _local(spec, log):
    def draw(n):
        log.append(n)
        if spec["kind"] == "fixed":
            return spec["value"]
        if spec["kind"] == "throw":
            raise RuntimeError(spec["message"])
        return "nonbytes"
    return draw


_SEED_KEYS = (("length", "length"), ("localBytes", "local_bytes"), ("quantumBytes", "quantum_bytes"), ("context", "context"),
              ("requireQuantum", "require_quantum"), ("healthTest", "health_test"))


def _seed_run(opts, keypair):
    reqs, locals_, errs = [], [], []
    kw = {py: opts[js] for js, py in _SEED_KEYS if js in opts}
    if opts.get("source") is not None:
        kw["source"] = _Source(opts["source"], reqs)
    if "local" in opts:
        kw["random_bytes_impl"] = _local(opts["local"], locals_)
    hook = opts.get("hook", "none")
    if hook != "none":
        def on_error(e):
            errs.append(_err(e))
            if hook == "throw":
                raise RuntimeError("hook boom")
        kw["on_qrng_error"] = on_error
    tail = lambda: {"qrngErrors": errs, "localRequested": locals_[0] if locals_ else None, "requests": reqs}  # noqa: E731
    try:
        r = (E.generate_keypair_with_entropy if keypair else E.secure_seed)(**kw)
    except Exception as e:  # noqa: BLE001 - compared against the reference refusal
        return _thrown(e, **tail())
    if keypair:
        return {"publicKey": r.public_key, "secretKeySha256": hashlib.sha256(r.secret_key).hexdigest(), "usedQuantum": r.used_quantum, **tail()}
    return {"seed": r.seed, "usedQuantum": r.used_quantum, "quantumByteCount": r.quantum_byte_count, "source": r.source, **tail()}


class _Response:
    def __init__(self, spec):
        self._spec = spec
        self.status = spec.get("status", 200)
        self.ok = spec.get("ok", 200 <= self.status <= 299)

    def json(self):
        if self._spec["kind"] == "jsonThrows":
            raise ValueError("bad json")
        return self._spec["body"] if self._spec["kind"] == "json" else {}

    def text(self):
        if self._spec["kind"] == "textThrows":
            raise RuntimeError("read failed")
        return self._spec.get("text", "")


def _transport(spec, log):
    if spec["kind"] == "none":
        return None

    def send(url, headers=None, redirect=None, timeout=None):
        log.append({"url": url, "headers": dict(headers), "redirect": redirect, "signal": timeout is not None})
        if spec["kind"] in ("throw", "throwString"):
            raise RuntimeError(spec["message"])
        if spec["kind"] == "hang":  # never answers within the source's deadline
            threading.Event().wait(5)
            raise RuntimeError("abandoned")
        return _Response(spec)
    return send


_HTTP_KEYS = (("apiKey", "api_key"), ("apiKeyHeader", "api_key_header"), ("format", "format"), ("timeoutMs", "timeout_ms"),
              ("maxBytes", "max_bytes"), ("lengthParam", "length_param"), ("extraParams", "extra_params"),
              ("allowInsecureLoopback", "allow_insecure_loopback"))


def _http_run(cfg, n, tr):
    log = []
    kw = {py: cfg[js] for js, py in _HTTP_KEYS if js in cfg}
    if "buildUrl" in cfg:
        suffix = cfg["buildUrl"]["suffix"]
        kw["build_url"] = lambda base, k: "%s/%s%s" % (base, k, suffix)
    try:
        src = E.HttpQrngSource(cfg.get("url"), transport=_transport(tr, log), **kw)
    except Exception as e:  # noqa: BLE001
        return _thrown(e)
    try:
        return {"name": src.name, "bytes": src.fetch(n), "requests": log}
    except Exception as e:  # noqa: BLE001
        key = cfg.get("apiKey")
        return _thrown(e, name=src.name, requests=log, leaksKey=bool(key) and key in str(e))


def _null(make):
    def run(reason, n):
        src = make() if reason is None else make(reason)
        try:
            src.fetch(n)
        except RuntimeError as e:
            return {"name": src.name, "$throws": str(e)}
        return {"name": src.name, "ok": True}
    return run


def _verdict(data, opts={}):  # noqa: B006 - read only; a null options object is passed as **None (a native TypeError)
    v = E.health_test_bytes(data, **(opts if opts is None else {k: opts[k] for k in ("h", "window") if k in opts}))
    return {"ok": True} if v.ok else {"ok": False, "test": v.test}


def _entropy_error(code, message):
    e = E.EntropyError(code, message)
    return {"name": e.name, "code": e.code, "message": str(e), "isError": isinstance(e, Exception)}


HANDLERS = {
    "constants": lambda: {n: getattr(E, n) for n in ("MAX_HKDF_OUTPUT", "MIN_LOCAL_BYTES", "DEFAULT_SEED_BYTES", "DEFAULT_MAX_QRNG_BYTES",
                                                    "DEFAULT_TIMEOUT_MS")},
    "repetitionCutoff": E.repetition_cutoff,
    "proportionCutoff": E.proportion_cutoff,
    "healthTestBytes": _verdict,
    "parseAnuUint8": E.parse_anu_uint8,
    "parseHex": E.parse_hex,
    "parseBase64": E.parse_base64,
    "mixEntropy": lambda local, quantum, opts=None: E.mix_entropy(local, quantum, **{k: (opts or {})[k] for k in ("length", "context")
                                                                                   if k in (opts or {})}),
    "secureSeed": lambda opts: _seed_run(opts, False),
    "generateKeyPairWithEntropy": lambda opts: _seed_run(opts, True),
    "httpQrng": _http_run,
    "nullQrng": _null(E.NullQrngSource),
    "unavailableSource": _null(E.unavailable_source),
    "entropyError": _entropy_error,
}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 562
    assert set(CASES) == set(HANDLERS), sorted(set(CASES) ^ set(HANDLERS))
    assert len(DEVIATIONS) == 2 and set(DEVIATIONS) <= set(_BY_NAME)


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_entropy_replay(fn):
    if fn == "httpQrng":
        pytest.importorskip("ada_url")  # a core dependency; only the job that installs none of them goes without
    bad = []
    for c in CASES[fn]:
        out = DEVIATIONS[c["name"]][1] if c["name"] in DEVIATIONS else c["out"]
        try:
            got = HANDLERS[fn](*_dec(c["args"]))
        except Exception as e:  # noqa: BLE001 - a native refusal, compared against the reference
            got = _thrown(e)
        if not _same(got, out):
            bad.append("%s\n    native: %s\n    ref:    %s" % (c["name"], canon(got)[:500], canon(out)[:500]))
    assert not bad, "%d of %d differ from the reference:\n  %s" % (len(bad), len(CASES[fn]), "\n  ".join(bad[:25]))


def test_default_csprng_and_public_entry_points():
    a, b = E.secure_seed(), E.secure_seed()
    assert len(a.seed) == 32 and a.seed != b.seed and a.used_quantum is False and a.source is None and repr(a.seed) not in repr(a)
    pair = E.generate_keypair_with_entropy(source=E.unavailable_source("offline"))
    assert len(pair.secret_key) == 32 and len(pair.public_key) == 32 and pair.used_quantum is False
    with pytest.raises(E.EntropyError) as x:
        E.secure_seed(source=E.NullQrngSource(), require_quantum=True)
    assert x.value.code == "quantum_required"
