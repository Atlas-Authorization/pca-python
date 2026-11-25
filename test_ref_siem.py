"""Differential oracle: atlas_pca.siem (OCSF / CEF / ECS mapping, scrub_error, sinks, export_batch) against the vectors
generated from the TypeScript reference (@atlasauth/pca-siem)."""
import pytest

from atlas_pca import siem as S
from base_oracle import load_ref, run

COUNT, BY_FN = load_ref("siem")


def _ev(r, f):
    return S.format_decision(r, f, None)


def _http(spec):
    calls = []
    mode = spec["mode"]

    def fetch(url, init):
        calls.append({"url": url, "method": init["method"], "headers": init["headers"], "body": init["body"]})
        if mode == "ok":
            return {"ok": True, "status": 200}
        if mode.startswith("st:"):
            parts = mode.split(":")
            res = {"ok": False, "status": int(parts[1])}
            if len(parts) > 2:
                res["statusText"] = ":".join(parts[2:])
            return res
        if mode.startswith("throws:"):
            raise RuntimeError(mode[7:])
        init["signal"].wait(5)  # hang until the sink gives up
        return {"ok": True, "status": 200}

    sink = S.http_sink(spec["url"], spec["format"], headers=spec.get("headers"), content_type=spec.get("contentType"),
                       name=spec.get("name"), timeout_ms=spec.get("timeoutMs"), fetch=fetch)
    result = sink.deliver([_ev(r, spec["format"]) for r in spec["events"]])
    return {"name": sink.name, "format": sink.format, "result": result, "request": calls[0] if calls else None}


def _console(spec):
    lines = []

    def logger(line):
        if spec.get("throws"):
            raise RuntimeError(spec["throws"])
        lines.append(line)

    sink = S.console_sink(spec.get("format"), logger, spec.get("name"))
    result = sink.deliver([_ev(r, sink.format) for r in spec["records"]])
    return {"name": sink.name, "format": sink.format, "result": result, "lines": lines}


def _export(spec):
    errors, delivered = [], []
    mode = spec["sinkMode"]

    def deliver(events):
        delivered.extend(e["line"] for e in events)
        if mode == "ok":
            return {"ok": True}
        if mode == "fail":
            return {"ok": False, "error": "collector said no token=abcdef123"}
        if mode == "failNoError":
            return {"ok": False}
        raise RuntimeError("deliver exploded Bearer abcdefghij")

    def on_error(e, ctx):
        errors.append({"message": str(e), "sink": ctx["sink"], "count": ctx["count"]})
        if mode == "throwsOnError" or spec.get("onErrorThrows"):
            raise RuntimeError("cb")

    sink = S.SiemSink("s1", spec["format"], deliver)
    result = S.export_batch(spec["records"], sink, on_error, spec.get("serialize"))
    return {"result": result, "errors": errors, "delivered": delivered}


MAP = {
    "toOcsfEvent": lambda r, o=None: S.to_ocsf_event(r, o),
    "toCef": lambda r, o=None: S.to_cef(r, o),
    "toEcs": lambda r, o=None: S.to_ecs(r, o),
    "formatDecision": lambda r, f, o=None: S.format_decision(r, f, o),
    "scrubError": S.scrub_error,
    "httpSinkScenario": _http,
    "consoleSinkScenario": _console,
    "exportScenario": _export,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 1290 and set(BY_FN) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    ran, _skipped = run(BY_FN[fn], MAP[fn])
    assert ran == len(BY_FN[fn])
