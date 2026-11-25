"""Differential oracle: atlas_pca.otel (redact_secrets, pca_span_attributes, instrument_guard over scripted tracers / meters /
guards) against the vectors generated from the TypeScript reference (@atlasauth/pca-otel)."""
import pytest

from atlas_pca import otel as O
from base_oracle import load_ref, run

COUNT, BY_FN = load_ref("otel")

MODES = {"identity": lambda s: s, "upper": lambda s: s.upper(), "brackets": lambda s: "<%s>" % s}


def _scenario(spec):
    events = []
    tm = spec.get("tracerMode") or "ok"
    mm = spec.get("meterMode") or "ok"

    def throw_if(cond):
        if cond:
            raise RuntimeError("exporter boom")

    class Span:
        def set_attribute(self, k, v):
            events.append({"ev": "setAttribute", "k": k, "v": v})
            throw_if(tm == "attrThrows")

        def set_status(self, s):
            e = {"ev": "setStatus", "code": s["code"]}
            if "message" in s:
                e["message"] = s["message"]
            events.append(e)
            throw_if(tm == "statusThrows")

        def record_exception(self, e):
            events.append({"ev": "recordException", "message": e.message, "noStack": e.__traceback__ is None})
            throw_if(tm == "recordThrows")

        def end(self):
            events.append({"ev": "end"})
            throw_if(tm == "endThrows")

    class Tracer:
        def start_span(self, name):
            events.append({"ev": "startSpan", "name": name})
            throw_if(tm == "startThrows")
            return Span()

    class Counter:
        def add(self, v, a):
            events.append({"ev": "add", "v": v, "a": a})
            throw_if(mm == "addThrows")

    class Histogram:
        def record(self, v, a):
            events.append({"ev": "record", "v": v, "a": a})
            throw_if(mm == "recordThrows")

    class Meter:
        def create_counter(self, name):
            events.append({"ev": "createCounter", "name": name})
            throw_if(mm == "createThrows")
            return Counter()

        def create_histogram(self, name):
            events.append({"ev": "createHistogram", "name": name})
            return Histogram()

    g = spec["guard"]

    def guard(_req):
        if "throws" in g:
            raise RuntimeError(g["throws"])
        return g["result"]

    try:
        wrapped = O.instrument_guard(guard, tracer=Tracer() if spec.get("tracer") else None,
                                     meter=Meter() if spec.get("meter") else None, span_name=spec.get("spanName"),
                                     redact=MODES[spec["redact"]] if spec.get("redact") else None)
    except Exception as e:  # noqa: BLE001
        return {"wrap": str(e), "events": events}
    try:
        outcome = {"result": wrapped("req")}
    except Exception as e:  # noqa: BLE001
        outcome = {"threw": str(e)}
    return {"outcome": outcome, "events": events}


MAP = {
    "redactSecrets": O.redact_secrets,
    "pcaSpanAttributes": lambda r, mode=None: O.pca_span_attributes(r, MODES[mode] if mode else None),
    "instrumentScenario": _scenario,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in BY_FN.values()) and set(BY_FN) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    ran, _skipped = run(BY_FN[fn], MAP[fn])
    assert ran == len(BY_FN[fn])
