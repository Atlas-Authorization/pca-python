"""OpenTelemetry instrumentation for PCA: wrap a verification guard so every decision emits a span and two metrics.
Port of the TypeScript reference (@atlasauth/pca-otel). Nothing from opentelemetry is imported: pass any tracer-like object
(start_span(name) -> span with set_attribute / set_status / record_exception / end) and meter-like object
(create_counter(name).add(n, attrs), create_histogram(name).record(n, attrs)). set_status receives a plain
{"code": int, "message"?: str} dict (UNSET 0, OK 1, ERROR 2); wrap it if your SDK wants a Status object.

This observes, it never decides: a tracer, meter or redactor that raises never changes what the guard returned.
"""
from __future__ import annotations

from ._fin import fin
import inspect
import re
from typing import Any, Callable, Dict, Optional

from .sdjwt_jws import js_to_string
from .siem import _WS, _u16len, _u16slice

STATUS_OK = 1
STATUS_ERROR = 2
MAX_TEXT = 256

_FL = re.A  # ASCII \w / \b, as in a non-unicode JavaScript regex
_FI = re.A | re.I
_REDACT = [
    (re.compile(r"\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*", _FL), "[redacted]"),
    (re.compile(r"\b(authorization[\"']?[%s]*[:=][%s]*)[^\n\"']*" % (_WS, _WS), _FI), r"\g<1>[redacted]"),
    (re.compile(r"\b(Bearer|Basic|Token)[%s]+[\w.~+/=-]{6,}" % _WS, _FI), r"\g<1> [redacted]"),
    (re.compile(r"([a-z][a-z0-9+.-]*://)[^%s/@]*:[^%s/@]*@" % (_WS, _WS), _FI), r"\g<1>[redacted]@"),
]
_KV = re.compile(r"\b((?:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|auth)[\"']?[%s]*[:=][%s]*)"
                 r"(\"[^\"]*\"|'[^']*'|[^%s\"'&,;]+)" % (_WS, _WS, _WS), _FI)
_LONG = re.compile(r"[A-Za-z0-9_-]{32,}")


def _kv(m: "re.Match[str]") -> str:
    val = m.group(2)
    q = val[0] if val[0] in "\"'" else ""
    return "%s%s[redacted]%s" % (m.group(1), q, q)


def redact_secrets(text: Any) -> str:
    """Remove what looks like a credential from text bound for telemetry (JWTs, Bearer / Basic credentials, URL userinfo,
    name=value pairs for secret-like names, 32+ character base64url / hex runs) and cut the result to 256 characters."""
    t = text if isinstance(text, str) else js_to_string(text)
    for rx, rep in _REDACT:
        t = rx.sub(rep, t)
    t = _KV.sub(_kv, t)
    t = _LONG.sub("[redacted]", t)
    return _u16slice(t, MAX_TEXT) + "..." if _u16len(t) > MAX_TEXT else t


def _g(o: Any, k: str) -> Any:
    return o.get(k) if isinstance(o, dict) else None


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and fin(v)


def _first_reason(result: Any) -> Any:
    """result?.verdict?.reasons?.[0], including JavaScript indexing into a string or an object keyed "0"."""
    rs = _g(_g(result, "verdict"), "reasons")
    if isinstance(rs, list):
        return rs[0] if rs else None
    if isinstance(rs, str):
        return _u16slice(rs, 1) if rs else None
    return _g(rs, "0")


def pca_span_attributes(result: Any, redact: Optional[Callable[[str], str]] = None) -> Dict[str, Any]:
    """Span attributes for a guard result; absent fields are omitted and pca.reason is added on deny only. Anything but an
    explicit ok is reported as a deny."""
    red = redact or redact_secrets
    ok = _g(result, "ok") is True
    attrs: Dict[str, Any] = {"pca.decision": "allow" if ok else "deny"}
    status = _g(result, "status")
    if _num(status):
        attrs["pca.status"] = status
    verdict = _g(result, "verdict")
    tier = _g(_g(verdict, "requiredThreshold"), "t")
    if _num(tier):
        attrs["pca.tier"] = tier
    risk = _g(verdict, "r")
    if _num(risk):
        attrs["pca.risk"] = risk
    action = _g(_g(result, "pcactn"), "action")
    verb = _g(action, "verb")
    if isinstance(verb, str):
        attrs["pca.verb"] = red(verb)
    resource = _g(action, "resource")
    if isinstance(resource, str):
        attrs["pca.resource"] = red(resource)
    if not ok:
        reason = _first_reason(result)
        if isinstance(reason, str):
            attrs["pca.reason"] = red(reason)
    return attrs


class TelemetryError(Exception):
    """The scrubbed copy of a guard failure recorded on a span: fresh message, no traceback, a sanitised class name."""

    def __init__(self, message: str, name: str = "Error") -> None:
        super().__init__(message)
        self.name = name
        self.message = message


def _safe(f: Callable[[], Any]) -> None:
    try:
        f()
    except Exception:  # noqa: BLE001 - the decision is the guard's, not the exporter's
        pass


def instrument_guard(guard: Callable[..., Any], tracer: Any = None, meter: Any = None, span_name: Optional[str] = None,
                     redact: Optional[Callable[[str], str]] = None) -> Callable[..., Any]:
    """Wrap a guard (sync or async) so each decision emits a span (default name pca.verify) and metrics (a pca.verifications
    counter and a pca.verify.risk histogram, created once). The wrapper returns the guard's result unchanged and re-raises
    its exceptions after recording a scrubbed copy on the span. With no tracer and no meter it is a transparent pass-through."""
    name = "pca.verify" if span_name is None else span_name
    counter = meter.create_counter("pca.verifications") if meter is not None else None
    histogram = meter.create_histogram("pca.verify.risk") if meter is not None else None
    red = redact or redact_secrets

    def start() -> Any:
        box: Dict[str, Any] = {}
        _safe(lambda: box.update(span=tracer.start_span(name) if tracer is not None else None))
        return box.get("span")

    def ok_path(span: Any, result: Any) -> None:
        if span:
            def annotate() -> None:
                for k, v in pca_span_attributes(result, red).items():
                    span.set_attribute(k, v)
                reason = None if _g(result, "ok") is True else _first_reason(result)
                if _g(result, "ok") is True:
                    span.set_status({"code": STATUS_OK})
                elif isinstance(reason, str):
                    span.set_status({"code": STATUS_ERROR, "message": red(reason)})
                else:
                    span.set_status({"code": STATUS_ERROR})
            _safe(annotate)
        decision = "allow" if _g(result, "ok") is True else "deny"
        if counter is not None:
            _safe(lambda: counter.add(1, {"decision": decision}))
        risk = _g(_g(result, "verdict"), "r")
        if histogram is not None and _num(risk):
            _safe(lambda: histogram.record(risk, {"decision": decision}))

    def err_path(span: Any, e: BaseException) -> None:
        if span:
            def record() -> None:
                # a fresh error: the original may carry credentials in its message, cause or traceback
                nm = type(e).__name__
                clean = TelemetryError(red(str(e)), nm if re.fullmatch(r"\w{1,64}", nm, re.A) else "Error")
                span.record_exception(clean)
                span.set_status({"code": STATUS_ERROR, "message": clean.message})
            _safe(record)

    def end(span: Any) -> None:
        if span:
            _safe(span.end)

    if inspect.iscoroutinefunction(guard):
        async def wrapped_async(*args: Any, **kwargs: Any) -> Any:
            span = start()
            try:
                result = await guard(*args, **kwargs)
                ok_path(span, result)
                return result
            except Exception as e:
                err_path(span, e)
                raise
            finally:
                end(span)
        return wrapped_async

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        span = start()
        try:
            result = guard(*args, **kwargs)
            ok_path(span, result)
            return result
        except Exception as e:
            err_path(span, e)
            raise
        finally:
            end(span)
    return wrapped
