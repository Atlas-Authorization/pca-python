"""Checks a live PCA deployment's assumptions: clock skew, the replay store, trusted-proxy settings, the signature-suite policy,
root-caveat enforcement and the verifier's required checks. Every check returns a result dict ``{"id", "status", "detail",
"remediation"?, "observed"?}`` (status pass / warn / fail / skip); ``run_doctor`` merges them, ``verdict_of`` reduces them,
``format_results`` prints them, and nothing printed carries a credential (``scrub_text``). Configuration is a plain dict with the
reference's sections and member names (``url``, ``clock``, ``store``, ``proxy``, ``verifier``). Checks that cannot be observed from
here say so instead of passing. Mirrors the TypeScript reference (@atlasauth/pca-doctor): same check ids, messages and order.

Network access is injected: ``fetch(url, method=..., headers=..., timeout_ms=...)`` returns an object with ``.headers.get(lowercase
name)`` (default: urllib, redirects not followed). The deployed library is probed through ``load_pca`` (default: the installed
``atlas_pca``, or the one found under ``verifier.pcaDir``). ``check_runtime`` adds what only makes sense for a Python install: which
registered suites this runtime can verify and which optional backends are importable.
"""
from __future__ import annotations

from ._fin import fin
import json
import math
import os
import random
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence
from urllib.parse import urljoin, urlsplit

from .facade import _string_to_number
from .harness import _to_fixed
from .pca import MAX_SKEW_MS, REGISTERED_SUITES
from .predicates import _UNDEF, _js_number_string, _js_string

CHECK_GROUPS = ("clock", "store", "proxy", "suites", "caveats")
DEFAULT_REFERENCE_URL = "https://www.google.com/generate_204"
ROOT_CAVEAT_MIN_VERSION = "0.4.1"
DEFAULT_REQUIRED = ["counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"]
PROXY_HEADERS = ("x-forwarded-for", "forwarded", "x-real-ip")

CLOCK_REMEDIATION = (
    "Synchronise every verifier, issuer and replay-store host with NTP (chrony or systemd-timesyncd) and alert on drift. PCA tolerates at "
    "most 60 s between any two clocks (PCACTN_MAX_SKEW_MS); replay retention is exp + skew, so a clock outside that bound can free a "
    "nonce early or reject fresh actions.")
PROXY_REMEDIATION = (
    "Set TRUSTED_PROXY_COUNT to exactly the number of reverse proxies in front of the API that APPEND to the trusted header (1 behind one "
    "load balancer / ingress; 0 when clients connect directly), and TRUSTED_PROXY_HEADER to the header they write. Too high lets a client "
    "pick its own rate-limit bucket with extra X-Forwarded-For entries; too low merges every client into the proxy's bucket.")
SUITES_REMEDIATION = (
    "Set the verifier's allowedSuites to exactly the suites your issuers sign with (names from SIG_SUITES), e.g. ['ed25519'] or "
    "['hybrid-ed25519-ml-dsa-65'].")
PQ_REMEDIATION = (
    "Never set allowUnboundPq. For pure-PQ or hybrid roots, configure pqPins (issuer Ed25519 identity -> PQ public key, from pqPinFor) or "
    "verify against your stored root grant (trustedRoot; requirePCA / verifyPCActnCore do this).")
ATOMICITY_REMEDIATION = (
    "Make consumeOnce / advance one atomic operation on the shared store, e.g. Postgres INSERT .. ON CONFLICT (key) DO UPDATE .. WHERE "
    "until < $now RETURNING and UPDATE .. WHERE counter < $n RETURNING, Redis SET key NX PX or a Lua compare-and-set; never read, then "
    "write. Then run the full kit: pca-store-conformance --adapter <your adapter>.")
DURABILITY_REMEDIATION = (
    "Keep consumed keys and counters in a store with synchronous, persistent commits (Postgres synchronous_commit=on; Redis appendfsync "
    "always and maxmemory-policy noeviction), shared by every verifier instance. An in-memory store is only correct for a single "
    "process whose lifetime covers the action lifetime.")
CAVEAT_REMEDIATION = (
    "Upgrade @atlasauth/pca to >= 0.4.1 in the deployed application (root caveats outside the envelope are enforced from 0.4.1), "
    "redeploy, and re-run pca-doctor with --pca-dir pointing at the application.")

USAGE = """pca-doctor [--url <deployment>] [options]

  --url URL              the live deployment (base URL of the API that verifies PCActns)
  --config FILE          JSON or JS config (see the pca-doctor guide); env and flags override it
  --store MODULE         replay-store adapter module (store conformance kit interface) for the atomicity / durability checks
  --store-option k=v     passed to the adapter factory (repeatable)
  --reference URL|local  clock reference (default https://www.google.com/generate_204)
  --max-skew-ms N        clock fail threshold (default 60000)
  --trusted-proxy-count N, --proxy-header H, --proxy-hops N   the deployment's proxy settings and the real hop count
  --pca-dir DIR          the deployed application's directory (its installed @atlasauth/pca is probed)
  --only a,b | --skip a,b   check groups: %s
  --no-probe             do not send forged forwarding headers to the deployment
  --strict               warnings fail too
  --json                 machine-readable output

Env: PCA_DOCTOR_URL, PCA_DOCTOR_REFERENCE_URL, PCA_DOCTOR_STORE, TRUSTED_PROXY_COUNT, TRUSTED_PROXY_HEADER, PCA_TRUSTED_PROXY_HOPS,
     PCA_ALLOWED_SUITES (comma list), PCA_PQ_PINS (JSON), PCA_ALLOW_UNBOUND_PQ.""" % ", ".join(CHECK_GROUPS)

# ---- JavaScript value semantics over decoded JSON ---------------------------------------------------

_WS = "\t\n\v\f\r                  　﻿"
_S = r"\t\n\v\f\r    -     　﻿"  # ECMAScript \s, as a class body


def _g(o: Any, k: str) -> Any:
    """``o?.k``: _UNDEF for a non-object or an absent member."""
    return o.get(k, _UNDEF) if isinstance(o, dict) else _UNDEF


def _nn(v: Any, default: Any) -> Any:
    """``v ?? default``."""
    return default if v is _UNDEF or v is None else v


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _truthy(v: Any) -> bool:
    if v is _UNDEF or v is None or v is False or v == "":
        return False
    if _is_num(v):
        return not (v == 0 or v != v)
    return True


def _number(v: Any) -> float:
    """ECMAScript Number(v)."""
    if v is _UNDEF:
        return math.nan
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if _is_num(v):
        return float(v)
    if isinstance(v, (str, list)):
        return _string_to_number(_js_string(v))
    return math.nan


def _finite(x: Any) -> bool:
    return _is_num(x) and fin(x)


def _is_integer(v: Any) -> bool:
    return _finite(v) and float(v) == math.floor(float(v))


def _neg_zero(v: Any) -> bool:
    return isinstance(v, float) and v == 0 and math.copysign(1.0, v) < 0


def _u16(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _pad_end(s: str, n: int) -> str:
    return s + " " * max(0, n - _u16(s))


def _num_str(v: Any) -> str:
    return _js_number_string(float(v)) if _is_num(v) else _js_string(v)


# ---- results --------------------------------------------------------------------------------------


def _res(id_: str, status: str, detail: str, remediation: Optional[str] = None, observed: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    r: Dict[str, Any] = {"id": id_, "status": status, "detail": detail}
    if remediation is not None:
        r["remediation"] = remediation
    if observed is not None:
        r["observed"] = observed
    return r


# ---- scrub ----------------------------------------------------------------------------------------

_RF = re.ASCII | re.IGNORECASE
_SCRUB_JWT = re.compile(r"\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*", re.ASCII)
_SCRUB_AUTH = re.compile(r"\b(authorization[\"']?[%s]*[:=][%s]*)[^\n\"']*" % (_S, _S), _RF)
_SCRUB_BEARER = re.compile(r"\b(Bearer|Basic|Token)[%s]+[\w.~+/=-]{6,}" % _S, _RF)
_SCRUB_URL = re.compile(r"([a-z][a-z0-9+.-]*://)[^%s/@]*:[^%s/@]*@" % (_S, _S), _RF)
_SCRUB_PAIR = re.compile(
    r"\b((?:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|auth|sslpassword)[\"']?[%s]*[:=][%s]*)"
    r"(\"[^\"]*\"|'[^']*'|[^%s\"'&,;]+)" % (_S, _S, _S), _RF)
_SCRUB_LONG = re.compile(r"[A-Za-z0-9_-]{40,}")


def scrub_text(text: Any) -> str:
    """Remove credentials from text the doctor prints: URL userinfo, ``token=`` / ``password=`` pairs, bearer credentials, JWTs and
    long token runs; cut to 600 UTF-16 units."""
    t = _js_string(text) if not isinstance(text, str) else text
    t = _SCRUB_JWT.sub("[redacted]", t)
    t = _SCRUB_AUTH.sub(lambda m: m.group(1) + "[redacted]", t)
    t = _SCRUB_BEARER.sub(lambda m: m.group(1) + " [redacted]", t)
    t = _SCRUB_URL.sub(lambda m: m.group(1) + "[redacted]@", t)
    t = _SCRUB_PAIR.sub(lambda m: m.group(1) + "[redacted]", t)
    t = _SCRUB_LONG.sub("[redacted]", t)
    u = t.encode("utf-16-le", "surrogatepass")
    if len(u) > 1200:
        return u[:1200].decode("utf-16-le", "surrogatepass") + "..."
    return t


def scrub_deep(v: Any, depth: int = 0) -> Any:
    """Scrub every string inside a JSON-like value (nesting deeper than 8 is left as it is)."""
    if isinstance(v, str):
        return scrub_text(v)
    if depth > 8 or not isinstance(v, (dict, list)):
        return v
    if isinstance(v, list):
        return [scrub_deep(x, depth + 1) for x in v]
    return {k: scrub_deep(x, depth + 1) for k, x in v.items()}


# ---- fetch and clock ------------------------------------------------------------------------------


class _Response:
    def __init__(self, status: int, headers: Any) -> None:
        self.status, self.headers = status, headers

    def read(self) -> bytes:
        return b""


def default_fetch(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, timeout_ms: float = 10_000) -> Any:
    """The default client (urllib): redirects are not followed and an HTTP error status is a response, not an exception."""
    import urllib.error
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a: Any, **k: Any) -> None:
            return None

    req = urllib.request.Request(url, method=method, headers=dict(headers or {}))
    try:
        r = urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout_ms / 1000)
        return _Response(r.status, r.headers)
    except urllib.error.HTTPError as e:
        return _Response(e.code, e.headers)


_MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
_RFC_DATE = re.compile(r"(?:[A-Za-z]+,?\s+)?(\d{1,2})\s+([A-Za-z]{3})[A-Za-z]*\s+(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(GMT|UTC|UT|Z|[+-]\d{4})",
                       re.IGNORECASE | re.ASCII)
_ISO_DATE = re.compile(r"(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(Z|[+-]\d{2}:\d{2}))?", re.ASCII)


def _epoch(y: int, mo: int, d: int, h: int, mi: int, s: int, ms: int, off_min: int) -> float:
    import datetime

    days = datetime.date(y, mo, 1).toordinal() - 719163 + d - 1
    return float(((days * 24 + h) * 60 + mi) * 60_000 + s * 1000 + ms - off_min * 60_000)


def parse_date(s: str) -> float:
    """``Date.parse``: NaN when unparseable. Covers the HTTP date (RFC 1123 with a zone; a weekday word is ignored, as the reference
    engine does) and ISO 8601 with a zone or date only (UTC). shortcut: a date without a zone is local time in the reference engine
    (host-dependent) and is NaN here; other legacy spellings are NaN."""
    t = s.strip(_WS)
    try:
        m = _RFC_DATE.fullmatch(t)
        if m:
            mn = m.group(2).lower()
            if mn not in _MONTHS:
                return math.nan
            h, mi, sec = int(m.group(4)), int(m.group(5)), int(m.group(6) or 0)
            if h > 24 or mi > 59 or sec > 59 or (h == 24 and (mi != 0 or sec != 0)):
                return math.nan
            z = m.group(7).upper()
            off = (-1 if z[0] == "-" else 1) * (int(z[1:3]) * 60 + int(z[3:5])) if re.fullmatch(r"[+-]\d{4}", z) else 0
            day = int(m.group(1))
            if day < 1 or day > 31:
                return math.nan
            return _epoch(int(m.group(3)), _MONTHS.index(mn) + 1, day, h, mi, sec, 0, off)
        m = _ISO_DATE.fullmatch(t)
        if m:
            import calendar

            y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if mo < 1 or mo > 12 or d < 1 or d > calendar.monthrange(y, mo)[1]:
                return math.nan
            h = int(m.group(4) or 0)
            mi = int(m.group(5) or 0)
            sec = int(m.group(6) or 0)
            if h > 24 or mi > 59 or sec > 59 or (h == 24 and (mi != 0 or sec != 0 or m.group(7) is not None)):
                return math.nan
            ms = int((m.group(7) + "00")[:3]) if m.group(7) else 0
            z = m.group(8)
            off = 0
            if z and z != "Z":
                off = (-1 if z[0] == "-" else 1) * (int(z[1:3]) * 60 + int(z[4:6]))
            return _epoch(y, mo, d, h, mi, sec, ms, off)
    except (ValueError, OverflowError):
        return math.nan
    return math.nan


def _wall_ms() -> float:
    import time

    return time.time() * 1000


def read_date(url: str, fetch: Callable[..., Any], now: Callable[[], float], timeout_ms: float) -> Dict[str, Any]:
    """One reading of a server's clock from its Date header (one-second resolution: +-0.5 s plus half the round trip): ``{"offsetMs",
    "uncertaintyMs"}`` (remote minus local) or ``{"error"}``."""
    t0 = now()
    try:
        res = fetch(url, method="HEAD", timeout_ms=timeout_ms)
    except Exception as e:  # noqa: BLE001 - any transport failure is an unobservable clock
        return {"error": "request failed: %s" % e}
    t1 = now()
    date = res.headers.get("date")
    d = math.nan if date is None else parse_date(date)
    if not fin(d):
        return {"error": "no Date header" if date is None else "unparseable Date header '%s'" % date}
    return {"offsetMs": d + 500 - (t0 + t1) / 2, "uncertaintyMs": 500 + (t1 - t0) / 2}


def _signed_s(ms: float) -> str:
    return "%s%s s" % ("+" if ms >= 0 else "-", _to_fixed(abs(ms) / 1000, 1))


def check_clock(cfg: Any, fetch: Callable[..., Any], now: Optional[Callable[[], float]] = None) -> Dict[str, Any]:
    """Clock skew of the deployment against a reference (the Date headers of both, or this machine's clock). FAIL only when the skew is
    beyond the limit even at the favourable end of the uncertainty interval; WARN when it is above the warning fraction or could be
    beyond the limit."""
    clock = now or _wall_ms
    url = _g(cfg, "url")
    if not _truthy(url):
        return _res("clock", "skip", "no deployment URL given (--url)")
    cc = _g(cfg, "clock")
    max_skew = _number(_nn(_g(cc, "maxSkewMs"), MAX_SKEW_MS))
    warn_at = max_skew * _number(_nn(_g(cc, "warnFraction"), 0.25))
    timeout = _number(_nn(_g(cc, "timeoutMs"), 10_000))
    dep = read_date(_js_string(url), fetch, clock, timeout)
    if "error" in dep:
        return _res("clock", "warn", "cannot observe the deployment's clock at %s: %s" % (_js_string(url), dep["error"]),
                    "Make the deployment answer with a Date header (RFC 9110 requires one from an origin with a clock), or check its clock "
                    "on the host. " + CLOCK_REMEDIATION)
    ref_url = _js_string(_nn(_g(cc, "referenceUrl"), DEFAULT_REFERENCE_URL))
    ref = {"offsetMs": 0.0, "uncertaintyMs": 0.0}
    ref_name = "this machine's clock"
    ref_note = ""
    if ref_url != "local":
        r = read_date(ref_url, fetch, clock, timeout)
        if "error" in r:
            ref_note = " (reference %s unusable: %s; compared with this machine's clock instead)" % (ref_url, r["error"])
        else:
            ref, ref_name = r, ref_url
    skew = dep["offsetMs"] - ref["offsetMs"]
    unc = dep["uncertaintyMs"] + ref["uncertaintyMs"]
    lower, upper = abs(skew) - unc, abs(skew) + unc
    status = "fail" if lower > max_skew else "warn" if abs(skew) > warn_at or upper > max_skew else "pass"
    detail = ("deployment clock %s relative to %s%s (+-%s s: Date has 1 s resolution, plus round trips); fail beyond %s s, warn above %s s. "
              "The Date header is written by whatever answers the request (a CDN or proxy may set it)."
              % (_signed_s(skew), ref_name, ref_note, _to_fixed(unc / 1000, 1), _js_number_string(max_skew / 1000), _js_number_string(warn_at / 1000)))
    return _res("clock", status, detail, None if status == "pass" else CLOCK_REMEDIATION,
                {"skewMs": skew, "uncertaintyMs": unc, "maxSkewMs": max_skew, "warnAtMs": warn_at, "reference": ref_name})


# ---- proxy ----------------------------------------------------------------------------------------


def check_proxy_config(cfg: Any) -> Dict[str, Any]:
    """The stated TRUSTED_PROXY_COUNT / TRUSTED_PROXY_HEADER against the stated number of appending proxies."""
    p = _g(cfg, "proxy")
    n = _g(p, "trustedProxyCount")
    if n is _UNDEF:
        return _res("proxy.config", "skip", "TRUSTED_PROXY_COUNT not given (config proxy.trustedProxyCount or env TRUSTED_PROXY_COUNT)")
    header = _nn(_g(p, "header"), "x-forwarded-for")
    hs, ns = _js_string(header), _js_string(n)

    def fail(detail: str) -> Dict[str, Any]:
        return _res("proxy.config", "fail", detail, PROXY_REMEDIATION)

    if not _is_integer(n) or n < 0 or _neg_zero(n) or n > 16:
        return fail("TRUSTED_PROXY_COUNT=%s is not an integer in 0..16" % ns)
    if header == "x-real-ip" and n == 0:
        return fail("TRUSTED_PROXY_HEADER=x-real-ip needs TRUSTED_PROXY_COUNT >= 1 (with 0 every forwarding header is ignored)")
    hops = _g(p, "hops")
    if hops is _UNDEF:
        return _res("proxy.config", "pass" if n == 0 else "warn",
                    "TRUSTED_PROXY_COUNT=%s (%s); the real number of appending proxies was not stated (proxy.hops / PCA_TRUSTED_PROXY_HOPS), "
                    "so it cannot be compared" % (ns, hs), None if n == 0 else PROXY_REMEDIATION)
    hp, h = _js_string(hops), _number(hops)
    if n > h:
        return fail("TRUSTED_PROXY_COUNT=%s is larger than the %s proxies in front of the API: a client chooses its own address (and "
                    "rate-limit bucket) with extra %s entries" % (ns, hp, hs))
    if n < h:
        return _res("proxy.config", "warn", "TRUSTED_PROXY_COUNT=%s is smaller than the %s proxies in front of the API: clients are keyed "
                    "by a proxy's address and share its bucket" % (ns, hp), PROXY_REMEDIATION)
    return _res("proxy.config", "pass", "TRUSTED_PROXY_COUNT=%s (%s) matches the stated %s appending proxies" % (ns, hs, hp))


def test_net_ip(rand: Optional[Callable[[], float]] = None) -> str:
    """A random documentation address (RFC 5737 TEST-NET-2 / -3): never a real client."""
    r = rand or random.random
    net = "198.51.100" if r() < 0.5 else "203.0.113"
    return "%s.%d" % (net, 1 + math.floor(r() * 254))


test_net_ip.__test__ = False  # type: ignore[attr-defined]  # not a pytest test


def forged_headers(rand: Optional[Callable[[], float]] = None) -> Dict[str, str]:
    """Forged values for all three forwarding headers at once (the server trusts at most one of them)."""
    r = rand or random.random
    chain = [test_net_ip(r) for _ in range(17)]
    return {"x-forwarded-for": ", ".join(chain), "forwarded": ", ".join("for=" + ip for ip in chain), "x-real-ip": test_net_ip(r)}


def _remaining(fetch: Callable[..., Any], url: str, headers: Dict[str, str], timeout_ms: float) -> Optional[float]:
    r = fetch(url, method="GET", headers=headers, timeout_ms=timeout_ms)
    try:
        r.read()
    except Exception:  # noqa: BLE001 - the body is irrelevant
        pass
    v = r.headers.get("ratelimit-remaining")
    n = math.nan if v is None else _string_to_number(v)
    return n if fin(n) else None


class _InvalidUrl(ValueError):
    code = "ERR_INVALID_URL"


def _href(path: str, base: str) -> str:
    """``new URL(path, base).href`` for the shapes a probe path takes (absolute URL, rooted path, relative path)."""
    b = urlsplit(base)
    if not b.scheme or not b.netloc:
        raise _InvalidUrl("Invalid URL")
    return urljoin(base if b.path else base + "/", path)


def check_proxy_probe(cfg: Any, fetch: Callable[..., Any], rand: Optional[Callable[[], float]] = None) -> Dict[str, Any]:
    """Forged forwarding headers sent to a public rate-limited path, watching ``RateLimit-Remaining``: a forged request that lands in a
    FRESH bucket while plain requests keep draining one bucket means client-written entries are trusted. A count that is too LOW is not
    observable from one vantage point."""
    id_ = "proxy.probe"
    url = _g(cfg, "url")
    if not _truthy(url):
        return _res(id_, "skip", "no deployment URL given (--url)")
    proxy = _g(cfg, "proxy")
    if _g(proxy, "probe") is False:
        return _res(id_, "skip", "disabled (--no-probe)")
    target = _href(_js_string(_nn(_g(proxy, "probePath"), "/v1/pca/suites")), _js_string(url))
    t = _number(_nn(_g(_g(cfg, "clock"), "timeoutMs"), 10_000))
    try:
        a = _remaining(fetch, target, {}, t)
        b = _remaining(fetch, target, {}, t)
        f = _remaining(fetch, target, forged_headers(rand), t)
        c = _remaining(fetch, target, {}, t)
    except Exception as e:  # noqa: BLE001
        return _res(id_, "warn", "probe request to %s failed: %s" % (target, e),
                    "Set proxy.probePath to a public, rate-limited path of the deployment, or run with --no-probe.")
    observed = {"url": target, "remaining": [a, b, f, c]}
    if a is None or b is None or f is None or c is None:
        return _res(id_, "skip", "not observable remotely: %s does not return a RateLimit-Remaining header on every response" % target,
                    observed=observed)
    sa, sb, sf, sc = _num_str(a), _num_str(b), _num_str(f), _num_str(c)
    if not (b < a and c < b):
        return _res(id_, "warn", "inconclusive: the plain requests' bucket did not drain monotonically (%s, %s, then %s): a window "
                    "rollover, a shared bucket or concurrent traffic. Re-run." % (sa, sb, sc), observed=observed)
    if f > b:
        return _res(id_, "fail", "a request with FORGED forwarding headers got a fresh rate-limit bucket (remaining %s, while the plain "
                    "requests' bucket was at %s): the deployment trusts client-written forwarding entries" % (sf, sb), PROXY_REMEDIATION, observed)
    return _res(id_, "pass", "forged X-Forwarded-For / Forwarded / X-Real-IP did not move the client to another bucket (remaining %s, %s, "
                "forged %s, %s). A count that is too LOW is not observable from one client." % (sa, sb, sf, sc), observed=observed)


# ---- suites ---------------------------------------------------------------------------------------

_B64U = re.compile(r"[A-Za-z0-9_-]+")
_ED25519_ID = re.compile(r"[A-Za-z0-9_-]{43}")


def _is_pq(alg: Any) -> bool:
    return isinstance(alg, str) and alg != "ed25519" and alg in REGISTERED_SUITES


def check_allowed_suites(cfg: Any, registry: Sequence[str] = REGISTERED_SUITES) -> Dict[str, Any]:
    """allowedSuites against the closed suite registry (the library's registered suite names, in registry order)."""
    id_ = "suites.allowed"
    v = _g(cfg, "verifier")
    if not _truthy(v):
        return _res(id_, "skip", "no verifier configuration given (config verifier.*)")
    lst = _g(v, "allowedSuites")
    known = ", ".join(registry)
    if lst is _UNDEF:
        return _res(id_, "warn", "allowedSuites is unset: every registered suite is accepted (%d: %s)" % (len(registry), known), SUITES_REMEDIATION)
    if not isinstance(lst, list) or not lst:
        return _res(id_, "fail", "allowedSuites is empty or not a list: no PCActn can verify", SUITES_REMEDIATION)
    unknown = [s for s in lst if not isinstance(s, str) or s not in registry]
    if unknown:
        return _res(id_, "fail", "allowedSuites names suite(s) outside the registry: %s (known: %s)" % (", ".join(_js_string(s) for s in unknown), known),
                    SUITES_REMEDIATION)
    return _res(id_, "pass", "allowedSuites = %s" % ", ".join(lst))


def check_pq_binding(cfg: Any) -> Dict[str, Any]:
    """allowUnboundPq / pqPins / trustedRoot sanity."""
    id_ = "suites.pq-binding"
    v = _g(cfg, "verifier")
    if not _truthy(v):
        return _res(id_, "skip", "no verifier configuration given (config verifier.*)")

    def fail(detail: str) -> Dict[str, Any]:
        return _res(id_, "fail", detail, PQ_REMEDIATION)

    if _g(v, "allowUnboundPq") is True:
        return fail("allowUnboundPq is set: PQ keys are read from the artifact, so a hybrid gives no protection against an Ed25519 forger "
                    "and a pure-PQ hop can be signed by any key")
    pins = _g(v, "pqPins")
    if pins is not _UNDEF:
        if not isinstance(pins, dict):
            return fail("pqPins is not an object of { ed25519 identity: pq public key }")
        bad = [k for k, val in pins.items() if not _ED25519_ID.fullmatch(k) or not isinstance(val, str) or not _B64U.fullmatch(val)]
        if bad:
            return fail("pqPins has malformed entries (key must be a 43-char base64url Ed25519 identity, value a base64url PQ key): %s" % ", ".join(bad))
    allowed = _nn(_g(v, "allowedSuites"), list(REGISTERED_SUITES))
    if not isinstance(allowed, list):
        raise TypeError("allowedSuites.filter is not a function")
    pq = [s for s in allowed if _is_pq(s)]
    if not pq:
        return _res(id_, "pass", "no post-quantum suite is accepted (Ed25519 only: no PQ binding needed, and no PQ protection)")
    pinned = pins is not _UNDEF and len(pins) > 0
    if not pinned and _g(v, "trustedRoot") is not True:
        return _res(id_, "warn", "post-quantum suite(s) accepted (%s) with neither pqPins nor a stored trustedRoot: a non-Ed25519 root is "
                    "refused (fail closed) or its PQ key is not pinned" % ", ".join(pq), PQ_REMEDIATION)
    return _res(id_, "pass", "PQ suites (%s) are bound: %s; allowUnboundPq off"
                % (", ".join(pq), "%d pin(s)" % len(pins) if pinned else "stored trustedRoot"))


# ---- root caveats and enforcement -----------------------------------------------------------------


class LoadedPca:
    """The library under test: its ``version``, where it was found (``path``) and how to ``probe`` it:
    ``probe(root_caveat, amount) -> {"allowed": bool, "reasons": [str]}`` decides a payment of ``amount`` USD under a root grant that
    carries ``root_caveat``."""

    def __init__(self, version: str, path: str, probe: Callable[[Dict[str, Any], float], Dict[str, Any]]) -> None:
        self.version, self.path, self.probe = version, path, probe


def compare_version(a: str, b: str) -> int:
    """-1 / 0 / 1 for a < b / = / > over major.minor.patch (pre-release tags ignored); NaN parts compare as -1."""
    pa = [_string_to_number(x) for x in re.split(r"[.+-]", a)[:3]]
    pb = [_string_to_number(x) for x in re.split(r"[.+-]", b)[:3]]
    for i in range(3):
        x = pa[i] if i < len(pa) and fin(pa[i]) else -1
        y = pb[i] if i < len(pb) and fin(pb[i]) else -1
        if x != y:
            return -1 if x < y else 1
    return 0


def _probe_in_process(root_caveat: Dict[str, Any], amount: float, now: Optional[int] = None) -> Dict[str, Any]:
    """A payment of ``amount`` USD under a root caveat, through the installed library's caveat evaluation."""
    from .pca import evaluate_caveats

    at = int(_wall_ms()) if now is None else now
    ok, failed = evaluate_caveats([root_caveat], {"now": at, "action": {"verb": "pay", "resource": "invoice:42", "reversibility_class": "reversible",
                                                                       "params": {"amount": amount, "currency": "usd"}}})
    return {"allowed": ok is True, "reasons": [str(f) for f in failed]}


_PROBE_CODE = (
    "import json,sys\n"
    "from atlas_pca.pca import evaluate_caveats\n"
    "cv,amount=json.loads(sys.argv[1])\n"
    "ok,failed=evaluate_caveats([cv],{'now':int(__import__('time').time()*1000),'action':{'verb':'pay','resource':'invoice:42',"
    "'reversibility_class':'reversible','params':{'amount':amount,'currency':'usd'}}})\n"
    "print(json.dumps({'allowed':ok is True,'reasons':[str(f) for f in failed]}))\n")


def _version_in(site: str) -> Optional[str]:
    try:
        names = sorted(os.listdir(site))
    except OSError:
        return None
    for n in names:
        if n.startswith("atlas_pca-") and n.endswith(".dist-info"):
            try:
                with open(os.path.join(site, n, "METADATA"), encoding="utf-8") as fh:
                    for line in fh:
                        if line.startswith("Version:"):
                            return line.split(":", 1)[1].strip()
            except OSError:
                return None
    return None


def load_pca(directory: Optional[str] = None) -> LoadedPca:
    """Load the library to probe: this process's ``atlas_pca``, or (with ``directory``) the copy installed under that directory
    (its ``site-packages``), probed in a child interpreter so the two never mix. Raises when none is installed there."""
    if not directory:
        from importlib import metadata

        import atlas_pca

        try:
            version = metadata.version("atlas-pca")
        except metadata.PackageNotFoundError:
            version = str(getattr(atlas_pca, "__version__", "unknown"))
        return LoadedPca(version, os.path.dirname(os.path.abspath(atlas_pca.__file__)), _probe_in_process)
    import glob
    import subprocess

    root = os.path.abspath(directory)
    cands = [root] + sorted(glob.glob(os.path.join(root, "**", "site-packages"), recursive=True))
    site = next((c for c in cands if os.path.isfile(os.path.join(c, "atlas_pca", "__init__.py"))), None)
    if site is None:
        raise RuntimeError("atlas_pca is not installed in %s or any site-packages below it" % directory)
    version = _version_in(site) or "unknown"

    def probe(cv: Dict[str, Any], amount: float) -> Dict[str, Any]:
        out = subprocess.run([sys.executable, "-c", _PROBE_CODE, json.dumps([cv, amount])], capture_output=True, text=True, timeout=60,
                             env=dict(os.environ, PYTHONPATH=site))
        if out.returncode != 0:
            raise RuntimeError((out.stderr.strip().splitlines() or ["probe failed"])[-1])
        return json.loads(out.stdout)

    return LoadedPca(version, os.path.join(site, "atlas_pca"), probe)


def _decision(raw: Any) -> Dict[str, Any]:
    reasons = raw.get("reasons") if isinstance(raw, dict) else None
    return {"allowed": isinstance(raw, dict) and raw.get("allowed") is True,
            "reasons": [_js_string(r) for r in reasons] if isinstance(reasons, list) else []}


def check_root_caveats(cfg: Any, load: Optional[Callable[[Optional[str]], LoadedPca]] = None) -> Dict[str, Any]:
    """Root-caveat enforcement (0.4.1 security fix): the deployed library must be >= 0.4.1, and a functional probe through THAT library
    must show a root max_spend of 100 denying 150 and allowing 50, and an unknown root caveat type denying (fail closed)."""
    id_ = "caveats.root"
    d = _g(_g(cfg, "verifier"), "pcaDir")
    pca_dir = d if _truthy(d) else None
    try:
        pca = (load or load_pca)(pca_dir if pca_dir is None else _js_string(pca_dir))
    except Exception as e:  # noqa: BLE001
        return _res(id_, "fail", "cannot load @atlasauth/pca%s: %s" % (" from %s" % _js_string(pca_dir) if pca_dir is not None else "", e), CAVEAT_REMEDIATION)
    where = "@atlasauth/pca %s at %s" % (pca.version, pca.path)
    if compare_version(pca.version, ROOT_CAVEAT_MIN_VERSION) < 0:
        return _res(id_, "fail", "%s: root caveats outside the envelope are NOT enforced before %s (legacy behaviour)" % (where, ROOT_CAVEAT_MIN_VERSION),
                    CAVEAT_REMEDIATION)
    try:
        over = _decision(pca.probe({"type": "max_spend", "usd": 100}, 150))
        under = _decision(pca.probe({"type": "max_spend", "usd": 100}, 50))
        unknown = _decision(pca.probe({"type": "pca-doctor-unknown-caveat"}, 50))
    except Exception as e:  # noqa: BLE001
        return _res(id_, "fail", "%s: the enforcement probe could not run: %s" % (where, e), CAVEAT_REMEDIATION)
    observed = {"version": pca.version, "over": over, "under": under, "unknown": unknown}
    if over["allowed"] or unknown["allowed"]:
        return _res(id_, "fail", "%s: a root caveat was NOT enforced (%s)"
                    % (where, "max_spend 100 allowed a 150 payment" if over["allowed"] else "an unknown root caveat type was allowed"),
                    CAVEAT_REMEDIATION, observed)
    if not under["allowed"]:
        return _res(id_, "warn", "%s: inconclusive: the control payment within the root max_spend was denied too (%s)" % (where, "; ".join(under["reasons"])),
                    observed=observed)
    return _res(id_, "pass", "%s: root caveats enforced (max_spend 100 denies 150, allows 50; an unknown root caveat type denies)" % where, observed=observed)


def check_enforcement(cfg: Any) -> Dict[str, Any]:
    """requirePCA must not run with insecureAllowUnenforced, and a custom ``require`` list should keep the defaults."""
    id_ = "verifier.enforcement"
    v = _g(cfg, "verifier")
    if not _truthy(v):
        return _res(id_, "skip", "no verifier configuration given (config verifier.*)")
    if _g(v, "insecureAllowUnenforced") is True:
        return _res(id_, "fail", "requirePCA runs with insecureAllowUnenforced: required checks that are not enforced do not deny",
                    "Remove insecureAllowUnenforced and supply the stores the required checks need (counter / revocation / budget).")
    req = _g(v, "require")
    if req is not _UNDEF:
        if isinstance(req, list):
            missing = [c for c in DEFAULT_REQUIRED if c not in req]
        elif isinstance(req, str):
            missing = [c for c in DEFAULT_REQUIRED if c not in req]  # String.prototype.includes: a substring test
        else:
            raise TypeError("require.includes is not a function")
        if missing:
            return _res(id_, "warn", "the require list drops default check(s): %s" % ", ".join(missing),
                        "Keep every default required check (%s) and add to it." % ", ".join(DEFAULT_REQUIRED))
    if _truthy(req):
        if not isinstance(req, list):
            raise TypeError("require.join is not a function")
        return _res(id_, "pass", "require = %s" % ", ".join("" if x is None else _js_string(x) for x in req))
    return _res(id_, "pass", "default required checks; insecureAllowUnenforced off")


# ---- the replay store -----------------------------------------------------------------------------


def load_adapter(spec: str, options: Optional[Dict[str, str]] = None) -> Any:
    """A store adapter: ``builtin:<name>`` (the kit's reference adapters) or ``module[:attribute]`` / ``path/to/file.py[:attribute]``.
    The export is an adapter (``name`` and ``open()``) or a factory taking the options dict and returning one."""
    from . import store_conformance_runner as kit

    opts = dict(options or {})
    if spec.startswith("builtin:"):
        name = spec[len("builtin:"):]
        if name not in kit.REFERENCE_ADAPTERS:
            raise ValueError("unknown built-in adapter '%s' (known: %s)" % (name, ", ".join(kit.REFERENCE_ADAPTERS)))
        exported: Any = kit.REFERENCE_ADAPTERS[name]
    else:
        import importlib
        import importlib.util

        target, _, attr = spec.partition(":")
        if target.endswith(".py"):
            s = importlib.util.spec_from_file_location("pca_doctor_store_adapter", os.path.abspath(target))
            if s is None or s.loader is None:
                raise ValueError("cannot load %s" % target)
            mod = importlib.util.module_from_spec(s)
            s.loader.exec_module(mod)
        else:
            mod = importlib.import_module(target)
        names = [attr] if attr else ["adapter", "create_adapter", "store_adapter"]
        found = next((getattr(mod, n) for n in names if hasattr(mod, n)), None)
        if found is None:
            raise ValueError("%s: exports none of %s" % (spec, ", ".join(names)))
        exported = found
    a = exported(opts) if callable(exported) and not hasattr(exported, "open") else exported
    if a is None or not callable(getattr(a, "open", None)) or not isinstance(getattr(a, "name", None), str):
        raise TypeError("%s: does not export a store adapter (an object with a string 'name' and an 'open()' method, or a factory returning one)" % spec)
    return a


_OP = {"consume": "consumeOnce", "advance": "advance"}


def _first_counterexample(h: Dict[str, Any]) -> str:
    from .store_conformance_model import format_ops

    if not h["violations"]:
        return ""
    v = h["violations"][0]
    return " First violating key %s: %s" % (v["key"], " | ".join(format_ops(v.get("counterexample") or [])))


def check_store(cfg: Any, loader: Optional[Callable[..., Any]] = None) -> List[Dict[str, Any]]:
    """Replay / counter store checks through the conformance kit's adapter interface: a REAL concurrent conflicting write (many clients
    consume one fresh key at once: exactly one may win; counters race on one stream) and durability (write, close, restart when the
    adapter can, read back). Short by design; the full kit goes further."""
    from . import store_conformance_runner as kit

    store = _g(cfg, "store")
    spec = _g(store, "adapter")
    if not _truthy(spec):
        detail = "no store adapter given (--store ./adapter.mjs); the replay store cannot be exercised remotely"
        return [_res("store.atomicity", "skip", detail), _res("store.durability", "skip", detail)]
    opts = _g(store, "options")
    try:
        adapter = (loader or load_adapter)(_js_string(spec), opts if isinstance(opts, dict) else {})
    except Exception as e:  # noqa: BLE001
        return [_res("store.atomicity", "fail", "cannot load the store adapter %s: %s" % (_js_string(spec), e),
                     "Point --store at a module exporting a store adapter (see the store conformance kit guide).")]
    try:
        kinds = kit.detect_kinds(adapter)
        return [_store_atomicity(adapter, kinds, store), _store_durability(adapter, kinds)]
    except Exception as e:  # noqa: BLE001
        return [_res("store.atomicity", "fail", "the store adapter failed: %s" % e, ATOMICITY_REMEDIATION)]
    finally:
        if callable(getattr(adapter, "teardown", None)):
            adapter.teardown()


def _store_atomicity(adapter: Any, kinds: Sequence[str], store: Any) -> Dict[str, Any]:
    from . import store_conformance_runner as kit

    clients = _nn(_g(store, "concurrency"), 32)
    rounds = _nn(_g(store, "rounds"), 10)
    parts: List[str] = []
    observed: Dict[str, Any] = {}
    status, cx = "pass", ""
    for kind in kinds:
        w = kit.run_burst(adapter, kind, {"clients": clients, "rounds": rounds, "values": 8})
        h = kit.check_history(w["ops"])
        winners = len({o["key"] for o in w["ops"] if o["res"] == "true"})
        observed[kind] = {"ops": h["ops"], "keys": h["keys"], "outcomes": h["outcomes"], "violations": len(h["violations"]),
                          "unresolved": len(h["unresolved"])}
        definite = h["outcomes"]["true"] + h["outcomes"]["false"]
        if h["violations"]:
            status = "fail"
            cx = cx or _first_counterexample(h)
            parts.append("%s: %d of %s same-key rounds NOT linearizable (%s concurrent clients)" % (_OP[kind], len(h["violations"]), _js_string(rounds), _js_string(clients)))
        elif definite == 0 or h["unresolved"]:
            if status == "pass":
                status = "warn"
            parts.append("%s: inconclusive (%d of %d calls failed or timed out%s)" % (
                _OP[kind], w["errors"], h["ops"], ", %d key(s) undecided" % len(h["unresolved"]) if h["unresolved"] else ""))
        else:
            parts.append("%s: %s rounds of %s concurrent conflicting calls linearizable%s%s" % (
                _OP[kind], _js_string(rounds), _js_string(clients),
                " (%d of %s rounds had exactly one TRUE)" % (winners, _js_string(rounds)) if kind == "consume" else "",
                ", %d calls failed closed" % w["errors"] if w["errors"] else ""))
    return _res("store.atomicity", status, "%s: %s.%s" % (adapter.name, "; ".join(parts), cx), None if status == "pass" else ATOMICITY_REMEDIATION, observed)


def _store_durability(adapter: Any, kinds: Sequence[str]) -> Dict[str, Any]:
    from . import store_conformance_runner as kit

    if (adapter.capabilities or {}).get("durable") is False:
        return _res("store.durability", "warn", "%s declares itself non-durable: a restart forgets consumed nonces" % adapter.name, DURABILITY_REMEDIATION)
    parts: List[str] = []
    status, cx = "pass", ""
    for kind in kinds:
        w = kit.run_durability(adapter, kind)
        h = kit.check_history(w["ops"])
        if h["violations"]:
            status = "fail"
            cx = cx or _first_counterexample(h)
            parts.append("%s: state LOST across close/restart" % _OP[kind])
        elif h["outcomes"]["true"] + h["outcomes"]["false"] < len(w["ops"]):
            if status == "pass":
                status = "warn"
            parts.append("%s: inconclusive (%d calls failed)" % (_OP[kind], w["errors"]))
        else:
            parts.append("%s: survived" % _OP[kind])
    how = ("write, close, restart() the backend, read back" if adapter.restart
           else "write, close, re-open (no restart() hook: the backend itself was not restarted)")
    return _res("store.durability", status, "%s (%s): %s.%s" % (adapter.name, how, "; ".join(parts), cx), None if status == "pass" else DURABILITY_REMEDIATION)


# ---- configuration --------------------------------------------------------------------------------


def _valid_http_url(u: Any) -> Optional[str]:
    """The scheme of ``u`` when it parses as an absolute URL, else None (the reference's ``new URL`` throws)."""
    if not isinstance(u, str):
        return None
    try:
        sp = urlsplit(u.strip(_WS))
        sp.port  # noqa: B018 - a malformed port raises
    except ValueError:
        return None
    scheme = sp.scheme.lower()
    if not scheme:
        return None
    if scheme in ("http", "https", "ftp", "ws", "wss") and not sp.hostname:
        return None
    return scheme


def config_problems(cfg: Any) -> List[str]:
    """Numeric settings that would make a check meaningless (NaN, negative, zero where a duration is needed) are configuration errors."""
    out: List[str] = []

    def pos(name: str, v: Any, integer: bool = False) -> None:
        if v is _UNDEF:
            return
        if not _is_num(v) or not fin(v) or v <= 0 or (integer and not _is_integer(v)):
            out.append("%s must be a positive %s" % (name, "integer" if integer else "number"))

    def nonneg(name: str, v: Any) -> None:
        if v is _UNDEF:
            return
        if not _is_num(v) or not _is_integer(v) or v < 0 or _neg_zero(v):
            out.append("%s must be a non-negative integer" % name)

    clock, store, proxy = _g(cfg, "clock"), _g(cfg, "store"), _g(cfg, "proxy")
    pos("clock.maxSkewMs", _g(clock, "maxSkewMs"))
    pos("clock.timeoutMs", _g(clock, "timeoutMs"))
    wf = _g(clock, "warnFraction")
    if wf is not _UNDEF and not (_is_num(wf) and 0 < wf <= 1):
        out.append("clock.warnFraction must be a number in (0, 1]")
    pos("store.concurrency", _g(store, "concurrency"), True)
    pos("store.rounds", _g(store, "rounds"), True)
    nonneg("proxy.trustedProxyCount", _g(proxy, "trustedProxyCount"))
    nonneg("proxy.hops", _g(proxy, "hops"))
    url = _g(cfg, "url")
    if url is not _UNDEF:
        scheme = _valid_http_url(url)
        if scheme is None:
            out.append("url is not a valid URL")
        elif scheme not in ("http", "https"):
            out.append("url must be an http(s) URL")
    return out


def run_doctor(cfg: Any, only: Optional[Sequence[str]] = None, fetch: Optional[Callable[..., Any]] = None, now: Optional[Callable[[], float]] = None,
               load: Optional[Callable[[Optional[str]], LoadedPca]] = None, loader: Optional[Callable[..., Any]] = None) -> List[Dict[str, Any]]:
    """Run the selected check groups (all by default) and scrub everything they report. An invalid configuration is reported as
    ``config`` failures and nothing else runs. A group that raises is a failed check, not a crashed run and not a skipped one."""
    sel = list(CHECK_GROUPS) if only is None else list(only)
    problems = config_problems(cfg)
    if problems:
        return [_res("config", "fail", scrub_text("invalid configuration: %s" % p), "Correct the setting; no check was run.") for p in problems]
    f = fetch or default_fetch
    out: List[Dict[str, Any]] = []

    def guarded(id_: str, run: Callable[[], Any]) -> None:
        try:
            r = run()
            out.extend(r if isinstance(r, list) else [r])
        except Exception as e:  # noqa: BLE001
            out.append(_res(id_, "fail", "%s could not run: %s" % (id_, scrub_text(str(e))),
                            "Fix the configuration or the dependency named above and run the doctor again."))

    if "clock" in sel:
        guarded("clock", lambda: check_clock(cfg, f, now))
    if "store" in sel:
        guarded("store", lambda: check_store(cfg, loader))
    if "proxy" in sel:
        guarded("proxy.config", lambda: check_proxy_config(cfg))
        guarded("proxy.probe", lambda: check_proxy_probe(cfg, f))
    if "suites" in sel:
        guarded("suites.allowed", lambda: check_allowed_suites(cfg))
        guarded("suites.pq", lambda: check_pq_binding(cfg))
    if "caveats" in sel:
        guarded("caveats.root", lambda: check_root_caveats(cfg, load))
        guarded("caveats.enforcement", lambda: check_enforcement(cfg))
    # nothing the doctor prints may carry a credential from the deployment URL, an adapter option or an error message
    return [scrub_deep(r) for r in out]


def verdict_of(results: Sequence[Dict[str, Any]], strict: bool = False) -> str:
    """fail if any check failed; warn if any warned (fail under strict); else pass. A run in which nothing was checked (no results, or
    every result skipped) is a fail: a doctor that looked at nothing must not report a healthy deployment."""
    if not any(r.get("status") != "skip" for r in results):
        return "fail"
    if any(r.get("status") == "fail" for r in results):
        return "fail"
    if any(r.get("status") == "warn" for r in results):
        return "fail" if strict else "warn"
    return "pass"


def format_results(results: Sequence[Dict[str, Any]], target: Optional[str] = None, strict: bool = False) -> str:
    lines = ["pca-doctor%s" % (": %s" % target if _truthy(target) else "")]
    for r in results:
        lines.append("  %s  %s %s" % (_pad_end(str(r["status"]).upper(), 4), _pad_end(str(r["id"]), 20), r["detail"]))
        if _truthy(r.get("remediation", _UNDEF)):
            lines.append("  %s  %s fix: %s" % (" " * 4, " " * 20, r["remediation"]))

    def n(s: str) -> int:
        return sum(1 for r in results if r.get("status") == s)

    if not any(r.get("status") != "skip" for r in results):
        lines.append("  FAIL  nothing checked        no check produced a result: nothing about this deployment was verified")
    lines.append("Summary: %d pass, %d warn, %d fail, %d skip -> %s" % (n("pass"), n("warn"), n("fail"), n("skip"), verdict_of(results, strict).upper()))
    return "\n".join(lines)


_TRUTHY_ENV = re.compile(r"1|true|yes|on", re.ASCII | re.IGNORECASE)


def _env_int(name: str, v: Optional[str]) -> Any:
    if v is None or v == "":
        return _UNDEF
    n = _string_to_number(v)
    if not _is_integer(n) or n < 0 or _neg_zero(n):
        raise ValueError("%s must be a non-negative integer" % name)
    return int(n)


def config_from_env(env: Dict[str, Optional[str]]) -> Dict[str, Any]:
    """The deployment's own environment variable names (as the API and the guides use them)."""
    c: Dict[str, Any] = {}
    if env.get("PCA_DOCTOR_URL"):
        c["url"] = env["PCA_DOCTOR_URL"]
    if env.get("PCA_DOCTOR_REFERENCE_URL"):
        c["clock"] = {"referenceUrl": env["PCA_DOCTOR_REFERENCE_URL"]}
    if env.get("PCA_DOCTOR_STORE"):
        c["store"] = {"adapter": env["PCA_DOCTOR_STORE"]}
    proxy: Dict[str, Any] = {}
    touched = False
    if env.get("TRUSTED_PROXY_COUNT") is not None:
        touched = True
        v = _env_int("TRUSTED_PROXY_COUNT", env["TRUSTED_PROXY_COUNT"])
        if v is not _UNDEF:
            proxy["trustedProxyCount"] = v
    if env.get("TRUSTED_PROXY_HEADER"):
        touched = True
        h = env["TRUSTED_PROXY_HEADER"].lower()
        if h not in PROXY_HEADERS:
            raise ValueError("TRUSTED_PROXY_HEADER must be one of %s" % ", ".join(PROXY_HEADERS))
        proxy["header"] = h
    if env.get("PCA_TRUSTED_PROXY_HOPS") is not None:
        touched = True
        v = _env_int("PCA_TRUSTED_PROXY_HOPS", env["PCA_TRUSTED_PROXY_HOPS"])
        if v is not _UNDEF:
            proxy["hops"] = v
    if touched:
        c["proxy"] = proxy
    verifier: Dict[str, Any] = {}
    if env.get("PCA_ALLOWED_SUITES") is not None:
        verifier["allowedSuites"] = [t for t in (s.strip(_WS) for s in env["PCA_ALLOWED_SUITES"].split(",")) if t]
    if env.get("PCA_PQ_PINS"):
        def _no_const(name: str) -> Any:
            raise ValueError(name)

        try:
            pins = json.loads(env["PCA_PQ_PINS"], parse_constant=_no_const)
        except ValueError:
            raise ValueError("PCA_PQ_PINS is not valid JSON") from None  # never echo the value
        if not isinstance(pins, dict) or not all(isinstance(x, str) for x in pins.values()):
            raise ValueError("PCA_PQ_PINS must be a JSON object of issuer -> public key strings")
        verifier["pqPins"] = pins
    if env.get("PCA_ALLOW_UNBOUND_PQ") is not None:
        verifier["allowUnboundPq"] = _TRUTHY_ENV.fullmatch(env["PCA_ALLOW_UNBOUND_PQ"]) is not None
    if verifier:
        c["verifier"] = verifier
    return c


def _spread(v: Any) -> Dict[str, Any]:
    """``{...v}`` of a decoded JSON value: an object's members, an array's or a string's indices."""
    if isinstance(v, dict):
        return dict(v)
    if isinstance(v, list):
        return {str(i): x for i, x in enumerate(v)}
    if isinstance(v, str):
        u = v.encode("utf-16-le", "surrogatepass")
        return {str(i): u[2 * i:2 * i + 2].decode("utf-16-le", "surrogatepass") for i in range(len(u) // 2)}
    return {}


def merge_config(*cs: Any) -> Dict[str, Any]:
    """Two-level merge: later sources win per field inside each section."""
    out: Dict[str, Any] = {}
    for c in cs:
        for k, val in c.items():
            if k in ("__proto__", "constructor", "prototype"):
                raise ValueError('config key "%s" is not allowed' % k)
            if val is _UNDEF:
                continue
            if isinstance(val, dict):
                merged = _spread(_nn(out.get(k, _UNDEF), {}))
                merged.update(val)
                out[k] = merged
            else:
                out[k] = val
    return out


def load_config_file(path: str) -> Dict[str, Any]:
    """A JSON file, or a Python file whose ``config`` (or ``CONFIG``) is the config dict."""
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    if path.endswith(".py"):
        import importlib.util

        s = importlib.util.spec_from_file_location("pca_doctor_config", os.path.abspath(path))
        if s is None or s.loader is None:
            raise ValueError("cannot load %s" % path)
        mod = importlib.util.module_from_spec(s)
        s.loader.exec_module(mod)
        cfg = getattr(mod, "config", getattr(mod, "CONFIG", None))
        if not isinstance(cfg, dict):
            raise ValueError("%s: defines no config dict" % path)
        return cfg
    raise ValueError("only a .json or .py config file can be loaded: %s" % path)


# ---- CLI ------------------------------------------------------------------------------------------


def _groups(flag: str, v: Optional[str]) -> List[str]:
    g = [x for x in (v or "").split(",") if x]
    bad = [x for x in g if x not in CHECK_GROUPS]
    if bad or not g:
        raise ValueError("%s: unknown check group(s) %s" % (flag, ", ".join(bad) or "(none given)"))
    return g


def _num_arg(flag: str, v: Optional[str]) -> float:
    n = math.nan if v is None or v == "" else _string_to_number(v)
    if not fin(n):
        raise ValueError("%s needs a number" % flag)
    return int(n) if n == math.floor(n) and abs(n) < 2 ** 53 else n


def _set(d: Dict[str, Any], key: str, v: Any) -> None:
    """``d.key = v`` where an undefined value leaves the member absent."""
    if v is None:
        d.pop(key, None)
    else:
        d[key] = v


def parse_doctor_args(argv: Sequence[str]) -> Dict[str, Any]:
    """The parsed command line: ``{"flags" (a config), "only", "json", "strict", "help", "config"?}``."""
    a: Dict[str, Any] = {"flags": {}, "only": list(CHECK_GROUPS), "json": False, "strict": False, "help": False}
    f = a["flags"]
    i = 0

    def sub(name: str) -> Dict[str, Any]:
        d = dict(f.get(name) or {})
        f[name] = d
        return d

    def nxt() -> Optional[str]:
        nonlocal i
        i += 1
        return argv[i] if i < len(argv) else None

    while i < len(argv):
        k = argv[i]
        if k == "--url":
            _set(f, "url", nxt())
        elif k == "--config":
            v = nxt()
            if v is None:
                a.pop("config", None)
            else:
                a["config"] = v
        elif k == "--store":
            _set(sub("store"), "adapter", nxt())
        elif k == "--store-option":
            kv = nxt() or ""
            eq = kv.find("=")
            if eq < 1:
                raise ValueError("--store-option needs k=v")
            st = sub("store")
            opts = dict(st.get("options") or {})
            opts[kv[:eq]] = kv[eq + 1:]
            st["options"] = opts
        elif k == "--reference":
            _set(sub("clock"), "referenceUrl", nxt())
        elif k == "--max-skew-ms":
            sub("clock")["maxSkewMs"] = _num_arg(k, nxt())
        elif k == "--trusted-proxy-count":
            sub("proxy")["trustedProxyCount"] = _num_arg(k, nxt())
        elif k == "--proxy-header":
            h = (nxt() or "").lower()
            if h not in PROXY_HEADERS:
                raise ValueError("--proxy-header must be x-forwarded-for, forwarded or x-real-ip")
            sub("proxy")["header"] = h
        elif k == "--proxy-hops":
            sub("proxy")["hops"] = _num_arg(k, nxt())
        elif k == "--no-probe":
            sub("proxy")["probe"] = False
        elif k == "--pca-dir":
            _set(sub("verifier"), "pcaDir", nxt())
        elif k == "--only":
            a["only"] = _groups(k, nxt())
        elif k == "--skip":
            s = _groups(k, nxt())
            a["only"] = [g for g in a["only"] if g not in s]
        elif k == "--strict":
            a["strict"] = True
        elif k == "--json":
            a["json"] = True
        elif k in ("-h", "--help"):
            a["help"] = True
        else:
            raise ValueError("unknown argument %s" % k)
        i += 1
    return a


def _json_string(s: str) -> str:
    esc = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
    return '"' + "".join(esc.get(c) or ("\\u%04x" % ord(c) if ord(c) < 0x20 or 0xD800 <= ord(c) <= 0xDFFF else c) for c in s) + '"'


def _stringify(v: Any, ind: str = "") -> str:
    """``JSON.stringify(v, null, 2)``."""
    if v is None or v is _UNDEF:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _json_string(v)
    if _is_num(v):
        return "null" if not fin(v) else _js_number_string(float(v))
    inner = ind + "  "
    if isinstance(v, (list, tuple)):
        if not v:
            return "[]"
        return "[\n" + ",\n".join(inner + _stringify(x, inner) for x in v) + "\n" + ind + "]"
    items = [(k, x) for k, x in v.items() if x is not _UNDEF]
    if not items:
        return "{}"
    return "{\n" + ",\n".join(inner + _json_string(str(k)) + ": " + _stringify(x, inner) for k, x in items) + "\n" + ind + "}"


def main(argv: Sequence[str], env: Optional[Dict[str, Optional[str]]] = None, print_out: Callable[[str], Any] = print,
         print_err: Callable[[str], Any] = lambda s: print(s, file=sys.stderr), **deps: Any) -> int:
    """Run the CLI: exit code 1 on any fail (and on warn with --strict), 2 on usage errors, else 0. ``deps`` are ``run_doctor``'s
    ``fetch`` / ``now`` / ``load`` / ``loader``."""
    try:
        a = parse_doctor_args(argv)
        if a["help"]:
            print_out(USAGE)
            return 0
        cfg = merge_config(load_config_file(a["config"]) if a.get("config") else {}, config_from_env(os.environ if env is None else env), a["flags"])
    except Exception as e:  # noqa: BLE001
        print_err("%s\n\n%s" % (scrub_text(str(e)), USAGE))
        return 2
    results = run_doctor(cfg, a["only"], **deps)
    verdict = verdict_of(results, a["strict"])
    url = cfg.get("url")
    if a["json"]:
        print_out(_stringify({"target": url, "verdict": verdict, "results": results}))
    else:
        print_out(format_results(results, _js_string(url) if _truthy(url) else None, a["strict"]))
    return 1 if verdict == "fail" else 0


# ---- what only makes sense for a Python install -----------------------------------------------------


def check_runtime(cfg: Any = None) -> Dict[str, Any]:
    """Which registered suites this Python runtime can verify, and which optional backends are importable. When ``verifier.allowedSuites``
    names a suite that is registered but not verifiable here, it fails closed at verification time: that is a warning here."""
    from .pca import suite_available

    avail = [s for s in REGISTERED_SUITES if suite_available(s)]
    missing = [s for s in REGISTERED_SUITES if s not in avail]
    extras = {}
    for mod in ("cryptography", "dilithium_py"):
        try:
            __import__(mod)
            extras[mod] = True
        except Exception:  # noqa: BLE001 - an absent or broken optional dependency
            extras[mod] = False
    observed = {"available": avail, "unavailable": missing, "extras": extras}
    allowed = _g(_g(cfg, "verifier"), "allowedSuites")
    want = [s for s in allowed if isinstance(s, str)] if isinstance(allowed, list) else []
    dead = [s for s in want if s in missing]
    if dead:
        return _res("suites.runtime", "warn", "allowedSuites names suite(s) this Python runtime cannot verify (they are refused, fail closed): %s. "
                    "Verifiable here: %s" % (", ".join(dead), ", ".join(avail)),
                    "Install the post-quantum backend (pip install atlas-pca[pq], or OpenSSL >= 3.5) or drop the suite from allowedSuites.", observed)
    return _res("suites.runtime", "pass", "verifiable in this runtime (%d of %d registered suites): %s" % (len(avail), len(REGISTERED_SUITES), ", ".join(avail)),
                observed=observed)


probe_decision = _probe_in_process  # the reference's probeDecision: a payment under a root caveat, decided by the installed library
