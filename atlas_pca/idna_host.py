"""WHATWG domainToASCII (UTS 46, non-transitional, no STD3 rules, no hyphen / length checks), the host mapping Node applies.

``ada-url`` (a core dependency: the Ada URL parser Node itself uses, as a binary wheel) makes the result byte-identical to the reference.
If it cannot be imported a stdlib approximation runs (NFKC + per-label punycode): fine for plain names, not UTS 46 conformant in corners.
Returns '' when a host cannot be encoded."""
import unicodedata

try:  # a core dependency; unusable only on a platform with no ada-url wheel
    from ada_url import idna as _ada
except Exception:  # noqa: BLE001 - absent or unusable: the approximation below
    _ada = None


def _approx(w: str) -> str:
    try:
        m = unicodedata.normalize("NFKC", "".join(c.lower() for c in w))
        for dot in "。．｡":
            m = m.replace(dot, ".")
        return ".".join(l if l.isascii() else "xn--" + l.encode("punycode").decode("ascii") for l in m.split("."))
    except Exception:  # noqa: BLE001
        return ""


def domain_to_ascii(w: str) -> str:
    if _ada is not None:
        try:
            r = _ada.encode(w)
            return r.decode("ascii") if isinstance(r, (bytes, bytearray)) else str(r)
        except Exception:  # noqa: BLE001 - Ada refused the host
            return ""
    return _approx(w)
