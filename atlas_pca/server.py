"""Framework-agnostic server guard for Proof-Carrying Authority (PCA).

Sits ON TOP of the reference verifier in ``atlas_pca.pca`` (``verify_pcactn_core``) and turns an
incoming request into an authorization decision. No crypto lives here: extraction + grant resolution
+ HTTP status mapping only.

A PCActn is carried either in the ``PCA-Action`` request header (base64url of the UTF-8 JSON, decoded
through the strict profile) or in a JSON request body shaped ``{"pcactn": <pcactn>}``.

Status mapping (mirrors the TS edge verifier):
  * 401 — no PCActn present, an undecodable one, or an unknown grant (authentication is missing/opaque)
  * 403 — a well-formed PCActn whose verdict denies (authority is insufficient)
  * 200 — verdict allows
Every non-200 result carries a ``WWW-Authenticate: PCA ...`` challenge string.
"""
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Union

from .pca import StrictJsonError, Verdict, decode_b64u_strict, strict_parse, verify_pcactn_core

PCA_HEADER = "PCA-Action"
REALM = "pca"

GrantResolver = Callable[[Optional[str]], Optional[dict]]


@dataclass
class PCAResult:
    """Outcome of the guard. ``ok`` is the one thing a caller must branch on."""

    ok: bool
    status: int
    verdict: Optional[Verdict] = None
    pcactn: Optional[dict] = None
    error: Optional[str] = None
    www_authenticate: Optional[str] = None

    # Dict-style access so callers can treat it as {ok, status, verdict, pcactn, ...}.
    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


def _quote(v: str) -> str:
    # auth-param quoted-string: escape backslash and double-quote (RFC 7235).
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def challenge(audience: Optional[str], error: Optional[str] = None,
              description: Optional[str] = None) -> str:
    """Build a ``WWW-Authenticate`` challenge value: ``PCA realm="pca", ...``."""
    parts = ["realm=" + _quote(REALM)]
    if audience is not None:
        parts.append("audience=" + _quote(audience))
    if error is not None:
        parts.append("error=" + _quote(error))
    if description is not None:
        parts.append("error_description=" + _quote(description))
    return "PCA " + ", ".join(parts)


def _get_header(headers: Mapping[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup over any Mapping (plain dict, Starlette Headers, Django headers)."""
    if headers is None:
        return None
    try:
        v = headers.get(name)  # fast path; Starlette/Django are already case-insensitive
    except Exception:
        v = None
    if v is not None:
        return v
    low = name.lower()
    try:
        for k, val in headers.items():
            if isinstance(k, str) and k.lower() == low:
                return val
    except Exception:
        return None
    return None


def _to_text(body: Union[bytes, bytearray, str, None]) -> Optional[str]:
    if body is None:
        return None
    if isinstance(body, (bytes, bytearray)):
        if not body:
            return None
        try:
            return bytes(body).decode("utf-8")
        except UnicodeDecodeError:
            return None
    if isinstance(body, str):
        return body if body else None
    return None


def extract_pcactn(headers: Mapping[str, str],
                   body: Union[bytes, bytearray, str, None]) -> "tuple[Optional[dict], Optional[str]]":
    """Pull the PCActn object out of the header or the body.

    Returns ``(pcactn, error)``. ``pcactn`` is the strict-parsed object on success; ``error`` is a short
    reason (``"absent"`` or ``"undecodable"``) that the guard maps to 401.
    """
    raw = _get_header(headers, PCA_HEADER)
    if raw is not None:
        decoded = decode_b64u_strict(raw)
        if decoded is None:
            return None, "undecodable"
        try:
            obj = strict_parse(decoded)
        except StrictJsonError:
            return None, "undecodable"
        if not isinstance(obj, dict):
            return None, "undecodable"
        return obj, None

    text = _to_text(body)
    if text is None:
        return None, "absent"
    try:
        envelope = strict_parse(text)
    except StrictJsonError:
        return None, "undecodable"
    if not isinstance(envelope, dict) or "pcactn" not in envelope:
        return None, "absent"
    inner = envelope["pcactn"]
    if not isinstance(inner, dict):
        return None, "undecodable"
    return inner, None


def require_pca(*, audience: str, resolve_grant: GrantResolver,
                now: Optional[int] = None) -> Callable[..., PCAResult]:
    """Build a framework-agnostic guard.

    ``audience``      — this resource server's own id; the PCActn's signed ``aud`` must equal it.
    ``resolve_grant`` — ``(grant_ref) -> grant | None``; maps the PCActn's ``grant_ref`` to the root grant.
    ``now``           — epoch milliseconds for the validity window (default: wall clock at check time).

    The returned callable takes ``(headers, body)`` and returns a :class:`PCAResult`.
    """

    def guard(headers: Mapping[str, str],
              body: Union[bytes, bytearray, str, None] = None) -> PCAResult:
        pcactn, err = extract_pcactn(headers, body)
        if pcactn is None:
            desc = "no PCActn presented" if err == "absent" else "PCActn could not be decoded"
            return PCAResult(ok=False, status=401, error=err,
                             www_authenticate=challenge(audience, "invalid_request", desc))

        grant_ref = pcactn.get("grant_ref") if isinstance(pcactn, dict) else None
        grant = resolve_grant(grant_ref)
        if not isinstance(grant, dict):
            return PCAResult(ok=False, status=401, pcactn=pcactn, error="unknown_grant",
                             www_authenticate=challenge(audience, "invalid_token",
                                                        "grant_ref does not resolve to a known grant"))

        verdict = verify_pcactn_core(pcactn, grant, now=now, audience=audience)
        if verdict.allow:
            return PCAResult(ok=True, status=200, verdict=verdict, pcactn=pcactn)
        return PCAResult(ok=False, status=403, verdict=verdict, pcactn=pcactn,
                         error=verdict.reason or "insufficient_authority",
                         www_authenticate=challenge(audience, "insufficient_authority", verdict.reason))

    return guard
