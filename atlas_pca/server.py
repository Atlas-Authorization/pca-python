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
Every non-200 result carries a ``WWW-Authenticate: PCA ...`` challenge string built only from fixed tokens and the
operator's own ``audience`` (never from verdict reasons or other request-derived text).
"""
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Union

from .pca import (StrictJsonError, PcaHeaderError, Verdict, artifact_too_large, decode_pca_header, strict_parse,
                  verify_pcactn_core)
from .authorize import AuthorizeOptions, AuthorizeResult

PCA_HEADER = "PCA-Action"
REALM = "pca"

GrantResolver = Callable[[Optional[str]], Optional[dict]]
# Intent Layer v2 verifier state: a dict (TS IntentV2Context), or a callable (pcactn) -> dict | None evaluated per request.
IntentV2Source = Union[dict, Callable[[dict], Optional[dict]], None]
# authorize mode: ``(headers, body) -> {"verb", "resource", "params"} | None``, the operation this request will execute.
OperationMapper = Callable[[Mapping[str, str], Union[bytes, bytearray, str, None]], Optional[Mapping[str, Any]]]


@dataclass
class PCAResult:
    """Outcome of the guard. ``ok`` is the one thing a caller must branch on."""

    ok: bool
    status: int
    verdict: Optional[Verdict] = None
    pcactn: Optional[dict] = None
    error: Optional[str] = None
    www_authenticate: Optional[str] = None
    #: authorize mode only: the full :class:`atlas_pca.authorize.AuthorizeResult` (checks, reasons, bound operation).
    authorization: Optional[AuthorizeResult] = None

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
        # 0.4.1: one strict decoder (unpadded base64url, no trimming, strict UTF-8 that keeps a BOM) for the header.
        try:
            decoded = decode_pca_header(raw)
        except PcaHeaderError:
            return None, "undecodable"
        if artifact_too_large(decoded):
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


def as_authorize_options(authorize: Union[AuthorizeOptions, Mapping[str, Any], None]) -> Optional[AuthorizeOptions]:
    """Normalize the ``authorize=`` option: an :class:`AuthorizeOptions`, a dict of its fields, or None."""
    if authorize is None or isinstance(authorize, AuthorizeOptions):
        return authorize
    if isinstance(authorize, Mapping):
        return AuthorizeOptions(**dict(authorize))
    raise TypeError("authorize must be an AuthorizeOptions, a dict of its fields, or None")


def require_pca(*, audience: str, resolve_grant: GrantResolver,
                now: Optional[int] = None, intent_policy: Optional[dict] = None,
                intent_v2: IntentV2Source = None,
                authorize: Union[AuthorizeOptions, Mapping[str, Any], None] = None,
                operation: Optional[OperationMapper] = None,
                signature_only: bool = False) -> Callable[..., PCAResult]:
    """Build a framework-agnostic guard.

    ``audience``      — this resource server's own id; the PCActn's signed ``aud`` must equal it.
    ``resolve_grant`` — ``(grant_ref) -> grant | None``; maps the PCActn's ``grant_ref`` to the root grant.
    ``now``           — epoch milliseconds for the validity window (default: wall clock at check time).
    ``intent_policy`` — optional Intent Layer M2 policy ``{"require", "min_fidelity_ppm", "max_residual_risk_ppm"}``
                        forwarded to ``verify_pcactn_core`` (an active policy denies a PCActn without a bound intent).
    ``intent_v2``     — optional Intent Layer v2 verifier state + policy (``policy``, ``params``, ``schema``, ``session``,
                        ``layers``, ``acc``, ``wb``; see ``atlas_pca.intent_v2.decide_intent_v2``): a dict, or a callable
                        ``(pcactn) -> dict | None`` evaluated per request (the host's store lookup: session root, held
                        grants, accumulator pre-state under its row lock, receipts, plaintext params). A callable that
                        raises fails closed (403 ``intent_v2_context_error``).

    ``authorize``     — the full pipeline (the default since 0.5): an :class:`atlas_pca.authorize.AuthorizeOptions` (or a
                        dict of its fields: ``state_store``, ``is_revoked``, ``plan``, ``context``, ``require``). Each
                        request goes through :func:`atlas_pca.authorize.authorize`: binding to the executed operation,
                        envelope predicates, root and delegated caveats, revocation and the replay counter, all
                        required. A missing component denies (403 ``authorize_config`` naming it); omitting ``authorize``
                        gives an empty option set, so every request is refused until you supply the store and the
                        revocation check. Nothing is ever downgraded to signature-only.
    ``signature_only`` — explicit opt-in to the core verifier alone (signature, chain, audience, validity, counter format):
                        no policy, replay or revocation check. Passing it together with ``authorize`` raises ``ValueError``.
    ``operation``     — authorize mode: ``(headers, body) -> {"verb", "resource", "params"} | None``, the operation the
                        handler will execute (from your routing and parsed body, never from the PCActn). The guard
                        call also accepts ``operation=`` directly. No operation denies (403).

    The returned callable takes ``(headers, body)`` (authorize mode: also ``operation=``) and returns a
    :class:`PCAResult`.
    """
    if signature_only and authorize is not None:
        raise ValueError("require_pca: signature_only and authorize are mutually exclusive")
    az = None if signature_only else (as_authorize_options(authorize) or AuthorizeOptions())

    def guard(headers: Mapping[str, str],
              body: Union[bytes, bytearray, str, None] = None, *,
              operation: Optional[Mapping[str, Any]] = None) -> PCAResult:
        pcactn, err = extract_pcactn(headers, body)
        if pcactn is None:
            desc = "no PCActn presented" if err == "absent" else "PCActn could not be decoded"
            return PCAResult(ok=False, status=401, error=err,
                             www_authenticate=challenge(audience, "invalid_request", desc))
        if az is not None:
            return _authorized(pcactn, headers, body, operation)

        grant_ref = pcactn.get("grant_ref") if isinstance(pcactn, dict) else None
        # Mirrors TS requirePCA: a grant_ref that is not a string (absent, null, list, dict, number) is a malformed
        # PCActn (401 invalid_pcactn) and never reaches the host's resolver.
        if not isinstance(grant_ref, str):
            return PCAResult(ok=False, status=401, pcactn=pcactn, error="malformed",
                             www_authenticate=challenge(audience, "invalid_pcactn", "malformed PCActn"))
        try:
            grant = resolve_grant(grant_ref)
        except Exception:  # noqa: BLE001 - the host's resolver failed: fail closed (TS: 403 guard error), never a 500
            return PCAResult(ok=False, status=403, pcactn=pcactn, error="resolve_grant_error",
                             www_authenticate=challenge(audience, "insufficient_authority",
                                                        "grant resolution failed (fail closed)"))
        if not isinstance(grant, dict):
            return PCAResult(ok=False, status=401, pcactn=pcactn, error="unknown_grant",
                             www_authenticate=challenge(audience, "invalid_token",
                                                        "grant_ref does not resolve to a known grant"))

        v2 = intent_v2
        if callable(intent_v2):
            try:
                v2 = intent_v2(pcactn)
            except Exception:  # noqa: BLE001 - the host's state lookup failed: fail closed, never verify without it
                return PCAResult(ok=False, status=403, pcactn=pcactn, error="intent_v2_context_error",
                                 www_authenticate=challenge(audience, "insufficient_authority",
                                                            "intent v2 verifier state unavailable (fail closed)"))
        verdict = verify_pcactn_core(pcactn, grant, now=now, audience=audience, intent_policy=intent_policy,
                                     intent_v2=v2)
        if verdict.allow:
            return PCAResult(ok=True, status=200, verdict=verdict, pcactn=pcactn)
        return PCAResult(ok=False, status=403, verdict=verdict, pcactn=pcactn,
                         error=verdict.reason or "insufficient_authority",
                         # Never echo verdict.reason into the header: it can carry attacker-controlled text (CR/LF ->
                         # header injection). TS requirePCA puts no reason in its challenge either; the reason stays
                         # on ``verdict`` / ``error`` for the host's (JSON-encoded) body.
                         www_authenticate=challenge(audience, "insufficient_authority"))

    def _authorized(pcactn: dict, headers: Mapping[str, str], body: Union[bytes, bytearray, str, None],
                    op: Optional[Mapping[str, Any]]) -> PCAResult:
        if op is None and mapper is not None:
            try:
                op = mapper(headers, body)
            except Exception:  # noqa: BLE001 - the host's mapping failed: no operation, which denies below
                op = None
        r = az.run(pcactn, operation=op, audience=audience, resolve_grant=resolve_grant, now=now,
                   intent_policy=intent_policy, intent_v2=intent_v2)
        if r.allow:
            return PCAResult(ok=True, status=200, verdict=r.verdict, pcactn=pcactn, authorization=r)
        code = "invalid_pcactn" if r.status == 401 else "insufficient_authority"
        # the reason stays on ``error`` / ``authorization`` (never in the header, see above)
        return PCAResult(ok=False, status=r.status, verdict=r.verdict, pcactn=pcactn, error=r.reason,
                         www_authenticate=challenge(audience, code), authorization=r)

    mapper = operation
    return guard
