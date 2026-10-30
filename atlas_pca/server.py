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
from typing import Any, Callable, Dict, Mapping, Optional, Union

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
    #: ``allow`` (ok), ``escalate`` (refused: ask the principal; ``escalation`` is the request) or ``deny``. ``ok`` is
    #: exactly ``decision == "allow"``; an escalate is never ok.
    decision: str = "deny"
    escalation: Optional[dict] = None

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


ESCALATION_HEADER = "PCA-Escalation-Answer"
FRESH_AT_HEADER = "pca-fresh-at"


def extract_escalation_answer(headers: Mapping[str, str], body: Union[bytes, bytearray, str, None]) -> Any:
    """The principal's EscalationAnswer: header ``PCA-Escalation-Answer`` (strict base64url JSON), else the body member
    ``escalation_answer``; None when absent or unreadable (an unreadable answer is no answer)."""
    try:
        raw = _get_header(headers, ESCALATION_HEADER)
        if raw is not None:
            return strict_parse(decode_pca_header(raw))
        text = _to_text(body)
        env = strict_parse(text) if text is not None else None
        return env.get("escalation_answer") if isinstance(env, dict) else None
    except Exception:  # noqa: BLE001
        return None


def extract_workflow_step(headers: Mapping[str, str], body: Union[bytes, bytearray, str, None],
                          callback: Optional[Callable[..., Any]] = None) -> Any:
    """The call's workflow step ``{commitment, receipts, step, units, goal_digest}``: the configured per-request
    ``callback(headers, body)`` when there is one (a callback that raises yields ``{}``, which admission refuses: fail
    closed), else the JSON body member ``workflow``; None when absent or the body is unreadable."""
    if callback is not None:
        try:
            return callback(headers, body)
        except Exception:  # noqa: BLE001
            return {}
    try:
        text = _to_text(body)
        env = strict_parse(text) if text is not None else None
        return env.get("workflow") if isinstance(env, dict) else None
    except Exception:  # noqa: BLE001
        return None


def presented_k1(headers: Mapping[str, str]) -> Dict[str, Any]:
    """Discharges and a narrow block as presented with a request: headers ``PCA-Discharges`` (strict base64url JSON array)
    and ``PCA-Narrow`` (strict base64url JSON, any value); an empty value is absent. Returns ``{"discharges"?, "narrow"?}``;
    raises ``ValueError`` (``PcaHeaderError`` / ``StrictJsonError`` are ``ValueError``s or are re-raised as one) when malformed."""
    out: Dict[str, Any] = {}
    try:
        d = _get_header(headers, "PCA-Discharges")
        if d is not None and d != "":
            arr = strict_parse(decode_pca_header(d))
            if not isinstance(arr, list):
                raise ValueError("PCA-Discharges must be a JSON array")
            out["discharges"] = arr
        n = _get_header(headers, "PCA-Narrow")
        if n is not None and n != "":
            out["narrow"] = strict_parse(decode_pca_header(n))
    except ValueError:
        raise
    except Exception as e:  # noqa: BLE001 - header and JSON errors alike
        raise ValueError("unreadable K1 header: %s" % type(e).__name__) from e
    return out


def require_pca(*, audience: str, resolve_grant: GrantResolver,
                now: Optional[int] = None, intent_policy: Optional[dict] = None,
                intent_v2: IntentV2Source = None,
                authorize: Union[AuthorizeOptions, Mapping[str, Any], None] = None,
                operation: Optional[OperationMapper] = None,
                signature_only: bool = False,
                fresh_at: Any = None) -> Callable[..., PCAResult]:
    """Build a framework-agnostic guard.

    ``audience``      — this resource server's own id; the PCActn's signed ``aud`` must equal it.
    ``resolve_grant`` — ``(grant_ref) -> grant | None``; maps the PCActn's ``grant_ref`` to the root grant.
    ``now``           — epoch milliseconds for the validity window (default: wall clock at check time).
    ``intent_policy`` — optional Intent Layer M2 policy ``{"require", "min_fidelity_ppm", "max_residual_risk_ppm", "approved_goal"}`` (``approved_goal`` = ``{"goal_digest", "policy_digest"}``, canonical base64url of 32 bytes each, selects goal binding v3)
                        forwarded to ``verify_pcactn_core`` (an active policy denies a PCActn without a bound intent).
    ``intent_v2``     — optional Intent Layer v2 verifier state + policy (``policy``, ``params``, ``schema``, ``session``,
                        ``layers``, ``acc``, ``wb``; see ``atlas_pca.intent_v2.decide_intent_v2``): a dict, or a callable
                        ``(pcactn) -> dict | None`` evaluated per request (the host's store lookup: session root, held
                        grants, accumulator pre-state under its row lock, receipts, plaintext params). A callable that
                        raises fails closed (403 ``intent_v2_context_error``).

    ``fresh_at``      — optional consistency-token policy (``atlas_pca.fresh_at``): a dict, or a callable ``(pcactn) -> dict |
                        None`` evaluated per request (a callable that raises denies, 403 ``fresh_at_context_error``). A
                        token in the ``pca-fresh-at`` request header (strict JSON) is read as ``side_carried`` only when the
                        PCActn has no ``fresh_at`` member; an unreadable header is a null token (denied).

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
        step = extract_workflow_step(headers, body, az.workflow_step) if az is not None and az.workflow is not None else None
        if az is not None and az.workflow is not None and (
                not isinstance(az.workflow, Mapping) or (az.workflow.get("required") is True and step is None)):
            # the workflow refusal needs no PCActn: it comes before the PCActn is read, exactly as in authorize()
            return _authorized(None, headers, body, operation, None, step)
        pcactn, err = extract_pcactn(headers, body)
        if pcactn is None:
            desc = "no PCActn presented" if err == "absent" else "PCActn could not be decoded"
            return PCAResult(ok=False, status=401, error=err,
                             www_authenticate=challenge(audience, "invalid_request", desc))
        fa = fresh_at
        if callable(fresh_at):
            try:
                fa = fresh_at(pcactn)
            except Exception:  # noqa: BLE001 - the host's state lookup failed: fail closed
                return PCAResult(ok=False, status=403, pcactn=pcactn, error="fresh_at_context_error",
                                 www_authenticate=challenge(audience, "insufficient_authority",
                                                            "fresh_at verifier state unavailable (fail closed)"))
        if isinstance(fa, dict) and isinstance(pcactn, dict) and "fresh_at" not in pcactn and "side_carried" not in fa:
            side = _get_header(headers, FRESH_AT_HEADER)
            if side is not None:
                try:
                    tok = strict_parse(side)
                except Exception:  # noqa: BLE001 - an unparseable token is a bad token (deny), never a missing one
                    tok = None
                fa = {**fa, "side_carried": tok}
        if az is not None:
            return _authorized(pcactn, headers, body, operation, fa, step)

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
                                     intent_v2=v2, fresh_at=fa)
        if verdict.allow:
            return PCAResult(ok=True, status=200, verdict=verdict, pcactn=pcactn, decision="allow")
        return PCAResult(ok=False, status=403, verdict=verdict, pcactn=pcactn,
                         error=verdict.reason or "insufficient_authority",
                         # Never echo verdict.reason into the header: it can carry attacker-controlled text (CR/LF ->
                         # header injection). TS requirePCA puts no reason in its challenge either; the reason stays
                         # on ``verdict`` / ``error`` for the host's (JSON-encoded) body.
                         www_authenticate=challenge(audience, "insufficient_authority"))

    def _authorized(pcactn: dict, headers: Mapping[str, str], body: Union[bytes, bytearray, str, None],
                    op: Optional[Mapping[str, Any]], fa: Any = None, step: Any = None) -> PCAResult:
        if op is None and mapper is not None:
            try:
                op = mapper(headers, body)
            except Exception:  # noqa: BLE001 - the host's mapping failed: no operation, which denies below
                op = None
        try:
            presented = presented_k1(headers)
        except ValueError:
            presented = {}  # unreadable discharges are no discharges: the K1 caveat stays unsatisfied
        r = az.run(pcactn, operation=op, audience=audience, resolve_grant=resolve_grant, now=now,
                   intent_policy=intent_policy, intent_v2=intent_v2,
                   escalation_answer=extract_escalation_answer(headers, body), presented_k1=presented, fresh_at=fa,
                   workflow=step, request=(headers, body))
        if r.allow:
            return PCAResult(ok=True, status=200, verdict=r.verdict, pcactn=pcactn, authorization=r, decision="allow",
                             escalation=r.escalation)
        code = "invalid_pcactn" if r.status == 401 else "insufficient_authority"
        # the reason stays on ``error`` / ``authorization`` (never in the header, see above)
        return PCAResult(ok=False, status=r.status, verdict=r.verdict, pcactn=pcactn, error=r.reason,
                         www_authenticate=challenge(audience, code), authorization=r, decision=r.decision,
                         escalation=r.escalation)

    mapper = operation
    return guard
