"""Flask integration for Proof-Carrying Authority.

``PCAFlask`` wraps the same guard as the Django middleware and the FastAPI dependency (``require_pca``). Use it as a
route decorator or install it app-wide; on a valid PCActn ``flask.g.pca`` is a :class:`PCAContext`, otherwise the request
is answered with a JSON 401 / 403 carrying ``WWW-Authenticate``::

    from flask import Flask, g
    from atlas_pca.flask import PCAFlask

    pca = PCAFlask(audience="rs-orders", resolve_grant=my_resolver, authorize=my_options, operation=my_operation)

    @app.post("/transfer")
    @pca.require
    def transfer():
        ...  # g.pca.pcactn / g.pca.verdict / g.pca.operation

    pca.init_app(app)   # or: every request of the app (each one needs a valid PCActn)

``operation`` is a callable ``(request) -> {"verb", "resource", "params"} | None`` naming what the route executes. The
default (0.5) is the full pipeline: without ``authorize`` every request is refused (403 ``authorize_config``);
``signature_only=True`` is the explicit opt-in to verifying the signature only and cannot be combined with ``authorize``.

Flask is imported lazily, so the base ``atlas_pca`` package stays dependency-free (``pip install 'atlas-pca[flask]'``).
"""
import functools
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Union

from .authorize import AuthorizedOperation, AuthorizeOptions
from .pca import Verdict
from .refusal_help import refusal_doc_url
from .server import GrantResolver, IntentV2Source, PCAResult, require_pca


@dataclass
class PCAContext:
    verdict: Verdict
    pcactn: dict
    operation: Optional[AuthorizedOperation] = None


def _flask() -> Any:
    try:
        import flask
    except Exception as exc:  # pragma: no cover - only when the extra isn't installed
        raise ImportError("atlas_pca.flask requires Flask. Install with: pip install 'atlas-pca[flask]'") from exc
    return flask


class PCAFlask:
    """Enforce a valid PCActn on the routes it decorates (``require``) or on every request (``init_app``)."""

    def __init__(self, *, audience: str, resolve_grant: GrantResolver, now: Optional[int] = None,
                 intent_policy: Optional[dict] = None, intent_v2: IntentV2Source = None,
                 authorize: Union[AuthorizeOptions, Mapping[str, Any], None] = None,
                 operation: Optional[Callable[[Any], Any]] = None, signature_only: bool = False,
                 fresh_at: Any = None, allowed_suites: Any = None, hooks: Optional[Mapping[str, Any]] = None,
                 attestation: Optional[Mapping[str, Any]] = None) -> None:
        _flask()
        if not audience:
            raise ValueError("PCAFlask requires an audience")
        if not callable(resolve_grant):
            raise ValueError("PCAFlask requires a callable resolve_grant")
        if signature_only is True and authorize is not None:
            raise ValueError("signature_only and authorize are mutually exclusive")
        if authorize is not None and not callable(operation):
            raise ValueError("authorize needs operation: a callable (request) -> {verb, resource, params}")
        self._authorize = signature_only is not True
        self._operation = operation if callable(operation) else None
        self._guard = require_pca(audience=audience, resolve_grant=resolve_grant, now=now, intent_policy=intent_policy,
                                  intent_v2=intent_v2, signature_only=signature_only is True, fresh_at=fresh_at,
                                  allowed_suites=allowed_suites,
                                  **({"authorize": authorize} if authorize is not None else {}),
                                  **({"hooks": hooks} if hooks is not None else {}),
                                  **({"attestation": attestation} if attestation is not None else {}))

    def check(self) -> Optional[Any]:
        """Run the guard on the current request: None when allowed (``g.pca`` is set), else the refusal response."""
        flask = _flask()
        request = flask.request
        try:
            body = request.get_data(cache=True)
        except Exception:
            body = None
        if self._authorize:
            op = None
            if self._operation is not None:
                try:
                    op = self._operation(request)
                except Exception:  # the mapping failed: no operation, which denies
                    op = None
            result: PCAResult = self._guard(request.headers, body, operation=op)
        else:
            result = self._guard(request.headers, body)
        if not result.ok:
            return self._deny(flask, result)
        flask.g.pca = PCAContext(verdict=result.verdict, pcactn=result.pcactn,
                                 operation=result.authorization.operation if result.authorization else None)
        return None

    @staticmethod
    def _deny(flask: Any, result: PCAResult) -> Any:
        err = result.error or "forbidden"
        resp = flask.jsonify({"error": err, "status": result.status, "decision": result.decision,
                              "doc": refusal_doc_url(err),
                              **({"escalation": result.escalation} if result.escalation else {})})
        resp.status_code = result.status
        if result.www_authenticate:
            resp.headers["WWW-Authenticate"] = result.www_authenticate
        return resp

    def require(self, view: Callable) -> Callable:
        """Route decorator: the view runs only on an allowing decision."""

        @functools.wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            refusal = self.check()
            return refusal if refusal is not None else view(*args, **kwargs)

        return wrapper

    def init_app(self, app: Any) -> None:
        """Guard every request of ``app`` (a ``before_request`` hook; a returned refusal ends the request)."""
        app.before_request(self.check)
