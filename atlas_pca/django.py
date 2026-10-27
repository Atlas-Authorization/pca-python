"""Django integration for Proof-Carrying Authority.

``PCAMiddleware`` is a new-style Django middleware. On a valid PCActn it sets ``request.pca`` (a
:class:`PCAContext`) and lets the request through; otherwise it short-circuits with a
``JsonResponse`` of status 401 or 403 carrying a ``WWW-Authenticate`` header.

Configure it via Django settings::

    MIDDLEWARE = [..., "atlas_pca.django.PCAMiddleware"]
    PCA_AUDIENCE = "rs-orders"
    PCA_RESOLVE_GRANT = "myapp.auth.resolve_grant"   # dotted path, or a callable
    # optional: PCA_NOW = <epoch-ms int>  (testing / fixed clock)
    # optional: PCA_INTENT_POLICY = {"require": True, "min_fidelity_ppm": 900000}  (Intent Layer M2)
    # optional: PCA_INTENT_V2 = {...} or a callable (pcactn) -> dict | None, or its dotted path  (Intent Layer v2 state)
    # the full pipeline is the default (0.5): PCA_AUTHORIZE = AuthorizeOptions(...) or a dict of its fields, or its
    #   dotted path, with PCA_OPERATION = a callable (request) -> {"verb", "resource", "params"} | None, or its dotted
    #   path. Without PCA_AUTHORIZE every request is refused (403 authorize_config).
    # explicit opt-in to the signature only: PCA_SIGNATURE_ONLY = True (cannot be combined with PCA_AUTHORIZE)

Django is imported lazily, so the base ``atlas_pca`` package stays dependency-free
(``pip install 'atlas-pca[django]'`` pulls Django in).
"""
from dataclasses import dataclass
from typing import Optional

from .authorize import AuthorizedOperation
from .pca import Verdict
from .server import PCAResult, as_authorize_options, require_pca


@dataclass
class PCAContext:
    verdict: Verdict
    pcactn: dict
    operation: Optional[AuthorizedOperation] = None


class PCAMiddleware:
    """Enforce a valid PCActn on every request routed through it."""

    def __init__(self, get_response):
        try:
            from django.conf import settings
            from django.utils.module_loading import import_string
        except Exception as exc:  # pragma: no cover - only when the extra isn't installed
            raise ImportError(
                "atlas_pca.django requires Django. Install with: pip install 'atlas-pca[django]'"
            ) from exc

        self.get_response = get_response

        audience = getattr(settings, "PCA_AUDIENCE", None)
        if not audience:
            from django.core.exceptions import ImproperlyConfigured
            raise ImproperlyConfigured("PCAMiddleware requires settings.PCA_AUDIENCE")

        resolver = getattr(settings, "PCA_RESOLVE_GRANT", None)
        if resolver is None:
            from django.core.exceptions import ImproperlyConfigured
            raise ImproperlyConfigured("PCAMiddleware requires settings.PCA_RESOLVE_GRANT")
        if isinstance(resolver, str):
            resolver = import_string(resolver)
        if not callable(resolver):
            from django.core.exceptions import ImproperlyConfigured
            raise ImproperlyConfigured("settings.PCA_RESOLVE_GRANT must be a dotted path or a callable")

        self._now = getattr(settings, "PCA_NOW", None)
        intent_v2 = getattr(settings, "PCA_INTENT_V2", None)
        if isinstance(intent_v2, str):
            intent_v2 = import_string(intent_v2)
        if intent_v2 is not None and not isinstance(intent_v2, dict) and not callable(intent_v2):
            from django.core.exceptions import ImproperlyConfigured
            raise ImproperlyConfigured("settings.PCA_INTENT_V2 must be a dict, a callable or a dotted path to a callable")
        authorize = getattr(settings, "PCA_AUTHORIZE", None)
        if isinstance(authorize, str):
            authorize = import_string(authorize)
        try:
            authorize = as_authorize_options(authorize)
        except TypeError as exc:
            from django.core.exceptions import ImproperlyConfigured
            raise ImproperlyConfigured("settings.PCA_AUTHORIZE must be an AuthorizeOptions, a dict of its fields "
                                       "or a dotted path to one") from exc
        operation = getattr(settings, "PCA_OPERATION", None)
        if isinstance(operation, str):
            operation = import_string(operation)
        signature_only = getattr(settings, "PCA_SIGNATURE_ONLY", False) is True
        if signature_only and authorize is not None:
            from django.core.exceptions import ImproperlyConfigured
            raise ImproperlyConfigured("settings.PCA_SIGNATURE_ONLY and settings.PCA_AUTHORIZE are mutually exclusive")
        if authorize is not None and not callable(operation):
            from django.core.exceptions import ImproperlyConfigured
            raise ImproperlyConfigured("settings.PCA_AUTHORIZE needs settings.PCA_OPERATION: a callable "
                                       "(request) -> {verb, resource, params} or its dotted path")
        self._authorize = not signature_only
        self._operation = operation if callable(operation) else None
        self._guard = require_pca(audience=audience, resolve_grant=resolver, now=self._now,
                                  intent_policy=getattr(settings, "PCA_INTENT_POLICY", None), intent_v2=intent_v2,
                                  signature_only=signature_only, **({"authorize": authorize} if authorize is not None else {}))

    def _deny(self, result: PCAResult):
        from django.http import JsonResponse

        resp = JsonResponse(
            {"error": result.error or "forbidden", "status": result.status, "decision": result.decision,
             **({"escalation": result.escalation} if result.escalation else {})},
            status=result.status,
        )
        if result.www_authenticate:
            resp["WWW-Authenticate"] = result.www_authenticate
        return resp

    def __call__(self, request):
        try:
            body = request.body
        except Exception:
            body = None
        if self._authorize:
            try:
                op = self._operation(request)
            except Exception:  # the mapping failed: no operation, which denies
                op = None
            result = self._guard(request.headers, body, operation=op)
        else:
            result = self._guard(request.headers, body)
        if not result.ok:
            return self._deny(result)
        request.pca = PCAContext(verdict=result.verdict, pcactn=result.pcactn,
                                 operation=result.authorization.operation if result.authorization else None)
        return self.get_response(request)
