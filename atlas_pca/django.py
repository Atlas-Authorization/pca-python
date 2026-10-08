"""Django integration for Proof-Carrying Authority.

``PCAMiddleware`` is a new-style Django middleware. On a valid PCActn it sets ``request.pca`` (a
:class:`PCAContext`) and lets the request through; otherwise it short-circuits with a
``JsonResponse`` of status 401 or 403 carrying a ``WWW-Authenticate`` header.

Configure it via Django settings::

    MIDDLEWARE = [..., "atlas_pca.django.PCAMiddleware"]
    PCA_AUDIENCE = "rs-orders"
    PCA_RESOLVE_GRANT = "myapp.auth.resolve_grant"   # dotted path, or a callable
    # optional: PCA_NOW = <epoch-ms int>  (testing / fixed clock)

Django is imported lazily, so the base ``atlas_pca`` package stays dependency-free
(``pip install 'atlas-pca[django]'`` pulls Django in).
"""
from dataclasses import dataclass

from .pca import Verdict
from .server import PCAResult, require_pca


@dataclass
class PCAContext:
    verdict: Verdict
    pcactn: dict


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
        self._guard = require_pca(audience=audience, resolve_grant=resolver, now=self._now)

    def _deny(self, result: PCAResult):
        from django.http import JsonResponse

        resp = JsonResponse(
            {"error": result.error or "forbidden", "status": result.status},
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
        result = self._guard(request.headers, body)
        if not result.ok:
            return self._deny(result)
        request.pca = PCAContext(verdict=result.verdict, pcactn=result.pcactn)
        return self.get_response(request)
