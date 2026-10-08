"""FastAPI integration for Proof-Carrying Authority.

``RequirePCA`` returns a FastAPI dependency you drop into a route with ``Depends(...)``. On success it
returns a :class:`PCAContext` (``.verdict`` / ``.pcactn``) and stashes the same object on
``request.state.pca``; on failure it raises ``HTTPException`` with a ``WWW-Authenticate`` header.

FastAPI / Starlette are imported lazily inside the factory so the base ``atlas_pca`` package keeps a
zero-dependency install. ``pip install 'atlas-pca[fastapi]'`` pulls FastAPI in.
"""
from dataclasses import dataclass
from typing import Callable, Optional

from .pca import Verdict
from .server import GrantResolver, PCAResult, require_pca


@dataclass
class PCAContext:
    """What a protected route receives: the allowing verdict and the verified PCActn."""

    verdict: Verdict
    pcactn: dict


def RequirePCA(*, audience: str, resolve_grant: GrantResolver,
               now: Optional[int] = None) -> Callable:
    """Create a FastAPI dependency enforcing a valid PCActn.

    Usage::

        from fastapi import Depends, FastAPI, Request
        from atlas_pca.fastapi import RequirePCA

        guard = RequirePCA(audience="rs-orders", resolve_grant=my_resolver)

        @app.post("/transfer")
        async def transfer(pca = Depends(guard), request: Request = None):
            ...  # pca.pcactn / pca.verdict ; also request.state.pca
    """
    try:
        from fastapi import HTTPException  # noqa: F401  (imported for a clear error if missing)
        from starlette.requests import Request
    except Exception as exc:  # pragma: no cover - only hit when the extra isn't installed
        raise ImportError(
            "atlas_pca.fastapi requires FastAPI. Install with: pip install 'atlas-pca[fastapi]'"
        ) from exc

    _guard = require_pca(audience=audience, resolve_grant=resolve_grant, now=now)

    async def dependency(request: Request) -> PCAContext:
        from fastapi import HTTPException  # local so the symbol is bound at call time

        body: Optional[bytes]
        try:
            body = await request.body()
        except Exception:
            body = None
        result: PCAResult = _guard(request.headers, body)
        if not result.ok:
            raise HTTPException(
                status_code=result.status,
                detail=result.error or "proof-carrying authority required",
                headers={"WWW-Authenticate": result.www_authenticate} if result.www_authenticate else None,
            )
        ctx = PCAContext(verdict=result.verdict, pcactn=result.pcactn)
        request.state.pca = ctx
        return ctx

    return dependency
