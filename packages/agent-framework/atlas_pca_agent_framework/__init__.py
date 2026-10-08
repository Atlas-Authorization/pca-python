"""Atlas Proof-Carrying Authority (PCA) guard for the Microsoft Agent Framework.

Make every Agent Framework tool/function call proof-carrying and policy-gated, built on the reference
PCActn verifier in ``atlas_pca`` (no crypto is reimplemented here). Wrap one ``@ai_function`` tool with
:func:`pca_tool`, or gate every tool an agent invokes with :func:`pca_function_middleware`. Carry the
proof via :func:`pca_context` (recommended, out-of-band) or the inline ``pca_action`` argument.
"""
from ._proof import (  # noqa: F401
    PCA_ARG,
    coerce_pcactn,
    current_proof,
    pca_context,
    reset_pca_action,
    set_pca_action,
)
from .middleware import (  # noqa: F401
    PcaFunctionMiddleware,
    RequireSpec,
    pca_function_middleware,
)
from .tool import (  # noqa: F401
    GuardedFunction,
    PcaToolDenied,
    pca_tool,
)
from .verifier import (  # noqa: F401
    CoreVerifier,
    GrantResolver,
    ToolDecision,
    Verifier,
)

__all__ = [
    "PCA_ARG",
    "CoreVerifier",
    "GrantResolver",
    "GuardedFunction",
    "PcaFunctionMiddleware",
    "PcaToolDenied",
    "RequireSpec",
    "ToolDecision",
    "Verifier",
    "coerce_pcactn",
    "current_proof",
    "pca_context",
    "pca_function_middleware",
    "pca_tool",
    "reset_pca_action",
    "set_pca_action",
]
