"""Atlas Proof-Carrying Authority (PCA) guard for Haystack (deepset).

Make every Haystack tool call proof-carrying and policy-gated, built on the reference PCActn verifier
in ``atlas_pca`` (no crypto is reimplemented here). Wrap one tool with :func:`pca_tool`, or a whole
agent's :class:`ToolInvoker` (and therefore its pipeline) with :func:`guard_tool_invoker` /
:func:`guard_tools`. Carry the proof via :func:`pca_context` or the ``pca_action`` invoke keyword.
"""
from ._proof import (  # noqa: F401
    PCA_ARG,
    coerce_pcactn,
    current_proof,
    pca_context,
    reset_pca_action,
    set_pca_action,
)
from .invoker import (  # noqa: F401
    RequireSpec,
    guard_tool_invoker,
    guard_tools,
)
from .tool import (  # noqa: F401
    GuardedTool,
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
    "GuardedTool",
    "PcaToolDenied",
    "RequireSpec",
    "ToolDecision",
    "Verifier",
    "coerce_pcactn",
    "current_proof",
    "guard_tool_invoker",
    "guard_tools",
    "pca_context",
    "pca_tool",
    "reset_pca_action",
    "set_pca_action",
]
