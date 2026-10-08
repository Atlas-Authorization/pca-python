"""Atlas Proof-Carrying Authority (PCA) guard for CrewAI tools.

Make every CrewAI tool call proof-carrying and policy-gated, built on the reference PCActn verifier in
``atlas_pca`` (no crypto is reimplemented here). Wrap one tool with :func:`pca_tool`, or a whole crew
with :func:`guard_crew` / :class:`PcaToolGuard`. Carry the proof via :func:`pca_context` or the
``pca_action`` tool-call keyword.
"""
from ._proof import (  # noqa: F401
    PCA_ARG,
    coerce_pcactn,
    current_proof,
    pca_context,
    reset_pca_action,
    set_pca_action,
)
from .crew import (  # noqa: F401
    PcaToolGuard,
    RequireSpec,
    guard_crew,
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
    "PcaToolGuard",
    "RequireSpec",
    "ToolDecision",
    "Verifier",
    "coerce_pcactn",
    "current_proof",
    "guard_crew",
    "guard_tools",
    "pca_context",
    "pca_tool",
    "reset_pca_action",
    "set_pca_action",
]
