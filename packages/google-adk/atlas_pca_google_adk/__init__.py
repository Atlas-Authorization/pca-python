"""Atlas Proof-Carrying Authority (PCA) guard for Google ADK (Agent Development Kit, Gemini/Vertex).

Make every ADK tool call proof-carrying and policy-gated at execution, built on the reference PCActn
verifier in ``atlas_pca`` (no crypto is reimplemented here). Wrap one tool with :func:`pca_tool`, or
gate a whole agent with :func:`pca_before_tool_callback`. Carry the proof via :func:`pca_context`, the
``tool_context`` session state (``"PCA-Action"``), or the inline ``pca_action`` tool argument.
"""
from ._proof import (  # noqa: F401
    PCA_ARG,
    PCA_STATE_KEY,
    coerce_pcactn,
    current_proof,
    pca_context,
    proof_from_tool_context,
    reset_pca_action,
    set_pca_action,
)
from .callback import (  # noqa: F401
    BeforeToolCallback,
    RequireSpec,
    pca_before_tool_callback,
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
    "BeforeToolCallback",
    "CoreVerifier",
    "GrantResolver",
    "GuardedTool",
    "PCA_ARG",
    "PCA_STATE_KEY",
    "PcaToolDenied",
    "RequireSpec",
    "ToolDecision",
    "Verifier",
    "coerce_pcactn",
    "current_proof",
    "pca_before_tool_callback",
    "pca_context",
    "pca_tool",
    "proof_from_tool_context",
    "reset_pca_action",
    "set_pca_action",
]
