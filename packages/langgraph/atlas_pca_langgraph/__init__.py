"""Atlas Proof-Carrying Authority (PCA) guard for LangGraph.

Make every LangGraph tool/node call proof-carrying and policy-gated at execution, and map a risky node
to LangGraph's ``interrupt()`` for step-up — built on the reference PCActn verifier in ``atlas_pca``
(no crypto is reimplemented here). LangGraph is the production-default graph runtime; this adapter is
graph-native where the older ``@atlasauth/pca-langchain`` adapter stops at the LCEL tool.

* :func:`pca_tool` — wrap one tool/callable so it requires a valid proof before it runs.
* :class:`PcaToolNode` / :func:`guard_tool_node` — gate every tool a ``ToolNode`` would execute.
* :func:`pca_guard_node` / :func:`pca_route` — a node that verifies the pending tool call and routes a
  risky one to step-up (via ``interrupt()`` when LangGraph is present).

Carry the proof via the graph state (``"PCA-Action"``), the config ``configurable``, the context var
(:func:`pca_context`), or the inline ``pca_action`` tool argument.
"""
from ._proof import (  # noqa: F401
    PCA_ARG,
    PCA_CONFIG_KEY,
    PCA_STATE_KEY,
    ProofInput,
    coerce_pcactn,
    current_proof,
    pca_context,
    proof_from_config,
    proof_from_state,
    reset_pca_action,
    resolve_proof,
    set_pca_action,
)
from .guard import (  # noqa: F401
    GuardNode,
    pca_guard_node,
    pca_route,
)
from .node import (  # noqa: F401
    PcaToolNode,
    RequireSpec,
    ToolMessageLike,
    guard_tool_node,
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
    "CoreVerifier",
    "GrantResolver",
    "GuardNode",
    "GuardedTool",
    "PCA_ARG",
    "PCA_CONFIG_KEY",
    "PCA_STATE_KEY",
    "PcaToolDenied",
    "PcaToolNode",
    "ProofInput",
    "RequireSpec",
    "ToolDecision",
    "ToolMessageLike",
    "Verifier",
    "coerce_pcactn",
    "current_proof",
    "guard_tool_node",
    "pca_context",
    "pca_guard_node",
    "pca_route",
    "pca_tool",
    "proof_from_config",
    "proof_from_state",
    "reset_pca_action",
    "resolve_proof",
    "set_pca_action",
]
