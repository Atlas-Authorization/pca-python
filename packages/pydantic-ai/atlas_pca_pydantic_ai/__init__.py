"""Proof-Carrying Authority (PCA) tool guard for Pydantic AI.

Make each Pydantic AI tool call proof-carrying + policy-gated at execution: before a guarded tool runs,
a valid PCActn for this tool is required and verified with the shared ``atlas_pca`` reference verifier
(no crypto is reimplemented here). See :func:`pca_tool` and :class:`PCAGuard`.
"""
from .capability import (  # noqa: F401
    Capability,
    capability_satisfies,
    parse_capability,
)
from .extract import PCA_KEY, extract_pcactn  # noqa: F401
from .guard import (  # noqa: F401
    PCADecision,
    PCADeps,
    PCAGuard,
    PCARejected,
    pca_tool,
)
from .verifier import CoreVerifier, GrantResolver, Verifier  # noqa: F401

__all__ = [
    "Capability",
    "CoreVerifier",
    "GrantResolver",
    "PCADecision",
    "PCADeps",
    "PCAGuard",
    "PCARejected",
    "PCA_KEY",
    "Verifier",
    "capability_satisfies",
    "extract_pcactn",
    "parse_capability",
    "pca_tool",
]
