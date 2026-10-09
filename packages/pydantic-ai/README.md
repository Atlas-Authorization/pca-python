# atlas-pca-pydantic-ai

Pydantic AI guard for **Proof-Carrying Authority (PCA)**: make every Pydantic AI tool call proof-carrying and
policy-gated. A tool only runs when the agent carries a valid, in-plan, resource-correct proof for exactly
that action. The adapter delegates all verification to [`atlas-pca`](https://pypi.org/project/atlas-pca/)
and reimplements no cryptography.

> Status: **0.2.0, unaudited.**

## Install

```sh
pip install atlas-pca-pydantic-ai
```

This installs `atlas-pca>=0.2.0,<0.3` as a dependency.

## Use

Entry points: `pca_tool / PCAGuard`.

```python
from atlas_pca_pydantic_ai import pca_tool
```

See the module docstrings in `atlas_pca_pydantic_ai` for the full API, and the PCA specification for the model.
The verifier applies the full check order, including `grant_ref_bound` (the signed `grant_ref` must equal
the root capability id), as of `atlas-pca` 0.2.0.

## Links

- Source: https://github.com/Atlas-Authorization/pca-python
- Specification and docs: https://github.com/Atlas-Authorization/pca

License: MIT
