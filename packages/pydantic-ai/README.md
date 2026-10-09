# atlas-pca-pydantic-ai

Pydantic AI guard for **Proof-Carrying Authority (PCA)**: make every Pydantic AI tool call proof-carrying and
policy-gated. A tool only runs when the agent carries a valid, in-plan, resource-correct proof for exactly
that action. The adapter delegates all verification to [`atlas-pca`](https://pypi.org/project/atlas-pca/)
and reimplements no cryptography.

> Status: **0.3.0, unaudited.**

### What is tested

The default test suite runs without the framework, against the shared conformance proofs. A second suite, `make test-real` (needs the framework installed), runs against the real framework and is pinned to Pydantic AI 2.54.0 (`pydantic-ai-slim`). It covers a real `Agent` with a scripted offline model: proofs on `RunContext.deps` (encoded and inline), sync and async tools, `Tool(...)` wrapping, and the refusal reaching the model as a retry prompt with the reason (missing, undecodable, tampered, wrong audience, insufficient capability). Each denial test checks that the tool body never ran, and checks the refusal reason wherever the framework surfaces it.

Not covered: other framework versions (only the pinned one is exercised), live model providers (the models are scripted and offline), and any property of the underlying `atlas-pca` verifier beyond what it already documents. This package has not been independently audited.

## Install

```sh
pip install atlas-pca-pydantic-ai
```

This installs `atlas-pca>=0.3.0,<0.4` as a dependency.

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
