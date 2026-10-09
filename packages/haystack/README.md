# atlas-pca-haystack

Haystack guard for **Proof-Carrying Authority (PCA)**: make every Haystack tool call proof-carrying and
policy-gated. A tool only runs when the agent carries a valid, in-plan, resource-correct proof for exactly
that action. The adapter delegates all verification to [`atlas-pca`](https://pypi.org/project/atlas-pca/)
and reimplements no cryptography.

> Status: **0.3.0, unaudited.**

### What is tested

The default test suite runs without the framework, against the shared conformance proofs. A second suite, `make test-real` (needs the framework installed), runs against the real framework and is pinned to Haystack 2.31.0 (`ToolInvoker`, `Agent`) and 3.3.0 (`Agent`; 3.x has no `ToolInvoker`). It covers real `Tool` objects through a real `ToolInvoker` (2.x) and `Agent` (2.x and 3.x), including `guard_tool_invoker` in a real `Pipeline`, thread-pool dispatch, and async tools. Each denial test checks that the tool body never ran, and checks the refusal reason wherever the framework surfaces it.

Not covered: other framework versions (only the pinned one is exercised), live model providers (the models are scripted and offline), and any property of the underlying `atlas-pca` verifier beyond what it already documents. This package has not been independently audited.

## Install

```sh
pip install atlas-pca-haystack
```

This installs `atlas-pca>=0.3.0,<0.4` as a dependency.

## Use

Entry points: `pca_tool / guard_tool_invoker / guard_tools`.

```python
from atlas_pca_haystack import pca_tool
```

See the module docstrings in `atlas_pca_haystack` for the full API, and the PCA specification for the model.
The verifier applies the full check order, including `grant_ref_bound` (the signed `grant_ref` must equal
the root capability id), as of `atlas-pca` 0.2.0.

## Links

- Source: https://github.com/Atlas-Authorization/pca-python
- Specification and docs: https://github.com/Atlas-Authorization/pca

License: MIT
