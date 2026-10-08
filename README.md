# pca-python

**The Python implementation of Proof-Carrying Authority (PCA) — an execution-authentication
framework for autonomous agents.**

This repo is the Python counterpart to
[`Atlas-Authorization/pca-js`](https://github.com/Atlas-Authorization/pca-js) (the TypeScript
ecosystem) and to [`Atlas-Authorization/pca`](https://github.com/Atlas-Authorization/pca) (the spec,
docs, playground and the independent language verifiers). The core verifier publishes to PyPI as
[`atlas-pca`](https://pypi.org/project/atlas-pca/); each framework adapter publishes as
`atlas-pca-<framework>`.

Classic auth answers two questions:

- **authN** — *who are you?* (OIDC, passkeys)
- **authZ** — *what may you do?* (OAuth scopes, roles)

Those were enough when a human was behind every action: the human *is* the policy engine, and their
identity implies faithfulness. An autonomous agent breaks that assumption — it is a stochastic,
externally-steerable process whose actions are unknown at grant time and manipulable (prompt injection,
tool-poisoning) at run time. A bearer token in a hijacked agent is full impersonation.

PCA adds a third question:

- **authF** — *is this specific action a faithful, uncompromised execution of an authority the principal
  actually conferred?*

PCA makes `authF` cheaply verifiable by replacing the bearer token with a **Proof-Carrying Action
(PCActn)**: with every action the agent presents a self-contained object, and the resource server
verifies a *proof* — not the possession of a secret. The core verifier runs **offline** with a stateless
set of eight fail-closed checks in a fixed, normative order (wire, version, audience, validity, chain,
plan-inclusion, leaf-signature, counter). Post-quantum (ML-DSA-65 / FIPS-204) verification is an
additive, optional rung on top of the base wire.

---

## Install

```sh
# the core verifier (this repo's primary package, at the repo root)
pip install atlas-pca

# a framework adapter — pick the agent framework you run
pip install atlas-pca-langgraph    # or atlas-pca-crewai, atlas-pca-pydantic-ai, ...
```

The core verifier is dependency-free. Extras pull in optional backends only when you want them:
`atlas-pca[fast]` (native Ed25519 via `cryptography`), `atlas-pca[pq]` (ML-DSA post-quantum),
`atlas-pca[fastapi]`, `atlas-pca[django]`.

```python
from atlas_pca import verify_pcactn_core

verdict = verify_pcactn_core(pcactn, grant, audience="https://api.example.com")
if not verdict.allow:
    raise PermissionError(f"authF failed: {verdict.reason}")
```

A framework adapter turns that verdict into a per-tool guard — every adapter exposes a `pca_tool(...)`
wrapper (plus framework-native middleware / callbacks / nodes) so a tool call only runs when the agent
carries a valid, in-plan, resource-correct proof for exactly that action:

```python
from atlas_pca_langgraph import pca_tool   # same entrypoint name in every adapter

guarded = pca_tool(my_tool, verb="write", resource="db/orders",
                   audience="https://api.example.com", resolve_grant=resolve_grant)
```

See each package's own module docstrings and the [spec repo](https://github.com/Atlas-Authorization/pca)
for the full model.

---

## Layout

The **core verifier is the repo-root package** — `pip install atlas-pca` (or `pip install .` from a
clone) installs the `atlas_pca` package that lives at the root, so the primary package needs no
subdirectory. Each framework adapter is its own installable distribution under `packages/<framework>/`,
with its own `pyproject.toml`; every adapter declares `atlas-pca` as a dependency and reimplements no
crypto. The shared conformance corpus is vendored at `conformance/` so every package's tests run offline
against the same known-good vectors.

```
.                      atlas_pca/          -> the core verifier package  (pip install atlas-pca)
                       pyproject.toml      -> the root (primary) package
                       conformance/        -> vendored shared test vectors
packages/<framework>/  atlas_pca_<fw>/     -> one framework adapter       (pip install atlas-pca-<fw>)
                       pyproject.toml
```

---

## Adapters

This repo bundles the core verifier plus **7** framework adapters. Each adapter builds
on `atlas-pca` and gates one agent framework's tool calls on a verified PCActn.

| Package | Install | What it does |
|---------|---------|--------------|
| [`atlas-pca-agent-framework`](packages/agent-framework) | `pip install atlas-pca-agent-framework` | Microsoft Agent Framework tool guard for Atlas Proof-Carrying Authority (PCA): make every tool/function call proof-carrying and policy-gated |
| [`atlas-pca-crewai`](packages/crewai) | `pip install atlas-pca-crewai` | CrewAI tool guard for Atlas Proof-Carrying Authority (PCA): make every CrewAI tool call proof-carrying and policy-gated |
| [`atlas-pca-fastmcp`](packages/fastmcp) | `pip install atlas-pca-fastmcp` | Per-tool Proof-Carrying Authority enforcement for FastMCP (verify a PCActn on every tools/call) |
| [`atlas-pca-google-adk`](packages/google-adk) | `pip install atlas-pca-google-adk` | Google ADK (Gemini/Vertex Agent Development Kit) tool guard for Atlas Proof-Carrying Authority (PCA): make every ADK tool call proof-carrying and policy-gated |
| [`atlas-pca-haystack`](packages/haystack) | `pip install atlas-pca-haystack` | Haystack (deepset) tool guard for Atlas Proof-Carrying Authority (PCA): make every Haystack tool/ToolInvoker call proof-carrying and policy-gated |
| [`atlas-pca-langgraph`](packages/langgraph) | `pip install atlas-pca-langgraph` | LangGraph tool/node guard for Atlas Proof-Carrying Authority (PCA): make every graph tool/node call proof-carrying and policy-gated, with interrupt()-based step-up for risky nodes |
| [`atlas-pca-pydantic-ai`](packages/pydantic-ai) | `pip install atlas-pca-pydantic-ai` | Proof-Carrying Authority tool guard for Pydantic AI (verify a PCActn before each tool runs) |

---

## Working in this repo

Everything runs offline against the vendored `conformance/` vectors — no install, no network, no agent
framework needed (the guards are duck-typed, so the adapters' tests run without the real framework).

```sh
# core verifier
pip install -e .
pytest                      # runs test_conformance.py + test_server.py at the root

# one adapter
pip install -e packages/langgraph
pytest packages/langgraph
```

---

## License

MIT — see [`LICENSE`](./LICENSE).
