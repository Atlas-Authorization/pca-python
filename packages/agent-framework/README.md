# atlas-pca-agent-framework

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Microsoft Agent Framework guard for **Proof-Carrying Authority (PCA)**: make every Agent Framework tool call proof-carrying and
gated. A tool only runs when the agent carries a valid proof (signatures, capability chain, plan inclusion,
audience, lifetime) whose signed verb and resource satisfy the capability the tool requires. The adapter delegates
all verification to [`atlas-pca`](https://pypi.org/project/atlas-pca/) and reimplements no cryptography.

By default the guard runs the full `atlas-pca` 0.5 `authorize` pipeline: the proof must be for exactly this call (the tool's capability with the call arguments as params), and the grant's predicates and caveats, revocation and the replay counter are enforced before the tool runs (risk scores and thresholds are not evaluated). A guard built without `authorize` options refuses every call with `authorize_config`; it never falls back to checking the signature only. Verifying the signature only is the explicit opt-in `signature_only=True`: then the tool's arguments are not compared with the signed parameters, and replay, revocation, the grant's caveats and limits and plan authorization are not evaluated (`counter_format: pass` is a format check, not replay protection). See Full authorization below.

> Status: **0.4.1, unaudited.**

### What is tested

The default test suite runs without the framework, against the shared conformance proofs. A second suite, `make test-real` (needs the framework installed), runs against the real framework and is pinned to Microsoft Agent Framework 1.21.0 (`agent-framework-core`). It covers a real `Agent` with a scripted offline chat client and the framework's function-invocation layer: `pca_tool` and `pca_function_middleware` allow with a valid proof and refuse a missing, tampered, wrong-audience or insufficient-capability one without running the tool. Each denial test checks that the tool body never ran, and checks the refusal reason wherever the framework surfaces it.

Not covered: other framework versions (only the pinned one is exercised), live model providers (the models are scripted and offline), and any property of the underlying `atlas-pca` verifier beyond what it already documents. This package has not been independently audited.

## Install

```sh
pip install atlas-pca-agent-framework
```

This installs `atlas-pca>=0.5,<0.6` as a dependency.

## Use

Entry points: `pca_tool / pca_function_middleware`.

```python
from atlas_pca_agent_framework import pca_tool
```

See the module docstrings in `atlas_pca_agent_framework` for the full API, and the PCA specification for the model.
The verifier applies the full check order, including `grant_ref_bound` (the signed `grant_ref` must equal
the root capability id), as of `atlas-pca` 0.2.0.

## Full authorization (the default, atlas-pca 0.5)

```python
from atlas_pca import AuthorizeOptions, SqliteStateStore
from atlas_pca_agent_framework import pca_tool

authorize = AuthorizeOptions(state_store=SqliteStateStore("pca-replay.db"), is_revoked=is_revoked)


@pca_tool("payments.send:payments/acme", audience="payments-rs", resolve_grant=resolve, authorize=authorize)
def send_payment(amount: float, currency: str) -> str:
    return "sent %s %s" % (amount, currency)
```

The proof must then be for exactly this call: the tool's `verb:resource` with its call arguments as the params. A
validly signed $400 payment under a $100 grant, a $50 proof used for $400, a proof for another tool, a replay or a
revoked grant are refused before the tool runs. `pca_function_middleware` takes the same option. Use one authorized
gate per tool, since each consumes the replay counter.

`is_revoked(pcactn, grant)` returns `True` for a revoked grant; `resolve(grant_ref)` returns the grant from your own
store. Every component is required: a missing one refuses the call. The replay counter is consumed only when every
other check passed. Not covered: the risk score, trust budget and threshold co-signature from the grant's
`risk_policy`; a grant that pins the agent (`agent_binding`) is refused.

## Signature-only mode

To verify only the signature, chain, audience, validity and counter format, pass `signature_only=True` (`pca_tool(..., signature_only=True)`, `pca_function_middleware(..., signature_only=True)`). Passing it together with `authorize` raises `ValueError` at construction. In this mode the arguments are not bound, and replay, revocation, caveats and predicates are not checked, so do those in your tool code or a full verifier.

## Upgrading to 0.5

- **Breaking:** the default is the full `authorize` pipeline. Add `authorize=AuthorizeOptions(state_store=..., is_revoked=...)` (with `resolve_grant`), or `signature_only=True` to keep the old behaviour. A custom `verifier=` now also needs `signature_only=True`.
- **Breaking:** the check name `counter` is now `counter_format` (core verdict) and `replay` (the stateful check in `authorize`); a replay refusal reads `replay: N is not greater than last seen M (replay)`.
- An unmet predicate limit is named in the refusal, e.g. `amount <= 100 not satisfied for payments.send on payments/acme`.
- Requires `atlas-pca>=0.5,<0.6`.

## Links

- Source: https://github.com/Atlas-Authorization/pca-python
- Specification and docs: https://github.com/Atlas-Authorization/pca

License: MIT
