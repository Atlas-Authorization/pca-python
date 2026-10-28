# atlas-pca-langgraph

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

LangGraph guard for **Proof-Carrying Authority (PCA)**: make every LangGraph tool call proof-carrying and
gated. A tool only runs when the agent carries a valid proof (signatures, capability chain, plan inclusion,
audience, lifetime) whose signed verb and resource satisfy the capability the tool requires. The adapter delegates
all verification to [`atlas-pca`](https://pypi.org/project/atlas-pca/) and reimplements no cryptography.

By default the guard runs the full `atlas-pca` 0.5 `authorize` pipeline: the proof must be for exactly this call (the tool's capability with the call arguments as params), and the grant's predicates and caveats, revocation and the replay counter are enforced before the tool runs (risk scores and thresholds are not evaluated). A guard built without `authorize` options refuses every call with `authorize_config`; it never falls back to checking the signature only. Verifying the signature only is the explicit opt-in `signature_only=True`: then the tool's arguments are not compared with the signed parameters, and replay, revocation, the grant's caveats and limits and plan authorization are not evaluated (`counter_format: pass` is a format check, not replay protection). See Full authorization below.

> Status: **0.5.0.** The adapter delegates every check to `atlas-pca`; it reimplements no cryptography.

### What is tested

The default test suite runs without the framework, against the shared conformance proofs. A second suite, `make test-real` (needs the framework installed), runs against the real framework and is pinned to LangGraph 1.2.14 with langchain-core 1.6.9. It covers a real `ToolNode` and `StateGraph`: proofs carried in the run config and in graph state, a real `StructuredTool`, and the `interrupt()`/`Command(resume=...)` step-up path (a tampered resume is refused, a valid one proceeds). Each denial test checks that the tool body never ran, and checks the refusal reason wherever the framework surfaces it.

Not covered: other framework versions (only the pinned one is exercised), live model providers (the models are scripted and offline), and any property of the underlying `atlas-pca` verifier beyond what it already documents. This package has not been independently audited.

## Install

```sh
pip install atlas-pca-langgraph
```

This installs `atlas-pca>=0.5,<0.6` as a dependency.

## Use

Entry points: `pca_tool / PcaToolNode / pca_guard_node`.

```python
from atlas_pca_langgraph import pca_tool
```

See the module docstrings in `atlas_pca_langgraph` for the full API, and the PCA specification for the model.
The verifier applies the full check order, including `grant_ref_bound` (the signed `grant_ref` must equal
the root capability id), as of `atlas-pca` 0.2.0.

## Full authorization (the default, atlas-pca 0.5)

```python
from atlas_pca import AuthorizeOptions, SqliteStateStore
from atlas_pca_langgraph import pca_tool

authorize = AuthorizeOptions(state_store=SqliteStateStore("pca-replay.db"), is_revoked=is_revoked)


@pca_tool("payments.send:payments/acme", audience="payments-rs", resolve_grant=resolve, authorize=authorize)
def send_payment(amount: float, currency: str) -> str:
    return "sent %s %s" % (amount, currency)
```

The proof must then be for exactly this call: the tool's `verb:resource` with its keyword arguments (minus the
injected `config`) as the params. A validly signed $400 payment under a $100 grant, a $50 proof used for $400, a
proof for another tool, a replay or a revoked grant raise `PcaToolDenied` before the function runs. `PcaToolNode` and
`guard_tool_node` take the same option. `pca_guard_node` stays a routing pre-check: put `authorize` on the node that
runs the tools, since each authorized gate consumes the replay counter.

`is_revoked(pcactn, grant)` returns `True` for a revoked grant; `resolve(grant_ref)` returns the grant from your own
store. Every component is required: a missing one refuses the call. The replay counter is consumed only when every
other check passed. Not covered: the risk score, trust budget and threshold co-signature from the grant's
`risk_policy`; a grant that pins the agent (`agent_binding`) is refused.

## Signature-only mode

To verify only the signature, chain, audience, validity and counter format, pass `signature_only=True` (`pca_tool(..., signature_only=True)`, `PcaToolNode(..., signature_only=True)`). Passing it together with `authorize` raises `ValueError` at construction. In this mode the arguments are not bound, and replay, revocation, caveats and predicates are not checked, so do those in your tool code or a full verifier.

## Fail-closed behaviour

Every row is a call on which the tool does not run. Unless a row says otherwise it is refused in both the default (authorize) mode and `signature_only=True`.

| Missing or invalid | Result |
|---|---|
| No proof presented | Refused: `no proof-carrying action presented` |
| Proof that cannot be decoded (strict base64url or JSON profile) | Treated as no proof; refused |
| `resolve_grant` returns nothing for the proof's `grant_ref` | Refused: `grant_ref does not resolve to a known grant` |
| Bad signature, broken capability chain, wrong or missing audience, outside the validity window, bad counter format | Refused with the failing check named |
| Proof for another verb or resource than the tool requires | Refused: `insufficient capability` |
| A signed $400 call under a $100 grant, arguments that differ from the signed params, a replay, a revoked grant (default mode) | Refused before the tool runs |
| Authorize options missing, or a missing `state_store` or `is_revoked` (default mode) | Every call refused with `authorize_config`; it never falls back to signature-only |
| A tool that declares no capability (default mode) | Refused (`operation`) |
| `authorize` together with `signature_only=True`; `verifier=` without `signature_only=True`; no `resolve_grant`; an empty `audience` | `ValueError` when the guard is built |
| `PcaToolNode` or `guard_tool_node` denies a pending call | The tool is not run; an error `ToolMessage` is returned to the model |
| `pca_guard_node` finds a pending call without a valid proof | Routes to step-up (an `interrupt` when LangGraph is installed, otherwise a `stepup` marker); the tool node is not reached |
| `pca_route` finds no routing marker | Routes to step-up, never to the tool node |
| A tool is absent from a `require` mapping (`signature_only=True`) | Needs only a valid proof for this audience; in default mode it is refused |

## Limits

- `pca_guard_node` is a routing pre-check (signature, audience, capability). It does not consume the replay counter or bind arguments; run the authorize pipeline on the node that executes the tools (`PcaToolNode` or `pca_tool`).
- A step-up resumes with a proof the host collects; this package does not authenticate the approver.
- The guard checks the proof at the tool boundary of one process. It does not replace the resource server when a tool makes a remote call.
- Replay and trust-budget state live in the `state_store` you supply; a per-process store does not stop a replay across processes. Use a shared store.
- Not evaluated: the risk score, trust budget and threshold co-signature from the grant's `risk_policy`; a grant that pins the agent (`agent_binding`) is refused.
- `signature_only=True` does not bind the arguments or stop replay, revocation or caveat violations.
- The `is_revoked` and `resolve_grant` callbacks are trusted; this package does not authenticate them.
- All verification is delegated to `atlas-pca`; this package reimplements no cryptography. It has not been independently audited.

## Upgrading to 0.5

- **Breaking:** the default is the full `authorize` pipeline. Add `authorize=AuthorizeOptions(state_store=..., is_revoked=...)` (with `resolve_grant`), or `signature_only=True` to keep the old behaviour. A custom `verifier=` now also needs `signature_only=True`.
- **Breaking:** the check name `counter` is now `counter_format` (core verdict) and `replay` (the stateful check in `authorize`); a replay refusal reads `replay: N is not greater than last seen M (replay)`.
- An unmet predicate limit is named in the refusal, e.g. `amount <= 100 not satisfied for payments.send on payments/acme`.
- Requires `atlas-pca>=0.5,<0.6`.

## Links

- Source: https://github.com/Atlas-Authorization/pca-python
- Specification and docs: https://github.com/Atlas-Authorization/pca

License: MIT
