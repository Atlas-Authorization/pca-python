# atlas-pca-fastmcp

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

FastMCP guard for **Proof-Carrying Authority (PCA)**: make every FastMCP tool call proof-carrying and
gated. A tool only runs when the agent carries a valid proof (signatures, capability chain, plan inclusion,
audience, lifetime) whose signed verb and resource satisfy the capability the tool requires. The adapter delegates
all verification to [`atlas-pca`](https://pypi.org/project/atlas-pca/) and reimplements no cryptography.

By default the guard runs the full `atlas-pca` 0.5 `authorize` pipeline: the proof must be for exactly this call (the tool's capability with the call arguments as params), and the grant's predicates and caveats, revocation and the replay counter are enforced before the tool runs (risk scores and thresholds are not evaluated). A guard built without `authorize` options refuses every call with `authorize_config`; it never falls back to checking the signature only. Verifying the signature only is the explicit opt-in `signature_only=True`: then the tool's arguments are not compared with the signed parameters, and replay, revocation, the grant's caveats and limits and plan authorization are not evaluated (`counter_format: pass` is a format check, not replay protection). See Full authorization below.

> Status: **0.5.0.** The adapter delegates every check to `atlas-pca`; it reimplements no cryptography.

### What is tested

The default test suite runs without the framework, against the shared conformance proofs. A second suite, `make test-real` (needs the framework installed), runs against the real framework and is pinned to FastMCP 4.1.0. It covers a real `FastMCP` server with the middleware, called through a real in-memory `Client`: proof in `_meta` and in tool arguments, absent/undecodable/tampered proofs, wrong audience, insufficient capability, the `@pca_tool` registry and the policy hook, each asserting the refusal reason the client sees. Each denial test checks that the tool body never ran, and checks the refusal reason wherever the framework surfaces it.

Not covered: other framework versions (only the pinned one is exercised), live model providers (the models are scripted and offline), and any property of the underlying `atlas-pca` verifier beyond what it already documents. This package has not been independently audited.

## Install

```sh
pip install atlas-pca-fastmcp
```

This installs `atlas-pca>=0.5,<0.6` as a dependency.

## Use

Entry points: `PCAMiddleware`.

```python
from atlas_pca_fastmcp import PCAMiddleware
```

See the module docstrings in `atlas_pca_fastmcp` for the full API, and the PCA specification for the model.
The verifier applies the full check order, including `grant_ref_bound` (the signed `grant_ref` must equal
the root capability id), as of `atlas-pca` 0.2.0.

## Full authorization (the default, atlas-pca 0.5)

```python
from atlas_pca import AuthorizeOptions, SqliteStateStore
from atlas_pca_fastmcp import pca_guard

guard = pca_guard(
    audience="payments-rs",
    resolve_grant=resolve,
    tool_capability={"send_payment": "payments.send:payments/acme"},
    authorize=AuthorizeOptions(state_store=SqliteStateStore("pca-replay.db"), is_revoked=is_revoked,
                               provenance_mediators=[agent_mediator_pin]),  # the agent's provenance recorder
)
# mcp.add_middleware(guard)
```

The proof must then be for exactly this call: the tool's exact `verb:resource` capability with the call arguments as
the params (a tool with no capability, or a wildcard one, is refused). A validly signed $400 payment under a $100
grant, a $50 proof used for $400, a proof for another tool, a replay or a revoked grant are refused before the tool
runs. The `policy` hook still runs after.

`is_revoked(pcactn, grant)` returns `True` for a revoked grant; `resolve(grant_ref)` returns the grant from your own
store. Every component is required: a missing one refuses the call. The replay counter is consumed only when every
other check passed. Not covered: the risk score, trust budget and threshold co-signature from the grant's
`risk_policy`; a grant that pins the agent (`agent_binding`) is refused.

## Provenance by default

`atlas-pca` 0.5 checks where every call comes from (check `provenance_flow`). A sensitive call whose choice or arguments do
not derive from the principal (an amount read out of an email, a recipient from a web page, or a call with no provenance at
all) is refused as `escalate` before the tool runs. A forged or tampered bundle is refused as `deny`. The gate cannot be
switched off in this adapter: the only opt-out is the grant's own signed `provenance: {"mode": "insecure_off"}`.

The agent sends its provenance bundle (from its `ProvenanceRecorder`, `for_action(...)`) next to the proof: in the
request `_meta` under `PCA-Provenance` as base64url JSON, or, for a client that cannot set `_meta`, under the same key in
the tool arguments (stripped before the tool runs, never part of the bound params). The guard forwards it to `authorize`.
A bundle that cannot be decoded is refused (`provenance_flow: the provenance bundle is unreadable (fail closed)`). When
the agent runs in this process, `pca_guard(..., recorder=recorder)` takes its session recorder: a call without a bundle
gets `recorder.for_action(operation)`, and every tool result is recorded as untrusted tool output.

Pin the agent's recording mediator in `AuthorizeOptions(provenance_mediators=[pin])` (or in the grant's
`provenance.mediators`); a bundle from an unpinned mediator counts as unlabelled. Use `provenance_actions` to declare
which actions are read-only; every unknown action is treated as sensitive.

## Signature-only mode

To verify only the signature, chain, audience, validity and counter format, pass `signature_only=True` (`pca_guard(..., signature_only=True)`). Passing it together with `authorize` raises `ValueError` at construction. In this mode the arguments are not bound, and replay, revocation, caveats and predicates are not checked, so do those in your tool code or a full verifier.

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
| A sensitive call with no provenance bundle, or whose choice or arguments come from tool output, retrieved or web content (default mode) | Refused as `escalate` (`provenance_flow: escalate: ...`) |
| A provenance bundle that is forged, tampered with or bound to another call (default mode) | Refused as `deny` (`provenance_flow: <code>: ...`) |
| A `PCA-Provenance` value that cannot be decoded (default mode) | Refused: `provenance_flow: the provenance bundle is unreadable (fail closed)` |
| Authorize options missing, or a missing `state_store` or `is_revoked` (default mode) | Every call refused with `authorize_config`; it never falls back to signature-only |
| A tool that declares no capability (default mode) | Refused (`operation`) |
| `authorize` together with `signature_only=True`; `verifier=` without `signature_only=True`; no `resolve_grant`; an empty `audience` | `ValueError` when the guard is built |
| A policy hook returns a reason | Refused: `policy_denied: <reason>`; the hook runs only after the proof and capability passed |
| Proof in neither request `_meta` nor the tool arguments | Refused: `no PCActn presented` |
| A tool with a wildcard capability, or none declared (default mode) | Refused (`operation`) |
| A denied call over MCP | `PCAAccessDenied` (a FastMCP tool error); the tool never runs |

## Limits

- The proof is read from the request metadata first, then from the arguments; a proof carried in the arguments is removed from the parameters the proof is bound to.
- A tool with no declared capability needs only a valid proof in `signature_only=True` mode; in default mode it is refused.
- The optional `policy` hook can only add refusals; it never grants.
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
- **Breaking:** provenance by default. A sensitive call now needs a provenance bundle that shows its choice and arguments come
  from the principal (see Provenance by default) and its mediator pinned in `provenance_mediators`. Without it the call
  escalates instead of running.

## Links

- Source: https://github.com/Atlas-Authorization/pca-python
- Specification and docs: https://github.com/Atlas-Authorization/pca

License: MIT
