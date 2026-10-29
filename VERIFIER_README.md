# atlas-pca

> Maturity: **stable** (stable core). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Reference verifier for **Proof-Carrying Authority (PCA)**, an execution-authentication framework for
autonomous agents. With every action the agent presents a self-contained proof-carrying action
(PCActn); the resource server verifies the proof offline instead of trusting a bearer token.

> Status: **0.5.0, stable core verifier.** The shared conformance corpus is reproduced byte for byte; the middleware
> checks the proof only (see the security contract for what each surface enforces).

## Install

```sh
pip install atlas-pca
```

The verifier has no required dependencies. Optional extras: `atlas-pca[fast]` (native Ed25519 via
`cryptography`), `atlas-pca[pq]` (ML-DSA-65 post-quantum signatures via `dilithium-py`),
`atlas-pca[fastapi]`, `atlas-pca[django]`.

## Use

`verify_pcactn_core` is the **structural** verifier: it checks the proof's wire form, chain, signatures, plan
inclusion and validity against the grant you pass in. It does not evaluate the grant's predicates, limits or
caveats, plan authorization, revocation, the trust budget or the threshold, so a passing result is necessary but
not sufficient to perform the action. Pass the grant from your own store (never one the request carries), and take
the authorization decision with a full verifier (the Atlas server's action endpoint, or `verifyPCActn` /
`requirePCA` from `@atlasauth/pca`).

<!-- pca-core-verify: allow structural pre-check; the README states the authorization decision is the full verifier -->
```python
from atlas_pca import verify_pcactn_core

structural = verify_pcactn_core(pcactn, grant_from_your_store, audience="https://api.example.com")
if not structural.allow:
    raise PermissionError(f"authF failed: {structural.reason}")
# structurally valid: now ask the full verifier whether this action is inside the grant
```

## Authorize an operation (0.5)

`authorize` is the full decision for one operation. It runs the structural checks above, then:

- binds the proof to the operation your handler will execute: the signed verb, resource and params digest must equal
  it, and the grant's predicates and caveats are evaluated against those params (a proof signed for $50 cannot pay
  $400);
- evaluates the grant's envelope predicates (default deny), the envelope's caveats, caveats placed on the root grant
  and caveats added by delegation (`max_spend`, `predicates`, `tool_schema`, `expires`, `rate`, ...; an unknown type is
  refused);
- checks revocation with your `is_revoked`;
- consumes the replay counter through an atomic store, only when everything else passed.

Every component is required. Without `audience`, `resolve_grant`, `state_store`, `is_revoked` or the operation, the
call is refused and `result.missing` names what is absent.

<!-- pca-readme-sample: authorize -->
```python
from atlas_pca import SqliteStateStore, authorize

store = SqliteStateStore("pca-replay.db")  # one row per (grant, agent); safe across processes


def is_revoked(pcactn, grant):
    return grant["id"] in revoked_grant_ids  # your revocation list


result = authorize(
    pcactn,
    operation={"verb": "payments.send", "resource": "payments/acme", "params": body},  # what you will execute
    audience="payments-rs",
    resolve_grant=grants.get,  # grant_ref -> grant, from your own store
    state_store=store,
    is_revoked=is_revoked,
    plan="single-step",
    provenance=bundle,  # the agent's provenance bundle (see "Provenance by default"); guards read the PCA-Provenance header
    provenance_mediators=mediator_pins,  # the mediator keys you pin
)
if not result.allow:
    raise PermissionError(result.reason)  # e.g. "policy: caveat(s) not satisfied: max_spend"
send_payment(**body)
```

- `plan="single-step"` accepts a proof whose plan is this one operation. For a multi-step plan, pass
  `context=lambda pcactn: {"plan": nodes, "plan_authorized": True}` with the plan the principal authorized.
- `result.status` is 200, 401 (no proof, or one that fails authentication) or 403. `result.checks` lists every check;
  `result.operation` (on success) is the bound operation, and `is_authorized_for(result, operation)` re-checks it where
  the side effect runs.
- `MemoryStateStore` is for a single process. Your own store implements `claim(key, counter)` as one atomic operation
  (for example a conditional `UPDATE ... WHERE last_counter < :counter`), returning `ClaimResult(ok, last_counter)`.
- Not covered by `authorize` here: the risk score, trust budget and threshold co-signature from the grant's
  `risk_policy`, and liveness beacons. A grant that pins the agent (`agent_binding`) needs an attestation verifier and
  is refused, and so is a proof carrying `zk_compliance`. The TypeScript `authorize` covers these. Revocation
  staleness, plan lifecycle, goal binding v3 and assurance labels are covered; see below.

The guards run this pipeline by default. A guard built without `authorize` options refuses every request with
403 `authorize_config` (`missing` names the state store and revocation check you still have to supply); it never
falls back to checking the signature only.

```python
from atlas_pca import AuthorizeOptions, require_pca

guard = require_pca(
    audience="payments-rs",
    resolve_grant=grants.get,
    authorize=AuthorizeOptions(state_store=store, is_revoked=is_revoked, provenance_mediators=mediator_pins),  # plan="single-step" by default
    operation=lambda headers, body: {"verb": "payments.send", "resource": "payments/acme", "params": json.loads(body)},
)
```

To verify the signature only (chain, audience, validity, counter format) and nothing else, opt in explicitly with
`signature_only=True` (FastAPI `RequirePCA(..., signature_only=True)`, Django `PCA_SIGNATURE_ONLY = True`). That guard
does not check policy, replay, revocation or the request body, so do those yourself. Passing `signature_only` together
with `authorize` is a configuration error and raises at construction (`ValueError`; Django `ImproperlyConfigured`).

### Check names and denial reasons

- `counter_format` is the stateless check that the counter is a non-negative safe integer; its failure reads
  `counter_format: missing or not a non-negative safe integer`. `replay` is the stateful check that the counter is
  strictly greater than the last one seen for the grant and holder; its failures read
  `replay: 3 is not greater than last seen 3 (replay)`, `replay: 3 was already claimed (replay)` and
  `replay: the replay store failed (fail closed)`. The name `counter` is no longer emitted; in `authorize(require=[...])`
  it is accepted as an alias of `replay`.
- When a predicate's verb and resource match the operation but a limit in its `where` is not met, the denial names the
  limit: `amount <= 100 not satisfied for payments.send on payments/acme`. Operands are spelled out for integers,
  booleans, `null`, short plain strings and short lists (`currency in ["usd", "eur"]`); anything else prints as
  `<number>` or `<value>`. When no predicate is in scope the reason stays `no predicate permits <verb> on <resource>`,
  and an empty list `envelope grants no predicates`.

FastAPI: `RequirePCA(..., authorize=AuthorizeOptions(...), operation=fn)`, where `fn(request, body)` (sync or async)
returns the operation the route executes; `pca.operation` is the bound operation. Django: `PCA_AUTHORIZE` (an
`AuthorizeOptions`, a dict of its fields, or a dotted path) and `PCA_OPERATION` (`fn(request)`, or a dotted path).
A denial happens before the route or view runs.

### `protect()`: secure defaults in one call

```python
from atlas_pca import protect
from atlas_pca.fastapi import RequirePCA

p = protect("ins_acme", [grant],
            operation=lambda request, body: {"verb": "payments.send", "resource": "payments/acme", "params": json.loads(body)})
guard = RequirePCA(**p.options)     # Django: PCA_AUDIENCE, PCA_RESOLVE_GRANT, PCA_AUTHORIZE, PCA_OPERATION from p.options
p.revoke(grant["id"])               # later: every action under that grant is refused
```

`protect(audience, grants, operation=None, *, now=None, is_revoked=None, **authorize_fields)` fills in the grant lookup
(your list, or a function of `grant_ref`; never the request), an in-memory replay store, a revocation source and
`plan="single-step"`. Fields you pass (`state_store=`, `require=`, ...) win. Use a durable `state_store` (for example
`SqliteStateStore`) when more than one process serves requests. The TypeScript `protect()` also prices risk from the
connector catalog; this verifier does not compute the risk score, so that part is omitted.

### Explaining a refusal

`explain_refusal(reason)` returns `{"check", "meaning", "fix", "docs"}` for any refusal reason (it never raises; an unknown
reason links the refusals table). Refusal responses carry a `doc` link to the matching entry of the refusals reference: the Django middleware puts `doc` next to `error`; the FastAPI dependency keeps `detail` as the reason string and returns a sibling `doc` field once you call `add_pca_handler(app)`.
A runnable server is in `examples/fastapi-server`.

## Acting as an agent (producing proofs)

The package also produces the proofs it verifies, so an agent written in Python needs no other runtime. The principal mints a
root grant for the agent's public key; the agent signs one PCActn per action and sends it in the `PCA-Action` header (the
`Agent` client keeps the replay counter, picks the nonce and builds the headers).

```python
from atlas_pca import Agent, generate_keypair, mint_grant
from atlas_pca.agent import DEFAULT_RISK_POLICY

principal, agent_key = generate_keypair(), generate_keypair()  # the principal's key stays with the principal

minted = mint_grant(principal, agent_key.public, {
    "predicates": [{"verb": "refund", "resource": "orders/*"}],
    "caveats": [{"type": "max_spend", "usd": 50}],
    "agent_binding": {},
    "risk_policy": DEFAULT_RISK_POLICY,
}, goal="refund order 1")

agent = Agent(agent_key, minted["grant"], aud="https://api.example.com")
action = agent.act("refund", "orders/1", {"amount_cents": 500})
# any HTTP client: requests.post(url, json=body, headers=action.headers)
response = agent.fetch("POST", "https://api.example.com/orders/1/refund", "refund", "orders/1", {"amount_cents": 500},
                       body=b'{"amount_cents": 500}', headers={"Content-Type": "application/json"})
```

Delegate to a sub-agent with `agent.delegate(sub_key, [{"type": "sealed"}])` (caveats are only ever appended, so a child is never
wider than its parent). Third-party and approval artifacts: `sign_discharge`, `sign_narrow`, `sign_escalation_answer` (with the
`render_digest` the approver saw), `sign_passport`, `sign_workflow` / `sign_step_receipt`, `sign_read_grant`, `sign_fresh_at`.
Ed25519 outputs are byte-exact against the shared producer vectors; ML-DSA-65 / ML-DSA-87 and the hybrid suites sign through
`dilithium-py` (`pip install atlas-pca[pq]`, then `generate_pq_keypair()`; SLH-DSA signs through OpenSSL >= 3.5, `generate_pq_keypair("SLH-DSA-SHA2-128f")`) and `Agent(..., alg="hybrid-ed25519-ml-dsa-65", pq=...)`).
Persist the counter (`Agent(on_counter=...)`) if the process can restart: a lower counter is refused as a replay.

## Provenance by default (0.5)

`authorize` (and every guard) runs a `provenance_flow` check on each operation. It answers one question: did the content that
chose this action, and each of its arguments, come from the principal, or from something the agent read (an email, a web
page, a tool output)? A sensitive action whose choice or arguments derive from untrusted content is escalated
(`decision == "escalate"`, reason `provenance_flow: escalate: ... (prompt-injection path)`): only a principal-signed
escalation answer admits it. A read-only action is never sensitive; an action you describe nothing about is treated as
sensitive. A chain that is forged, broken, or bound to another operation is denied.

The labels come from signed receipts written by the agent harness (the mediator, which sees every segment of the agent's
context), never from the agent itself. On the agent side:

```python
from atlas_pca import create_provenance_recorder

rec = create_provenance_recorder(mediator="assistant-harness", kid="k1", secret_key=mediator_seed)  # 32-byte Ed25519 seed
rec.principal("Email the Q3 report to bob@acme.example")  # what the principal typed
rec.tool("gmail.read", inbox_text)                         # also rec.retrieval(source, content), rec.web(url, content)
bundle = rec.for_action({"verb": "email.send", "resource": "mail", "params": params})
# send it with the request: header PCA-Provenance (base64url JSON), or the JSON body member "pca_provenance"
```

`principal_direct_provenance(recorder, operation)` records an operation the principal issued directly. On the server, pin the
mediator key (`rec.pin`, `{"mediator", "kid", "pk"}`, plus `pq_pk` for a hybrid suite) and say what each action does:

```python
authorize(pcactn, operation=op, ..., provenance=bundle,         # or provenance_request=(headers, body)
          provenance_mediators=[mediator_pin],
          provenance_actions=lambda op: {"effects": ["send"], "traits": ["pca.exfiltration"]})
AuthorizeOptions(..., provenance_mediators=[mediator_pin])      # the guards read the header or the body member
```

- No bundle, or one from an unpinned mediator, means the content is unlabelled: a sensitive action escalates.
- A header that does not decode is refused (`the provenance bundle is unreadable (fail closed)`); so is an
  `provenance_actions` or `provenance_observed` callback that raises.
- `provenance_observed=(pcactn, operation, session) -> [{"origin", "source"}]` adds content your server knows the agent saw.
- A plan the principal authorized through a `PlanRegistry`, or an admitted workflow step, counts as the principal choosing
  the action (a plan supplied by `context` does not).
- The principal can designate mediators inside the signed grant: envelope member `provenance: {"mediators": [pin]}`.
- The only way to turn the check off is the principal-signed envelope member `provenance: {"mode": "insecure_off"}`
  (the check then reads `not-enforced`). It is dangerous: injected content can then steer any action of that grant.

## Undo windows (0.5)

An escalated operation that can be undone may run now under a veto window instead of waiting for approval. Give `authorize`
(or `AuthorizeOptions`) an `undo_admit` hook:

```python
def undo_admit(pcactn, grant, operation):
    # durably open the undo record first; return None to leave the escalation in place
    record = undo_ledger.open(operation, window_ms=resolve_undo_window(requested_ms, policy))
    return {"id": record.id, "window_end": record.window_end, "compensation": {"verb": "drafts.delete", "resource": "drafts"}}

result = authorize(pcactn, operation=op, ..., undo_admit=undo_admit)
if result.allow and result.undo:
    ...  # runs now; result.obligations == [{"kind": "undo_window", "params": {"id", "window_end"}, "due": window_end}]
```

- The hook is called only for an unanswered escalation. It is never called for a provenance escalation (`provenance_flow` or
  the intent `provenance` check failed: being reversible does not make an injected action safe), when an escalation answer is
  presented, or for a denial.
- Return the admission only after the record is durably open. A hook that raises, or returns anything malformed, admits
  nothing and the escalation stands.
- On admission the result is an allow with `checks["undo_window"] == "pass"`, the reason
  `undo_window: runs now under a veto window until <window_end> (compensation <verb>)`, `result.undo` (the admission) and the
  `undo_window` obligation. An enforcement point that does not run undo windows must refuse it
  (`pep_obligation_gate(..., supported)` does).

The pure layer for the undo service: `sign_undo_token` / `undo_token_check` (the one-click veto token; checks in the order
`malformed`, `signer`, `signature`, `record`, `binding`, `expired`, valid through `window_end`), `encode_undo_token` /
`decode_undo_token`, `sign_undo_receipt` / `verify_undo_receipt` and `undo_receipt_chain_error` (the signed, hash-linked
receipt chain of a record), `undo_transition` (the state machine: veto, finalize, abort, effect, compensated,
compensation failed, retry; the record passed in is never modified), `compensation_digest` and `resolve_undo_window`
(30 seconds to 24 hours, 15 minutes by default).

## Hardware attestation

The package checks hardware evidence itself: AMD SEV-SNP, Intel TDX (DCAP), Azure Attestation, Google Confidential Space and
NVIDIA GPU. Install the `attest` extra (it needs the `cryptography` package; the base package stays dependency-free), build a
verifier from a configuration and run it over the evidence for one action:

```python
from atlas_pca.attest import verifier_from_config

v = verifier_from_config(
    "amd-sev-snp",
    {"family": "genoa", "binding": "report-data", "policy": {"measurements": ["<hex of the 48-byte launch measurement>"]}},
    resolve_evidence=lambda document: document["evidence"],  # the vendor evidence for this action (the default)
)
res = v.verify(document, {"holderPub": key, "grantRef": "passport:" + pid, "epoch": 0, "nonce": nonce}, now_ms)
# res["ok"] and res["bound"]: the quote is genuine, bound to that holder, grant, epoch and nonce; res["measured"] is the measured identity
```

The configuration and the evidence of each vendor are the language-neutral ones of the shared conformance vectors (bytes are
standard base64 strings), and the verifiers answer exactly what the TypeScript verifiers answer, reason text included. They fail
closed: a missing allowlist, trust anchor, issuer, collateral or binding is a denial, never a pass, and a configuration that
would accept anything raises `AttestConstructError` at construction. They are classical (ECDSA, RSA), not post-quantum, and do
no network I/O: the evidence, the collateral (Intel PCS, NVIDIA reference manifests, CRLs, OCSP responses) and the trust anchors
are yours to supply.

To verify hardware-rooted passports with it, pass it as `default_verifier`; an `attest` callable you supply still wins:

```python
from atlas_pca import verify_passport

verify_passport(signed, issuers, now_ms, revoked=revoked, default_verifier=v)  # None, or the reason code
```

## Caveat enforcement (policy layer)

`verify_pcactn_core` (and the `require_pca` / FastAPI / Django guards in `signature_only` mode) does
**not** evaluate caveats. `authorize` above does. To evaluate caveats yourself, call the policy helpers with your own
action context:

```python
from atlas_pca import evaluate_caveats, policy_caveats

ok, failed = evaluate_caveats(policy_caveats(grant, pcactn["cap_chain"]), {
    "now": now_ms,
    "delegation_depth": len(pcactn["cap_chain"]) - 1,
    "action": {"verb": "pay", "resource": "invoice:42", "params": {"amount": 150, "currency": "usd"}},
})
if not ok:
    raise PermissionError(f"caveat(s) not satisfied: {', '.join(failed)}")
```

`policy_caveats(grant, chain)` is the grant's own caveats (the root's, without its first `envelope` caveat) followed by
the caveats the delegation hops appended. Since 0.4.1 the root's caveats are included: caveats placed on the root grant
outside the envelope are enforced exactly like delegated ones. `evaluate_caveats` implements `max_spend` (`{usd}`
against `action.params.amount`, currency absent or `"usd"`/`"USD"`), `expires`, `not_before`, `rate`,
`max_blast_radius`, `reversibility_max`, `delegation_depth` and `budget_alloc`; any other type is unsatisfied (fail
closed). It never raises.

The `PCA-Action` header is strict unpadded base64url of UTF-8 text (`decode_pca_header`): padding, the standard
alphabet, whitespace anywhere or invalid UTF-8 is a 401.

## Optimistic path and transparency ledger (0.5)

Verify what an operator of the optimistic fast path or of a transparency log publishes. All functions are total (they return a verdict, never raise) and accept Ed25519 signatures only.

```python
from atlas_pca import claim_check, settlement_wire_check, verify_tree_head, verify_ledger_consistency, verify_checkpoint_chain

claim_check(claim, pcactn_digest, agent_public, server_now_ms)      # "ok" or the first failing check
settlement_wire_check(record, guardian_public)                      # "ok", "shape", "split", "signature", ...
verify_tree_head(sth, guardian_public, {"witnessKeys": [...], "threshold": 1})   # guardian signature plus witness cosignatures
verify_checkpoint_chain([{"sth": a}, {"sth": b, "proof": proof}], guardian_public)  # {"ok": True} or {"ok": False, "at": i}
```

A log gives tamper evidence only when at least one independent witness cosigns its heads; pass a witness policy to require it.

## Execution records, plans, staleness, assurance and the mesh (0.5)

**Execute at most once.** `authorize` decides and consumes the replay counter; `execute_authorized` then runs your side
effect once, under a durable record per operation id (the idempotency key for the downstream call). A retry of the same
proof is answered from the record, a crash never re-runs anything, and an operation whose outcome is unknown is
`uncertain` until you reconcile it.

```python
from atlas_pca import AuthorizeOptions, create_executor, recover_operations, resolve_operation, sqlite_operation_store

operations = sqlite_operation_store("pca-operations.db")  # shared across worker processes on one host
execute = create_executor(
    operations=operations,
    options=AuthorizeOptions(state_store=store, is_revoked=is_revoked),
    audience="payments-rs",
    resolve_grant=grants.get,
)
outcome = execute(pcactn, {"verb": "payments.send", "resource": "payments/acme", "params": body},
                  lambda h: send_payment(idempotency_key=h.idempotency_key, **body))
# outcome.status: committed | failed | aborted | pending | uncertain | refused | denied; outcome.replayed
```

An irreversible operation (the stricter of the signed class and your `reversibility_class_of`; a missing class counts as
irreversible) is re-checked immediately before it runs: the grant is not revoked, the proof has not expired and a
registered plan is still executable. `recover_operations(store)` settles stale records at startup; `resolve_operation`
settles an `uncertain` one after you asked the downstream system by the idempotency key.

**Plan lifecycle.** `PlanRegistry` records a plan as `draft`, `validated`, `committed`, `authorized` and `revoked`; the
root is computed from the nodes, and `authorize(plans=registry)` (or `AuthorizeOptions(plans=...)`) accepts a multi-step
plan only while it is executable (authorized, approval unexpired, nodes still hash to the root). Pass
`SqliteAtomicKv(path)` as `kv` for durable state.

**Revocation staleness.** `authorize(revocation_staleness=RevocationStaleness(guardian_public=...))` caps how old the
revocation state may be: 5 minutes by default and 2 minutes for an irreversible action. Supply the state in the context
callback as `{"revocation_state": {"kind": "epoch", "epoch": signed_epoch}}` (or `{"kind": "root", "root": ..,
"issued_at": ..}`); an irreversible action needs a guardian-signed epoch unless you allow an unsigned root. `is_revoked`
still decides revocation. The helpers `check_revocation_age`, `check_revocation_epoch`, `effective_reversibility` and
`revocation_max_age_ms` are exported.

The gate also proves no capability in the chain is revoked: after the freshness step every capability id (default: each `id` in
the PCActn's `cap_chain`; override with `RevocationStaleness(ids=lambda pcactn: [...])`) needs a valid non-membership proof
against the state's root, from `RevocationStaleness(proof_for=lambda cap_id, pcactn: proof)`. A missing proof denies (fail
closed), so a staleness policy without a proof source denies every request that has a capability chain. `verify_non_membership`
is exported.

**Goal binding v3.** An intent policy with `approved_goal={"goal_digest": .., "policy_digest": ..}` (both canonical
base64url, 32 bytes) accepts only a root grant whose goal commitment opens to exactly that approved goal and compiled
policy (`intent_goal_v3`, `intent_goal_commit_v3`). A v1 or v2 grant does not open it.

**Assurance labels.** Every `authorize` result carries `assurance`, saying what each passing check rests on. Label your
own verifier hooks with `set_assurance_label(hook, "hardware", vendor="amd-sev-snp")` and build a report with
`assurance_report(pcactn, checks, hooks={"attestation": hook})`. `require_assurance={"signature": "pq"}` (also
`attestation`, `zk`, `threshold`, `allowAwaitingAudit`) fails the `assurance` check before any replay state is written when the
evidence is weaker, missing, unlabelled, awaiting-audit, degraded or unsupported. Reasons start with `assurance: `.

**Test your own store.** `run_state_store_conformance(lambda: MyStateStore(dsn))` and
`run_operation_store_conformance(...)` race real threads against your store (one burst on a handle, a burst spread over
several handles, a claim that must survive a restart or a crash) and return a report: `assert report.ok, report.render()`.

**Cross-domain mesh.** `verify_mesh_proof(proof, trust)` verifies a whole delegation across organisations offline: the
capability chain, one witnessed head per issuing domain (k-of-n cosignatures, freshness, optional pinned heads with RFC 9162
consistency proofs), log inclusion, revocation non-membership for every capability and issuer key, and the signed leaf
action. It never raises and returns `MeshVerdict(ok, reason, hop)`.

## Checks

Verification is stateless, fail-closed and runs in a fixed, normative order:
`wire`, `version`, `audience`, `validity`, `chain`, `grant_ref_bound`, `plan_inclusion`,
`leaf_signature`, `counter_format`.

`grant_ref_bound` (new in 0.2.0) requires the signed `grant_ref` to equal the id of the root capability
(`cap_chain[0]`), so replay state cannot be keyed on an attacker-chosen value.

The package runs the shared PCA conformance corpus: 676 PCActn vectors (129 that must verify, 547 that must be
refused) and 984 primitive vectors (canonical JSON, base64url, JSON parsing, Merkle proofs, caveat evaluation,
threshold shares, chain pins and more). The cross-language gate also runs it against the full adversarial set of
4,358 PCActn vectors and 1,178 adversarial primitives. The TypeScript, Rust, Go and other verifiers run the same files. Vectors
that need a signature suite this package does not implement are skipped by the runner; the verifier refuses such a
suite with `unsupported_suite`.

## What a passing result does not cover

`counter_format: pass` is a format check: the counter is a non-negative integer. It does **not** mean the action was
not replayed. `verify_pcactn_core` is stateless by design: the resource server must persist, per grant and agent, the last
accepted counter and refuse anything not strictly greater, atomically across all of its processes. `authorize` does
this through its `state_store`.

By default, `require_pca` and the FastAPI / Django guards run `authorize` (see above), which checks replay,
revocation, caveats, envelope predicates, plan authorization and the request operation, but not risk or thresholds.
With `signature_only=True` they run `verify_pcactn_core` only: no replay, revocation, caveats, envelope predicates or
plan authorization check, and no comparison of the request body with the signed `params_digest`. Do those in your
handler, or delegate the decision to a full verifier.

## Upgrading to 0.5

- **Breaking:** `require_pca`, `RequirePCA` and `PCAMiddleware` run the full `authorize` pipeline by default. Pass
  `authorize=` (state store, revocation check) and an `operation` mapping, or add `signature_only=True` to keep the
  old signature-only behaviour. Without either, requests are refused with 403 `authorize_config`.
- **Breaking:** the core check `counter` is now `counter_format`, and the stateful check in `authorize` is `replay`.
  Rename any code that reads `verdict.checks["counter"]` or `result.checks["counter"]`.
- Denial reasons for an unmet predicate limit now name the limit instead of `no predicate permits ...`.
- **Breaking:** assurance reasons and wording follow the reference: `unmet_assurance` returns `assurance: ...` text (for
  example `assurance: software attestation required but there is no attestation evidence`), a carried `bond_ref` reads
  `bond verification is not implemented by this verifier`, and a requirement with an unknown value is refused.
- **Breaking:** provenance by default. Every authorized operation needs a provenance bundle from a pinned mediator, or a
  sensitive action escalates (see "Provenance by default"). The only opt-out is the grant envelope member
  `provenance: {"mode": "insecure_off"}`.
- Added: `verify_mesh_proof`, `execute_authorized` / `create_executor` / `recover_operations`, `PlanRegistry`,
  `RevocationStaleness`, goal binding v3 (`approved_goal`), `set_assurance_label` and the step-up client.
- Framework adapters (`atlas-pca-*`) require `atlas-pca>=0.5,<0.6`.

## Links

- Source: https://github.com/Atlas-Authorization/pca-python
- Specification and docs: https://github.com/Atlas-Authorization/pca

License: MIT

## Suite policy defaults

- No list (`allowed_suites=None`) means no restriction: the verifier accepts every signature suite it knows.
- An empty list (`allowed_suites=[]`) means refuse everything.
- The hosted API defaults to `ed25519` plus the hybrids that include Ed25519, and refuses the pure post-quantum suites (`ml-dsa-*`, `slh-dsa-*`, `fn-dsa-*`, `less-cat1`) unless the operator lists them. To match it offline, pass `allowed_suites` exactly: `ed25519`, `hybrid-ed25519-ml-dsa-65`, `hybrid-nested-ed25519-ml-dsa-65`, `hybrid-ed25519-ml-dsa-87`, `hybrid-ed25519-slh-dsa-sha2-128f`, `hybrid-ed25519-slh-dsa-sha2-256s`, `hybrid-ed25519-less-cat1`. The effective hosted list is readable at `GET /v1/pca/suites`; see the [wire formats reference](https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/wire-formats.md).
