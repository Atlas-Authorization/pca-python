"""``explain_refusal(reason)``: turn a refusal reason from ``authorize`` / ``require_pca`` into what it means, how to fix
it, and the page that explains it. The reasons themselves are pinned across all ten languages and the conformance vectors,
so they are never reworded; this maps them (by their leading check name) to guidance instead. Unknown reasons return a
generic entry that still links the table. The wording is the same as the TypeScript ``explainRefusal``.
"""
import re
from typing import Any, Dict

#: Base of the published PCA docs.
PCA_DOCS = "https://github.com/Atlas-Authorization/pca/blob/main/docs"
_REF = PCA_DOCS + "/reference/refusals.md"

_TABLE = (
    ("authorize_config",
     "The guard was built without a required component, so it refuses every request (fail closed).",
     "Add the component the reason names (audience, resolveGrant, budgetStore, hooks.revocation). protect() fills them with safe defaults.",
     PCA_DOCS + "/guides/resource-server-quickstart.md"),
    ("authorize",
     "The guard was built without a required component, so it refuses every request (fail closed).",
     "Add the component the reason names (audience, resolveGrant, budgetStore, hooks.revocation). protect() fills them with safe defaults.",
     PCA_DOCS + "/guides/resource-server-quickstart.md"),
    ("operation",
     "The signed action is not the operation this route executes (other verb, resource or params).",
     "Sign the action the route runs, with the same params. If this is a tool server, use one tool-to-action mapping on both sides.",
     _REF + "#operation"),
    ("audience",
     "The proof was signed for a different server.",
     "Make the agent sign with the same audience string the server is configured with.",
     _REF + "#audience"),
    ("replay",
     "This proof (or an older counter) was already used.",
     "Each action needs a fresh proof. If this is a retry of an action that already ran, use an operation record instead of resending.",
     _REF + "#replay"),
    ("counter_format",
     "The proof carries no valid anti-replay counter.",
     "Build the proof with the agent facade (act) or buildPCActn, which set it.",
     _REF + "#replay"),
    ("plan_root_authorized",
     "The plan the action belongs to was not authorized by the principal.",
     "Use plan: single-step (protect() does) for one-action proofs, or have the principal authorize the committed plan root.",
     _REF + "#plan_root_authorized"),
    ("plan_state",
     "The plan is committed but not executable now (not authorized, expired or revoked).",
     "Check the plan state named in the reason and re-authorize or recommit.",
     _REF + "#plan_root_authorized"),
    ("revocation",
     "The grant, or the revocation source, refused.",
     "The grant was revoked, or no revocation source is configured. Configure hooks.revocation (protect() does).",
     _REF + "#revocation"),
    ("validity",
     "The proof is outside its validity window.",
     "Check clocks on both sides; request a fresh proof.",
     _REF + "#validity"),
    ("grant_ref",
     "The proof does not name a grant this server knows.",
     "Register the principal's grant with the server (its grants list or resolveGrant). The grant comes from your store, never from the request.",
     _REF + "#grant_ref"),
    ("grant_ref_bound",
     "The proof does not name a grant this server knows.",
     "Register the principal's grant with the server (its grants list or resolveGrant). The grant comes from your store, never from the request.",
     _REF + "#grant_ref"),
    ("policy",
     "The grant does not permit this action or these parameters (a predicate or limit failed).",
     "Widen the grant if the action is legitimate (the principal signs a new one); otherwise this is the guard working.",
     _REF + "#policy"),
    ("delegated_caveats",
     "A caveat added by a delegation refused the action.",
     "The sub-agent was narrowed below this action. Delegate with the caveats you intend.",
     _REF + "#policy"),
    ("threshold",
     "The risk needs a co-signature from the principal (step-up).",
     "Collect the co-sign through the step-up flow, or lower the risk the server prices.",
     PCA_DOCS + "/concepts/threshold-and-step-up.md"),
    ("risk_inputs",
     "A risk input the server must vouch for was not supplied.",
     "Supply it in the risk option (catalogRisk derives the common ones; protect() uses it).",
     _REF + "#risk_inputs"),
    ("chain",
     "The delegation chain does not verify back to the grant.",
     "Rebuild the chain with delegate()/subAgent(); do not edit a grant or hop after signing.",
     _REF + "#chain"),
    ("leaf_signature",
     "The proof signature does not verify.",
     "The proof was altered, or signed by a key that is not the chain leaf.",
     _REF + "#chain"),
    ("wire",
     "The proof is not well-formed under the strict wire profile.",
     "Send the proof exactly as encoded by encodePCActn (header PCA-Action, or body { pcactn }).",
     PCA_DOCS + "/reference/wire-formats.md"),
    ("malformed",
     "The proof could not be read.",
     "Send the proof exactly as encoded by encodePCActn (header PCA-Action, or body { pcactn }).",
     PCA_DOCS + "/reference/wire-formats.md"),
    ("freshness",
     "The consistency token or revocation epoch is stale.",
     "Refresh the token from the guardian and retry.",
     _REF + "#freshness"),
    ("template",
     "The grant is not an instantiation of a linked policy template.",
     "Mint the grant from the template the server requires.",
     PCA_DOCS + "/guides/policy-analysis.md"),
)


def explain_refusal(reason: Any) -> Dict[str, str]:
    """Guidance for a refusal reason: ``{"check", "meaning", "fix", "docs"}``. Never raises."""
    text = reason if isinstance(reason, str) else ""
    m = re.match(r"[a-z_]+", text)
    head = m.group(0) if m else ""
    hit = next((r for r in _TABLE if r[0] == head), None) or next((r for r in _TABLE if (r[0] + ":") in text), None)
    if hit:
        return {"check": hit[0], "meaning": hit[1], "fix": hit[2], "docs": hit[3]}
    return {"check": "unknown", "meaning": "The guard refused and the reason is not in the table.",
            "fix": "Read the reason as written; every refusal names the check that failed.", "docs": _REF}


def refusal_doc_url(reason: Any) -> str:
    """The reference-table URL for a refusal reason: ``refusals.md#<check>``, or the table itself when the check is unknown."""
    c = explain_refusal(reason)["check"]
    return _REF if c == "unknown" else _REF + "#" + c
