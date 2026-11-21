"""Generate-then-review natural-language policy authoring: the approval half of the reference ``nl`` module (the grounding prompt and the strict parse are
:func:`atlas_pca.intent_compilers.nl_prompt` / ``parse_nl_policy``). A model's completion is only ever a DRAFT: it is parsed strictly, grounded in the catalog
(a hallucinated verb is dropped and reported), content-addressed and bound to the instruction text, the model id and the prompt, and linted. A reviewer whose
key the verifier pinned signs the exact draft (:func:`approve_draft`); :func:`load_approved_policy` re-derives everything from the draft contents and is the
only door from a draft to policy; :func:`agent_from_approved_nl` is the only NL-to-agent path. The model is an injected ``complete(prompt) -> str``.
Guaranteed: no model output is enforced without a pinned reviewer's unexpired signature over the exact permissions, limits, catalog and (v2) the instruction,
model and prompt; every verb is in the catalog; the static analyzer has no error finding. A v1 approval (signed before the binding) still loads, flagged
``legacy_unbound_instruction``. Not guaranteed: that the model understood the instruction or that the reviewer read the draft."""
from __future__ import annotations

import math
from ._fin import fin
import time
from typing import Any, Callable, Dict, List, Optional

from .actions_import_common import _lenient, hash_canonical_lenient
from .agent import KeyPair
from .catalog import DEFAULT_CATALOG, Catalog
from .facade import compile_policy, create_agent
from .intent_compilers import nl_prompt, parse_nl_policy
from .pca import b64u, verify_b64u
from .policy_sim import lint_policy

__all__ = ["NL_APPROVAL_DOMAIN", "NL_APPROVAL_DOMAIN_V2", "MAX_NL_OUTPUT_BYTES", "MAX_NL_APPROVAL_TTL_MS", "policy_from_nl", "catalog_digest", "draft_binding",
           "draft_digest_v2", "draft_digest", "draft_policy_from_nl", "approve_draft", "approve_draft_legacy_v1", "load_approved_policy", "agent_from_approved_nl"]

NL_APPROVAL_DOMAIN = "atlas-pca/nl-approval/v1\0"
NL_APPROVAL_DOMAIN_V2 = "atlas-pca/nl-approval/v2\0"
MAX_NL_OUTPUT_BYTES = 16_384
MAX_NL_APPROVAL_TTL_MS = 24 * 3_600_000
_DEFAULT_TTL_MS = 3_600_000


def _u16_sorted(xs: Any) -> list:
    """Array.prototype.sort() with no comparator: UTF-16 code-unit order."""
    return sorted(xs, key=lambda s: s.encode("utf-16-be", "surrogatepass"))


def _cat(catalog: Optional[Catalog]) -> Catalog:
    return DEFAULT_CATALOG if catalog is None else catalog


def _lints_of(permissions: Any, limits: Any, catalog: Catalog) -> List[dict]:
    return lint_policy(compile_policy(permissions, limits, catalog.all()), catalog) if len(permissions) > 0 else []


def policy_from_nl(instruction: str, complete: Callable[[str], str], catalog: Optional[Catalog] = None) -> Dict[str, Any]:
    """Ask the model for a policy, ground it against the catalog and lint the compiled result: ``{permissions, limits, unknownVerbs, droppedLimits, raw,
    lints}``. Never trusts the model; raises only when the completion raises."""
    cat = _cat(catalog)
    raw = complete(nl_prompt(instruction, cat.all()))
    parsed = parse_nl_policy(raw, cat.all())
    return dict(parsed, raw=raw, lints=_lints_of(parsed["permissions"], parsed["limits"], cat))


def catalog_digest(catalog: Catalog) -> str:
    """The digest of the catalog vocabulary a draft was grounded against: sha256 over the lenient canonical rows [verb, reversibility, amountField|null]
    sorted by verb (NOT the connector catalog's own digest)."""
    rows = sorted(([s["verb"], s["reversibility"], s.get("amountField")] for s in catalog.all()), key=lambda r: r[0].encode("utf-16-be", "surrogatepass"))
    return hash_canonical_lenient({"v": 1, "rows": rows})


def draft_binding(instruction: str, catalog: Catalog, model: Optional[str] = None) -> Dict[str, Any]:
    """What approval v2 adds to a draft digest, all recomputable from public inputs: the instruction digest, the model id (or None) and the prompt digest."""
    return {"instruction_digest": hash_canonical_lenient({"d": "atlas-pca/nl-instruction/v1", "text": instruction}), "model": model,
            "prompt_digest": hash_canonical_lenient({"d": "atlas-pca/nl-prompt/v1", "text": nl_prompt(instruction, catalog.all())})}


def _sorted_permissions(permissions: dict) -> dict:
    return {c: _u16_sorted(permissions[c]) for c in _u16_sorted(permissions)}


def draft_digest_v2(permissions: dict, limits: dict, catalog_digest_: str, binding: dict) -> str:
    """The digest an approval v2 signs: the v1 content plus {instruction_digest, model, prompt_digest} (connector and action lists sorted)."""
    return hash_canonical_lenient({"v": 2, "permissions": _sorted_permissions(permissions), "limits": limits, "catalog_digest": catalog_digest_,
                                   "instruction_digest": binding["instruction_digest"], "model": binding["model"], "prompt_digest": binding["prompt_digest"]})


def draft_digest(permissions: dict, limits: dict, catalog_digest_: str) -> str:
    """The digest a v1 (pre-binding) reviewer signed: {permissions, limits, catalog digest}. Kept so old approvals still load."""
    return hash_canonical_lenient({"v": 1, "permissions": _sorted_permissions(permissions), "limits": limits, "catalog_digest": catalog_digest_})


def draft_policy_from_nl(instruction: str, complete: Callable[[str], str], catalog: Optional[Catalog] = None, model: Optional[str] = None) -> Dict[str, Any]:
    """Ask the model for a DRAFT (never enforced). Raises when the completion is not a string or exceeds MAX_NL_OUTPUT_BYTES UTF-8 bytes."""
    cat = _cat(catalog)
    raw = complete(nl_prompt(instruction, cat.all()))
    if not isinstance(raw, str) or len(raw.encode("utf-8", "surrogatepass")) > MAX_NL_OUTPUT_BYTES:
        raise ValueError("draftPolicyFromNL: model output exceeds %d bytes or is not a string" % MAX_NL_OUTPUT_BYTES)
    p = parse_nl_policy(raw, cat.all())
    lints = _lints_of(p["permissions"], p["limits"], cat)
    cd = catalog_digest(cat)
    binding = draft_binding(instruction, cat, model)
    return {"status": "draft", "instruction": instruction, "permissions": p["permissions"], "limits": p["limits"], "catalog_digest": cd, "binding": binding,
            "digest": draft_digest_v2(p["permissions"], p["limits"], cd, binding), "unknownVerbs": p["unknownVerbs"], "droppedLimits": p["droppedLimits"],
            "lints": lints, "analyzerOk": len(p["permissions"]) > 0 and not any(l["level"] == "error" for l in lints)}


def _approval_message(a: dict) -> bytes:
    body = {"v": a["v"], "digest": a["digest"], "catalog_digest": a["catalog_digest"], "reviewer": a["reviewer"], "approved_at": a["approved_at"],
            "expires_at": a["expires_at"]}
    return (NL_APPROVAL_DOMAIN_V2 if a["v"] == 2 else NL_APPROVAL_DOMAIN).encode("utf-8") + _lenient(body).encode("utf-8")


def _finite(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and fin(x)


def _signed(body: dict, secret: bytes) -> dict:
    return dict(body, sig=b64u(KeyPair(bytes(secret), allow_insecure_signer=True).sign(_approval_message(body))))


def approve_draft(draft: dict, reviewer_secret: bytes, opts: Optional[dict] = None) -> Dict[str, Any]:
    """The human step: sign the exact draft (approval v2). ``opts`` = {"now", "ttlMs"} (default 1 h, at most 24 h). Raises for a draft the analyzer rejects or
    that proposed verbs outside the catalog, and for an invalid time or ttl."""
    opts = opts or {}
    if not draft["analyzerOk"]:
        raise ValueError("approveDraft: the draft did not pass the static analyzer")
    if len(draft["unknownVerbs"]) > 0:
        raise ValueError("approveDraft: the draft proposed verbs that are not in the catalog")
    now = opts["now"] if opts.get("now") is not None else int(time.time() * 1000)
    ttl = opts["ttlMs"] if opts.get("ttlMs") is not None else _DEFAULT_TTL_MS
    if not _finite(now) or not _finite(ttl) or ttl <= 0 or ttl > MAX_NL_APPROVAL_TTL_MS:
        raise ValueError("approveDraft: invalid time or ttl")
    return _signed({"v": 2, "digest": draft["digest"], "catalog_digest": draft["catalog_digest"], "reviewer": KeyPair(bytes(reviewer_secret), allow_insecure_signer=True).public,
                    "approved_at": now, "expires_at": now + ttl}, reviewer_secret)


def approve_draft_legacy_v1(draft: dict, reviewer_secret: bytes, opts: Optional[dict] = None) -> Dict[str, Any]:
    """DEPRECATED pre-binding approval (v1): signs the draft WITHOUT the instruction, model or prompt. Only for the legacy-load window."""
    v2 = approve_draft(draft, reviewer_secret, opts)
    return _signed({"v": 1, "digest": draft_digest(draft["permissions"], draft["limits"], draft["catalog_digest"]), "catalog_digest": draft["catalog_digest"],
                    "reviewer": v2["reviewer"], "approved_at": v2["approved_at"], "expires_at": v2["expires_at"]}, reviewer_secret)


def _is_int(n: Any) -> bool:
    return not isinstance(n, bool) and isinstance(n, (int, float)) and fin(n) and n == math.floor(n) and abs(n) <= 9007199254740991 \
        and not (isinstance(n, float) and n == 0 and math.copysign(1, n) < 0)


def _to_number(x: Any) -> float:
    """The ECMAScript ToNumber of a JSON value used in a comparison (a numeric string counts, anything else unusable is NaN)."""
    if isinstance(x, bool):
        return float(x)
    if isinstance(x, (int, float)):
        return x
    if isinstance(x, str):
        try:
            return float(x.strip() or 0)
        except ValueError:
            return math.nan
    return math.nan


def load_approved_policy(draft: Any, approval: Any, opts: dict) -> Dict[str, Any]:
    """The only door from a draft to policy: recomputes the digest, the grounding and the lints from the draft contents. ``opts`` = {"reviewers": [pinned
    reviewer keys], "catalog"?, "now"?}. Returns ``{"ok": True, permissions, limits, reviewer, instruction, legacy_unbound_instruction}`` or ``{"ok": False,
    "reason"}`` (no_reviewers_pinned, not_a_draft, catalog_mismatch, tampered_draft, unknown_verbs, empty_permissions, analyzer_error, malformed_approval,
    digest_mismatch, reviewer_not_pinned, ttl_too_long, not_yet_valid, expired, bad_signature). Never raises."""
    def fail(reason: str) -> Dict[str, Any]:
        return {"ok": False, "reason": reason}
    try:
        cat = _cat(opts.get("catalog"))
        now = _to_number(opts["now"] if opts.get("now") is not None else int(time.time() * 1000))
        reviewers = opts.get("reviewers")
        if not isinstance(reviewers, list) or len(reviewers) == 0:
            return fail("no_reviewers_pinned")
        if not draft or draft.get("status") != "draft" or not isinstance(draft.get("permissions"), (dict, list)) or not isinstance(draft.get("limits"), (dict, list)):
            return fail("not_a_draft")
        cd = catalog_digest(cat)
        if draft.get("catalog_digest") != cd:
            return fail("catalog_mismatch")
        if not isinstance(draft.get("instruction"), str):
            return fail("not_a_draft")
        legacy_draft = "binding" not in draft
        if not legacy_draft and not isinstance(draft["binding"], dict):
            return fail("not_a_draft")
        if legacy_draft:
            if draft_digest(draft["permissions"], draft["limits"], cd) != draft.get("digest"):
                return fail("tampered_draft")
        else:
            b = draft["binding"]
            binding = draft_binding(draft["instruction"], cat, b.get("model") if isinstance(b.get("model"), str) else None)
            if b.get("instruction_digest") != binding["instruction_digest"] or b.get("prompt_digest") != binding["prompt_digest"] or b.get("model") != binding["model"]:
                return fail("tampered_draft")
            if draft_digest_v2(draft["permissions"], draft["limits"], cd, binding) != draft.get("digest"):
                return fail("tampered_draft")
        # re-ground: every verb must be in the catalog, whatever the draft claims
        perms = draft["permissions"]
        for c, acts in (perms.items() if isinstance(perms, dict) else enumerate(perms)):
            if not isinstance(acts, list) or any(not isinstance(a, str) or cat.get("%s.%s" % (c, a)) is None for a in acts):
                return fail("unknown_verbs")
        if isinstance(draft.get("unknownVerbs"), list) and len(draft["unknownVerbs"]) > 0:
            return fail("unknown_verbs")
        if len(perms) == 0:
            return fail("empty_permissions")
        if any(l["level"] == "error" for l in _lints_of(perms, draft["limits"], cat)):
            return fail("analyzer_error")
        a = approval
        if (not isinstance(a, dict) or isinstance(a.get("v"), bool) or a.get("v") not in (1, 2) or not isinstance(a.get("sig"), str)
                or not isinstance(a.get("reviewer"), str) or not isinstance(a.get("digest"), str) or not isinstance(a.get("catalog_digest"), str)
                or not _is_int(a.get("approved_at")) or not _is_int(a.get("expires_at"))):
            return fail("malformed_approval")
        legacy = a["v"] == 1
        if legacy_draft and not legacy:
            return fail("digest_mismatch")  # a v2 approval promises the instruction is bound; a binding-less draft cannot honor that
        if a["digest"] != (draft_digest(perms, draft["limits"], cd) if legacy else draft["digest"]) or a["catalog_digest"] != cd:
            return fail("digest_mismatch")
        if a["reviewer"] not in reviewers:
            return fail("reviewer_not_pinned")
        ttl = a["expires_at"] - a["approved_at"]
        if ttl <= 0 or ttl > MAX_NL_APPROVAL_TTL_MS:
            return fail("ttl_too_long")
        if not (fin(now) and a["approved_at"] <= now):
            return fail("not_yet_valid")
        if not (fin(now) and now < a["expires_at"]):
            return fail("expired")
        if not verify_b64u(a["reviewer"], _approval_message(a), a["sig"]):
            return fail("bad_signature")
        return {"ok": True, "permissions": perms, "limits": draft["limits"], "reviewer": a["reviewer"], "instruction": draft["instruction"],
                "legacy_unbound_instruction": legacy}
    except Exception:  # noqa: BLE001 - the loader never throws
        return fail("malformed_approval")


def agent_from_approved_nl(req: dict) -> Dict[str, Any]:
    """The ONLY NL-to-agent path: mints an agent from a draft a pinned reviewer signed. ``req`` = {"draft", "approval", "reviewers", "principal" (KeyPair),
    "goal", "catalog"?, "aud"?, "holder"?, "now"?}. Raises with the rejection reason otherwise; a v2 approval requires the goal to equal the approved
    instruction. Returns {"agent", "reviewer", "legacy_unbound_instruction"}."""
    loaded = load_approved_policy(req["draft"], req["approval"], req)
    if not loaded["ok"]:
        raise ValueError("agentFromApprovedNL: %s" % loaded["reason"])
    if not loaded["legacy_unbound_instruction"] and req["goal"] != loaded["instruction"]:
        raise ValueError("agentFromApprovedNL: goal_mismatch")
    cat = req.get("catalog")
    agent = create_agent(req["principal"], req["goal"], loaded["permissions"], loaded["limits"], holder=req.get("holder"),
                         catalog=None if cat is None else cat.all(), aud=req.get("aud"), now=req.get("now"))
    return {"agent": agent, "reviewer": loaded["reviewer"], "legacy_unbound_instruction": loaded["legacy_unbound_instruction"]}
