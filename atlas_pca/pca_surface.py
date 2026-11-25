"""Small public functions and constants of the TypeScript flagship that the verifier needs under their reference semantics: the cheap
pre-authentication chain check, the holder-committed PQ key, discharge requests, policy-side obligation collection, the detector-receipt
policy fold, the cheap PCActn claims, hash-suite helpers and a handful of constants and aliases. Each is pure and total unless its doc says it
raises. Records are dicts with the reference's member names."""
from ._fin import fin
import hashlib
import math
from typing import Any, Dict, List, Optional, Sequence

from .caveat_lang import CAVEAT_NEEDS_DISCHARGE, bound_caveats, needs_discharge_error
from .dataflow import DETECTOR_RECEIPT_DOMAIN, _ID_RE, detector_receipt_shape_error
from .intent_wb import _closed_members, _is_safe_int, verify_artifact_sig
from .obligations import merge_obligations, obligations_error
from .pca import (CAP_DOMAIN, CAVEAT_LIMIT_REASON, MAX_CAVEATS_PER_CHAIN, MAX_CAVEATS_PER_HOP, MAX_CHAIN_DEPTH, MAX_LIFETIME_MS, MAX_SKEW_MS,
                  _SIG_SUITES, _resolve_pq_key, _resolve_suite, _signable_hop_body, _suite_policy_error, _verify_b64u, cap_hash, hash_canonical,
                  unb64u)
from .predicates import evaluate_condition_tri

__all__ = ["holder_pq_key", "verify_chain_cheap", "discharge_requests", "collect_obligations", "MAX_DETECTOR_RECEIPTS", "detector_policy_error",
           "detector_signal", "pcactn_cheap_claims", "DEFAULT_HASH_SUITE", "b64u_len", "hash_with_suite", "is_canonical_b64u", "is_hash_suite",
           "REPLAY_MIN_RETENTION_MS", "verify_goal_commit", "APPROVAL_RENDER_KIND", "CATALOG_REVERSIBILITY_SCORE", "STATEFUL_REQUIRED_CHECKS",
           "EXECUTION_REQUIRED_CHECKS", "PCA_NEED_DOMAIN", "PCA_GRANT_MAX_DETAILS", "PCA_GRANT_MAX_CHAIN_LEN", "PCACTN_DEFAULT_TTL_MS",
           "ACTION_DEF_VERSION", "PARAM_TYPES_V1", "SENSITIVITY_LEVELS", "TAINT_CONTEXT_RE", "MAX_PQ_SIGNER_ENTRIES", "verify_membership",
           "validate_revocation_staleness", "named_unmet_limit_reason", "agent_caveat_context", "catalog_risk"]

# ---- constants -------------------------------------------------------------------------------------------------------------

DEFAULT_HASH_SUITE = "sha256"  #: an absent ``hash_suite`` MUST be read as this
REPLAY_MIN_RETENTION_MS = MAX_LIFETIME_MS + 2 * MAX_SKEW_MS  #: minimum nonce retention: the longest action lifetime plus twice the clock skew
APPROVAL_RENDER_KIND = "pca-approval-render"
CATALOG_REVERSIBILITY_SCORE = {"reversible": 1, "rate_limited": 0.4, "costly": 0.4, "irreversible": 0}
STATEFUL_REQUIRED_CHECKS = ("counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound")
EXECUTION_REQUIRED_CHECKS = STATEFUL_REQUIRED_CHECKS + ("params_digest", "policy")
PCA_NEED_DOMAIN = "atlas-pca/need/v1"
PCA_GRANT_MAX_DETAILS = 16
PCA_GRANT_MAX_CHAIN_LEN = 16
PCACTN_DEFAULT_TTL_MS = 20 * 60_000
ACTION_DEF_VERSION = 1
PARAM_TYPES_V1 = ("string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref")
SENSITIVITY_LEVELS = ("free", "material", "critical")
MAX_DETECTOR_RECEIPTS = 32
MAX_PQ_SIGNER_ENTRIES = 256
import re as _re
TAINT_CONTEXT_RE = _re.compile(r"session_taint_max:[a-z_]{1,16}")


# ---- hash suites -----------------------------------------------------------------------------------------------------------

def is_hash_suite(s: Any) -> bool:
    return s in ("sha256", "sha384") and isinstance(s, str)


def hash_with_suite(data: bytes, suite: str = DEFAULT_HASH_SUITE) -> bytes:
    """Dispatch a raw-byte hash over the selected suite (the default is byte-identical to a bare SHA-256)."""
    return hashlib.sha384(bytes(data)).digest() if suite == "sha384" else hashlib.sha256(bytes(data)).digest()


def b64u_len(n: int) -> int:
    """The unpadded base64url length of `n` bytes."""
    return math.ceil((n * 4) / 3)


def is_canonical_b64u(s: Any, length: Optional[int] = None) -> bool:
    """True iff `s` is canonical base64url (optionally of an exact decoded byte length)."""
    from .pca import decode_b64u_strict
    return decode_b64u_strict(s, length) is not None


def verify_goal_commit(commit: str, goal: str, salt: str) -> bool:
    """Open a goal commitment with (goal, salt)."""
    from .agent import goal_commit_of
    return goal_commit_of(goal, salt) == commit


# ---- capability chain ------------------------------------------------------------------------------------------------------

def holder_pq_key(alg: Any, holder: str, artifact_pq_pk: Any, holder_pq: Optional[str], allow_unbound_pq: bool = False) -> Dict[str, Any]:
    """The PQ verify key of a chain-leaf or threshold-share signature, resolved through the single choke point from the holder's ``holder_pq``
    commitment: ``{"pq": key}``, or ``{}`` for ed25519 and (so the signature check fails closed) when the artifact's ``pq_pk`` is not the
    committed key. Natives have no ``allowUnboundPq``: an artifact's own key is never enough."""
    spec = _SIG_SUITES.get(alg) if isinstance(alg, str) else (_SIG_SUITES["ed25519"] if alg is None else None)
    if spec is None or not spec[1]:
        return {}
    pq = _resolve_pq_key(holder, artifact_pq_pk, holder_pq=holder_pq)
    return {} if pq is None else {"pq": pq}


def _well_typed(c: Any) -> bool:
    """The reference's ``wellTyped``: the string members, the optional members (a string when present, null is not absent) and caveat objects with a string type."""
    if not isinstance(c, dict):
        return False
    if not all(isinstance(c.get(k), str) for k in ("id", "issuer", "holder", "body_digest", "sig")):
        return False
    if not all(k not in c or isinstance(c[k], str) for k in ("alg", "pq_pk", "pq_sig", "holder_pq", "parent")):
        return False
    return isinstance(c.get("caveats"), list) and all(isinstance(cv, dict) and isinstance(cv.get("type"), str) for cv in c["caveats"])


def verify_chain_cheap(chain: Any, expected_root_issuer: Optional[str] = None, allowed_suites: Any = None) -> Dict[str, Any]:
    """A pre-authentication necessary-condition check of a delegation chain: shape, caveat limits, depth, suite policy, parent links, body
    digests and the Ed25519 halves (at most ``MAX_CHAIN_DEPTH`` verifications). ``{"ok": True, "pqHops"}`` is NEVER an authentication: the caller
    must still run the full verifier after matching the root to a stored grant. A pure-PQ hop passes on structure alone."""
    try:
        arr = chain if isinstance(chain, list) else []
        if not arr:
            return {"ok": False, "reason": "empty chain"}
        if len(arr) > MAX_CHAIN_DEPTH:
            return {"ok": False, "reason": "chain too long (max %d hops)" % MAX_CHAIN_DEPTH}
        total = 0
        for c in arr:
            n = len(c["caveats"]) if isinstance(c, dict) and isinstance(c.get("caveats"), list) else 0
            total += n
            if n > MAX_CAVEATS_PER_HOP or total > MAX_CAVEATS_PER_CHAIN:
                return {"ok": False, "reason": CAVEAT_LIMIT_REASON}
        pq_hops = 0
        for i, c in enumerate(arr):
            label = "hop %d" % i
            if not _well_typed(c):
                return {"ok": False, "reason": "%s: malformed capability" % label}
            suite, err = _resolve_suite(c)
            if suite is None:
                return {"ok": False, "reason": "%s: %s" % (label, err)}
            bad = _suite_policy_error(c.get("alg"), label, allowed_suites)
            if bad is not None:
                return {"ok": False, "reason": bad}
            if i == 0:
                if c.get("parent") is not None:
                    return {"ok": False, "reason": "hop 0: root must not have a parent"}
                if expected_root_issuer is not None and c["issuer"] != expected_root_issuer:
                    return {"ok": False, "reason": "hop 0: root issuer is not the expected principal"}
            else:
                parent = arr[i - 1]
                if c.get("parent") != cap_hash(parent):
                    return {"ok": False, "reason": "%s: broken parent link" % label}
                if c["issuer"] != parent["holder"]:
                    return {"ok": False, "reason": "%s: issuer is not the parent's bound holder" % label}
            body, e2 = _signable_hop_body(c)
            if body is None:
                return {"ok": False, "reason": "%s: %s" % (label, e2)}
            try:
                digest = hash_canonical(body)
            except Exception:  # noqa: BLE001
                return {"ok": False, "reason": "%s: malformed body" % label}
            if digest != c["body_digest"] or c.get("id") != c["body_digest"]:
                return {"ok": False, "reason": "%s: body digest mismatch" % label}
            _, needs_pk, needs_pq_sig, key_type, _ = _SIG_SUITES[suite]
            if key_type is None or needs_pq_sig:  # the suite has an Ed25519 half
                signer = c["issuer"] if i == 0 else arr[i - 1]["holder"]
                if not _verify_b64u(signer, CAP_DOMAIN + unb64u(c["body_digest"]), c["sig"]):
                    return {"ok": False, "reason": "%s: bad signature (not signed by expected key)" % label}
            if needs_pk:
                pq_hops += 1
        return {"ok": True, "pqHops": pq_hops}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": "malformed capability chain: %s" % (str(e) or "unverifiable")}


def discharge_requests(grant: dict, chain: Any, action_digest: Optional[str] = None) -> List[dict]:
    """What a verifier that answered ``escalate`` for a missing discharge asks for: one request per undischarged ``needs_discharge`` caveat of
    the leaf hop."""
    out: List[dict] = []
    for b in bound_caveats(grant, chain) or []:
        c = b["caveat"]
        if not isinstance(c, dict) or c.get("type") != CAVEAT_NEEDS_DISCHARGE or needs_discharge_error(c) is not None:
            continue
        r: Dict[str, Any] = {"v": 1, "kind": "pca-discharge-request", "caveat_id": c["id"], "issuer": c["issuer"], "cap_hash": b["cap_hash"], "bind": c["bind"]}
        if c["bind"] == "action" and action_digest is not None:
            r["action_digest"] = action_digest
        r.update({"require": c["require"], "ttl_ms": c["ttl_ms"]})
        out.append(r)
    return out


def verify_membership(root: str, proof: Any, rid: str) -> bool:
    """`rid` IS in the sorted revocation set `root` commits to (inclusion against the size-bound root)."""
    from .intent_v2 import _leaf_ok
    return isinstance(proof, dict) and _leaf_ok(root, proof.get("size"), rid, proof)


def validate_revocation_staleness(p: Any) -> None:
    """Raises ``TypeError`` on a malformed staleness policy (a configuration error, raised at construction, never at request time)."""
    from .revocation_staleness import RevocationStaleness
    try:
        if isinstance(p, RevocationStaleness):
            RevocationStaleness(max_revocation_age_ms=p.max_revocation_age_ms, staleness=p.staleness)
        else:
            m = p if isinstance(p, dict) else {}
            if "maxRevocationAgeMs" in m and m["maxRevocationAgeMs"] is None:  # null is not undefined: the reference refuses it
                raise ValueError("maxRevocationAgeMs must be a positive finite number")
            RevocationStaleness(max_revocation_age_ms=m.get("maxRevocationAgeMs"), staleness=m.get("staleness"))
    except ValueError as e:
        raise TypeError(str(e)) from None


def named_unmet_limit_reason(predicates: Any, ctx: Any) -> Optional[str]:
    """Denial wording naming the unmet limit, or None when none is in scope."""
    try:
        from .predicates import _first_unmet_limit
        from .safe_regex import with_regex_budget
        limit = with_regex_budget(lambda: _first_unmet_limit(predicates, ctx))
        a = ctx.get("action") if isinstance(ctx, dict) else None
        if limit is None:
            return None
        return "%s not satisfied for %s on %s" % (limit, (a or {}).get("verb"), (a or {}).get("resource"))
    except Exception:  # noqa: BLE001
        return None


def agent_caveat_context(base: dict, action: dict) -> dict:
    """Extend a stock caveat context with the action and the derived tool call so ``predicates`` / ``tool_schema`` caveats can be evaluated:
    ``{**base, "action": action, "toolCall": {"tool", "args", "toolSignatureDigest"?}}``. The derived fields are applied LAST: a caller-supplied
    context can never substitute a different action or tool call. ``args`` is the action's params when that is a plain object, else ``{}``."""
    a = action.get("action") if isinstance(action, dict) else None
    verb = a.get("verb") if isinstance(a, dict) else None
    params = a.get("params") if isinstance(a, dict) else None
    tool_call = {"tool": verb if isinstance(verb, str) else "", "args": params if isinstance(params, dict) else {}}
    if isinstance(action, dict) and isinstance(action.get("toolBinding"), str):
        tool_call["toolSignatureDigest"] = action["toolBinding"]
    return dict(base, action=action, toolCall=tool_call)


# ---- obligations -----------------------------------------------------------------------------------------------------------

def collect_obligations(rules: Any, ctx: dict) -> dict:
    """Policy-side collection: the obligations of every rule whose ``when`` is true OR cannot be decided (a missing value adds duties: the
    tightening direction). A malformed rule or obligation list is a refusal: ``{"ok": True, "obligations"}`` or ``{"ok": False, "reason"}``."""
    try:
        if rules is None:
            return {"ok": True, "obligations": []}
        if not isinstance(rules, list):
            return {"ok": False, "reason": "obligation rules must be an array"}
        lists: List[Any] = []
        ids = set()
        for i, r in enumerate(rules):
            if not isinstance(r, dict) or not isinstance(r.get("id"), str) or not 0 < len(r["id"]) <= 64 or not isinstance(r.get("when"), dict) \
                    or any(k not in ("id", "when", "obligations") for k in r):
                return {"ok": False, "reason": "obligation rule %d is malformed" % i}
            if r["id"] in ids:
                return {"ok": False, "reason": "obligation rule id '%s' is a duplicate" % r["id"]}
            ids.add(r["id"])
            e = obligations_error(r.get("obligations"))
            if e or not isinstance(r.get("obligations"), list) or len(r["obligations"]) == 0:
                return {"ok": False, "reason": "obligation rule '%s': %s" % (r["id"], e or "obligations must not be empty")}
            if evaluate_condition_tri(r["when"], ctx) != "false":
                lists.append(r["obligations"])
        return merge_obligations(*lists)
    except Exception:  # noqa: BLE001
        return {"ok": False, "reason": "evaluation error (fail closed)"}


# ---- detector receipts: the policy and the tighten-only fold ---------------------------------------------------------------

def detector_policy_error(p: Any) -> Optional[str]:
    """None when well-formed."""
    if not isinstance(p, dict) or _closed_members(p, ["detectors"]) is not None:
        return "policy must be {detectors}"
    if not isinstance(p.get("detectors"), list) or len(p["detectors"]) > 16:
        return "detectors must hold at most 16 entries"
    ids = set()
    for d in p["detectors"]:
        if not isinstance(d, dict) or _closed_members(d, ["id", "keys", "on_suspicious", "max_age_ms"], ["categories"]) is not None:
            return "detector entry is malformed"
        if not isinstance(d["id"], str) or not _ID_RE.fullmatch(d["id"]) or d["id"] == "invalid" or d["id"] in ids:
            return 'detector ids must be distinct ids other than "invalid"'
        ids.add(d["id"])
        k = d["keys"]
        if not isinstance(k, list) or not 1 <= len(k) <= 8 or not all(isinstance(x, dict) and isinstance(x.get("pk"), str)
                                                                      and ("pq_pk" not in x or isinstance(x["pq_pk"], str)) for x in k):
            return "detector '%s': keys must hold 1..8 pins" % d["id"]
        if d["on_suspicious"] not in ("escalate", "deny"):
            return "detector '%s': on_suspicious must be escalate or deny" % d["id"]
        c = d.get("categories")
        if "categories" in d and not (isinstance(c, list) and len(c) >= 1 and all(isinstance(x, str) and _ID_RE.fullmatch(x) for x in c)):
            return "detector '%s': categories must be 1+ ids" % d["id"]
        if not (_is_safe_int(d["max_age_ms"]) and 1 <= d["max_age_ms"] <= 86_400_000):
            return "detector '%s': max_age_ms must be 1..86400000" % d["id"]
    return None


_RANK = {"ok": 2, "escalate": 1, "deny": 0}


def _receipt_problem(r: Any, policy: dict, digests: Sequence[str], session: Optional[str], now: int) -> Optional[str]:
    se = detector_receipt_shape_error(r)
    if se:
        return "malformed: %s" % se
    d = next((x for x in policy["detectors"] if x["id"] == r["detector"]), None)
    if d is None:
        return "undeclared detector '%s'" % r["detector"]
    if not any(verify_artifact_sig(DETECTOR_RECEIPT_DOMAIN, r, k) for k in d["keys"]):
        return "detector '%s': no pinned key signed it" % d["id"]
    if r["input_digest"] not in digests:
        return "detector '%s': the receipt is about other content" % d["id"]
    if "session" in r and r["session"] != session:
        return "detector '%s': bound to another session" % d["id"]
    if r["iat"] > now:
        return "detector '%s': from the future" % d["id"]
    if now - r["iat"] > d["max_age_ms"]:
        return "detector '%s': stale" % d["id"]
    return None


def detector_signal(policy: Any, now: Any, receipts: Any = None, input_digests: Any = None, session: Optional[str] = None) -> Dict[str, Any]:
    """The tighten-only fold of detector receipts. Total. A malformed policy is ``deny``. For each receipt: shape, declared detector, a pinned
    key's signature, content in `input_digests`, session, ``iat <= now`` and age. A valid ``suspicious`` with an acting category lowers the signal
    to the detector's ``on_suspicious``; a valid ``no_finding`` does nothing; an invalid receipt lowers it to ``escalate``. Returns
    ``{"signal", "env": {"detect": ...}, "flagged", "rejected"}``."""
    flagged: set = set()
    rejected: List[dict] = []
    signal = "ok"
    env: Dict[str, Any] = {}

    def lower(s: str) -> None:
        nonlocal signal
        if _RANK[s] < _RANK[signal]:
            signal = s
    try:
        pe = detector_policy_error(policy)
        if pe:
            return {"signal": "deny", "env": {"detect": {"invalid": 0}}, "flagged": [], "rejected": [{"index": -1, "reason": "policy: %s" % pe}]}
        for d in policy["detectors"]:
            env[d["id"]] = False
        rs = [] if receipts is None else receipts
        digests = input_digests if isinstance(input_digests, list) else []
        if not isinstance(rs, list) or len(rs) > MAX_DETECTOR_RECEIPTS or not _is_safe_int(now):
            lower("escalate")
            rejected.append({"index": -1, "reason": "receipt list or clock malformed"})
        else:
            for index, r in enumerate(rs):
                why = _receipt_problem(r, policy, digests, session, now)
                if why:
                    rejected.append({"index": index, "reason": why})
                    lower("escalate")
                    continue
                if r["verdict"] != "suspicious":
                    continue
                d = next(x for x in policy["detectors"] if x["id"] == r["detector"])
                if d.get("categories") is not None and len(r["categories"]) > 0 and not any(c in d["categories"] for c in r["categories"]):
                    continue
                flagged.add(d["id"])
                env[d["id"]] = True
                lower(d["on_suspicious"])
    except Exception as e:  # noqa: BLE001
        lower("deny")
        rejected.append({"index": -1, "reason": "evaluation error (fail closed): %s" % (str(e) or "unknown")})
    env["invalid"] = len(rejected)
    return {"signal": signal, "env": {"detect": env}, "flagged": sorted(flagged), "rejected": rejected}


# ---- cheap claims ----------------------------------------------------------------------------------------------------------

def pcactn_cheap_claims(p: dict, audience: str, now: Any) -> Optional[Dict[str, str]]:
    """The pre-signature ``aud`` / ``iat`` / ``exp`` check of a PCActn: None when it passes, else ``{"check": "audience" | "validity", "reason"}``."""
    if not isinstance(p.get("aud"), str) or len(p["aud"]) == 0 or p["aud"] != audience:
        return {"check": "audience", "reason": "aud does not match this resource server / instance"}
    if not _is_safe_int(p.get("iat")) or not _is_safe_int(p.get("exp")):
        return {"check": "validity", "reason": "iat and exp must be safe-integer epoch ms"}
    if not _is_safe_int(now):
        return {"check": "validity", "reason": "the verifier clock is not a safe integer epoch-ms"}
    if not p["exp"] > p["iat"]:
        return {"check": "validity", "reason": "exp must be greater than iat"}
    if p["exp"] - p["iat"] > MAX_LIFETIME_MS:
        return {"check": "validity", "reason": "lifetime exceeds %d ms" % MAX_LIFETIME_MS}
    if p["iat"] > now + MAX_SKEW_MS:
        return {"check": "validity", "reason": "iat is in the future (clock skew)"}
    if now > p["exp"]:
        return {"check": "validity", "reason": "the PCActn has expired"}
    return None


def catalog_risk(verb: Any, params: Any, grant: Any, catalog: Any = None, taint: Any = None) -> Dict[str, Any]:
    """The server-side risk inputs a catalogued verb implies: ``{"reversibility", "blastRadius", "confidence"[, "taint"]}`` from the catalog spec (an
    action with an ``amountField`` is scaled by the grant's envelope ``kappa``: a missing, negative or non-numeric amount or no ``kappa`` is the full
    blast radius), or ``{}`` for an uncatalogued verb. ``taint`` (a finite number, clamped to [0, 1]) is passed through when given. Total."""
    from .authorize import read_envelope
    from .catalog import DEFAULT_CATALOG

    def unit(x: Any) -> float:
        return min(1, max(0, x))

    def num(x: Any) -> bool:
        return not isinstance(x, bool) and isinstance(x, (int, float)) and fin(x)
    spec = (catalog if catalog is not None else DEFAULT_CATALOG).get(verb)
    if not spec:
        return {}
    rev_name = spec.get("reversibility")
    reversibility = CATALOG_REVERSIBILITY_SCORE[rev_name] if isinstance(rev_name, str) and rev_name in CATALOG_REVERSIBILITY_SCORE else 0
    blast = unit(spec["blastRadius"])
    if spec.get("amountField") is not None:
        field = spec["amountField"]
        amount = params[field] if isinstance(params, dict) and field in params else None
        env = read_envelope(grant)
        kappa = env["risk_policy"].get("kappa") if env is not None and isinstance(env.get("risk_policy"), dict) else None
        blast = unit(amount / kappa) if num(amount) and amount >= 0 and num(kappa) and kappa > 0 else 1
    out: Dict[str, Any] = {"reversibility": reversibility, "blastRadius": blast, "confidence": 1}
    if num(taint):
        out["taint"] = unit(taint)
    return out
