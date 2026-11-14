"""More producer-side signers: the artifacts an agent, a principal, a guardian, a site or a resource server signs beyond the
grant and the PCActn (`atlas_pca.agent`). Same wire as the TypeScript reference, byte for byte for Ed25519 and for the
deterministic PQ suites. Every signer runs the reference's checks before signing and raises on a malformed body (fail closed).

    from atlas_pca.signers_more import sign_threshold_share, sign_pq_binding, sign_caution, sign_revocation_epoch

Suites: the functions that take `alg` / `pq` sign under any suite this runtime can sign (`atlas_pca.agent.sign_with_suite`);
a suite it cannot sign raises `UnsupportedSuite` ("unsupported_suite: <alg>").
"""
import json
import math
import re
from typing import Any, Dict, List, Optional, Sequence

from .agent import (DEFAULT_RISK_POLICY, KeyPair, PqKeyPair, _bind_suite, _clone, _sign_body, goal_commit_of, mint_root,
                    sign_artifact, sign_with_suite)
from .intent_v2 import (ACTION_SCHEMA_DOMAIN, INTENT_SESSION_SIG_DOMAIN, _epoch_message, action_schema_shape_error,
                        session_root_shape_error)
from .intent_wb import FACT_DOMAIN, LABELS_DOMAIN, OFFER_SET_DOMAIN
from .mesh import MESH_ACTION_DOMAIN, _msg as _mesh_msg
from .pca import (INTENT_GOAL_V2_PREFIX, INTENT_GOAL_V2C_PREFIX, MAP_FORM_COMMIT, PQ_PK_LENGTHS, _SIG_SUITES, _b32, b64u,
                  canonical_bytes, canonical_bytes_strict, cap_hash, decode_b64u_strict, hash_canonical,
                  intent_session_caveat_error, share_message, signer_set_hash)
from .policy_link import (TEMPLATE_SIG_DOMAIN, TIGHTEN_SIG_DOMAIN, _message as _policy_message, template_def_error,
                          template_digest, tighten_overlay_error)
from .readside import READ_RECEIPT_DOMAIN, read_grant_digest, read_receipt_ref

__all__ = [
    "sign_threshold_share", "sign_prepared_share", "sign_pq_binding", "pq_pin_for", "sign_caution", "sign_heartbeat",
    "sign_read_receipt", "sign_mesh_action", "assemble_mesh_proof", "sign_session_root", "mint_session_grant",
    "sign_action_schema", "action_schema_key_of", "sign_labels", "sign_fact", "sign_offer_set", "sign_template", "sign_tighten",
    "sign_revocation_epoch", "MAX_CAUTION_REASON_LEN", "sign_intent_required", "intent_required_shape_error",
    "INTENT_REQUIRED_DOMAIN", "sign_progress_step", "PROGRESS_SIG_DOMAIN",
]

_MAX_SAFE = 9007199254740991


def _is_safe_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and -_MAX_SAFE <= v <= _MAX_SAFE


def _alg_of(alg: Optional[str]) -> str:
    return alg or "ed25519"


# ---- threshold shares (threshold.ts signShare / signPreparedShare) ----------------------------------------------------------

def sign_prepared_share(role: str, key: KeyPair, prepared: bytes, alg: Optional[str] = None,
                        pq: Optional[PqKeyPair] = None) -> Dict[str, str]:
    """Sign already-computed share bytes (the `share_message` a step-up hands a principal device). Ed25519 gives
    {role, publicKey, sig}, byte-identical to the pre-agility share; another suite adds `alg` (and `pq_sig` for a hybrid).
    The role's PQ public key is registered in the signer set, not carried in the share."""
    parts = sign_with_suite(alg, key, pq, prepared)
    share = {"role": role, "publicKey": key.public, "sig": parts["sig"]}
    if _alg_of(alg) != "ed25519":
        share["alg"] = alg
        if "pq_sig" in parts:
            share["pq_sig"] = parts["pq_sig"]
    return share


def sign_threshold_share(role: str, key: KeyPair, message: bytes, signer_set: Sequence[dict], t: int,
                         alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> Dict[str, str]:
    """A role's EXPLICIT threshold share (agent, guardian or principal) over the v2.1 bound share message
    `"atlas-pca/share/<role>\\0" || sha256(message) || signerSetHash || t [|| suite tag]` (`message` is the PCActn's threshold
    message). The share can only be replayed into the same signer set and threshold."""
    if isinstance(t, bool) or t not in (1, 2, 3):
        raise ValueError("sign_threshold_share: t must be 1, 2 or 3")
    ssh = signer_set_hash(list(signer_set) if isinstance(signer_set, (list, tuple)) else signer_set)
    if ssh is None:
        raise ValueError("sign_threshold_share: malformed signer set")
    return sign_prepared_share(role, key, share_message(role, message, ssh, t, alg), alg, pq)


# ---- PQ key binding (pq.ts signPqBinding / pqPinFor) ------------------------------------------------------------------------

PQ_BIND_DOMAIN = b"atlas-pca/pq-binding/v2\x00"


def _pq_binding_message(ed: str, pq: str, epoch: int, aud: str) -> bytes:
    return PQ_BIND_DOMAIN + ("%s\x00%s\x00%d\x00%s" % (ed, pq, epoch, aud)).encode("utf-8")


def sign_pq_binding(key: KeyPair, pq_public: str, epoch: int, aud: str) -> Dict[str, Any]:
    """An identity's signed statement "this PQ key is mine, as of `epoch`, for audience `aud`" (an Ed25519 signature over
    the domain, the identity, the PQ key, the epoch and the audience). `epoch` grows on every rotation (>= 1)."""
    if not _is_safe_int(epoch) or epoch < 1:
        raise ValueError("sign_pq_binding: epoch must be a positive safe integer")
    if not isinstance(aud, str) or not aud:
        raise ValueError("sign_pq_binding: aud (the instance/audience id) is required")
    return {"ed": key.public, "pq": pq_public, "epoch": epoch, "aud": aud,
            "sig": b64u(key.sign(_pq_binding_message(key.public, pq_public, epoch, aud)))}


def pq_pin_for(binding: Any, aud: str) -> Optional[Dict[str, str]]:
    """The one-entry PQ pin `{ed: pq}` of a binding that verifies for `aud`, else None. Never raises."""
    from .pca import _verify_b64u
    try:
        if not isinstance(binding, dict) or not isinstance(binding.get("ed"), str) or not isinstance(binding.get("sig"), str):
            return None
        if not isinstance(aud, str) or not aud or binding.get("aud") != aud:
            return None
        if not _is_safe_int(binding.get("epoch")) or binding["epoch"] < 1:
            return None
        pk = decode_b64u_strict(binding.get("pq"))
        if pk is None or len(pk) not in PQ_PK_LENGTHS:
            return None
        msg = _pq_binding_message(binding["ed"], binding["pq"], binding["epoch"], binding["aud"])
        return {binding["ed"]: binding["pq"]} if _verify_b64u(binding["ed"], msg, binding["sig"]) else None
    except Exception:  # noqa: BLE001 - total
        return None


# ---- agent-native: caution, lease heartbeat ---------------------------------------------------------------------------------

MAX_CAUTION_REASON_LEN = 64
_REASON_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-")


def _msg_of(domain: str, body: Any) -> bytes:
    return canonical_bytes({"d": domain, "b": body})


def _caution_body_error(b: Any) -> Optional[str]:
    if not isinstance(b, dict):
        return "not an object"
    if not isinstance(b.get("action_digest"), str) or not b["action_digest"]:
        return "action_digest required"
    if not isinstance(b.get("holder"), str) or not b["holder"]:
        return "holder required"
    c = b.get("caution")
    if isinstance(c, bool) or not isinstance(c, (int, float)) or not math.isfinite(c) or c < 0 or c > 1:
        return "caution must be a finite number in [0,1]"
    if "reason" in b:
        r = b["reason"]
        if not isinstance(r, str) or not r or len(r) > MAX_CAUTION_REASON_LEN or not set(r) <= _REASON_CHARS:
            return "invalid reason"
    return None


def sign_caution(body: Dict[str, Any], holder: KeyPair) -> Dict[str, Any]:
    """The holder's signed caution claim about an action ({action_digest, caution in [0,1], reason?, holder}). Raises on an
    invalid body (NaN or out-of-range caution, a bad reason)."""
    err = _caution_body_error(body)
    if err:
        raise ValueError("sign_caution: " + err)
    clean: Dict[str, Any] = {"action_digest": body["action_digest"], "caution": body["caution"], "holder": body["holder"]}
    if "reason" in body:
        clean["reason"] = body["reason"]
    out = dict(clean)
    out["sig"] = b64u(holder.sign(_msg_of("atlas-pca/caution/v1", clean)))
    return out


PROGRESS_SIG_DOMAIN = "atlas-pca/progress-step/v2"


def sign_progress_step(step: Dict[str, Any], holder: KeyPair) -> Dict[str, Any]:
    """The holder's signed progress step {step, holder, sig}: Ed25519 over the domain-separated binding of the step to the
    holder, goal, action, before/after state, sequence, chain link and step digest (progress.ts signProgressStep)."""
    msg = _msg_of(PROGRESS_SIG_DOMAIN, {
        "holder": holder.public, "goal_commitment": step["goal_commitment"], "action_digest": step["action_digest"],
        "before_digest": step["before_digest"], "after_digest": step["after_digest"], "seq": step["seq"], "prev": step["prev"],
        "step_digest": step["digest"]})
    return {"step": step, "holder": holder.public, "sig": b64u(holder.sign(msg))}


def sign_heartbeat(body: Dict[str, Any], holder: KeyPair) -> Dict[str, Any]:
    """The lease holder's signed liveness proof ({cap_id, seq, at, holder, lease_issued_at})."""
    clean = {"cap_id": body["cap_id"], "seq": body["seq"], "at": body["at"], "holder": body["holder"],
             "lease_issued_at": body["lease_issued_at"]}
    out = dict(clean)
    out["sig"] = b64u(holder.sign(_msg_of("atlas-pca/lease-hb/v2", clean)))
    return out


# ---- read receipt (readside.ts signReadReceipt, resource-server side) -------------------------------------------------------

def sign_read_receipt(rs: KeyPair, grant: dict, verb: str, resource: str, purpose: str, fields: Dict[str, Any],
                      labels: List[str], issued_at: int, prev: Optional[dict] = None) -> Dict[str, Any]:
    """The resource server's signed receipt for a read under `grant` (the read grant BODY); `prev` is the previous receipt."""
    base = {"v": 1, "grant": read_grant_digest(grant), "verb": verb, "resource": resource, "purpose": purpose,
            "seq": prev["seq"] + 1 if prev else 0, "prev": read_receipt_ref(prev) if prev else None, "fields": fields,
            "labels": labels, "issued_at": issued_at, "signer": rs.public}
    out = dict(base)
    out["sig"] = _sign_body(rs, READ_RECEIPT_DOMAIN, base)
    return out


# ---- cross-domain mesh (mesh.ts signMeshAction / assembleMeshProof) ---------------------------------------------------------

def sign_mesh_action(chain: Sequence[dict], action: dict, leaf: KeyPair) -> str:
    """The leaf holder's signature over {action, tip = capHash(last hop)}."""
    tip = cap_hash(chain[-1])
    return b64u(leaf.sign(_mesh_msg(MESH_ACTION_DOMAIN, {"action": action, "tip": tip})))


def _js_key(v: Any) -> str:
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


def assemble_mesh_proof(chain: Sequence[dict], hops: Sequence[dict], action: dict, leaf: KeyPair,
                        pin_proofs: Optional[Sequence[dict]] = None) -> Dict[str, Any]:
    """A compact mesh proof: hops issued against the same head share one table entry (their cosignatures merged by
    witness), identical revocation bracketing leaves are carried once, and the leaf holder signs the action."""
    heads: List[dict] = []
    head_idx: Dict[str, int] = {}
    leaves: List[dict] = []
    leaf_idx: Dict[str, int] = {}

    def leaf_of(lp: dict) -> int:
        k = _js_key(lp)
        if k not in leaf_idx:
            leaf_idx[k] = len(leaves)
            leaves.append(lp)
        return leaf_idx[k]

    def compact(n: dict) -> dict:
        out: Dict[str, Any] = {"size": n["size"]}
        if n.get("lo"):
            out["lo"] = leaf_of(n["lo"])
        if n.get("hi"):
            out["hi"] = leaf_of(n["hi"])
        return out

    out_hops = []
    for ev in hops:
        h = ev["head"]
        k = "%s|%s" % (h["sig"], _js_key(h["head"]))
        if k not in head_idx:
            head_idx[k] = len(heads)
            heads.append({"head": h["head"], "sig": h["sig"], "cosigs": list(h["cosigs"])})
        else:
            entry = heads[head_idx[k]]
            have = {c["witness"] for c in entry["cosigs"]}
            for c in h["cosigs"]:
                if c["witness"] not in have:
                    entry["cosigs"].append(c)
        o: Dict[str, Any] = {"domain": ev["domain"], "head": head_idx[k], "inclusion": ev["inclusion"],
                             "revocation": {"cap": compact(ev["revocation"]["cap"]),
                                            "issuer_key": compact(ev["revocation"]["issuer_key"])}}
        if ev.get("binding"):
            o["binding"] = ev["binding"]
        out_hops.append(o)
    proof: Dict[str, Any] = {"chain": list(chain), "heads": heads, "rev_leaves": leaves, "hops": out_hops, "action": action,
                             "action_sig": sign_mesh_action(chain, action, leaf)}
    if pin_proofs:
        proof["pin_proofs"] = list(pin_proofs)
    return proof


# ---- Intent v2 session root and session grant (intent-session.ts) -----------------------------------------------------------

_ROOT_MEMBERS = ("v", "kind", "session", "principals", "intent_ref", "schema", "layers", "accumulators", "monitors",
                 "question_uri")


def sign_session_root(body: Dict[str, Any], principal: KeyPair, alg: Optional[str] = None,
                      pq: Optional[PqKeyPair] = None) -> Dict[str, Any]:
    """Sign the session root S as one of its principals (the signer's Ed25519 key must be listed in `principals`)."""
    bad = session_root_shape_error(body, signed=False)
    if bad:
        raise ValueError("sign_session_root: " + bad)
    if not any(isinstance(p, dict) and p.get("key") == principal.public for p in body["principals"]):
        raise ValueError("sign_session_root: the signer is not one of the session principals")
    base: Dict[str, Any] = {k: body[k] for k in _ROOT_MEMBERS}
    for k in ("revocation", "flows"):
        if k in body:
            base[k] = body[k]
    base["expires_at"] = body["expires_at"]
    base["signer"] = principal.public
    return sign_artifact(INTENT_SESSION_SIG_DOMAIN, base, principal, alg, pq)


def mint_session_grant(principal: KeyPair, holder: str, session: str, seq: int, root: str, map_digest: str,
                       predicates: list, prev: Optional[str] = None, map_form: Optional[str] = None,
                       caveats: Optional[list] = None, agent_binding: Optional[dict] = None,
                       risk_policy: Optional[dict] = None, salt: Optional[str] = None, holder_pq: Optional[str] = None,
                       alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> Dict[str, Any]:
    """G_0 (seq 0) or a delta grant D_k: a principal-signed root capability whose caveats are the envelope (goal
    `pca-intent:v2:<session>:<map_digest>`, or `v2c` over a committed map) and the `intent_session` caveat. Returns
    {"grant", "goal_salt"} (the salt goes in the PCActn's `intent.goal_salt`)."""
    import os
    sc: Dict[str, Any] = {"type": "intent_session", "session": session, "seq": seq, "root": root}
    if prev is not None:
        sc["prev"] = prev
    bad = intent_session_caveat_error(sc)
    if bad:
        raise ValueError("mint_session_grant: " + bad)
    if not _b32(map_digest):
        raise ValueError("mint_session_grant: map_digest must be canonical base64url (32 bytes)")
    goal_salt = salt if salt is not None else b64u(os.urandom(16))
    goal = (INTENT_GOAL_V2C_PREFIX if map_form == MAP_FORM_COMMIT else INTENT_GOAL_V2_PREFIX) + session + ":" + map_digest
    envelope = _clone({"type": "envelope", "goal_commit": goal_commit_of(goal, goal_salt), "predicates": predicates,
                       "caveats": caveats if caveats is not None else [],
                       "agent_binding": agent_binding if agent_binding is not None else {},
                       "risk_policy": risk_policy if risk_policy is not None else DEFAULT_RISK_POLICY})
    grant = mint_root(principal, holder, [envelope, sc], holder_pq, alg, pq)
    return {"grant": grant, "goal_salt": goal_salt}


# ---- site-signed documents: action schema, labels; oracle facts -------------------------------------------------------------

def _site_sig(alg: Optional[str], kid: str, parts: Dict[str, str]) -> Dict[str, str]:
    sig = {"alg": _alg_of(alg), "kid": kid, "value": parts["sig"]}
    if "pq_sig" in parts:
        sig["pq_value"] = parts["pq_sig"]
    return sig


def sign_action_schema(doc: Dict[str, Any], kid: str, site: KeyPair, alg: Optional[str] = None,
                       pq: Optional[PqKeyPair] = None) -> Dict[str, Any]:
    """Sign an action schema as the site: `sig = {alg, kid, value, pq_value?}` over utf8(domain) || strictCanonical(doc).
    `kid` names the site's discovery key entry (`action_schema_key_of`)."""
    bad = action_schema_shape_error(doc, signed=False)
    if bad:
        raise ValueError("sign_action_schema: " + bad)
    body = {k: v for k, v in doc.items() if k != "sig"}
    parts = sign_with_suite(alg, site, pq, ACTION_SCHEMA_DOMAIN.encode("utf-8") + canonical_bytes_strict(body))
    out = dict(doc)
    out["sig"] = _site_sig(alg, kid, parts)
    return out


# ---- intent_required (intent-required.ts signIntentRequired, site side) -------------------------------------------------------

INTENT_REQUIRED_DOMAIN = "atlas-pca/intent-required/v1\x00"
_IR_KEYS = ("v", "kind", "session", "map_digest", "schema", "pcactn_digest", "action_digest", "cell", "reason", "question_id",
            "friction", "delivered_to", "expires_at", "sig")
_QUESTION_ID = re.compile(r"[A-Za-z0-9_-]{1,64}", re.ASCII)


def _cell_coords_error(c: Any) -> Optional[str]:
    if not isinstance(c, dict) or not 1 <= len(c) <= 64:
        return "coords must be an object of 1..64 dimensions"
    for k, v in c.items():
        if not 1 <= len(k.encode("utf-16-le")) // 2 <= 256:
            return "a coordinate path must be 1..256 characters"
        if isinstance(v, list) and len(v) == 2 and all(_is_safe_int(x) for x in v):
            if not 0 <= v[0] <= v[1]:
                return "coords '%s': need 0 <= lo <= hi" % k
        elif isinstance(v, list) and 1 <= len(v) <= 256 and all(isinstance(x, str) for x in v):
            if len(set(v)) != len(v):
                return "coords '%s': values must be distinct" % k
        else:
            return "coords '%s': an index range [lo, hi] or a value set" % k
    return None


def intent_required_shape_error(b: Any) -> Optional[str]:
    """The reference's shape check of an UNSIGNED `pca-intent-required` v1 body (the signer's pre-check)."""
    if not isinstance(b, dict):
        return "not an object"
    for k in b:
        if k not in _IR_KEYS:
            return "unknown member '%s'" % k
    if b.get("v") != 1 or isinstance(b.get("v"), bool) or b.get("kind") != "pca-intent-required":
        return "not a pca-intent-required v1"
    for k in ("session", "map_digest", "schema", "pcactn_digest", "action_digest"):
        if not _b32(b.get(k)):
            return "%s must be canonical base64url (32 bytes)" % k
    cell = b.get("cell")
    if not isinstance(cell, dict) or sorted(cell) != ["coords", "verb"] or not isinstance(cell["verb"], str) or not cell["verb"]:
        return "cell must be {verb, coords}"
    ce = _cell_coords_error(cell["coords"])
    if ce:
        return ce
    if b.get("reason") != "uncertain":
        return "reason must be 'uncertain'"
    if not isinstance(b.get("question_id"), str) or not _QUESTION_ID.fullmatch(b["question_id"]):
        return "question_id must match [A-Za-z0-9_-]{1,64}"
    if b.get("friction") not in ("tap", "hold", "typed", "device"):
        return "unknown friction tier"
    if b.get("delivered_to") not in ("wallet", "agent"):
        return "delivered_to must be 'wallet' or 'agent'"
    if not (_is_safe_int(b.get("expires_at")) and b["expires_at"] >= 0):
        return "expires_at must be a non-negative safe integer"
    if "sig" in b:
        return "an unsigned body must not carry sig"
    return None


def sign_intent_required(body: Dict[str, Any], kid: str, site: KeyPair, alg: Optional[str] = None,
                         pq: Optional[PqKeyPair] = None) -> Dict[str, Any]:
    """The site's signed `pca-intent-required` v1 body: `sig = {alg, kid, value, pq_value?}` over
    utf8(domain) || strictCanonical(body), pinned by the same discovery key entry as the action schema."""
    bad = intent_required_shape_error(body)
    if bad:
        raise ValueError("sign_intent_required: " + bad)
    parts = sign_with_suite(alg, site, pq, INTENT_REQUIRED_DOMAIN.encode("utf-8") + canonical_bytes_strict(body))
    out = dict(body)
    out["sig"] = _site_sig(alg, kid, parts)
    return out


def action_schema_key_of(kid: str, site: KeyPair, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> Dict[str, str]:
    """The discovery key entry {kid, alg, pk, pq_pk?} a verifier pins for a site signer."""
    a = _alg_of(alg)
    if a not in _SIG_SUITES:
        raise ValueError("unknown signature alg %r" % (a,))
    k = {"kid": kid, "alg": a, "pk": site.public}
    if a != "ed25519" and pq is not None:
        k["pq_pk"] = pq.public
    return k


def sign_labels(body: Dict[str, Any], key: KeyPair, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> Dict[str, Any]:
    """A site's signed label receipt (`pca-labels` v1)."""
    full: Dict[str, Any] = {"v": 1, "kind": "pca-labels"}
    full.update(body)
    return sign_artifact(LABELS_DOMAIN, full, key, alg, pq)


def sign_fact(body: Dict[str, Any], key: KeyPair, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> Dict[str, Any]:
    """An oracle's signed fact (`pca-fact` v1)."""
    full: Dict[str, Any] = {"v": 1, "kind": "pca-fact"}
    full.update(body)
    return sign_artifact(FACT_DOMAIN, full, key, alg, pq)


def sign_offer_set(body: Dict[str, Any], key: KeyPair, alg: Optional[str] = None, pq: Optional[PqKeyPair] = None) -> Dict[str, Any]:
    """A site's signed offer set (`pca-offer-set` v1; the body carries its own v / kind)."""
    return sign_artifact(OFFER_SET_DOMAIN, body, key, alg, pq)


# ---- linked policy templates (policy-link.ts signTemplate / signTighten) ----------------------------------------------------

def sign_template(definition: Dict[str, Any], key: KeyPair) -> Dict[str, Any]:
    """The principal's signed policy template {def, signer, sig}."""
    e = template_def_error(definition)
    if e:
        raise ValueError("sign_template: " + e)
    return {"def": definition, "signer": key.public,
            "sig": b64u(key.sign(_policy_message(TEMPLATE_SIG_DOMAIN, template_digest(definition))))}


def sign_tighten(overlay: Dict[str, Any], key: KeyPair) -> Dict[str, Any]:
    """The principal's signed tighten overlay {overlay, signer, sig} (it can only add where conditions and caveats)."""
    e = tighten_overlay_error(overlay)
    if e:
        raise ValueError("sign_tighten: " + e)
    return {"overlay": overlay, "signer": key.public,
            "sig": b64u(key.sign(_policy_message(TIGHTEN_SIG_DOMAIN, hash_canonical(overlay))))}


# ---- revocation epoch (revocation.ts signRevocationEpoch, guardian side) ----------------------------------------------------

_EPOCH_FIELDS = ("instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after")


def sign_revocation_epoch(guardian: KeyPair, body: Dict[str, Any], alg: Optional[str] = None,
                          pq: Optional[PqKeyPair] = None) -> Dict[str, Any]:
    """The guardian's signed revocation epoch over {instance_id, grant_ref, epoch, set_size, root, issued_at, not_after}; a
    non-ed25519 suite binds `alg` and `pq_pk` into the signed bytes."""
    fields = {k: body[k] for k in _EPOCH_FIELDS}
    annotated = _bind_suite(fields, alg, pq)
    parts = sign_with_suite(alg, guardian, pq, _epoch_message(annotated))
    out = dict(fields)
    out["guardian"] = guardian.public
    out["sig"] = parts["sig"]
    if _alg_of(alg) != "ed25519":
        out["alg"], out["pq_pk"] = alg, pq.public
        if "pq_sig" in parts:
            out["pq_sig"] = parts["pq_sig"]
    return out
