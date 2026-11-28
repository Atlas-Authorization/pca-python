"""Key rotation and subtree revocation for capability chains (the TypeScript reference, @atlasauth/pca-rotate).

A chain binds authority to keys, so rotating or losing a key means re-issuing what it carried under a fresh key and naming the old
one in a revocation record a registry can act on. Re-issue uses the real builders (:func:`atlas_pca.agent.mint_root` /
:func:`atlas_pca.agent.delegate`) and carries exactly the caveats each replaced hop carried, so a re-issue can never widen
authority. Keys are :class:`atlas_pca.agent.KeyPair`; chains and revocation records are plain JSON-shaped dicts."""
from __future__ import annotations

from ._fin import fin
import time
from typing import Any, Dict, List, Optional, Sequence

from .agent import KeyPair, delegate, mint_root


def _now_ms() -> int:
    return int(time.time() * 1000)


def _pub(secret: Any) -> str:
    if not isinstance(secret, KeyPair):
        raise TypeError("expected a KeyPair secret key")
    return secret.public


def _at(chain: Sequence[Any], i: int, ctx: str) -> Dict[str, Any]:
    if not 0 <= i < len(chain):
        raise IndexError("%s: no capability at index %d (chain length %d)" % (ctx, i, len(chain)))
    c = chain[i]
    if not isinstance(c, dict):
        raise TypeError("%s: a chain hop is not an object" % ctx)
    return c


def _appended_caveats(parent: Dict[str, Any], child: Dict[str, Any]) -> list:
    """The caveats a child appended beyond its parent (caveats are append-only, so re-delegating with this slice reproduces it)."""
    pc, cc = parent.get("caveats"), child.get("caveats")
    if not isinstance(cc, list) or not isinstance(pc, list):
        raise TypeError("malformed capability: caveats must be arrays")
    if len(cc) < len(pc):
        raise ValueError("malformed chain: a child carries fewer caveats than its parent (not an attenuation)")
    return cc[len(pc):]


def _check_now(now: Any, ctx: str) -> None:
    if now is not None and (isinstance(now, bool) or not isinstance(now, (int, float)) or not fin(now)):
        raise TypeError("%s: now must be a finite number" % ctx)


def _require_non_empty(chain: Any, ctx: str) -> None:
    if not isinstance(chain, list) or len(chain) == 0:
        raise ValueError("%s: empty chain" % ctx)


def rotate_agent_key(chain: Any, old_holder_secret: KeyPair, new_key_pair: KeyPair, reason: Optional[str] = None,
                     now: Optional[float] = None) -> Dict[str, Any]:
    """Rotate the AGENT (leaf holder) key: the leaf's parent re-signs the leaf, re-binding it to ``new_key_pair`` with the leaf's
    exact caveats. ``old_holder_secret`` must be the leaf's issuer (the parent's holder); a root-only chain has no leaf to
    re-issue. Returns ``{"chain", "revocation"}``."""
    _require_non_empty(chain, "rotateAgentKey")
    if len(chain) < 2:
        raise ValueError("rotateAgentKey: a root-only chain has no leaf delegation to re-issue; use rotatePrincipalKey")
    parent = _at(chain, len(chain) - 2, "rotateAgentKey")
    leaf = _at(chain, len(chain) - 1, "rotateAgentKey")
    signer_pub = _pub(old_holder_secret)
    if signer_pub != leaf.get("issuer"):
        raise ValueError("rotateAgentKey: oldHolderSecret (pub %s) is not the leaf's issuer %s; the leaf is re-signed by its parent holder (the leaf issuer)"
                         % (signer_pub, leaf.get("issuer")))
    if not isinstance(new_key_pair, KeyPair):
        raise TypeError("expected a KeyPair for the new key")
    new_holder = new_key_pair.public
    if new_holder == leaf.get("holder"):
        raise ValueError("rotateAgentKey: newKeyPair is the key being rotated out")
    _check_now(now, "rotateAgentKey")
    new_leaf = delegate(parent, old_holder_secret, new_holder, _appended_caveats(parent, leaf))
    return {
        "chain": list(chain[:-1]) + [new_leaf],
        "revocation": {"capId": leaf.get("id"), "holder": leaf.get("holder"), "issuer": leaf.get("issuer"), "capIds": [leaf.get("id")],
                       "reason": "agent key rotated" if reason is None else reason, "revokedAt": _now_ms() if now is None else now},
    }


def rotate_principal_key(old_principal_secret: KeyPair, new_principal_key_pair: KeyPair, chain: Any = None, old_root: Any = None,
                         holder_secrets: Optional[Sequence[KeyPair]] = None, reason: Optional[str] = None,
                         now: Optional[float] = None) -> Dict[str, Any]:
    """Rotate the PRINCIPAL (root) key by re-rooting: mint a fresh root under ``new_principal_key_pair`` bound to the same holder and
    caveats, then re-issue every downstream hop (``holder_secrets``: each non-root hop's issuer secret, in chain order). Pass the full
    ``chain`` or, for a root-only chain, just ``old_root``. Returns ``{"chain", "revocation"}`` (the whole old chain is revoked)."""
    if chain is None:
        chain = [old_root] if old_root else []
    _require_non_empty(chain, "rotatePrincipalKey")
    old_root = _at(chain, 0, "rotatePrincipalKey")
    if "parent" in old_root:
        raise ValueError("rotatePrincipalKey: chain[0] is not a root (it has a parent)")
    old_pub = _pub(old_principal_secret)
    if old_pub != old_root.get("issuer"):
        raise ValueError("rotatePrincipalKey: oldPrincipalSecret (pub %s) is not the root's issuer %s" % (old_pub, old_root.get("issuer")))
    secrets = [] if holder_secrets is None else holder_secrets
    if len(secrets) != len(chain) - 1:
        raise ValueError("rotatePrincipalKey: expected %d holderSecrets (one per non-root hop), got %d" % (len(chain) - 1, len(secrets)))
    if not isinstance(new_principal_key_pair, KeyPair):
        raise TypeError("expected a KeyPair for the new principal key")
    if new_principal_key_pair.public == old_root.get("issuer"):
        raise ValueError("rotatePrincipalKey: newPrincipalKeyPair is the key being rotated out")
    _check_now(now, "rotatePrincipalKey")
    if not isinstance(old_root, dict) or "holder" not in old_root:  # an undefined holder reaches the canonical encoder
        raise TypeError("canonicalize: unsupported type undefined")
    new_root = mint_root(new_principal_key_pair, old_root.get("holder"), old_root.get("caveats"))
    new_chain: List[Dict[str, Any]] = [new_root]
    for i in range(1, len(chain)):
        old_parent = _at(chain, i - 1, "rotatePrincipalKey")
        old_child = _at(chain, i, "rotatePrincipalKey")
        signer = secrets[i - 1]
        signer_pub = _pub(signer)
        if signer_pub != old_child.get("issuer"):
            raise ValueError("rotatePrincipalKey: holderSecret for hop %d (pub %s) is not that hop's issuer %s" % (i, signer_pub, old_child.get("issuer")))
        if not isinstance(old_child, dict) or "holder" not in old_child:
            raise TypeError("canonicalize: unsupported type undefined")
        new_chain.append(delegate(new_chain[i - 1], signer, old_child.get("holder"), _appended_caveats(old_parent, old_child)))
    return {
        "chain": new_chain,
        "revocation": {"capId": old_root.get("id"), "issuer": old_root.get("issuer"), "holder": old_root.get("holder"),
                       "subtreeRoot": old_root.get("id"), "capIds": [c.get("id") if isinstance(c, dict) else None for c in chain],
                       "reason": "principal key rotated (re-root)" if reason is None else reason, "revokedAt": _now_ms() if now is None else now},
    }


def _index_of_holder(chain: Sequence[Any], holder: Any) -> int:
    for i in range(len(chain)):
        if _at(chain, i, "revokeAndReissueSubtree").get("holder") == holder:
            return i
    return -1


def revoke_and_reissue_subtree(chain: Any, compromised_holder: Any, new_key_pair: KeyPair, ancestor_secret: KeyPair,
                               reason: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """Treat ``compromised_holder`` as COMPROMISED: revoke the hop it first holds and every descendant, and re-issue one delegation
    from the nearest safe ancestor to ``new_key_pair`` carrying the deepest leaf's caveats (never wider). ``ancestor_secret`` is the
    safe ancestor's holder secret. Raises when the holder is not in the chain or is the root holder. Returns ``{"chain", "revocation"}``."""
    _require_non_empty(chain, "revokeAndReissueSubtree")
    idx = _index_of_holder(chain, compromised_holder)
    if idx < 0:
        raise ValueError("revokeAndReissueSubtree: holder %s is not in the chain" % (compromised_holder,))
    if idx == 0:
        raise ValueError("revokeAndReissueSubtree: the compromised holder is the root holder (no safe delegation ancestor); rotate the root with rotatePrincipalKey")
    ancestor = _at(chain, idx - 1, "revokeAndReissueSubtree")
    subtree_root = _at(chain, idx, "revokeAndReissueSubtree")
    leaf = _at(chain, len(chain) - 1, "revokeAndReissueSubtree")
    ancestor_pub = _pub(ancestor_secret)
    if ancestor_pub != ancestor.get("holder"):
        raise ValueError("revokeAndReissueSubtree: ancestorSecret (pub %s) is not the safe ancestor's holder %s" % (ancestor_pub, ancestor.get("holder")))
    if not isinstance(new_key_pair, KeyPair):
        raise TypeError("expected a KeyPair for the new key")
    new_holder = new_key_pair.public
    if any(isinstance(c, dict) and c.get("holder") == new_holder for c in chain[idx:]):
        raise ValueError("revokeAndReissueSubtree: newKeyPair is a key held inside the compromised subtree")
    _check_now(now, "revokeAndReissueSubtree")
    new_hop = delegate(ancestor, ancestor_secret, new_holder, _appended_caveats(ancestor, leaf))
    return {
        "chain": list(chain[:idx]) + [new_hop],
        "revocation": {"capId": subtree_root.get("id"), "holder": compromised_holder, "issuer": subtree_root.get("issuer"),
                       "subtreeRoot": subtree_root.get("id"), "capIds": [c.get("id") for c in chain[idx:]],
                       "reason": "delegation subtree compromised" if reason is None else reason, "revokedAt": _now_ms() if now is None else now},
    }


def compromised_key_flow(chain: Any, compromised_holder: Any, new_key_pair: KeyPair, ancestor_secret: KeyPair,
                         reason: Optional[str] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """:func:`revoke_and_reissue_subtree` end to end: one revocation record PER capability in the compromised subtree (root to
    leaf) plus the re-issued chain. Returns ``{"revocations", "reissued"}``."""
    _require_non_empty(chain, "compromisedKeyFlow")
    idx = _index_of_holder(chain, compromised_holder)
    if idx < 0:
        raise ValueError("compromisedKeyFlow: holder %s is not in the chain" % (compromised_holder,))
    reissued = revoke_and_reissue_subtree(chain, compromised_holder, new_key_pair, ancestor_secret, reason, now)["chain"]
    subtree_root = _at(chain, idx, "compromisedKeyFlow")
    revoked_at = _now_ms() if now is None else now
    why = "delegation subtree compromised" if reason is None else reason
    return {
        "revocations": [{"capId": c.get("id"), "holder": c.get("holder"), "issuer": c.get("issuer"), "subtreeRoot": subtree_root.get("id"),
                         "capIds": [c.get("id")], "reason": why, "revokedAt": revoked_at} for c in chain[idx:]],
        "reissued": reissued,
    }


def apply_rotation(sink: Any, records: Any, reissued: Optional[Sequence[Any]] = None) -> List[str]:
    """Revoke what a rotation replaced, all or nothing. ``sink`` has ``revoke(input)``, ``unrevoke(key)`` and ``lookup(kind, value)``
    (a :class:`atlas_pca.revoke.RevocationRegistry` fits). Every capability id the record(s) cover is revoked; if any revoke fails, the
    ones this call added are removed again and the error is re-raised. Only capability ids are revoked (revoking the old holder key
    would deny the re-issued chain). Refuses, before touching the sink, a record naming no capability id and a re-issued chain that
    shares an id with what is being revoked. Returns the revoked ids."""
    lst = records if isinstance(records, list) else [records]
    todo: Dict[str, Any] = {}
    for r in lst:
        if r is None:
            raise TypeError("applyRotation: a record is null")
        rd = r if isinstance(r, dict) else {}
        if rd.get("capIds") is not None:
            ids = rd["capIds"]
            # the reference iterates a string character by character; a string here is refused instead
            if not isinstance(ids, list):
                raise TypeError("applyRotation: capIds must be a list")
        else:
            ids = [rd["capId"]] if "capId" in rd else []
        for i in ids:
            if not isinstance(i, str) or len(i) == 0:
                raise TypeError("applyRotation: a record names an invalid capability id")
            if i not in todo:
                todo[i] = rd
    if len(todo) == 0:
        raise ValueError("applyRotation: the record names no capability to revoke")
    if reissued is not None and not isinstance(reissued, list):
        raise TypeError("applyRotation: reissued must be a chain")
    kept = []
    for c in reissued or []:
        if c is None:
            raise TypeError("applyRotation: a re-issued hop is null")
        kept.append(c.get("id") if isinstance(c, dict) else None)
    for i in todo:
        if i in kept:
            raise ValueError("applyRotation: the re-issued chain contains a capability that is being revoked")
    added: List[str] = []
    try:
        for i, r in todo.items():
            if sink.lookup("cap", i) is None:
                added.append(i)
            sink.revoke({"kind": "cap", "value": i, "reason": r.get("reason"), "revokedAt": r.get("revokedAt")})
    except Exception:
        for i in added:
            try:
                sink.unrevoke({"kind": "cap", "value": i})
            except Exception:  # noqa: BLE001 - best effort: the original failure is the one to report
                pass
        raise
    return list(todo)


__all__ = ["apply_rotation", "compromised_key_flow", "revoke_and_reissue_subtree", "rotate_agent_key", "rotate_principal_key"]
