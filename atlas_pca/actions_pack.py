"""Signed action packs, the producer side (the TypeScript ``pack``): :func:`shard_defs`, :func:`build_pack` (sort, chain to the previous
version, derive and sign the evolution, shard, sign the pack) and :func:`verify_upgrade` (a pack is the successor of the previous one and its
signed evolution is EXACTLY the computed change). The verifier half (:func:`atlas_pca.actions_registry.verify_pack`) is unchanged. Signing is
Ed25519 (the registry key suite of this SDK)."""
from typing import Any, Callable, Dict, List, Optional

from . import actions as A
from .actions_evolve import evolution_error, evolution_records, sign_evolution
from .actions_registry import (ACTION_PACK_KIND, MAX_EVOLUTION_RECORDS, PACK_SHARD_KIND, PACK_SIG_DOMAIN, compare_versions, pack_defs, pack_digest,
                               pack_shape_error, rules_digest, shard_digest, verify_pack, _message)
from .agent import KeyPair
from .pca import b64u

__all__ = ["DEFAULT_SHARD_DEFS", "shard_defs", "build_pack", "verify_upgrade"]

DEFAULT_SHARD_DEFS = 512  #: largest shard the builder writes by default
MAX_PACK_DEFS = 4096


def _verb_key(d: dict) -> bytes:
    return d["verb"].encode("utf-16-be", "surrogatepass")


def shard_defs(defs: List[dict], max: int = DEFAULT_SHARD_DEFS) -> List[Dict[str, Any]]:  # noqa: A002 - the reference's name
    """Shard names are the resource family (``resource.type`` first segment) of the defs, split in order into chunks of `max`."""
    if isinstance(max, bool) or not isinstance(max, int) or max < 1:
        raise A.ActionKitError("bad_shard_size", "the shard size must be a positive integer")
    fam: Dict[str, List[dict]] = {}
    for d in defs:
        fam.setdefault(d["resource"]["type"].split(".")[0], []).append(d)
    out: List[Dict[str, Any]] = []
    for f in sorted(fam, key=lambda s: s.encode("utf-16-be", "surrogatepass")):
        lst = fam[f]
        n = 1
        for i in range(0, len(lst), max):
            out.append({"name": "%s-%d" % (f, n) if len(lst) > max else f, "defs": lst[i:i + max]})
            n += 1
    return out


def build_pack(ns: str, version: str, stability: str, defs: List[dict], source: dict, kid: str, secret: bytes, *,
               reg: Optional[Dict[str, dict]] = None, prev: Optional[Dict[str, Any]] = None, shard: Any = None,
               attestation_verified: Optional[Callable[[dict], Any]] = None) -> Dict[str, Any]:
    """Build, chain and sign a pack: ``{"pack", "shards"}``. `prev` is ``{"pack", "shards"?}`` (the previous signed pack and its shard
    documents): it chains ``prev`` and derives the signed evolution. `shard` (True, or ``{"max"?, "uri"?: name -> uri}``) shards the pack (always
    above MAX_PACK_DEFS defs). Raises :class:`ActionKitError` on any inconsistency."""
    reg = A.CORE_REGISTRY if reg is None else reg
    ds = sorted(defs, key=_verb_key)
    from .actions_registry import _sorted_unique_defs_error
    de = _sorted_unique_defs_error(ds)
    if de:
        raise A.ActionKitError("bad_pack", de)
    if len(ds) == 0:
        raise A.ActionKitError("empty_pack", "a pack has at least one def")
    prev_defs = pack_defs(prev["pack"], prev.get("shards")) if prev else []
    if prev:
        if prev["pack"]["ns"] != ns:
            raise A.ActionKitError("bad_chain", "the previous pack is of another namespace")
        if compare_versions(version, prev["pack"]["version"]) <= 0:
            raise A.ActionKitError("bad_chain", "the version must increase")
    evolution = sign_evolution(evolution_records(ns, prev_defs, ds, reg, attestation_verified), kid, secret)
    root = A.pack_root([A.def_digest(d) for d in ds])
    want_shards = True if (shard is not None and shard is not False) else len(ds) > MAX_PACK_DEFS
    shards: Dict[str, Any] = {}
    body: Any = ds
    if want_shards:
        opts = shard if isinstance(shard, dict) else {}
        refs = []
        for s in shard_defs(ds, opts.get("max", DEFAULT_SHARD_DEFS)):
            doc = {"v": 1, "kind": PACK_SHARD_KIND, "ns": ns, "version": version, "name": s["name"], "defs": s["defs"]}
            shards[s["name"]] = doc
            uri = opts["uri"](s["name"]) if callable(opts.get("uri")) else "shards/%s.json" % s["name"]
            refs.append({"name": s["name"], "digest": shard_digest(doc), "uri": uri})
        body = {"shards": refs}
    unsigned = {"v": 1, "kind": ACTION_PACK_KIND, "ns": ns, "version": version, "stability": stability, "traits_digest": A.traits_digest(reg),
                "roles_digest": A.tables_digest(), "rules_digest": rules_digest(), "root": root, "defs": body, "source": source,
                "prev": pack_digest(prev["pack"]) if prev else None, "evolution": evolution}
    pe = pack_shape_error(unsigned, False)
    if pe:
        raise A.ActionKitError("bad_pack", pe)
    sig = {"alg": "ed25519", "kid": kid, "value": b64u(KeyPair(bytes(secret)).sign(_message(PACK_SIG_DOMAIN, unsigned)))}
    return {"pack": {**unsigned, "sig": sig}, "shards": shards}


def verify_upgrade(prev: dict, nxt: dict, keys: Any, *, prev_shards: Optional[dict] = None, shards: Optional[dict] = None,
                   reg: Optional[Dict[str, dict]] = None, attestation_verified: Optional[Callable[[dict], Any]] = None) -> Dict[str, Any]:
    """Verify `nxt` as the successor of `prev`: both verify, same namespace, ``nxt.prev`` is `prev`'s digest, the version increases and the
    signed evolution is EXACTLY the computed change (a registry cannot sign ``narrow`` for a widening def). ``{"ok": True}`` or
    ``{"ok": False, "reason"}``."""
    a = verify_pack(prev, keys, prev_shards)
    if not a["ok"]:
        return {"ok": False, "reason": "previous pack: %s" % a["reason"]}
    b = verify_pack(nxt, keys, shards)
    if not b["ok"]:
        return {"ok": False, "reason": "pack: %s" % b["reason"]}
    if nxt["ns"] != prev["ns"]:
        return {"ok": False, "reason": "the packs are of different namespaces"}
    if nxt["prev"] != a["digest"]:
        return {"ok": False, "reason": "chain gap: prev does not name the previous pack"}
    if compare_versions(nxt["version"], prev["version"]) <= 0:
        return {"ok": False, "reason": "the version does not increase"}
    ee = evolution_error(nxt["ns"], a["defs"], b["defs"], nxt["evolution"], keys, A.CORE_REGISTRY if reg is None else reg, attestation_verified)
    return {"ok": True} if ee is None else {"ok": False, "reason": ee}
