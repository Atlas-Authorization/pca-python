"""The issuing side of the agent mesh (the TypeScript ``mesh`` and ``durable-mesh-witness``): an independent log witness
(:class:`MeshWitness`) with its durable stores, the issuer-side domain (:class:`MeshDomain`: delegation log, revocation set, head
publication, per-hop evidence), cross-domain capability translation, the federated trust budget and mutual-transparency cross references.
Verification of a whole proof is :func:`atlas_pca.mesh.verify_mesh_proof`; signing the leaf action and assembling the proof are in
:mod:`atlas_pca.signers_more`. Records are dicts with the reference's member names; keys are :class:`atlas_pca.agent.KeyPair`."""
import copy
import json
import math
from ._fin import fin
import os
from typing import Any, Callable, Dict, List, Optional, Sequence

from .agent import KeyPair
from .caveat_lang import ChainView  # noqa: F401  (re-exported for callers that hold views)
from .ledger_proofs import RevocationSet, consistency_proof, inclusion_proof
from .grants import merkle_proof
from .intent_v2 import compare_utf8
from .mesh import (DEFAULT_MAX_CHAIN_LENGTH, DEFAULT_MAX_CLOCK_SKEW_MS, MESH_BINDING_DOMAIN, MESH_COSIG_DOMAIN, MESH_HEAD_DOMAIN, _effective, authority_out,
                   _msg, _narrows, _valid_head, check_head_advance)
from .pca import _is_num, _js_nonneg_int, _verify_b64u, b64u, cap_hash, hash_canonical, merkle_root, verify_chain, canonical_bytes_strict
from .risk import debit, debit_consolidated, safety_bound, sub_budget

__all__ = ["build_mesh_example", "demonstrate_fork_rejection", "key_revocation_id", "MemoryMeshWitnessStore", "FileMeshWitnessStore", "MeshWitness", "MeshDomain", "translate_capability",
           "verify_translated_capability", "translated_effective_authority", "create_federated_budget", "allocate_sub", "spend_federated",
           "federated_safety_bound", "mesh_action_digest", "cross_reference_commit", "anchor_cross_reference", "verify_cross_reference"]

_MAX_REV_IDS = 1_000_000


def key_revocation_id(agent_public: str) -> str:
    """Id used in a domain's revocation set to revoke an agent KEY (kills every capability it issues)."""
    return "key:%s" % _text(agent_public)


def _text(v: Any) -> str:
    """A value as the reference prints it inside a string (only strings are meaningful ids; the rest is for parity on bad input)."""
    if isinstance(v, str):
        return v
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    if isinstance(v, list):
        return ",".join("" if x is None else _text(x) for x in v)
    return "[object Object]" if isinstance(v, dict) else str(v)


def _u16(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


# ---- witness stores ------------------------------------------------------------------------------------------------------

class MemoryMeshWitnessStore:
    """In-process store (a test double, and the default when no store is given). It does not survive a restart."""

    def __init__(self) -> None:
        self._state: Optional[str] = None

    def load(self) -> Optional[dict]:
        return None if self._state is None else json.loads(self._state)

    def save(self, state: dict) -> None:
        self._state = json.dumps(state)


class FileMeshWitnessStore:
    """A file-backed store. Every save writes a temporary file, fsyncs it, renames it over the real file and fsyncs the directory, so a crash
    leaves the old state or the new one, never a torn file. The file carries a digest of its state: a file that does not parse, has the wrong
    shape or fails the digest makes ``load`` raise (a witness never starts empty over a damaged file). A missing file is a first run.
    Single process: two witnesses must not share one file."""

    def __init__(self, path: str) -> None:
        self._path = path

    def load(self) -> Optional[dict]:
        if not os.path.exists(self._path):
            return None
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception:  # noqa: BLE001
            raise ValueError("FileMeshWitnessStore: the state file is not valid JSON; refusing to start empty") from None
        if not isinstance(doc, dict) or doc.get("v") != 1 or not isinstance(doc.get("digest"), str) or not isinstance(doc.get("state"), dict):
            raise ValueError("FileMeshWitnessStore: the state file has an unexpected shape; refusing to start empty")
        if hash_canonical(doc["state"]) != doc["digest"]:
            raise ValueError("FileMeshWitnessStore: the state file fails its digest; refusing to start empty")
        return doc["state"]

    def save(self, state: dict) -> None:
        body = json.dumps({"v": 1, "state": state, "digest": hash_canonical(state)})
        tmp = self._path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, body.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self._path)
        try:
            dfd = os.open(os.path.dirname(os.path.abspath(self._path)), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass  # some platforms cannot fsync a directory; the rename above is already atomic


# ---- witness -------------------------------------------------------------------------------------------------------------

def _state_of(seen: Dict[str, dict]) -> dict:
    items = [{"head": dict(s["head"]), "rev_ids": list(s["rev"])} for s in seen.values()]
    items.sort(key=lambda x: _u16(x["head"]["domain"]))
    return {"seen": items}


class MeshWitness:
    """An independent log witness. It cosigns a domain head only if (1) the domain signed it, (2) it is an RFC 9162-verified append-only
    extension of the last head THIS witness cosigned for that domain, (3) its revocation list reproduces ``rev_root`` and is a superset of
    the previously cosigned list, and (4) the timestamp does not regress (nor run ahead of the witness's own clock, when configured). State
    is committed only after every check passes (and after the store saved it). First sight of a domain is trust-on-first-use.

    `secret` is the witness's :class:`KeyPair`; `store` (``load()`` / ``save(state)``) is durable memory (a corrupt state raises: the witness
    never starts empty over damaged memory); `clock` (``() -> ms``) and `max_clock_skew_ms` refuse heads from the witness's future."""

    def __init__(self, secret: KeyPair, store: Any = None, clock: Optional[Callable[[], float]] = None,
                 max_clock_skew_ms: Optional[float] = None) -> None:
        self._secret, self._store, self._clock = secret, store, clock
        self._skew = DEFAULT_MAX_CLOCK_SKEW_MS if max_clock_skew_ms is None else max_clock_skew_ms
        self.id = secret.public
        self._seen: Dict[str, dict] = {}
        loaded = store.load() if store is not None else None
        if loaded is not None:
            self.import_state(loaded)

    def last_seen(self, domain: str) -> Optional[dict]:
        """The newest head this witness cosigned for `domain` (what a domain must prove consistency from)."""
        s = self._seen.get(domain)
        return dict(s["head"]) if s else None

    def cosign(self, req: Any) -> Dict[str, str]:
        """Cosign a head: ``req`` is ``{"head": CosignedHead, "consistency"?, "rev_ids"}``. Raises (and changes nothing) if any rule is violated."""
        ch = req.get("head") if isinstance(req, dict) else None
        if not isinstance(ch, dict) or _valid_head(ch.get("head")) is None or not isinstance(ch.get("sig"), str):
            raise ValueError("witness: malformed head")
        h = ch["head"]
        if not _verify_b64u(h["domain"], _msg(MESH_HEAD_DOMAIN, h), ch["sig"]):
            raise ValueError("witness: head not signed by its domain")
        if self._clock is not None:
            clk = self._clock()
            if not (_is_num(clk) and _is_num(self._skew) and h["timestamp"] <= clk + self._skew):
                raise ValueError("witness: head timestamp is in the future")
        ids = req.get("rev_ids")
        if not isinstance(ids, list) or len(ids) > _MAX_REV_IDS or not all(isinstance(i, str) for i in ids):
            raise ValueError("witness: malformed revocation list")
        rs = RevocationSet(ids)
        if rs.size != h["rev_size"] or rs.root != h["rev_root"]:
            raise ValueError("witness: revocation list does not match head")
        prev = self._seen.get(h["domain"])
        if prev is not None:
            why = check_head_advance(prev["head"], h, req.get("consistency"))
            if why:
                raise ValueError("witness: %s" % why)
            if not (h["timestamp"] >= prev["head"]["timestamp"]):
                raise ValueError("witness: timestamp regresses")
            now = set(rs.list())
            if not all(i in now for i in prev["rev"]):
                raise ValueError("witness: revocation set drops a previously cosigned revocation")
        if self._store is not None:
            nxt = dict(self._seen)
            nxt[h["domain"]] = {"head": dict(h), "rev": rs.list()}
            try:
                self._store.save(_state_of(nxt))  # persist first, commit to memory second
            except Exception:  # noqa: BLE001
                raise ValueError("witness: could not persist state; refusing to cosign") from None
        self._seen[h["domain"]] = {"head": dict(h), "rev": rs.list()}
        return {"witness": self.id, "sig": b64u(self._secret.sign(_msg(MESH_COSIG_DOMAIN, h)))}

    def export_state(self) -> dict:
        """Memory for persistence, in a deterministic order."""
        return _state_of(self._seen)

    def import_state(self, state: Any) -> None:
        """Restore memory; each record must be internally consistent (its revocation list reproduces its root)."""
        nxt: Dict[str, dict] = {}
        seen = state.get("seen") if isinstance(state, dict) else None
        for s in ([] if seen is None else seen):
            if not isinstance(s, dict) or _valid_head(s.get("head")) is None or not isinstance(s.get("rev_ids"), list) \
                    or not all(isinstance(i, str) for i in s["rev_ids"]):
                raise ValueError("witness: malformed state")
            rs = RevocationSet(s["rev_ids"])
            if rs.size != s["head"]["rev_size"] or rs.root != s["head"]["rev_root"]:
                raise ValueError("witness: malformed state")
            nxt[s["head"]["domain"]] = {"head": dict(s["head"]), "rev": rs.list()}
        self._seen.clear()
        self._seen.update(nxt)


# ---- domain --------------------------------------------------------------------------------------------------------------

class MeshDomain:
    """Issuer-side state of one organisation: an append-only delegation log, a revocation set and head publication (in memory, so the
    protocol can be exercised end to end)."""

    def __init__(self, name: str, secret: KeyPair) -> None:
        self.name, self._secret, self.id = name, secret, secret.public
        self._log: List[str] = []
        self._rev = RevocationSet()
        self._snaps: Dict[str, dict] = {}

    def enroll(self, agent: str, role: str) -> Dict[str, str]:
        """Vouch that an agent key belongs to this domain."""
        return {"agent": agent, "domain": self.id, "role": role,
                "sig": b64u(self._secret.sign(_msg(MESH_BINDING_DOMAIN, {"agent": agent, "domain": self.id, "role": role})))}

    def record(self, cap: dict) -> int:
        """Log a delegation hop issued in this domain. Idempotent."""
        h = cap_hash(cap)
        if h in self._log:
            return self._log.index(h)
        self._log.append(h)
        return len(self._log) - 1

    def revoke(self, rid: str) -> None:
        """Revoke a capability id (``cap["id"]``) or an agent key (:func:`key_revocation_id`)."""
        self._rev.revoke(rid)

    def revocation_set_copy(self) -> RevocationSet:
        return RevocationSet(self._rev.list())

    def consistency_proof(self, old_size: int, new_size: Optional[int] = None) -> dict:
        """RFC 9162 consistency proof between two sizes of this domain's current log."""
        return consistency_proof(self._log, old_size, new_size)

    def pin_proof(self, pin: dict, head: dict) -> dict:
        """The proof a verifier holding `pin` needs to accept `head` (a head this domain published, larger than the pin)."""
        snap = self._snaps.get(head.get("sig"))
        if snap is None:
            raise ValueError("pinProof: unknown head")
        return {"domain": self.id, "proof": consistency_proof(snap["log"], pin["size"], head["head"]["size"])}

    def publish_head(self, witnesses: Sequence[MeshWitness], timestamp: Any, threshold: Optional[int] = None) -> dict:
        """Publish a head: domain-signed, then cosigned by `witnesses`, each shown a real consistency proof from ITS last-seen head plus the
        revocation list. Raises if a witness refuses (unless `threshold` tolerates it); nothing is recorded as published on failure."""
        head = {"domain": self.id, "size": len(self._log), "root": "" if not self._log else merkle_root(self._log), "rev_root": self._rev.root,
                "rev_size": self._rev.size, "timestamp": timestamp}
        ch: Dict[str, Any] = {"head": head, "sig": b64u(self._secret.sign(_msg(MESH_HEAD_DOMAIN, head))), "cosigs": []}
        rev_ids = self._rev.list()
        errors: List[Exception] = []
        for w in witnesses:
            prev = w.last_seen(self.id)
            consistency = None
            if prev and prev["size"] < head["size"]:
                consistency = consistency_proof(self._log, prev["size"], head["size"])
            elif prev and prev["size"] > head["size"]:
                consistency = {"oldSize": prev["size"], "newSize": head["size"], "path": []}  # will be refused as a rollback
            try:
                req = {"head": ch, "rev_ids": rev_ids}
                if consistency is not None:
                    req["consistency"] = consistency
                ch["cosigs"].append(w.cosign(req))
            except Exception as e:  # noqa: BLE001
                errors.append(e)
        need = len(witnesses) if threshold is None else threshold
        if len(ch["cosigs"]) < need:
            raise errors[0] if errors else ValueError("publishHead: not enough witnesses")
        self._snaps[ch["sig"]] = {"log": list(self._log), "rev": RevocationSet(self._rev.list())}
        return ch

    def evidence(self, cap: dict, head: dict, binding: Optional[dict] = None) -> dict:
        """Per-hop evidence against a previously published head. Raises if the cap is not in that head's log or if the cap or issuer key is
        revoked as of that head (no non-membership proof can exist)."""
        snap = self._snaps.get(head.get("sig"))
        if snap is None:
            raise ValueError("evidence: unknown head")
        h = cap_hash(cap)
        if h not in snap["log"]:
            raise ValueError("evidence: capability not in this head")
        ev: Dict[str, Any] = {"domain": self.id, "head": head, "inclusion": merkle_proof(snap["log"], snap["log"].index(h)),
                              "revocation": {"cap": snap["rev"].non_membership_proof(cap["id"]),
                                             "issuer_key": snap["rev"].non_membership_proof(key_revocation_id(cap["issuer"]))}}
        if binding:
            ev["binding"] = binding
        return ev


# ---- 1. cross-domain capability translation ------------------------------------------------------------------------------

_XCAP_DOMAIN = "atlas-pca/mesh-xcap/v1\x00"
_XANCHOR_DOMAIN = "atlas-pca/mesh-xanchor/v1\x00"
_ACTION_DIGEST_DOMAIN = "atlas-pca/mesh-action-digest/v1\x00"


def _clone_caveats(cs: Any) -> list:
    return json.loads(canonical_bytes_strict(cs).decode("utf-8"))  # rejects anything unhashable


def _is_caveat_array(x: Any) -> bool:
    return isinstance(x, list) and all(isinstance(c, dict) and isinstance(c.get("type"), str) for c in x)


def _xcap_body(tc: dict) -> dict:
    return {"v": "atlas-pca/mesh-xcap/v1", "from": tc["fromGuardian"], "to": tc["toGuardian"], "source_tip": tc["source_tip"],
            "caveats": tc["caveats"], "issued_at": tc["issued_at"]}


def translate_capability(chain: List[dict], from_guardian: str, to_guardian: str, bridge: KeyPair, issued_at: Any,
                         additional_caveats: Any = (), pq_pins: Any = None) -> Dict[str, Any]:
    """Translate a capability chain (rooted in Guardian A's grant) into a capability valid in Guardian B's domain. The result's caveats are
    A's chain-tip caveats followed by B's `additional_caveats` (append-only, hence monotone narrowing), signed by `bridge`. RAISES on
    malformed input; the verifier (:func:`verify_translated_capability`) is the total, fail-closed function."""
    ok, reason = verify_chain(chain, None, pq_pins=pq_pins)
    if not ok:
        raise ValueError("translateCapability: invalid source chain: %s" % reason)
    if isinstance(additional_caveats, tuple):  # omitted: none; an explicit null is refused, as in the reference
        additional_caveats = []
    if not _is_caveat_array(additional_caveats):
        raise ValueError("translateCapability: additionalCaveats must be an array of caveats")
    tip = chain[-1]
    caveats = _clone_caveats(tip["caveats"]) + _clone_caveats(additional_caveats)
    source_tip = cap_hash(tip)
    tc = {"fromGuardian": from_guardian, "toGuardian": to_guardian, "source_tip": source_tip, "caveats": caveats, "issued_at": issued_at}
    return {"source": chain, "fromGuardian": from_guardian, "toGuardian": to_guardian, "bridge": bridge.public, "source_tip": source_tip,
            "caveats": caveats, "issued_at": issued_at, "sig": b64u(bridge.sign(_msg(_XCAP_DOMAIN, _xcap_body(tc))))}


def translated_effective_authority(tc: Any) -> Any:
    """The translated effective authority: the conjunction of all translated caveats, or ``{"error"}`` on an unknown or malformed caveat."""
    if not isinstance(tc, dict) or not _is_caveat_array(tc.get("caveats")):
        return {"error": "malformed translated capability"}
    e, err = _effective(tc["caveats"])
    return {"error": err} if e is None else authority_out(e)


_NOT_GIVEN: Any = object()
_TRANSLATE_OPTIONS = {"fromGuardian": "from_guardian", "toGuardian": "to_guardian", "bridge": "bridge", "rootIssuer": "root_issuer", "now": "now",
                      "pqPins": "pq_pins"}


def _js_number(v: Any) -> float:
    """A clock value as the reference's comparison reads it: a number as is, numeric text as its value, anything else NaN (never past)."""
    if isinstance(v, bool):
        return float(v)
    if isinstance(v, (int, float)):
        return v
    try:
        return float(v.strip() or 0) if isinstance(v, str) else math.nan
    except ValueError:
        return math.nan


def verify_translated_capability(tc: Any, from_guardian: Any = _NOT_GIVEN, to_guardian: Any = _NOT_GIVEN, bridge: Any = _NOT_GIVEN,
                                 root_issuer: Optional[str] = None, now: Any = None, pq_pins: Any = None, *, options: Any = _NOT_GIVEN) -> Dict[str, Any]:
    """Verify a translated capability END TO END, OFFLINE. TOTAL: never raises, fails closed on any malformed input. Checks the source chain,
    the guardian and bridge pins, the source tip binding, the append-only caveat prefix, the bridge signature, the monotone narrowing of the
    effective authority and (optionally) expiry as of `now`. Returns ``{"ok": True, "from", "to", "bridge", "effective"}`` or
    ``{"ok": False, "reason"}``.

    A pin that is given must match: ``bridge=None`` is a pin no capability satisfies, not an absent one. ``options`` takes the reference's
    options object instead of the keywords (members ``fromGuardian``, ``toGuardian``, ``bridge``, ``rootIssuer``, ``now``, ``pqPins``); a
    None options object is refused, as the reference refuses it."""
    def fail(reason: str) -> Dict[str, Any]:
        return {"ok": False, "reason": reason}
    if options is not _NOT_GIVEN:
        if options is None:
            return fail("malformed translated capability")
        given = {py: options[js] for js, py in _TRANSLATE_OPTIONS.items() if js in options} if isinstance(options, dict) else {}
        return verify_translated_capability(tc, **given)
    try:
        if not isinstance(tc, dict) or not isinstance(tc.get("source"), list) or not isinstance(tc.get("fromGuardian"), str) \
                or not isinstance(tc.get("toGuardian"), str):
            return fail("malformed translated capability")
        if not all(isinstance(tc.get(k), str) for k in ("bridge", "source_tip", "sig")) or not _is_num(tc.get("issued_at")) \
                or not _is_caveat_array(tc.get("caveats")):
            return fail("malformed translated capability")
        ok, reason = verify_chain(tc["source"], root_issuer, pq_pins=pq_pins)
        if not ok:
            return fail("source chain: %s" % reason)
        if from_guardian is not _NOT_GIVEN and tc["fromGuardian"] != from_guardian:
            return fail("source guardian mismatch")
        if to_guardian is not _NOT_GIVEN and tc["toGuardian"] != to_guardian:
            return fail("target guardian mismatch")
        if bridge is not _NOT_GIVEN and tc["bridge"] != bridge:
            return fail("bridge key mismatch")
        if tc["fromGuardian"] == tc["toGuardian"]:
            return fail("translation does not cross a domain boundary")
        tip = tc["source"][-1]
        if tc["source_tip"] != cap_hash(tip):
            return fail("source_tip does not match the source chain tip")
        if len(tc["caveats"]) < len(tip["caveats"]):
            return fail("translation drops a source caveat (widening)")
        for j, c in enumerate(tip["caveats"]):
            if hash_canonical(tc["caveats"][j]) != hash_canonical(c):
                return fail("translation altered or reordered source caveat %d (widening)" % j)
        if not _verify_b64u(tc["bridge"], _msg(_XCAP_DOMAIN, _xcap_body(tc)), tc["sig"]):
            return fail("translation not signed by the declared bridge key")
        eff_s, err = _effective(tip["caveats"])
        if eff_s is None:
            return fail("source caveats: %s" % err)
        eff_t, err = _effective(tc["caveats"])
        if eff_t is None:
            return fail(err)
        if not _narrows(eff_t, eff_s):
            return fail("translated authority widens the source authority")
        if now is not None and eff_t["expires_at"] is not None and not (fin(_js_number(now)) and _js_number(now) <= eff_t["expires_at"]):
            return fail("translated capability expired")
        return {"ok": True, "from": tc["fromGuardian"], "to": tc["toGuardian"], "bridge": tc["bridge"], "effective": authority_out(eff_t)}
    except Exception:  # noqa: BLE001
        return fail("malformed translated capability")


# ---- 2. consolidated cross-domain budget ---------------------------------------------------------------------------------

_MAX_BUDGET_DEPTH = DEFAULT_MAX_CHAIN_LENGTH


def _valid_budget_state(s: Any) -> bool:
    if not isinstance(s, dict) or not isinstance(s.get("nodes"), dict) or not isinstance(s.get("root"), str) or not _is_num(s.get("kappa")) \
            or not _is_num(s.get("bMax")):
        return False
    if s["kappa"] <= 0 or s["bMax"] < 0 or s["root"] not in s["nodes"]:
        return False
    for n in s["nodes"].values():
        if not isinstance(n, dict) or not isinstance(n.get("domain"), str) or not _is_num(n.get("B")) or n["B"] < 0:
            return False
        if "parent" in n and not isinstance(n["parent"], str):
            return False
    return True


def create_federated_budget(root_id: Any, root_domain: Any, B0: Any, kappa: Any, b_max: Any) -> Dict[str, Any]:
    """A federated budget rooted at `root_id` (in `root_domain`) with initial budget ``B0 <= b_max``. Fail-closed on a malformed policy or
    allocation: ``{"ok": True, "state"}`` or ``{"ok": False, "reason"}``."""
    if not isinstance(root_id, str) or not isinstance(root_domain, str):
        return {"ok": False, "reason": "malformed root"}
    if not _is_num(kappa) or kappa <= 0:
        return {"ok": False, "reason": "kappa must be finite and > 0"}
    if not _is_num(b_max) or b_max < 0:
        return {"ok": False, "reason": "bMax must be finite and >= 0"}
    if not _is_num(B0) or B0 < 0:
        return {"ok": False, "reason": "B0 must be finite and >= 0"}
    if B0 > b_max:
        return {"ok": False, "reason": "B0 exceeds bMax"}
    return {"ok": True, "state": {"nodes": {root_id: {"domain": root_domain, "B": B0}}, "root": root_id, "kappa": kappa, "bMax": b_max}}


def allocate_sub(state: Any, id: Any, domain: Any, parent: Any, alloc: Any) -> Dict[str, Any]:  # noqa: A002
    """Allocate a sub-agent budget: a new node `id` (in `domain`) under `parent`, with ceiling `alloc` (``0 <= alloc <= parent's CURRENT
    remaining``). The allocation is a ceiling, not a reservation. Fail-closed on an unknown parent, a duplicate id or an excess allocation."""
    if not _valid_budget_state(state):
        return {"ok": False, "reason": "malformed budget state"}
    if not isinstance(id, str) or not isinstance(domain, str) or not isinstance(parent, str):
        return {"ok": False, "reason": "malformed allocation"}
    if id in state["nodes"]:
        return {"ok": False, "reason": "node id already exists"}
    if parent not in state["nodes"]:
        return {"ok": False, "reason": "unknown parent"}
    sub = sub_budget({"B": state["nodes"][parent]["B"], "tau": 0}, alloc)
    if not sub["ok"]:
        return {"ok": False, "reason": sub["reason"]}
    return {"ok": True, "state": dict(state, nodes=dict(state["nodes"], **{id: {"domain": domain, "parent": parent, "B": sub["sub"]["B"]}}))}


def _budget_path(state: dict, node_id: str) -> Dict[str, Any]:
    path: List[str] = []
    seen = set()
    cur: Optional[str] = node_id
    while cur is not None:
        if cur not in state["nodes"]:
            return {"ok": False, "reason": "unknown node"}
        if cur in seen:
            return {"ok": False, "reason": "cycle in budget tree"}
        if len(path) >= _MAX_BUDGET_DEPTH:
            return {"ok": False, "reason": "budget tree too deep"}
        seen.add(cur)
        path.append(cur)
        cur = state["nodes"][cur].get("parent")
    if path[-1] != state["root"]:
        return {"ok": False, "reason": "node is not rooted at the budget root"}
    return {"ok": True, "path": path}


def spend_federated(state: Any, node_id: Any, c: Any) -> Dict[str, Any]:
    """Spend `c` at `node_id`: debits that node AND every ancestor up to the root, each exactly once, ONLY IF all of them can cover it (atomic;
    fail-closed with no state change otherwise). Every spend debits the root, so the whole delegation DAG draws on one budget."""
    if not _valid_budget_state(state):
        return {"ok": False, "reason": "malformed budget state"}
    if not isinstance(node_id, str):
        return {"ok": False, "reason": "malformed node id"}
    if not _is_num(c) or c < 0:
        return {"ok": False, "reason": "spend must be finite and >= 0"}
    p = _budget_path(state, node_id)
    if not p["ok"]:
        return {"ok": False, "reason": p["reason"]}
    path, root_id = p["path"], state["root"]
    nodes = dict(state["nodes"])
    if node_id == root_id:
        r = state["nodes"][root_id]
        if not (_is_num(r["B"]) and r["B"] >= c):
            return {"ok": False, "reason": "root budget insufficient"}
        nodes[root_id] = dict(r, B=debit({"B": r["B"], "tau": 0}, c)["B"])
        return {"ok": True, "state": dict(state, nodes=nodes)}
    interior = path[1:-1]
    for i in interior:
        if not (_is_num(state["nodes"][i]["B"]) and state["nodes"][i]["B"] >= c):
            return {"ok": False, "reason": 'ancestor "%s" budget insufficient' % i}
    dc = debit_consolidated({"B": state["nodes"][root_id]["B"], "tau": 0}, {"B": state["nodes"][node_id]["B"], "tau": 0}, c)
    if not dc["ok"]:
        return {"ok": False, "reason": dc["reason"]}
    nodes[node_id] = dict(state["nodes"][node_id], B=dc["sub"]["B"])
    nodes[root_id] = dict(state["nodes"][root_id], B=dc["parent"]["B"])
    for i in interior:
        nodes[i] = dict(state["nodes"][i], B=debit({"B": state["nodes"][i]["B"], "tau": 0}, c)["B"])
    return {"ok": True, "state": dict(state, nodes=nodes)}


def federated_safety_bound(p: Any) -> float:
    """Whatever the shape of the delegation DAG, the total risk of the collective spend between two human recharges is at most
    ``bMax / kappa`` (the single-agent safety bound, now covering the whole cross-domain swarm)."""
    if not isinstance(p, dict) or not _is_num(p.get("bMax")) or not _is_num(p.get("kappa")):
        return 0
    return safety_bound(p)


# ---- 3. mutual transparency: the cross-reference linking commitment ------------------------------------------------------

def mesh_action_digest(action: dict) -> str:
    """Digest of a mesh action for anchoring (domain-separated, strict-canonical)."""
    return hash_canonical({"v": _ACTION_DIGEST_DOMAIN, "action": action})


def cross_reference_commit(x: dict) -> str:
    """The deterministic digest of ``{action, from, to, nonce, at}``: both Guardians anchor THIS value."""
    return hash_canonical({"v": "atlas-pca/mesh-xref/v1", "action_digest": x["action_digest"], "from": x["fromGuardian"], "to": x["toGuardian"],
                           "nonce": x["nonce"], "at": x["at"]})


def anchor_cross_reference(domain_secret: KeyPair, commit: str, seq: int) -> Dict[str, Any]:
    """A Guardian signs an anchor binding `commit` at log position `seq`."""
    return {"domain": domain_secret.public, "commit": commit, "seq": seq,
            "sig": b64u(domain_secret.sign(_msg(_XANCHOR_DOMAIN, {"commit": commit, "seq": seq})))}


def _valid_anchor(a: Any) -> bool:
    return isinstance(a, dict) and isinstance(a.get("domain"), str) and isinstance(a.get("commit"), str) and _js_nonneg_int(a.get("seq")) \
        and isinstance(a.get("sig"), str)


def verify_cross_reference(x: Any, anchors: Any) -> Dict[str, Any]:
    """Verify a cross-reference: both Guardians' anchors commit to the SAME action digest and are each validly signed. TOTAL, fail-closed."""
    def fail(reason: str) -> Dict[str, Any]:
        return {"ok": False, "reason": reason}
    try:
        if not isinstance(x, dict) or not all(isinstance(x.get(k), str) for k in ("action_digest", "fromGuardian", "toGuardian", "nonce")) \
                or not _is_num(x.get("at")):
            return fail("malformed cross-reference")
        if not isinstance(anchors, dict) or not _valid_anchor(anchors.get("from")) or not _valid_anchor(anchors.get("to")):
            return fail("malformed anchors")
        if x["fromGuardian"] == x["toGuardian"]:
            return fail("cross-reference must span two distinct domains")
        expected = cross_reference_commit(x)
        a_from, a_to = anchors["from"], anchors["to"]
        if a_from["domain"] != x["fromGuardian"]:
            return fail("source anchor domain does not match the cross-reference")
        if a_to["domain"] != x["toGuardian"]:
            return fail("target anchor domain does not match the cross-reference")
        if a_from["commit"] != expected:
            return fail("source anchor commits a different action")
        if a_to["commit"] != expected:
            return fail("target anchor commits a different action")
        if not _verify_b64u(a_from["domain"], _msg(_XANCHOR_DOMAIN, {"commit": a_from["commit"], "seq": a_from["seq"]}), a_from["sig"]):
            return fail("source anchor signature invalid")
        if not _verify_b64u(a_to["domain"], _msg(_XANCHOR_DOMAIN, {"commit": a_to["commit"], "seq": a_to["seq"]}), a_to["sig"]):
            return fail("target anchor signature invalid")
        return {"ok": True, "commit": expected}
    except Exception:  # noqa: BLE001
        return fail("malformed cross-reference")


# ---- the worked example ----------------------------------------------------------------------------------------------------

def _example_key(label: str) -> KeyPair:
    """A PUBLIC, fixed example key: the first 32 bytes of the TEXT of a domain-tagged hash (as the reference builds it). Never a real key."""
    return KeyPair(hash_canonical({"seed": "atlas-pca/mesh-example/%s" % label}).encode("utf-8")[:32], allow_insecure_signer=True)


def build_mesh_example(now: Any = 1_800_000_000_000) -> Dict[str, Any]:
    """A worked proof with 4 hops across 3 organisations (the human's home is org A): human -> orchestrator (logged in A), orchestrator ->
    tool agent (A), tool agent -> service agent (B), service agent -> leaf worker (C); the leaf then performs ``payments.refund`` for 25
    under /orders/42. Org A publishes two successive heads, the second cosigned only after every witness verified the consistency proof.
    Returns the parts so callers can build variants: ``{"trust", "proof", "evidence", "domains": {"A", "B", "C"}, "witnesses", "keys",
    "chain", "heads": {"A0", "A", "B", "C"}, "bindings"}``. All keys are fixed public example keys."""
    from .agent import delegate, mint_root
    from .signers_more import assemble_mesh_proof
    keys = {k: _example_key(k) for k in ("human", "orchestrator", "tool", "service", "leaf")}
    A, B, C = (MeshDomain("org-%s" % n, _example_key("domain-%s" % n)) for n in "ABC")
    witnesses = [MeshWitness(_example_key("witness-%d" % i)) for i in (1, 2, 3)]
    root = mint_root(keys["human"], keys["orchestrator"].public, [
        {"type": "scope", "actions": ["payments.refund", "payments.read", "orders.read"]}, {"type": "resource", "prefix": "/orders/"},
        {"type": "max_amount", "max": 500}, {"type": "expires", "at": now + 3_600_000}, {"type": "audience", "domains": [C.id]}])
    c1 = delegate(root, keys["orchestrator"], keys["tool"].public,
                  [{"type": "scope", "actions": ["payments.refund", "payments.read"]}, {"type": "max_amount", "max": 100}])
    c2 = delegate(c1, keys["tool"], keys["service"].public, [{"type": "resource", "prefix": "/orders/42"}, {"type": "max_hops", "n": 4}])
    c3 = delegate(c2, keys["service"], keys["leaf"].public, [{"type": "scope", "actions": ["payments.refund"]}, {"type": "max_amount", "max": 50}])
    chain = [root, c1, c2, c3]
    A.record(root)
    h_a0 = A.publish_head(witnesses, now - 2_000)
    A.record(c1)
    h_a = A.publish_head(witnesses, now - 1_000)  # size 1 -> 2: consistency-proven by every witness
    B.record(c2)
    C.record(c3)
    h_b = B.publish_head(witnesses, now - 1_000)
    h_c = C.publish_head(witnesses, now - 1_000)
    b_orch = A.enroll(keys["orchestrator"].public, "orchestrator")
    b_tool = B.enroll(keys["tool"].public, "tool-agent")
    b_svc = C.enroll(keys["service"].public, "service-agent")
    evidence = [A.evidence(root, h_a), A.evidence(c1, h_a, b_orch), B.evidence(c2, h_b, b_tool), C.evidence(c3, h_c, b_svc)]
    action = {"type": "payments.refund", "resource": "/orders/42/line/1", "amount": 25, "service_domain": C.id, "nonce": "n-0001", "at": now}
    proof = assemble_mesh_proof(chain, evidence, action, keys["leaf"])
    trust = {"humanPrincipal": keys["human"].public, "witnesses": [w.id for w in witnesses], "threshold": 2, "now": now,
             "allowedDomains": [A.id, B.id, C.id], "rootDomain": A.id}
    return {"trust": trust, "proof": proof, "evidence": evidence, "domains": {"A": A, "B": B, "C": C}, "witnesses": witnesses, "keys": keys,
            "chain": chain, "heads": {"A0": h_a0, "A": h_a, "B": h_b, "C": h_c}, "bindings": {"orchestrator": b_orch, "tool": b_tool, "service": b_svc}}


def demonstrate_fork_rejection() -> Dict[str, Any]:
    """Witnesses verify real RFC 9162 consistency: a malicious domain rewrites an early log entry and grows the forked log PAST the size the
    witness last saw. A size-only check would accept it; the consistency proof (computed over the forked log) does not."""
    from .agent import mint_root
    k, hk = _example_key("fork-domain"), _example_key("fork-human")

    def mk(n: int) -> dict:
        return mint_root(hk, hk.public, [{"type": "scope", "actions": ["a%d" % n]}])

    w = MeshWitness(_example_key("fork-witness"))
    honest = MeshDomain("X", k)
    honest.record(mk(0))
    honest.record(mk(1))
    honest.publish_head([w], 100)
    honest.record(mk(2))
    honest_ok = True
    try:
        honest.publish_head([w], 200)
    except Exception:  # noqa: BLE001
        honest_ok = False
    prior = w.last_seen(honest.id)
    fork = MeshDomain("X", k)  # same key, rewritten history (entry 0 differs), grown past the prior size
    for n in (100, 1, 2, 3):
        fork.record(mk(n))
    reason, rejected = "", False
    try:
        fork.publish_head([w], 300)
    except Exception as e:  # noqa: BLE001
        rejected, reason = True, str(e)
    return {"honest_extension_cosigned": honest_ok, "fork_larger_than_prior": 4 > prior["size"], "size_only_check_would_accept": 4 >= prior["size"],
            "fork_rejected": rejected, "fork_reason": reason}
