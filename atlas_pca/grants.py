"""The producing side of the operational plane (port of the TypeScript reference, @atlasauth/pca-grants): domain-separated Ed25519
signing, the signers for leases, revocations, blueprints and break-glass records, policy bundle signing and assembly, the
decision log (hash chain, Merkle commitment, signed heads, inclusion proofs, streaming batches), replay tooling, consistency
token issuing, lease renewal, group kill, attestation-gated blueprint admission and the lease-store conformance kit.

The verification side lives in :mod:`atlas_pca.k3`, :mod:`atlas_pca.lease`, :mod:`atlas_pca.blueprint`, :mod:`atlas_pca.break_glass`
and :mod:`atlas_pca.fresh_at`. Secrets are 32-byte Ed25519 seeds; signing goes through ``atlas_pca.ed25519.sign_secret`` (the
``cryptography`` package, or the opt-in ``allow_insecure_signer``). Everything the reference awaits is synchronous here; a store
or hook is a plain callable. A signer refuses (raises ``ValueError``) on a malformed record, exactly where the reference throws."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import ed25519 as _ed
from .blueprint import _body as _bp_body, _well_formed as _bp_wf
from .break_glass import (
    BREAK_GLASS_DOMAIN,
    BREAK_GLASS_REVIEW_DOMAIN,
    _BODY_KEYS as _BG_KEYS,
    _REV_KEYS as _RV_KEYS,
    _rv_well_formed,
    _well_formed as _bg_wf,
)
from .fresh_at import FRESH_AT_DOMAIN, FRESH_AT_NUMERIC, check_fresh_at
from .k3 import (
    BUNDLE_DOMAIN,
    LOG_HEAD_DOMAIN,
    bundle_digest,
    bundle_shape_error,
    is_obj,
    is_str,
    is_uint,
    record_commit,
    u16key,
    verify_body,
    verify_bundle as _verify_bundle_core,
)
from .lease import (
    LEASE_DOMAIN,
    LEASE_REVOKE_DOMAIN,
    LeaseRegistry,
    _BODY_KEYS as _LEASE_KEYS,
    _REV_KEYS,
    _rev_well_formed,
    _well_formed as _lease_wf,
    check_lease,
    lease_cap,
    shard_of,
)
from .pca import _build, _is_safe_int, _leaf_hash, _split, b64u, canonical_bytes_strict, hash_canonical, merkle_root

AGENT_BLUEPRINT_DOMAIN = "atlas-pca/agent-blueprint/v1\0"


def _spread(x: Any) -> dict:
    """JavaScript object spread (``{...x}``): a dict copies, a list or string spreads its indices, anything else adds nothing."""
    if isinstance(x, dict):
        return dict(x)
    if isinstance(x, (list, str)):
        return {str(i): v for i, v in enumerate(x)}
    return {}


def _without(o: dict, *drop: str) -> dict:
    return {k: v for k, v in o.items() if k not in drop}


def _truthy(x: Any) -> bool:
    """JavaScript truthiness (an empty dict or list is truthy)."""
    if x is None or x is False or x == "":
        return False
    if isinstance(x, (int, float)) and not isinstance(x, bool):
        return x == x and x != 0
    return True


def _entries(x: Any) -> List[Any]:
    """``Object.entries`` for the shapes a JSON value can take."""
    if isinstance(x, dict):
        return list(x.items())
    if isinstance(x, (list, str)):
        return [(str(i), v) for i, v in enumerate(x)]
    return []


# ---- sig.ts -------------------------------------------------------------------------------------------------------------

def _msg(domain: str, body: Any) -> bytes:
    return domain.encode("utf-8") + canonical_bytes_strict(body)


def signer_of(secret: bytes) -> str:
    """The b64u public key of a 32-byte Ed25519 seed."""
    return b64u(_ed.public_key(secret))


def sign_body(domain: str, body: Any, secret: bytes) -> str:
    """Domain-separated Ed25519 signature over strict-canonical JSON (raises on a body outside the strict profile)."""
    return b64u(_ed.sign_secret(secret, _msg(domain, body)))


sign_domain_body = sign_body
verify_domain_body = verify_body


# ---- signers ------------------------------------------------------------------------------------------------------------

def sign_lease(secret: bytes, l: Any) -> dict:
    """Sign a lease record. Raises on a malformed record or one that outlives its cap."""
    base = {"v": 1, **_spread(l), "authority": signer_of(secret)}
    if not _lease_wf(base) or base["expires_at"] > lease_cap(base):
        raise ValueError("signLease: a malformed lease, or one past issued_at + max_ttl")
    return {**base, "sig": sign_body(LEASE_DOMAIN, {k: base[k] for k in _LEASE_KEYS}, secret)}


def sign_lease_unsafe_over_cap(secret: bytes, l: Any) -> dict:
    """Conformance-vector builder only: signs a record that outlives its cap, to prove verifiers refuse it."""
    base = {"v": 1, **_spread(l), "authority": signer_of(secret)}
    if not _lease_wf(base):
        raise ValueError("signLeaseUnsafeOverCap: malformed")
    return {**base, "sig": sign_body(LEASE_DOMAIN, {k: base[k] for k in _LEASE_KEYS}, secret)}


def sign_lease_revocation(secret: bytes, r: Any) -> dict:
    base = {"v": 1, **_spread(r), "authority": signer_of(secret)}
    if not _rev_well_formed(base):
        raise ValueError("signLeaseRevocation: malformed")
    return {**base, "sig": sign_body(LEASE_REVOKE_DOMAIN, {k: base[k] for k in _REV_KEYS}, secret)}


def sign_blueprint(secret: bytes, b: Any) -> dict:
    """Sign a blueprint record with the operator's secret. Raises on a malformed record."""
    base = {"v": 1, **_spread(b), "operator": signer_of(secret)}
    if not _bp_wf(base):
        raise ValueError("signBlueprint: a malformed blueprint")
    return {**base, "sig": sign_body(AGENT_BLUEPRINT_DOMAIN, _bp_body(base), secret)}


def sign_break_glass(secret: bytes, b: Any) -> dict:
    base = {"v": 1, **_spread(b), "authority": signer_of(secret)}
    if not _bg_wf(base):
        raise ValueError("signBreakGlass: malformed, or the window is longer than 24 hours, or the budget is outside 1..16")
    return {**base, "sig": sign_body(BREAK_GLASS_DOMAIN, {k: base[k] for k in _BG_KEYS}, secret)}


def sign_break_glass_review(secret: bytes, r: Any) -> dict:
    base = {"v": 1, **_spread(r), "reviewer": signer_of(secret)}
    if not _rv_well_formed(base):
        raise ValueError("signBreakGlassReview: malformed")
    return {**base, "sig": sign_body(BREAK_GLASS_REVIEW_DOMAIN, {k: base[k] for k in _RV_KEYS}, secret)}


# ---- policy bundles -----------------------------------------------------------------------------------------------------

def _shadow_error(b: Any) -> Optional[str]:
    s = b.get("shadow") if is_obj(b) else None
    if not (is_obj(b) and "shadow" in b):
        return None
    if not isinstance(s, list) or len(s) == 0 or len(s) > 16 or not all(is_str(g, 128) for g in s) or len(set(s)) != len(s):
        return "bad shadow"
    return None


def bundle_shape_error_full(b: Any) -> Optional[str]:
    """The reference's complete shape check: ``k3.bundle_shape_error`` plus the ``shadow`` member (a list of 1 to 16 distinct digests)."""
    return bundle_shape_error(b) or _shadow_error(b)


def verify_bundle(b: Any, signers: Any, threshold: Any, verifier_version: Any, last: Any = None) -> dict:
    """:func:`atlas_pca.k3.verify_bundle` with the ``shadow`` member checked too (a malformed one is ``malformed``)."""
    try:
        e = bundle_shape_error_full(b)
    except Exception:
        e = "not a policy bundle"
    if e:
        return {"ok": False, "code": "malformed", "reason": e}
    return _verify_bundle_core(b, signers, threshold, verifier_version, last)


def sign_bundle(body: Any, secret: bytes) -> dict:
    """One signer's signature over the bundle body: ``{signer, sig}``. Collect k of them and call :func:`assemble_bundle`."""
    e = bundle_shape_error_full(body)
    if e:
        raise ValueError("signBundle: " + e)
    return {"signer": signer_of(secret), "sig": sign_body(BUNDLE_DOMAIN, _without(body, "sigs"), secret)}


def assemble_bundle(body: dict, sigs: list) -> dict:
    return {**_without(body, "sigs"), "sigs": sigs}


# ---- decision records ---------------------------------------------------------------------------------------------------

def mask_record(r: dict, mask_classes: Sequence[str]) -> dict:
    """Mask by data CLASS: every detail field whose class is in ``mask_classes`` becomes a commitment."""
    if not _truthy(r.get("detail")) or not _truthy(r.get("classes")):
        return r
    classes = r["classes"]
    detail: Dict[str, Any] = {}
    for k, v in _entries(r["detail"]):
        cls = classes.get(k) if isinstance(classes, dict) else None
        detail[k] = "masked:%s:%s" % (cls, hash_canonical({"d": "atlas-pca/mask/v1", "k": k, "v": v})) \
            if cls is not None and cls in mask_classes else v
    return {**r, "detail": detail}


def merkle_proof(leaves: List[Any], index: Any) -> dict:
    """RFC 6962 audit path of leaf ``index``: ``{index, size, path: [{side, hash}]}``. Raises on an index out of range."""
    if isinstance(index, bool) or not isinstance(index, (int, float)) or index != index or index in (float("inf"), float("-inf")) \
            or int(index) != index or index < 0 or index >= len(leaves):
        raise ValueError("merkleProof: index out of range")
    path: List[Dict[str, str]] = []

    def prove(hs: List[bytes], idx: int) -> None:
        if len(hs) == 1:
            return
        k = _split(len(hs))
        if idx < k:
            prove(hs[:k], idx)
            path.append({"side": "R", "hash": b64u(_build(hs[k:]))})
        else:
            prove(hs[k:], idx - k)
            path.append({"side": "L", "hash": b64u(_build(hs[:k]))})

    prove([_leaf_hash(x) for x in leaves], int(index))
    return {"index": index, "size": len(leaves), "path": path}


class DecisionLog:
    """Append-only decision log: hash-chained, Merkle-committed, with signed heads and inclusion proofs."""

    def __init__(self, secret: bytes, mask_classes: Optional[Sequence[str]] = None) -> None:
        self._secret = secret
        self._mask = list(mask_classes) if mask_classes is not None else []
        self._recs: List[dict] = []

    @property
    def size(self) -> int:
        return len(self._recs)

    @property
    def signer(self) -> str:
        return signer_of(self._secret)

    def append(self, r: dict) -> dict:
        masked = mask_record(r, self._mask)
        rec = {"v": 1, **masked, "seq": len(self._recs), "prev": record_commit(self._recs[-1]) if self._recs else ""}
        self._recs.append(rec)
        return rec

    def head(self, now: Any) -> dict:
        last = self._recs[-1] if self._recs else None
        base = {"v": 1, "size": len(self._recs), "root": merkle_root([record_commit(r) for r in self._recs]),
                "last_commit": record_commit(last) if last is not None else "", "issued_at": now, "signer": self.signer}
        return {**base, "sig": sign_body(LOG_HEAD_DOMAIN, base, self._secret)}

    def proof(self, seq: Any) -> dict:
        return merkle_proof([record_commit(r) for r in self._recs], seq)

    def slice(self, start: int, end: int) -> List[dict]:
        return self._recs[start:end]


def next_batch(log: DecisionLog, from_: Any, max_: Any, now: Any) -> dict:
    """The next batch of at most ``max_`` records starting at ``from_`` (the stream cursor) with a freshly signed head."""
    if not _is_safe_int(from_) or from_ < 0 or not _is_safe_int(max_) or max_ < 1:
        raise ValueError("nextBatch: bad cursor or size")
    return {"from": from_, "records": log.slice(int(from_), int(from_) + int(max_)), "head": log.head(now)}


_RANK = {"deny": 0, "escalate": 1, "allow": 2}


def _rank(x: Any) -> Optional[int]:
    return _RANK.get(x) if isinstance(x, str) else None


def _gt(a: Optional[int], b: Optional[int]) -> bool:
    return a is not None and b is not None and a > b


def semantic_diff(cases: List[dict], old_decide: Callable[[Any], Any], new_decide: Callable[[Any], Any]) -> List[dict]:
    """"What would have changed": re-run the pure decision function over recorded traffic under two revisions. Analysis tooling."""
    out = []
    for c in cases:
        before = old_decide(c["input"])
        after = new_decide(c["input"])
        if before != after:
            out.append({"action_digest": c["action_digest"], "before": before, "after": after,
                        "direction": "widened" if _gt(_rank(after), _rank(before)) else "tightened"})
    return out


def audit_replay(records: List[dict], cases: List[dict], decide: Callable[[Any, Any], Any]) -> List[dict]:
    """Records whose logged decision differs from a replay under their own revision's decide function (tamper or drift)."""
    by_action = {c["action_digest"]: c["input"] for c in cases}
    return [r for r in records if r["action_digest"] in by_action and decide(by_action[r["action_digest"]], r["bundle_revision"]) != r["decision"]]


# ---- consistency tokens (issuing side) ----------------------------------------------------------------------------------

def _fresh_body(t: dict) -> dict:
    return {"v": t["v"], "scope": t["scope"], "revocation_epoch": t["revocation_epoch"], "ledger_tree_size": t["ledger_tree_size"],
            "budget_version": t["budget_version"], "policy_revision": t["policy_revision"], "policy_digest": t["policy_digest"],
            "issued_at": t["issued_at"], "signer": t["signer"]}


def sign_fresh_at(secret: bytes, scope: Any, state: dict, issued_at: Any) -> dict:
    ok = is_str(scope, 256) and is_str(state.get("policy_digest"), 128) and all(is_uint(state.get(k)) for k in FRESH_AT_NUMERIC) and is_uint(issued_at)
    if not ok:
        raise ValueError("signFreshAt: a malformed state")
    base = {"v": 1, "scope": scope, **state, "issued_at": issued_at, "signer": signer_of(secret)}
    return {**base, "sig": sign_body(FRESH_AT_DOMAIN, _fresh_body(base), secret)}


def merge_fresh_at(a: dict, b: dict) -> dict:
    """Field-wise maximum of two states (the client-side fold). Equal revisions with different digests keep ``a``'s digest."""
    return {
        "revocation_epoch": max(a["revocation_epoch"], b["revocation_epoch"]),
        "ledger_tree_size": max(a["ledger_tree_size"], b["ledger_tree_size"]),
        "budget_version": max(a["budget_version"], b["budget_version"]),
        "policy_revision": max(a["policy_revision"], b["policy_revision"]),
        "policy_digest": b["policy_digest"] if b["policy_revision"] > a["policy_revision"] else a["policy_digest"],
    }


def gate_decision(decision: str, v: dict) -> str:
    """Compose a freshness verdict into a decision: it can only tighten (allow -> escalate/deny), never loosen."""
    if decision == "deny" or v.get("decision") == "deny":
        return "deny"
    if v.get("decision") == "escalate":
        return "escalate"
    return decision


class FreshAtIssuer:
    """Verifier-side state holder: advance on every write, mint the token for the write, check incoming tokens."""

    def __init__(self, secret: bytes, scope: str, initial: dict) -> None:
        self._secret = secret
        self.scope = scope
        self._state = dict(initial)

    @property
    def current(self) -> dict:
        return dict(self._state)

    def advance(self, patch: dict, now: Any) -> dict:
        """Apply a write (any subset of counters; each only moves forward) and return its token."""
        self._state = merge_fresh_at(self._state, {**self._state, **patch})
        return sign_fresh_at(self._secret, self.scope, self._state, now)

    def check(self, token: Any, now: Any, max_token_age_ms: Any = None) -> dict:
        return check_fresh_at(token, self._state, signer_of(self._secret), self.scope, now, max_token_age_ms)


# ---- leases: renewal ----------------------------------------------------------------------------------------------------

def renew_lease(secret: bytes, registry: LeaseRegistry, lease_id: str, now: Any, increment: Any, justification_digest: str,
                approvers: Optional[list] = None, veto: Optional[Callable[[dict], bool]] = None,
                chain: Optional[Sequence[str]] = None) -> dict:
    """Authority side: sign and register the next record of a lease. ``veto(current) is True`` refuses a renewal; it can never lengthen one."""
    if not is_uint(now) or not is_uint(increment) or increment < 1:
        return {"ok": False, "code": "bad_input"}
    cur = registry.get(lease_id)
    if cur is None:
        return {"ok": False, "code": "unknown_lease"}
    if veto is not None and veto(cur) is True:
        return {"ok": False, "code": "vetoed"}
    expires = min(now + increment, lease_cap(cur))
    rest = _without(cur, "v", "sig", "authority")
    try:
        record = sign_lease(secret, {**rest, "seq": cur["seq"] + 1, "renewed_at": now, "expires_at": expires,
                                     "justification_digest": justification_digest, "approvers": approvers if approvers is not None else cur["approvers"]})
    except Exception:
        return {"ok": False, "code": "expired_lease" if expires <= now else "bad_input"}
    r = registry.accept(record, chain if chain is not None else ())
    return {"ok": True, "record": record} if r["ok"] else {"ok": False, "code": r["code"]}


# ---- blueprints: group kill and attestation-gated admission ---------------------------------------------------------------

def group_kill(secret: bytes, registry: Any, key: str, now: Any, reason: Optional[str] = None, revocation: Any = None,
               fresh_at: Any = None) -> dict:
    """GROUP KILL: the operator signs the blueprint as ``disabled`` at the next epoch; the registry accepts it and, when given
    ``revocation`` (an object with ``revoke({kind, value, reason, revokedAt})``), also revokes the blueprint key as an issuer; when
    given ``fresh_at`` (a :class:`FreshAtIssuer`) its ``revocation_epoch`` advances to the record's epoch and the token is returned."""
    cur = registry.get(key)
    if cur is None:
        return {"ok": False, "code": "unknown_blueprint"}
    record = sign_blueprint(secret, {**_without(cur, "sig", "operator", "v"), "status": "disabled", "epoch": cur["epoch"] + 1, "issued_at": now})
    r = registry.accept(record)
    if not r["ok"]:
        return r
    if revocation is not None:
        revocation.revoke({"kind": "issuer", "value": key, "reason": reason if reason is not None else "blueprint disabled (group kill)", "revokedAt": now})
    out: Dict[str, Any] = {"ok": True, "record": record}
    if fresh_at is not None:
        out["freshAt"] = fresh_at.advance({"revocation_epoch": record["epoch"]}, now)
    return out


def _pin_matches(pin: Any, ident: Any) -> bool:
    ents = _entries(pin)
    missing = object()
    return len(ents) > 0 and all(v is not None and (ident.get(k, missing) if isinstance(ident, dict) else missing) == v for k, v in ents)


def admit_with_evidence(blueprint: dict, get_evidence: Callable[[], Any]) -> dict:
    """Admit from adapter evidence ``{ok, bound, identity?, reason?}``: ``ok`` and ``bound`` must both be exactly True, and the
    identity the adapter established must match one runtime pin. A raised error or malformed result denies."""
    pins = blueprint.get("runtime_pins")
    if pins is None or len(pins) == 0:
        return {"admitted": False, "code": "no_pins"}
    try:
        r = get_evidence()
    except Exception as e:  # noqa: BLE001 - a verifier that throws is a denial
        return {"admitted": False, "code": "verifier_error", "reason": type(e).__name__}
    g = (lambda k: r.get(k)) if isinstance(r, dict) else (lambda k: None)
    if g("ok") is not True:
        return {"admitted": False, "code": "not_ok", **({"reason": g("reason")} if isinstance(g("reason"), str) else {})}
    if g("bound") is not True:
        return {"admitted": False, "code": "not_bound"}
    ident = g("identity")
    if not isinstance(ident, (dict, list)):
        return {"admitted": False, "code": "no_identity"}
    for p in pins:
        if _pin_matches(p, ident):
            return {"admitted": True, "identity": ident, "pin": p}
    return {"admitted": False, "code": "no_matching_pin"}


def admit_blueprint_instance(blueprint: dict, document: Any, verifier: Callable[[dict], Any], now_ms: Any, ctx: Any = None,
                             expected: Any = None) -> dict:
    """Admit through a hardware attestation verifier: ``verifier({document, ctx, nowMs, expected})`` returns
    ``{ok, bound, measured?, reason?}``. No pins or no evidence is a denial."""
    pins = blueprint.get("runtime_pins")
    if pins is None or len(pins) == 0:
        return {"admitted": False, "code": "no_pins"}
    if document is None:
        return {"admitted": False, "code": "not_ok", "reason": "no evidence"}

    def evidence() -> dict:
        h = verifier({"document": document, "ctx": ctx, "nowMs": now_ms, "expected": expected})
        g = (lambda k: h.get(k)) if isinstance(h, dict) else (lambda k: None)
        out: Dict[str, Any] = {"ok": g("ok") is True, "bound": g("bound") is True}
        if g("measured"):
            out["identity"] = g("measured")
        if isinstance(g("reason"), str):
            out["reason"] = g("reason")
        return out

    return admit_with_evidence(blueprint, evidence)


class AdmissionRegistry:
    """Holds admissions by instance key, blueprint key and the blueprint EPOCH they were made under; plug ``checker(now)`` into the check as ``admitted``."""

    def __init__(self) -> None:
        self._m: Dict[str, Dict[str, Any]] = {}

    def admit(self, instance_key: str, bp: dict, until: Any) -> None:
        self._m["%s\0%s" % (bp["key"], instance_key)] = {"epoch": bp["epoch"], "until": until}

    def revoke(self, instance_key: str, bp_key: str) -> bool:
        return self._m.pop("%s\0%s" % (bp_key, instance_key), None) is not None

    def checker(self, now: Any) -> Callable[[str, dict], bool]:
        def check(instance_key: str, bp: dict) -> bool:
            a = self._m.get("%s\0%s" % (bp["key"], instance_key))
            return a is not None and a["epoch"] == bp["epoch"] and now < a["until"]
        return check


# ---- lease store conformance kit --------------------------------------------------------------------------------------------

class LeaseStoreConformanceError(Exception):
    """A lease store failed a conformance check (``lease store conformance: <check>: <detail>``)."""


_SK = bytes([61]) * 32
_T0 = 1_800_000_000_000
_DAY = 86_400_000


def _mk(lease_id: str, **over: Any) -> dict:
    base = {"lease_id": lease_id, "path": "svc/%d/%s" % (len(lease_id) % 3, lease_id), "grant_ref": "g-" + lease_id, "holder": "agent",
            "requester": "alice", "approvers": ["bob"], "justification_digest": "j1", "seq": 1, "issued_at": _T0, "renewed_at": _T0,
            "expires_at": _T0 + 600_000, "max_ttl": 3_600_000}
    base.update(over)
    return base


def _fail(check: str, detail: str) -> None:
    raise LeaseStoreConformanceError("lease store conformance: %s: %s" % (check, detail))


def _expect_eq(check: str, got: Any, want: Any) -> None:
    if json.dumps(got, sort_keys=True) != json.dumps(want, sort_keys=True):
        _fail(check, "got %s, want %s" % (json.dumps(got, sort_keys=True), json.dumps(want, sort_keys=True)))


def run_lease_store_conformance(open_: Callable[[], Any], reopen: Optional[Callable[[Any], Any]] = None, shards: int = 16) -> List[str]:
    """Run against any lease key-value store (``get(key)`` and an atomic ``update(key, fn)``) before trusting it with leases.
    ``open_()`` returns a fresh empty store; ``reopen(kv)`` the same store opened again as a restarted process would (omit to skip the
    restart check). Raises :class:`LeaseStoreConformanceError` on the first failure and returns the names of the checks passed."""
    passed: List[str] = []
    auth = signer_of(_SK)
    policy = {"authorities": [auth]}

    # 1. spread
    reg = LeaseRegistry(policy, open_(), shards=shards)
    ids = ["lease-%d" % i for i in range(256)]
    for i in ids:
        _expect_eq("spread: issue " + i, reg.accept(sign_lease(_SK, _mk(i)))["ok"], True)
    per = [0] * shards
    for i in ids:
        per[shard_of(i, shards)] += 1
    if max(per) > len(ids) / 4 or len([n for n in per if n > 0]) < shards / 2:
        _fail("spread", "256 leases landed %s" % json.dumps(per))
    for i in ids:
        got = reg.get(i)
        if got is None or got["lease_id"] != i:
            _fail("spread", "%s not found after issue" % i)
    passed.append("spread")

    # 2. atomic update: of many concurrent renewals of one lease exactly one wins and the rest are forks
    reg = LeaseRegistry(policy, open_(), shards=shards)
    reg.accept(sign_lease(_SK, _mk("hot")))
    rivals = [sign_lease(_SK, _mk("hot", seq=2, renewed_at=_T0 + 1000, expires_at=_T0 + 700_000 + i, justification_digest="r%d" % i)) for i in range(8)]
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(reg.accept, rivals))
    _expect_eq("atomic: one winner", len([r for r in results if r["ok"]]), 1)
    _expect_eq("atomic: the rest are forks", len([r for r in results if not r["ok"] and r["code"] == "lease_fork"]), 7)
    _expect_eq("atomic: ledger length", [h["seq"] for h in reg.history("hot")], [1, 2])
    passed.append("atomic update")

    # 3. independence
    reg = LeaseRegistry(policy, open_(), shards=shards)
    ids = ["ind-%d" % i for i in range(32)]
    for i in ids:
        reg.accept(sign_lease(_SK, _mk(i)))
    renewed = [reg.accept(sign_lease(_SK, _mk(i, seq=2, renewed_at=_T0 + 10, expires_at=_T0 + 900_000, justification_digest="j2"))) for i in ids]
    _expect_eq("independence", all(r["ok"] for r in renewed), True)
    passed.append("independent leases")

    # 4 + 5. revocation placement
    reg = LeaseRegistry(policy, open_(), shards=shards)
    ids = ["rv-%d" % i for i in range(64)]
    for i in ids:
        reg.accept(sign_lease(_SK, _mk(i, path="db/prod/ro")))
    lone = sign_lease(_SK, _mk("lone", path="other/x"))
    reg.accept(lone)
    by_lease = sign_lease_revocation(_SK, {"target": "lease", "value": "lone", "revoked_at": _T0 + 5})
    _expect_eq("revoke by lease", reg.revoke(by_lease), {"ok": True, "revoked": 1})
    holders = sum(1 for i in range(shards) if len(reg.shard_revocations(i)) > 0)
    _expect_eq("lease revocation lands in exactly one shard", holders, 1)
    _expect_eq("revoked lease is dead", check_lease(lone, reg, _T0 + 6)["decision"], "deny")
    by_prefix = sign_lease_revocation(_SK, {"target": "prefix", "value": "db/prod", "revoked_at": _T0 + 10})
    _expect_eq("revoke by prefix covers every lease in every shard", reg.revoke(by_prefix), {"ok": True, "revoked": 64})
    _expect_eq("revoke twice is idempotent", reg.revoke(by_prefix), {"ok": True, "revoked": 64})
    for i in range(shards):
        lst = reg.shard_revocations(i)
        if not any(r["sig"] == by_prefix["sig"] for r in lst):
            _fail("prefix revocation in every shard", "shard %d lacks it" % i)
        _expect_eq("no duplicate in shard %d" % i, len([r for r in lst if r["sig"] == by_prefix["sig"]]), 1)
    for i in ids:
        cur = reg.get(i)
        _expect_eq("check " + i, check_lease(cur, reg, _T0 + 11)["decision"], "deny")
        _expect_eq("renewal of %s refused" % i, reg.accept(sign_lease(_SK, _mk(i, path="db/prod/ro", seq=2, renewed_at=_T0 + 20, expires_at=_T0 + 700_000, justification_digest="x")))["ok"], False)
    fresh = sign_lease(_SK, _mk("after", path="db/prod/ro", issued_at=_T0 + 100, renewed_at=_T0 + 100, expires_at=_T0 + 900_000))
    _expect_eq("a lease issued after the revocation is new", reg.accept(fresh)["ok"], True)
    passed.append("revocation placement")

    # 6. shard-count mismatch
    kv = open_()
    LeaseRegistry(policy, kv, shards=shards).accept(sign_lease(_SK, _mk("m1")))
    other = LeaseRegistry(policy, kv, shards=shards * 2)
    _expect_eq("shard mismatch accept", other.accept(sign_lease(_SK, _mk("m2"))), {"ok": False, "code": "store_unreachable"})
    _expect_eq("shard mismatch check", check_lease(sign_lease(_SK, _mk("m1")), other, _T0 + 1)["decision"], "deny")
    passed.append("shard count is pinned")

    # 7. restart
    if reopen is not None:
        kv = open_()
        reg = LeaseRegistry(policy, kv, shards=shards)
        l = sign_lease(_SK, _mk("persist"))
        reg.accept(l)
        reg.accept(sign_lease(_SK, _mk("persist", seq=2, renewed_at=_T0 + 5, expires_at=_T0 + 800_000, justification_digest="j2")))
        reg.revoke(sign_lease_revocation(_SK, {"target": "prefix", "value": "gone", "revoked_at": _T0 + 50}))
        again = LeaseRegistry(policy, reopen(kv), shards=shards)
        _expect_eq("restart: renewal ledger", [h["seq"] for h in again.history("persist")], [1, 2])
        _expect_eq("restart: revocation kept", len(again.shard_revocations(0)), 1)
        _expect_eq("restart: old record still superseded", check_lease(l, again, _T0 + 6)["decision"], "deny")
        passed.append("state survives a restart")

    # 8. ceiling and pruning
    now = [_T0]
    reg = LeaseRegistry({"authorities": [auth], "maxTtlCeiling": _DAY}, open_(), shards=shards, clock=lambda: now[0])
    _expect_eq("ceiling refuses a longer max_ttl", reg.accept(sign_lease(_SK, _mk("big", max_ttl=_DAY + 1, expires_at=_T0 + 1000))), {"ok": False, "code": "ttl_ceiling"})
    reg.accept(sign_lease(_SK, _mk("small", max_ttl=_DAY)))
    reg.revoke(sign_lease_revocation(_SK, {"target": "prefix", "value": "svc", "revoked_at": _T0}))
    for i in range(shards):
        _expect_eq("kept before the ceiling passes (shard %d)" % i, len(reg.shard_revocations(i)), 1)
    now[0] = _T0 + _DAY + 1
    reg.accept(sign_lease(_SK, _mk("trigger", issued_at=now[0], renewed_at=now[0], expires_at=now[0] + 1000, max_ttl=5000)))
    reg.revoke(sign_lease_revocation(_SK, {"target": "prefix", "value": "zzz", "revoked_at": now[0]}))
    for i in range(shards):
        left = [r["value"] for r in reg.shard_revocations(i)]
        if "svc" in left:
            _fail("pruning", "shard %d still holds the expired revocation" % i)
        if "zzz" not in left:
            _fail("pruning", "shard %d lost the fresh revocation" % i)
    passed.append("pruning bounds revocations")
    return passed
