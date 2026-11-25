"""The undo-window coordinator (the TypeScript ``server/undo``): admission, the durable ledger, the human surface and the real rollback.

    admit      ELIGIBILITY. An action gets a veto window only when the policy does not turn windows off, its signed reversibility class is
               ``reversible``, the `engine` (the verifier's own CONFIRMED action definitions) returns a plan, and the compensating action is
               AUTHORIZED under the original grant (the policy VM releases it over the original PCActn's verified chain).
    open       writes the record DURABLY before the effect may run (a store that is not durable is refused), signs the ``opened`` receipt,
               mints the one-click undo token and notifies the principal. A window nobody was told about is no window: a failed notification
               aborts the record and raises an alert.
    veto       a valid token (or an operator, a fraud proof, a revocation policy) inside the window moves ``open -> vetoed`` exactly once and
               starts the compensation.
    compensate re-decides the compensating action under the grant AS IT STOOD AT ADMISSION, then runs it at most once per attempt through
               the ``operations`` store and the `compensate` executor. Success: ``compensated`` and the budget reservation released.
               Anything else: ``compensation_failed``, the reservation kept and an alert raised (never silent).
    finalize_due closes the windows whose time is up (``open -> finalized``) and commits their budget reservations.

Synchronous (the reference is promise based; every injected callable here is a plain callable). The budget ledger (``commit(key, id)`` and
``release(key, id, evidence)`` returning ``{"outcome": "settled" | "replayed" | ...}``) and the bond ledger (``slash_bond(params)``) are the
interfaces of :mod:`atlas_pca.store_conformance_profiles`; records are dicts with the reference's member names."""
import copy
import json
import time
from typing import Any, Callable, Dict, List, Optional, Sequence

from .agent import KeyPair
from .authorize import read_envelope  # noqa: F401
from .gateway import decode_pcactn
from .pca import b64u, canonicalize, hash_canonical
from .policy_vm import decide
from .revocation_staleness import class_rank
from .undo import (UNDO_STATES, UndoError, compensation_digest, decode_undo_token, encode_undo_token, resolve_undo_window, sign_undo_token,
                   undo_token_check, undo_token_digest, undo_transition, with_receipt)

__all__ = ["MemoryUndoStore", "KvUndoStore", "is_undo_store", "missing_undo_components", "create_undo_coordinator", "report_undo_effect",
           "undo_signer_public", "hosted_undo_veto_relay", "UNDO_RELAY_GRACE_MS", "undo_notifier_from_dispatcher"]

_MAX_CAS = 64
#: With a veto relay, a window is finalized only this long after it ended (a veto in flight at the relay still lands).
UNDO_RELAY_GRACE_MS = 60_000
_PREFIX = "pca-undo/v1/"


def _id_ok(i: Any) -> bool:
    return isinstance(i, str) and len(i) > 0 and not any(ord(c) < 0x20 or ord(c) == 0x7F for c in i)


def _matches(r: dict, q: dict) -> bool:
    return (r["state"] == q["state"] and (q.get("windowEndedBy") is None or r["window_end"] <= q["windowEndedBy"])
            and (q.get("grantRef") is None or r["grant_ref"] == q["grantRef"]) and (q.get("bondRef") is None or r.get("bond_ref") == q["bondRef"]))


def is_undo_store(s: Any) -> bool:
    return s is not None and all(callable(getattr(s, m, None)) for m in ("get", "create", "replace", "list")) and isinstance(getattr(s, "durable", None), bool)


class MemoryUndoStore:
    """A process-memory store: ``durable`` is False, so the coordinator refuses it unless a test says it accepts losing every open window on
    restart. Never use it in production."""

    durable = False

    def __init__(self) -> None:
        self._m: Dict[str, dict] = {}

    def get(self, id: str) -> Optional[dict]:  # noqa: A002
        r = self._m.get(id)
        return copy.deepcopy(r) if r is not None else None

    def create(self, rec: dict) -> dict:
        if not _id_ok(rec.get("id") if isinstance(rec, dict) else None):
            raise UndoError("invalid", "an undo record id is a non-empty string without control characters")
        cur = self._m.get(rec["id"])
        if cur is not None:
            return {"created": False, "record": copy.deepcopy(cur)}
        self._m[rec["id"]] = copy.deepcopy(rec)
        return {"created": True}

    def replace(self, id: str, expected_ver: int, nxt: dict) -> bool:  # noqa: A002
        if nxt["id"] != id:
            raise UndoError("invalid", "replace: the record id cannot change")
        cur = self._m.get(id)
        if cur is None or cur["ver"] != expected_ver:
            return False
        self._m[id] = copy.deepcopy(nxt)
        return True

    def list(self, q: dict) -> List[dict]:
        out = sorted((r for r in self._m.values() if _matches(r, q)), key=lambda r: r["id"].encode("utf-16-be", "surrogatepass"))
        return copy.deepcopy(out[:q["limit"]] if q.get("limit") is not None else out)


def _decode_record(raw: Any) -> Optional[dict]:
    if raw is None:
        return None
    if not isinstance(raw, dict) or raw.get("v") != 1 or not _id_ok(raw.get("id")) or raw.get("state") not in UNDO_STATES \
            or isinstance(raw.get("ver"), bool) or not isinstance(raw.get("ver"), int) or not isinstance(raw.get("receipts"), list):
        raise UndoError("store_corrupt", "an undo record has the wrong shape")
    return raw


class KvUndoStore:
    """The reference store over any atomic key-value store (:class:`atlas_pca.SqliteAtomicKv` or :class:`atlas_pca.MemoryAtomicKv`): one
    document per record, every write one atomic read-modify-write. `durable` is declared by the caller (True only over a persistent kv).
    shortcut: ``list`` scans every key (fine for a single host's backlog); a database store indexes (state, window_end)."""

    def __init__(self, kv: Any, durable: bool) -> None:
        if kv is None or not all(callable(getattr(kv, m, None)) for m in ("get", "update", "keys")):
            raise UndoError("store_missing", "KvUndoStore needs an atomic kv with get, update and keys")
        if not isinstance(durable, bool):
            raise UndoError("invalid", "say whether the kv is durable (True or False)")
        self._kv, self.durable = kv, durable

    def _k(self, id: str) -> str:  # noqa: A002
        if not _id_ok(id):
            raise UndoError("invalid", "an undo record id is a non-empty string without control characters")
        return _PREFIX + id

    def get(self, id: str) -> Optional[dict]:  # noqa: A002
        r = _decode_record(self._kv.get(self._k(id)))
        return copy.deepcopy(r) if r is not None else None

    def create(self, rec: dict) -> dict:
        seen: List[Any] = []

        def fn(prev: Any) -> Any:
            existing = _decode_record(prev)
            seen.append(existing)
            return None if existing else copy.deepcopy(rec)
        self._kv.update(self._k(rec["id"]), fn)
        return {"created": False, "record": copy.deepcopy(seen[0])} if seen and seen[0] else {"created": True}

    def replace(self, id: str, expected_ver: int, nxt: dict) -> bool:  # noqa: A002
        if nxt["id"] != id:
            raise UndoError("invalid", "replace: the record id cannot change")
        done = [False]

        def fn(prev: Any) -> Any:
            cur = _decode_record(prev)
            done[0] = cur is not None and cur["ver"] == expected_ver
            return copy.deepcopy(nxt) if done[0] else None
        self._kv.update(self._k(id), fn)
        return done[0]

    def list(self, q: dict) -> List[dict]:
        out: List[dict] = []
        for key in sorted(k for k in self._kv.keys() if k.startswith(_PREFIX)):
            r = _decode_record(self._kv.get(key))
            if r and _matches(r, q):
                out.append(copy.deepcopy(r))
            if q.get("limit") is not None and len(out) >= q["limit"]:
                break
        return out


def missing_undo_components(o: Any) -> List[str]:
    """The names of the required coordinator components that are absent or malformed."""
    x = o if isinstance(o, dict) else {}
    m: List[str] = []
    if not is_undo_store(x.get("store")):
        m.append("store")
    if x.get("engine") is None or not callable(getattr(x["engine"], "plan", None)):
        m.append("engine")
    if not isinstance(x.get("signerSecret"), (bytes, bytearray)) or len(x["signerSecret"]) != 32:
        m.append("signerSecret")
    if not isinstance(x.get("audience"), str) or len(x["audience"]) == 0:
        m.append("audience")
    for k in ("resolveGrant", "compensate", "alert"):
        if not callable(x.get(k)):
            m.append(k)
    ops = x.get("operations")
    if ops is None or not all(callable(getattr(ops, n, None)) for n in ("create", "get", "transition")):
        m.append("operations")
    if x.get("notifier") is None or not callable(getattr(x["notifier"], "notify", None)):
        m.append("notifier")
    return m


def _strip(r: dict) -> dict:
    return {k: v for k, v in r.items() if k not in ("pcactn", "receipts")}


def undo_signer_public(secret: bytes) -> str:
    """The undo service key's public half, for verifying tokens and receipts elsewhere."""
    return KeyPair(bytes(secret)).public


def create_undo_coordinator(*, store: Any, engine: Any, signerSecret: bytes, audience: str, resolveGrant: Callable[[str, dict], Optional[dict]],  # noqa: N803
                            compensate: Callable[[dict], Any], operations: Any, notifier: Any, alert: Callable[[dict], Any],
                            policy: Optional[Callable[[dict, dict], Optional[dict]]] = None, window: Optional[dict] = None,
                            resolveTarget: Optional[Callable[[dict], Optional[str]]] = None, budget: Optional[dict] = None,  # noqa: N803
                            pqPins: Any = None, effectTimeoutMs: int = 5 * 60_000, now: Optional[Callable[[], float]] = None,  # noqa: N803
                            relay: Any = None, insecureVolatileStore: bool = False, bonds: Any = None) -> "UndoCoordinator":  # noqa: N803
    """Build the coordinator. The keyword names are the reference's option names. Raises ``config`` for a missing component and
    ``not_durable`` for a volatile store (fail closed). `engine.plan(op, {"operationId"})` returns a plan or None; `compensate(call)` runs the
    compensating action (raise on failure); `budget` is a budget ledger (:class:`atlas_pca.budget_ledger.KvBudgetLedger`, or anything with ``commit(key, id)`` and
    ``release(key, id, evidence)``) or ``{"ledger", "evidence"?}``: a release carries no evidence unless ``evidence(reservation, reason)`` supplies it
    (for example a release signed with :func:`atlas_pca.budget_ledger.sign_release`). `bonds` is a bond ledger (:class:`atlas_pca.bond_settlement.StoreBondLedger`, or anything with
    ``slash_bond(params)``) used by :meth:`UndoCoordinator.rollback_on_slash`. `relay.pending()` lists vetoes received elsewhere."""
    opts = {"store": store, "engine": engine, "signerSecret": signerSecret, "audience": audience, "resolveGrant": resolveGrant, "compensate": compensate,
            "operations": operations, "notifier": notifier, "alert": alert}
    missing = missing_undo_components(opts)
    if missing:
        raise UndoError("config", "undo coordinator: missing required component(s): %s" % ", ".join(missing))
    if store.durable is not True and insecureVolatileStore is not True:
        raise UndoError("not_durable", "an undo ledger must be durable: a restart would lose every open window and its compensation")
    if not (isinstance(effectTimeoutMs, (int, float)) and not isinstance(effectTimeoutMs, bool) and effectTimeoutMs >= 0):
        raise UndoError("config", "undo coordinator: effectTimeoutMs must be a non-negative number")  # NaN is refused; +Infinity is the never-settle cap
    return UndoCoordinator(opts, policy=policy, window=window, resolve_target=resolveTarget, budget=budget, pq_pins=pqPins,
                           effect_timeout_ms=effectTimeoutMs, clock=now, relay=relay, bonds=bonds)


class UndoCoordinator:
    def __init__(self, o: dict, *, policy: Any, window: Any, resolve_target: Any, budget: Any, pq_pins: Any, effect_timeout_ms: int, clock: Any,
                 relay: Any, bonds: Any = None) -> None:
        self._o, self._policy, self._window, self._resolve_target = o, policy, window, resolve_target
        if budget is not None and not isinstance(budget, dict):
            budget = {"ledger": budget}
        self._budget, self._pq_pins, self._effect_timeout, self._relay = budget, pq_pins, effect_timeout_ms, relay
        self._bonds = bonds
        self._clock = clock or (lambda: time.time() * 1000)
        self._store, self._secret, self._engine = o["store"], bytes(o["signerSecret"]), o["engine"]
        self.signer_public = undo_signer_public(self._secret)

    # ---- plumbing ----
    def _now(self) -> int:
        t = self._clock()
        try:
            t = int(t // 1)
        except (OverflowError, ValueError):
            raise UndoError("invalid", "the clock returned a non-finite time") from None
        return t

    def _alert(self, a: dict) -> None:
        try:
            self._o["alert"](a)
        except Exception:  # noqa: BLE001 - an alert sink that throws is itself a failure the operator must see
            import sys
            sys.stderr.write("pca undo alert (%s) for %s: %s\n" % (a["code"], a["record"], a["reason"]))

    def _notify(self, n: dict) -> dict:
        try:
            r = self._o["notifier"].notify(n)
            return {"delivered": True} if isinstance(r, dict) and r.get("delivered") is True else \
                {"delivered": False, "reason": (r or {}).get("reason") if isinstance(r, dict) and r.get("reason") else "no channel delivered the notice"}
        except Exception as e:  # noqa: BLE001
            return {"delivered": False, "reason": str(e) or "notifier error"}

    def _apply(self, id: str, ev: dict, check_at: Optional[int] = None) -> dict:  # noqa: A002
        for _ in range(_MAX_CAS):
            cur = self._store.get(id)
            if cur is None:
                return {"refused": "unknown", "reason": "no undo record %s" % id}
            t = self._now()
            tr = undo_transition(cur, ev, t if check_at is None else check_at)  # a relayed veto is judged as of when the principal made it
            if tr["outcome"] == "refused":
                return {"refused": tr["code"], "reason": tr["reason"]}
            if tr["outcome"] == "replayed":
                return {"record": tr["record"], "applied": False}
            nxt = with_receipt(tr["record"], tr["receipt"], t, self._secret)
            if self._store.replace(id, cur["ver"], nxt):
                return {"record": nxt, "applied": True}
        raise UndoError("conflict_exhausted", "undo record %s kept changing" % id)

    def _must(self, id: str, ev: dict) -> dict:  # noqa: A002
        r = self._apply(id, ev)
        if "refused" in r:
            raise UndoError("invalid", "%s: %s" % (r["refused"], r["reason"]))
        return r

    def _settle_budget(self, rec: dict, how: str) -> None:
        b = self._budget
        if not b or not rec.get("budget"):
            return
        for r in rec["budget"]:
            try:
                if how == "commit":
                    o = b["ledger"].commit(r["key"], r["id"])
                else:
                    ev = b["evidence"](r, how) if callable(b.get("evidence")) else None  # no evidence unless the caller supplies it
                    o = b["ledger"].release(r["key"], r["id"], ev)
                if o.get("outcome") not in ("settled", "replayed"):
                    self._alert({"level": "warning", "code": "budget_settle_failed", "record": rec["id"],
                                 "reason": "%s of %s/%s: %s" % (how, r["key"], r["id"], o.get("outcome"))})
            except Exception as e:  # noqa: BLE001
                self._alert({"level": "warning", "code": "budget_settle_failed", "record": rec["id"],
                             "reason": "%s of %s/%s: %s" % (how, r["key"], r["id"], str(e) or "error")})

    def _policy_of(self, op: dict, grant: dict) -> dict:
        return ((self._policy(op, grant) or {}) if self._policy else {})

    def _compensation_allowed(self, pc: dict, grant: dict, op: dict, at: int) -> dict:
        d = decide({"grant": grant, "trustedRoot": grant, "chain": pc.get("cap_chain"), **({"pqPins": self._pq_pins} if self._pq_pins is not None else {}),
                    "action": {"action": {"verb": op["verb"], "resource": op["resource"], "params": op.get("params") or {}}}, "risk": {},
                    "budget": {"B": 0, "tau": at}, "now": at})
        if d["releaseGuardianShare"]:
            return {"ok": True, "reason": ""}
        return {"ok": False, "reason": next((r for r in d["reasons"] if not r.startswith("risk input")), "the grant does not authorize the compensating action")}

    # ---- the API ----
    def admit(self, pcactn: dict, operation: dict, converted: bool, grant: Optional[dict] = None) -> dict:
        """ELIGIBILITY: an admission dict, or ``{"refused": reason}``. Never raises."""
        try:
            pc, op = pcactn, operation
            if not pc or not op or not isinstance(op.get("verb"), str) or not isinstance(op.get("resource"), str):
                return {"refused": "no operation"}
            g = grant or self._o["resolveGrant"](pc.get("grant_ref"), pc)
            if not g:
                return {"refused": "unknown grant"}
            pol = self._policy_of(op, g)
            mode = pol.get("mode") or "always"
            if mode == "off":
                return {"refused": "policy: undo windows are off"}
            if mode == "escalations" and not converted:
                return {"refused": "policy: windows only replace approvals"}
            if class_rank((pc.get("action") or {}).get("reversibility_class")) != 0:  # the stricter of the signed class and the definition applies
                return {"refused": "the signed class is %s" % (pc.get("action") or {}).get("reversibility_class")}
            id_ = hash_canonical(pc)
            plan = self._engine.plan(op, {"operationId": id_})
            if not plan:
                return {"refused": "not confirmed reversible, or no confirmed compensating action"}
            comp = {"verb": plan["compensation"]["verb"], "resource": op["resource"], "params": copy.deepcopy(plan["compensation"]["params"]),
                    "undo_of": id_, "def_digest": plan["compensation"]["def_digest"]}
            if plan["compensation"].get("target_param") is not None:
                comp["target_param"] = plan["compensation"]["target_param"]
            t = self._now()
            allowed = self._compensation_allowed(pc, g, {"verb": comp["verb"], "resource": comp["resource"], "params": comp["params"]}, t)
            if not allowed["ok"]:
                return {"refused": "the compensating action is not authorized under the grant: %s" % allowed["reason"]}
            window_ms = resolve_undo_window(pol.get("windowMs"), self._window or {})
            return {"id": id_, "opened_at": t, "window_end": t + window_ms, "converted": converted, "plan": plan, "compensation": comp, "pcactn": pc,
                    "grant": g, "operation": {"verb": op["verb"], "resource": op["resource"], "params": copy.deepcopy(op.get("params") or {})}}
        except Exception as e:  # noqa: BLE001
            return {"refused": "undo admission error (fail closed): %s" % (str(e) or "unknown")}

    def _info_of(self, rec: dict) -> dict:
        return {"id": rec["id"], "window_end": rec["window_end"], "converted": rec["converted"],
                "compensation": {"verb": rec["compensation"]["verb"], "resource": rec["compensation"]["resource"]},
                "token": encode_undo_token(sign_undo_token(rec, self._secret)),
                "obligation": {"kind": "undo_window", "params": {"id": rec["id"], "window_end": rec["window_end"]}, "due": rec["window_end"]}}

    def open(self, adm: dict, bond: Optional[dict] = None) -> dict:
        """Write the record durably, sign the ``opened`` receipt, mint the one-click token and tell the principal. `bond` is
        ``{"ref", "challengeEndsAt"}``."""
        chain = adm["pcactn"]["cap_chain"]
        window_end = max(adm["window_end"], int(bond["challengeEndsAt"] // 1)) if bond else adm["window_end"]
        cdig = compensation_digest(adm["compensation"])
        base: Dict[str, Any] = {"v": 1, "id": adm["id"], "aud": self._o["audience"], "grant_ref": adm["pcactn"]["grant_ref"], "holder": chain[-1]["holder"],
                                "principal": adm["grant"]["issuer"],
                                "action": {"verb": adm["operation"]["verb"], "resource": adm["operation"]["resource"],
                                           "params_digest": adm["pcactn"]["action"]["params_digest"], "def_digest": adm["plan"]["def_digest"]},
                                "compensation": adm["compensation"], "compensation_digest": cdig}
        if adm["plan"].get("render_digest") is not None:
            base["render_digest"] = adm["plan"]["render_digest"]
        base.update({"opened_at": adm["opened_at"], "window_end": window_end, "converted": adm["converted"], "state": "open", "ver": 0,
                     "pcactn": canonicalize(adm["pcactn"])})
        if bond:
            base["bond_ref"] = bond["ref"]
        base.update({"attempt": 0, "receipts": []})
        rec = with_receipt(base, {"event": "opened", "note": "converted" if adm["converted"] else ""}, adm["opened_at"], self._secret)
        c = self._store.create(rec)
        if not c["created"]:
            # a retry of the same admission returns the same window; anything else is a different action under the same id
            if c["record"]["compensation_digest"] != cdig or c["record"]["state"] != "open":
                raise UndoError("invalid", "undo record %s already exists with other terms or state %s" % (adm["id"], c["record"]["state"]))
            return self._info_of(c["record"])
        info = self._info_of(rec)
        notice: Dict[str, Any] = {"kind": "opened", "record": _strip(rec), "token": info["token"]}
        if adm["plan"].get("render"):
            notice["render"] = adm["plan"]["render"]
        n = self._notify(notice)
        if not n["delivered"]:
            self._apply(rec["id"], {"kind": "abort", "reason": "notify_failed"})
            self._alert({"level": "critical", "code": "notify_failed", "record": rec["id"],
                         "reason": "the principal could not be told about the undo window: %s" % (n.get("reason") or "not delivered")})
            raise UndoError("invalid", "notify_failed: the undo window could not be announced (%s)" % (n.get("reason") or "not delivered"))
        return info

    def get(self, id: str) -> Optional[dict]:  # noqa: A002
        return self._store.get(id)

    def hold_budget(self, id: str, reservations: Sequence[dict]) -> dict:  # noqa: A002
        """Hold aggregate budget reservations ``[{"key", "id"}]`` until the window closes."""
        for _ in range(_MAX_CAS):
            cur = self._store.get(id)
            if cur is None:
                raise UndoError("invalid", "no undo record %s" % id)
            if cur["state"] not in ("open", "vetoed"):
                raise UndoError("invalid", "a %s record holds no budget" % cur["state"])
            nxt = dict(cur, budget=list(cur.get("budget") or []) + [{"key": r["key"], "id": r["id"]} for r in reservations], ver=cur["ver"] + 1)
            if self._store.replace(id, cur["ver"], nxt):
                return nxt
        raise UndoError("conflict_exhausted", "undo record %s kept changing" % id)

    def record_effect(self, id: str, result: Any = None, has_result: bool = False) -> dict:  # noqa: A002
        """Report the original effect (its result names the compensation target). A veto that arrived while it ran is acted on now."""
        ev: Dict[str, Any] = {"kind": "effect"}
        if has_result or result is not None:
            ev["result"] = result
        r = self._must(id, ev)
        return self._run_compensation(r["record"]) if r["record"]["state"] == "vetoed" else r["record"]

    def abort(self, id: str, reason: str) -> dict:  # noqa: A002
        r = self._must(id, {"kind": "abort", "reason": reason})
        if r["applied"]:
            self._settle_budget(r["record"], "effect_not_run")
        return r["record"]

    def _finish_compensated(self, rec: dict) -> dict:
        if rec["state"] == "compensated":
            self._settle_budget(rec, "rollback")
            self._notify({"kind": "compensated", "record": _strip(rec)})
        return rec

    def _run_compensation(self, rec0: dict) -> dict:
        rec = rec0
        if rec["state"] != "vetoed":
            return rec
        t = self._now()
        if rec.get("effect") is None and t - ((rec.get("veto") or {}).get("at", t)) < self._effect_timeout:
            return rec  # wait for the effect report (record_effect resumes)
        pc = decode_pcactn(rec["pcactn"])
        grant = self._o["resolveGrant"](rec["grant_ref"], pc)

        def fail(reason: str, code: str = "compensation_failed") -> dict:
            r = self._apply(rec["id"], {"kind": "compensation_failed", "reason": reason})
            out = (self._store.get(rec["id"]) or rec) if "refused" in r else r["record"]
            if "refused" not in r and r["applied"]:
                self._alert({"level": "critical", "code": code, "record": rec["id"], "reason": reason})
                self._notify({"kind": "compensation_failed", "record": _strip(out)})
            return out

        if not grant:
            return fail("the grant is no longer known: the compensation cannot be authorized", "compensation_denied")
        params: Dict[str, Any] = dict(rec["compensation"]["params"])
        tp = rec["compensation"].get("target_param")
        if tp is not None:
            if self._resolve_target:
                target = self._resolve_target(rec)
            else:
                res = (rec.get("effect") or {}).get("result")
                target = res["id"] if isinstance(res, dict) and isinstance(res.get("id"), str) and len(res["id"]) > 0 else None
            if target is None:
                return fail("the target '%s' of the compensation is unknown (no effect result names it)" % tp)
            params[tp] = target
        op = {"verb": rec["compensation"]["verb"], "resource": rec["compensation"]["resource"], "params": params}
        dec = self._compensation_allowed(pc, grant, op, rec["opened_at"])
        if not dec["ok"]:
            return fail("the compensating action is not authorized under the grant: %s" % dec["reason"], "compensation_denied")
        ops = self._o["operations"]
        # at most once per attempt: the operation record is created before the compensator runs
        op_id = hash_canonical({"d": "atlas-pca/undo-compensation-op/v1", "record": rec["id"], "attempt": rec["attempt"]})
        orec = {"id": op_id, "state": "pending", "verb": op["verb"], "resource": op["resource"], "params_digest": hash_canonical(params),
                "reversibility": "irreversible", "startedAt": t}
        prev = ops.create(orec)
        if prev is not None:
            if prev["state"] == "committed":
                r = self._apply(rec["id"], {"kind": "compensated", **({"result": prev["result"]} if "result" in prev else {})})
                rec = rec if "refused" in r else r["record"]
                return self._finish_compensated(rec)
            if prev["state"] in ("failed", "uncertain"):
                return fail("compensation attempt %s %s: %s" % (rec["attempt"], prev["state"], prev.get("error") or ""))
            if prev["state"] == "aborted":
                r = self._apply(rec["id"], {"kind": "compensation_failed", "reason": "attempt never started"})
                if "refused" in r:
                    return rec
                again = self._apply(rec["id"], {"kind": "retry"})
                return r["record"] if "refused" in again else self._run_compensation(again["record"])
            # pending / executing: another worker holds it, or a crash; stale ones are settled here
            if t - (prev.get("executingAt") if prev.get("executingAt") is not None else prev["startedAt"]) > self._effect_timeout:
                settled = dict(prev, state="aborted", error="never started", finishedAt=t) if prev["state"] == "pending" else \
                    dict(prev, state="uncertain", error="no outcome recorded: the compensation may or may not have run", finishedAt=t)
                ops.transition(prev["id"], prev["state"], settled)
                return self._run_compensation(self._store.get(rec["id"]) or rec)
            return rec
        # re-read under the record: a concurrent retry or resolution wins
        cur = self._store.get(rec["id"])
        if cur is None or cur["state"] != "vetoed" or cur["attempt"] != rec["attempt"]:
            ops.transition(op_id, "pending", dict(orec, state="aborted", error="the undo record moved on", finishedAt=self._now()))
            return cur or rec
        running = dict(orec, state="executing", executingAt=self._now())
        if not ops.transition(op_id, "pending", running):
            return self._store.get(rec["id"]) or rec
        call: Dict[str, Any] = {"operation": op, "idempotencyKey": op_id, "undoOf": rec["id"], "record": {k: v for k, v in cur.items() if k != "pcactn"}}
        if (rec.get("effect") or {}).get("result") is not None:
            call["originalResult"] = rec["effect"]["result"]
        try:
            result = self._o["compensate"](call)
        except Exception as e:  # noqa: BLE001
            error = str(e)
            try:
                ops.transition(op_id, "executing", dict(running, state="failed", error=error, finishedAt=self._now()))
            except Exception:  # noqa: BLE001
                pass
            return fail("the compensating action failed: %s" % error)
        try:
            ops.transition(op_id, "executing", dict(running, state="committed", result=result, finishedAt=self._now()))
        except Exception:  # noqa: BLE001
            pass
        r = self._apply(rec["id"], {"kind": "compensated", **({"result": result} if result is not None else {})})
        if "refused" in r:
            return self._store.get(rec["id"]) or rec
        return self._finish_compensated(r["record"])

    def veto(self, id: str, token: Any = None, at: Optional[int] = None, operator: Optional[str] = None,  # noqa: A002
             veto: Optional[dict] = None) -> dict:
        """Veto with the one-click `token` (the principal; `at` is the relayed veto time), as an authenticated `operator` of this server, or with
        a prepared `veto` (revocation, fraud proof). ``{"ok": True, "record", "replayed"}`` or ``{"ok": False, "code", "reason"}``."""
        try:
            cur = self._store.get(id)
            if cur is None:
                return {"ok": False, "code": "unknown", "reason": "no undo record %s" % id}
            t, check_at = self._now(), None
            if token is not None:
                if at is not None:
                    if isinstance(at, bool) or not isinstance(at, int) or at > t or at < cur["opened_at"]:
                        return {"ok": False, "code": "malformed", "reason": "a relayed veto time must lie between the opening of the window and now"}
                    t = check_at = at
                tok = decode_undo_token(token) if isinstance(token, str) else token
                chk = undo_token_check(tok, self.signer_public, cur, t)
                if chk != "ok":
                    return {"ok": False, "code": chk, "reason": "the undo token was refused (%s)" % chk}
                v = {"at": t, "via": "token", "by": cur["principal"], "evidence": undo_token_digest(tok)}
            elif operator is not None:
                if not isinstance(operator, str) or len(operator) == 0:
                    return {"ok": False, "code": "malformed", "reason": "an operator veto names the operator"}
                v = {"at": t, "via": "operator", "by": operator}
            else:
                v = dict(veto or {}, at=t)
            r = self._apply(id, {"kind": "veto", "veto": v}, check_at)
            if "refused" in r:
                return {"ok": False, "code": r["refused"], "reason": r["reason"]}
            if r["applied"]:
                self._notify({"kind": "vetoed", "record": _strip(r["record"])})
            done = self._run_compensation(r["record"])
            return {"ok": True, "record": done, "replayed": not r["applied"]}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "code": "malformed", "reason": "veto error (fail closed): %s" % (str(e) or "unknown")}

    def sync_relay(self) -> List[dict]:
        """Apply the relay's pending vetoes now (also done by every ``finalize_due``). Raises when the relay cannot be read."""
        if not self._relay:
            return []
        lst = self._relay.pending()
        if not isinstance(lst, list):
            raise UndoError("invalid", "the veto relay returned no list")
        return [self.veto(x["id"], token=x["token"], at=x["at"]) for x in lst if isinstance(x, dict) and isinstance(x.get("id"), str)]

    def compensate(self, id: str) -> dict:  # noqa: A002
        cur = self._store.get(id)
        if cur is None:
            raise UndoError("invalid", "no undo record %s" % id)
        return self._run_compensation(cur)

    def retry(self, id: str) -> dict:  # noqa: A002
        return self._run_compensation(self._must(id, {"kind": "retry"})["record"])

    def finalize_due(self) -> List[str]:
        """Close the windows whose time is up (``open -> finalized``) and commit their budget reservations."""
        out: List[str] = []
        try:
            self.sync_relay()
        except Exception as e:  # noqa: BLE001
            # a veto may be waiting at the relay: closing any window now could finalize an action the principal undid
            self._alert({"level": "critical", "code": "veto_relay_failed", "record": "*",
                         "reason": "the veto relay could not be read; no window was finalized: %s" % (str(e) or "error")})
            return out
        for rec in self._store.list({"state": "open", "windowEndedBy": self._now() - 1 - (UNDO_RELAY_GRACE_MS if self._relay else 0)}):
            r = self._apply(rec["id"], {"kind": "finalize"})
            if "refused" in r or not r["applied"]:
                continue
            out.append(rec["id"])
            if r["record"].get("effect") is None:
                self._alert({"level": "warning", "code": "effect_unknown", "record": rec["id"],
                             "reason": "the window closed without an effect report: reconcile the original operation"})
            self._settle_budget(r["record"], "commit")
            self._notify({"kind": "finalized", "record": _strip(r["record"])})
        return out

    def recover(self) -> List[str]:
        """After a restart: resume every vetoed record's compensation, then finalize what is due."""
        out: List[str] = []
        for rec in self._store.list({"state": "vetoed"}):
            if self._run_compensation(rec)["state"] != "vetoed":
                out.append(rec["id"])
        out.extend(self.finalize_due())
        return out

    def on_revocation(self, grant_ref: str) -> List[str]:
        """A grant was revoked: veto its open windows when the policy says so, else alert and tell the principal."""
        out: List[str] = []
        for rec in self._store.list({"state": "open", "grantRef": grant_ref}):
            pc = decode_pcactn(rec["pcactn"])
            grant = self._o["resolveGrant"](rec["grant_ref"], pc)
            pol = self._policy_of({"verb": rec["action"]["verb"], "resource": rec["action"]["resource"]}, grant) if grant else {}
            if (pol.get("onRevocation") or "keep") == "veto":
                if self.veto(rec["id"], veto={"at": 0, "via": "revocation", "by": grant_ref})["ok"]:
                    out.append(rec["id"])
            else:
                self._alert({"level": "warning", "code": "revoked_open_window", "record": rec["id"],
                             "reason": "grant %s was revoked while this window is open; the principal can still undo it" % grant_ref})
                self._notify({"kind": "revoked", "record": _strip(rec)})
        return out

    def rollback_on_slash(self, params: dict, bonds: Any = None) -> dict:
        """Slash a bond (the bond ledger re-verifies the fraud proof itself and refuses outside the challenge window), then undo the record."""
        bonds = bonds if bonds is not None else self._bonds
        if bonds is None:
            raise UndoError("config", "rollback_on_slash needs a bond ledger (pass bonds= to the coordinator or to this call)")
        settlement = bonds.slash_bond(params)
        evidence = hash_canonical({"d": "atlas-pca/undo-slash-ref/v1", "settlement": settlement})
        recs = self._store.list({"state": "open", "bondRef": params["claimId"]})
        target = recs[0] if recs else self._store.get(params["claimId"])
        if target is None:
            return {"settlement": settlement, "veto": {"ok": False, "code": "unknown", "reason": "no undo record for bond %s" % params["claimId"]}}
        v = self.veto(target["id"], veto={"at": 0, "via": "fraud_proof", "by": params["claimId"], "evidence": evidence})
        if not v["ok"]:
            self._alert({"level": "critical", "code": "slash_after_window", "record": target["id"],
                         "reason": "the bond was slashed but the effect could not be rolled back: %s" % v["reason"]})
        return {"settlement": settlement, "veto": v}


def report_undo_effect(undo: UndoCoordinator, id: str, outcome: dict) -> dict:  # noqa: A002
    """Report the outcome of executing an undo-windowed action: a committed effect is recorded (its result names the compensation target), an
    effect that failed or never started aborts the window (nothing to undo; held budget released); pending / uncertain leaves it running."""
    status = outcome.get("status")
    if status == "committed":
        return undo.record_effect(id, outcome.get("result"), "result" in outcome)
    if status in ("failed", "aborted", "refused"):
        return undo.abort(id, "effect_%s" % status)
    r = undo.get(id)
    if r is None:
        raise UndoError("invalid", "no undo record %s" % id)
    return r


def hosted_undo_veto_relay(base_url: str, secret_key: str, fetch: Callable[[str, dict], Any], limit: int = 200) -> Any:
    """The veto relay over a hosted undo ledger: ``GET {base_url}/v1/pca/undo/vetoes`` with the instance secret key. `fetch(url, init)` returns an
    object with ``ok``, ``status`` and ``json()``. A non-2xx answer or a malformed body raises (and so finalizes nothing)."""
    base = base_url.rstrip("/")

    class _Relay:
        @staticmethod
        def pending() -> List[dict]:
            res = fetch("%s/v1/pca/undo/vetoes?limit=%d" % (base, min(200, max(1, int(limit)))),
                        {"method": "GET", "headers": {"authorization": "Bearer %s" % secret_key, "accept": "application/json"}})
            if not res.ok:
                raise UndoError("invalid", "the veto relay answered %s" % res.status)
            body = res.json()
            if not isinstance(body, dict) or not isinstance(body.get("data"), list):
                raise UndoError("invalid", "the veto relay answered without a data list")
            out = []
            for row in body["data"]:
                v = row.get("veto") if isinstance(row, dict) else None
                if not isinstance(row, dict) or not isinstance(row.get("record_id"), str) or not isinstance(v, dict) or not isinstance(v.get("token"), str) \
                        or isinstance(v.get("at"), bool) or not isinstance(v.get("at"), (int, float)):
                    raise UndoError("invalid", "the veto relay answered a malformed entry")
                out.append({"id": row["record_id"], "token": v["token"], "at": int(v["at"])})
            return out
    return _Relay()


def undo_notifier_from_dispatcher(dispatcher: Any, undo_url: Callable[[str, str], str], inbox_url: Optional[str] = None) -> Any:
    """An undo notifier over the approval channels (Slack, webhook, email, SMS, push). The notice becomes a step-up-shaped message whose link
    is the one-click undo URL (`undo_url(token, record id)`) and whose render is the WYSIWYS render of the action."""
    class _Notifier:
        @staticmethod
        def notify(n: dict) -> dict:
            r, kind = n["record"], n["kind"]
            until = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(r["window_end"] / 1000)) + ".%03dZ" % (int(r["window_end"]) % 1000)
            what = "%s on %s" % (r["action"]["verb"], r["action"]["resource"])
            reason = {
                "opened": "Already done: %s. You can undo it until %s." % (what, until),
                "vetoed": "Undo started for %s." % what,
                "compensated": "Undone: %s." % what,
                "compensation_failed": "UNDO FAILED for %s: %s. An operator has been alerted." % (what, (r.get("outcome") or {}).get("reason") or "unknown"),
                "revoked": "The agent's grant was revoked. %s can still be undone until %s." % (what, until),
            }.get(kind, "Final: %s can no longer be undone." % what)
            req: Dict[str, Any] = {"id": "undo:%s:%s" % (r["id"], kind), "verb": r["action"]["verb"], "resource": r["action"]["resource"], "tier": 3,
                                   "reason": reason, "goalCommit": "",
                                   "lineage": {"goalCommit": "", "goalVerified": False, "because": reason,
                                               "chain": [{"kind": "action", "label": "%s %s" % (r["action"]["verb"], r["action"]["resource"]),
                                                          "detail": "undo: %s" % r["compensation"]["verb"]}]},
                                   "r": 0, "requestedAt": r["opened_at"]}
            if n.get("render") is not None and r.get("render_digest") is not None:
                req["render"], req["renderDigest"] = n["render"], r["render_digest"]
            link = undo_url(n["token"], r["id"]) if kind == "opened" and n.get("token") is not None else inbox_url
            out = dispatcher.notify_all(req, {"inboxUrl": link} if link is not None else {})
            if any(d["delivered"] for d in out):
                return {"delivered": True}
            return {"delivered": False, "reason": "; ".join("%s: %s" % (d["kind"], d.get("reason") or "not delivered") for d in out) or "no enabled channel"}
    return _Notifier()
