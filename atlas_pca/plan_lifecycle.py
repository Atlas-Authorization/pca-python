"""Plan lifecycle (T10): explicit states around the plan commitment (the Merkle root an agent signs into every PCActn) and
the principal's plan authorization.

    draft --validate--> validated --commit--> committed --authorize--> authorized
      |_____________________|_______________________|__________revoke______|--> revoked

* ``draft``: the nodes are recorded; the root is computed from them (never taken from the caller).
* ``validated``: the nodes are well-formed (unique ids, verb and resource, a known reversibility class) and passed the
  server's own ``validator``.
* ``committed``: the root is fixed. A committed plan is NOT executable: it still needs the principal.
* ``authorized``: the principal approved this root for this grant, optionally until ``expiresAt``.
* ``revoked``: terminal; every later action against the root is denied.

"Executable" is not stored: it is evaluated at the moment of use. A plan is executable when it is ``authorized``, the
approval has not expired and its stored nodes still hash to the root. :meth:`PlanRegistry.check` adds the per-action rules
a server applies immediately before execution: the node exists and the operation's verb, resource and params still match
what the principal approved.

Records and results are plain dicts with the reference's keys (``grantRef``, ``createdAt``, ...), so a registry on a shared
store is interchangeable with the other implementations'. ``authorize(plans=registry)`` feeds the stored plan and its
executability into the verification context.
"""
from __future__ import annotations

import copy
import math
import threading
import time
from typing import Any, Callable, Dict, Optional, Sequence

from .atomic_kv import MemoryAtomicKv
from .pca import EMPTY_PARAMS_DIGEST, _plan_leaf, conditions_digest, merkle_root, params_digest
from .revocation_staleness import CLASS_RANK

PLAN_STATES = ("draft", "validated", "committed", "authorized", "revoked")


def plan_root(nodes: Sequence[dict]) -> str:
    """The Merkle root of a plan's nodes (plan-node leaves; equals the TypeScript root). Raises on an unhashable plan."""
    return merkle_root([_plan_leaf(n.get("id"), n, conditions_digest(n.get("pre"), n.get("post"))) for n in nodes])


def _structural_problem(nodes: Any) -> Optional[str]:
    if not isinstance(nodes, list) or not nodes:
        return "a plan needs at least one node"
    ids = set()
    for n in nodes:
        if not isinstance(n, dict) or not isinstance(n.get("id"), str) or n["id"] == "":
            return "every node needs an id"
        if n["id"] in ids:
            return "duplicate node id '%s'" % n["id"]
        ids.add(n["id"])
        if not isinstance(n.get("verb"), str) or n["verb"] == "" or not isinstance(n.get("resource"), str) or n["resource"] == "":
            return "node '%s' needs a verb and a resource" % n["id"]
        rc = n.get("reversibility_class")
        if "reversibility_class" in n and not (isinstance(rc, str) and rc in CLASS_RANK):
            return "node '%s' has an unknown reversibility class '%s'" % (n["id"], rc)
    return None


def _is_record(v: Any) -> bool:
    return isinstance(v, dict) and isinstance(v.get("root"), str) and isinstance(v.get("nodes"), list)


def _finite(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


class PlanRegistry:
    """The plan registry. ``kv`` is an atomic key/value store (:class:`atlas_pca.MemoryAtomicKv` by default;
    :class:`atlas_pca.SqliteAtomicKv` for durable, multi-process state). ``now`` is the clock (epoch ms). ``validator`` is
    the server's validation, run by :meth:`validate` after the structural checks: ``(record) -> {"ok": True} | {"ok": False,
    "reason": str}``; an exception refuses."""

    def __init__(self, *, kv: Any = None, prefix: str = "pca-plan:", now: Optional[Callable[[], int]] = None,
                 validator: Optional[Callable[[dict], dict]] = None) -> None:
        self._kv = kv if kv is not None else MemoryAtomicKv()
        self._pre = prefix
        self._clock = now or (lambda: int(time.time() * 1000))
        self._validator = validator

    # -- storage
    def _key(self, grant_ref: str, root: str) -> str:
        from urllib.parse import quote
        return "%s%s:%s" % (self._pre, quote(grant_ref, safe="-_.!~*'()"), root)

    def get(self, grant_ref: str, root: str) -> Optional[dict]:
        v = self._kv.get(self._key(grant_ref, root))
        return v if _is_record(v) else None

    def _move(self, grant_ref: str, root: str, frm: Sequence[str], to: str, nxt: Callable[[dict], dict]) -> dict:
        out: Dict[str, Any] = {"ok": False, "state": "unknown", "reason": "plan %s is unknown for this grant" % root}

        def step(prev: Any) -> Any:
            if not _is_record(prev):
                return None
            if prev["state"] not in frm:
                out.clear()
                out.update(ok=False, state=prev["state"], reason="plan %s is %s: cannot %s" % (root, prev["state"], to))
                return None
            rec = nxt(prev)
            out.clear()
            out.update(ok=True, record=rec)
            return rec

        self._kv.update(self._key(grant_ref, root), step)
        return out

    # -- lifecycle
    def draft(self, grant_ref: str, nodes: Any) -> dict:
        """Record a draft plan for a grant. The root is computed from `nodes`. Re-drafting an existing root is refused."""
        if not isinstance(grant_ref, str) or grant_ref == "":
            return {"ok": False, "state": "unknown", "reason": "a plan needs a grant"}
        # structural problems are reported by `validate` (a draft can be inspected first); an unhashable plan has no root
        try:
            root = plan_root(nodes)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "state": "unknown", "reason": "the plan cannot be committed: %s" % str(e).replace("merkle_root:", "merkleRoot:")}
        rec = {"grantRef": grant_ref, "root": root, "nodes": copy.deepcopy(list(nodes)), "state": "draft", "createdAt": self._clock()}
        out: Dict[str, Any] = {"ok": True, "record": rec}

        def step(prev: Any) -> Any:
            if _is_record(prev):
                out.clear()
                out.update(ok=False, state=prev["state"], reason="plan %s already exists (%s)" % (root, prev["state"]))
                return None
            return rec

        self._kv.update(self._key(grant_ref, root), step)
        return out

    def validate(self, grant_ref: str, root: str) -> dict:
        """draft -> validated (structural checks, then the server's `validator`)."""
        cur = self.get(grant_ref, root)
        if cur is None:
            return {"ok": False, "state": "unknown", "reason": "plan %s is unknown for this grant" % root}
        if cur["state"] != "draft":
            return {"ok": False, "state": cur["state"], "reason": "plan %s is %s: cannot validate" % (root, cur["state"])}
        problem = _structural_problem(cur["nodes"])
        if problem is None:
            try:
                problem = None if plan_root(cur["nodes"]) == root else "the stored nodes no longer hash to the root"
            except Exception:  # noqa: BLE001
                problem = "the stored nodes no longer hash to the root"
        if problem:
            return {"ok": False, "state": cur["state"], "reason": "plan %s is invalid: %s" % (root, problem)}
        if self._validator is not None:
            try:
                v = self._validator(copy.deepcopy(cur))
            except Exception as e:  # noqa: BLE001
                v = {"ok": False, "reason": "validator error (fail closed): %s" % e}
            if not (isinstance(v, dict) and v.get("ok") is True):
                why = v.get("reason") if isinstance(v, dict) and v.get("ok") is False and v.get("reason") else "refused by the validator"
                return {"ok": False, "state": cur["state"], "reason": "plan %s is invalid: %s" % (root, why)}
        return self._move(grant_ref, root, ["draft"], "validate", lambda r: dict(r, state="validated", validatedAt=self._clock()))

    def commit(self, grant_ref: str, root: str) -> dict:
        """validated -> committed: the root is fixed; it still needs the principal's authorization to execute."""
        return self._move(grant_ref, root, ["validated"], "commit", lambda r: dict(r, state="committed", committedAt=self._clock()))

    def authorize(self, grant_ref: str, root: str, approval: Any) -> dict:
        """committed -> authorized: the principal's approval (call it only after verifying the principal's consent)."""
        def state() -> str:
            r = self.get(grant_ref, root)
            return r["state"] if r else "unknown"

        if not isinstance(approval, dict) or not isinstance(approval.get("by"), str) or approval["by"] == "":
            return {"ok": False, "state": state(), "reason": "an approval names who approved (`by`)"}
        if "expiresAt" in approval and not _finite(approval["expiresAt"]):
            return {"ok": False, "state": state(), "reason": "approval.expiresAt must be a time (epoch ms)"}
        return self._move(grant_ref, root, ["committed"], "authorize",
                          lambda r: dict(r, state="authorized", authorizedAt=self._clock(), approval=dict(approval)))

    def revoke(self, grant_ref: str, root: str, reason: str) -> dict:
        """Any state except revoked -> revoked (terminal)."""
        return self._move(grant_ref, root, ["draft", "validated", "committed", "authorized"], "revoke",
                          lambda r: dict(r, state="revoked", revokedAt=self._clock(), revokedReason="" if reason is None else str(reason)))

    # -- use
    def status(self, grant_ref: str, root: str, now: Optional[int] = None) -> dict:
        """The state now and whether the plan is executable (authorized, approval unexpired, nodes still hash to the root)."""
        now = self._clock() if now is None else now
        rec = self.get(grant_ref, root)
        if rec is None:
            return {"state": "unknown", "executable": False, "reason": "plan %s is unknown for this grant" % root}
        if rec["state"] != "authorized":
            why = ("committed but not authorized by the principal" if rec["state"] == "committed"
                   else "revoked (%s)" % (rec.get("revokedReason") if rec.get("revokedReason") is not None else "no reason given")
                   if rec["state"] == "revoked" else "%s, not authorized" % rec["state"])
            return {"state": rec["state"], "executable": False, "reason": "plan %s is %s" % (root, why), "record": rec}
        exp = (rec.get("approval") or {}).get("expiresAt")
        if exp is not None and not now < exp:
            return {"state": rec["state"], "executable": False, "record": rec,
                    "reason": "plan %s: the principal's approval expired at %s" % (root, _num(exp))}
        try:
            same = plan_root(rec["nodes"]) == root
        except Exception:  # noqa: BLE001
            same = False
        if not same:
            return {"state": rec["state"], "executable": False, "reason": "plan %s: the stored nodes no longer hash to the root" % root, "record": rec}
        return {"state": rec["state"], "executable": True, "record": rec}

    def check(self, grant_ref: str, root: str, *, node_id: Optional[str] = None, operation: Optional[dict] = None,
              now: Optional[int] = None) -> dict:
        """`status` plus the per-action staleness rules (the node exists, the operation matches it). Run it immediately
        before execution."""
        s = self.status(grant_ref, root, now)
        if not s["executable"] or "record" not in s:
            return s
        if node_id is None and operation is None:
            return s
        node = next((n for n in s["record"]["nodes"] if n.get("id") == node_id), None) if node_id is not None else None
        if node_id is not None and node is None:
            return dict(s, executable=False, reason="plan %s has no node '%s'" % (root, node_id))
        if operation is not None:
            candidates = [node] if node is not None else s["record"]["nodes"]
            try:
                digest = params_digest(operation.get("params"))
            except Exception:  # noqa: BLE001
                return dict(s, executable=False, reason="plan %s: the operation's params cannot be hashed" % root)
            if not any(n.get("verb") == operation.get("verb") and n.get("resource") == operation.get("resource")
                       and (n.get("params_digest") if n.get("params_digest") is not None else EMPTY_PARAMS_DIGEST) == digest
                       for n in candidates):
                return dict(s, executable=False, reason="plan %s: the operation (%s on %s with these params) is not what the principal approved"
                            % (root, operation.get("verb"), operation.get("resource")))
        return s

    def is_plan_authorized(self, grant_ref: str, plan_root_: str) -> bool:
        """True only when the plan is executable now (for ``authorize`` hooks that take a yes / no)."""
        try:
            return self.status(grant_ref, plan_root_)["executable"] is True
        except Exception:  # noqa: BLE001
            return False

    def context(self, grant_ref: str, root: str, now: Optional[int] = None) -> Optional[dict]:
        """The verifier context for an action against `root`: ``{"plan", "planAuthorized", "status"}``; None: unknown root."""
        s = self.status(grant_ref, root, now)
        if "record" not in s:
            return None
        return {"plan": copy.deepcopy(s["record"]["nodes"]), "planAuthorized": s["executable"], "status": s}


def _num(v: Any) -> str:
    from .predicates import _js_number_string
    return _js_number_string(float(v))


def create_plan_registry(**kw: Any) -> PlanRegistry:
    """Build a :class:`PlanRegistry` (see its arguments)."""
    return PlanRegistry(**kw)
