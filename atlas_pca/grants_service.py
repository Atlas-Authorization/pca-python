"""The grant management resource and its HTTP bindings (port of the TypeScript reference, @atlasauth/pca-grants): list / inspect / amend /
revoke and incremental authorization for principals, nothing widening in place. ``GrantService`` runs over a grant store you pass
(:class:`MemoryGrantStore` is for tests and single-process use); ``grant_resource_handler`` and ``lease_resource_handler`` turn it into
framework-neutral handlers over a plain request dict ``{method, path, query?, body?}`` returning ``{status, body}``; ``GrantClient``
is the matching client over an injected transport.

The pure verification side (amendment, revoke and need-approval decisions) is :mod:`atlas_pca.k3`; this module adds the stateful service.
Hooks (``verify_step_up``, ``on_revoke``, ``on_change``, ``validate_need``, providers) are plain callables."""
from __future__ import annotations

import copy
import json
import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote, quote_plus

from .fresh_at import verify_fresh_at
from .k3 import (
    GRANT_AMEND_DOMAIN,
    GRANT_REVOKE_DOMAIN,
    NEED_APPROVE_DOMAIN,
    _num,
    amend_message,
    authority_digest,
    authority_ok,
    compare_authority,
    grant_revoke_message,
    is_obj,
    is_str,
    merge_authority,
    need_approve_message,
    u16key,
    verify_body,
    verify_need_approval,
    verify_revoke_signature,
)
from .lease import LeaseRegistry, check_lease
from .grants import merge_fresh_at, sign_body

NEED_REQUEST_DOMAIN = "atlas-pca/need-request/v1\0"
GRANT_STEPUP_DOMAIN = "atlas-pca/grant-stepup/v1\0"
GRANTS_PATH = "/pca/grants"
NEEDS_PATH = "/pca/needs"
LEASES_PATH = "/pca/leases"
sign_grant_body = sign_body


def need_request_message(grant_id: str, rev: Any, needs: Any) -> dict:
    return {"grant": grant_id, "rev": rev, "needs": needs}


def step_up_message(grant_id: str, challenge_id: str, nonce: str) -> dict:
    return {"grant": grant_id, "challenge": challenge_id, "nonce": nonce}


class GrantError(Exception):
    """A refusal with a stable ``code``: not_found, conflict, bad_request, not_narrower, signature_required, bad_signature,
    step_up_required, not_active, need_not_lowered_only, need_not_adjustable, forbidden."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_FAIL_MESSAGE = {
    "not_found": "no such grant", "conflict": "conflict", "bad_request": "malformed request", "not_narrower": "a narrow amendment must be strictly narrower",
    "signature_required": "the amendment is signed (by the principal when it widens)", "bad_signature": "the signature does not verify for this grant revision",
    "step_up_required": "widening needs a satisfied step-up", "not_active": "grant is not active",
    "need_not_lowered_only": "an approval may only lower amounts of the requested needs", "need_not_adjustable": "the need is not adjustable",
    "forbidden": "not authorised",
}
_STATUS = {"not_found": 404, "conflict": 409, "bad_request": 400, "not_narrower": 422, "signature_required": 401, "bad_signature": 401,
           "step_up_required": 403, "not_active": 409, "need_not_lowered_only": 422, "need_not_adjustable": 422, "forbidden": 403}


class MemoryGrantStore:
    """In-process grant store (forgets everything on restart). A store has ``get/put/list`` for grants and ``get_need/put_need/list_needs``."""

    def __init__(self) -> None:
        self._g: Dict[str, dict] = {}
        self._n: Dict[str, dict] = {}

    def get(self, gid: str) -> Optional[dict]:
        return copy.deepcopy(self._g.get(gid))

    def put(self, g: dict) -> None:
        self._g[g["id"]] = copy.deepcopy(g)

    def list(self) -> List[dict]:
        return [copy.deepcopy(x) for x in self._g.values()]

    def get_need(self, nid: str) -> Optional[dict]:
        return copy.deepcopy(self._n.get(nid))

    def put_need(self, n: dict) -> None:
        self._n[n["id"]] = copy.deepcopy(n)

    def list_needs(self, grant_id: str) -> List[dict]:
        return [copy.deepcopy(x) for x in self._n.values() if x["grant_id"] == grant_id]


def _verify_amendment(cur: dict, req: Any, step_up_ok: bool, cmp: Callable[[dict, dict], str]) -> dict:
    """``k3.verify_amendment`` with a custom authority comparison (same normative check order)."""
    try:
        if not is_obj(req) or req.get("action") not in ("narrow", "merge", "replace"):
            return {"ok": False, "code": "bad_request"}
        if not authority_ok(req.get("authority")):
            return {"ok": False, "code": "bad_request"}
        if cur["status"] != "active":
            return {"ok": False, "code": "not_active"}
        action, auth = req["action"], req["authority"]
        nxt = merge_authority(cur["authority"], auth) if action == "merge" else auth
        order = cmp(cur["authority"], nxt)
        widens = order in ("wider", "incomparable")
        if (not widens and action == "narrow" and order == "equal") or (widens and action == "narrow"):
            return {"ok": False, "code": "not_narrower"}
        signed_by = req.get("signed_by")
        if not isinstance(req.get("sig"), str) or signed_by not in ("holder", "principal"):
            return {"ok": False, "code": "signature_required"}
        if widens and signed_by != "principal":
            return {"ok": False, "code": "signature_required"}
        who = cur["principal"] if signed_by == "principal" else cur["agent"]
        if not verify_body(GRANT_AMEND_DOMAIN, amend_message(cur, action, auth), who, req["sig"]):
            return {"ok": False, "code": "bad_signature"}
        if widens and not step_up_ok:
            return {"ok": False, "code": "step_up_required"}
        return {"ok": True, "widens": widens, "next": nxt}
    except Exception:
        return {"ok": False, "code": "bad_request"}


def _js_number(s: str) -> float:
    """JavaScript ``Number(string)``: trimmed, empty is 0, decimal / Infinity / 0x 0o 0b forms, anything else NaN."""
    t = s.strip(" \t\n\r\v\f                 　﻿")
    if t == "":
        return 0.0
    if re.fullmatch(r"[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?", t):
        return float(t)
    if re.fullmatch(r"[+-]?Infinity", t):
        return float(t.replace("Infinity", "inf"))
    m = re.fullmatch(r"0([xXoObB])([0-9a-fA-F]+)", t)
    if m:
        try:
            return float(int(m.group(2), {"x": 16, "o": 8, "b": 2}[m.group(1).lower()]))
        except ValueError:
            return float("nan")
    return float("nan")


def _id_lt(a: Any, b: Any) -> bool:
    return u16key(a) < u16key(b)


class GrantService:
    """``store`` (:class:`MemoryGrantStore` or your own), ``now() -> epoch ms``, ``new_id(kind)`` with kind ``grant`` or ``need``; optional
    ``compare(old, new) -> order``, ``providers`` ({usage, remaining_budget, policy_card, residual}: each ``(grant) -> value``),
    ``verify_step_up(ref, grant) -> bool`` (absent: widening is refused), ``on_revoke(ids, scope, root)``, ``on_change(kind, grant)`` and
    ``validate_need(need) -> error string | None``."""

    def __init__(self, store: Any, now: Callable[[], Any], new_id: Callable[[str], str], compare: Optional[Callable[[dict, dict], str]] = None,
                 providers: Optional[dict] = None, verify_step_up: Optional[Callable[[str, dict], Any]] = None,
                 on_revoke: Optional[Callable[[List[str], str, dict], Any]] = None, on_change: Optional[Callable[[str, dict], Any]] = None,
                 validate_need: Optional[Callable[[dict], Optional[str]]] = None) -> None:
        self.store, self._now, self._new_id = store, now, new_id
        self._cmp = compare or compare_authority
        self._providers = providers
        self._verify_step_up, self._on_revoke, self._on_change, self._validate_need = verify_step_up, on_revoke, on_change, validate_need

    def register(self, g: dict) -> dict:
        """Create a grant record (the host calls this when a grant is registered)."""
        if not authority_ok(g.get("authority")):
            raise GrantError("bad_request", "malformed authority")
        if self.store.get(g["id"]) is not None:
            raise GrantError("conflict", "grant id exists")
        now = self._now()
        status = g.get("status")
        rec = {**g, "status": status if status is not None else "active", "rev": 1, "created_at": now,
               "history": [{"rev": 1, "authority_digest": authority_digest(g["authority"]), "at": now, "action": "create"}]}
        self.store.put(rec)
        return rec

    def list(self, f: Optional[dict] = None) -> dict:
        f = f or {}
        lim = f.get("limit")
        limit = min(max(50 if lim is None else lim, 1), 200)
        allg = [g for g in self.store.list()
                if (f.get("principal") is None or g["principal"] == f["principal"]) and (f.get("agent") is None or g["agent"] == f["agent"])
                and (f.get("status") is None or g["status"] == f["status"])]
        allg.sort(key=lambda g: u16key(g["id"]))
        if f.get("cursor") is not None:
            allg = [g for g in allg if _id_lt(f["cursor"], g["id"])]
        page = allg[: int(limit)]
        out: Dict[str, Any] = {"grants": [self._view(g, False) for g in page]}
        if len(allg) > limit:
            out["next_cursor"] = page[-1]["id"]
        return out

    def inspect(self, gid: str) -> dict:
        return self._view(self._must(gid), True)

    def _view(self, g: dict, rich: bool) -> dict:
        view = {k: v for k, v in g.items() if k != "history"}
        view["authority_digest"] = authority_digest(g["authority"])
        view["pending_needs"] = [n["id"] for n in self.store.list_needs(g["id"]) if n["status"] == "pending"]
        p = self._providers
        if rich and p:
            for key, name in (("usage", "usage"), ("remaining_budget", "remaining_budget"), ("policy_card", "policy_card"), ("residual", "residual")):
                if p.get(name):
                    view[key] = p[name](g)
        return view

    def _must(self, gid: str) -> dict:
        g = self.store.get(gid)
        if g is None:
            raise GrantError("not_found", "no such grant")
        return g

    def _changed(self, kind: str, g: dict) -> None:
        if self._on_change:
            self._on_change(kind, g)

    def amend(self, gid: str, req: Any) -> dict:
        cur = self._must(gid)
        v = _verify_amendment(cur, req, False, self._cmp)
        # evaluate the (possibly consuming) step-up only when everything else already passed
        if not v["ok"] and v["code"] == "step_up_required" and req.get("step_up_ref") and self._verify_step_up and self._verify_step_up(req["step_up_ref"], cur):
            v = _verify_amendment(cur, req, True, self._cmp)
        if not v["ok"]:
            raise GrantError(v["code"], _FAIL_MESSAGE[v["code"]])
        now = self._now()
        if not v["widens"]:
            cur["authority"] = v["next"]
            cur["rev"] += 1
            cur["history"].append({"rev": cur["rev"], "authority_digest": authority_digest(v["next"]), "at": now, "action": req["action"]})
            self.store.put(cur)
            self._changed("amend", cur)
            return {"grant": self._view(cur, True), "created": False}
        nid = self._new_id("grant")
        fresh = {**cur, "id": nid, "authority": v["next"], "rev": 1, "status": "active", "supersedes": cur["id"], "created_at": now,
                 "history": [{"rev": 1, "authority_digest": authority_digest(v["next"]), "at": now, "action": "supersedes:%s" % cur["id"]}]}
        fresh.pop("superseded_by", None)
        cur["status"] = "superseded"
        cur["superseded_by"] = nid
        self.store.put(fresh)
        self.store.put(cur)
        self._changed("supersede", fresh)
        return {"grant": self._view(fresh, True), "created": True}

    def revoke(self, gid: str, scope: Any, auth: dict) -> dict:
        """Authorised by the principal's signature over ``{grant id, scope}`` (``auth = {"sig": ...}``) or by a host-authenticated admin
        (``auth = {"admin": True}``). ``agent`` revokes every grant of the grant's agent and principal; ``subtree`` the grant and every descendant."""
        if scope not in ("grant", "agent", "subtree"):
            raise GrantError("bad_request", "unknown scope")
        root = self._must(gid)
        if "sig" in auth:
            rv = verify_revoke_signature(root, scope, auth["sig"])
            if not rv["ok"]:
                raise GrantError(rv["code"], _FAIL_MESSAGE[rv["code"]])
        elif auth.get("admin") is not True:
            raise GrantError("forbidden", "not authorised")
        allg = self.store.list()
        if scope == "grant":
            hit = [root]
        elif scope == "agent":
            hit = [g for g in allg if g["agent"] == root["agent"] and g["principal"] == root["principal"]]
        else:
            ids = {gid}
            grew = True
            while grew:
                grew = False
                for g in allg:
                    if g.get("parent") is not None and g["parent"] in ids and g["id"] not in ids:
                        ids.add(g["id"])
                        grew = True
            hit = [g for g in allg if g["id"] in ids]
        revoked: List[str] = []
        for g in hit:
            if g["status"] == "revoked":
                continue
            g["status"] = "revoked"
            g["history"].append({"rev": g["rev"], "authority_digest": authority_digest(g["authority"]), "at": self._now(), "action": "revoke:%s" % scope})
            self.store.put(g)
            revoked.append(g["id"])
        if self._on_revoke:
            self._on_revoke(revoked, scope, root)
        self._changed("revoke", root)
        return {"revoked": revoked}

    def request_needs(self, grant_id: str, needs: Any) -> dict:
        """Agent side: ask for more. Typed needs only (validated); no authority changes until the principal approves."""
        g = self._must(grant_id)
        if g["status"] != "active":
            raise GrantError("not_active", "grant is %s" % g["status"])
        if not isinstance(needs, list) or len(needs) < 1 or len(needs) > 32:
            raise GrantError("bad_request", "1..32 needs")
        for n in needs:
            if not is_obj(n) or not is_str(n.get("verb"), 128) or not is_str(n.get("resource"), 512) or \
                    ("limits" in n and not (is_obj(n["limits"]) and all(_num(v) and v >= 0 for v in n["limits"].values()))):
                raise GrantError("bad_request", "malformed need")
            e = self._validate_need(n) if self._validate_need else None
            if e:
                raise GrantError("bad_request", e)
        nr = {"id": self._new_id("need"), "grant_id": grant_id, "needs": copy.deepcopy(needs), "status": "pending", "created_at": self._now()}
        self.store.put_need(nr)
        self._changed("need", g)
        return nr

    def approve_needs(self, need_id: str, approved: Any, sig: Any, step_up_ref: Optional[str] = None) -> dict:
        """Principal side: approve the delta (amounts may only be LOWERED, and only when the need is ``adjustable``); the result is a widening merge."""
        nr = self.store.get_need(need_id)
        if nr is None:
            raise GrantError("not_found", "no such need request")
        if nr["status"] != "pending":
            raise GrantError("conflict", "need request is %s" % nr["status"])
        g = self._must(nr["grant_id"])
        v = verify_need_approval(nr, g, approved, sig, False)
        if not v["ok"] and v["code"] == "step_up_required" and step_up_ref and self._verify_step_up and self._verify_step_up(step_up_ref, g):
            v = verify_need_approval(nr, g, approved, sig, True)
        if not v["ok"]:
            raise GrantError(v["code"], _FAIL_MESSAGE[v["code"]])
        authority = v["authority"]
        nid = self._new_id("grant")
        now = self._now()
        fresh = {**g, "id": nid, "authority": authority, "rev": 1, "status": "active", "supersedes": g["id"], "created_at": now,
                 "history": [{"rev": 1, "authority_digest": authority_digest(authority), "at": now, "action": "needs:%s" % need_id}]}
        fresh.pop("superseded_by", None)
        g["status"] = "superseded"
        g["superseded_by"] = nid
        nr["status"] = "approved"
        nr["result_grant_id"] = nid
        self.store.put(fresh)
        self.store.put(g)
        self.store.put_need(nr)
        self._changed("supersede", fresh)
        return {"grant": self._view(fresh, True), "created": True}

    def need_grant_id(self, need_id: str) -> str:
        """The grant a need request belongs to (the HTTP binding uses it to scope a caller to its own grants)."""
        nr = self.store.get_need(need_id)
        if nr is None:
            raise GrantError("not_found", "no such need request")
        return nr["grant_id"]

    def deny_needs(self, need_id: str) -> None:
        nr = self.store.get_need(need_id)
        if nr is None:
            raise GrantError("not_found", "no such need request")
        if nr["status"] != "pending":
            raise GrantError("conflict", "need request is %s" % nr["status"])
        nr["status"] = "denied"
        self.store.put_need(nr)


# ---- HTTP binding --------------------------------------------------------------------------------------------------------

def grant_management_metadata(base: str) -> dict:
    """Discovery fragment for ``/.well-known/pca-configuration``."""
    return {"grant_management": {"grants_endpoint": base + GRANTS_PATH, "needs_endpoint": base + NEEDS_PATH, "amend_actions": ["narrow", "merge", "replace"],
                                 "revoke_scopes": ["grant", "agent", "subtree"], "widening": "new_grant_id_with_supersedes"}}


def _err(e: BaseException) -> dict:
    if isinstance(e, GrantError):
        return {"status": _STATUS[e.code], "body": {"error": e.code, "message": str(e)}}
    return {"status": 500, "body": {"error": "server_error"}}


def _segments(path: Any) -> List[str]:
    return [s for s in str(path).split("/") if s]


def grant_resource_handler(svc: GrantService, authenticate: Callable[[dict], Optional[dict]]) -> Callable[[dict], dict]:
    """``authenticate(request) -> {principal?, admin?} | None``: who is calling, as the host authenticated them. ``principal`` limits every
    read and write to that principal's grants."""
    def handle(req: dict) -> dict:
        try:
            who = authenticate(req)
            if not who or (not who.get("admin") and not who.get("principal")):
                return {"status": 401, "body": {"error": "unauthenticated"}}
            seg = _segments(req.get("path"))
            q = req.get("query") or {}
            b = req["body"] if is_obj(req.get("body")) else {}
            method = req.get("method")

            def own(gid: str) -> None:
                g = svc.inspect(gid)
                if not who.get("admin") and g["principal"] != who.get("principal"):
                    raise GrantError("not_found", "no such grant")

            if not seg or seg[0] != "pca":
                return {"status": 404, "body": {"error": "not_found"}}
            kind = seg[1] if len(seg) > 1 else None
            if kind == "grants":
                if len(seg) == 2 and method == "GET":
                    status = q.get("status")
                    if status is not None and status not in ("active", "revoked", "superseded"):
                        raise GrantError("bad_request", "bad status")
                    principal = q.get("principal") if who.get("admin") else who.get("principal")
                    limit = _js_number(q["limit"]) if q.get("limit") is not None else None
                    f: Dict[str, Any] = {}
                    if principal:
                        f["principal"] = principal
                    if q.get("agent"):
                        f["agent"] = q["agent"]
                    if status:
                        f["status"] = status
                    if limit is not None and limit == limit and limit not in (float("inf"), float("-inf")):
                        f["limit"] = limit
                    if q.get("cursor"):
                        f["cursor"] = q["cursor"]
                    return {"status": 200, "body": svc.list(f)}
                gid = seg[2] if len(seg) > 2 else None
                if not gid:
                    return {"status": 404, "body": {"error": "not_found"}}
                own(gid)
                if len(seg) == 3 and method == "GET":
                    return {"status": 200, "body": svc.inspect(gid)}
                if len(seg) == 3 and method == "DELETE":
                    scope = q.get("scope") if q.get("scope") is not None else "grant"
                    sig = b.get("sig") if isinstance(b.get("sig"), str) else None
                    # a principal-scoped caller must still sign; only an admin may revoke without a principal signature
                    r = svc.revoke(gid, scope, {"admin": True} if who.get("admin") and not sig else {"sig": sig or ""})
                    return {"status": 200, "body": r}
                if len(seg) == 4 and seg[3] == "amend" and method == "POST":
                    r = svc.amend(gid, req.get("body"))
                    return {"status": 201 if r["created"] else 200, "body": r["grant"]}
                if len(seg) == 4 and seg[3] == "needs" and method == "POST":
                    return {"status": 201, "body": svc.request_needs(gid, b.get("needs"))}
            if kind == "needs" and len(seg) > 3 and seg[3] == "approve" and method == "POST":
                own(svc.need_grant_id(seg[2]))
                if not isinstance(b.get("sig"), str) or not isinstance(b.get("approved"), list):
                    raise GrantError("bad_request", "sig and approved are required")
                r = svc.approve_needs(seg[2], b["approved"], b["sig"], b["step_up_ref"] if isinstance(b.get("step_up_ref"), str) else None)
                return {"status": 201, "body": r["grant"]}
            if kind == "needs" and len(seg) > 3 and seg[3] == "deny" and method == "POST":
                own(svc.need_grant_id(seg[2]))
                svc.deny_needs(seg[2])
                return {"status": 200, "body": {"status": "denied"}}
            return {"status": 404, "body": {"error": "not_found"}}
        except Exception as e:  # noqa: BLE001 - a handler never raises
            return _err(e)
    return handle


# ---- lease HTTP binding --------------------------------------------------------------------------------------------------

_LEASE_STATUS = {"bad_record": 400, "bad_seq": 409, "stale_seq": 409, "lease_fork": 409, "renewal_mismatch": 422, "over_max_ttl": 422, "ttl_ceiling": 422,
                 "not_extending": 422, "stale_justification": 422, "expired_lease": 409, "revoked": 409, "sod": 403, "unknown_authority": 403,
                 "store_unreachable": 503}


def lease_management_metadata(base: str) -> dict:
    return {"leases": {"leases_endpoint": base + LEASES_PATH, "revoke_targets": ["lease", "prefix", "grant"]}}


def lease_resource_handler(reg: LeaseRegistry, authenticate: Callable[[dict], Optional[dict]], now: Optional[Callable[[], Any]] = None) -> Callable[[dict], dict]:
    """Hosted lease routes. The server only stores records the lease authority already signed; it never mints one.
    POST /pca/leases ``{lease, chain?}`` issues or renews; GET /pca/leases/:id; POST /pca/leases/:id/check ``{lease}``;
    POST /pca/leases/revoke ``{revocation}``. ``authenticate(request) -> {admin?, principal?} | None``."""
    import time as _time

    clock = now or (lambda: int(_time.time() * 1000))

    def handle(req: dict) -> dict:
        try:
            who = authenticate(req)
            if not who or (not who.get("admin") and not who.get("principal")):
                return {"status": 401, "body": {"error": "unauthenticated"}}
            seg = _segments(req.get("path"))
            b = req["body"] if is_obj(req.get("body")) else {}
            method = req.get("method")
            if len(seg) < 2 or seg[0] != "pca" or seg[1] != "leases":
                return {"status": 404, "body": {"error": "not_found"}}

            def visible(holder: Any) -> bool:
                return who.get("admin") is True or who.get("principal") == holder

            if len(seg) == 2 and method == "POST":
                if not who.get("admin"):
                    return {"status": 403, "body": {"error": "forbidden"}}
                chain = b["chain"] if isinstance(b.get("chain"), list) and all(isinstance(x, str) for x in b["chain"]) else []
                r = reg.accept(b.get("lease"), chain)
                if r["ok"]:
                    return {"status": 201 if r["replaced"] else 200, "body": r}
                return {"status": _LEASE_STATUS.get(r["code"], 400), "body": {"error": r["code"], **({"message": r["reason"]} if r.get("reason") else {})}}
            if len(seg) == 3 and seg[2] == "revoke" and method == "POST":
                if not who.get("admin"):
                    return {"status": 403, "body": {"error": "forbidden"}}
                r = reg.revoke(b.get("revocation"))
                if r["ok"]:
                    return {"status": 200, "body": r}
                return {"status": 503 if r["code"] == "store_unreachable" else 403 if r["code"] == "unknown_authority" else 400, "body": {"error": r["code"]}}
            lid = seg[2] if len(seg) > 2 else None
            if not lid:
                return {"status": 404, "body": {"error": "not_found"}}
            if len(seg) == 3 and method == "GET":
                cur = reg.get(lid)
                if cur is None or not visible(cur["holder"]):
                    return {"status": 404, "body": {"error": "not_found"}}
                return {"status": 200, "body": {"lease": cur, "history": reg.history(lid)}}
            if len(seg) == 4 and seg[3] == "check" and method == "POST":
                cur = reg.get(lid)
                if cur is None or not visible(cur["holder"]):
                    return {"status": 404, "body": {"error": "not_found"}}
                d = check_lease(b.get("lease"), reg, clock())
                return {"status": 200 if d["decision"] == "allow" else 403, "body": d}
            return {"status": 404, "body": {"error": "not_found"}}
        except Exception:  # noqa: BLE001
            return {"status": 500, "body": {"error": "server_error"}}
    return handle


# ---- client --------------------------------------------------------------------------------------------------------------

class GrantApiError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code = status, code


def _form(q: dict) -> str:
    return "&".join("%s=%s" % (quote_plus(str(k), safe="*").replace("~", "%7E"), quote_plus(str(v), safe="*").replace("~", "%7E"))
                    for k, v in q.items() if v is not None)


def _comp(s: Any) -> str:
    return quote(str(s), safe="!~*'()")


class GrantClient:
    """Client for the grant management resource over an injected transport: ``fetch({method, url, headers, body}) -> {status, headers, body}``
    where ``body`` is the response text (or an already parsed value) and ``headers`` a dict (looked up case-insensitively). The client
    carries the newest ``pca-fresh-at`` token it has seen: attached to later requests, and with ``fresh_signer`` set a header that does
    not verify is ignored."""

    def __init__(self, base_url: str, fetch: Callable[[dict], dict], fresh_signer: Optional[str] = None,
                 headers: Optional[Callable[[], Dict[str, str]]] = None) -> None:
        self._base = base_url[:-1] if base_url.endswith("/") else base_url
        self._fetch, self._signer, self._headers = fetch, fresh_signer, headers
        self._latest: Optional[dict] = None

    @property
    def fresh_at(self) -> Optional[dict]:
        """The newest consistency token seen on any response: attach it to later requests to make them read-your-writes."""
        return self._latest

    def fold_fresh_at(self, s: dict) -> Optional[dict]:
        return merge_fresh_at(self._latest, s) if self._latest else None

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        hdrs = {"content-type": "application/json"}
        if self._latest:
            hdrs["pca-fresh-at"] = json.dumps(self._latest, separators=(",", ":"), ensure_ascii=False)
        if self._headers:
            hdrs.update(self._headers())
        req: Dict[str, Any] = {"method": method, "url": self._base + path, "headers": hdrs}
        if body is not None:
            req["body"] = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
        res = self._fetch(req)
        rh = {str(k).lower(): v for k, v in (res.get("headers") or {}).items()}
        tok = rh.get("pca-fresh-at")
        if tok:
            try:
                t = json.loads(tok)
                if self._signer is not None and not verify_fresh_at(t, self._signer):
                    raise ValueError("unverified")
                lt = self._latest
                # monotone fold: never replace a fresher token with an older one
                if not lt or (t["revocation_epoch"] >= lt["revocation_epoch"] and t["policy_revision"] >= lt["policy_revision"]
                              and t["ledger_tree_size"] >= lt["ledger_tree_size"] and t["budget_version"] >= lt["budget_version"]):
                    self._latest = t
            except Exception:  # noqa: BLE001 - freshness is only ever tightened by a valid token
                pass
        raw = res.get("body")
        try:
            data = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else (raw if raw is not None else {})
        except Exception:  # noqa: BLE001
            data = {}
        status = res["status"]
        if not (200 <= status < 300):
            d = data if isinstance(data, dict) else {}
            raise GrantApiError(status, d.get("error") or "error", d.get("message") or str(res.get("reason") or status))
        return data

    def list(self, q: Optional[dict] = None) -> dict:
        s = _form(q or {})
        return self._call("GET", GRANTS_PATH + ("?" + s if s else ""))

    def inspect(self, gid: str) -> dict:
        return self._call("GET", "%s/%s" % (GRANTS_PATH, _comp(gid)))

    def amend(self, gid: str, req: dict) -> dict:
        return self._call("POST", "%s/%s/amend" % (GRANTS_PATH, _comp(gid)), req)

    def revoke(self, gid: str, scope: str = "grant", sig: Optional[str] = None) -> dict:
        return self._call("DELETE", "%s/%s?scope=%s" % (GRANTS_PATH, _comp(gid), scope), {"sig": sig} if sig else None)

    def request_needs(self, gid: str, needs: list) -> dict:
        return self._call("POST", "%s/%s/needs" % (GRANTS_PATH, _comp(gid)), {"needs": needs})

    def approve_needs(self, need_id: str, approved: list, sig: str, step_up_ref: Optional[str] = None) -> dict:
        return self._call("POST", "%s/%s/approve" % (NEEDS_PATH, _comp(need_id)), {"approved": approved, "sig": sig, **({"step_up_ref": step_up_ref} if step_up_ref else {})})

    def deny_needs(self, need_id: str) -> dict:
        return self._call("POST", "%s/%s/deny" % (NEEDS_PATH, _comp(need_id)))


def create_grant_client(base_url: str, fetch: Callable[[dict], dict], fresh_signer: Optional[str] = None,
                        headers: Optional[Callable[[], Dict[str, str]]] = None) -> GrantClient:
    return GrantClient(base_url, fetch, fresh_signer, headers)
