"""List-authorized (port of the TypeScript reference, @atlasauth/pca-grants): "which objects of this type may this agent touch?".
Authority is capability AND relationship: ``permits`` (the grant's own predicates) decides, a relation source can only NARROW. Every page
is charged to a read accumulator (scanned AND returned objects), pages are bound by a signed cursor (changing subject, type, filter,
policy, relation or limit between pages is refused) and the result carries a signed receipt.

A candidate source is an object with ``page({type, cursor?, limit}) -> {objects, next?}``; a relation source an object with
``check({subject, relation, object}) -> bool`` and optionally ``list_objects({subject, relation, type, cursor?, limit}) -> {objects, next?}``;
a read accumulator an object with ``charge(key, units, now) -> bool`` (:class:`WindowReadAccumulator` is the reference one)."""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from ._fin import fin
from .grants import sign_body, signer_of
from .k3 import (
    LIST_CURSOR_DOMAIN,
    LIST_RECEIPT_DOMAIN,
    list_bind,
    objects_digest,
    verify_list_cursor,
    verify_list_receipt,
)
from .pca import _is_safe_int, b64u, hash_canonical

MAX_PAGE_LIMIT = 500

__all__ = ["LIST_CURSOR_DOMAIN", "LIST_RECEIPT_DOMAIN", "MAX_PAGE_LIMIT", "ListError", "WindowReadAccumulator", "candidates_from_relation",
           "list_authorized", "list_bind", "objects_digest", "verify_list_cursor", "verify_list_receipt"]


class ListError(Exception):
    """``code`` is ``read_budget_exhausted``, ``bad_cursor`` or ``bad_limit``."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _RelationCandidates:
    def __init__(self, rel: Any, subject: str, relation: str) -> None:
        self._list = rel.list_objects
        self._subject, self._relation = subject, relation

    def page(self, q: dict) -> dict:
        return self._list({"subject": self._subject, "relation": self._relation, **q})


def candidates_from_relation(rel: Any, subject: str, relation: str) -> Any:
    """Adapt a relation source's ``list_objects`` into a candidate source for one subject and relation."""
    if not callable(getattr(rel, "list_objects", None)):
        raise TypeError("candidatesFromRelation: the relation source has no listObjects")
    return _RelationCandidates(rel, subject, relation)


class WindowReadAccumulator:
    """Reference accumulator: ``cap`` units per ``window_ms`` fixed window per key. ``charge`` returns False when the charge would exceed the cap."""

    def __init__(self, cap: Any, window_ms: Any) -> None:
        self._cap, self._window = cap, window_ms
        self._used: Dict[str, Dict[str, Any]] = {}

    def charge(self, key: str, units: Any, now: Any) -> bool:
        if not (fin(units) and fin(now)):
            return False
        e = self._used.get(key)
        cur = {"start": now, "n": 0} if e is None or now - e["start"] >= self._window else e
        if not (cur["n"] + units <= self._cap):
            return False
        cur["n"] += units
        self._used[key] = cur
        return True


def _enc_cursor(c: dict, secret: bytes) -> str:
    return "%s.%s" % (b64u(json.dumps(c, separators=(",", ":"), ensure_ascii=False).encode("utf-8")), sign_body(LIST_CURSOR_DOMAIN, c, secret))


def list_authorized(*, subject: str, resource_type: str, permits: Callable[[str], Any], candidates: Any, filter_id: str, policy_digest: str,
                    fresh_at_digest: str, page: dict, reads: Any, now: Any, signing_secret: bytes, relation: Optional[dict] = None,
                    max_scan: Optional[int] = None) -> dict:
    """One page of authorized objects: ``{objects, next_cursor?, receipt}``. ``relation`` is ``{source, relation}``; ``page`` is
    ``{cursor?, limit}``. Raises :class:`ListError` (``bad_limit``, ``bad_cursor``, ``read_budget_exhausted``)."""
    limit = page.get("limit")
    if not _is_safe_int(limit) or limit < 1 or limit > MAX_PAGE_LIMIT:
        raise ListError("bad_limit", "limit must be 1..%d" % MAX_PAGE_LIMIT)
    limit = int(limit)
    signer = signer_of(signing_secret)
    bind_inputs: Dict[str, Any] = {"subject": subject, "resourceType": resource_type, "filterId": filter_id, "policyDigest": policy_digest, "limit": limit}
    if relation is not None:
        bind_inputs["relation"] = relation
    bind = list_bind(bind_inputs)
    inner: Optional[str] = None
    skip_in = 0
    if page.get("cursor") is not None:
        c = verify_list_cursor(page["cursor"], signer, bind_inputs)
        if not c["ok"]:
            raise ListError("bad_cursor", "subject, type, filter, policy or limit changed between pages" if c["reason"] == "bind"
                            else "the page cursor is malformed, forged or from another signer")
        inner = c.get("inner")
        skip_in = c["skip"]
    max_scan_n = min(max_scan if max_scan is not None else limit * 4, 1000)
    key = hash_canonical({"s": subject, "t": resource_type})
    out: List[str] = []
    scanned = 0
    # candidate pages are always `limit` long so a resume point (page start + objects already consumed) is exact
    page_start = inner
    skip = skip_in
    resume: Optional[Dict[str, Any]] = None
    while True:
        q: Dict[str, Any] = {"type": resource_type, "limit": limit}
        if page_start is not None:
            q["cursor"] = page_start
        pg = candidates.page(q)
        objs = list(pg["objects"])[:limit]
        # charge what was SCANNED before anything is returned: enumeration by filter-heavy scans is the attack
        if not reads.charge(key, max(len(objs) - skip, 1), now):
            raise ListError("read_budget_exhausted", "the read budget for this subject and type is exhausted")
        i = skip
        while i < len(objs) and len(out) < limit:
            scanned += 1
            o = objs[i]
            i += 1
            if not permits(o):
                continue
            if relation is not None and not relation["source"].check({"subject": subject, "relation": relation["relation"], "object": o}):
                continue
            out.append(o)
        if i < len(objs):
            resume = {"skip": i}
            if page_start is not None:
                resume["inner"] = page_start
            break
        nxt = pg.get("next")
        if nxt is None or nxt == "" or len(objs) == 0:
            break
        page_start = nxt
        skip = 0
        if len(out) >= limit or scanned >= max_scan_n:
            resume = {"inner": nxt, "skip": 0}
            break
    receipt = {"v": 1, "subject": subject, "resource_type": resource_type, "policy_digest": policy_digest, "fresh_at": fresh_at_digest,
               "filter_digest": filter_id, "count": len(out), "objects_digest": objects_digest(out), "issued_at": now, "signer": signer}
    result: Dict[str, Any] = {"objects": out}
    if resume is not None:
        cur: Dict[str, Any] = {"v": 1}
        if "inner" in resume:
            cur["inner"] = resume["inner"]
        cur.update({"skip": resume["skip"], "bind": bind, "signer": signer})
        result["next_cursor"] = _enc_cursor(cur, signing_secret)
    result["receipt"] = {**receipt, "sig": sign_body(LIST_RECEIPT_DOMAIN, receipt, signing_secret)}
    return result
