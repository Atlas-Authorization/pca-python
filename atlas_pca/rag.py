"""FGA for RAG (the TypeScript ``pca-rag``): retrieval-time, per-principal document filtering driven by the PCA policy engine.

Given a principal (or a verified PCActn's holder), candidate documents that each carry ACL metadata (a ``{"relation", "object"}`` entry or
``relation:object`` tags) and a policy (raw PCA predicates, an OpenFGA model and tuples, or an envelope ``{"predicates", "denies"?,
"report"?}``), :func:`filter_documents` returns ONLY the documents the principal may see. FAIL CLOSED: a document is admitted only when a
permit predicate cleanly matches and no deny predicate matches; anything unknown (no ACL, an unreadable document, an incomplete policy
translation) is dropped. Every decision is captured in a decision record with a content-addressed ``digest`` of the whole decision set.
Documents are dicts (or objects exposing ``id`` / ``acl`` / ``tags`` through ``getattr``); decision records use the reference's member
names (``allowedIds``, ``droppedIds``, ``policyIncomplete``, ...)."""
import asyncio
import inspect
from typing import Any, Callable, Dict, List, Optional

from .pca import hash_canonical
from .policy_bridge import _MISSING, decide, openfga_to_pca

__all__ = ["principal_from_pcactn", "acls_from_metadata", "compile_policy", "filter_documents", "with_pca_filter",
           "with_langchain_pca_filter", "with_llamaindex_pca_filter"]


def _to_principal(p: Any) -> Optional[dict]:
    if isinstance(p, str):
        return {"id": p}
    return p if isinstance(p, dict) else None


def _spread(v: Any) -> dict:
    """JS object spread ``{...v}``: an object as is, an array or a string by index (a string per UTF-16 code unit), any other value nothing."""
    if isinstance(v, dict):
        return v
    if isinstance(v, list):
        return {str(i): x for i, x in enumerate(v)}
    if isinstance(v, str):
        b = v.encode("utf-16-le", "surrogatepass")
        return {str(i): b[2 * i:2 * i + 2].decode("utf-16-le", "surrogatepass") for i in range(len(b) // 2)}
    return {}


_UNSET: Any = object()  # JS undefined: an explicit None (null) is kept, as the reference keeps it


def principal_from_pcactn(p: Any, id: Optional[str] = None, attributes: Any = _UNSET, env: Any = _UNSET) -> dict:
    """The acting identity of an (already verified) PCActn: the LEAF capability holder. `id` maps that key to the identity the policy is keyed
    on; it defaults to the raw leaf holder. Raises TypeError on a PCActn with no capability chain."""
    chain = p.get("cap_chain") if isinstance(p, dict) and isinstance(p.get("cap_chain"), list) else []
    leaf = chain[-1] if chain else None
    if not isinstance(leaf, dict) or not isinstance(leaf.get("holder"), str) or len(leaf["holder"]) == 0:
        raise TypeError("principalFromPCActn: PCActn has no leaf capability holder")
    out: Dict[str, Any] = {"id": leaf["holder"] if id is None else id}
    if attributes is not _UNSET:
        out["attributes"] = attributes
    if env is not _UNSET:
        out["env"] = env
    return out


def _is_acl(v: Any) -> bool:
    return isinstance(v, dict) and isinstance(v.get("relation"), str) and len(v["relation"]) > 0 \
        and isinstance(v.get("object"), str) and len(v["object"]) > 0


def _acl_array(acl: Any) -> List[dict]:
    if isinstance(acl, list):
        return [a for a in acl if _is_acl(a)]
    return [acl] if _is_acl(acl) else []


def _tag_to_acl(tag: Any) -> Optional[dict]:
    if not isinstance(tag, str):
        return None
    i = tag.find(":")
    if i <= 0 or i >= len(tag) - 1:
        return None
    return {"relation": tag[:i], "object": tag[i + 1:]}  # the split is at the FIRST ':' so an object id may itself contain ':'


def acls_from_metadata(acl: Any, tags: Any) -> List[dict]:
    """Collect ACL entries from freeform ``acl`` and ``tags`` metadata."""
    out = _acl_array(acl)
    if isinstance(tags, list):
        for t in tags:
            a = _tag_to_acl(t)
            if a is not None:
                out.append(a)
    return out


def _incomplete(reason: str) -> dict:
    return {"predicates": [], "denies": [], "incomplete": True, "incompleteReason": reason}


def compile_policy(policy: Any) -> dict:
    """Compile a policy (a predicate list, ``{"openfga": {"model", "tuples"}}`` or ``{"predicates", "denies"?, "report"?}``), or pass an
    already compiled one through. Total: a value that is not a policy is an incomplete policy (nothing is admitted)."""
    if not isinstance(policy, (dict, list)):
        return _incomplete("no usable policy was supplied (fail closed)")
    if isinstance(policy, dict) and isinstance(policy.get("incomplete"), bool):
        return policy
    if isinstance(policy, list):
        return {"predicates": policy, "denies": [], "incomplete": False}
    if "openfga" not in policy and not isinstance(policy.get("predicates"), list):
        return _incomplete("the policy has no predicates and is not an OpenFGA policy (fail closed)")
    if "openfga" in policy:
        fga = policy["openfga"]
        if not isinstance(fga, (dict, list)):
            return _incomplete("the OpenFGA policy has no model (fail closed)")
        fd = fga if isinstance(fga, dict) else {}  # an array has no model / tuples members
        br = openfga_to_pca(fd.get("model"), fd.get("tuples", _MISSING))
        return {"predicates": br["predicates"], "denies": br["denies"], "report": br["report"], "incomplete": len(br["report"]["errors"]) > 0}
    out = {"predicates": policy["predicates"] if isinstance(policy.get("predicates"), list) else [],
           "denies": policy["denies"] if isinstance(policy.get("denies"), list) else []}
    if "report" in policy:
        report = policy["report"]
        errs = report.get("errors", _MISSING) if isinstance(report, dict) else _MISSING  # report.errors.length throws unless errors is defined
        if errs is _MISSING or errs is None:
            raise TypeError("Cannot read properties of %s (reading 'length')" % ("undefined" if errs is _MISSING else "null"))
        out["incomplete"] = (len(errs) if isinstance(errs, (list, str)) else 0) > 0
        out["report"] = report
    else:
        out["incomplete"] = False
    return out


def _decide_document(doc_id: str, acls: List[dict], principal: dict, compiled: dict) -> dict:
    if compiled["incomplete"]:
        return {"id": doc_id, "allowed": False, "reason": compiled.get("incompleteReason") or "policy translation incomplete (fail closed)"}
    if not isinstance(principal.get("id"), str) or len(principal["id"]) == 0:
        return {"id": doc_id, "allowed": False, "reason": "no principal identity (fail closed)"}
    if not acls:
        return {"id": doc_id, "allowed": False, "reason": "no decidable ACL metadata (fail closed)"}
    last = "no relation grants access (fail closed)"
    for acl in acls:
        ctx: Dict[str, Any] = {"action": {"verb": acl["relation"], "resource": acl["object"]},
                               "subject": {**_spread(principal.get("attributes")), "id": principal["id"]}}
        if principal.get("env") is not None:
            ctx["env"] = principal["env"]
        try:
            res = decide({"predicates": compiled["predicates"], "denies": compiled["denies"]}, ctx)
        except Exception:  # noqa: BLE001 - fail closed
            last = "evaluator error (fail closed)"
            continue
        if res.get("allowed"):
            d = {"id": doc_id, "allowed": True, "via": acl, "reason": "granted: %s has %s on %s" % (principal["id"], acl["relation"], acl["object"])}
            if res.get("matched") is not None:
                d["matched"] = res["matched"]
            return d
        if res.get("reason") is not None:
            last = res["reason"]
    return {"id": doc_id, "allowed": False, "reason": last}


def _run_filter(principal_input: Any, candidates: Any, policy: Any, get_id: Callable[[Any, int], Any], get_acls: Callable[[Any], Any]) -> dict:
    principal = _to_principal(principal_input) or {"id": ""}
    compiled = compile_policy(policy)
    items = candidates if isinstance(candidates, list) else []
    documents, decisions, allowed_ids, dropped_ids, allowed_idx, seen = [], [], [], [], [], set()
    for i, doc in enumerate(items):
        try:
            did = get_id(doc, i)
            acls = _acl_array(get_acls(doc))  # entries that are not {relation, object} strings are not ACLs
        except Exception:  # noqa: BLE001 - metadata that cannot be read is unknown: fail closed
            fid = "doc#%d" % i
            decisions.append({"id": fid, "allowed": False, "reason": "unreadable document metadata (fail closed)"})
            dropped_ids.append(fid)
            continue
        if not isinstance(did, str) or len(did) == 0:
            did = "doc#%d" % i
        if did in seen:  # two candidates with one id are told apart by position
            did = "%s#dup%d" % (did, i)
        seen.add(did)
        d = _decide_document(did, acls, principal, compiled)
        decisions.append(d)
        if d["allowed"]:
            documents.append(doc)
            allowed_ids.append(did)
            allowed_idx.append(i)
        else:
            dropped_ids.append(did)
    base = {"principal": principal["id"] if isinstance(principal.get("id"), str) else "", "considered": len(items), "allowedIds": allowed_ids,
            "allowedIndexes": allowed_idx, "droppedIds": dropped_ids, "policyIncomplete": compiled["incomplete"]}
    digest = hash_canonical({"v": 1, "kind": "pca-rag/filter", **base})
    decision = {**base, "decisions": decisions, "digest": digest}
    if compiled.get("report") is not None:
        decision["report"] = compiled["report"]
    return {"documents": documents, "decision": decision}


def _attr(doc: Any, key: str) -> Any:
    return doc.get(key) if isinstance(doc, dict) else getattr(doc, key, None)


def _default_id(doc: Any, _i: int = 0) -> Any:
    if doc is None:
        raise TypeError("cannot read properties of null")  # the reference throws on `doc.id`: the document is unreadable (fail closed)
    return _attr(doc, "id")


def _default_acls(doc: Any) -> List[dict]:
    return acls_from_metadata(_attr(doc, "acl"), _attr(doc, "tags"))


def filter_documents(principal: Any, candidates: List[Any], policy: Any, get_id: Optional[Callable[[Any, int], str]] = None,
                     get_acls: Optional[Callable[[Any], List[dict]]] = None) -> Dict[str, Any]:
    """Filter a candidate set to the documents `principal` may see under `policy`: ``{"documents", "decision"}`` (admitted documents in
    candidate order, and the proof trace). `get_id` / `get_acls` override how a document's id and ACL entries are read."""
    return _run_filter(principal, candidates, policy, get_id or _default_id, get_acls or _default_acls)


def _record_retrieved(recorder: Any, docs: List[Any], get_id: Callable[[Any, int], Any]) -> None:
    """Record every admitted document as untrusted retrieval content (a document's text can carry an injected instruction)."""
    if recorder is None:
        return
    for i, doc in enumerate(docs):
        try:
            src = get_id(doc, i)
            src = src if isinstance(src, str) and src else "doc#%d" % i
        except Exception:  # noqa: BLE001
            src = "doc#%d" % i
        recorder.retrieval(src, doc)


class _Filtered:
    def __init__(self) -> None:
        self._last: Optional[dict] = None

    def last_decision(self) -> Optional[dict]:
        """The decision (proof trace) of the most recent retrieval, or None."""
        return self._last


def with_pca_filter(retriever: Any, principal: Any, policy: Any, get_id: Optional[Callable[[Any, int], str]] = None,
                    get_acls: Optional[Callable[[Any], List[dict]]] = None, recorder: Any = None) -> Any:
    """Wrap a retriever (``retrieve(query, k=None)``, sync or async) so every result set is filtered to what `principal` may see BEFORE it
    reaches the model. The wrapper has the same ``retrieve`` (a coroutine when the wrapped one is) plus ``last_decision()``."""
    compiled = compile_policy(policy)
    gid, gacl = get_id or _default_id, get_acls or _default_acls
    out = _Filtered()

    def finish(docs: Any) -> List[Any]:
        res = _run_filter(principal, docs if isinstance(docs, list) else [], compiled, gid, gacl)
        out._last = res["decision"]
        _record_retrieved(recorder, res["documents"], gid)
        return res["documents"]

    if inspect.iscoroutinefunction(getattr(retriever, "retrieve", None)):
        async def aretrieve(query: str, k: Any = None) -> List[Any]:
            return finish(await retriever.retrieve(query, k))
        out.retrieve = aretrieve  # type: ignore[attr-defined]
    else:
        out.retrieve = lambda query, k=None: finish(retriever.retrieve(query, k))  # type: ignore[attr-defined]
    return out


def _meta_string(meta: Any, key: str) -> Optional[str]:
    if not isinstance(meta, dict):
        return None
    v = meta.get(key)
    return v if isinstance(v, str) and len(v) > 0 else None


def with_langchain_pca_filter(retriever: Any, principal: Any, policy: Any, get_id: Optional[Callable[[Any, int], str]] = None,
                              get_acls: Optional[Callable[[Any], List[dict]]] = None, recorder: Any = None) -> Any:
    """Wrap a LangChain-shaped retriever (``invoke`` or ``get_relevant_documents``): results are filtered post-retrieval; ACLs are read from
    each document's ``metadata`` (``acl`` and ``tags``). Documents expose ``page_content`` and ``metadata``. The wrapper has ``invoke`` and
    ``get_relevant_documents`` (both coroutines when the wrapped call is) and ``last_decision()``."""
    compiled = compile_policy(policy)
    gid = get_id or (lambda doc, i: _meta_string(_attr(doc, "metadata"), "id") or _meta_string(_attr(doc, "metadata"), "source") or "doc#%d" % i)
    gacl = get_acls or (lambda doc: acls_from_metadata((_attr(doc, "metadata") or {}).get("acl"), (_attr(doc, "metadata") or {}).get("tags")))
    out = _Filtered()
    fn = getattr(retriever, "invoke", None)
    if not callable(fn):
        fn = getattr(retriever, "get_relevant_documents", None)
    if not callable(fn):
        raise TypeError("withLangChainPcaFilter: retriever has neither invoke nor get_relevant_documents")

    def finish(docs: Any) -> List[Any]:
        res = _run_filter(principal, docs if isinstance(docs, list) else [], compiled, gid, gacl)
        out._last = res["decision"]
        _record_retrieved(recorder, res["documents"], gid)
        return res["documents"]

    if inspect.iscoroutinefunction(fn):
        async def arun(q: str) -> List[Any]:
            return finish(await fn(q))
        out.invoke = out.get_relevant_documents = arun  # type: ignore[attr-defined]
    else:
        out.invoke = out.get_relevant_documents = lambda q: finish(fn(q))  # type: ignore[attr-defined]
    return out


def with_llamaindex_pca_filter(retriever: Any, principal: Any, policy: Any, get_id: Optional[Callable[[Any, int], str]] = None,
                               get_acls: Optional[Callable[[Any], List[dict]]] = None, recorder: Any = None) -> Any:
    """Wrap a LlamaIndex-shaped retriever (``retrieve(query)`` returning node-with-score items that carry a ``node`` with ``id_`` and
    ``metadata``): the result is filtered post-retrieval; ACLs are read from each node's ``metadata`` (``acl`` and ``tags``)."""
    compiled = compile_policy(policy)

    def node_meta(item: Any) -> Any:
        return _attr(_attr(item, "node"), "metadata") or {}

    def default_id(item: Any, i: int) -> str:
        nid = _attr(_attr(item, "node"), "id_")
        return nid if isinstance(nid, str) and nid else (_meta_string(node_meta(item), "id") or "node#%d" % i)

    gid = get_id or default_id
    gacl = get_acls or (lambda item: acls_from_metadata(node_meta(item).get("acl"), node_meta(item).get("tags")))
    out = _Filtered()

    def finish(items: Any) -> List[Any]:
        res = _run_filter(principal, items if isinstance(items, list) else [], compiled, gid, gacl)
        out._last = res["decision"]
        _record_retrieved(recorder, res["documents"], gid)
        return res["documents"]

    if inspect.iscoroutinefunction(getattr(retriever, "retrieve", None)):
        async def aretrieve(params: Any) -> List[Any]:
            return finish(await retriever.retrieve(params))
        out.retrieve = aretrieve  # type: ignore[attr-defined]
    else:
        out.retrieve = lambda params: finish(retriever.retrieve(params))  # type: ignore[attr-defined]
    return out
