"""The dispute evidence bundle `pca-intent-evidence` v1 (Intent Layer v2): closed-member shape validation, the deterministic normal
form, the commitments-only form and the digest that commits to it, the bundle reference and its anchor-log leaf, the accumulator
cap reader, and the validators of the verifier's trust inputs. Port of @atlasauth/pca-evidence of the TypeScript reference.

The full replay (`verify_evidence_bundle`) lives in atlas_pca.evidence_verify and is re-exported here. Not ported: the COSE signed
statement over the bundle reference and the command-line tool.

Inputs are JSON values; the reference's JavaScript semantics (property reads on any value, `Object.keys` order, relational
comparison, the `||` chain of the sort comparators, JSON round-trip copy) are reproduced where a hostile bundle reaches them, so a
malformed bundle gives the same shape error, the same order or the same refusal (an exception) as the reference.
"""
from __future__ import annotations

from ._fin import fin
import functools
import math
from typing import Any, Callable, Dict, List, Optional

from .authorize import read_envelope
from .explain import _UNDEF, _get, _gt, _iter, _keys, _lt, _rd, _to_num, _truthy
from .pca import decode_b64u_strict, hash_canonical
from .predicates import _js_string, is_group_condition, is_leaf_condition

EVIDENCE_DOMAIN = "atlas-pca/intent-evidence/v1"
EVIDENCE_REPORT_DOMAIN = "atlas-pca/intent-evidence-report/v1"
EVIDENCE_CONTENT_TYPE = "application/pca-intent-evidence+json"
INTENT_ANCHOR_DOMAIN = "atlas-pca/intent-anchor/v1"

_MAX_SAFE = 2 ** 53 - 1

_TOP_KEYS = ["v", "kind", "subject", "statement", "session_root", "schema", "root_grant", "maps", "answers", "canary_labels", "canaries",
             "deltas", "pcactns", "verdicts", "accumulator", "facts", "classifier", "offer_sets", "labels", "effects", "settlements",
             "revocation_epochs", "anchors"]


# ---- JavaScript value helpers --------------------------------------------------------------------------------------------------

def _is_obj(v: Any) -> bool:
    return isinstance(v, dict)


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _is_int(v: Any) -> bool:
    """A safe integer that is not -0."""
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return abs(v) <= _MAX_SAFE
    return isinstance(v, float) and fin(v) and v == math.floor(v) and abs(v) <= _MAX_SAFE and not (v == 0 and math.copysign(1, v) < 0)


def _is_one(v: Any) -> bool:
    return _is_num(v) and v == 1


def _present(o: Dict[str, Any], k: str) -> bool:
    return k in o


def _plain(v: Any) -> Any:
    """JSON.parse(JSON.stringify(v)): a deep copy in which -0 becomes 0."""
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    if isinstance(v, float) and v == 0:
        return 0
    return v


def _spread(v: Any) -> Dict[str, Any]:
    """The members `{...v}` copies: an object's own, an array's or a string's indices, nothing for any other value."""
    if isinstance(v, dict):
        return dict(v)
    if isinstance(v, list):
        return {str(i): x for i, x in enumerate(v)}
    if isinstance(v, str):
        return {str(i): c for i, c in enumerate(v)}
    return {}


def _cmp(a: Any, b: Any) -> int:
    return -1 if _lt(a, b) else 1 if _gt(a, b) else 0


def _sub(a: Any, b: Any) -> float:
    return _to_num(a) - _to_num(b)


def _or(first: float, rest: Callable[[], float]) -> float:
    """`first || rest()` for numbers: zero and NaN are falsy."""
    return first if (first != 0 and first == first) else rest()


def _sort(lst: Any, cmpfn: Callable[[Any, Any], float]) -> None:
    if not isinstance(lst, list):
        raise TypeError("sort is not a function")
    lst.sort(key=functools.cmp_to_key(cmpfn))


def _sort_set(v: Any) -> None:
    """`arr?.sort((a, c) => cmp(key(a), key(c)))`: absent or null is skipped; a non-array throws."""
    if v is _UNDEF or v is None:
        return
    _sort(v, lambda a, c: _cmp(hash_canonical(a), hash_canonical(c)))


# ---- shape -----------------------------------------------------------------------------------------------------------------------

def _closed(o: Any, keys: List[str], where: str) -> Optional[str]:
    if not _is_obj(o):
        return "%s must be an object" % where
    for k in _keys(o):
        if k not in keys:
            return '%s: unknown member "%s"' % (where, k)
    return None


def bundle_shape_error(b: Any) -> Optional[str]:
    """Closed-member shape validation (unknown members are refused at every level the bundle owns). None when well formed."""
    top = _closed(b, _TOP_KEYS, "bundle")
    if top:
        return top
    x = b
    g = lambda o, k: _get(o, k)  # noqa: E731
    if not _is_one(g(x, "v")) or g(x, "kind") != "pca-intent-evidence":
        return "not a pca-intent-evidence v1 bundle"
    subj = _closed(g(x, "subject"), ["pcactn_digest", "aud", "session"], "subject")
    if subj:
        return subj
    s = g(x, "subject")
    if not all(isinstance(g(s, k), str) for k in ("pcactn_digest", "aud", "session")):
        return "subject members must be strings"
    st = _closed(g(x, "statement"), ["commit", "opening"], "statement")
    if st:
        return st
    if not isinstance(g(g(x, "statement"), "commit"), str):
        return "statement.commit must be a string"
    sr = g(x, "session_root")
    if not _is_obj(sr) or not _is_one(g(sr, "v")) or g(sr, "kind") != "pca-intent-session":
        return "session_root is not a pca-intent-session v1"
    if not isinstance(g(sr, "session"), str) or not isinstance(g(sr, "intent_ref"), str) or not _is_int(g(sr, "expires_at")):
        return "session_root is missing session / intent_ref / expires_at"
    pr = g(sr, "principals")
    if not isinstance(pr, list) or len(pr) == 0 or not all(_is_obj(p) and isinstance(g(p, "key"), str) for p in pr):
        return "session_root.principals must be a non-empty key list"
    sc = _closed(g(x, "schema"), ["doc", "anchor"], "schema")
    if sc:
        return sc
    doc = g(g(x, "schema"), "doc")
    if not _is_obj(doc) or g(doc, "kind") != "pca-action-schema" or not _is_obj(g(doc, "sig")):
        return "schema.doc is not a signed pca-action-schema"
    if not _is_obj(g(x, "root_grant")):
        return "root_grant must be a capability"
    for k in ("maps", "answers", "canary_labels", "deltas", "pcactns", "verdicts", "effects", "revocation_epochs", "anchors"):
        if not isinstance(g(x, k), list):
            return "%s must be an array" % k
    for k in ("facts", "classifier", "offer_sets", "labels", "settlements"):
        if _present(x, k) and not isinstance(x[k], list):
            return "%s must be an array" % k
    for i, m in enumerate(x["maps"]):
        e = _closed(m, ["seq", "commit", "map", "disclosed"], "maps[%d]" % i)
        if e:
            return e
        if not _is_int(g(m, "seq")) or g(m, "seq") < 0 or not isinstance(g(m, "commit"), str):
            return "maps[%d] needs an integer seq and a commit" % i
    for i, c in enumerate(x["canary_labels"]):
        e = _closed(c, ["question_id", "label"], "canary_labels[%d]" % i)
        if e:
            return e
        lab = g(c, "label")
        if not isinstance(g(c, "question_id"), str) or not (_is_num(lab) and (lab == 0 or lab == 1)):
            return "canary_labels[%d] is malformed" % i
    cs = _closed(g(x, "canaries"), ["asked", "false_yes", "false_no"], "canaries")
    if cs:
        return cs
    cn = x["canaries"]
    if not all(_is_int(g(cn, k)) and g(cn, k) >= 0 for k in ("asked", "false_yes", "false_no")):
        return "canaries counts must be non-negative integers"
    ac = _closed(g(x, "accumulator"), ["holder", "events", "receipts", "sequencer_keys"], "accumulator")
    if ac:
        return ac
    acc = x["accumulator"]
    if g(acc, "holder") not in ("site_local", "sequenced") or not isinstance(g(acc, "holder"), str):
        return "accumulator.holder must be site_local or sequenced"
    if not isinstance(g(acc, "events"), list):
        return "accumulator.events must be an array"
    for i, ev in enumerate(acc["events"]):
        e = _closed(ev, ["acc", "post", "pcactn_digest", "delta", "status"], "accumulator.events[%d]" % i)
        if e:
            return e
        if (not isinstance(g(ev, "acc"), str) or not _is_int(g(ev, "post")) or g(ev, "post") < 0
                or not isinstance(g(ev, "pcactn_digest"), str)):
            return "accumulator.events[%d] is malformed" % i
        if _present(ev, "delta") and not (_is_int(ev["delta"]) and ev["delta"] >= 0):
            return "accumulator.events[%d].delta must be a non-negative integer" % i
    if _present(acc, "receipts") and not isinstance(acc["receipts"], list):
        return "accumulator.receipts must be an array"
    if _present(acc, "sequencer_keys") and not isinstance(acc["sequencer_keys"], list):
        return "accumulator.sequencer_keys must be an array"
    for i, r in enumerate(x["revocation_epochs"]):
        e = _closed(r, ["epoch", "revoked"], "revocation_epochs[%d]" % i)
        if e:
            return e
        if not _is_obj(g(r, "epoch")) or not isinstance(g(r, "revoked"), list):
            return "revocation_epochs[%d] needs an epoch and its revoked list" % i
    for i, a in enumerate(x["anchors"]):
        e = _closed(a, ["kind", "digest", "index", "proof", "signed_tree_head"], "anchors[%d]" % i)
        if e:
            return e
    for i, ef in enumerate(x["effects"]):
        if not _is_obj(ef) or not isinstance(g(ef, "pcactn_digest"), str):
            return "effects[%d] needs a pcactn_digest" % i
    return None


# ---- normal form -----------------------------------------------------------------------------------------------------------------

def _seq_of(c: Any) -> Any:
    cvs = _rd(c, "caveats")
    if not isinstance(cvs, list):
        raise TypeError("find is not a function")
    for k in cvs:
        if _rd(k, "type") == "intent_session":
            seq = _get(k, "seq")
            return seq if _is_int(seq) else _MAX_SAFE
    return _MAX_SAFE


def _effect_key(e: Any) -> str:
    """hashCanonical of the effect without its params opening (`const {params, ...k} = e`)."""
    if e is None or e is _UNDEF:
        raise TypeError("cannot destructure")
    return hash_canonical({k: v for k, v in _spread(e).items() if k != "params"})


def normalize_bundle(b: Any) -> Any:
    """Deterministic normal form: the members that are sets (answers, deltas, PCActns, verdicts, effects, epochs, anchors, maps,
    canary labels, ...) are sorted by a content key; `accumulator.events` is a sequence and is never reordered. Raises on a
    bundle that cannot be put in order (a refusal, like the reference's thrown error)."""
    x = _plain(b)
    key = hash_canonical
    r = lambda o, k: _rd(o, k)  # noqa: E731
    _sort(r(x, "maps"), lambda a, c: _or(_sub(r(a, "seq"), r(c, "seq")), lambda: _cmp(r(a, "commit"), r(c, "commit"))))
    _sort(r(x, "answers"), lambda a, c: _or(_sub(r(a, "observed_at"), r(c, "observed_at")),
                                            lambda: _or(_cmp(r(a, "question_id"), r(c, "question_id")), lambda: _cmp(r(a, "sig"), r(c, "sig")))))
    _sort(r(x, "canary_labels"), lambda a, c: _or(_cmp(r(a, "question_id"), r(c, "question_id")), lambda: _sub(r(a, "label"), r(c, "label"))))
    _sort(r(x, "deltas"), lambda a, c: _or(_sub(_seq_of(a), _seq_of(c)), lambda: _cmp(r(a, "id"), r(c, "id"))))
    _sort(r(x, "pcactns"), lambda a, c: _or(_sub(r(a, "iat"), r(c, "iat")),
                                            lambda: _or(_sub(r(a, "counter"), r(c, "counter")), lambda: _cmp(key(a), key(c)))))
    _sort(r(x, "verdicts"), lambda a, c: _or(_cmp(r(a, "pcactn_digest"), r(c, "pcactn_digest")), lambda: _cmp(key(a), key(c))))
    # sorted without the params opening, so withholding an opening never reorders the commitments-only form
    _sort(r(x, "effects"), lambda a, c: _or(_cmp(r(a, "pcactn_digest"), r(c, "pcactn_digest")), lambda: _cmp(_effect_key(a), _effect_key(c))))
    # issue order (not epoch number): a rollback, an epoch issued later with a lower number, must stay visible
    ep = lambda o, k: r(r(o, "epoch"), k)  # noqa: E731
    _sort(r(x, "revocation_epochs"), lambda a, c: _or(_sub(ep(a, "issued_at"), ep(c, "issued_at")),
                                                      lambda: _or(_sub(ep(a, "epoch"), ep(c, "epoch")), lambda: _cmp(key(a), key(c)))))
    _sort(r(x, "anchors"), lambda a, c: _or(_cmp(r(a, "kind"), r(c, "kind")),
                                            lambda: _or(_sub(r(a, "index"), r(c, "index")), lambda: _cmp(r(a, "digest"), r(c, "digest")))))
    for k in ("facts", "classifier", "offer_sets", "labels", "settlements"):
        _sort_set(_get(x, k))
    receipts = _get(r(x, "accumulator"), "receipts")
    if _truthy(receipts):
        _sort(receipts, lambda a, c: _cmp(key(a), key(c)))
    return x


def build_evidence_bundle(parts: Any) -> Any:
    """Assemble a bundle in normal form. Raises ValueError on a malformed part (the exporter's bug, not evidence)."""
    b: Dict[str, Any] = {"v": 1, "kind": "pca-intent-evidence"}
    b.update(_spread(parts))
    n = normalize_bundle(b)
    bad = bundle_shape_error(n)
    if bad:
        raise ValueError("buildEvidenceBundle: %s" % bad)
    return n


def _commitment(b: Any) -> Any:
    """(the commitments-only form, whether a committed member is undefined): an undefined member cannot be hashed."""
    n = normalize_bundle(b)
    rest = {k: v for k, v in n.items() if k != "anchors"}
    undef = False
    statement = _get(n, "statement")
    if statement is None or statement is _UNDEF:
        raise TypeError("cannot read 'commit' of undefined")
    commit = _get(statement, "commit")
    rest["statement"] = {}
    if commit is _UNDEF:
        undef = True
    else:
        rest["statement"]["commit"] = commit
    maps = []
    for m in n["maps"]:
        seq, mc, disclosed = _rd(m, "seq"), _rd(m, "commit"), _get(m, "disclosed")
        entry: Dict[str, Any] = {}
        for k, v in (("seq", seq), ("commit", mc)):
            if v is _UNDEF:
                undef = True
            else:
                entry[k] = v
        if disclosed is not _UNDEF:
            entry["disclosed"] = disclosed
        maps.append(entry)
    rest["maps"] = maps
    rest["effects"] = [{k: v for k, v in _spread(_check_obj(e)).items() if k != "params"} for e in n["effects"]]
    return rest, undef


def _check_obj(e: Any) -> Any:
    if e is None or e is _UNDEF:
        raise TypeError("cannot destructure")
    return e


def commitment_form(b: Any) -> Any:
    """The commitments-only normal form: no anchors, no statement opening, no full maps, no effect params; every signed artifact
    and every claim stays in."""
    return _commitment(b)[0]


def evidence_digest(b: Any) -> str:
    """The bundle's content address: the hash over the commitments-only normal form."""
    form, undef = _commitment(b)
    if undef:
        raise TypeError("canonicalize: undefined member")
    return hash_canonical({"d": EVIDENCE_DOMAIN, "b": form})


def evidence_ref(bundle: Any) -> Dict[str, Any]:
    """The public reference to a bundle: its digest and subject (the bundle itself stays with the site)."""
    digest = evidence_digest(bundle)
    return {"kind": "pca-intent-evidence-ref", "digest": digest, "subject": _spread(_rd(bundle, "subject"))}


def anchor_commit(kind: Any, digest: Any) -> str:
    """The intent-log leaf for an anchored artifact (any kind)."""
    return hash_canonical({"d": INTENT_ANCHOR_DOMAIN, "kind": kind, "digest": digest})


def evidence_anchor_commit(digest: Any) -> str:
    return anchor_commit("evidence", digest)


# ---- accumulator cap -------------------------------------------------------------------------------------------------------------

def _leaf_caps(conds: Any, path: str) -> List[Any]:
    out: List[Any] = []
    for c in _iter([] if conds is None or conds is _UNDEF else conds):
        if is_leaf_condition(c):
            if c["field"] != path or "ref" in c or not _is_num(c.get("value")):
                continue
            if c.get("op") == "lte":
                out.append(c["value"])
            elif c.get("op") == "lt":
                out.append(c["value"] - 1)
        elif is_group_condition(c) and "all_of" in c:
            out.extend(_leaf_caps(c["all_of"], path))
    return out


def cap_of(grant: Any, acc_id: Any, verb: Any) -> Any:
    """The cap `env.acc.<id>.post <= v` that the grant's envelope states for `verb`: per predicate the tightest bound in its `where`
    (descending into `all_of`); across predicates (a union) the loosest. None when a predicate admitting the verb states no bound,
    or none admits it."""
    env = read_envelope(grant)
    if not env:
        return None
    path = "env.acc.%s.post" % _js_string(acc_id)
    cap: Any = None
    for p in env["predicates"]:
        pv = _rd(p, "verb")
        verbs = [_js_string(x) for x in pv] if isinstance(pv, list) else [_js_string(pv)]
        if verb not in verbs and "*" not in verbs:
            continue
        caps = _leaf_caps(_get(p, "where"), path)
        if len(caps) == 0:
            return None
        m = min(caps)
        cap = m if cap is None else max(cap, m)
    return cap


# ---- trust-input validators ------------------------------------------------------------------------------------------------------

def principals_trust_error(p: Any = _UNDEF) -> Optional[str]:
    """Validate `trust.principals`: a non-empty array of closed `{key, pq_pk?}` with canonical keys. None = valid (an absent value
    is valid)."""
    if p is _UNDEF:
        return None
    if not isinstance(p, list) or len(p) == 0:
        return "trust.principals must be a non-empty array of {key, pq_pk?}"
    for i, x in enumerate(p):
        if not isinstance(x, dict):
            return "trust.principals[%d] must be an object {key, pq_pk?}" % i
        for k in _keys(x):
            if k != "key" and k != "pq_pk":
                return "trust.principals[%d]: unknown member '%s'" % (i, k)
        if decode_b64u_strict(x.get("key"), 32) is None:
            return "trust.principals[%d].key must be canonical base64url (32 bytes)" % i
        if "pq_pk" in x and decode_b64u_strict(x["pq_pk"]) is None:
            return "trust.principals[%d].pq_pk must be canonical base64url" % i
    return None


def acc_trust_error(a: Any = _UNDEF) -> Optional[str]:
    """Validate `trust.acc` like the core `policy.acc`: closed members, non-negative safe integers. None = valid."""
    if a is _UNDEF:
        return None
    if not isinstance(a, dict):
        return "trust.acc must be an object"
    for k in _keys(a):
        v = a[k]
        if k != "max_receipt_age_s" and k != "max_keyset_age_s":
            return "trust.acc: unknown member '%s'" % k
        if not (_is_int(v) and v >= 0):
            return "trust.acc.%s must be a non-negative safe integer" % k
    return None


def verify_evidence_bundle(bundle: Any, trust: Any = None) -> Dict[str, Any]:
    """Replay a dispute evidence bundle against the reader's trust inputs and return the findings report (see atlas_pca.evidence_verify)."""
    from .evidence_verify import verify_evidence_bundle as _verify  # deferred: the replay imports most of the intent modules
    return _verify(bundle, trust)


def evidence_signed_statement(bundle: Any, alg: str, key: Any, issuer: str, subject: Any = None) -> bytes:
    """A COSE Signed Statement over the bundle reference, ready to register with a SCITT service. `subject` defaults to the bundle subject's
    ``pcactn_digest``. `alg`, `key` and `issuer` are those of :func:`atlas_pca.scitt.sign_statement`."""
    from .scitt import sign_statement
    ref = evidence_ref(bundle)
    return sign_statement(ref, alg, key, issuer, ref["subject"].get("pcactn_digest") if subject is None else subject, EVIDENCE_CONTENT_TYPE)
