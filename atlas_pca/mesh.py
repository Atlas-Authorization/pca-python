"""Cross-domain mesh proofs (the agent mesh, mesh.ts `verifyMeshProof`). A mesh proof carries a capability chain, one
witnessed head per issuing domain, per-hop log inclusion and revocation non-membership proofs, and a signed leaf action.
`verify_mesh_proof` checks all of it offline and returns the reference's reason and failing hop (-1 when none is named).

Scope: everything verifyMeshProof does, including RFC 9162 consistency proofs from a pinned head. The witness side
(cosigning, head publication) is not here: a verifier only needs to check what they produced."""
from typing import Any, NamedTuple, Optional

from .intent_v2 import _UNDEF, _UTF8_ORDER, _js_str, verify_non_membership
from .ledger import verify_ledger_consistency
from .pca import _is_num, _js_nonneg_int, _verify_b64u, canonical_bytes_strict, cap_hash, verify_chain, verify_inclusion
from .predicates import _js_number_string

MESH_HEAD_DOMAIN = "atlas-pca/mesh-head/v1\x00"
MESH_COSIG_DOMAIN = "atlas-pca/mesh-cosig/v1\x00"
MESH_BINDING_DOMAIN = "atlas-pca/mesh-binding/v1\x00"
MESH_ACTION_DOMAIN = "atlas-pca/mesh-action/v1\x00"
DEFAULT_MAX_HEAD_AGE_MS = 5 * 60_000
DEFAULT_MAX_CLOCK_SKEW_MS = 60_000
DEFAULT_MAX_CHAIN_LENGTH = 64
_MAX_COSIGS = 256
_MAX_PATH = 128


class MeshVerdict(NamedTuple):
    ok: bool
    reason: Optional[str] = None
    hop: int = -1


def _fail(reason: str, hop: int) -> MeshVerdict:
    return MeshVerdict(False, reason, hop)


def _str(x: Any) -> bool:
    return isinstance(x, str)


def _strings(v: Any) -> Optional[list]:
    return v if isinstance(v, list) and all(_str(x) for x in v) else None


def _truthy(v: Any) -> bool:
    if v is None or v is False:
        return False
    if _is_num(v):
        return v != 0
    if isinstance(v, str):
        return v != ""
    return True


def _msg(domain: str, body: Any) -> Optional[bytes]:
    try:
        return domain.encode("utf-8") + canonical_bytes_strict(body)
    except Exception:  # noqa: BLE001 - a body that is not canonicalisable has no message
        return None


def _valid_head(h: Any) -> Optional[dict]:
    if not (isinstance(h, dict) and _str(h.get("domain")) and _str(h.get("root")) and _str(h.get("rev_root"))):
        return None
    if not (_js_nonneg_int(h.get("size")) and _js_nonneg_int(h.get("rev_size")) and _is_num(h.get("timestamp"))):
        return None
    return h if (h["size"] == 0) == (h["root"] == "") else None


def _valid_consistency(c: Any) -> Optional[dict]:
    if not (isinstance(c, dict) and _js_nonneg_int(c.get("oldSize")) and _js_nonneg_int(c.get("newSize"))):
        return None
    p = c.get("path")
    return c if isinstance(p, list) and len(p) <= _MAX_PATH and all(_str(x) for x in p) else None


def _valid_inclusion(i: Any) -> Optional[dict]:
    if not (isinstance(i, dict) and _js_nonneg_int(i.get("index")) and _js_nonneg_int(i.get("size"))):
        return None
    return i if isinstance(i.get("path"), list) and len(i["path"]) <= _MAX_PATH else None


def _valid_action(a: Any) -> Optional[dict]:
    if not (isinstance(a, dict) and all(_str(a.get(k)) for k in ("type", "resource", "service_domain", "nonce")) and _is_num(a.get("at"))):
        return None
    return None if "amount" in a and not _is_num(a["amount"]) else a


# ---- effective authority ----

def _intersect(have: bool, a: Optional[list], b: list) -> list:
    if not have:
        return sorted(dict.fromkeys(b), key=_UTF8_ORDER)
    return [x for x in a if x in b]


def _min(cur: Any, v: Any) -> Any:
    return v if cur is None else min(cur, v)


def _effective(caveats: Any):
    """[authority, None] or [None, reason] (an unknown or malformed caveat)."""
    e = {"actions": None, "prefixes": [], "max_amount": None, "expires_at": None, "audience": None, "max_hops": None}
    if not isinstance(caveats, list):
        return None, "malformed proof"
    for c in caveats:
        if not isinstance(c, dict):
            return None, "malformed proof"
        t = c.get("type")
        if t == "scope":
            a = _strings(c.get("actions"))
            if a is None:
                return None, "malformed scope caveat"
            e["actions"] = _intersect(e["actions"] is not None, e["actions"], a)
        elif t == "resource":
            if not _str(c.get("prefix")):
                return None, "malformed resource caveat"
            e["prefixes"].append(c["prefix"])
        elif t == "max_amount":
            if not _is_num(c.get("max")):
                return None, "malformed max_amount caveat"
            e["max_amount"] = _min(e["max_amount"], c["max"])
        elif t == "expires":
            if not _is_num(c.get("at")):
                return None, "malformed expires caveat"
            e["expires_at"] = _min(e["expires_at"], c["at"])
        elif t == "audience":
            d = _strings(c.get("domains"))
            if d is None:
                return None, "malformed audience caveat"
            e["audience"] = _intersect(e["audience"] is not None, e["audience"], d)
        elif t == "max_hops":
            if not _is_num(c.get("n")):
                return None, "malformed max_hops caveat"
            e["max_hops"] = _min(e["max_hops"], c["n"])
        else:
            return None, 'unknown caveat type "%s" (fail closed)' % _js_str(c.get("type", _UNDEF))
    return e, None


def _narrows(child: dict, parent: dict) -> bool:
    for k in ("actions", "audience"):
        if parent[k] is not None and (child[k] is None or not all(x in parent[k] for x in child[k])):
            return False
    for k in ("max_amount", "expires_at", "max_hops"):
        if parent[k] is not None and (child[k] is None or child[k] > parent[k]):
            return False
    return all(p in child["prefixes"] for p in parent["prefixes"])


def _num_s(x: Any) -> str:
    return _js_number_string(float(x))


def _admits(e: dict, a: dict, now: Any, chain_len: int) -> Optional[str]:
    if e["actions"] is not None and a["type"] not in e["actions"]:
        return 'action "%s" not in scope' % a["type"]
    for p in e["prefixes"]:
        if not a["resource"].startswith(p):
            return 'resource "%s" outside prefix "%s"' % (a["resource"], p)
    if e["max_amount"] is not None and ("amount" not in a or a["amount"] > e["max_amount"]):
        return "amount exceeds ceiling " + _num_s(e["max_amount"])
    if e["expires_at"] is not None and now > e["expires_at"]:
        return "capability expired"
    if e["audience"] is not None and a["service_domain"] not in e["audience"]:
        return "service domain not in audience"
    if e["max_hops"] is not None and chain_len > e["max_hops"]:
        return "chain exceeds max_hops " + _num_s(e["max_hops"])
    return None


# ---- heads ----

def check_head_advance(prev: Any, nxt: Any, proof: Any = None) -> Optional[str]:
    """Is `nxt` a legitimate successor of `prev` (same domain)? A failure reason or None (checkHeadAdvance)."""
    p = _valid_head(prev)
    n = _valid_head(nxt)
    if p is None or n is None:
        return "malformed head"
    if p["domain"] != n["domain"]:
        return "head is for a different domain"
    if n["size"] < p["size"] or n["rev_size"] < p["rev_size"]:
        return "head rolls back"
    if n["size"] == p["size"]:
        if n["root"] != p["root"]:
            return "equivocation (same size, different log)"
    else:
        c = _valid_consistency(proof)
        if c is None or c["oldSize"] != p["size"] or c["newSize"] != n["size"]:
            return "consistency proof required for a larger head"
        if not verify_ledger_consistency(p["root"], n["root"], c):
            return "head is not consistent with the previous head (fork or rewrite)"
    if n["rev_size"] == p["rev_size"] and n["rev_root"] != p["rev_root"]:
        return "equivocation (revocation set)"
    return None


def _opt(t: dict, k: str, default: Any) -> Any:
    if k not in t:
        return default
    return t[k] if _is_num(t[k]) and t[k] >= 0 else None


def _valid_trust(t: Any):
    """The validated trust configuration as a dict, or a reason string."""
    if not isinstance(t, dict) or not _str(t.get("humanPrincipal")):
        return "invalid trust configuration"
    ws = _strings(t.get("witnesses"))
    if ws is None:
        return "invalid trust configuration"
    c = {"human": t["humanPrincipal"], "witnesses": list(dict.fromkeys(ws))}
    if not (_js_nonneg_int(t.get("threshold")) and 1 <= t["threshold"] <= len(c["witnesses"])):
        return "invalid trust configuration: threshold"
    c["threshold"] = t["threshold"]
    if not _is_num(t.get("now")):
        return "invalid trust configuration: now"
    c["now"] = t["now"]
    c["max_head_age"] = _opt(t, "maxHeadAgeMs", DEFAULT_MAX_HEAD_AGE_MS)
    if c["max_head_age"] is None:
        return "invalid trust configuration: maxHeadAgeMs"
    c["max_skew"] = _opt(t, "maxClockSkewMs", DEFAULT_MAX_CLOCK_SKEW_MS)
    if c["max_skew"] is None:
        return "invalid trust configuration: maxClockSkewMs"
    c["max_action_age"] = None
    if "maxActionAgeMs" in t:
        c["max_action_age"] = _opt(t, "maxActionAgeMs", 0)
        if c["max_action_age"] is None:
            return "invalid trust configuration: maxActionAgeMs"
    c["max_chain"] = DEFAULT_MAX_CHAIN_LENGTH
    if "maxChainLength" in t:
        if not (_js_nonneg_int(t["maxChainLength"]) and t["maxChainLength"] >= 1):
            return "invalid trust configuration: maxChainLength"
        c["max_chain"] = t["maxChainLength"]
    ad = _strings(t.get("allowedDomains"))
    if not ad:
        return "invalid trust configuration: allowedDomains is required"
    c["allowed"] = ad
    rd = t.get("rootDomain")
    if not (_str(rd) and rd in ad):
        return "invalid trust configuration: rootDomain is required and must be in allowedDomains"
    c["root_domain"] = rd
    c["issuer_domains"] = None
    if "issuerDomains" in t:
        m = t["issuerDomains"]
        if not (isinstance(m, dict) and all(_str(x) for x in m.values())):
            return "invalid trust configuration: issuerDomains"
        c["issuer_domains"] = m
    c["pinned"] = None
    if "pinnedHeads" in t:
        if not isinstance(t["pinnedHeads"], dict):
            return "invalid trust configuration: pinnedHeads"
        c["pinned"] = t["pinnedHeads"]
    c["pq_pins"] = {k: v for k, v in t["pqPins"].items() if _str(v)} if isinstance(t.get("pqPins"), dict) else None
    return c


def _check_cosigned_head(ch: Any, expected_domain: str, t: dict, pin_proof: Any) -> Optional[str]:
    chm = ch if isinstance(ch, dict) else {}
    h = chm.get("head")
    if not isinstance(h, dict) or h.get("domain") != expected_domain:
        return "head is for a different domain"
    if _valid_head(h) is None:
        return "malformed head"
    sig = chm.get("sig")
    if not _str(sig):
        return "malformed head"
    domain = h["domain"]
    m = _msg(MESH_HEAD_DOMAIN, h)
    if m is None or not _verify_b64u(domain, m, sig):
        return "head not signed by its domain key"
    cosigs = chm.get("cosigs")
    if not (isinstance(cosigs, list) and len(cosigs) <= _MAX_COSIGS):
        return "malformed head"
    good = set()
    cm = _msg(MESH_COSIG_DOMAIN, h)
    for c in cosigs:
        if not (isinstance(c, dict) and _str(c.get("witness")) and _str(c.get("sig"))):
            continue
        w = c["witness"]
        if w in t["witnesses"] and w not in good and cm is not None and _verify_b64u(w, cm, c["sig"]):
            good.add(w)
    if len(good) < t["threshold"]:
        return "head has %d/%s trusted witness cosignatures" % (len(good), _num_s(t["threshold"]))
    ts = h["timestamp"]
    if ts > t["now"] + t["max_skew"]:
        return "head timestamp is in the future"
    if t["now"] - ts > t["max_head_age"]:
        return "head is stale"
    if t["pinned"] is not None and domain in t["pinned"] and _truthy(t["pinned"][domain]):
        why = check_head_advance(t["pinned"][domain], h, pin_proof)
        if why is not None:
            return why + " (vs pinned head)"
    return None


def _expand_nm(c: Any, leaves: list):
    if not (isinstance(c, dict) and _js_nonneg_int(c.get("size"))):
        return None
    out = {"size": c["size"]}
    for side in ("lo", "hi"):
        if side in c:
            ix = c[side]
            if not (_js_nonneg_int(ix) and ix < len(leaves)):
                return None
            out[side] = leaves[int(ix)]
    return out


def verify_mesh_proof(proof: Any, trust: Any) -> MeshVerdict:
    """Verify a mesh proof end to end, offline. Both arguments are parsed JSON. Total: any malformed input is a verdict
    (`MeshVerdict(ok, reason, hop)`), never an exception."""
    try:
        return _verify(proof, trust)
    except Exception:  # noqa: BLE001
        return _fail("malformed proof", -1)


def _verify(p: Any, trust: Any) -> MeshVerdict:
    t = _valid_trust(trust)
    if isinstance(t, str):
        return _fail(t, -1)
    if not isinstance(p, dict):
        return _fail("malformed proof", -1)
    chain, hops, heads, rev_leaves = p.get("chain"), p.get("hops"), p.get("heads"), p.get("rev_leaves")
    if not all(isinstance(x, list) for x in (chain, hops, heads, rev_leaves)):
        return _fail("malformed proof", -1)
    action = _valid_action(p.get("action"))
    if not _str(p.get("action_sig")) or action is None:
        return _fail("malformed action", -1)
    if "pin_proofs" in p:
        arr = p["pin_proofs"]
        if not (isinstance(arr, list) and len(arr) <= _MAX_COSIGS):
            return _fail("malformed pin proofs", -1)
        for x in arr:
            if not (isinstance(x, dict) and _str(x.get("domain")) and _valid_consistency(x.get("proof")) is not None):
                return _fail("malformed pin proofs", -1)
    if not chain or len(chain) > t["max_chain"]:
        return _fail("chain length out of bounds", -1)
    if len(heads) > len(chain) or len(rev_leaves) > 2 * len(chain):
        return _fail("evidence tables exceed chain size", -1)
    ok, why = verify_chain(chain, t["human"], None, t["pq_pins"], None)
    if not ok:
        return _fail("chain: %s" % why, -1)
    if len(hops) != len(chain):
        return _fail("hop evidence count does not match chain length", -1)
    for leaf in rev_leaves:
        if not (isinstance(leaf, dict) and _str(leaf.get("id")) and _valid_inclusion(leaf.get("proof")) is not None):
            return _fail("malformed revocation leaves", -1)
    used = {h["head"] for h in hops if isinstance(h, dict) and _js_nonneg_int(h.get("head"))}
    if len(used) != len(heads):
        return _fail("unreferenced or missing head in evidence table", -1)

    head_errs: dict = {}
    prev = None
    for i, cap in enumerate(chain):
        ev = hops[i]
        if not isinstance(ev, dict):
            return _fail("malformed hop evidence", i)
        domain = ev.get("domain")
        if not (_str(domain) and _js_nonneg_int(ev.get("head")) and ev["head"] < len(heads) and isinstance(ev.get("revocation"), dict)):
            return _fail("malformed hop evidence", i)
        if domain not in t["allowed"]:
            return _fail("issuing domain not allowed by policy", i)
        if i == 0 and domain != t["root_domain"]:
            return _fail("root capability must be anchored in the pinned root domain", i)
        issuer = cap["issuer"] if isinstance(cap.get("issuer"), str) else ""
        if i > 0 and t["issuer_domains"] is not None and issuer in t["issuer_domains"] and t["issuer_domains"][issuer] != domain:
            return _fail("issuer key is pinned to a different domain", i)

        hi = int(ev["head"])
        ch = heads[hi]
        if hi not in head_errs:
            hm = ch.get("head") if isinstance(ch, dict) else None
            dom = hm["domain"] if isinstance(hm, dict) and _str(hm.get("domain")) else ""
            pin_proof = None
            if isinstance(p.get("pin_proofs"), list):
                for x in p["pin_proofs"]:
                    if isinstance(x, dict) and x.get("domain") == dom:
                        pin_proof = x["proof"]
                        break
            head_errs[hi] = _check_cosigned_head(ch, dom, t, pin_proof)
        if not (isinstance(ch, dict) and ch.get("head") is not None):
            return _fail("malformed proof", -1)  # `ch.head.domain` throws in the reference
        hm = ch["head"]
        if not isinstance(hm, dict) or hm.get("domain") != domain:
            return _fail("source-domain anchor: head is for a different domain", i)
        if head_errs[hi] is not None:
            return _fail("source-domain anchor: %s" % head_errs[hi], i)

        incl = _valid_inclusion(ev.get("inclusion"))
        if incl is None or incl["size"] != hm["size"] or not verify_inclusion(hm["root"], incl, cap_hash(cap)):
            return _fail("hop not included in the issuing domain log", i)

        if i > 0:
            b = ev.get("binding")
            if not (isinstance(b, dict) and _str(b.get("role")) and _str(b.get("sig")) and b.get("agent") == cap.get("issuer") and b.get("domain") == domain):
                return _fail("missing or mismatched domain binding for issuer", i)
            m = _msg(MESH_BINDING_DOMAIN, {"agent": b["agent"], "domain": b["domain"], "role": b["role"]})
            if m is None or not _verify_b64u(domain, m, b["sig"]):
                return _fail("domain binding signature invalid", i)

        rev = ev["revocation"]
        rev_root = hm["rev_root"]
        cid = cap["id"] if isinstance(cap.get("id"), str) else ""
        nm_cap = _expand_nm(rev.get("cap"), rev_leaves)
        if nm_cap is None or not verify_non_membership(rev_root, nm_cap, cid):
            return _fail("capability revoked (or revocation proof invalid)", i)
        nm_key = _expand_nm(rev.get("issuer_key"), rev_leaves)
        if nm_key is None or not verify_non_membership(rev_root, nm_key, "key:" + issuer):
            return _fail("issuer key revoked (or revocation proof invalid)", i)

        eff, why = _effective(cap.get("caveats"))
        if why is not None:
            return _fail(why, i)
        if prev is not None and not _narrows(eff, prev):
            return _fail("hop widens authority", i)
        prev = eff

    at = action["at"]
    if at > t["now"] + t["max_skew"]:
        return _fail("action timestamp is in the future", -1)
    if t["max_action_age"] is not None and t["now"] - at > t["max_action_age"]:
        return _fail("action is stale", -1)
    tip = chain[-1]
    am = _msg(MESH_ACTION_DOMAIN, {"action": action, "tip": cap_hash(tip)})
    if am is None or not _verify_b64u(tip["holder"], am, p["action_sig"]):
        return _fail("action not signed by the chain tip holder", -1)
    denied = _admits(prev, action, t["now"], len(chain))
    if denied is not None:
        return _fail("action not admitted: " + denied, -1)
    return MeshVerdict(True, None, -1)
