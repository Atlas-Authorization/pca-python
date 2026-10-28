"""Action-kit registry layer (native port): signed evolution records, principal re-approvals, the grant pin decision, signed packs
(with shards), pack inclusion proofs, the rollback tracker and rule 22 over a whole v2 document.

Natives verify signatures, digests and pins; they do NOT recompute the semantic diff (a tracker therefore checks chain, version and
signatures, not that the signed evolution equals the computed change). Pure and total: malformed input is a refusal."""
import re
from typing import Any, Dict, List, Optional

from . import actions as A
from .intent_v2 import (
    _UNDEF, _pinned_suite_error, _resolve_registered, _unsupported, suite_capability_error, SCHEMA_V2_CAVEATS,
)
from .pca import canonical_bytes_strict, decode_b64u_strict, hash_canonical, verify_inclusion

ACTION_PACK_KIND = "pca-action-pack"
ACTION_PIN_ON_NEW = ("deny", "escalate")
EVOLUTION_CLASSES = ("equal", "narrow", "widen", "incomparable", "added", "removed")
EVOLUTION_RECORD_KIND = "pca-evolution-record"
REAPPROVAL_KIND = "pca-reapproval"
EVOLUTION_DOMAIN = "atlas-pca/action-evolution/v1\x00"
EVOLUTION_DIFF_DOMAIN = "atlas-pca/action-evolution-diff/v1"
REAPPROVAL_DOMAIN = "atlas-pca/action-reapproval/v1\x00"
MAX_EVOLUTION_STEPS = 32
MAX_ESC_TIER = 3
PACK_SIG_DOMAIN = "atlas-pca/action-pack/v1\x00"
PACK_REF_DOMAIN = "atlas-pca/action-pack-ref/v1"
PACK_SHARD_DOMAIN = "atlas-pca/action-pack-shard/v1"
RULES_DIGEST_DOMAIN = "atlas-pca/action-rules/v1"
PACK_SHARD_KIND = "pca-action-pack-shard"
STABILITIES = ("draft", "beta", "stable")
MAX_EVOLUTION_RECORDS = 65536

_B64U_43 = re.compile(r"[A-Za-z0-9_-]{43}", re.ASCII)
_NS_RE = re.compile(r"[a-z0-9_]+(?:\.[a-z0-9_]+){0,5}", re.ASCII)
_VERB_RE = re.compile(r"[a-z0-9_]+(?:\.[a-z0-9_]+){1,5}", re.ASCII)
_SEMVER_RE = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})", re.ASCII)
_SHARD_NAME_RE = re.compile(r"[a-z0-9_]+(?:[.-][a-z0-9_]+){0,7}", re.ASCII)


def _is_obj(v: Any) -> bool:
    return isinstance(v, dict)


def _u16len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _closed(o: dict, allowed) -> Optional[str]:
    for k in o:
        if k not in allowed:
            return "unknown member '%s'" % k
    return None


def _sha(x: Any) -> bool:
    return isinstance(x, str) and _B64U_43.fullmatch(x) is not None


def _is1(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v == 1


def _message(domain: str, body: Any) -> bytes:
    return domain.encode("utf-8") + canonical_bytes_strict(body)


def _tier(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= MAX_ESC_TIER


# ---- evolution records -------------------------------------------------------------------------------------------------------

def evolution_record_error(x: Any, signed: bool = True) -> Optional[str]:
    if not _is_obj(x):
        return "evolution record must be an object"
    u = _closed(x, ["v", "kind", "ns", "verb", "from", "to", "class", "reasons"] + (["sig"] if signed else []))
    if u:
        return "evolution record: " + u
    if not _is1(x.get("v")) or x.get("kind") != EVOLUTION_RECORD_KIND:
        return "evolution record: bad v/kind"
    if not isinstance(x.get("ns"), str) or _NS_RE.fullmatch(x["ns"]) is None:
        return "evolution record: bad ns"
    if not isinstance(x.get("verb"), str) or _VERB_RE.fullmatch(x["verb"]) is None:
        return "evolution record: bad verb"
    if x.get("from") is not None and not _sha(x.get("from")):
        return "evolution record: bad from"
    if x.get("to") is not None and not _sha(x.get("to")):
        return "evolution record: bad to"
    c = x.get("class")
    if not isinstance(c, str) or c not in EVOLUTION_CLASSES:
        return "evolution record: bad class"
    if (c == "added") != (x.get("from") is None) or (c == "removed") != (x.get("to") is None):
        return "evolution record: endpoints do not match the class"
    r = x.get("reasons")
    if not isinstance(r, list) or len(r) > 64 or any(not isinstance(e, str) or _u16len(e) > 512 for e in r):
        return "evolution record: bad reasons"
    if signed:
        s = x.get("sig")
        if not _is_obj(s) or _closed(s, ["alg", "kid", "value", "pq_value"]) is not None:
            return "evolution record: bad sig"
        if not isinstance(s.get("kid"), str) or not (0 < _u16len(s["kid"]) <= 128) or not isinstance(s.get("value"), str) or not isinstance(s.get("alg"), str):
            return "evolution record: bad sig"
        if "pq_value" in s and not isinstance(s["pq_value"], str):
            return "evolution record: bad sig"
    try:
        canonical_bytes_strict({k: v for k, v in x.items() if k != "sig"})
    except Exception as e:  # noqa: BLE001
        return "evolution record: %s" % e
    return None


def evolution_diff_digest(r: dict) -> str:
    """Digest of ONE record's diff {ns, verb, from, to, class, reasons}; raises when a member is absent (the reference throws)."""
    return hash_canonical({"d": EVOLUTION_DIFF_DOMAIN, "ns": r["ns"], "verb": r["verb"], "from": r["from"], "to": r["to"],
                           "class": r["class"], "reasons": r["reasons"]})


def verify_registry_sig(domain: str, body: Any, sig: Any, keys: Any) -> Dict[str, Any]:
    """Verify a registry-signed body under `domain` against the pinned registry keys (the suite comes from the KEY entry). Total."""
    try:
        if not isinstance(keys, list):
            return {"ok": False, "reason": "the registry keys must be an array"}
        key = next((k for k in keys if _is_obj(k) and k.get("kid", _UNDEF) == sig.get("kid", _UNDEF)), None)
        if key is None:
            return {"ok": False, "reason": "no registry key with kid '%s'" % sig.get("kid")}
        if "pq_pk" in key and not isinstance(key["pq_pk"], str):
            return {"ok": False, "reason": "the registry key pq_pk must be a string"}
        if decode_b64u_strict(key.get("pk"), 32) is None:
            return {"ok": False, "reason": "registry key pk is not canonical base64url (32 bytes)"}
        ka = _resolve_registered(key.get("alg", _UNDEF))
        if ka is None or ka != _resolve_registered(sig.get("alg", _UNDEF)):
            return {"ok": False, "reason": "sig.alg does not match the pinned key suite"}
        pins = {key["pk"]: key["pq_pk"]} if "pq_pk" in key else None
        err = _pinned_suite_error(ka, key["pk"], key.get("pq_pk", _UNDEF), _message(domain, body), sig.get("value"), sig.get("pq_value", _UNDEF), pins)
        if err is not None:
            return {"ok": False, "reason": "signature invalid"}
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": "verification error: %s" % e}


def verify_evolution_record(rec: Any, keys: Any) -> Dict[str, Any]:
    bad = evolution_record_error(rec)
    if bad:
        return {"ok": False, "reason": bad}
    return verify_registry_sig(EVOLUTION_DOMAIN, {k: v for k, v in rec.items() if k != "sig"}, rec["sig"], keys)


def reapproval_valid(r: Any, grant_id: Any, issuer: Any, verb: Any, diff: Any) -> bool:
    try:
        if not _is_obj(r) or _closed(r, ["v", "kind", "grant", "verb", "diff", "sig"]) is not None:
            return False
        if not _is1(r.get("v")) or r.get("kind") != REAPPROVAL_KIND or r.get("grant", _UNDEF) != grant_id or r.get("verb", _UNDEF) != verb or r.get("diff", _UNDEF) != diff:
            return False
        s = r.get("sig")
        if not _is_obj(s) or _closed(s, ["alg", "value"]) is not None or s.get("alg") != "ed25519" or not isinstance(s.get("value"), str):
            return False
        body = {k: v for k, v in r.items() if k != "sig"}
        return _pinned_suite_error("ed25519", issuer, _UNDEF, _message(REAPPROVAL_DOMAIN, body), s["value"], _UNDEF, None) is None
    except Exception:  # noqa: BLE001
        return False


# ---- the pin -----------------------------------------------------------------------------------------------------------------

def action_pin_error(x: Any) -> Optional[str]:
    if not _is_obj(x):
        return "actions must be an object"
    u = _closed(x, ["pack", "defs", "on_new_action", "max_esc", "preauth_esc", "caveats"])
    if u:
        return "actions: " + u
    p = x.get("pack")
    if not _is_obj(p) or _closed(p, ["ns", "root"]) is not None:
        return "actions.pack must be {ns, root}"
    if not isinstance(p.get("ns"), str) or _NS_RE.fullmatch(p["ns"]) is None:
        return "actions.pack.ns is not a namespace"
    if not _sha(p.get("root")):
        return "actions.pack.root must be a base64url digest"
    if not isinstance(x.get("on_new_action"), str) or x["on_new_action"] not in ACTION_PIN_ON_NEW:
        return "actions.on_new_action must be 'deny' or 'escalate'"
    if "max_esc" in x and not _tier(x["max_esc"]):
        return "actions.max_esc must be an integer tier 0..3"
    if "preauth_esc" in x and not _tier(x["preauth_esc"]):
        return "actions.preauth_esc must be an integer tier 0..3"
    if _tier(x.get("max_esc")) and _tier(x.get("preauth_esc")) and x["preauth_esc"] > x["max_esc"]:
        return "actions.preauth_esc exceeds actions.max_esc"
    if "caveats" in x:
        c = x["caveats"]
        if not isinstance(c, list) or any(not isinstance(k, str) or k not in SCHEMA_V2_CAVEATS for k in c) or len(set(c)) != len(c):
            return "actions.caveats must be distinct caveat kinds"
    if "defs" in x:
        if not _is_obj(x["defs"]):
            return "actions.defs must be an object"
        for verb, d in x["defs"].items():
            if _VERB_RE.fullmatch(verb) is None:
                return "actions.defs: '%s' is not a verb" % verb
            if not _sha(d):
                return "actions.defs.%s must be a base64url digest" % verb
    return None


def _deny(code: str, reason: str, escalate: bool = False, needs: Optional[str] = None) -> dict:
    out = {"ok": False, "code": code, "escalate": escalate, "reason": reason}
    if needs is not None:
        out["needs_reapproval"] = needs
    return out


def decide_pin(i: dict) -> dict:
    """Decide the pin for one verb: exact digest, pack root, or a chain of verified `equal`/`narrow` (or principal-approved) evolution steps."""
    try:
        pe = action_pin_error(i.get("pin"))
        if pe:
            return _deny("bad_pin", pe)
        pin = i["pin"]
        doc = i["doc"]
        verb = i["verb"]
        verbs = doc.get("verbs") if _is_obj(doc) else None
        v = next((x for x in verbs if _is_obj(x) and x.get("verb", _UNDEF) == verb), None) if isinstance(verbs, list) else None
        if v is None:
            return _deny("unknown_verb", "the accepted schema does not declare '%s'" % verb)
        pk = doc.get("pack")
        if not _is_obj(pk) or pk.get("ns", _UNDEF) != pin["pack"]["ns"]:
            return _deny("pack_mismatch", "the schema does not come from the pinned pack '%s'" % pin["pack"]["ns"])
        if "defs" not in pin:
            if pk.get("root", _UNDEF) == pin["pack"]["root"]:
                return {"ok": True, "via": "pack"}
            return _deny("pack_mismatch", "the pack root differs from the pinned root (the grant pins the pack as a whole)")
        if verb not in pin["defs"]:
            return _deny("new_action", "the grant does not name '%s' (on_new_action: %s)" % (verb, pin["on_new_action"]), pin["on_new_action"] == "escalate")
        pinned = pin["defs"][verb]
        presented = v.get("def")
        if not isinstance(presented, str):
            return _deny("def_changed", "the schema verb carries no definition digest")
        if presented == pinned:
            return {"ok": True, "via": "exact"}
        edges: Dict[str, list] = {}
        keys = i.get("keys") or []
        grant = i["grant"]
        for r in i.get("records") or []:
            if not verify_evolution_record(r, keys)["ok"]:
                continue
            if r["ns"] != pin["pack"]["ns"] or r["verb"] != verb or r["from"] is None or r["to"] is None:
                continue
            diff = evolution_diff_digest(r)
            free = r["class"] in ("equal", "narrow")
            approved = free or any(reapproval_valid(a, grant["id"], grant["issuer"], verb, diff) for a in (i.get("reapprovals") or []))
            edges.setdefault(r["from"], []).append({"to": r["to"], "blocked": None if approved else diff})

        def search(usable_only: bool) -> dict:
            parent: dict = {}
            seen = {pinned}
            frontier = [pinned]
            step = 0
            while step < MAX_EVOLUTION_STEPS and frontier and presented not in parent:
                nxt = []
                for f in frontier:
                    for e in edges.get(f, []):
                        if e["to"] in seen or (usable_only and e["blocked"] is not None):
                            continue
                        seen.add(e["to"])
                        parent[e["to"]] = {"from": f, "blocked": e["blocked"]}
                        nxt.append(e["to"])
                frontier = nxt
                step += 1
            return parent

        if presented in search(True):
            return {"ok": True, "via": "chain"}
        allp = search(False)
        if presented in allp:
            first = None
            cur = presented
            while cur != pinned:
                p = allp[cur]
                if p["blocked"] is not None:
                    first = p["blocked"]
                cur = p["from"]
            return _deny("def_changed", "the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve", False, first)
        return _deny("def_changed", "the definition differs from the pinned digest and no signed evolution record chains to it")
    except Exception as e:  # noqa: BLE001
        return _deny("bad_pin", "pin evaluation error (fail closed): %s" % e)


# ---- signed packs -----------------------------------------------------------------------------------------------------------

def compare_versions(a: str, b: str) -> int:
    pa, pb = _SEMVER_RE.fullmatch(a), _SEMVER_RE.fullmatch(b)
    if not pa or not pb:
        raise A.ActionKitError("bad_version", "'%s' is not MAJOR.MINOR.PATCH" % (a if not pa else b))
    for k in (1, 2, 3):
        d = int(pa.group(k)) - int(pb.group(k))
        if d != 0:
            return d
    return 0


def rules_digest() -> str:
    return hash_canonical({"d": RULES_DIGEST_DOMAIN, "prules": list(A.PARAM_RULE_IDS), "caveats": list(A.CAVEAT_KINDS), "context": list(A.CONTEXT_KEYS)})


def pack_digest(p: dict) -> str:
    return hash_canonical({"d": PACK_REF_DOMAIN, "p": p})


def shard_digest(s: dict) -> str:
    return hash_canonical({"d": PACK_SHARD_DOMAIN, "s": s})


def _sorted_unique_defs_error(defs: list) -> Optional[str]:
    for i, d in enumerate(defs):
        e = A.validate_def(d)
        if e:
            return "def %d: %s" % (i, e)
        if i > 0 and not (A_utf16(defs[i - 1]["verb"]) < A_utf16(d["verb"])):
            return "defs must be sorted by verb and unique (at '%s')" % d["verb"]
    return None


def A_utf16(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def pack_shape_error(x: Any, signed: bool = True) -> Optional[str]:
    try:
        if not _is_obj(x):
            return "pack must be an object"
        e = _closed(x, ["v", "kind", "ns", "version", "stability", "traits_digest", "roles_digest", "rules_digest", "root", "defs", "source", "prev", "evolution"] + (["sig"] if signed else []))
        if e:
            return "pack: " + e
        if not _is1(x.get("v")) or x.get("kind") != ACTION_PACK_KIND:
            return "pack: bad v/kind"
        if not isinstance(x.get("ns"), str) or _NS_RE.fullmatch(x["ns"]) is None:
            return "pack: bad ns"
        if not isinstance(x.get("version"), str) or _SEMVER_RE.fullmatch(x["version"]) is None:
            return "pack: version must be MAJOR.MINOR.PATCH"
        if not isinstance(x.get("stability"), str) or x["stability"] not in STABILITIES:
            return "pack: bad stability"
        for k in ("traits_digest", "roles_digest", "rules_digest", "root"):
            if not _sha(x.get(k)):
                return "pack: %s must be a base64url digest" % k
        if x.get("prev") is not None and not _sha(x.get("prev")):
            return "pack: bad prev"
        s = x.get("source")
        if not _is_obj(s) or _closed(s, ["kind", "uri", "spec_digest", "licence", "licence_notes"]) is not None:
            return "pack: source must be {kind, uri, spec_digest, licence, licence_notes}"
        for k in ("kind", "uri", "spec_digest", "licence", "licence_notes"):
            v = s.get(k)
            if not isinstance(v, str) or (k != "licence_notes" and len(v) == 0) or _u16len(v) > 2048:
                return "pack: source.%s is not a string of 1..2048 characters" % k
        d = x.get("defs")
        if isinstance(d, list):
            if len(d) == 0 or len(d) > 4096:
                return "pack: inline defs must number 1..4096 (larger packs are sharded)"
            de = _sorted_unique_defs_error(d)
            if de:
                return "pack: " + de
        else:
            if not _is_obj(d) or _closed(d, ["shards"]) is not None or not isinstance(d.get("shards"), list) or len(d["shards"]) == 0 or len(d["shards"]) > 4096:
                return "pack: defs must be a list of defs or {shards}"
            names = set()
            for r in d["shards"]:
                if not _is_obj(r) or _closed(r, ["name", "digest", "uri"]) is not None:
                    return "pack: bad shard ref"
                if not isinstance(r.get("name"), str) or _SHARD_NAME_RE.fullmatch(r["name"]) is None or r["name"] in names:
                    return "pack: shard names must be distinct simple names"
                names.add(r["name"])
                if not _sha(r.get("digest")) or not isinstance(r.get("uri"), str) or len(r["uri"]) == 0 or _u16len(r["uri"]) > 2048:
                    return "pack: bad shard digest or uri"
        ev = x.get("evolution")
        if not isinstance(ev, list) or len(ev) > MAX_EVOLUTION_RECORDS:
            return "pack: evolution must be a list of records"
        for r in ev:
            re_ = evolution_record_error(r)
            if re_:
                return "pack: " + re_
        if signed:
            g = x.get("sig")
            if not _is_obj(g) or _closed(g, ["alg", "kid", "value", "pq_value"]) is not None or not isinstance(g.get("kid"), str) or not isinstance(g.get("value"), str) or not isinstance(g.get("alg"), str):
                return "pack: bad sig"
        hash_canonical({k: v for k, v in x.items() if k != "sig"})
        return None
    except Exception as err:  # noqa: BLE001
        return "pack: %s" % err


def pack_defs(pack: dict, shards: Optional[dict] = None) -> list:
    shards = shards or {}
    if isinstance(pack["defs"], list):
        return list(pack["defs"])
    allv: list = []
    for r in pack["defs"]["shards"]:
        s = shards.get(r["name"]) if isinstance(shards, dict) else None
        if s is None:
            raise A.ActionKitError("missing_shard", "shard '%s' was not supplied" % r["name"])
        if shard_digest(s) != r["digest"]:
            raise A.ActionKitError("shard_digest_mismatch", "shard '%s' does not match its digest" % r["name"])
        if s.get("v") != 1 or s.get("kind") != PACK_SHARD_KIND or s.get("ns") != pack["ns"] or s.get("version") != pack["version"] or s.get("name") != r["name"] or not isinstance(s.get("defs"), list):
            raise A.ActionKitError("bad_shard", "shard '%s' is not a shard of this pack" % r["name"])
        allv.extend(s["defs"])
    return sorted(allv, key=lambda d: A_utf16(d["verb"]))


def verify_pack(pack: Any, keys: Any, shards: Optional[dict] = None) -> Dict[str, Any]:
    """Shape, signature under the pinned registry keys, vocabulary digests, shards, defs, the recomputed Merkle root, and every evolution record."""
    try:
        se = pack_shape_error(pack)
        if se:
            return {"ok": False, "reason": se}
        body = {k: v for k, v in pack.items() if k != "sig"}
        v = verify_registry_sig(PACK_SIG_DOMAIN, body, pack["sig"], keys)
        if not v["ok"]:
            return {"ok": False, "reason": "pack signature: %s" % v["reason"]}
        if pack["traits_digest"] != A.traits_digest(A.CORE_REGISTRY):
            return {"ok": False, "reason": "traits_digest does not match the trait registry"}
        if pack["roles_digest"] != A.tables_digest():
            return {"ok": False, "reason": "roles_digest does not match the vocabulary tables"}
        if pack["rules_digest"] != rules_digest():
            return {"ok": False, "reason": "rules_digest does not match the rule tables"}
        try:
            defs = pack_defs(pack, shards)
        except A.ActionKitError as e:
            return {"ok": False, "reason": str(e)}
        de = _sorted_unique_defs_error(defs)
        if de:
            return {"ok": False, "reason": de}
        if len(defs) == 0 or len(defs) > 1_000_000:
            return {"ok": False, "reason": "the pack lists no defs or too many"}
        digests = [A.def_digest(d) for d in defs]
        if A.pack_root(digests) != pack["root"]:
            return {"ok": False, "reason": "the Merkle root does not match the defs"}
        have = set(digests)
        for r in pack["evolution"]:
            rv = verify_evolution_record(r, keys)
            if not rv["ok"]:
                return {"ok": False, "reason": "evolution record: %s" % rv["reason"]}
            if r["ns"] != pack["ns"]:
                return {"ok": False, "reason": "evolution record of another namespace"}
            if r["to"] is not None and r["to"] not in have:
                return {"ok": False, "reason": "evolution record for '%s' names a definition that is not in the pack" % r["verb"]}
        return {"ok": True, "defs": defs, "digest": pack_digest(pack)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "reason": "pack verification error: %s" % e}


def verify_pack_proof(root: Any, proof: Any, digest: Any) -> bool:
    return verify_inclusion(root, proof, A._leaf(digest))


class PackTracker:
    """The verifier's view of a registry: refuses rollback, fork and chain gap. The semantic diff of an upgrade is not recomputed natively."""

    def __init__(self, keys: Any):
        self.keys = keys
        self.seen: Dict[str, dict] = {}

    def accept(self, pack: Any, shards: Optional[dict] = None) -> Dict[str, Any]:
        v = verify_pack(pack, self.keys, shards)
        if not v["ok"]:
            return {"ok": False, "code": "bad_pack", "reason": v["reason"]}
        cur = self.seen.get(pack["ns"])
        if cur is None:
            self.seen[pack["ns"]] = {"version": pack["version"], "digest": v["digest"]}
            return {"ok": True, "status": "first"}
        if cur["digest"] == v["digest"]:
            return {"ok": True, "status": "same"}
        c = compare_versions(pack["version"], cur["version"])
        if c < 0:
            return {"ok": False, "code": "rollback", "reason": "older than the accepted version"}
        if c == 0:
            return {"ok": False, "code": "fork", "reason": "two different packs claim one version"}
        if pack["prev"] != cur["digest"]:
            return {"ok": False, "code": "chain_gap", "reason": "prev does not name the accepted pack"}
        self.seen[pack["ns"]] = {"version": pack["version"], "digest": v["digest"]}
        return {"ok": True, "status": "upgrade"}


# ---- rule 22 over a whole document -------------------------------------------------------------------------------------------

_CODES = ("schema_floor_forged", "schema_traits_forged", "unknown_trait", "traits_digest_mismatch", "bad_registry")


def _code_of(e: Optional[str]) -> dict:
    if e is None:
        return {"ok": True}
    return {"ok": False, "code": next((c for c in _CODES if c in e), "unknown")}


def rule22_integrity(doc: Any, pins: Any = None) -> dict:
    """`pins` = the verifier's pinned reviewer keys; absent = no verb is confirmed (each must carry every trait of the registry)."""
    return _code_of(A.schema_floor_error(doc, pins))


def rule22_decide(doc: Any, verb: str, grant: dict, context: list) -> str:
    try:
        v = next((x for x in doc.get("verbs", []) if x.get("verb") == verb), None)
        if v is None or A.profile_error(v.get("floors")) is not None:
            return "deny"
        kinds = [k for k in grant["caveats"] if isinstance(k, str) and k in A.CAVEAT_KINDS]
        ctx = [k for k in context if A._is_context_key(k)]
        return A.floor_decision({"caveats": kinds, "max_esc": grant["max_esc"], "preauth_esc": grant["preauth_esc"]}, {"context": ctx}, v["floors"])
    except Exception:  # noqa: BLE001
        return "deny"
