"""The hosted action registry of one instance: the publish gate and the verifier's view of the active versions (native port of hosted.ts
of the TypeScript reference @atlasauth/pca-actions). Pure: storage, keys and time are the caller's. Fail closed everywhere: an action the
view does not know, that no pinned reviewer key confirmed, or that is deprecated gets the top of the trait registry, no provenance facts,
is irreversible and never undoable."""
import re
from typing import Any, Callable, Dict, List, Optional

from .actions import (
    CAVEAT_KINDS, CORE_REGISTRY, def_digest, extend_registry, floor_decision, floor_of, join, leq, top_traits, _u16key,
)
from .actions_build import verify_signed_pack
from .actions_diff import diff_defs
from .actions_effective import effective_with, is_confirmed
from .actions_registry import compare_versions
from .actions_review import attestation_verifier
from .actions_rules import compile_business_rules, diff_business_rules, lint_business_rules, rules_review_error
from .actions_render import provenance_info_of
from .actions_undo import undo_engine
from .authorize import read_envelope
from .pca import hash_canonical

RULES_DOC_KIND = "pca-action-rules"
HOSTED_VERSION_DOMAIN = "atlas-pca/hosted-action-version/v1"
_PLAIN_SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_EFFECTIVE_DIMS = ("confirmation", "effective.traits", "effective.profile")
_SERVER_CLASS = {"reversible": "reversible", "rate_limited": "costly", "irreversible": "irreversible"}
Verifier = Optional[Callable[[dict], Any]]


def registry_of_traits(traits: List[dict]) -> Dict[str, dict]:
    """The trait registry of a version: core plus its custom traits. Raises for custom traits that do not extend their implies."""
    return CORE_REGISTRY if len(traits) == 0 else extend_registry(CORE_REGISTRY, traits)


def review_opts_of(pins: Any, reg: Dict[str, dict]) -> Verifier:
    """The confirmation verifier of an instance: a signature by a pinned reviewer key (no pins: nothing is confirmed)."""
    return None if pins is None else attestation_verifier(reg, pins)


def rules_doc_error(x: Any, ns: str, defs: List[dict]) -> Optional[str]:
    """None iff `x` is a rules document for `ns` whose every verb is in `defs` and whose rules lint without errors."""
    if not isinstance(x, dict):
        return "rules must be a pca-action-rules document"
    for k in x:
        if k not in ("v", "kind", "ns", "rules", "reviews"):
            return "rules: unknown member '%s'" % k
    if x.get("v") != 1 or isinstance(x.get("v"), bool) or x.get("kind") != RULES_DOC_KIND:
        return "rules: not a %s v1 document" % RULES_DOC_KIND
    if x.get("ns") != ns:
        return "rules: ns '%s' is not the pack's '%s'" % (_js(x.get("ns")), ns)
    if not isinstance(x.get("rules"), dict):
        return "rules.rules must map verbs to rules blocks"
    if "reviews" in x and not isinstance(x["reviews"], dict):
        return "rules.reviews must map verbs to rules reviews"
    by_verb = {d["verb"]: d for d in defs}
    for verb, block in x["rules"].items():
        d = by_verb.get(verb)
        if d is None:
            return "rules: '%s' is not an action of the pack" % verb
        errs = [f for f in lint_business_rules(d, block) if f["severity"] == "error"]
        if errs:
            return "rules for '%s': %s" % (verb, "; ".join(f["message"] for f in errs))
    for verb in x.get("reviews") or {}:
        if verb not in by_verb:
            return "rules.reviews: '%s' is not an action of the pack" % verb
    return None


def _js(v: Any) -> str:
    from .intent_wb import _js_str
    return _js_str(v)


def hosted_version_digest(v: dict) -> str:
    return hash_canonical({"d": HOSTED_VERSION_DOMAIN, "pack": v["pack"], "rules": v["rules"], "traits": v["traits"], "deprecated": sorted(v["deprecated"], key=_u16key)})


def _fail(code: str, reason: str, verbs: Optional[List[str]] = None) -> dict:
    out = {"ok": False, "code": code, "reason": reason}
    if verbs:
        out["verbs"] = verbs
    return out


def _safe_confirmed(d: dict, review: Verifier) -> bool:
    try:
        return is_confirmed(d, review)
    except Exception:  # noqa: BLE001
        return False


def _diff_defs_across(o: dict, n: dict, o_reg: dict, n_reg: dict, o_rev: Verifier, n_rev: Verifier) -> dict:
    """diff_defs, but each side under its own registry and review (a trait registry change shows up in the effective dimensions)."""
    base = diff_defs(o, n, n_reg, n_rev)
    if o_reg is n_reg:
        return base
    eo = effective_with(o, o_reg, o_rev)["eff"]
    en = effective_with(n, n_reg, n_rev)["eff"]
    rel = (None if leq(en, eo) else "narrow") if leq(eo, en) else ("widen" if leq(en, eo) else "incomparable")
    if rel is None:
        return base
    reasons = sorted([r for r in base["reasons"] if not r.startswith("effective.profile")] + ["effective.profile: " + rel])
    bc = base["class"]
    cls = "incomparable" if rel == "incomparable" or bc == "incomparable" or (rel == "widen" and bc == "narrow") or (rel == "narrow" and bc == "widen") else "widen" if rel == "widen" or bc == "widen" else "narrow"
    return {"class": cls, "reasons": reasons}


def publish_gate(i: dict) -> dict:
    """Decide whether a version may become the active one of its namespace and compute what it changes. i: {current?, pack, rules?, traits?,
    publisherKeys, pins, pin?}. Refused: bad_pack, bad_traits, bad_rules, ns_mismatch, bad_version / not_newer, widen_unreviewed (an action whose
    effective authority or business rules widen without a reviewer signature). Removed actions become deprecated."""
    traits: List[dict] = []
    if "traits" in i:
        if not isinstance(i["traits"], list):
            return _fail("bad_traits", "traits must be a list of trait definitions")
        traits = i["traits"]
    try:
        reg = registry_of_traits(traits)
    except Exception as e:  # noqa: BLE001
        return _fail("bad_traits", str(e))
    pv = verify_signed_pack(i.get("pack"), i["publisherKeys"], reg)
    if not pv["ok"]:
        return _fail("bad_pack", pv["reason"])
    pack = i["pack"]
    if _PLAIN_SEMVER.fullmatch(pack["version"]) is None:
        return _fail("bad_version", "version '%s' must be MAJOR.MINOR.PATCH" % pack["version"])
    cur = i.get("current")
    if cur and cur["ns"] != pack["ns"]:
        return _fail("ns_mismatch", "the active namespace is '%s', the pack is '%s'" % (cur["ns"], pack["ns"]))
    if cur and not i.get("pin") and compare_versions(pack["version"], cur["version"]) <= 0:
        return _fail("not_newer", "version %s is not above the active %s" % (pack["version"], cur["version"]))
    rules = {"v": 1, "kind": RULES_DOC_KIND, "ns": pack["ns"], "rules": {}} if "rules" not in i else i["rules"]
    re_ = rules_doc_error(rules, pack["ns"], pack["defs"])
    if re_:
        return _fail("bad_rules", re_)

    pins = i.get("pins")
    review = review_opts_of(pins, reg)
    prev_reg = reg
    if cur:
        try:
            prev_reg = registry_of_traits(cur["traits"])
        except Exception:  # noqa: BLE001
            prev_reg = reg
    prev_review = review_opts_of(pins, prev_reg)
    changes: List[dict] = []
    blocked: List[str] = []
    reasons: List[str] = []
    old_defs = {d["verb"]: d for d in (cur["pack"]["defs"] if cur else [])}
    old_dep = set(cur["deprecated"]) if cur else set()
    new_verbs = {d["verb"] for d in pack["defs"]}
    for n in pack["defs"]:
        o = old_defs.get(n["verb"])
        new_rules = rules["rules"].get(n["verb"])
        confirmed = _safe_confirmed(n, review)
        if o is None or n["verb"] in old_dep:
            change: Dict[str, Any] = {"verb": n["verb"], "class": "added", "reasons": []}
            if confirmed:
                change["reviewed"] = True
        else:
            d = _diff_defs_across(o, n, prev_reg, reg, prev_review, review)
            change = {"verb": n["verb"], "class": d["class"], "reasons": d["reasons"]}
            if any(any(r.startswith("%s: widen" % dim) or r.startswith("%s: incomparable" % dim) for dim in _EFFECTIVE_DIMS) for r in d["reasons"]):
                if confirmed:
                    change["reviewed"] = True
                else:
                    blocked.append(n["verb"])
                    reasons.append("%s: its effective authority widens without a valid confirmation of the new definition" % n["verb"])
        old_rules = cur["rules"]["rules"].get(n["verb"]) if o is not None and n["verb"] not in old_dep else None
        if old_rules is not None or new_rules is not None:
            try:
                rd = diff_business_rules(n, old_rules, new_rules)
            except Exception as e:  # noqa: BLE001
                rd = {"class": "incomparable", "reasons": ["rules: %s" % e]}
            if rd["class"] != "equal":
                change["rules"] = rd
            if rd["class"] in ("widen", "incomparable"):
                err = rules_review_error((rules.get("reviews") or {}).get(n["verb"]), n, new_rules if new_rules is not None else {}, pins)
                if err is None:
                    change["reviewed"] = True
                else:
                    blocked.append(n["verb"])
                    reasons.append("%s: its business rules widen (%s) without a valid rules review: %s" % (n["verb"], ", ".join(rd["reasons"]), err))
        if change["class"] != "equal" or change.get("rules"):
            changes.append(change)
    deprecated = {v for v in old_dep if v not in new_verbs}
    for v in old_defs:
        if v in new_verbs or v in old_dep:
            continue
        deprecated.add(v)
        changes.append({"verb": v, "class": "deprecated", "reasons": ["removed from the namespace: treated as unknown"]})
    changes.sort(key=lambda c: _u16key(c["verb"]))
    if blocked:
        out = _fail("widen_unreviewed", "\n".join(reasons), sorted(set(blocked), key=_u16key))
        out["changes"] = changes
        return out
    body = {"pack": pack, "rules": rules, "traits": traits, "deprecated": sorted(deprecated, key=_u16key)}
    return {"ok": True, "version": {"ns": pack["ns"], "version": pack["version"], "digest": hosted_version_digest(body), "prev": cur["digest"] if cur else None, **body, "changes": changes}}


# ---- the verifier's view -----------------------------------------------------------------------------------------------------

def grant_facts_of(grant: Any) -> dict:
    """Grant facts for rule 22 from a stored grant: envelope caveat types plus the pin block's caveats and escalation tiers."""
    env = read_envelope(grant)
    a = env.get("actions") if isinstance(env, dict) else None
    a = a if isinstance(a, dict) else {}

    def tier(v: Any, d: int) -> int:
        return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 3 else d

    caveats = [c.get("type") if isinstance(c, dict) else None for c in ((env.get("caveats") if isinstance(env, dict) else None) or [])]
    caveats += a["caveats"] if isinstance(a.get("caveats"), list) else []
    return {"caveats": [t for t in caveats if isinstance(t, str)], "max_esc": tier(a.get("max_esc"), 3), "preauth_esc": tier(a.get("preauth_esc"), 0)}


def _broken_rules(verb: str) -> dict:
    """A rules block that no longer compiles denies every call of its action (its tightening must not silently disappear)."""
    return {"v": 1, "verb": verb, "rules_digest": "", "def_digest": "", "tighten": [{"id": "rules_broken", "when": {"field": "action.verb", "op": "eq", "value": verb}, "signal": "deny",
            "reason": "the business rules of this action no longer compile"}], "accumulators": []}


class HostedView:
    """The verifier's view: lookup(verb), provenance(op), undo_plan(op), floor(verb, grant, call_context)."""

    def __init__(self, versions: List[dict], pins: Any):
        self.pins = pins
        self.by_verb: Dict[str, dict] = {}
        self.deprecated = set()
        regs: List[dict] = []
        self.versions = []
        self.broken = set()
        for v in versions:
            self.versions.append("%s@%s" % (v["ns"], v["version"]))
            try:
                reg = registry_of_traits(v["traits"])
            except Exception:  # noqa: BLE001
                for d in (v.get("pack") or {}).get("defs") or []:
                    if isinstance(d, dict) and isinstance(d.get("verb"), str):
                        self.broken.add(d["verb"])
                continue
            regs.append(reg)
            review = review_opts_of(pins, reg)
            for d in v["pack"]["defs"]:
                if d["verb"] not in self.by_verb:
                    e = {"def": d, "reg": reg, "review": review}
                    if v["rules"]["rules"].get(d["verb"]):
                        e["rules"] = v["rules"]["rules"][d["verb"]]
                    self.by_verb[d["verb"]] = e
            self.deprecated.update(v["deprecated"])
        for x in self.deprecated | self.broken:
            self.by_verb.pop(x, None)
        if not regs:
            self.top = floor_of(CORE_REGISTRY, top_traits(CORE_REGISTRY))
        else:
            tops = [floor_of(r, top_traits(r)) for r in regs]
            self.top = tops[0]
            for b in tops[1:]:
                self.top = b if leq(self.top, b) else self.top if leq(b, self.top) else join(self.top, b)
        self.top_trait_ids = sorted({t for r in (regs or [CORE_REGISTRY]) for t in top_traits(r)}, key=_u16key)
        self._cache: Dict[str, dict] = {}
        self._prov: Dict[str, dict] = {}
        for verb, e in self.by_verb.items():
            try:
                if _safe_confirmed(e["def"], e["review"]):
                    self._prov[verb] = provenance_info_of(e["def"], e["reg"], e["review"])
            except Exception:  # noqa: BLE001
                pass  # unknown: sensitive
        groups: Dict[int, dict] = {}
        for e in self.by_verb.values():
            groups.setdefault(id(e["reg"]), {"reg": e["reg"], "defs": []})["defs"].append(e["def"])
        self._undo = {k: undo_engine(g["defs"], pins, g["reg"]) for k, g in groups.items()}

    def lookup(self, verb: str) -> dict:
        hit = self._cache.get(verb)
        if hit is not None:
            return hit
        e = self.by_verb.get(verb)
        out: Dict[str, Any] = {"verb": verb, "confirmed": False, "known": e is not None, "deprecated": verb in self.deprecated, "profile": self.top,
                               "traits": self.top_trait_ids, "serverClass": "irreversible"}
        if e is None and verb in self.broken and verb not in self.deprecated:
            out = {**out, "known": True, "rules": _broken_rules(verb)}
        if e is not None:
            try:
                eff = effective_with(e["def"], e["reg"], e["review"])
                confirmed = eff["confirmed"] is True
                idem = e["def"]["idempotency"]["param"] if (e["def"].get("idempotency") or {}).get("mode") == "key_param" else None
                nxt = {**out, "def_digest": def_digest(e["def"]), "confirmed": confirmed}
                if idem is not None:
                    nxt["idempotency_param"] = idem
                if confirmed:
                    nxt.update({"profile": eff["eff"], "traits": eff["traits"], "serverClass": _SERVER_CLASS[eff["eff"]["rev"]]})
                if e.get("rules"):
                    nxt["rules"] = compile_business_rules(e["def"], e["rules"])
                out = nxt
            except Exception:  # noqa: BLE001
                out = {**out, "confirmed": False, "profile": self.top, "traits": self.top_trait_ids, "serverClass": "irreversible", "rules": _broken_rules(verb)}
        self._cache[verb] = out
        return out

    def provenance(self, op: dict) -> Optional[dict]:
        return self._prov.get(op["verb"])

    def undo_plan(self, op: dict) -> Optional[dict]:
        e = self.by_verb.get(op["verb"])
        return None if e is None else self._undo[id(e["reg"])](op)

    def floor(self, verb: str, grant: dict, call_context: List[str]) -> str:
        try:
            kinds = [c for c in grant["caveats"] if c in CAVEAT_KINDS]
            return floor_decision({"caveats": kinds, "max_esc": grant["max_esc"], "preauth_esc": grant["preauth_esc"]}, {"context": call_context}, self.lookup(verb)["profile"])
        except Exception:  # noqa: BLE001
            return "deny"


def hosted_view(versions: List[dict], pins: Any) -> HostedView:
    return HostedView(versions, pins)


def hosted_call_context(l: Optional[dict], params: Optional[dict]) -> List[str]:
    """The context keys the hosted server itself establishes for a call: fresh revocation always; an idempotency key when one is present."""
    out = ["fresh_revocation"]
    k = (l or {}).get("idempotency_param")
    if k is not None and params is not None and isinstance(params.get(k), str) and len(params[k]) > 0:
        out.append("idempotency")
    return out


def rate_keys_of(c: dict, who: dict) -> List[dict]:
    """The event keys of a rules block's rate limits: verb, window and scope id (never a rule index or the rules digest)."""
    out = []
    for a in c["accumulators"]:
        scope = "org" if a.get("scope") == "org" else "principal"
        i = who.get("org") if scope == "org" else who.get("principal")
        ms = 0 if a["win"]["kind"] == "task" else a["win"]["ms"]
        e: Dict[str, Any] = {"id": a["id"], "ms": ms}
        if isinstance(i, str) and len(i) > 0 and ms > 0:
            e["key"] = "%s|%s|%s:%s" % (c["verb"], ms, scope, i)
        out.append(e)
    return out
