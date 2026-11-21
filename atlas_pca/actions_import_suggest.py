"""The deterministic suggestion layer (native port of import/suggest.ts and import/rules.ts of the TypeScript reference @atlasauth/pca-actions).
A versioned rule set proposes traits, param roles and param tags for a draft def. Union only: a suggestion can ADD a trait, a role (to a param
that has none) or a tag, never remove or replace anything, and it never marks a def confirmed. A suggested def is still `pca.unreviewed` for floor
purposes; suggestions only improve the card and the review queue. `path_re` is a JavaScript regular expression (see actions_import_jsre)."""
import re
from typing import Any, Dict, List, Optional

from .actions import (
    _TRAIT_ID_RE, PARAM_TAGS, ActionKitError, _jtruthy, _u16key, _verify_b64u, is_role,
)
from .actions_import_common import tokens_of
from .actions_import_jsre import compile_js, js_test, to_utf16
from .actions_import_rules_data import DEFAULT_RULES_JSON
from .agent import KeyPair
from .intent_wb import _UNDEF, _utf16_len
from .pca import b64u, canonical_bytes_strict, hash_canonical

SUGGEST_RULES_KIND = "pca-suggest-rules"
SUGGEST_RULES_DOMAIN = "atlas-pca/suggest-rules/v1"
_RULE_ID_RE = re.compile(r"SR-[0-9]{3,4}")
_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_MATCH_KEYS = ("methods", "path_re", "name_tokens", "name_tokens_strict", "param_names", "param_names_all", "param_types", "param_formats", "roles", "effects")
_PARAM_TYPES = ("string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref")
MAX_RULES = 1024
MAX_LIST = 64
# a group that holds a quantifier or an alternation, followed by another quantifier: the shapes that backtrack exponentially
_NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*][^)]*\)[+*{]|\([^)]*\|[^)]*\)[+*{]")
_BACKREF = re.compile(r"\\[1-9]")
_LOOKAROUND = re.compile(r"\(\?[<=!]")


def _is_one(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and v == 1


def _is_str_list(v: Any, mx: int = MAX_LIST) -> bool:
    return isinstance(v, list) and 0 < len(v) <= mx and all(isinstance(x, str) and 0 < _utf16_len(x) <= 64 for x in v)


def suggest_rules_error(r: Any, known: Optional[set] = None) -> Optional[str]:
    """None if the rule set is well formed: closed members, unique ids, safe regular expressions, known trait/role/tag names."""
    if not isinstance(r, dict):
        return "rules must be an object"
    for k in r:
        if k not in ("v", "kind", "version", "rules", "digest", "sig"):
            return "unknown member '%s'" % k
    if not _is_one(r.get("v")) or r.get("kind") != SUGGEST_RULES_KIND:
        return "not a suggest-rules document (v 1)"
    if not isinstance(r.get("version"), str) or _VERSION_RE.fullmatch(r["version"]) is None:
        return "version must be semver"
    rules = r.get("rules")
    if not isinstance(rules, list) or len(rules) == 0 or len(rules) > MAX_RULES:
        return "rules must be 1..%d entries" % MAX_RULES
    ids: set = set()
    for rule in rules:
        if not isinstance(rule, dict):
            return "a rule must be an object"
        for k in rule:
            if k not in ("id", "match", "adds", "note"):
                return "rule: unknown member '%s'" % k
        rid = rule.get("id")
        if not isinstance(rid, str) or _RULE_ID_RE.fullmatch(rid) is None or rid in ids:
            return "rule ids must be unique SR-nnn"
        ids.add(rid)
        w = rid
        note = rule.get("note")
        if not isinstance(note, str) or _utf16_len(note) == 0 or _utf16_len(note) > 200:
            return "%s: note must be 1..200 characters" % w
        m = rule.get("match")
        if not isinstance(m, dict) or len(m) == 0:
            return "%s: match must be a non-empty object" % w
        for k in m:
            if k not in _MATCH_KEYS:
                return "%s: unknown match member '%s'" % (w, k)
        for k in ("methods", "name_tokens", "name_tokens_strict", "param_names", "param_names_all", "param_formats", "roles"):
            if k in m and not _is_str_list(m[k]):
                return "%s: match.%s must be 1..%d short strings" % (w, k, MAX_LIST)
        if "methods" in m and not all(s == s.upper() for s in m["methods"]):
            return "%s: methods are uppercase" % w
        if "param_types" in m and (not _is_str_list(m["param_types"]) or not all(t in _PARAM_TYPES for t in m["param_types"])):
            return "%s: match.param_types is not a list of param types" % w
        if "effects" in m and not _is_str_list(m["effects"], 12):
            return "%s: match.effects must be a list of effects" % w
        if "path_re" in m:
            p = m["path_re"]
            if not isinstance(p, str) or _utf16_len(p) == 0 or _utf16_len(p) > 128:
                return "%s: path_re must be 1..128 characters" % w
            if _NESTED_QUANTIFIER.search(p) or _BACKREF.search(p) or _LOOKAROUND.search(p):
                return "%s: path_re uses a construct outside the bounded subset (nested quantifiers, backreferences, lookaround)" % w
            try:
                compile_js(p)
            except ValueError:
                return "%s: path_re is not a regular expression" % w
        has_param = "param_names" in m or "param_names_all" in m or "param_formats" in m or "roles" in m
        if "param_types" in m and "param_names" not in m and "param_formats" not in m and "param_names_all" not in m:
            return "%s: param_types needs param_names, param_names_all or param_formats" % w
        if not _is_str_list(rule.get("adds"), 16):
            return "%s: adds must be 1..16 entries" % w
        for a in rule["adds"]:
            if a.startswith("tag:"):
                if a[4:] not in PARAM_TAGS:
                    return "%s: unknown tag '%s'" % (w, a)
                if not has_param:
                    return "%s: a tag needs a param matcher" % w
            elif is_role(a):
                if not has_param:
                    return "%s: a role needs a param matcher" % w
            elif _TRAIT_ID_RE.fullmatch(a) is not None:
                if known is not None and a not in known:
                    return "%s: unknown trait '%s'" % (w, a)
            else:
                return "%s: '%s' is not a trait, role or tag:" % (w, a)
    return None


def rules_digest(r: dict) -> str:
    """b64u sha256 of the strict canonical rule set (without digest and sig)."""
    return hash_canonical({"d": SUGGEST_RULES_DOMAIN, "rules": {"v": r["v"], "kind": r["kind"], "version": r["version"], "rules": r["rules"]}})


def seal_rules(r: dict) -> dict:
    return {**r, "digest": rules_digest(r)}


def _rules_message(digest: str) -> bytes:
    return (SUGGEST_RULES_DOMAIN + "\0").encode("utf-8") + canonical_bytes_strict({"digest": digest})


def sign_rules(r: dict, kid: str, secret: bytes) -> dict:
    """Sign a rule set as the rules publisher (a release step; the signature covers the digest)."""
    bad = suggest_rules_error(r)
    if bad:
        raise ActionKitError("bad_rules", bad)
    sealed = seal_rules(r)
    return {**sealed, "sig": {"alg": "ed25519", "kid": kid, "value": b64u(KeyPair(bytes(secret)).sign(_rules_message(sealed["digest"])))}}


def verify_rules(doc: Any, pins: Any) -> dict:
    """Verify a signed rule set against pinned publisher keys: shape, digest, signature. Never raises."""
    try:
        bad = suggest_rules_error(doc)
        if bad:
            return {"ok": False, "reason": bad}
        if doc.get("digest") != rules_digest(doc):
            return {"ok": False, "reason": "digest does not match the rules"}
        sig = doc.get("sig", _UNDEF)
        if not _jtruthy(sig):
            return {"ok": False, "reason": "the rule set is not signed"}
        kid = sig.get("kid", _UNDEF) if isinstance(sig, dict) else _UNDEF
        k = next((p for p in pins if isinstance(p, dict) and p.get("kid", _UNDEF) == kid and kid is not _UNDEF), None)
        if k is None:
            return {"ok": False, "reason": "no pinned rules key '%s'" % ("undefined" if kid is _UNDEF else kid if isinstance(kid, str) else kid)}
        value = sig.get("value", _UNDEF) if isinstance(sig, dict) else _UNDEF
        return {"ok": True} if _verify_b64u(k.get("pk"), _rules_message(doc["digest"]), value) else {"ok": False, "reason": "rules signature invalid"}
    except Exception as e:  # noqa: BLE001 - the verifier never raises
        return {"ok": False, "reason": "rules verification error: %s" % e}


# ---- facts -------------------------------------------------------------------------------------------------------------------

def stem(t: str) -> str:
    """Light stemmer: plural, -ing, -ed and a trailing -e fold together (`charges`, `charged`, `charging` -> `charg`)."""
    s = t
    if len(s) > 4 and s.endswith("ies"):
        s = s[:-3] + "y"
    elif re.search(r"(ss|x|z|ch|sh)es\Z", s) and len(s) > 4:
        s = s[:-2]
    elif len(s) > 3 and s.endswith("s") and not s.endswith("ss"):
        s = s[:-1]
    if len(s) > 5 and s.endswith("ing"):
        s = s[:-3]
    elif len(s) > 4 and s.endswith("ed"):
        s = s[:-2]
    if len(s) > 3 and s.endswith("e"):
        s = s[:-1]
    return s


_SEP = "|"


def _path_tokens(p: str) -> List[str]:
    return [t for s in p.split("/") if len(s) > 0 and "{" not in s and "}" not in s for t in tokens_of(s)]


def _u16_slice(s: str, n: int) -> str:
    return s.encode("utf-16-le", "surrogatepass")[:2 * n].decode("utf-16-le", "surrogatepass")


def facts_of(d: dict) -> dict:
    b = d.get("bindings") or {}
    methods: Dict[str, None] = {}
    locs: List[str] = []
    src: List[List[str]] = []
    path_src: set = set()
    src.append([t for s in d["verb"].split(".")[1:] for t in tokens_of(s)])
    for a in d.get("aliases") or []:
        src.append(tokens_of(a))
    src.append(tokens_of(d["title"]))
    if b.get("openapi"):
        o = b["openapi"]
        src.append(tokens_of(o["operationId"]))
        if o.get("method"):
            methods[o["method"].upper()] = None
        if o.get("path"):
            locs.append(o["path"])
            path_src.add(len(src))
            src.append(_path_tokens(o["path"]))
    if b.get("http"):
        methods[b["http"]["method"].upper()] = None
        locs.append(b["http"]["path"])
        path_src.add(len(src))
        src.append(_path_tokens(b["http"]["path"]))
    if b.get("mcp"):
        locs.append(b["mcp"]["tool"])
        src.append(tokens_of(b["mcp"]["tool"]))
    if b.get("graphql"):
        methods[b["graphql"]["op"].upper()] = None
        locs.append(b["graphql"]["field"])
        src.append(tokens_of(b["graphql"]["field"]))
    if b.get("grpc"):
        locs.append("%s/%s" % (b["grpc"]["service"], b["grpc"]["method"]))
        src.append(tokens_of(b["grpc"]["service"]))
        src.append(tokens_of(b["grpc"]["method"]))
    if b.get("asyncapi"):
        methods[b["asyncapi"]["op"].upper()] = None
        locs.append(b["asyncapi"]["channel"])
        src.append(tokens_of(b["asyncapi"]["channel"]))
    tokens: List[str] = []
    strict: List[str] = []
    for i, s in enumerate(src):
        if tokens:
            tokens.append(_SEP)
        tokens.extend(stem(x) for x in s)
        if i not in path_src:
            if strict:
                strict.append(_SEP)
            strict.extend(stem(x) for x in s)
    params = []
    for name in sorted(d["params"], key=_u16key):
        p = d["params"][name]
        e = {"name": name, "tokens": [stem(x) for x in tokens_of(name)], "type": p["type"]}
        if p.get("format"):
            e["format"] = p["format"]
        if p.get("role"):
            e["role"] = p["role"]
        params.append(e)
    return {"methods": list(methods), "locs": [_u16_slice(x, 512) for x in locs], "tokens": tokens, "strict": strict, "params": params,
            "effects": list(dict.fromkeys(d["effects"]))}


def _has_seq(hay: List[str], pat: List[str]) -> bool:
    if not pat:
        return False
    return any(hay[i:i + len(pat)] == pat for i in range(len(hay) - len(pat) + 1))


def _pat_of(s: str) -> List[str]:
    return [stem(t) for t in tokens_of(s)]


EMPTY_SUGGESTION = {"traits": [], "roles": {}, "tags": {}, "fired": []}
_INT_ROLES = ("money.amount", "money.fee", "count.limit", "bytes.size")


def _role_fits(role: str, typ: str) -> bool:
    if role in _INT_ROLES:
        return typ == "integer"
    if role.startswith("time."):
        return typ in ("date", "datetime", "integer")
    return typ == "string"


def _is_trait_add(a: str) -> bool:
    return not a.startswith("tag:") and not is_role(a)


def _sorted(xs) -> list:
    return sorted(xs, key=_u16key)


def suggest_with_rules(d: dict, rules: dict, registry: Optional[Dict[str, dict]] = None) -> dict:
    """Run the rules over a def. Only trait ids in `registry` (when given) can be suggested. Pure and deterministic."""
    f = facts_of(d)
    traits: Dict[str, None] = {}
    roles: Dict[str, str] = {}
    tags: Dict[str, Dict[str, None]] = {}
    fired: List[str] = []
    stems = f["tokens"]
    for rule in rules["rules"]:
        m = rule["match"]
        if _jtruthy(m.get("methods")) and not any(x in f["methods"] for x in m["methods"]):
            continue
        if _jtruthy(m.get("effects")) and not any(e in f["effects"] for e in m["effects"]):
            continue
        if _jtruthy(m.get("name_tokens")) and not any(_has_seq(stems, _pat_of(p)) for p in m["name_tokens"]):
            continue
        if _jtruthy(m.get("name_tokens_strict")) and not any(_has_seq(f["strict"], _pat_of(p)) for p in m["name_tokens_strict"]):
            continue
        if _jtruthy(m.get("path_re")):
            rx = compile_js(m["path_re"])
            if not any(js_test(rx, loc) for loc in f["locs"]):
                continue
        if _jtruthy(m.get("roles")) and not any("role" in p and p["role"] in m["roles"] for p in f["params"]):
            continue
        matched: List[dict] = []
        if m.get("param_names") is not None or m.get("param_formats") is not None:
            pats = [_pat_of(x) for x in (m.get("param_names") or [])]
            for p in f["params"]:
                if _jtruthy(m.get("param_types")) and p["type"] not in m["param_types"]:
                    continue
                if _jtruthy(m.get("param_names")) and not any(_has_seq(p["tokens"], q) for q in pats):
                    continue
                if _jtruthy(m.get("param_formats")) and ("format" not in p or p["format"] not in m["param_formats"]):
                    continue
                matched.append(p)
            if not matched:
                continue
        if _jtruthy(m.get("param_names_all")):
            ok = True
            for n in m["param_names_all"]:
                q = _pat_of(n)
                if not any(_has_seq(p["tokens"], q) and (not _jtruthy(m.get("param_types")) or p["type"] in m["param_types"] or p["type"] == "string") for p in f["params"]):
                    ok = False
                    break
            if not ok:
                continue
        fired.append(rule["id"])
        for a in rule["adds"]:
            if a.startswith("tag:"):
                for p in matched:
                    tags.setdefault(p["name"], {})[a[4:]] = None
            elif _is_trait_add(a):
                if registry is None or a in registry:
                    traits[a] = None
            else:
                for p in matched:
                    if "role" not in p and p["name"] not in roles and _role_fits(a, p["type"]):
                        roles[p["name"]] = a
    traits.pop("pca.unreviewed", None)
    return {"traits": _sorted(traits), "roles": roles, "tags": {k: _sorted(tags[k]) for k in _sorted(tags)}, "fired": fired}


def union_suggestions(a: dict, b: dict) -> dict:
    """Union two suggestions (the restrictive direction, so no intersection is needed)."""
    tags = {}
    for k in dict.fromkeys([*a["tags"], *b["tags"]]):
        tags[k] = _sorted(dict.fromkeys([*a["tags"].get(k, []), *b["tags"].get(k, [])]))
    return {"traits": _sorted(dict.fromkeys([*a["traits"], *b["traits"]])), "roles": {**b["roles"], **a["roles"]}, "tags": tags, "fired": [*a["fired"], *b["fired"]]}


def apply_suggestion(d: dict, s: dict, by: dict) -> dict:
    """Apply a suggestion to a def. UNION ONLY: traits are added, a role is set only on a param without one, tags are added; nothing is
    removed or replaced, no attestation is created, and `review.state` goes from `unreviewed` to `suggested`."""
    params: Dict[str, dict] = {}
    added_roles: Dict[str, str] = {}
    added_tags: Dict[str, List[str]] = {}
    for name, p in d["params"].items():
        q = p
        role = s["roles"].get(name)
        if role is not None and "role" not in p and _role_fits(role, p["type"]):
            q = {**q, "role": role}
            added_roles[name] = role
        t = s["tags"].get(name)
        if t is not None:
            fresh = [x for x in t if x not in (p.get("tags") or [])]
            if fresh:
                q = {**q, "tags": _sorted(dict.fromkeys([*(p.get("tags") or []), *fresh]))}
                added_tags[name] = fresh
        params[name] = q
    fresh_traits = [t for t in s["traits"] if t not in (d.get("traits") or [])]
    # a money-moving action must be safe to repeat (lint LD-004): add the optional idempotency key the pack generator adds
    idem = d.get("idempotency")
    if "pca.money_moving" in s["traits"] and (idem is None or idem.get("mode") == "none"):
        idem = {"mode": "key_param", "param": "idempotency_key"}
        if "idempotency_key" not in params:
            params["idempotency_key"] = {"type": "string", "max_len": 64, "required": False}
    review = d["review"]
    prev = review.get("suggested_by") or {}
    prev_added = prev.get("added") or {"traits": [], "roles": {}, "tags": {}}
    added = {
        "traits": _sorted(dict.fromkeys([*prev_added["traits"], *fresh_traits])),
        "roles": {**prev_added["roles"], **added_roles},
        "tags": {k: _sorted(dict.fromkeys([*prev_added["tags"].get(k, []), *added_tags.get(k, [])])) for k in _sorted(dict.fromkeys([*prev_added["tags"], *added_tags]))},
    }
    rules = by.get("rules") or prev.get("rules")
    models = [*(prev.get("models") or []), *(by.get("models") or [])]
    suggested_by = {**({"rules": rules} if rules else {}), **({"models": models} if models else {}), "added": added}
    state = "suggested" if review["state"] in ("unreviewed", "suggested") else review["state"]
    out = {**d, "params": params}
    if idem is not None:
        out["idempotency"] = idem
    if fresh_traits or (d.get("traits") or []):
        out["traits"] = _sorted(dict.fromkeys([*(d.get("traits") or []), *s["traits"]]))
    out["review"] = {**review, "state": state, "suggested_by": suggested_by}
    return out


def default_rules() -> dict:
    return DEFAULT_RULES_JSON


def default_rules_sealed() -> dict:
    return seal_rules(DEFAULT_RULES_JSON)


DEFAULT_RULES_VERSION = DEFAULT_RULES_JSON["version"]
