"""Linked policy templates (security contract C-242, C-243). Port of packages/pca/src/policy-link.ts (the TypeScript is
authoritative): template definitions, instantiation with closed slot domains, signed templates and tighten overlays, and
resolution of a grant's `template_ref`. Every function is total and never raises; anything malformed fails closed."""
import re
from typing import Any, Dict, List, Optional

from .pca import _verify_b64u, hash_canonical, sha256

__all__ = ["template_def_error", "template_digest", "verify_template", "tighten_overlay_error", "verify_tighten",
           "instantiate_template", "template_ref_error", "resolve_link", "verify_linked_policy", "link_digest"]

TEMPLATE_VERSION = 1
TEMPLATE_KIND = "pca-policy-template"
TEMPLATE_SIG_DOMAIN = "atlas-pca/policy-template/v1\0"
TIGHTEN_KIND = "pca-template-tighten"
TIGHTEN_SIG_DOMAIN = "atlas-pca/template-tighten/v1\0"
MAX_SLOTS = 32
MAX_SLOT_STRING = 256
MAX_SLOT_SET = 64
_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_NAME_SOURCE = "^[a-z][a-z0-9_]{0,63}$"
_MAX_SAFE = 9007199254740991


def _is_obj(v: Any) -> bool:
    return isinstance(v, dict)


def _is_int(v: Any) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return abs(v) <= _MAX_SAFE
    return isinstance(v, float) and v.is_integer() and abs(v) <= _MAX_SAFE


def _u16len(s: str) -> int:
    return len(s.encode("utf-16-le", "surrogatepass")) // 2


def _message(domain: str, digest: str) -> bytes:
    return domain.encode("utf-8") + sha256(digest.encode("utf-8"))


def _scan(v: Any, decl: dict, used: set) -> Optional[str]:
    if isinstance(v, list):
        for x in v:
            e = _scan(x, decl, used)
            if e:
                return e
        return None
    if not _is_obj(v):
        return None
    for k in v:
        if k in ("__proto__", "constructor", "prototype"):
            return f"body has the forbidden key '{k}'"
    if "$slot" in v:
        extra = [k for k in v if k not in ("$slot", "pre", "post")]
        if extra:
            return f"placeholder has unknown member '{extra[0]}'"
        if not isinstance(v["$slot"], str) or v["$slot"] not in decl:
            return f"placeholder names undeclared slot '{_js_str(v['$slot'])}'"
        for k in ("pre", "post"):
            if k in v and not isinstance(v[k], str):
                return f"placeholder {k} must be a string"
        used.add(v["$slot"])
        return None
    for k in v:
        e = _scan(v[k], decl, used)
        if e:
            return e
    return None


def _js_str(x: Any) -> str:
    if isinstance(x, str):
        return x
    if x is None:
        return "null"
    if isinstance(x, bool):
        return "true" if x else "false"
    return str(x)


def template_def_error(d: Any) -> Optional[str]:
    if not _is_obj(d):
        return "template must be an object"
    if d.get("v") != TEMPLATE_VERSION or d.get("kind") != TEMPLATE_KIND:
        return "template v / kind mismatch"
    if not isinstance(d.get("id"), str) or not _NAME_RE.fullmatch(d["id"]):
        return f"template id must match {_NAME_SOURCE}"
    if not isinstance(d.get("version"), str) or len(d["version"]) == 0 or _u16len(d["version"]) > 64:
        return "template version must be a string of 1..64 characters"
    slots = d.get("slots")
    if not _is_obj(slots):
        return "slots must be an object"
    names = list(slots)
    if len(names) > MAX_SLOTS:
        return f"more than {MAX_SLOTS} slots"
    for n in names:
        s = slots[n]
        if not _NAME_RE.fullmatch(n):
            return f"slot name '{n}' must match {_NAME_SOURCE}"
        if not _is_obj(s):
            return f"slot '{n}' must be an object"
        if s.get("type") not in ("string", "integer", "set"):
            return f"slot '{n}'.type must be string, integer or set"
        if s["type"] == "set" and not isinstance(s.get("values"), list):
            return f"set slot '{n}' needs a closed values list"
        if "values" in s and (not isinstance(s["values"], list) or len(s["values"]) > MAX_SLOT_SET or any(not isinstance(x, str) for x in s["values"])):
            return f"slot '{n}'.values must be a list of strings"
        if s["type"] == "integer":
            for k in ("min", "max"):
                if k in s and not _is_int(s[k]):
                    return f"slot '{n}'.{k} must be a safe integer"
    body = d.get("body")
    if not _is_obj(body) or not isinstance(body.get("predicates"), list):
        return "body.predicates must be an array"
    if "caveats" in body and not isinstance(body["caveats"], list):
        return "body.caveats must be an array"
    used: set = set()
    e = _scan(body, slots, used)
    if e:
        return e
    for n in names:
        if n not in used:
            return f"slot '{n}' is declared but never used"
    return None


def template_digest(d: Any) -> str:
    return hash_canonical(d)


def _trusted(t: Any, signer: Any) -> bool:
    return isinstance(signer, str) and signer in list(t)


def verify_template(t: Any, trusted: Any) -> Dict[str, Any]:
    try:
        e = template_def_error(t.get("def") if _is_obj(t) else None)
        if e:
            return {"ok": False, "reason": e}
        if not _trusted(trusted, t.get("signer")):
            return {"ok": False, "reason": "template signer is not trusted"}
        sig = t.get("sig")
        if not isinstance(sig, str) or not _verify_b64u(t["signer"], _message(TEMPLATE_SIG_DOMAIN, template_digest(t["def"])), sig):
            return {"ok": False, "reason": "bad template signature"}
        return {"ok": True}
    except Exception:
        return {"ok": False, "reason": "template verification error (fail closed)"}


def tighten_overlay_error(o: Any) -> Optional[str]:
    if not _is_obj(o):
        return "overlay must be an object"
    if o.get("v") != TEMPLATE_VERSION or o.get("kind") != TIGHTEN_KIND:
        return "overlay v / kind mismatch"
    for k in o:
        if k not in ("v", "kind", "template_id", "version_digest", "add_where", "add_caveats"):
            return f"overlay has unknown member '{k}' (an overlay can only add where conditions and caveats)"
    if not isinstance(o.get("template_id"), str) or not _NAME_RE.fullmatch(o["template_id"]):
        return "overlay template_id invalid"
    if not isinstance(o.get("version_digest"), str) or len(o["version_digest"]) == 0:
        return "overlay version_digest invalid"
    if "add_where" in o and (not isinstance(o["add_where"], list) or any(not _is_obj(c) for c in o["add_where"])):
        return "overlay add_where must be a list of conditions"
    if "add_caveats" in o and (not isinstance(o["add_caveats"], list) or any(not _is_obj(c) or not isinstance(c.get("type"), str) for c in o["add_caveats"])):
        return "overlay add_caveats must be a list of caveats"
    return None


def verify_tighten(t: Any, trusted: Any) -> Dict[str, Any]:
    try:
        e = tighten_overlay_error(t.get("overlay") if _is_obj(t) else None)
        if e:
            return {"ok": False, "reason": e}
        if not _trusted(trusted, t.get("signer")):
            return {"ok": False, "reason": "overlay signer is not trusted"}
        sig = t.get("sig")
        if not isinstance(sig, str) or not _verify_b64u(t["signer"], _message(TIGHTEN_SIG_DOMAIN, hash_canonical(t["overlay"])), sig):
            return {"ok": False, "reason": "bad overlay signature"}
        return {"ok": True}
    except Exception:
        return {"ok": False, "reason": "overlay verification error (fail closed)"}


def _slot_value_error(name: str, d: dict, v: Any) -> Optional[str]:
    t = d["type"]
    if t == "string":
        if not isinstance(v, str) or len(v) == 0 or _u16len(v) > MAX_SLOT_STRING:
            return f"slot '{name}' must be a string of 1..{MAX_SLOT_STRING} characters"
        if "values" in d and v not in d["values"]:
            return f"slot '{name}' is outside its closed value set"
        return None
    if t == "integer":
        if not _is_int(v):
            return f"slot '{name}' must be a safe integer"
        if "min" in d and v < d["min"]:
            return f"slot '{name}' is below its minimum"
        if "max" in d and v > d["max"]:
            return f"slot '{name}' is above its maximum"
        return None
    if not isinstance(v, list) or len(v) == 0 or len(v) > MAX_SLOT_SET or any(not isinstance(x, str) for x in v):
        return f"slot '{name}' must be a non-empty list of strings"
    if len(set(v)) != len(v):
        return f"slot '{name}' has duplicate members"
    if "values" in d and any(x not in d["values"] for x in v):
        return f"slot '{name}' has a member outside its closed set"
    return None


class _Refuse(Exception):
    pass


def _matcher_safe(name: str, val: Any) -> None:
    for x in (val if isinstance(val, list) else [val]):
        if isinstance(x, str) and ("*" in x or x.startswith("re:")):
            raise _Refuse(f"slot '{name}' would inject a wildcard or regex matcher into a verb or resource")


def _fill(v: Any, slots: dict, key: Optional[str] = None) -> Any:
    if isinstance(v, list):
        return [_fill(x, slots, key) for x in v]
    if not _is_obj(v):
        return v
    if "$slot" in v:
        name = v["$slot"]
        val = slots[name]
        if key in ("verb", "resource"):
            _matcher_safe(name, val)
        pre = v["pre"] if isinstance(v.get("pre"), str) else ""
        post = v["post"] if isinstance(v.get("post"), str) else ""
        if pre == "" and post == "":
            return val
        if not isinstance(val, str) or "*" in val or "\u0000" in val:
            raise _Refuse(f"slot '{name}' cannot be spliced into a string (wildcard or non-string)")
        out = pre + val + post
        if pre == "" and out.startswith("re:"):
            raise _Refuse(f"slot '{name}' would inject a regex matcher")
        return out
    return {k: _fill(v[k], slots, k) for k in v}


def instantiate_template(d: Any, slots: Any) -> Dict[str, Any]:
    try:
        e = template_def_error(d)
        if e:
            return {"ok": False, "reason": e}
        if not _is_obj(slots):
            return {"ok": False, "reason": "slots must be an object"}
        for k in slots:
            if k not in d["slots"]:
                return {"ok": False, "reason": f"slot '{k}' is not declared by the template"}
        for n, decl in d["slots"].items():
            if n not in slots:
                return {"ok": False, "reason": f"slot '{n}' is not filled"}
            se = _slot_value_error(n, decl, slots[n])
            if se:
                return {"ok": False, "reason": se}
        pol = _fill(d["body"], slots)
        return {"ok": True, "policy": {"predicates": pol["predicates"], "caveats": pol.get("caveats", [])}}
    except _Refuse as r:
        return {"ok": False, "reason": str(r)}
    except Exception:
        return {"ok": False, "reason": "instantiation error (fail closed)"}


def template_ref_error(r: Any) -> Optional[str]:
    if not _is_obj(r):
        return "template_ref must be an object"
    for k in r:
        if k not in ("template_id", "version_digest", "slots", "bind_params_digest"):
            return f"template_ref has unknown member '{k}'"
    if not isinstance(r.get("template_id"), str) or not _NAME_RE.fullmatch(r["template_id"]):
        return "template_ref.template_id invalid"
    if not isinstance(r.get("version_digest"), str) or len(r["version_digest"]) == 0 or len(r["version_digest"]) > 128:
        return "template_ref.version_digest invalid"
    if "slots" in r and "bind_params_digest" in r:
        return "template_ref has both slots and bind_params_digest"
    if "bind_params_digest" in r:
        d = r["bind_params_digest"]
        return None if isinstance(d, str) and 0 < len(d) <= 128 else "template_ref.bind_params_digest invalid"
    if not _is_obj(r.get("slots")):
        return "template_ref.slots must be an object"
    return None


def resolve_link(ref: Any, reg: Any) -> Dict[str, Any]:
    try:
        re_ = template_ref_error(ref)
        if re_:
            return {"ok": False, "reason": re_}
        t = reg["templates"].get(ref["version_digest"]) if ref["version_digest"] in reg["templates"] else None
        if t is None:
            return {"ok": False, "reason": "template version is not in the registry"}
        v = verify_template(t, reg["trusted"])
        if not v["ok"]:
            return {"ok": False, "reason": v.get("reason") or "template refused"}
        if template_digest(t["def"]) != ref["version_digest"]:
            return {"ok": False, "reason": "registry entry does not match its digest"}
        if t["def"]["id"] != ref["template_id"]:
            return {"ok": False, "reason": "template id does not match the reference"}
        slots = ref.get("slots")
        if "bind_params_digest" in ref:
            params = reg.get("params")
            bound = params.get(ref["bind_params_digest"]) if isinstance(params, dict) else None
            if not _is_obj(bound):
                return {"ok": False, "reason": "parameter object is not available"}
            if hash_canonical(bound) != ref["bind_params_digest"]:
                return {"ok": False, "reason": "parameter object does not match bind_params_digest"}
            slots = bound
        inst = instantiate_template(t["def"], slots)
        if not inst["ok"]:
            return inst
        predicates: List[Any] = inst["policy"]["predicates"]
        caveats: List[Any] = inst["policy"]["caveats"]
        applied = 0
        for o in reg.get("overlays") or []:
            ov = o.get("overlay") if _is_obj(o) else None
            if not _is_obj(ov) or ov.get("version_digest") != ref["version_digest"] or ov.get("template_id") != ref["template_id"]:
                continue
            vv = verify_tighten(o, reg["trusted"])
            if not vv["ok"]:
                return {"ok": False, "reason": vv.get("reason") or "overlay refused"}
            add = ov.get("add_where") or []
            predicates = [{**p, "where": [*(p.get("where") or []), *add]} for p in predicates]
            caveats = [*caveats, *(ov.get("add_caveats") or [])]
            applied += 1
        return {"ok": True, "policy": {"predicates": predicates, "caveats": caveats}, "overlays": applied}
    except Exception:
        return {"ok": False, "reason": "link resolution error (fail closed)"}


def verify_linked_policy(envelope: Any, reg: Any) -> Dict[str, Any]:
    try:
        if "template_ref" not in envelope:
            return {"ok": True}
        r = resolve_link(envelope["template_ref"], reg)
        if not r["ok"]:
            return {"ok": False, "reason": r["reason"]}
        if hash_canonical({"predicates": envelope["predicates"], "caveats": envelope["caveats"]}) != hash_canonical(r["policy"]):
            return {"ok": False, "reason": "grant policy differs from the linked template instantiation"}
        return {"ok": True, "template": envelope["template_ref"]["version_digest"]}
    except Exception:
        return {"ok": False, "reason": "link verification error (fail closed)"}


def link_digest(ref: Any) -> str:
    return hash_canonical(ref)
