"""GraphQL SDL or introspection JSON to drafts (native port of import/graphql.ts of the TypeScript reference @atlasauth/pca-actions). Query
fields are reads, Mutation fields are writes, Subscription fields are streaming reads; arguments and input objects are flattened to dotted
params. There is no method signal, so everything stays `unreviewed`. A schema is {"types": {name: typedef}, "query"?, "mutation"?, "subscription"?};
a typedef is {"kind", "name", "fields": [{"name", "args", "type", "desc"?, "deprecated"}], "values"}; a type is {"k": "named"|"list"|"nonnull", ...}."""
import re
from typing import Any, List, Optional

from .actions import ActionKitError
from .actions_import_common import (
    UTF8_ORDER, add_todo, clip, emit_def, finish, flatten_object, is_obj, is_str, new_budget, new_ctx, with_trait,
)

_SPACE = " \t\n\r,﻿"
_NAME0 = re.compile(r"[_A-Za-z]")
_NAMEN = re.compile(r"[_0-9A-Za-z]")
_NUM0 = re.compile(r"[-0-9]")
_NUMN = re.compile(r"[-+.0-9eE]")
_PUNCT = "!$&():=@[]{|}"


def _lex(src: str, max_tokens: int) -> List[tuple]:
    out: List[tuple] = []
    n = len(src)
    i = 0

    def push(t: tuple) -> None:
        if len(out) >= max_tokens:
            raise ActionKitError("import_limit", "the GraphQL source has too many tokens")
        out.append(t)

    while i < n:
        ch = src[i]
        if ch in _SPACE:
            i += 1
            continue
        if ch == "#":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if ch == '"':
            if src.startswith('"""', i):
                j = i + 3
                s: List[str] = []
                while j < n and not src.startswith('"""', j):
                    if src.startswith('\\"""', j):
                        s.append('"""')
                        j += 4
                    else:
                        s.append(src[j])
                        j += 1
                if j >= n:
                    raise ActionKitError("bad_source", "unterminated GraphQL block string")
                push(("str", "".join(s)))
                i = j + 3
            else:
                j = i + 1
                s = []
                while j < n and src[j] != '"':
                    if src[j] == "\n":
                        raise ActionKitError("bad_source", "unterminated GraphQL string")
                    if src[j] == "\\":
                        s.append(src[j + 1] if j + 1 < n else "")
                        j += 2
                    else:
                        s.append(src[j])
                        j += 1
                if j >= n:
                    raise ActionKitError("bad_source", "unterminated GraphQL string")
                push(("str", "".join(s)))
                i = j + 1
            continue
        if _NAME0.fullmatch(ch):
            j = i + 1
            while j < n and _NAMEN.fullmatch(src[j]):
                j += 1
            push(("name", src[i:j]))
            i = j
            continue
        if _NUM0.fullmatch(ch):
            j = i + 1
            while j < n and _NUMN.fullmatch(src[j]):
                j += 1
            push(("int", src[i:j]))
            i = j
            continue
        if src.startswith("...", i):
            push(("punct", "..."))
            i += 3
            continue
        if ch in _PUNCT:
            push(("punct", ch))
            i += 1
            continue
        raise ActionKitError("bad_source", "unexpected character in GraphQL source at offset %d" % i)
    push(("eof", ""))
    return out


class _P:
    def __init__(self, toks: List[tuple], schema: dict, max_depth: int):
        self.i = 0
        self.toks = toks
        self.schema = schema
        self.max_depth = max_depth

    @property
    def cur(self) -> tuple:
        return self.toks[self.i]

    def next(self) -> tuple:
        t = self.toks[self.i]
        if t[0] != "eof":
            self.i += 1
        return t

    def is_(self, v: str) -> bool:
        return self.cur[0] != "str" and self.cur[1] == v

    def eat(self, v: str) -> bool:
        if self.is_(v):
            self.i += 1
            return True
        return False

    def expect(self, v: str) -> None:
        if not self.eat(v):
            raise ActionKitError("bad_source", "GraphQL parse error: expected '%s' near '%s'" % (v, clip(self.cur[1], 30)))

    def name(self) -> str:
        t = self.next()
        if t[0] != "name":
            raise ActionKitError("bad_source", "GraphQL parse error: expected a name near '%s'" % clip(t[1], 30))
        return t[1]

    def desc(self) -> Optional[str]:
        return self.next()[1] if self.cur[0] == "str" else None

    def type(self, depth: int = 0) -> dict:
        if depth > self.max_depth:
            raise ActionKitError("import_limit", "GraphQL type nesting is too deep")
        if self.eat("["):
            t = {"k": "list", "of": self.type(depth + 1)}
            self.expect("]")
        else:
            t = {"k": "named", "name": self.name()}
        return {"k": "nonnull", "of": t} if self.eat("!") else t

    def value(self, depth: int = 0) -> None:
        if depth > self.max_depth:
            raise ActionKitError("import_limit", "GraphQL value nesting is too deep")
        t = self.cur
        if t[0] in ("str", "int", "name"):
            self.i += 1
            return
        if self.eat("["):
            while not self.is_("]") and self.cur[0] != "eof":
                self.value(depth + 1)
            self.expect("]")
            return
        if self.eat("{"):
            while not self.is_("}") and self.cur[0] != "eof":
                self.name()
                self.expect(":")
                self.value(depth + 1)
            self.expect("}")
            return
        if self.eat("$"):
            self.name()
            return
        raise ActionKitError("bad_source", "GraphQL parse error: unexpected '%s'" % clip(t[1], 30))

    def directives(self) -> bool:
        deprecated = False
        while self.eat("@"):
            if self.name() == "deprecated":
                deprecated = True
            if self.eat("("):
                while not self.is_(")") and self.cur[0] != "eof":
                    self.name()
                    self.expect(":")
                    self.value()
                self.expect(")")
        return deprecated

    def args(self) -> list:
        out: list = []
        if not self.eat("("):
            return out
        while not self.is_(")"):
            if self.cur[0] == "eof":
                raise ActionKitError("bad_source", "GraphQL parse error: unterminated argument list")
            desc = self.desc()
            name = self.name()
            self.expect(":")
            ty = self.type()
            if self.eat("="):
                self.value()
            self.directives()
            out.append({"name": name, "type": ty, **({"desc": desc} if desc else {})})
        self.expect(")")
        return out

    def fields(self, inp: bool) -> list:
        out: list = []
        if not self.eat("{"):
            return out
        while not self.is_("}"):
            if self.cur[0] == "eof":
                raise ActionKitError("bad_source", "GraphQL parse error: unterminated field list")
            desc = self.desc()
            name = self.name()
            args = [] if inp else self.args()
            self.expect(":")
            ty = self.type()
            if inp and self.eat("="):
                self.value()
            d = self.directives()
            out.append({"name": name, "args": args, "type": ty, "deprecated": d, **({"desc": desc} if desc else {})})
        self.expect("}")
        return out

    def def_(self) -> None:
        self.desc()
        kw = self.name()
        if kw == "extend":
            self.def_()
            return
        if kw == "schema":
            self.directives()
            self.expect("{")
            while not self.is_("}"):
                if self.cur[0] == "eof":
                    raise ActionKitError("bad_source", "GraphQL parse error: unterminated schema block")
                op = self.name()
                self.expect(":")
                ty = self.name()
                if op in ("query", "mutation", "subscription"):
                    self.schema[op] = ty
            self.expect("}")
            return
        if kw == "scalar":
            n = self.name()
            self.directives()
            self.merge({"kind": "scalar", "name": n, "fields": [], "values": []})
            return
        if kw == "directive":
            self.expect("@")
            self.name()
            self.args()
            if self.cur[1] == "repeatable":
                self.i += 1
            if self.cur[1] == "on":
                self.i += 1
            self.eat("|")
            self.name()
            while self.eat("|"):
                self.name()
            return
        if kw in ("type", "interface", "input"):
            n = self.name()
            if self.cur[1] == "implements":
                self.i += 1
                self.eat("&")
                self.name()
                while self.eat("&"):
                    self.name()
            self.directives()
            self.merge({"kind": "object" if kw == "type" else "input" if kw == "input" else "interface", "name": n, "fields": self.fields(kw == "input"), "values": []})
            return
        if kw == "union":
            n = self.name()
            self.directives()
            if self.eat("="):
                self.eat("|")
                self.name()
                while self.eat("|"):
                    self.name()
            self.merge({"kind": "union", "name": n, "fields": [], "values": []})
            return
        if kw == "enum":
            n = self.name()
            self.directives()
            values: List[str] = []
            if self.eat("{"):
                while not self.is_("}"):
                    if self.cur[0] == "eof":
                        raise ActionKitError("bad_source", "GraphQL parse error: unterminated enum")
                    self.desc()
                    values.append(self.name())
                    self.directives()
                self.expect("}")
            self.merge({"kind": "enum", "name": n, "fields": [], "values": values})
            return
        raise ActionKitError("bad_source", "GraphQL parse error: unsupported definition '%s' (only type-system definitions are imported)" % clip(kw, 30))

    def merge(self, d: dict) -> None:
        old = self.schema["types"].get(d["name"])
        if old is None:
            self.schema["types"][d["name"]] = d
            return
        old["fields"].extend(d["fields"])
        old["values"].extend(d["values"])


def parse_graphql_sdl(src: str, max_tokens: int = 2_000_000) -> dict:
    toks = _lex(src, max_tokens)
    schema: dict = {"types": {}}
    p = _P(toks, schema, 32)
    while p.cur[0] != "eof":
        p.def_()
    return schema


# ---- introspection -> model ------------------------------------------------------------------------------------------------

def _introspect_type(t: Any, depth: int = 0) -> dict:
    if depth > 16 or not is_obj(t):
        raise ActionKitError("bad_source", "malformed introspection type reference")
    if t.get("kind") == "NON_NULL":
        return {"k": "nonnull", "of": _introspect_type(t.get("ofType"), depth + 1)}
    if t.get("kind") == "LIST":
        return {"k": "list", "of": _introspect_type(t.get("ofType"), depth + 1)}
    if not is_str(t.get("name")):
        raise ActionKitError("bad_source", "malformed introspection type reference")
    return {"k": "named", "name": t["name"]}


_KINDS = {"OBJECT": "object", "INPUT_OBJECT": "input", "ENUM": "enum", "SCALAR": "scalar", "INTERFACE": "interface", "UNION": "union"}


def _field_of(f: Any) -> Optional[dict]:
    if not is_obj(f) or not is_str(f.get("name")):
        return None
    raw = f.get("args")
    args = []
    for a in (raw if isinstance(raw, list) else []):
        if is_obj(a) and is_str(a.get("name")):
            args.append({"name": a["name"], "type": _introspect_type(a.get("type")), **({"desc": a["description"]} if is_str(a.get("description")) else {})})
    out = {"name": f["name"], "args": args, "type": {"k": "named", "name": "String"} if "type" not in f else _introspect_type(f["type"]),
           "deprecated": f.get("isDeprecated") is True}
    if is_str(f.get("description")):
        out["desc"] = f["description"]
    return out


def from_introspection(doc: Any) -> dict:
    root = doc["data"] if is_obj(doc) and is_obj(doc.get("data")) else doc
    s = root["__schema"] if is_obj(root) and is_obj(root.get("__schema")) else None
    if s is None or not isinstance(s.get("types"), list):
        raise ActionKitError("bad_source", "not a GraphQL introspection result (no __schema.types)")
    schema: dict = {"types": {}}

    def root_name(k: str) -> Optional[str]:
        return s[k]["name"] if is_obj(s.get(k)) and is_str(s[k].get("name")) else None

    for key, k in (("query", "queryType"), ("mutation", "mutationType"), ("subscription", "subscriptionType")):
        n = root_name(k)
        if n:
            schema[key] = n
    for t in s["types"]:
        if not is_obj(t) or not is_str(t.get("name")) or not is_str(t.get("kind")):
            continue
        if t["name"].startswith("__"):
            continue
        kind = _KINDS.get(t["kind"])
        if kind is None:
            continue
        raw = t.get("inputFields") if kind == "input" else t.get("fields")
        ev = t.get("enumValues")
        schema["types"][t["name"]] = {
            "kind": kind, "name": t["name"],
            "fields": [f for f in (_field_of(x) for x in (raw if isinstance(raw, list) else [])) if f is not None],
            "values": [e["name"] for e in (ev if isinstance(ev, list) else []) if is_obj(e) and is_str(e.get("name"))],
        }
    return schema


# ---- model -> JSON-schema-like -> params -----------------------------------------------------------------------------------

SCALARS = {
    "Int": {"type": "integer", "format": "int32"}, "String": {"type": "string"}, "ID": {"type": "string"}, "Boolean": {"type": "boolean"},
    "Float": {"type": "number"}, "Date": {"type": "string", "format": "date"}, "DateTime": {"type": "string", "format": "date-time"},
    "Email": {"type": "string", "format": "email"}, "UUID": {"type": "string", "format": "uuid"}, "URL": {"type": "string", "format": "url"},
    "URI": {"type": "string", "format": "url"},
}


def _schema_of(t: dict, gs: dict, c, bud, stack: tuple, where: str):
    nonnull = False
    cur = t
    while cur["k"] == "nonnull":
        nonnull = True
        cur = cur["of"]
    if cur["k"] == "list":
        return {"type": "array", "items": _schema_of(cur["of"], gs, c, bud, stack, where)[0]}, nonnull
    name = cur["name"]
    spent = bud.left <= 0
    bud.left -= 1
    if spent:
        if not bud.exhausted:
            bud.exhausted = True
            add_todo(c, where, "ref_budget", "type expansion stopped at the node budget (declared string; refine or drop)")
        return {}, nonnull
    if name in SCALARS:
        return dict(SCALARS[name]), nonnull
    d = gs["types"].get(name)
    if d is None:
        add_todo(c, where, "unknown_type", "type '%s' is not defined in the schema (declared string)" % clip(name, 60))
        return {}, nonnull
    if d["kind"] == "enum":
        return {"type": "string", "enum": list(dict.fromkeys(d["values"]))}, nonnull
    if d["kind"] == "scalar":
        return {"type": "string"}, nonnull
    if d["kind"] == "input":
        if name in stack:
            add_todo(c, where, "cyclic_ref", "input type '%s' is recursive (declared string; refine or drop)" % clip(name, 60))
            return {}, nonnull
        properties: dict = {}
        required: List[str] = []
        for f in d["fields"]:
            r, nn = _schema_of(f["type"], gs, c, bud, stack + (name,), where)
            if f["name"] != "__proto__":  # assigning `__proto__` on a JS object sets its prototype: never a member
                properties[f["name"]] = {**r, **({"description": f["desc"]} if f.get("desc") else {})}
            if nn:
                required.append(f["name"])
        return {"type": "object", "properties": properties, "required": required}, nonnull
    add_todo(c, where, "output_type", "type '%s' is an output type and cannot be an argument (declared string)" % clip(name, 60))
    return {}, nonnull


def import_graphql(source: Any, opts: dict) -> dict:
    """`source` is SDL text or an introspection result (parsed JSON)."""
    c = new_ctx("graphql", source, opts)
    gs = parse_graphql_sdl(source) if isinstance(source, str) else from_introspection(source)
    roots = ((gs.get("query", "Query"), "query"), (gs.get("mutation", "Mutation"), "mutation"), (gs.get("subscription", "Subscription"), "subscription"))
    for root_name, op in roots:
        rt = gs["types"].get(root_name)
        if rt is None:
            continue
        for f in sorted(rt["fields"], key=lambda x: UTF8_ORDER(x["name"])):
            where = "%s %s" % (op, clip(f["name"], 80))
            c.root = None
            bud = new_budget(c)
            properties: dict = {}
            required: List[str] = []
            for a in f["args"]:
                r, nn = _schema_of(a["type"], gs, c, bud, (), "%s(%s)" % (where, a["name"]))
                if a["name"] != "__proto__":
                    properties[a["name"]] = {**r, **({"description": a["desc"]} if a.get("desc") else {})}
                if nn:
                    required.append(a["name"])
            params: dict = {}
            flatten_object({"type": "object", "properties": properties, "required": required}, c, bud, where, params)
            if f["deprecated"]:
                add_todo(c, where, "deprecated", "the field is marked @deprecated")
            desc = f.get("desc")
            emit_def(
                c, f["name"], ["update"] if op == "mutation" else ["read"], "one", params, {"graphql": {"op": op, "field": clip(f["name"], 200)}},
                title=desc.split("\n")[0] if desc else f["name"], description=desc,
                idempotency={"mode": "natural"} if op != "mutation" else None,
                traits=with_trait(None, "pca.bulk") if op == "subscription" else None,
            )
    return finish(c)
