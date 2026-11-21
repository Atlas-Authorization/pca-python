"""Protobuf services to drafts, from `.proto` text or a binary FileDescriptorSet (native port of import/grpc.ts of the TypeScript reference
@atlasauth/pca-actions). `service.method` becomes the verb; `google.api.http` gives method and path; `idempotency_level` gives read /
idempotent; field behavior (REQUIRED, OUTPUT_ONLY) refines params; streaming methods get `pca.bulk`. Offline, bounded, no code generation.
A model is {"messages": {full: {full, fields, mapEntry}}, "enums": {full: {full, values}}, "services": [{full, name, methods}]}."""
import math
import re
from typing import Any, List, Optional

from .actions import _JS_WS, ActionKitError
from .actions_import_common import UTF8_ORDER, add_todo, clip, emit_def, finish, flatten_object, new_budget, new_ctx, with_trait
from .sdjwt_jws import js_num

SCALAR_NAMES = frozenset(("double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32", "fixed64", "sfixed32", "sfixed64", "bool", "string", "bytes"))
_ID0 = re.compile(r"[A-Za-z_.]")
_IDN = re.compile(r"[A-Za-z0-9_.]")
_NUM0 = re.compile(r"[-0-9]")
_NUMN = re.compile(r"[-+.0-9A-Za-z]")
_PUNCT = "{}[]()<>=;,:"


def _new_model() -> dict:
    return {"messages": {}, "enums": {}, "services": []}


def _lex(src: str, max_tokens: int) -> List[tuple]:
    out: List[tuple] = []
    n = len(src)
    i = 0

    def push(t: tuple) -> None:
        if len(out) >= max_tokens:
            raise ActionKitError("import_limit", "the proto source has too many tokens")
        out.append(t)

    while i < n:
        ch = src[i]
        if ch in _JS_WS:
            i += 1
            continue
        if src.startswith("//", i):
            while i < n and src[i] != "\n":
                i += 1
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j < 0:
                raise ActionKitError("bad_source", "unterminated comment in proto source")
            i = j + 2
            continue
        if ch == '"' or ch == "'":
            j = i + 1
            s: List[str] = []
            while j < n and src[j] != ch:
                if src[j] == "\n":
                    raise ActionKitError("bad_source", "unterminated string in proto source")
                if src[j] == "\\":
                    s.append(src[j + 1] if j + 1 < n else "")
                    j += 2
                else:
                    s.append(src[j])
                    j += 1
            if j >= n:
                raise ActionKitError("bad_source", "unterminated string in proto source")
            push(("str", "".join(s)))
            i = j + 1
            continue
        if _ID0.fullmatch(ch):
            j = i + 1
            while j < n and _IDN.fullmatch(src[j]):
                j += 1
            push(("id", src[i:j]))
            i = j
            continue
        if _NUM0.fullmatch(ch):
            j = i + 1
            while j < n and _NUMN.fullmatch(src[j]):
                j += 1
            push(("num", src[i:j]))
            i = j
            continue
        if ch in _PUNCT:
            push(("p", ch))
            i += 1
            continue
        raise ActionKitError("bad_source", "unexpected character in proto source at offset %d" % i)
    return out


def _qual(scope: str, name: str) -> str:
    return name if scope == "" else "%s.%s" % (scope, name)


class _PP:
    def __init__(self, toks: List[tuple], m: dict, max_depth: int):
        self.i = 0
        self.pkg = ""
        self.toks = toks
        self.m = m
        self.max_depth = max_depth

    @property
    def cur(self) -> Optional[tuple]:
        return self.toks[self.i] if 0 <= self.i < len(self.toks) else None

    def is_(self, v: str) -> bool:
        t = self.cur
        return t is not None and t[0] != "str" and t[1] == v

    def eat(self, v: str) -> bool:
        if self.is_(v):
            self.i += 1
            return True
        return False

    def fail(self, msg: str):
        t = self.cur
        raise ActionKitError("bad_source", "proto parse error: %s near '%s'" % (msg, clip(t[1] if t is not None else "<end>", 30)))

    def expect(self, v: str) -> None:
        if not self.eat(v):
            self.fail("expected '%s'" % v)

    def id(self) -> str:
        t = self.cur
        if t is None or t[0] != "id":
            self.fail("expected an identifier")
        self.i += 1
        return t[1]

    def _take(self) -> Optional[tuple]:
        t = self.cur
        self.i += 1
        return t

    def skip_to(self, open_: str, close: str, depth: int = 1) -> None:
        while depth > 0:
            t = self._take()
            if t is None:
                self.fail("unterminated block")
            if t[0] == "p":
                if t[1] == open_:
                    depth += 1
                elif t[1] == close:
                    depth -= 1

    def skip_statement(self) -> None:
        while self.cur is not None and not self.is_(";"):
            if self.is_("{"):
                self.i += 1
                self.skip_to("{", "}")
                return
            self.i += 1
        self.eat(";")

    def file(self) -> None:
        while self.cur is not None:
            if self.eat(";"):
                continue
            kw = self.id()
            if kw == "package":
                self.pkg = self.id()
                self.expect(";")
            elif kw == "message":
                self.message(self.pkg, 0)
            elif kw == "enum":
                self.enum_def(self.pkg)
            elif kw == "service":
                self.service()
            elif kw == "extend":
                self.id()
                self.expect("{")
                self.skip_to("{", "}")
            else:
                self.skip_statement()

    def enum_def(self, scope: str) -> None:
        full = _qual(scope, self.id())
        self.expect("{")
        values: List[str] = []
        while not self.is_("}"):
            if self.cur is None:
                self.fail("unterminated enum")
            if self.is_("option") or self.is_("reserved"):
                self.skip_statement()
                continue
            values.append(self.id())
            self.skip_statement()
        self.expect("}")
        self.m["enums"][full] = {"full": full, "values": values}

    def field_options(self) -> List[str]:
        behavior: List[str] = []
        if not self.eat("["):
            return behavior
        depth = 1
        in_behavior = False
        while depth > 0:
            t = self._take()
            if t is None:
                self.fail("unterminated field options")
            if t[0] == "p":
                if t[1] in ("[", "{"):
                    depth += 1
                elif t[1] in ("]", "}"):
                    depth -= 1
                elif t[1] == ",":
                    in_behavior = False
            elif t[0] == "id":
                if t[1].endswith("field_behavior"):
                    in_behavior = True
                elif in_behavior and re.fullmatch(r"[A-Z_]+", t[1]):
                    behavior.append(t[1])
        return behavior

    def message(self, scope: str, depth: int) -> None:
        if depth > self.max_depth:
            raise ActionKitError("import_limit", "proto message nesting is too deep")
        full = _qual(scope, self.id())
        msg = {"full": full, "fields": [], "mapEntry": False}
        self.m["messages"][full] = msg
        self.expect("{")

        def field(label: Optional[str], oneof: bool) -> None:
            repeated = label == "repeated"
            typ = self.id()
            fmap = None
            if typ == "map" and self.eat("<"):
                k = self.id()
                self.expect(",")
                v = self.id()
                self.expect(">")
                fmap = [k, v]
                typ = "map"
                repeated = False
            fname = self.id()
            self.expect("=")
            self.i += 1  # field number
            behavior = self.field_options()
            self.expect(";")
            f = {"name": fname, "type": typ, "scope": full, "repeated": repeated, "optional": label == "optional" or oneof, "behavior": behavior}
            if fmap:
                f["map"] = fmap
            msg["fields"].append(f)

        while not self.is_("}"):
            if self.cur is None:
                self.fail("unterminated message")
            if self.eat(";"):
                continue
            kw = self.cur[1] if self.cur[0] == "id" else ""
            if kw == "message":
                self.i += 1
                self.message(full, depth + 1)
                continue
            if kw == "enum":
                self.i += 1
                self.enum_def(full)
                continue
            if kw == "oneof":
                self.i += 1
                self.id()
                self.expect("{")
                while not self.is_("}"):
                    if self.cur is None:
                        self.fail("unterminated oneof")
                    if self.is_("option"):
                        self.skip_statement()
                        continue
                    field(None, True)
                self.expect("}")
                continue
            if kw in ("option", "reserved", "extensions"):
                self.skip_statement()
                continue
            if kw == "extend":
                self.i += 1
                self.id()
                self.expect("{")
                self.skip_to("{", "}")
                continue
            if kw == "group":
                self.skip_statement()
                continue
            if kw in ("repeated", "optional", "required"):
                self.i += 1
                field(kw, False)
                continue
            field(None, False)
        self.expect("}")

    def _stream(self) -> bool:
        t = self.cur
        if t is not None and t[1] == "stream" and t[0] == "id":
            self.i += 1
            return True
        return False

    def service(self) -> None:
        name = self.id()
        svc = {"full": _qual(self.pkg, name), "name": name, "methods": []}
        self.expect("{")
        while not self.is_("}"):
            if self.cur is None:
                self.fail("unterminated service")
            if self.eat(";"):
                continue
            if self.id() != "rpc":
                self.skip_statement()
                continue
            mname = self.id()
            self.expect("(")
            cs = self._stream()
            inp = self.id()
            self.expect(")")
            if self.id() != "returns":
                self.fail("expected 'returns'")
            self.expect("(")
            ss = self._stream()
            out = self.id()
            self.expect(")")
            m = {"name": mname, "input": inp, "output": out, "cs": cs, "ss": ss, "scope": self.pkg}
            if self.eat("{"):
                while not self.is_("}"):
                    if self.cur is None:
                        self.fail("unterminated rpc body")
                    if not self.is_("option"):
                        self.skip_statement()
                        continue
                    self.i += 1
                    if self.eat("("):
                        oname = self.id()
                        self.expect(")")
                    else:
                        oname = self.id()
                    self.expect("=")
                    if self.is_("{"):
                        self.i += 1
                        depth = 1
                        while depth > 0:
                            t = self._take()
                            if t is None:
                                self.fail("unterminated option")
                            if t[0] == "p":
                                if t[1] == "{":
                                    depth += 1
                                elif t[1] == "}":
                                    depth -= 1
                                continue
                            if depth == 1 and oname.endswith("http") and t[0] == "id" and t[1] in ("get", "put", "post", "delete", "patch") and self.is_(":"):
                                self.i += 1
                                path = self.cur[1] if self.cur is not None and self.cur[0] == "str" else ""
                                self.i += 1
                                if "http" not in m:
                                    m["http"] = {"method": t[1].upper(), "path": path}
                            elif depth == 1 and oname.endswith("http") and t[0] == "id" and t[1] == "body" and self.is_(":"):
                                self.i += 1
                                if self.cur is not None and self.cur[0] == "str" and "http" in m:
                                    m["http"]["body"] = self.cur[1]
                                self.i += 1
                        self.eat(";")
                    else:
                        v = self.cur
                        self.i += 1
                        if oname.endswith("idempotency_level") and v is not None:
                            m["idem"] = v[1]
                        self.eat(";")
                self.expect("}")
                self.eat(";")
            else:
                self.expect(";")
            svc["methods"].append(m)
        self.expect("}")
        self.m["services"].append(svc)


def parse_proto(src: str, max_tokens: int = 2_000_000) -> dict:
    m = _new_model()
    _PP(_lex(src, max_tokens), m, 32).file()
    return m


# ---- binary descriptor set -------------------------------------------------------------------------------------------------

class _Reader:
    def __init__(self, b: bytes, end: Optional[int] = None):
        self.p = 0
        self.b = b
        self.end = len(b) if end is None else end

    def more(self) -> bool:
        return self.p < self.end

    def varint(self) -> float:
        """A JavaScript number: accumulated in double arithmetic, as the reference does (a 10-byte varint loses low bits)."""
        r = 0.0
        mul = 1.0
        for _ in range(10):
            if self.p >= self.end:
                raise ActionKitError("bad_source", "truncated descriptor")
            byte = self.b[self.p]
            self.p += 1
            r += float(byte & 0x7F) * mul
            if byte & 0x80 == 0:
                return r
            mul *= 128
        raise ActionKitError("bad_source", "overlong varint in descriptor")

    def len(self) -> "_Reader":
        n = self.varint()
        if n > self.end - self.p:
            raise ActionKitError("bad_source", "descriptor length exceeds the buffer")
        r = _Reader(self.b, self.p + int(n))
        r.p = self.p
        self.p += int(n)
        return r

    def skip(self, wt: int) -> None:
        if wt == 0:
            self.varint()
        elif wt == 1:
            self.adv(8)
        elif wt == 2:
            self.len()
        elif wt == 5:
            self.adv(4)
        else:
            raise ActionKitError("bad_source", "unsupported wire type %d in descriptor" % wt)

    def adv(self, n: int) -> None:
        if n > self.end - self.p:
            raise ActionKitError("bad_source", "truncated descriptor")
        self.p += n

    def str(self) -> str:
        r = self.len()
        raw = bytes(self.b[r.p:r.end])
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]  # TextDecoder drops a leading byte-order mark
        return raw.decode("utf-8", "replace")


def _tag(r: _Reader):
    t = r.varint()
    return int(math.floor(t / 8)), int(t % 8)


_FTYPES = {1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32", 6: "fixed64", 7: "fixed32", 8: "bool", 9: "string", 12: "bytes", 13: "uint32",
           15: "sfixed32", 16: "sfixed64", 17: "sint32", 18: "sint64"}
_BEHAV = {"2": "REQUIRED", "3": "OUTPUT_ONLY", "4": "INPUT_ONLY", "5": "IMMUTABLE"}
_HTTP_VERBS = {2: "GET", 3: "PUT", 4: "POST", 5: "DELETE", 6: "PATCH"}


def parse_descriptor_set(data: bytes) -> dict:
    m = _new_model()
    top = _Reader(bytes(data))

    def read_enum(r: _Reader, scope: str) -> None:
        name = ""
        values: List[str] = []
        while r.more():
            f, wt = _tag(r)
            if f == 1 and wt == 2:
                name = r.str()
            elif f == 2 and wt == 2:
                v = r.len()
                while v.more():
                    vf, vw = _tag(v)
                    if vf == 1 and vw == 2:
                        values.append(v.str())
                    else:
                        v.skip(vw)
            else:
                r.skip(wt)
        full = _qual(scope, name)
        m["enums"][full] = {"full": full, "values": values}

    def read_msg(r: _Reader, scope: str, depth: int) -> None:
        if depth > 32:
            raise ActionKitError("import_limit", "descriptor message nesting is too deep")
        name = ""
        fields: list = []
        nested: list = []
        enums: list = []
        map_entry = False
        while r.more():
            f, wt = _tag(r)
            if f == 1 and wt == 2:
                name = r.str()
            elif f == 2 and wt == 2:
                fr = r.len()
                fd = {"name": "", "type": 0.0, "label": 1.0, "typeName": "", "proto3opt": False, "behavior": []}
                while fr.more():
                    ff, fw = _tag(fr)
                    if ff == 1 and fw == 2:
                        fd["name"] = fr.str()
                    elif ff == 4 and fw == 0:
                        fd["label"] = fr.varint()
                    elif ff == 5 and fw == 0:
                        fd["type"] = fr.varint()
                    elif ff == 6 and fw == 2:
                        fd["typeName"] = fr.str()
                    elif ff == 17 and fw == 0:
                        fd["proto3opt"] = fr.varint() == 1
                    elif ff == 8 and fw == 2:
                        o = fr.len()
                        while o.more():
                            of, ow = _tag(o)
                            if of == 1052 and ow == 0:
                                fd["behavior"].append(js_num(o.varint()))
                            elif of == 1052 and ow == 2:
                                pk = o.len()
                                while pk.more():
                                    fd["behavior"].append(js_num(pk.varint()))
                            else:
                                o.skip(ow)
                    else:
                        fr.skip(fw)
                fields.append(fd)
            elif f == 3 and wt == 2:
                nested.append(r.len())
            elif f == 4 and wt == 2:
                enums.append(r.len())
            elif f == 7 and wt == 2:
                o = r.len()
                while o.more():
                    of, ow = _tag(o)
                    if of == 7 and ow == 0:
                        map_entry = o.varint() == 1
                    else:
                        o.skip(ow)
            else:
                r.skip(wt)
        full = _qual(scope, name)
        m["messages"][full] = {"full": full, "mapEntry": map_entry, "fields": [
            {"name": f["name"], "scope": full, "repeated": f["label"] == 3, "optional": f["proto3opt"],
             "type": f["typeName"] if f["typeName"] != "" else _FTYPES.get(f["type"], "bytes"),
             "behavior": [_BEHAV.get(b, "") for b in f["behavior"]]} for f in fields]}
        for n in nested:
            read_msg(n, full, depth + 1)
        for e in enums:
            read_enum(e, full)

    while top.more():
        f, wt = _tag(top)
        if f != 1 or wt != 2:
            top.skip(wt)
            continue
        fr = top.len()
        pkg = ""
        msgs: list = []
        enums: list = []
        svcs: list = []
        while fr.more():  # package may follow the messages in the wire order: collect first, then resolve scopes
            ff, fw = _tag(fr)
            if ff == 2 and fw == 2:
                pkg = fr.str()
            elif ff == 4 and fw == 2:
                msgs.append(fr.len())
            elif ff == 5 and fw == 2:
                enums.append(fr.len())
            elif ff == 6 and fw == 2:
                svcs.append(fr.len())
            else:
                fr.skip(fw)
        for r in msgs:
            read_msg(r, pkg, 0)
        for r in enums:
            read_enum(r, pkg)
        for r in svcs:
            name = ""
            methods: list = []
            while r.more():
                sf, sw = _tag(r)
                if sf == 1 and sw == 2:
                    name = r.str()
                elif sf == 2 and sw == 2:
                    mr = r.len()
                    me: dict = {"name": "", "input": "", "output": "", "cs": False, "ss": False, "scope": pkg}
                    while mr.more():
                        mf, mw = _tag(mr)
                        if mf == 1 and mw == 2:
                            me["name"] = mr.str()
                        elif mf == 2 and mw == 2:
                            me["input"] = mr.str()
                        elif mf == 3 and mw == 2:
                            me["output"] = mr.str()
                        elif mf == 5 and mw == 0:
                            me["cs"] = mr.varint() == 1
                        elif mf == 6 and mw == 0:
                            me["ss"] = mr.varint() == 1
                        elif mf == 4 and mw == 2:
                            o = mr.len()
                            while o.more():
                                of, ow = _tag(o)
                                if of == 34 and ow == 0:
                                    me["idem"] = {1: "NO_SIDE_EFFECTS", 2: "IDEMPOTENT"}.get(o.varint(), "IDEMPOTENCY_UNKNOWN")
                                elif of == 72295728 and ow == 2:
                                    h = o.len()
                                    while h.more():
                                        hf, hw = _tag(h)
                                        if hf in _HTTP_VERBS and hw == 2:
                                            if "http" not in me:
                                                me["http"] = {"method": _HTTP_VERBS[hf], "path": h.str()}
                                            else:
                                                h.str()
                                        elif hf == 7 and hw == 2:
                                            b = h.str()
                                            if "http" in me:
                                                me["http"]["body"] = b
                                        else:
                                            h.skip(hw)
                                else:
                                    o.skip(ow)
                        else:
                            mr.skip(mw)
                    methods.append(me)
                else:
                    r.skip(sw)
            m["services"].append({"full": _qual(pkg, name), "name": name, "methods": methods})
    return m


# ---- model -> params -------------------------------------------------------------------------------------------------------

def _resolve_name(m: dict, name: str, scope: str) -> Optional[str]:
    if name.startswith("."):
        return name[1:]
    parts = [] if scope == "" else scope.split(".")
    for k in range(len(parts), -1, -1):
        cand = ".".join([*parts[:k], name])
        if cand in m["messages"] or cand in m["enums"]:
            return cand
    return name if name in m["messages"] or name in m["enums"] else None


_WKT_STRING = ("google.protobuf.StringValue", "google.protobuf.BytesValue")
_WKT_INT = ("google.protobuf.Int32Value", "google.protobuf.Int64Value", "google.protobuf.UInt32Value", "google.protobuf.UInt64Value")


def _field_schema(m: dict, f: dict, c, stack: tuple, where: str, budget: dict) -> dict:
    def one(typ: str, scope: str) -> dict:
        if typ in SCALAR_NAMES:
            if "int" in typ or "fixed" in typ:
                return {"type": "integer", "format": "int64"}
            if typ == "bool":
                return {"type": "boolean"}
            if typ in ("string", "bytes"):
                return {"type": "string"}
            return {"type": "number"}
        ab = typ[1:] if typ.startswith(".") else None
        if ab == "google.protobuf.Timestamp" or typ == "google.protobuf.Timestamp":
            return {"type": "string", "format": "date-time"}
        t = ab if ab is not None else typ
        if t in _WKT_STRING:
            return {"type": "string"}
        if t in _WKT_INT:
            return {"type": "integer", "format": "int64"}
        if t == "google.protobuf.BoolValue":
            return {"type": "boolean"}
        if t.startswith("google.protobuf."):
            return {}
        full = _resolve_name(m, typ, scope)
        if full is None:
            add_todo(c, where, "unknown_type", "type '%s' is not defined in the proto source (declared string)" % clip(typ, 60))
            return {}
        en = m["enums"].get(full)
        if en:
            return {"type": "string", "enum": list(dict.fromkeys(en["values"]))}
        return _msg_schema(m, full, c, stack, where, budget)

    if f.get("map"):
        return {"type": "object"}
    s = one(f["type"], f["scope"])
    return {"type": "array", "items": s} if f["repeated"] else s


def _msg_schema(m: dict, full: str, c, stack: tuple, where: str, budget: dict) -> dict:
    msg = m["messages"].get(full)
    if msg is None:
        return {}
    if full in stack:
        add_todo(c, where, "cyclic_ref", "message '%s' is recursive (declared string; refine or drop)" % clip(full, 80))
        return {}
    stop = len(stack) > c.lim["max_ref_depth"]
    if not stop:
        budget["n"] -= 1
        stop = budget["n"] <= 0
    if stop:
        add_todo(c, where, "ref_budget", "message expansion stopped at the bound (declared string; refine or drop)")
        return {}
    properties: dict = {}
    required: List[str] = []
    for f in msg["fields"]:
        if "OUTPUT_ONLY" in f["behavior"]:
            continue
        if f["name"] != "__proto__":
            properties[f["name"]] = _field_schema(m, f, c, stack + (full,), "%s.%s" % (where, f["name"]), budget)
        if "REQUIRED" in f["behavior"]:
            required.append(f["name"])
    return {"type": "object", "properties": properties, "required": required}


def import_grpc(source: Any, opts: dict) -> dict:
    """`source` is `.proto` text or the bytes of a binary FileDescriptorSet."""
    c = new_ctx("grpc", source, opts)
    if isinstance(source, str):
        m = parse_proto(source)
    elif isinstance(source, (bytes, bytearray)):
        m = parse_descriptor_set(bytes(source))
    else:
        raise ActionKitError("bad_source", "a gRPC source is .proto text or a binary FileDescriptorSet")
    for svc in sorted(m["services"], key=lambda s: UTF8_ORDER(s["full"])):
        for me in sorted(svc["methods"], key=lambda s: UTF8_ORDER(s["name"])):
            where = "%s/%s" % (svc["name"], me["name"])
            c.root = None
            bud = new_budget(c)
            inp = _resolve_name(m, me["input"], me["scope"])
            inp = inp if inp is not None else re.sub(r"^\.", "", me["input"])
            schema = _msg_schema(m, inp, c, (), where, {"n": c.lim["max_ref_nodes"]})
            params: dict = {}
            if "properties" in schema:
                flatten_object(schema, c, bud, where, params)
            elif inp not in m["messages"] and not inp.startswith("google.protobuf."):
                add_todo(c, where, "unknown_type", "request type '%s' is not defined in the source (no parameters)" % clip(me["input"], 60))
            http = me.get("http")
            hm = http["method"] if http else None
            effects = ["read"] if hm == "GET" else ["delete"] if hm == "DELETE" else ["create"] if hm == "POST" else ["update"] if hm in ("PUT", "PATCH") \
                else ["read"] if me.get("idem") == "NO_SIDE_EFFECTS" else ["update"]
            natural = me.get("idem") in ("NO_SIDE_EFFECTS", "IDEMPOTENT") or hm in ("GET", "PUT", "DELETE")
            traits = None
            if me["cs"] or me["ss"]:
                traits = with_trait(traits, "pca.bulk")
                add_todo(c, where, "streaming", "a streaming method: acts on many messages (pca.bulk added)")
            bindings = {"grpc": {"service": clip(svc["full"], 250), "method": clip(me["name"], 250)}}
            if http and http["path"]:
                bindings["http"] = {"method": http["method"], "path": clip(http["path"], 250)}
            emit_def(
                c, "%s %s" % (svc["name"], me["name"]), effects, "one", params, bindings,
                title=re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", me["name"]), idempotency={"mode": "natural"} if natural else None, traits=traits,
            )
    return finish(c)
