"""Token-tape form of the Goal IR (the TypeScript reference is @atlasauth/pca-goal `codec`). A tape is a list of
`[tag, value]` tokens, tag in k (keyword number) | i (integer) | s (string). Encoding is STRICT: anything that is not exactly an
IR value raises IrError (or the TypeError a JavaScript property read of null would), so a malformed value never reaches a
parser as something that merely happens to parse. IR values are the JSON trees of the reference (dicts with a `k` discriminant)."""
from typing import Any, Callable, List

from .analyzer_js import UNDEF, jget, truthy, u16key

__all__ = [
    "IrError", "OPS", "AGGS", "enc_unit", "enc_q", "enc_v", "enc_term", "enc_cond", "encode_goal", "encode_ontology", "encode_act",
    "encode_hist", "decode_policy", "decode_goal", "TapeReader", "okeys", "oget",
]


class IrError(Exception):
    """pca-goal: <message>"""

    def __init__(self, m: str):
        super().__init__("pca-goal: " + m)


def _K(n: int) -> list:
    return ["k", n]


def _safe_int(n: Any) -> bool:
    if isinstance(n, bool):
        return False
    if isinstance(n, int):
        return abs(n) <= 9007199254740991
    if isinstance(n, float):
        return n.is_integer() and abs(n) <= 9007199254740991 and not (n == 0 and str(n).startswith("-"))
    return False


def _I(n: Any) -> list:
    if not _safe_int(n):
        raise IrError("%s is not a safe integer" % (n,))
    return ["i", int(n)]


def _S(s: Any) -> list:
    if not isinstance(s, str):
        raise IrError("string expected")
    return ["s", s]


def _bad(what: str, v: Any) -> Any:
    raise IrError("unknown %s: %r" % (what, v))


def _list(xs: Any, f: Callable[[Any], list]) -> list:
    if not isinstance(xs, (list, tuple)):
        raise IrError("array expected")
    out = [_I(len(xs))]
    for x in xs:
        out.extend(f(x))
    return out


def _strs(xs: Any) -> list:
    return _list(xs, lambda s: [_S(s)])


OPS = ["eq", "ne", "lt", "lte", "gt", "gte", "in", "nin"]
AGGS = ["count", "sum", "max", "distinct"]
_UNITS = {"count": 301, "duration": 302, "instant": 303, "bytes": 304, "ratio": 305}


def enc_unit(u: Any) -> list:
    k = jget(u, "k")
    if k == "money":
        return [_K(300), _S(jget(u, "ccy"))]
    if isinstance(k, str) and k in _UNITS:
        return [_K(_UNITS[k])]
    return _bad("unit", u)


def enc_q(q: Any) -> list:
    return enc_unit(jget(q, "u")) + [_I(jget(q, "n"))]


def _enc_ty(t: Any) -> list:
    k = jget(t, "k")
    if k == "q":
        return [_K(310)] + enc_unit(jget(t, "u"))
    return [_K(311)] if k == "s" else _bad("type", t)


def _enc_atom(a: Any) -> list:
    k = jget(a, "k")
    if k == "q":
        return [_K(320)] + enc_q(jget(a, "q"))
    if k == "s":
        return [_K(321), _S(jget(a, "s"))]
    return _bad("set member (sets hold quantities and strings only)", a)


def enc_v(v: Any) -> list:
    k = jget(v, "k")
    if k == "q":
        return [_K(330)] + enc_q(jget(v, "q"))
    if k == "s":
        return [_K(331), _S(jget(v, "s"))]
    if k == "set":
        return [_K(332)] + _list(jget(v, "items"), _enc_atom)
    return _bad("value", v)


def enc_term(t: Any) -> list:
    k = jget(t, "k")
    if k == "param":
        return [_K(340), _S(jget(t, "path"))] + _enc_ty(jget(t, "ty"))
    if k == "lit":
        return [_K(341)] + enc_v(jget(t, "v"))
    if k == "hist":
        return [_K(342), _S(jget(t, "bid"))] + enc_unit(jget(t, "u"))
    return _bad("term", t)


def _enc_op(op: Any) -> list:
    if isinstance(op, str) and op in OPS:
        return [_K(350 + OPS.index(op))]
    return _bad("operator", op)


def enc_cond(c: Any) -> list:
    k = jget(c, "k")
    if k == "true":
        return [_K(360)]
    if k == "cmp":
        return [_K(361)] + _enc_op(jget(c, "op")) + enc_term(jget(c, "l")) + enc_term(jget(c, "r"))
    if k == "and":
        return [_K(362)] + enc_cond(jget(c, "a")) + enc_cond(jget(c, "b"))
    if k == "or":
        return [_K(363)] + enc_cond(jget(c, "a")) + enc_cond(jget(c, "b"))
    if k == "not":
        return [_K(364)] + enc_cond(jget(c, "c"))
    return _bad("condition", c)


def _enc_part(s: Any) -> list:
    k = jget(s, "k")
    if k == "exact":
        return [_K(375), _S(jget(s, "id"))]
    if k == "oneof":
        return [_K(376)] + _strs(jget(s, "ids"))
    if k == "related":
        return [_K(377), _S(jget(s, "rel")), _S(jget(s, "anchor"))]
    return _bad("resource part", s)


def _enc_res(s: Any) -> list:
    k = jget(s, "k")
    if k == "exact":
        return [_K(370), _S(jget(s, "id"))]
    if k == "oneof":
        return [_K(371)] + _strs(jget(s, "ids"))
    if k == "related":
        return [_K(372), _S(jget(s, "rel")), _S(jget(s, "anchor"))]
    if k == "any":
        return [_K(373), _S(jget(s, "reason"))]
    if k == "all_of":
        return [_K(374)] + _list(jget(s, "parts"), _enc_part)
    return _bad("resource selector", s)


def _enc_grant(g: Any) -> list:
    return [_K(380), _S(jget(g, "gid")), _S(jget(g, "verb"))] + _enc_res(jget(g, "res")) + enc_cond(jget(g, "cond"))


def _enc_target(t: Any) -> list:
    k = jget(t, "k")
    if k == "verb":
        return [_K(390), _S(jget(t, "verb"))]
    return [_K(391), _S(jget(t, "cls"))] if k == "effect" else _bad("prohibit target", t)


def _enc_prohibit(p: Any) -> list:
    return [_K(392), _S(jget(p, "pid"))] + _enc_target(jget(p, "target")) + _enc_res(jget(p, "res")) + enc_cond(jget(p, "cond"))


def _enc_sel(s: Any) -> list:
    k = jget(s, "k")
    if k == "gids":
        return [_K(410)] + _strs(jget(s, "gids"))
    return [_K(411), _S(jget(s, "cls"))] if k == "effect" else _bad("selection", s)


def _enc_window(w: Any) -> list:
    k = jget(w, "k")
    if k == "task":
        return [_K(420)]
    if k == "sliding":
        return [_K(421), _I(jget(w, "ms"))]
    if k == "period":
        return [_K(422), _I(jget(w, "ms")), _I(jget(w, "t0"))]
    if k == "lifetime":
        return [_K(423)]
    return _bad("window", w)


def _enc_scope(s: Any) -> list:
    k = jget(s, "k")
    if k == "session":
        return [_K(430)]
    if k == "principal":
        return [_K(431)]
    if k == "org":
        return [_K(432)]
    if k == "fleet":
        return [_K(433)] + _strs(jget(s, "agents"))
    return _bad("scope", s)


def _enc_on_exceed(o: Any) -> list:
    if o == "deny":
        return [_K(440)]
    return [_K(441)] if o == "escalate" else _bad("on_exceed", o)


def _enc_bcore(b: Any) -> list:
    agg = jget(b, "agg")
    if not (isinstance(agg, str) and agg in AGGS):
        _bad("aggregate", agg)
    return ([_K(450), _K(400 + AGGS.index(agg))] + enc_term(jget(b, "value")) + [_S(jget(b, "key"))] + _enc_window(jget(b, "window"))
            + _enc_scope(jget(b, "scope")) + enc_q(jget(b, "cap")) + _enc_on_exceed(jget(b, "onExceed")))


def _enc_bound(b: Any) -> list:
    return [_K(451), _S(jget(b, "bid"))] + _enc_sel(jget(b, "sel")) + _enc_bcore(b)


def _enc_validity(v: Any) -> list:
    return [_K(460), _I(jget(v, "notBefore")), _I(jget(v, "notAfter")), _I(jget(v, "maxIdle"))]


def _enc_deleg(d: Any) -> list:
    return [_K(461), _I(jget(d, "maxDepth")), _I(1 if truthy(jget(d, "narrowOnly")) else 0)] + _strs(jget(d, "mayTouch"))


def _enc_hole(h: Any) -> list:
    return [_K(470), _S(jget(h, "hid")), _S(jget(h, "q"))] + _strs(jget(h, "domain")) + _strs(jget(h, "affects")) + [_I(1 if truthy(jget(h, "global")) else 0)]


def encode_goal(g: Any) -> list:
    """The goal as a token tape."""
    return ([_K(480), _I(jget(g, "v")), _S(jget(g, "principal")), _S(jget(g, "ontDigest")), _S(jget(g, "nlDigest"))]
            + _strs(jget(g, "sources")) + _list(jget(g, "grants"), _enc_grant) + _list(jget(g, "prohibits"), _enc_prohibit)
            + _list(jget(g, "bounds"), _enc_bound) + _enc_validity(jget(g, "validity")) + _enc_deleg(jget(g, "deleg"))
            + _list(jget(g, "escalateOn"), enc_cond) + _strs(jget(g, "wildcardAck")) + _list(jget(g, "holes"), _enc_hole))


def _enc_param_decl(p: Any) -> list:
    return [_K(500), _S(jget(p, "path"))] + _enc_ty(jget(p, "ty"))


def _enc_verb_decl(v: Any) -> list:
    return [_K(501), _S(jget(v, "verb")), _S(jget(v, "cls"))] + _list(jget(v, "params"), _enc_param_decl)


def _enc_rel_decl(r: Any) -> list:
    return [_K(502), _S(jget(r, "rel")), _S(jget(r, "anchor"))] + _strs(jget(r, "members"))


def encode_ontology(o: Any) -> list:
    return [_K(510)] + _list(jget(o, "verbs"), _enc_verb_decl) + _list(jget(o, "rels"), _enc_rel_decl)


def okeys(o: Any) -> List[str]:
    """Object.keys(o): a dict's keys, an array's / string's indices, nothing for other primitives; null throws."""
    if o is None or o is UNDEF:
        raise TypeError("cannot convert undefined or null to object")
    if isinstance(o, dict):
        return list(o.keys())
    if isinstance(o, (list, tuple)):
        return [str(i) for i in range(len(o))]
    if isinstance(o, str):
        return [str(i) for i in range(len(o.encode("utf-16-le", "surrogatepass")) // 2)]
    return []


def oget(o: Any, k: str) -> Any:
    if isinstance(o, dict):
        return o.get(k, UNDEF)
    if isinstance(o, (list, tuple)):
        return o[int(k)]
    if isinstance(o, str):
        u = o.encode("utf-16-le", "surrogatepass")
        i = int(k)
        return u[2 * i:2 * i + 2].decode("utf-16-le", "surrogatepass")
    return UNDEF


def _enc_act(a: Any) -> list:
    keys = sorted(okeys(jget(a, "params")), key=u16key)
    params = jget(a, "params")
    return ([_K(530), _S(jget(a, "verb")), _S(jget(a, "res"))] + _list(keys, lambda k: [_K(520), _S(k)] + enc_v(oget(params, k)))
            + [_I(jget(a, "t")), _S(jget(a, "sess")), _S(jget(a, "prin")), _S(jget(a, "org")), _S(jget(a, "agent")), _I(jget(a, "depth"))])


def encode_act(a: Any) -> list:
    return _enc_act(a)


def _enc_adm(a: Any) -> list:
    return [_K(531), _S(jget(a, "gid"))] + _enc_act(jget(a, "act"))


def encode_hist(h: Any) -> list:
    aggs = jget(h, "aggs")
    keys = sorted(okeys(aggs), key=u16key)
    return [_K(541)] + _list(jget(h, "adms"), _enc_adm) + [_I(jget(h, "last"))] + _list(keys, lambda k: [_K(540), _S(k)] + enc_q(oget(aggs, k)))


# ---- decoding ----------------------------------------------------------------------------------------------------------

class TapeReader:
    def __init__(self, t: Any):
        self.t = t
        self.i = 0

    def next(self) -> list:
        if not isinstance(self.t, (list, tuple)) or self.i >= len(self.t):
            raise IrError("truncated tape")
        x = self.t[self.i]
        self.i += 1
        if not isinstance(x, (list, tuple)) or len(x) < 2:
            raise IrError("malformed token")
        return x

    def k(self) -> int:
        x = self.next()
        if x[0] != "k" or not _safe_int(x[1]):
            raise IrError("keyword expected")
        return int(x[1])

    def int(self) -> int:
        x = self.next()
        if x[0] != "i" or not _safe_int(x[1]):
            raise IrError("integer expected")
        return int(x[1])

    def str(self) -> str:
        x = self.next()
        if x[0] != "s" or not isinstance(x[1], str):
            raise IrError("string expected")
        return x[1]

    def done(self) -> bool:
        return self.i >= len(self.t)

    def list(self, f: Callable[[], Any]) -> list:
        n = self.int()
        if n < 0:
            raise IrError("negative length")
        return [f() for _ in range(n)]

    def strs(self) -> list:
        return self.list(self.str)


_UNIT_TAGS = {301: "count", 302: "duration", 303: "instant", 304: "bytes", 305: "ratio"}


def _d_unit(r: TapeReader) -> dict:
    k = r.k()
    if k == 300:
        return {"k": "money", "ccy": r.str()}
    if k not in _UNIT_TAGS:
        raise IrError("bad unit tag %d" % k)
    return {"k": _UNIT_TAGS[k]}


def _d_q(r: TapeReader) -> dict:
    u = _d_unit(r)
    return {"u": u, "n": r.int()}


def _d_ty(r: TapeReader) -> dict:
    k = r.k()
    if k == 310:
        return {"k": "q", "u": _d_unit(r)}
    if k == 311:
        return {"k": "s"}
    raise IrError("bad type tag %d" % k)


def _d_atom(r: TapeReader) -> dict:
    k = r.k()
    if k == 320:
        return {"k": "q", "q": _d_q(r)}
    if k == 321:
        return {"k": "s", "s": r.str()}
    raise IrError("bad atom tag %d" % k)


def _d_v(r: TapeReader) -> dict:
    k = r.k()
    if k == 330:
        return {"k": "q", "q": _d_q(r)}
    if k == 331:
        return {"k": "s", "s": r.str()}
    if k == 332:
        return {"k": "set", "items": r.list(lambda: _d_atom(r))}
    raise IrError("bad value tag %d" % k)


def _d_term(r: TapeReader) -> dict:
    k = r.k()
    if k == 340:
        path = r.str()
        return {"k": "param", "path": path, "ty": _d_ty(r)}
    if k == 341:
        return {"k": "lit", "v": _d_v(r)}
    if k == 342:
        bid = r.str()
        return {"k": "hist", "bid": bid, "u": _d_unit(r)}
    raise IrError("bad term tag %d" % k)


def _d_op(r: TapeReader) -> str:
    i = r.k() - 350
    if 0 <= i < len(OPS):
        return OPS[i]
    raise IrError("bad operator")


def _d_n(r: TapeReader) -> dict:
    k = r.k()
    if k == 600:
        return {"k": "true"}
    if k == 601:
        return {"k": "false"}
    if k == 602:
        op = _d_op(r)
        l = _d_term(r)
        return {"k": "atom", "op": op, "l": l, "r": _d_term(r)}
    if k == 603:
        a = _d_n(r)
        return {"k": "and", "a": a, "b": _d_n(r)}
    if k == 604:
        a = _d_n(r)
        return {"k": "or", "a": a, "b": _d_n(r)}
    raise IrError("bad condition tag %d" % k)


def _d_res_pat(r: TapeReader) -> dict:
    k = r.k()
    if k == 630:
        return {"k": "star"}
    if k == 631:
        return {"k": "set", "ids": r.strs()}
    raise IrError("bad resource pattern tag %d" % k)


def _d_window(r: TapeReader) -> dict:
    k = r.k()
    if k == 420:
        return {"k": "task"}
    if k == 421:
        return {"k": "sliding", "ms": r.int()}
    if k == 422:
        ms = r.int()
        return {"k": "period", "ms": ms, "t0": r.int()}
    if k == 423:
        return {"k": "lifetime"}
    raise IrError("bad window tag %d" % k)


def _d_scope(r: TapeReader) -> dict:
    k = r.k()
    if k == 430:
        return {"k": "session"}
    if k == 431:
        return {"k": "principal"}
    if k == 432:
        return {"k": "org"}
    if k == 433:
        return {"k": "fleet", "agents": r.strs()}
    raise IrError("bad scope tag %d" % k)


def _d_agg(r: TapeReader) -> str:
    i = r.k() - 400
    if 0 <= i < len(AGGS):
        return AGGS[i]
    raise IrError("bad aggregate")


def _d_on_exceed(r: TapeReader) -> str:
    oe = r.k()
    if oe != 440 and oe != 441:
        raise IrError("bad on_exceed")
    return "deny" if oe == 440 else "escalate"


def _d_ceil(r: TapeReader) -> dict:
    if r.k() != 610:
        raise IrError("ceiling expected")
    bid = r.str()
    sel_gids = r.strs()
    sel_verbs = r.strs()
    if r.k() != 450:
        raise IrError("bound core expected")
    agg = _d_agg(r)
    value = _d_term(r)
    key = r.str()
    window = _d_window(r)
    scope = _d_scope(r)
    cap = _d_q(r)
    return {"bid": bid, "selGids": sel_gids, "selVerbs": sel_verbs, "agg": agg, "value": value, "key": key, "window": window,
            "scope": scope, "cap": cap, "onExceed": _d_on_exceed(r)}


def decode_policy(t: Any) -> dict:
    """Decode the compiler's policy tape (after its leading status token); raises IrError unless the whole tape is one policy."""
    r = TapeReader(t)
    if r.k() != 650:
        raise IrError("policy expected")

    def pred() -> dict:
        if r.k() != 620:
            raise IrError("pred")
        gid = r.str()
        verb = r.str()
        res = _d_res_pat(r)
        return {"gid": gid, "verb": verb, "res": res, "cond": _d_n(r)}

    def proh() -> dict:
        if r.k() != 640:
            raise IrError("prohibition")
        pid = r.str()
        verbs = r.strs()
        res = _d_res_pat(r)
        return {"pid": pid, "verbs": verbs, "res": res, "cond": _d_n(r)}

    preds = r.list(pred)
    prohs = r.list(proh)
    ceils = r.list(lambda: _d_ceil(r))
    escs = r.list(lambda: _d_n(r))
    if r.k() != 460:
        raise IrError("validity")
    nb = r.int()
    na = r.int()
    validity = {"notBefore": nb, "notAfter": na, "maxIdle": r.int()}
    if r.k() != 461:
        raise IrError("delegation")
    md = r.int()
    nrw = r.int() == 1
    deleg = {"maxDepth": md, "narrowOnly": nrw, "mayTouch": r.strs()}
    if not r.done():
        raise IrError("trailing tokens after policy")
    return {"preds": preds, "prohs": prohs, "ceils": ceils, "escs": escs, "validity": validity, "deleg": deleg}


def _d_cond(r: TapeReader) -> dict:
    k = r.k()
    if k == 360:
        return {"k": "true"}
    if k == 361:
        op = _d_op(r)
        l = _d_term(r)
        return {"k": "cmp", "op": op, "l": l, "r": _d_term(r)}
    if k == 362:
        a = _d_cond(r)
        return {"k": "and", "a": a, "b": _d_cond(r)}
    if k == 363:
        a = _d_cond(r)
        return {"k": "or", "a": a, "b": _d_cond(r)}
    if k == 364:
        return {"k": "not", "c": _d_cond(r)}
    raise IrError("bad condition tag %d" % k)


def _d_part(r: TapeReader) -> dict:
    k = r.k()
    if k == 375:
        return {"k": "exact", "id": r.str()}
    if k == 376:
        return {"k": "oneof", "ids": r.strs()}
    if k == 377:
        rel = r.str()
        return {"k": "related", "rel": rel, "anchor": r.str()}
    raise IrError("bad resource part tag %d" % k)


def _d_res(r: TapeReader) -> dict:
    k = r.k()
    if k == 370:
        return {"k": "exact", "id": r.str()}
    if k == 371:
        return {"k": "oneof", "ids": r.strs()}
    if k == 372:
        rel = r.str()
        return {"k": "related", "rel": rel, "anchor": r.str()}
    if k == 373:
        return {"k": "any", "reason": r.str()}
    if k == 374:
        return {"k": "all_of", "parts": r.list(lambda: _d_part(r))}
    raise IrError("bad resource selector tag %d" % k)


def _expect(r: TapeReader, k: int, what: str) -> None:
    if r.k() != k:
        raise IrError("%s expected" % what)


def decode_goal(t: Any) -> dict:
    """Parse a goal tape; raises IrError unless the whole tape is exactly one goal."""
    r = TapeReader(t)
    _expect(r, 480, "goal")
    v = r.int()
    principal = r.str()
    ont_digest = r.str()
    nl_digest = r.str()
    sources = r.strs()

    def grant() -> dict:
        _expect(r, 380, "grant")
        gid = r.str()
        verb = r.str()
        res = _d_res(r)
        return {"gid": gid, "verb": verb, "res": res, "cond": _d_cond(r)}

    def prohibit() -> dict:
        _expect(r, 392, "prohibit")
        pid = r.str()
        tk = r.k()
        if tk == 390:
            target = {"k": "verb", "verb": r.str()}
        elif tk == 391:
            target = {"k": "effect", "cls": r.str()}
        else:
            raise IrError("bad prohibit target")
        res = _d_res(r)
        return {"pid": pid, "target": target, "res": res, "cond": _d_cond(r)}

    def bound() -> dict:
        _expect(r, 451, "bound")
        bid = r.str()
        sk = r.k()
        if sk == 410:
            sel = {"k": "gids", "gids": r.strs()}
        elif sk == 411:
            sel = {"k": "effect", "cls": r.str()}
        else:
            raise IrError("bad selection")
        _expect(r, 450, "bound core")
        agg = _d_agg(r)
        value = _d_term(r)
        key = r.str()
        window = _d_window(r)
        scope = _d_scope(r)
        cap = _d_q(r)
        return {"bid": bid, "sel": sel, "agg": agg, "value": value, "key": key, "window": window, "scope": scope, "cap": cap,
                "onExceed": _d_on_exceed(r)}

    def hole() -> dict:
        _expect(r, 470, "hole")
        hid = r.str()
        q = r.str()
        domain = r.strs()
        affects = r.strs()
        return {"hid": hid, "q": q, "domain": domain, "affects": affects, "global": r.int() == 1}

    grants = r.list(grant)
    prohibits = r.list(prohibit)
    bounds = r.list(bound)
    _expect(r, 460, "validity")
    nb = r.int()
    na = r.int()
    validity = {"notBefore": nb, "notAfter": na, "maxIdle": r.int()}
    _expect(r, 461, "delegation")
    md = r.int()
    nrw = r.int() == 1
    deleg = {"maxDepth": md, "narrowOnly": nrw, "mayTouch": r.strs()}
    escalate_on = r.list(lambda: _d_cond(r))
    wildcard_ack = r.strs()
    holes = r.list(hole)
    if not r.done():
        raise IrError("trailing tokens after goal")
    return {"v": v, "principal": principal, "ontDigest": ont_digest, "nlDigest": nl_digest, "sources": sources, "grants": grants,
            "prohibits": prohibits, "bounds": bounds, "validity": validity, "deleg": deleg, "escalateOn": escalate_on,
            "wildcardAck": wildcard_ack, "holes": holes}
