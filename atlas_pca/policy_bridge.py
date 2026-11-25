"""Import external authorization policy into PCA predicates. Port of the TypeScript reference (@atlasauth/pca-policy-bridge).

  cedar_to_pca(text)            Cedar permit / forbid policies
  rego_to_pca(text)             OPA / Rego allow-rule subset
  openfga_to_pca(model, tuples) OpenFGA / Zanzibar ReBAC model + relationship tuples
  cel_to_condition(...)         strict CEL expressions (one condition, or a rejection naming the construct)
  decide(result, ctx)           deny-overrides-permit over a translation, built on the core predicate evaluator

Every translator returns {predicates, denies, caveats, report: {source, translated, skipped, errors}}; whatever is not modeled fails
closed. Text is read the way JavaScript reads it (UTF-16 code units, the JavaScript whitespace set, ASCII word characters), so
messages and offsets agree with the reference."""
import re
from typing import Any, Dict, List, Optional, Tuple

from .predicates import evaluate_predicates
from .safe_regex import to_units

# ---- JavaScript text semantics ---------------------------------------------------------------------------------------------------

_WS = "\t\n\u000b\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
_WS_CHARS = "\t\n\u000b\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
_S = "[" + _WS + "]"
_DOT = "[^\n\r\u2028\u2029]"
_A = re.ASCII


def _trim(s: str) -> str:
    return s.strip(_WS_CHARS)


def _from_units(s: str) -> str:
    """A UTF-16 unit view back to a string: surrogate pairs combine, a lone surrogate stays."""
    if not any("\ud800" <= c <= "\udfff" for c in s):
        return s
    return s.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


def _deep_from_units(v: Any) -> Any:
    if isinstance(v, str):
        return _from_units(v)
    if isinstance(v, list):
        return [_deep_from_units(x) for x in v]
    if isinstance(v, dict):
        return {_from_units(k): _deep_from_units(x) for k, x in v.items()}
    return v


def _jstr(s: str) -> str:
    """`JSON.stringify` of a unit-view string (a lone surrogate is escaped, a pair stays)."""
    out = ['"']
    n = len(s)
    i = 0
    while i < n:
        c = s[i]
        o = ord(c)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif c == "\b":
            out.append("\\b")
        elif c == "\f":
            out.append("\\f")
        elif c == "\n":
            out.append("\\n")
        elif c == "\r":
            out.append("\\r")
        elif c == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        elif 0xD800 <= o <= 0xDBFF and i + 1 < n and 0xDC00 <= ord(s[i + 1]) <= 0xDFFF:
            out.append(c)
            out.append(s[i + 1])
            i += 1
        elif 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        else:
            out.append(c)
        i += 1
    out.append('"')
    return "".join(out)


def _jverb(v: Any) -> str:
    return _jstr(v) if isinstance(v, str) else "[" + ",".join(_jstr(x) for x in v) + "]"


_WS_RUN = re.compile(_S + "+")


def _truncate(s: str) -> str:
    one = _trim(_WS_RUN.sub(" ", s))
    return one[:77] + "..." if len(one) > 80 else one


def _u16key(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def _number(s: str) -> Any:
    """`Number(s)` of a decimal literal as the JSON number the reference serializes."""
    if "." in s:
        return float(s)
    v = int(s)
    return float(v) if abs(v) > 9007199254740991 else v


def _key_order(m: Dict[str, Any]) -> List[str]:
    """JavaScript own-key order: array-index keys ascending, then insertion order."""
    idx = [k for k in m if k.isascii() and k.isdigit() and (k == "0" or k[0] != "0") and len(k) <= 10 and int(k) < 4294967295]
    idx.sort(key=int)
    s = set(idx)
    return idx + [k for k in m if k not in s]


def _entries(o: Any) -> Optional[List[Tuple[str, Any]]]:
    """`Object.entries` of an object or array value; None for anything else."""
    if isinstance(o, dict):
        return [(k, o[k]) for k in _key_order(o)]
    if isinstance(o, list):
        return [(str(i), x) for i, x in enumerate(o)]
    return None


# ---- bracket and quote aware scanning ----------------------------------------------------------------------------------------------


def _index_of_top_level(text: str, token: str) -> int:
    depth = 0
    in_str = False
    for i, ch in enumerate(text):
        if in_str:
            if ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and text.startswith(token, i):
            return i
    return -1


def _split_top_level(text: str, delim: str) -> List[str]:
    out: List[str] = []
    depth = 0
    in_str = False
    start = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_str:
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if depth == 0 and text.startswith(delim, i):
            out.append(text[start:i])
            i += len(delim) - 1
            start = i + 1
        i += 1
    out.append(text[start:])
    return out


def _match_delim(text: str, open_: int, o: str, c: str) -> int:
    depth = 0
    in_str = False
    for i in range(open_, len(text)):
        ch = text[i]
        if in_str:
            if ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == o:
            depth += 1
        elif ch == c:
            depth -= 1
            if depth == 0:
                return i
    return -1


def _new_report(source: str) -> Dict[str, Any]:
    return {"source": source, "translated": [], "skipped": [], "errors": []}


def _result(predicates: List[Any], denies: List[Any], report: Dict[str, Any]) -> Dict[str, Any]:
    return {"predicates": predicates, "denies": denies, "caveats": [], "report": report}


def _trimmed_non_empty(parts: List[str]) -> List[str]:
    return [t for t in (_trim(p) for p in parts) if len(t) > 0]


# ---- Cedar -------------------------------------------------------------------------------------------------------------------------

_ENTITY_PARENTS = "env.entity_parents"


class CedarError(Exception):
    """A construct outside the modeled Cedar subset; the message lands in the report."""


def cedar_to_pca(policy_text: str) -> Dict[str, Any]:
    """Cedar `permit` / `forbid` policies as permit predicates and deny predicates (consume with `decide`)."""
    return translate_cedar(policy_text, True)


def translate_cedar(policy_text: str, error_guards: bool) -> Dict[str, Any]:
    """`error_guards=False` omits the trailing "no attribute was missing" guard (bare structure; not exact)."""
    report = _new_report("cedar")
    predicates: List[Any] = []
    denies: List[Any] = []
    cleaned = re.sub(r"//[^\n]*", "", to_units(policy_text))
    for stmt in _trimmed_non_empty(_split_top_level(cleaned, ";")):
        try:
            _translate_statement(stmt, predicates, denies, report, error_guards)
        except RecursionError:
            report["errors"].append('policy "%s": Maximum call stack size exceeded' % _truncate(stmt))
        except CedarError as e:
            report["errors"].append('policy "%s": %s' % (_truncate(stmt), e))
    return _deep_from_units(_result(predicates, denies, report))


_ANNOT = re.compile(_S + r"*(?:@[A-Za-z_][\w]*" + _S + r"*\([^)]*\)" + _S + r"*)+", _A)
_HEAD = re.compile(_S + r"*(permit|forbid)" + _S + r"*\(", _A | re.IGNORECASE)
_SCOPE = re.compile(r"(principal|action|resource)\b" + _S + r"*(?:(==|in|is)" + _S + r"*)?([\s\S]*)", _A)


def _translate_statement(stmt: str, permits: List[Any], denies: List[Any], report: Dict[str, Any], error_guards: bool) -> None:
    body = stmt
    annot = _ANNOT.match(body)
    if annot:
        body = body[annot.end():]
    head = _HEAD.match(body)
    if not head:
        report["skipped"].append('unrecognized statement: "%s"' % _truncate(stmt))
        return
    effect = "forbid" if head.group(1).lower() == "forbid" else "permit"
    open_idx = body.index("(", head.start())
    close_idx = _match_delim(body, open_idx, "(", ")")
    if close_idx < 0:
        raise CedarError("unterminated scope parentheses")
    scope_text = body[open_idx + 1:close_idx]
    rest = body[close_idx + 1:]
    scope = _parse_scope(scope_text)
    where: List[Any] = list(scope["scopeConditions"])
    guards: List[Any] = []
    for kind, text in _parse_condition_blocks(rest):
        parsed = _parse_expr(text)
        if parsed is None:
            report["skipped"].append('unmodeled %s-condition "%s" \u2014 policy dropped (fail closed)' % (kind, _truncate(text)))
            if effect == "forbid":
                report["errors"].append('forbid could not be fully modeled and was dropped \u2014 treat result as fail-closed: "%s"' % _truncate(stmt))
            return
        where.append(parsed if kind == "when" else {"not": parsed})
        g = _no_error(parsed)
        if g is not None:
            guards.append(g)
    condition_count = len(where)
    if error_guards and guards:
        where.append(guards[0] if len(guards) == 1 else {"all_of": guards})
    predicate: Dict[str, Any] = {"verb": scope["verb"]}
    if scope.get("resource") is not None:
        predicate["resource"] = scope["resource"]
    if where:
        predicate["where"] = where
    on = " on %s" % scope["resource"] if scope.get("resource") else ""
    if effect == "permit":
        permits.append(predicate)
        report["translated"].append("permit \u2192 verb %s%s (%d condition(s))" % (_jverb(scope["verb"]), on, condition_count))
    else:
        denies.append(predicate)
        report["translated"].append("forbid \u2192 deny verb %s%s (%d condition(s))" % (_jverb(scope["verb"]), on, condition_count))


def _parse_scope(scope_text: str) -> Dict[str, Any]:
    clauses = _trimmed_non_empty(_split_top_level(scope_text, ","))
    result: Dict[str, Any] = {"verb": "*", "scopeConditions": []}
    for clause in clauses:
        m = _SCOPE.fullmatch(clause)
        if not m:
            raise CedarError('unparseable scope clause "%s"' % _truncate(clause))
        variable, op, operand = m.group(1), m.group(2), _trim(m.group(3) or "")
        if not op:
            continue
        if variable == "action":
            if op == "==":
                eid = _entity_id(operand)
                if eid is None:
                    raise CedarError('action == expects an Action entity, got "%s"' % _truncate(operand))
                result["verb"] = eid
            elif op == "in" and operand.startswith("["):
                verbs: List[str] = []
                for it in _trimmed_non_empty(_split_top_level(operand[1:-1], ",")):
                    eid = _entity_id(it)
                    if eid is None:
                        raise CedarError('action in [...] expects Action entities, got "%s"' % _truncate(it))
                    verbs.append(eid)
                result["verb"] = verbs
            else:
                raise CedarError('unsupported action scope operator "%s"' % op)
        else:
            field = "action.resource" if variable == "resource" else "subject.id"
            if op == "==":
                uid = _entity_uid(operand)
                if variable == "resource":
                    if uid is None:
                        raise CedarError('resource == expects an entity, got "%s"' % _truncate(operand))
                    result["resource"] = uid
                else:
                    if uid is None:
                        raise CedarError('principal == expects an entity, got "%s"' % _truncate(operand))
                    result["scopeConditions"].append({"field": field, "op": "eq", "value": uid})
            elif op == "is":
                t = _type_name(operand)
                if t is None:
                    raise CedarError('%s is expects a type, got "%s"' % (variable, _truncate(operand)))
                result["scopeConditions"].append({"field": field, "op": "is_a", "value": t})
            else:
                mem = _member_of_condition(field, operand)
                if mem is None:
                    raise CedarError('%s in expects an entity (hierarchy), got "%s"' % (variable, _truncate(operand)))
                result["scopeConditions"].append(mem)
    return result


_BLOCK = re.compile(r"\b(when|unless)\b" + _S + r"*\{", _A)


def _parse_condition_blocks(rest: str) -> List[Tuple[str, str]]:
    blocks: List[Tuple[str, str]] = []
    pos = 0
    while True:
        m = _BLOCK.search(rest, pos)
        if m is None:
            break
        kind = "unless" if m.group(1) == "unless" else "when"
        open_ = rest.index("{", m.start())
        close = _match_delim(rest, open_, "{", "}")
        if close < 0:
            raise CedarError("unterminated %s block" % kind)
        blocks.append((kind, rest[open_ + 1:close]))
        pos = close + 1
    return blocks


def _parse_expr(text: str) -> Optional[Dict[str, Any]]:
    t = _trim(text)
    if len(t) == 0:
        return None
    ors = _trimmed_non_empty(_split_top_level(t, "||"))
    if len(ors) > 1:
        subs = [_parse_expr(s) for s in ors]
        if any(s is None for s in subs):
            return None
        return {"any_of": subs}
    ands = _trimmed_non_empty(_split_top_level(t, "&&"))
    if len(ands) > 1:
        subs = [_parse_expr(s) for s in ands]
        if any(s is None for s in subs):
            return None
        return {"all_of": subs}
    if t.startswith("(") and _match_delim(t, 0, "(", ")") == len(t) - 1:
        return _parse_expr(t[1:-1])
    return _parse_atom(t)


_CMP_TOKENS = (("==", "eq"), ("!=", "ne"), ("<=", "lte"), (">=", "gte"), ("<", "lt"), (">", "gt"))
_WORD_OP = re.compile(r"([\s\S]*?" + "[^" + _WS + "]" + r")" + _S + r"+(in|is|like|has)" + _S + r"+([\s\S]+)", _A)


def _parse_atom(text: str) -> Optional[Dict[str, Any]]:
    t = _trim(text)
    for tok, op in _CMP_TOKENS:
        idx = _index_of_top_level(t, tok)
        if idx >= 0:
            return _build_comparison(_trim(t[:idx]), op, _trim(t[idx + len(tok):]))
    wm = _WORD_OP.fullmatch(t)
    if wm:
        return _build_word_op(_trim(wm.group(1)), wm.group(2), _trim(wm.group(3)))
    return None


def _build_comparison(lhs_raw: str, op: str, rhs_raw: str) -> Optional[Dict[str, Any]]:
    field = _to_field_path(lhs_raw)
    if field is None:
        return None
    if field == "action.verb":
        if op != "eq" and op != "ne":
            return None
        eid = _entity_id(rhs_raw)
        return None if eid is None else {"field": field, "op": op, "value": eid}
    if _is_path_expr(rhs_raw):
        ref = _to_field_path(rhs_raw)
        if ref is not None:
            return {"field": field, "op": op, "ref": ref}
    ok, value = _to_literal(rhs_raw)
    if not ok:
        return None
    return {"field": field, "op": op, "value": value}


_IDENT = re.compile(r"[A-Za-z_]\w*", _A)


def _build_word_op(lhs_raw: str, kind: str, rhs_raw: str) -> Optional[Dict[str, Any]]:
    if kind == "has":
        if not _IDENT.fullmatch(rhs_raw):
            return None
        field = _to_field_path("%s.%s" % (lhs_raw, rhs_raw))
        return None if field is None else {"field": field, "op": "exists"}
    field = _to_field_path(lhs_raw)
    if field is None:
        return None
    if field == "action.verb":
        if kind != "in":
            return None
        inner = rhs_raw[1:-1] if rhs_raw.startswith("[") and rhs_raw.endswith("]") else rhs_raw
        ids = [_entity_id(x) for x in _trimmed_non_empty(_split_top_level(inner, ","))]
        return {"field": field, "op": "in", "value": ids} if ids and all(i is not None for i in ids) else None
    if kind == "is":
        t = _type_name(rhs_raw)
        return None if t is None else {"field": field, "op": "is_a", "value": t}
    if kind == "like":
        sm = re.fullmatch(r'"([\s\S]*)"', rhs_raw)
        if not sm:
            return None
        return {"field": field, "op": "like", "value": _cedar_like_to_glob(sm.group(1))}
    if rhs_raw.startswith("["):
        inner = rhs_raw[1:-1] if rhs_raw.endswith("]") else rhs_raw[1:]
        items = _trimmed_non_empty(_split_top_level(inner, ","))
        if items and all(_entity_uid(it) is not None for it in items):
            return {"field": field, "op": "member_of", "value": [_entity_uid(it) for it in items], "collection": _ENTITY_PARENTS}
        values: List[Any] = []
        for it in items:
            ok, v = _to_literal(it)
            if not ok:
                return None
            values.append(v)
        return {"field": field, "op": "in", "value": values}
    return _member_of_condition(field, rhs_raw)


def _member_of_condition(field: str, operand: str) -> Optional[Dict[str, Any]]:
    uid = _entity_uid(operand)
    if uid is not None:
        return {"field": field, "op": "member_of", "value": uid, "collection": _ENTITY_PARENTS}
    if _is_path_expr(operand):
        ref = _to_field_path(operand)
        if ref is not None:
            return {"field": field, "op": "member_of", "ref": ref, "collection": _ENTITY_PARENTS}
    return None


_PATH_HEAD = re.compile(r"(principal|resource|action|context)\b", _A)


def _is_path_expr(expr: str) -> bool:
    return _PATH_HEAD.match(expr) is not None


_P_PRINCIPAL = re.compile(r"principal\.([A-Za-z_][\w.]*)", _A)
_P_RESOURCE = re.compile(r"resource\.([A-Za-z_][\w.]*)", _A)
_P_CONTEXT = re.compile(r"context\.([A-Za-z_][\w.]*)", _A)


def _to_field_path(expr: str) -> Optional[str]:
    if expr == "principal":
        return "subject.id"
    if expr == "resource":
        return "action.resource"
    if expr == "action":
        return "action.verb"
    if expr == "context":
        return "env"
    m = _P_PRINCIPAL.fullmatch(expr)
    if m:
        return "subject." + m.group(1)
    m = _P_RESOURCE.fullmatch(expr)
    if m:
        return "env.resource." + m.group(1)
    m = _P_CONTEXT.fullmatch(expr)
    if m:
        return "env." + m.group(1)
    return None


_TYPE_NAME = re.compile(r"[A-Za-z_]\w*(::[A-Za-z_]\w*)*", _A)
_ENTITY_ID = re.compile(_DOT + r'+::"([^"]*)"')
_ENTITY_UID = re.compile("(" + _DOT + r'+)::"([^"]*)"')
_STR_LIT = re.compile(r'"([^"]*)"')
_NUM_LIT = re.compile(r"-?\d+(\.\d+)?", _A)


def _type_name(expr: str) -> Optional[str]:
    s = _trim(expr)
    return s if _TYPE_NAME.fullmatch(s) else None


def _entity_id(expr: str) -> Optional[str]:
    m = _ENTITY_ID.fullmatch(_trim(expr))
    return m.group(1) if m else None


def _entity_uid(expr: str) -> Optional[str]:
    m = _ENTITY_UID.fullmatch(_trim(expr))
    return "%s::%s" % (m.group(1), m.group(2)) if m else None


def _to_literal(expr: str) -> Tuple[bool, Any]:
    s = _trim(expr)
    m = _STR_LIT.fullmatch(s)
    if m:
        return True, m.group(1)
    if s == "true":
        return True, True
    if s == "false":
        return True, False
    if _NUM_LIT.fullmatch(s):
        return True, _number(s)
    uid = _entity_uid(s)
    if uid is not None:
        return True, uid
    return False, None


def _escape_glob_literal(ch: str) -> str:
    return "\\" + ch if ch in "*?\\" else ch


def _cedar_like_to_glob(inner: str) -> str:
    out: List[str] = []
    i = 0
    n = len(inner)
    while i < n:
        ch = inner[i]
        if ch == "\\":
            nxt = inner[i + 1] if i + 1 < n else None
            if nxt == "*":
                out.append("\\*")
                i += 2
                continue
            if nxt is not None:
                out.append(_escape_glob_literal(nxt))
                i += 2
                continue
            out.append("\\\\")
            i += 1
            continue
        out.append("*" if ch == "*" else _escape_glob_literal(ch))
        i += 1
    return "".join(out)


# --- Cedar evaluation-error semantics: the guard that makes a policy apply only when no absent attribute is read -----------------------

_TOTAL_FIELDS = ("subject.id", "action.verb", "action.resource", "env")


def _guarded_paths(field: Optional[str]) -> List[str]:
    if field is None or field in _TOTAL_FIELDS or field.startswith("env.entity_parents"):
        return []
    return [field] if field.startswith("subject.") or field.startswith("env.") else []


def _exists(field: str) -> Dict[str, Any]:
    return {"field": field, "op": "exists"}


def _all_of(xs: List[Any]) -> Any:
    return xs[0] if len(xs) == 1 else {"all_of": xs}


def _any_of(xs: List[Any]) -> Any:
    return xs[0] if len(xs) == 1 else {"any_of": xs}


def _no_error(c: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """"Evaluating this expression raises no Cedar error", as a condition (None = it cannot)."""
    if "not" in c:
        return _no_error(c["not"])
    if "all_of" in c or "any_of" in c:
        is_and = "all_of" in c
        kids = c["all_of"] if is_and else c["any_of"]
        acc: Optional[Dict[str, Any]] = None
        for kid in reversed(kids):
            n = _no_error(kid)
            cont = None if acc is None else _any_of([{"not": kid} if is_and else kid, acc])
            acc = cont if n is None else n if cont is None else _all_of([n, cont])
        return acc
    field = c.get("field")
    if c.get("op") == "exists" and field is not None:
        base = re.sub(r"\.[^.]+\Z", "", field)
        deep = len(base.split(".")) >= (3 if base.startswith("env.resource") else 2)
        base_needs = [_exists(p) for p in _guarded_paths(base)] if deep else []
        return None if not base_needs else _all_of(base_needs)
    needs = [_exists(p) for p in _guarded_paths(field) + _guarded_paths(c.get("ref"))]
    return None if not needs else _all_of(needs)


# ---- Rego --------------------------------------------------------------------------------------------------------------------------

_PKG = re.compile(r"\bpackage" + _S + r"+([A-Za-z_][\w.]*)", _A)
_DEFAULT = re.compile(r"\bdefault" + _S + r"+allow" + _S + r"*(?::?=)" + _S + r"*(true|false)\b", _A)
_ALLOW = re.compile(r"\ballow\b" + _S + r"*(?:(?::?=" + _S + r"*true\b|=" + _S + r"*true\b|\bif\b)" + _S + r"*)?\{", _A)
_NOT = re.compile(r"not" + _S + r"+([\s\S]+)", _A)
_UNMODELED_A = re.compile(r":=|\bsome\b|\bevery\b|\[" + _DOT + r"*\|" + _DOT + r"*\]", _A)
_UNMODELED_IDX = re.compile(r"\binput\.[\w.]*\[", _A)
_REGO_CMP = re.compile(r"(input\.[\w.]+)" + _S + r"*(==|!=|<=|>=|<|>|\bin\b)" + _S + r"*([\s\S]+)", _A)
_INPUT_PATH = re.compile(r"input\.[\w.]+", _A)
_STARTSWITH = re.compile(r"startswith\(" + _S + r"*(input\.[\w.]+)" + _S + r'*,' + _S + r'*"([^"]*)"' + _S + r"*\)", _A)
_GLOB = re.compile(r'glob\.match\(' + _S + r'*"([^"]*)"' + _S + r"*," + _S + r"*(\[" + _S + r"*\]|null)" + _S + r"*," + _S + r"*(input\.[\w.]+)" + _S + r"*\)", _A)
_REGO_STR = re.compile(r'"([^"]*)"', re.S)


def rego_to_pca(module_text: str) -> Dict[str, Any]:
    """OPA / Rego `allow` rules (a conjunction of input comparisons per rule) as permit predicates; anything else drops its rule."""
    report = _new_report("rego")
    predicates: List[Any] = []
    src = re.sub(r"#[^\n]*", "", to_units(module_text))
    pkg = _PKG.search(src)
    if pkg:
        report["translated"].append("package %s" % pkg.group(1))
    d = _DEFAULT.search(src)
    if d and d.group(1) == "true":
        report["skipped"].append("`default allow = true` is not modeled (cannot express allow-unless); treated as default-deny")
    elif not d:
        report["skipped"].append("no `default allow = false` found; assuming default-deny")
    for body in _extract_allow_bodies(src, report):
        _translate_rule(body, predicates, report)
    return _deep_from_units(_result(predicates, [], report))


def _extract_allow_bodies(src: str, report: Dict[str, Any]) -> List[str]:
    bodies: List[str] = []
    pos = 0
    while True:
        m = _ALLOW.search(src, pos)
        if m is None:
            break
        open_ = src.index("{", m.start())
        close = _match_delim(src, open_, "{", "}")
        if close < 0:
            report["errors"].append("unterminated `allow { ... }` block")
            break
        bodies.append(src[open_ + 1:close])
        pos = close + 1
    return bodies


def _translate_rule(body: str, predicates: List[Any], report: Dict[str, Any]) -> None:
    statements = [t for t in (_trim(s) for s in re.split(r"[\n;]", body)) if len(t) > 0]
    verb: Any = "*"
    resource: Optional[str] = None
    where: List[Any] = []
    for stmt in statements:
        parsed = _parse_statement(stmt)
        kind = parsed[0]
        if kind == "unmodeled":
            report["skipped"].append('unmodeled statement "%s" \u2014 rule dropped (fail closed)' % _truncate(stmt))
            return
        if kind == "verb":
            if isinstance(verb, str) and verb == "*":
                verb = parsed[1]
            else:
                have = verb if isinstance(verb, list) else [verb]
                nxt = parsed[1] if isinstance(parsed[1], list) else [parsed[1]]
                both = [v for v in have if v in nxt]
                if not both:
                    report["translated"].append("rule can never match (contradictory action selectors), nothing emitted")
                    return
                verb = both[0] if len(both) == 1 else both
        elif kind == "resource":
            if resource is not None and resource != parsed[1]:
                report["translated"].append("rule can never match (contradictory resource selectors), nothing emitted")
                return
            resource = parsed[1]
        else:
            where.append(parsed[1])
    predicate: Dict[str, Any] = {"verb": verb}
    if resource is not None:
        predicate["resource"] = resource
    if where:
        predicate["where"] = where
    predicates.append(predicate)
    report["translated"].append("allow \u2192 verb %s%s (%d condition(s))" % (_jverb(verb), " on %s" % resource if resource else "", len(where)))


_UNMODELED: Tuple[str, Any] = ("unmodeled", None)


def _parse_statement(stmt: str) -> Tuple[str, Any]:
    s = _trim(stmt)
    nm = _NOT.fullmatch(s)
    if nm:
        inner = _parse_statement(_trim(nm.group(1)))
        if inner[0] != "condition":
            return _UNMODELED
        c = inner[1]
        if c.get("op") == "eq" and isinstance(c.get("field"), str):
            needs = [{"field": f, "op": "exists"} for f in [c["field"]] + ([c["ref"]] if isinstance(c.get("ref"), str) else [])]
            return ("condition", {"not": {"all_of": needs + [c]}})
        return ("condition", {"not": c})
    builtin = _parse_builtin(s)
    if builtin is not None:
        return builtin
    if _UNMODELED_A.search(s):
        return _UNMODELED
    if "(" in s:
        return _UNMODELED
    if _UNMODELED_IDX.search(s):
        return _UNMODELED
    m = _REGO_CMP.fullmatch(s)
    if not m:
        return _UNMODELED
    path, op_tok, rhs_raw = m.group(1), m.group(2), _trim(m.group(3))
    sub = path[len("input."):]
    if op_tok == "in":
        ok, values = _parse_set_literal(rhs_raw)
        if not ok:
            return _UNMODELED
        if sub == "action":
            verbs = [v for v in values if isinstance(v, str)]
            if len(verbs) != len(values):
                return _UNMODELED
            return ("verb", verbs)
        return ("condition", {"field": "env." + sub, "op": "in", "value": values})
    if (op_tok == "==" or op_tok == "!=") and _INPUT_PATH.fullmatch(rhs_raw):
        return ("condition", {"field": "env." + sub, "op": "ne" if op_tok == "!=" else "eq", "ref": "env." + rhs_raw[len("input."):]})
    ok, value = _rego_literal(rhs_raw)
    if not ok:
        return _UNMODELED
    if op_tok == "==":
        if sub == "action" and isinstance(value, str):
            return ("verb", value)
        if sub == "resource" and isinstance(value, str):
            return ("resource", value)
        return ("condition", {"field": "env." + sub, "op": "eq", "value": value})
    if op_tok == "!=":
        return ("condition", {"field": "env." + sub, "op": "ne", "value": value})
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return _UNMODELED
    cmp_ = "lt" if op_tok == "<" else "lte" if op_tok == "<=" else "gt" if op_tok == ">" else "gte"
    return ("condition", {"field": "env." + sub, "op": cmp_, "value": value})


def _parse_builtin(s: str) -> Optional[Tuple[str, Any]]:
    sw = _STARTSWITH.fullmatch(s)
    if sw:
        return ("condition", {"field": "env." + sw.group(1)[len("input."):], "op": "prefix", "value": sw.group(2)})
    gm = _GLOB.fullmatch(s)
    if gm:
        pattern = gm.group(1)
        if re.search(r"[\[\]{}]", pattern):
            return _UNMODELED
        if gm.group(2).startswith("[") and re.search(r"[*?\\]", pattern):
            return _UNMODELED
        return ("condition", {"field": "env." + gm.group(3)[len("input."):], "op": "like", "value": pattern})
    return None


def _rego_literal(expr: str) -> Tuple[bool, Any]:
    s = _trim(expr)
    m = _REGO_STR.fullmatch(s)
    if m:
        return True, m.group(1)
    if s == "true":
        return True, True
    if s == "false":
        return True, False
    if _NUM_LIT.fullmatch(s):
        return True, _number(s)
    return False, None


def _parse_set_literal(expr: str) -> Tuple[bool, List[Any]]:
    s = _trim(expr)
    is_set = s.startswith("{") and s.endswith("}")
    is_arr = s.startswith("[") and s.endswith("]")
    if not is_set and not is_arr:
        return False, []
    values: List[Any] = []
    for it in _trimmed_non_empty(_split_top_level(s[1:-1], ",")):
        ok, v = _rego_literal(it)
        if not ok:
            return False, []
        values.append(v)
    return True, values


# ---- OpenFGA -----------------------------------------------------------------------------------------------------------------------

_MAX_DEPTH = 32
_MISSING = object()


def openfga_to_pca(model: Any, tuples: Any = _MISSING) -> Dict[str, Any]:
    """An OpenFGA / Zanzibar model plus relationship tuples as one permit per (user, object, relation) triple that holds
    (`this`, computedUserset, union, intersection, difference, tupleToUserset; bounded and cycle-guarded)."""
    report = _new_report("openfga")
    predicates: List[Any] = []
    type_relations = _parse_model(model, report)
    tuple_list = _parse_tuples(tuples, report)
    if type_relations is None:
        return _result(predicates, [], report)

    direct: Dict[str, Dict[str, None]] = {}
    users_seen: Dict[str, None] = {}
    wildcard_types: Dict[str, None] = {}
    objects_seen: Dict[str, None] = {}
    userset_tuples = 0
    for t in tuple_list:
        objects_seen[t["object"]] = None
        direct.setdefault("%s\u0000%s" % (t["object"], t["relation"]), {})[t["user"]] = None
        if "#" in t["user"]:
            userset_tuples += 1
        elif _is_wildcard(t["user"]):
            wildcard_types[t["user"][:-2]] = None
        else:
            users_seen[t["user"]] = None
    if userset_tuples > 0:
        report["skipped"].append("%d userset-valued tuple(s) (user contains '#') not expanded to concrete users" % userset_tuples)

    plans: Dict[str, Dict[str, Any]] = {}
    for type_, relations in type_relations.items():
        for relation, node in relations.items():
            built = _build_plan(node)
            if not built["ok"] or "plan" not in built:
                report["skipped"].append("relation %s#%s: %s \u2014 skipped" % (type_, relation, built.get("reason", "unsupported rewrite")))
                continue
            if built["partial"]:
                report["skipped"].append("relation %s#%s: some union children unsupported and dropped (under-approximated)" % (type_, relation))
            plans["%s\u0000%s" % (type_, relation)] = built["plan"]
            report["translated"].append("relation %s#%s (%s)" % (type_, relation, _describe_plan(built["plan"])))

    def type_of(obj: str) -> str:
        i = obj.find(":")
        return obj if i < 0 else obj[:i]

    def object_of_userset(p: str) -> str:
        i = p.find("#")
        return p if i < 0 else p[:i]

    def holds_rel(user: str, obj: str, relation: str, depth: int, visited: frozenset) -> bool:
        key = "%s\u0000%s" % (obj, relation)
        if depth > _MAX_DEPTH or key in visited:
            return False
        plan = plans.get("%s\u0000%s" % (type_of(obj), relation))
        if plan is None:
            return False
        return eval_plan(user, obj, relation, plan, depth, visited | {key})

    def eval_plan(user: str, obj: str, relation: str, plan: Dict[str, Any], depth: int, visited: frozenset) -> bool:
        kind = plan["kind"]
        if kind == "direct":
            s = direct.get("%s\u0000%s" % (obj, relation))
            return s is not None and (user in s or ("%s:*" % type_of(user)) in s)
        if kind == "computed":
            return holds_rel(user, obj, plan["relation"], depth + 1, visited)
        if kind == "union":
            return any(eval_plan(user, obj, relation, c, depth, visited) for c in plan["children"])
        if kind == "intersection":
            return all(eval_plan(user, obj, relation, c, depth, visited) for c in plan["children"])
        if kind == "difference":
            return eval_plan(user, obj, relation, plan["base"], depth, visited) and not eval_plan(user, obj, relation, plan["subtract"], depth, visited)
        related = direct.get("%s\u0000%s" % (obj, plan["tupleset"]))
        if related is None:
            return False
        return any(holds_rel(user, object_of_userset(p), plan["computed"], depth + 1, visited) for p in related)

    sorted_users = sorted(users_seen, key=_u16key)
    for obj in sorted(objects_seen, key=_u16key):
        type_ = type_of(obj)
        relations = type_relations.get(type_)
        if relations is None:
            report["skipped"].append('object %s: type "%s" not defined in model \u2014 ignored' % (obj, type_))
            continue
        for relation in sorted(relations, key=_u16key):
            if "%s\u0000%s" % (type_, relation) not in plans:
                continue
            for user in sorted_users:
                if holds_rel(user, obj, relation, 0, frozenset()):
                    predicates.append({"verb": relation, "resource": obj, "where": [{"field": "subject.id", "op": "eq", "value": user}]})
            # a public tuple (`type:*`) grants every subject of that type, including ones no tuple names
            for wtype in sorted(wildcard_types, key=_u16key):
                if not holds_rel("%s:\u0000anyone" % wtype, obj, relation, 0, frozenset()):
                    continue
                named = [u for u in sorted_users if type_of(u) == wtype]
                where: List[Any] = [{"field": "subject.id", "op": "like", "value": "%s:*" % _escape_glob(wtype)}]
                if named:
                    where.append({"not": {"field": "subject.id", "op": "in", "value": named}})
                predicates.append({"verb": relation, "resource": obj, "where": where})
    return _result(predicates, [], report)


def _is_wildcard(user: str) -> bool:
    return user.endswith(":*") and len(to_units(user)) > 2 and "#" not in user


def _escape_glob(t: str) -> str:
    return re.sub(r"[*?\\]", lambda m: "\\" + m.group(0), t)


def _describe_plan(plan: Dict[str, Any]) -> str:
    k = plan["kind"]
    if k == "direct":
        return "direct"
    if k == "computed":
        return "computed %s" % plan["relation"]
    if k == "union":
        return "union[%s]" % ", ".join(_describe_plan(c) for c in plan["children"])
    if k == "intersection":
        return "intersection[%s]" % ", ".join(_describe_plan(c) for c in plan["children"])
    if k == "difference":
        return "difference(%s - %s)" % (_describe_plan(plan["base"]), _describe_plan(plan["subtract"]))
    return "%s from %s" % (plan["computed"], plan["tupleset"])


def _is_rewrite(v: Any) -> bool:
    return isinstance(v, (dict, list))


def _has_own(o: Any, k: str) -> bool:
    return isinstance(o, dict) and k in o


def _child_nodes(container: Any) -> Optional[List[Any]]:
    if not isinstance(container, (dict, list)):
        return None
    child = container.get("child") if isinstance(container, dict) else None
    return child if isinstance(child, list) else None


def _relation_of(v: Any) -> Optional[str]:
    if not isinstance(v, (dict, list)):
        return None
    rel = v.get("relation") if isinstance(v, dict) else None
    return rel if isinstance(rel, str) and len(rel) > 0 else None


def _build_plan(node: Any) -> Dict[str, Any]:
    if _has_own(node, "this"):
        return {"ok": True, "plan": {"kind": "direct"}, "partial": False}
    if _has_own(node, "computedUserset"):
        cu = node["computedUserset"]
        rel = cu.get("relation") if isinstance(cu, dict) else None
        if not isinstance(rel, str) or len(rel) == 0:
            return {"ok": False, "partial": False, "reason": "computedUserset without a relation"}
        return {"ok": True, "plan": {"kind": "computed", "relation": rel}, "partial": False}
    if _has_own(node, "union"):
        children = _child_nodes(node["union"])
        if children is None:
            return {"ok": False, "partial": False, "reason": "union without children"}
        subs: List[Any] = []
        partial = False
        for child in children:
            if not _is_rewrite(child):
                partial = True
                continue
            sub = _build_plan(child)
            if not sub["ok"] or "plan" not in sub:
                partial = True  # OR under-approximates safely: drop the unmodeled child
                continue
            if sub["partial"]:
                partial = True
            subs.append(sub["plan"])
        if not subs:
            return {"ok": False, "partial": partial, "reason": "union with no modeled children"}
        return {"ok": True, "plan": {"kind": "union", "children": subs}, "partial": partial}
    if _has_own(node, "intersection"):
        children = _child_nodes(node["intersection"])
        if children is None:
            return {"ok": False, "partial": False, "reason": "intersection without children"}
        subs = []
        for child in children:
            if not _is_rewrite(child):
                return {"ok": False, "partial": False, "reason": "intersection child is not a rewrite"}
            sub = _build_plan(child)
            if not sub["ok"] or "plan" not in sub:
                return {"ok": False, "partial": False, "reason": "intersection child unmodeled (%s)" % sub.get("reason", "unsupported")}
            subs.append(sub["plan"])
        if not subs:
            return {"ok": False, "partial": False, "reason": "intersection with no children"}
        return {"ok": True, "plan": {"kind": "intersection", "children": subs}, "partial": False}
    if _has_own(node, "difference"):
        diff = node["difference"]
        if not isinstance(diff, (dict, list)):
            return {"ok": False, "partial": False, "reason": "malformed difference"}
        base_node = diff.get("base") if isinstance(diff, dict) else None
        sub_node = diff.get("subtract") if isinstance(diff, dict) else None
        if not _is_rewrite(base_node) or not _is_rewrite(sub_node):
            return {"ok": False, "partial": False, "reason": "difference needs both base and subtract"}
        base = _build_plan(base_node)
        subtract = _build_plan(sub_node)
        if not base["ok"] or "plan" not in base:
            return {"ok": False, "partial": False, "reason": "difference base unmodeled (%s)" % base.get("reason", "?")}
        if not subtract["ok"] or "plan" not in subtract:
            return {"ok": False, "partial": False, "reason": "difference subtract unmodeled (%s)" % subtract.get("reason", "?")}
        return {"ok": True, "plan": {"kind": "difference", "base": base["plan"], "subtract": subtract["plan"]}, "partial": base["partial"] or subtract["partial"]}
    if _has_own(node, "tupleToUserset"):
        ttu = node["tupleToUserset"]
        if not isinstance(ttu, (dict, list)):
            return {"ok": False, "partial": False, "reason": "malformed tupleToUserset"}
        tupleset_rel = _relation_of(ttu.get("tupleset") if isinstance(ttu, dict) else None)
        computed_rel = _relation_of(ttu.get("computedUserset") if isinstance(ttu, dict) else None)
        if tupleset_rel is None:
            return {"ok": False, "partial": False, "reason": "tupleToUserset without a tupleset relation"}
        if computed_rel is None:
            return {"ok": False, "partial": False, "reason": "tupleToUserset without a computedUserset relation"}
        return {"ok": True, "plan": {"kind": "ttu", "tupleset": tupleset_rel, "computed": computed_rel}, "partial": False}
    return {"ok": False, "partial": False, "reason": "unknown rewrite node"}


def _parse_model(model: Any, report: Dict[str, Any]) -> Optional[Dict[str, Dict[str, Any]]]:
    if not isinstance(model, (dict, list)):
        report["errors"].append("model is not an object")
        return None
    defs = model.get("type_definitions") if isinstance(model, dict) else None
    if not isinstance(defs, list):
        report["errors"].append("model.type_definitions is missing or not an array")
        return None
    out: Dict[str, Dict[str, Any]] = {}
    for d in defs:
        if not isinstance(d, (dict, list)):
            continue
        t = d.get("type") if isinstance(d, dict) else None
        if not isinstance(t, str) or len(t) == 0:
            continue
        rels = d.get("relations") if isinstance(d, dict) else None
        rel_map: Dict[str, Any] = {}
        entries = _entries(rels)
        if entries is not None:
            for name, node in entries:
                if _is_rewrite(node):
                    rel_map[name] = node
        out[t] = rel_map
    return out


def _parse_tuples(tuples: Any, report: Dict[str, Any]) -> List[Dict[str, str]]:
    if not isinstance(tuples, list):
        if tuples is not _MISSING:
            report["errors"].append("tuples is not an array")
        return []
    out: List[Dict[str, str]] = []
    for t in tuples:
        if not isinstance(t, dict):
            continue
        user, relation, obj = t.get("user"), t.get("relation"), t.get("object")
        if isinstance(user, str) and isinstance(relation, str) and isinstance(obj, str):
            out.append({"user": user, "relation": relation, "object": obj})
    return out


# ---- decide ------------------------------------------------------------------------------------------------------------------------


def _length(x: Any) -> Any:
    if x is None:
        raise TypeError("cannot read properties of null (reading 'length')")
    return len(x) if isinstance(x, (list, str)) else None


def decide(result: Any, ctx: Any) -> Dict[str, Any]:
    """One action under a translation with deny-overrides-permit (Cedar's combining rule), built on the core evaluator. An
    incomplete translation (`report.errors` non-empty) denies everything."""
    report = result.get("report") if isinstance(result, dict) else None
    if report is not None and report is not False and report != 0 and report != "":
        n = _length(report["errors"] if isinstance(report, dict) else None)
        if n is not None and n > 0:
            return {"allowed": False, "reason": "translation incomplete (fail closed)"}
    denies = result["denies"]
    n = _length(denies)
    if n is not None and n > 0:
        denied = evaluate_predicates(denies, ctx)
        if denied["allowed"]:
            return {"allowed": False, "matched": denied["matched"], "reason": "forbidden by deny policy"}
    return evaluate_predicates(result["predicates"], ctx)


# ---- strict CEL --------------------------------------------------------------------------------------------------------------------

_MAX_EXPR = 4096
_CEL_MAX_DEPTH = 32
_MAX_NODES = 256
_MAX_LIST = 64
_MAX_STR = 256
_CEL_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")
_PCA_PATH = re.compile(r"(action|subject|env)(\.[A-Za-z_][A-Za-z0-9_]*)+")
_FORBIDDEN = ("__proto__", "constructor", "prototype")
_PUNCT = ("&&", "||", "==", "!=", "<=", ">=", "<", ">", "!", "(", ")", "[", "]", ",", ".", "-")
_UNSUPPORTED_CH = {
    "+": "arithmetic (+)", "*": "arithmetic (*)", "/": "arithmetic (/)", "%": "arithmetic (%)", "?": "the conditional operator",
    ":": "the conditional operator / map literal", "{": "map or message literal", "}": "map or message literal", "@": "@", "&": "bitwise &",
    "|": "bitwise |", "^": "^", "~": "~", "=": "assignment", "`": "quoted identifier",
}
_RELOPS = ("==", "!=", "<", "<=", ">", ">=")
_REJECTED_FUNCS = frozenset((
    "size matches exists all exists_one map filter int uint double string bytes bool duration type dyn min max getHours getDayOfWeek "
    "getMinutes getSeconds getFullYear getMonth getDate getDayOfMonth getDayOfYear getMilliseconds extract format lowerAscii upperAscii "
    "trim split join replace substring indexOf lastIndexOf charAt isIpv4 inIpRange cidr ip isCIDR containsIp url quantity semver optional"
).split())
_ESCAPES = {"\\": "\\", '"': '"', "'": "'", "n": "\n", "t": "\t", "r": "\r"}
_TS = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?Z", _A)


class _Reject(Exception):
    def __init__(self, code: str, message: str, at: int) -> None:
        super().__init__(message)
        self.code, self.message, self.at = code, message, at


def _rej(code: str, message: str, at: int) -> Any:
    raise _Reject(code, message, at)


def _is_letter(c: str) -> bool:
    return ("A" <= c <= "Z") or ("a" <= c <= "z") or c == "_"


def _is_digit(c: str) -> bool:
    return "0" <= c <= "9"


def _lex(src: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    n = len(src)
    i = 0
    while i < n:
        c = src[i]
        if c in " \t\n\r":
            i += 1
            continue
        if c == "/" and src[i + 1:i + 2] == "/":
            _rej("unsupported", "comments", i)
        if _is_letter(c):
            j = i + 1
            while j < n and (_is_letter(src[j]) or _is_digit(src[j])):
                j += 1
            w = src[i:j]
            if w in ("r", "b", "R", "B") and src[j:j + 1] in ('"', "'"):
                _rej("unsupported", "%s literal" % ("raw string" if w.lower() == "r" else "bytes"), i)
            out.append({"k": "id", "v": w, "at": i})
            i = j
            continue
        if _is_digit(c):
            j = i
            while j < n and _is_digit(src[j]):
                j += 1
            nxt = src[j:j + 1]
            if nxt == "." and _is_digit(src[j + 1:j + 2] or ""):
                _rej("unsupported", "double literal", i)
            if nxt in ("e", "E"):
                _rej("unsupported", "double literal", i)
            if nxt in ("u", "U"):
                _rej("unsupported", "unsigned integer literal", i)
            if nxt in ("x", "X"):
                _rej("unsupported", "hexadecimal literal", i)
            w = src[i:j]
            if len(w) > 1 and w[0] == "0":
                _rej("unsupported", "integer literal with a leading zero", i)
            out.append({"k": "int", "v": w, "at": i})
            i = j
            continue
        if c == '"' or c == "'":
            if src.startswith(c * 3, i):
                _rej("unsupported", "triple-quoted string", i)
            j = i + 1
            parts: List[str] = []
            while True:
                d = src[j:j + 1]
                if d == "" or d == "\n" or d == "\r":
                    _rej("syntax", "unterminated string", i)
                if d == c:
                    break
                if d == "\\":
                    e = src[j + 1:j + 2]
                    if e == "" or e not in _ESCAPES:
                        _rej("unsupported", "string escape \\%s" % e, j)
                    parts.append(_ESCAPES[e])
                    j += 2
                    continue
                parts.append(d)
                j += 1
            s = "".join(parts)
            if len(s) > _MAX_STR:
                _rej("too_complex", "string literal longer than %d" % _MAX_STR, i)
            out.append({"k": "str", "v": s, "at": i})
            i = j + 1
            continue
        p = next((x for x in _PUNCT if src.startswith(x, i)), None)
        if p is None:
            _rej("unsupported" if c in _UNSUPPORTED_CH else "syntax", _UNSUPPORTED_CH.get(c, "unexpected character '%s'" % c), i)
        out.append({"k": "p", "v": p, "at": i})
        i += len(p)
    return out


def _days_from_civil(y: int, m: int, d: int) -> int:
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _parse_timestamp(s: str, at: int) -> int:
    m = _TS.fullmatch(s)
    if not m:
        _rej("unsupported", "timestamp() argument must be RFC 3339 UTC (Z) with at most millisecond precision", at)
    date, time = m.group(1).split("T")
    y, mo, d = (int(x) for x in date.split("-"))
    h, mi, sec = (int(x) for x in time.split(":"))
    ms = int((m.group(2) or "").ljust(3, "0"))
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    dim = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    if not (1 <= mo <= 12 and 1 <= d <= dim[mo - 1] and h <= 23 and mi <= 59 and sec <= 59):
        _rej("unsupported", "timestamp() is not a real instant", at)
    return (((_days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60 + sec) * 1000 + ms


def _parse(src: Any) -> Dict[str, Any]:
    if not isinstance(src, str) or len(src) == 0:
        _rej("syntax", "empty expression", 0)
    if len(src) > _MAX_EXPR:
        _rej("too_complex", "expression longer than %d characters" % _MAX_EXPR, 0)
    toks = _lex(src)
    st = {"pos": 0, "nodes": 0}

    def peek() -> Optional[Dict[str, Any]]:
        return toks[st["pos"]] if st["pos"] < len(toks) else None

    def is_p(v: str) -> bool:
        t = peek()
        return t is not None and t["k"] == "p" and t["v"] == v

    def eat(v: str) -> bool:
        if is_p(v):
            st["pos"] += 1
            return True
        return False

    def need(v: str) -> None:
        if not eat(v):
            t = peek()
            _rej("syntax", "expected '%s'" % v, t["at"] if t else len(src))

    def tick(at: int) -> None:
        st["nodes"] += 1
        if st["nodes"] > _MAX_NODES:
            _rej("too_complex", "more than %d nodes" % _MAX_NODES, at)

    def expr(d: int) -> Dict[str, Any]:
        if d > _CEL_MAX_DEPTH:
            t = peek()
            _rej("too_complex", "nesting deeper than %d" % _CEL_MAX_DEPTH, t["at"] if t else 0)
        return or_(d)

    def or_(d: int) -> Dict[str, Any]:
        left = and_(d)
        while is_p("||"):
            at = peek()["at"]  # type: ignore[index]
            st["pos"] += 1
            tick(at)
            left = {"t": "or", "l": left, "r": and_(d), "at": at}
        return left

    def and_(d: int) -> Dict[str, Any]:
        left = rel(d)
        while is_p("&&"):
            at = peek()["at"]  # type: ignore[index]
            st["pos"] += 1
            tick(at)
            left = {"t": "and", "l": left, "r": rel(d), "at": at}
        return left

    def is_relop(t: Dict[str, Any]) -> bool:
        return (t["k"] == "p" and t["v"] in _RELOPS) or (t["k"] == "id" and t["v"] == "in")

    def rel(d: int) -> Dict[str, Any]:
        left = unary(d)
        t = peek()
        if t is None or not is_relop(t):
            return left
        st["pos"] += 1
        tick(t["at"])
        n = {"t": "rel", "op": t["v"], "l": left, "r": unary(d), "at": t["at"]}
        u = peek()
        if u is not None and is_relop(u):
            _rej("unsupported", "chained comparison", u["at"])
        return n

    def unary(d: int) -> Dict[str, Any]:
        t = peek()
        if t is not None and t["k"] == "p" and t["v"] == "!":
            st["pos"] += 1
            tick(t["at"])
            if d + 1 > _CEL_MAX_DEPTH:
                _rej("too_complex", "nesting deeper than %d" % _CEL_MAX_DEPTH, t["at"])
            return {"t": "not", "e": unary(d + 1), "at": t["at"]}
        if t is not None and t["k"] == "p" and t["v"] == "-":
            nx = toks[st["pos"] + 1] if st["pos"] + 1 < len(toks) else None
            if nx is None or nx["k"] != "int":
                _rej("unsupported", "unary minus on a non-literal", t["at"])
            st["pos"] += 2
            return int_node("-" + nx["v"], t["at"])  # type: ignore[index]
        return member(d)

    def int_node(text: str, at: int) -> Dict[str, Any]:
        tick(at)
        v = int(text)
        if abs(v) > 9007199254740991:
            _rej("unsupported", "integer literal outside the safe-integer range", at)
        return {"t": "int", "v": v, "at": at}

    def args(d: int) -> List[Dict[str, Any]]:
        a: List[Dict[str, Any]] = []
        if not is_p(")"):
            a.append(expr(d + 1))
            while eat(","):
                a.append(expr(d + 1))
        need(")")
        return a

    def member(d: int) -> Dict[str, Any]:
        n = primary(d)
        while is_p("."):
            dot = peek()
            st["pos"] += 1
            ident = peek()
            if ident is None or ident["k"] != "id":
                _rej("syntax", "expected a name after '.'", dot["at"])  # type: ignore[index]
            st["pos"] += 1
            if is_p("("):
                st["pos"] += 1
                a = args(d)
                if ident["v"] not in ("startsWith", "endsWith", "contains"):  # type: ignore[index]
                    _rej("unsupported", "method '%s'" % ident["v"], ident["at"])  # type: ignore[index]
                if len(a) != 1:
                    _rej("syntax", "'%s' takes one argument" % ident["v"], ident["at"])  # type: ignore[index]
                tick(ident["at"])  # type: ignore[index]
                n = {"t": "method", "target": n, "fn": ident["v"], "arg": a[0], "at": ident["at"]}  # type: ignore[index]
            else:
                if n["t"] != "var":
                    _rej("unsupported", "field selection on something that is not a declared variable", dot["at"])  # type: ignore[index]
                n = dict(n, name="%s.%s" % (n["name"], ident["v"]))  # type: ignore[index]
        if is_p("["):
            _rej("unsupported", "index operator", peek()["at"])  # type: ignore[index]
        return n

    def primary(d: int) -> Dict[str, Any]:
        t = peek()
        if t is None:
            _rej("syntax", "unexpected end of expression", len(src))
        assert t is not None
        if t["k"] == "int":
            st["pos"] += 1
            return int_node(t["v"], t["at"])
        if t["k"] == "str":
            st["pos"] += 1
            tick(t["at"])
            return {"t": "str", "v": t["v"], "at": t["at"]}
        if t["k"] == "p" and t["v"] == "(":
            st["pos"] += 1
            e = expr(d + 1)
            need(")")
            return e
        if t["k"] == "p" and t["v"] == "[":
            st["pos"] += 1
            items: List[Dict[str, Any]] = []
            if not is_p("]"):
                while True:
                    if len(items) >= _MAX_LIST:
                        _rej("too_complex", "list longer than %d" % _MAX_LIST, t["at"])
                    items.append(expr(d + 1))
                    if not eat(","):
                        break
            need("]")
            tick(t["at"])
            return {"t": "list", "items": items, "at": t["at"]}
        if t["k"] == "id":
            st["pos"] += 1
            if t["v"] == "true" or t["v"] == "false":
                tick(t["at"])
                return {"t": "bool", "v": t["v"] == "true", "at": t["at"]}
            if t["v"] == "null":
                _rej("unsupported", "null", t["at"])
            if is_p("("):
                st["pos"] += 1
                a = args(d)
                if t["v"] == "has":
                    if len(a) != 1 or a[0]["t"] != "var":
                        _rej("syntax", "has() takes one declared variable", t["at"])
                    tick(t["at"])
                    return {"t": "has", "e": a[0], "at": t["at"]}
                if t["v"] == "timestamp":
                    if len(a) != 1 or a[0]["t"] != "str":
                        _rej("unsupported", "timestamp() of a non-literal", t["at"])
                    return {"t": "ts", "v": _parse_timestamp(a[0]["v"], t["at"]), "at": t["at"]}
                _rej("unsupported", ("function '%s'" if t["v"] in _REJECTED_FUNCS else "unknown function '%s'") % t["v"], t["at"])
            if t["v"] == "in":
                _rej("syntax", "unexpected 'in'", t["at"])
            tick(t["at"])
            return {"t": "var", "name": t["v"], "at": t["at"]}
        _rej("syntax", "unexpected '%s'" % t["v"], t["at"])
        raise AssertionError  # unreachable

    root = expr(0)
    if st["pos"] < len(toks):
        _rej("syntax", "unexpected '%s'" % toks[st["pos"]]["v"], toks[st["pos"]]["at"])
    return root


def _cel_error(e: _Reject) -> Dict[str, Any]:
    return {"ok": False, "code": e.code, "message": e.message, "at": e.at}


_INTERNAL = {"ok": False, "code": "syntax", "message": "internal error", "at": 0}


def parse_cel(expression: Any) -> Dict[str, Any]:
    """Parse a CEL expression of the supported subset: {ok: True, ast} or {ok: False, code, message, at}."""
    try:
        return _deep_from_units({"ok": True, "ast": _parse(to_units(expression) if isinstance(expression, str) else expression)})
    except _Reject as e:
        return _deep_from_units(_cel_error(e))
    except Exception:  # noqa: BLE001 - the reference reports any non-rejection as an internal error
        return dict(_INTERNAL)


def _schema_error(s: Any) -> Optional[str]:
    if not isinstance(s, dict):
        return "the schema must be an object"
    vars_ = s.get("vars")
    if not isinstance(vars_, dict):
        return "the schema needs a vars object"
    for name in _key_order(vars_):
        v = vars_[name]
        if not _CEL_IDENT.fullmatch(name) or any(x in _FORBIDDEN for x in name.split(".")):
            return "bad variable name '%s'" % name
        path = v.get("path") if isinstance(v, dict) else None
        if not isinstance(v, (dict, list)) or not isinstance(path, str) or not _PCA_PATH.fullmatch(path) or any(x in _FORBIDDEN for x in path.split(".")):
            return "variable '%s' needs a path rooted at action, subject or env" % name
        t = v.get("type")
        if not isinstance(t, str) or t not in ("string", "int", "bool", "timestamp_ms"):
            return "variable '%s' has an unsupported type" % name
        if "optional" in v and not isinstance(v["optional"], bool):
            return "variable '%s': optional must be a boolean" % name
    return None


def cel_to_condition(expression: Any, schema: Any) -> Dict[str, Any]:
    """ONE boolean CEL expression as a PCA condition, or a rejection naming the construct (there is no best-effort mode):
    {ok: True, condition, fields} or {ok: False, code, message, at}. `schema` is {vars: {name: {path, type, optional?}}}."""
    se = _schema_error(schema)
    if se is not None:
        return {"ok": False, "code": "bad_schema", "message": se, "at": 0}
    try:
        ast = _parse(to_units(expression) if isinstance(expression, str) else expression)
    except _Reject as e:
        return _deep_from_units(_cel_error(e))
    except Exception:  # noqa: BLE001
        return dict(_INTERNAL)
    fields: Dict[str, None] = {}
    svars = schema["vars"]

    def operand(n: Dict[str, Any]) -> Dict[str, Any]:
        if n["t"] == "var":
            if n["name"] not in svars:
                _rej("unknown_identifier", "'%s' is not declared in the schema" % n["name"], n["at"])
            return {"kind": "var", "v": svars[n["name"]], "name": n["name"]}
        if n["t"] == "int":
            return {"kind": "lit", "type": "int", "value": n["v"]}
        if n["t"] == "str":
            return {"kind": "lit", "type": "string", "value": n["v"]}
        if n["t"] == "bool":
            return {"kind": "lit", "type": "bool", "value": n["v"]}
        if n["t"] == "ts":
            return {"kind": "lit", "type": "timestamp_ms", "value": n["v"]}
        _rej("unsupported", "a computed value as a comparison operand", n["at"])
        raise AssertionError

    def type_of(o: Dict[str, Any]) -> str:
        return o["v"]["type"] if o["kind"] == "var" else o["type"]

    def read(o: Dict[str, Any]) -> str:
        fields[o["v"]["path"]] = None
        return o["v"]["path"]

    def flat(n: Dict[str, Any], t: str, out: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if n["t"] == t:
            flat(n["l"], t, out)
            flat(n["r"], t, out)
        else:
            out.append(n)
        return out

    def tr(n: Dict[str, Any]) -> Dict[str, Any]:
        t = n["t"]
        if t == "or":
            return {"any_of": [tr(x) for x in flat(n, "or", [])]}
        if t == "and":
            return {"all_of": [tr(x) for x in flat(n, "and", [])]}
        if t == "not":
            return {"not": tr(n["e"])}
        if t == "has":
            o = operand(n["e"])
            if o["kind"] != "var":
                _rej("syntax", "has() takes a declared variable", n["at"])
            if o["v"].get("optional") is not True:
                _rej("has_requires_optional", "has(%s): mark the variable optional in the schema (its container must always be present)" % o["name"], n["at"])
            return {"field": read(o), "op": "exists", "value": True}
        if t == "var":
            o = operand(n)
            hint = " (write %s == true)" % n["name"] if o["kind"] == "var" and o["v"]["type"] == "bool" else ""
            _rej("unsupported", "a bare variable '%s' as a condition%s" % (n["name"], hint), n["at"])
        if t == "method":
            tg = operand(n["target"])
            if tg["kind"] != "var" or tg["v"]["type"] != "string":
                _rej("type_mismatch", "%s needs a string variable" % n["fn"], n["at"])
            if n["arg"]["t"] != "str" or len(n["arg"]["v"]) == 0:
                _rej("unsupported", "%s of anything but a non-empty string literal" % n["fn"], n["at"])
            lit = n["arg"]["v"]
            if n["fn"] == "startsWith":
                return {"field": read(tg), "op": "prefix", "value": lit}
            esc = re.sub(r"[\\*?]", lambda m: "\\" + m.group(0), lit)
            glob = "*" + esc if n["fn"] == "endsWith" else "*" + esc + "*"
            if len(glob) > 512:
                _rej("too_complex", "literal too long for a glob", n["at"])
            return {"field": read(tg), "op": "like", "value": glob}
        if t == "rel":
            if n["op"] == "in":
                left = operand(n["l"])
                if left["kind"] != "var":
                    _rej("constant_expression", 'the left side of "in" must be a declared variable', n["at"])
                if n["r"]["t"] != "list" or len(n["r"]["items"]) == 0:
                    _rej("unsupported", '"in" against anything but a non-empty list literal', n["at"])
                items = [operand(x) for x in n["r"]["items"]]
                if any(i["kind"] != "lit" or i["type"] != left["v"]["type"] for i in items):
                    _rej("type_mismatch", "list items must be %s literals" % left["v"]["type"], n["at"])
                return {"field": read(left), "op": "in", "value": [i["value"] for i in items]}
            left = operand(n["l"])
            right = operand(n["r"])
            if left["kind"] == "lit" and right["kind"] == "lit":
                _rej("constant_expression", "a comparison of two literals", n["at"])
            if type_of(left) != type_of(right):
                _rej("type_mismatch", "%s against %s" % (type_of(left), type_of(right)), n["at"])
            ty = type_of(left)
            eq_op = n["op"] == "==" or n["op"] == "!="
            if not eq_op and ty == "bool":
                _rej("type_mismatch", "ordering of booleans", n["at"])
            pca_op = {"==": "eq", "!=": "ne", "<": "lt", "<=": "lte", ">": "gt", ">=": "gte"}[n["op"]]
            flip = {"eq": "eq", "ne": "ne", "lt": "gt", "lte": "gte", "gt": "lt", "gte": "lte"}
            if left["kind"] == "var" and right["kind"] == "var":
                return {"field": read(left), "op": pca_op, "ref": read(right)}
            if left["kind"] == "var":
                return {"field": read(left), "op": pca_op, "value": right["value"]}
            return {"field": read(right), "op": flip[pca_op], "value": left["value"]}
        _rej("constant_expression", "a bare constant is not a condition", n["at"])
        raise AssertionError

    try:
        condition = tr(ast)
        if not fields:
            _rej("constant_expression", "the expression reads no variable", 0)
        return _deep_from_units({"ok": True, "condition": condition, "fields": sorted(fields, key=_u16key)})
    except _Reject as e:
        return _deep_from_units(_cel_error(e))
    except Exception:  # noqa: BLE001
        return dict(_INTERNAL)


def cel_to_predicate(expression: Any, schema: Any, scope: Any) -> Dict[str, Any]:
    """One CEL expression as a permit predicate for `scope.verb` (and optionally `scope.resource`)."""
    r = cel_to_condition(expression, schema)
    if not r["ok"]:
        return r
    p: Dict[str, Any] = {"verb": scope["verb"]}
    if isinstance(scope, dict) and "resource" in scope:
        p["resource"] = scope["resource"]
    p["where"] = [r["condition"]]
    return {"ok": True, "predicate": p, "fields": r["fields"]}


def _js_text(x: Any) -> str:
    return "undefined" if x is _MISSING else "null" if x is None else "true" if x is True else "false" if x is False else str(x)


def cel_conditions_to_pca(items: Any, schema: Any) -> Dict[str, Any]:
    """A batch of named CEL expressions: every one is translated or REPORTED; one rejection makes `report.errors` non-empty, and
    `decide` then denies everything (an incomplete import never grants)."""
    predicates: List[Any] = []
    translated: List[str] = []
    errors: List[str] = []
    for it in items:
        scope: Dict[str, Any] = {"verb": it.get("verb")}
        if "resource" in it:
            scope["resource"] = it["resource"]
        r = cel_to_predicate(it.get("expression"), schema, scope)
        name = _js_text(it.get("name") if "name" in it else _MISSING)
        if r["ok"]:
            predicates.append(r["predicate"])
            translated.append("%s: translated exactly (reads %s)" % (name, ", ".join(r["fields"])))
        else:
            errors.append("%s: rejected (%s) at %d: %s" % (name, r["code"], r["at"], r["message"]))
    return {"predicates": predicates, "denies": [], "caveats": [], "report": {"source": "cel", "translated": translated, "skipped": [], "errors": errors}}
