"""A platform's own business rules for one action, compiled into tighten rules and count accumulators (native port of business-rules.ts
of the TypeScript reference @atlasauth/pca-actions). Every compiled rule signals `escalate` or `deny`, never `allow`: a rule can only
lower a decision. Anything the evaluator cannot decide fires the rule (fail closed). Time zones use the standard zoneinfo database."""
from ._fin import fin
import math
import re
from typing import Any, Dict, List, Optional

from .actions import ActionKitError, def_digest, reviewer_pins_error, _u16key, _verify_b64u, canonical_bytes_strict, b64u
from .agent import KeyPair
from .intent_wb import _js_str
from .pca import hash_canonical
from .predicates import evaluate_condition_tri

RULE_DAYS = ("sun", "mon", "tue", "wed", "thu", "fri", "sat")
RATE_PERIODS = {"hour": 3_600_000, "day": 86_400_000}
MAX_RULE_CURRENCIES = 32
MAX_RULE_LIST = 64
MAX_RULE_APPROVERS = 16
MAX_RULE_EXAMPLES = 32
_CCY_RE = re.compile(r"[A-Z]{3}")
_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_HHMM_RE = re.compile(r"([01][0-9]|2[0-3]):([0-5][0-9])")
_DOMAIN_RE = re.compile(r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
_ADDRESS_RE = re.compile(r"[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}")
_DEC_RE = re.compile(r"(0|[1-9][0-9]{0,14})(?:\.([0-9]{1,6}))?")
_AT_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_TZ_RE = re.compile(r"[A-Za-z0-9_+\-/]+")
_RULE_KEYS = ("amount", "approval", "scope", "rate", "hours", "recipients", "required", "examples")
BUSINESS_RULES_DOMAIN = "atlas-pca/action-business-rules/v1"
RULES_REVIEW_DOMAIN = "atlas-pca/action-rules-review/v1"
DEFAULT_EXAMPLE_AT = "2026-01-07T15:00:00Z"
_UNDEF = object()


def _isobj(v: Any) -> bool:
    return isinstance(v, dict)


def _isnum(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _isi(v: Any) -> bool:
    """Number.isSafeInteger."""
    if not _isnum(v):
        return False
    if isinstance(v, float) and (not fin(v) or not v.is_integer()):
        return False
    return abs(v) <= 9007199254740991


def _negzero(v: Any) -> bool:
    return isinstance(v, float) and v == 0 and math.copysign(1, v) < 0


def _bad(msg: str) -> None:
    raise ActionKitError("bad_rules", msg)


def _closed(o: dict, allowed, at: str) -> None:
    for k in o:
        if k not in allowed:
            _bad("%s: unknown member '%s'" % (at, k))


def resolve_param_ref(d: dict, r: Any, at: str) -> dict:
    """The parameter a reference names ({param} or {role}), with its definition. Raises bad_rules for none or several."""
    if not _isobj(r):
        _bad("%s: name a parameter ({param} or {role})" % at)
    has_p, has_r = isinstance(r.get("param"), str), isinstance(r.get("role"), str)
    if has_p == has_r:
        _bad("%s: give exactly one of param or role" % at)
    if has_p:
        p = d["params"].get(r["param"])
        if p is None:
            _bad("%s: '%s' has no parameter '%s'" % (at, d["verb"], _js_str(r["param"])))
        return {"name": r["param"], "p": p}
    hits = sorted((n for n in d["params"] if d["params"][n].get("role") == r["role"]), key=_u16key)
    if len(hits) != 1:
        _bad("%s: '%s' has %s parameter%s with role %s" % (at, d["verb"], "no" if not hits else "several", "" if not hits else "s", _js_str(r["role"])))
    return {"name": hits[0], "p": d["params"][hits[0]]}


def money_of(d: dict) -> dict:
    """The money parameters of an action: {amount, exp, ccy: {literal} | {param}}."""
    hits = sorted((n for n in d["params"] if d["params"][n].get("role") == "money.amount"), key=_u16key)
    if len(hits) != 1:
        _bad("'%s' needs exactly one parameter with role money.amount for an amount or approval-above rule (has %d)" % (d["verb"], len(hits)))
    name = hits[0]
    p = d["params"][name]
    if p["type"] != "integer":
        _bad("'%s': the money.amount parameter '%s' must be an integer" % (d["verb"], name))
    u = p.get("unit")
    if u is None or u["kind"] != "money":
        _bad("'%s': the amount parameter '%s' declares no money unit (its currency)" % (d["verb"], name))
    if isinstance(u["ccy"], str):
        return {"amount": name, "exp": u.get("exp"), "ccy": {"literal": u["ccy"]}}
    frm = u["ccy"]["from"]
    if frm not in d["params"]:
        _bad("'%s': the currency parameter '%s' does not exist" % (d["verb"], frm))
    return {"amount": name, "exp": u.get("exp"), "ccy": {"param": frm}}


def minor_units(v: Any, exp: int, at: str) -> int:
    """Integer minor units of a money value under exponent `exp`. Raises bad_rules for a non-integer or over-precise value."""
    if _isnum(v):
        if not _isi(v) or v < 0 or _negzero(v):
            _bad("%s: an amount is a non-negative integer of minor units, or a decimal string" % at)
        return int(v)
    if not isinstance(v, str):
        _bad("%s: an amount is a number of minor units or a decimal string" % at)
    m = _DEC_RE.fullmatch(v)
    if not m:
        _bad("%s: '%s' is not a decimal amount" % (at, v))
    frac = m.group(2) or ""
    if len(frac) > exp:
        _bad("%s: '%s' has more decimals than the currency's %d" % (at, v, exp))
    n = int(m.group(1)) * 10 ** exp + int(frac.ljust(exp, "0") or "0")
    if n > 9007199254740991:
        _bad("%s: '%s' is too large" % (at, v))
    return n


def _mins(hhmm: str) -> float:
    """``Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3, 5))``: a malformed time is NaN, not an error."""
    from .facade import _string_to_number
    return _string_to_number(hhmm[0:2]) * 60 + _string_to_number(hhmm[3:5])


_ZONE_CACHE: Dict[str, Any] = {}


def _zone(tz: str) -> Any:
    """A ZoneInfo for an IANA name, matched case-insensitively like the reference's Intl (shortcut: needs the system tz database)."""
    if tz in _ZONE_CACHE:
        return _ZONE_CACHE[tz]
    from zoneinfo import ZoneInfo, available_timezones  # lazy: absent tz data means no known zones (fail closed)
    z = None
    try:
        z = ZoneInfo(tz)
    except Exception:  # noqa: BLE001
        low = tz.lower()
        for name in available_timezones():
            if name.lower() == low:
                z = ZoneInfo(name)
                break
    _ZONE_CACHE[tz] = z
    return z


def known_time_zone(tz: Any) -> bool:
    """Is this a time zone the runtime knows (IANA name)?"""
    if not isinstance(tz, str) or len(tz) == 0 or len(tz) > 64 or _TZ_RE.fullmatch(tz) is None:
        return False
    try:
        return _zone(tz) is not None
    except Exception:  # noqa: BLE001
        return False


def _days_from_civil(y: int, m: int, d: int) -> int:
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def parse_utc_ms(s: Any) -> Optional[int]:
    """Date.parse of an RFC 3339 `...Z` second-precision time: day 1..31 rolls over the month, 24:00:00 is the next day; else None (NaN)."""
    if not isinstance(s, str) or _AT_RE.fullmatch(s) is None:
        return None
    y, mo, d, h, mi, se = int(s[0:4]), int(s[5:7]), int(s[8:10]), int(s[11:13]), int(s[14:16]), int(s[17:19])
    if not (1 <= mo <= 12 and 1 <= d <= 31 and mi <= 59 and se <= 59 and (h <= 23 or (h == 24 and mi == 0 and se == 0))):
        return None
    return (_days_from_civil(y, mo, 1) + d - 1) * 86_400_000 + h * 3_600_000 + mi * 60_000 + se * 1000


def business_rules_error(d: dict, rules: Any) -> Optional[str]:
    """None iff `rules` is a well-formed rules block for `d`; the reason otherwise."""
    try:
        _validate_rules(d, rules)
        return None
    except Exception as e:  # noqa: BLE001
        return str(e)


def _ccy_map(d: dict, m: Any, at: str) -> None:
    if not _isobj(m) or len(m) == 0 or len(m) > MAX_RULE_CURRENCIES:
        _bad("%s: a map of 1..%d currencies to amounts" % (at, MAX_RULE_CURRENCIES))
    money = money_of(d)
    for c, v in m.items():
        if _CCY_RE.fullmatch(c) is None:
            _bad("%s: '%s' is not an ISO 4217 currency code" % (at, c))
        minor_units(v, money["exp"], "%s.%s" % (at, c))


def _ref_of(s: dict) -> dict:
    return {k: s[k] for k in ("param", "role") if k in s}


def _validate_rules(d: dict, r: Any) -> None:
    if not _isobj(r):
        _bad("rules must be an object")
    _closed(r, _RULE_KEYS, "rules")
    if len([k for k in r if k != "examples"]) == 0:
        _bad("rules: name at least one rule")
    if "amount" in r:
        a = r["amount"]
        if not _isobj(a):
            _bad("rules.amount must be {max: {CCY: amount}}")
        _closed(a, ("max",), "rules.amount")
        _ccy_map(d, a.get("max"), "rules.amount.max")
    if "approval" in r:
        ap = r["approval"]
        if not _isobj(ap):
            _bad("rules.approval must be an object")
        _closed(ap, ("above", "always", "approvers", "group"), "rules.approval")
        if "always" in ap and ap["always"] is not True:
            _bad("rules.approval.always is true or absent")
        if ("above" not in ap) == ("always" not in ap):
            _bad("rules.approval: give exactly one of above or always")
        if "above" in ap:
            _ccy_map(d, ap["above"], "rules.approval.above")
        if "approvers" in ap and (not _isi(ap["approvers"]) or ap["approvers"] < 1 or ap["approvers"] > MAX_RULE_APPROVERS):
            _bad("rules.approval.approvers is 1..%d" % MAX_RULE_APPROVERS)
        if "group" in ap and (not isinstance(ap["group"], str) or _NAME_RE.fullmatch(ap["group"]) is None):
            _bad("rules.approval.group is a lowercase name")
    if "scope" in r:
        sc = r["scope"]
        if not isinstance(sc, list) or len(sc) == 0 or len(sc) > MAX_RULE_LIST:
            _bad("rules.scope is a list of 1..%d bindings" % MAX_RULE_LIST)
        for i, s in enumerate(sc):
            if not _isobj(s):
                _bad("rules.scope[%d] must be an object" % i)
            _closed(s, ("param", "role", "caller"), "rules.scope[%d]" % i)
            p = resolve_param_ref(d, _ref_of(s), "rules.scope[%d]" % i)["p"]
            if p["type"] not in ("string", "integer"):
                _bad("rules.scope[%d]: the bound parameter must be a string or integer id" % i)
            if not isinstance(s.get("caller"), str) or _NAME_RE.fullmatch(s["caller"]) is None:
                _bad("rules.scope[%d].caller is a lowercase attribute name of the caller" % i)
    if "rate" in r:
        rt = r["rate"]
        if not isinstance(rt, list) or len(rt) == 0 or len(rt) > 4:
            _bad("rules.rate is a list of 1..4 limits")
        for i, x in enumerate(rt):
            if not _isobj(x):
                _bad("rules.rate[%d] must be an object" % i)
            _closed(x, ("max", "per", "by"), "rules.rate[%d]" % i)
            if not _isi(x.get("max")) or x["max"] < 1 or x["max"] > 1_000_000:
                _bad("rules.rate[%d].max is 1..1000000" % i)
            if not isinstance(x.get("per"), str) or x["per"] not in RATE_PERIODS:
                _bad("rules.rate[%d].per is hour or day" % i)
            if "by" in x and x["by"] not in ("principal", "org"):
                _bad("rules.rate[%d].by is principal or org" % i)
    if "hours" in r:
        h = r["hours"]
        if not _isobj(h):
            _bad("rules.hours must be an object")
        _closed(h, ("days", "from", "to", "tz", "outside"), "rules.hours")
        days = h.get("days")
        if not isinstance(days, list) or len(days) == 0 or not all(isinstance(x, str) and x in RULE_DAYS for x in days) or len(set(days)) != len(days):
            _bad("rules.hours.days is a list of distinct days (%s)" % ", ".join(RULE_DAYS))
        if not isinstance(h.get("from"), str) or _HHMM_RE.fullmatch(h["from"]) is None or not isinstance(h.get("to"), str) or _HHMM_RE.fullmatch(h["to"]) is None:
            _bad("rules.hours.from and .to are HH:MM (24 h)")
        if not isinstance(h.get("tz"), str) or not known_time_zone(h["tz"]):
            _bad("rules.hours.tz '%s' is not a known IANA time zone" % _js_str(h.get("tz", _UNDEF) if "tz" in h else _UNDEF))
        if "outside" in h and h["outside"] not in ("escalate", "deny"):
            _bad("rules.hours.outside is escalate or deny")
    if "recipients" in r:
        x = r["recipients"]
        if not _isobj(x):
            _bad("rules.recipients must be an object")
        _closed(x, ("param", "role", "domains", "addresses"), "rules.recipients")
        res = resolve_param_ref(d, _ref_of(x), "rules.recipients")
        name, p = res["name"], res["p"]
        if p["type"] in ("array", "set"):
            if p.get("items") is not None and p["items"] != "string":
                _bad("rules.recipients: '%s' must hold strings" % name)
            mi = p.get("max_items")
            if not _isi(mi) or _negzero(mi) or mi > MAX_RULE_LIST:
                _bad("rules.recipients: the list parameter '%s' needs max_items <= %d so every entry can be checked" % (name, MAX_RULE_LIST))
        elif p["type"] != "string":
            _bad("rules.recipients: '%s' must be a string or a bounded list of strings" % name)
        doms, adds = x.get("domains", _UNDEF), x.get("addresses", _UNDEF)
        if doms is _UNDEF and adds is _UNDEF:
            _bad("rules.recipients: give domains and/or addresses")
        if doms is not _UNDEF and (not isinstance(doms, list) or len(doms) == 0 or len(doms) > MAX_RULE_LIST or not all(isinstance(v, str) and _DOMAIN_RE.fullmatch(v) for v in doms)):
            _bad("rules.recipients.domains is a list of lowercase domain names")
        if adds is not _UNDEF and (not isinstance(adds, list) or len(adds) == 0 or len(adds) > MAX_RULE_LIST or not all(isinstance(v, str) and _ADDRESS_RE.fullmatch(v) for v in adds)):
            _bad("rules.recipients.addresses is a list of lowercase email addresses")
    if "required" in r:
        rq = r["required"]
        if not isinstance(rq, list) or len(rq) == 0 or len(rq) > MAX_RULE_LIST or len(set(map(repr, rq))) != len(rq):
            _bad("rules.required is a list of distinct parameter names")
        for n in rq:
            if not isinstance(n, str) or n not in d["params"]:
                _bad("rules.required: '%s' has no parameter '%s'" % (d["verb"], _js_str(n)))
    if "examples" in r:
        ex = r["examples"]
        if not isinstance(ex, list) or len(ex) > MAX_RULE_EXAMPLES:
            _bad("rules.examples is a list of at most %d" % MAX_RULE_EXAMPLES)
        for i, e in enumerate(ex):
            if not _isobj(e):
                _bad("rules.examples[%d] must be an object" % i)
            _closed(e, ("params", "caller", "at", "recent", "expect"), "rules.examples[%d]" % i)
            if not _isobj(e.get("params")):
                _bad("rules.examples[%d].params must be an object" % i)
            if "caller" in e and not _isobj(e["caller"]):
                _bad("rules.examples[%d].caller must be an object" % i)
            if "at" in e and parse_utc_ms(e["at"]) is None:
                _bad("rules.examples[%d].at is an RFC 3339 UTC time (…Z)" % i)
            if "recent" in e and (not _isobj(e["recent"]) or not all(_isi(n) and n >= 0 and not _negzero(n) for n in e["recent"].values())):
                _bad("rules.examples[%d].recent maps rate indexes to counts" % i)
            if e.get("expect") not in ("allow", "escalate", "deny"):
                _bad("rules.examples[%d].expect is allow, escalate or deny" % i)


# ---- compiled form -----------------------------------------------------------------------------------------------------------

def business_rules_digest(verb: str, rules: dict) -> str:
    """Digest of a rules block (examples are tests, not rules)."""
    return hash_canonical({"d": BUSINESS_RULES_DOMAIN, "verb": verb, "rules": {k: v for k, v in rules.items() if k != "examples"}})


def _P(n: str) -> str:
    return "action.params." + n


def _ccy_cond(m: dict, c: str) -> Optional[dict]:
    if "param" in m["ccy"]:
        return {"field": _P(m["ccy"]["param"]), "op": "eq", "value": c}
    return None if m["ccy"]["literal"] == c else {"field": "action.verb", "op": "eq", "value": "\u0000never"}


def _and(cs: list) -> dict:
    xs = [c for c in cs if c is not None]
    return xs[0] if len(xs) == 1 else {"all_of": xs}


def _always(verb: str) -> dict:
    return {"field": "action.verb", "op": "eq", "value": verb}


def _rule_id(s: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", s.lower())[:64]


def format_money(minor: int, ccy: str, exp: int) -> str:
    """`12345` minor units of USD (exp 2) -> "123.45 USD". Deterministic (no locale)."""
    s = str(minor).rjust(exp + 1, "0")
    return "%s %s" % ((s[:-exp] + "." + s[-exp:]) if exp > 0 else s, ccy)


_DAY_NAMES = {"sun": "Sun", "mon": "Mon", "tue": "Tue", "wed": "Wed", "thu": "Thu", "fri": "Fri", "sat": "Sat"}


def _hours_text(h: dict) -> str:
    ds = sorted(h["days"], key=RULE_DAYS.index)
    idx = [RULE_DAYS.index(x) for x in ds]
    run = len(idx) > 2 and all(k == 0 or x == idx[k - 1] + 1 for k, x in enumerate(idx))
    days = "%s-%s" % (_DAY_NAMES[ds[0]], _DAY_NAMES[ds[-1]]) if run else ", ".join(_DAY_NAMES[x] for x in ds)
    return "%s %s-%s (%s)" % (days, h["from"], h["to"], h["tz"])


def _recipients_text(x: dict) -> str:
    return " or ".join(["addresses at " + dm for dm in x.get("domains") or []] + list(x.get("addresses") or []))


def compile_business_rules(d: dict, rules: dict) -> dict:
    """Compile a rules block for `d` into tighten rules and accumulators. Raises bad_rules for a malformed block. Deterministic."""
    _validate_rules(d, rules)
    t: List[dict] = []
    acc: List[dict] = []
    out: Dict[str, Any] = {"v": 1, "verb": d["verb"], "rules_digest": business_rules_digest(d["verb"], rules), "def_digest": def_digest(d), "tighten": t, "accumulators": acc}
    money = money_of(d) if "amount" in rules or "above" in (rules.get("approval") or {}) else None

    def unlisted(listed: List[str]) -> Optional[dict]:
        if money is None:
            return None
        if "param" in money["ccy"]:
            return {"not": {"field": _P(money["ccy"]["param"]), "op": "in", "value": listed}}
        return None if money["ccy"]["literal"] in listed else _always(d["verb"])

    if "amount" in rules:
        listed = sorted(rules["amount"]["max"], key=_u16key)
        for c in listed:
            mx = minor_units(rules["amount"]["max"][c], money["exp"], "rules.amount.max." + c)
            t.append({"id": _rule_id("amount_max_" + c), "when": _and([_ccy_cond(money, c), {"field": _P(money["amount"]), "op": "gt", "value": mx}]), "signal": "deny",
                      "reason": "the amount is above the %s ceiling" % format_money(mx, c, money["exp"])})
        u = unlisted(listed)
        if u:
            t.append({"id": "amount_currency", "when": u, "signal": "deny", "reason": "only %s amounts are allowed" % ", ".join(listed)})
    if "approval" in rules:
        ap = rules["approval"]
        out["approval"] = {"approvers": ap["approvers"] if ap.get("approvers") is not None else 1}
        if "group" in ap:
            out["approval"]["group"] = ap["group"]
        if ap.get("always"):
            t.append({"id": "approval_always", "when": _always(d["verb"]), "signal": "escalate", "reason": "this action always needs approval"})
        else:
            listed = sorted(ap["above"], key=_u16key)
            for c in listed:
                x = minor_units(ap["above"][c], money["exp"], "rules.approval.above." + c)
                t.append({"id": _rule_id("approval_above_" + c), "when": _and([_ccy_cond(money, c), {"field": _P(money["amount"]), "op": "gt", "value": x}]), "signal": "escalate",
                          "reason": "amounts above %s need approval" % format_money(x, c, money["exp"])})
            u = unlisted(listed)
            if u:
                t.append({"id": "approval_currency", "when": u, "signal": "escalate", "reason": "amounts in a currency other than %s need approval" % ", ".join(listed)})
    for i, s in enumerate(rules.get("scope") or []):
        name = resolve_param_ref(d, {"param": s["param"]} if "param" in s else {"role": s["role"]}, "rules.scope[%d]" % i)["name"]
        # `not eq`: an absent caller attribute or parameter is undecided, so the rule fires
        t.append({"id": "scope_%d" % i, "when": {"not": {"field": _P(name), "op": "eq", "ref": "subject." + s["caller"]}}, "signal": "deny", "reason": "%s must be the caller's own %s" % (name, s["caller"])})
    for i, r in enumerate(rules.get("rate") or []):
        rid = "rate_%d" % i
        by = r.get("by") or "principal"
        acc.append({"id": rid, "agg": "count", "sel": {"verbs": [d["verb"]]}, "win": {"kind": "sliding", "ms": RATE_PERIODS[r["per"]]}, "key": None, "domain_max": r["max"], "cap": r["max"],
                    "holder": {"kind": "site_local"}, "scope": by})
        t.append({"id": rid, "when": {"field": "env.acc." + rid, "op": "gte", "value": r["max"]}, "signal": "deny", "reason": "at most %d per %s per %s" % (r["max"], r["per"], by)})
    if "hours" in rules:
        h = rules["hours"]
        frm, to = _mins(h["from"]), _mins(h["to"])
        dows = sorted(RULE_DAYS.index(x) for x in h["days"])
        if frm < to:
            in_time = {"all_of": [{"field": "env.clock.min", "op": "gte", "value": frm}, {"field": "env.clock.min", "op": "lt", "value": to}]}
            day = {"field": "env.clock.dow", "op": "in", "value": dows}
        else:
            # an overnight window (22:00-06:00): the day named is the day the window starts
            in_time = {"any_of": [{"field": "env.clock.min", "op": "gte", "value": frm}, {"field": "env.clock.min", "op": "lt", "value": to}]}
            day = {"any_of": [{"all_of": [{"field": "env.clock.dow", "op": "in", "value": dows}, {"field": "env.clock.min", "op": "gte", "value": frm}]},
                              {"all_of": [{"field": "env.clock.dow", "op": "in", "value": [(x + 1) % 7 for x in dows]}, {"field": "env.clock.min", "op": "lt", "value": to}]}]}
        out["clock_tz"] = h["tz"]
        t.append({"id": "hours", "when": {"not": {"all_of": [day, in_time]}}, "signal": h.get("outside") or "escalate", "reason": "outside " + _hours_text(h)})
    if "recipients" in rules:
        x = rules["recipients"]
        res = resolve_param_ref(d, {"param": x["param"]} if "param" in x else {"role": x["role"]}, "rules.recipients")
        name, p = res["name"], res["p"]

        def ok_at(path: str) -> dict:
            alts = [{"field": path, "op": "like", "value": "*@" + re.sub(r"[\\*?]", lambda m: "\\" + m.group(0), dm)} for dm in x.get("domains") or []]
            if x.get("addresses") is not None:
                alts.append({"field": path, "op": "in", "value": sorted(x["addresses"], key=_u16key)})
            return {"any_of": alts}

        if p["type"] == "string":
            ok = ok_at(_P(name))
        else:
            n = p["max_items"]
            ok = {"all_of": [{"any_of": [{"field": _P("%s.%d" % (name, i)), "op": "exists", "value": False}, ok_at(_P("%s.%d" % (name, i)))]} for i in range(n)]
                  + [{"field": _P("%s.%d" % (name, n)), "op": "exists", "value": False}]}
        t.append({"id": "recipients", "when": {"not": ok}, "signal": "deny", "reason": "%s may only name %s" % (name, _recipients_text(x))})
    for i, n in enumerate(rules.get("required") or []):
        pr = d["params"][n]
        missing = {"any_of": [{"field": _P(n), "op": "exists", "value": False}, {"field": _P(n), "op": "eq", "value": ""}]} if pr["type"] == "string" else {"field": _P(n), "op": "exists", "value": False}
        t.append({"id": "required_%d" % i, "when": missing, "signal": "deny", "reason": "%s is required" % n})
    for r in t:
        if r.get("reason") is not None and len(r["reason"].encode("utf-16-le", "surrogatepass")) // 2 > 256:
            r["reason"] = r["reason"].encode("utf-16-le", "surrogatepass")[:253 * 2].decode("utf-16-le", "surrogatepass") + "..."
    return out


# ---- evaluation --------------------------------------------------------------------------------------------------------------

_DECISION_RANK = {"deny": 0, "escalate": 1, "allow": 2}


def meet_decision(a: str, b: str) -> str:
    """Meet in the order deny < escalate < allow."""
    return a if _DECISION_RANK[a] <= _DECISION_RANK[b] else b


def clock_at(now: Any, tz: str) -> Optional[dict]:
    """Day of week (0 = Sunday) and minute of day at `now` (ms since the epoch) in `tz`, or None when it cannot be computed.
    shortcut: instants outside years 1..9999 give None (datetime range), where the reference still answers; upgrade if rules ever need them."""
    try:
        if not _isnum(now) or not fin(now):
            return None
        from datetime import datetime
        z = _zone(tz)
        if z is None:
            return None
        dt = datetime.fromtimestamp(int(now) / 1000, z)
        return {"dow": (dt.weekday() + 1) % 7, "min": dt.hour * 60 + dt.minute}
    except Exception:  # noqa: BLE001
        return None


def rules_context(c: dict, i: dict) -> dict:
    """The predicate context the compiled rules are evaluated in: verifier-computed `env` members only."""
    env: Dict[str, Any] = {}
    if c.get("clock_tz") is not None:
        k = clock_at(i.get("now"), c["clock_tz"])
        if k:
            env["clock"] = k
    acc: Dict[str, Any] = {}
    for a in c["accumulators"]:
        n = (i.get("counts") or {}).get(a["id"])
        if _isi(n) and n >= 0:
            acc[a["id"]] = n
    env["acc"] = acc
    return {"action": {"verb": c["verb"], "resource": i.get("resource") if i.get("resource") is not None else "", "params": i["params"]}, "subject": i.get("subject") if i.get("subject") is not None else {}, "env": env}


def evaluate_business_rules(c: dict, i: dict) -> dict:
    """Evaluate compiled rules: `allow` unless a rule fires; a fired rule caps the decision at its signal. Never raises."""
    try:
        ctx = rules_context(c, i)
        decision = "allow"
        reasons: List[str] = []
        fired: List[str] = []
        approval = False
        for r in c["tighten"]:
            if evaluate_condition_tri(r["when"], ctx) == "false":
                continue
            decision = meet_decision(decision, r["signal"])
            fired.append(r["id"])
            reasons.append("%s: %s" % (r["id"], r["reason"] if r.get("reason") is not None else r["signal"]))
            if r["signal"] == "escalate" and r["id"].startswith("approval_"):
                approval = True
        out = {"decision": decision, "reasons": reasons, "fired": fired}
        if approval and c.get("approval"):
            out["approval"] = c["approval"]
        return out
    except Exception as e:  # noqa: BLE001
        return {"decision": "deny", "reasons": ["rules: evaluation error (fail closed): %s" % e], "fired": []}


def with_business_rules(base: str, v: dict) -> str:
    """The decision with rules applied to a base decision: the meet, so rules never raise it."""
    return meet_decision(base, v["decision"])


def run_rule_examples(d: dict, rules: dict) -> List[dict]:
    """Run a rules block's examples."""
    c = compile_business_rules(d, rules)
    out = []
    for index, e in enumerate(rules.get("examples") or []):
        counts = {a["id"]: (e.get("recent") or {}).get(str(k), 0) for k, a in enumerate(c["accumulators"])}
        inp: Dict[str, Any] = {"params": e["params"], "now": parse_utc_ms(e.get("at", DEFAULT_EXAMPLE_AT)), "counts": counts}
        if e.get("caller") is not None:
            inp["subject"] = e["caller"]
        v = evaluate_business_rules(c, inp)
        out.append({"index": index, "expect": e["expect"], "got": v["decision"], "ok": v["decision"] == e["expect"], "why": "; ".join(v["reasons"]) or "no rule fired"})
    return out


def explain_business_rules(d: dict, rules: dict) -> List[str]:
    """One plain sentence per rule, for the policy card and the dashboard. Raises bad_rules for a malformed block."""
    _validate_rules(d, rules)
    out: List[str] = []
    m = money_of(d) if "amount" in rules or "above" in (rules.get("approval") or {}) else None

    def lst(mp: dict) -> str:
        return ", ".join(format_money(minor_units(mp[c], m["exp"], c), c, m["exp"]) for c in sorted(mp, key=_u16key))

    if "amount" in rules:
        out.append("Refuses amounts above %s; any other currency is refused." % lst(rules["amount"]["max"]))
    if "approval" in rules:
        ap = rules["approval"]
        n = ap["approvers"] if ap.get("approvers") is not None else 1
        who = "%d approver%s%s" % (n, "" if n == 1 else "s", " from the %s group" % ap["group"] if ap.get("group") else "")
        out.append("Always needs approval by %s." % who if ap.get("always") else "Needs approval by %s when the amount is above %s (or in another currency)." % (who, lst(ap["above"])))
    for s in rules.get("scope") or []:
        name = resolve_param_ref(d, {"param": s["param"]} if "param" in s else {"role": s["role"]}, "rules.scope")["name"]
        out.append("Only the caller's own records: %s must be the caller's %s." % (name, s["caller"]))
    for r in rules.get("rate") or []:
        out.append("At most %d per %s per %s." % (r["max"], r["per"], "organisation" if r.get("by") == "org" else "principal"))
    if "hours" in rules:
        out.append("Only %s; outside those hours it %s." % (_hours_text(rules["hours"]), "is refused" if rules["hours"].get("outside") == "deny" else "needs approval"))
    if "recipients" in rules:
        x = rules["recipients"]
        name = resolve_param_ref(d, {"param": x["param"]} if "param" in x else {"role": x["role"]}, "rules.recipients")["name"]
        out.append("%s may only name %s." % (name, _recipients_text(x)))
    if "required" in rules:
        out.append("Requires %s." % ", ".join(rules["required"]))
    return out


# ---- lint (contradictions and dead rules) --------------------------------------------------------------------------------------

BUSINESS_RULE_LINTS = (
    ("LR-001", "error", "a rules block is malformed or names a parameter the action does not have"),
    ("LR-002", "error", "a contradiction: under the rules the action can never be allowed"),
    ("LR-003", "warning", "a rule that can never fire or that another rule already covers"),
    ("LR-004", "error", "a rules example does not decide as it expects"),
)


def lint_business_rules(d: dict, rules: Any) -> List[dict]:
    """Lint one action's rules."""
    def f(rule: str, severity: str, message: str) -> dict:
        return {"rule": rule, "severity": severity, "verb": d["verb"], "message": message}

    e = business_rules_error(d, rules)
    if e:
        return [f("LR-001", "error", e)]
    r = rules
    out: List[dict] = []
    m = money_of(d) if "amount" in r or "above" in (r.get("approval") or {}) else None
    amt = d["params"][m["amount"]] if m else None
    ccy_values = None
    if m:
        ccy_values = d["params"][m["ccy"]["param"]].get("values") if "param" in m["ccy"] else [m["ccy"]["literal"]]
    if "amount" in r and m:
        listed = list(r["amount"]["max"])
        if ccy_values is not None and not any(c in listed for c in ccy_values):
            out.append(f("LR-002", "error", "rules.amount: none of the action's currencies (%s) has a ceiling, so every call is refused" % ", ".join(ccy_values)))
        for c in listed:
            mx = minor_units(r["amount"]["max"][c], m["exp"], c)
            if ccy_values is not None and c not in ccy_values:
                out.append(f("LR-003", "warning", "rules.amount.max.%s: the action never uses %s" % (c, c)))
            if amt is not None and amt.get("min") is not None and mx < amt["min"]:
                out.append(f("LR-002", "error", "rules.amount.max.%s: the ceiling %s is below the parameter's minimum, so every %s call is refused" % (c, format_money(mx, c, m["exp"]), c)))
            if amt is not None and amt.get("max") is not None and mx >= amt["max"]:
                out.append(f("LR-003", "warning", "rules.amount.max.%s: the parameter's own maximum already bounds the amount below this ceiling" % c))
    if "above" in (r.get("approval") or {}) and m:
        for c in r["approval"]["above"]:
            x = minor_units(r["approval"]["above"][c], m["exp"], c)
            ceil = r["amount"]["max"].get(c) if "amount" in r else None
            if ceil is not None and x >= minor_units(ceil, m["exp"], c):
                out.append(f("LR-003", "warning", "rules.approval.above.%s: above the amount ceiling, so the approval can never be asked for" % c))
            if "amount" in r and ceil is None:
                out.append(f("LR-003", "warning", "rules.approval.above.%s: %s has no ceiling, so it is always refused before an approval" % (c, c)))
    if "hours" in r and r["hours"]["from"] == r["hours"]["to"]:
        h = r["hours"]
        out.append(f("LR-002", "error", "rules.hours: the window %s-%s is empty, so the action is %s" % (h["from"], h["to"], "always refused" if h.get("outside") == "deny" else "always escalated")))
    if "required" in r:
        for n in r["required"]:
            if d["params"][n].get("required") is not False and d["params"][n]["type"] != "string":
                out.append(f("LR-003", "warning", "rules.required: '%s' is already required by the definition" % n))
    if "rate" in r:
        seen: Dict[str, int] = {}
        for x in r["rate"]:
            k = "%s|%s" % (x["per"], x.get("by") or "principal")
            if k in seen:
                out.append(f("LR-003", "warning", "rules.rate: two limits per %s per %s; only the lower (%d) matters" % (x["per"], x.get("by") or "principal", min(seen[k], x["max"]))))
            seen[k] = min(seen.get(k, math.inf), x["max"])
        h, dd = seen.get("hour|principal"), seen.get("day|principal")
        if h is not None and dd is not None and dd <= h:
            out.append(f("LR-003", "warning", "rules.rate: the daily limit is not above the hourly one, so the hourly limit never fires"))
    try:
        for x in run_rule_examples(d, r):
            if not x["ok"]:
                out.append(f("LR-004", "error", "rules.examples[%d]: expected %s, got %s (%s)" % (x["index"], x["expect"], x["got"], x["why"])))
    except Exception as err:  # noqa: BLE001
        out.append(f("LR-001", "error", str(err)))
    return out


# ---- semantic diff of rules (widening needs a reviewer) ------------------------------------------------------------------------

def _set_rel(a, b) -> str:
    A, B = set(a), set(b)
    a_in_b, b_in_a = A <= B, B <= A
    return "eq" if a_in_b and b_in_a else "narrow" if b_in_a else "widen" if a_in_b else "inc"


def _num_rel(a: float, b: float) -> str:
    return "eq" if a == b else "narrow" if b < a else "widen"


def _presence(a: Any, b: Any) -> Optional[str]:
    return "eq" if a is _UNDEF and b is _UNDEF else "narrow" if a is _UNDEF else "widen" if b is _UNDEF else None


def _combine(rs: List[str]) -> str:
    has = rs.__contains__
    return "inc" if has("inc") or (has("narrow") and has("widen")) else "widen" if has("widen") else "narrow" if has("narrow") else "eq"


def _flip(r: str) -> str:
    return "widen" if r == "narrow" else "narrow" if r == "widen" else r


def _js_range(lo: float, hi: float):
    """``for (let x = lo; x < hi; x++)``: integers from ``lo`` (stepping 1 from a fractional or NaN start) while below ``hi``; NaN never loops."""
    if lo != lo or hi != hi:
        return []
    out, x = [], lo
    while x < hi:
        out.append(x)
        x += 1
    return out


def _minutes_of_week(h: dict) -> set:
    s = set()
    frm, to = _mins(h["from"]), _mins(h["to"])
    for day in h["days"]:
        base = (RULE_DAYS.index(day) if isinstance(day, str) and day in RULE_DAYS else -1) * 1440  # indexOf: an unknown day is -1
        if frm < to:
            s.update(base + x for x in _js_range(frm, to))
        elif frm > to:
            s.update(base + x for x in _js_range(frm, 1440))
            s.update(((base + 1440) % 10080) + x for x in _js_range(0, to))
    return s


def diff_business_rules(d: dict, prev: Optional[dict], nxt: Optional[dict]) -> dict:
    """The semantic diff of two rules blocks of one action (either may be absent): {class, reasons}. Conservative: unordered = incomparable."""
    o, n = (prev if isinstance(prev, dict) else {}), (nxt if isinstance(nxt, dict) else {})  # a rules block that is not an object has no members (property reads of a primitive are undefined)
    g = lambda x, k: x.get(k, _UNDEF)  # noqa: E731
    uses_money = "amount" in o or "amount" in n or "above" in (o.get("approval") or {}) or "above" in (n.get("approval") or {})
    m = money_of(d) if uses_money else None
    rels: List[tuple] = []

    def ccy_map_rel(a: dict, b: dict) -> str:
        rs = [_set_rel(list(a), list(b))]
        for c in a:
            if c in b:
                rs.append(_num_rel(minor_units(a[c], m["exp"], c), minor_units(b[c], m["exp"], c)))
        return _combine(rs)

    p = _presence(g(o, "amount"), g(n, "amount"))
    rels.append(("amount", p if p is not None else ccy_map_rel(o["amount"]["max"], n["amount"]["max"])))
    p = _presence(g(o, "approval"), g(n, "approval"))
    if p is None:
        a, b = o["approval"], n["approval"]
        rs: List[str] = []
        if a.get("always") and b.get("always"):
            rs.append("eq")
        elif a.get("always"):
            rs.append("widen")
        elif b.get("always"):
            rs.append("narrow")
        else:
            rs.append(ccy_map_rel(a["above"], b["above"]))
        rs.append(_num_rel(-(a["approvers"] if a.get("approvers") is not None else 1), -(b["approvers"] if b.get("approvers") is not None else 1)))
        rs.append("eq" if g(a, "group") == g(b, "group") else "inc")
        p = _combine(rs)
    rels.append(("approval", p))

    def skey(s: Any) -> str:
        if s is None:
            raise TypeError("Cannot read properties of null (reading 'param')")
        mem = (lambda k: s.get(k, _UNDEF)) if isinstance(s, dict) else (lambda k: _UNDEF)  # a primitive has no members
        param, role = mem("param"), mem("role")
        return "%s|%s|%s" % ("" if param is _UNDEF or param is None else _js_str(param), "" if role is _UNDEF or role is None else _js_str(role), _js_str(mem("caller")))

    rels.append(("scope", _flip(_set_rel([skey(s) for s in o.get("scope") or []], [skey(s) for s in n.get("scope") or []]))))

    def best(rs) -> Dict[str, float]:
        mp: Dict[str, float] = {}
        for x in rs or []:
            k = "%s|%s" % (x["per"], x.get("by") or "principal")
            mp[k] = min(mp.get(k, math.inf), x["max"])
        return mp

    A, B = best(o.get("rate")), best(n.get("rate"))
    rs = []
    for k in list(A) + [k for k in B if k not in A]:
        rs.append("narrow" if k not in A else "widen" if k not in B else _num_rel(A[k], B[k]))
    rels.append(("rate", _combine(rs)))
    p = _presence(g(o, "hours"), g(n, "hours"))
    if p is None:
        a, b = o["hours"], n["hours"]
        if a["tz"] != b["tz"]:
            p = "inc"
        else:
            sa, sb = _minutes_of_week(a), _minutes_of_week(b)
            inner = "eq" if sa == sb else "narrow" if sb <= sa else "widen" if sa <= sb else "inc"
            p = _combine([inner, _num_rel(0 if a.get("outside") == "deny" else 1, 0 if b.get("outside") == "deny" else 1)])
    rels.append(("hours", p))
    p = _presence(g(o, "recipients"), g(n, "recipients"))
    if p is None:
        a, b = o["recipients"], n["recipients"]
        if a.get("param") != b.get("param") or a.get("role") != b.get("role"):
            p = "inc"
        else:
            allowed_a = ["@" + x for x in a.get("domains") or []] + list(a.get("addresses") or [])
            allowed_b = ["@" + x for x in b.get("domains") or []] + list(b.get("addresses") or [])

            def covered(x: str, st: list) -> bool:
                return x in st or (not x.startswith("@") and ("@" + (x.split("@")[1] if "@" in x else "undefined")) in st)

            b_in_a = all(covered(x, allowed_a) for x in allowed_b)
            a_in_b = all(covered(x, allowed_b) for x in allowed_a)
            p = "eq" if b_in_a and a_in_b else "narrow" if b_in_a else "widen" if a_in_b else "inc"
    rels.append(("recipients", p))
    rels.append(("required", _flip(_set_rel(o.get("required") or [], n.get("required") or []))))
    diffs = [(k, r) for k, r in rels if r != "eq"]
    reasons = sorted("rules.%s: %s" % (k, "incomparable" if r == "inc" else r) for k, r in diffs)
    cls = _combine([r for _, r in diffs])
    return {"class": "equal" if cls == "eq" else "incomparable" if cls == "inc" else cls, "reasons": reasons}


# ---- the reviewer's signature over a widened rules block -------------------------------------------------------------------------

def rules_review_message(b: dict) -> bytes:
    body = canonical_bytes_strict({"verb": b["verb"], "def_digest": b["def_digest"], "rules_digest": b["rules_digest"], "reviewer_kid": b["reviewer_kid"], "ts": b["ts"]})
    return (RULES_REVIEW_DOMAIN + "\0").encode("utf-8") + body


def sign_rules_review(b: dict, secret: bytes) -> dict:
    return {**b, "sig": b64u(KeyPair(bytes(secret)).sign(rules_review_message(b)))}


def rules_review_error(r: Any, d: dict, rules: dict, pins: Any) -> Optional[str]:
    """None iff `r` is a valid review of exactly these rules on exactly this def (digests, pinned reviewer key, validity, signature). Never raises."""
    try:
        if pins is None:
            return "no reviewer keys are pinned"
        pe = reviewer_pins_error(pins)
        if pe:
            return "bad pins: " + pe
        if not _isobj(r):
            return "no rules review"
        if r.get("verb") != d["verb"]:
            return "the rules review names another action"
        if r.get("def_digest") != def_digest(d):
            return "the rules review covers another version of the action"
        if r.get("rules_digest") != business_rules_digest(d["verb"], rules):
            return "the rules review covers other rules"
        ts = r.get("ts")
        if not isinstance(r.get("sig"), str) or not isinstance(r.get("reviewer_kid"), str) or not _isi(ts) or _negzero(ts):
            return "malformed rules review"
        key = next((k for k in pins["keys"] if k["kid"] == r["reviewer_kid"]), None)
        if key is None:
            return "no pinned key '%s'" % r["reviewer_kid"]
        if "reviewer" not in key["roles"]:
            return "key '%s' does not hold the reviewer role" % key["kid"]
        if (key.get("not_before") is not None and ts < key["not_before"]) or (key.get("not_after") is not None and ts > key["not_after"]):
            return "the review time is outside the key validity"
        body = {k: v for k, v in r.items() if k != "sig"}
        return None if _verify_b64u(key["pk"], rules_review_message(body), r["sig"]) else "the rules review signature is invalid"
    except Exception as e:  # noqa: BLE001
        return "malformed rules review: %s" % e
