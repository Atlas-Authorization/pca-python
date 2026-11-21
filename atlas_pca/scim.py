"""SCIM 2.0 provisioning for PCA agents: the passport <-> SCIM ``Agent`` mapping, a framework-agnostic ``/Agents`` resource
server over request dicts (list + ``eq`` filter + pagination, get, POST registers a passport, PUT, PATCH, DELETE), and the push
adapters for Microsoft Entra Agent ID and Okta with an injected fetch callable. Port of the TypeScript reference
(@atlasauth/pca-scim). Resources, request and response objects are plain dicts with the wire member names; a 204 response has no
``body`` member. Options dicts use the reference's names (``baseUrl``, ``now``, ``authenticate``, ``allowUnauthenticated``)."""
from ._fin import fin, to_float
import json
import math
import re
import time
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote

from .pca import _js_keys, hash_canonical

AGENT_SCHEMA_URN = "urn:ietf:params:scim:schemas:atlas:2.0:Agent"
LIST_RESPONSE_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCH_OP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"
AGENT_RESOURCE_TYPE = "Agent"
ENTRA_AGENT_EXTENSION_URN = "urn:ietf:params:scim:schemas:extension:microsoft:agent:2.0:Agent"
OKTA_AGENT_EXTENSION_URN = "urn:okta:scim:schemas:custom:1.0:Agent"
SCIM_CONTENT_TYPE = "application/scim+json"

_UNDEF = object()  # an absent JSON member (TypeScript `undefined`), distinct from null


class ScimValueError(Exception):
    def __init__(self, scim_type: str, detail: str):
        super().__init__(detail)
        self.scim_type = scim_type


# ---- JavaScript value semantics ---------------------------------------------------------------------------------------------

def _num_str(v: Any) -> str:
    """Number::toString."""
    if isinstance(v, int):
        if abs(v) <= 2 ** 53:
            return str(v)
        v = to_float(v)
    if v != v:
        return "NaN"
    if v in (math.inf, -math.inf):
        return "Infinity" if v > 0 else "-Infinity"
    if v == 0:
        return "0"
    sign = "-" if v < 0 else ""
    _s, digs, e = Decimal(repr(abs(v))).as_tuple()
    ds = "".join(map(str, digs))
    stripped = ds.rstrip("0")
    e += len(ds) - len(stripped)
    ds = stripped
    k = len(ds)
    n = e + k
    if k <= n <= 21:
        return sign + ds + "0" * (n - k)
    if 0 < n <= 21:
        return sign + ds[:n] + "." + ds[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + ds
    e1 = n - 1
    exp = "e" + ("+" if e1 >= 0 else "-") + str(abs(e1))
    return sign + (ds if k == 1 else ds[0] + "." + ds[1:]) + exp


def _js(v: Any) -> str:
    """String(v) / a template-literal rendering of a JSON value."""
    if v is _UNDEF:
        return "undefined"
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float)):
        return _num_str(v)
    if isinstance(v, list):
        return ",".join("" if x is None else _js(x) for x in v)
    return "[object Object]"


_JS_WS = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"  # WhiteSpace + LineTerminator, each character (a dash would be one too)
_NUM_DEC = re.compile(r"[+-]?(?:Infinity|[0-9]+\.?[0-9]*(?:[eE][+-]?[0-9]+)?|\.[0-9]+(?:[eE][+-]?[0-9]+)?)", re.ASCII)


def _js_number(v: Any) -> float:
    """Number(v) for the values a query string member can hold."""
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        return float(v)
    s = _js(v).strip(_JS_WS)
    if s == "":
        return 0.0
    try:
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", s):
            return float(int(s[2:], 16))
        if re.fullmatch(r"0[oO][0-7]+", s):
            return float(int(s[2:], 8))
        if re.fullmatch(r"0[bB][01]+", s):
            return float(int(s[2:], 2))
        if _NUM_DEC.fullmatch(s):
            return float(s.replace("Infinity", "inf"))
    except (ValueError, OverflowError):
        pass
    return math.nan


def _is_integer(n: float) -> bool:
    return fin(n) and n == math.floor(n)


def _is_rec(v: Any) -> bool:
    return isinstance(v, dict)


def _as_str(v: Any) -> Optional[str]:
    return v if isinstance(v, str) else None


def _as_bool(v: Any) -> Optional[bool]:
    if isinstance(v, bool):
        return v
    if v == "true" and isinstance(v, str):
        return True
    if v == "false" and isinstance(v, str):
        return False
    return None


def _as_str_list(v: Any) -> Optional[List[str]]:
    return v if isinstance(v, list) and all(isinstance(x, str) for x in v) else None


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _first(*vals: Any) -> Any:
    for v in vals:
        if v is not None:
            return v
    return None


# ---- passports (re-exported by the reference from the PCA core) -----------------------------------------------------------------

def passport_fingerprint(p: Dict[str, Any]) -> str:
    def nn(k: str) -> Any:
        return p.get(k)
    return hash_canonical({
        "d": "atlas-pca/passport/v1",
        "model_id": p.get("model_id"),
        "weights_digest": nn("weights_digest"),
        "system_prompt_digest": nn("system_prompt_digest"),
        "tool_manifest_digest": nn("tool_manifest_digest"),
        "runtime_measurement": nn("runtime_measurement"),
        "operator": p.get("operator"),
        "hardware_rooted": p.get("hardware_rooted"),
    })


def issue_passport(identity: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(identity)
    out["id"] = passport_fingerprint(identity)
    return out


class PassportRegistry:
    def __init__(self, passports: List[Dict[str, Any]]):
        self._by_id: Dict[Any, Dict[str, Any]] = {}
        for p in passports:
            self._by_id[p["id"]] = p

    def get(self, id: Any) -> Optional[Dict[str, Any]]:
        try:
            return self._by_id.get(id)
        except TypeError:
            return None

    def has(self, id: Any) -> bool:
        return self.get(id) is not None

    def all(self) -> List[Dict[str, Any]]:
        return list(self._by_id.values())


def build_registry(passports: List[Dict[str, Any]]) -> PassportRegistry:
    return PassportRegistry(passports)


# ---- passport <-> SCIM mapping ----------------------------------------------------------------------------------------------

def _iso_at(now: Callable[[], Any]) -> str:
    d = datetime(1970, 1, 1) + timedelta(milliseconds=int(now()))
    return "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ" % (d.year, d.month, d.day, d.hour, d.minute, d.second, d.microsecond // 1000)


def _now_default() -> int:
    return int(time.time() * 1000)


def _enc(s: str) -> str:
    return quote(s, safe="!~*'()-_.")


def _build_meta(id: Any, sans_meta: Any, inp: dict) -> Dict[str, Any]:
    now = inp["now"] if inp.get("now") is not None else _now_default
    base = re.sub(r"/+$", "", inp["baseUrl"]) if "baseUrl" in inp else ""
    return {
        "resourceType": AGENT_RESOURCE_TYPE,
        "created": inp["created"] if inp.get("created") is not None else _iso_at(now),
        "lastModified": inp["lastModified"] if inp.get("lastModified") is not None else _iso_at(now),
        "location": "%s/Agents/%s" % (base, _enc(_js(id))),
        "version": 'W/"%s"' % hash_canonical(sans_meta),
    }


def passport_to_scim(passport: dict, proj: dict, meta: Optional[dict] = None) -> Dict[str, Any]:
    """A SCIM ``Agent`` for a passport. ``meta`` = {baseUrl?, created?, lastModified?, now?}."""
    meta = meta if meta is not None else {}
    base: Dict[str, Any] = {
        "schemas": [AGENT_SCHEMA_URN],
        "id": passport["id"],
        "displayName": proj["displayName"] if proj.get("displayName") is not None else "%s (%s)" % (_js(passport.get("model_id", _UNDEF)), _js(passport.get("operator", _UNDEF))),
        "active": proj["active"] if proj.get("active") is not None else True,
        "capabilities": list(proj["capabilities"]) if proj.get("capabilities") is not None else [],
        "passportRef": passport["id"],
        "passport": passport,
    }
    if "owner" not in proj:
        raise TypeError("canonicalize: unsupported type undefined")  # the reference hashes an undefined owner and throws
    base["owner"] = proj["owner"]
    if "externalId" in proj:
        base["externalId"] = proj["externalId"]
    if "holder" in proj:
        base["holder"] = proj["holder"]
    out = dict(base)
    out["meta"] = _build_meta(passport["id"], base, meta)
    return out


def _read_identity(body: dict) -> Dict[str, Any]:
    nested = body.get("passport")
    if _is_rec(nested):
        model_id, operator = _as_str(nested.get("model_id")), _as_str(nested.get("operator"))
        if model_id is None or operator is None:
            raise ScimValueError("invalidValue", "passport.model_id and passport.operator are required")
        hw = _as_bool(nested.get("hardware_rooted"))
        identity: Dict[str, Any] = {
            "model_id": model_id,
            "operator": operator,
            "hardware_rooted": hw if hw is not None else False,
            "issued_at": nested["issued_at"] if _is_number(nested.get("issued_at")) else 0,
        }
        for src, dst in (("weights_digest", "weights_digest"), ("system_prompt_digest", "system_prompt_digest"),
                         ("tool_manifest_digest", "tool_manifest_digest"), ("runtime_measurement", "runtime_measurement")):
            v = _as_str(nested.get(src))
            if v is not None:
                identity[dst] = v
        measured = _as_bool(nested.get("weights_measured"))
        if measured is not None:
            identity["weights_measured"] = measured
        return identity
    model_id = _first(_as_str(body.get("model")), _as_str(body.get("model_id")))
    operator = _as_str(body.get("operator"))
    if model_id is None or operator is None:
        raise ScimValueError("invalidValue", "an Agent requires either a `passport` object or `model` + `operator`")
    hw = _as_bool(body.get("hardwareRooted"))
    return {"model_id": model_id, "operator": operator, "hardware_rooted": hw if hw is not None else False, "issued_at": 0}


def _read_projection(body: dict) -> Dict[str, Any]:
    nested = body.get("passport")
    owner = _first(_as_str(body.get("owner")), _as_str(body.get("operator")),
                   _as_str(nested.get("operator")) if _is_rec(nested) else None, "")
    proj: Dict[str, Any] = {"owner": owner}
    for k, v in (("displayName", _as_str(body.get("displayName"))), ("externalId", _as_str(body.get("externalId"))),
                 ("active", _as_bool(body.get("active"))), ("capabilities", _as_str_list(body.get("capabilities"))),
                 ("holder", _as_str(body.get("holder")))):
        if v is not None:
            proj[k] = v
    return proj


def scim_to_provisioning_request(value: Any) -> Dict[str, Any]:
    """{identity, projection} from an untrusted SCIM write body (a nested ``passport`` or the flat IdP form); raises ScimValueError."""
    if not _is_rec(value):
        raise ScimValueError("invalidSyntax", "request body must be a JSON object")
    if "schemas" in value and not (isinstance(value["schemas"], list) and AGENT_SCHEMA_URN in value["schemas"]):
        raise ScimValueError("invalidValue", "schemas must include %s" % AGENT_SCHEMA_URN)
    return {"identity": _read_identity(value), "projection": _read_projection(value)}


# ---- store ------------------------------------------------------------------------------------------------------------------

class AgentStore:
    """The in-memory store; any object with all/get/put/delete/registry works. Entries are {"resource", "passport"}."""

    def __init__(self, seed: Optional[List[dict]] = None):
        self._by_id: Dict[Any, dict] = {}
        for s in seed or []:
            self._by_id[s["resource"]["id"]] = s

    def all(self) -> List[dict]:
        return list(self._by_id.values())

    def get(self, id: Any) -> Optional[dict]:
        try:
            return self._by_id.get(id)
        except TypeError:
            return None

    def put(self, stored: dict) -> None:
        self._by_id[stored["resource"]["id"]] = stored

    def delete(self, id: Any) -> bool:
        try:
            return self._by_id.pop(id, _UNDEF) is not _UNDEF
        except TypeError:
            return False

    def registry(self) -> PassportRegistry:
        return build_registry([s["passport"] for s in self._by_id.values()])


def create_memory_store(seed: Optional[List[dict]] = None) -> AgentStore:
    return AgentStore(seed)


# ---- envelopes + filter -----------------------------------------------------------------------------------------------------

def scim_error(status: int, detail: str, scim_type: Any = _UNDEF) -> Dict[str, Any]:
    body: Dict[str, Any] = {"schemas": [ERROR_SCHEMA], "status": _js(status), "detail": detail}
    if scim_type is not _UNDEF:
        body["scimType"] = scim_type
    return body


def scim_list_response(resources: List[dict], total_results: Any, start_index: Any) -> Dict[str, Any]:
    return {"schemas": [LIST_RESPONSE_SCHEMA], "totalResults": total_results, "startIndex": start_index,
            "itemsPerPage": len(resources), "Resources": resources}


_FILTERABLE = frozenset(("userName", "displayName", "externalId", "id", "active", "owner"))
_WS = "[" + _JS_WS + "]"
_NOT_LT = "[^\n\r  ]"  # JavaScript `.`
_FILTER = re.compile(r"\A" + _WS + r"*([A-Za-z0-9_]+)" + _WS + r"+eq" + _WS + r'+(?:"((?:[^"\\]|\\' + _NOT_LT + r')*)"|(true|false))' + _WS + r"*\Z", re.IGNORECASE | re.ASCII)
_UNESC = re.compile(r"\\(" + _NOT_LT + ")")


def parse_filter(filter: Any) -> Dict[str, Any]:
    """The ``attr eq "value"`` / ``attr eq true|false`` subset; raises ScimValueError("invalidFilter")."""
    if not isinstance(filter, str):
        raise ScimValueError("invalidFilter", "filter must be a string")
    m = _FILTER.match(filter)
    if not m:
        raise ScimValueError("invalidFilter", 'unsupported filter (only `attr eq "value"` is supported): %s' % filter)
    attr = m.group(1)
    if attr not in _FILTERABLE:
        raise ScimValueError("invalidFilter", "filter attribute not supported: %s" % attr)
    if m.group(3) is not None:
        return {"attr": attr, "value": m.group(3).lower() == "true"}
    return {"attr": attr, "value": _UNESC.sub(r"\1", m.group(2) or "")}


def _seq(a: Any, b: Any) -> bool:
    """=== for strings and booleans."""
    return type(a) is type(b) and a == b


def _matches_filter(agent: dict, f: dict) -> bool:
    a = f["attr"]
    if a in ("userName", "displayName"):
        return _seq(agent.get("displayName"), f["value"])
    if a in ("externalId", "id", "owner"):
        return _seq(agent.get(a), f["value"])
    if a == "active":
        return _seq(agent.get("active"), f["value"])
    return False


# ---- PATCH ------------------------------------------------------------------------------------------------------------------

_MUTABLE_PATHS = frozenset(("active", "displayName", "externalId", "owner", "capabilities", "holder"))


def _read_patch_ops(value: Any) -> List[dict]:
    if not _is_rec(value):
        raise ScimValueError("invalidSyntax", "PATCH body must be a JSON object")
    ops = value.get("Operations")
    if not isinstance(ops, list) or len(ops) == 0:
        raise ScimValueError("invalidValue", "PATCH requires a non-empty Operations array")
    out = []
    for raw in ops:
        o = raw if _is_rec(raw) else None
        op_raw = o.get("op", _UNDEF) if o is not None else _UNDEF
        op = op_raw.lower() if isinstance(op_raw, str) else None
        if op not in ("add", "replace", "remove"):
            raise ScimValueError("invalidValue", "unsupported PATCH op: %s" % _js(op_raw))
        parsed: Dict[str, Any] = {"op": op}
        path = _as_str(o.get("path")) if o is not None else None
        if path is not None:
            parsed["path"] = path
        if o is not None and "value" in o:
            parsed["value"] = o["value"]
        out.append(parsed)
    return out


def _projection_of(resource: dict) -> Dict[str, Any]:
    proj: Dict[str, Any] = {"owner": resource["owner"], "active": resource["active"], "capabilities": list(resource["capabilities"])}
    if resource.get("displayName") is not None:
        proj["displayName"] = resource["displayName"]
    if resource.get("externalId") is not None:
        proj["externalId"] = resource["externalId"]
    if resource.get("holder") is not None:
        proj["holder"] = resource["holder"]
    return proj


def _apply_scalar(proj: dict, path: str, op: str, value: Any) -> None:
    if path == "active":
        if op == "remove":
            proj["active"] = True
            return
        b = _as_bool(value)
        if b is None:
            raise ScimValueError("invalidValue", "`active` must be a boolean")
        proj["active"] = b
        return
    if path == "capabilities":
        if op == "remove":
            proj["capabilities"] = []
            return
        arr = _as_str_list(value)
        if arr is None:
            raise ScimValueError("invalidValue", "`capabilities` must be a string array")
        proj["capabilities"] = (list(proj.get("capabilities") or []) + arr) if op == "add" else list(arr)
        return
    if op == "remove":
        if path in ("displayName", "owner"):
            raise ScimValueError("mutability", "`%s` cannot be removed" % path)
        if path in ("externalId", "holder"):
            proj.pop(path, None)
        return
    s = _as_str(value)
    if s is None:
        raise ScimValueError("invalidValue", "`%s` must be a string" % path)
    proj[path] = s


def _apply_patch_op(proj: dict, op: dict) -> None:
    if "path" not in op:
        if op["op"] == "remove":
            raise ScimValueError("noTarget", "a `remove` op requires a `path`")
        obj = op.get("value")
        if not _is_rec(obj):
            raise ScimValueError("invalidValue", "a pathless PATCH value must be an object")
        for key in _js_keys(obj):
            if key not in _MUTABLE_PATHS:
                raise ScimValueError("mutability", "attribute is immutable or unknown: %s" % key)
            _apply_scalar(proj, key, "replace", obj[key])
        return
    if op["path"] not in _MUTABLE_PATHS:
        raise ScimValueError("mutability", "attribute is immutable or unknown: %s" % op["path"])
    _apply_scalar(proj, op["path"], op["op"], op.get("value"))


# ---- the SCIM server --------------------------------------------------------------------------------------------------------

def _json_response(status: int, body: Any, extra: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    headers = {"content-type": SCIM_CONTENT_TYPE}
    headers.update(extra or {})
    return {"status": status, "body": body, "headers": headers}


def _error_response(status: int, detail: str, scim_type: Any = _UNDEF) -> Dict[str, Any]:
    return _json_response(status, scim_error(status, detail, scim_type))


def _resource_response(status: int, resource: dict) -> Dict[str, Any]:
    return _json_response(status, resource, {"location": resource["meta"]["location"], "etag": resource["meta"]["version"]})


def _parse_int_param(v: Any, fallback: float) -> float:
    if v is _UNDEF:
        return fallback
    n = _js_number(v)
    return n if _is_integer(n) else fallback


def scim_handler(store: Any, options: Optional[dict] = None) -> Callable[[dict], Dict[str, Any]]:
    """``handler({"method", "id"?, "query"?, "body"?}) -> {"status", "body", "headers"}``. ``authenticate(req)`` must return exactly
    True to admit a request (False, a raise or any other value is a 401); it is required unless ``allowUnauthenticated`` is True."""
    options = options if options is not None else {}
    authenticate = options.get("authenticate")
    if not callable(authenticate) and options.get("allowUnauthenticated") is not True:
        raise TypeError("scimHandler: `authenticate` is required (or pass allowUnauthenticated: true explicitly)")

    def meta_input() -> dict:
        inp: dict = {}
        if "baseUrl" in options:
            inp["baseUrl"] = options["baseUrl"]
        if options.get("now") is not None:
            inp["now"] = options["now"]
        return inp

    def handle_list(query: Any) -> dict:
        q = query if _is_rec(query) else {}
        items = [s["resource"] for s in store.all()]
        flt = q.get("filter", _UNDEF)
        if flt is not _UNDEF and flt != "":
            try:
                parsed = parse_filter(flt)
            except ScimValueError as e:
                return _error_response(400, str(e), e.scim_type)
            items = [a for a in items if _matches_filter(a, parsed)]
        total = len(items)
        start = max(1.0, _parse_int_param(q.get("startIndex", _UNDEF), 1.0))
        cnt_raw = q.get("count", _UNDEF)
        lo = int(min(start - 1, 2 ** 62))
        if cnt_raw is _UNDEF:
            page = items[lo:]
        else:
            cnt = max(0.0, _parse_int_param(cnt_raw, float(total)))
            page = items[lo:int(min(start - 1 + cnt, 2 ** 62))]
        return _json_response(200, scim_list_response(page, total, start))

    def rematerialize(existing: dict, proj: dict) -> dict:
        meta = meta_input()
        meta["created"] = existing["resource"]["meta"]["created"]
        return passport_to_scim(existing["passport"], proj, meta)

    def handle_create(body: Any) -> dict:
        try:
            req = scim_to_provisioning_request(body)
        except ScimValueError as e:
            return _error_response(400, str(e), e.scim_type)
        passport = issue_passport(req["identity"])
        if store.get(passport["id"]):
            return _error_response(409, "an agent with this attested identity already exists (id %s)" % passport["id"], "uniqueness")
        resource = passport_to_scim(passport, req["projection"], meta_input())
        store.put({"resource": resource, "passport": passport})
        return _resource_response(201, resource)

    def handle_replace(id: Any, body: Any) -> dict:
        existing = store.get(id)
        if not existing:
            return _error_response(404, "Agent %s not found" % _js(id))
        if not _is_rec(body):
            return _error_response(400, "request body must be a JSON object", "invalidSyntax")
        try:
            proj = _read_projection(body)
        except ScimValueError as e:
            return _error_response(400, str(e), e.scim_type)
        if proj["owner"] == "":
            proj["owner"] = existing["resource"]["owner"]
        resource = rematerialize(existing, proj)
        store.put({"resource": resource, "passport": existing["passport"]})
        return _resource_response(200, resource)

    def handle_patch(id: Any, body: Any) -> dict:
        existing = store.get(id)
        if not existing:
            return _error_response(404, "Agent %s not found" % _js(id))
        proj = _projection_of(existing["resource"])
        try:
            for op in _read_patch_ops(body):
                _apply_patch_op(proj, op)
        except ScimValueError as e:
            return _error_response(400, str(e), e.scim_type)
        resource = rematerialize(existing, proj)
        store.put({"resource": resource, "passport": existing["passport"]})
        return _resource_response(200, resource)

    def handle_delete(id: Any) -> dict:
        if not store.delete(id):
            return _error_response(404, "Agent %s not found" % _js(id))
        return {"status": 204, "headers": {}}

    def handle_get_one(id: Any) -> dict:
        existing = store.get(id)
        if not existing:
            return _error_response(404, "Agent %s not found" % _js(id))
        return _resource_response(200, existing["resource"])

    def handle(req: dict) -> Dict[str, Any]:
        if callable(authenticate):
            try:
                ok = authenticate(req) is True
            except Exception:  # noqa: BLE001 - a raising check is a refusal
                ok = False
            if not ok:
                r = _error_response(401, "authentication required")
                r["headers"] = {"content-type": SCIM_CONTENT_TYPE, "www-authenticate": "Bearer"}
                return r
        method = req.get("method", _UNDEF)
        id = req.get("id", _UNDEF)
        if method == "GET":
            return handle_list(req.get("query")) if id is _UNDEF else handle_get_one(id)
        if method == "POST":
            if id is not _UNDEF:
                return _error_response(405, "POST is not allowed on an individual Agent")
            return handle_create(req.get("body"))
        if method == "PUT":
            return _error_response(405, "PUT requires an Agent id") if id is _UNDEF else handle_replace(id, req.get("body"))
        if method == "PATCH":
            return _error_response(405, "PATCH requires an Agent id") if id is _UNDEF else handle_patch(id, req.get("body"))
        if method == "DELETE":
            return _error_response(405, "DELETE requires an Agent id") if id is _UNDEF else handle_delete(id)
        return _error_response(405, "method not allowed: %s" % _js(method))

    return handle


# ---- push adapters ----------------------------------------------------------------------------------------------------------

def _extension_attributes(agent: dict) -> Dict[str, Any]:
    attrs: Dict[str, Any] = {
        "owner": agent["owner"],
        "model": agent["passport"]["model_id"],
        "operator": agent["passport"]["operator"],
        "hardwareRooted": agent["passport"]["hardware_rooted"],
        "capabilities": list(agent["capabilities"]),
        "passportRef": agent["passportRef"],
    }
    if agent.get("holder") is not None:
        attrs["holder"] = agent["holder"]
    return attrs


def to_entra_agent_payload(agent: dict) -> Dict[str, Any]:
    return {
        "schemas": [AGENT_SCHEMA_URN, ENTRA_AGENT_EXTENSION_URN],
        "externalId": agent["externalId"] if agent.get("externalId") is not None else agent["passportRef"],
        "displayName": agent["displayName"],
        "active": agent["active"],
        ENTRA_AGENT_EXTENSION_URN: _extension_attributes(agent),
    }


def to_okta_scim_payload(agent: dict) -> Dict[str, Any]:
    return {
        "schemas": [AGENT_SCHEMA_URN, OKTA_AGENT_EXTENSION_URN],
        "userName": agent["passportRef"],
        "externalId": agent["externalId"] if agent.get("externalId") is not None else agent["passportRef"],
        "displayName": agent["displayName"],
        "active": agent["active"],
        OKTA_AGENT_EXTENSION_URN: _extension_attributes(agent),
    }


def push_provision(payload: dict, target: dict) -> Dict[str, Any]:
    """POST a provisioning payload. ``target`` = {endpoint, token, fetch}; ``fetch(url, {"method", "headers", "body"})`` returns an
    object (or dict) with ``ok``, ``status`` and ``json()`` (injected: there is no default network client)."""
    f = target.get("fetch")
    if not callable(f):
        raise RuntimeError("pushProvision: no fetch available - pass one explicitly")
    res = f(target["endpoint"], {
        "method": "POST",
        "headers": {"authorization": "Bearer %s" % _js(target["token"]), "content-type": SCIM_CONTENT_TYPE},
        "body": json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
    })
    get = (lambda k: res[k]) if isinstance(res, dict) else (lambda k: getattr(res, k))
    try:
        body = get("json")()
    except Exception:  # noqa: BLE001 - an unreadable body is null
        body = None
    return {"ok": get("ok"), "status": get("status"), "body": body}


def push_to_entra(agent: dict, target: dict) -> Dict[str, Any]:
    return push_provision(to_entra_agent_payload(agent), target)


def push_to_okta(agent: dict, target: dict) -> Dict[str, Any]:
    return push_provision(to_okta_scim_payload(agent), target)
