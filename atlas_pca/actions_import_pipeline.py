"""`import -> suggest` as one call, the text forms the CLI prints and reads (JSON Lines of defs), and the importer registry (native port of
import/pipeline.ts and import/registry.ts of the TypeScript reference @atlasauth/pca-actions). Pure: no file system, no network. The YAML a
`defsToYaml` writes needs a YAML emitter; none is available without a dependency, so it is not ported (see actions_author for the loader side)."""
import json
from typing import Any, Dict, List, Optional

from .actions import CORE_REGISTRY, ActionKitError, validate_def, _JS_WS, _u16key
from .actions_import_asyncapi import import_asyncapi
from .actions_import_common import IMPORT_KINDS
from .actions_import_graphql import import_graphql
from .actions_import_grpc import import_grpc
from .actions_import_jsonschema import import_json_schema
from .actions_import_mcp import import_mcp
from .actions_import_model import suggest_with_models
from .actions_import_openapi import import_openapi
from .actions_import_suggest import apply_suggestion, default_rules, rules_digest, suggest_with_rules
from .pca import canonicalize_strict

MAX_IMPORT_OPS = 20_000


def import_actions(kind: Any, source: Any, opts: dict) -> dict:
    """Import one source of the given kind. Every def is `unreviewed`."""
    if kind == "openapi":
        return import_openapi(source, opts)
    if kind == "mcp":
        return import_mcp(source, opts)
    if kind == "graphql":
        return import_graphql(source, opts)
    if kind == "grpc":
        return import_grpc(source, opts)
    if kind == "asyncapi":
        return import_asyncapi(source, opts)
    if kind == "jsonschema":
        return import_json_schema(source, opts)
    raise ActionKitError("bad_kind", "unknown import kind '%s' (one of %s)" % (kind, ", ".join(IMPORT_KINDS)))


def suggest_defs(defs: List[dict], o: Optional[dict] = None) -> dict:
    """Suggest for already imported defs: new defs (state `suggested`) and the model errors, if any. `o`: mode ("rules" default, "model", "none"),
    rules, registry, models (adapter objects)."""
    o = o or {}
    mode = o.get("mode") or "rules"
    if mode == "none":
        return {"defs": list(defs), "errors": []}
    registry = o.get("registry") or CORE_REGISTRY
    rules = o.get("rules") or default_rules()
    digest = rules_digest(rules)
    out: List[dict] = []
    errors: List[dict] = []
    for d in defs:
        s = suggest_with_rules(d, rules, registry)
        models = None
        if mode == "model":
            run = suggest_with_models(d, o.get("models") or [], registry)
            errors.extend({"verb": d["verb"], **e} for e in run["errors"])
            s = {"traits": sorted(dict.fromkeys([*s["traits"], *run["suggestion"]["traits"]]), key=_u16key), "roles": s["roles"], "tags": s["tags"], "fired": s["fired"]}
            models = run["models"]
        out.append(apply_suggestion(d, s, {"rules": {"version": rules["version"], "digest": digest, "fired": s["fired"]}, **({"models": models} if models else {})}))
    return {"defs": out, "errors": errors}


def import_and_suggest(kind: Any, source: Any, opts: dict, suggest: Optional[dict] = None) -> dict:
    r = import_actions(kind, source, opts)
    s = suggest_defs(r["defs"], suggest)
    return {**r, "defs": s["defs"], "suggestErrors": s["errors"]}


# ---- JSON Lines ----------------------------------------------------------------------------------------------------------------

def defs_to_jsonl(defs: List[dict]) -> str:
    """One def per line, strict canonical JSON, sorted by verb: byte-reproducible."""
    return "\n".join(canonicalize_strict(d) for d in sorted(defs, key=lambda d: _u16key(d["verb"]))) + ("\n" if defs else "")


def _no_constant(c: str):
    raise ValueError("not JSON: " + c)


def jsonl_to_defs(text: str) -> List[dict]:
    """Parse and validate a JSONL file of defs. Raises ActionKitError('bad_defs') naming the first bad line."""
    out: List[dict] = []
    for i, line in enumerate(text.split("\n")):
        l = line.strip(_JS_WS)
        if len(l) == 0:
            continue
        try:
            v = json.loads(l, parse_constant=_no_constant)
        except ValueError:
            raise ActionKitError("bad_defs", "line %d: not JSON" % (i + 1))
        bad = validate_def(v)
        if bad is not None:
            raise ActionKitError("bad_defs", "line %d: %s" % (i + 1, bad))
        out.append(v)
    return out


# ---- importer registry (the shape the CLI reads) -------------------------------------------------------------------------------

def run_importer(kind: str, doc: Any, opts: dict) -> dict:
    """`IMPORTERS[kind](document, {ns, uri?, licence?, verb?})` -> {defs, todo: ["<where>: <message>"]}. Unknown kind: KeyError."""
    if kind not in IMPORT_KINDS:
        raise KeyError(kind)
    if kind == "jsonschema" and not opts.get("verb"):
        raise ValueError("a JSON Schema import needs --verb <ns.noun.action>")
    r = import_actions(kind, doc, opts)
    return {"defs": r["defs"], "todo": ["%s: %s" % (t["where"], t["message"]) for t in r["todo"]]}
