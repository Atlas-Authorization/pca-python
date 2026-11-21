"""One JSON Schema plus a caller-given verb to one def (native port of import/jsonschema.ts of the TypeScript reference @atlasauth/pca-actions)."""
from typing import Any

from .actions import _VERB_RE, EFFECTS, ActionKitError
from .actions_import_common import add_todo, clip, emit_def, finish, flatten_object, is_obj, is_str, new_budget, new_ctx, resolve_schema


def import_json_schema(schema: Any, opts: dict) -> dict:
    """`opts`: the common import options plus `verb` (required, `<ns>.<noun>.<action>`), `title`, `description`, `effects` (default ["update"])."""
    c = new_ctx("jsonschema", schema, opts)
    verb = opts.get("verb")
    if not is_str(verb) or _VERB_RE.fullmatch(verb) is None or not verb.startswith(opts["ns"] + "."):
        raise ActionKitError("bad_verb", "verb must be a valid verb in namespace '%s'" % opts["ns"])
    effects = opts.get("effects")
    effects = ["update"] if effects is None else effects
    if not isinstance(effects, list) or len(effects) == 0 or not all(is_str(e) and e in EFFECTS for e in effects):
        raise ActionKitError("bad_effects", "effects must be 1+ known effects")
    if not is_obj(schema):
        raise ActionKitError("bad_source", "a JSON Schema must be an object")
    bud = new_budget(c)
    root = resolve_schema(schema, c, bud, verb)
    params: dict = {}
    if root.get("type") == "object" or is_obj(root.get("properties")):
        flatten_object(root, c, bud, verb, params)
    else:
        add_todo(c, verb, "not_object", "the schema is not an object schema: the def has no parameters")
    title = opts.get("title")
    description = opts.get("description")
    emit_def(
        c, "_".join(verb.split(".")[1:]), effects, "one", params, {}, verb=verb,
        title=title if title is not None else root["title"] if is_str(root.get("title")) else None,
        description=description if description is not None else clip(root.get("description"), 600),
    )
    return finish(c)
