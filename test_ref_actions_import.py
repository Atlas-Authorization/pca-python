"""Differential replay: the OpenAPI / MCP / JSON Schema / AsyncAPI importers and their shared helpers against the TypeScript reference."""
import pytest

from atlas_pca import actions_import_asyncapi as AA
from atlas_pca import actions_import_common as C
from atlas_pca import actions_import_jsonschema as JS
from atlas_pca import actions_import_mcp as MC
from atlas_pca import actions_import_openapi as OA
from base_oracle import load_ref, run

COUNT, CASES = load_ref("actions-import-core")

MAP = {
    "tokensOf": C.tokens_of, "humanize": C.humanize, "verbOf": C.verb_of, "aliasOf": C.alias_of, "paramSeg": C.param_seg, "clip": C.clip,
    "pointer": C.pointer, "resolveLimits": C.resolve_limits,
    "checkParsed": lambda root, over: C.check_parsed(root, C.resolve_limits(over)),
    "textSizeCheck": lambda text, over: C.text_size_check(text, C.resolve_limits(over)),
    "importOpenApi": OA.import_openapi, "importMcp": MC.import_mcp, "importJsonSchema": JS.import_json_schema, "importAsyncApi": AA.import_asyncapi,
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
