"""Differential replay: the GraphQL and gRPC importers (SDL / introspection / .proto / descriptor set parsers included) against the TypeScript reference."""
import pytest

from atlas_pca import actions_import_graphql as G
from atlas_pca import actions_import_grpc as P
from base_oracle import load_ref, run

COUNT, CASES = load_ref("actions-import-sdl")


def _gschema(s):
    return {"types": [[k, v] for k, v in s["types"].items()], **{k: s[k] for k in ("query", "mutation", "subscription") if k in s}}


def _pmodel(m):
    return {"messages": [[k, v] for k, v in m["messages"].items()], "enums": [[k, v["values"]] for k, v in m["enums"].items()], "services": m["services"]}


MAP = {
    "importGraphql": G.import_graphql,
    "parseGraphqlSdl": lambda s: _gschema(G.parse_graphql_sdl(s)),
    "fromIntrospection": lambda d: _gschema(G.from_introspection(d)),
    "importGrpc": P.import_grpc,
    "parseProto": lambda s: _pmodel(P.parse_proto(s)),
    "parseDescriptorSet": lambda b: _pmodel(P.parse_descriptor_set(b)),
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
