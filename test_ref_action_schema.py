"""Replays the TS-reference oracle of the site-signed action schema (testdata/ref-action-schema.json.gz, 173 cases, and ref-action-schema-draft.json.gz,
104 cases): every exported constant, the value-dependent reversibility, the wallet floor test, verb lookup, signing under every suite (byte-exact), the
discovery key entry, the content digest, verification (every refusal), the MCP hint classes and the two drafting importers (todo strings compared exactly
and in order). Every fn has a handler and the totals are asserted; a reference refusal needs a native exception. A verification reason that carries a
caught error's text (``schema verification error:``, ``malformed schema:``) is compared by prefix."""
import os

import pytest

from atlas_pca import action_schema as S
from atlas_pca import intent_v2 as V
from atlas_pca.agent import generate_pq_keypair
from base_oracle import HERE, canon, load, run

COUNT, CASES = load("action-schema", os.path.join(HERE, "testdata", "ref-action-schema.json.gz"))
DRAFT_COUNT, DRAFT_CASES = load("action-schema-draft", os.path.join(HERE, "testdata", "ref-action-schema-draft.json.gz"))
PREFIXES = ("schema verification error:", "malformed schema:")


def _re(p):
    return {"$regex": "^%s$" % p.pattern}


def _constants():
    return {
        "ACTION_SCHEMA_DOMAIN": V.ACTION_SCHEMA_DOMAIN, "ACTION_SCHEMA_REF_DOMAIN": V.ACTION_SCHEMA_REF_DOMAIN, "ACTION_SCHEMA_KIND": V.ACTION_SCHEMA_KIND,
        "WELL_KNOWN_PCA_ACTIONS_PATH": S.WELL_KNOWN_PCA_ACTIONS_PATH, "SENSITIVITIES": list(V.SENSITIVITIES),
        "SCHEMA_REVERSIBILITY": list(V.SCHEMA_REVERSIBILITY), "PARAM_TYPES": list(V.PARAM_TYPES), "PARAM_TYPES_V2": list(V.PARAM_TYPES_V2),
        "SCHEMA_V2_EFFECTS": list(V.SCHEMA_V2_EFFECTS), "SCHEMA_V2_CAVEATS": list(V.SCHEMA_V2_CAVEATS), "SCHEMA_V2_PRULES": list(V.SCHEMA_V2_PRULES),
        "SCHEMA_V2_CONTEXT": list(V.SCHEMA_V2_CONTEXT), "SCHEMA_V2_TAGS": list(V.SCHEMA_V2_TAGS), "SCHEMA_V2_PROVENANCE": list(V.SCHEMA_V2_PROVENANCE),
        "MAX_SCHEMA_VERBS": V.MAX_SCHEMA_VERBS, "MAX_SCHEMA_PARAMS": V.MAX_SCHEMA_PARAMS, "MAX_SCHEMA_VALUES": V.MAX_SCHEMA_VALUES,
        "DEFAULT_MAX_LEN": V.DEFAULT_MAX_LEN, "DEFAULT_MAX_ITEMS": V.DEFAULT_MAX_ITEMS, "PARAM_PATH_RE": _re(V.PARAM_PATH_RE),
        "PARAM_PATH_RE_V2": _re(V.PARAM_PATH_RE_V2), "UNIT_ID_RE": _re(V.UNIT_ID_RE), "WALLET_FLOOR_PREFIXES": list(S.WALLET_FLOOR_PREFIXES),
        "WALLET_FLOOR_EXACT": list(S.WALLET_FLOOR_EXACT)}


def _suite(su):
    if su is None:
        return None, None
    pq = generate_pq_keypair("ML-DSA-65", su["pqSeed"]) if su.get("pqSeed") is not None else None
    return su["alg"], pq


def _sign(doc, kid, secret, su):
    alg, pq = _suite(su)
    return S.sign_action_schema(doc, kid, secret, alg, pq)


def _key_of(kid, secret, su):
    alg, pq = _suite(su)
    return S.action_schema_key_of(kid, secret, alg, pq)


def _same(got, out, _case):
    if isinstance(out, dict) and isinstance(out.get("reason"), str) and out["reason"].startswith(PREFIXES):
        pre = next(p for p in PREFIXES if out["reason"].startswith(p))
        return (isinstance(got, dict) and got.get("ok") is False and isinstance(got.get("reason"), str) and got["reason"].startswith(pre)
                and set(got) == set(out))
    return canon(got) == canon(out)


HANDLERS = {
    "constants": _constants,
    "reversibilityOf": S.reversibility_of,
    "floorApplies": S.floor_applies,
    "schemaVerb": V.schema_verb,
    "signActionSchema": _sign,
    "actionSchemaKeyOf": _key_of,
    "actionSchemaDigest": V.action_schema_digest,
    "verifyActionSchema": V.verify_action_schema,
    "reversibilityFromMcpHints": S.reversibility_from_mcp_hints,
    "draftSchemaFromMcpTools": S.draft_schema_from_mcp_tools,
    "draftSchemaFromOpenApi": S.draft_schema_from_openapi,
}
TOTALS = {"constants": 1, "reversibilityOf": 20, "floorApplies": 19, "schemaVerb": 9, "signActionSchema": 12, "actionSchemaKeyOf": 6, "actionSchemaDigest": 4,
          "verifyActionSchema": 30, "reversibilityFromMcpHints": 9, "draftSchemaFromMcpTools": 31, "draftSchemaFromOpenApi": 32}
DRAFT_TOTALS = {"draftSchemaFromOpenApi": 16, "reversibilityFromMcpHints": 9, "reversibilityOf": 72, "schemaVerb": 7}


def test_every_corpus_fn_has_a_handler_and_the_total_is_pinned():
    assert COUNT == 173 and set(CASES) == set(HANDLERS)
    assert {fn: len(cs) for fn, cs in CASES.items()} == TOTALS
    assert DRAFT_COUNT == 104 and set(DRAFT_CASES) <= set(HANDLERS)
    assert {fn: len(cs) for fn, cs in DRAFT_CASES.items()} == DRAFT_TOTALS


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_action_schema_replay(fn):
    assert run(CASES[fn], HANDLERS[fn], compare=_same) == (TOTALS[fn], 0)


@pytest.mark.parametrize("fn", sorted(DRAFT_TOTALS))
def test_action_schema_draft_replay(fn):
    assert run(DRAFT_CASES[fn], HANDLERS[fn], compare=_same) == (DRAFT_TOTALS[fn], 0)
