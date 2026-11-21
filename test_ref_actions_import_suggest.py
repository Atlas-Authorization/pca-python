"""Differential replay: the suggestion rules (validation, digest, signature, matching, application), the model assist and the provider adapters
against the TypeScript reference."""
import hashlib

import pytest

from atlas_pca import actions as A
from atlas_pca import actions_import_model as M
from atlas_pca import actions_import_suggest as S
from atlas_pca import ed25519
from base_oracle import load_ref, run

ed25519.allow_insecure_signer()  # signing needs `cryptography` otherwise; the vectors use throwaway seeds
COUNT, CASES = load_ref("actions-import-suggest")
CORE = A.CORE_REGISTRY


def _rules(x):
    return S.default_rules() if x == "default" else x


def _reg(x):
    return CORE if x == "core" else None


def _seed(label):
    return hashlib.sha256(("atlas-pca-conformance/" + label).encode()).digest()


class _Adapter:
    def __init__(self, spec):
        self.id = spec["id"]
        self.version = spec.get("version")
        self._spec = spec

    def complete(self, req):
        if "throws" in self._spec:
            raise RuntimeError(self._spec["throws"])
        return self._spec.get("answer")


def _facts(d):
    return S.facts_of(d)


def _provider(cfg, spec, req):
    calls = []

    class Res:
        ok = spec.get("ok", True)
        status = spec.get("status", 200)

        def json(self):
            if spec.get("badjson"):
                raise RuntimeError("bad json")
            return spec.get("json")

    def fetch(url, init):
        calls.append({"url": url, "headers": init["headers"], "body": init["body"]})
        if "throws" in spec:
            raise RuntimeError(spec["throws"])
        return Res()

    a = M.provider_adapter(M.ModelEnvConfig(cfg["provider"], cfg["model"], cfg["apiKey"]), fetch)
    try:
        return {"call": calls[0] if calls else None, "text": a.complete(req)}
    except Exception as e:  # noqa: BLE001
        return {"call": calls[0] if calls else None, "error": str(e)}


MAP = {
    "stem": S.stem,
    "factsOf": _facts,
    "DEFAULT_RULES": S.default_rules,
    "DEFAULT_RULES_SEALED_DIGEST": lambda: S.default_rules_sealed()["digest"],
    "suggestRulesError": lambda r, k=None: S.suggest_rules_error(_rules(r), None if k is None else set(k)),
    "rulesDigest": lambda r: S.rules_digest(_rules(r)),
    "sealRules": S.seal_rules,
    "signRules": lambda r, kid, label: S.sign_rules(r, kid, _seed(label)),
    "verifyRules": S.verify_rules,
    "suggestWithRules": lambda d, r, g=None: S.suggest_with_rules(d, _rules(r), _reg(g)),
    "applySuggestion": S.apply_suggestion,
    "unionSuggestions": S.union_suggestions,
    "vocabulary": lambda g: M.vocabulary(_reg(g) or CORE),
    "promptDigest": lambda g: M.prompt_digest(_reg(g) or CORE),
    "buildRequest": lambda d: M.build_request(d, CORE),
    "parseTraitList": lambda t: M.parse_trait_list(t, CORE),
    "suggestWithModels": lambda d, ads: M.suggest_with_models(d, [_Adapter(a) for a in ads], CORE),
    "modelConfigFromEnv": lambda env, flags: M.model_config_from_env(env, flags).to_map(),
    "providerAdapterComplete": _provider,
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
