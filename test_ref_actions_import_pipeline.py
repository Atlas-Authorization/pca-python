"""Differential replay: the import pipeline, the importer registry, the JSON Lines forms and the suggestion evaluation against the TypeScript
reference (the review half of the same corpus is replayed by test_ref_actions_review)."""
import pytest

from atlas_pca import actions_import_eval as EV
from atlas_pca import actions_import_pipeline as PL
from base_oracle import load_ref, run

COUNT, CASES = load_ref("actions-import-review")


class _Adapter:
    def __init__(self, spec):
        self.id = spec["id"]
        self.version = spec.get("version")
        self._spec = spec

    def complete(self, req):
        if "throws" in self._spec:
            raise RuntimeError(self._spec["throws"])
        return self._spec.get("answer")


def _suggest_opts(s):
    o = dict(s)
    if o.get("rules") == "default":
        from atlas_pca.actions_import_suggest import default_rules
        r = default_rules()
        o["rules"] = {**r, "rules": r["rules"][:20]}
    if o.get("models") is not None:
        o["models"] = [_Adapter(m) for m in o["models"]]
    return o


def _eval(entries, rules=None, alpha=None):
    return EV.eval_suggest(entries, None if rules in (None, "default") else rules, None, alpha)


MAP = {
    "parseHandTsv": EV.parse_hand_tsv,
    "parseCorpusJsonl": EV.parse_corpus_jsonl,
    "realSplit": EV.real_split,
    "importCorpus": EV.import_corpus,
    "evalSuggest": _eval,
    "renderEvalMarkdown": EV.render_eval_markdown,
    "floorFailures": EV.floor_failures,
    "importActions": PL.import_actions,
    "IMPORTERS": PL.run_importer,
    "importAndSuggest": lambda kind, d, op, so: PL.import_and_suggest(kind, d, op, _suggest_opts(so)),
    "suggestDefs": lambda d, s=None: PL.suggest_defs(d, _suggest_opts(s or {})),
    "defsToJsonl": PL.defs_to_jsonl,
    "jsonlToDefs": PL.jsonl_to_defs,
}


def test_every_function_is_covered():
    # the remaining functions of the corpus are the review flow
    assert set(CASES) - set(MAP) == {"confirmDef", "verifyAttestation", "reviewStatus", "revertStale", "reviewPriority", "prepareReview", "reviewQueueOrder"}


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
