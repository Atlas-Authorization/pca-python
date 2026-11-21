"""Replay of the authoring-file text loader (YAML 1.2 core and JSON, with source positions) against the reference corpus. Needs ruamel.yaml
(the `yaml` extra) for the syntax layer. A syntax error is compared by class (the parser's wording is its own); a result where this loader
is deliberately STRICTER than the reference (see atlas_pca.actions_yaml_load) must be a single "not YAML" refusal on a text that uses one of
the documented constructs, never a different successful value."""
import os
import re

import pytest

pytest.importorskip("ruamel.yaml")
from atlas_pca.actions_author import load_actions_text  # noqa: E402
from base_oracle import HERE, load  # noqa: E402

CASES = load("actions-yaml-load-py", os.path.join(HERE, "test-data", "ref-actions-yaml-load-py.json.gz"))[1]["loadActionsText"]
SYNTAX = ("not YAML", "YAML warning", "not JSON")
STRICTER = re.compile(r"(^|\s)!(?!!(str|map|seq)\b)\S|\? \[|\r(?!\n)|!!binary")


def _norm(r):
    return {k: r[k] for k in ("defs", "notes", "errors", "locs", "rules", "ns") if k in r}


def test_matches_the_reference():
    bad, stricter = [], 0
    for c in CASES:
        text, fmt = c["args"]
        got, exp = load_actions_text(text, fmt), c["out"]
        e0 = (exp.get("errors") or [{}])[0].get("message", "")
        if e0.startswith(SYNTAX):
            ok = (len(got["errors"]) == 1 and got["defs"] == [] and got["errors"][0]["message"].startswith(SYNTAX[:2] if fmt == "yaml" else SYNTAX[2]))
        elif _norm(got) == _norm(exp):
            ok = True
        else:
            ok = bool(STRICTER.search(text)) and len(got["errors"]) == 1 and got["errors"][0]["message"].startswith("not YAML") and got["defs"] == []
            stricter += ok
        if not ok:
            bad.append((c["name"], text[:80], str(got)[:300], str(exp)[:300]))
    assert not bad, "%d of %d differ:\n%s" % (len(bad), len(CASES), "\n".join(map(str, bad[:12])))
