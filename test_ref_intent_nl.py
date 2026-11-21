"""Replays the reference corpus for the natural-language facade compiler (nl_prompt, parse_nl_policy, nl_facade_compiler)."""
import gzip
import json
import os

from atlas_pca.facade import BUILTIN_ACTIONS
from atlas_pca.intent_compilers import nl_facade_compiler, nl_prompt, parse_nl_policy, run_compilers

DATA = os.path.join(os.path.dirname(__file__), "test-data", "ref-intent-nl-java.json.gz")


def _cat(extras):
    if extras is None:
        return None
    return BUILTIN_ACTIONS + [dict(e, verb=e["connector"] + "." + e["action"]) for e in extras]


def _run(c):
    fn, args = c["fn"], c["args"]
    if fn == "nlPrompt":
        return nl_prompt(args[0], _cat(args[1]))
    if fn == "parseNLPolicy":
        return parse_nl_policy(args[0], _cat(args[1]))
    text, raw, extras = args
    seen = []

    def complete(p):
        seen.append(p)
        if raw == "THROWS":
            raise RuntimeError("llm down")
        return raw
    comp = nl_facade_compiler("nl", "fam", complete)
    if fn == "nlCompile":
        out = comp.compile({"text": text, "catalog": _cat(extras)})
        return {"prompt": seen[0], "output": out}
    return run_compilers({"text": text, "catalog": _cat(extras)}, [comp])


def test_nl_corpus():
    cases = json.load(gzip.open(DATA))["cases"]
    bad = []
    for c in cases:
        try:
            got = _run(c)
            ok = got == c["out"]
        except Exception as e:  # noqa: BLE001
            got, ok = repr(e), isinstance(c["out"], dict) and "$throws" in c["out"]
        if not ok:
            bad.append((c["name"], got))
    assert not bad, bad[:3]
