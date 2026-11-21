"""Differential replay of the TypeScript reference (@atlasauth/pca-goal interpret): candidate extraction, slot filling, the rule, form
and model interpreters, prompts and keys, grounding, vendor completions over an injected fetch, the typed refund form and the lexical
comparator. A shipped ontology travels by name and is resolved from the shipped data."""
import pytest

from atlas_pca import goal_interpret as I
from atlas_pca import goal_ontologies as OS
from atlas_pca import goal_roundtrip as RT
from base_oracle import load_ref, run

COUNT, BY_FN = load_ref("goal-interpret")


def _o(x):
    return OS.shipped_ontology(x) if isinstance(x, str) and OS.shipped_ontology(x) is not None else x


def _src(s):
    return {} if s is None else {"sources": s}


def _fill(on, tid, text, lc):
    on = _o(on)
    return I.fill_template(next(z for z in on["templates"] if z["id"] == tid), on, text, lc)


def _llm(on, text, src, mode, inc, lc):
    def complete(_p):
        if mode.get("throw"):
            raise RuntimeError("boom")
        return mode["raw"]
    return I.llm_interpreter("m", "f", complete, bool(inc), lc).interpret(dict({"principal": "p1", "text": text, "ontology": _o(on)}, **_src(src)))


def _grounded(on, tid, sn, v, txt):
    on = _o(on)
    t = next(z for z in on["templates"] if z["id"] == tid)
    s = next(z for z in t["slots"] if z["name"] == sn)
    return I.grounded(s, v, I.extract_candidates(txt, on), on)


class _Resp:
    def __init__(self, ok, status, body):
        self.ok, self.status, self._body = ok, status, body

    def json(self):
        return self._body


def _vendor(_x, kind, cfg, fake, system, user):
    req = {}
    if not fake:  # the generator's plain success stub
        fake = {"ok": True, "status": 200, "body": {"content": [{"type": "text", "text": "x"}]} if kind == "anthropic" else {"choices": [{"message": {"content": "x"}}]}}

    def fetch(url, init):
        req.update({"url": url, "method": init["method"], "headers": init["headers"], "body": init["body"]})
        if fake.get("throwMsg"):
            raise RuntimeError(fake["throwMsg"])
        return _Resp(fake.get("ok"), fake.get("status"), fake.get("body"))
    if kind == "anthropic":
        c = I.anthropic_completion(cfg["apiKey"], cfg["model"], fetch, cfg.get("maxTokens", 1024))
    else:
        c = I.openai_completion(cfg["apiKey"], cfg["model"], fetch, cfg.get("baseUrl"))
    try:
        return {"text": c({"system": system, "user": user}), "req": req}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e), "req": req}


FNS = {
    "slotStemsOf": I.slot_stems, "sourceDigest": I.source_digest,
    "extractCandidates": lambda on, text, lc: I.extract_candidates(text, _o(on), lc), "fillTemplateById": _fill,
    "interpretRule": lambda on, text, src, lc: I.rule_interpreter("rule", lc).interpret(dict({"principal": "p1", "text": text, "ontology": _o(on)}, **_src(src))),
    "buildPromptOf": lambda on, text, src, inc: I.build_prompt(dict({"principal": "p", "text": text, "ontology": _o(on)}, **_src(src)), inc),
    "interpretForm": lambda on, f, text: I.form_interpreter().interpret(
        dict({"principal": "p1", "text": text, "ontology": _o(on)}, **({} if f is None else {"form": f}), **({"sources": ["s"]} if text == "form text" else {}))),
    "interpretLlm": _llm, "promptKeyOf": lambda _x, m, s, u: I.prompt_key(m, {"system": s, "user": u}),
    "replayLookup": lambda _x, m, rec, s, u: I.replay_completion(m, rec)({"system": s, "user": u}),
    "parseTemplateJSON": I.parse_template_json, "groundedOf": _grounded, "vendor": _vendor,
    "interpretRefundForm": lambda f, ont, pr: I.interpret_form(f, ont, "pr1" if pr is None else pr),
    "lexicalCompare": lambda on, tx, ex: RT.lexical_comparator(_o(on)).equivalent(tx, ex),
}


def test_every_function_is_covered():
    assert set(BY_FN) == set(FNS)


@pytest.mark.parametrize("fn", sorted(FNS))
def test_matches_reference(fn):
    ran, _ = run(BY_FN[fn], FNS[fn])
    assert ran == len(BY_FN[fn])
