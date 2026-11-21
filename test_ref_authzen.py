"""Differential replay of the AuthZEN PDP, handler and search APIs (atlas_pca.authzen) against the vectors generated from the
TypeScript reference (@atlasauth/pca-authzen). The PDP / provider tables below mirror the ones the generator names."""
import pytest

from atlas_pca import authzen as A
from base_oracle import canon, load_ref, run

COUNT, CASES = load_ref("authzen")
NOW = 1_000_000


def _boom(_r=None):
    raise RuntimeError("boom")


def _bad_tool(_n):
    raise RuntimeError("bad tool")


CFG = {
    "none": {"resolve": lambda r: None, "now": lambda: NOW},
    "throws": {"resolve": _boom, "now": lambda: NOW},
    "noauth": {"resolve": lambda r: {"grant": {}, "policy": {}}, "now": lambda: NOW},
    "auth": {"resolve": lambda r: {"grant": {}, "policy": {}}, "authorizer": lambda i: {"allow": True}, "now": lambda: NOW},
    "max2": {"resolve": lambda r: None, "max_evaluations": 2, "now": lambda: NOW},
    "toolmap": {"resolve": lambda r: None, "tool_capability": lambda n: "cap." + n, "now": lambda: NOW},
    "toolthrow": {"resolve": lambda r: None, "tool_capability": _bad_tool, "now": lambda: NOW},
}


def _u(i, **extra):
    return dict({"type": "user", "id": i}, **extra)


PROV = {
    "none": {},
    "full": {
        "search_subject": lambda r: {"results": [_u("a"), _u("b"), {"type": "group", "id": "g"}, _u("a"), {"id": "a", "type": "user"}],
                                     "page": {"next_token": "", "total": 3, "properties": {"k": 1}}, "context": {"c": 1}},
        "search_resource": lambda r: {"results": [{"type": "doc", "id": "1"}, {"type": "doc", "id": "2"}, {"type": "user", "id": "x"}], "page": {"next_token": "n1"}},
        "search_action": lambda r: {"results": [{"name": "read"}, {"name": "write"}, {"name": "read"}, {"name": "read", "properties": {"p": 1}}]},
    },
    "nopage": {"search_subject": lambda r: {"results": [_u("a"), _u("b")]}, "search_resource": lambda r: {"results": []}, "search_action": lambda r: {"results": []}},
    "emptyprops": {"search_subject": lambda r: {"results": [_u("a")], "page": {"next_token": "z", "properties": {}}, "context": {}}},
    "bad": {"search_subject": lambda r: {"results": [None]}, "search_resource": lambda r: {"results": [5]}, "search_action": lambda r: {"results": [None, 5]}},
    "notarray": {"search_subject": lambda r: {"results": "x"}, "search_resource": lambda r: {}, "search_action": lambda r: {"results": None}},
    "throws": {"search_subject": _boom, "search_resource": _boom, "search_action": _boom},
    "echo": {k: (lambda r: {"results": [], "context": {"saw": r}}) for k in ("search_subject", "search_resource", "search_action")},
    "partial": {"search_resource": lambda r: {"results": []}},
}


def _pdp(c):
    return A.authzen_pdp(CFG[c])


def _eq(got, out, case):
    """The verifier's own check map / reason text is language-specific: the verify-stage cases compare decision + stage."""
    if case["name"].endswith(("/pc17", "/pc18")) and out["context"]["reason_admin"].get("stage") == "verify":
        g, o = got["context"]["reason_admin"], out["context"]["reason_admin"]
        return got["decision"] == out["decision"] and g.get("stage") == o["stage"] == "verify"
    return canon(got) == canon(out)


MAP = {
    "isAccessEvaluationRequest": A.is_access_evaluation_request,
    "isAccessEvaluationsRequest": A.is_access_evaluations_request,
    "isCoazToolAuthorizationRequest": A.is_coaz_tool_authorization_request,
    "isAuthzenSubject": A.is_authzen_subject,
    "isAuthzenAction": A.is_authzen_action,
    "isAuthzenResource": A.is_authzen_resource,
    "isSubjectSearch": A.is_subject_search,
    "isResourceSearch": A.is_resource_search,
    "isActionSearch": A.is_action_search,
    "defaultToAction": A.default_to_action,
    "approvalOf": A.approval_of,
    "isApprovalRequired": A.is_approval_required,
    "pdp.evaluate": lambda c, r: _pdp(c).evaluate(r),
    "pdp.evaluations": lambda c, r: _pdp(c).evaluations(r),
    "pdp.evaluateTool": lambda c, r: _pdp(c).evaluate_tool(r),
    "authzenHandler": lambda c, r: A.authzen_handler(_pdp(c))(r),
    "authzenSearchHandler": lambda p, r: A.authzen_search_handler(PROV[p])(r),
    "searchMetadata": lambda base, p: A.search_metadata(base, PROV[p]),
}


def test_every_oracle_function_is_replayed():
    assert set(CASES) == set(MAP) and COUNT == sum(len(v) for v in CASES.values())


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn], compare=_eq)
