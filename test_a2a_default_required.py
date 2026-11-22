"""A2A task verification is default-deny like the reference: the stateless required checks (revocation included) must PASS."""
from atlas_pca import a2a as A

PCA = {"cap_chain": [{"issuer": "p"}], "action": {}}
TASK = A.attach_pca_to_a2a_task({"id": "t1"}, PCA)
ALL = {n: "pass" for n in A.DEFAULT_REQUIRED_CHECKS}


def _opts(checks, **kw):
    return {"aud": "rs-1", "grant": {"issuer": "p"}, "verify": lambda p, g, o, c: {"allow": True, "checks": checks, "reasons": []}, **kw}


def test_every_default_check_must_pass():
    assert A.verify_a2a_task(TASK, _opts(ALL))["ok"] is True
    for n in A.DEFAULT_REQUIRED_CHECKS:
        assert A.verify_a2a_task(TASK, _opts({**ALL, n: "not-enforced"}))["ok"] is False
        missing = {k: v for k, v in ALL.items() if k != n}
        assert A.verify_a2a_task(TASK, _opts(missing))["ok"] is False


def test_an_explicit_list_replaces_the_default():
    assert A.verify_a2a_task(TASK, _opts({"audience": "pass"}, requireChecks=["audience"]))["ok"] is True
