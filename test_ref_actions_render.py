"""Differential replay: approval-render wrappers, facade specs and provenance facts against the TypeScript reference."""
import pytest

from atlas_pca import actions_render as R
from base_oracle import load_ref, run

COUNT, CASES = load_ref("actions-render-facade")


def _opt(c):
    return lambda _d: c


def _prov_actions(ds, c, probes):
    f = R.provenance_actions(ds, None, _opt(c))
    return [f({"verb": v}) for v in probes]


MAP = {
    "renderApproval": lambda d, p, c: R.render_approval_with(d, p, _opt(c)),
    "renderDigestForAction": lambda d, p, pc, c: R.render_digest_for_action(d, p, pc, _opt(c)),
    "approverRenderCheck": lambda d, p, r, c: R.approver_render_check(d, p, r, _opt(c)),
    "singleTapAllowed": R.single_tap_allowed,
    "renderersFromDefs": lambda ds, v, p, c: R.renderers_from_defs(ds, _opt(c))(v, "", p),
    "specOfDef": lambda d, r, c: R.spec_of_def(d, None, _opt(c), r),
    "facadeSpecs": lambda ds, r, c: R.facade_specs(ds, None, _opt(c), r),
    "provenanceInfoOf": lambda d, c: R.provenance_info_of(d, None, _opt(c)),
    "provenanceActions": _prov_actions,
}


def test_every_function_is_covered():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
