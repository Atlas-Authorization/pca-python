"""Static analyzability of authority (port of the TypeScript reference, @atlasauth/pca-analyzer): what can this whole delegated
authority EVER do? The bounded decision engine, relational queries, quantitative exposure, residual policies, data filters, narrowing,
coverage, minimal-flip counterfactuals, schema validation and the policy test runner. Policies and results are plain JSON trees.

`admits_concrete(policy, action)` is the exact admission check atlas_pca.authzen takes as its injected `admits_concrete` callable;
`decide_action(to_model(policy), action)` yields the ternary decision ('allow' | 'escalate' | 'deny')."""
from .analyzer_core import *  # noqa: F401,F403
from .analyzer_core import (  # noqa: F401
    ABSENT, DEFAULT_MAX_COMBINATIONS, FRESH_STRING, FULL_INTERVAL, admits, admits_action, admits_concrete, always_allows, always_denies,
    analyze_caveats, bound_of, collect, collect_probes, context_of_action, decide, decide_action, decision_at_context, disjoint, equivalent,
    field_probes, interval_empty, intent_conformance, normalize_policy, numeric_conjunction_satisfiable, predicate_numeric_satisfiable,
    probe_set, product_size, reachable, rep_to_action, representatives, search, subsumes, tighten_interval, to_model, veto_applies,
    vetoes_from_constitution,
)
from .analyzer_coverage import coverage, coverage_gate, minimal_flip, permit_id, witness_of  # noqa: F401
from .analyzer_exposure import (  # noqa: F401
    dag_exposure, delegation_envelope, diff_gate, diff_policies, escalation_surface, find_with_backend, max_exposure, resolve_action,
    thresholds_of,
)
from .analyzer_narrowing import (  # noqa: F401
    ACCESS_REQUEST_SIG_DOMAIN, sign_access_request, suggest_narrowing, verify_access_request,
)
from .analyzer_residual import (  # noqa: F401
    eval_filter, eval_ucast, evaluate_residual, policy_digest_of, residual, residual_policy, to_filter, to_ucast, what_may_i_do,
)
from .analyzer_validate import (  # noqa: F401
    POLICY_TESTS_KIND, POLICY_TESTS_SIG_DOMAIN, decide_all, generate_boundary_tests, policy_tests_doc, run_policy_tests, sign_policy_tests,
    validate_policy_against_schema, verb_shapes, verb_shapes_from_action_defs, verify_policy_tests,
)
