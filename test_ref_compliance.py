"""The compliance evidence module (atlas_pca.compliance) replayed against vectors generated from the TypeScript reference
(@atlasauth/pca-compliance): AuditEvent normalisation, the control-mapping table, per-framework compliance reports, their JSON
and Markdown renderers, and the console-activity framework report. Hostile shapes included: the reports must match text for text."""
import pytest

from atlas_pca import compliance as C
from base_oracle import load_ref, run

COUNT, CASES = load_ref("compliance")

MAP = {
    "constants": lambda: {"COMPLIANCE_FRAMEWORKS": list(C.COMPLIANCE_FRAMEWORKS), "CONTROL_MAPPINGS": C.CONTROL_MAPPINGS},
    "controlMappings": C.control_mappings,
    "toAuditEvent": C.to_audit_event,
    "toComplianceReport": C.to_compliance_report,
    "renderJson": C.render_json,
    "renderMarkdown": C.render_markdown,
    "frameworkReport": C.framework_report,
    "frameworkReportToMarkdown": C.framework_report_to_markdown,
}


def test_corpus_is_the_full_oracle():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
