"""run_adapter_acceptance through a tiny in-process adapter built on authorize(): the matrix must equal the expected table."""
from atlas_pca.arg_provenance import PROV_HEADER
from atlas_pca.authorize import authorize
from atlas_pca.pca import PcaHeaderError, decode_pca_header
from atlas_pca.server import PCA_HEADER
from atlas_pca.testing import ADAPTER_ACCEPTANCE_EXPECTED, acceptance_operation, run_adapter_acceptance


def _harness(options, ran_log=None):
    def send(req):
        op = acceptance_operation({"method": req["method"], "url": req["path"], "body": req["body"]})
        if op is None:
            return {"status": 403, "handlerRan": False}
        h = req["headers"]
        try:
            proof = decode_pca_header(h.get(PCA_HEADER))
        except PcaHeaderError:
            return {"status": 401, "handlerRan": False}
        r = authorize(proof, operation=op, provenance_request=(h, req["body"]), **options)
        if not r.allow:
            return {"status": r.status if r.status in (401, 403) else 403, "handlerRan": False}
        if ran_log is not None:
            ran_log.append(op)
        return {"status": 200, "handlerRan": True, "operation": r.operation}
    return send


def test_acceptance_matrix_equals_expected():
    assert PROV_HEADER  # the bundle travels in this header
    assert run_adapter_acceptance(_harness) == ADAPTER_ACCEPTANCE_EXPECTED


def test_acceptance_async_harness():
    async def harness(options):
        send = _harness(options)

        async def asend(req):
            return send(req)
        return asend
    assert run_adapter_acceptance(harness) == ADAPTER_ACCEPTANCE_EXPECTED


def test_acceptance_detects_a_fail_open_adapter():
    # an adapter that runs the handler without authorizing must NOT equal the table
    got = run_adapter_acceptance(lambda o: (lambda req: {"status": 200, "handlerRan": True}))
    assert got != ADAPTER_ACCEPTANCE_EXPECTED
