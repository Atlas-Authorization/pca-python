"""Test harness for provenance by default (not a test module): authorize() runs the provenance gate on every call, so a test
whose operation comes straight from the principal presents a principal-direct bundle recorded by this SDK's own recorder under
the shared harness pin (Ed25519 seed = 32 bytes of 0x01, mediator ``conformance-harness``, kid ``k1``), exactly as the
TypeScript harnesses do. The gate stays ON: the bundle is what lets these calls pass it.

    authorize(p, operation=op, ..., **prov(op))                       # direct calls
    AuthorizeOptions(..., provenance_mediators=[PIN])                 # guards: send prov_header(op) with the request
"""
import json

from atlas_pca.arg_provenance import PROV_HEADER, create_provenance_recorder, principal_direct_provenance
from atlas_pca.pca import b64u

SEED = bytes([1]) * 32
MEDIATOR, KID = "conformance-harness", "k1"


def recorder():
    return create_provenance_recorder(mediator=MEDIATOR, kid=KID, secret_key=SEED)


PIN = recorder().pin


def bundle_for(op):
    """A principal-direct bundle for ``op`` ({verb, resource, params}) under the harness pin."""
    return principal_direct_provenance(recorder(), {"verb": op["verb"], "resource": op["resource"], "params": op.get("params") or {}})


def prov(op):
    """The authorize() keyword arguments that present ``op``'s principal-direct bundle under the pinned harness mediator."""
    return {"provenance": bundle_for(op), "provenance_mediators": [PIN]}


def prov_header(op):
    """``{"PCA-Provenance": <base64url JSON>}`` carrying ``op``'s principal-direct bundle (for guard / framework tests)."""
    return {PROV_HEADER: b64u(json.dumps(bundle_for(op)).encode("utf-8"))}
