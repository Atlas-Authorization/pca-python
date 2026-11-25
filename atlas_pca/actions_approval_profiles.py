"""The remaining approval profiles of approval-profiles.ts of the TypeScript reference @atlasauth/pca-actions: the Secure Payment Confirmation
expectation and the CIBA / RAR authorization_details entry. PSD2 linking, minor units and batches are in approval.py."""
from typing import Any, Dict

from .approval import approval_render_digest, binding_words, minor_to_decimal, psd2_linking


def spc_expectation(r: dict, top_origin: str, payee_as: str = "name") -> dict:
    """What a WebAuthn assertion verifier must find in the signed `clientData.payment`. The payee value is the name or the origin the browser shows."""
    link = psd2_linking(r)
    out: Dict[str, Any] = {"topOrigin": top_origin, "total": {"currency": link["currency"], "value": minor_to_decimal(link["amount_minor"], link["exp"])}}
    out["payeeName" if payee_as == "name" else "payeeOrigin"] = link["payee"]
    return out


def ciba_approval_details(r: dict) -> dict:
    """RFC 9396 authorization_details entry carrying the canonical render, plus the speakable match code."""
    render_digest = approval_render_digest(r)
    return {"authorization_details": [{"type": "pca_approval", "render": r, "render_digest": render_digest}], "match_code": binding_words(render_digest)}
