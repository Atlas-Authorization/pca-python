"""k05 differential oracle: undo windows, the pure layer (atlas_pca.undo) against the shared TS-generated
testdata/k05-undo.json.gz (every native replays the same file). Secrets travel as base64url of the 32-byte Ed25519 seed."""
import pytest

from atlas_pca import undo as U
from k05_oracle import b64d, load, run

COUNT, CASES = load("undo")


def _sk(s):
    return b64d(s) if isinstance(s, str) else s


MAP = {
    "compensationDigest": U.compensation_digest,
    "signUndoToken": lambda rec, sk: U.sign_undo_token(rec, _sk(sk)),
    "undoTokenCheck": U.undo_token_check,
    "encodeUndoToken": U.encode_undo_token,
    "undoTokenDigest": U.undo_token_digest,
    "decodeUndoToken": U.decode_undo_token,
    "signUndoReceipt": lambda body, sk: U.sign_undo_receipt(body, _sk(sk)),
    "undoReceiptDigest": U.undo_receipt_digest,
    "verifyUndoReceipt": U.verify_undo_receipt,
    "undoReceiptChainError": U.undo_receipt_chain_error,
    "undoTransition": U.undo_transition,
    "resolveUndoWindow": U.resolve_undo_window,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == 5985 and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])
