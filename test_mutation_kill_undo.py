"""Mutation kills for undo windows (atlas_pca.undo and the undo_window obligation kind): the token check order (every failure
code reachable, the inclusive exp boundary), the receipt member count, the chain's prev / at / last-state rules, every
transition row, the window clamp edges and the obligation parameters."""
import copy

import pytest

from atlas_pca.agent import KeyPair
from atlas_pca.obligations import OBLIGATION_KINDS, obligation_error
from atlas_pca.undo import (UNDO_COMPENSATION_DOMAIN, UNDO_DEFAULT_WINDOW_MS, UNDO_EVENTS, UNDO_MAX_WINDOW_MS, UNDO_MIN_WINDOW_MS,
                            UNDO_RECEIPT_DOMAIN, UNDO_RECEIPT_REF_DOMAIN, UNDO_STATES, UNDO_TOKEN_DOMAIN, UNDO_TOKEN_REF_DOMAIN,
                            VETO_VIAS, compensation_digest, decode_undo_token, encode_undo_token, resolve_undo_window,
                            sign_undo_receipt, sign_undo_token, undo_receipt_chain_error, undo_receipt_digest, undo_token_check,
                            undo_transition, verify_undo_receipt)
from atlas_pca.pca import b64u

SEED, OTHER = bytes([7]) * 32, bytes([8]) * 32
SIGNER = KeyPair(SEED).public
T0, END = 1_800_000_000_000, 1_800_000_900_000
C = {"verb": "drafts.delete", "resource": "drafts:box1", "params": {"box": "box1"}, "undo_of": "op_1", "def_digest": "D" * 43}
CD = compensation_digest(C)
REC = {"id": "op_1", "aud": "drafts-rs", "principal": "P" * 43, "compensation_digest": CD, "render_digest": "R" * 43,
       "window_end": END}
TOKEN = sign_undo_token(REC, SEED)


def test_constants():
    assert [UNDO_TOKEN_DOMAIN, UNDO_RECEIPT_DOMAIN, UNDO_COMPENSATION_DOMAIN, UNDO_RECEIPT_REF_DOMAIN, UNDO_TOKEN_REF_DOMAIN] == [
        "atlas-pca/undo-token/v1\x00", "atlas-pca/undo-receipt/v1\x00", "atlas-pca/undo-compensation/v1",
        "atlas-pca/undo-receipt-ref/v1", "atlas-pca/undo-token-ref/v1"]
    assert (UNDO_MIN_WINDOW_MS, UNDO_DEFAULT_WINDOW_MS, UNDO_MAX_WINDOW_MS) == (30_000, 900_000, 86_400_000)
    assert UNDO_STATES == ("open", "vetoed", "compensated", "compensation_failed", "finalized")
    assert UNDO_EVENTS == ("opened", "vetoed", "compensated", "compensation_failed", "finalized", "aborted", "retried", "effect")
    assert VETO_VIAS == ("token", "operator", "fraud_proof", "revocation")
    assert "undo_window" in OBLIGATION_KINDS


def test_compensation_digest_binds_every_member_and_target_param_only_when_present():
    base = compensation_digest(C)
    for k, v in (("verb", "x"), ("resource", "x"), ("params", {}), ("undo_of", "op_2"), ("def_digest", "E" * 43)):
        assert compensation_digest(dict(C, **{k: v})) != base
    assert compensation_digest(dict(C, target_param="draft")) != base


# ---- token: the check order --------------------------------------------------------------------------------------------

def test_token_ok_and_inclusive_exp():
    assert undo_token_check(TOKEN, SIGNER, REC, T0) == "ok"
    assert undo_token_check(TOKEN, SIGNER, REC, END) == "ok"
    assert undo_token_check(TOKEN, SIGNER, REC, END + 1) == "expired"
    assert undo_token_check(TOKEN, SIGNER, REC, T0 + 0.5) == "expired"
    assert undo_token_check(TOKEN, SIGNER, REC, None) == "expired"


@pytest.mark.parametrize("mut", [
    lambda t: dict(t, x=1), lambda t: {k: v for k, v in t.items() if k != "aud"}, lambda t: dict(t, v=2), lambda t: dict(t, v=True),
    lambda t: dict(t, kind="pca-undo-receipt"), lambda t: dict(t, record=""), lambda t: dict(t, record="a\x01"),
    lambda t: dict(t, record="r" * 257), lambda t: dict(t, aud=1), lambda t: dict(t, principal=None),
    lambda t: dict(t, compensation_digest=1), lambda t: dict(t, render_digest=None), lambda t: dict(t, exp=1.5),
    lambda t: dict(t, exp=2 ** 53), lambda t: dict(t, signer=1), lambda t: dict(t, sig=b64u(bytes(63))), lambda t: dict(t, sig="x"),
    lambda t: "token", lambda t: None, lambda t: [t],
])
def test_token_malformed_comes_first(mut):
    assert undo_token_check(mut(dict(TOKEN)), "someone-else", REC, END + 1) == "malformed"


def test_token_each_later_code_in_order():
    # signer before signature: a token re-signed by another key fails on the signer pin first
    other = sign_undo_token(REC, OTHER)
    assert undo_token_check(other, SIGNER, REC, T0) == "signer"
    assert undo_token_check(TOKEN, KeyPair(OTHER).public, REC, T0) == "signer"
    # signature before record / binding / expiry
    assert undo_token_check(dict(TOKEN, exp=END + 60_000), SIGNER, dict(REC, id="op_9"), END + 120_000) == "signature"
    assert undo_token_check(dict(TOKEN, aud="other-rs"), SIGNER, REC, T0) == "signature"
    # record before binding
    assert undo_token_check(sign_undo_token(dict(REC, id="op_9", aud="x"), SEED), SIGNER, REC, T0) == "record"
    # binding: each bound member, before expiry
    for k, v in (("aud", "other-rs"), ("principal", "Q" * 43), ("compensation_digest", "Z" * 43), ("render_digest", "S" * 43),
                 ("window_end", END + 1)):
        assert undo_token_check(TOKEN, SIGNER, dict(REC, **{k: v}), END + 5) == "binding", k
    no_render = {k: v for k, v in REC.items() if k != "render_digest"}
    assert undo_token_check(TOKEN, SIGNER, no_render, T0) == "binding"
    t2 = sign_undo_token(no_render, SEED)
    assert t2["render_digest"] == "" and undo_token_check(t2, SIGNER, no_render, T0) == "ok"
    assert undo_token_check(t2, SIGNER, dict(no_render, render_digest=None), T0) == "ok"


def test_token_encoding():
    s = encode_undo_token(TOKEN)
    assert decode_undo_token(s) == TOKEN
    assert decode_undo_token(s + "=") is None and decode_undo_token("") is None and decode_undo_token(1) is None
    assert decode_undo_token("A" * 4097) is None
    assert decode_undo_token(b64u(b"[1]")) is None and decode_undo_token(b64u(b"\xff\xfe")) is None
    assert decode_undo_token(b64u(b'{"a": NaN}')) is None


# ---- receipts ----------------------------------------------------------------------------------------------------------

def _r(event, state, at, prev, note=""):
    return sign_undo_receipt({"record": "op_1", "event": event, "state": state, "at": at, "compensation_digest": CD, "prev": prev,
                              "note": note}, SEED)


R0 = _r("opened", "open", T0, "", "converted")
R1 = _r("effect", "open", T0 + 1000, undo_receipt_digest(R0))
R2 = _r("vetoed", "vetoed", T0 + 1000, undo_receipt_digest(R1), "token")


def test_receipt_member_count_and_fields():
    assert len(R0) == 11 and verify_undo_receipt(R0, SIGNER) is True
    assert verify_undo_receipt(dict(R0, extra=1), SIGNER) is False
    assert verify_undo_receipt({k: v for k, v in R0.items() if k != "note"}, SIGNER) is False
    for k, v in (("v", 2), ("kind", "pca-undo-token"), ("record", ""), ("event", "deleted"), ("state", "pending"), ("at", -0.5),
                 ("compensation_digest", 1), ("prev", None), ("note", None), ("signer", KeyPair(OTHER).public), ("sig", "x")):
        assert verify_undo_receipt(dict(R0, **{k: v}), SIGNER) is False, k
    assert verify_undo_receipt(dict(R0, note="operator"), SIGNER) is False  # signed content
    assert verify_undo_receipt(R0, KeyPair(OTHER).public) is False
    assert verify_undo_receipt("x", SIGNER) is False


def _chain(rs, state="vetoed", **kw):
    return undo_receipt_chain_error(dict({"id": "op_1", "compensation_digest": CD, "state": state, "receipts": rs}, **kw), SIGNER)


def test_chain_rules():
    assert _chain([R0, R1, R2]) is None
    assert _chain([R0], state="open") is None
    assert _chain([]) == "no receipts" and _chain(None) == "no receipts"
    assert _chain([R0, R2]) is not None                       # prev skips one
    assert _chain([_r("opened", "open", T0, "x" * 43)], state="open") is not None  # the first prev is ''
    assert _chain([R1], state="open") is not None             # the first event is opened
    back = _r("effect", "open", T0 - 1, undo_receipt_digest(R0))
    assert _chain([R0, back], state="open") is not None       # at never decreases
    same = _r("effect", "open", T0, undo_receipt_digest(R0))
    assert _chain([R0, same], state="open") is None           # equal times are fine
    assert _chain([R0, R1, R2], state="open") is not None     # the last state is the record's
    assert _chain([R0, R1, R2], id="op_2") is not None
    assert _chain([R0, R1, R2], compensation_digest="Z" * 43) is not None


# ---- transitions -------------------------------------------------------------------------------------------------------

def R(state, **x):
    return dict({"state": state, "window_end": END, "ver": 3, "attempt": 0}, **x)


E = {"effect": {"at": T0}}
VETO = {"kind": "veto", "veto": {"at": T0, "via": "token", "by": "P" * 43}}

ROWS = [
    (R("open"), VETO, T0, ("applied", "vetoed")),
    (R("open"), VETO, END, ("applied", "vetoed")),
    (R("open"), VETO, END + 1, ("refused", "window_closed")),
    (R("vetoed"), VETO, END + 1, ("replayed", None)),
    (R("compensated", **E), VETO, T0, ("replayed", None)),
    (R("compensation_failed", **E), VETO, T0, ("replayed", None)),
    (R("finalized"), VETO, T0, ("refused", "finalized")),
    (R("open"), {"kind": "veto", "veto": {"at": T0, "via": "email", "by": "x"}}, T0, ("refused", "invalid")),
    (R("open"), {"kind": "veto", "veto": {"at": T0, "via": "token", "by": ""}}, T0, ("refused", "invalid")),
    (R("open"), {"kind": "veto", "veto": {"at": 0.5, "via": "token", "by": "x"}}, T0, ("refused", "invalid")),
    (R("open"), {"kind": "veto"}, T0, ("refused", "invalid")),
    (R("open"), {"kind": "finalize"}, END, ("refused", "window_open")),
    (R("open"), {"kind": "finalize"}, END + 1, ("applied", "finalized")),
    (R("finalized"), {"kind": "finalize"}, T0, ("replayed", None)),
    (R("vetoed"), {"kind": "finalize"}, END + 1, ("refused", "vetoed")),
    (R("compensated"), {"kind": "finalize"}, END + 1, ("refused", "vetoed")),
    (R("open"), {"kind": "abort", "reason": "x"}, T0, ("applied", "finalized")),
    (R("vetoed"), {"kind": "abort", "reason": "x"}, T0, ("applied", "finalized")),
    (R("open", **E), {"kind": "abort", "reason": "x"}, T0, ("refused", "effect_recorded")),
    (R("finalized", outcome={"at": T0, "status": "aborted"}), {"kind": "abort", "reason": "x"}, T0, ("replayed", None)),
    (R("finalized", outcome={"at": T0, "status": "finalized"}), {"kind": "abort", "reason": "x"}, T0, ("refused", "finalized")),
    (R("compensated"), {"kind": "abort", "reason": "x"}, T0, ("refused", "finalized")),
    (R("open"), {"kind": "effect", "result": {"id": "d"}}, T0, ("applied", "open")),
    (R("vetoed"), {"kind": "effect"}, T0, ("applied", "vetoed")),
    (R("open", **E), {"kind": "effect"}, T0, ("replayed", None)),
    (R("finalized"), {"kind": "effect"}, T0, ("refused", "finalized")),
    (R("vetoed", **E), {"kind": "compensated"}, T0, ("applied", "compensated")),
    (R("compensation_failed", **E), {"kind": "compensated"}, T0, ("applied", "compensated")),
    (R("open", **E), {"kind": "compensated"}, T0, ("refused", "not_vetoed")),
    (R("compensated", **E), {"kind": "compensated"}, T0, ("replayed", None)),
    (R("vetoed", **E), {"kind": "compensation_failed", "reason": "x"}, T0, ("applied", "compensation_failed")),
    (R("compensation_failed", **E), {"kind": "compensation_failed", "reason": "x"}, T0, ("replayed", None)),
    (R("open", **E), {"kind": "compensation_failed", "reason": "x"}, T0, ("refused", "not_vetoed")),
    (R("compensation_failed", attempt=2), {"kind": "retry"}, T0, ("applied", "vetoed")),
    (R("vetoed"), {"kind": "retry"}, T0, ("refused", "not_failed")),
    (R("open"), {"kind": "explode"}, T0, ("refused", "invalid")),
    (R("open"), None, T0, ("refused", "invalid")),
    (R("pending"), VETO, T0, ("refused", "invalid")),
    (R("open", window_end=1.5), VETO, T0, ("refused", "invalid")),
    (R("open", ver=None), VETO, T0, ("refused", "invalid")),
    (R("open"), VETO, T0 + 0.5, ("refused", "invalid")),
    ("x", VETO, T0, ("refused", "invalid")),
]


@pytest.mark.parametrize("i", range(len(ROWS)))
def test_transition_row(i):
    rec, ev, now, (outcome, x) = ROWS[i]
    before = copy.deepcopy(rec)
    r = undo_transition(rec, ev, now)
    assert r["outcome"] == outcome
    if outcome == "refused":
        assert r["code"] == x and isinstance(r["reason"], str)
    elif outcome == "applied":
        assert (r["record"]["state"], r["record"]["ver"]) == (x, 4)
    else:
        assert r["record"] is rec
    assert rec == before


def test_transition_details():
    v = undo_transition(R("open"), VETO, T0)
    assert v["record"]["veto"] == VETO["veto"] and v["receipt"] == {"event": "vetoed", "note": "token"}
    f = undo_transition(R("open"), {"kind": "finalize"}, END + 1)
    assert f["record"]["outcome"] == {"at": END + 1, "status": "finalized"} and f["receipt"] == {"event": "finalized", "note": ""}
    a = undo_transition(R("open"), {"kind": "abort", "reason": "y" * 600}, T0)
    assert a["record"]["outcome"]["status"] == "aborted" and len(a["record"]["outcome"]["reason"]) == 512
    assert a["receipt"] == {"event": "aborted", "note": "y" * 128}
    e = undo_transition(R("open"), {"kind": "effect", "result": {"id": "d"}}, T0)
    assert e["record"]["effect"] == {"at": T0, "result": {"id": "d"}} and e["receipt"]["event"] == "effect"
    assert undo_transition(R("open"), {"kind": "effect"}, T0)["record"]["effect"] == {"at": T0}
    c = undo_transition(R("vetoed", **E), {"kind": "compensated", "result": 1}, T0)
    assert c["record"]["outcome"] == {"at": T0, "status": "compensated", "result": 1}
    cf = undo_transition(R("vetoed", **E), {"kind": "compensation_failed", "reason": "down"}, T0)
    assert cf["record"]["outcome"]["reason"] == "down" and cf["receipt"] == {"event": "compensation_failed", "note": "down"}
    rt = undo_transition(R("compensation_failed", attempt=2), {"kind": "retry"}, T0)
    assert (rt["record"]["attempt"], rt["receipt"]["event"]) == (3, "retried")


# ---- window clamp ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("req,policy,want", [
    (None, {}, 900_000), (float("nan"), {}, 900_000), (float("inf"), {}, 900_000), (True, {}, 900_000), ("60000", {}, 900_000),
    (29_999, {}, 30_000), (30_000, {}, 30_000), (30_001, {}, 30_001), (86_399_999, {}, 86_399_999), (86_400_000, {}, 86_400_000),
    (86_400_001, {}, 86_400_000), (120_000.9, {}, 120_000), (600_000, {"max_ms": 300_000}, 300_000),
    (600_000, {"maxMs": 300_000}, 300_000), (5, {"min_ms": 1}, 30_000), (5, {"min_ms": 40_000}, 40_000),
    (None, {"default_ms": 60_000}, 60_000), (None, {"defaultMs": 1}, 30_000), (1, {"minMs": 120_000, "maxMs": 60_000}, 120_000),
    (100_000_000, {"max_ms": 100_000_000}, 86_400_000),
])
def test_window_clamp(req, policy, want):
    assert resolve_undo_window(req, policy) == want


# ---- the undo_window obligation ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("o,ok", [
    ({"kind": "undo_window", "params": {"id": "op_1", "window_end": END}}, True),
    ({"kind": "undo_window", "params": {"id": "op_1", "window_end": 0}, "due": END}, True),
    ({"kind": "undo_window", "params": {"id": "x" * 128, "window_end": END}}, True),
    ({"kind": "undo_window", "params": {"id": "x" * 129, "window_end": END}}, False),
    ({"kind": "undo_window", "params": {"id": "", "window_end": END}}, False),
    ({"kind": "undo_window", "params": {"id": "op_1", "window_end": -1}}, False),
    ({"kind": "undo_window", "params": {"id": "op_1", "window_end": 1.5}}, False),
    ({"kind": "undo_window", "params": {"id": "op_1", "window_end": 2 ** 53}}, False),
    ({"kind": "undo_window", "params": {"id": "op_1", "window_end": END, "by": "x"}}, False),
    ({"kind": "undo_window", "params": {"id": "op_1"}}, False),
    ({"kind": "undo_window", "params": {"window_end": END}}, False),
    ({"kind": "undo_window"}, False),
    ({"kind": "undo_window", "params": {"id": 1, "window_end": END}}, False),
])
def test_undo_window_obligation_params(o, ok):
    assert (obligation_error(o) is None) is ok
