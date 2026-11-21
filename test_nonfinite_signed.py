"""NaN, +/-Infinity and an int beyond the double range (a JSON integer such as 10**400) at the token lifetime, replay clock, allow-token clock,
signing window, ledger clock and CIBA amount: each refuses (or is ignored) through the public API, never admitted and never an OverflowError."""
import json
import math

import pytest

from atlas_pca.agent import keypair_from_seed
from atlas_pca.atomic_kv import MemoryAtomicKv
from atlas_pca.ciba import ciba_action_from_step_up
from atlas_pca.connect import InMemoryConnectionStore, TokenVault, refresh_connection
from atlas_pca.connect_replay import InMemoryReplayStore, guard_pcactn_replay
from atlas_pca.connectors import exchange_code
from atlas_pca.frost_net import NetworkCoordinator, issue_allow_token, verify_allow_token
from atlas_pca.ledger_store import KvLedgerStore, LedgerStoreError, StoredLedger
from atlas_pca.pca import b64u, unb64u

BAD = [math.nan, math.inf, -math.inf, 10 ** 400, -(10 ** 400)]
HUGE = [10 ** 400, -(10 ** 400)]
NOW = 1_800_000_000_000


class Resp:
    ok, status = True, 200

    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body

    def text(self):
        return ""


# ---- connect.refresh_connection: expires_in and a JWT exp claim ---------------------------------------------------------------------

def _refresh(body):
    conn = {"provider": "github", "accessToken": "old", "scopes": ["repo"]}
    cfg = {"tokenEndpoint": "https://idp.example/token", "clientId": "cid"}
    return refresh_connection(conn, cfg, "rt", [], lambda url, init: Resp(body), 1_000, 300_000)


@pytest.mark.parametrize("bad", BAD)
def test_refresh_expires_in_that_is_not_finite_falls_back_to_the_default_lifetime(bad):
    assert _refresh({"access_token": "tok", "expires_in": 60})["expiresAt"] == 1_000 + 60_000
    assert _refresh({"access_token": "tok", "expires_in": bad})["expiresAt"] == 1_000 + 300_000  # a huge int was admitted as a ~10**403 ms expiry


def _jwt(exp):
    return "h." + b64u(json.dumps({"exp": exp}).encode("utf-8")) + ".s"


@pytest.mark.parametrize("bad", BAD)
def test_refresh_jwt_exp_that_is_not_finite_falls_back_to_the_default_lifetime(bad):
    assert _refresh({"access_token": _jwt(2_000_000_000)})["expiresAt"] == 2_000_000_000_000
    assert _refresh({"access_token": _jwt(bad)})["expiresAt"] == 1_000 + 300_000


# ---- connectors.exchange_code: expires_in ---------------------------------------------------------------------------------------------

def _exchange(body):
    vault = TokenVault(strict=False, insecure_skip_plan_root_check=True, store=InMemoryConnectionStore(), now=lambda: NOW)
    return exchange_code({"providerId": "github", "clientId": "cid", "clientSecret": "sec", "code": "abc", "redirectUri": "https://app.example/cb",
                          "fetch": lambda url, init: Resp(body), "now": NOW,
                          "bind": {"vault": vault, "agentId": "agent", "authority": {"principal": "p"}}})


@pytest.mark.parametrize("bad", BAD)
def test_exchange_code_expires_in_that_is_not_finite_gets_the_default_lifetime(bad):
    assert _exchange({"access_token": "tok", "expires_in": 60})["expiresAt"] == NOW + 60_000
    assert _exchange({"access_token": "tok", "expires_in": bad})["expiresAt"] == NOW + 3_600_000


# ---- connect_replay.guard_pcactn_replay: the verifier clock ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", HUGE)
def test_replay_guard_refuses_a_clock_beyond_the_double_range(bad):
    p = {"cap_chain": [{"holder": "h"}], "grant_ref": "g", "aud": "a", "iat": 1000, "exp": 2000, "nonce": "n", "counter": 1}
    assert guard_pcactn_replay(InMemoryReplayStore(), p, "a", 1500) == {"ok": True}
    assert guard_pcactn_replay(InMemoryReplayStore(), p, "a", bad) == {"ok": False, "code": "malformed", "reason": "verifier clock is not an integer epoch-ms"}


# ---- frost_net: allow-token clock and the signing window --------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", HUGE)
def test_allow_token_refuses_a_clock_beyond_the_double_range(bad):
    seed, gpk, msg = b"\x05" * 32, b"\x07" * 32, b"message"
    token = issue_allow_token(seed, {"message": msg, "groupPublicKey": gpk})  # no window: only the clock check can refuse a bad time
    expect = {"policyAuthorityPublicKey": unb64u(token["authority"]), "groupPublicKey": gpk, "message": msg}
    assert verify_allow_token(token, dict(expect, now=1500)) == {"ok": True}
    assert verify_allow_token(token, dict(expect, now=bad)) == {"ok": False, "reason": "invalid verification time"}


@pytest.mark.parametrize("window", [math.nan, math.inf, -math.inf] + HUGE)
def test_signing_window_that_is_not_finite_means_no_deadline(window):
    coord = NetworkCoordinator(b"\x07" * 32, 1, [], verification_shares=[])
    with pytest.raises(ValueError, match="message must be bytes"):
        coord.sign("not bytes", None, None, 1000)  # a finite window drives the session on its own thread
    with pytest.raises(ValueError, match="message must be bytes"):
        coord.sign("not bytes", None, None, window)  # a huge window overflowed the thread join instead of driving directly


# ---- ledger_store: the checkpoint clock --------------------------------------------------------------------------------------------------

def _ledger(clock):
    g = keypair_from_seed(b"\x04" * 32, allow_insecure_signer=True)
    h = StoredLedger.open(KvLedgerStore(MemoryAtomicKv()), g, "inst", "pr", clock)
    h.append("c1")
    return h


@pytest.mark.parametrize("bad", BAD)
def test_ledger_checkpoint_refuses_a_clock_that_is_not_finite(bad):
    assert _ledger(lambda: NOW).checkpoint()["timestamp"] == NOW
    with pytest.raises(LedgerStoreError) as e:
        _ledger(lambda: bad).checkpoint()
    assert e.value.code == "clock_invalid"


# ---- ciba: the amount ----------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", BAD)
def test_ciba_amount_that_is_not_finite_is_refused(bad):
    step_up = {"verb": "pay.send", "resource": "acct:1", "params": {"amount": 25, "currency": "USD", "payee": "Bob"}}
    assert ciba_action_from_step_up(step_up) == {"verb": "pay.send", "resource": "acct:1", "amount": "25", "currency": "USD", "payee": "Bob"}
    step_up["params"]["amount"] = bad
    with pytest.raises(ValueError, match="plain non-negative decimal amount"):
        ciba_action_from_step_up(step_up)
