"""create_agent / compile_policy / parse_limit: the reference's member names and refusal texts, dry_run, the counter,
sub-agents, headers and the risk claim."""
import pytest

from atlas_pca import verify_pcactn_core
from atlas_pca.agent import keypair_from_seed
from atlas_pca.facade import compile_policy, create_agent, parse_limit
from atlas_pca.pca import canonicalize, decode_pca_header

NOW = 1_800_000_000_000
P, H, SUB = (keypair_from_seed(bytes([i]) * 32) for i in (7, 8, 9))


def refuses(fn, text):
    with pytest.raises(ValueError) as e:
        fn()
    assert str(e.value) == text


def handle(**kw):
    return create_agent(P, "refund order 1", {"stripe": ["refund"], "gmail": ["send"]}, {"refund": "$100/day", "send": "3/hour"},
                        holder=H, aud="rs", now=NOW, **kw)


def test_parse_limit():
    assert parse_limit("$5.50/week") == {"amount": 5.5, "unit": "usd", "periodMs": 604800000}
    assert parse_limit("10") == {"amount": 10, "unit": "count"}
    assert parse_limit(" 3 / hour ") == {"amount": 3, "unit": "count", "periodMs": 3600000}
    refuses(lambda: parse_limit(""), "parseLimit: empty limit")
    refuses(lambda: parse_limit("   "), "parseLimit: empty limit")
    refuses(lambda: parse_limit(None), "parseLimit: empty limit")
    refuses(lambda: parse_limit("1" * 65), "parseLimit: limit is longer than 64 characters")
    refuses(lambda: parse_limit("five dollars"), "parseLimit: cannot parse limit 'five dollars'")
    refuses(lambda: parse_limit("$5/fortnight"), "parseLimit: unknown period 'fortnight' in '$5/fortnight'")
    refuses(lambda: parse_limit("5/constructor"), "parseLimit: unknown period 'constructor' in '5/constructor'")


def test_compile_policy():
    p = compile_policy({"stripe": ["refund"]}, {"refund": "$100/day"}, now=NOW)
    assert set(p) == {"predicates", "caveats", "riskPolicy", "actions", "budgetModel", "limits", "inputLimits", "approximations"}
    assert p["budgetModel"] == "dollars" and p["limits"]["stripe.refund"]["periodMs"] == 86400000
    assert compile_policy({"stripe": ["refund"]}, now=NOW)["budgetModel"] == "risk"
    refuses(lambda: compile_policy({}, now=NOW), "compilePolicy: no permissions granted")
    refuses(lambda: compile_policy({"stripe": "refund"}, now=NOW), "compilePolicy: permissions.stripe must be an array")
    refuses(lambda: compile_policy({"gmail": ["send"]}, {"send": "$5"}, now=NOW),
            "compilePolicy: '$' limit on 'gmail.send' but the catalog gives that verb no amount field, so the limit could not be enforced")
    with pytest.raises(ValueError, match=r"^compilePolicy: derived risk policy invalid: "):
        compile_policy({"stripe": ["refund"]}, risk_policy={"kappa": 0}, now=NOW)


def test_dry_run():
    h = handle()
    assert h.dry_run("stripe.refund", "charge:1", {"amount": 5}, now=NOW) == {"allowed": True, "t": 1}
    assert h.dry_run("stripe.refund", "charge:1", {"amount": 500}, now=NOW) == {
        "allowed": False, "reason": "amount <= 100 not satisfied for stripe.refund on charge:1"}
    assert h.dry_run("github.push", "x", {}, now=NOW) == {"allowed": False, "reason": "no predicate permits github.push on x"}


def test_act_counter_headers_risk_and_verifies():
    h = handle()
    a = h.act("stripe.refund", "charge:1", {"amount": 5}, now=NOW)
    p = a["pcactn"]
    assert p["counter"] == 1 and "nonce" not in p
    assert p["risk_claim"] == {"r": 0.05, "inputs": {"blastRadius": 0.05}}
    assert set(a["headers"]) == {"PCA-Action", "PCA-Provenance"}
    assert decode_pca_header(a["headers"]["PCA-Action"]) == a["encoded"] == canonicalize(p)
    assert verify_pcactn_core(p, h.grant, audience="rs", now=NOW + 1000, insecure_skip_plan_root_check=True).allow
    assert h.act("stripe.refund", "charge:1", {"amount": 5}, counter=7, now=NOW)["pcactn"]["counter"] == 7
    assert h.act("stripe.refund", "charge:2", {}, now=NOW)["pcactn"]["counter"] == 8
    assert h.act("stripe.refund", "charge:3", {}, counter=2, now=NOW)["pcactn"]["counter"] == 2
    assert h.counter == 8


def test_act_needs_aud():
    h = create_agent(P, "g", {"stripe": ["refund"]}, holder=H, now=NOW)
    refuses(lambda: h.act("stripe.refund", "charge:1", now=NOW),
            "act: aud (resource-server / instance id) is required (pass aud= here or to create_agent)")
    assert h.act("stripe.refund", "charge:1", aud="rs2", now=NOW)["pcactn"]["aud"] == "rs2"


def test_sub_agent():
    h = handle()
    s = h.sub_agent(SUB, [{"type": "budget_alloc", "limit": 5}])
    assert len(s.chain) == 2 and s.chain[-1]["holder"] == SUB.public and s.holder is SUB
    p = s.act("stripe.refund", "charge:1", {"amount": 5}, now=NOW)["pcactn"]
    assert verify_pcactn_core(p, h.grant, audience="rs", now=NOW + 1000, insecure_skip_plan_root_check=True).allow
    assert h.encode_grant() == s.encode_grant()


def test_grant_names_the_mediator_and_salt():
    h = handle(goal_salt="fixed-salt")
    assert h.goal_salt == "fixed-salt"
    env = h.grant["caveats"][0]
    assert env["provenance"] == {"mediators": [h.provenance.pin]}
