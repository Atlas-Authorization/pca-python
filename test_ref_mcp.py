"""Differential oracle: the MCP adapter's client step-up, conformance matrix, tool-to-schema drafting and closed-world check
(atlas_pca.mcp) against the vectors generated from the TypeScript reference (@atlasauth/pca-mcp)."""
import pytest

from atlas_pca import mcp as M
from atlas_pca.agent import PCA_HEADER
from atlas_pca.pca import b64u
from base_oracle import load_ref, run

COUNT, CASES = load_ref("mcp")

MAP = {
    "parseChallenges": M.parse_challenges,
    "checkAuthorizationResponseIss": M.check_authorization_response_iss,
    "pcaNeedProblem": M.pca_need_problem,
    "planStepUp": M.plan_step_up,
    "constants": lambda: {"MCP_CLIENT_REVISIONS": list(M.MCP_CLIENT_REVISIONS), "MCP_AUTH_CLIENT_ROWS": M.MCP_AUTH_CLIENT_ROWS},
    "pcaHeaders": lambda encoded: {PCA_HEADER: b64u(encoded.encode("utf-8"))},  # the header is base64url of the UTF-8 text, unpadded
    "guardToolResult": M.guard_tool_result,
    "draftActionSchemaFromMcp": M.draft_action_schema_from_mcp,
    "applySchemaDecisions": M.apply_schema_decisions,
    "verbOfTool": M.verb_of_tool,
    "conformToolCall": M.conform_tool_call,
}


def test_corpus_is_the_full_oracle():
    assert COUNT == sum(len(v) for v in CASES.values()) and set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    ran, _ = run(CASES[fn], MAP[fn])
    assert ran == len(CASES[fn])


def test_tool_call_of():
    body = '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"t","arguments":{"a":1}}}'
    assert M.tool_call_of(body) == {"name": "t", "arguments": {"a": 1}}
    assert M.tool_call_of('{"method":"tools/call","params":{"name":"t","arguments":[1]}}') == {"name": "t", "arguments": {}}
    for bad in (None, 5, "", "{", "[]", '{"method":"tools/list"}', '{"method":"tools/call","params":{}}', '{"method":"tools/call","params":{"name":5}}',
                '{"method":"tools/call","params":{"name":"t","arguments":NaN}}'):
        assert M.tool_call_of(bad) is None


def test_pca_fetch_attaches_a_proof_and_records_the_result():
    class Agent:
        provenance = None

        def act(self, verb, resource, params):
            class A:
                headers = {"PCA-Action": "e30"}
                pcactn = {}
                provenance = None
            self.seen = (verb, resource, params)
            return A()

    sent = []
    agent = Agent()
    f = M.pca_fetch(agent, lambda n, a: {"verb": "v." + n, "resource": "r"} if n == "t" else None, lambda url, init: sent.append(init) or "res")
    assert f("u", {"body": '{"method":"tools/call","params":{"name":"t","arguments":{"a":1}}}', "headers": {"x": "y"}}) == "res"
    assert sent[0]["headers"]["PCA-Action"] == "e30" and sent[0]["headers"]["x"] == "y" and agent.seen == ("v.t", "r", {"a": 1})
    f("u", {"body": '{"method":"tools/call","params":{"name":"other"}}'})
    assert "PCA-Action" not in (sent[1].get("headers") or {})
    f("u", {"body": "not json"})
    assert len(sent) == 3
    # per-call audience: forwarded to the agent's act
    class AudAgent(Agent):
        def act(self, verb, resource, params, aud=None):
            self.aud_seen = aud
            return super().act(verb, resource, params)
    a2 = AudAgent()
    M.pca_fetch(a2, lambda n, a: {"verb": "v", "resource": "r"}, lambda u, i: "res", aud="https://other")(
        "u", {"body": '{"method":"tools/call","params":{"name":"t","arguments":{}}}'})
    assert a2.aud_seen == "https://other"


def test_with_pca_per_call_audience_and_import_defs():
    from atlas_pca.agent import Agent as PAgent, keypair_from_seed, mint_grant, DEFAULT_RISK_POLICY
    p, h = keypair_from_seed(b"\x01" * 32, allow_insecure_signer=True), keypair_from_seed(b"\x02" * 32, allow_insecure_signer=True)
    env = {"predicates": [{"verb": "refund", "resource": "orders/*"}], "caveats": [], "risk_policy": DEFAULT_RISK_POLICY}
    ag = PAgent(h, mint_grant(p, h.public, env, "g", salt="s")["grant"], "aud-a")
    seen = []
    w = M.with_pca(ag, "refund", "orders/1", lambda a, e=None: {"content": []}, on_proof=lambda pca, a: seen.append(pca.pcactn["aud"]),
                   aud="aud-b")
    assert w({"x": 1}) == {"content": []} and seen == ["aud-b"]
    r = M.import_action_defs_from_mcp([{"name": "send_mail", "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}}}}],
                                      {"ns": "mcp"})
    assert [d["verb"] for d in r["defs"]] == ["mcp.mail.send"] and r["todo"] == []
