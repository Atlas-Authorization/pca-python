"""PCA wire-format v2 conformance driver (native Python verifier).

Runs the shared curated core (golden + a sample of the adversarial families) at packages/pca/conformance/vectors.json (172 v2 vectors plus the
threshold-share and pq-artifact primitive tables) against the native `atlas_pca` verifier, requiring it to
reproduce `allow` and every listed check for EVERY vector it can evaluate.

Signature-suite coverage. The verifier implements the THREE cross-impl suites every conformant impl must agree
on: classical `ed25519`, the pure lattice `ml-dsa-65` (FIPS-204) and the hybrid `ed25519 + ml-dsa-65`. The
lattice/hybrid suites route through `dilithium-py`; when that library is absent they FAIL CLOSED, so a vector
that would need a genuine positive crypto verdict under them is skipped (never silently passed). The remaining
seven registered suites (ml-dsa-87, slh-dsa-sha2-128f/256s, their hybrids and the SUF-CMA nested hybrid) are
not implemented in Python and are likewise skipped, per suite, with an explicit count.

A terminal `wire` failure (`{wire: false}`) is suite-AGNOSTIC: the verifier rejects an unknown / unimplemented
suite (unknown `alg`, or a `pq_sig` the suite requires but cannot size) at the wire stage, which IS the correct
contract verdict for those negatives, so those vectors are still RUN even when their suite is unimplemented.

Runs under pytest or directly (`python3 test_conformance.py`). No pytest dependency.
"""
import copy
import json
import os
import unittest

from atlas_pca import (
    REGISTERED_SUITES, StrictJsonError, action_schema_digest, canonicalize_strict, check_session_revocation, conform_action,
    decide_classifier_dimensions, decide_intent_world, decide_param_provenance, decode_b64u_strict, hash_canonical,
    merkle_root, params_digest, strict_parse, verify_action_schema, verify_artifact_suite, verify_chain, verify_inclusion,
    verify_pcactn_core, verify_threshold_share,
)
from atlas_pca.mldsa import ml_dsa65_available
from atlas_pca.intent_map import commit_leaves, decide_map_primitive
from atlas_pca.pca import b64u, sha256, signer_set_hash, supported_suites

DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance")


def _load(name):
    with open(os.path.join(DIR, name), encoding="utf-8") as f:
        return json.load(f)


DOC = _load("vectors.json")

# This verifier's capability manifest in this runtime (supported_suites(): ed25519 + every ML-DSA / SLH-DSA suite whose
# backend - dilithium-py or OpenSSL >= 3.5 libcrypto - is usable; packages/pca/conformance/SUITES.md). A vector needing a
# suite outside it is not skipped silently: the verifier must deny it with the distinct reason unsupported_suite.
_ML_DSA = ml_dsa65_available()
SUPPORTED_SUITES = frozenset(supported_suites())


def _alg(obj):
    return obj.get("alg", "ed25519") if isinstance(obj, dict) else "ed25519"


def _unsupported_suite(v):
    """The concrete signature suite a vector exercises that this verifier does NOT run, if any: the leaf `alg`
    for requires:"pq", or any capability-hop `alg` for requires:"pq-nonleaf". None otherwise (core vectors, and
    vectors that stay entirely within SUPPORTED_SUITES — e.g. a downgrade hop stripped back to ed25519)."""
    p = v.get("pcactn")
    if not isinstance(p, dict):
        return None
    req = v.get("requires")
    # 0.4.1: a vector may name the concrete suite it needs (e.g. a pure ml-dsa-87 / slh-dsa threshold share). A
    # suite this verifier does not implement is skipped (with its count), never silently passed.
    if isinstance(req, str) and req not in ("pq", "pq-nonleaf"):
        return None if req in SUPPORTED_SUITES else req
    if req == "pq":
        a = _alg(p)
        return None if a in SUPPORTED_SUITES else a
    if req == "pq-nonleaf":
        for hop in p.get("cap_chain", []) or []:
            a = _alg(hop)
            if a not in SUPPORTED_SUITES:
                return a
    return None


def _intent_policy(ctx):
    """Intent Layer M2: a vector's verifier policy. `context.intent_policy_json` (raw JSON TEXT, parsed here with the
    platform parser so e.g. 950000.0 stays a float) wins over `context.intent_policy`. A bare `-0` integer lexeme parses
    as -0.0, like JSON.parse in the reference (negative zero is a misconfigured threshold)."""
    if "intent_policy_json" in ctx:
        return json.loads(ctx["intent_policy_json"], parse_int=lambda t: -0.0 if t == "-0" else int(t))
    return ctx.get("intent_policy")



_REV_PARAMS = ("session", "scope", "authority", "ids", "now", "max_age_ms", "last")


def _input(e):
    """A primitive entry's input (README "Raw JSON text members"): `input_json`, the WHOLE input as raw JSON text, wins
    over `input` and is parsed here with the platform parser, a bare `-0` kept as negative zero (-0.0)."""
    if "input_json" in e:
        return json.loads(e["input_json"], parse_int=lambda t: -0.0 if t == "-0" else int(t))
    return e["input"]


def _intent_v2(ctx):
    """Intent Layer v2: the vector's verifier state (`context.intent_v2`, TS IntentV2Context), passed as is."""
    return ctx.get("intent_v2")


def _table(name):
    """A primitive table, or None when this corpus does not carry it yet (the caller skips with a count)."""
    t = DOC["primitives"].get(name)
    return t if isinstance(t, list) and t else None


def _terminal_wire_false(v):
    c = v["expect"]["checks"]
    return len(c) == 1 and c.get("wire") is False


def _lacks_suite(e):
    """README "Suite capability": a W-B primitive whose `requires_suite` this runtime lacks is not compared."""
    rs = e.get("requires_suite")
    return isinstance(rs, str) and rs not in SUPPORTED_SUITES


class Conformance(unittest.TestCase):
    def _assert_suite_refusal(self, refused, ref_accepts, reason):
        """An entry under a suite outside the manifest must be refused; when the reference accepts it, with unsupported_suite."""
        self.assertTrue(refused, reason)
        if ref_accepts:
            self.assertIn("unsupported_suite", reason or "", reason)

    def test_format(self):
        self.assertEqual(DOC["format"], 2)
        self.assertGreaterEqual(len(DOC["vectors"]), 172 + 60)  # 172 golden + the sampled adv-* families (minimum, not exact: the full set is vectors-adversarial.json.gz)

    def test_vectors(self):
        self.assertTrue(DOC["vectors"])
        passed = 0
        skipped_by_suite = {}
        for v in DOC["vectors"]:
            suite = _unsupported_suite(v)
            # Skip ONLY a vector whose expected verdict needs a genuine signature outcome under an unrunnable
            # suite. A terminal {wire:false} negative is run regardless: unknown/unimplemented alg -> wire fail.
            if suite is not None and not _terminal_wire_false(v):
                skipped_by_suite[suite] = skipped_by_suite.get(suite, 0) + 1
                if isinstance(v.get("pcactn"), dict):
                    with self.subTest(v["name"] + " (unsupported_suite)"):
                        ctx = v["context"]
                        got = verify_pcactn_core(v["pcactn"], v["grant"], now=ctx["now"], audience=ctx["aud"])
                        self.assertFalse(got.allow, got.reason)
                        self.assertIn("unsupported_suite", got.reason or "", got.reason)
                continue
            # Intent Layer v2 (README "Suite capability"): `requires_suite` names the suite a v2 artifact uses. A suite
            # outside this runtime's manifest (supported_suites()) is not compared: the verdict must deny with
            # `unsupported_suite` in its reason (never allow, never another reason), and the vector is counted.
            req_suite = v.get("requires_suite")
            if isinstance(req_suite, str) and req_suite not in SUPPORTED_SUITES:
                skipped_by_suite[req_suite] = skipped_by_suite.get(req_suite, 0) + 1
                with self.subTest(v["name"] + " (unsupported_suite)"):
                    ctx = v["context"]
                    raw = v["pcactn_json"] if "pcactn_json" in v else v["pcactn"]
                    got = verify_pcactn_core(raw, v["grant"], now=ctx["now"], audience=ctx["aud"],
                                             allowed_suites=ctx.get("allowed_suites"),
                                             intent_policy=_intent_policy(ctx), intent_v2=_intent_v2(ctx))
                    self.assertFalse(got.allow, got.reason)
                    # a vector that names its refusal (reason_contains: e.g. the session-root pin checks) reaches it
                    # before the suite work, on every host
                    self.assertIn(v["expect"].get("reason_contains", "unsupported_suite"), got.reason or "", got.reason)
                continue
            with self.subTest(v["name"]):
                raw = v["pcactn_json"] if "pcactn_json" in v else v["pcactn"]
                ctx = v["context"]
                # Intent Layer M2: an `intent-*` vector may carry `context.intent_policy`; `expect.checks.intent` is
                # present exactly when the check was evaluated. Intent Layer v2: `context.intent_v2` is the verifier
                # state; `expect.checks` lists schema / intent_session / layers / accumulators / facts / provenance /
                # classes exactly when reported.
                got = verify_pcactn_core(raw, v["grant"], now=ctx["now"], audience=ctx["aud"],
                                         allowed_suites=ctx.get("allowed_suites"),
                                         intent_policy=_intent_policy(ctx), intent_v2=_intent_v2(ctx))
                self.assertEqual(got.allow, v["expect"]["allow"], got.reason)
                self.assertEqual(got.checks, v["expect"]["checks"], got.reason)
                if "reason_contains" in v["expect"]:
                    self.assertIn(v["expect"]["reason_contains"], got.reason or "", got.reason)
            passed += 1
        total = len(DOC["vectors"])
        skipped = sum(skipped_by_suite.values())
        print(f"\n[vectors] {passed}/{total} passed; {skipped} skipped "
              f"(dilithium-py {'present' if _ML_DSA else 'ABSENT'})")
        for s in sorted(skipped_by_suite):
            print(f"  skip suite {s}: {skipped_by_suite[s]}")
        self.assertEqual(passed + skipped, total)
        # The three cross-impl suites MUST be exercised on BOTH the leaf (requires:"pq") and hops
        # (requires:"pq-nonleaf") whenever their crypto backend is available.
        if _ML_DSA:
            leaf_ran = [v["name"] for v in DOC["vectors"]
                        if v.get("requires") == "pq" and _unsupported_suite(v) is None
                        and _alg(v["pcactn"]) in ("ml-dsa-65", "hybrid-ed25519-ml-dsa-65")]
            hop_ran = [v["name"] for v in DOC["vectors"]
                       if v.get("requires") == "pq-nonleaf" and _unsupported_suite(v) is None
                       and any(_alg(h) in ("ml-dsa-65", "hybrid-ed25519-ml-dsa-65")
                               for h in v["pcactn"].get("cap_chain", []))]
            self.assertTrue(leaf_ran, "cross-impl PQ leaf vectors must run")
            self.assertTrue(hop_ran, "cross-impl PQ non-leaf hop vectors must run")

    def test_smallorder_forgeries_reject(self):
        vs = [v for v in DOC["vectors"] if v["name"].startswith("forge-smallorder-")]
        self.assertEqual(len(vs), 3)
        for v in vs:
            got = verify_pcactn_core(v["pcactn"], v["grant"], now=v["context"]["now"], audience=v["context"]["aud"])
            self.assertFalse(got.allow, v["name"])

    def test_threshold_shares(self):
        """v2.1 agent-leaf share binding: every primitives.threshold_share[] entry must verify over the
        signerSetHash|t-bound share message iff `valid`; in particular the PRE-v2.1 bare agent share and a
        cross-signer-set replay MUST be rejected. An entry whose `requires` suite this runtime lacks is not compared: it
        must be refused (fail closed, unsupported_suite) and is counted."""
        shares = DOC["primitives"]["threshold_share"]
        self.assertTrue(shares)
        accepted = rejected = unsupported = 0
        bare_rejected = wrong_set_rejected = False
        for s in shares:
            name = s.get("name") or s["role"]
            want = s.get("valid", True)
            req = s.get("requires")
            if isinstance(req, str) and req not in SUPPORTED_SUITES:
                unsupported += 1
                with self.subTest(name + " (unsupported_suite)"):
                    self.assertFalse(verify_threshold_share(s), f"{name}: share under unsupported suite {req} verified")
                continue
            with self.subTest(name):
                got = verify_threshold_share(s)
                self.assertEqual(got, want, f"{name}: share verified={got}, want valid={want}")
            if want:
                accepted += 1
            else:
                rejected += 1
            if name == "agent-bare-rejected":
                bare_rejected = not verify_threshold_share(s)
            if name == "agent-bound-wrong-set":
                wrong_set_rejected = not verify_threshold_share(s)
        self.assertTrue(bare_rejected, "v2.1 binding: the pre-v2.1 bare agent share MUST be rejected")
        self.assertTrue(wrong_set_rejected, "v2.1 binding: a cross-signer-set agent share replay MUST be rejected")
        print(f"\n[threshold_share] {accepted} valid accepted, {rejected} invalid rejected "
              f"(incl. v2.1 bare-agent-share + cross-signer-set replay); {unsupported} refused as unsupported_suite")

    def test_pq_artifacts(self):
        """pq_artifact[]: each transparency/authority artifact signature must verify over `message` under its
        suite iff `valid`, for the IMPLEMENTED suites. Artifacts under an unrunnable suite are skipped per suite."""
        arts = DOC["primitives"]["pq_artifact"]
        self.assertTrue(arts)
        checked = 0
        skipped_by_suite = {}
        for a in arts:
            alg = a.get("alg", "ed25519")
            if alg not in SUPPORTED_SUITES:
                skipped_by_suite[alg] = skipped_by_suite.get(alg, 0) + 1
                continue
            with self.subTest(f"{a['artifact']}/{alg}/valid={a['valid']}"):
                self.assertEqual(verify_artifact_suite(a), a["valid"], a.get("description"))
            checked += 1
        skipped = sum(skipped_by_suite.values())
        print(f"\n[pq_artifact] {checked} checked, {skipped} skipped")
        for s in sorted(skipped_by_suite):
            print(f"  skip suite {s}: {skipped_by_suite[s]}")
        self.assertEqual(checked + skipped, len(arts))

    def test_chain_pin(self):
        """R4-01: the standalone verify_chain needs a verifier-side PQ pin (pq_pins) or the stored grant (trusted_root)
        for a non-ed25519 root. Suite capability: an entry whose `requires` suite this runtime lacks is compared only where
        no signature is needed (the pin / policy refusals, decided on the registered suite before any crypto); an entry the
        reference ACCEPTS must be refused with unsupported_suite (fail closed), and one it rejects for a crypto reason must
        be refused. Those are counted as unsupported, never passed."""
        vecs = DOC["primitives"].get("chain_pin", [])
        self.assertGreaterEqual(len(vecs), 25)
        ran = skipped = 0
        for v in vecs:
            req = v.get("requires")
            lacks = isinstance(req, str) and req not in SUPPORTED_SUITES
            pin_reason = v["expect"].get("reason", "").startswith("hop 0: root suite")
            with self.subTest(v["name"]):
                ok, why = verify_chain(v["chain"], v.get("expected_root_issuer"), v.get("allowed_suites"),
                                       pq_pins=v.get("pq_pins"), trusted_root=v.get("trusted_root"))
                if lacks and not pin_reason:
                    self.assertFalse(ok, why)
                    if v["expect"]["ok"]:
                        self.assertIn("unsupported_suite", why or "", why)
                else:
                    self.assertEqual(ok, v["expect"]["ok"], why)
                    if pin_reason:
                        self.assertEqual(why, v["expect"]["reason"])
            if lacks and not pin_reason:
                skipped += 1
            else:
                ran += 1
        print(f"\n[chain_pin] {ran} checked, {skipped} unsupported_suite (suite outside this runtime's manifest)")
        self.assertEqual(ran + skipped, len(vecs))

    def test_intent_schema(self):
        """Rule 14 alone (primitives.intent_schema): `sig` = verify_action_schema, `digest` = action_schema_digest when
        the signature is valid, `conform` = conform_action {ok, code?, path?}. Reasons are not compared."""
        t = _table("intent_schema")
        if t is None:
            print("\n[intent_schema] table absent: 0 checked, 1 table skipped")
            return
        for e in t:
            i, x = _input(e), e["expect"]
            with self.subTest(e["name"]):
                self.assertEqual(verify_action_schema(i["schema"], i["keys"])["ok"], x["sig"], e["name"])
                if "digest" in x:
                    self.assertEqual(action_schema_digest(i["schema"]), x["digest"], e["name"])
                c = conform_action(i["schema"], i["verb"], i["params"])
                got = {"ok": c["ok"]}
                if not c["ok"]:
                    got["code"] = c["code"]
                    if "path" in c:
                        got["path"] = c["path"]
                self.assertEqual(got, x["conform"], e["name"])
        print(f"\n[intent_schema] {len(t)} checked")

    def test_intent_revocation(self):
        """Rule 13 step 7 alone (primitives.intent_revocation, input {epoch, revoked, session, authority, ids, now,
        max_age_ms, last?}): check_session_revocation `ok`. An entry whose epoch names a suite outside this runtime's
        manifest must be refused with unsupported_suite (counted, not compared)."""
        t = _table("intent_revocation")
        if t is None:
            print("\n[intent_revocation] table absent: 0 checked, 1 table skipped")
            return
        for e in t:
            i = _input(e)
            # the EVIDENCE is the input without the check parameters (so an extra input member makes it malformed)
            ev = {k: v for k, v in i.items() if k not in _REV_PARAMS}
            kw = {"last": i["last"]} if "last" in i else {}
            if "scope" in i:
                kw["scope"] = i["scope"]
            alg = i["epoch"].get("alg", "ed25519") if isinstance(i.get("epoch"), dict) else "ed25519"
            with self.subTest(e["name"]):
                got = check_session_revocation(ev, session=i["session"], authority=i["authority"], ids=i["ids"],
                                               now=i["now"], max_age_ms=i["max_age_ms"], **kw)
                if isinstance(alg, str) and alg in REGISTERED_SUITES and alg not in SUPPORTED_SUITES:
                    self.assertFalse(got["ok"])
                    self.assertIn("unsupported_suite", got.get("reason", ""))
                else:
                    self.assertEqual(got["ok"], e["expect"]["ok"], got.get("reason"))
        print(f"\n[intent_revocation] {len(t)} checked")

    def test_intent_map_commit(self):
        """Rule 19 (primitives.intent_map_commit): the commitment of a full leaf list {kind, salt, leaf} exactly."""
        t = _table("intent_map_commit")
        if t is None:
            print("\n[intent_map_commit] table absent: 0 checked, 1 table skipped")
            return
        for e in t:
            with self.subTest(e["name"]):
                self.assertEqual(commit_leaves(_input(e)["leaves"]), e["expect"]["map_commit"], e["name"])
        print(f"\n[intent_map_commit] {len(t)} checked")

    def test_intent_map(self):
        """Rule 19 Z0 (primitives.intent_map): `ok`, and when true the cell indices and `p_ppm` exactly (reasons are not
        compared; `params` absent = {})."""
        t = _table("intent_map")
        if t is None:
            print("\n[intent_map] table absent: 0 checked, 1 table skipped")
            return
        for e in t:
            x = e["expect"]
            with self.subTest(e["name"]):
                got = decide_map_primitive(_input(e))
                self.assertEqual(got["ok"], x["ok"], got.get("reason"))
                if x["ok"]:
                    self.assertEqual(got["cell"], x["cell"], e["name"])
                    self.assertEqual(got["p_ppm"], x["p_ppm"], e["name"])
        print(f"\n[intent_map] {len(t)} checked")

    def test_intent_world(self):
        """Rule 16 alone (primitives.intent_world): `ok`, and when true `world` and `single_source` exactly."""
        t = _table("intent_world")
        if t is None:
            print("\n[intent_world] table absent: 0 checked, 1 table skipped")
            return
        for e in t:
            x = e["expect"]
            with self.subTest(e["name"]):
                got = decide_intent_world(_input(e))
                if _lacks_suite(e):
                    self._assert_suite_refusal(not got["ok"], x["ok"], got.get("reason"))
                    continue
                self.assertEqual(got["ok"], x["ok"], got.get("reason"))
                if x["ok"]:
                    self.assertEqual(got["world"], x["world"], e["name"])
                    self.assertEqual(got["single_source"], x["single_source"], e["name"])
        print(f"\n[intent_world] {len(t)} checked")

    def test_intent_provenance(self):
        """Rule 17 alone (primitives.intent_provenance): `outcome`; unless deny, `labels` and `classes`; for a
        question, `friction`."""
        t = _table("intent_provenance")
        if t is None:
            print("\n[intent_provenance] table absent: 0 checked, 1 table skipped")
            return
        for e in t:
            x = e["expect"]
            with self.subTest(e["name"]):
                got = decide_param_provenance(_input(e))
                if _lacks_suite(e):
                    self._assert_suite_refusal(got["outcome"] == "deny", x["outcome"] != "deny", got.get("reason"))
                    continue
                self.assertEqual(got["outcome"], x["outcome"], got.get("reason"))
                if x["outcome"] != "deny":
                    self.assertEqual(got["labels"], x["labels"], e["name"])
                    self.assertEqual(got["classes"], x["classes"], e["name"])
                if x["outcome"] == "question":
                    self.assertEqual(got["friction"], x["friction"], e["name"])
        print(f"\n[intent_provenance] {len(t)} checked")

    def test_intent_classifier(self):
        """Rule 18 alone (primitives.intent_classifier): `ok`, and when true `classes` exactly."""
        t = _table("intent_classifier")
        if t is None:
            print("\n[intent_classifier] table absent: 0 checked, 1 table skipped")
            return
        for e in t:
            x = e["expect"]
            with self.subTest(e["name"]):
                got = decide_classifier_dimensions(_input(e))
                if _lacks_suite(e):
                    self._assert_suite_refusal(not got["ok"], x["ok"], got.get("reason"))
                    continue
                self.assertEqual(got["ok"], x["ok"], got.get("reason"))
                if x["ok"]:
                    self.assertEqual(got["classes"], x["classes"], e["name"])
        print(f"\n[intent_classifier] {len(t)} checked")

    def test_intent_wb_active(self):
        """Which W-B checks a verifier reports (primitives.intent_wb_active, reference intentWBActive): {facts,
        provenance, classes} exactly. Skipped with a count when the table or atlas_pca.intent_wb.intent_wb_active is absent."""
        import atlas_pca.intent_wb as wb
        t = _table("intent_wb_active")
        fn = getattr(wb, "intent_wb_active", None)
        if t is None or fn is None:
            print("\n[intent_wb_active] %s: 0 checked, 1 table skipped" % ("table absent" if t is None else "intent_wb_active not implemented"))
            return
        for e in t:
            with self.subTest(e["name"]):
                self.assertEqual(fn(_input(e)), e["expect"], e["name"])
        print(f"\n[intent_wb_active] {len(t)} checked")

    def test_intent_read_purpose(self):
        """Read purpose (V14, primitives.intent_read_purpose, reference decideReadPurpose): {outcome, minimise, uncovered}
        exactly. Skipped with a count when the table or atlas_pca.intent_wb.decide_read_purpose is absent."""
        import atlas_pca.intent_wb as wb
        t = _table("intent_read_purpose")
        fn = getattr(wb, "decide_read_purpose", None)
        if t is None or fn is None:
            print("\n[intent_read_purpose] %s: 0 checked, 1 table skipped" % ("table absent" if t is None else "decide_read_purpose not implemented"))
            return
        for e in t:
            with self.subTest(e["name"]):
                got = fn(_input(e))
                self.assertEqual({k: got.get(k) for k in e["expect"]}, e["expect"], e["name"])
        print(f"\n[intent_read_purpose] {len(t)} checked")

    def test_primitives(self):
        prim = DOC["primitives"]
        for c in prim["canonical"]:
            self.assertEqual(canonicalize_strict(c["value"]), c["expect"])
            self.assertEqual(b64u(sha256(c["expect"].encode("utf-8"))), c["hash"])
            self.assertEqual(hash_canonical(c["value"]), c["hash"])
        for m in prim["merkle"]:
            self.assertEqual(merkle_root(m["leaves"]), m["root"])
            for i, pr in enumerate(m["proofs"]):
                self.assertTrue(verify_inclusion(m["root"], pr, m["leaves"][i]))
        self.assertEqual(params_digest(), prim["params_digest_empty"])

    def test_json_parse(self):
        for c in DOC["primitives"]["json_parse"]:
            with self.subTest(_input(c)[:40]):
                if c["accept"]:
                    self.assertEqual(canonicalize_strict(strict_parse(_input(c))), c["canonical"])
                else:
                    with self.assertRaises(StrictJsonError):
                        strict_parse(_input(c))

    def test_b64u(self):
        for c in DOC["primitives"]["b64u"]:
            with self.subTest(_input(c)[:30]):
                self.assertEqual(decode_b64u_strict(_input(c), c.get("len")) is not None, c["valid"])

    def test_threshold_set(self):
        """R6-02/R6-03/R6-04: whole signer-set validation, t in 1..3, PQ-required roles. Entries whose `requires`
        suite this runtime lacks are skipped (counted), never passed."""
        ents = DOC["primitives"].get("threshold_set", [])
        self.assertGreaterEqual(len(ents), 55)
        ran = skipped = 0
        for e in ents:
            req = e.get("requires")
            if req is not None and req not in SUPPORTED_SUITES:
                skipped += 1
                continue
            with self.subTest(e["name"]):
                try:
                    got = verify_threshold_share(e)
                except Exception as ex:  # noqa: BLE001
                    self.fail(f"{e['name']}: raised {type(ex).__name__}: {ex}")
                self.assertEqual(got, e["valid"], e["name"])
            ran += 1
        print(f"\n[threshold_set] {ran} checked, {skipped} skipped")

    def test_signer_set_hash(self):
        ents = DOC["primitives"].get("signer_set_hash", [])
        self.assertGreaterEqual(len(ents), 8)
        for e in ents:
            with self.subTest(e["name"]):
                h = signer_set_hash(e["signer_set"])
                self.assertIsNotNone(h, e["name"])
                self.assertEqual(b64u(h), e["hash"], e["name"])

    def test_malformed(self):
        """R6-05: every malformed input is a clean deny; no exception escapes a public entry point."""
        ents = DOC["primitives"].get("malformed", [])
        self.assertGreaterEqual(len(ents), 80)
        for m in ents:
            i = _input(m)
            with self.subTest(m["name"]):
                try:
                    if m["api"] == "chain":
                        r = verify_chain(i["chain"], i["expected_root_issuer"])
                        self.assertIsInstance(r, tuple)
                        self.assertFalse(r[0], m["name"])
                        self.assertIsInstance(r[1], str)
                    elif m["api"] == "threshold_share":
                        self.assertIs(verify_threshold_share(i), False, m["name"])
                    elif m["api"] == "pcactn_json":
                        v = verify_pcactn_core(i["text"], i["grant"], i["now"], i["aud"])
                        self.assertFalse(v.allow, m["name"])
                    else:
                        self.fail("unknown api " + m["api"])
                except AssertionError:
                    raise
                except Exception as ex:  # noqa: BLE001
                    self.fail(f"{m['name']}: raised {type(ex).__name__}: {ex}")

    def test_depth(self):
        """Nesting depth at limit-1 / limit / limit+1 and huge on every untrusted-input entry point (primitives.depth):
        each verdict equals the reference's, and no exception / RecursionError escapes."""
        ents = DOC["primitives"].get("depth", [])
        self.assertGreaterEqual(len(ents), 29)
        for e in ents:
            with self.subTest(e["name"]):
                inp = _expand_depth(e)
                try:
                    if e["api"] == "chain":
                        got = verify_chain(inp["chain"], inp["expected_root_issuer"])[0]
                    elif e["api"] == "threshold_share":
                        got = verify_threshold_share(inp)
                    elif e["api"] == "pcactn_json":
                        got = verify_pcactn_core(inp["text"], inp["grant"], inp["now"], inp["aud"]).allow
                    elif e["api"] == "json_parse":
                        try:
                            strict_parse(inp["text"])
                            got = True
                        except StrictJsonError:
                            got = False
                    else:
                        self.fail("unknown api " + e["api"])
                except AssertionError:
                    raise
                except BaseException as ex:  # noqa: BLE001 - RecursionError / MemoryError included
                    self.fail(f"{e['name']}: raised {type(ex).__name__}")
                self.assertIs(got, e["valid"], e["name"])


def _expand_depth(e):
    """Apply a depth case's optional `expand` ({marker, levels, leaf}) ITERATIVELY: the verifier, not the runner, must
    face the huge value. chain / threshold_share: the string value equal to `marker` anywhere in input is replaced by
    `levels` nested lists around `leaf`; pcactn_json / json_parse: the substring `marker` of input.text is replaced."""
    inp = _input(e)
    x = e.get("expand")
    if not x:
        return inp
    if e["api"] in ("pcactn_json", "json_parse"):
        nested = "[" * x["levels"] + json.dumps(x["leaf"], separators=(",", ":")) + "]" * x["levels"]
        return dict(inp, text=inp["text"].replace(x["marker"], nested, 1))
    inp = copy.deepcopy(inp)  # the corpus is loaded once per process: never replace the marker in the shared entry
    v = x["leaf"]
    for _ in range(x["levels"]):
        v = [v]
    stack = [inp]
    while stack:
        c = stack.pop()
        items = list(c.items()) if isinstance(c, dict) else list(enumerate(c)) if isinstance(c, list) else []
        for k, val in items:
            if val == x["marker"]:
                c[k] = v
                return inp
            if isinstance(val, (dict, list)):
                stack.append(val)
    raise AssertionError("depth marker not found in " + e["name"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
