"""Differential / mutation kills for atlas_pca/actions.py: the trait algebra against an independent eight-round one-step
implication oracle (random registries with custom traits), exact FloorDecision boundaries, digest invariance, registry refusals
and the rule 22 schema-verb integrity messages. Self-contained and unittest-compatible (mutmut runs it under pytest)."""
import copy
import random
import unittest
from unittest import mock

from atlas_pca import actions as A

REV = ["reversible", "rate_limited", "irreversible"]


def oracle_closure(reg, ids):
    """Eight rounds of one-step implication (the model the proofs reason about), independent of A.closure."""
    cur = set(ids)
    for i in cur:
        if i not in reg:
            return None
    for _ in range(8):
        nxt = set(cur)
        for i in cur:
            nxt |= set(reg[i]["implies"])
        cur = nxt
    return sorted(cur)


def oracle_floor(reg, ids):
    cl = oracle_closure(reg, ids)
    r = {"risk": 0, "rev": "reversible", "blast_ppm": 0, "esc": 0, "caveats": set(), "context": set(), "prules": set()}
    for i in cl:
        f = reg[i]["floor"]
        r["risk"] = max(r["risk"], f["risk"])
        r["esc"] = max(r["esc"], f["esc"])
        r["blast_ppm"] = max(r["blast_ppm"], f["blast_ppm"])
        if REV.index(f["rev"]) > REV.index(r["rev"]):
            r["rev"] = f["rev"]
        for k in ("caveats", "context", "prules"):
            r[k] |= set(f[k])
    return {**r, "caveats": sorted(r["caveats"]), "context": sorted(r["context"]), "prules": sorted(r["prules"])}


def rand_profile(rnd):
    return A.profile({
        "risk": rnd.randint(0, 3), "rev": rnd.choice(REV), "blast_ppm": rnd.choice([0, 1, 50000, 999999, 1000000]), "esc": rnd.randint(0, 3),
        "caveats": rnd.sample(list(A.CAVEAT_KINDS), rnd.randint(0, 3)), "context": rnd.sample(list(A.CONTEXT_KEYS), rnd.randint(0, 2)),
        "prules": rnd.sample(list(A.PARAM_RULE_IDS), rnd.randint(0, 2)),
    })


def rand_registry(rnd, n):
    """Core registry plus n custom traits, each implying earlier ones and extending their floors (a valid registry)."""
    custom = []
    reg = dict(A.CORE_REGISTRY)
    for i in range(n):
        pool = list(reg)
        imp = rnd.sample(pool, rnd.randint(0, 3))
        fl = rand_profile(rnd)
        for u in imp:
            fl = A.join(fl, reg[u]["floor"])
        t = {"id": "acme.t%d" % i, "implies": imp, "floor": fl, "card_phrase": "t%d" % i}
        custom.append(t)
        reg[t["id"]] = t
    return custom


class ActionsOracle(unittest.TestCase):
    def test_closure_and_floor_match_the_oracle_on_random_registries(self):
        rnd = random.Random(0xA7)
        for round_ in range(60):
            custom = rand_registry(rnd, rnd.randint(0, 12))
            reg = A.extend_registry(A.CORE_REGISTRY, custom) if custom else A.CORE_REGISTRY
            ids = list(reg)
            for _ in range(15):
                s = rnd.sample(ids, rnd.randint(0, 5))
                self.assertEqual(A.closure(reg, s), oracle_closure(reg, s))
                self.assertEqual(A.floor_of(reg, s), oracle_floor(reg, s))

    def test_closure_is_idempotent_monotone_and_floor_is_monotone(self):
        rnd = random.Random(7)
        custom = rand_registry(rnd, 10)
        reg = A.extend_registry(A.CORE_REGISTRY, custom)
        ids = list(reg)
        for _ in range(100):
            a = rnd.sample(ids, rnd.randint(0, 4))
            b = a + rnd.sample(ids, rnd.randint(0, 3))
            ca, cb = A.closure(reg, a), A.closure(reg, b)
            self.assertEqual(A.closure(reg, ca), ca)
            self.assertTrue(set(ca) <= set(cb))
            self.assertTrue(A.leq(A.floor_of(reg, a), A.floor_of(reg, b)))
            for t in ca:
                self.assertTrue(A.leq(reg[t]["floor"], A.floor_of(reg, a)))

    def test_unknown_trait_is_refused_with_its_name(self):
        with self.assertRaises(A.ActionKitError) as c:
            A.closure(A.CORE_REGISTRY, ["pca.nope"])
        self.assertEqual((c.exception.code, str(c.exception)), ("unknown_trait", "unknown trait 'pca.nope'"))

    def test_implies_depth_eight_accepted_nine_refused(self):
        def chain(n):
            return [{"id": "acme.c%d" % i, "implies": ["acme.c%d" % (i + 1)] if i < n - 1 else [], "floor": A.profile(), "card_phrase": "c"} for i in range(n)]
        reg = A.extend_registry(A.CORE_REGISTRY, chain(8))
        self.assertEqual(len(A.closure(reg, ["acme.c0"])), 8)
        with self.assertRaises(A.ActionKitError) as c:
            A.extend_registry(A.CORE_REGISTRY, chain(9))
        self.assertEqual(str(c.exception), "trait 'acme.c0': implies depth 9 exceeds 8")

    def test_registry_refusals_exact(self):
        P = A.profile()
        t = lambda i, im=(), fl=P, cp="x": {"id": i, "implies": list(im), "floor": fl, "card_phrase": cp}
        cases = [
            ([t("acme.a"), t("acme.a")], "trait 'acme.a' is defined twice"),
            ([t("pca.new")], "trait 'pca.new': the pca. namespace is reserved for core traits"),
            ([t("acme.a", ["acme.zz"])], "trait 'acme.a' implies unknown trait 'acme.zz'"),
            ([t("acme.a", ["acme.b"]), t("acme.b", ["acme.a"])], "trait 'acme.a': implies cycle"),
            ([t("acme.a", ["acme.b"]), t("acme.b", [], A.profile({"esc": 1}))], "trait 'acme.a': floor is below the floor of implied 'acme.b' (a trait may only extend what it implies)"),
            ([t("acme.a", [], P, "")], "trait 'acme.a': card_phrase must be a non-empty string up to 120 characters"),
            ([t("acme.a", [], P, "y" * 121)], "trait 'acme.a': card_phrase must be a non-empty string up to 120 characters"),
            ([t("Acme.a")], "trait id 'Acme.a' is malformed"),
        ]
        for defs, msg in cases:
            self.assertEqual(A.registry_error(defs), msg)
        self.assertIsNone(A.registry_error([t("acme.a", [], P, "y" * 120)]))
        self.assertIsNone(A.registry_error([t("pca.new")], core=True))
        self.assertIsNotNone(A.registry_error([t("acme.t%d" % i) for i in range(513)]))
        self.assertIsNone(A.registry_error([t("acme.t%d" % i) for i in range(512)]))
        nine = [t("acme.i%d" % i) for i in range(9)]
        self.assertEqual(A.registry_error([t("acme.a", [x["id"] for x in nine])] + nine), "trait 'acme.a': implies must be up to 8 distinct trait ids")
        self.assertIsNone(A.registry_error([t("acme.a", [x["id"] for x in nine[:8]])] + nine[:8]))

    def test_profile_error_bounds(self):
        ok = A.profile()
        self.assertIsNone(A.profile_error(ok))
        for k, v in (("risk", 4), ("risk", -1), ("esc", 4), ("blast_ppm", 1000001), ("blast_ppm", -1), ("rev", "x")):
            self.assertIsNotNone(A.profile_error({**ok, k: v}), (k, v))
        for k, v in (("risk", 3), ("esc", 3), ("blast_ppm", 1000000)):
            self.assertIsNone(A.profile_error({**ok, k: v}))
        self.assertEqual(A.profile_error({**ok, "caveats": ["window", "amount_cap"]}), "profile.caveats must be sorted and distinct")
        self.assertEqual(A.profile_error({**ok, "caveats": ["window", "window"]}), "profile.caveats must be sorted and distinct")

    def test_floor_decision_boundaries(self):
        g = {"caveats": ["amount_cap", "window"], "max_esc": 2, "preauth_esc": 1}
        call = {"context": ["idempotency"]}
        p = lambda **k: A.profile(k)
        fd = lambda rho, grant=g, c=call: A.floor_decision(grant, c, rho)
        self.assertEqual(fd(p(esc=1)), "allow")            # esc == preauth is allowed
        self.assertEqual(fd(p(esc=2)), "escalate")         # above preauth, at max: escalate
        self.assertEqual(fd(p(esc=3)), "deny")             # above max: deny
        self.assertEqual(fd(p(esc=3), {**g, "max_esc": 3, "preauth_esc": 3}), "allow")
        self.assertEqual(fd(p(esc=2), {**g, "max_esc": 2, "preauth_esc": 2}), "allow")
        self.assertEqual(fd(p(caveats=["amount_cap"])), "allow")                 # rho subset of grant
        self.assertEqual(fd(p(caveats=["amount_cap", "window"])), "allow")       # equal sets
        self.assertEqual(fd(p(caveats=["count_cap"])), "escalate")               # rho needs one the grant lacks
        self.assertEqual(fd(p(), {**g, "caveats": []}), "allow")                 # grant extra caveats never matter in reverse
        self.assertEqual(fd(p(context=["idempotency"])), "allow")
        self.assertEqual(fd(p(context=["revocable"])), "escalate")
        self.assertEqual(fd(p(context=["idempotency"]), g, {"context": []}), "escalate")
        self.assertEqual(fd(p(esc=3, caveats=["count_cap"])), "deny")            # deny wins over escalate

    def test_floor_decision_antitone_on_random_profiles(self):
        rnd = random.Random(99)
        rank = {"deny": 0, "escalate": 1, "allow": 2}
        for _ in range(400):
            g = {"caveats": rnd.sample(list(A.CAVEAT_KINDS), rnd.randint(0, 5)), "max_esc": rnd.randint(0, 3), "preauth_esc": rnd.randint(0, 3)}
            c = {"context": rnd.sample(list(A.CONTEXT_KEYS), rnd.randint(0, 4))}
            p = rand_profile(rnd)
            q = A.join(p, rand_profile(rnd))
            self.assertLessEqual(rank[A.floor_decision(g, c, q)], rank[A.floor_decision(g, c, p)])

    def test_join_and_leq_exact(self):
        a = A.profile({"risk": 1, "rev": "rate_limited", "blast_ppm": 5, "esc": 2, "caveats": ["window"], "context": ["revocable"], "prules": ["array_bounded"]})
        b = A.profile({"risk": 2, "rev": "reversible", "blast_ppm": 9, "esc": 1, "caveats": ["amount_cap"]})
        j = A.join(a, b)
        self.assertEqual(j, {"risk": 2, "rev": "rate_limited", "blast_ppm": 9, "esc": 2, "caveats": ["amount_cap", "window"], "context": ["revocable"], "prules": ["array_bounded"]})
        self.assertEqual(A.join(b, a), j)
        self.assertTrue(A.leq(a, j) and A.leq(b, j) and not A.leq(j, a) and not A.leq(j, b))
        for k, v in (("risk", 2), ("rev", "irreversible"), ("blast_ppm", 6), ("esc", 3), ("caveats", ["window", "count_cap"]), ("context", ["idempotency"]), ("prules", ["export_bounded"])):
            self.assertFalse(A.leq({**a, k: v} if k not in ("caveats", "context", "prules") else {**a, k: sorted(set(a[k]) | set(v))}, a), k)
        self.assertTrue(A.leq(a, a) and A.leq(A.BOTTOM, a))

    def test_core_registry_shape(self):
        self.assertEqual(len(A.CORE_REGISTRY), 22)
        mm = A.CORE_REGISTRY["pca.money_moving"]["floor"]
        self.assertEqual((mm["risk"], mm["rev"], mm["blast_ppm"], mm["esc"]), (3, "rate_limited", 700000, 2))
        imp = A.CORE_REGISTRY["pca.impersonation"]
        self.assertEqual(imp["implies"], ["pca.external_communication"])
        self.assertTrue(A.leq(A.CORE_REGISTRY["pca.external_communication"]["floor"], imp["floor"]))
        self.assertEqual(imp["floor"]["rev"], "irreversible")
        self.assertEqual(A.floor_of(A.CORE_REGISTRY, []), A.BOTTOM)


def base_def():
    return {
        "v": 1, "kind": "pca-action-def", "verb": "acme.thing.refund", "aliases": ["refund", "undo"], "title": "Refund",
        "effects": ["pay", "update"], "resource": {"type": "acme.thing", "id": {"prefix": "t_", "class": "alnum", "len": [4, 32]}, "scope": "one"},
        "params": {
            "amount": {"type": "integer", "role": "money.amount", "min": 1, "max": 100, "unit": {"kind": "money", "ccy": "USD", "exp": 2}},
            "key": {"type": "string", "max_len": 64},
        },
        "idempotency": {"mode": "key_param", "param": "key"}, "context": ["revocable", "idempotency"], "traits": ["pca.bulk", "pca.cost_incurring"],
        "review": {"state": "authored"},
    }


def shuffled(rnd, v):
    if isinstance(v, dict):
        ks = list(v)
        rnd.shuffle(ks)
        return {k: shuffled(rnd, v[k]) for k in ks}
    return [shuffled(rnd, x) for x in v] if isinstance(v, list) else v


class ActionsDigest(unittest.TestCase):
    def test_def_is_valid_and_digest_is_invariant(self):
        d = base_def()
        self.assertIsNone(A.validate_def(d))
        want = A.def_digest(d)
        rnd = random.Random(5)
        for _ in range(25):
            e = shuffled(rnd, d)
            for k in ("aliases", "effects", "context", "traits"):
                rnd.shuffle(e[k])
            self.assertEqual(A.def_digest(e), want)
        e = copy.deepcopy(d)
        e["review"] = {"state": "unreviewed"}
        e["since"] = "9.9"
        e["examples"] = [{"params": {}, "expect": "deny"}]
        self.assertEqual(A.def_digest(e), want)

    def test_every_defining_member_changes_the_digest(self):
        d = base_def()
        want = A.def_digest(d)
        edits = [
            lambda e: e.update(title="Refund!"), lambda e: e.update(verb="acme.thing.refund2"), lambda e: e["aliases"].append("x1"),
            lambda e: e["effects"].remove("update"), lambda e: e["params"]["amount"].update(max=101), lambda e: e["params"]["key"].update(max_len=65),
            lambda e: e.update(reversibility="rate_limited"), lambda e: e.update(blast={"radius": "tenant"}), lambda e: e["context"].append("dry_run_first"),
            lambda e: e["traits"].remove("pca.bulk"), lambda e: e["resource"].update(scope="set"), lambda e: e.update(description="d"),
            lambda e: e.update(side_effects=[{"target": "t", "kind": "send"}]),
        ]
        seen = {want}
        for f in edits:
            e = copy.deepcopy(d)
            f(e)
            self.assertIsNone(A.validate_def(e))
            dg = A.def_digest(e)
            self.assertNotIn(dg, seen)
            seen.add(dg)

    def test_normalize_defaults_and_ppm(self):
        n = A.normalize(base_def())
        self.assertEqual(n["blast"], {"radius": "one", "ppm": 50000})
        self.assertEqual(n["reversibility"], "irreversible")
        self.assertEqual(n["aliases"], ["refund", "undo"])
        self.assertEqual(n["params"]["amount"]["accumulates"], ["money.usd"])
        self.assertEqual((n["params"]["amount"]["sensitivity"], n["params"]["key"]["sensitivity"], n["params"]["key"]["required"]), ("critical", "free", True))
        d = base_def()
        d["blast"] = {"radius": "bounded", "ppm": 1}
        self.assertEqual(A.normalize(d)["blast"], {"radius": "bounded", "ppm": 300000})  # ppm only raises
        d["blast"] = {"radius": "bounded", "ppm": 300001}
        self.assertEqual(A.normalize(d)["blast"]["ppm"], 300001)
        ro = base_def()
        ro["effects"] = ["read"]
        del ro["idempotency"]["param"]
        ro["idempotency"] = {"mode": "none"}
        self.assertEqual(A.normalize(ro)["reversibility"], "reversible")

    def test_effective_joins_decl_and_floor(self):
        d = base_def()
        e = A.effective(d, A.CORE_REGISTRY)  # no reviewer pinned: unconfirmed means every trait of the registry
        self.assertFalse(e["confirmed"])
        self.assertEqual(e["traits"], A.top_traits(A.CORE_REGISTRY))
        self.assertEqual(e["closure"], e["traits"])
        d["review"] = {"state": "confirmed"}  # confirmed without a valid attestation is still the top
        self.assertEqual(A.effective(d, A.CORE_REGISTRY)["traits"], A.top_traits(A.CORE_REGISTRY))
        with mock.patch.object(A, "verify_attestation", return_value=True):  # signed paths are pinned by the shared vectors
            e = A.effective(d, A.CORE_REGISTRY)
        self.assertTrue(e["confirmed"])
        self.assertEqual(e["traits"], ["pca.bulk", "pca.cost_incurring", "pca.irreversible", "pca.money_moving"])
        self.assertNotIn("pca.unreviewed", e["traits"])
        self.assertEqual(e["eff"], A.join(e["decl"], e["floor"]))
        self.assertEqual(e["eff"]["blast_ppm"], 700000)       # the floor (money_moving) lifts the declared 50000
        self.assertEqual(e["decl"]["blast_ppm"], 50000)
        self.assertEqual(e["decl"]["risk"], 2)                 # a critical parameter
        d["effects"], d["params"] = ["read"], {"q": {"type": "string", "max_len": 5}}
        d["idempotency"], d["review"], d["traits"] = {"mode": "none"}, {"state": "authored"}, []
        e = A.effective(d, A.CORE_REGISTRY)  # authored no longer counts as confirmed
        self.assertEqual(e["traits"], A.top_traits(A.CORE_REGISTRY))
        self.assertEqual(e["decl"]["risk"], 0)
        self.assertEqual(e["decl"]["rev"], "reversible")

    def test_validate_def_refusals(self):
        bad = [
            lambda d: d.update(world=[]), lambda d: d["params"]["amount"].update(default=0.5), lambda d: d.update(title="é"),
            lambda d: d.update(title="x\ud800"), lambda d: d.update(effects=[]), lambda d: d.update(effects=["pay", "pay"]),
            lambda d: d.update(verb="Acme.x"), lambda d: d.update(aliases=["acme.thing.refund"]), lambda d: d["params"].update({"a.b.c.d": {"type": "boolean"}}),
            lambda d: d["params"].update({"constructor": {"type": "boolean"}}), lambda d: d["params"]["key"].update(role="money.amount"),
            lambda d: d["params"]["amount"].update(min=5, max=1), lambda d: d.update(idempotency={"mode": "key_param", "param": "nope"}),
            lambda d: d.update(idempotency={"mode": "none", "param": "key"}), lambda d: d["resource"].update(id={"prefix": "x", "class": "uuid", "len": [36, 36]}),
            lambda d: d.update(blast={"radius": "one", "ppm": 1000001}), lambda d: d.update(context=["session_taint_max:Bad"]),
            lambda d: d.update(title="t" * 121), lambda d: d.update(v=2), lambda d: d.update(review={"state": "nope"}),
        ]
        for f in bad:
            d = base_def()
            f(d)
            self.assertIsNotNone(A.validate_def(d))
        ok = base_def()
        ok["title"] = "t" * 120
        ok["blast"] = {"radius": "one", "ppm": 1000000}
        ok["context"] = ["session_taint_max:high"]
        self.assertIsNone(A.validate_def(ok))
        self.assertTrue(A.validate_def([]).startswith("def must be"))
        self.assertTrue(A.validate_def({"a": float("nan")}).startswith("not strict JSON"))


def sverb(**over):
    f = A.floor_of(A.CORE_REGISTRY, ["pca.irreversible"])
    v = {"verb": "a.b", "kind": "write", "params": {"action.params.x": {"type": "boolean"}}, "effects": ["update"],
         "traits": ["pca.irreversible"], "def": "A" * 43, "floors": f}
    v.update(over)
    return v


class SchemaVerbIntegrity(unittest.TestCase):
    R = A.CORE_REGISTRY

    def setUp(self):  # these cases are about the implied-trait and floor checks of a CONFIRMED verb
        p = mock.patch.object(A, "verb_confirmation_error", return_value=None)
        p.start()
        self.addCleanup(p.stop)

    def test_honest_verb_passes(self):
        self.assertIsNone(A.schema_verb_floor_error(sverb(), self.R))

    def test_forged_floors_each_field(self):
        f = A.floor_of(self.R, ["pca.irreversible"])
        msg = "schema_floor_forged: floors are below the floor of the carried traits"
        for k, v in (("esc", f["esc"] - 1), ("risk", f["risk"] - 1), ("rev", "rate_limited"), ("context", []), ("blast_ppm", -1)):
            self.assertEqual(A.schema_verb_floor_error(sverb(floors={**f, k: v}), self.R), msg, k)
        # equal and higher floors are fine
        self.assertIsNone(A.schema_verb_floor_error(sverb(floors={**f, "esc": 3}), self.R))

    def test_dropped_and_unknown_traits(self):
        self.assertEqual(A.schema_verb_floor_error(sverb(traits=[]), self.R), "schema_traits_forged: missing implied trait pca.irreversible")
        self.assertEqual(A.schema_verb_floor_error(sverb(traits=["pca.irreversible", "pca.zzz"]), self.R), "unknown_trait: unknown trait 'pca.zzz'")
        pay = sverb(effects=["pay"], traits=["pca.irreversible"])
        self.assertEqual(A.schema_verb_floor_error(pay, self.R), "schema_traits_forged: missing implied trait pca.money_moving")

    def test_declared_reversibility_floor(self):
        v = sverb(reversibility="rate_limited", traits=[], floors=A.profile({"rev": "reversible"}))
        self.assertEqual(A.schema_verb_floor_error(v, self.R), "schema_floor_forged: floors.rev is below the declared reversibility")
        v["floors"] = A.profile({"rev": "rate_limited"})
        self.assertIsNone(A.schema_verb_floor_error(v, self.R))
        rd = sverb(kind="read", effects=["read"], traits=[], floors=A.profile())
        self.assertIsNone(A.schema_verb_floor_error(rd, self.R))
        by = sverb(reversibility_by={"param": "action.params.x", "map": {"true": "reversible", "false": "rate_limited"}}, traits=[], floors=A.profile({"rev": "rate_limited"}))
        self.assertIsNone(A.schema_verb_floor_error(by, self.R))   # a boolean map covers its domain: no default needed
        by["floors"] = A.profile({"rev": "reversible"})
        self.assertEqual(A.schema_verb_floor_error(by, self.R), "schema_floor_forged: floors.rev is below the declared reversibility")

    def test_implied_traits_from_roles_tags_arrays(self):
        P = lambda **k: {"action.params.x": k}
        cases = [
            (P(type="string", role="url.target"), "pca.network_egress"), (P(type="string", tags=["pii"]), "pca.pii_access"),
            (P(type="string", tags=["pci"]), "pca.regulated_data"), (P(type="string", role="credential.key"), "pca.credential_access"),
            (P(type="array", items="string"), "pca.bulk"),
        ]
        for params, t in cases:
            v = sverb(params=params, traits=["pca.irreversible"])
            self.assertEqual(A.schema_verb_floor_error(v, self.R), "schema_traits_forged: missing implied trait " + t)
        self.assertIsNone(A.schema_verb_floor_error(sverb(params=P(type="array", items="string", max_items=3)), self.R))
        ro = sverb(kind="read", effects=["read"], traits=[], floors=A.profile(), params=P(type="integer", role="money.amount"))
        self.assertEqual(A.schema_verb_floor_error(ro, self.R), "schema_traits_forged: missing implied trait pca.financial_data_read")

    def test_not_v2_and_malformed(self):
        v = sverb()
        del v["floors"]
        self.assertEqual(A.schema_verb_floor_error(v, self.R), "schema_floor_forged: not a v2 verb")
        self.assertTrue(A.schema_verb_floor_error(sverb(effects=["zzz"]), self.R).startswith("schema_floor_forged"))

    def test_whole_document(self):
        doc = {"verbs": [sverb()]}
        self.assertIsNone(A.schema_floor_error(doc))
        self.assertEqual(A.schema_floor_error({"verbs": [sverb(traits=[])]}), "a.b: schema_traits_forged: missing implied trait pca.irreversible")
        doc["traits_digest"] = A.traits_digest(A.CORE_REGISTRY)
        self.assertIsNone(A.schema_floor_error(doc))
        doc["traits_digest"] = "B" * 43
        self.assertTrue(A.schema_floor_error(doc).startswith("traits_digest_mismatch: "))
        cust = {"id": "acme.x", "implies": ["pca.irreversible"], "floor": A.floor_of(self.R, ["pca.irreversible"]), "card_phrase": "x"}
        reg = A.extend_registry(A.CORE_REGISTRY, [cust])
        d2 = {"verbs": [sverb(traits=["acme.x", "pca.irreversible"])], "trait_defs": [cust], "traits_digest": A.traits_digest(reg)}
        self.assertIsNone(A.schema_floor_error(d2))
        d2["trait_defs"] = [{**cust, "id": "pca.sneaky"}]
        self.assertTrue(A.schema_floor_error(d2).startswith("bad_registry: "))


class UnconfirmedVerb(unittest.TestCase):
    R = A.CORE_REGISTRY

    def test_unconfirmed_must_carry_every_trait(self):
        top = A.top_traits(self.R)
        v = sverb(traits=top, floors=A.floor_of(self.R, top))
        self.assertIsNone(A.schema_verb_floor_error(v, self.R))
        v["traits"] = [t for t in top if t != "pca.bulk"]
        self.assertEqual(A.schema_verb_floor_error(v, self.R), "schema_traits_forged: unconfirmed action must carry every trait (missing pca.bulk)")
        self.assertIsNotNone(A.schema_verb_floor_error(sverb(), self.R))

    def test_pins_errors_mean_unconfirmed(self):
        k = {"kid": "k", "pk": "A" * 43, "roles": ["reviewer"]}
        self.assertIsNone(A.reviewer_pins_error({"keys": [k]}))
        for bad in ({}, {"keys": [{**k, "roles": ["reviewer", "model"]}]}, {"keys": [k, k]}, {"keys": [{**k, "pk": "A" * 42}]},
                    {"keys": [k, {**k, "kid": "m", "roles": ["importer"]}]}, {"keys": [{**k, "not_after": -1}]}):
            self.assertIsNotNone(A.reviewer_pins_error(bad))
            self.assertIsNotNone(A.verb_confirmation_error(sverb(), self.R, bad))
        self.assertFalse(A.verify_attestation({"review": {"state": "confirmed"}}, self.R, {"keys": [k]}))


class PackProof(unittest.TestCase):
    def test_every_leaf_proves_and_sizes_cover_non_powers_of_two(self):
        from atlas_pca.pca import verify_inclusion
        for n in (1, 2, 3, 5, 8, 9, 17):
            ds = ["d%03d" % i for i in range(n)]
            root = A.pack_root(ds)
            self.assertEqual(root, A.pack_root(list(reversed(ds))))
            for d in ds:
                p = A.pack_proof(ds, d)
                self.assertEqual((p["size"], p["index"]), (n, ds.index(d)))
                self.assertTrue(verify_inclusion(root, p, A._leaf(d)))
                self.assertFalse(verify_inclusion(root, p, A._leaf(d + "x")))
        with self.assertRaises(A.ActionKitError):
            A.pack_root(["a", "a"])
        with self.assertRaises(A.ActionKitError):
            A.pack_root([])
        with self.assertRaises(A.ActionKitError):
            A.pack_proof(["a"], "b")


if __name__ == "__main__":
    unittest.main()
