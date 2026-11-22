"""Differential replay of the wallet side of the Intent Layer v2 (atlas_pca.wallet, wallet_card, wallet_pricing, wallet_omega:
signed answers, friction tiers, cell coordinates, noise numerics, canaries, approval fatigue, risk-priced escalation, the trusted card,
clarification) against vectors generated from the TypeScript reference (@atlasauth/pca-wallet). A reference throw requires the port to
raise. Doubles from transcendental functions (the information gain, the population noise) are compared to 1e-12 relative; the channel scenarios,
which carry the exact Clopper-Pearson noise bounds, the admission policy and etaUnderLoad, are compared exactly. The trusted question channel, population priors and
question delivery are replayed through wallet_population / wallet_delivery / wallet_channel (the channel scenarios drive a whole session)."""
import copy
import hashlib
import math

import pytest

from atlas_pca import (ed25519, wallet as W, wallet_card as C, wallet_channel as CH, wallet_delivery as DL, wallet_handlers as H, wallet_omega as O,
                       wallet_population as PO, wallet_pricing as P)
from base_oracle import b64d, canon, load_ref, norm, run

ed25519.allow_insecure_signer()
COUNT, CASES = load_ref("wallet")
OM = CASES["omegas"][0]["out"]

NOT_PORTED = set()


def seed(label):
    return hashlib.sha256(("atlas-pca-conformance/" + label).encode()).digest()


def key(k):
    """A signing key: the loader has already turned {"$seed": label} into the base64url of its seed."""
    return b64d(k) if isinstance(k, str) else seed(k["$seed"])


def sub(x):
    if isinstance(x, list):
        return [sub(v) for v in x]
    if isinstance(x, dict):
        if list(x) == ["$omega"]:
            return OM[x["$omega"]]
        if list(x) == ["$seed"]:
            return seed(x["$seed"])
        return {k: sub(v) for k, v in x.items()}
    return x


def vs_of(i, verb):
    return next(v for v in OM[i]["verbs"] if v["verb"] == verb)


def close(got, out, case=None):
    a, b = norm(got), out
    return _close(a, b)


def _close(a, b):
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_close(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_close(x, y) for x, y in zip(a, b))
    if isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool) and not isinstance(b, bool):
        return math.isclose(a, b, rel_tol=1e-12, abs_tol=1e-15)
    return canon(a) == canon(b)


def verify_wrapped(a, principals=None):
    r = W.verify_intent_answer(a, principals)
    return {"ok": False, "reason": "malformed answer"} if r["ok"] is False and r["reason"].startswith("malformed answer:") else r


def pick(ctx):
    ctx = sub(ctx)
    rands = list(ctx["rands"])
    state = {"i": 0}

    def rand():
        if state["i"] >= len(rands):
            raise RuntimeError("rand exhausted")
        state["i"] += 1
        return rands[state["i"] - 1]

    c = {"omega": ctx["omega"], "confirmed": ctx["confirmed"], "knownNo": lambda v, idx: ctx["knownNo"].get(W.cell_key(v, idx)),
         "knownYes": ctx["knownYes"], "exclude": set(ctx["exclude"]), "rand": rand, "lowHarmSession": ctx["lowHarmSession"],
         "canariesSoFar": ctx["canariesSoFar"]}
    if "rho" in ctx:
        c["rho"] = ctx["rho"]
    return W.pick_canary(c)


def sliding(window, ops):
    c = W.SlidingWindowCounter() if window is None else W.SlidingWindowCounter(window)
    out = []
    for op in ops:
        try:
            out.append({"v": c.count(op[1]) if op[0] == "count" else c.try_add(op[1], op[2])})
        except Exception:  # noqa: BLE001
            out.append({"err": True})
    return out


def resolve(om, verb, coords):
    r = W.resolve_coords(sub(om), verb, coords)
    return {"ok": True, "verb": r["vs"]["verb"], "box": r["box"]} if r["ok"] else r


def of_action(i, a):
    r = W.cell_of_action(OM[i], a)
    return {"verb": r["vs"]["verb"], "idx": r["idx"]} if r else None


def render(x):
    x = dict(x)
    om = OM[x.pop("omegaId")]
    return C.render_card({"omega": om, **x})


def card_body(c):
    return {k: v for k, v in c.items() if k != "rendered_digest"}


def plan(x):
    x = sub(x)
    v = x["view"]
    view = {"p": lambda verb, i: v["p"].get(W.cell_key(verb, i), 0), "vetoed": lambda verb, i: W.cell_key(verb, i) in v["vetoed"],
            "outsideCeiling": lambda verb, i: W.cell_key(verb, i) in v["ceiling"]}
    return C.plan_clarification({"omega": x["omega"], "view": view, "candidates": x["candidates"], "asked": set(x["asked"]),
                                 "etaPos": x["etaPos"], "etaNeg": x["etaNeg"]})


def upd(cfg, cal, ans, risks):
    return P.update_calibration(cfg, cal, ans, risks)


def sign_with(fn):
    return lambda body, k: fn(body, key(k))


def constants():
    return {
        "FRICTION_ORDER": list(W.FRICTION_ORDER), "INTENT_ANSWER_SIG_DOMAIN": W.INTENT_ANSWER_SIG_DOMAIN,
        "INTENT_ANSWER_REF_DOMAIN": W.INTENT_ANSWER_REF_DOMAIN, "INTENT_TYPED_DOMAIN": W.INTENT_TYPED_DOMAIN,
        "INTENT_DEVICE_CHALLENGE_DOMAIN": W.INTENT_DEVICE_CHALLENGE_DOMAIN, "MIN_HOLD_MS": W.MIN_HOLD_MS,
        "PROVENANCE_ORDER": list(W.PROVENANCE_ORDER), "DEFAULT_FRICTION_THRESHOLDS": W.DEFAULT_FRICTION_THRESHOLDS,
        "CARD_DOMAIN": C.CARD_DOMAIN, "CLARIFY_REASONS": list(C.CLARIFY_REASONS), "REASON_LABELS": C.REASON_LABELS,
        "MAX_CANDIDATES": C.MAX_CANDIDATES, "EMPTY_NOISE": W.EMPTY_NOISE, "NOISE_PRIOR": W.NOISE_PRIOR,
        "DEFAULT_FATIGUE": W.DEFAULT_FATIGUE, "PPM": P.PPM, "MAX_MULTIPLIER_PPM": P.MAX_MULTIPLIER_PPM,
    }


def omega_dim(i, verb, k):
    return vs_of(i, verb)["dims"][k]


# ---- population priors, delivery and the question channel -------------------------------------------------------------------------------------

def seq(xs):
    state = {"i": 0}

    def rand():
        if state["i"] >= len(xs):
            raise RuntimeError("rand exhausted")
        state["i"] += 1
        return xs[state["i"] - 1]
    return rand


def aggregate(schema, period, opts, votes, rel, rands):
    a = PO.PopulationAggregator(schema, period, {**({"maxCellsPerPrincipal": opts["maxCellsPerPrincipal"]} if "maxCellsPerPrincipal" in opts else {}), "rand": seq(rands)})
    vr = [a.contribute(v) for v in votes]
    try:
        release = a.release(rel)
    except Exception:  # noqa: BLE001
        release = {"err": True}
    return {"votes": vr, "release": release}


def prior(rel, beta, i, verb, contained):
    pm = PO.population_prior(rel, beta)
    return {"beta": pm["beta"], "weight": pm["weight"](vs_of(i, verb), lambda c: c in contained)}


def notice(ir, keys, site, now, *inbox):
    return DL.site_question_notice(ir, {"keys": keys, "site": site, "now": now, **({"inboxUrl": inbox[0]} if inbox else {})})


def hook(cfg, script, notices):
    calls, idx = [], [0]

    def fetch(url, init):
        calls.append({"url": url, "method": init["method"], "headers": init["headers"], "body": init["body"]})
        step = script[idx[0]] if idx[0] < len(script) else {"ok": True, "status": 200}
        idx[0] += 1
        if step.get("throw"):
            raise RuntimeError(step["throw"])
        return {"ok": step["ok"], "status": step["status"]}
    ch = DL.question_webhook_channel({**({"url": cfg["url"]} if "url" in cfg else {}), **({"headers": cfg["headers"]} if cfg.get("headers") else {}), "fetch": fetch})
    return {"kind": ch.kind, "enabled": ch.enabled, "deliveries": [ch.notify(n) for n in notices], "calls": calls}


def tchan(kind, name, script, notices):
    sent, idx = [], [0]
    cfg = {"siteName": name}
    if script is not None:
        def send(b):
            sent.append(b)
            st = script[idx[0]] if idx[0] < len(script) else None
            idx[0] += 1
            if st and st.get("throw"):
                raise RuntimeError(st["throw"])
        cfg["send"] = send
    ch = DL.question_text_channel(kind, cfg)
    return {"kind": ch.kind, "enabled": ch.enabled, "deliveries": [ch.notify(n) for n in notices], "sent": sent}


def dispatch(cfgs, note):
    chans = []
    for c in cfgs:
        if c["type"] == "webhook":
            chans.append(DL.question_webhook_channel({**({"url": c["url"]} if "url" in c else {}), "fetch": lambda url, init: {"ok": True, "status": 200}}))
        else:
            chans.append(DL.question_text_channel(c["type"], {"siteName": "S", **({"send": lambda b: None} if c.get("enabled") else {})}))
    d = DL.create_question_dispatcher(chans)
    return {"n": len(d.channels), "deliveries": d.notify_all(note)}


def channel(spec0):
    spec = sub(spec0)
    state = {"t": spec["t0"], "counts": spec["noise"]}
    hourly = W.SlidingWindowCounter(spec["windowMs"]) if "windowMs" in spec else W.SlidingWindowCounter()
    for ts in spec["hourlyPre"]:
        hourly.try_add(ts, 9007199254740991)
    rand = seq(spec["rands"])
    V = spec["view"]
    view = {"p": lambda v, i: V["p"].get(W.cell_key(v, i), 0), "vetoed": lambda v, i: W.cell_key(v, i) in V["vetoed"],
            "outsideCeiling": lambda v, i: W.cell_key(v, i) in V["ceiling"], "confirmed": lambda: V["confirmed"]}

    def on_noise(n):
        state["counts"] = n

    def lift(a):
        v = W.action_values_of(a)
        return {"verb": v["verb"], "values": {**v["values"], **spec["lift"]["add"]}}

    opts = {"omega": spec["omega"], "session": spec["session"], "mapDigest": lambda: spec["mapDigest"], "principalSecret": seed(spec["principal"]), "site": spec["site"],
            "view": view, "hourly": hourly, "noise": lambda: state["counts"], "onNoise": on_noise, "rand": rand, "now": lambda: state["t"]}
    for k in ("statementText", "units", "sensitivity", "identityPaths", "caps", "rho", "fatigue", "maxPerScreen", "maxBoxCells"):
        if k in spec and (spec[k] or k in ("rho", "maxPerScreen", "maxBoxCells", "statementText")):
            opts[k] = spec[k]
    if spec.get("device"):
        opts["device"] = copy.deepcopy(spec["device"])
    if spec.get("liftCand"):
        opts["liftCandidate"] = lambda a: {"verb": a["verb"], "values": {**a["values"], **spec["liftCand"]}}
    if spec.get("lift"):
        opts["lift"] = lift
    ch = CH.TrustedChannel(opts)
    seen, steps = [], []
    resolver = lambda sid: ch if sid == spec["session"] else None  # noqa: E731
    for st in spec["steps"]:
        try:
            q = st.get("q")
            qid = (seen[q] if q < len(seen) else None) if q is not None else st.get("qid")
            op = st["op"]
            if op == "time":
                state["t"] = st["t"]
                r = {"t": state["t"]}
            elif op == "receive":
                r = ch.receive(st["ir"], {"action": st["action"]})
            elif op == "next":
                r = ch.next_screen()
                for x in (r or {}).get("questions", []):
                    seen.append(x["questionId"])
            elif op == "answer":
                r = ch.answer(qid, st["response"])
            elif op == "clarify":
                r = ch.clarify(st["body"])
            elif op == "hQuestion":
                r = H.question_handler(resolver)(st.get("sid", spec["session"]), st["body"])
            elif op == "hClarify":
                r = H.clarify_handler(resolver)(st.get("sid", spec["session"]), st["body"])
            elif op == "summary":
                r = ch.summary()
            elif op == "state":
                r = {"digest": ch.state_digest(), "asked": ch.questions_asked()}
            elif op == "noise":
                r = {"noise": ch.noise(), "admission": ch.admission()}
            elif op == "challenge":
                r = ch.device_challenge_for(qid)
            else:
                raise ValueError("bad op " + op)
        except Exception:  # noqa: BLE001
            r = {"$err": True}
        steps.append({"op": st["op"], "r": r})
    dev = opts.get("device")
    return {"steps": steps, "noise": state["counts"], "signCounts": dev.get("signCounts") if dev else None}


# fn -> (callable over the decoded args, comparer or None for exact canonical-JSON equality)
MAP = {
    "isFrictionTier": (W.is_friction_tier, None), "frictionRank": (W.friction_rank, None), "maxFriction": (W.max_friction, None),
    "satisfiesTier": (W.satisfies_tier, None), "isProvenanceLevel": (W.is_provenance_level, None), "worstProvenance": (W.worst_provenance, None),
    "frictionFor": (W.friction_for, None), "pcaActionDigest": (W.pca_action_digest, None), "actionValuesOf": (W.action_values_of, None),
    "isB64u32": (W.is_b64u32, None), "isObj": (W.is_obj, None), "coordsError": (W.coords_error, None),
    "answerShapeError": (W.answer_shape_error, None),
    "signIntentAnswer": (lambda a, k: W.sign_intent_answer(a, key(k)), None),
    "verifyIntentAnswer": (verify_wrapped, None), "answerRef": (W.answer_ref, None), "typedDigest": (W.typed_digest, None),
    "deviceChallenge": (lambda a: W.device_challenge(a["questionId"], a["renderedDigest"], a["y"], a.get("actionDigest")), None),
    "lnGamma": (W.ln_gamma, close), "betacf": (W.betacf, close), "betaInc": (W.beta_inc, close), "betaQuantile": (W.beta_quantile, close),
    "clopperPearsonUpper": (W.clopper_pearson_upper, close), "binEnt": (W.bin_ent, close),
    "recordCanary": (W.record_canary, None), "estimateNoise": (W.estimate_noise, close), "cellKey": (W.cell_key, None),
    "boundaryNeighbours": (lambda om, c: W.boundary_neighbours(sub(om), c), None), "pickCanary": (pick, None),
    "etaUnderLoad": (W.eta_under_load, close), "noiseState": (W.noise_state, close), "admissionPolicy": (W.admission_policy, close),
    "doubleConfirmed": (W.double_confirmed, None), "slidingWindow": (sliding, None),
    "signPricingConfig": (sign_with(P.sign_pricing_config), None), "pricingConfigError": (P.pricing_config_error, None),
    "freshCalibration": (P.fresh_calibration, None), "decideEscalation": (P.decide_escalation, None),
    "signAnswer": (sign_with(P.sign_answer), None), "updateCalibration": (upd, None),
    "signAutonomyRaise": (sign_with(P.sign_autonomy_raise), None),
    "applyAutonomyRaise": (lambda cfg, r, k: P.apply_autonomy_raise(cfg, r, key(k)), None),
    "omega.verbCellCount": (lambda i, v: O.verb_cell_count(vs_of(i, v)), None),
    "omega.cellCount": (lambda i, v, k: O.cell_count(omega_dim(i, v, k)), None),
    "omega.numCells": (lambda i, v, k: O.num_cells(omega_dim(i, v, k)), None), "omega.labelOf": (O.label_of, None),
    "omega.decodeCell": (lambda i, v, f: O.decode_cell(vs_of(i, v), f), None),
    "omega.cellStats": (lambda i, v, ix: O.cell_stats(vs_of(i, v), ix), close),
    "omega.cellRep": (lambda i, v, ix: O.cell_rep(vs_of(i, v), ix), None),
    "omega.cellOf": (lambda i, v, oc: O.cell_of(vs_of(i, v), oc), None),
    "coordKeyOf": (W.coord_key_of, None), "resolveCoords": (resolve, None),
    "coordsOfBox": (lambda i, v, b: W.coords_of_box(vs_of(i, v), b), None),
    "coordsOfCell": (lambda i, v, ix: W.coords_of_cell(vs_of(i, v), ix), None),
    "cellInBox": (W.cell_in_box, None), "boxCells": (W.box_cells, None), "boxSize": (W.box_size, None),
    "cellOfAction": (of_action, None), "flatIndex": (lambda i, v, ix: W.flat_index(vs_of(i, v), ix), None),
    "cleanText": (C.clean_text, None), "last4": (C.last4, None), "formatNumber": (C.format_number, None),
    "renderCard": (render, None), "cardDigest": (C.card_digest, None), "cardDigestMatches": (C.card_digest_matches, None),
    "cardText": (C.card_text, None), "partialError": (C.partial_error, None), "normalizeTyped": (C.normalize_typed, None),
    "expectedTyped": (C.expected_typed, None), "parseClarifyRequest": (C.parse_clarify_request, None),
    "informationGain": (C.information_gain, close), "planClarification": (plan, close),
    "gaussianSigma": (PO.gaussian_sigma, close), "gaussian": (lambda xs: PO.gaussian(seq(xs)), close), "rrKeepProbability": (PO.rr_keep_probability, close),
    "randomizedResponse": (lambda y, e, r: PO.randomized_response(y, e, lambda: r), None), "debiasRandomizedResponse": (PO.debias_randomized_response, close),
    "populationCellKey": (lambda sch, i, v, ix: PO.population_cell_key(sch, vs_of(i, v), ix), None), "aggregate": (aggregate, close),
    "populationPrior": (prior, close), "siteQuestionNotice": (notice, None), "clarificationNotice": (DL.clarification_notice, None),
    "questionText": (DL.question_text, None), "webhookChannel": (hook, None), "textChannel": (tchan, None), "dispatcher": (dispatch, None),
    "channel": (channel, None),  # the noise estimate (exact Clopper-Pearson bounds), the admission policy and etaUnderLoad are compared exactly
    "omegas": (None, None), "constants": (None, None),
}


def test_corpus_is_fully_accounted_for():
    assert COUNT == sum(len(v) for v in CASES.values())
    assert set(CASES) == set(MAP) | NOT_PORTED


@pytest.mark.parametrize("fn", sorted(k for k, v in MAP.items() if v[0] is not None))
def test_matches_the_reference(fn):
    call, compare = MAP[fn]
    run(CASES[fn], call, compare=compare)


def test_constants():
    expected = CASES["constants"][0]["out"]
    got = norm(constants())
    for k, v in got.items():
        assert canon(expected[k]) == canon(v), k
