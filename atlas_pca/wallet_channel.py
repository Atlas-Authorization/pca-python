"""The trusted question channel of the wallet (PCA Intent Layer v2, 3.4 and 3.14): one instance per session. SELECTION belongs to the
verifier (questions enter only as a site-signed `intent_required`, re-derived by the wallet, or as a structured agent clarification whose
cell the wallet picks itself); RENDERING and ORDERING belong to the wallet; friction scales with harm; canaries are inserted with
probability rho and update only the noise counts; caps and a freeze on the estimated false-yes rate bound the questions; a cell is asked
at most once per session; under estimated noise an irreversible cell needs two confirmations. Native port of the TypeScript reference
(@atlasauth/pca-wallet, channel.ts). Options, items and results are plain dicts with the reference's member names; the view is a dict of
callables {p, vetoed, outsideCeiling, confirmed}."""
from __future__ import annotations

import math
import re
from typing import Any, Callable, Dict, List, Optional

from ._fin import fin
from .intent_omega import cell_rep as _learner_cell_rep
from .intent_required import verify_intent_required
from .pca import decode_b64u_strict, hash_canonical
from .wallet import (DEFAULT_FATIGUE, DEFAULT_FRICTION_THRESHOLDS, MIN_HOLD_MS, action_values_of, admission_policy, box_cells, cell_in_box,
                     cell_key, cell_of_action, coords_of_cell, device_challenge, double_confirmed, flat_index, friction_for, friction_rank,
                     max_friction, noise_state, pca_action_digest, pick_canary, record_canary, resolve_coords, sign_intent_answer, typed_digest)
from .wallet_card import expected_typed, normalize_typed, partial_error, parse_clarify_request, plan_clarification, render_card
from .wallet_omega import DEFAULT_HARM, cell_rep, cell_stats

_B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_SPLIT = re.compile(r"[|,]")


def _u16(s: str) -> bytes:
    return s.encode("utf-16-be", "surrogatepass")


def learner_view(l: Any, opts: Optional[dict] = None) -> Dict[str, Callable]:
    """A grant view over an intent learner, with an optional ceiling predicate insideCeiling(verb, idx) (True = inside every ceiling)."""
    opts = opts or {}

    def vs_of(verb: str) -> dict:
        vs = next((v for v in l.omega["verbs"] if v["verb"] == verb), None)
        if vs is None:
            raise ValueError("learnerView: unknown verb %s" % verb)
        return vs

    inside = opts.get("insideCeiling")
    return {
        "p": lambda verb, idx: l.acceptance(_learner_cell_rep(vs_of(verb), idx)),
        "vetoed": lambda verb, idx: l.is_vetoed(_learner_cell_rep(vs_of(verb), idx)),
        "outsideCeiling": lambda verb, idx: (not inside(verb, idx)) if inside else False,
        "confirmed": lambda: [{"verb": c["verb"], "idx": c["cell"]} for c in l.cells() if c["inGrant"]],
    }


class TrustedChannel:
    def __init__(self, opts: dict):
        self.o = opts
        self._pending: Dict[str, dict] = {}
        self._asked: set = set()
        self._canary_used: set = set()
        self._known_yes: List[dict] = []
        self._confirmations: Dict[str, List[dict]] = {}
        self._refused_while_frozen: List[dict] = []
        self._session_questions = 0
        self._canaries = 0
        self._screen_no = 0

    # ---- options -----------------------------------------------------------------------------------------------------------
    @property
    def _per_session(self) -> int:
        v = (self.o.get("caps") or {}).get("perSession")
        return 6 if v is None else v

    @property
    def _per_hour(self) -> int:
        v = (self.o.get("caps") or {}).get("perHour")
        return 12 if v is None else v

    @property
    def _fatigue(self) -> dict:
        return self.o.get("fatigue") or DEFAULT_FATIGUE

    def noise(self) -> Dict[str, Any]:
        """The current noise state (eta+ under load, frozen?)."""
        return noise_state(self.o["noise"](), self.o["hourly"].count(self.o["now"]()), self._fatigue)

    def admission(self) -> Dict[str, Any]:
        """The admission policy the learner should use now (tau, eta+, eta-; double confirmation)."""
        return admission_policy(self.noise(), self._fatigue)

    def questions_asked(self) -> int:
        return self._session_questions

    def _new_id(self) -> str:
        s = "q_"
        for _ in range(10):
            s += _B64U[math.floor(self.o["rand"]() * 64) % 64]
        return self._new_id() if s in self._pending else s

    def _box_stats(self, vs: dict, box: List[List[int]]) -> Optional[Dict[str, float]]:
        cells = box_cells(box)
        mx = self.o.get("maxBoxCells")
        if len(cells) > (4096 if mx is None else mx):
            return None
        m = 0.0
        mh = 0.0
        harm = self.o.get("harm") or DEFAULT_HARM
        for idx in cells:
            s = cell_stats(vs, idx, harm)
            m += s["mass"]
            mh += s["mass"] * s["harm"]
        return {"weight": mh, "meanHarm": mh / m if m > 0 else 0}

    def _friction_of(self, vs: dict, box: List[List[int]], mean_harm: float, site_min: Optional[str], irreversible: bool) -> str:
        provenance: List[dict] = []
        widens_identity = False
        sens = self.o.get("sensitivity") or {}
        identity_paths = self.o.get("identityPaths") or []
        for k, d in enumerate(vs["dims"]):
            if d["path"].startswith("env.prov.") and d["kind"] == "cat":
                param = d["path"][len("env.prov."):]
                levels: List[str] = []
                for i in box[k]:
                    v = d["values"][i]
                    levels.extend(_SPLIT.split(v["value"] + "*" if v["kind"] == "prefix" else v["value"]))
                provenance.append({"path": param, "sensitivity": sens.get(param) or "material", "levels": levels})
            if d["kind"] == "cat" and d["path"] in identity_paths:
                # widening an identity parameter = the box admits a value beyond the confirmed (exact, named) ones
                if any(d["values"][i]["kind"] != "exact" for i in box[k]):
                    widens_identity = True
        rev_fn = self.o.get("reversibility")
        rev = rev_fn(vs, box) if rev_fn else vs["reversibility"]
        inp: Dict[str, Any] = {"reversibility": rev, "expectedHarm": mean_harm, "provenance": provenance, "widensCriticalIdentity": widens_identity}
        if site_min:
            inp["siteMin"] = site_min
        tier = friction_for(inp, self.o.get("friction") or DEFAULT_FRICTION_THRESHOLDS)["tier"]
        if irreversible and self.admission()["doubleConfirmIrreversible"]:
            tier = max_friction(tier, "typed")
        return tier

    def _render(self, kind: str, verb: str, coords: dict, friction: str, action: Optional[dict], vs: dict, box: List[List[int]],
                reason: Optional[str] = None) -> Optional[Dict[str, Any]]:
        rev_fn = self.o.get("reversibility")
        base: Dict[str, Any] = {"omega": self.o["omega"], "verb": verb, "coords": coords,
                                "site": {"origin": self.o["site"]["origin"], "name": self.o["site"]["name"]}}
        if self.o.get("statementText") is not None:
            base["statementText"] = self.o["statementText"]
        base["reversibility"] = rev_fn(vs, box) if rev_fn else vs["reversibility"]
        if self.o.get("units"):
            base["units"] = self.o["units"]
        if action:
            base["action"] = action
        base["kind"] = kind
        if reason:
            base["reason"] = reason
        r = render_card({**base, "friction": friction})
        # a typed question needs a value to type; with none on the card, the only stronger tier is the device
        if r["ok"] and friction_rank(friction) == friction_rank("typed") and not r["card"].get("typed"):
            r = render_card({**base, "friction": "device"})
        return {"card": r["card"], "friction": r["card"]["friction"]} if r["ok"] else None

    def _gate(self) -> Dict[str, Any]:
        if self.noise()["frozen"]:
            return {"ok": False, "code": "frozen", "reason": "the estimated false-yes rate is above η_stop: no more questions this session"}
        if not (self._session_questions < self._per_session):
            return {"ok": False, "code": "cap_session", "reason": "at most %s questions per session" % self._per_session}
        now = self.o["now"]()
        if not (fin(now) and self.o["hourly"].count(now) < self._per_hour):
            return {"ok": False, "code": "cap_hour", "reason": "at most %s questions per hour" % self._per_hour}
        return {"ok": True}

    def _enqueue(self, it: dict) -> None:
        vs = it.pop("vs")
        it["flat"] = min(flat_index(vs, idx) for idx in box_cells(it["box"]))
        self._pending[it["id"]] = it

    def _count(self) -> None:
        self._session_questions += 1
        if not self.o["hourly"].try_add(self.o["now"](), 9007199254740991):
            raise RuntimeError("unreachable")

    def _maybe_canary(self) -> None:
        """Insert a canary with probability rho (rendered and ordered like a real question)."""
        exclude = set(self._canary_used)
        for p in self._pending.values():
            for idx in box_cells(p["box"]):
                exclude.add(cell_key(p["verb"], idx))
        low_harm = all(p["kind"] != "real" or friction_rank(p["card"]["friction"]) <= friction_rank("hold") for p in self._pending.values())
        view = self.o["view"]
        ctx: Dict[str, Any] = {
            "omega": self.o["omega"], "confirmed": view["confirmed"](),
            "knownNo": lambda verb, idx: "ceiling" if view["outsideCeiling"](verb, idx) else ("veto" if view["vetoed"](verb, idx) else None),
            "knownYes": self._known_yes, "exclude": exclude, "rand": self.o["rand"], "lowHarmSession": low_harm, "canariesSoFar": self._canaries,
        }
        if self.o.get("rho") is not None:
            ctx["rho"] = self.o["rho"]
        c = pick_canary(ctx)
        if not c:
            return
        vs = next(v for v in self.o["omega"]["verbs"] if v["verb"] == c["verb"])
        box = [[i] for i in c["idx"]]
        st = self._box_stats(vs, box)
        if not st:
            return
        coords = coords_of_cell(vs, c["idx"])
        action = {"verb": c["verb"], "values": cell_rep(vs, c["idx"])["values"]}
        friction = self._friction_of(vs, box, st["meanHarm"], None, False)
        r = self._render("question", c["verb"], coords, friction, action, vs, box)
        if not r:
            return
        self._canaries += 1
        self._canary_used.add(cell_key(c["verb"], c["idx"]))
        self._enqueue({"id": self._new_id(), "kind": "canary", "source": "elicitation", "verb": c["verb"], "box": box, "coords": coords, "card": r["card"],
                       "action": action, "irreversible": False, "expected": c["expected"], "weight": st["weight"], "jit": False, "vs": vs})

    def receive(self, ir: dict, ctx: dict) -> Dict[str, Any]:
        """Receive a site-signed intent_required (delivered directly, or relayed unchanged by the agent) together with the action the
        agent attempted. Every check fails closed."""
        now = self.o["now"]()
        v = verify_intent_required(ir, self.o["site"]["keys"], now)
        if not v["ok"]:
            return {"ok": False, "code": "bad_site_signature", "reason": v["reason"]}
        if ir["session"] != self.o["session"]:
            return {"ok": False, "code": "wrong_session", "reason": "the question is for another session"}
        if ir["map_digest"] != self.o["mapDigest"]():
            return {"ok": False, "code": "stale_map", "reason": "the question names another map version"}
        action = ctx["action"]
        if action["verb"] != ir["cell"]["verb"] or pca_action_digest(action) != ir["action_digest"]:
            return {"ok": False, "code": "action_mismatch", "reason": "the action does not match the signed action digest"}
        if self.o.get("lift"):
            lifted = self.o["lift"](action)
        else:
            lifted = action_values_of(action)
        r = resolve_coords(self.o["omega"], ir["cell"]["verb"], ir["cell"]["coords"])
        if not r["ok"]:
            return {"ok": False, "code": "cell_mismatch", "reason": r["reason"]}
        at = cell_of_action(self.o["omega"], lifted)
        if not at or not cell_in_box(r["box"], at["idx"]):
            return {"ok": False, "code": "cell_mismatch", "reason": "the action's cell (re-derived by the wallet) is not the cell the site names"}
        st = self._box_stats(r["vs"], r["box"])
        if not st:
            return {"ok": False, "code": "cell_too_large", "reason": "the question covers too many cells"}
        cells = box_cells(r["box"])
        view = self.o["view"]
        verb = r["vs"]["verb"]
        for idx in cells:
            if view["outsideCeiling"](verb, idx):
                return {"ok": False, "code": "not_uncertain", "reason": "the cell is outside a ceiling: the principal cannot widen it"}
            if view["vetoed"](verb, idx):
                return {"ok": False, "code": "not_uncertain", "reason": "the cell was vetoed"}
        pa = view["p"](verb, at["idx"])
        if not (pa > 0 and pa < 1):
            return {"ok": False, "code": "not_uncertain", "reason": "the cell is denied" if pa <= 0 else "the cell is already in the grant"}
        if any(cell_key(verb, idx) in self._asked for idx in cells):
            return {"ok": False, "code": "already_asked", "reason": "a cell is asked at most once per session"}
        g = self._gate()
        if not g["ok"]:
            if g["code"] == "frozen":
                self._refused_while_frozen.append({"verb": verb, "coords": ir["cell"]["coords"]})
            return g
        rev_fn = self.o.get("reversibility")
        rev = rev_fn(r["vs"], r["box"]) if rev_fn else r["vs"]["reversibility"]
        irreversible = rev == "irreversible"
        friction = self._friction_of(r["vs"], r["box"], st["meanHarm"], ir["friction"], irreversible)
        rendered = self._render("question", ir["cell"]["verb"], ir["cell"]["coords"], friction, lifted, r["vs"], r["box"])
        if not rendered:
            return {"ok": False, "code": "render_failed", "reason": "the card could not be rendered"}
        if ir["question_id"] in self._pending:
            return {"ok": False, "code": "already_asked", "reason": "duplicate question id"}
        for idx in cells:
            self._asked.add(cell_key(verb, idx))
        self._count()
        self._enqueue({"id": ir["question_id"], "kind": "real", "source": "elicitation", "verb": ir["cell"]["verb"], "box": r["box"], "coords": ir["cell"]["coords"],
                       "card": rendered["card"], "action": lifted, "actionDigest": ir["action_digest"], "irreversible": irreversible, "weight": st["weight"],
                       "expiresAt": ir["expires_at"], "jit": True, "vs": r["vs"]})
        self._maybe_canary()
        return {"ok": True, "questionId": ir["question_id"], "friction": rendered["friction"]}

    def clarify(self, body: Any) -> Dict[str, Any]:
        """An agent clarification (3.14): {candidates: [<= 8 structured actions], reason}, no text. Certain cells are answered at once
        (dry run); among the uncertain ones the wallet picks the most informative and asks it."""
        parsed = parse_clarify_request(body)
        if not parsed["ok"]:
            return {"status": 400, "verdicts": [], "error": parsed["error"]}
        st = self.noise()
        pin: Dict[str, Any] = {
            "omega": self.o["omega"], "view": self.o["view"], "candidates": parsed["request"]["candidates"], "asked": self._asked,
            "etaPos": min(0.5 - 1e-9, st["etaPosBar"]), "etaNeg": min(0.5 - 1e-9, st["etaNegBar"]), "harm": self.o.get("harm") or DEFAULT_HARM,
        }
        if self.o.get("liftCandidate"):
            pin["lift"] = self.o["liftCandidate"]
        plan = plan_clarification(pin)
        if not plan["ask"]:
            return {"status": 200, "verdicts": plan["verdicts"]}
        g = self._gate()
        if not g["ok"]:
            return {"status": 200 if g["code"] == "frozen" else 429, "verdicts": plan["verdicts"], "refused": g["code"]}
        ask = plan["ask"]
        vs = next(v for v in self.o["omega"]["verbs"] if v["verb"] == ask["verb"])
        box = [[i] for i in ask["idx"]]
        stats = self._box_stats(vs, box)
        coords = coords_of_cell(vs, ask["idx"])
        raw = parsed["request"]["candidates"][ask["index"]]
        action = self.o["liftCandidate"](raw) if self.o.get("liftCandidate") else raw
        rev_fn = self.o.get("reversibility")
        rev = rev_fn(vs, box) if rev_fn else vs["reversibility"]
        irreversible = rev == "irreversible"
        friction = self._friction_of(vs, box, stats["meanHarm"], None, irreversible)
        rendered = self._render("clarification", vs["verb"], coords, friction, action, vs, box, parsed["request"]["reason"])
        if not rendered:
            return {"status": 200, "verdicts": plan["verdicts"], "refused": "render_failed"}
        qid = self._new_id()
        self._asked.add(cell_key(vs["verb"], ask["idx"]))
        self._count()
        self._enqueue({"id": qid, "kind": "real", "source": "clarification", "verb": vs["verb"], "box": box, "coords": coords, "card": rendered["card"], "action": action,
                       "irreversible": irreversible, "weight": stats["weight"], "jit": False, "vs": vs})
        self._maybe_canary()
        return {"status": 200, "verdicts": plan["verdicts"], "questionId": qid}

    def _ordered(self) -> List[dict]:
        """Pending items in display order: friction desc, E[h|c]*mu(c) desc, cell index asc, id asc."""
        return sorted(self._pending.values(), key=lambda i: (-friction_rank(i["card"]["friction"]), -i["weight"], i["flat"], _u16(i["id"])))

    def next_screen(self) -> Optional[Dict[str, Any]]:
        """The next screen. A typed or device question is always alone; tap/hold questions share up to maxPerScreen."""
        now = self.o["now"]()
        for qid, it in list(self._pending.items()):
            if it.get("expiresAt") is not None and not (fin(now) and now <= it["expiresAt"]):
                del self._pending[qid]
        items = [it for it in self._ordered() if it.get("shownOn") is None]
        if len(items) == 0:
            return None
        nxt = self._screen_no + 1
        eligible = [it for it in items if it.get("notBefore") is None or nxt >= it["notBefore"]]
        self._screen_no = nxt
        if len(eligible) == 0:
            return {"screen": nxt, "kind": "interstitial", "questions": []}
        first = eligible[0]
        picked = [first]
        if friction_rank(first["card"]["friction"]) <= friction_rank("hold"):
            mx = self.o.get("maxPerScreen")
            mx = 3 if mx is None else mx
            for it in eligible[1:]:
                if len(picked) >= mx:
                    break
                if friction_rank(it["card"]["friction"]) <= friction_rank("hold"):
                    picked.append(it)
        for it in picked:
            it["shownOn"] = nxt
        return {"screen": nxt, "kind": "questions", "questions": [{"questionId": it["id"], "card": it["card"]} for it in picked]}

    def answer(self, question_id: str, response: dict) -> Dict[str, Any]:
        """The principal's response to a shown question."""
        it = self._pending.get(question_id)
        if it is None:
            return {"ok": False, "code": "unknown_question", "reason": "no such pending question"}
        if it.get("shownOn") is None:
            return {"ok": False, "code": "not_shown", "reason": "the question was never shown"}
        now = self.o["now"]()
        if it.get("expiresAt") is not None and not (fin(now) and now <= it["expiresAt"]):
            del self._pending[question_id]
            return {"ok": False, "code": "expired", "reason": "the question expired"}
        partial = None
        ans = response.get("answer")
        if ans == "no":
            y = 0
        elif ans == "partly":
            e = partial_error(it["card"], response.get("partial"))
            if e:
                return {"ok": False, "code": "bad_response", "reason": e}
            y = 1
            partial = response.get("partial")
        else:
            y = 1
        ux: Dict[str, Any] = {"tier": it["card"]["friction"], "rendered_digest": it["card"]["rendered_digest"], "canary": it["kind"] == "canary"}
        if y == 1:
            ev = self._tier_evidence(it, response, question_id)
            if not ev["ok"]:
                return ev
            ux.update(ev["ux"])
        plain_yes = y == 1 and partial is None
        if (it["kind"] != "canary" and it["jit"] and it["irreversible"] and plain_yes and it.get("actionDigest")
                and friction_rank(it["card"]["friction"]) >= friction_rank("typed")):
            ux["action_digest"] = it["actionDigest"]
            ux["consent_for_action"] = True
        body: Dict[str, Any] = {"map_digest": self.o["mapDigest"](), "session": self.o["session"], "question_id": question_id, "verb": it["verb"],
                                "cell": it["coords"], "y": y}
        if partial:
            body["partial"] = partial
        body["source"] = it["source"]
        body["observed_at"] = now
        body["ux"] = ux
        answer = sign_intent_answer(body, self.o["principalSecret"])
        del self._pending[question_id]
        if it["kind"] == "canary":
            self.o["onNoise"](record_canary(self.o["noise"](), it["expected"], y))
            return {"ok": True, "kind": "canary", "answer": answer}
        if y == 0:
            return {"ok": True, "kind": "veto", "answer": answer}
        if plain_yes and friction_rank(it["card"]["friction"]) >= friction_rank("typed") and all(len(ids) == 1 for ids in it["box"]):
            # a verified high-friction yes: a source of known-yes canaries
            self._known_yes.append({"verb": it["verb"], "idx": [ids[0] for ids in it["box"]]})
        if plain_yes and it["irreversible"] and self.admission()["doubleConfirmIrreversible"]:
            import json
            key = "%s|%s" % (it["verb"], json.dumps(it["coords"], separators=(",", ":"), ensure_ascii=False))
            recs = list(self._confirmations.get(key, [])) + [{"screen": it["shownOn"], "tier": it["card"]["friction"]}]
            self._confirmations[key] = recs
            if it["kind"] == "confirmation" and it.get("first") and double_confirmed(recs):
                return {"ok": True, "kind": "confirmed", "answers": [it["first"], answer]}
            if it["kind"] == "confirmation":
                return {"ok": True, "kind": "pending_confirmation", "answer": answer}
            # schedule the second, independent confirmation: at least one other screen in between
            second = dict(it)
            second.update({"id": self._new_id(), "kind": "confirmation", "first": answer, "notBefore": it["shownOn"] + 2})
            second.pop("shownOn", None)
            self._pending[second["id"]] = second
            return {"ok": True, "kind": "pending_confirmation", "answer": answer}
        return {"ok": True, "kind": "answer", "answer": answer}

    def _tier_evidence(self, it: dict, response: dict, question_id: str) -> Dict[str, Any]:
        r = {} if response.get("answer") == "no" else response
        tier = it["card"]["friction"]
        if tier == "tap":
            return {"ok": True, "ux": {}}
        if tier == "hold":
            hm = r.get("holdMs")
            if not (isinstance(hm, (int, float)) and not isinstance(hm, bool) and fin(hm) and hm == math.floor(hm) and hm >= MIN_HOLD_MS):
                return {"ok": False, "code": "tier_evidence", "reason": "hold for at least %d ms" % MIN_HOLD_MS}
            return {"ok": True, "ux": {"hold_ms": hm}}
        if tier == "typed":
            t = it["card"].get("typed")
            if not t or not it.get("action") or not isinstance(r.get("typed"), str):
                return {"ok": False, "code": "tier_evidence", "reason": "type the value shown on the card"}
            want = expected_typed(it["card"], it["action"])
            got = normalize_typed(r["typed"], t["mode"], (self.o.get("units") or {}).get(t["path"]))
            if want is None or got is None or got != want:
                return {"ok": False, "code": "typed_mismatch", "reason": "the typed value does not match the card"}
            return {"ok": True, "ux": {"typed_digest": typed_digest(question_id, got)}}
        if tier == "device":
            from .webauthn import verify_assertion
            wa = r.get("webauthn")
            dev = self.o.get("device")
            if not wa or not dev:
                return {"ok": False, "code": "tier_evidence", "reason": "a security-key assertion is required"}
            cred = wa.get("credential_id")
            pk = dev["credentials"].get(cred) if isinstance(cred, str) else None
            ad = decode_b64u_strict(wa.get("authenticator_data"))
            cd = decode_b64u_strict(wa.get("client_data_json"))
            sg = decode_b64u_strict(wa.get("signature"))
            if not pk or ad is None or cd is None or sg is None:
                return {"ok": False, "code": "tier_evidence", "reason": "unknown credential or malformed assertion"}
            challenge = device_challenge(question_id, it["card"]["rendered_digest"], 1, it["actionDigest"] if (it["jit"] and it["irreversible"] and it.get("actionDigest")) else None)
            counts = dev.get("signCounts")
            stored = 0 if counts is None else counts.get(cred, 0)
            res = verify_assertion({"authenticator_data": ad, "client_data_json": cd, "signature": sg, "public_key": pk},
                                   {"expected_challenge": challenge, "rp_id": dev["rpId"], "origins": dev["origins"], "require_uv": True, "stored_sign_count": stored})
            if not res["ok"]:
                return {"ok": False, "code": "tier_evidence", "reason": "security key: %s" % res["reason"]}
            if counts is not None:
                counts[cred] = res["signCount"]
            return {"ok": True, "ux": {"webauthn": dict(wa)}}
        raise ValueError("unknown friction tier")

    def device_challenge_for(self, question_id: str) -> Optional[str]:
        """The WebAuthn challenge the wallet UI passes to navigator.credentials.get for a shown device-tier question."""
        it = self._pending.get(question_id)
        if it is None or it.get("shownOn") is None or it["card"]["friction"] != "device":
            return None
        return device_challenge(question_id, it["card"]["rendered_digest"], 1, it["actionDigest"] if (it["jit"] and it["irreversible"] and it.get("actionDigest")) else None)

    def summary(self) -> Dict[str, Any]:
        """The end-of-session summary shown instead of questions once the session froze."""
        return {"frozen": self.noise()["frozen"], "refused": list(self._refused_while_frozen), "asked": self._session_questions, "canaries": self._canaries}

    def state_digest(self) -> str:
        """A stable digest of the channel's pending state (for tests and audit logs)."""
        return hash_canonical({"d": "atlas-pca/wallet-channel-state/v1",
                               "p": [{"id": i["id"], "k": i["kind"], "d": i["card"]["rendered_digest"]} for i in self._ordered()],
                               "a": sorted(self._asked, key=_u16), "n": self._session_questions})
