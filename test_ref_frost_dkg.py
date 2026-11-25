"""Replays the TS-reference oracle of the FROST distributed key generation (testdata/ref-frost-dkg.json.gz, 439 cases, plus the CI-generated
ref-frost-dkg-gen.json.gz, 286 cases that carry derived secrets: round-2 shares, signing shares, revealed shares and the wire bytes of share messages):
round 1 and its proof, the signed shares, complaints, rebuttals and blame, the qualified set, echo agreement, finalize, the in-process ceremony (with
cheaters and an equivocating echo), the wire codec, the inbox, the in-memory network, the TLS framing model and one party's whole ceremony over a scripted
channel. A refusal of a producing function is compared by the fact that it refuses; a DkgChannelError by its code, peer and class (the text is
informative); the verdict / resolution / echo-agreement reasons exactly. The reference's random draws (``$rng``) are replayed through the ``random_bytes``
seam. Needs libsodium (the ``ristretto`` extra). When CI is set the generated corpus must be present (the workflow generates it) or the test fails."""
import math
import os

import pytest

pytest.importorskip("pysodium")
from atlas_pca import frost_dkg as D  # noqa: E402
from atlas_pca import frost_dkg_channel as C  # noqa: E402
from atlas_pca import frost_dkg_tls as T  # noqa: E402
from atlas_pca.pca import b64u  # noqa: E402
from base_oracle import HERE, canon, norm, covered, load, load_gen, merge_cases, require_gen, run  # noqa: E402

COUNT, MAIN = load("frost-dkg", os.path.join(HERE, "testdata", "ref-frost-dkg.json.gz"))
GEN = load_gen("frost-dkg")
CASES = merge_cases(MAIN, GEN)
NUM = {"NaN": math.nan, "Infinity": math.inf, "-Infinity": -math.inf}
MAIN_TOTALS = {"constants": 1, "dkgRound1": 56, "dkgVerifyRound1": 36, "dkgSignShare": 20, "dkgRound2": 5, "dkgVerifyShare": 3, "dkgFileComplaint": 2,
               "dkgVerifyComplaint": 3, "dkgResolveBlame": 1, "dkgQualifiedSet": 13, "dkgTranscriptDigest": 10, "dkgEcho": 4, "dkgCheckEchoes": 18, "dkgFinalize": 1,
               "frostDkgSimulate": 13, "encodeDkgMessage": 18, "decodeDkgMessage": 56, "decodeDkgRound1Package": 32, "decodeDkgShareMessage": 27,
               "decodeDkgComplaints": 25, "decodeDkgRebuttals": 9, "decodeDkgEcho": 13, "dkgInbox": 24, "memoryNetwork": 11, "tlsFrameEncode": 5,
               "tlsFrameDecode": 17, "runDkgOverChannel": 16}
GEN_COUNT = 286


def _rv(v):
    if isinstance(v, dict):
        if set(v) == {"$num"}:
            return NUM[v["$num"]]
        return {k: _rv(x) for k, x in v.items()}
    return [_rv(x) for x in v] if isinstance(v, list) else v


def _rng(args):
    if args and isinstance(args[-1], dict) and set(args[-1]) == {"$rng"}:
        draws = iter(args[-1]["$rng"])
        return args[:-1], lambda n: next(draws)[:n]
    return args, os.urandom


def _state(spec):
    return D.dkg_round1(spec["id"], spec["t"], spec["n"], spec["sessionId"], {"coefficients": spec["coefficients"], "popNonce": spec["popNonce"]})["state"]


def _err(e):
    if isinstance(e, C.DkgChannelError):
        return {"$throws": str(e), "code": e.code, "class": "DkgChannelError", "peer": e.peer}
    return {"$throws": str(e)}


def _bodies(m):
    return {"ok": True, "bodies": {str(k): v for k, v in m.items()}}


# ---- handlers ----

def _round1(identifier, t, n, session_id, opts, *rest):
    rb = _rng(list(rest))[1] if rest else os.urandom
    return {"package": D.dkg_round1(identifier, t, n, session_id, opts, rb)["package"]}


def _simulate(t, n, opts, *rest):
    rb = _rng(list(rest))[1] if rest else os.urandom
    r = D.frost_dkg_simulate(t, n, opts, rb)
    return {k: r[k] for k in ("groupPublicKey", "participantShares", "groupCommitment", "keyPackages", "round1Packages", "qualified", "complaints",
                              "rebuttals", "echoes", "sessionId")}


def _inbox(a):
    ib = C.DkgInbox(a["sessionId"], a["peers"])
    out = []
    for op in a["ops"]:
        try:
            k = op["op"]
            if k == "accept":
                ib.accept(op["sender"], op["bytes"])
                out.append({"ok": True})
            elif k == "fail":
                ib.fail(op["peer"], C.DkgChannelError(op["code"], None, op["message"]))
                out.append({"ok": True})
            elif k == "peerGone":
                ib.peer_gone(op["peer"])
                out.append({"ok": True})
            elif k == "close":
                ib.close()
                out.append({"ok": True})
            elif k == "collect":
                out.append(_bodies(ib.collect(op["kind"], op["from"], op["timeoutMs"])))
            else:
                raise AssertionError("bad op")
        except Exception as e:  # noqa: BLE001
            out.append(_err(e))
    return out


def _network(a):
    m = a.get("intercept")

    def intercept(d):
        hit = (m.get("kind") is None or m["kind"] == d["kind"]) and (m.get("from") is None or m["from"] == d["from"]) and (m.get("to") is None or m["to"] == d["to"])
        if not hit:
            return d["bytes"]
        if m["action"] == "drop":
            return None
        return m["bytes"] if m["action"] == "replace" else d["bytes"]
    net = C.create_memory_dkg_network(a["ids"], a["sessionId"], intercept if m else None)
    chans = net["channels"]
    out = [{"channels": {str(i): {"self": ch.self, "peers": ch.peers} for i, ch in chans.items()}}]
    for op in a["ops"]:
        try:
            ch = chans.get(op["at"]) if op.get("at") is not None else None
            k = op["op"]
            if k == "broadcast":
                chans[op["from"]].broadcast(op["kind"], op["body"])
                out.append({"ok": True})
            elif k == "send":
                chans[op["from"]].send(op["to"], op["kind"], op["body"])
                out.append({"ok": True})
            elif k == "deliver":
                net["deliver"](op["from"], op["to"], op["bytes"])
                out.append({"ok": True})
            elif k == "collect":
                out.append(_bodies(ch.collect(op["kind"], op["fromIds"], op["timeoutMs"])))
            elif k == "close":
                ch.close()
                out.append({"ok": True})
            else:
                raise AssertionError("bad op")
        except Exception as e:  # noqa: BLE001
            out.append(_err(e))
    return out


def _tls_decode(a):
    d = T.FrameDecoder()
    accepted = []
    for chunk in a["chunks"]:
        if d.error:
            break
        accepted.extend(d.feed(chunk))
    return {"accepted": accepted, "error": d.error, "buffered": d.buffered}


_PHASES = ["round1", "share", "complaints", "rebuttals", "echo"]


def _party(spec, *rest):
    rb = _rng(list(rest))[1] if rest else os.urandom
    sid = spec["sessionId"]
    peers = spec["peers"] if spec.get("peers") is not None else sorted(p for p in spec["participants"] if p != spec["self"])
    inbox = C.DkgInbox(sid, peers)
    pending = list(spec.get("inbound") or [])
    outbound = []
    for g in spec.get("gone") or []:
        inbox.peer_gone(g)

    class Ch:
        self = spec["self"]

        def __init__(self):
            self.peers = peers

        def broadcast(self, kind, body):
            outbound.append({"op": "broadcast", "kind": kind, "bytes": C.encode_dkg_message(sid, kind, body)})

        def send(self, to, kind, body):
            if to not in peers:
                raise C.DkgChannelError("identity", to, "not a connected peer")
            outbound.append({"op": "send", "kind": kind, "to": to, "bytes": C.encode_dkg_message(sid, kind, body)})

        def collect(self, kind, from_ids, tmo):
            lim = _PHASES.index(kind)
            keep = []
            for m in pending:
                if _PHASES.index(m["kind"]) <= lim:
                    inbox.accept(m["from"], m["bytes"])
                else:
                    keep.append(m)
            pending[:] = keep
            return inbox.collect(kind, from_ids, tmo)

        def close(self):
            inbox.close()
    try:
        r = C.run_dkg_over_channel(Ch(), spec["t"], spec["participants"], sid, spec.get("timeoutMs"), None, rb)
        return {"outbound": outbound, "result": {"qualified": r["qualified"], "complaints": r["complaints"], "keyPackage": r["keyPackage"]}}
    except Exception as e:  # noqa: BLE001
        return {"outbound": outbound, "error": _err(e)}


def _prep(f):
    def go(*args):
        return f(*_rv(list(args)))
    return go


HANDLERS = {
    "constants": lambda: {"DKG_WIRE_VERSION": C.DKG_WIRE_VERSION, "DKG_MAX_MESSAGE_BYTES": C.DKG_MAX_MESSAGE_BYTES, "DKG_MAX_PARTICIPANTS": C.DKG_MAX_PARTICIPANTS,
                          "DKG_MESSAGE_KINDS": list(C.DKG_MESSAGE_KINDS)},
    "dkgRound1": _prep(_round1),
    "dkgVerifyRound1": _prep(D.dkg_verify_round1),
    "dkgSignShare": _prep(lambda spec, to, share: D.dkg_sign_share(_state(spec), to, share)),
    "dkgRound2": _prep(lambda spec, pkgs: D.dkg_round2(_state(spec), pkgs)),
    "dkgVerifyShare": _prep(D.dkg_verify_share),
    "dkgFileComplaint": _prep(D.dkg_file_complaint),
    "dkgVerifyComplaint": _prep(D.dkg_verify_complaint),
    "dkgRebut": _prep(lambda accused, complaint, spec: D.dkg_rebut(accused, complaint, _state(spec))),
    "dkgResolveBlame": _prep(D.dkg_resolve_blame),
    "dkgQualifiedSet": _prep(D.dkg_qualified_set),
    "dkgTranscriptDigest": _prep(D.dkg_transcript_digest),
    "dkgEcho": _prep(D.dkg_echo),
    "dkgCheckEchoes": _prep(D.dkg_check_echoes),
    "dkgFinalize": _prep(lambda me, spec, recvd, pkgs, q, ag: D.dkg_finalize(me, _state(spec), recvd, pkgs, q, ag)),
    "frostDkgSimulate": _prep(_simulate),
    "encodeDkgMessage": _prep(C.encode_dkg_message),
    "decodeDkgMessage": _prep(C.decode_dkg_message),
    "decodeDkgRound1Package": _prep(C.decode_dkg_round1_package),
    "decodeDkgShareMessage": _prep(C.decode_dkg_share_message),
    "decodeDkgComplaints": _prep(C.decode_dkg_complaints),
    "decodeDkgRebuttals": _prep(C.decode_dkg_rebuttals),
    "decodeDkgEcho": _prep(C.decode_dkg_echo),
    "dkgInbox": _prep(_inbox),
    "memoryNetwork": _prep(_network),
    "tlsFrameEncode": T.frame_encode,
    "tlsFrameDecode": _prep(_tls_decode),
    "runDkgOverChannel": _prep(_party),
}


def _eq(g, o):
    g = norm(g)
    """Recursive equality; a DkgChannelError is compared by code, peer and class (its text is informative)."""
    if isinstance(o, dict):
        if not isinstance(g, dict):
            return False
        skip = "$throws" if o.get("class") == "DkgChannelError" else None
        keys = {k for k in o}
        return set(g) == keys and all(True if k == skip else _eq(g[k], o[k]) for k in keys)
    if isinstance(o, list):
        return isinstance(g, (list, tuple)) and len(g) == len(o) and all(_eq(x, y) for x, y in zip(g, o))
    return canon(g) == canon(o)


def _same(got, out, _case):
    return _eq(got, out)


def _refused(got, case):
    return False


def test_every_corpus_fn_has_a_handler_and_the_main_totals_are_pinned():
    assert COUNT == 439 and {fn: len(cs) for fn, cs in MAIN.items()} == MAIN_TOTALS
    assert covered(CASES, GEN, HANDLERS)
    if GEN is not None:
        assert GEN[0] == GEN_COUNT


@pytest.mark.parametrize("fn", sorted(HANDLERS))
def test_frost_dkg_replay(fn):
    cases = CASES.get(fn, [])
    assert len(cases) >= MAIN_TOTALS.get(fn, 0)
    run(cases, HANDLERS[fn], compare=_same, refused=_refused)


def test_generated_secret_corpus_is_present_in_ci():
    if GEN is None:
        require_gen("frost-dkg")
    assert GEN[0] == GEN_COUNT
