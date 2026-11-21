"""Differential replay of the deployment doctor (scrubbing, the clock / proxy / suites / root-caveat / enforcement checks, result
formatting, configuration, the CLI and the full run) against the TypeScript reference. Network, clock and the deployed library are
replayed from the named fakes the reference used."""
import pytest

from atlas_pca import doctor as D
from atlas_pca.control_evals import mulberry32
from base_oracle import load_ref, run

COUNT, CASES = load_ref("doctor")
URL1 = "https://api.example.com"


class _Resp:
    def __init__(self, rsp):
        self._rsp = rsp
        self.status = 200
        self.headers = self

    def get(self, name):
        return self._rsp.get("date") if name == "date" else self._rsp.get("rl") if name == "ratelimit-remaining" else None

    def read(self):
        return b""


class _Env:
    """A fake network and clock: every fetch pops the next entry of its url (the last one repeats), advances the clock by `rtt`
    BEFORE answering and raises when the entry says so."""

    def __init__(self, spec):
        self.t, self.spec, self.idx = spec["now"], spec, {}

    def now(self):
        return self.t

    def fetch(self, url, method="GET", headers=None, timeout_ms=None):
        lst = self.spec["responses"].get(url)
        if lst is None:
            raise Exception("no route " + url)
        i = self.idx.get(url, 0)
        self.idx[url] = i + 1
        rsp = lst[min(i, len(lst) - 1)]
        self.t += rsp.get("rtt") or 0
        if rsp.get("throw"):
            raise Exception(rsp["throw"])
        return _Resp(rsp)


def _fake_pca(spec):
    """The reference's named fake library: it decides a payment under the root caveat the way each behaviour says."""
    behavior = spec["behavior"]

    def probe(cav, amount):
        if behavior == "throws":
            raise Exception("boom")
        if behavior == "allow-all":
            return {"allowed": True, "reasons": []}
        if behavior == "deny-all":
            return {"allowed": False, "reasons": ["denied", 7]}
        if behavior == "nonarray-reasons":
            return {"allowed": False, "reasons": "x"}
        if cav["type"] == "max_spend":
            if behavior == "ignore-max":
                return {"allowed": True, "reasons": []}
            return {"allowed": True, "reasons": []} if amount <= cav["usd"] else {"allowed": False, "reasons": ["over max_spend"]}
        if behavior == "ignore-unknown":
            return {"allowed": True, "reasons": []}
        return {"allowed": False, "reasons": ["unknown caveat type"]}

    return probe


def _loader(spec):
    def load(_dir):
        if spec.get("throws"):
            raise Exception(spec["throws"])
        return D.LoadedPca(spec["version"], spec["path"], _fake_pca(spec))

    return load


def _consts():
    return {"USAGE": D.USAGE, "CHECK_GROUPS": list(D.CHECK_GROUPS), "DEFAULT_REQUIRED": D.DEFAULT_REQUIRED,
            "ROOT_CAVEAT_MIN_VERSION": D.ROOT_CAVEAT_MIN_VERSION, "DEFAULT_REFERENCE_URL": D.DEFAULT_REFERENCE_URL,
            "SUITES_REMEDIATION": D.SUITES_REMEDIATION, "PQ_REMEDIATION": D.PQ_REMEDIATION, "CLOCK_REMEDIATION": D.CLOCK_REMEDIATION,
            "PROXY_REMEDIATION": D.PROXY_REMEDIATION, "ATOMICITY_REMEDIATION": D.ATOMICITY_REMEDIATION,
            "DURABILITY_REMEDIATION": D.DURABILITY_REMEDIATION, "CAVEAT_REMEDIATION": D.CAVEAT_REMEDIATION}


def _clock(cfg, spec):
    e = _Env(spec)
    return D.check_clock(cfg, e.fetch, e.now)


def _read_date(_unused, spec):
    e = _Env(spec)
    return D.read_date(URL1, e.fetch, e.now, 1000)


def _probe(cfg, spec):
    return D.check_proxy_probe(cfg, _Env(spec).fetch, mulberry32(7))


def _main(argv, env):
    out, err = [], []
    code = D.main(argv, env, out.append, err.append)
    return {"code": code, "out": out, "err": err}


def _run_doctor(cfg, only, spec, caveat):
    e = _Env(spec)
    return D.run_doctor(cfg, only, fetch=e.fetch, now=e.now, load=_loader(caveat))


MAP = {
    "consts": _consts,
    "scrubText": D.scrub_text,
    "scrubDeep": D.scrub_deep,
    "checkAllowedSuites": D.check_allowed_suites,
    "checkPqBinding": D.check_pq_binding,
    "checkProxyConfig": D.check_proxy_config,
    "testNetIp": lambda seed: D.test_net_ip(mulberry32(seed)),
    "forgedHeaders": lambda seed: D.forged_headers(mulberry32(seed)),
    "checkClock": _clock,
    "readDate": _read_date,
    "checkProxyProbe": _probe,
    "compareVersion": D.compare_version,
    "checkRootCaveats": lambda cfg, spec: D.check_root_caveats(cfg, _loader(spec)),
    "checkEnforcement": D.check_enforcement,
    "configProblems": D.config_problems,
    "verdictOf": lambda *a: D.verdict_of(*a),
    "formatResults": lambda rs, target, strict: D.format_results(rs, target, strict),
    "configFromEnv": D.config_from_env,
    "mergeConfig": lambda *a: D.merge_config(*a),
    "parseDoctorArgs": D.parse_doctor_args,
    "main": _main,
    "runDoctor": _run_doctor,
}


def test_corpus_is_the_full_oracle():
    assert set(CASES) == set(MAP)


@pytest.mark.parametrize("fn", sorted(MAP))
def test_matches_the_reference(fn):
    run(CASES[fn], MAP[fn])


def test_runtime_check_reports_the_registered_suites():
    r = D.check_runtime({"verifier": {"allowedSuites": ["ed25519"]}})
    assert r["id"] == "suites.runtime" and r["status"] == "pass" and "ed25519" in r["observed"]["available"]
