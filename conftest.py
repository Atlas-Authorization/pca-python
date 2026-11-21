import sys

import pytest

from atlas_pca import ed25519 as _ed25519

# The suite signs with fixed test keys; the dependency-free CI job has no `cryptography`, so it opts in to the built-in signer.
# Set directly, not through allow_insecure_signer(): mutmut's forced-fail check makes every mutated function raise, and a
# raise while pytest loads conftest is a usage error (exit 4), not the failing tests the check expects.
_ed25519._ALLOW_INSECURE = True

# Tests that `import pysodium` directly must find the same libsodium the package does (a Homebrew copy is outside ctypes' macOS search path):
# load it once through the package's own lookup so later plain imports reuse the loaded module.
try:
    from atlas_pca import _sodium_path

    with _sodium_path.prefer_bundled():
        import pysodium  # noqa: F401
except Exception:  # noqa: BLE001 - no libsodium at all: the tests that need it skip or fail on their own
    pass


@pytest.fixture(autouse=True)
def _signer_opt_in():
    """Several modules switch the built-in signer off again when they finish: restore the suite-wide opt-in before every test, or the
    dependency-free job (no `cryptography`) would fail every later test that signs."""
    _ed25519._ALLOW_INSECURE = True
    yield


# Replay corpora whose cases need `cryptography` (EC / RSA verification, X.509): the dependency-free job skips them, as its workflow says.
_NEEDS_CRYPTOGRAPHY = frozenset((
    "test_ref_attest_maa.py", "test_ref_attest_nvidia.py", "test_ref_attest_vendors.py", "test_ref_sevsnp_helpers.py", "test_ref_scitt.py",
    "test_ref_webauthn.py",
))


_NEEDS_RUAMEL = frozenset(("test_ref_actions_test_runner.py",))  # its cases read authoring files in YAML (the `yaml` extra)


def pytest_collection_modifyitems(config, items):
    import importlib.util
    for module, names, why in (("cryptography", _NEEDS_CRYPTOGRAPHY, "the `cryptography` package (the dependency-free job skips the crypto-backed replays)"),
                               ("ruamel.yaml", _NEEDS_RUAMEL, "the `yaml` extra (ruamel.yaml)")):
        try:
            found = importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            found = False
        if found:
            continue
        skip = pytest.mark.skip(reason="needs " + why)
        for item in items:
            if item.path.name in names:
                item.add_marker(skip)


def _pca_settings():
    conf = sys.modules.get("django.conf")
    if conf is None or not conf.settings.configured:
        return None
    return conf.settings


@pytest.fixture(autouse=True)
def _isolate_pca_django_settings():
    """Django settings are process-global: whatever settings.PCA_* a test sets is put back afterwards, so no test sees
    another's (e.g. a leaked PCA_SIGNATURE_ONLY making PCA_AUTHORIZE raise). mutmut runs every test in one process in
    its own order, so a test must not depend on what an earlier one left behind."""
    s = _pca_settings()
    before = {n: getattr(s, n) for n in dir(s) if n.startswith("PCA_")} if s is not None else {}
    yield
    s = _pca_settings()
    if s is None:
        return
    for n in [n for n in dir(s) if n.startswith("PCA_")]:
        delattr(s, n)
    for n, v in before.items():
        setattr(s, n, v)


def pytest_configure(config):
    """mutmut runs each mutant in a process forked from its fork server; cap THAT process's address space (the CI Mutate
    step sets PCA_MUTANT_AS_HEADROOM_MB) so a mutant allocating without bound dies alone with MemoryError instead of
    exhausting the runner. Such a death is a RUN ERROR, not a kill (pytest_runtest_makereport below records which). Never the clean/stats runs (no mutant name), which start real threads."""
    import os
    headroom = os.environ.get("PCA_MUTANT_AS_HEADROOM_MB")
    if not headroom or "__mutmut_" not in os.environ.get("MUTANT_UNDER_TEST", ""):
        return
    import resource
    with open("/proc/self/status") as f:
        vm_kb = next(int(line.split()[1]) for line in f if line.startswith("VmSize:"))
    cap = (vm_kb * 1024) + int(headroom) * 1024 * 1024
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    if soft == resource.RLIM_INFINITY or cap < soft:
        resource.setrlimit(resource.RLIMIT_AS, (cap, hard))


_CRASH = (MemoryError, RecursionError)


def _escape(text):
    """`text` with every lone surrogate written as a backslash escape (execnet cannot encode one, and an unencodable report kills the whole xdist session)."""
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def _sanitize_report(rep):
    """Make a test report safe to serialise whatever its failure text holds (a replay mismatch can quote a string with a lone surrogate)."""
    if isinstance(rep.longrepr, tuple):  # a skip: (file, line, reason)
        rep.longrepr = tuple(_escape(x) if isinstance(x, str) else x for x in rep.longrepr)
    elif rep.longrepr is not None:
        rep.longrepr = _escape(rep.longrepr if isinstance(rep.longrepr, str) else str(rep.longrepr))
    rep.sections = [(_escape(a), _escape(b)) for a, b in rep.sections]
    if getattr(rep, "wasxfail", None) is not None:
        rep.wasxfail = _escape(str(rep.wasxfail))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Mutation evidence (CI sets PCA_RUNERR_DIR): the first failing test of a mutant run writes <mutant>.decided (an
    ordinary failure: assertion, wrong value, expected exception missing) or <mutant>.crash (MemoryError / RecursionError
    under the per-mutant memory cap). mutmut-survivors.py counts a `killed` mutant as killed only with a .decided record;
    a crash, a pytest internal error or a death outside any test is a run error the merge requires a ledger reason for."""
    outcome = yield
    rep = outcome.get_result()
    _sanitize_report(rep)
    import os
    d = os.environ.get("PCA_RUNERR_DIR")
    if not d or not rep.failed:
        return
    try:
        from mutmut.mutation import trampoline
        name = trampoline._mutant_under_test or os.environ.get("MUTANT_UNDER_TEST", "")
    except Exception:  # noqa: BLE001 - another mutmut layout: the env var it mirrors
        name = os.environ.get("MUTANT_UNDER_TEST", "")
    if "__mutmut_" not in name:
        return
    exc = call.excinfo
    e, crash = exc.value if exc is not None else None, False
    for _ in range(8):  # a MemoryError re-raised as another type (raise ... from / during handling) is still a crash
        if e is None:
            break
        crash = crash or isinstance(e, _CRASH)
        e = e.__cause__ or e.__context__
    kind = "crash" if crash else "decided"
    with open(os.path.join(d, name + "." + kind), "a", encoding="utf-8") as f:
        f.write("%s\t%s\t%s\n" % (item.nodeid, rep.when, exc.typename if exc is not None else "?"))


def pytest_collection_modifyitems(config, items):
    """test_basec_deadline.py runs first. Its tests call the loops and recursions a mutant could stop from terminating under
    a hard alarm, so the first failing test of such a mutant is an ordinary failure that decides it; run later, the same
    mutant would hang or recurse inside whichever older test reaches it first, and mutmut would record a run error
    (timeout / RecursionError / MemoryError) instead of a kill. test_base_kill_agent3_first.py runs before them: it decides the
    mutants that would crash the process (NULL pointers to libcrypto or memset, a dropped modular reduction) with stand-ins that
    no other mutant can stall. The sort is stable: every other order is unchanged."""
    import os
    first = ("test_basec_deadline.py", "test_misc_survivors_a.py")  # the second decides the RSASSA-PSS parameter walk before the slow subprocess tests

    def rank(it):
        name = os.path.basename(str(getattr(it, "path", None) or it.fspath))
        return 0 if name == "test_base_kill_agent3_first.py" else 1 if name in first else 2
    items.sort(key=rank)
