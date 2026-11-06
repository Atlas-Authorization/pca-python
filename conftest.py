import sys

import pytest


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


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Mutation evidence (CI sets PCA_RUNERR_DIR): the first failing test of a mutant run writes <mutant>.decided (an
    ordinary failure: assertion, wrong value, expected exception missing) or <mutant>.crash (MemoryError / RecursionError
    under the per-mutant memory cap). mutmut-survivors.py counts a `killed` mutant as killed only with a .decided record;
    a crash, a pytest internal error or a death outside any test is a run error the merge requires a ledger reason for."""
    outcome = yield
    rep = outcome.get_result()
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
