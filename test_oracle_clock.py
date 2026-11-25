"""The replay clock is the corpus header's clockMs; a corpus without it uses the fallback."""
import gzip
import json

from base_oracle import REFERENCE_CLOCK_MS, load, near_clock, reference_clock_ms


def _corpus(tmp_path, name, clock, clock_cases=()):
    case = json.dumps({"fn": "f", "name": "n", "args": [], "out": None}, separators=(",", ":"))  # the corpus format: one compact line per case
    head = '{"about":"a","generator":"g.mts","count":1' + (',"clockMs":%d' % clock if clock is not None else "") + (',"clockCases":%s' % json.dumps(list(clock_cases)) if clock_cases else "") + ',"cases":[\n'
    p = tmp_path / name
    with gzip.open(p, "wb") as fh:
        fh.write((head + case + "\n]}\n").encode())
    return str(p)


def test_header_clock_is_read(tmp_path):
    _, cases = load("x", _corpus(tmp_path, "a.json.gz", 1_900_000_000_000))
    assert reference_clock_ms(cases) == 1_900_000_000_000
    assert near_clock(1_900_000_030_000, cases) and not near_clock(REFERENCE_CLOCK_MS, cases)


def test_missing_header_clock_falls_back(tmp_path):
    _, cases = load("x", _corpus(tmp_path, "b.json.gz", None))
    assert reference_clock_ms(cases) == REFERENCE_CLOCK_MS
    assert reference_clock_ms({"clockMs": 5}) == 5 and reference_clock_ms() == REFERENCE_CLOCK_MS


def test_clock_cases_run_with_the_wall_clock_at_clock_ms_and_others_do_not(tmp_path):
    import time
    from base_oracle import run
    _, cases = load("x", _corpus(tmp_path, "c.json.gz", 1_900_000_000_000, ["n"]))
    seen = []
    run(cases["f"], lambda: seen.append(time.time()) or None)
    assert seen == [1_900_000_000.0] and time.time() < 1_900_000_000  # restored after the case
    _, plain = load("x", _corpus(tmp_path, "d.json.gz", 1_900_000_000_000))
    seen.clear()
    run(plain["f"], lambda: seen.append(time.time()) or None)
    assert seen[0] != 1_900_000_000.0
