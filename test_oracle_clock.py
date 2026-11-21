"""The replay clock is the corpus header's clockMs; a corpus without it uses the fallback."""
import gzip
import json

from base_oracle import REFERENCE_CLOCK_MS, load, near_clock, reference_clock_ms


def _corpus(tmp_path, name, clock):
    case = json.dumps({"fn": "f", "name": "n", "args": [], "out": None})
    head = '{"about":"a","generator":"g.mts","count":1' + (',"clockMs":%d' % clock if clock is not None else "") + ',"cases":[\n'
    p = tmp_path / name
    with gzip.open(p, "wb") as fh:
        fh.write((head + case + "\n]}\n").encode())
    return str(p)


def test_header_clock_is_read(tmp_path):
    _, cases = load("x", _corpus(tmp_path, "a.json.gz", 1_700_000_000_000))
    assert reference_clock_ms(cases) == 1_700_000_000_000
    assert near_clock(1_700_000_030_000, cases) and not near_clock(REFERENCE_CLOCK_MS, cases)


def test_missing_header_clock_falls_back(tmp_path):
    _, cases = load("x", _corpus(tmp_path, "b.json.gz", None))
    assert reference_clock_ms(cases) == REFERENCE_CLOCK_MS
    assert reference_clock_ms({"clockMs": 5}) == 5 and reference_clock_ms() == REFERENCE_CLOCK_MS
