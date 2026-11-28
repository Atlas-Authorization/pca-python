"""A lone surrogate is written as U+FFFD (EF BF BD) like the reference TextEncoder: str.encode raises, 'surrogatepass' writes ED xx xx."""
import hashlib

from atlas_pca import lease, prohibitions
from atlas_pca.goal_binding import goal_commit, open_commit
from atlas_pca.pca import utf8

FFFD = b"\xef\xbf\xbd"


def test_utf8_replaces_a_lone_surrogate_with_fffd():
    assert utf8("a\ud800b") == b"a" + FFFD + b"b"
    assert utf8("a\udc00b") == b"a" + FFFD + b"b"
    assert utf8("\udc00\ud800") == FFFD + FFFD
    assert utf8("\U0001F600") == b"\xf0\x9f\x98\x80"
    assert utf8("😀") == b"\xf0\x9f\x98\x80"  # an adjacent high and low unit is one code point, as in JavaScript


def test_open_commit_answers_false_not_raises_on_a_lone_surrogate():
    assert open_commit("\ud800", "g", "p", "s") is False
    assert open_commit(goal_commit("g", "p", "s"), "g", "p", "s") is True
    assert goal_commit("g\ud800", "p", "s") == goal_commit("g�", "p", "s")


def test_shard_of_and_domain_message_use_the_fffd_bytes():
    assert lease.shard_of("l\ud800", 16) == int.from_bytes(hashlib.sha256(b"l" + FFFD).digest()[:4], "big") % 16
    assert prohibitions._domain_message("d", "x\ud800") == b"d" + hashlib.sha256(b"x" + FFFD).digest()
