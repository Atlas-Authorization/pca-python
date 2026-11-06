"""0.5 mutation-kill tests of the attest group that need no `cryptography`: the SPDM transcript parser (every reason and
boundary), the NVIDIA firmware policy, the strict XML subset (entity decoding, structure, namespaces), the V8 JSON.parse
message model, compact-JWS parsing, the verifier factory's `collateral` switch and the MAA verifier's pre-signature path.
Every expected string is the TypeScript reference's (packages/pca/src/attest-nvidia-spdm.ts, attest-nvidia-rim.ts,
attest-azure-maa.ts, test-support/attestation-wire.ts; V8 JSON.parse for the JSON messages)."""
import base64
import json

import pytest

from atlas_pca import attest_common as C
from atlas_pca import attest_nvidia as N
from atlas_pca import attest_xml as X
from atlas_pca.attest import verifier_from_config
from atlas_pca.attest_amd import AttestConstructError
from atlas_pca.attest_azure import AzureMaaVerifier


def b64u(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


# ------------------------------------------------------------------------------------------------ SPDM transcript


def tx(records=b"", num_blocks=0, rec_len=None, opaque=b"", opaque_len=None, code=0xE0, resp_code=0x60, req_ver=0x11, resp_ver=0x12, tail=b""):
    req = bytes([req_ver, code, 1, 2]) + bytes(range(32)) + bytes([5])
    rl = len(records) if rec_len is None else rec_len
    ol = len(opaque) if opaque_len is None else opaque_len
    resp = bytes([resp_ver, resp_code, 3, 4, num_blocks]) + rl.to_bytes(3, "little") + records + b"\x09" * 32 + ol.to_bytes(2, "little") + opaque + b"\xee" * 96
    return req + resp + tail


def perr(t):
    with pytest.raises(ValueError) as e:
        N.parse_nvidia_spdm_evidence(t)
    return str(e.value)


P = "parseNvidiaSpdmEvidence: "


def test_spdm_minimal_transcript_is_exactly_175_bytes_and_parses_whole():
    t = tx()
    assert len(t) == 175
    assert N.parse_nvidia_spdm_evidence(bytearray(t)) == {
        "request": {"version": 0x11, "nonce": bytes(range(32))},
        "response_version": 0x12,
        "measurements": [],
        "opaque": {},
        "signature": b"\xee" * 96,
        "signedBytes": t[:-96],
    }
    assert perr(t[:-1]) == P + "transcript too short (174)"
    assert perr(b"") == P + "transcript too short (0)"


@pytest.mark.parametrize("code,hx", [(0x00, "0x0"), (0xFF, "0xff"), (0xE1, "0xe1"), (0x0E, "0xe")])
def test_spdm_request_code(code, hx):
    assert perr(tx(code=code)) == P + "request code %s is not GET_MEASUREMENTS" % hx


def test_spdm_response_code():
    assert perr(tx(resp_code=0x61)) == P + "response code is not MEASUREMENTS"
    assert perr(tx(resp_code=0x00)) == P + "response code is not MEASUREMENTS"


def test_spdm_record_length_boundaries():
    over = P + "measurement record length overruns transcript"
    assert perr(tx(rec_len=1)) == over  # 8 + 1 + 130 > 138
    assert perr(tx(rec_len=0x000100)) == over  # the middle byte of the u24
    assert perr(tx(rec_len=0x010000)) == over  # the high byte of the u24
    # one byte more room: the length check passes and the 1-byte record is a truncated block header
    assert perr(tx(rec_len=1, opaque=b"\x00", opaque_len=0)) == P + "truncated measurement block header"
    assert perr(tx(records=b"\x01\x01\x03", num_blocks=1)) == P + "truncated measurement block header"


def blk(index, size_lo, size_hi, body):
    return bytes([index, 1, size_lo, size_hi]) + body


def test_spdm_measurement_block_bounds():
    over = P + "measurement block overruns record"
    assert perr(tx(blk(1, 2, 0, b"\x00\x00"), 1)) == over  # size < 3 although it fits
    assert perr(tx(blk(1, 3, 0, b"\x00\x00"), 1)) == over  # size 3 does not fit
    assert perr(tx(blk(1, 3, 1, b"\x07\x00\x00"), 1)) == over  # u16 high byte: size 259
    dmtf = P + "DMTF value overruns measurement block"
    assert perr(tx(blk(1, 3, 0, b"\x07\x01\x00"), 1)) == dmtf
    assert perr(tx(blk(1, 4, 0, b"\x07\x01\x01\xab"), 1)) == dmtf  # vsize 257
    p = N.parse_nvidia_spdm_evidence(tx(blk(1, 3, 0, b"\x07\x00\x00") + blk(9, 4, 0, b"\x08\x01\x00\xab") + blk(2, 6, 0, b"\x00\x02\x00abc"), 3))
    assert p["measurements"] == [
        {"index": 1, "valueType": 7, "digest": b""},
        {"index": 9, "valueType": 8, "digest": b"\xab"},
        {"index": 2, "valueType": 0, "digest": b"ab"},
    ]
    assert perr(tx(blk(1, 3, 0, b"\x07\x00\x00"), 0)) == P + "header says 0 blocks, parsed 1"
    assert perr(tx(blk(1, 3, 0, b"\x07\x00\x00"), 2)) == P + "header says 2 blocks, parsed 1"


def test_spdm_opaque_tlvs():
    assert perr(tx(opaque=b"\x03\x00\x01")) == P + "truncated opaque TLV header"
    ov = P + "opaque TLV overruns opaque data"
    assert perr(tx(opaque=b"\x03\x00\x02\x00x")) == ov
    assert perr(tx(opaque=b"\x03\x00\x00\x01x")) == ov  # u16 length high byte
    assert perr(tx(opaque=b"\x03\x00\x01\x00x", opaque_len=4)) == P + "opaque length + signature do not exactly fill the transcript"
    assert perr(tx(opaque=b"", opaque_len=1)) == P + "opaque length + signature do not exactly fill the transcript"
    got = N.parse_nvidia_spdm_evidence(tx(opaque=b"\x03\x00\x01\x00x" + b"\x03\x01\x00\x00" + b"\x03\x00\x01\x00y"))
    assert got["opaque"] == {3: b"y", 0x103: b""}


# ------------------------------------------------------------------------------------------------ firmware policy


IDS = {"driverVersion": "580.95.05", "vbiosVersion": "96.00.9f.00.04"}


def fw_err(fw):
    with pytest.raises(AttestConstructError) as e:
        N._compile_firmware_policy(fw)
    assert isinstance(e.value, TypeError)
    return str(e.value)


def test_firmware_policy_absent_accepts_anything():
    for fw in (None, False, 0, ""):
        assert N._compile_firmware_policy(fw)({"driverVersion": "garbage", "vbiosVersion": "zz"}) is None


def test_firmware_policy_empty_object_still_checks_the_report_versions():
    # JS `!{}` is false: an empty policy still refuses an unparseable reported version (fixed: Python treated {} as no policy)
    chk = N._compile_firmware_policy({})
    assert chk(IDS) is None
    assert chk({"driverVersion": "abc", "vbiosVersion": "96.00"}) == "driver version 'abc' in the GPU report is not parseable"
    assert chk({"driverVersion": "1", "vbiosVersion": "zz"}) == "VBIOS version 'zz' in the GPU report is not parseable"


def test_firmware_policy_malformed_entries():
    m = "nvidiaCollateralHook: malformed "
    assert fw_err({"minDriverVersion": "1.a"}) == m + "minDriverVersion '1.a'"
    assert fw_err({"minDriverVersion": "9f"}) == m + "minDriverVersion '9f'"  # decimal radix
    assert fw_err({"minDriverVersion": 5}) == m + "minDriverVersion '5'"
    assert fw_err({"minVbiosVersion": "zz"}) == m + "minVbiosVersion 'zz'"
    assert fw_err({"minVbiosVersion": "96.12345"}) == m + "minVbiosVersion '96.12345'"
    assert fw_err({"denyDriverVersions": ["1", "1..2"]}) == m + "denyDriverVersions entry '1..2'"
    assert fw_err({"denyVbiosVersions": ["96.00", "g"]}) == m + "denyVbiosVersions entry 'g'"
    assert fw_err({"minDriverVersion": "1.2\n"}) == m + "minDriverVersion '1.2\n'"
    # empty strings are "not set", exactly like the reference's truthiness test
    assert N._compile_firmware_policy({"minDriverVersion": "", "minVbiosVersion": ""})(IDS) is None


def test_firmware_policy_floors_and_deny_lists():
    chk = N._compile_firmware_policy({"minDriverVersion": "580.95.05", "minVbiosVersion": "96.00.9f.00.04", "denyDriverVersions": ["570.1"], "denyVbiosVersions": ["96.0.A0.0.4"]})
    assert chk(IDS) is None
    assert chk(dict(IDS, driverVersion="580.95.4")) == "driver 580.95.4 is below the minimum 580.95.05"
    assert chk(dict(IDS, driverVersion="580.95.5")) is None  # 05 == 5 numerically
    assert chk(dict(IDS, driverVersion="580.95.5.0")) is None
    assert chk(dict(IDS, driverVersion="580.95")) == "driver 580.95 is below the minimum 580.95.05"
    assert chk(dict(IDS, driverVersion="1000")) is None
    assert chk(dict(IDS, vbiosVersion="96.00.9e.00.04")) == "VBIOS 96.00.9e.00.04 is below the minimum 96.00.9f.00.04"
    assert chk(dict(IDS, vbiosVersion="96.00.a0.00.04")) == "VBIOS 96.00.a0.00.04 is on the deny list"  # a0 > 9f only in hex
    assert chk(dict(IDS, vbiosVersion="96.00.A1")) is None
    # the order of the gates: driver parse, VBIOS parse, driver floor, VBIOS floor, driver deny, VBIOS deny
    assert chk({"driverVersion": "x", "vbiosVersion": "y"}) == "driver version 'x' in the GPU report is not parseable"
    assert chk({"driverVersion": "1", "vbiosVersion": "1"}) == "driver 1 is below the minimum 580.95.05"
    assert chk({"driverVersion": "600", "vbiosVersion": "1"}) == "VBIOS 1 is below the minimum 96.00.9f.00.04"
    deny = N._compile_firmware_policy({"denyDriverVersions": ["570.1"], "denyVbiosVersions": ["96.0.A0.0.4"]})
    assert deny({"driverVersion": "570.1.0", "vbiosVersion": "96.00.a0.00.04"}) == "driver 570.1.0 is on the deny list"
    assert deny({"driverVersion": "570.1.1", "vbiosVersion": "96.00.a0.00.04"}) == "VBIOS 96.00.a0.00.04 is on the deny list"
    assert deny({"driverVersion": "570.1.1", "vbiosVersion": "96.00.a0.00.05"}) is None


def test_version_helpers():
    assert N._parse_version("1.2", 10) == [1, 2]
    assert N._parse_version("0012.3", 10) == [12, 3]
    assert N._parse_version("ABCD.1", 16) == [0xABCD, 1]
    for v, r in (("1.", 10), (".1", 10), ("", 10), ("a", 10), ("12345", 16), ("1.2\n", 10), (5, 10), (None, 16)):
        assert N._parse_version(v, r) is None
    assert N._cmp_version([1, 2], [1, 2, 0]) == 0
    assert N._cmp_version([1, 3], [1, 2, 9]) == 1
    assert N._cmp_version([1], [1, 0, 1]) == -1
    assert N._cmp_version([], []) == 0
    assert N._cmp_version([2], [1, 99]) == 1


# ------------------------------------------------------------------------------------------------ the verifier factory


NV = {"rootSpkiSha256": ["aa"]}
NO_PINS = "createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)"
NO_RIM = "nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root"


# JS truthiness of `col`: 0, "", false and null install no hook; an empty object or array, a number or a string do
@pytest.mark.parametrize("col,msg", [(None, NO_PINS), (False, NO_PINS), (0, NO_PINS), (0.0, NO_PINS), ("", NO_PINS), (True, NO_RIM), ({}, NO_RIM), ([], NO_RIM), (1, NO_RIM), ("x", NO_RIM), ({"rimRootSpkiSha256": []}, NO_RIM)])
def test_factory_collateral_switch(col, msg):
    cfg = dict(NV)
    if col is not None:
        cfg["collateral"] = col
    with pytest.raises(AttestConstructError) as e:
        verifier_from_config("nvidia-gpu-spdm", cfg)
    assert str(e.value) == msg


@pytest.mark.parametrize("col", [None, False, 0, ""])
def test_factory_falsy_collateral_builds_no_hook_when_measurements_are_pinned(col):
    v = verifier_from_config("nvidia-gpu-spdm", dict(NV, policy={"measurements": {"1": "ab"}}, collateral=col))
    assert v._post_verify is None


def test_factory_collateral_forwards_the_hook_options():
    v = verifier_from_config("nvidia-gpu-spdm", dict(NV, collateral={"rimRootSpkiSha256": ["bb"]}))
    assert isinstance(v, N.NvidiaSpdmVerifier)
    with pytest.raises(AttestConstructError) as e:
        verifier_from_config("nvidia-gpu-spdm", dict(NV, collateral={"rimRootSpkiSha256": ["bb"], "firmware": {"minDriverVersion": "x"}}))
    assert str(e.value) == "nvidiaCollateralHook: malformed minDriverVersion 'x'"


def test_js_str_renders_json_null_as_string_of_null():
    assert C.js_str(None) == "null"
    with pytest.raises(AttestConstructError) as e:
        N._compile_firmware_policy({"denyDriverVersions": [None]})
    assert str(e.value) == "nvidiaCollateralHook: malformed denyDriverVersions entry 'null'"
    with pytest.raises(AttestConstructError) as e:
        verifier_from_config(None, {})
    assert str(e.value) == "unknown attestation vendor null"
    assert N.NvidiaSpdmVerifier({"rootSpkiSha256": ["aa"], "policy": {"measurements": {"1": None}}})._want == [(1, "null")]  # String(d).toLowerCase()


# ------------------------------------------------------------------------------------------------ XML subset


def test_unescape_references():
    u = X._unescape
    assert u("a&#x41;b&#x4a;&#x4A;&#65;", False) == "aAbJJA"
    assert u("&lt;&gt;&amp;&quot;&apos;", False) == "<>&\"'"
    assert u("a\tb\nc", False) == "a\tb\nc"  # text keeps whitespace
    assert u("a\tb\nc\rd", True) == "a b c d"  # an attribute value normalises it
    assert u("&#x9;&#10;", True) == "\t\n"  # character references are not normalised
    assert u("", True) == "" and u("plain", True) == "plain"
    # this wording is the SDK's own diagnostics (the reference surfaces xmldom's text), not a cross-language contract
    for s, msg in (("&#x;", "bad character reference"), ("&#xG1;", "bad character reference"), ("&#;", "bad character reference"), ("&#1a;", "bad character reference"),
                   ("&nope;", "unknown entity &nope;"), ("&amp", "unterminated entity reference"), ("a&", "unterminated entity reference")):
        with pytest.raises(X.XmlError) as e:
            u(s, False)
        assert str(e.value) == msg
    with pytest.raises(X.XmlError) as e:
        u("a<b", True)
    assert str(e.value) == "'<' in an attribute value"
    assert u("a<b", False) == "a<b"


def test_parse_xml_structure_and_cdata():
    d = X.parse_xml('  <a  b = "1"\tc=\'2&amp;\' d=">"><![CDATA[<x>&amp;]]>t&#x41;<e/></a  >\n')
    r = d.root
    assert [(a.qname, a.value) for a in r.attrs] == [("b", "1"), ("c", "2&"), ("d", ">")]
    assert r.children[:2] == ["<x>&amp;", "tA"] and r.element_children()[0].qname == "e"
    assert X.canonicalize(r) == '<a b="1" c="2&amp;" d=">">&lt;x&gt;&amp;amp;tA<e></e></a>'
    assert d.violations == []
    assert X.parse_xml("<a>x<b>y</b>z</a>").root.text_content() == "xyz"
    assert X.parse_xml("<a/>").root.get_attribute("missing") == ""


def test_parse_xml_declarations_and_violations():
    d = X.parse_xml('<!DOCTYPE a [<!ENTITY x "y">]><a/><!-- after -->')
    assert d.violations == ["DTD / DOCTYPE is not permitted", "XML comments are not permitted"]
    assert d.root.qname == "a"
    d = X.parse_xml('<?pi x?><r xmlns:XML="u"><c XML:a="1" xml:lang="en"/></r>')
    assert d.violations == ["XML processing instructions are not permitted", "xml:* attribute 'XML:a' is not permitted (C14N 1.1 profile)", "xml:* attribute 'xml:lang' is not permitted (C14N 1.1 profile)"]
    c = d.root.element_children()[0]
    assert [(a.local, a.ns) for a in c.attrs] == [("a", "u"), ("lang", "http://www.w3.org/XML/1998/namespace")]


def test_parse_xml_namespaces():
    d = X.parse_xml('<r xmlns="d"><c a="1" xmlns:p="u" p:b="2"/><e xmlns=""/><p:f xmlns:p="v"/></r>')
    r = d.root
    c, e, f = r.element_children()
    assert (r.ns, c.ns, e.ns, f.ns) == ("d", "d", "", "v")
    assert [(a.qname, a.prefix, a.local, a.ns) for a in c.attrs] == [("a", "", "a", ""), ("p:b", "p", "b", "u")]
    assert c.decls == {"p": "u"} and c.scope == {"": "d", "p": "u"} and e.scope == {} and f.scope == {"": "d", "p": "v"}
    assert r.element_children("d") == [c] and r.element_children(None, "f") == [f] and r.element_children("v", "f") == [f]
    assert r.element_children("d", "e") == [] and r.descendants("v", "f") == [f]
    assert X.canonicalize(r) == '<r xmlns="d"><c xmlns:p="u" a="1" p:b="2"></c><e xmlns=""></e><p:f xmlns:p="v"></p:f></r>'


# this wording is the SDK's own diagnostics (the reference surfaces xmldom's text), not a cross-language contract
@pytest.mark.parametrize("text,msg", [
    ("", "no root element"), ("   ", "no root element"), ("<!-- only -->", "no root element"),
    ("<a>", "unclosed element <a>"), ("<a><b>", "unclosed element <b>"),
    ("<a></b>", "mismatched end tag </b>"), ("</a>", "mismatched end tag </a>"),
    ("<a/><b/>", "more than one root element"), ("x<a/>", "text outside the root element"), ("<a/>x", "text outside the root element"),
    ("<a b=1/>", "unquoted attribute value"), ("<a b=", "unquoted attribute value"),
    ("<a b/>", "attribute without a value"), ("<a b", "attribute without a value"),
    ('<a b="1"c="2"/>', "missing whitespace before an attribute"), ('<a 1="x"/>', "bad attribute name"),
    ("<a b='1' b='2'/>", "duplicate attribute b"), ('<a b="1/>', "unterminated attribute value"),
    ("<a", "unterminated start tag"), ("<a ", "unterminated start tag"), ("<1a/>", "bad start tag"),
    ("<p:a/>", "unbound namespace prefix p"), ('<a q:b="1"/>', "unbound namespace prefix q"), ('<a xmlns:p=""/>', "namespace prefix cannot be undeclared"),
    ("<a><![CDATA[x</a>", "bad CDATA section"), ("<![CDATA[x]]><a/>", "bad CDATA section"),
    ("<a><!-- x </a>", "unterminated comment"), ("<a><?pi </a>", "unterminated processing instruction"), ("<!DOCTYPE a [ <a/>", "unterminated declaration"),
    ("<a></ a>", "bad end tag"), ("<a></a x>", "bad end tag"), ("<a></a", "bad end tag"),
    ("<a>&nope;</a>", "unknown entity &nope;"), ('<a b="<"/>', "'<' in an attribute value"),
])
def test_parse_xml_refuses_ill_formed(text, msg):
    with pytest.raises(X.XmlError) as e:
        X.parse_xml(text)
    assert str(e.value) == msg


# ------------------------------------------------------------------------------------------------ V8 JSON.parse messages


def jerr(text):
    with pytest.raises(C.JsError) as e:
        C.js_json_loads(text)
    return str(e.value)


def pad(p, n):  # an unexpected 'x' at position p of an n-character JSON array
    s = "[" + " " * (p - 1) + "x" + " " * (n - p - 2) + "]"
    assert len(s) == n
    return s


# messages recorded from V8 (node): JSON.parse(pad(p, n))
@pytest.mark.parametrize("p,n,msg", [
    (9, 20, "Unexpected token 'x', \"[        x         ]\" is not valid JSON"),
    (10, 20, "Unexpected token 'x', \"[         x        ]\" is not valid JSON"),
    (9, 21, "Unexpected token 'x', \"[        x         \"... is not valid JSON"),
    (10, 21, "Unexpected token 'x', ...\"[         x         \"... is not valid JSON"),
    (11, 21, "Unexpected token 'x', ...\"          x        ]\" is not valid JSON"),
    (14, 25, "Unexpected token 'x', ...\"          x         \"... is not valid JSON"),
    (15, 25, "Unexpected token 'x', ...\"          x        ]\" is not valid JSON"),
    (16, 25, "Unexpected token 'x', ...\"          x       ]\" is not valid JSON"),
    (23, 25, "Unexpected token 'x', ...\"          x]\" is not valid JSON"),
])
def test_v8_context_windows(p, n, msg):
    assert jerr(pad(p, n)) == msg


@pytest.mark.parametrize("text,msg", [
    ("[1, 2, 3, 4, 5, 6, 7, x]", "Unexpected token 'x', ...\" 5, 6, 7, x]\" is not valid JSON"),
    ("x234567890123456789012345", "Unexpected token 'x', \"x234567890\"... is not valid JSON"),
    ("[1,2,3,4,5,6,7,8,9,x,1,2,3,4,5,6,7,8,9]", "Unexpected token 'x', ...\"5,6,7,8,9,x,1,2,3,4,\"... is not valid JSON"),
    ("tx", "Unexpected token 'x', \"tx\" is not valid JSON"),
    ("nulx", "Unexpected token 'x', \"nulx\" is not valid JSON"),
    ("NaN", '"NaN" is not valid JSON'),
    ("Infinity", '"Infinity" is not valid JSON'),
    ("undefined", '"undefined" is not valid JSON'),
    ("[object Object]", '"[object Object]" is not valid JSON'),
    ("t", "Unexpected end of JSON input"),
    ('{"k":tx}', "Unexpected token 'x', \"{\"k\":tx}\" is not valid JSON"),
    ("[nul]", "Unexpected token ']', \"[nul]\" is not valid JSON"),
    ("[nulx]", "Unexpected token 'x', \"[nulx]\" is not valid JSON"),
    ("[f]", "Unexpected token ']', \"[f]\" is not valid JSON"),
    ("[1, NaN]", "Unexpected token 'N', \"[1, NaN]\" is not valid JSON"),
    ("[Infinity]", "Unexpected token 'I', \"[Infinity]\" is not valid JSON"),
    (" NaN", "Unexpected token 'N', \" NaN\" is not valid JSON"),
    ('["NaN", NaN]', "Unexpected token 'N', \"[\"NaN\", NaN]\" is not valid JSON"),
    ('["a\\"NaN", Infinity]', "Unexpected token 'I', \"[\"a\\\"NaN\", Infinity]\" is not valid JSON"),
    ('{"NaN":[true, NaN]}', "Unexpected token 'N', \"{\"NaN\":[true, NaN]}\" is not valid JSON"),
    # the reference's Node appends " (line 1 column N)" to these two families; the coordinator's ruling keeps the bare form
    ("-", "No number after minus sign in JSON at position 1 (line 1 column 2)"),
    ("-x", "No number after minus sign in JSON at position 1 (line 1 column 2)"),
    ("-Infinity", "No number after minus sign in JSON at position 1 (line 1 column 2)"),
    ("[-Infinity]", "No number after minus sign in JSON at position 2 (line 1 column 3)"),
    ('["Infinity", -Infinity]', "No number after minus sign in JSON at position 14 (line 1 column 15)"),
    (" ", "Unexpected end of JSON input"),
])
def test_v8_messages(text, msg):
    assert jerr(text) == msg


def test_a_value_error_that_is_not_a_constant_keeps_position_zero(monkeypatch):
    def loads(_text, **_kw):
        raise ValueError("Exceeds the limit for integer string conversion")
    monkeypatch.setattr(C.json, "loads", loads)
    assert jerr("[1]") == "Unexpected token '[', \"[1]\" is not valid JSON"


def test_v8_message_direct_edges():
    assert C._v8_json_message("abc", 3) == "Unexpected end of JSON input"
    assert C._v8_json_message("abc", 9) == "Unexpected end of JSON input"
    assert C._v8_json_message("a" * 30, 25) == "Unexpected token 'a', ...\"%s\" is not valid JSON" % ("a" * 15)


@pytest.mark.parametrize("s,hx", [
    ("QUJD", "414243"), ("QUJ", "4142"), ("QU", "41"), ("Q", ""), ("QUJDR", "414243"), ("QU=JD", "41"), ("Q U\nJ*D", "414243"),
    ("-_8", "fbff"), ("_-_-", "ffeffe"), ("QUJD====RQ", "414243"), ("", ""), ("++//", "fbefff"),
])
def test_node_lenient_base64_matches_buffer_from(s, hx):  # node: Buffer.from(s, 'base64').toString('hex')
    assert C.node_b64decode(s).hex() == hx


# ------------------------------------------------------------------------------------------------ compact JWS


def seg(obj):
    return b64u(obj if isinstance(obj, bytes) else json.dumps(obj).encode())


def jws_err(token):
    with pytest.raises(TypeError) as e:
        C.parse_jws(token, "fn")
    return str(e.value)


def test_parse_jws_whole_result():
    h = seg({"alg": "ES256", "kid": "k1", "jku": "https://j", "typ": "JWT", "x5c": ["a", "b"], "extra": 1})
    p = seg({"a": 1, "b": [True]})
    assert C.parse_jws("%s.%s.AQI" % (h, p), "fn") == {
        "header": {"alg": "ES256", "kid": "k1", "jku": "https://j", "typ": "JWT", "x5c": ["a", "b"]},
        "payload": {"a": 1, "b": [True]},
        "signingInput": ("%s.%s" % (h, p)).encode(),
        "signature": b"\x01\x02",
    }
    h2 = seg({"alg": "RS256", "kid": 1, "jku": None, "typ": ["x"], "x5c": ["a", 1]})
    assert C.parse_jws("%s.%s.AA" % (h2, p), "fn")["header"] == {"alg": "RS256"}
    h3 = seg({"alg": "x", "x5c": "a", "kid": ""})
    assert C.parse_jws("%s.%s.AA" % (h3, p), "fn")["header"] == {"alg": "x", "kid": ""}
    assert C.parse_jws("%s.%s.AA" % (seg({"alg": "x", "x5c": []}), p), "fn")["header"] == {"alg": "x", "x5c": []}


def test_parse_jws_refusals():
    h, p = seg({"alg": "ES256"}), seg({})
    assert jws_err(5) == "fn: empty token"
    assert jws_err("") == "fn: empty token"
    assert jws_err("%s.%s" % (h, p)) == "fn: a compact JWS has exactly three dot-separated parts"
    assert jws_err("%s.%s.AA.AA" % (h, p)) == "fn: a compact JWS has exactly three dot-separated parts"
    for t in (".%s.AA" % p, "%s..AA" % h, "%s.%s." % (h, p)):
        assert jws_err(t) == "fn: empty JWS segment"
    j = "fn: malformed JSON segment: "
    assert jws_err("%s*.%s.AA" % (h, p)) == j + "non-canonical compact JWS: bad-character"
    assert jws_err("%s.%s*.AA" % (h, p)) == j + "non-canonical compact JWS: bad-character"
    assert jws_err("QUJDR.%s.AA" % p) == j + "non-canonical compact JWS: non-canonical-base64url (impossible length)"
    assert jws_err("QR.%s.AA" % p) == j + "non-canonical compact JWS: non-canonical-base64url"
    assert jws_err("%s.%s.AA" % (seg(b"tx"), p)) == j + "Unexpected token 'x', \"tx\" is not valid JSON"
    assert jws_err("%s.%s.AA" % (h, seg(b"tx"))) == j + "Unexpected token 'x', \"tx\" is not valid JSON"
    for bad in (b"[]", b"null", b"1", b'"s"'):
        assert jws_err("%s.%s.AA" % (seg(bad), p)) == "fn: header is not a JSON object"
        assert jws_err("%s.%s.AA" % (h, seg(bad))) == "fn: payload is not a JSON object"
    for hdr in ({}, {"alg": ""}, {"alg": 1}, {"alg": None}):
        assert jws_err("%s.%s.AA" % (seg(hdr), p)) == "fn: header has no alg"
    s = "fn: malformed signature segment: non-canonical compact JWS: "
    assert jws_err("%s.%s.A*" % (h, p)) == s + "bad-character"
    assert jws_err("%s.%s.AAAAA" % (h, p)) == s + "non-canonical-base64url (impossible length)"
    assert jws_err("%s.%s.AB" % (h, p)) == s + "non-canonical-base64url"


# ------------------------------------------------------------------------------------------------ MAA verifier before the signature


# the certificate parser's own diagnostics (the reference surfaces OpenSSL's text), not a cross-language contract
TRUNCATED = "error:0688010A:asn1 encoding routines::nested asn1 error (truncated)"
MAA = {"trustedIssuers": ["https://maa.example"], "trustAnchors": {"rootSpkiSha256": ["aa"]}, "policy": {"tdxMrtds": ["aa"]}}


def maa(ev=None, resolver=True, raise_=None):
    def resolve(_doc):
        if raise_ is not None:
            raise raise_
        return ev

    opts = dict(MAA)
    if resolver:
        opts["resolve_evidence"] = resolve
    return AzureMaaVerifier(opts).verify({}, {"holderPub": "h"}, 1_800_000_000_000)


def tok(header, payload=None):
    return "%s.%s.AA" % (seg(header), seg(payload or {}))


def fail(reason):
    return {"ok": False, "reason": reason}


def test_maa_verify_fails_closed_on_a_raising_resolver():
    assert maa(raise_=RuntimeError("boom")) == fail("azure-maa verification error (fail closed): boom")
    assert maa(raise_=ValueError("")) == fail("azure-maa verification error (fail closed): ")


def test_maa_verify_pre_signature_reasons():
    assert maa(resolver=False) == fail("no Azure MAA evidence resolver configured (fail closed)")
    for ev in (None, "tok", {}, {"token": ""}, {"token": 5}):
        assert maa(ev) == fail("no Azure MAA token for this action")
    assert maa({"token": "a.b"}) == fail("MAA token parse failed: parseMaaJwt: a compact JWS has exactly three dot-separated parts")
    assert maa({"token": tok({"alg": "HS256"})}) == fail("unsupported JWS alg 'HS256' (MAA uses ES256 / RS256)")
    assert maa({"token": tok({"alg": "ES256"})}) == fail("no signing x5c available (no JWKS and no header x5c)")
    assert maa({"token": tok({"alg": "ES256", "x5c": []})}) == fail("no signing x5c available (no JWKS and no header x5c)")
    assert maa({"token": tok({"alg": "RS256", "x5c": [""]})}) == fail("MAA signing chain invalid: empty x5c entry at index 0")
    two = {"keys": [{"kid": "a", "x5c": ["x"]}, {"kid": "b", "x5c": ["y"]}]}
    assert maa({"token": tok({"alg": "ES256"}), "jwks": two}) == fail("token has no kid and the JWKS publishes multiple keys (ambiguous)")
    assert maa({"token": tok({"alg": "ES256", "kid": ""}), "jwks": two}) == fail("token has no kid and the JWKS publishes multiple keys (ambiguous)")
    assert maa({"token": tok({"alg": "ES256"}), "jwks": {"keys": [{"kid": "a"}]}}) == fail("JWKS key carries no x5c chain")
    assert maa({"token": tok({"alg": "ES256"}), "jwks": {"keys": [{"x5c": []}]}}) == fail("JWKS key carries no x5c chain")
    assert maa({"token": tok({"alg": "ES256"}), "jwks": {"keys": [{"x5c": [""]}]}}) == fail("MAA signing chain invalid: empty x5c entry at index 0")
    assert maa({"token": tok({"alg": "ES256", "kid": "k9"}), "jwks": two}) == fail("no JWKS key matches the token kid 'k9' (untrusted signer)")
    assert maa({"token": tok({"alg": "ES256", "kid": "a"}), "jwks": {"keys": [{"kid": "a", "x5c": []}]}}) == fail("JWKS key 'a' carries no x5c chain")
    assert maa({"token": tok({"alg": "ES256", "kid": "b"}), "jwks": two}) == fail("MAA signing chain invalid: malformed x5c certificate at index 0: " + TRUNCATED)
    # an empty JWKS falls back to the header chain
    assert maa({"token": tok({"alg": "ES256", "x5c": [""]}), "jwks": {"keys": []}}) == fail("MAA signing chain invalid: empty x5c entry at index 0")
