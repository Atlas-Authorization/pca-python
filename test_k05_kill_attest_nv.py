"""0.5 mutation-kill tests of the NVIDIA / XML / Azure MAA / GCP Confidential Space group: the strict XML subset and its canonical
form, the SPDM transcript parser edges, the RIM document element matching, the RIM ids / golden comparison / CRL gate, the
collateral hook and verifier messages, the MAA x5c chain and verifier, and the GCP key resolution and token verifier.
Expected strings and limits are the TypeScript reference's (packages/pca/src/attest-nvidia-spdm.ts, attest-nvidia-rim.ts,
attest-azure-maa.ts, attest-gcp-confidential-space.ts). Wording that embeds a library's own error text in the reference is
the SDK's own diagnostics here and not a cross-language contract."""
import hashlib
import json
import signal
import types

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric import ed25519

from atlas_pca import attest_azure as A
from atlas_pca import attest_common as C
from atlas_pca import attest_gcp as G
from atlas_pca import attest_nvidia as N
from atlas_pca import attest_xml as X
from atlas_pca.attest_amd import AttestConstructError
from atlas_pca.attest_azure import AzureMaaVerifier, verify_x5c_chain
from test_attest_units import EXP, NOW, b64, b64u
from test_k05_kill_attest_crypto import (
    BIND,
    DM,
    DS,
    DV,
    ISS,
    NS,
    NS_S,
    ONE,
    SM,
    SV,
    TS_OK,
    CM,
    META,
    W,
    base,
    ec_jwk,
    key_is,
    maa_token,
    pem,
    ref,
    resolve,
    res,
    rim,
    rim_text,
    rsa_jwk,
    run,
    signed,
    spki,
    tdx_ok,
    x5,
    xf,
)
from test_k05_kill_attest_pure import tx

PI = "XML processing instructions are not permitted"
CMT = "XML comments are not permitted"
DTD = "DTD / DOCTYPE is not permitted"


# ------------------------------------------------------------------------------------------------ helpers


def _alarm(_signum, _frame):
    raise TimeoutError("did not terminate")


def bounded(fn, *args, secs=2):
    """A mutant that stops a scan advancing loops forever: cut it off so the test fails instead of hanging."""
    try:
        old = signal.signal(signal.SIGALRM, _alarm)
    except (AttributeError, ValueError):
        return fn(*args)
    signal.setitimer(signal.ITIMER_REAL, secs)
    try:
        return fn(*args)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


@pytest.fixture
def strict_hash(monkeypatch):
    """hashlib.new with case-sensitive algorithm names (the Node / OpenSSL spelling is the lowercase one)."""
    real = hashlib.new

    def new(name, *a, **k):
        if name != name.lower():
            raise ValueError("unsupported hash type " + name)
        return real(name, *a, **k)

    monkeypatch.setattr(hashlib, "new", new)


# ------------------------------------------------------------------------------------------------ XML subset


def test_xml_node_defaults_and_first_colon_split():
    e = X.Element("a", None)
    assert (e.qname, e.prefix, e.local, e.ns, e.attrs, e.decls, e.scope, e.children, e.parent) == ("a", "", "a", "", [], {}, {}, [], None)
    p = X.Element("p:q:r", e)
    assert (p.prefix, p.local, p.parent) == ("p", "q:r", e)
    a = X.Attr("x:y:z", "v")
    assert (a.prefix, a.local, a.ns, a.value, a.qname) == ("x", "y:z", "", "v", "x:y:z")
    b = X.Attr("n", "v")
    assert (b.prefix, b.local) == ("", "n")


def test_xml_parent_links():
    d = X.parse_xml("<a><b><c/></b></a>")
    b = d.root.children[0]
    assert d.root.parent is None and b.parent is d.root and b.children[0].parent is b


def test_xml_processing_instruction_scan():
    d = bounded(X.parse_xml, "<a><??></a>")
    assert d.violations == [PI] and d.root.children == []
    d = bounded(X.parse_xml, "<a><?>x?></a>")  # a "?>" that starts one character into the instruction does not end it
    assert d.violations == [PI] and d.root.children == []
    d = bounded(X.parse_xml, "<a><?p?><?q?></a>")
    assert d.violations == [PI, PI] and d.root.children == []


def test_xml_comment_scan():
    d = bounded(X.parse_xml, "<a><!----></a>")
    assert d.violations == [CMT] and d.root.children == []
    d = bounded(X.parse_xml, "<a><!-->x--></a>")  # "-->" overlapping the opener does not end the comment
    assert d.violations == [CMT] and d.root.children == []
    d = bounded(X.parse_xml, "<a><!--x--><!--y--></a>")
    assert d.violations == [CMT, CMT] and d.root.children == []


def test_xml_cdata_scan():
    assert bounded(X.parse_xml, "<a><![CDATA[]]></a>").root.children == [""]
    assert bounded(X.parse_xml, "<a><![CDATA[x]]><![CDATA[y]]></a>").root.children == ["x", "y"]
    assert bounded(X.parse_xml, "<a>]]><![CDATA[x]]></a>").root.children == ["]]>", "x"]


def test_xml_text_outside_the_root_is_judged_by_xml_whitespace_only():
    for t in ("\x0c<a/>", "\xa0<a/>", "<a/> ", "\x0b<a/>"):
        with pytest.raises(X.XmlError) as e:
            X.parse_xml(t)
        assert str(e.value) == "text outside the root element"
    assert X.parse_xml(" \t\r\n<a/> \n").root.qname == "a"


def test_xml_default_namespace_undeclared_at_the_root():
    d = X.parse_xml('<a xmlns=""/>')
    assert d.root.scope == {} and d.root.decls == {"": ""} and d.root.ns == ""


def test_xml_declaration_scan():
    for text in ("<!><a/>", "<!A [ [ ] > ] ><a/>", "<!A [ ] [ > ] ><a/>"):
        d = X.parse_xml(text)
        assert d.violations == [DTD] and d.root.qname == "a", text


def test_xml_attribute_quoting_and_whitespace_normalisation():
    with pytest.raises(X.XmlError) as e:
        X.parse_xml("<a b=XvX/>")
    assert str(e.value) == "unquoted attribute value"
    assert X.parse_xml('<a b="aXb"/>').root.get_attribute("b") == "aXb"
    assert X.parse_xml('<a b="a\tb"/>').root.get_attribute("b") == "a b"


def test_xml_reference_edges():
    with pytest.raises(X.XmlError) as e:
        X._unescape("&#a1;", False)
    assert str(e.value) == "bad character reference"
    assert X._unescape("&#9;", False) == "\t"
    with pytest.raises(X.XmlError):  # a C0 control is not an XML Char
        X._unescape("&#5;", False)
    with pytest.raises(X.XmlError) as e:
        X._unescape("&;", False)
    assert str(e.value) == "unknown entity &;"


def test_xml_canonical_skip_applies_at_every_depth():
    d = X.parse_xml("<r><a><b/><s/></a></r>")
    s = d.root.children[0].children[1]
    assert X.canonicalize(d.root, skip=s) == "<r><a><b></b></a></r>"


def test_xml_canonical_escapes():
    assert X._enc_text("a\r<>&b") == "a&#xD;&lt;&gt;&amp;b"
    assert X._enc_attr('&<">\t\n\rZ') == "&amp;&lt;&quot;>&#x9;&#xA;&#xD;Z"


# ------------------------------------------------------------------------------------------------ SPDM transcript edges


def _block(index, vsize):
    return bytes([index, 0]) + (3 + vsize).to_bytes(2, "little") + bytes([0]) + vsize.to_bytes(2, "little") + bytes([index]) * vsize


def test_spdm_record_length_uses_all_three_bytes():
    records = _block(1, 30000) + _block(2, 35522)
    assert len(records) == 65536
    p = N.parse_nvidia_spdm_evidence(tx(records=records, num_blocks=2))
    assert [(m["index"], len(m["digest"])) for m in p["measurements"]] == [(1, 30000), (2, 35522)]
    assert N._u24(b"\x01\x02\x03", 0) == 0x030201


def test_spdm_opaque_entry_that_fills_the_data_exactly():
    p = N.parse_nvidia_spdm_evidence(tx(opaque=(3).to_bytes(2, "little") + (0).to_bytes(2, "little")))
    assert p["opaque"] == {3: b""}


# ------------------------------------------------------------------------------------------------ RIM document matching


def _ok(r):
    assert r["ok"] is True, r
    return r["rim"]


def test_rim_matching_ignores_decoys_in_other_places():
    w = W()
    foreign = ' xmlns:o="u"'
    # a second dsig child of the root, of another kind, does not make the Signature "not direct"
    assert _ok(rim(signed(meta=META + "<ds:Extra %s/>" % DS)))["tagId"] == "T1"
    # the first dsig child of SignedInfo / Reference is not what is read: elements are found by name
    assert _ok(rim(signed(cm='<ds:Foo Algorithm="x"/>' + CM)))
    assert _ok(rim(signed(sm="<o:SignatureMethod%s Algorithm=\"bad\"/>" % foreign + SM)))
    assert _ok(rim(signed(reference=ref() + "<o:Reference%s/>" % foreign)))
    assert _ok(rim(signed(reference=ref(transforms="<o:Transforms%s/>" % foreign + TS_OK))))
    assert _ok(rim(signed(reference=ref(dm="<o:DigestMethod%s Algorithm=\"bad\"/>" % foreign + DM))))
    assert _ok(rim(signed(reference=ref(dv="<o:DigestValue%s/>" % foreign + DV))))
    assert _ok(rim(signed(sv="<o:SignatureValue%s/>" % foreign + SV)))
    certs = "".join("<ds:X509Certificate>%s</ds:X509Certificate>" % b64(d) for d in (w.direct_leaf_der, w.root_der))
    assert _ok(rim(signed(ki="<o:KeyInfo%s/>" % foreign + "<ds:KeyInfo><ds:X509Data>%s</ds:X509Data></ds:KeyInfo>" % certs)))
    assert _ok(rim(signed(ki="<ds:KeyInfo><ds:KeyName>n</ds:KeyName><o:X509Data%s/><ds:X509Data>%s</ds:X509Data></ds:KeyInfo>" % (foreign, certs))))
    decoys = "<ds:X509SubjectName>s</ds:X509SubjectName><o:X509Certificate%s>junk</o:X509Certificate>" % foreign
    assert _ok(rim(signed(ki="<ds:KeyInfo><ds:X509Data>%s%s</ds:X509Data></ds:KeyInfo>" % (decoys, certs))))


def test_rim_skips_non_measurement_resources_before_a_measurement():
    got = _ok(rim(signed(resources='<Resource type="Other"/><Thing/>' + ONE)))
    assert list(got["golden"]) == [1]


# ------------------------------------------------------------------------------------------------ RIM ids


VB = bytes.fromhex("aabbcc0496009f00")[::-1]  # renders as 96.00.9f.00.04


def opaque(extra=None, drop=()):
    d = {3: b"535.104.05\0", 6: VB, 15: b"cs15\0", 17: b"pr17", 18: b"ps18"}
    d.update(extra or {})
    for k in drop:
        d.pop(k, None)
    return d


IDS = {
    "chip": "GH100",
    "driver": "NV_GPU_DRIVER_GH100_535.104.05",
    "vbios": "NV_GPU_VBIOS_PR17_PS18_CS15_96009F0004",
    "driverVersion": "535.104.05",
    "vbiosVersion": "96.00.9f.00.04",
}


def ids_of(op):
    return N.nvidia_rim_ids_for_report({"opaque": op})


def test_rim_ids_hopper_and_blackwell_forms():
    assert ids_of(opaque()) == IDS
    gb = ids_of(opaque({35: b"GB100\0"}))
    assert gb == dict(IDS, chip="GB100", driver="NV_GPU_CC_DRIVER_GB100_535.104.05")
    assert ids_of(opaque({35: b"GH100"})) == IDS  # an explicit Hopper chip keeps the Hopper form
    for chip in (b"AB1", b"A" + b"B" * 11):
        assert ids_of(opaque({35: chip}))["chip"] == chip.decode()


def test_rim_ids_chip_shape():
    for chip in (b"", b"AB", b"gb100", b"1AB", b"AB-1", b"A" + b"B" * 12, b"G H100"):
        assert ids_of(opaque({35: chip})) is None, chip


def test_rim_ids_need_every_field():
    for tag in (3, 6, 15, 17, 18):
        assert ids_of(opaque(drop=(tag,))) is None, tag
    for tag in (3, 15, 17, 18):
        assert ids_of(opaque({tag: b"\0"})) is None, tag
    assert ids_of({}) is None


# ------------------------------------------------------------------------------------------------ golden comparison


def gold(index, hashes, active=True, size=None):
    return {"index": index, "active": active, "alternatives": len(hashes), "size": size if size is not None else len(hashes[0]) // 2, "hashes": hashes}


def rimg(*gs):
    return {"golden": {x["index"]: x for x in gs}}


def rep(*meas, op=None):
    return {"measurements": [{"index": i, "digest": d} for i, d in meas], "opaque": op or {}}


def cmp(report, drv, vb=None):
    return N.compare_report_to_rims(report, drv, vb if vb is not None else rimg())


def differ(n):
    return {"ok": False, "reason": "runtime measurements differ from the golden RIM values at %d index(es)" % n}


def test_compare_conflict_and_inactive_entries():
    assert cmp(rep((4, b"\xaa")), rimg(gold(3, ["aa"])), rimg(gold(3, ["bb"]))) == {
        "ok": False, "reason": "driver and VBIOS RIMs both have an active measurement at index 3"}
    # an inactive VBIOS entry never conflicts and never stops the scan of the ones after it
    assert cmp(rep((1, b"\xaa"), (2, b"\x00")), rimg(gold(0, ["aa"])), rimg(gold(5, ["bb"], active=False), gold(1, ["cc"]))) == differ(1)
    assert cmp(rep((4, b"\xaa")), rimg(gold(3, ["aa"])), rimg(gold(3, ["bb"], active=False))) == {"ok": True}


def test_compare_counts_of_active_measurements():
    assert cmp(rep((1, b"\xaa")), rimg(gold(0, ["aa"], active=False))) == {"ok": False, "reason": "RIMs carry no active golden measurements"}
    assert cmp(rep((1, b"\xaa")), rimg()) == {"ok": False, "reason": "RIMs carry no active golden measurements"}
    assert cmp(rep((1, b"\xaa")), rimg(gold(0, ["aa"]))) == {"ok": True}  # one active, one carried
    assert cmp(rep((1, b"\xaa")), rimg(gold(0, ["aa"]), gold(1, ["bb"]))) == {
        "ok": False, "reason": "RIMs list more active measurements than the report carries"}


def test_compare_digest_rules():
    assert cmp(rep((1, b"\xbb")), rimg(gold(0, ["aa", "bb"]))) == {"ok": True}
    assert cmp(rep((1, b"\xbb")), rimg(gold(0, ["aa"]))) == differ(1)
    assert cmp(rep((1, b"\xaa")), rimg(gold(5, ["aa"]))) == differ(1)  # no runtime block at the index
    assert cmp(rep((1, b"\xab\xcd")), rimg(gold(0, ["abcd"], size=1))) == differ(1)  # right bytes, wrong declared size
    assert cmp(rep((1, b"\x00"), (2, b"\x00")), rimg(gold(0, ["aa"]), gold(1, ["bb"]))) == differ(2)


def test_compare_nvdec_block_skip():
    one = rimg(gold(34, ["aa"]))
    r = lambda op: cmp(rep((35, b"\x00"), op=op), one)  # noqa: E731
    assert r({11: b"\x55"}) == {"ok": True}
    assert r({11: b"\x55\x01"}) == {"ok": True}
    for op in ({11: b"\x54"}, {11: b"\x56"}, {11: b""}, {}, {12: b"\x55"}):
        assert r(op) == differ(1), op
    disabled = {11: b"\x55"}
    assert cmp(rep((34, b"\x00"), op=disabled), rimg(gold(33, ["aa"]))) == differ(1)  # only block 35 is skipped
    assert cmp(rep((37, b"\x00"), op=disabled), rimg(gold(36, ["aa"]))) == differ(1)
    # the skip does not end the scan
    assert cmp(rep((35, b"\x00"), (41, b"\x00"), op=disabled), rimg(gold(34, ["aa"]), gold(40, ["bb"]))) == differ(1)


# ------------------------------------------------------------------------------------------------ CRL gate


def test_revocation_refuses_a_verified_crl_without_a_revoked_set(monkeypatch):
    monkeypatch.setattr(N, "verify_crl", lambda crl, key, now: {"ok": True, "revoked": None})
    chain = [types.SimpleNamespace(public_key=None, serial_hex="01", subject="CN=a")]
    assert N.check_nvidia_chain_revocation(chain, [b"x"], 1) == {"ok": False, "reason": "CRL #0 rejected: no chain certificate verifies it"}


# ------------------------------------------------------------------------------------------------ collateral hook


def hctx(op=None, subject="CN=NVIDIA GH100 Device", **over):
    c = {"report": {"opaque": opaque() if op is None else op, "measurements": []}, "leaf": types.SimpleNamespace(subject=subject), "chain": ["chain"], "nowMs": 77, "evidence": {"e": 1}}
    c.update(over)
    return c


def mkhook(**o):
    d = {"rimRootSpkiSha256": ["aa"], "resolve": lambda ids, ev: None}
    d.update(o)
    return N.NvidiaCollateralHook(d)


def rim_ok(product="GH100", version="535.104.05"):
    return {"ok": True, "rim": {"product": product, "version": version, "golden": {}}}


def test_hook_naming_and_family_gates():
    assert mkhook()(hctx(op={})) == "GPU report does not carry the opaque fields needed to name its RIMs"
    assert mkhook()(hctx()) == "no RIM collateral supplied for this report"
    for subject in ("GH100", "CN=GH100", "GH100,O=x", "a GH100 b"):
        assert mkhook()(hctx(subject=subject)) == "no RIM collateral supplied for this report", subject
    mism = "device leaf subject '%s' is not a GH100 device certificate (chip family mismatch)"
    assert mkhook()(hctx(subject="O=Acme\nCN=Other")) == mism % "O=Acme, CN=Other"
    for subject in ("CN=XGH100", "CN=GH100X", "CN=GH1000", "CN=gh100x1"):
        assert mkhook()(hctx(subject=subject)) == mism % subject, subject


def test_hook_resolve_receives_the_ids_and_the_evidence():
    seen = []
    mkhook(resolve=lambda ids, ev: seen.append((ids, ev)))(hctx())
    assert seen == [(IDS, {"e": 1})]


def _hook_flow(monkeypatch, d, v, **o):
    seq = iter([d, v])
    calls = []
    monkeypatch.setattr(N, "verify_nvidia_rim", lambda xml, pins, now: (calls.append((xml, pins, now)), next(seq))[1])
    bundle = {"driverRimXml": "D", "vbiosRimXml": "V"}
    r = mkhook(resolve=lambda ids, ev: bundle, **o)(hctx())
    return r, calls


def test_hook_rim_failures_and_products(monkeypatch):
    bad = {"ok": False, "reason": "boom"}
    r, calls = _hook_flow(monkeypatch, bad, bad)
    assert r == "driver RIM: boom" and calls == [("D", ["aa"], 77), ("V", ["aa"], 77)]
    assert _hook_flow(monkeypatch, rim_ok(), dict(bad, reason="b2"))[0] == "VBIOS RIM: b2"
    assert _hook_flow(monkeypatch, rim_ok("GB100"), rim_ok("GH100", "96.00.9F.00.04"))[0] == (
        "driver RIM product 'GB100' does not match the GPU chip 'GH100' (wrong-family manifest)")
    assert _hook_flow(monkeypatch, rim_ok(), rim_ok("GB100", "96.00.9F.00.04"))[0] == (
        "VBIOS RIM product 'GB100' does not match the GPU chip 'GH100' (wrong-family manifest)")
    assert _hook_flow(monkeypatch, rim_ok(version="1"), rim_ok("GH100", "96.00.9F.00.04"))[0] == "driver RIM version '1' does not match the report's driver '535.104.05'"
    assert _hook_flow(monkeypatch, rim_ok(), rim_ok(version="9.9"))[0] == "VBIOS RIM version '9.9' does not match the report's VBIOS '96.00.9f.00.04'"


@pytest.mark.parametrize("opts,bundle,want", [
    ({}, {}, ["crl"]),
    ({"requireCrls": False}, {}, []),
    ({"requireCrls": False}, {"crls": [b"c"]}, ["crl"]),
    ({"requireCrls": False}, {"ocsp": [b"o"]}, ["ocsp"]),
    ({"revocation": "crl"}, {}, ["crl"]),
    ({"revocation": "ocsp"}, {}, ["ocsp"]),
    ({"revocation": "both"}, {}, ["crl", "ocsp"]),
    ({"revocation": "ocsp"}, {"crls": [b"c"]}, ["crl", "ocsp"]),
    ({"revocation": "crl", "requireCrls": False}, {}, ["crl"]),
])
def test_hook_revocation_mode_table(monkeypatch, opts, bundle, want):
    monkeypatch.setattr(N, "verify_nvidia_rim", lambda xml, pins, now: rim_ok() if xml == "D" else rim_ok("GH100", "96.00.9F.00.04"))
    monkeypatch.setattr(N, "compare_report_to_rims", lambda r, d, v: {"ok": True})
    calls = []
    monkeypatch.setattr(N, "check_nvidia_chain_revocation", lambda chain, crls, now, req: (calls.append(("crl", chain, crls, now, req)), {"ok": True})[1])
    monkeypatch.setattr(N, "check_nvidia_chain_ocsp", lambda chain, ocsp, now: (calls.append(("ocsp", chain, ocsp, now)), {"ok": True})[1])
    b = dict(driverRimXml="D", vbiosRimXml="V", **bundle)
    assert mkhook(resolve=lambda ids, ev: b, requireCrlIssuers=["X"], **opts)(hctx()) is None
    assert [c[0] for c in calls] == want
    for c in calls:
        assert c[1] == ["chain"] and c[3] == 77
        if c[0] == "crl":
            assert c[2] == bundle.get("crls", []) and c[4] == ["X"]
        else:
            assert c[2] == bundle.get("ocsp", [])


def test_hook_revocation_failures_are_prefixed(monkeypatch):
    monkeypatch.setattr(N, "verify_nvidia_rim", lambda xml, pins, now: rim_ok() if xml == "D" else rim_ok("GH100", "96.00.9F.00.04"))
    monkeypatch.setattr(N, "compare_report_to_rims", lambda r, d, v: {"ok": True})
    monkeypatch.setattr(N, "check_nvidia_chain_revocation", lambda *a: {"ok": False, "reason": "r1"})
    monkeypatch.setattr(N, "check_nvidia_chain_ocsp", lambda *a: {"ok": False, "reason": "r2"})
    b = {"driverRimXml": "D", "vbiosRimXml": "V"}
    assert mkhook(resolve=lambda i, e: b)(hctx()) == "revocation: r1"
    assert mkhook(resolve=lambda i, e: b, revocation="ocsp")(hctx()) == "revocation (OCSP): r2"


# ------------------------------------------------------------------------------------------------ verifier construction / messages


def nv(**o):
    d = {"rootSpkiSha256": ["aa"], "postVerify": lambda c: None}
    d.update(o)
    return N.NvidiaSpdmVerifier(d)


def test_verifier_policy_shapes():
    for pol in ("bad", ["x"], 5):
        assert nv(policy=pol)._want == []
    assert nv(policy=None)._leaf_includes is None
    assert nv(policy={"measurements": [1, 2]})._want == []
    assert nv(policy={"measurements": {1: "AB", "2": "cd"}})._want == [(1, "ab"), (2, "cd")]


def test_verifier_measurement_index_range():
    ok = lambda k: nv(policy={"measurements": {k: "ab"}})._want  # noqa: E731
    assert ok("0") == [(0, "ab")] and ok("255") == [(255, "ab")] and ok(0) == [(0, "ab")]
    for k in ("-1", "256", "1.5", "x"):
        with pytest.raises(AttestConstructError) as e:
            ok(k)
        assert str(e.value) == "createNvidiaSpdmVerifier: measurement index out of range"


def _nv_env(monkeypatch, subject="CN=x\nO=y"):
    leaf = types.SimpleNamespace(subject=subject, public_key="PK")
    monkeypatch.setattr(N, "verify_nvidia_device_chain", lambda pem_, pins, now: {"ok": True, "leaf": leaf, "chain": ["c"]})
    monkeypatch.setattr(N, "ecdsa_verify_raw", lambda *a: True)
    monkeypatch.setattr(N, "attestation_challenge_sha256", lambda e: bytes(range(32)))
    return leaf


def tlv(tag, val):
    return tag.to_bytes(2, "little") + len(val).to_bytes(2, "little") + val


def test_verifier_passes_the_document_to_the_resolver(monkeypatch):
    seen = []
    nv(resolve_evidence=lambda d: seen.append(d))._post_verify  # noqa: B018
    r = nv(resolve_evidence=lambda d: seen.append(d)).verify("DOC", EXP, 1)
    assert seen == ["DOC"] and r == {"ok": False, "reason": "no NVIDIA GPU evidence for this action"}


def test_verifier_requires_an_expected_binding(monkeypatch):
    _nv_env(monkeypatch)
    v = nv(resolve_evidence=lambda d: {"evidence": tx(resp_ver=0x11), "certChainPem": "p"})
    assert v.verify({}, None, 1) == {"ok": False, "reason": "no expected attestation binding supplied"}


def test_verifier_success_shape_and_driver_decoding(monkeypatch):
    leaf = _nv_env(monkeypatch)
    seen = []
    ev = {"evidence": tx(resp_ver=0x11, opaque=tlv(3, b"5\xff\xfe\0\0") + tlv(6, VB)), "certChainPem": "p"}
    v = nv(resolve_evidence=lambda d: ev, postVerify=lambda ctx: seen.append(ctx))
    r = v.verify({}, EXP, 9)
    assert r == {
        "ok": True, "bound": True,
        "measured": {"model_id": "", "weights_digest": "", "weights_measured": False, "runtime_measurement": "", "operator": ""},
        "hostAsserted": {"attestation_type": "nvidia-gpu-cc", "gpu_measurements_sha384": hashlib.sha384().hexdigest(), "leaf_subject": "CN=x, O=y",
                         "driver_version": "5��", "vbios_version": "96.00.9f.00.04"},
    }
    assert len(seen) == 1 and set(seen[0]) == {"report", "chain", "leaf", "nowMs", "evidence"}
    assert seen[0]["leaf"] is leaf and seen[0]["chain"] == ["c"] and seen[0]["nowMs"] == 9 and seen[0]["evidence"] is ev


def test_verifier_unexpected_errors_fail_closed():
    def boom(_d):
        raise ValueError("boom")

    assert nv(resolve_evidence=boom).verify({}, EXP, 1) == {"ok": False, "reason": "nvidia-spdm verification error (fail closed): boom"}


# ------------------------------------------------------------------------------------------------ Azure MAA


def test_azure_kty_names():
    w = W()
    assert A._kty(w.aleaf.public_key()) == "EC"
    assert A._kty(w.rsa.public_key()) == "RSA"
    ed = ed25519.Ed25519PrivateKey.generate().public_key()
    assert A._kty(ed) == C.key_type(ed) and A._kty(ed) not in ("EC", "RSA")


def test_azure_x5c_anchors_must_be_an_object():
    leaf = x5(W().adirect_der)
    for anchors in (None, "abc", [], 5):
        assert verify_x5c_chain(leaf, anchors, NOW) == xf("no MAA trust anchor configured (fail closed)")


def test_azure_x5c_single_character_pin_is_an_anchor():
    leaf = x5(W().adirect_der)
    assert verify_x5c_chain(leaf, {"rootSpkiSha256": ["a"]}, NOW) == xf("x5c chain does not anchor in a configured MAA trust root")


def test_azure_x5c_root_certificate_anchors_by_fingerprint_when_in_the_chain():
    w = W()
    chain = x5(w.aleaf_der, w.ainter_der, w.aroot_der, w.aother_der)
    r = verify_x5c_chain(chain, {"rootCertsPem": [pem(w.aroot_der)]}, NOW)  # nothing above the anchor is examined
    assert r["ok"] is True and r["leaf"].raw == w.aleaf_der


def test_azure_x5c_hash_names_are_lowercase(strict_hash):
    w = W()
    inchain = verify_x5c_chain(x5(w.adirect_der), {"rootSpkiSha256": [spki(w.aleaf.public_key())]}, NOW)
    assert inchain["ok"] is True and inchain["leafSpkiSha256"] == spki(w.aleaf.public_key())
    external = verify_x5c_chain(x5(w.aleaf_der, w.ainter_der), {"rootCertsPem": [pem(w.aroot_der)]}, NOW)
    assert external["ok"] is True and external["leafSpkiSha256"] == spki(w.aleaf.public_key())
    assert verify_x5c_chain(x5(w.aleaf_der, w.ainter_der, w.aroot_der), {"rootSpkiSha256": [w.apin]}, NOW)["ok"] is True


def test_azure_jws_unsupported_alg_message():
    parsed = {"header": {"alg": "HS256"}, "signature": b"", "signingInput": b""}
    assert A._verify_jws_signature(parsed, types.SimpleNamespace(public_key=None)) == "unsupported JWS alg 'HS256' (MAA uses ES256 / RS256)"


def test_azure_jwks_key_that_is_not_an_object():
    assert A._resolve_signing_x5c({}, {"keys": [5]}) == {"reason": "JWKS key carries no x5c chain"}
    assert A._resolve_signing_x5c({}, {"keys": [{"x5c": ["a"]}]}) == {"x5c": ["a"]}


AZ_OPTS = {"trustedIssuers": [ISS], "trustAnchors": {"rootSpkiSha256": ["aa"]}, "policy": {"tdxMrtds": ["aa"]}}


def test_azure_construction_anchor_counts_and_allowlists():
    for anchors in (None, "x", []):
        with pytest.raises(AttestConstructError) as e:
            AzureMaaVerifier(dict(AZ_OPTS, trustAnchors=anchors))
        assert str(e.value) == "createAzureMaaVerifier: trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted"
    AzureMaaVerifier(dict(AZ_OPTS, trustAnchors={"rootCertsPem": ["x"], "rootSpkiSha256": ["y"]}))  # both kinds count, they do not cancel
    AzureMaaVerifier(dict(AZ_OPTS, trustAnchors={"rootCertsPem": ["x"], "rootSpkiSha256": None}))
    v = AzureMaaVerifier(dict(AZ_OPTS, policy={"sevSnpMeasurements": [], "tdxMrtds": ["aa"]}))
    assert (v._has_sev, v._has_tdx) == (False, True)
    v = AzureMaaVerifier(dict(AZ_OPTS, policy={"sevSnpMeasurements": ["aa"], "tdxMrtds": []}))
    assert (v._has_sev, v._has_tdx) == (True, False)


def test_azure_verifier_passes_the_document_to_the_resolver():
    seen = []
    v = AzureMaaVerifier(dict(AZ_OPTS, resolve_evidence=lambda d: seen.append(d)))
    assert v.verify("DOC", EXP, NOW) == xf("no Azure MAA token for this action") and seen == ["DOC"]


def test_azure_signing_chain_without_a_leaf_is_untrusted(monkeypatch):
    for answer, why in (({"ok": True}, "untrusted"), ({"ok": False}, "untrusted"), ({"ok": False, "reason": "boom"}, "boom"), ({"ok": True, "reason": "x"}, "x")):
        monkeypatch.setattr(A, "verify_x5c_chain", lambda *a, answer=answer: answer)
        assert run(token=maa_token(base())) == xf("MAA signing chain invalid: " + why)


def test_azure_skew_is_rounded_up_to_whole_seconds():
    assert run(base(exp=NS_S - 2), skew=1001) == tdx_ok()
    assert run(base(exp=NS_S - 2), skew=1000) == xf("MAA token expired")
    assert run(base(exp=NS_S - 1), skew=1000) == tdx_ok()


# ------------------------------------------------------------------------------------------------ GCP keys


class _Py39Int:
    """`int` as before Python 3.11: from_bytes needs its byte order."""

    @staticmethod
    def from_bytes(b, byteorder, *, signed=False):
        return int.from_bytes(b, byteorder, signed=signed)


def test_gcp_jwk_numbers_name_their_byte_order(monkeypatch):
    monkeypatch.setattr(G, "int", _Py39Int, raising=False)
    w = W()
    assert C.spki_sha(G._jwk_key(rsa_jwk(w.rsa)), "sha256") == spki(w.rsa.public_key())
    assert C.spki_sha(G._jwk_key(ec_jwk(w.aleaf, "P-256", 32)), "sha256") == spki(w.aleaf.public_key())


def test_gcp_hash_names_are_lowercase(strict_hash):
    w = W()
    chain = x5(w.aleaf_der, w.ainter_der)
    assert G.verify_jwk_x5c_chain(chain, {"trustedKeySpki": [spki(w.aleaf.public_key())]}, NOW, 0) is None
    a = ec_jwk(w.aleaf, "P-256", 32, kid="a")
    r = resolve({"kid": "a"}, anchors={"trustedJwks": {"keys": [a]}})
    key_is(r, w.aleaf)
    key_is(resolve({"kid": "e"}, {"keys": [dict(a, kid="e")]}, {"trustedJwks": {"keys": [a]}}), w.aleaf)  # compared against the pinned set
    key_is(resolve({"kid": "b"}, {"keys": [ec_jwk(w.aother, "P-256", 32, kid="b")]}, {"trustedKeySpki": [spki(w.aother.public_key())]}), w.aother)
    honest = dict(ec_jwk(w.aleaf, "P-256", 32, kid="k"), x5c=chain)
    key_is(resolve({"kid": "k"}, {"keys": [honest]}, {"rootCertsPem": [pem(w.aroot_der)]}), w.aleaf)


def test_gcp_single_certificate_header_chain_is_used():
    w = W()
    one = x5(w.aleaf_der)
    pins = {"trustedKeySpki": [spki(w.aleaf.public_key())]}
    key_is(resolve({"kid": "k", "x5c": one}, anchors=pins), w.aleaf)
    key_is(resolve({"x5c": one}, anchors=pins), w.aleaf)


def test_gcp_empty_x5c_beside_a_key_is_no_chain():
    w = W()
    j = dict(ec_jwk(w.aother, "P-256", 32, kid="k"), x5c=[])
    assert resolve({"kid": "k"}, {"keys": [j]}, {"rootCertsPem": [pem(w.aroot_der)]}) == {
        "reason": "signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)"}


def test_gcp_jws_signature_key_messages():
    w = W()
    p = lambda alg: {"header": {"alg": alg}, "signature": b"", "signingInput": b""}  # noqa: E731
    assert G._verify_jws_signature(p("ES256"), w.leaf.public_key()) == "ES256 token but signing key is EC/P-384 (not EC P-256)"
    assert G._verify_jws_signature(p("ES256"), w.rsa.public_key()) == "ES256 token but signing key is RSA/undefined (not EC P-256)"
    assert G._verify_jws_signature(p("HS256"), None) == "unsupported JWS alg 'HS256' (Confidential Space uses RS256)"


def test_gcp_nonce_candidates():
    assert G._nonce_candidates(["a", "", "bc"]) == ["a", "bc"]
    assert G._nonce_candidates("") == [] and G._nonce_candidates("a") == ["a"] and G._nonce_candidates(5) == []


# ------------------------------------------------------------------------------------------------ GCP verifier

GISS = "https://gcp.example"
IMG = "AB" * 32
GCP_OPTS = {"trustedIssuers": [GISS], "trustAnchors": {"trustedKeySpki": ["aa"]}, "policy": {"imageDigests": [IMG]}}


def gcp_ctor(**o):
    return G.GcpConfidentialSpaceVerifier(dict(GCP_OPTS, **o))


def test_gcp_construction_issuers_anchors_and_policy():
    for iss in ("", 5, None):
        with pytest.raises(AttestConstructError) as e:
            gcp_ctor(trustedIssuers=["https://a", iss])
        assert str(e.value) == "createGcpConfidentialSpaceVerifier: every trusted issuer must be a non-empty URL string"
    gcp_ctor(trustedIssuers=["x"])
    for anchors in (None, "x", {}):
        with pytest.raises(AttestConstructError) as e:
            gcp_ctor(trustAnchors=anchors)
        assert str(e.value) == (
            "createGcpConfidentialSpaceVerifier: trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted")
    gcp_ctor(trustAnchors={"trustedJwks": {"keys": [{}]}, "trustedKeySpki": ["aa"]})  # the kinds add up, they do not cancel
    gcp_ctor(trustAnchors={"trustedKeySpki": ["aa"], "rootCertsPem": ["x"]})
    for pol in (None, "x", {}, {"imageDigests": "abc"}, {"imageDigests": []}):
        with pytest.raises(AttestConstructError) as e:
            gcp_ctor(policy=pol)
        assert str(e.value) == "createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)"


def test_gcp_construction_skew():
    assert gcp_ctor()._skew == 0
    assert gcp_ctor(clockSkewMs="x")._skew == 0 and gcp_ctor(clockSkewMs=-5)._skew == 0
    assert gcp_ctor(clockSkewMs=3000)._skew == 3000


def gtoken(claims, alg="RS256"):
    return "%s.%s.%s" % (b64u(json.dumps({"alg": alg}).encode()), b64u(json.dumps(claims).encode()), b64u(b"sig"))


def gclaims(**over):
    c = {
        "iss": GISS, "exp": NS_S + 3600, "swname": "CONFIDENTIAL_SPACE", "hwmodel": "GCP_AMD_SEV", "dbgstat": "disabled-since-boot", "eat_nonce": BIND,
        "submods": {"confidential_space": {}, "container": {"image_digest": IMG}},
    }
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def gok():
    return {
        "ok": True, "bound": True,
        "measured": {"model_id": "", "weights_digest": "", "weights_measured": False, "runtime_measurement": IMG, "operator": ""},
        "hostAsserted": {"attestation_type": "sev-snp", "hwmodel": "GCP_AMD_SEV", "image_digest": IMG},
    }


@pytest.fixture
def gv(monkeypatch):
    monkeypatch.setattr(G, "_resolve_trusted_signing_key", lambda *a: {"key": object()})
    monkeypatch.setattr(G, "_verify_jws_signature", lambda parsed, key: None)

    def go(claims, policy=None, skew=None, resolver=None):
        pol = {"imageDigests": [IMG]}
        pol.update(policy or {})
        opts = dict(GCP_OPTS, policy=pol, resolve_evidence=resolver or (lambda d: {"token": gtoken(claims)}))
        if skew is not None:
            opts["clockSkewMs"] = skew
        return G.GcpConfidentialSpaceVerifier(opts).verify("DOC", EXP, NOW)

    return go


def gf(reason):
    return {"ok": False, "reason": reason}


def test_gcp_verifier_baseline_and_resolver_argument(gv):
    assert gv(gclaims()) == gok()
    seen = []
    assert gv(None, resolver=lambda d: seen.append(d)) == gf("no GCP Confidential Space token for this action") and seen == ["DOC"]


def test_gcp_time_window_and_rounding(gv):
    nbf, iat = "Confidential Space token not yet valid (nbf)", "Confidential Space token issued in the future (iat)"
    for claim, why in (("nbf", nbf), ("iat", iat)):
        assert gv(gclaims(**{claim: NS_S}), skew=2000) == gok()  # a skew moves the window outward, never inward
        assert gv(gclaims(**{claim: NS_S + 2}), skew=2000) == gok()  # exactly at the edge
        assert gv(gclaims(**{claim: NS_S + 3}), skew=2000) == gf(why)
        assert gv(gclaims(**{claim: NS_S + 5}), skew=1000) == gf(why)  # a skew is milliseconds, rounded up to seconds
        assert gv(gclaims(**{claim: NS_S + 2}), skew=1001) == gok()
        assert gv(gclaims(**{claim: NS_S + 3}), skew=1001) == gf(why)
    assert gv(gclaims(exp=NS_S - 2), skew=1001) == gok()
    assert gv(gclaims(exp=NS_S - 2), skew=1000) == gf("Confidential Space token expired")


def test_gcp_non_numeric_time_claims_are_absent(gv):
    assert gv(gclaims(iat="x", nbf="y")) == gok()
    assert gv(gclaims(exp="x")) == gf("token has no exp (cannot bound validity — fail closed)")


def test_gcp_submods_must_be_an_object(gv):
    why = gf("token carries no submods.confidential_space (not a Confidential Space token)")
    for sub in ("x", ["confidential_space"], 5):
        assert gv(gclaims(submods=sub)) == why


def test_gcp_swname_and_swversion(gv):
    assert gv(gclaims(swname=None)) == gf("unexpected swname 'undefined' (expected 'CONFIDENTIAL_SPACE')")
    assert gv(gclaims(swname="FOO")) == gf("unexpected swname 'FOO' (expected 'CONFIDENTIAL_SPACE')")
    assert gv(gclaims(swname="FOO"), policy={"expectedSwName": "BAR"}) == gf("unexpected swname 'FOO' (expected 'BAR')")
    allow = {"allowedSwVersions": ["1.2"]}
    assert gv(gclaims(swversion="1.2"), policy=allow) == gok()
    assert gv(gclaims(swversion=["0", "1.2"]), policy=allow) == gok()
    assert gv(gclaims(swversion="9"), policy=allow) == gf("swversion not in policy allowlist")
    # an empty string names no version, even if the allowlist lists the empty string
    assert gv(gclaims(swversion=""), policy={"allowedSwVersions": [""]}) == gf("swversion not in policy allowlist")


def test_gcp_unexpected_errors_fail_closed():
    def boom(_d):
        raise ValueError("boom")

    opts = dict(GCP_OPTS, resolve_evidence=boom)
    assert G.GcpConfidentialSpaceVerifier(opts).verify("DOC", EXP, NOW) == gf("gcp-confidential-space verification error (fail closed): boom")
