"""0.5 mutation-kill tests of the attest group over keys, certificates, CRLs and signed documents minted here: the strict chain
profile (x509-strict strictChainError, on every NVIDIA / MAA / GCP chain), the NVIDIA device chain, the signed RIM document
(every XMLDSig gate and golden-measurement rule), CRL revocation, the MAA x5c chain and token verifier, and the GCP JWK / x5c
key resolution. Expected strings and limits are the TypeScript reference's (packages/pca/src/attest-nvidia-spdm.ts,
attest-nvidia-rim.ts, attest-azure-maa.ts, attest-gcp-confidential-space.ts, x509-strict.ts). Where a reason embeds a
library's own error text in the reference (OpenSSL / xmldom), the SDK's own diagnostics are pinned exactly; that wording is not a
cross-language contract."""
import datetime
import functools
import hashlib
import json

import pytest

pytest.importorskip("cryptography")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from atlas_pca import attest_common as C
from atlas_pca import attest_der as D
from atlas_pca import attest_gcp as G
from atlas_pca import attest_nvidia as N
from atlas_pca.attest_azure import AzureMaaVerifier, verify_x5c_chain
from atlas_pca.attest_cert import Cert
from atlas_pca.attest_xml import canonicalize, parse_xml
from test_attest_units import EXP, NA, NB, NOW, b64, b64u, ms

NB_MS, NA_MS = ms(2025, 1, 1), ms(2035, 1, 1)
DER = serialization.Encoding.DER
CRIT = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"\x05\x00")
EKU = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
ASN1 = "error:0688010A:asn1 encoding routines::nested asn1 error (%s)"  # the SDK's own diagnostics, not a cross-language contract
NO_START = "error:0480006C:PEM routines::no start line"  # ditto
CA_LEAF = "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)"


def nm(cn):
    if isinstance(cn, str):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, cn[0]), x509.NameAttribute(NameOID.COMMON_NAME, cn[1])])


def ku(cert_sign):
    return x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=cert_sign, crl_sign=cert_sign, encipher_only=False, decipher_only=False)


def mk(cn, issuer, pub, signer, serial, ca, extra=(), h=None, nb=NB, na=NA, bc=True, usage=True, pathlen=None):
    b = x509.CertificateBuilder().subject_name(nm(cn)).issuer_name(nm(issuer)).public_key(pub).serial_number(serial).not_valid_before(nb).not_valid_after(na)
    if bc:
        b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=pathlen), critical=True)
    if ca and usage:
        b = b.add_extension(ku(True), critical=True)
    for ext, critical in extra:
        b = b.add_extension(ext, critical=critical)
    return b.sign(signer, h or hashes.SHA384()).public_bytes(DER)


def pem(der):
    return "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % b64(der)


def spki(key):
    return hashlib.sha256(key.public_bytes(DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


class World:
    pass


@functools.lru_cache(maxsize=1)
def W():
    w = World()
    gen = lambda curve: ec.generate_private_key(curve())  # noqa: E731
    w.root, w.inter, w.leaf, w.other = gen(ec.SECP384R1), gen(ec.SECP384R1), gen(ec.SECP384R1), gen(ec.SECP384R1)
    w.root_der = mk("NV Root", "NV Root", w.root.public_key(), w.root, 0x1003, True)
    w.inter_der = mk("NV Inter", "NV Root", w.inter.public_key(), w.root, 0x1002, True)
    w.leaf_der = mk(("Acme", "NV Leaf"), "NV Inter", w.leaf.public_key(), w.inter, 0x1001, False)
    w.direct_leaf_der = mk("NV Leaf", "NV Root", w.leaf.public_key(), w.root, 0x1004, False)
    w.pin = spki(w.root.public_key())
    # the P-256 family of the token vendors
    s = hashes.SHA256()
    w.aroot, w.ainter, w.aleaf, w.aother = gen(ec.SECP256R1), gen(ec.SECP256R1), gen(ec.SECP256R1), gen(ec.SECP256R1)
    w.aroot_der = mk("Root", "Root", w.aroot.public_key(), w.aroot, 1, True, h=s)
    w.ainter_der = mk("Inter", "Root", w.ainter.public_key(), w.aroot, 2, True, h=s)
    w.aleaf_der = mk("Leaf", "Inter", w.aleaf.public_key(), w.ainter, 3, False, h=s)
    w.adirect_der = mk("Leaf", "Root", w.aleaf.public_key(), w.aroot, 4, False, h=s)
    w.aother_der = mk("Other", "Other", w.aother.public_key(), w.aother, 5, True, h=s)
    w.apin = spki(w.aroot.public_key())
    w.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return w


# ------------------------------------------------------------------------------------------------ strict_chain_error


def test_strict_chain_error_table():
    w = W()
    s = hashes.SHA256()
    k = w.aleaf
    root = w.aroot
    r = lambda *a, **kw: mk("R", "R", root.public_key(), root, 9, True, h=s, *a, **kw)  # noqa: E731
    leaf = w.adirect_der
    assert D.strict_chain_error([leaf, w.aroot_der]) is None
    assert D.strict_chain_error([leaf]) is None
    assert D.strict_chain_error([w.aroot_der]) is None  # one certificate has no leaf / issuer relationship
    assert D.strict_chain_error([]) is None
    assert D.strict_chain_error([w.aroot_der, w.aroot_der]) == CA_LEAF
    assert D.strict_chain_error([leaf, leaf]) == "issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)"
    no_bc = mk("R", "R", root.public_key(), root, 9, True, h=s, bc=False, usage=False)
    assert D.strict_chain_error([leaf, no_bc]) == "issuer certificate at depth 1 has no BasicConstraints (not a CA)"
    no_sign = mk("R", "R", root.public_key(), root, 9, True, h=s, usage=False, extra=[(ku(False), True)])
    assert D.strict_chain_error([leaf, no_sign]) == "issuer certificate at depth 1 keyUsage lacks keyCertSign"
    len0 = mk("R", "R", root.public_key(), root, 9, True, h=s, pathlen=0)
    assert D.strict_chain_error([leaf, len0]) is None
    assert D.strict_chain_error([leaf, w.ainter_der, len0]) == "issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)"
    crit_leaf = mk("L", "R", k.public_key(), root, 7, False, h=s, extra=[(CRIT, True)])
    assert D.strict_chain_error([crit_leaf, w.aroot_der]) == "certificate at depth 0 has an unrecognised critical extension 1.2.3.4"
    assert D.strict_chain_error([crit_leaf]) == "certificate at depth 0 has an unrecognised critical extension 1.2.3.4"
    assert D.strict_chain_error([leaf, r(extra=[(CRIT, True)])]) == "certificate at depth 1 has an unrecognised critical extension 1.2.3.4"
    assert D.strict_chain_error([mk("L", "R", k.public_key(), root, 7, False, h=s, extra=[(CRIT, False)]), r()]) is None
    # extendedKeyUsage is the one critical extension the chain profile allows beyond the role extensions
    eku_leaf = mk("L", "R", k.public_key(), root, 7, False, h=s, extra=[(EKU, True)])
    assert D.strict_chain_error([eku_leaf, r()]) is None
    assert D.unrecognised_critical_extension(eku_leaf) == "2.5.29.37"
    assert D.strict_chain_error([b"garbage"]) == "certificate extension parse failed: DER: element overruns its parent"


def test_strict_chain_error_extension_table_failure_fails_closed(monkeypatch):
    def boom(_der, _ok):
        raise D.DerError("x")

    monkeypatch.setattr(D, "unrecognised_critical_extension", boom)
    assert D.strict_chain_error([W().adirect_der]) == "certificate extension parse failed: x"


# ------------------------------------------------------------------------------------------------ NVIDIA device chain


def chain_pem(*ders):
    return "\n".join(pem(d) for d in ders)


def test_device_chain_accepts_and_returns_the_parsed_chain():
    w = W()
    for pin in (w.pin, w.pin.upper()):
        r = N.verify_nvidia_device_chain(chain_pem(w.leaf_der, w.inter_der, w.root_der), ["00" * 32, pin], NOW)
        assert r["ok"] is True and r["leaf"].raw == w.leaf_der and [c.raw for c in r["chain"]] == [w.leaf_der, w.inter_der, w.root_der]
    assert N.verify_nvidia_device_chain(pem(w.root_der), [w.pin], NB_MS)["ok"] is True
    assert N.verify_nvidia_device_chain(pem(w.root_der), [w.pin], NA_MS)["ok"] is True


def test_device_chain_refusals_in_reference_order():
    w = W()
    f = lambda reason: {"ok": False, "reason": reason}  # noqa: E731
    v = lambda ders, pins=None, now=NOW: N.verify_nvidia_device_chain(chain_pem(*ders), pins or [w.pin], now)  # noqa: E731
    assert N.verify_nvidia_device_chain("", [w.pin], NOW) == f("device chain unparseable: parsePemChain: no certificates found")
    assert N.verify_nvidia_device_chain(chain_pem(*[w.root_der] * 6), [w.pin], NOW) == f("device chain unparseable: parsePemChain: chain longer than 5")
    assert N.verify_nvidia_device_chain(chain_pem(*[w.root_der] * 5), [w.pin], NOW) == f("device chain profile: " + CA_LEAF)
    assert v([w.root_der], now=NB_MS - 1) == f("device chain cert #0 is outside its validity window")
    assert v([w.root_der], now=NA_MS + 1) == f("device chain cert #0 is outside its validity window")
    expired = mk("I", "NV Root", w.inter.public_key(), w.root, 8, True, na=datetime.datetime(2026, 1, 1))
    assert v([w.direct_leaf_der, expired]) == f("device chain cert #1 is outside its validity window")
    assert v([w.adirect_der]) == f("device chain cert #0 is not an ECDSA P-384 key")
    assert v([w.direct_leaf_der, w.aroot_der]) == f("device chain cert #1 is not an ECDSA P-384 key")
    assert v([w.leaf_der, w.direct_leaf_der]) == f("device chain cert #1 issues a certificate but is not a CA")
    assert v([w.leaf_der, w.root_der]) == f("device chain link #0 signature does not verify under its issuer")
    assert v([w.leaf_der, w.inter_der, w.inter_der]) == f("device chain link #1 signature does not verify under its issuer")
    assert v([w.direct_leaf_der]) == f("device chain root is not a self-signed CA")
    assert v([w.inter_der]) == f("device chain root is not a self-signed CA")
    assert v([w.root_der], ["00" * 32]) == f("chain root is not a pinned NVIDIA root")


def test_device_chain_runs_the_strict_profile():
    w = W()
    f = lambda reason: {"ok": False, "reason": "device chain profile: " + reason}  # noqa: E731
    v = lambda *ders: N.verify_nvidia_device_chain(chain_pem(*ders), [w.pin], NOW)  # noqa: E731
    ca_leaf = mk("L", "NV Root", w.leaf.public_key(), w.root, 8, True)
    assert v(ca_leaf, w.root_der) == f(CA_LEAF)
    crit_leaf = mk("L", "NV Root", w.leaf.public_key(), w.root, 8, False, extra=[(CRIT, True)])
    assert v(crit_leaf, w.root_der) == f("certificate at depth 0 has an unrecognised critical extension 1.2.3.4")
    # before the pin: an unpinned chain with a bad profile reports the profile
    assert N.verify_nvidia_device_chain(chain_pem(crit_leaf, w.root_der), ["00" * 32], NOW) == f("certificate at depth 0 has an unrecognised critical extension 1.2.3.4")
    crit_root = mk("NV Root", "NV Root", w.root.public_key(), w.root, 8, True, extra=[(CRIT, True)])
    assert v(w.direct_leaf_der, crit_root) == f("certificate at depth 1 has an unrecognised critical extension 1.2.3.4")
    eku_leaf = mk("L", "NV Root", w.leaf.public_key(), w.root, 8, False, extra=[(EKU, True)])
    assert v(eku_leaf, w.root_der)["ok"] is True


# ------------------------------------------------------------------------------------------------ the signed RIM document


NS = "http://www.w3.org/2000/09/xmldsig#"
DS = 'xmlns:ds="%s"' % NS
A_C14N = "http://www.w3.org/2006/12/xml-c14n11"
A_ENV = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
A_EC = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
A_SHA = "http://www.w3.org/2001/04/xmldsig-more#sha384"
CM = '<ds:CanonicalizationMethod Algorithm="%s"/>' % A_C14N
SM = '<ds:SignatureMethod Algorithm="%s"/>' % A_EC
DM = '<ds:DigestMethod Algorithm="%s"/>' % A_SHA
DV = "<ds:DigestValue>@D@</ds:DigestValue>"
SV = "<ds:SignatureValue>@S@</ds:SignatureValue>"
META = '<Meta product="GH100" colloquialVersion="535.104.05"/>'


def T(alg):
    return '<ds:Transform Algorithm="%s"/>' % alg


TS_OK = "<ds:Transforms>%s%s</ds:Transforms>" % (T(A_ENV), T(A_C14N))


def res(attrs):
    return '<Resource type="Measurement" %s/>' % attrs


ONE = res('index="1" alternatives="1" size="1" active="true" Hash0="ab"')


def ref(attr='URI=""', transforms=TS_OK, dm=DM, dv=DV):
    return "<ds:Reference %s>%s%s%s</ds:Reference>" % (attr, transforms, dm, dv)


def keyinfo(*ders):
    return "<ds:KeyInfo><ds:X509Data>%s</ds:X509Data></ds:KeyInfo>" % "".join("<ds:X509Certificate>%s</ds:X509Certificate>" % b64(d) for d in ders)


def rim_text(resources=ONE, cm=CM, sm=SM, reference=None, sv=SV, ki=None, meta=META, payload=None):
    w = W()
    pl = "<Payload>%s</Payload>" % resources if payload is None else payload
    ki = keyinfo(w.direct_leaf_der, w.root_der) if ki is None else ki
    si = "<ds:SignedInfo>%s%s%s</ds:SignedInfo>" % (cm, sm, ref() if reference is None else reference)
    return '<SoftwareIdentity xmlns="urn:swid" tagId="T1">%s%s\n<ds:Signature %s>%s%s%s</ds:Signature></SoftwareIdentity>' % (meta, pl, DS, si, sv, ki)


def signed(text=None, digest=None, wrap=lambda s: s, key=None, sig=None, **kw):
    """Fill the @D@ / @S@ placeholders: the digest of the document without its Signature, then an ECDSA P-384 signature of the
    canonical SignedInfo."""
    t = rim_text(**kw) if text is None else text
    doc = parse_xml(t.replace("@D@", "AA").replace("@S@", "AA"))
    s = doc.root.element_children(NS, "Signature")[0]
    d = digest if digest is not None else b64(hashlib.sha384(canonicalize(doc.root, skip=s).encode()).digest())
    t = t.replace("@D@", wrap(d))
    si = parse_xml(t.replace("@S@", "AA")).root.element_children(NS, "Signature")[0].element_children(NS, "SignedInfo")[0]
    if sig is None:
        r, ss = utils.decode_dss_signature((key or W().leaf).sign(canonicalize(si).encode(), ec.ECDSA(hashes.SHA384())))
        sig = r.to_bytes(48, "big") + ss.to_bytes(48, "big")
    return t.replace("@S@", wrap(b64(sig)))


def rim(xml, pins=None, now=NOW):
    return N.verify_nvidia_rim(xml, [W().pin] if pins is None else pins, now)


def rf(reason):
    return {"ok": False, "reason": "RIM: " + reason}


def test_rim_document_gates():
    for x in (None, 5, b"<a/>", "", "<a/>" + " " * 3_999_997):
        assert rim(x) == rf("empty or oversized document")
    assert rim("<a/>" + " " * 3_999_996) == rf("root element is not SoftwareIdentity")  # exactly 4,000,000 characters
    for pins in ((), [], ("x",), "abc", {"a": 1}):
        assert N.verify_nvidia_rim("<a/>", pins, NOW) == rf("no pinned RIM root configured")
    assert N.verify_nvidia_rim("", [], NOW) == rf("empty or oversized document")
    assert rim("<SoftwareIdentity><!--x--></SoftwareIdentity>") == rf("XML comments are not permitted")
    assert rim('<SoftwareIdentity><a xml:lang="en"/><!--c--></SoftwareIdentity>') == rf("xml:* attribute 'xml:lang' is not permitted (C14N 1.1 profile)")
    assert rim("<SoftwareIdentity>") == rf("verification error (fail closed): unclosed element <SoftwareIdentity>")  # the SDK's own XML diagnostics
    assert rim("<Other/>") == rf("root element is not SoftwareIdentity")


def test_rim_signature_placement():
    one = rf("expected exactly one Signature element")
    direct = rf("the Signature must be a direct child of the root")
    sig = "<ds:Signature %s/>" % DS
    other = '<o:Signature xmlns:o="u"/>'
    assert rim("<SoftwareIdentity/>") == one
    assert rim('<x:SoftwareIdentity xmlns:x="u"/>') == one  # the root is matched by its local name
    assert rim("<SoftwareIdentity>%s</SoftwareIdentity>" % other) == one
    assert rim("<SoftwareIdentity>%s%s</SoftwareIdentity>" % (sig, sig)) == one
    assert rim("<SoftwareIdentity>%s<x>%s</x></SoftwareIdentity>" % (sig, sig)) == one
    assert rim("<SoftwareIdentity><x>%s</x></SoftwareIdentity>" % sig) == direct
    assert rim("<SoftwareIdentity>%s<x>%s</x></SoftwareIdentity>" % (other, sig)) == direct  # a foreign namespace is not it
    assert rim("<SoftwareIdentity>%s%s</SoftwareIdentity>" % (other, sig)) == rf("expected exactly one SignedInfo")
    si = "<ds:SignedInfo/>"
    assert rim("<SoftwareIdentity><ds:Signature %s>%s%s</ds:Signature></SoftwareIdentity>" % (DS, si, si)) == rf("expected exactly one SignedInfo")
    assert rim('<SoftwareIdentity><ds:Signature %s><o:SignedInfo xmlns:o="u"/></ds:Signature></SoftwareIdentity>' % DS) == rf("expected exactly one SignedInfo")
    assert rim("<SoftwareIdentity><ds:Signature %s>%s</ds:Signature></SoftwareIdentity>" % (DS, si)) == rf("CanonicalizationMethod must be C14N 1.1")


def test_rim_algorithm_gates():
    c14n, sig_m, refs = rf("CanonicalizationMethod must be C14N 1.1"), rf("SignatureMethod must be ECDSA-SHA384"), rf("expected exactly one Reference")
    uri, tr, dg = rf('Reference URI must be "" (the whole document)'), rf("transforms must be exactly [enveloped-signature, C14N 1.1]"), rf("DigestMethod must be SHA-384")
    wrong = '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
    assert rim(rim_text(cm="")) == c14n
    assert rim(rim_text(cm=wrong)) == c14n
    assert rim(rim_text(cm=wrong + CM)) == c14n  # the first one counts
    assert rim(rim_text(cm='<o:CanonicalizationMethod xmlns:o="u" Algorithm="%s"/>' % A_C14N)) == c14n
    assert rim(rim_text(cm=CM + wrong, sm="")) == sig_m
    assert rim(rim_text(sm="")) == sig_m
    assert rim(rim_text(sm='<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>')) == sig_m
    assert rim(rim_text(reference="")) == refs
    assert rim(rim_text(reference=ref() + ref())) == refs
    assert rim(rim_text(reference=ref('URI="#x"'))) == uri
    assert rim(rim_text(reference=ref("", transforms=""))) == tr  # an absent URI reads as the empty string
    for bad in ("<ds:Transforms/>", "<ds:Transforms>%s</ds:Transforms>" % T(A_ENV), "<ds:Transforms>%s%s</ds:Transforms>" % (T(A_C14N), T(A_ENV)),
                "<ds:Transforms>%s%s</ds:Transforms>" % (T(A_ENV), T(A_ENV)), "<ds:Transforms>%s%s</ds:Transforms>" % (T(A_C14N), T(A_C14N)),
                "<ds:Transforms>%s%s%s</ds:Transforms>" % (T(A_ENV), T(A_C14N), T(A_C14N)),
                '<ds:Transforms>%s<o:Transform xmlns:o="u" Algorithm="%s"/></ds:Transforms>' % (T(A_ENV), A_C14N)):
        assert rim(rim_text(reference=ref(transforms=bad))) == tr
    assert rim(rim_text(reference=ref(transforms=T(A_ENV) + T(A_C14N), dm=""))) == dg  # Transform directly under Reference is accepted
    assert rim(rim_text(reference=ref(dm=""))) == dg
    assert rim(rim_text(reference=ref(dm='<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'))) == dg


def test_rim_value_and_keyinfo_gates():
    w = W()
    missing, none = rf("missing DigestValue / SignatureValue"), rf("no signer certificates in KeyInfo")
    assert rim(rim_text(reference=ref(dv=""))) == missing
    assert rim(rim_text(reference=ref(dv="<ds:DigestValue> \n </ds:DigestValue>"))) == missing
    assert rim(rim_text(sv="")) == missing
    assert rim(rim_text(sv="<ds:SignatureValue>\t</ds:SignatureValue>")) == missing
    for ki in ("<ds:Other/>", "<ds:KeyInfo/>", "<ds:KeyInfo><ds:X509Data/></ds:KeyInfo>"):
        assert rim(rim_text(ki=ki)) == none
    x = rim_text()
    assert rim(x, ["00" * 32]) == {"ok": False, "reason": "RIM signer chain: chain root is not a pinned NVIDIA root"}
    assert rim(rim_text(ki=keyinfo(w.adirect_der))) == {"ok": False, "reason": "RIM signer chain: device chain cert #0 is not an ECDSA P-384 key"}
    assert rim(rim_text(ki=keyinfo(b"junk"))) == {"ok": False, "reason": "RIM signer chain: device chain unparseable: " + ASN1 % "truncated"}
    ca_leaf = mk("L", "NV Root", w.leaf.public_key(), w.root, 8, True)
    assert rim(rim_text(ki=keyinfo(ca_leaf, w.root_der))) == {"ok": False, "reason": "RIM signer chain: device chain profile: " + CA_LEAF}
    assert rim(rim_text(), now=NA_MS + 1) == {"ok": False, "reason": "RIM signer chain: device chain cert #0 is outside its validity window"}
    # a chain failure that raises inside the pin comparison is still a refusal
    err = rim(rim_text(), [5])
    assert err["ok"] is False and err["reason"].startswith("RIM: verification error (fail closed): ")


def test_rim_signature_and_digest():
    w = W()
    n = rf("SignatureValue is not a 96-byte P-384 signature")
    assert rim(signed(sig=bytes(95))) == n
    assert rim(signed(sig=bytes(97))) == n
    no = rf("SignedInfo signature does not verify under the signer certificate")
    assert rim(signed(sig=bytes(96))) == no
    assert rim(signed(key=w.other)) == no
    assert rim(signed(digest="AAAA")) == rf("document digest does not match the signed DigestValue")
    assert rim(signed().replace('Hash0="ab"', 'Hash0="ac"')) == rf("document digest does not match the signed DigestValue")
    assert rim(signed().replace('tagId="T1"', 'tagId="T2"')) == rf("document digest does not match the signed DigestValue")
    assert rim(signed(meta="")) == rf("missing Meta / Payload")
    assert rim(signed(payload="")) == rf("missing Meta / Payload")


def good(r):
    assert set(r) == {"ok", "rim"} and r["ok"] is True
    return r["rim"]


def test_rim_accepts_and_reads_the_golden_values():
    w = W()
    rs = "".join([
        res('index="0" alternatives="2" size="2" active="TRUE" Hash1="BBBB" Hash0="aaaa"'),
        res('index="0x10" alternatives="1" size="1" active="false" Hash0="0F"'),
        res('index=" 3 " alternatives="3" size="1" Hash10="0a" Hash2="02" Hash1="01" HashX="zz" Hash="zz"'),
        '<Resource type="Other" index="x"/>',
        '<Thing type="Measurement" index="x"/>',
    ])
    # whitespace inside the base64 values is not significant
    spaced = lambda s: " " + s[:4] + "\n\t" + s[4:] + " "  # noqa: E731
    wrapped = "<ds:KeyInfo><ds:X509Data>%s</ds:X509Data></ds:KeyInfo>" % "".join("<ds:X509Certificate>\n%s\n</ds:X509Certificate>" % spaced(b64(d)) for d in (w.direct_leaf_der, w.root_der))
    got = good(rim(signed(resources=rs, wrap=spaced, ki=wrapped)))
    assert (got["tagId"], got["product"], got["version"], got["signerSubject"]) == ("T1", "GH100", "535.104.05", "CN=NV Leaf")
    assert set(got) == {"tagId", "product", "version", "golden", "signerSubject"}
    assert good(rim(signed(ki=keyinfo(w.leaf_der, w.inter_der, w.root_der))))["signerSubject"] == "O=Acme, CN=NV Leaf"
    assert got["golden"] == {
        0: {"index": 0, "active": True, "alternatives": 2, "size": 2, "hashes": ["aaaa", "bbbb"]},
        16: {"index": 16, "active": False, "alternatives": 1, "size": 1, "hashes": ["0f"]},
        3: {"index": 3, "active": False, "alternatives": 3, "size": 1, "hashes": ["01", "02", "0a"]},
    }
    # a chain of the (self-signed, pinned) root alone signs; a missing index reads as 0
    one = good(rim(signed(key=w.root, ki=keyinfo(w.root_der), resources=res('alternatives="1" size="1" Hash0="ab"'))))
    assert one["signerSubject"] == "CN=NV Root"
    assert one["golden"] == {0: {"index": 0, "active": False, "alternatives": 1, "size": 1, "hashes": ["ab"]}}
    # an absent Meta attribute reads as the empty string
    bare = good(rim(signed(meta="<Meta/>")))
    assert (bare["product"], bare["version"]) == ("", "")


@pytest.mark.parametrize("attrs", [
    'index="-1" alternatives="1" size="1"', 'index="1.5" alternatives="1" size="1"', 'index="abc" alternatives="1" size="1"', 'index="Infinity" alternatives="1" size="1"',
    'index="1" alternatives="0" size="1"', 'index="1" alternatives="1.5" size="1"', 'index="1" alternatives="x" size="1"', 'index="1" alternatives="-1" size="1"', 'index="1" size="1"',
    'index="1" alternatives="1" size="0"', 'index="1" alternatives="1" size="1.5"', 'index="1" alternatives="1" size="x"', 'index="1" alternatives="1"',
])
def test_rim_malformed_measurement(attrs):
    assert rim(signed(resources=res(attrs + ' Hash0="ab"'))) == rf("malformed Measurement resource")


@pytest.mark.parametrize("attrs", [
    'alternatives="2" size="1" Hash0="ab"', 'alternatives="1" size="1" Hash0="ab" Hash1="cd"', 'alternatives="1" size="1"',
    'alternatives="1" size="2" Hash0="ab"', 'alternatives="1" size="1" Hash0="abcd"', 'alternatives="1" size="1" Hash0="zz"', 'alternatives="1" size="1" Hash0=""',
    'alternatives="2" size="1" Hash0="ab" Hash1="zz"', 'alternatives="2" size="1" Hash0="ab" Hash1="abcd"',
])
def test_rim_inconsistent_hash_list(attrs):
    assert rim(signed(resources=res('index="4" ' + attrs))) == rf("Measurement 4 hash list is inconsistent with alternatives/size")


def test_rim_duplicates_and_no_measurements():
    a = 'alternatives="1" size="1" Hash0="ab"'
    assert rim(signed(resources=res('index="5" ' + a) + res('index="6" ' + a) + res('index="0x5" ' + a))) == rf("duplicate Measurement index 5")
    assert rim(signed(resources="")) == rf("no measurements")
    assert rim(signed(resources='<Resource type="Other"/><Thing/>')) == rf("no measurements")
    assert rim(signed(resources='<Resource type="measurement" index="1"/>')) == rf("no measurements")


# ------------------------------------------------------------------------------------------------ CRL revocation


def crl(signer, revoked=(), last=datetime.datetime(2026, 1, 1), nxt=datetime.datetime(2027, 1, 1)):
    b = x509.CertificateRevocationListBuilder().issuer_name(nm("I")).last_update(last).next_update(nxt)
    for s in revoked:
        b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(s).revocation_date(datetime.datetime(2025, 6, 1)).build())
    return b.sign(signer, hashes.SHA256()).public_bytes(DER)


def chain3():
    w = W()
    return [Cert(w.leaf_der), Cert(w.inter_der), Cert(w.root_der)]


def rev(crls, require=None, chain=None):
    return N.check_nvidia_chain_revocation(chain3() if chain is None else chain, crls, NOW, require)


def test_revocation_accepts_with_the_exact_count():
    w = W()
    assert rev([crl(w.inter)]) == {"ok": True, "verifiedCrls": 1}
    assert rev([crl(w.inter), crl(w.root)]) == {"ok": True, "verifiedCrls": 2}
    assert N.check_nvidia_chain_revocation(chain3(), [crl(w.inter)], NOW) == {"ok": True, "verifiedCrls": 1}
    assert rev([crl(w.inter)], []) == {"ok": True, "verifiedCrls": 1}


def test_revocation_only_the_issuer_of_a_certificate_can_revoke_it():
    w = W()
    assert rev([]) == {"ok": False, "reason": "no CRLs supplied"}
    assert rev([crl(w.inter, [0x1001])]) == {"ok": False, "reason": "chain certificate 'O=Acme, CN=NV Leaf' is revoked"}
    assert rev([crl(w.root, [0x1002])]) == {"ok": False, "reason": "chain certificate 'CN=NV Inter' is revoked"}
    assert rev([crl(w.inter), crl(w.root, [0x1002])]) == {"ok": False, "reason": "chain certificate 'CN=NV Inter' is revoked"}
    assert rev([crl(w.root, [0x1001])])["ok"] is True  # the root did not issue the leaf
    assert rev([crl(w.inter, [0x1002])])["ok"] is True  # the intermediate did not issue itself
    assert rev([crl(w.root, [0x1003])])["ok"] is True  # the self-signed root is never checked
    assert rev([crl(w.leaf, [0x1001])])["ok"] is True  # the leaf issued nothing
    assert rev([crl(w.inter, [0x9999])])["ok"] is True


def test_revocation_keeps_the_most_informative_failure():
    w = W()
    stale = dict(last=datetime.datetime(2025, 1, 1), nxt=datetime.datetime(2026, 1, 1))
    future = dict(last=datetime.datetime(2027, 1, 1), nxt=datetime.datetime(2028, 1, 1))
    sig = "CRL signature does not verify under the issuer"
    r = lambda ci, why: {"ok": False, "reason": "CRL #%d rejected: %s" % (ci, why)}  # noqa: E731
    assert rev([crl(w.other)]) == r(0, sig)
    assert rev([crl(w.inter), crl(w.other)]) == r(1, sig)
    assert rev([crl(w.leaf, **stale)]) == r(0, "CRL is stale (nextUpdate passed)")  # first in the chain, later wrong keys do not overwrite
    assert rev([crl(w.inter, **stale)]) == r(0, "CRL is stale (nextUpdate passed)")  # after a wrong key, before a wrong key
    assert rev([crl(w.root, **future)]) == r(0, "CRL thisUpdate is in the future")  # last in the chain
    assert rev([crl(w.other)], chain=[]) == r(0, "no chain certificate verifies it")


def test_revocation_required_issuers():
    w = W()
    assert rev([crl(w.inter)], ["NV Inter"]) == {"ok": True, "verifiedCrls": 1}
    assert rev([crl(w.inter)], ["nter"]) == {"ok": True, "verifiedCrls": 1}
    assert rev([crl(w.inter)], ["NV Root"]) == {"ok": False, "reason": "no verified CRL issued by a certificate matching 'NV Root'"}
    assert rev([crl(w.inter)], ["NV Inter", "NV Root"]) == {"ok": False, "reason": "no verified CRL issued by a certificate matching 'NV Root'"}
    assert rev([crl(w.inter), crl(w.root)], ["NV Root", "NV Inter"]) == {"ok": True, "verifiedCrls": 2}


# ------------------------------------------------------------------------------------------------ the MAA x5c chain


def xf(reason):
    return {"ok": False, "reason": reason}


def x5(*ders):
    return [b64(d) for d in ders]


def test_x5c_structure_and_validity():
    w = W()
    pinned = {"rootSpkiSha256": [spki(w.aleaf.public_key())]}
    for bad in (None, "abc", [], {}):
        assert verify_x5c_chain(bad, pinned, NOW) == xf("empty x5c certificate chain")
    assert verify_x5c_chain([""], pinned, NOW) == xf("empty x5c entry at index 0")
    assert verify_x5c_chain(x5(w.adirect_der) + [5], pinned, NOW) == xf("empty x5c entry at index 1")
    assert verify_x5c_chain(x5(w.adirect_der) + ["!!!!"], pinned, NOW) == xf("malformed x5c certificate at index 1: " + ASN1 % "truncated")
    assert verify_x5c_chain(["AAAA"], pinned, NOW) == xf("malformed x5c certificate at index 0: " + ASN1 % "not a SEQUENCE")
    leaf = x5(w.adirect_der)
    out = xf("x5c certificate at index 0 is outside its validity window")
    assert verify_x5c_chain(leaf, pinned, NB_MS)["ok"] is True
    assert verify_x5c_chain(leaf, pinned, NA_MS)["ok"] is True
    assert verify_x5c_chain(leaf, pinned, NB_MS - 1) == out
    assert verify_x5c_chain(leaf, pinned, NA_MS + 1) == out
    assert verify_x5c_chain(leaf, pinned, NB_MS - 1000, 1000)["ok"] is True
    assert verify_x5c_chain(leaf, pinned, NA_MS + 1000, 1000)["ok"] is True
    assert verify_x5c_chain(leaf, pinned, NB_MS - 1000, 999) == out
    assert verify_x5c_chain(leaf, pinned, NA_MS + 1000, 999) == out
    for skew in (-5000, float("nan"), float("inf"), "1000", None):  # a negative or non-finite skew is no skew
        assert verify_x5c_chain(leaf, pinned, NB_MS - 1, skew) == out
    expired = mk("I", "Root", w.ainter.public_key(), w.aroot, 8, True, h=hashes.SHA256(), na=datetime.datetime(2026, 1, 1))
    assert verify_x5c_chain(x5(w.adirect_der, expired), pinned, NOW) == xf("x5c certificate at index 1 is outside its validity window")
    assert verify_x5c_chain(leaf, {}, NB_MS - 1) == out  # validity comes before the anchors


def test_x5c_no_anchor_configured():
    leaf = x5(W().adirect_der)
    no = xf("no MAA trust anchor configured (fail closed)")
    for anchors in ({}, {"rootSpkiSha256": []}, {"rootSpkiSha256": ["", 5]}, {"rootCertsPem": []}, {"rootSpkiSha256": None, "rootCertsPem": None}):
        assert verify_x5c_chain(leaf, anchors, NOW) == no


def test_x5c_in_chain_anchor():
    w = W()
    def v(ders, *pins):
        return verify_x5c_chain(x5(*ders), {"rootSpkiSha256": list(pins)}, NOW)
    def ok(r):
        assert set(r) == {"ok", "leaf", "leafSpkiSha256"} and r["ok"] is True and r["leafSpkiSha256"] == spki(w.aleaf.public_key())
        return r["leaf"].raw
    assert ok(v([w.adirect_der], spki(w.aleaf.public_key()))) == w.adirect_der
    assert ok(v([w.adirect_der], spki(w.aleaf.public_key()).upper())) == w.adirect_der
    assert ok(v([w.aleaf_der, w.ainter_der, w.aroot_der], w.apin)) == w.aleaf_der
    assert ok(v([w.aleaf_der, w.ainter_der, w.aother_der], spki(w.ainter.public_key()))) == w.aleaf_der  # nothing above the anchor is examined
    crit_top = mk("Other", "Other", w.aother.public_key(), w.aother, 6, True, h=hashes.SHA256(), extra=[(CRIT, True)])
    assert ok(v([w.aleaf_der, w.ainter_der, crit_top], spki(w.ainter.public_key()))) == w.aleaf_der
    assert ok(v([w.adirect_der, w.aother_der, w.aroot_der], spki(w.aleaf.public_key()), w.apin)) == w.adirect_der  # the lowest match is the anchor
    assert v([w.adirect_der, w.aother_der, w.aroot_der], w.apin) == xf("x5c link 0 is not signed by the certificate above it")
    assert v([w.aleaf_der, w.ainter_der, w.aother_der], spki(w.aother.public_key())) == xf("x5c link 1 is not signed by the certificate above it")
    assert v([w.adirect_der, w.aroot_der], "00" * 32) == xf("x5c chain does not anchor in a configured MAA trust root")
    p = "x5c chain profile: "
    ca_leaf = mk("L", "Root", w.aleaf.public_key(), w.aroot, 8, True, h=hashes.SHA256())
    assert v([ca_leaf, w.aroot_der], w.apin) == xf(p + CA_LEAF)
    crit_leaf = mk("L", "Root", w.aleaf.public_key(), w.aroot, 8, False, h=hashes.SHA256(), extra=[(CRIT, True)])
    assert v([crit_leaf, w.aroot_der], w.apin) == xf(p + "certificate at depth 0 has an unrecognised critical extension 1.2.3.4")
    assert v([crit_leaf], spki(w.aleaf.public_key())) == xf(p + "certificate at depth 0 has an unrecognised critical extension 1.2.3.4")
    non_ca = mk("Root", "Root", w.aroot.public_key(), w.aroot, 8, False, h=hashes.SHA256())
    assert v([w.adirect_der, non_ca], w.apin) == xf(p + "issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)")


def test_x5c_external_root():
    w = W()
    def v(ders, *roots):
        return verify_x5c_chain(x5(*ders), {"rootCertsPem": [pem(r) for r in roots]}, NOW)
    r = v([w.aleaf_der, w.ainter_der], w.aroot_der)
    assert r["ok"] is True and r["leaf"].raw == w.aleaf_der and r["leafSpkiSha256"] == spki(w.aleaf.public_key()) and set(r) == {"ok", "leaf", "leafSpkiSha256"}
    assert v([w.aleaf_der, w.ainter_der], w.aother_der, w.aroot_der)["ok"] is True
    # the configured root also anchors by fingerprint when the chain carries it
    assert v([w.aleaf_der, w.ainter_der, w.aroot_der], w.aroot_der)["ok"] is True
    assert v([w.adirect_der, w.ainter_der], w.aother_der) == xf("x5c link 0 is not signed by the certificate above it")
    assert v([w.aleaf_der, w.ainter_der, w.aother_der], w.aroot_der) == xf("x5c link 1 is not signed by the certificate above it")
    assert v([w.aleaf_der, w.ainter_der], w.aother_der) == xf("x5c chain does not anchor in a configured MAA trust root")
    p = "x5c chain profile: "
    crit_leaf = mk("L", "Inter", w.aleaf.public_key(), w.ainter, 8, False, h=hashes.SHA256(), extra=[(CRIT, True)])
    assert v([crit_leaf, w.ainter_der], w.aroot_der) == xf(p + "certificate at depth 0 has an unrecognised critical extension 1.2.3.4")
    crit_int = mk("Inter", "Root", w.ainter.public_key(), w.aroot, 8, True, h=hashes.SHA256(), extra=[(CRIT, True)])
    assert v([w.aleaf_der, crit_int], w.aroot_der) == xf(p + "certificate at depth 1 has an unrecognised critical extension 1.2.3.4")
    eku_leaf = mk("L", "Inter", w.aleaf.public_key(), w.ainter, 8, False, h=hashes.SHA256(), extra=[(EKU, True)])
    assert v([eku_leaf, w.ainter_der], w.aroot_der)["ok"] is True
    assert verify_x5c_chain(x5(w.adirect_der), {"rootCertsPem": ["junk"]}, NOW) == xf("x5c chain verification error (fail closed): " + NO_START)


# ------------------------------------------------------------------------------------------------ the MAA token verifier


ISS = "https://maa.example"
MRTD, SNP = "AA" * 48, "BB" * 48
NS_S = NOW // 1000
BIND = C.attestation_binding(EXP).hex()


def maa_token(claims, alg="ES256", key=None, x5c=None, header=None, sig=None):
    w = W()
    hd = {"alg": alg, "x5c": x5c if x5c is not None else x5(w.adirect_der, w.aroot_der)}
    hd.update(header or {})
    h, p = b64u(json.dumps(hd).encode()), b64u(json.dumps(claims).encode())
    if sig is None:
        r, s = utils.decode_dss_signature((key or w.aleaf).sign(("%s.%s" % (h, p)).encode(), ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return "%s.%s.%s" % (h, p, b64u(sig))


def tdx(**extra):
    d = {"x-ms-attestation-type": "tdxvm", "tdx_mrtd": MRTD, "tdx_report_data": BIND}
    d.update(extra)
    return {k: v for k, v in d.items() if v is not None}


def snp(**extra):
    d = {"x-ms-attestation-type": "sevsnpvm", "x-ms-sevsnpvm-launchmeasurement": SNP, "x-ms-sevsnpvm-reportdata": BIND}
    d.update(extra)
    return {k: v for k, v in d.items() if v is not None}


def base(**over):
    c = {"iss": ISS, "exp": NS_S + 3600, "x-ms-isolation-tee": tdx()}
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def run(claims=None, policy=None, now=NOW, expected=EXP, skew=None, token=None):
    opts = {"trustedIssuers": [ISS], "trustAnchors": {"rootSpkiSha256": [W().apin]}, "policy": policy or {"tdxMrtds": [MRTD]},
            "resolve_evidence": lambda _d: {"token": token if token is not None else maa_token(claims if claims is not None else base())}}
    if skew is not None:
        opts["clockSkewMs"] = skew
    return AzureMaaVerifier(opts).verify({}, expected, now)


def measured(rm):
    return {"model_id": "", "weights_digest": "", "weights_measured": False, "runtime_measurement": rm, "operator": ""}


def tdx_ok(host=None):
    return {"ok": True, "bound": True, "measured": measured(MRTD.lower()), "hostAsserted": host or {"attestation_type": "tdxvm"}}


def test_maa_signature_branch():
    w = W()
    assert run(token=maa_token(base(), sig=bytes(63))) == xf("ES256 signature is 63 bytes (expected 64: r‖s)")
    assert run(token=maa_token(base(), sig=bytes(64))) == xf("JWS ES256 signature does not verify under the MAA signing key")
    assert run(token=maa_token(base(), key=w.aother)) == xf("JWS ES256 signature does not verify under the MAA signing key")
    assert run(token=maa_token(base(), alg="RS256", sig=bytes(64))) == xf("RS256 token but signing key is EC (not RSA)")
    ca_leaf = mk("L", "Root", w.aleaf.public_key(), w.aroot, 8, True, h=hashes.SHA256())
    assert run(token=maa_token(base(), x5c=x5(ca_leaf, w.aroot_der))) == xf("MAA signing chain invalid: x5c chain profile: " + CA_LEAF)
    p384_leaf = mk("L", "Root", w.leaf.public_key(), w.aroot, 8, False, h=hashes.SHA256())
    assert run(token=maa_token(base(), x5c=x5(p384_leaf, w.aroot_der))) == xf("ES256 token but signing key is EC/P-384 (not EC P-256)")


def test_maa_issuer_and_time_window():
    bad_iss = "token iss '%s' is not a configured trusted MAA instance"
    assert run(base(iss="")) == xf(bad_iss % "")
    assert run(base(iss=5)) == xf(bad_iss % "undefined")
    assert run(base(iss="https://other")) == xf(bad_iss % "https://other")
    assert run(base(exp=None)) == xf("token has no exp (cannot bound validity — fail closed)")
    assert run(base(exp="9" * 12)) == xf("token has no exp (cannot bound validity — fail closed)")
    assert run(base(exp=True)) == xf("token has no exp (cannot bound validity — fail closed)")
    assert run(base(exp=NS_S)) == tdx_ok()
    assert run(base(exp=NS_S), now=NOW + 999) == tdx_ok()  # whole seconds
    assert run(base(exp=NS_S), now=NOW + 1000) == xf("MAA token expired")
    assert run(base(exp=NS_S - 1)) == xf("MAA token expired")
    assert run(base(exp=NS_S - 2), skew=1500) == tdx_ok()  # the skew rounds up to whole seconds
    assert run(base(exp=NS_S - 3), skew=1500) == xf("MAA token expired")
    assert run(base(exp=NS_S - 1), skew=-5000) == xf("MAA token expired")
    assert run(base(exp=NS_S - 1), skew="9000") == xf("MAA token expired")
    assert run(base(nbf=NS_S)) == tdx_ok()
    assert run(base(nbf=NS_S + 1)) == xf("MAA token not yet valid (nbf)")
    assert run(base(nbf=NS_S + 2), skew=1500) == tdx_ok()
    assert run(base(nbf=NS_S + 3), skew=1500) == xf("MAA token not yet valid (nbf)")
    assert run(base(nbf="later")) == tdx_ok()  # a non-number is no claim
    assert run(base(iat=NS_S)) == tdx_ok()
    assert run(base(iat=NS_S + 1)) == xf("MAA token issued in the future (iat)")
    assert run(base(iat=NS_S + 2), skew=1500) == tdx_ok()
    assert run(base(iat=NS_S + 3), skew=1500) == xf("MAA token issued in the future (iat)")
    assert run(base(iat="later")) == tdx_ok()


def test_maa_isolation_claims_and_binding():
    unexpected = "unexpected x-ms-attestation-type '%s' (expected sevsnpvm | tdxvm)"
    assert run(base(**{"x-ms-isolation-tee": {}})) == xf(unexpected % "undefined")
    assert run(base(**{"x-ms-isolation-tee": tdx(**{"x-ms-attestation-type": 5})})) == xf(unexpected % "undefined")
    assert run(base(**{"x-ms-isolation-tee": tdx(**{"x-ms-attestation-type": "sgx"})})) == xf(unexpected % "sgx")
    # the isolation record falls back to the top-level type; without a record the top level is the record
    inner = tdx(**{"x-ms-attestation-type": None})
    assert run(base(**{"x-ms-isolation-tee": inner, "x-ms-attestation-type": "tdxvm"})) == tdx_ok()
    for rec in (None, "scalar"):
        top = dict(tdx(), iss=ISS, exp=NS_S + 3600)
        if rec:
            top["x-ms-isolation-tee"] = rec
        assert run(top) == tdx_ok()
    assert run(base(), expected=None) == xf("no expected attestation binding supplied")
    assert run(base(), expected=dict(EXP, grantRef="")) == xf("binding not constructible: binding: grantRef required")
    assert run(base(**{"x-ms-isolation-tee": tdx(tdx_report_data=None)})) == xf("token carries no report-data claim to bind the PCA challenge")
    assert run(base(**{"x-ms-isolation-tee": tdx(tdx_report_data="")})) == xf("token carries no report-data claim to bind the PCA challenge")
    assert run(base(**{"x-ms-isolation-tee": tdx(tdx_report_data="!!!")})) == xf("report-data claim is not decodable (hex/base64)")
    assert run(base(**{"x-ms-isolation-tee": tdx(tdx_report_data="00" * 64)})) == xf("report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)")
    raw = C.attestation_binding(EXP)
    for form in ("0x" + BIND, "0X" + BIND.upper(), " %s " % BIND, b64(raw), b64u(raw)):
        assert run(base(**{"x-ms-isolation-tee": tdx(tdx_report_data=form)})) == tdx_ok()
    for key in ("x-ms-tdx-report-data", "x-ms-tdx-reportdata"):
        assert run(base(**{"x-ms-isolation-tee": tdx(**{"tdx_report_data": None, key: BIND})})) == tdx_ok()
    sha512 = hashlib.sha512(raw).hexdigest()
    assert run(base(**{"x-ms-isolation-tee": tdx(tdx_report_data=sha512)}), {"tdxMrtds": [MRTD], "reportDataHash": "sha512"}) == tdx_ok()
    # a SEV-SNP token does not read the TDX report-data name
    assert run(base(**{"x-ms-isolation-tee": snp(**{"x-ms-sevsnpvm-reportdata": None, "tdx_report_data": BIND})}), {"sevSnpMeasurements": [SNP]}) == xf("token carries no report-data claim to bind the PCA challenge")


def test_maa_runtime_user_data_binding():
    pol = {"tdxMrtds": [MRTD], "runtimeUserDataBinding": True}
    tee = {"x-ms-isolation-tee": tdx(tdx_report_data=None)}
    bad = "runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)"
    assert run(base(**dict(tee, **{"x-ms-runtime": {"user-data": BIND}})), pol) == tdx_ok()
    assert run(base(**dict(tee, **{"x-ms-runtime": {"user-data": BIND}})), pol, expected=dict(EXP, nonce="")) == xf("binding not constructible: binding: nonce required")
    assert run(base(**dict(tee, **{"x-ms-runtime": "x"})), pol) == xf("token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)")
    for empty in ({}, {"user-data": ""}, {"user-data": 5}):
        assert run(base(**dict(tee, **{"x-ms-runtime": empty})), pol) == xf("x-ms-runtime carries no user-data to bind the PCA challenge")
    assert run(base(**dict(tee, **{"x-ms-runtime": {"user-data": "00" * 64}})), pol) == xf(bad)
    assert run(base(**dict(tee, **{"x-ms-runtime": {"user-data": "!!!"}})), pol) == xf(bad)
    # only the literal `true` selects the runtime path
    assert run(base(**dict(tee, **{"x-ms-runtime": {"user-data": BIND}})), {"tdxMrtds": [MRTD], "runtimeUserDataBinding": 1}) == xf("token carries no report-data claim to bind the PCA challenge")


def tee_tdx(**extra):
    return base(**{"x-ms-isolation-tee": tdx(**extra)})


def test_maa_tdx_policy():
    pol = {"tdxMrtds": [MRTD]}
    assert run(tee_tdx(), {"sevSnpMeasurements": [SNP]}) == xf("tdxvm token but policy configures no TDX MRTD allowlist (fail closed)")
    assert run(tee_tdx(tdx_mrtd=None)) == xf("tdxvm token carries no MRTD claim")
    assert run(tee_tdx(tdx_mrtd="")) == xf("tdxvm token carries no MRTD claim")
    assert run(tee_tdx(tdx_mrtd="CC" * 48)) == xf("TDX MRTD not in policy allowlist")
    assert run(tee_tdx(), {"tdxMrtds": [MRTD.lower()]}) == tdx_ok()
    assert run(tee_tdx(**{"tdx_mrtd": None, "x-ms-tdx-mrtd": MRTD})) == tdx_ok()
    dbg = xf("TDX guest is debuggable (no confidentiality)")
    assert run(tee_tdx(tdx_td_attributes_debug=True)) == dbg
    assert run(tee_tdx(tdx_td_attributes_debug=1)) == tdx_ok()
    assert run(tee_tdx(tdx_td_attributes_debug=False)) == tdx_ok()
    assert run(tee_tdx(dbgstat="enabled")) == dbg
    assert run(tee_tdx(dbgstat="")) == dbg
    assert run(tee_tdx(dbgstat="disabled")) == tdx_ok()
    assert run(tee_tdx(dbgstat=5)) == tdx_ok()
    allow = {"tdxMrtds": [MRTD], "allowDebug": True}
    assert run(tee_tdx(tdx_td_attributes_debug=True), allow) == tdx_ok()
    assert run(tee_tdx(dbgstat="enabled"), allow) == tdx_ok()
    assert run(tee_tdx(dbgstat="enabled"), {"tdxMrtds": [MRTD], "allowDebug": 1}) == dbg
    st = "TDX platform TCB status '%s' is not accepted by policy"
    for ok_status in ("UpToDate", "SWHardeningNeeded"):
        assert run(tee_tdx(attester_tcb_status=ok_status)) == tdx_ok({"attestation_type": "tdxvm", "tcb_status": ok_status})
    assert run(tee_tdx(attester_tcb_status="OutOfDate")) == xf(st % "OutOfDate")
    assert run(tee_tdx(attester_tcb_status="uptodate")) == xf(st % "uptodate")
    assert run(tee_tdx(attester_tcb_status="")) == xf(st % "")
    assert run(tee_tdx(attester_tcb_status=5)) == tdx_ok()
    custom = dict(pol, tdxAllowedTcbStatuses=["OutOfDate"])
    assert run(tee_tdx(attester_tcb_status="OutOfDate"), custom) == tdx_ok({"attestation_type": "tdxvm", "tcb_status": "OutOfDate"})
    assert run(tee_tdx(attester_tcb_status="UpToDate"), custom) == xf(st % "UpToDate")
    rt = xf("TDX RTMR0 not in policy allowlist")
    rp = dict(pol, tdxRtmrs=["CC" * 48])
    assert run(tee_tdx(), rp) == rt
    assert run(tee_tdx(tdx_rtmr0="DD" * 48), rp) == rt
    assert run(tee_tdx(tdx_rtmr0="cc" * 48), rp) == tdx_ok({"attestation_type": "tdxvm", "rtmr0": "cc" * 48})
    assert run(tee_tdx(**{"x-ms-tdx-rtmr0": "CC" * 48}), rp) == tdx_ok({"attestation_type": "tdxvm", "rtmr0": "cc" * 48})
    assert run(tee_tdx(tdx_rtmr0="DD" * 48)) == tdx_ok({"attestation_type": "tdxvm", "rtmr0": "dd" * 48})  # no allowlist: reported only
    assert run(tee_tdx(tdx_rtmr0="DD" * 48), dict(pol, tdxRtmrs=[])) == tdx_ok({"attestation_type": "tdxvm", "rtmr0": "dd" * 48})


def tee_snp(**extra):
    return base(**{"x-ms-isolation-tee": snp(**extra)})


SNP_POL = {"sevSnpMeasurements": [SNP]}


def snp_ok(**host):
    h = {"attestation_type": "sevsnpvm"}
    h.update(host)
    return {"ok": True, "bound": True, "measured": measured(SNP.lower()), "hostAsserted": h}


def test_maa_sev_snp_policy():
    assert run(tee_snp()) == xf("sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)")
    assert run(tee_snp(), SNP_POL) == snp_ok()
    assert run(tee_snp(), {"sevSnpMeasurements": [SNP.lower()]}) == snp_ok()
    no = {"x-ms-sevsnpvm-launchmeasurement": None}
    assert run(tee_snp(**no), SNP_POL) == xf("sevsnpvm token carries no launch-measurement claim")
    assert run(tee_snp(**{"x-ms-sevsnpvm-launchmeasurement": ""}), SNP_POL) == xf("sevsnpvm token carries no launch-measurement claim")
    assert run(tee_snp(**{"x-ms-sevsnpvm-launchmeasurement": "CC" * 48}), SNP_POL) == xf("SEV-SNP launch measurement not in policy allowlist")
    dbg = {"x-ms-sevsnpvm-is-debuggable": True}
    assert run(tee_snp(**dbg), SNP_POL) == xf("SEV-SNP guest is debuggable (no confidentiality)")
    assert run(tee_snp(**dbg), dict(SNP_POL, allowDebug=True)) == snp_ok()
    assert run(tee_snp(**dbg), dict(SNP_POL, allowDebug=1)) == xf("SEV-SNP guest is debuggable (no confidentiality)")
    assert run(tee_snp(**{"x-ms-sevsnpvm-is-debuggable": "true"}), SNP_POL) == snp_ok()
    assert run(tee_snp(**{"x-ms-sevsnpvm-is-debuggable": False}), SNP_POL) == snp_ok()
    hd = "x-ms-sevsnpvm-hostdata"
    host_pol = dict(SNP_POL, sevSnpHostData=["DD" * 32])
    bad_host = xf("SEV-SNP host-data not in policy allowlist")
    assert run(tee_snp(), host_pol) == bad_host
    assert run(tee_snp(**{hd: "EE" * 32}), host_pol) == bad_host
    assert run(tee_snp(**{hd: "dd" * 32}), host_pol) == snp_ok(host_data="dd" * 32)
    assert run(tee_snp(**{hd: "EE" * 32}), SNP_POL) == snp_ok(host_data="ee" * 32)
    assert run(tee_snp(**{hd: "EE" * 32}), dict(SNP_POL, sevSnpHostData=[])) == snp_ok(host_data="ee" * 32)


def test_maa_sev_snp_tcb():
    cl = {"x-ms-sevsnpvm-bootloader-svn": 4, "x-ms-sevsnpvm-snpfw-svn": 5, "x-ms-sevsnpvm-microcode-svn": 6, "x-ms-sevsnpvm-tee-svn": 7.0}
    assert run(tee_snp(**cl), SNP_POL) == snp_ok(bootloader_svn="4", snpfw_svn="5", microcode_svn="6", tee_svn="7")
    floors = {"bootloader": 4, "snp": 5, "microcode": 6, "tee": 7}
    assert run(tee_snp(**cl), dict(SNP_POL, sevSnpMinTcb=floors)) == snp_ok(bootloader_svn="4", snpfw_svn="5", microcode_svn="6", tee_svn="7")
    # a non-SVN value is not reported, and without a floor is not refused
    for junk in (-1, 1.5, "4", True):
        assert run(tee_snp(**{"x-ms-sevsnpvm-bootloader-svn": junk}), SNP_POL) == snp_ok()
    assert run(tee_snp(**{"x-ms-sevsnpvm-bootloader-svn": 0}), SNP_POL) == snp_ok(bootloader_svn="0")
    rows = [("bootloader", "x-ms-sevsnpvm-bootloader-svn"), ("snp", "x-ms-sevsnpvm-snpfw-svn"), ("microcode", "x-ms-sevsnpvm-microcode-svn"), ("tee", "x-ms-sevsnpvm-tee-svn")]
    for name, claim in rows:
        pol = dict(SNP_POL, sevSnpMinTcb={name: 2})
        assert run(tee_snp(**{claim: 1}), pol) == xf("SEV-SNP %s SVN 1 is below the policy minimum 2" % name)
        assert run(tee_snp(**{claim: 1.0}), pol) == xf("SEV-SNP %s SVN 1 is below the policy minimum 2" % name)
        missing = xf("SEV-SNP %s SVN claim '%s' is missing or not a non-negative integer (policy requires a minimum)" % (name, claim))
        assert run(tee_snp(), pol) == missing
        for junk in (-1, 2.5, "2", True):
            assert run(tee_snp(**{claim: junk}), pol) == missing
    # the claims are walked bootloader, snp, microcode, tee
    all_f = dict(SNP_POL, sevSnpMinTcb=floors)
    assert run(tee_snp(), all_f) == xf("SEV-SNP bootloader SVN claim 'x-ms-sevsnpvm-bootloader-svn' is missing or not a non-negative integer (policy requires a minimum)")
    assert run(tee_snp(**{"x-ms-sevsnpvm-bootloader-svn": 4}), all_f) == xf("SEV-SNP snp SVN claim 'x-ms-sevsnpvm-snpfw-svn' is missing or not a non-negative integer (policy requires a minimum)")
    assert run(tee_snp(**dict(cl, **{"x-ms-sevsnpvm-tee-svn": 6})), all_f) == xf("SEV-SNP tee SVN 6 is below the policy minimum 7")


# ------------------------------------------------------------------------------------------------ GCP JWK keys


def ec_jwk(key, crv, size, **extra):
    n = key.public_key().public_numbers()
    d = {"kty": "EC", "crv": crv, "x": b64u(n.x.to_bytes(size, "big")), "y": b64u(n.y.to_bytes(size, "big"))}
    d.update(extra)
    return d


def rsa_jwk(key, **extra):
    n = key.public_key().public_numbers()
    d = {"kty": "RSA", "n": b64u(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")), "e": b64u(n.e.to_bytes(3, "big"))}
    d.update(extra)
    return d


def fp(key):
    return C.spki_sha(key, "sha256")


def test_jwk_key_forms():
    w = W()
    assert fp(G._jwk_key(rsa_jwk(w.rsa))) == spki(w.rsa.public_key())
    assert fp(G._jwk_key(ec_jwk(w.aleaf, "P-256", 32))) == spki(w.aleaf.public_key())
    assert fp(G._jwk_key(ec_jwk(w.leaf, "P-384", 48))) == spki(w.leaf.public_key())
    p521 = ec.generate_private_key(ec.SECP521R1())
    assert fp(G._jwk_key(ec_jwk(p521, "P-521", 66))) == spki(p521.public_key())
    assert fp(G._jwk_key({"x5c": x5(w.adirect_der, w.aroot_der)})) == spki(w.aleaf.public_key())
    # RSA before EC before x5c
    assert fp(G._jwk_key(rsa_jwk(w.rsa, x5c=x5(w.adirect_der)))) == spki(w.rsa.public_key())
    assert fp(G._jwk_key(ec_jwk(w.aother, "P-256", 32, x5c=x5(w.adirect_der)))) == spki(w.aother.public_key())
    e = ec_jwk(w.aleaf, "P-256", 32)
    r = rsa_jwk(w.rsa)
    for jwk in ({}, {"n": r["n"]}, {"e": r["e"]}, {"n": r["n"], "e": 3}, dict(e, kty="ec"), dict(e, kty=None), dict(e, crv=5), dict(e, x=5), dict(e, y=None),
                {"x5c": []}, {"x5c": [5]}, {"x5c": "abc"}):
        assert G._jwk_key(jwk) is None
    with pytest.raises(ValueError) as err:
        G._jwk_key(dict(e, crv="P-999"))
    assert str(err.value) == "Invalid EC curve name"
    with pytest.raises(ValueError) as err:
        G._jwk_key(dict(e, x=e["y"]))  # off the curve
    assert str(err.value) == "Invalid JWK EC key"


def test_key_from_jwk():
    w = W()
    assert fp(G._key_from_jwk(ec_jwk(w.aleaf, "P-256", 32))["key"]) == spki(w.aleaf.public_key())
    assert G._key_from_jwk({}) == {"reason": "JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate"}
    u = "JWKS key is not a usable public key: "
    e = ec_jwk(w.aleaf, "P-256", 32)
    assert G._key_from_jwk(dict(e, crv="P-999")) == {"reason": u + "Invalid EC curve name"}  # node createPublicKey
    assert G._key_from_jwk(dict(e, crv="p-256")) == {"reason": u + "Invalid EC curve name"}
    assert G._key_from_jwk(dict(e, x=e["y"])) == {"reason": u + "Invalid JWK EC key"}  # off the curve, node's text
    assert G._key_from_jwk({"x5c": ["AAAA"]}) == {"reason": u + ASN1 % "not a SEQUENCE"}
    k1 = ec.generate_private_key(ec.SECP256K1())
    assert fp(G._key_from_jwk(ec_jwk(k1, "secp256k1", 32))["key"]) == spki(k1.public_key())  # node accepts this curve too


NOANCHOR = "x5c chain does not anchor in a configured GCP trust root"


def test_gcp_x5c_chain_structure():
    w = W()
    v = lambda x, anchors=None, now=NOW, skew=0: G.verify_jwk_x5c_chain(x, anchors if anchors is not None else {"rootCertsPem": [pem(w.aroot_der)]}, now, skew)  # noqa: E731
    for bad in (None, "x", []):
        assert v(bad) == "empty x5c certificate chain"
    assert v([""]) == "empty x5c entry at index 0"
    assert v(x5(w.aleaf_der) + [5]) == "empty x5c entry at index 1"
    assert v(x5(w.aleaf_der) + ["!!!!"]) == "malformed x5c certificate at index 1: " + ASN1 % "truncated"
    chain = x5(w.aleaf_der, w.ainter_der)
    assert v(chain) is None
    assert v(chain, now=NB_MS) is None and v(chain, now=NA_MS) is None
    assert v(chain, now=NB_MS - 1) == "x5c certificate at index 0 is outside its validity window"
    assert v(chain, now=NA_MS + 1) == "x5c certificate at index 0 is outside its validity window"
    assert v(chain, now=NB_MS - 1000, skew=1000) is None
    assert v(chain, now=NB_MS - 1000, skew=999) == "x5c certificate at index 0 is outside its validity window"
    expired = mk("I", "Root", w.ainter.public_key(), w.aroot, 8, True, h=hashes.SHA256(), na=datetime.datetime(2026, 1, 1))
    assert v(x5(w.aleaf_der, expired)) == "x5c certificate at index 1 is outside its validity window"
    assert v(x5(w.adirect_der, w.ainter_der)) == "x5c link 0 is not signed by the certificate above it"
    assert v(x5(w.aleaf_der, w.ainter_der, w.aother_der)) == "x5c link 1 is not signed by the certificate above it"


def test_gcp_x5c_chain_profile():
    w = W()
    ca_leaf = mk("L", "Root", w.aleaf.public_key(), w.aroot, 8, True, h=hashes.SHA256())
    crit = mk("L", "Root", w.aleaf.public_key(), w.aroot, 8, False, h=hashes.SHA256(), extra=[(CRIT, True)])
    pinned = {"trustedKeySpki": [w.apin]}
    assert G.verify_jwk_x5c_chain(x5(ca_leaf, w.aroot_der), pinned, NOW, 0) == "x5c chain profile: " + CA_LEAF  # before any anchor
    assert G.verify_jwk_x5c_chain(x5(crit, w.aroot_der), pinned, NOW, 0) == "x5c chain profile: certificate at depth 0 has an unrecognised critical extension 1.2.3.4"
    eku = mk("L", "Root", w.aleaf.public_key(), w.aroot, 8, False, h=hashes.SHA256(), extra=[(EKU, True)])
    assert G.verify_jwk_x5c_chain(x5(eku, w.aroot_der), pinned, NOW, 0) is None


def test_gcp_x5c_chain_anchors():
    w = W()
    chain = x5(w.aleaf_der, w.ainter_der)
    v = lambda anchors: G.verify_jwk_x5c_chain(chain, anchors, NOW, 0)  # noqa: E731
    assert v({}) == NOANCHOR
    assert v({"trustedKeySpki": None, "rootCertsPem": None}) == NOANCHOR
    assert v({"trustedKeySpki": ["00" * 32]}) == NOANCHOR
    assert v({"trustedKeySpki": [spki(w.aleaf.public_key())]}) is None  # any certificate of the chain may be the pinned key
    assert v({"trustedKeySpki": [spki(w.ainter.public_key()).upper()]}) is None
    assert v({"trustedKeySpki": [w.apin]}) == NOANCHOR  # the root is not in this chain
    assert v({"rootCertsPem": [pem(w.aroot_der)]}) is None
    assert v({"rootCertsPem": [pem(w.aother_der)]}) == NOANCHOR
    key_pem = w.aroot.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    assert v({"rootCertsPem": [key_pem]}) is None  # a bare public key is accepted as a root
    assert v({"rootCertsPem": ["junk"]}) == NOANCHOR
    assert v({"rootCertsPem": ["junk", pem(w.aother_der), key_pem]}) is None


def resolve(header, ev=None, anchors=None, now=NOW, skew=0):
    return G._resolve_trusted_signing_key(header, ev, anchors if anchors is not None else {}, now, skew)


def key_is(r, key):
    assert "reason" not in r
    assert fp(r["key"]) == spki(key.public_key())


def test_resolve_header_x5c_paths():
    w = W()
    hx = x5(w.aleaf_der, w.ainter_der)
    roots = {"rootCertsPem": [pem(w.aroot_der)]}
    key_is(resolve({"kid": "k", "x5c": hx}, anchors=roots), w.aleaf)  # kid matches nothing: the header chain, anchored
    key_is(resolve({"x5c": hx}, anchors=roots), w.aleaf)
    key_is(resolve({"kid": "", "x5c": hx}, anchors=roots), w.aleaf)
    assert resolve({"kid": "k", "x5c": hx}, anchors={"rootCertsPem": [pem(w.aother_der)]}) == {"reason": "signing key not trusted: " + NOANCHOR}
    assert resolve({"x5c": hx}) == {"reason": "signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)"}
    assert resolve({"kid": "k", "x5c": []}) == {"reason": "no JWKS key matches the token kid 'k' (untrusted signer)"}
    assert resolve({"kid": "k"}) == {"reason": "no JWKS key matches the token kid 'k' (untrusted signer)"}
    single = "no kid on the token and no unambiguous single signing key available"
    assert resolve({}) == {"reason": single}
    assert resolve({"kid": ""}) == {"reason": single}
    assert resolve({"x5c": []}) == {"reason": single}
    # the chain check honours the clock and the skew
    late = NA_MS + 1000
    assert resolve({"x5c": hx}, anchors=roots, now=late) == {"reason": "signing key not trusted: x5c certificate at index 0 is outside its validity window"}
    key_is(resolve({"x5c": hx}, anchors=roots, now=late, skew=1000), w.aleaf)


def test_resolve_refuses_a_key_beside_a_genuine_chain():
    """A genuine public chain vouches only for its own leaf (reference 365d0e8ec): the forgery is an attacker's key in the JWK beside it."""
    w = W()
    hx = x5(w.aleaf_der, w.ainter_der)
    forged = dict(ec_jwk(w.aother, "P-256", 32, kid="k"), x5c=hx)
    honest = dict(ec_jwk(w.aleaf, "P-256", 32, kid="k"), x5c=hx)
    for anchors in ({"rootCertsPem": [pem(w.aroot_der)]}, {"trustedKeySpki": [Cert(w.ainter_der).spki_hash("sha256")]}):
        assert resolve({"kid": "k"}, {"keys": [forged]}, anchors) == {"reason": "signing key not trusted: the JWK key is not the key of its x5c leaf"}
        key_is(resolve({"kid": "k"}, {"keys": [honest]}, anchors), w.aleaf)


def test_resolve_jwks_picking_and_trust():
    w = W()
    a = ec_jwk(w.aleaf, "P-256", 32, kid="a")
    b = ec_jwk(w.aother, "P-256", 32, kid="b")
    no_anchor = {"reason": "signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)"}
    single = {"reason": "no kid on the token and no unambiguous single signing key available"}
    # the pinned JWKS: trusted as is
    t = {"trustedJwks": {"keys": [a]}}
    key_is(resolve({"kid": "a"}, anchors=t), w.aleaf)
    key_is(resolve({}, anchors=t), w.aleaf)
    assert resolve({}, anchors={"trustedJwks": {"keys": [a, b]}}) == single
    assert resolve({"kid": "z"}, anchors=t) == {"reason": "no JWKS key matches the token kid 'z' (untrusted signer)"}
    # the evidence JWKS: looked at first, trusted only through an anchor
    assert resolve({"kid": "b"}, {"keys": [b]}) == no_anchor
    assert resolve({}, {"keys": [b]}) == no_anchor
    assert resolve({}, {"keys": [a, b]}) == single
    key_is(resolve({}, {"keys": [a, b]}, t), w.aleaf)  # ambiguous evidence falls through to the pinned JWKS
    same_kid = dict(b, kid="a")
    assert resolve({"kid": "a"}, {"keys": [same_kid]}, t) == no_anchor  # the evidence key wins the pick and is not the pinned one
    key_is(resolve({"kid": "e"}, {"keys": [dict(a, kid="e")]}, t), w.aleaf)  # same key material under another kid
    key_is(resolve({"kid": "e"}, {"keys": [dict(a, kid="e")]}, {"trustedJwks": {"keys": [{"kid": "junk"}, {"kid": "t", "kty": "EC", "crv": "P-999", "x": "AA", "y": "AA"}, a]}}), w.aleaf)  # unusable pins are skipped
    assert resolve({"kid": "e"}, {"keys": [dict(b, kid="e")]}, t) == no_anchor
    pins = {"trustedKeySpki": [spki(w.aother.public_key()).upper()]}
    key_is(resolve({"kid": "b"}, {"keys": [b]}, pins), w.aother)
    assert resolve({"kid": "a"}, {"keys": [a]}, pins) == no_anchor
    # an evidence key carrying a chain
    chain_key = {"kid": "c", "x5c": x5(w.aleaf_der, w.ainter_der)}
    key_is(resolve({"kid": "c"}, {"keys": [chain_key]}, {"rootCertsPem": [pem(w.aroot_der)]}), w.aleaf)
    assert resolve({"kid": "c"}, {"keys": [chain_key]}, {"rootCertsPem": [pem(w.aother_der)]}) == {"reason": "signing key not trusted: " + NOANCHOR}
    key_is(resolve({"kid": "c"}, {"keys": [chain_key]}, {"trustedKeySpki": [spki(w.ainter.public_key())]}), w.aleaf)  # a pin on a higher certificate
    assert resolve({"kid": "c"}, {"keys": [chain_key]}, {"trustedKeySpki": ["00" * 32]}) == {"reason": "signing key not trusted: " + NOANCHOR}
    assert resolve({"kid": "c"}, {"keys": [chain_key]}, {"trustedJwks": {"keys": [b]}}) == no_anchor  # no root and no pin: the chain has nothing to reach
    # junk JWKS shapes
    for junk in (None, 5, {}, {"keys": "x"}, {"keys": 5}):
        assert resolve({}, junk) == single
    assert resolve({}, {"keys": [5]}) == {"reason": "JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate"}
    key_is(resolve({"kid": "a"}, {"keys": [5, a]}, t), w.aleaf)


def fields(r):
    assert set(r) == {"key", "spkiSha256", "fromTrustedJwks", "jwk"}
    return {k: v for k, v in r.items() if k != "key"}


def test_resolve_returns_every_reference_field():
    w = W()
    sa, so = spki(w.aleaf.public_key()), spki(w.aother.public_key())
    a = ec_jwk(w.aleaf, "P-256", 32, kid="a")
    b = ec_jwk(w.aother, "P-256", 32, kid="b")
    t = {"trustedJwks": {"keys": [a]}}
    assert fields(resolve({"kid": "a"}, anchors=t)) == {"spkiSha256": sa, "fromTrustedJwks": True, "jwk": a}
    assert fields(resolve({"kid": "b"}, {"keys": [b]}, {"trustedKeySpki": [so]})) == {"spkiSha256": so, "fromTrustedJwks": False, "jwk": b}
    e = dict(a, kid="e")
    assert fields(resolve({"kid": "e"}, {"keys": [e]}, t)) == {"spkiSha256": sa, "fromTrustedJwks": False, "jwk": e}
    hx = x5(w.aleaf_der, w.ainter_der)
    roots = {"rootCertsPem": [pem(w.aroot_der)]}
    assert fields(resolve({"kid": "k", "x5c": hx}, anchors=roots)) == {"spkiSha256": sa, "fromTrustedJwks": False, "jwk": {"x5c": hx, "kid": "k"}}
    assert fields(resolve({"x5c": hx}, anchors=roots)) == {"spkiSha256": sa, "fromTrustedJwks": False, "jwk": {"x5c": hx}}
    c = {"kid": "c", "x5c": hx}
    assert fields(resolve({"kid": "c"}, {"keys": [c]}, roots)) == {"spkiSha256": sa, "fromTrustedJwks": False, "jwk": c}


# ------------------------------------------------------------------------------------------------ the strict profile, site by site


PROFILE = {
    "leaf_ca": CA_LEAF,
    "issuer_ca_false": "issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)",
    "ku_no_sign": "issuer certificate at depth 1 keyUsage lacks keyCertSign",
    "path_len": "issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)",
    "crit_leaf": "certificate at depth 0 has an unrecognised critical extension 1.2.3.4",
    "crit_inter": "certificate at depth 1 has an unrecognised critical extension 1.2.3.4",
}
CASES = sorted(PROFILE)
ISSUES = "device chain cert #1 issues a certificate but is not a CA"  # the reference's NVIDIA issuer gate runs before the profile


def fam(big):
    w = W()
    return (w.leaf, w.inter, w.root, w.other, hashes.SHA384()) if big else (w.aleaf, w.ainter, w.aroot, w.aother, hashes.SHA256())


def chain_of(case, big, external=False):
    """[leaf, intermediate, top] with `case` planted (None / "eku" = a clean chain); `external` signs the top by a fourth key."""
    leaf, inter, top, ext, h = fam(big)
    lk = {"ca": case == "leaf_ca", "extra": [(CRIT, True)] if case == "crit_leaf" else [(EKU, True)] if case == "eku" else []}
    ik = {"ca": case != "issuer_ca_false", "extra": [(CRIT, True)] if case == "crit_inter" else []}
    if case == "ku_no_sign":
        ik.update(usage=False, extra=[(ku(False), True)])
    tk = {"pathlen": 0} if case == "path_len" else {}
    return [
        mk("L", "I", leaf.public_key(), inter, 21, h=h, **lk),
        mk("I", "T", inter.public_key(), top, 22, h=h, **ik),
        mk("T", "E" if external else "T", top.public_key(), ext if external else top, 23, True, h=h, **tk),
    ]


@pytest.mark.parametrize("case", CASES)
def test_profile_azure_in_chain_anchor(case):
    assert verify_x5c_chain(x5(*chain_of(case, False)), {"rootSpkiSha256": [W().apin]}, NOW) == xf("x5c chain profile: " + PROFILE[case])


def test_profile_azure_slices_to_the_anchor_index():
    w = W()
    inter_pin = {"rootSpkiSha256": [spki(w.ainter.public_key())]}
    leaf_pin = {"rootSpkiSha256": [spki(w.aleaf.public_key())]}
    v = lambda case, anchors: verify_x5c_chain(x5(*chain_of(case, False)), anchors, NOW)  # noqa: E731
    # inside the slice [leaf, intermediate]
    assert v("leaf_ca", inter_pin) == xf("x5c chain profile: " + CA_LEAF)
    assert v("crit_leaf", inter_pin) == xf("x5c chain profile: " + PROFILE["crit_leaf"])
    assert v("crit_inter", inter_pin) == xf("x5c chain profile: " + PROFILE["crit_inter"])
    assert v("issuer_ca_false", inter_pin) == xf("x5c chain profile: " + PROFILE["issuer_ca_false"])
    assert v("ku_no_sign", inter_pin) == xf("x5c chain profile: " + PROFILE["ku_no_sign"])
    # the top's pathLen is above the anchor: not examined
    assert v("path_len", inter_pin)["ok"] is True
    # an anchored leaf: the slice is the leaf alone
    assert v("leaf_ca", leaf_pin)["ok"] is True  # one certificate has no role relationship
    assert v("crit_inter", leaf_pin)["ok"] is True
    assert v("crit_leaf", leaf_pin) == xf("x5c chain profile: " + PROFILE["crit_leaf"])


@pytest.mark.parametrize("case", CASES)
def test_profile_azure_external_root(case):
    anchors = {"rootCertsPem": [pem(W().aother_der)]}
    assert verify_x5c_chain(x5(*chain_of(case, False, external=True)), anchors, NOW) == xf("x5c chain profile: " + PROFILE[case])


def test_profile_azure_controls_with_critical_eku():
    w = W()
    a = verify_x5c_chain(x5(*chain_of("eku", False)), {"rootSpkiSha256": [w.apin]}, NOW)
    b = verify_x5c_chain(x5(*chain_of("eku", False, external=True)), {"rootCertsPem": [pem(w.aother_der)]}, NOW)
    assert a["ok"] is True and b["ok"] is True


@pytest.mark.parametrize("case", CASES)
def test_profile_gcp(case):
    assert G.verify_jwk_x5c_chain(x5(*chain_of(case, False)), {"trustedKeySpki": [W().apin]}, NOW, 0) == "x5c chain profile: " + PROFILE[case]


def test_profile_gcp_control_with_critical_eku():
    assert G.verify_jwk_x5c_chain(x5(*chain_of("eku", False)), {"trustedKeySpki": [W().apin]}, NOW, 0) is None


def nv_reason(case):
    return ISSUES if case in ("issuer_ca_false", "ku_no_sign") else "device chain profile: " + PROFILE[case]


@pytest.mark.parametrize("case", CASES)
def test_profile_nvidia_device_chain(case):
    assert N.verify_nvidia_device_chain(chain_pem(*chain_of(case, True)), [W().pin], NOW) == xf(nv_reason(case))


def test_profile_nvidia_control_with_critical_eku():
    assert N.verify_nvidia_device_chain(chain_pem(*chain_of("eku", True)), [W().pin], NOW)["ok"] is True


@pytest.mark.parametrize("case", CASES)
def test_profile_rim_signer(case):
    assert rim(rim_text(ki=keyinfo(*chain_of(case, True)))) == xf("RIM signer chain: " + nv_reason(case))


def test_profile_rim_signer_control_with_critical_eku():
    assert good(rim(signed(ki=keyinfo(*chain_of("eku", True)))))["signerSubject"] == "CN=L"
