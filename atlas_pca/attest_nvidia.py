"""NVIDIA GPU (Hopper / Blackwell, CC mode) SPDM attestation verifier and its RIM / CRL / OCSP collateral hook.

Native counterpart of `createNvidiaSpdmVerifier` and `nvidiaCollateralHook`: the device chain to a PINNED NVIDIA root, the SPDM
GET_MEASUREMENTS transcript signature (ECDSA P-384), the PCA binding through the SPDM request nonce, the pinned measurement
blocks, and (optionally) the signed Reference Integrity Manifests, firmware policy and CRL / OCSP revocation. Fails closed
with the reference's reason strings.
"""
import base64
import hashlib
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from .attest_amd import AttestConstructError
from .attest_cert import Cert
from .attest_common import (
    attestation_challenge_sha256,
    ecdsa_verify_raw,
    js_number,
    js_str,
    js_trim,
    key_type,
    node_b64decode,
    node_curve,
    pem_blocks,
    to_hex,
)
from .attest_der import x509_valid_at
from .attest_intel import serial_is_revoked, verify_crl
from .attest_ocsp import check_nvidia_chain_ocsp
from .attest_xml import Element, XmlError, canonicalize, parse_xml

NVIDIA_SPDM_SUITE = "nvidia-gpu-spdm-ecdsa-p384-sha384"
_REQ_LEN, _NONCE_LEN, _SIG_LEN = 37, 32, 96
_MAX_CHAIN = 5
OPAQUE_DRIVER_VERSION, OPAQUE_VBIOS_VERSION, OPAQUE_CHIP_INFO = 3, 6, 35

_NS_DSIG = "http://www.w3.org/2000/09/xmldsig#"
_ALG_C14N11 = "http://www.w3.org/2006/12/xml-c14n11"
_ALG_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
_ALG_ECDSA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
_ALG_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
_NVDEC0_DISABLED = 0x55
_NVDEC_BLOCK_INDEX = 35


def _b(b: bytes, o: int) -> int:
    return b[o] if 0 <= o < len(b) else 0


def _u16(b: bytes, o: int) -> int:
    return _b(b, o) | (_b(b, o + 1) << 8)


def _u24(b: bytes, o: int) -> int:
    return _b(b, o) | (_b(b, o + 1) << 8) | (_b(b, o + 2) << 16)


# ------------------------------------------------------------------------------------------------ SPDM transcript


def parse_nvidia_spdm_evidence(b: bytes) -> Dict[str, Any]:
    """Parse an SPDM request || response GPU attestation transcript. Total: raises ValueError on any structural problem."""
    b = bytes(b)
    if len(b) < _REQ_LEN + 8 + _NONCE_LEN + 2 + _SIG_LEN:
        raise ValueError("parseNvidiaSpdmEvidence: transcript too short (%d)" % len(b))
    code = _b(b, 1)
    if code != 0xE0:
        raise ValueError("parseNvidiaSpdmEvidence: request code 0x%x is not GET_MEASUREMENTS" % code)
    request = {"nonce": b[4:4 + _NONCE_LEN]}
    r = b[_REQ_LEN:]
    if _b(r, 1) != 0x60:
        raise ValueError("parseNvidiaSpdmEvidence: response code is not MEASUREMENTS")
    num_blocks = _b(r, 4)
    rec_len = _u24(r, 5)
    o = 8
    if o + rec_len + _NONCE_LEN + 2 + _SIG_LEN > len(r):
        raise ValueError("parseNvidiaSpdmEvidence: measurement record length overruns transcript")
    measurements: List[Dict[str, Any]] = []
    rec_end = o + rec_len
    while o < rec_end:
        if o + 4 > rec_end:
            raise ValueError("parseNvidiaSpdmEvidence: truncated measurement block header")
        index = _b(r, o)
        size = _u16(r, o + 2)
        body_start = o + 4
        if body_start + size > rec_end or size < 3:
            raise ValueError("parseNvidiaSpdmEvidence: measurement block overruns record")
        value_type = _b(r, body_start)
        vsize = _u16(r, body_start + 1)
        if 3 + vsize > size:
            raise ValueError("parseNvidiaSpdmEvidence: DMTF value overruns measurement block")
        measurements.append({"index": index, "valueType": value_type, "digest": r[body_start + 3:body_start + 3 + vsize]})
        o = body_start + size
    if len(measurements) != num_blocks:
        raise ValueError("parseNvidiaSpdmEvidence: header says %d blocks, parsed %d" % (num_blocks, len(measurements)))
    o += _NONCE_LEN
    opaque_len = _u16(r, o)
    o += 2
    if o + opaque_len + _SIG_LEN != len(r):
        raise ValueError("parseNvidiaSpdmEvidence: opaque length + signature do not exactly fill the transcript")
    opaque: Dict[int, bytes] = {}
    opaque_end = o + opaque_len
    while o < opaque_end:
        if o + 4 > opaque_end:
            raise ValueError("parseNvidiaSpdmEvidence: truncated opaque TLV header")
        t = _u16(r, o)
        ln = _u16(r, o + 2)
        o += 4
        if o + ln > opaque_end:
            raise ValueError("parseNvidiaSpdmEvidence: opaque TLV overruns opaque data")
        opaque[t] = r[o:o + ln]
        o += ln
    return {
        "request": request,
        "measurements": measurements,
        "opaque": opaque,
        "signature": r[len(r) - _SIG_LEN:],
        "signedBytes": b[: len(b) - _SIG_LEN],
    }


def format_vbios_version(raw: bytes) -> str:
    """NVIDIA's VBIOS version rendering: byte-reverse, then re-pair as dotted hex (e.g. `96.00.9f.00.04`)."""
    hx = bytes(reversed(raw)).hex()
    half = len(hx) // 2
    temp = hx[half:] + hx[half - 2:half]
    return ".".join(re.findall(r".{1,2}", temp))


# ------------------------------------------------------------------------------------------------ device chain


def parse_pem_chain(pem: str) -> List[Cert]:
    blocks = pem_blocks(pem)
    if len(blocks) == 0:
        raise ValueError("parsePemChain: no certificates found")
    if len(blocks) > _MAX_CHAIN:
        raise ValueError("parsePemChain: chain longer than %d" % _MAX_CHAIN)
    return [Cert.from_pem(b) for b in blocks]


def verify_nvidia_device_chain(pem: str, root_spki_sha256: List[str], now_ms: float) -> Dict[str, Any]:
    """Every link signature-verified, every issuer a CA, every certificate valid at `now`, the root self-signed and PINNED."""
    try:
        chain = parse_pem_chain(pem)
    except Exception as e:
        return {"ok": False, "reason": "device chain unparseable: %s" % e}
    for i, c in enumerate(chain):
        if not x509_valid_at(c.raw, now_ms):
            return {"ok": False, "reason": "device chain cert #%d is outside its validity window" % i}
        pk = c.public_key
        if key_type(pk) != "ec" or node_curve(pk) != "secp384r1":
            return {"ok": False, "reason": "device chain cert #%d is not an ECDSA P-384 key" % i}
    for i in range(len(chain) - 1):
        issuer = chain[i + 1]
        if not issuer.ca:
            return {"ok": False, "reason": "device chain cert #%d issues a certificate but is not a CA" % (i + 1)}
        if not chain[i].verify(issuer.public_key):
            return {"ok": False, "reason": "device chain link #%d signature does not verify under its issuer" % i}
    root = chain[-1]
    if not root.ca or not root.verify_self():
        return {"ok": False, "reason": "device chain root is not a self-signed CA"}
    pins = set(p.lower() for p in root_spki_sha256)
    if root.spki_sha256() not in pins:
        return {"ok": False, "reason": "chain root is not a pinned NVIDIA root"}
    return {"ok": True, "leaf": chain[0], "chain": chain}


# ------------------------------------------------------------------------------------------------ RIM (SWID XML, XMLDSig)


def _pem_of_der_b64(b64: str) -> str:
    body = re.sub(r"\s+", "", b64)
    lines = re.findall(r".{1,64}", body)
    return "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % "\n".join(lines)


def _text_of(el: Optional[Element]) -> Optional[str]:
    return None if el is None else el.text_content()


def verify_nvidia_rim(xml: Any, rim_root_spki_sha256: List[str], now_ms: float) -> Dict[str, Any]:
    """A RIM document (XML text): the strict XMLDSig profile, the digest, the ECDSA-P384 signature and the signer chain to the
    pinned CoRIM signing root; golden measurements are read ONLY from the verified tree."""

    def fail(reason: str) -> Dict[str, Any]:
        return {"ok": False, "reason": reason}

    try:
        if not isinstance(xml, str) or len(xml) == 0 or len(xml) > 4_000_000:
            return fail("RIM: empty or oversized document")
        if not isinstance(rim_root_spki_sha256, list) or len(rim_root_spki_sha256) == 0:
            return fail("RIM: no pinned RIM root configured")
        doc = parse_xml(xml)
        if doc.violations:
            return fail("RIM: %s" % doc.violations[0])
        root = doc.root
        assert root is not None
        if root.local != "SoftwareIdentity":
            return fail("RIM: root element is not SoftwareIdentity")
        if len(root.descendants(_NS_DSIG, "Signature")) != 1:
            return fail("RIM: expected exactly one Signature element")
        sigs = root.element_children(_NS_DSIG, "Signature")
        if len(sigs) != 1:
            return fail("RIM: the Signature must be a direct child of the root")
        sig = sigs[0]
        signed_info = sig.element_children(_NS_DSIG, "SignedInfo")
        if len(signed_info) != 1:
            return fail("RIM: expected exactly one SignedInfo")
        si = signed_info[0]

        def alg_of(els: List[Element]) -> Optional[str]:
            return els[0].get_attribute("Algorithm") if els else None

        if alg_of(si.element_children(_NS_DSIG, "CanonicalizationMethod")) != _ALG_C14N11:
            return fail("RIM: CanonicalizationMethod must be C14N 1.1")
        if alg_of(si.element_children(_NS_DSIG, "SignatureMethod")) != _ALG_ECDSA384:
            return fail("RIM: SignatureMethod must be ECDSA-SHA384")
        refs = si.element_children(_NS_DSIG, "Reference")
        if len(refs) != 1:
            return fail("RIM: expected exactly one Reference")
        ref = refs[0]
        if ref.get_attribute("URI") != "":
            return fail('RIM: Reference URI must be "" (the whole document)')
        tr = ref.element_children(_NS_DSIG, "Transforms")
        transforms = [t.get_attribute("Algorithm") for t in (tr[0] if tr else ref).element_children(_NS_DSIG, "Transform")]
        if len(transforms) != 2 or transforms[0] != _ALG_ENVELOPED or transforms[1] != _ALG_C14N11:
            return fail("RIM: transforms must be exactly [enveloped-signature, C14N 1.1]")
        if alg_of(ref.element_children(_NS_DSIG, "DigestMethod")) != _ALG_SHA384:
            return fail("RIM: DigestMethod must be SHA-384")
        dv = ref.element_children(_NS_DSIG, "DigestValue")
        sv = sig.element_children(_NS_DSIG, "SignatureValue")
        digest_value = re.sub(r"\s+", "", dv[0].text_content()) if dv else None
        sig_value_b64 = re.sub(r"\s+", "", sv[0].text_content()) if sv else None
        if not digest_value or not sig_value_b64:
            return fail("RIM: missing DigestValue / SignatureValue")

        key_info = sig.element_children(_NS_DSIG, "KeyInfo")
        x509_data = key_info[0].element_children(_NS_DSIG, "X509Data") if key_info else []
        cert_b64 = [c.text_content() for c in x509_data[0].element_children(_NS_DSIG, "X509Certificate")] if x509_data else []
        if len(cert_b64) == 0:
            return fail("RIM: no signer certificates in KeyInfo")
        chain = verify_nvidia_device_chain("\n".join(_pem_of_der_b64(c) for c in cert_b64), rim_root_spki_sha256, now_ms)
        if not chain["ok"]:
            return fail("RIM signer chain: %s" % chain["reason"])

        si_canon = canonicalize(si)
        sig_raw = node_b64decode(sig_value_b64)
        if len(sig_raw) != 96:
            return fail("RIM: SignatureValue is not a 96-byte P-384 signature")
        if not ecdsa_verify_raw(chain["leaf"].public_key, sig_raw, si_canon.encode("utf-8"), "sha384"):
            return fail("RIM: SignedInfo signature does not verify under the signer certificate")

        canon = canonicalize(root, skip=sig)
        if base64.b64encode(hashlib.sha384(canon.encode("utf-8")).digest()).decode("ascii") != digest_value:
            return fail("RIM: document digest does not match the signed DigestValue")

        meta = next((c for c in root.element_children() if c.local == "Meta"), None)
        payload = next((c for c in root.element_children() if c.local == "Payload"), None)
        if meta is None or payload is None:
            return fail("RIM: missing Meta / Payload")
        golden: Dict[int, Dict[str, Any]] = {}
        for r in payload.element_children():
            if r.local != "Resource" or r.get_attribute("type") != "Measurement":
                continue
            index = js_number(r.get_attribute("index"))
            alternatives = js_number(r.get_attribute("alternatives"))
            size = js_number(r.get_attribute("size"))
            hash_attrs = [a for a in r.attrs if re.fullmatch(r"Hash[0-9]+", a.local)]
            hash_attrs.sort(key=lambda a: int(a.local[4:]))
            hashes = [a.value.lower() for a in hash_attrs]
            if not _is_int(index) or index < 0 or not _is_int(alternatives) or alternatives < 1 or not _is_int(size) or size < 1:
                return fail("RIM: malformed Measurement resource")
            index, alternatives, size = int(index), int(alternatives), int(size)
            if len(hashes) != alternatives or any(not re.fullmatch(r"[0-9a-f]+", h) or len(h) != size * 2 for h in hashes):
                return fail("RIM: Measurement %d hash list is inconsistent with alternatives/size" % index)
            if index in golden:
                return fail("RIM: duplicate Measurement index %d" % index)
            golden[index] = {"index": index, "active": r.get_attribute("active").lower() == "true", "alternatives": alternatives, "size": size, "hashes": hashes}
        if len(golden) == 0:
            return fail("RIM: no measurements")
        return {
            "ok": True,
            "rim": {"tagId": root.get_attribute("tagId"), "product": meta.get_attribute("product"), "version": meta.get_attribute("colloquialVersion"), "golden": golden},
        }
    except XmlError as e:
        return fail("RIM: verification error (fail closed): %s" % e)
    except Exception as e:
        return fail("RIM: verification error (fail closed): %s" % e)


def _is_int(v: float) -> bool:
    return v == v and v not in (float("inf"), float("-inf")) and float(v).is_integer()


# ------------------------------------------------------------------------------------------------ RIM ids, comparison, revocation


def _ascii(b: Optional[bytes]) -> str:
    s = bytes(b or b"").decode("latin-1")
    return js_trim(re.sub(r"\0+$", "", s))


def nvidia_rim_ids_for_report(report: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """The RIM ids this report requires (read from the GPU's own signed opaque data); None when they cannot be named."""
    o = report["opaque"]
    driver_version = _ascii(o.get(OPAQUE_DRIVER_VERSION))
    vb = o.get(OPAQUE_VBIOS_VERSION)
    project = _ascii(o.get(17)).upper()
    project_sku = _ascii(o.get(18)).upper()
    chip_sku = _ascii(o.get(15)).upper()
    if not driver_version or vb is None or not project or not project_sku or not chip_sku:
        return None
    chip = "GH100"
    chip_raw = o.get(OPAQUE_CHIP_INFO)
    if chip_raw is not None:
        chip = _ascii(chip_raw)
        if not re.fullmatch(r"[A-Z][A-Z0-9]{2,11}", chip):
            return None
    vbios_version = format_vbios_version(vb)
    return {
        "chip": chip,
        "driver": ("NV_GPU_DRIVER_GH100_%s" % driver_version) if chip == "GH100" else ("NV_GPU_CC_DRIVER_%s_%s" % (chip, driver_version)),
        "vbios": "NV_GPU_VBIOS_%s_%s_%s_%s" % (project, project_sku, chip_sku, vbios_version.replace(".", "").upper()),
        "driverVersion": driver_version,
        "vbiosVersion": vbios_version,
    }


def compare_report_to_rims(report: Dict[str, Any], driver: Dict[str, Any], vbios: Dict[str, Any]) -> Dict[str, Any]:
    """NVIDIA's merge / alternatives / NVDEC0 rules."""
    merged: Dict[int, Dict[str, Any]] = {}
    for g in driver["golden"].values():
        if g["active"]:
            merged[g["index"]] = g
    for g in vbios["golden"].values():
        if not g["active"]:
            continue
        if g["index"] in merged:
            return {"ok": False, "reason": "driver and VBIOS RIMs both have an active measurement at index %d" % g["index"]}
        merged[g["index"]] = g
    if len(merged) == 0:
        return {"ok": False, "reason": "RIMs carry no active golden measurements"}
    runtime = {m["index"] - 1: m["digest"] for m in report["measurements"]}
    if len(merged) > len(runtime):
        return {"ok": False, "reason": "RIMs list more active measurements than the report carries"}
    nvdec = report["opaque"].get(11)
    nvdec_disabled = nvdec is not None and len(nvdec) > 0 and nvdec[0] == _NVDEC0_DISABLED
    mismatches = 0
    for index in sorted(merged):
        g = merged[index]
        if index + 1 == _NVDEC_BLOCK_INDEX and nvdec_disabled:
            continue
        digest = runtime.get(index)
        hx = to_hex(digest) if digest is not None else ""
        if digest is None or len(digest) != g["size"] or hx not in g["hashes"]:
            mismatches += 1
    if mismatches > 0:
        return {"ok": False, "reason": "runtime measurements differ from the golden RIM values at %d index(es)" % mismatches}
    return {"ok": True}


def check_nvidia_chain_revocation(chain: List[Cert], crls: List[bytes], now_ms: float, require_issuers: Optional[List[str]] = None) -> Dict[str, Any]:
    """The device chain against CRLs: every supplied CRL verifies under one chain certificate and is fresh, no chain
    certificate (other than the root) is listed by its issuer, and `require_issuers` each have a verified CRL."""
    if len(crls) == 0:
        return {"ok": False, "reason": "no CRLs supplied"}
    covered = set()
    for ci, crl in enumerate(crls):
        issuer_idx = -1
        revoked = None
        last_reason = "no chain certificate verifies it"
        for i, cert in enumerate(chain):
            r = verify_crl(crl, cert.public_key, now_ms)
            if r["ok"]:
                issuer_idx = i
                revoked = r["revoked"]
                break
            if last_reason == "no chain certificate verifies it" or "signature does not verify" in last_reason:
                last_reason = r["reason"]
        if issuer_idx < 0 or revoked is None:
            return {"ok": False, "reason": "CRL #%d rejected: %s" % (ci, last_reason)}
        covered.add(issuer_idx)
        for i in range(len(chain) - 1):
            if i + 1 == issuer_idx and serial_is_revoked(revoked, chain[i].serial_hex):
                return {"ok": False, "reason": "chain certificate '%s' is revoked" % chain[i].subject.replace("\n", ", ")}
    for need in require_issuers or []:
        if not any(need in chain[i].subject for i in covered):
            return {"ok": False, "reason": "no verified CRL issued by a certificate matching '%s'" % need}
    return {"ok": True, "verifiedCrls": len(crls)}


# ------------------------------------------------------------------------------------------------ firmware policy


def _parse_version(v: Any, radix: int) -> Optional[List[int]]:
    pat = r"[0-9]+(\.[0-9]+)*" if radix == 10 else r"[0-9a-fA-F]{1,4}(\.[0-9a-fA-F]{1,4})*"
    if not isinstance(v, str) or not re.fullmatch(pat, v):
        return None
    return [int(x, radix) for x in v.split(".")]


def _cmp_version(a: List[int], b: List[int]) -> int:
    for i in range(max(len(a), len(b))):
        d = (a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)
        if d != 0:
            return -1 if d < 0 else 1
    return 0


def _compile_firmware_policy(fw: Any) -> Callable[[Dict[str, str]], Optional[str]]:
    if not fw:
        return lambda ids: None

    def need(v: Any, radix: int, what: str) -> List[int]:
        p = _parse_version(v, radix)
        if p is None:
            raise AttestConstructError("nvidiaCollateralHook: malformed %s '%s'" % (what, js_str(v)))
        return p

    min_d = need(fw["minDriverVersion"], 10, "minDriverVersion") if fw.get("minDriverVersion") else None
    min_v = need(fw["minVbiosVersion"], 16, "minVbiosVersion") if fw.get("minVbiosVersion") else None
    deny_d = [need(v, 10, "denyDriverVersions entry") for v in (fw.get("denyDriverVersions") or [])]
    deny_v = [need(v, 16, "denyVbiosVersions entry") for v in (fw.get("denyVbiosVersions") or [])]

    def check(ids: Dict[str, str]) -> Optional[str]:
        d = _parse_version(ids["driverVersion"], 10)
        v = _parse_version(ids["vbiosVersion"], 16)
        if d is None:
            return "driver version '%s' in the GPU report is not parseable" % ids["driverVersion"]
        if v is None:
            return "VBIOS version '%s' in the GPU report is not parseable" % ids["vbiosVersion"]
        if min_d is not None and _cmp_version(d, min_d) < 0:
            return "driver %s is below the minimum %s" % (ids["driverVersion"], fw["minDriverVersion"])
        if min_v is not None and _cmp_version(v, min_v) < 0:
            return "VBIOS %s is below the minimum %s" % (ids["vbiosVersion"], fw["minVbiosVersion"])
        if any(_cmp_version(d, x) == 0 for x in deny_d):
            return "driver %s is on the deny list" % ids["driverVersion"]
        if any(_cmp_version(v, x) == 0 for x in deny_v):
            return "VBIOS %s is on the deny list" % ids["vbiosVersion"]
        return None

    return check


# ------------------------------------------------------------------------------------------------ the collateral hook


class NvidiaCollateralHook:
    """The post-verification hook: RIM signature + golden comparison + driver / VBIOS version binding + revocation.
    `resolve(ids, evidence)` supplies the bundle {driverRimXml, vbiosRimXml, crls?, ocsp?} (or None)."""

    def __init__(self, opts: Dict[str, Any]) -> None:
        pins = opts.get("rimRootSpkiSha256")
        if not isinstance(pins, list) or len(pins) == 0:
            raise AttestConstructError("nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root")
        self._pins = pins
        self._firmware = _compile_firmware_policy(opts.get("firmware"))
        self._resolve: Callable[[Dict[str, str], Any], Optional[Dict[str, Any]]] = opts["resolve"]
        self._revocation = opts.get("revocation")
        self._require_crls = opts.get("requireCrls")
        self._require_issuers = opts.get("requireCrlIssuers")

    def __call__(self, ctx: Dict[str, Any]) -> Optional[str]:
        ids = nvidia_rim_ids_for_report(ctx["report"])
        if ids is None:
            return "GPU report does not carry the opaque fields needed to name its RIMs"
        subject = ctx["leaf"].subject
        # the chip name comes from the (signed) report: escaped so no report byte can alter the pattern
        if not re.search("(^|[^A-Za-z0-9])%s([^A-Za-z0-9]|$)" % re.escape(ids["chip"]), subject):
            return "device leaf subject '%s' is not a %s device certificate (chip family mismatch)" % (subject.replace("\n", ", "), ids["chip"])
        fw_why = self._firmware(ids)
        if fw_why:
            return "firmware policy: %s" % fw_why
        bundle = self._resolve(ids, ctx.get("evidence"))
        if bundle is None:
            return "no RIM collateral supplied for this report"
        d = verify_nvidia_rim(bundle.get("driverRimXml"), self._pins, ctx["nowMs"])
        v = verify_nvidia_rim(bundle.get("vbiosRimXml"), self._pins, ctx["nowMs"])
        if not d["ok"]:
            return "driver RIM: %s" % d["reason"]
        if not v["ok"]:
            return "VBIOS RIM: %s" % v["reason"]
        if d["rim"]["product"] != ids["chip"]:
            return "driver RIM product '%s' does not match the GPU chip '%s' (wrong-family manifest)" % (d["rim"]["product"], ids["chip"])
        if v["rim"]["product"] != ids["chip"]:
            return "VBIOS RIM product '%s' does not match the GPU chip '%s' (wrong-family manifest)" % (v["rim"]["product"], ids["chip"])
        if d["rim"]["version"] != ids["driverVersion"]:
            return "driver RIM version '%s' does not match the report's driver '%s'" % (d["rim"]["version"], ids["driverVersion"])
        if v["rim"]["version"].replace(".", "").upper() != ids["vbiosVersion"].replace(".", "").upper():
            return "VBIOS RIM version '%s' does not match the report's VBIOS '%s'" % (v["rim"]["version"], ids["vbiosVersion"])
        cmp = compare_report_to_rims(ctx["report"], d["rim"], v["rim"])
        if not cmp["ok"]:
            return cmp["reason"]
        mode = self._revocation
        if mode is None:
            mode = None if self._require_crls is False else "crl"
        crls = bundle.get("crls") or []
        if len(crls) > 0 or mode == "crl" or mode == "both":
            rev = check_nvidia_chain_revocation(ctx["chain"], crls, ctx["nowMs"], self._require_issuers)
            if not rev["ok"]:
                return "revocation: %s" % rev["reason"]
        ocsp = bundle.get("ocsp") or []
        if len(ocsp) > 0 or mode == "ocsp" or mode == "both":
            o = check_nvidia_chain_ocsp(ctx["chain"], ocsp, ctx["nowMs"])
            if not o["ok"]:
                return "revocation (OCSP): %s" % o["reason"]
        return None


# ------------------------------------------------------------------------------------------------ the verifier


def _default_identity() -> Dict[str, Any]:
    return {"model_id": "", "weights_digest": "", "weights_measured": False, "runtime_measurement": "", "operator": ""}


class NvidiaSpdmVerifier:
    """`verify(document, expected, now_ms)` -> {ok, bound?, reason?, measured?, hostAsserted?}."""

    def __init__(self, opts: Dict[str, Any]) -> None:
        pins = opts.get("rootSpkiSha256")
        if not isinstance(pins, list) or len(pins) == 0:
            raise AttestConstructError("createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)")
        pol = opts.get("policy")
        pol = pol if isinstance(pol, dict) else {}
        meas = pol.get("measurements")
        pinned = list(meas.items()) if isinstance(meas, dict) else []
        self._post_verify = opts.get("postVerify")
        if len(pinned) == 0 and self._post_verify is None:
            raise AttestConstructError(
                "createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)"
            )
        want: List[Tuple[float, str]] = [(js_number(i) if isinstance(i, str) else float(i), js_str(d).lower()) for i, d in pinned]
        for i, _d in want:
            if not _is_int(i) or i < 0 or i > 255:
                raise AttestConstructError("createNvidiaSpdmVerifier: measurement index out of range")
        self._want = [(int(i), d) for i, d in want]
        self._pins = pins
        self._leaf_includes = pol.get("leafSubjectIncludes")
        self._resolve = opts.get("resolve_evidence")

    def verify(self, document: Any, expected: Any, now_ms: Any) -> Dict[str, Any]:
        def fail(reason: str) -> Dict[str, Any]:
            return {"ok": False, "reason": reason}

        try:
            if self._resolve is None:
                return fail("no NVIDIA GPU evidence resolver configured (fail closed)")
            ev = self._resolve(document)
            if not isinstance(ev, dict) or not isinstance(ev.get("evidence"), (bytes, bytearray)) or not isinstance(ev.get("certChainPem"), str):
                return fail("no NVIDIA GPU evidence for this action")
            chain = verify_nvidia_device_chain(ev["certChainPem"], self._pins, now_ms)
            if not chain["ok"]:
                return fail(chain["reason"])
            leaf: Cert = chain["leaf"]
            inc = self._leaf_includes
            if inc and inc not in leaf.subject:
                return fail("device leaf subject does not contain '%s'" % inc)
            try:
                report = parse_nvidia_spdm_evidence(bytes(ev["evidence"]))
            except ValueError as e:
                return fail("GPU attestation report parse failed: %s" % e)
            if not ecdsa_verify_raw(leaf.public_key, report["signature"], report["signedBytes"], "sha384"):
                return fail("GPU attestation report signature does not verify under the device identity key")
            if expected is None:
                return fail("no expected attestation binding supplied")
            try:
                challenge = attestation_challenge_sha256(expected)
            except TypeError as e:
                return fail("binding not constructible: %s" % e)
            if report["request"]["nonce"] != challenge:
                return fail("SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)")
            by_index = {m["index"]: m for m in report["measurements"]}
            for idx, digest_hex in self._want:
                m = by_index.get(idx)
                if m is None:
                    return fail("measurement block %d missing from report" % idx)
                if to_hex(m["digest"]) != digest_hex:
                    return fail("measurement block %d does not match the pinned digest" % idx)
            if self._post_verify is not None:
                why = self._post_verify({"report": report, "chain": chain["chain"], "leaf": leaf, "nowMs": now_ms, "evidence": ev})
                if why:
                    return fail(why)
            h = hashlib.sha384()
            for m in sorted(report["measurements"], key=lambda m: m["index"]):
                h.update(m["digest"])
            host: Dict[str, str] = {"attestation_type": "nvidia-gpu-cc", "gpu_measurements_sha384": h.hexdigest(), "leaf_subject": leaf.subject.replace("\n", ", ")}
            drv = report["opaque"].get(OPAQUE_DRIVER_VERSION)
            vbios = report["opaque"].get(OPAQUE_VBIOS_VERSION)
            if drv is not None:
                host["driver_version"] = re.sub(r"\0+$", "", bytes(drv).decode("utf-8", "replace"))
            if vbios is not None:
                host["vbios_version"] = format_vbios_version(vbios)
            return {"ok": True, "bound": True, "measured": _default_identity(), "hostAsserted": host}
        except Exception as e:
            return fail("nvidia-spdm verification error (fail closed): %s" % e)
