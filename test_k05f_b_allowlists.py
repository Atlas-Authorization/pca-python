"""A present policy allowlist that is not an array of strings is refused at construction (`<ctor>: policy.<key> must be an array of
strings`): before, `hostData: "aa"` read as "no list" and the check silently widened to accept-all."""
import pytest

from atlas_pca.attest_amd import AmdSnpVerifier, AttestConstructError
from atlas_pca.attest_azure import AzureMaaVerifier
from atlas_pca.attest_gcp import GcpConfidentialSpaceVerifier
from atlas_pca.attest_intel import IntelDcapVerifier

AMD = {"family": "genoa", "binding": "report-data", "policy": {"measurements": ["00" * 48]}}
INTEL = {"binding": "report-data", "policy": {"mrtds": ["00" * 48]}}
AZ = {"trustedIssuers": ["https://maa.example"], "trustAnchors": {"rootSpkiSha256": ["aa"]}, "policy": {"tdxMrtds": ["aa"]}}
GCP = {"trustedIssuers": ["https://gcp.example"], "trustAnchors": {"trustedKeySpki": ["aa"]}, "policy": {"imageDigests": ["sha256:aa"]}}

CASES = [
    (AmdSnpVerifier, AMD, "createAmdSnpVerifier", "hostData", None),
    (AmdSnpVerifier, AMD, "createAmdSnpVerifier", "chipIds", None),
    (IntelDcapVerifier, INTEL, "createIntelDcapVerifier", "fmspcs", None),
    (IntelDcapVerifier, INTEL, "createIntelDcapVerifier", "rtmrs", None),
    (IntelDcapVerifier, INTEL, "createIntelDcapVerifier", "acceptStatuses", "collateral"),
    (AzureMaaVerifier, AZ, "createAzureMaaVerifier", "sevSnpHostData", None),
    (AzureMaaVerifier, AZ, "createAzureMaaVerifier", "tdxRtmrs", None),
    (AzureMaaVerifier, AZ, "createAzureMaaVerifier", "tdxAllowedTcbStatuses", None),
    (GcpConfidentialSpaceVerifier, GCP, "createGcpConfidentialSpaceVerifier", "allowedTeeTypes", None),
    (GcpConfidentialSpaceVerifier, GCP, "createGcpConfidentialSpaceVerifier", "allowedSwVersions", None),
]


def build(cls, base, key, nest, value):
    pol = dict(base["policy"])
    if nest:
        pol[nest] = {key: value}
    else:
        pol[key] = value
    return cls(dict(base, policy=pol))


def text(ctor, key, nest):
    return "%s: policy.%s%s must be an array of strings" % (ctor, nest + "." if nest else "", key)


@pytest.mark.parametrize("cls,base,ctor,key,nest", CASES)
@pytest.mark.parametrize("bad", ["aa", 5, {"a": "b"}, ["aa", 1], [None], True, False, 0, ""])
def test_a_non_array_of_strings_is_refused(cls, base, ctor, key, nest, bad):
    with pytest.raises(AttestConstructError) as e:
        build(cls, base, key, nest, bad)
    assert str(e.value) == text(ctor, key, nest)


@pytest.mark.parametrize("cls,base,ctor,key,nest", CASES)
@pytest.mark.parametrize("ok", [None, [], ["aa"], ["aa", "bb"]])
def test_absent_null_and_string_arrays_construct(cls, base, ctor, key, nest, ok):
    if ok == [] and key == "allowedTeeTypes":
        pytest.skip("an empty allowedTeeTypes list has its own refusal")
    build(cls, base, key, nest, ok)


@pytest.mark.parametrize("cls,base,ctor,key,nest", CASES)
def test_an_absent_key_constructs(cls, base, ctor, key, nest):
    cls(dict(base))


@pytest.mark.parametrize("bad", ["x", 5, True, False, 0, "", [], [{}]])
def test_a_non_object_intel_collateral_policy_is_refused(bad):
    with pytest.raises(AttestConstructError) as e:
        build(IntelDcapVerifier, INTEL, "collateral", None, bad)
    assert str(e.value) == "createIntelDcapVerifier: policy.collateral must be an object"


@pytest.mark.parametrize("ok", [None, {}, {"minTcbEvaluationDataNumber": 7}])
def test_an_object_or_absent_intel_collateral_policy_constructs(ok):
    build(IntelDcapVerifier, INTEL, "collateral", None, ok)
