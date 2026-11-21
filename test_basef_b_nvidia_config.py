"""NVIDIA verifier / collateral-hook configuration is typed at construction (reference attest-nvidia-rim.ts / attest-nvidia-spdm.ts):
a malformed firmware policy, deny list, issuer list or leaf-subject filter is refused instead of being silently dropped."""
import pytest

from atlas_pca import attest_nvidia as N
from atlas_pca.attest_amd import AttestConstructError


def hook(**o):
    d = {"rimRootSpkiSha256": ["aa"], "resolve": lambda ids, ev: None}
    d.update(o)
    return N.NvidiaCollateralHook(d)


def refused(text, **o):
    with pytest.raises(AttestConstructError) as e:
        hook(**o)
    assert str(e.value) == text


@pytest.mark.parametrize("bad", ["x", 5, True, False, 0, "", [], [1]])
def test_a_non_object_firmware_is_refused(bad):
    refused("nvidiaCollateralHook: firmware must be an object", firmware=bad)


@pytest.mark.parametrize("ok", [None, {}, {"minDriverVersion": "535.1"}])
def test_absent_or_object_firmware_constructs(ok):
    hook(firmware=ok)
    hook()


@pytest.mark.parametrize("key,bad,shown", [("minDriverVersion", 535, "535"), ("minVbiosVersion", 5, "5"), ("minDriverVersion", True, "true"),
                                           ("minVbiosVersion", {"a": 1}, "{'a': 1}")])
def test_a_present_minimum_must_be_a_string(key, bad, shown):
    refused("nvidiaCollateralHook: malformed %s '%s'" % (key, shown), firmware={key: bad})


@pytest.mark.parametrize("key", ["minDriverVersion", "minVbiosVersion"])
def test_a_falsy_minimum_is_no_minimum(key):
    hook(firmware={key: 0})
    hook(firmware={key: ""})
    hook(firmware={key: None})


@pytest.mark.parametrize("key,what", [("denyDriverVersions", "denyDriverVersions"), ("denyVbiosVersions", "denyVbiosVersions")])
def test_deny_lists_must_be_arrays_of_parseable_strings(key, what):
    refused("nvidiaCollateralHook: malformed %s entry '535.1'" % what, firmware={key: "535.1"})
    refused("nvidiaCollateralHook: malformed %s entry '5'" % what, firmware={key: ["535.1", 5]})
    refused("nvidiaCollateralHook: malformed %s entry 'x'" % what, firmware={key: ["x"]})
    hook(firmware={key: []})
    hook(firmware={key: None})
    hook(firmware={key: ["535.1"]})


@pytest.mark.parametrize("bad", ["NVIDIA GH100", ["a", 1], [None], 5, {"a": "b"}, True])
def test_require_crl_issuers_must_list_only_strings(bad):
    refused("nvidiaCollateralHook: requireCrlIssuers must list only strings", requireCrlIssuers=bad)


@pytest.mark.parametrize("ok", [None, [], ["NVIDIA GH100"]])
def test_require_crl_issuers_accepts_absent_or_string_lists(ok):
    hook(requireCrlIssuers=ok)


@pytest.mark.parametrize("bad", [5, True, ["a"], {"a": 1}])
def test_leaf_subject_includes_must_be_a_string(bad):
    with pytest.raises(AttestConstructError) as e:
        N.NvidiaSpdmVerifier({"rootSpkiSha256": ["aa"], "postVerify": lambda c: None, "policy": {"leafSubjectIncludes": bad}})
    assert str(e.value) == "createNvidiaSpdmVerifier: policy.leafSubjectIncludes must be a string"


@pytest.mark.parametrize("ok", [None, "", "GH100"])
def test_leaf_subject_includes_accepts_absent_or_a_string(ok):
    N.NvidiaSpdmVerifier({"rootSpkiSha256": ["aa"], "postVerify": lambda c: None, "policy": {"leafSubjectIncludes": ok}})
