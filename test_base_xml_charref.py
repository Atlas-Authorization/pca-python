"""XML numeric character references (NVIDIA RIM parser): digits only, no sign or space, no overflow, XML 1.0 Char only; leading zeros are legal."""
import pytest

from atlas_pca.attest_xml import XmlError, _unescape


@pytest.mark.parametrize("ref", ["&#+65;", "&#-65;", "&#x+41;", "&#X-41;", "&#X41;", "&#X10FFFF;", "&# 65;", "&#x 41;", "&#65 ;", "&#;", "&#x;",
                                 "&#99999999999;", "&#x110000;", "&#1114112;"]
                         + ["&#%d;" % n for n in (0, 0x8, 0xB, 0xC, 0xE, 0x1F, 0xD800, 0xDFFF, 0xFFFE, 0xFFFF)]
                         + ["&#x%X;" % n for n in (0, 0x8, 0xB, 0xC, 0xE, 0x1F, 0xD800, 0xDFFF, 0xFFFE, 0xFFFF)])
def test_refused(ref):
    with pytest.raises(XmlError, match="^bad character reference$"):
        _unescape("a" + ref + "b", False)


@pytest.mark.parametrize("ref,ch", [("&#000065;", "A"), ("&#x000041;", "A"), ("&#65;", "A"),
                                    ("&#1114111;", chr(0x10FFFF)), ("&#x10FFFF;", chr(0x10FFFF))]
                         + [("&#%d;" % n, chr(n)) for n in (0x9, 0xA, 0xD, 0x20, 0xD7FF, 0xE000, 0xFFFD, 0x10000)]
                         + [("&#x%x;" % n, chr(n)) for n in (0x9, 0xA, 0xD, 0x20, 0xD7FF, 0xE000, 0xFFFD, 0x10000)])
def test_accepted(ref, ch):
    assert _unescape("a" + ref + "b", False) == "a" + ch + "b"
    assert _unescape(ref, True) == ch
