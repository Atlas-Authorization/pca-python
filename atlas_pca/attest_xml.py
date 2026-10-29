"""A strict XML subset parser and Inclusive Canonical XML (C14N 1.0, identical to C14N 1.1 for documents without `xml:*`
attributes) for the NVIDIA RIM XMLDSig check. Pure standard library.

Accepted: elements, attributes, text, CDATA, the five predefined entities and character references. Comments, processing
instructions (including the XML declaration) and a DOCTYPE are PARSED but recorded as profile violations (the RIM profile
rejects all of them); anything ill-formed raises XmlError.
"""
import re
from typing import Dict, List, Optional, Tuple, Union


class XmlError(Exception):
    pass


_XML_NS = "http://www.w3.org/XML/1998/namespace"
_NAME_START = r"[A-Za-z_:À-˿Ͱ-῿Ⰰ-퟿豈-﷏ﷰ-�]"
_NAME_CHAR = r"[A-Za-z0-9_:.\-·À-˿̀-῿Ⰰ-퟿豈-﷏ﷰ-�]"
_NAME = re.compile(_NAME_START + _NAME_CHAR + "*")
_WS = " \t\r\n"


class Attr:
    __slots__ = ("qname", "prefix", "local", "ns", "value")

    def __init__(self, qname: str, value: str) -> None:
        self.qname = qname
        self.prefix, _, rest = qname.partition(":")
        if rest == "":
            self.prefix, self.local = "", qname
        else:
            self.local = rest
        self.ns = ""
        self.value = value


class Element:
    __slots__ = ("qname", "prefix", "local", "ns", "attrs", "decls", "scope", "children", "parent")

    def __init__(self, qname: str, parent: Optional["Element"]) -> None:
        self.qname = qname
        pre, sep, rest = qname.partition(":")
        if sep:
            self.prefix, self.local = pre, rest
        else:
            self.prefix, self.local = "", qname
        self.ns = ""
        self.attrs: List[Attr] = []  # without namespace declarations
        self.decls: Dict[str, str] = {}  # declared on this element: prefix ('' = default) -> uri
        self.scope: Dict[str, str] = {}  # in scope on this element (after its own declarations), without 'xml'
        self.children: List[Union["Element", str]] = []
        self.parent = parent

    def get_attribute(self, qname: str) -> str:
        for a in self.attrs:
            if a.qname == qname:
                return a.value
        return ""

    def element_children(self, ns: Optional[str] = None, local: Optional[str] = None) -> List["Element"]:
        return [c for c in self.children if isinstance(c, Element) and (ns is None or c.ns == ns) and (local is None or c.local == local)]

    def descendants(self, ns: str, local: str) -> List["Element"]:
        out: List[Element] = []
        for c in self.children:
            if isinstance(c, Element):
                if c.ns == ns and c.local == local:
                    out.append(c)
                out.extend(c.descendants(ns, local))
        return out

    def text_content(self) -> str:
        out: List[str] = []
        for c in self.children:
            out.append(c if isinstance(c, str) else c.text_content())
        return "".join(out)


_ENTITIES = {"lt": "<", "gt": ">", "amp": "&", "quot": '"', "apos": "'"}


def _unescape(s: str, attr: bool) -> str:
    if "&" not in s and not attr:
        return s
    out: List[str] = []
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "&":
            j = s.find(";", i + 1)
            if j < 0:
                raise XmlError("unterminated entity reference")
            ref = s[i + 1:j]
            if ref.startswith("#x") or ref.startswith("#X"):
                if not re.fullmatch(r"[0-9a-fA-F]+", ref[2:]):
                    raise XmlError("bad character reference")
                out.append(chr(int(ref[2:], 16)))
            elif ref.startswith("#"):
                if not re.fullmatch(r"[0-9]+", ref[1:]):
                    raise XmlError("bad character reference")
                out.append(chr(int(ref[1:])))
            elif ref in _ENTITIES:
                out.append(_ENTITIES[ref])
            else:
                raise XmlError("unknown entity &%s;" % ref)
            i = j + 1
            continue
        if attr and ch in "\t\r\n":
            out.append(" ")
        elif ch == "<" and attr:
            raise XmlError("'<' in an attribute value")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


class Document:
    def __init__(self) -> None:
        self.root: Optional[Element] = None
        self.violations: List[str] = []  # in document order


def _skip_ws(s: str, i: int) -> int:
    while i < len(s) and s[i] in _WS:
        i += 1
    return i


def parse_xml(text: str) -> Document:
    doc = Document()
    n = len(text)
    i = 0
    stack: List[Element] = []
    while i < n:
        if text[i] != "<":
            j = text.find("<", i)
            j = n if j < 0 else j
            chunk = text[i:j]
            if not stack:
                if chunk.strip(_WS) != "":
                    raise XmlError("text outside the root element")
            else:
                stack[-1].children.append(_unescape(chunk, False))
            i = j
            continue
        if text.startswith("<!--", i):
            j = text.find("-->", i + 4)
            if j < 0:
                raise XmlError("unterminated comment")
            doc.violations.append("XML comments are not permitted")
            i = j + 3
            continue
        if text.startswith("<![CDATA[", i):
            j = text.find("]]>", i + 9)
            if j < 0 or not stack:
                raise XmlError("bad CDATA section")
            stack[-1].children.append(text[i + 9:j])
            i = j + 3
            continue
        if text.startswith("<?", i):
            j = text.find("?>", i + 2)
            if j < 0:
                raise XmlError("unterminated processing instruction")
            doc.violations.append("XML processing instructions are not permitted")
            i = j + 2
            continue
        if text.startswith("<!", i):
            depth = 0
            j = i + 2
            while j < n:
                c = text[j]
                if c == "[":
                    depth += 1
                elif c == "]":
                    depth -= 1
                elif c == ">" and depth <= 0:
                    break
                j += 1
            if j >= n:
                raise XmlError("unterminated declaration")
            doc.violations.append("DTD / DOCTYPE is not permitted")
            i = j + 1
            continue
        if text.startswith("</", i):
            m = _NAME.match(text, i + 2)
            if not m:
                raise XmlError("bad end tag")
            j = _skip_ws(text, m.end())
            if j >= n or text[j] != ">":
                raise XmlError("bad end tag")
            if not stack or stack[-1].qname != m.group(0):
                raise XmlError("mismatched end tag </%s>" % m.group(0))
            stack.pop()
            i = j + 1
            continue
        # start tag
        m = _NAME.match(text, i + 1)
        if not m:
            raise XmlError("bad start tag")
        parent = stack[-1] if stack else None
        if parent is None and doc.root is not None:
            raise XmlError("more than one root element")
        el = Element(m.group(0), parent)
        j = m.end()
        raw_attrs: List[Tuple[str, str]] = []
        while True:
            k = _skip_ws(text, j)
            if k >= n:
                raise XmlError("unterminated start tag")
            if text[k] == ">" or text.startswith("/>", k):
                break
            if k == j:
                raise XmlError("missing whitespace before an attribute")
            am = _NAME.match(text, k)
            if not am:
                raise XmlError("bad attribute name")
            k = _skip_ws(text, am.end())
            if k >= n or text[k] != "=":
                raise XmlError("attribute without a value")
            k = _skip_ws(text, k + 1)
            if k >= n or text[k] not in "\"'":
                raise XmlError("unquoted attribute value")
            q = text[k]
            e = text.find(q, k + 1)
            if e < 0:
                raise XmlError("unterminated attribute value")
            if any(a == am.group(0) for a, _v in raw_attrs):
                raise XmlError("duplicate attribute %s" % am.group(0))
            raw_attrs.append((am.group(0), _unescape(text[k + 1:e], True)))
            j = e + 1
        self_close = text.startswith("/>", k)
        i = k + (2 if self_close else 1)
        scope = dict(parent.scope) if parent is not None else {}
        for qn, val in raw_attrs:
            if qn == "xmlns":
                el.decls[""] = val
            elif qn.startswith("xmlns:"):
                if val == "":
                    raise XmlError("namespace prefix cannot be undeclared")
                el.decls[qn[6:]] = val
            else:
                el.attrs.append(Attr(qn, val))
        for p, uri in el.decls.items():
            if uri == "" and p == "":
                scope.pop("", None)
            else:
                scope[p] = uri
        el.scope = scope
        if el.prefix:
            if el.prefix not in scope:
                raise XmlError("unbound namespace prefix %s" % el.prefix)
            el.ns = scope[el.prefix]
        else:
            el.ns = scope.get("", "")
        for a in el.attrs:
            if a.prefix == "xml":
                a.ns = _XML_NS
            elif a.prefix:
                if a.prefix not in scope:
                    raise XmlError("unbound namespace prefix %s" % a.prefix)
                a.ns = scope[a.prefix]
            if a.qname.lower().startswith("xml:"):
                doc.violations.append("xml:* attribute '%s' is not permitted (C14N 1.1 profile)" % a.qname)
        if parent is not None:
            parent.children.append(el)
        else:
            doc.root = el
        if not self_close:
            stack.append(el)
    if stack:
        raise XmlError("unclosed element <%s>" % stack[-1].qname)
    if doc.root is None:
        raise XmlError("no root element")
    return doc


# ------------------------------------------------------------------------------------------------ canonical XML


def _enc_text(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\r", "&#xD;")


def _enc_attr(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace('"', "&quot;").replace("\t", "&#x9;").replace("\n", "&#xA;").replace("\r", "&#xD;")


def canonicalize(el: Element, skip: Optional[Element] = None, apex_scope: Optional[Dict[str, str]] = None) -> str:
    """Inclusive C14N of the subtree at `el` (an apex: every in-scope namespace is declared on it). `skip` drops one descendant
    (the enveloped Signature); `apex_scope` overrides the apex's in-scope namespaces."""
    out: List[str] = []
    _render(el, el.scope if apex_scope is None else apex_scope, None, skip, out)
    return "".join(out)


def _render(el: Element, scope: Dict[str, str], parent_out: Optional[Dict[str, str]], skip: Optional[Element], out: List[str]) -> None:
    out.append("<" + el.qname)
    prev = parent_out if parent_out is not None else {}
    ns_out: List[Tuple[str, str]] = []
    for prefix, uri in scope.items():
        if parent_out is None:
            ns_out.append((prefix, uri))
        elif prev.get(prefix) != uri:
            ns_out.append((prefix, uri))
    if parent_out is not None and "" in prev and "" not in scope:
        ns_out.append(("", ""))  # xmlns="" undeclares the inherited default namespace
    for prefix, uri in sorted(ns_out, key=lambda t: t[0]):
        out.append(' xmlns="%s"' % _enc_attr(uri) if prefix == "" else ' xmlns:%s="%s"' % (prefix, _enc_attr(uri)))
    for a in sorted(el.attrs, key=lambda a: (a.ns, a.local)):
        out.append(' %s="%s"' % (a.qname, _enc_attr(a.value)))
    out.append(">")
    for c in el.children:
        if isinstance(c, str):
            out.append(_enc_text(c))
        elif c is not skip:
            _render(c, c.scope, {k: v for k, v in scope.items()}, skip, out)
    out.append("</" + el.qname + ">")
