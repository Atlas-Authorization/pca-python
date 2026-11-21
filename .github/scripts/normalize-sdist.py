#!/usr/bin/env python3
"""Make sdists neutral and reproducible, or check that they are.

    python .github/scripts/normalize-sdist.py dist/*.tar.gz          rewrite each sdist in place
    python .github/scripts/normalize-sdist.py --check dist/*.tar.gz  exit 1 if any sdist is not normalized

setuptools writes the building account into every tar header (uid/gid and the user and group NAMES), and the file
mtimes of the checkout. The rewrite keeps every member's name, type, mode and bytes and sets:
  uid = gid = 0, uname = gname = "" (no account name), mtime = SOURCE_DATE_EPOCH (the tagged commit's time),
  members in sorted order, no PAX owner/time records, gzip header without a file name or time.
Two builds of the same commit then produce byte-identical sdists, and no account name ships.
"""
import gzip
import io
import os
import sys
import tarfile

OWNER_PAX = ("uid", "gid", "uname", "gname", "mtime", "atime", "ctime")


def epoch():
    v = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if not v.isdigit():
        sys.exit("normalize-sdist: set SOURCE_DATE_EPOCH (e.g. the tagged commit's time: git log -1 --format=%ct)")
    return int(v)


def problems(path, when):
    out = []
    with tarfile.open(path, "r:gz") as t:
        names = []
        for m in t.getmembers():
            names.append(m.name)
            if m.uid or m.gid or m.uname or m.gname:
                out.append("%s: owner fields set" % m.name)
            if when is not None and int(m.mtime) != when:
                out.append("%s: mtime %d != SOURCE_DATE_EPOCH" % (m.name, int(m.mtime)))
            if any(k in m.pax_headers for k in OWNER_PAX):
                out.append("%s: PAX owner/time record" % m.name)
        if names != sorted(names):
            out.append("members not in sorted order")
    with open(path, "rb") as f:
        head = f.read(10)
    if head[4:8] != b"\0\0\0\0":
        out.append("gzip header carries a timestamp")
    return out


def normalize(path, when):
    with tarfile.open(path, "r:gz") as src:
        members = sorted(src.getmembers(), key=lambda m: m.name)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as dst:
            for m in members:
                data = src.extractfile(m) if m.isfile() else None
                m.uid = m.gid = 0
                m.uname = m.gname = ""
                m.mtime = when
                m.pax_headers = {k: v for k, v in m.pax_headers.items() if k not in OWNER_PAX}
                dst.addfile(m, data)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        with gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0) as g:
            g.write(buf.getvalue())
    os.replace(tmp, path)


def main(argv):
    check = "--check" in argv
    files = [a for a in argv if a != "--check"]
    if not files:
        sys.exit(__doc__)
    when = epoch()
    bad = 0
    for path in files:
        if not path.endswith(".tar.gz"):
            continue
        if check:
            p = problems(path, when)
            for line in p[:10]:
                print("%s: %s" % (os.path.basename(path), line))
            bad += bool(p)
            print("%s %s" % ("FAIL" if p else "ok  ", os.path.basename(path)))
        else:
            normalize(path, when)
            print("normalized %s" % os.path.basename(path))
    if bad:
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
