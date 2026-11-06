#!/usr/bin/env python3
"""Report, for every distribution file, whether PyPI already has it (the publish step skips those) or would get it.

    python .github/scripts/pypi-plan.py [--dry-run] <dir> ...

Reads only the public PyPI JSON API. A file PyPI already has under the same name but with different bytes is an error:
PyPI never accepts a file name twice, so the attested file could never be the one users download.
Exit 0: every file is either new or already on PyPI with the same SHA-256. Exit 1 (outside --dry-run, where both are
only reported): a same-name file with other bytes, or PyPI could not be asked.
"""
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request

API = os.environ.get("PYPI_JSON_API", "https://pypi.org/pypi")


def project_and_version(filename):
    # wheel: {name}-{ver}(-{build})?-{py}-{abi}-{plat}.whl ; sdist: {name}-{ver}.tar.gz (names normalized with "_")
    if filename.endswith(".whl"):
        name, ver = filename.split("-")[:2]
    elif filename.endswith(".tar.gz"):
        name, ver = filename[: -len(".tar.gz")].rsplit("-", 1)
    else:
        return None
    return re.sub(r"[-_.]+", "-", name).lower(), ver


def released_files(project, version, cache):
    key = (project, version)
    if key not in cache:
        url = "%s/%s/%s/json" % (API, project, version)
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "pca-release"}), timeout=30) as r:
                cache[key] = {u["filename"]: u["digests"]["sha256"] for u in json.load(r)["urls"]}
        except urllib.error.HTTPError as e:
            cache[key] = {} if e.code == 404 else None
        except (urllib.error.URLError, OSError, ValueError):
            cache[key] = None
    return cache[key]


def main(argv):
    dry = "--dry-run" in argv
    dirs = [a for a in argv if a != "--dry-run"]
    if not dirs:
        sys.exit(__doc__)
    cache, bad, rows = {}, 0, []
    for d in dirs:
        for f in sorted(os.listdir(d)):
            pv = project_and_version(f)
            if pv is None:
                continue
            with open(os.path.join(d, f), "rb") as fh:
                ours = hashlib.sha256(fh.read()).hexdigest()
            live = released_files(pv[0], pv[1], cache)
            if live is None:
                rows.append((f, "unknown (PyPI did not answer)"))
                bad += not dry
            elif f not in live:
                rows.append((f, "would upload" if dry else "to upload"))
            elif live[f] == ours:
                rows.append((f, "already on PyPI (same bytes): skipped"))
            else:
                rows.append((f, "ON PYPI WITH DIFFERENT BYTES"))
                print("::%s::%s is on PyPI with different bytes" % ("warning" if dry else "error", f))
                bad += not dry
    for f, state in rows:
        print("%-60s %s" % (f, state))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as out:
            out.write("### PyPI%s\n\n| file | state |\n|---|---|\n" % (" (dry run: nothing uploaded)" if dry else ""))
            out.writelines("| %s | %s |\n" % r for r in rows)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main(sys.argv[1:])
