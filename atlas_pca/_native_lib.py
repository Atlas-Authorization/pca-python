"""Native libraries that ship inside the platform wheels (atlas_pca/_native): the path of a bundled file, or None (pure wheel, sdist,
or a platform with no bundled copy). Loaders try this first, then their environment variable and the system lookup."""
import os

_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_native")


def bundled(*names):
    for n in names:
        p = os.path.join(_DIR, n)
        if os.path.isfile(p):
            return p
    return None
