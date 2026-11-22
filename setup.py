"""Pure wheel by default; with ATLAS_PCA_PLATFORM_WHEEL=1 (the release's native-wheel job, after native/libsodium/build.sh filled atlas_pca/_native) a
py3-none-<platform> wheel that carries the bundled libsodium."""
import os

from setuptools import setup

if os.environ.get("ATLAS_PCA_PLATFORM_WHEEL") == "1":
    from setuptools.command.bdist_wheel import bdist_wheel
    from setuptools.dist import Distribution

    class PlatformWheel(bdist_wheel):
        def get_tag(self):
            return "py3", "none", super().get_tag()[2]

    class HasNative(Distribution):
        def has_ext_modules(self):
            return True

    setup(cmdclass={"bdist_wheel": PlatformWheel}, distclass=HasNative)
else:
    setup()
