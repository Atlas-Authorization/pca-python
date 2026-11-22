# Extracted goal kernel (generated, do not edit)

This directory holds the Python translation of the Dafny-proved goal compiler (`formal/dafny/Goal.dfy` in the flagship
repository), produced with the pinned Dafny (`formal/dafny/TOOLCHAIN.lock`) by `formal/dafny/build-native.sh py`.
CI produces it: the "Goal kernel native extractions" workflow translates the same sources, fails when the files committed here
differ from a fresh translation, and uploads the fresh translation as an artifact to commit.

`atlas_pca.goal_kernel` loads it from here. Until it is committed, every kernel call raises `GoalKernelUnavailable`
(there is no fallback) and `test_ref_goal_kernel.py` skips its kernel tests (set `PCA_GOAL_KERNEL_REQUIRE=1` to make them fail).
Only this README is written by hand; `build-native.sh` keeps it and replaces every other file.
