"""Packaging smoke check for a platform wheel: every native library the wheel is expected to carry is there and loads through the
module's own loader. Run with the wheel installed: python -m atlas_pca._native_smoke"""
import sys

from atlas_pca import _native_lib, bls12, fhe_seal, fndsa_native, mpc_lwe_ot, pq_backends, sandbox, sandbox_wasm, zk_native

b = _native_lib.bundled
assert b("libpca_gt.so", "libpca_gt.dylib", "libpca_gt.dll"), "pairing library not bundled"
bls12.lib()
bls12.gt_lib()
assert b("liblweot.so", "liblweot.dylib", "lweot.dll"), "lwe-ot library not bundled"
mpc_lwe_ot._load()
assert b("libfndsa.so", "libfndsa.dylib", "fndsa.dll"), "fndsa library not bundled"
fndsa_native._load()
assert b("libpcazk.so", "libpcazk.dylib", "pcazk.dll"), "zk library not bundled"
assert zk_native.version()
assert b("libsealc.so", "libsealc.dylib", "sealc.dll"), "SEAL library not bundled"
fhe_seal._load()
assert b("libatlas_less.so", "libatlas_less.dylib", "atlas_less.dll"), "LESS library not bundled"
assert pq_backends._libless() is not None, "LESS library did not load"
assert b("pca-wasmtime-host", "pca-wasmtime-host.exe") and b("pca-wasmtime-host.sha256"), "wasmtime host or its pin not bundled"
r = sandbox_wasm.run_component(sandbox.HandleTable("smoke", None, {}), "(component)", fuel=1000)
assert r.get("reason") not in ("host_missing", "host_unpinned", "host_hash_mismatch", "host_unavailable"), r
print("native libraries load:", sys.platform)
