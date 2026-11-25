#!/usr/bin/env bash
# Builds libsodium (the official release, SHA-256 pinned) into <outdir> as libsodium.so / libsodium.dylib / libsodium.dll, the file atlas_pca/_sodium_path.py looks for.
# Windows takes the official prebuilt MSVC DLL (same release, SHA-256 pinned). Usage: build.sh <outdir>
set -euo pipefail
out="${1:?usage: build.sh <outdir>}"
ver=1.0.20
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    curl -fsSL -o "$work/s.zip" "https://download.libsodium.org/libsodium/releases/libsodium-$ver-stable-msvc.zip"
    echo "ebaa204fdfcedc51dc1ee1bbd03c8d552a14b3372f87f94e44c71a8533f77df4  $work/s.zip" | sha256sum -c - >&2
    "${PYTHON:-python}" -m zipfile -e "$work/s.zip" "$work/x"
    cp "$work/x/libsodium/x64/Release/v143/dynamic/libsodium.dll" "$out/libsodium.dll"
    ;;
  *)
    curl -fsSL -o "$work/s.tgz" "https://download.libsodium.org/libsodium/releases/libsodium-$ver.tar.gz"
    echo "ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19  $work/s.tgz" | { sha256sum -c - 2>/dev/null || shasum -a 256 -c -; } >&2
    tar -xzf "$work/s.tgz" -C "$work"
    ( cd "$work/libsodium-stable" && ./configure --disable-static --enable-shared --prefix="$work/p" >&2 && make -j"$(getconf _NPROCESSORS_ONLN)" >&2 && make install >&2 )
    if [ "$(uname -s)" = Darwin ]; then cp -L "$work/p/lib/libsodium.dylib" "$out/libsodium.dylib"; else cp -L "$work/p/lib/libsodium.so" "$out/libsodium.so"; fi
    ;;
esac
ls -l "$out" >&2
