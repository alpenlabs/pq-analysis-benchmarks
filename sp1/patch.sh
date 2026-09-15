#!/usr/bin/env bash
# Fetch the pinned third-party crates from crates.io and apply
# patches/<crate>-<version>.patch into patched/<crate>, which Cargo.toml
# substitutes for the registry crates via [patch.crates-io]. Checksums are the
# ones in Cargo.lock.
set -euo pipefail
cd "$(dirname "$0")"
# crate         version         sha256 (from Cargo.lock)
crates="
p3-field        0.4.3-succinct  3dc75969ca3ac847f43e632ab979d59ff7a68f9eac8dbf8edcbba47fc2e1d3aa
p3-koala-bear   0.4.3-succinct  3a9683cd0ef68100df7c62490533047bcf19c04c4a0fa1efc9d7c1e03e31f6b3
p3-symmetric    0.4.3-succinct  9047ce85c086a9b3f118e10078f10636f7bfeed5da871a04da0b61400af8793a
p3-challenger   0.4.3-succinct  b6a908924d43e4cfb93fb41c8346cac211b70314385a9037e9241f5b7f3eaf77
sp1-prover      6.3.1           ee3b14f599150ddbd3d3829ec4080dc9e10d6dac66e9741260d5a5a116fbcb02
"
mkdir -p patched
echo "$crates" | while read -r crate version sha256; do
    [ -n "$crate" ] || continue
    curl -sSL -o "patched/$crate-$version.crate" "https://static.crates.io/crates/$crate/$crate-$version.crate"
    echo "$sha256  patched/$crate-$version.crate" | shasum -a 256 -c -
    rm -rf "patched/$crate"
    tar xzf "patched/$crate-$version.crate" -C patched
    mv "patched/$crate-$version" "patched/$crate"
    patch -p1 -d "patched/$crate" < "patches/$crate-$version.patch"
done
