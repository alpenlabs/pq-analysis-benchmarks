#!/usr/bin/env bash
# Fetch the pinned risc0-core crate from crates.io and apply
# patches/risc0-core-3.0.2.patch into patched/risc0-core, which Cargo.toml
# substitutes for the registry crate via [patch.crates-io].
set -euo pipefail
cd "$(dirname "$0")"
crate=risc0-core-3.0.2
sha256=d6eb2d2b2c6cac0e43cbb2202daacee1a2f24d0dfa03fd08887a11dc6defdcc1  # as in Cargo.lock
mkdir -p patched
curl -sSL -o "patched/$crate.crate" "https://static.crates.io/crates/risc0-core/$crate.crate"
echo "$sha256  patched/$crate.crate" | shasum -a 256 -c -
rm -rf patched/risc0-core
tar xzf "patched/$crate.crate" -C patched
mv "patched/$crate" patched/risc0-core
patch -p1 -d patched/risc0-core < "patches/$crate.patch"
