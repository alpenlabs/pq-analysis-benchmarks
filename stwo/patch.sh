#!/usr/bin/env bash
# Fetch the pinned revision of starkware-libs/proving and apply
# patches/proving-<rev>.patch into patched/proving, which Cargo.toml
# substitutes for the git dependencies via
# [patch."https://github.com/starkware-libs/proving"]. The whole monorepo is
# checked out because its crates inherit from the workspace manifest and
# depend on each other by path; only crates/circuits is modified.
set -euo pipefail
cd "$(dirname "$0")"
repo=https://github.com/starkware-libs/proving
rev=49f8e037eb5dcfb587fa46d37c9611ceb6f51f78
rm -rf patched/proving
mkdir -p patched/proving
git -C patched/proving init -q
git -C patched/proving remote add origin "$repo"
git -C patched/proving fetch -q --depth 1 origin "$rev"
git -C patched/proving checkout -q FETCH_HEAD
patch -p1 -d patched/proving < "patches/proving-${rev:0:8}.patch"
