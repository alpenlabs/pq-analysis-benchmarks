# Rust workspaces in this repository; extend as sp1/ and stwo/ are added.
workspaces := "risc0 sp1 stwo gadgets"

# Show available commands
default:
    @just --list

# Run a cargo command in every workspace
[private]
each +args:
    #!/usr/bin/env bash
    set -euo pipefail
    for ws in {{workspaces}}; do
        [ ! -x "$ws/patch.sh" ] || [ -d "$ws/patched" ] || "./$ws/patch.sh"
        echo "== $ws"
        (cd "$ws" && RISC0_SKIP_BUILD=1 SP1_SKIP_PROGRAM_BUILD=true cargo {{args}})
    done

# Check formatting
[group('code-quality')]
fmt-check-ws:
    @just each fmt --all --check

# Format source code
[group('code-quality')]
fmt-ws:
    @just each fmt --all

# Run clippy
[group('code-quality')]
lint-check-ws:
    @just each clippy --workspace --locked --all-targets -- -D warnings

# Run clippy and apply fixes
[group('code-quality')]
lint-fix-ws:
    @just each clippy --workspace --locked --all-targets --fix --allow-dirty --allow-staged -- -D warnings

# Check formatting of TOML files
[group('code-quality')]
fmt-check-toml: ensure-taplo
    taplo fmt --check

# Format TOML files
[group('code-quality')]
fmt-toml: ensure-taplo
    taplo fmt

# Lint TOML files
[group('code-quality')]
lint-check-toml: ensure-taplo
    taplo lint

# Check spelling
[group('code-quality')]
lint-check-codespell: ensure-codespell
    codespell

# Fix spelling
[group('code-quality')]
lint-fix-codespell: ensure-codespell
    codespell -w

# Run all lints and checks without fixing
[group('code-quality')]
lint: fmt-check-ws fmt-check-toml lint-check-toml lint-check-ws lint-check-codespell
    @echo "OK: lints and formatting"

# Run all lints and apply fixes where possible
[group('code-quality')]
lint-fix: fmt-toml fmt-ws lint-fix-ws lint-fix-codespell
    @echo "OK: lints and formatting fixes"

# Re-derive the committed results from the committed artifacts (what CI runs)
[group('check')]
check: patch-risc0 patch-sp1 patch-stwo
    #!/usr/bin/env bash
    set -euo pipefail
    cd risc0
    for g in trivial fib journal; do
        RISC0_SKIP_BUILD=1 cargo run --release --locked -p host -- size "$g" "size-$g.json"
        diff "size-$g.json" ../results/risc0/size.json
        RISC0_SKIP_BUILD=1 cargo run --release --locked -p host -- count "$g" "count-$g.json"
        python3 ../ledger_diff.py "count-$g.json" ../results/risc0/ops.json
        RISC0_SKIP_BUILD=1 cargo run --release --locked -p host -- params "$g" "params-$g.json"
        diff "params-$g.json" ../results/risc0/params.json
    done
    cd ../sp1
    for g in trivial fib journal; do
        SP1_SKIP_PROGRAM_BUILD=true cargo run --release --locked -- size "$g" "size-$g.json"
        diff "size-$g.json" ../results/sp1/size.json
        SP1_SKIP_PROGRAM_BUILD=true cargo run --release --locked -- count "$g" "count-$g.json"
        python3 ../ledger_diff.py "count-$g.json" ../results/sp1/ops.json
        SP1_SKIP_PROGRAM_BUILD=true cargo run --release --locked -- params "$g" "params-$g.json"
        diff "params-$g.json" ../results/sp1/params.json
        SP1_SKIP_PROGRAM_BUILD=true cargo run --release --locked -- shrink-size "$g" "shrink-size-$g.json"
        diff "shrink-size-$g.json" ../results/sp1/shrink/size.json
        SP1_SKIP_PROGRAM_BUILD=true cargo run --release --locked -- shrink-count "$g" "shrink-count-$g.json"
        python3 ../ledger_diff.py "shrink-count-$g.json" ../results/sp1/shrink/ops.json
        SP1_SKIP_PROGRAM_BUILD=true cargo run --release --locked -- shrink-params "$g" "shrink-params-$g.json"
        diff "shrink-params-$g.json" ../results/sp1/shrink/params.json
    done
    cd ../stwo
    for g in trivial fib journal; do
        RUST_MIN_STACK=8388608 cargo run --release --locked -- size "$g"
        RUST_MIN_STACK=8388608 cargo run --release --locked -- size "$g.leaf" "size-$g.json"
        diff "size-$g.json" ../results/stwo/size.json
        RUST_MIN_STACK=8388608 cargo run --release --locked -- count "$g" "count-$g.json"
        diff "count-$g.json" ../results/stwo/ops.json
        RUST_MIN_STACK=8388608 cargo run --release --locked -- params "$g" "params-$g.json"
        diff "params-$g.json" ../results/stwo/params.json
    done
    cd ../gadgets
    cargo run --release --locked -- gadgets.json
    diff gadgets.json ../results/gadgets.json
    cd ..
    python3 gates.py
    git diff --exit-code results/gates.json README.md

# Measure the Boolean gate costs with g16ckt and write results/gadgets.json
[group('check')]
gadgets:
    cd gadgets && cargo run --release --locked

# Fetch risc0-core and apply patches/risc0-core-3.0.2.patch into risc0/patched/
[group('prerequisites')]
patch-risc0:
    ./risc0/patch.sh

# Fetch the Plonky3 crates and apply sp1/patches/ into sp1/patched/
[group('prerequisites')]
patch-sp1:
    ./sp1/patch.sh

# Fetch the pinned starkware-libs/proving revision and apply stwo/patches/ into stwo/patched/
[group('prerequisites')]
patch-stwo:
    ./stwo/patch.sh

# Prove the Risc0 guests and write artifacts/risc0/<guest>.bin (needs r0vm)
[group('prove')]
prove-risc0: patch-risc0
    #!/usr/bin/env bash
    set -euo pipefail
    cd risc0
    for g in trivial fib journal; do
        cargo run --release -p host -- prove "$g"
    done

# Prove the SP1 guests and write artifacts/sp1/<guest>.{bin,vk} (needs cargo prove)
[group('prove')]
prove-sp1: patch-sp1
    #!/usr/bin/env bash
    set -euo pipefail
    cd sp1
    for g in trivial fib journal; do
        cargo run --release -- prove "$g"
    done

# Take the committed SP1 compressed proofs through the shrink stage and write
# artifacts/sp1/<guest>.shrink.bin and artifacts/sp1/shrink.vk. Needs a prover
# but not a guest toolchain: it reads the committed proofs, so it can be re-run
# without re-proving.
[group('prove')]
shrink-sp1: patch-sp1
    #!/usr/bin/env bash
    set -euo pipefail
    cd sp1
    for g in trivial fib journal; do
        SP1_SKIP_PROGRAM_BUILD=true cargo run --release -- shrink "$g"
    done

# Prove the Stwo guests and write artifacts/stwo/<guest>.bin
[group('prove')]
prove-stwo: patch-stwo
    #!/usr/bin/env bash
    set -euo pipefail
    cd stwo
    for g in trivial fib journal; do
        RUST_MIN_STACK=8388608 cargo run --release -- prove "$g"
        RUST_MIN_STACK=8388608 cargo run --release -- wrap "$g"
    done

# Check if taplo is installed
[group('prerequisites')]
ensure-taplo:
    #!/usr/bin/env bash
    if ! command -v taplo &> /dev/null; then
        echo "taplo not found: https://taplo.tamasfe.dev/cli/installation/binary.html"
        exit 1
    fi

# Check if codespell is installed
[group('prerequisites')]
ensure-codespell:
    #!/usr/bin/env bash
    if ! command -v codespell &> /dev/null; then
        echo "codespell not found: pip install codespell"
        exit 1
    fi
