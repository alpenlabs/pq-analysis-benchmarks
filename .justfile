# Rust workspaces in this repository; extend as sp1/ and stwo/ are added.
workspaces := "risc0 sp1 stwo"

# Show available commands
default:
    @just --list

# Run a cargo command in every workspace
[private]
each +args:
    #!/usr/bin/env bash
    set -euo pipefail
    for ws in {{workspaces}}; do
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
check:
    #!/usr/bin/env bash
    set -euo pipefail
    cd risc0
    for g in trivial fib journal; do
        RISC0_SKIP_BUILD=1 cargo run --release --locked -p host -- size "$g"
    done
    cd ../sp1
    for g in trivial fib journal; do
        SP1_SKIP_PROGRAM_BUILD=true cargo run --release --locked -- size "$g"
    done
    cd ../stwo
    RUST_MIN_STACK=8388608 cargo run --release --locked -- size trivial

# Prove the Risc0 guests and write artifacts/risc0/<guest>.bin (needs r0vm)
[group('prove')]
prove-risc0:
    #!/usr/bin/env bash
    set -euo pipefail
    cd risc0
    for g in trivial fib journal; do
        cargo run --release -p host -- prove "$g"
    done

# Prove the SP1 guests and write artifacts/sp1/<guest>.{bin,vk} (needs cargo prove)
[group('prove')]
prove-sp1:
    #!/usr/bin/env bash
    set -euo pipefail
    cd sp1
    for g in trivial fib journal; do
        cargo run --release -- prove "$g"
    done

# Prove the Stwo guest and write artifacts/stwo/trivial.bin
[group('prove')]
prove-stwo:
    cd stwo && RUST_MIN_STACK=8388608 cargo run --release -- prove trivial

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
