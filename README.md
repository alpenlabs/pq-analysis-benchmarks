# stark-boolean-verifier

Reproducible measurements of the verifier for the final compressed STARK proof
of three zkVMs: Risc0., SP1 and Stwo.

Versions are pinned. Proof artifacts are committed under `artifacts/`, so
every step except proving runs without a prover toolchain.

Layout: `risc0/`, `sp1/`, `stwo/` hold one Rust workspace each.
Instrumentation of third-party crates is kept as patch files under
`patches/` and applied to the unmodified registry sources at build time.

## Risc0

Install the Risc0 toolchain (`rzup`, providing `r0vm` 3.0.5) following
https://dev.risczero.com/api/zkvm/install. Then:

```sh
cd risc0
cargo run --release -p host -- prove <guest>   # writes artifacts/risc0/<guest>.bin
cargo run --release -p host -- size <guest>    # size breakdown of that receipt
```

Guests: `trivial` (commits one `u32`), `fib` (a few million cycles, several
segments), `journal` (commits 4 KiB). `size` needs only stable Rust and the
committed receipts.

## SP1

Install the SP1 toolchain (`sp1up`, providing `cargo prove`) following
https://docs.succinct.xyz/docs/sp1/getting-started/install. Then:

```sh
cd sp1
cargo run --release -- prove <guest>   # writes artifacts/sp1/<guest>.{bin,vk}
cargo run --release -- size <guest>    # size breakdown of that proof
```

Guests: `trivial` (commits one `u32`), `fib` (a few million cycles, proved
with a 2^22-cycle shard size so it spans several shards), `journal` (commits
4 KiB). Proving runs the CPU prover in-process. `size` needs only stable
Rust and the committed artifacts (build with `SP1_SKIP_PROGRAM_BUILD=true`
to skip the guest build).

## Stwo

The guests are Cairo 0 programs (`stwo/programs/<guest>/<guest>.cairo`),
committed together with their `compiled.json` so only Rust is needed to
prove. To recompile one:

```sh
uvx --from cairo-lang==0.14.0.1 cairo-compile --proof_mode \
    programs/<guest>/<guest>.cairo --output programs/<guest>/compiled.json
```

The Rust toolchain is pinned by `stwo/rust-toolchain.toml` and installed by
rustup on first use.

```sh
cd stwo
RUST_MIN_STACK=8388608 cargo run --release -- prove <guest>   # writes artifacts/stwo/<guest>.bin
RUST_MIN_STACK=8388608 cargo run --release -- size <guest>    # size breakdown of that proof
```

Guests: `trivial` (writes one value to the output). Prover parameters are
in `stwo/params.json`
(`pow_bits` 26, blowup 2, 70 queries, `canonical_small` preprocessed trace).
Stwo has no recursion wrap, so unlike the other two the proof is one STARK
over the whole execution.
