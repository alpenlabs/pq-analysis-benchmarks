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
cargo run --release -- prove   # writes artifacts/sp1/trivial.{bin,vk}
cargo run --release -- size    # size breakdown of that proof
```

Proving runs the CPU prover in-process. `size` needs only stable Rust and
the committed artifacts (build with `SP1_SKIP_PROGRAM_BUILD=true` to skip
the guest build).
