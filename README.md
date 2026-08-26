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
cargo run --release -p host -- prove   # writes artifacts/risc0/receipt.bin
cargo run --release -p host -- size    # size breakdown of that receipt
```

`size` needs only stable Rust and the committed receipt.
