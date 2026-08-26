# stark-boolean-verifier

Reproducible measurements of the verifier for the final compressed STARK proof
of three zkVMs: Risc0., SP1 and Stwo.

Versions are pinned. Proof artifacts are committed under `artifacts/`, so
every step except proving runs without a prover toolchain.

Layout: `risc0/`, `sp1/`, `stwo/` hold one Rust workspace each.
Instrumentation of third-party crates is kept as patch files
(`<workspace>/patches/`) and applied by `<workspace>/patch.sh` to the
unmodified crates.io sources, which Cargo then uses via `[patch.crates-io]`.
`just check` re-derives everything under `results/` from the committed
artifacts.

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

```sh
./patch.sh                                     # once; fetches risc0-core 3.0.2 and applies patches/
cargo run --release -p host -- count <guest>   # writes results/risc0/ops.json
```

`count` verifies the receipt and writes an operation ledger. Poseidon2
permutations are counted by a `poseidon2` hash suite injected through
`VerifierContext`, per `HashFn`/`Rng` method, without modifying the
verifier (`risc0/host/src/count.rs`). BabyBear operations are counted by
`patches/risc0-core-3.0.2.patch`, which adds a counter to each `Elem`
operator impl and to `pow`/`inv` (extension-field operations decompose
into base operations; Montgomery conversions are not counted). The hash
suite snapshots the counters around every call it forwards, so the ledger
separates `in_hash_suite` (the permutations, which are BabyBear arithmetic
themselves) from `residual` (the rest of the verifier) by measurement;
`mul_per_permutation` must come out an integer. Multiplications inside
`pow` are listed as a call count rather than a multiplication count: `pow`
is square-and-multiply and the verifier raises generators to Fiat-Shamir
derived query positions, so that number varies with the seal (by a few
hundred out of 687 thousand). Poseidon2 is the hash the shipped verifier
uses; the split is what allows a different hash to be costed in its place.
The ledger is the same for every guest, since the succinct receipt proves
the fixed recursion circuit; CI diffs each guest's output against the
committed file.

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

```sh
./patch.sh                              # once; fetches the pinned Plonky3 crates and applies patches/
cargo run --release -- count <guest>    # writes results/sp1/ops.json
```

`count` verifies the proof with `LightProver` and writes the operation
ledger. SP1 has no hash-suite injection point, so the counters are patches
to the Plonky3 crates it uses: `p3-field` holds the counters and instruments
`exp_u64_by_squaring`; `p3-koala-bear` counts `Add`/`Sub`/`Mul`/`Sum` and
`try_inverse`; `p3-symmetric` and `p3-challenger` count the permutations
performed by `TruncatedPermutation::compress`, `PaddingFreeSponge` and
`DuplexChallenger`, and attribute the field operations inside each to the
hash. The ledger has the same shape as Risc0's, with `mul_per_permutation`
(296 for this Poseidon2: width 16, `x^3`) as the integrality check.

## Stwo

The guests are Cairo 0 programs (`stwo/programs/<guest>/<guest>.cairo`),
committed together with their `compiled.json` so only Rust is needed to
prove. To recompile one:

```sh
uvx --from cairo-lang==0.14.0.1 cairo-compile --proof_mode \
    programs/<guest>/<guest>.cairo --output programs/<guest>/compiled.json
```

The prover crates are pinned to a revision of `starkware-libs/proving`, the
monorepo that superseded `stwo-cairo` in July 2026. The Rust toolchain is
pinned by `stwo/rust-toolchain.toml` and installed by rustup on first use.

```sh
cd stwo
RUST_MIN_STACK=8388608 cargo run --release -- prove <guest>   # writes artifacts/stwo/<guest>.bin
RUST_MIN_STACK=8388608 cargo run --release -- size <guest>    # size breakdown of that proof
```

Guests: `trivial` (writes one value to the output), `fib` (100,000
recursive steps; sized to stay under the 2^20-row limit of the
`canonical_small` preprocessed trace), `journal` (writes 1,024 values to
the output). Prover parameters are in `stwo/params.json`
(`pow_bits` 26, blowup 2, 70 queries, `canonical_small` preprocessed trace).
The flat proof is one STARK over the whole execution, so its size scales
with the populated AIR columns. The constant-size artifact is the leaf
circuit proof of upstream's recursion: the guest runs as a task of the leaf
bootloader (`stwo/leaf/`), its Cairo proof is verified inside the leaf
verifier circuit, and that circuit is proved. The circuit is fixed by the
registry (`stwo/leaf/circuit_registry.json`, the `canonical_small` registry
with Cairo trace log size 20), so the leaf proof has the same size and circuit
hash for every guest that fits.

```sh
RUST_MIN_STACK=8388608 cargo run --release -- wrap <guest>        # writes artifacts/stwo/<guest>.leaf.json
RUST_MIN_STACK=8388608 cargo run --release -- size <guest>.leaf   # size and verification
```

`wrap` needs about 30 GB of memory and takes about 20 s per guest.
