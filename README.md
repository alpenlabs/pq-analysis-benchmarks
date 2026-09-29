# stark-boolean-verifier

Reproducible Boolean-circuit cost estimates for the final compressed STARK
verifiers in Risc0, SP1, and Stwo. SP1's intermediate shrink proof is included
as an additional comparison.

Versions are pinned and proof artifacts are committed under `artifacts/`, so
verification and measurement do not require a prover toolchain.

## Results

Proof size is the verifier input beyond public inputs. Under the free-XOR
model, nonfree gates are AND-type gates and total gates also include XORs. The
Groth16 row is a g16ckt BN254 verifier with one public input and a compressed
proof, including in-circuit decompression. Exact counts are in
`results/gates.json`.

<!-- gates.py: table start -->
| verifier | hash | proof size | nonfree gates\* (billions) | total gates\* (billions) | nonfree vs. groth16 |
|---|---|---:|---:|---:|---:|
| risc0 3.0.5 | poseidon2-babybear | 217.7 KiB | 15.64 | 56.18 | 5.29x |
| risc0, blake3 swap‡ | blake3 | 217.7 KiB | 1.56 | 5.36 | 0.53x |
| sp1 6.3.1 | poseidon2-koalabear | 1.21 MiB | 39.64 | 145.55 | 13.41x |
| sp1 6.3.1, shrink† | poseidon2-koalabear | 870.2 KiB | 28.20 | 103.43 | 9.54x |
| sp1, blake3 swap‡ | blake3 | 1.21 MiB | 3.40 | 12.55 | 1.15x |
| sp1, shrink†, blake3 swap‡ | blake3 | 870.2 KiB | 2.81 | 10.25 | 0.95x |
| stwo 49f8e037 | blake2s | 533.2 KiB | 7.13 | 24.42 | 2.41x |
| stwo, blake3 swap‡ | blake3 | 533.2 KiB | 7.06 | 24.03 | 2.39x |
| groth16 bn254 (baseline) | - | 128 B | 2.96 | 11.25 | 1.00x |

\* Includes field arithmetic, inversion and exponentiation work, and hashes.
Stwo's hinted inverses are priced as in-circuit computations; equality checks
(about 0.05%) and fixed rewiring are not priced.

† Produced by SP1's unmodified prover but not returned by its public API.

‡ Hypothetical one-for-one hash replacement; no such prover or verifier fork
exists.
<!-- gates.py: table end -->

These are shipped parameter sets, not systems normalized to a common security
level.

<!-- gates.py: params start -->
| verifier | field | rate | queries | fold | PoW bits | trace log size | stated security |
|---|---|---:|---:|---:|---:|---:|---|
| risc0 3.0.5 | babybear^4 | 1/4 | 50 | 16 | 0 | 18 | 97 bits, conjectured |
| sp1 6.3.1 | koalabear^4 | 1/4 | 124 | 2 | 16 | 20 | 100 bits, unique decoding |
| sp1 6.3.1, shrink | koalabear^4 | 1/8 | 94 | 2 | 22 | 18 | 100 bits, unique decoding |
| stwo 49f8e037 | m31^4 | 1/2 | 70 | 16 | 26 | 23 | 96 bits, conjectured |
<!-- gates.py: params end -->

The security figures and their stated bases come from each project's source.
Trace size refers to the measured recursion or leaf circuit.

## Reproduce the measurements

Run the same checks as CI against the committed proof artifacts:

```sh
just check
```

This applies the pinned instrumentation patches, verifies the artifacts,
rebuilds the operation ledgers and gadget costs, and checks the generated
results. To recalculate only the summary table from existing result files:

```sh
python3 gates.py
```

The three committed guests are `trivial`, `fib`, and `journal`. Regenerating
proofs requires the corresponding prover toolchain:

| command | requirement | output |
|---|---|---|
| `just prove-risc0` | Risc0 `r0vm` 3.0.5 | `artifacts/risc0/` |
| `just prove-sp1` | SP1 `cargo prove` | `artifacts/sp1/` |
| `just shrink-sp1` | SP1 prover; no guest toolchain | SP1 shrink artifacts |
| `just prove-stwo` | pinned Rust toolchain; about 50 GB RAM for wrapping | `artifacts/stwo/` |

Use `just --list` to see linting, patching, and individual measurement commands.

## Method

Each verifier writes an operation ledger to `results/<system>/ops.json`.
Risc0 and SP1 are instrumented through patches to their pinned field and hash
crates. Stwo's verifier already builds a circuit, so its circuit gate counts
are read directly. Patches live beside each workspace and are applied by its
`patch.sh`.

`gadgets/` measures Boolean costs with the pinned g16ckt instrumentation.
`gates.py` combines those costs with the operation ledgers and updates the
tables above. Hash-swap rows replace hash units one-for-one while leaving field
arithmetic unchanged. Stwo's table result uses Karatsuba extension-field
multiplication; both that result and its native schoolbook alternative are
recorded in `results/gates.json`.

Proofs and keys are checked against `artifacts/manifest.json`. The Stwo leaf
output is also tied to the committed program hash. This ensures measurements
are derived from the expected artifacts before their ledgers are compared.

## Repository layout

| path | purpose |
|---|---|
| `risc0/`, `sp1/`, `stwo/` | pinned verifier and measurement workspaces |
| `gadgets/` | Boolean gadget measurements and Groth16 baseline |
| `artifacts/` | committed proofs, keys, and manifest |
| `results/` | operation ledgers, parameters, sizes, and gate totals |
| `gates.py` | combines measurements and regenerates the result tables |
| `ledger_diff.py` | compares regenerated ledgers with committed results |
