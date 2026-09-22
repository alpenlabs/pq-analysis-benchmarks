//! `prove <guest>`: run the guest and write a compressed proof and verifying key to
//! `artifacts/sp1/<guest>.{bin,vk}`.
//! `size <guest> [out]`: read them back and report the serialized size per component;
//!                  write the proof size without public inputs as JSON (default
//!                  `results/sp1/size.json`; it is the same for every guest).
//! `count <guest> [out]`: verify the proof with the patched Plonky3 crates and
//!                  write the operation ledger as JSON (default
//!                  `results/sp1/ops.json`; it is the same for every guest).
//!
//! `shrink <guest>`: take the committed compressed proof through SP1's shrink
//!                  stage and write the result to `artifacts/sp1/<guest>.shrink.bin`
//!                  and the shrink verifying key to `artifacts/sp1/shrink.vk`.
//!                  Needs a prover; the other shrink commands read what it wrote.
//! `shrink-size`, `shrink-count`, `shrink-params <guest> [out]`: the same three
//!                  measurements for the shrink proof, into
//!                  `results/sp1/shrink/{size,ops,params}.json`.
//!
//! Guests: trivial, fib, journal.

use anyhow::{bail, Context, Result};
use p3_field::counters as c;
use p3_field::PrimeField32;
use serde::Serialize;
use sp1_hypercube::{MachineVerifyingKey, SP1PcsProofInner, SP1RecursionProof};
use sp1_primitives::fri_params::{
    recursion_fri_config, shrink_fri_config, SP1_SHRINK_WRAP_POW_BITS, SP1_TARGET_BITS_OF_SECURITY,
};
use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext};
use sp1_prover::verify::SP1Verifier;
use sp1_prover::worker::cpu_worker_builder;
use sp1_prover::{SHRINK_LOG_STACKING_HEIGHT, SHRINK_MAX_LOG_ROW_COUNT};
use sp1_sdk::blocking::{LightProver, ProveRequest, Prover, ProverClient};
use sp1_sdk::prover::ProvingKey;
use sp1_sdk::{Elf, HashableKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};
use sp1_verifier::VerifierRecursionVks;

/// Shard size (cycles) used when proving `fib`; the default is 2^24, which
/// would fit it in one shard.
const FIB_SHARD_SIZE: u64 = 1 << 22;

/// Reads the guest ELF that `build.rs` (sp1-build) compiles into the guest's
/// target directory. It is read at run time rather than embedded with
/// `include_elf!` so that the script compiles without the guest toolchain
/// (`SP1_SKIP_PROGRAM_BUILD=true`), which is how `size`, `count` and `params`
/// run in CI.
fn elf(name: &str) -> Result<Elf> {
    if !["trivial", "fib", "journal"].contains(&name) {
        bail!("unknown guest {name}");
    }
    let path = format!(
        "../programs/{name}/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/{name}"
    );
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading guest ELF {path} (build the guests with `cargo prove build` or without SP1_SKIP_PROGRAM_BUILD)"))?;
    Ok(Elf::from(bytes))
}

fn paths(name: &str) -> (String, String) {
    (
        format!("../artifacts/sp1/{name}.bin"),
        format!("../artifacts/sp1/{name}.vk"),
    )
}

const MANIFEST: &str = "../artifacts/manifest.json";

fn read_artifact(name: &str) -> Result<(SP1ProofWithPublicValues, SP1VerifyingKey)> {
    let (proof_path, vk_path) = paths(name);
    let proof = SP1ProofWithPublicValues::load(&proof_path)?;
    let vk: SP1VerifyingKey = bincode::deserialize(&std::fs::read(&vk_path)?)?;
    Ok((proof, vk))
}

/// Checks a verifying key's hash against the `sp1/<key>/vk_hash` entry of
/// `artifacts/manifest.json`.
fn check_manifest_hash(key: &str, hash: String) -> Result<()> {
    let manifest: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(MANIFEST)?)?;
    let expected = manifest["sp1"][key]["vk_hash"].as_str().ok_or_else(|| {
        anyhow::anyhow!("no sp1/{key} entry in {MANIFEST}; the committed vk hashes to {hash}")
    })?;
    if hash != expected {
        bail!("sp1/{key}: vk hash {hash} != manifest {expected}");
    }
    Ok(())
}

/// Checks the committed verifying key's hash against `artifacts/manifest.json`
/// (written by `prove`).
fn check_manifest(name: &str, vk: &SP1VerifyingKey) -> Result<()> {
    check_manifest_hash(name, vk.bytes32())
}

/// Checks the committed shrink verifying key against `artifacts/manifest.json`
/// (written by `shrink`). The key is also pinned by SP1 itself: `verify_shrink`
/// checks its membership in the recursion vk tree whose root `sp1-verifier`
/// ships. This catches a swapped file first, with a clearer error.
fn check_shrink_manifest(vk: &MachineVerifyingKey<SP1GlobalContext>) -> Result<()> {
    check_manifest_hash("shrink", vk.bytes32())
}

/// Loads the committed proof and verifying key of `name`, verifies the proof
/// against the key, and checks the key against the manifest.
fn load_artifact(name: &str) -> Result<(SP1ProofWithPublicValues, SP1VerifyingKey)> {
    let (proof, vk) = read_artifact(name)?;
    // LightProver verifies without building proving keys.
    LightProver::new().verify(&proof, &vk, None)?;
    check_manifest(name, &vk)?;
    Ok((proof, vk))
}

fn prove(name: &str) -> Result<()> {
    let elf = elf(name)?;
    let (proof_path, vk_path) = paths(name);
    let shard_size = match name {
        "fib" => FIB_SHARD_SIZE,
        _ => 1 << 24,
    };
    std::env::set_var("SHARD_SIZE", shard_size.to_string());
    let client = ProverClient::from_env();
    let (_, report) = client.execute(elf.clone(), SP1Stdin::new()).run()?;
    let cycles = report.total_instruction_count();
    println!(
        "{name}: {cycles} cycles, shard size {shard_size}, {} shards",
        cycles.div_ceil(shard_size)
    );
    let pk = client.setup(elf)?;
    let vk = pk.verifying_key().clone();
    let proof = client.prove(&pk, SP1Stdin::new()).compressed().run()?;
    client.verify(&proof, &vk, None)?;
    proof.save(&proof_path)?;
    std::fs::write(&vk_path, bincode::serialize(&vk)?)?;
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(MANIFEST)?)?;
    manifest["sp1"][name]["vk_hash"] = vk.bytes32().into();
    std::fs::write(
        MANIFEST,
        format!("{}\n", serde_json::to_string_pretty(&manifest)?),
    )?;
    Ok(())
}

fn len<T: Serialize>(v: &T) -> Result<usize> {
    Ok(bincode::serialized_size(v)? as usize)
}

#[derive(Serialize)]
struct Size {
    /// Bytes a verifier needs beyond the public inputs: the shard proof
    /// without its public values, the recursion vk and its Merkle proof.
    /// Excludes public_values, sp1_version and tee_proof.
    proof_bytes: usize,
    components: std::collections::BTreeMap<&'static str, usize>,
}

fn size(name: &str, out: &str) -> Result<()> {
    let (proof_path, vk_path) = paths(name);
    let (proof, _vk) = load_artifact(name)?;
    let p = match &proof.proof {
        SP1Proof::Compressed(p) => p,
        _ => bail!("expected a compressed proof"),
    };
    let s = &p.proof;
    let e = &s.evaluation_proof;
    let b = &e.pcs_proof.basefold_proof;
    let rows = [
        ("shard proof: public_values", len(&s.public_values)?),
        ("shard proof: main_commitment", len(&s.main_commitment)?),
        ("shard proof: logup_gkr_proof", len(&s.logup_gkr_proof)?),
        ("shard proof: zerocheck_proof", len(&s.zerocheck_proof)?),
        ("shard proof: opened_values", len(&s.opened_values)?),
        ("shard proof: evaluation_proof", len(e)?),
        ("  pcs_proof (stacked BaseFold)", len(&e.pcs_proof)?),
        ("    fri_commitments", len(&b.fri_commitments)?),
        (
            "    component query openings + paths",
            len(&b.component_polynomials_query_openings_and_proofs)?,
        ),
        (
            "    FRI query openings + paths",
            len(&b.query_phase_openings_and_proofs)?,
        ),
        (
            "    batch_evaluations",
            len(&e.pcs_proof.batch_evaluations)?,
        ),
        ("  sumcheck_proof", len(&e.sumcheck_proof)?),
        ("  jagged_eval_proof", len(&e.jagged_eval_proof)?),
        ("shard proof total", len(s)?),
        ("recursion vk (inside proof)", len(&p.vk)?),
        ("vk_merkle_proof", len(&p.vk_merkle_proof)?),
        ("proof total (incl. enum tag)", len(&proof.proof)?),
        ("public_values", len(&proof.public_values)?),
        ("sp1_version", len(&proof.sp1_version)?),
        ("tee_proof", len(&proof.tee_proof)?),
        ("file total", std::fs::metadata(&proof_path)?.len() as usize),
        (
            "verifying key file",
            std::fs::metadata(&vk_path)?.len() as usize,
        ),
    ];
    println!("guest = {name}, sp1_version = {}", proof.sp1_version);
    for (name, n) in rows {
        println!("{n:>8}  {name}");
    }
    let components = std::collections::BTreeMap::from([
        (
            "shard_proof_without_public_values",
            len(s)? - len(&s.public_values)?,
        ),
        ("recursion_vk", len(&p.vk)?),
        ("vk_merkle_proof", len(&p.vk_merkle_proof)?),
    ]);
    let size = Size {
        proof_bytes: components.values().sum(),
        components,
    };
    std::fs::write(out, format!("{}\n", serde_json::to_string_pretty(&size)?))?;
    println!(
        "{:>8}  proof without public inputs (written to {out})",
        size.proof_bytes
    );
    Ok(())
}

#[derive(Clone, Copy, Default, Serialize)]
struct Ops {
    mul: u64,
    add: u64,
    sub: u64,
}

#[derive(Serialize)]
struct Ledger {
    system: &'static str,
    version: String,
    artifact: &'static str,
    hash: Hash,
    field: Field,
}

#[derive(Serialize)]
struct Hash {
    function: &'static str,
    permutations: Perms,
}

/// Poseidon2 permutations, by the p3-symmetric / p3-challenger site that
/// performs them.
#[derive(Serialize)]
struct Perms {
    truncated_permutation_compress: u64,
    padding_free_sponge: u64,
    duplex_challenger: u64,
    total: u64,
}

#[derive(Serialize)]
struct Field {
    base: &'static str,
    counted_at: &'static str,
    /// Spent inside the permutations counted above. Charged to the hash.
    in_hash_suite: Ops,
    /// The verifier's own arithmetic, excluding the hash and the
    /// multiplications inside `exp_u64_by_squaring` (recorded separately as
    /// `pow.mul`). The 36 multiplications of each `try_inverse` are in here.
    residual: Ops,
    pow: Pow,
    /// `in_hash_suite.mul / permutations`; exact.
    mul_per_permutation: u64,
}

#[derive(Serialize)]
struct Pow {
    /// `exp_u64_by_squaring` calls (one per FRI query); their multiplication
    /// count depends on the exponent bits.
    calls: u64,
    /// KoalaBear `try_inverse` calls during verification, a fixed 29
    /// squarings and 7 multiplications each, counted in `residual`.
    /// Extension-field inverses bottom out in one base inverse each; the
    /// verifier's are the FRI fold divisors (one per query per round) and
    /// the GKR output denominators.
    inv_calls: u64,
    /// Multiplications performed inside the `exp_u64_by_squaring` calls. Kept
    /// out of `residual` because the count varies with the proof, so
    /// `residual` diffs exactly and this field is compared within a
    /// tolerance. The gate estimate prices it with `residual`: the verifier
    /// circuit's only input is the proof, so exponentiations are computed
    /// in-circuit, not supplied as witnesses. (Additions and subtractions
    /// inside `pow` are zero for KoalaBear and stay in `residual`.)
    mul: u64,
}

fn load(a: &std::sync::atomic::AtomicU64) -> u64 {
    a.load(std::sync::atomic::Ordering::Relaxed)
}

/// Runs `verify` between counter snapshots and writes the resulting operation
/// ledger to `out`. `artifact` names what was verified.
fn count_verify(
    artifact: &'static str,
    out: &str,
    verify: impl FnOnce() -> Result<()>,
) -> Result<()> {
    // Parallel reductions combine partial sums with extra additions whose
    // number depends on how rayon splits the work; one thread makes the
    // count deterministic and equal to the sequential verifier's.
    std::env::set_var("RAYON_NUM_THREADS", "1");
    // Every counter is read as its change across `verify`, so that nothing
    // done before it enters the ledger. That matters: constructing the
    // verifier (`SP1Verifier::new`) builds SP1's RISC-V and recursion
    // machines, which evaluates every AIR once on concrete field values and
    // performs about 400 thousand multiplications and 10,806 inversions of
    // constants. The caller constructs the verifier before calling this.
    let counters = [
        &c::MUL,
        &c::ADD,
        &c::SUB,
        &c::POW_MUL,
        &c::POW_ADD,
        &c::POW_SUB,
        &c::HASH_MUL,
        &c::HASH_ADD,
        &c::HASH_SUB,
        &c::PERM_COMPRESS,
        &c::PERM_SPONGE,
        &c::PERM_DUPLEX,
        &c::POW_CALLS,
        &c::INV_CALLS,
    ];
    let before = counters.map(load);
    verify()?;
    let after = counters.map(load);
    let d = |i: usize| after[i] - before[i];
    let total = Ops {
        mul: d(0),
        add: d(1),
        sub: d(2),
    };
    let in_pow = Ops {
        mul: d(3),
        add: d(4),
        sub: d(5),
    };
    let in_hash_suite = Ops {
        mul: d(6),
        add: d(7),
        sub: d(8),
    };
    let perms = Perms {
        truncated_permutation_compress: d(9),
        padding_free_sponge: d(10),
        duplex_challenger: d(11),
        total: d(9) + d(10) + d(11),
    };
    let (pow_calls, inv_calls) = (d(12), d(13));
    assert_eq!(in_hash_suite.mul % perms.total, 0);
    let ledger = Ledger {
        system: "sp1",
        version: lock_version("sp1-sdk"),
        artifact,
        hash: Hash {
            function: "poseidon2-koalabear",
            permutations: Perms { ..perms },
        },
        field: Field {
            base: "koalabear",
            counted_at: "KoalaBear Add/Sub/Mul impls; extension-field ops decompose into these",
            in_hash_suite,
            residual: Ops {
                mul: total.mul - in_hash_suite.mul - in_pow.mul,
                add: total.add - in_hash_suite.add,
                sub: total.sub - in_hash_suite.sub,
            },
            pow: Pow {
                calls: pow_calls,
                inv_calls,
                mul: in_pow.mul,
            },
            mul_per_permutation: in_hash_suite.mul / perms.total,
        },
    };
    let json = serde_json::to_string_pretty(&ledger)?;
    std::fs::write(out, format!("{json}\n"))?;
    let p = &ledger.hash.permutations;
    println!("{artifact}: poseidon2 permutations = {}", p.total);
    for (name, n) in [
        (
            "truncated_permutation_compress",
            p.truncated_permutation_compress,
        ),
        ("padding_free_sponge", p.padding_free_sponge),
        ("duplex_challenger", p.duplex_challenger),
    ] {
        println!("{n:>8}  {name}");
    }
    let f = &ledger.field;
    for (name, t, h, r) in [
        ("mul", total.mul, f.in_hash_suite.mul, f.residual.mul),
        ("add", total.add, f.in_hash_suite.add, f.residual.add),
        ("sub", total.sub, f.in_hash_suite.sub, f.residual.sub),
    ] {
        println!("koalabear {name}: {t} measured = {h} in hash suite + {r} residual");
    }
    println!(
        "  (+ {} mul inside {} pow calls, exponent-dependent, recorded as pow.mul; {} add, {} sub inside pow stay in residual)",
        in_pow.mul, f.pow.calls, in_pow.add, in_pow.sub
    );
    Ok(())
}

fn count(name: &str, out: &str) -> Result<()> {
    let (proof, vk) = read_artifact(name)?;
    // Constructed outside the counted closure: building the verifier's
    // machines is not verification (see `count_verify`).
    let prover = LightProver::new();
    count_verify("compressed proof", out, || {
        prover.verify(&proof, &vk, None)?;
        Ok(())
    })?;
    // Hashing the vk uses the counted permutation, so the manifest check
    // runs after the ledger is read.
    check_manifest(name, &vk)
}

/// The shrink proof: an `SP1RecursionProof` in the same shape as the
/// compressed proof, but produced by and verified against the shrink machine.
type ShrinkProof = SP1RecursionProof<SP1GlobalContext, SP1PcsProofInner>;

/// The shrink verifying key. It is a constant of the proof system (SP1 fixes
/// the shrink program), but unlike the wrap key SP1 does not ship it as a
/// released artifact, so `shrink` writes out the one its prover derives.
const SHRINK_VK: &str = "../artifacts/sp1/shrink.vk";

fn shrink_path(name: &str) -> String {
    format!("../artifacts/sp1/{name}.shrink.bin")
}

/// Takes the committed compressed proof of `name` through SP1's shrink stage
/// and writes the result next to it.
///
/// Shrink is the recursion step between the compressed proof and the wrap
/// proof: it verifies the compressed proof inside a smaller recursion machine
/// (`RecursionAir::shrink_machine`) at a higher FRI blowup, and is the last
/// stage still over KoalaBear. `sp1-prover` runs it inside `run_shrink_wrap`
/// and immediately consumes it with the wrap prover, so neither the SDK nor
/// the worker API hands it back; `patches/sp1-prover-6.3.1.patch` only widens
/// `ShrinkProver::{prove, verify}` to `pub` so it can be called directly.
fn shrink(name: &str) -> Result<()> {
    let (proof, _vk) = load_artifact(name)?;
    let compressed = match proof.proof {
        SP1Proof::Compressed(p) => *p,
        _ => bail!("expected a compressed proof"),
    };
    let runtime = tokio::runtime::Runtime::new()?;
    let (shrink_proof, shrink_vk) = runtime.block_on(async move {
        let worker = cpu_worker_builder().build().await?;
        let prover = worker
            .prover_engine()
            .recursion_prover
            .shrink_prover
            .clone();
        let shrink_proof = prover
            .prove(compressed)
            .await
            .map_err(|e| anyhow::anyhow!("shrink prove failed: {e:?}"))?;
        prover
            .verify(&shrink_proof)
            .map_err(|e| anyhow::anyhow!("shrink verify failed: {e:?}"))?;
        anyhow::Ok((shrink_proof, prover.verifying_key.clone()))
    })?;
    let path = shrink_path(name);
    std::fs::write(&path, bincode::serialize(&shrink_proof)?)?;
    std::fs::write(SHRINK_VK, bincode::serialize(&shrink_vk)?)?;
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(MANIFEST)?)?;
    manifest["sp1"]["shrink"]["vk_hash"] = shrink_vk.bytes32().into();
    std::fs::write(
        MANIFEST,
        format!("{}\n", serde_json::to_string_pretty(&manifest)?),
    )?;
    println!(
        "{name}: shrink proof written to {path} ({} bytes) and {SHRINK_VK}",
        std::fs::metadata(&path)?.len()
    );
    Ok(())
}

fn read_shrink(name: &str) -> Result<(ShrinkProof, MachineVerifyingKey<SP1GlobalContext>)> {
    let path = shrink_path(name);
    let proof = bincode::deserialize(&std::fs::read(&path).with_context(|| {
        format!("reading {path}; produce it with `cargo run --release -p script -- shrink {name}`")
    })?)?;
    let vk = bincode::deserialize(&std::fs::read(SHRINK_VK)?)?;
    Ok((proof, vk))
}

/// Verifies a shrink proof the way `SP1Verifier` does: the shard proof against
/// the shrink verifying key, the key's membership in the recursion vk tree,
/// and the public values (digest, vk root, `is_complete`, and that the proof
/// is for `vk`).
fn verify_shrink(verifier: &SP1Verifier, proof: &ShrinkProof, vk: &SP1VerifyingKey) -> Result<()> {
    verifier
        .verify_shrink(proof, vk)
        .map_err(|e| anyhow::anyhow!("shrink verification failed: {e:?}"))
}

fn shrink_verifier(shrink_vk: MachineVerifyingKey<SP1GlobalContext>) -> SP1Verifier {
    let mut verifier = SP1Verifier::new(VerifierRecursionVks::default());
    verifier.set_shrink_vk(shrink_vk);
    verifier
}

fn shrink_size(name: &str, out: &str) -> Result<()> {
    let (_proof, vk) = load_artifact(name)?;
    let (p, shrink_vk) = read_shrink(name)?;
    check_shrink_manifest(&shrink_vk)?;
    verify_shrink(&shrink_verifier(shrink_vk), &p, &vk)?;
    check_manifest(name, &vk)?;
    let path = shrink_path(name);
    let s = &p.proof;
    let e = &s.evaluation_proof;
    let b = &e.pcs_proof.basefold_proof;
    let rows = [
        ("shard proof: public_values", len(&s.public_values)?),
        ("shard proof: main_commitment", len(&s.main_commitment)?),
        ("shard proof: logup_gkr_proof", len(&s.logup_gkr_proof)?),
        ("shard proof: zerocheck_proof", len(&s.zerocheck_proof)?),
        ("shard proof: opened_values", len(&s.opened_values)?),
        ("shard proof: evaluation_proof", len(e)?),
        ("  pcs_proof (stacked BaseFold)", len(&e.pcs_proof)?),
        ("    fri_commitments", len(&b.fri_commitments)?),
        (
            "    component query openings + paths",
            len(&b.component_polynomials_query_openings_and_proofs)?,
        ),
        (
            "    FRI query openings + paths",
            len(&b.query_phase_openings_and_proofs)?,
        ),
        (
            "    batch_evaluations",
            len(&e.pcs_proof.batch_evaluations)?,
        ),
        ("  sumcheck_proof", len(&e.sumcheck_proof)?),
        ("  jagged_eval_proof", len(&e.jagged_eval_proof)?),
        ("shard proof total", len(s)?),
        ("shrink vk (inside proof, constant)", len(&p.vk)?),
        ("vk_merkle_proof (constant)", len(&p.vk_merkle_proof)?),
        ("file total", std::fs::metadata(&path)?.len() as usize),
    ];
    println!("guest = {name}, artifact = shrink proof");
    for (row, n) in rows {
        println!("{n:>8}  {row}");
    }
    // Unlike the compressed proof, whose `vk` is whichever compress program
    // shape the reduction ended on, the shrink proof's `vk` is the fixed
    // shrink key and its Merkle proof is the fixed path to it, so a verifier
    // can hold both as constants. They are listed separately for that reason.
    let components = std::collections::BTreeMap::from([
        (
            "shard_proof_without_public_values",
            len(s)? - len(&s.public_values)?,
        ),
        ("shrink_vk", len(&p.vk)?),
        ("vk_merkle_proof", len(&p.vk_merkle_proof)?),
    ]);
    let size = Size {
        proof_bytes: components.values().sum(),
        components,
    };
    std::fs::write(out, format!("{}\n", serde_json::to_string_pretty(&size)?))?;
    println!(
        "{:>8}  proof without public inputs (written to {out})",
        size.proof_bytes
    );
    Ok(())
}

fn shrink_count(name: &str, out: &str) -> Result<()> {
    // `read_artifact`, not `load_artifact`: verifying the compressed proof
    // first would run the counted permutation.
    let (_proof, vk) = read_artifact(name)?;
    let (proof, shrink_vk) = read_shrink(name)?;
    let verifier = shrink_verifier(shrink_vk.clone());
    count_verify("shrink proof", out, || {
        verify_shrink(&verifier, &proof, &vk)
    })?;
    // Both checks hash a key with the counted permutation, so they run after
    // the ledger is read.
    check_shrink_manifest(&shrink_vk)?;
    check_manifest(name, &vk)
}

/// Writes the proof-system parameters the shrink verifier is compiled with
/// (`sp1-primitives::fri_params::shrink_fri_config`, `sp1-prover::components`),
/// after checking the shrink proof verifies.
fn shrink_params(name: &str, out: &str) -> Result<()> {
    let (_proof, vk) = load_artifact(name)?;
    let (proof, shrink_vk) = read_shrink(name)?;
    check_shrink_manifest(&shrink_vk)?;
    verify_shrink(&shrink_verifier(shrink_vk), &proof, &vk)?;
    let fri = shrink_fri_config();
    let params = Params {
        system: "sp1",
        version: lock_version("sp1-sdk"),
        artifact: "shrink proof",
        field: FieldParams {
            base: "koalabear",
            modulus: SP1Field::ORDER_U32,
            extension_degree: size_of::<SP1ExtensionField>() / size_of::<SP1Field>(),
        },
        fri: FriParams {
            log_blowup: fri.log_blowup,
            queries: fri.num_queries,
            log_fold: 1,
            pow_bits: fri.proof_of_work_bits,
        },
        log_stacking_height: SHRINK_LOG_STACKING_HEIGHT,
        max_log_row_count: SHRINK_MAX_LOG_ROW_COUNT,
        security: Security {
            stated_bits: SP1_TARGET_BITS_OF_SECURITY,
            basis: "unique decoding: queries = ceil((target - pow_bits) / -log2((1 + rate) / 2))",
            source: "sp1-primitives/src/fri_params.rs",
        },
    };
    assert_eq!(fri.proof_of_work_bits, SP1_SHRINK_WRAP_POW_BITS);
    std::fs::write(out, format!("{}\n", serde_json::to_string_pretty(&params)?))?;
    println!("{}", serde_json::to_string_pretty(&params)?);
    Ok(())
}

/// Version of `name` as pinned in this workspace's `Cargo.lock`.
#[derive(Serialize)]
struct Params {
    system: &'static str,
    version: String,
    artifact: &'static str,
    field: FieldParams,
    fri: FriParams,
    log_stacking_height: u32,
    max_log_row_count: usize,
    security: Security,
}

#[derive(Serialize)]
struct FieldParams {
    base: &'static str,
    modulus: u32,
    extension_degree: usize,
}

#[derive(Serialize)]
struct FriParams {
    log_blowup: usize,
    queries: usize,
    log_fold: u32,
    pow_bits: usize,
}

#[derive(Serialize)]
struct Security {
    stated_bits: usize,
    basis: &'static str,
    source: &'static str,
}

/// Writes the proof-system parameters the compressed-proof verifier is
/// compiled with (`sp1-primitives::fri_params`, `sp1-verifier::compressed`),
/// after checking the artifact verifies.
fn params(name: &str, out: &str) -> Result<()> {
    load_artifact(name)?;
    let fri = recursion_fri_config();
    let params = Params {
        system: "sp1",
        version: lock_version("sp1-sdk"),
        artifact: "compressed proof",
        field: FieldParams {
            base: "koalabear",
            modulus: SP1Field::ORDER_U32,
            extension_degree: size_of::<SP1ExtensionField>() / size_of::<SP1Field>(),
        },
        fri: FriParams {
            log_blowup: fri.log_blowup,
            queries: fri.num_queries,
            log_fold: 1,
            pow_bits: fri.proof_of_work_bits,
        },
        log_stacking_height: sp1_verifier::compressed::RECURSION_LOG_STACKING_HEIGHT,
        max_log_row_count: sp1_verifier::compressed::RECURSION_MAX_LOG_ROW_COUNT,
        security: Security {
            stated_bits: SP1_TARGET_BITS_OF_SECURITY,
            basis: "unique decoding: queries = ceil((target - pow_bits) / -log2((1 + rate) / 2))",
            source: "sp1-primitives/src/fri_params.rs",
        },
    };
    std::fs::write(out, format!("{}\n", serde_json::to_string_pretty(&params)?))?;
    println!("{}", serde_json::to_string_pretty(&params)?);
    Ok(())
}

fn lock_version(name: &str) -> String {
    let lock = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.lock"));
    let mut lines = lock.lines();
    lines
        .by_ref()
        .find(|l| *l == format!("name = \"{name}\""))
        .unwrap_or_else(|| panic!("{name} not in Cargo.lock"));
    let version = lines
        .next()
        .unwrap()
        .trim_start_matches("version = ")
        .trim_matches('"');
    match lines.next().and_then(|l| l.strip_prefix("source = \"git+")) {
        Some(src) => {
            let repo = src
                .split('?')
                .next()
                .unwrap()
                .trim_start_matches("https://github.com/");
            let rev = &src.rsplit('#').next().unwrap()[..8];
            format!("{repo}@{rev}")
        }
        None => version.to_string(),
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match (
        args.get(1).map(String::as_str),
        args.get(2).map(String::as_str),
    ) {
        (Some("prove"), Some(g)) => prove(g),
        (Some("size"), Some(g)) => size(
            g,
            args.get(3)
                .map_or("../results/sp1/size.json", String::as_str),
        ),
        (Some("count"), Some(g)) => count(
            g,
            args.get(3)
                .map_or("../results/sp1/ops.json", String::as_str),
        ),
        (Some("params"), Some(g)) => params(
            g,
            args.get(3)
                .map_or("../results/sp1/params.json", String::as_str),
        ),
        (Some("shrink"), Some(g)) => shrink(g),
        (Some("shrink-size"), Some(g)) => shrink_size(
            g,
            args.get(3)
                .map_or("../results/sp1/shrink/size.json", String::as_str),
        ),
        (Some("shrink-count"), Some(g)) => shrink_count(
            g,
            args.get(3)
                .map_or("../results/sp1/shrink/ops.json", String::as_str),
        ),
        (Some("shrink-params"), Some(g)) => shrink_params(
            g,
            args.get(3)
                .map_or("../results/sp1/shrink/params.json", String::as_str),
        ),
        _ => bail!(
            "usage: script prove|size|count|params|shrink|shrink-size|shrink-count|shrink-params <trivial|fib|journal> [out.json]"
        ),
    }
}
