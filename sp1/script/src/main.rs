//! `prove <guest>`: run the guest and write a compressed proof and verifying key to
//! `artifacts/sp1/<guest>.{bin,vk}`.
//! `size <guest> [out]`: read them back and report the serialized size per component;
//!                  write the proof size without public inputs as JSON (default
//!                  `results/sp1/size.json`; it is the same for every guest).
//! `count <guest> [out]`: verify the proof with the patched Plonky3 crates and
//!                  write the operation ledger as JSON (default
//!                  `results/sp1/ops.json`; it is the same for every guest).
//!
//! Guests: trivial, fib, journal.

use anyhow::{bail, Result};
use p3_field::counters as c;
use p3_field::PrimeField32;
use serde::Serialize;
use sp1_primitives::fri_params::{recursion_fri_config, SP1_TARGET_BITS_OF_SECURITY};
use sp1_primitives::{SP1ExtensionField, SP1Field};
use sp1_sdk::blocking::{LightProver, ProveRequest, Prover, ProverClient};
use sp1_sdk::prover::ProvingKey;
use sp1_sdk::{
    include_elf, Elf, HashableKey, SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
};

/// Shard size (cycles) used when proving `fib`; the default is 2^24, which
/// would fit it in one shard.
const FIB_SHARD_SIZE: u64 = 1 << 22;

fn elf(name: &str) -> Result<Elf> {
    Ok(match name {
        "trivial" => include_elf!("trivial"),
        "fib" => include_elf!("fib"),
        "journal" => include_elf!("journal"),
        _ => bail!("unknown guest {name}"),
    })
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

/// Checks the committed verifying key's hash against `artifacts/manifest.json`
/// (written by `prove`).
fn check_manifest(name: &str, vk: &SP1VerifyingKey) -> Result<()> {
    let manifest: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(MANIFEST)?)?;
    let expected = manifest["sp1"][name]["vk_hash"].as_str().ok_or_else(|| {
        anyhow::anyhow!(
            "no sp1/{name} entry in {MANIFEST}; the committed vk hashes to {}",
            vk.bytes32()
        )
    })?;
    if vk.bytes32() != expected {
        bail!("{name}.vk: vk hash {} != manifest {expected}", vk.bytes32());
    }
    Ok(())
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
    /// The verifier's own arithmetic, excluding the hash and the operations
    /// inside `exp_u64_by_squaring`.
    residual: Ops,
    pow: Pow,
    /// `in_hash_suite.mul / permutations`; exact.
    mul_per_permutation: u64,
}

#[derive(Serialize)]
struct Pow {
    /// `exp_u64_by_squaring` calls; their operation count depends on the
    /// exponent bits, so it is kept out of `residual`.
    calls: u64,
    /// KoalaBear `try_inverse` calls, a fixed 29 squarings + 7 multiplications each.
    inv_calls: u64,
}

fn load(a: &std::sync::atomic::AtomicU64) -> u64 {
    a.load(std::sync::atomic::Ordering::Relaxed)
}

fn count(name: &str, out: &str) -> Result<()> {
    let (proof, vk) = read_artifact(name)?;
    // Parallel reductions combine partial sums with extra additions whose
    // number depends on how rayon splits the work; one thread makes the
    // count deterministic and equal to the sequential verifier's.
    std::env::set_var("RAYON_NUM_THREADS", "1");
    let before = [&c::MUL, &c::ADD, &c::SUB].map(load);
    LightProver::new().verify(&proof, &vk, None)?;
    let d = |i: usize, a: &std::sync::atomic::AtomicU64| load(a) - before[i];
    let total = Ops {
        mul: d(0, &c::MUL),
        add: d(1, &c::ADD),
        sub: d(2, &c::SUB),
    };
    let in_pow = Ops {
        mul: load(&c::POW_MUL),
        add: load(&c::POW_ADD),
        sub: load(&c::POW_SUB),
    };
    let in_hash_suite = Ops {
        mul: load(&c::HASH_MUL),
        add: load(&c::HASH_ADD),
        sub: load(&c::HASH_SUB),
    };
    let perms = Perms {
        truncated_permutation_compress: load(&c::PERM_COMPRESS),
        padding_free_sponge: load(&c::PERM_SPONGE),
        duplex_challenger: load(&c::PERM_DUPLEX),
        total: load(&c::PERM_COMPRESS) + load(&c::PERM_SPONGE) + load(&c::PERM_DUPLEX),
    };
    assert_eq!(in_hash_suite.mul % perms.total, 0);
    let ledger = Ledger {
        system: "sp1",
        version: lock_version("sp1-sdk"),
        artifact: "compressed proof",
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
                add: total.add - in_hash_suite.add - in_pow.add,
                sub: total.sub - in_hash_suite.sub - in_pow.sub,
            },
            pow: Pow {
                calls: load(&c::POW_CALLS),
                inv_calls: load(&c::INV_CALLS),
            },
            mul_per_permutation: in_hash_suite.mul / perms.total,
        },
    };
    let json = serde_json::to_string_pretty(&ledger)?;
    std::fs::write(out, format!("{json}\n"))?;
    // Hashing the vk uses the counted permutation, so the manifest check
    // runs after the ledger is read.
    check_manifest(name, &vk)?;
    let p = &ledger.hash.permutations;
    println!("guest = {name}, poseidon2 permutations = {}", p.total);
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
        "  (+ {} mul, {} add, {} sub inside {} pow calls, exponent-dependent, not in the ledger)",
        in_pow.mul, in_pow.add, in_pow.sub, f.pow.calls
    );
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
        _ => bail!("usage: script prove|size|count|params <trivial|fib|journal> [out.json]"),
    }
}
