//! `prove <guest>`: run the guest and write a compressed proof and verifying key to
//! `artifacts/sp1/<guest>.{bin,vk}`.
//! `size <guest>`:  read them back and report the serialized size per component.
//!
//! Guests: trivial, fib, journal.

use anyhow::{bail, Result};
use serde::Serialize;
use sp1_sdk::blocking::{LightProver, ProveRequest, Prover, ProverClient};
use sp1_sdk::prover::ProvingKey;
use sp1_sdk::{include_elf, Elf, SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};

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
    Ok(())
}

fn len<T: Serialize>(v: &T) -> Result<usize> {
    Ok(bincode::serialized_size(v)? as usize)
}

fn size(name: &str) -> Result<()> {
    let (proof_path, vk_path) = paths(name);
    let proof = SP1ProofWithPublicValues::load(&proof_path)?;
    let vk: SP1VerifyingKey = bincode::deserialize(&std::fs::read(&vk_path)?)?;
    // LightProver verifies without building proving keys.
    LightProver::new().verify(&proof, &vk, None)?;
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
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match (
        args.get(1).map(String::as_str),
        args.get(2).map(String::as_str),
    ) {
        (Some("prove"), Some(g)) => prove(g),
        (Some("size"), Some(g)) => size(g),
        _ => bail!("usage: script prove|size <trivial|fib|journal>"),
    }
}
