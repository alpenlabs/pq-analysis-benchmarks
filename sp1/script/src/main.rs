//! `prove`: run the guest and write a compressed proof and verifying key to `artifacts/sp1/`.
//! `size`:  read them back and report the serialized size per component.

use anyhow::{bail, Result};
use serde::Serialize;
use sp1_sdk::blocking::{LightProver, ProveRequest, Prover, ProverClient};
use sp1_sdk::prover::ProvingKey;
use sp1_sdk::{include_elf, Elf, SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};

const ELF: Elf = include_elf!("trivial");
const PROOF: &str = "../artifacts/sp1/trivial.bin";
const VK: &str = "../artifacts/sp1/trivial.vk";

fn prove() -> Result<()> {
    let client = ProverClient::from_env();
    let (_, report) = client.execute(ELF, SP1Stdin::new()).run()?;
    println!("{} cycles", report.total_instruction_count());
    let pk = client.setup(ELF)?;
    let vk = pk.verifying_key().clone();
    let proof = client.prove(&pk, SP1Stdin::new()).compressed().run()?;
    client.verify(&proof, &vk, None)?;
    proof.save(PROOF)?;
    std::fs::write(VK, bincode::serialize(&vk)?)?;
    Ok(())
}

fn len<T: Serialize>(v: &T) -> Result<usize> {
    Ok(bincode::serialized_size(v)? as usize)
}

fn size() -> Result<()> {
    let proof = SP1ProofWithPublicValues::load(PROOF)?;
    let vk: SP1VerifyingKey = bincode::deserialize(&std::fs::read(VK)?)?;
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
        ("file total", std::fs::metadata(PROOF)?.len() as usize),
        ("verifying key file", std::fs::metadata(VK)?.len() as usize),
    ];
    println!("sp1_version = {}", proof.sp1_version);
    for (name, n) in rows {
        println!("{n:>8}  {name}");
    }
    Ok(())
}

fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("prove") => prove(),
        Some("size") => size(),
        _ => bail!("usage: script prove|size"),
    }
}
