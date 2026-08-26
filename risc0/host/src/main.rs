//! `prove`: run the guest and write a succinct receipt to `artifacts/risc0/`.
//! `size`:  read that receipt and report its serialized size per component.

use anyhow::{bail, Result};
use methods::{GUEST_ELF, GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts, Receipt};
use serde::Serialize;

const RECEIPT: &str = "../artifacts/risc0/receipt.bin";

fn prove() -> Result<()> {
    let env = ExecutorEnv::builder().build()?;
    let receipt = default_prover()
        .prove_with_opts(env, GUEST_ELF, &ProverOpts::succinct())?
        .receipt;
    receipt.verify(GUEST_ID)?;
    std::fs::write(RECEIPT, bincode::serialize(&receipt)?)?;
    Ok(())
}

fn len<T: Serialize>(v: &T) -> Result<usize> {
    Ok(bincode::serialized_size(v)? as usize)
}

fn size() -> Result<()> {
    let bytes = std::fs::read(RECEIPT)?;
    let receipt: Receipt = bincode::deserialize(&bytes)?;
    let s = match &receipt.inner {
        InnerReceipt::Succinct(s) => s,
        other => bail!("expected a succinct receipt, got {other:?}"),
    };
    let rows = [
        ("seal (u32 words * 4)", s.seal.len() * 4),
        ("seal, bincode (adds 8-byte length)", len(&s.seal)?),
        ("control_id", len(&s.control_id)?),
        ("control_inclusion_proof", len(&s.control_inclusion_proof)?),
        ("claim", len(&s.claim)?),
        ("hashfn", len(&s.hashfn)?),
        ("verifier_parameters", len(&s.verifier_parameters)?),
        ("inner receipt total (incl. enum tag)", len(&receipt.inner)?),
        ("journal", len(&receipt.journal)?),
        ("metadata", len(&receipt.metadata)?),
        ("receipt total", bytes.len()),
    ];
    println!("hashfn = {}", s.hashfn);
    println!("seal words = {}", s.seal.len());
    for (name, n) in rows {
        println!("{n:>8}  {name}");
    }
    Ok(())
}

fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("prove") => prove(),
        Some("size") => size(),
        _ => bail!("usage: host prove|size"),
    }
}
