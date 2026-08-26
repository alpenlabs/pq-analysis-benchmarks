//! `prove <guest>`: run the guest and write a succinct receipt to `artifacts/risc0/<guest>.bin`.
//! `size <guest>`:  read that receipt and report its serialized size per component.
//!
//! Guests: trivial, fib, journal.

use anyhow::{bail, Result};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts, Receipt, VerifierContext};
use serde::Serialize;

fn guest(name: &str) -> Result<(&'static [u8], [u32; 8])> {
    Ok(match name {
        "trivial" => (methods::TRIVIAL_ELF, methods::TRIVIAL_ID),
        "fib" => (methods::FIB_ELF, methods::FIB_ID),
        "journal" => (methods::JOURNAL_ELF, methods::JOURNAL_ID),
        _ => bail!("unknown guest {name}"),
    })
}

fn receipt_path(name: &str) -> String {
    format!("../artifacts/risc0/{name}.bin")
}

fn prove(name: &str) -> Result<()> {
    let (elf, id) = guest(name)?;
    let env = ExecutorEnv::builder().build()?;
    let info = default_prover().prove_with_opts(env, elf, &ProverOpts::succinct())?;
    info.receipt.verify(id)?;
    println!(
        "{name}: {} cycles, {} segments",
        info.stats.total_cycles, info.stats.segments
    );
    std::fs::write(receipt_path(name), bincode::serialize(&info.receipt)?)?;
    Ok(())
}

fn len<T: Serialize>(v: &T) -> Result<usize> {
    Ok(bincode::serialized_size(v)? as usize)
}

fn size(name: &str) -> Result<()> {
    let bytes = std::fs::read(receipt_path(name))?;
    let receipt: Receipt = bincode::deserialize(&bytes)?;
    // Image IDs are placeholders under RISC0_SKIP_BUILD, so verify the seal only.
    receipt.verify_integrity_with_context(&VerifierContext::default())?;
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
    println!(
        "guest = {name}, hashfn = {}, seal words = {}",
        s.hashfn,
        s.seal.len()
    );
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
        _ => bail!("usage: host prove|size <trivial|fib|journal>"),
    }
}
