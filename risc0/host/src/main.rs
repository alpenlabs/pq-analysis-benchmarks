//! `prove <guest>`: run the guest and write a succinct receipt to `artifacts/risc0/<guest>.bin`.
//! `size <guest>`:  read that receipt and report its serialized size per component.
//! `count <guest> [out]`: verify that receipt with a counting hash suite and
//!                  patched field arithmetic, and write the operation ledger as
//!                  JSON (default `results/risc0/ops.json`; it is the same for
//!                  every guest).
//!
//! Guests: trivial, fib, journal.

mod count;

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

#[derive(Serialize)]
struct Ledger {
    system: &'static str,
    version: &'static str,
    artifact: &'static str,
    hash: count::Hash,
    field: count::Field,
}

fn count(name: &str, out: &str) -> Result<()> {
    let receipt: Receipt = bincode::deserialize(&std::fs::read(receipt_path(name))?)?;
    let (suite, counters) = count::counting_suite();
    let mut suites = VerifierContext::default_hash_suites();
    suites.insert(suite.name.clone(), suite);
    let ctx = VerifierContext::default().with_suites(suites);
    let start = count::Ops::now();
    receipt.verify_integrity_with_context(&ctx)?;
    let total = count::Ops::now().since(start);
    let ledger = Ledger {
        system: "risc0",
        version: "3.0.5",
        artifact: "succinct receipt",
        hash: counters.report(),
        field: counters.field(total),
    };
    let json = serde_json::to_string_pretty(&ledger)?;
    std::fs::write(out, format!("{json}\n"))?;
    let p = &ledger.hash.permutations;
    println!("guest = {name}, poseidon2 permutations = {}", p.total);
    for (name, n) in [
        ("hash_pair", p.hash_pair),
        ("hash_elem_slice", p.hash_elem_slice),
        ("hash_ext_elem_slice", p.hash_ext_elem_slice),
        ("rng", p.rng),
    ] {
        println!("{n:>8}  {name}");
    }
    let f = &ledger.field;
    for (name, t, h, r) in [
        ("mul", total.mul, f.in_hash_suite.mul, f.residual.mul),
        ("add", total.add, f.in_hash_suite.add, f.residual.add),
        ("sub", total.sub, f.in_hash_suite.sub, f.residual.sub),
    ] {
        println!("babybear {name}: {t} measured = {h} in hash suite + {r} residual");
    }
    println!(
        "  (mul: + {} inside {} pow calls, exponent-dependent, not in the ledger)",
        total.pow_mul, f.pow.calls
    );
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
        (Some("count"), Some(g)) => count(
            g,
            args.get(3)
                .map_or("../results/risc0/ops.json", String::as_str),
        ),
        _ => bail!("usage: host prove|size|count <trivial|fib|journal> [out.json]"),
    }
}
