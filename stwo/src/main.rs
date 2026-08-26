//! `prove <guest>`: run the compiled Cairo program `programs/<guest>/compiled.json` with the
//! prover parameters in `params.json` and write the proof (binary format) to
//! `artifacts/stwo/<guest>.bin`.
//! `size <guest>`:  read that proof back, verify it, and report its size per component.
//!
//! Guests: trivial, fib, journal.

use std::path::PathBuf;

use anyhow::{Result, bail};
use cairo_air::CairoProofForRustVerifier;
use cairo_air::utils::{ProofFormat, deserialize_proof_from_file};
use cairo_air::verifier::verify_cairo;
use cairo_vm::types::layout_name::LayoutName;
use stwo_cairo_dev_utils::vm_utils::{ProgramType, run_and_adapt};
use stwo_cairo_prover::prover::create_and_serialize_proof;
use stwo_cairo_prover::stwo::core::vcs_lifted::blake2_merkle::{
    Blake2sMerkleChannel, Blake2sMerkleHasher,
};

fn proof_path(name: &str) -> PathBuf {
    PathBuf::from(format!("../artifacts/stwo/{name}.bin"))
}

fn prove(name: &str) -> Result<()> {
    let program = PathBuf::from(format!("programs/{name}/compiled.json"));
    if !program.exists() {
        bail!("unknown guest {name}");
    }
    let input = run_and_adapt(
        &program,
        ProgramType::Json,
        LayoutName::all_cairo_stwo,
        None,
    )?;
    create_and_serialize_proof(
        input,
        true,
        proof_path(name),
        ProofFormat::Binary,
        Some(PathBuf::from("params.json")),
    )
}

fn size(name: &str) -> Result<()> {
    let path = proof_path(name);
    let proof: CairoProofForRustVerifier<Blake2sMerkleHasher> =
        deserialize_proof_from_file(&path, ProofFormat::Binary)?;
    let sp = &proof.stark_proof;
    let cfg = sp.config;
    let b = sp.size_breakdown_estimate();
    let n_columns: usize = sp.queried_values.0.iter().map(|t| t.len()).sum();
    let rows = [
        ("OODS samples", b.oods_samples),
        ("queried values", b.queries_values),
        ("FRI witness + last layer", b.fri_samples),
        ("FRI decommitments", b.fri_decommitments),
        ("trace decommitments", b.trace_decommitments),
        ("intrinsic total (size_estimate)", sp.size_estimate()),
        (
            "file (bincode + bzip2)",
            std::fs::metadata(&path)?.len() as usize,
        ),
    ];
    println!(
        "guest = {name}, pow_bits = {}, log_blowup = {}, n_queries = {}, security_bits = {}, \
         preprocessed_trace = {:?}, commitment trees = {}, queried columns = {}",
        cfg.pow_bits,
        cfg.fri_config.log_blowup_factor,
        cfg.fri_config.n_queries,
        cfg.security_bits(),
        proof.preprocessed_trace_variant,
        sp.commitments.0.len(),
        n_columns,
    );
    for (name, n) in rows {
        println!("{n:>8}  {name}");
    }
    verify_cairo::<Blake2sMerkleChannel>(proof).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    println!("verified");
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
        _ => bail!("usage: stwo-size prove|size <trivial|fib|journal>"),
    }
}
