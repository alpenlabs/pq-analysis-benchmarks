//! `prove <guest>`: run the compiled Cairo program `programs/<guest>/compiled.json` with the
//! prover parameters in `params.json` and write the proof (binary format) to
//! `artifacts/stwo/<guest>.bin`.
//! `size <guest>`:  read that proof back, verify it, and report its size per component.
//! `wrap <guest>`:  run the guest as a task of the leaf bootloader, prove it, verify that proof
//! inside the leaf verifier circuit and prove the circuit (upstream's `leaf_prover`), writing
//! the leaf circuit proof to `artifacts/stwo/<guest>.leaf.json`.
//! `size <guest>.leaf`: report and verify that leaf circuit proof.
//!
//! Guests: trivial, fib, journal.

use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};
use cairo_air::CairoProofForRustVerifier;
use cairo_air::utils::{ProofFormat, deserialize_proof_from_file};
use cairo_air::verifier::verify_cairo;
use cairo_vm::types::layout_name::LayoutName;
use circuit_common::N_RESERVED;
use circuit_common::preprocessed::layout_from_component_sizes;
use circuit_multiverifier::verify::shared_config;
use circuit_registry::CircuitRegistry;
use circuit_serialize::deserialize::deserialize_proof_with_config;
use circuit_verifier::verify::{CircuitConfig, CircuitPublicData, verify_circuit};
use circuits::ivalue::IValue;
use leaf_prover::prove_leaf::prove_leaf_from_files;
use stwo::core::fields::qm31::QM31;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo_cairo_dev_utils::vm_utils::{ProgramType, run_and_adapt};
use stwo_cairo_prover::prover::create_and_serialize_proof;
use stwo_run_and_prove_recursive_tree::{LeafInput, LeafProofExt};

const BOOTLOADER: &str = "leaf/leaf_simple_bootloader_compiled.json";
const REGISTRY: &str = "leaf/circuit_registry.json";

fn proof_path(name: &str) -> PathBuf {
    PathBuf::from(format!("../artifacts/stwo/{name}.bin"))
}

fn program_path(name: &str) -> Result<PathBuf> {
    let program = PathBuf::from(format!("programs/{name}/compiled.json"));
    if !program.exists() {
        bail!("unknown guest {name}");
    }
    Ok(program)
}

fn leaf_path(name: &str) -> PathBuf {
    PathBuf::from(format!("../artifacts/stwo/{name}.leaf.json"))
}

fn wrap(name: &str) -> Result<()> {
    let program = std::fs::canonicalize(program_path(name)?)?;
    let dir = std::env::temp_dir();
    let preimage = dir.join(format!("stwo-{name}-preimage.json"));
    let input = dir.join(format!("stwo-{name}-input.json"));
    std::fs::write(
        &input,
        serde_json::to_string_pretty(&serde_json::json!({
            "tasks": [{
                "type": "RunProgramTask",
                "path": program,
                "program_hash_function": "blake",
            }],
            "fact_topologies_path": null,
            "single_page": true,
            "output_preimage_dump_path": preimage,
        }))?,
    )?;
    let proof = prove_leaf_from_files(
        &PathBuf::from(BOOTLOADER),
        &Some(input),
        &PathBuf::from(REGISTRY),
    );
    // The bootloader's output is a Blake2s digest of these felts (program hash, outputs).
    let dumped: Vec<String> = serde_json::from_str(&std::fs::read_to_string(&preimage)?)?;
    let output_preimage = dumped
        .iter()
        .map(|hex| {
            num_bigint::BigUint::parse_bytes(hex.trim_start_matches("0x").as_bytes(), 16)
                .map(|n| n.to_string())
                .ok_or_else(|| anyhow!("bad felt {hex}"))
        })
        .collect::<Result<_>>()?;
    let leaf = LeafInput {
        proof,
        output_preimage,
    };
    std::fs::write(leaf_path(name), serde_json::to_string(&leaf)?)?;
    Ok(())
}

fn size_leaf(name: &str) -> Result<()> {
    let path = leaf_path(name);
    let leaf: LeafInput = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let registry =
        CircuitRegistry::from_path(&PathBuf::from(REGISTRY)).map_err(|e| anyhow!("{e}"))?;
    let entry = registry
        .leaf_verifiers
        .iter()
        .find(|e| e.circuit_hash == leaf.proof.circuit_hash)
        .ok_or_else(|| anyhow!("circuit hash not in registry"))?;
    let config = registry.config(&entry.config).map_err(|e| anyhow!("{e}"))?;
    let layout = layout_from_component_sizes(&config.target_sizes());
    let trace_log_size = *layout.values().max().unwrap();
    let pcs = PcsConfig::from_fri_and_trace_size(config.fri_config, trace_log_size);
    let shared = shared_config(layout.clone(), pcs);
    let mut bytes = leaf.proof.proof.as_slice();
    let proof = deserialize_proof_with_config(&mut bytes, &shared.proof_config)
        .map_err(|e| anyhow!("{e:?}"))?;
    println!(
        "guest = {name}.leaf, leaf verifier for Cairo trace log size {}, circuit hash {:?}, \
         circuit trace log size {trace_log_size}, pow_bits = {}, n_queries = {}, fold_step = {}",
        entry.trace_log_size,
        leaf.proof.circuit_hash,
        config.fri_config.pow_bits,
        config.fri_config.n_queries,
        config.fri_config.fold_step,
    );
    println!(
        "{:>8}  leaf circuit proof (serialized)",
        leaf.proof.proof.len()
    );
    println!("{:>8}  file (json)", std::fs::metadata(&path)?.len());
    let output_values = leaf
        .output_values()
        .map_err(|e| anyhow!("{e:?}"))?
        .iter()
        .map(|w| QM31::pack_u32(*w))
        .collect();
    let circuit_config = CircuitConfig {
        config: pcs,
        n_outputs: N_RESERVED,
        preprocessed_column_log_sizes: layout,
        preprocessed_root: leaf.proof.preprocessed_root(),
    };
    verify_circuit(circuit_config, proof, CircuitPublicData { output_values })
        .map_err(|e| anyhow!("{e}"))?;
    println!("verified");
    Ok(())
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
        cfg.fri_config.pow_bits,
        cfg.fri_config.log_blowup_factor,
        cfg.fri_config.n_queries,
        cfg.fri_config.security_bits(),
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
        (Some("size"), Some(g)) => match g.strip_suffix(".leaf") {
            Some(inner) => size_leaf(inner),
            None => size(g),
        },
        (Some("wrap"), Some(g)) => wrap(g),
        _ => bail!("usage: stwo-size prove|wrap|size <trivial|fib|journal>[.leaf]"),
    }
}
