//! `prove <guest>`: run the compiled Cairo program `programs/<guest>/compiled.json` with the
//! prover parameters in `params.json` and write the proof (binary format) to
//! `artifacts/stwo/<guest>.bin`.
//! `size <guest>`:  read that proof back, verify it, and report its size per component.
//! `wrap <guest>`:  run the guest as a task of the leaf bootloader, prove it, verify that proof
//! inside the leaf verifier circuit and prove the circuit (upstream's `leaf_prover`), writing
//! the leaf circuit proof to `artifacts/stwo/<guest>.leaf.json`.
//! `count <guest> [out]`: verify the leaf proof and write the verification circuit's gate
//!                  counts as JSON (default `results/stwo/ops.json`; same for every guest).
//! `size <guest>.leaf [out]`: report and verify that leaf circuit proof; write its size
//!                  without public inputs as JSON (default `results/stwo/size.json`; same
//!                  for every guest).
//!
//! Guests: trivial, fib, journal.

use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};
use cairo_air::CairoProofForRustVerifier;
use cairo_air::utils::{ProofFormat, deserialize_proof_from_file};
use cairo_air::verifier::verify_cairo;
use cairo_program_runner_lib::hints::compute_program_hash_chain;
use cairo_program_runner_lib::types::HashFunc;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::program::Program;
use circuit_common::N_RESERVED;
use circuit_common::finalize::ComponentSizes;
use circuit_common::preprocessed::layout_from_component_sizes;
use circuit_multiverifier::verify::shared_config;
use circuit_registry::CircuitRegistry;
use circuit_serialize::deserialize::deserialize_proof_with_config;
use circuit_verifier::verify::{CircuitConfig, CircuitPublicData, verify_circuit};
use circuits::context::FinalizedContext;
use circuits::ivalue::IValue;
use leaf_prover::prove_leaf::prove_leaf_from_files;
use serde::Serialize;
use starknet_types_core::felt::Felt;
use stwo::core::fields::m31::P;
use stwo::core::fields::qm31::QM31;
use stwo::core::fri::FriConfig;
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

/// Verifies the leaf circuit proof of `name` by building the verification
/// circuit, printing the size lines on the way; returns the finalized circuit.
/// The registry entry and verifier configuration a leaf proof selects.
struct LeafSetup {
    leaf: LeafInput,
    cairo_trace_log_size: u32,
    fri: FriConfig,
    sizes: ComponentSizes,
    trace_log_size: u32,
}

fn leaf_setup(name: &str) -> Result<LeafSetup> {
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
    Ok(LeafSetup {
        leaf,
        cairo_trace_log_size: entry.trace_log_size,
        fri: config.fri_config,
        sizes: config.target_sizes(),
        trace_log_size,
    })
}

/// Checks that the leaf's output preimage names the committed guest program:
/// its first felt is the bootloader's Blake program hash of the task, which
/// `wrap` ran from `programs/<name>/compiled.json`.
fn check_program_hash(name: &str, leaf: &LeafInput) -> Result<()> {
    let bytes = std::fs::read(program_path(name)?)?;
    let program = Program::from_bytes(&bytes, Some("main")).map_err(|e| anyhow!("{e}"))?;
    let stripped = program.get_stripped_program().map_err(|e| anyhow!("{e}"))?;
    let computed =
        compute_program_hash_chain(&stripped, 0, HashFunc::Blake).map_err(|e| anyhow!("{e:?}"))?;
    let claimed = leaf
        .output_preimage
        .first()
        .ok_or_else(|| anyhow!("empty output preimage"))?;
    if Felt::from_dec_str(claimed)? != computed {
        bail!("{name}: output preimage program hash {claimed} != {computed} from programs/{name}");
    }
    Ok(())
}

fn verify_leaf(name: &str) -> Result<FinalizedContext<QM31>> {
    let path = leaf_path(name);
    let LeafSetup {
        leaf,
        cairo_trace_log_size,
        fri,
        sizes,
        trace_log_size,
    } = leaf_setup(name)?;
    check_program_hash(name, &leaf)?;
    let layout = layout_from_component_sizes(&sizes);
    let pcs = PcsConfig::from_fri_and_trace_size(fri, trace_log_size);
    let shared = shared_config(layout.clone(), pcs);
    let mut bytes = leaf.proof.proof.as_slice();
    let proof = deserialize_proof_with_config(&mut bytes, &shared.proof_config)
        .map_err(|e| anyhow!("{e:?}"))?;
    println!(
        "guest = {name}.leaf, leaf verifier for Cairo trace log size {}, circuit hash {:?}, \
         circuit trace log size {trace_log_size}, pow_bits = {}, n_queries = {}, fold_step = {}",
        cairo_trace_log_size, leaf.proof.circuit_hash, fri.pow_bits, fri.n_queries, fri.fold_step,
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
    let context = verify_circuit(circuit_config, proof, CircuitPublicData { output_values })
        .map_err(|e| anyhow!("{e}"))?;
    println!("verified");
    Ok(context)
}

#[derive(Serialize)]
struct Size {
    /// Bytes a verifier needs beyond the public inputs: the serialized leaf
    /// circuit proof, the circuit hash that selects the registry entry and
    /// the preprocessed root of that circuit (eight u32 words each).
    /// Excludes the output preimage.
    proof_bytes: usize,
    components: std::collections::BTreeMap<&'static str, usize>,
}

fn size_leaf(name: &str, out: &str) -> Result<()> {
    verify_leaf(name)?;
    let leaf: LeafInput = serde_json::from_str(&std::fs::read_to_string(leaf_path(name))?)?;
    let components = std::collections::BTreeMap::from([
        ("leaf_circuit_proof", leaf.proof.proof.len()),
        ("circuit_hash", size_of_val(&leaf.proof.circuit_hash)),
        (
            "preprocessed_root",
            size_of_val(&leaf.proof.circuit_preprocessed_root.0),
        ),
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

#[derive(Serialize)]
struct Ledger {
    system: &'static str,
    version: String,
    artifact: &'static str,
    verifier: &'static str,
    hash: Hash,
    field: Field,
    n_vars: usize,
}

#[derive(Serialize)]
struct Hash {
    function: &'static str,
    /// 64-byte Blake2s compressions (`Stats::blake_updates`).
    compressions: usize,
    /// Gates that implement them: `blake_g` is 80 per compression (10 rounds of
    /// 8 G functions); `triple_xor` is the finalization; `m31_to_u32` re-encodes
    /// field elements as 32-bit words at the hash boundary.
    gates: HashGates,
}

#[derive(Serialize)]
struct HashGates {
    blake_g: usize,
    triple_xor: usize,
    m31_to_u32: usize,
}

#[derive(Serialize)]
struct Field {
    base: &'static str,
    /// Gate counts from the finalized circuit (`Circuit`).
    gates: FieldGates,
    /// Higher-level operations that the gates above already include.
    /// Inversions are not computed by the circuit: `inv`, `div` and
    /// `Simd::inv` each guess the result (a prover hint) and check it with
    /// one `mul` and one `eq`. The gate estimate prices them as computed
    /// in-circuit, since the verifier circuit's only input is the proof.
    ops: FieldOps,
}

#[derive(Serialize)]
struct FieldGates {
    add: usize,
    sub: usize,
    mul: usize,
    pointwise_mul: usize,
    eq: usize,
    permutation: usize,
    permutation_inputs: usize,
    output: usize,
}

#[derive(Serialize)]
struct FieldOps {
    /// `ops::inv`: QM31 inversions, one guess each.
    inv: usize,
    /// `ops::div`: QM31 divisions, one guess each.
    div: usize,
    /// `Simd::inv` calls (FRI twiddles), each inverting `len` M31 values at
    /// once. Counted by `patches/proving-49f8e037.patch`.
    m31_inv_calls: usize,
    /// M31 inversions performed by those calls (the sum of their `len`).
    m31_inv: usize,
    /// QM31 variables guessed by those calls (`ceil(len / 4)` each).
    m31_inv_vars: usize,
    /// All guessed (prover-supplied) variables.
    guess: usize,
    /// `inv + div + m31_inv_vars`: the guesses that are inversion results.
    guess_for_inversions: usize,
    /// The rest: the proof and public inputs entering the circuit (the
    /// circuit's actual input) and bit decompositions of values already in
    /// the circuit, both free in a Boolean circuit. See the README.
    guess_other: usize,
}

fn count(name: &str, out: &str) -> Result<()> {
    let context = verify_leaf(name)?;
    let (c, s) = (context.circuit(), context.stats());
    assert_eq!(c.blake_g_gate.len(), 80 * s.blake_updates);
    assert_eq!(
        c.permutation.iter().map(|p| p.inputs.len()).sum::<usize>(),
        s.permutation_inputs
    );
    let ledger = Ledger {
        system: "stwo",
        version: lock_version("stwo-cairo-prover"),
        artifact: "leaf circuit proof",
        verifier: "circuit_verifier::verify_circuit: the verifier is a stwo-circuits circuit; counts are its gates",
        hash: Hash {
            function: "blake2s",
            compressions: s.blake_updates,
            gates: HashGates {
                blake_g: c.blake_g_gate.len(),
                triple_xor: c.triple_xor.len(),
                m31_to_u32: c.m31_to_u32.len(),
            },
        },
        field: Field {
            base: "qm31",
            gates: FieldGates {
                add: c.add.len(),
                sub: c.sub.len(),
                mul: c.mul.len(),
                pointwise_mul: c.pointwise_mul.len(),
                eq: c.eq.len(),
                permutation: c.permutation.len(),
                permutation_inputs: s.permutation_inputs,
                output: c.output.len(),
            },
            ops: FieldOps {
                inv: s.inv,
                div: s.div,
                m31_inv_calls: s.simd_inv,
                m31_inv: s.simd_inv_lanes,
                m31_inv_vars: s.simd_inv_vars,
                guess: s.guess,
                guess_for_inversions: s.inv + s.div + s.simd_inv_vars,
                guess_other: s.guess - s.inv - s.div - s.simd_inv_vars,
            },
        },
        n_vars: c.n_vars,
    };
    let json = serde_json::to_string_pretty(&ledger)?;
    std::fs::write(out, format!("{json}\n"))?;
    let (h, f) = (&ledger.hash, &ledger.field);
    println!("blake2s compressions = {}", h.compressions);
    for (name, n) in [
        ("blake_g", h.gates.blake_g),
        ("triple_xor", h.gates.triple_xor),
        ("m31_to_u32", h.gates.m31_to_u32),
        ("qm31 add", f.gates.add),
        ("qm31 sub", f.gates.sub),
        ("qm31 mul", f.gates.mul),
        ("qm31 pointwise_mul", f.gates.pointwise_mul),
        ("eq", f.gates.eq),
        ("permutation", f.gates.permutation),
        ("output", f.gates.output),
    ] {
        println!("{n:>8}  {name} gates");
    }
    let o = &f.ops;
    println!(
        "guesses = {} = {} inversion results ({} qm31 inv + {} qm31 div + {} qm31 vars holding {} m31 inversions in {} Simd::inv calls) + {} proof, public input and bit-decomposition wires",
        o.guess,
        o.guess_for_inversions,
        o.inv,
        o.div,
        o.m31_inv_vars,
        o.m31_inv,
        o.m31_inv_calls,
        o.guess_other
    );
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

/// Version of `name` as pinned in this workspace's `Cargo.lock`.
#[derive(Serialize)]
struct Params {
    system: &'static str,
    version: String,
    artifact: &'static str,
    field: FieldParams,
    fri: FriParams,
    trace_log_size: u32,
    cairo_trace_log_size: u32,
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
    log_blowup: u32,
    queries: usize,
    log_fold: u32,
    log_last_layer_degree_bound: u32,
    pow_bits: u32,
}

#[derive(Serialize)]
struct Security {
    stated_bits: u32,
    basis: &'static str,
    source: &'static str,
}

/// Writes the proof-system parameters of the leaf verifier the proof
/// selects from the registry, after verifying the proof.
fn params(name: &str, out: &str) -> Result<()> {
    verify_leaf(name)?;
    let setup = leaf_setup(name)?;
    let params = Params {
        system: "stwo",
        version: lock_version("stwo-cairo-prover"),
        artifact: "leaf circuit proof",
        field: FieldParams {
            base: "m31",
            modulus: P,
            extension_degree: size_of::<QM31>() / size_of::<u32>(),
        },
        fri: FriParams {
            log_blowup: setup.fri.log_blowup_factor,
            queries: setup.fri.n_queries,
            log_fold: setup.fri.fold_step,
            log_last_layer_degree_bound: setup.fri.log_last_layer_degree_bound,
            pow_bits: setup.fri.pow_bits,
        },
        trace_log_size: setup.trace_log_size,
        cairo_trace_log_size: setup.cairo_trace_log_size,
        security: Security {
            stated_bits: setup.fri.security_bits(),
            basis: "conjectured: pow_bits + log_blowup * queries",
            source: "stwo/src/core/fri.rs, FriConfig::security_bits",
        },
    };
    std::fs::write(out, format!("{}\n", serde_json::to_string_pretty(&params)?))?;
    println!("{}", serde_json::to_string_pretty(&params)?);
    Ok(())
}

fn lock_version(name: &str) -> String {
    let lock = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/./Cargo.lock"));
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
        // The proving crates are redirected to the patched checkout (see
        // patch.sh), so the lock has no source for them; the revision is the
        // one Cargo.toml pins for the git dependencies they replace.
        None => manifest_git_rev().unwrap_or_else(|| version.to_string()),
    }
}

/// `starkware-libs/proving@<rev>` from the first git dependency on that
/// repository in Cargo.toml, which pins the revision patch.sh checks out.
fn manifest_git_rev() -> Option<String> {
    let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/./Cargo.toml"));
    let line = manifest
        .lines()
        .find(|l| l.contains("git = \"https://github.com/starkware-libs/proving\""))?;
    let rev = line.split("rev = \"").nth(1)?.split('"').next()?;
    Some(format!("starkware-libs/proving@{}", &rev[..8]))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match (
        args.get(1).map(String::as_str),
        args.get(2).map(String::as_str),
    ) {
        (Some("prove"), Some(g)) => prove(g),
        (Some("size"), Some(g)) => match g.strip_suffix(".leaf") {
            Some(inner) => size_leaf(
                inner,
                args.get(3)
                    .map_or("../results/stwo/size.json", String::as_str),
            ),
            None => size(g),
        },
        (Some("wrap"), Some(g)) => wrap(g),
        (Some("count"), Some(g)) => count(
            g,
            args.get(3)
                .map_or("../results/stwo/ops.json", String::as_str),
        ),
        (Some("params"), Some(g)) => params(
            g,
            args.get(3)
                .map_or("../results/stwo/params.json", String::as_str),
        ),
        _ => bail!("usage: stwo-size prove|wrap|size|count|params <trivial|fib|journal>[.leaf]"),
    }
}
