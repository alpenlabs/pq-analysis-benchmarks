//! `prove <guest>`: run the guest and write a succinct receipt to `artifacts/risc0/<guest>.bin`.
//! `size <guest> [out]`: read that receipt and report its serialized size per component;
//!                  write the proof size without public inputs as JSON (default
//!                  `results/risc0/size.json`; it is the same for every guest).
//! `count <guest> [out]`: verify that receipt with a counting hash suite and
//!                  patched field arithmetic, and write the operation ledger as
//!                  JSON (default `results/risc0/ops.json`; it is the same for
//!                  every guest).
//!
//! Guests: trivial, fib, journal.

mod count;

use anyhow::{bail, Result};
use risc0_circuit_recursion::CircuitImpl;
use risc0_core::field::baby_bear::{Elem, ExtElem, P};
use risc0_core::field::{Elem as _, ExtElem as _};
use risc0_zkp::adapter::CircuitInfo;
use risc0_zkvm::sha::{Digest, Digestible};
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

const MANIFEST: &str = "../artifacts/manifest.json";

/// Image ID the committed receipt of `name` must be bound to
/// (`artifacts/manifest.json`, written by `prove`).
fn expected_image_id(name: &str) -> Result<Digest> {
    let manifest: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(MANIFEST)?)?;
    let hex = manifest["risc0"][name]["image_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no risc0/{name} entry in {MANIFEST}"))?;
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<_, _>>()?;
    Ok(Digest::try_from(bytes.as_slice())?)
}

/// Loads the committed receipt and verifies it, seal and claim, against the
/// manifest's image ID with `ctx`.
fn load_receipt(name: &str, ctx: &VerifierContext) -> Result<Receipt> {
    let receipt: Receipt = bincode::deserialize(&std::fs::read(receipt_path(name))?)?;
    let image_id = expected_image_id(name).map_err(|e| {
        let claimed = receipt
            .claim()
            .ok()
            .and_then(|c| c.as_value().ok().map(|c| c.pre.digest()));
        anyhow::anyhow!("{e}; the committed receipt claims image ID {claimed:?}")
    })?;
    receipt.verify_with_context(ctx, image_id)?;
    Ok(receipt)
}

fn prove(name: &str) -> Result<()> {
    let (elf, id) = guest(name)?;
    let env = ExecutorEnv::builder().build()?;
    let info = default_prover().prove_with_opts(env, elf, &ProverOpts::succinct())?;
    info.receipt.verify(id)?;
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(MANIFEST)?)?;
    manifest["risc0"][name]["image_id"] = Digest::from(id).to_string().into();
    std::fs::write(
        MANIFEST,
        format!("{}\n", serde_json::to_string_pretty(&manifest)?),
    )?;
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

#[derive(Serialize)]
struct Size {
    /// Bytes a verifier needs beyond the public inputs: the seal, the
    /// control ID and its inclusion proof. Excludes claim, hashfn,
    /// verifier_parameters, journal and metadata.
    proof_bytes: usize,
    components: std::collections::BTreeMap<&'static str, usize>,
}

fn size(name: &str, out: &str) -> Result<()> {
    let bytes = std::fs::read(receipt_path(name))?;
    let receipt = load_receipt(name, &VerifierContext::default())?;
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
    let components = std::collections::BTreeMap::from([
        ("seal", s.seal.len() * 4),
        ("control_id", len(&s.control_id)?),
        ("control_inclusion_proof", len(&s.control_inclusion_proof)?),
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
    hash: count::Hash,
    field: count::Field,
}

fn count(name: &str, out: &str) -> Result<()> {
    let receipt: Receipt = bincode::deserialize(&std::fs::read(receipt_path(name))?)?;
    let image_id = load_receipt(name, &VerifierContext::default()).and(expected_image_id(name))?;
    let (suite, counters) = count::counting_suite();
    let mut suites = VerifierContext::default_hash_suites();
    suites.insert(suite.name.clone(), suite);
    let ctx = VerifierContext::default().with_suites(suites);
    let start = count::Ops::now();
    receipt.verify_with_context(&ctx, image_id)?;
    let total = count::Ops::now().since(start);
    let ledger = Ledger {
        system: "risc0",
        version: lock_version("risc0-zkvm"),
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

/// Version of `name` as pinned in this workspace's `Cargo.lock`.
#[derive(Serialize)]
struct Params {
    system: &'static str,
    version: String,
    artifact: &'static str,
    field: FieldParams,
    fri: FriParams,
    trace_log_size: u32,
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
    pow_bits: u32,
}

#[derive(Serialize)]
struct Security {
    stated_bits: u32,
    basis: &'static str,
    source: &'static str,
}

/// Writes the proof-system parameters the verifier is compiled with, read
/// from the `risc0-zkp` constants and the receipt itself.
fn params(name: &str, out: &str) -> Result<()> {
    let receipt = load_receipt(name, &VerifierContext::default())?;
    let InnerReceipt::Succinct(s) = &receipt.inner else {
        bail!("expected a succinct receipt");
    };
    // The seal starts with the circuit's globals followed by one element
    // holding the po2 of the trace, read the way `ReadIOP::read_slice_with_po2`
    // does.
    let po2 = Elem::from_u32_words(&[s.seal[CircuitImpl::OUTPUT_SIZE]]).to_u32_words()[0];
    assert!(po2 as usize <= risc0_zkp::MAX_CYCLES_PO2);
    let params = Params {
        system: "risc0",
        version: lock_version("risc0-zkvm"),
        artifact: "succinct receipt",
        field: FieldParams {
            base: "babybear",
            modulus: P,
            extension_degree: ExtElem::EXT_SIZE,
        },
        fri: FriParams {
            log_blowup: risc0_zkp::INV_RATE.trailing_zeros(),
            queries: risc0_zkp::QUERIES,
            log_fold: risc0_zkp::FRI_FOLD.trailing_zeros(),
            pow_bits: 0,
        },
        trace_log_size: po2,
        security: Security {
            stated_bits: 97,
            basis: "conjectured; no proof-of-work grinding",
            source: "risc0-zkp/src/lib.rs, doc comment on QUERIES",
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
                .map_or("../results/risc0/size.json", String::as_str),
        ),
        (Some("count"), Some(g)) => count(
            g,
            args.get(3)
                .map_or("../results/risc0/ops.json", String::as_str),
        ),
        (Some("params"), Some(g)) => params(
            g,
            args.get(3)
                .map_or("../results/risc0/params.json", String::as_str),
        ),
        _ => bail!("usage: host prove|size|count|params <trivial|fib|journal> [out.json]"),
    }
}
