//! Boolean gate counts of the primitives `gates.py` prices, measured with the
//! gate-count instrumentation of alpenlabs/g16 (`g16ckt`) at the pinned
//! revision and written to `results/gadgets.json`.
//!
//! Cost model: free-XOR garbling. "nonfree" is the AND-type gate count, XOR
//! and XNOR are free. Every gadget is evaluated on several inputs and its
//! output checked against native arithmetic before its count is recorded; the
//! count is the same on every input, since the circuits are data-independent.
//!
//! BLAKE3 and the Groth16 verifier are g16ckt's own gadgets. BLAKE2s and the
//! field operations are built here from the same u32 primitives
//! (`full_adder`, `bigint`), so all figures share one adder and one multiplier.

mod blake2s;
mod field;
mod groth16;
mod poseidon2;
mod qm31;

use std::collections::BTreeMap;

use g16ckt::circuit::CircuitBuilder;
use g16ckt::gadgets::hash::blake3::{HashOutput, InputMessage, blake3_hash};
use serde::Serialize;

#[derive(Serialize)]
pub struct Gadget {
    pub nonfree: u64,
    pub xor: u64,
    pub total: u64,
    pub validated_against: &'static str,
}

impl Gadget {
    pub fn new(nonfree: u64, total: u64, validated_against: &'static str) -> Self {
        Gadget {
            nonfree,
            xor: total - nonfree,
            total,
            validated_against,
        }
    }
}

#[derive(Serialize)]
struct Report {
    source: BTreeMap<&'static str, &'static str>,
    cost_model: &'static str,
    gadgets: BTreeMap<&'static str, Gadget>,
}

fn blake3_64b() -> Gadget {
    let input = [0xa5u8; 64];
    let res = CircuitBuilder::streaming_execute::<_, _, HashOutput>(
        InputMessage { byte_arr: input },
        10_000,
        |ctx, input| blake3_hash(ctx, *input),
    );
    assert_eq!(res.output_value.value, *blake3::hash(&input).as_bytes());
    let gc = &res.gate_count;
    Gadget::new(
        gc.nonfree_gate_count(),
        gc.total_gate_count(),
        "blake3 crate",
    )
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "../results/gadgets.json".into());
    let mut gadgets = BTreeMap::new();
    let mut record = |name: &'static str, g: Gadget| {
        println!(
            "{:<40} nonfree {:>13}  xor {:>13}  total {:>13}",
            name, g.nonfree, g.xor, g.total
        );
        gadgets.insert(name, g);
    };
    record("blake3_compression_64b", blake3_64b());
    record("blake2s_compression_64b", blake2s::measure());
    for (name, g) in field::measure() {
        record(name, g);
    }
    for (name, g) in poseidon2::measure() {
        record(name, g);
    }
    for (name, g) in qm31::measure() {
        record(name, g);
    }
    for (name, g) in groth16::measure() {
        record(name, g);
    }
    let report = Report {
        source: BTreeMap::from([
            ("repository", "https://github.com/alpenlabs/g16"),
            ("crate", "g16ckt"),
            ("rev", "f78c01da1ec9138b6c3a1c872405c1eefbaca48e"),
        ]),
        cost_model: "free-XOR garbling; nonfree = AND-type gates, xor = XOR/XNOR gates",
        gadgets,
    };
    std::fs::write(
        &out,
        format!("{}\n", serde_json::to_string_pretty(&report).unwrap()),
    )
    .unwrap();
    println!("written to {out}");
}
