//! g16ckt's Groth16 (BN254) verifier gadget, the baseline the STARK verifiers
//! are compared with. Follows g16ckt's `groth16_gc_gate_count` example: a
//! deterministic dummy circuit is set up and proved with arkworks, and the
//! in-circuit verifier is run on the real proof, whose acceptance is the
//! validation. The verifier has one public input; each further input adds
//! one G1 scalar multiplication.

use g16ckt::ark::{self, AffineRepr, CircuitSpecificSetupSNARK, SNARK, UniformRand};
use g16ckt::circuit::{CircuitBuilder, StreamingResult};
use g16ckt::{Groth16VerifyInput, groth16_verify, groth16_verify_compressed};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::Gadget;

#[derive(Copy, Clone)]
struct Dummy<F: ark::PrimeField> {
    a: Option<F>,
    b: Option<F>,
    num_variables: usize,
    num_constraints: usize,
}

impl<F: ark::PrimeField> ark::ConstraintSynthesizer<F> for Dummy<F> {
    fn generate_constraints(
        self,
        cs: ark::ConstraintSystemRef<F>,
    ) -> Result<(), ark::SynthesisError> {
        let missing = ark::SynthesisError::AssignmentMissing;
        let a = cs.new_witness_variable(|| self.a.ok_or(missing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(missing))?;
        let c = cs.new_input_variable(|| Ok(self.a.ok_or(missing)? * self.b.ok_or(missing)?))?;
        for _ in 0..(self.num_variables - 3) {
            cs.new_witness_variable(|| self.a.ok_or(missing))?;
        }
        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(ark::lc!() + a, ark::lc!() + b, ark::lc!() + c)?;
        }
        cs.enforce_constraint(ark::lc!(), ark::lc!(), ark::lc!())?;
        Ok(())
    }
}

/// Returns (uncompressed proof verifier, compressed proof verifier).
pub fn measure() -> [(&'static str, Gadget); 2] {
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = Dummy::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << 6,
    };
    let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).unwrap();
    let public = circuit.a.unwrap() * circuit.b.unwrap();
    let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).unwrap();
    let input = Groth16VerifyInput {
        public: vec![public],
        a: proof.a.into_group(),
        b: proof.b.into_group(),
        c: proof.c.into_group(),
        vk,
    };

    let full: StreamingResult<_, _, bool> =
        CircuitBuilder::streaming_execute(input.clone(), 160_000, groth16_verify);
    assert!(full.output_value, "groth16_verify rejected a valid proof");
    let compressed: StreamingResult<_, _, bool> =
        CircuitBuilder::streaming_execute(input.compress(), 160_000, groth16_verify_compressed);
    assert!(
        compressed.output_value,
        "groth16_verify_compressed rejected a valid proof"
    );

    let validated = "arkworks Groth16 proof accepted by the in-circuit verifier";
    [
        (
            "groth16_bn254_verify_1_input",
            Gadget::new(
                full.gate_count.nonfree_gate_count(),
                full.gate_count.total_gate_count(),
                validated,
            ),
        ),
        (
            "groth16_bn254_verify_compressed_1_input",
            Gadget::new(
                compressed.gate_count.nonfree_gate_count(),
                compressed.gate_count.total_gate_count(),
                validated,
            ),
        ),
    ]
}
