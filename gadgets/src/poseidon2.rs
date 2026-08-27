//! The two Poseidon2 permutations the verifiers hash with, as Boolean gadgets
//! over the Montgomery-form field gadgets, mirroring the pinned code step by
//! step: risc0-zkp's `poseidon2_mix` (BabyBear, width 24, x^7, 8 full and 21
//! partial rounds) and SP1's `my_kb_16_perm` (p3 Poseidon2 over KoalaBear,
//! width 16, x^3, 8 external and 20 internal rounds). Each is checked against
//! the native permutation on several states.

use std::collections::BTreeMap;

use g16ckt::circuit::{CircuitBuilder, ExecuteMode, FALSE_WIRE, StreamingMode};
use g16ckt::gadgets::bigint::{BigIntWires, add, sub};
use g16ckt::gadgets::hash::blake3::{HashOutput, InputMessage};
use p3_field::{AbstractField, PrimeField32};
use p3_symmetric::Permutation;
use risc0_zkp::core::hash::poseidon2::{
    CELLS, M_INT_DIAG_HZN, ROUND_CONSTANTS, ROUNDS_HALF_FULL, ROUNDS_PARTIAL, poseidon2_mix,
};
use risc0_zkp::field::baby_bear::BabyBearElem;

use crate::Gadget;
use crate::field::{
    BABYBEAR_MU, BABYBEAR_P, KOALABEAR_MU, KOALABEAR_P, W, constant, mod_add, monty_mul,
    monty_mul_const, pack_output, redc, word,
};

type Ctx = StreamingMode<ExecuteMode>;

// ---------------------------------------------------------------- risc0

fn bb_add(c: &mut Ctx, a: &BigIntWires, b: &BigIntWires) -> BigIntWires {
    mod_add(c, a, b, BABYBEAR_P)
}

fn bb_mul(c: &mut Ctx, a: &BigIntWires, b: &BigIntWires) -> BigIntWires {
    monty_mul(c, a, b, BABYBEAR_P, BABYBEAR_MU)
}

/// x^7 as risc0: x2 = x*x, x4 = x2*x2, x6 = x4*x2, x7 = x6*x.
fn bb_sbox(c: &mut Ctx, x: &BigIntWires) -> BigIntWires {
    let x2 = bb_mul(c, x, x);
    let x4 = bb_mul(c, &x2, &x2);
    let x6 = bb_mul(c, &x4, &x2);
    bb_mul(c, &x6, x)
}

fn bb_double(c: &mut Ctx, x: &BigIntWires) -> BigIntWires {
    bb_add(c, x, x)
}

/// `multiply_by_4x4_circulant`, with the 2x and 4x as doublings.
fn bb_circulant(c: &mut Ctx, x: &[BigIntWires]) -> [BigIntWires; 4] {
    let t0 = bb_add(c, &x[0], &x[1]);
    let t1 = bb_add(c, &x[2], &x[3]);
    let x1_2 = bb_double(c, &x[1]);
    let t2 = bb_add(c, &x1_2, &t1);
    let x3_2 = bb_double(c, &x[3]);
    let t3 = bb_add(c, &x3_2, &t0);
    let t1_2 = bb_double(c, &t1);
    let t1_4 = bb_double(c, &t1_2);
    let t4 = bb_add(c, &t1_4, &t3);
    let t0_2 = bb_double(c, &t0);
    let t0_4 = bb_double(c, &t0_2);
    let t5 = bb_add(c, &t0_4, &t2);
    let t6 = bb_add(c, &t3, &t5);
    let t7 = bb_add(c, &t2, &t4);
    [t6, t5, t7, t4]
}

fn bb_m_ext(c: &mut Ctx, cells: &mut [BigIntWires]) {
    let outs: Vec<[BigIntWires; 4]> = (0..CELLS / 4)
        .map(|i| bb_circulant(c, &cells[4 * i..4 * i + 4]))
        .collect();
    let mut sums: [BigIntWires; 4] = core::array::from_fn(|j| outs[0][j].clone());
    for out in &outs[1..] {
        for j in 0..4 {
            sums[j] = bb_add(c, &sums[j], &out[j]);
        }
    }
    for i in 0..CELLS {
        cells[i] = bb_add(c, &outs[i / 4][i % 4], &sums[i % 4]);
    }
}

fn bb_m_int(c: &mut Ctx, cells: &mut [BigIntWires]) {
    let mut sum = cells[0].clone();
    for cell in &cells[1..] {
        sum = bb_add(c, &sum, cell);
    }
    for i in 0..CELLS {
        let d = monty_mul_const(
            c,
            &cells[i],
            M_INT_DIAG_HZN[i].as_u32_montgomery(),
            BABYBEAR_P,
            BABYBEAR_MU,
        );
        cells[i] = bb_add(c, &sum, &d);
    }
}

fn bb_full_round(c: &mut Ctx, cells: &mut [BigIntWires], round: usize) {
    for i in 0..CELLS {
        let rc = constant(ROUND_CONSTANTS[round * CELLS + i].as_u32_montgomery());
        let s = bb_add(c, &cells[i], &rc);
        cells[i] = bb_sbox(c, &s);
    }
    bb_m_ext(c, cells);
}

fn bb_partial_round(c: &mut Ctx, cells: &mut [BigIntWires], round: usize) {
    let rc = constant(ROUND_CONSTANTS[round * CELLS].as_u32_montgomery());
    let s = bb_add(c, &cells[0], &rc);
    cells[0] = bb_sbox(c, &s);
    bb_m_int(c, cells);
}

fn risc0_permutation(c: &mut Ctx, cells: &mut [BigIntWires]) {
    let mut round = 0;
    bb_m_ext(c, cells);
    for _ in 0..ROUNDS_HALF_FULL {
        bb_full_round(c, cells, round);
        round += 1;
    }
    for _ in 0..ROUNDS_PARTIAL {
        bb_partial_round(c, cells, round);
        round += 1;
    }
    for _ in 0..ROUNDS_HALF_FULL {
        bb_full_round(c, cells, round);
        round += 1;
    }
}

// ---------------------------------------------------------------- sp1

const KW: usize = 16;

fn kb_add(c: &mut Ctx, a: &BigIntWires, b: &BigIntWires) -> BigIntWires {
    mod_add(c, a, b, KOALABEAR_P)
}

/// x^3 as p3 `cube`: x2 = x*x, x3 = x2*x.
fn kb_sbox(c: &mut Ctx, x: &BigIntWires) -> BigIntWires {
    let x2 = monty_mul(c, x, x, KOALABEAR_P, KOALABEAR_MU);
    monty_mul(c, &x2, x, KOALABEAR_P, KOALABEAR_MU)
}

/// p3 `apply_mat4`.
fn kb_mat4(c: &mut Ctx, x: &mut [BigIntWires]) {
    let t01 = kb_add(c, &x[0], &x[1]);
    let t23 = kb_add(c, &x[2], &x[3]);
    let t0123 = kb_add(c, &t01, &t23);
    let t01123 = kb_add(c, &t0123, &x[1]);
    let t01233 = kb_add(c, &t0123, &x[3]);
    let x0_2 = kb_add(c, &x[0], &x[0]);
    let x2_2 = kb_add(c, &x[2], &x[2]);
    let n3 = kb_add(c, &t01233, &x0_2);
    let n1 = kb_add(c, &t01123, &x2_2);
    let n0 = kb_add(c, &t01123, &t01);
    let n2 = kb_add(c, &t01233, &t23);
    x[0] = n0;
    x[1] = n1;
    x[2] = n2;
    x[3] = n3;
}

/// p3 `mds_light_permutation` for width 16.
fn kb_external_layer(c: &mut Ctx, state: &mut [BigIntWires]) {
    for i in (0..KW).step_by(4) {
        kb_mat4(c, &mut state[i..i + 4]);
    }
    let sums: [BigIntWires; 4] = core::array::from_fn(|k| {
        let mut s = state[k].clone();
        for j in (4..KW).step_by(4) {
            s = kb_add(c, &s, &state[j + k]);
        }
        s
    });
    for i in 0..KW {
        state[i] = kb_add(c, &state[i], &sums[i % 4]);
    }
}

fn widen(x: &BigIntWires, bits: usize) -> BigIntWires {
    let mut b = x.bits.clone();
    b.resize(bits, FALSE_WIRE);
    BigIntWires { bits: b }
}

fn trunc(x: &BigIntWires, bits: usize) -> BigIntWires {
    BigIntWires {
        bits: x.bits[..bits].to_vec(),
    }
}

/// p3-koala-bear's specialised internal layer for width 16: u64 sums of the
/// Montgomery values, the diagonal as shifts, one `monty_reduce` per cell.
fn kb_internal_layer(c: &mut Ctx, state: &mut [BigIntWires]) {
    const SHIFTS: [usize; 15] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15];
    // part_sum = sum of state[1..] (fits 36 bits), full_sum = part_sum + state[0].
    let mut part_sum = widen(&state[1], 2 * W);
    for s in &state[2..] {
        part_sum = trunc(&add(c, &part_sum, &widen(s, 2 * W)), 2 * W);
    }
    let full_sum = trunc(&add(c, &part_sum, &widen(&state[0], 2 * W)), 2 * W);
    // -state[0] as a Montgomery value: p - v (KoalaBear::neg = 0 - v).
    let neg0 = trunc(&sub(c, &constant(KOALABEAR_P), &state[0]), W);
    let s0 = trunc(&add(c, &part_sum, &widen(&neg0, 2 * W)), 2 * W);
    let mut new = vec![redc(c, &s0, KOALABEAR_P, KOALABEAR_MU)];
    for i in 1..KW {
        let mut shifted = vec![FALSE_WIRE; SHIFTS[i - 1]];
        shifted.extend_from_slice(&state[i].bits);
        shifted.resize(2 * W, FALSE_WIRE);
        let si = trunc(&add(c, &full_sum, &BigIntWires { bits: shifted }), 2 * W);
        new.push(redc(c, &si, KOALABEAR_P, KOALABEAR_MU));
    }
    state.clone_from_slice(&new);
}

fn kb_monty(x: u32) -> u32 {
    (((x as u64) << 32) % KOALABEAR_P as u64) as u32
}

fn sp1_permutation(c: &mut Ctx, state: &mut [BigIntWires]) {
    use slop_koala_bear::{
        KoalaBear_BEGIN_EXT_CONSTS, KoalaBear_END_EXT_CONSTS, KoalaBear_PARTIAL_CONSTS,
    };
    kb_external_layer(c, state);
    for rc in KoalaBear_BEGIN_EXT_CONSTS
        .iter()
        .chain(KoalaBear_END_EXT_CONSTS.iter())
        .take(4)
    {
        for i in 0..KW {
            let s = kb_add(c, &state[i], &constant(kb_monty(rc[i].as_canonical_u32())));
            state[i] = kb_sbox(c, &s);
        }
        kb_external_layer(c, state);
    }
    for rc in KoalaBear_PARTIAL_CONSTS.iter() {
        let s = kb_add(c, &state[0], &constant(kb_monty(rc.as_canonical_u32())));
        state[0] = kb_sbox(c, &s);
        kb_internal_layer(c, state);
    }
    for rc in KoalaBear_END_EXT_CONSTS.iter() {
        for i in 0..KW {
            let s = kb_add(c, &state[i], &constant(kb_monty(rc[i].as_canonical_u32())));
            state[i] = kb_sbox(c, &s);
        }
        kb_external_layer(c, state);
    }
}

// ---------------------------------------------------------------- harness

/// Runs `perm` on `state` (Montgomery words) and returns the first eight
/// output words (the digest the hash suites read) plus the gate counts.
fn run(perm: fn(&mut Ctx, &mut [BigIntWires]), state: &[u32]) -> ([u32; 8], u64, u64) {
    fn go<const N: usize>(
        perm: fn(&mut Ctx, &mut [BigIntWires]),
        state: &[u32],
    ) -> ([u32; 8], u64, u64) {
        let mut msg = [0u8; N];
        for (i, v) in state.iter().enumerate() {
            msg[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
        }
        let n = state.len();
        let res = CircuitBuilder::streaming_execute::<_, _, HashOutput>(
            InputMessage { byte_arr: msg },
            10_000,
            |ctx, input| {
                let mut cells: Vec<BigIntWires> =
                    (0..n).map(|i| word(&input.byte_arr, 4 * i, W)).collect();
                perm(ctx, &mut cells);
                let bits: Vec<_> = cells[..8].iter().flat_map(|w| w.bits.clone()).collect();
                pack_output(&bits)
            },
        );
        let o = res.output_value.value;
        let out = core::array::from_fn(|i| {
            u32::from_le_bytes([o[4 * i], o[4 * i + 1], o[4 * i + 2], o[4 * i + 3]])
        });
        (
            out,
            res.gate_count.nonfree_gate_count(),
            res.gate_count.total_gate_count(),
        )
    }
    match state.len() {
        24 => go::<96>(perm, state),
        16 => go::<64>(perm, state),
        _ => unreachable!(),
    }
}

fn states(width: usize) -> Vec<Vec<u32>> {
    vec![
        vec![0; width],
        (0..width as u32).collect(),
        (0..width as u32)
            .map(|i| i.wrapping_mul(0x9e37_79b9) & 0x7fff_ffff)
            .collect(),
    ]
}

pub fn measure() -> BTreeMap<&'static str, Gadget> {
    let mut out = BTreeMap::new();

    // risc0: the state is 24 raw (Montgomery) BabyBear words.
    let mut last: Option<Gadget> = None;
    for state in states(CELLS) {
        let state: Vec<u32> = state
            .iter()
            .map(|v| BabyBearElem::new(*v).as_u32_montgomery())
            .collect();
        let mut native: [BabyBearElem; CELLS] =
            core::array::from_fn(|i| BabyBearElem::new_raw(state[i]));
        poseidon2_mix(&mut native);
        let expected: [u32; 8] = core::array::from_fn(|i| native[i].as_u32_montgomery());
        let (got, nonfree, total) = run(risc0_permutation, &state);
        assert_eq!(got, expected, "risc0 poseidon2 mismatch");
        let g = Gadget::new(nonfree, total, "risc0-zkp poseidon2_mix");
        if let Some(prev) = &last {
            assert_eq!((prev.nonfree, prev.total), (g.nonfree, g.total));
        }
        last = Some(g);
    }
    out.insert("poseidon2_babybear_w24_permutation", last.unwrap());

    // sp1: canonical KoalaBear inputs, compared in Montgomery form.
    let perm = slop_koala_bear::my_kb_16_perm();
    let mut last: Option<Gadget> = None;
    for state in states(KW) {
        let native: [slop_koala_bear::KoalaBear; KW] =
            core::array::from_fn(|i| slop_koala_bear::KoalaBear::from_canonical_u32(state[i]));
        let native = perm.permute(native);
        let expected: [u32; 8] = core::array::from_fn(|i| kb_monty(native[i].as_canonical_u32()));
        let monty: Vec<u32> = state.iter().map(|v| kb_monty(*v)).collect();
        let (got, nonfree, total) = run(sp1_permutation, &monty);
        assert_eq!(got, expected, "sp1 poseidon2 mismatch");
        let g = Gadget::new(
            nonfree,
            total,
            "slop-koala-bear my_kb_16_perm (sp1-primitives poseidon2_init)",
        );
        if let Some(prev) = &last {
            assert_eq!((prev.nonfree, prev.total), (g.nonfree, g.total));
        }
        last = Some(g);
    }
    out.insert("poseidon2_koalabear_w16_permutation", last.unwrap());
    out
}
