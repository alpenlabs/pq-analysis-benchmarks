//! QM31 gadgets over the measured M31 gadgets, for pricing the gates of
//! Stwo's leaf verifier circuit. QM31 = CM31[u]/(u^2 - (2 + i)) with
//! CM31 = M31[i]/(i^2 + 1). Two multiplication layouts are measured:
//! Karatsuba at both levels with the constant 2 + i applied by adds, and the
//! schoolbook layout stwo's own `CM31::mul`/`QM31::mul` use (four M31
//! products per CM31 product, five CM31 products per QM31 product). Both are
//! checked against a native reference.

use std::collections::BTreeMap;

use g16ckt::circuit::{CircuitBuilder, ExecuteMode, StreamingMode};
use g16ckt::gadgets::bigint::BigIntWires;
use g16ckt::gadgets::hash::blake3::{HashOutput, InputMessage};

use crate::Gadget;
use crate::field::{M31_P, m31_add, m31_mul, m31_sub, pack_output, word};

type Ctx = StreamingMode<ExecuteMode>;
type Cm = [BigIntWires; 2];
type Qm = [BigIntWires; 4];

fn cm_add(c: &mut Ctx, a: &Cm, b: &Cm) -> Cm {
    [m31_add(c, &a[0], &b[0]), m31_add(c, &a[1], &b[1])]
}

fn cm_sub(c: &mut Ctx, a: &Cm, b: &Cm) -> Cm {
    [m31_sub(c, &a[0], &b[0]), m31_sub(c, &a[1], &b[1])]
}

/// (a + bi)(c + di) with four products, as stwo.
fn cm_mul_schoolbook(c: &mut Ctx, x: &Cm, y: &Cm) -> Cm {
    let ac = m31_mul(c, &x[0], &y[0]);
    let bd = m31_mul(c, &x[1], &y[1]);
    let ad = m31_mul(c, &x[0], &y[1]);
    let bc = m31_mul(c, &x[1], &y[0]);
    [m31_sub(c, &ac, &bd), m31_add(c, &ad, &bc)]
}

/// (a + bi)(c + di) with three products.
fn cm_mul_karatsuba(c: &mut Ctx, x: &Cm, y: &Cm) -> Cm {
    let ac = m31_mul(c, &x[0], &y[0]);
    let bd = m31_mul(c, &x[1], &y[1]);
    let s = m31_add(c, &x[0], &x[1]);
    let t = m31_add(c, &y[0], &y[1]);
    let st = m31_mul(c, &s, &t);
    let im = m31_sub(c, &st, &ac);
    [m31_sub(c, &ac, &bd), m31_sub(c, &im, &bd)]
}

/// (2 + i)(a + bi) = (2a - b) + (a + 2b)i, by adds.
fn cm_mul_r(c: &mut Ctx, x: &Cm) -> Cm {
    let a2 = m31_add(c, &x[0], &x[0]);
    let b2 = m31_add(c, &x[1], &x[1]);
    [m31_sub(c, &a2, &x[1]), m31_add(c, &x[0], &b2)]
}

fn split(q: &Qm) -> (Cm, Cm) {
    ([q[0].clone(), q[1].clone()], [q[2].clone(), q[3].clone()])
}

fn join(a: Cm, b: Cm) -> Qm {
    let [a0, a1] = a;
    let [b0, b1] = b;
    [a0, a1, b0, b1]
}

/// (A + B*u)(C + D*u) = (AC + R*BD) + (AD + BC)*u, as stwo (R BD is a general CM31 product).
fn qm_mul_schoolbook(c: &mut Ctx, x: &Qm, y: &Qm) -> Qm {
    let (a, b) = split(x);
    let (d, e) = split(y);
    let r: Cm = [
        BigIntWires::new_constant(31, &2u32.into()).unwrap(),
        BigIntWires::new_constant(31, &1u32.into()).unwrap(),
    ];
    let ac = cm_mul_schoolbook(c, &a, &d);
    let bd = cm_mul_schoolbook(c, &b, &e);
    let rbd = cm_mul_schoolbook(c, &r, &bd);
    let ad = cm_mul_schoolbook(c, &a, &e);
    let bc = cm_mul_schoolbook(c, &b, &d);
    join(cm_add(c, &ac, &rbd), cm_add(c, &ad, &bc))
}

/// Karatsuba at both levels; R applied by adds.
fn qm_mul_karatsuba(c: &mut Ctx, x: &Qm, y: &Qm) -> Qm {
    let (a, b) = split(x);
    let (d, e) = split(y);
    let ac = cm_mul_karatsuba(c, &a, &d);
    let bd = cm_mul_karatsuba(c, &b, &e);
    let s = cm_add(c, &a, &b);
    let t = cm_add(c, &d, &e);
    let st = cm_mul_karatsuba(c, &s, &t);
    let rbd = cm_mul_r(c, &bd);
    let mid = cm_sub(c, &st, &ac);
    join(cm_add(c, &ac, &rbd), cm_sub(c, &mid, &bd))
}

fn qm_pointwise_mul(c: &mut Ctx, x: &Qm, y: &Qm) -> Qm {
    core::array::from_fn(|i| m31_mul(c, &x[i], &y[i]))
}

fn qm_add(c: &mut Ctx, x: &Qm, y: &Qm) -> Qm {
    core::array::from_fn(|i| m31_add(c, &x[i], &y[i]))
}

fn qm_sub(c: &mut Ctx, x: &Qm, y: &Qm) -> Qm {
    core::array::from_fn(|i| m31_sub(c, &x[i], &y[i]))
}

// Native reference over u64.
const P: u64 = M31_P as u64;
fn nm(a: u64, b: u64) -> u64 {
    a * b % P
}
fn na(a: u64, b: u64) -> u64 {
    (a + b) % P
}
fn ns(a: u64, b: u64) -> u64 {
    (a + P - b) % P
}
fn ncm(x: [u64; 2], y: [u64; 2]) -> [u64; 2] {
    [
        ns(nm(x[0], y[0]), nm(x[1], y[1])),
        na(nm(x[0], y[1]), nm(x[1], y[0])),
    ]
}
fn nqm(x: [u64; 4], y: [u64; 4]) -> [u64; 4] {
    let (a, b) = ([x[0], x[1]], [x[2], x[3]]);
    let (d, e) = ([y[0], y[1]], [y[2], y[3]]);
    let ac = ncm(a, d);
    let rbd = ncm([2, 1], ncm(b, e));
    let ad = ncm(a, e);
    let bc = ncm(b, d);
    [
        na(ac[0], rbd[0]),
        na(ac[1], rbd[1]),
        na(ad[0], bc[0]),
        na(ad[1], bc[1]),
    ]
}

type Op = fn(&mut Ctx, &Qm, &Qm) -> Qm;

fn run(op: Op, x: [u64; 4], y: [u64; 4]) -> ([u64; 4], u64, u64) {
    let mut msg = [0u8; 32];
    for (i, v) in x.iter().chain(y.iter()).enumerate() {
        msg[4 * i..4 * i + 4].copy_from_slice(&(*v as u32).to_le_bytes());
    }
    let res = CircuitBuilder::streaming_execute::<_, _, HashOutput>(
        InputMessage { byte_arr: msg },
        10_000,
        |ctx, input| {
            let a: Qm = core::array::from_fn(|i| word(&input.byte_arr, 4 * i, 31));
            let b: Qm = core::array::from_fn(|i| word(&input.byte_arr, 16 + 4 * i, 31));
            let out = op(ctx, &a, &b);
            let bits: Vec<_> = out.iter().flat_map(padded32).collect();
            pack_output(&bits)
        },
    );
    let o = res.output_value.value;
    let got = core::array::from_fn(|i| {
        u32::from_le_bytes([o[4 * i], o[4 * i + 1], o[4 * i + 2], o[4 * i + 3]]) as u64
    });
    (
        got,
        res.gate_count.nonfree_gate_count(),
        res.gate_count.total_gate_count(),
    )
}

fn padded32(w: &BigIntWires) -> Vec<g16ckt::WireId> {
    let mut bits = w.bits.clone();
    bits.resize(32, g16ckt::circuit::FALSE_WIRE);
    bits
}

fn measure_op(
    name: &'static str,
    op: Op,
    reference: fn([u64; 4], [u64; 4]) -> [u64; 4],
) -> (&'static str, Gadget) {
    let inputs = [
        ([1, 2, 3, 4], [5, 6, 7, 8]),
        ([P - 1, P - 1, P - 1, P - 1], [P - 1, P - 1, P - 1, P - 1]),
        (
            [0x1234_5678, 0x0765_4321, 0x5a5a_5a5a, 0x3c3c_3c3c],
            [0x0f0f_0f0f, 0x7fff_0000, 0x0000_ffff, 0x1357_9bdf],
        ),
        ([0, 0, 0, P - 1], [0, 0, 0, P - 1]),
    ];
    let mut last: Option<Gadget> = None;
    for (x, y) in inputs {
        let (got, nonfree, total) = run(op, x, y);
        assert_eq!(got, reference(x, y), "{name}({x:?}, {y:?})");
        let g = Gadget::new(
            nonfree,
            total,
            "M31/CM31/QM31 arithmetic restated natively over u64",
        );
        if let Some(prev) = &last {
            assert_eq!(
                (prev.nonfree, prev.total),
                (g.nonfree, g.total),
                "{name}: data-dependent count"
            );
        }
        last = Some(g);
    }
    (name, last.unwrap())
}

pub fn measure() -> BTreeMap<&'static str, Gadget> {
    BTreeMap::from([
        measure_op("qm31_mul_karatsuba", qm_mul_karatsuba, nqm),
        measure_op("qm31_mul_schoolbook", qm_mul_schoolbook, nqm),
        measure_op("qm31_pointwise_mul", qm_pointwise_mul, |x, y| {
            core::array::from_fn(|i| nm(x[i], y[i]))
        }),
        measure_op("qm31_add", qm_add, |x, y| {
            core::array::from_fn(|i| na(x[i], y[i]))
        }),
        measure_op("qm31_sub", qm_sub, |x, y| {
            core::array::from_fn(|i| ns(x[i], y[i]))
        }),
    ])
}
