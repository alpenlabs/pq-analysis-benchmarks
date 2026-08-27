//! Modular arithmetic gadgets for the three 31-bit primes, as the pinned
//! verifiers compute it: Montgomery form with REDC for BabyBear (risc0-core)
//! and KoalaBear (p3-koala-bear), Mersenne reduction for M31 (stwo). Each is
//! checked against a native reference on several inputs.

use std::collections::BTreeMap;

use g16ckt::WireId;
use g16ckt::circuit::{CircuitBuilder, ExecuteMode, FALSE_WIRE, StreamingMode};
use g16ckt::gadgets::bigint::{
    BigIntWires, add, add_without_carry, mul_by_constant, mul_by_constant_modulo_power_two,
    mul_karatsuba, self_or_zero, sub,
};
use g16ckt::gadgets::hash::blake3::{HashOutput, HashOutputWires, InputMessage, U8};
use num_bigint::BigUint;

use crate::Gadget;

pub const W: usize = 32;

pub const BABYBEAR_P: u32 = 0x7800_0001; // 2^31 - 2^27 + 1
pub const BABYBEAR_MU: u32 = 0x8800_0001; // -p^-1 mod 2^32 (risc0-core `M`)
pub const KOALABEAR_P: u32 = 0x7f00_0001; // 2^31 - 2^24 + 1
pub const KOALABEAR_MU: u32 = 0x8100_0001;
pub const M31_P: u32 = 0x7fff_ffff;

pub fn word(bytes: &[U8], off: usize, bits: usize) -> BigIntWires {
    BigIntWires {
        bits: (0..bits).map(|i| bytes[off + i / 8].0[i % 8]).collect(),
    }
}

pub fn pack_output(bits: &[WireId]) -> HashOutputWires {
    let mut all = [FALSE_WIRE; 256];
    all[..bits.len()].copy_from_slice(bits);
    let value: [U8; 32] = core::array::from_fn(|i| {
        let mut b = [FALSE_WIRE; 8];
        b.copy_from_slice(&all[i * 8..(i + 1) * 8]);
        U8(b)
    });
    HashOutputWires { value }
}

pub fn constant(n: u32) -> BigIntWires {
    BigIntWires::new_constant(W, &BigUint::from(n)).unwrap()
}

/// `x` (W bits) minus `p` if that does not borrow, else `x`.
fn reduce_once<C: g16ckt::CircuitContext>(circuit: &mut C, x: &BigIntWires, p: u32) -> BigIntWires {
    let d = sub(circuit, x, &constant(p)); // W + 1 bits, top = borrow
    let borrow = d.bits[W];
    let corr = self_or_zero(circuit, &constant(p), borrow);
    let reduced = BigIntWires {
        bits: d.bits[..W].to_vec(),
    };
    add_without_carry(circuit, &reduced, &corr)
}

/// REDC, mirroring `monty_reduce` (p3-koala-bear) and `mul` (risc0-core).
pub fn monty_mul<C: g16ckt::CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigIntWires,
    p: u32,
    mu: u32,
) -> BigIntWires {
    let x = mul_karatsuba(circuit, a, b); // 64 bits
    redc(circuit, &x, p, mu)
}

/// Montgomery reduction of a 64-bit `x` (`monty_reduce` in p3-koala-bear):
/// `x * 2^-32 mod p`, for `x < p * 2^32`.
pub fn redc<C: g16ckt::CircuitContext>(
    circuit: &mut C,
    x: &BigIntWires,
    p: u32,
    mu: u32,
) -> BigIntWires {
    assert_eq!(x.bits.len(), 2 * W);
    let x_lo = BigIntWires {
        bits: x.bits[..W].to_vec(),
    };
    let t = mul_by_constant_modulo_power_two(circuit, &x_lo, &BigUint::from(mu), W);
    let u = mul_by_constant(circuit, &t, &BigUint::from(p)); // 64 bits
    let d = sub(
        circuit,
        x,
        &BigIntWires {
            bits: u.bits[..2 * W].to_vec(),
        },
    );
    let over = d.bits[2 * W];
    let hi = BigIntWires {
        bits: d.bits[W..2 * W].to_vec(),
    };
    let corr = self_or_zero(circuit, &constant(p), over);
    add_without_carry(circuit, &hi, &corr)
}

/// Montgomery multiplication by a constant (already in Montgomery form).
pub fn monty_mul_const<C: g16ckt::CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    c: u32,
    p: u32,
    mu: u32,
) -> BigIntWires {
    let x = mul_by_constant(circuit, a, &BigUint::from(c)); // 64 bits
    redc(circuit, &x, p, mu)
}

fn monty_mul_ref(a: u32, b: u32, p: u32, mu: u32) -> u32 {
    let x = a as u64 * b as u64;
    let t = x.wrapping_mul(mu as u64) & 0xFFFF_FFFF;
    let u = t * p as u64;
    let (d, over) = x.overflowing_sub(u);
    ((d >> 32) as u32).wrapping_add(if over { p } else { 0 })
}

/// `a + b mod p` as both stacks write it: add, then subtract `p` unless that borrows.
pub fn mod_add<C: g16ckt::CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigIntWires,
    p: u32,
) -> BigIntWires {
    let s = add(circuit, a, b);
    let s = BigIntWires {
        bits: s.bits[..W].to_vec(),
    };
    reduce_once(circuit, &s, p)
}

/// `a - b mod p`: subtract, add back `p` if that borrowed.
pub fn mod_sub<C: g16ckt::CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigIntWires,
    p: u32,
) -> BigIntWires {
    let d = sub(circuit, a, b);
    let borrow = d.bits[W];
    let corr = self_or_zero(circuit, &constant(p), borrow);
    let d = BigIntWires {
        bits: d.bits[..W].to_vec(),
    };
    add_without_carry(circuit, &d, &corr)
}

/// Mersenne-31 multiply: 31x31 product, fold the high 31 bits onto the low
/// 31 twice, then subtract `p` once if needed (stwo `M31::reduce` semantics).
pub fn m31_mul<C: g16ckt::CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigIntWires,
) -> BigIntWires {
    let x = mul_karatsuba(circuit, a, b); // 62 bits
    let lo = BigIntWires {
        bits: x.bits[..31].to_vec(),
    };
    let hi = BigIntWires {
        bits: x.bits[31..62].to_vec(),
    };
    let s = add(circuit, &lo, &hi); // 32 bits, < 2^32 - 1
    let lo2 = BigIntWires {
        bits: s.bits[..31].to_vec(),
    };
    let hi2 = BigIntWires {
        bits: vec![s.bits[31]],
    };
    let mut hi2_padded = hi2.bits.clone();
    hi2_padded.resize(31, FALSE_WIRE);
    let r = add(circuit, &lo2, &BigIntWires { bits: hi2_padded }); // 32 bits, <= 2^31
    m31_bits(reduce_once(circuit, &r, M31_P))
}

/// Drops the top bit of a reduced 32-bit M31 value (it is zero) so M31
/// gadgets compose: they take and return 31-bit values.
fn m31_bits(x: BigIntWires) -> BigIntWires {
    BigIntWires {
        bits: x.bits[..31].to_vec(),
    }
}

pub fn m31_add<C: g16ckt::CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigIntWires,
) -> BigIntWires {
    // stwo `partial_reduce(a + b)`: a, b < p so the sum fits 32 bits.
    let s = add(circuit, a, b); // 32 bits
    m31_bits(reduce_once(circuit, &s, M31_P))
}

pub fn m31_sub<C: g16ckt::CircuitContext>(
    circuit: &mut C,
    a: &BigIntWires,
    b: &BigIntWires,
) -> BigIntWires {
    // stwo `partial_reduce(a + p - b)`, at 32 bits so a + p keeps its carry.
    let mut a32 = a.bits.clone();
    a32.push(FALSE_WIRE);
    let mut b32 = b.bits.clone();
    b32.push(FALSE_WIRE);
    let t = add(circuit, &BigIntWires { bits: a32 }, &constant(M31_P)); // 33 bits
    let t = BigIntWires {
        bits: t.bits[..W].to_vec(),
    };
    let d = sub(circuit, &t, &BigIntWires { bits: b32 }); // no borrow: a + p >= b
    let d = BigIntWires {
        bits: d.bits[..W].to_vec(),
    };
    m31_bits(reduce_once(circuit, &d, M31_P))
}

type Op = fn(&mut StreamingMode<ExecuteMode>, &BigIntWires, &BigIntWires) -> BigIntWires;

fn run(op: Op, bits: usize, a: u32, b: u32) -> (u32, u64, u64) {
    let mut msg = [0u8; 8];
    msg[..4].copy_from_slice(&a.to_le_bytes());
    msg[4..].copy_from_slice(&b.to_le_bytes());
    let res = CircuitBuilder::streaming_execute::<_, _, HashOutput>(
        InputMessage { byte_arr: msg },
        10_000,
        |ctx, input| {
            let x = word(&input.byte_arr, 0, bits);
            let y = word(&input.byte_arr, 4, bits);
            pack_output(&op(ctx, &x, &y).bits)
        },
    );
    let o = res.output_value.value;
    let gc = &res.gate_count;
    (
        u32::from_le_bytes([o[0], o[1], o[2], o[3]]),
        gc.nonfree_gate_count(),
        gc.total_gate_count(),
    )
}

fn measure_op(
    name: &'static str,
    op: Op,
    bits: usize,
    reference: impl Fn(u32, u32) -> u32,
    p: u32,
    validated_against: &'static str,
) -> (&'static str, Gadget) {
    let inputs = [
        (1, 1),
        (0x1234_5678 % p, 0x0765_4321 % p),
        (p - 1, p - 1),
        (p - 1, 1),
        (0, p - 1),
        (0x5a5a_5a5a % p, 0x3c3c_3c3c % p),
    ];
    let mut last: Option<Gadget> = None;
    for (a, b) in inputs {
        let (got, nonfree, total) = run(op, bits, a, b);
        assert_eq!(got, reference(a, b), "{name}({a:#x}, {b:#x})");
        let g = Gadget::new(nonfree, total, validated_against);
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
    let mut out = BTreeMap::new();
    for (field, p, mu) in [
        ("babybear", BABYBEAR_P, BABYBEAR_MU),
        ("koalabear", KOALABEAR_P, KOALABEAR_MU),
    ] {
        let names: [&'static str; 3] = match field {
            "babybear" => ["babybear_mul", "babybear_add", "babybear_sub"],
            _ => ["koalabear_mul", "koalabear_add", "koalabear_sub"],
        };
        let mul: Op = if field == "babybear" {
            |c, a, b| monty_mul(c, a, b, BABYBEAR_P, BABYBEAR_MU)
        } else {
            |c, a, b| monty_mul(c, a, b, KOALABEAR_P, KOALABEAR_MU)
        };
        let add_op: Op = if field == "babybear" {
            |c, a, b| mod_add(c, a, b, BABYBEAR_P)
        } else {
            |c, a, b| mod_add(c, a, b, KOALABEAR_P)
        };
        let sub_op: Op = if field == "babybear" {
            |c, a, b| mod_sub(c, a, b, BABYBEAR_P)
        } else {
            |c, a, b| mod_sub(c, a, b, KOALABEAR_P)
        };
        let reference = match field {
            "babybear" => "risc0-core baby_bear::mul/add/sub (u32 reference restated here)",
            _ => "p3-koala-bear monty_reduce/add/sub (u32 reference restated here)",
        };
        out.extend([
            measure_op(
                names[0],
                mul,
                W,
                |a, b| monty_mul_ref(a, b, p, mu),
                p,
                reference,
            ),
            measure_op(
                names[1],
                add_op,
                W,
                |a, b| ((a as u64 + b as u64) % p as u64) as u32,
                p,
                reference,
            ),
            measure_op(
                names[2],
                sub_op,
                W,
                |a, b| ((a as u64 + p as u64 - b as u64) % p as u64) as u32,
                p,
                reference,
            ),
        ]);
    }
    let p = M31_P as u64;
    let m31 = "stwo M31::reduce / partial_reduce (u64 reference restated here)";
    out.extend([
        measure_op(
            "m31_mul",
            m31_mul,
            31,
            |a, b| ((a as u64 * b as u64) % p) as u32,
            M31_P,
            m31,
        ),
        measure_op(
            "m31_add",
            m31_add,
            31,
            |a, b| ((a as u64 + b as u64) % p) as u32,
            M31_P,
            m31,
        ),
        measure_op(
            "m31_sub",
            m31_sub,
            31,
            |a, b| ((a as u64 + p - b as u64) % p) as u32,
            M31_P,
            m31,
        ),
        measure_op(
            "karatsuba_31x31",
            mul_karatsuba,
            31,
            |a, b| (a as u64 * b as u64) as u32,
            M31_P,
            "low 32 bits of the native product",
        ),
    ]);
    out
}
