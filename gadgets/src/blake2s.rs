//! BLAKE2s-256 (RFC 7693) over a fixed-length message, from the same u32
//! primitives as g16ckt's BLAKE3 gadget. Digests are checked against the
//! `blake2` crate.

use crate::Gadget;
use g16ckt::circuit::{CircuitBuilder, FALSE_WIRE};
use g16ckt::gadgets::basic::full_adder;
use g16ckt::gadgets::bigint::BigIntWires;
use g16ckt::gadgets::hash::blake3::{
    HashOutput, HashOutputWires, InputMessage, InputMessageWires, U8,
};
use g16ckt::{CircuitContext, Gate, WireId};
use num_bigint::BigUint;

#[derive(Debug, Clone, Copy)]
struct U32([WireId; 32]);

impl U32 {
    fn from_constant(n: u32) -> U32 {
        let wires: Vec<WireId> = BigIntWires::new_constant(32, &BigUint::from(n))
            .unwrap()
            .bits;
        U32(wires.try_into().unwrap())
    }

    fn xor<C: CircuitContext>(circuit: &mut C, a: U32, b: U32) -> U32 {
        let c: Vec<WireId> = (0..32)
            .map(|i| {
                let res = circuit.issue_wire();
                circuit.add_gate(Gate::xor(a.0[i], b.0[i], res));
                res
            })
            .collect();
        U32(c.try_into().unwrap())
    }

    /// BLAKE2s rotates right; bit i of the result is bit (i + n) mod 32 of the input.
    fn rotate_right(value: U32, n: u32) -> U32 {
        let mut result = [FALSE_WIRE; 32];
        let shift = (n % 32) as usize;
        for (i, result_i) in result.iter_mut().enumerate() {
            *result_i = value.0[(i + shift) % 32];
        }
        U32(result)
    }

    fn wrapping_add<C: CircuitContext>(circuit: &mut C, a: U32, b: U32) -> U32 {
        let mut result = [FALSE_WIRE; 32];
        let mut carry = FALSE_WIRE;
        for (i, result_i) in result.iter_mut().enumerate() {
            (*result_i, carry) = full_adder(circuit, a.0[i], b.0[i], carry);
        }
        U32(result)
    }

    /// Little-endian byte i of this word.
    fn byte(&self, i: usize) -> U8 {
        let mut b = [FALSE_WIRE; 8];
        b.copy_from_slice(&self.0[i * 8..(i + 1) * 8]);
        U8(b)
    }

    fn from_bytes_le(bytes: [U8; 4]) -> U32 {
        let mut w = [FALSE_WIRE; 32];
        for (i, byte) in bytes.iter().enumerate() {
            w[i * 8..(i + 1) * 8].copy_from_slice(&byte.0);
        }
        U32(w)
    }
}

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[allow(clippy::too_many_arguments)]
fn g<C: CircuitContext>(
    circuit: &mut C,
    v: &mut [U32; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: U32,
    y: U32,
) {
    v[a] = U32::wrapping_add(circuit, v[a], v[b]);
    v[a] = U32::wrapping_add(circuit, v[a], x);
    v[d] = U32::rotate_right(U32::xor(circuit, v[d], v[a]), 16);
    v[c] = U32::wrapping_add(circuit, v[c], v[d]);
    v[b] = U32::rotate_right(U32::xor(circuit, v[b], v[c]), 12);
    v[a] = U32::wrapping_add(circuit, v[a], v[b]);
    v[a] = U32::wrapping_add(circuit, v[a], y);
    v[d] = U32::rotate_right(U32::xor(circuit, v[d], v[a]), 8);
    v[c] = U32::wrapping_add(circuit, v[c], v[d]);
    v[b] = U32::rotate_right(U32::xor(circuit, v[b], v[c]), 7);
}

/// One BLAKE2s compression: `h <- F(h, m, t, last)`.
fn compress<C: CircuitContext>(
    circuit: &mut C,
    h: [U32; 8],
    m: [U32; 16],
    t: u64,
    last: bool,
) -> [U32; 8] {
    let mut v: [U32; 16] = core::array::from_fn(|i| {
        if i < 8 {
            h[i]
        } else {
            let mut c = IV[i - 8];
            // t and the finalization flag are circuit constants (the message length is
            // fixed by the circuit), so these XORs fold into constants and cost nothing.
            if i == 12 {
                c ^= t as u32;
            }
            if i == 13 {
                c ^= (t >> 32) as u32;
            }
            if i == 14 && last {
                c ^= 0xFFFF_FFFF;
            }
            U32::from_constant(c)
        }
    });

    for s in SIGMA.iter() {
        g(circuit, &mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(circuit, &mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(circuit, &mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(circuit, &mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(circuit, &mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(circuit, &mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(circuit, &mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(circuit, &mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    core::array::from_fn(|i| {
        let x = U32::xor(circuit, h[i], v[i]);
        U32::xor(circuit, x, v[i + 8])
    })
}

/// Unkeyed BLAKE2s-256 over a fixed-length message.
fn blake2s_hash<const N: usize, C: CircuitContext>(
    circuit: &mut C,
    input: InputMessageWires<N>,
) -> HashOutputWires {
    // Parameter block: digest length 32, key length 0, fanout 1, depth 1.
    let mut h: [U32; 8] = core::array::from_fn(|i| {
        U32::from_constant(if i == 0 { IV[0] ^ 0x0101_0020 } else { IV[i] })
    });

    let zero_byte = U8([FALSE_WIRE; 8]);
    let n_blocks = if N == 0 { 1 } else { N.div_ceil(64) };

    for blk in 0..n_blocks {
        let m: [U32; 16] = core::array::from_fn(|w| {
            let bytes: [U8; 4] = core::array::from_fn(|b| {
                let idx = blk * 64 + w * 4 + b;
                if idx < N {
                    input.byte_arr[idx]
                } else {
                    zero_byte
                }
            });
            U32::from_bytes_le(bytes)
        });
        let last = blk == n_blocks - 1;
        let t = if last {
            N as u64
        } else {
            ((blk + 1) * 64) as u64
        };
        h = compress(circuit, h, m, t, last);
    }

    let value: [U8; 32] = core::array::from_fn(|i| h[i / 4].byte(i % 4));
    HashOutputWires { value }
}

/// One 64-byte block: a Merkle node or one absorbed block.
pub fn measure() -> Gadget {
    use blake2::Digest;
    let mut last = None;
    for fill in [0x00u8, 0xa5, 0xff] {
        let input = [fill; 64];
        let res = CircuitBuilder::streaming_execute::<_, _, HashOutput>(
            InputMessage { byte_arr: input },
            10_000,
            |ctx, input| blake2s_hash(ctx, *input),
        );
        let expected: [u8; 32] = blake2::Blake2s256::digest(input).into();
        assert_eq!(res.output_value.value, expected, "blake2s digest mismatch");
        let gc = &res.gate_count;
        let g = Gadget::new(
            gc.nonfree_gate_count(),
            gc.total_gate_count(),
            "blake2 crate",
        );
        if let Some(prev) = &last {
            let prev: &Gadget = prev;
            assert_eq!((prev.nonfree, prev.total), (g.nonfree, g.total));
        }
        last = Some(g);
    }
    last.unwrap()
}
