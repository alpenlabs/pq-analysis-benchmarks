//! Operation count of succinct-receipt verification.
//!
//! A counting `HashSuite` replaces the stock `poseidon2` suite in the
//! `VerifierContext`; the verifier itself is not modified. Permutation buckets
//! are named after the `HashFn`/`Rng` trait methods through which they are
//! reached, so the numbers carry no interpretation of their own.
//!
//! Base-field operations are read from the counters that
//! `patches/risc0-core-3.0.2.patch` adds to the `BabyBearElem` operator impls.
//! The suite snapshots them around every call it forwards, so the operations
//! spent inside the hash suite (Poseidon2 is itself BabyBear arithmetic) are
//! separated from the rest of the verifier without being estimated.

use std::collections::BTreeMap;
use std::rc::Rc;

use risc0_core::field::baby_bear::counters;
use risc0_zkp::core::digest::Digest;
use risc0_zkp::core::hash::poseidon2::{
    unpadded_hash, Poseidon2HashSuite, CELLS, CELLS_OUT, CELLS_RATE, ROUNDS_HALF_FULL,
    ROUNDS_PARTIAL,
};
use risc0_zkp::core::hash::{HashFn, HashSuite, Rng, RngFactory};
use risc0_zkp::field::baby_bear::{BabyBear, BabyBearElem, BabyBearExtElem};
use risc0_zkp::field::{Elem as _, ExtElem as _};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

/// Permutations performed by `unpadded_hash` on `n` elements: one per full
/// rate block, plus one for a partial block or for the empty input.
pub fn unpadded_hash_perms(n: usize) -> usize {
    n / CELLS_RATE + usize::from(!n.is_multiple_of(CELLS_RATE) || n == 0)
}

/// Snapshot of the patched risc0-core counters.
#[derive(Clone, Copy, Default, Serialize)]
pub struct Ops {
    pub mul: u64,
    pub add: u64,
    pub sub: u64,
    #[serde(skip)]
    pub pow_calls: u64,
    #[serde(skip)]
    pub pow_mul: u64,
    #[serde(skip)]
    pub inv_calls: u64,
}

impl Ops {
    pub fn now() -> Self {
        Ops {
            mul: counters::MUL.load(Relaxed),
            add: counters::ADD.load(Relaxed),
            sub: counters::SUB.load(Relaxed),
            pow_calls: counters::POW_CALLS.load(Relaxed),
            pow_mul: counters::POW_MUL.load(Relaxed),
            inv_calls: counters::INV_CALLS.load(Relaxed),
        }
    }

    pub fn since(self, start: Ops) -> Ops {
        Ops {
            mul: self.mul - start.mul,
            add: self.add - start.add,
            sub: self.sub - start.sub,
            pow_calls: self.pow_calls - start.pow_calls,
            pow_mul: self.pow_mul - start.pow_mul,
            inv_calls: self.inv_calls - start.inv_calls,
        }
    }
}

/// Attributes the field operations performed while it is alive to the hash suite.
struct InSuite<'a>(&'a Counters, Ops);

impl<'a> InSuite<'a> {
    fn new(c: &'a Counters) -> Self {
        InSuite(c, Ops::now())
    }
}

impl Drop for InSuite<'_> {
    fn drop(&mut self) {
        let d = Ops::now().since(self.1);
        self.0.suite_mul.fetch_add(d.mul, Relaxed);
        self.0.suite_add.fetch_add(d.add, Relaxed);
        self.0.suite_sub.fetch_add(d.sub, Relaxed);
    }
}

#[derive(Default)]
pub struct Counters {
    suite_mul: AtomicU64,
    suite_add: AtomicU64,
    suite_sub: AtomicU64,
    pair_calls: AtomicUsize,
    elem_calls: AtomicUsize,
    elem_perms: AtomicUsize,
    elem_hist: Mutex<BTreeMap<usize, usize>>,
    ext_calls: AtomicUsize,
    ext_perms: AtomicUsize,
    ext_hist: Mutex<BTreeMap<usize, usize>>,
    rng_mixes: AtomicUsize,
    rng_squeezed: AtomicUsize,
    rng_perms: AtomicUsize,
}

/// `HashFn` is `Send + Sync`, so the stock (private) `Poseidon2HashFn` cannot
/// be wrapped; its three methods are restated over the public `unpadded_hash`.
struct CountingHashFn(Arc<Counters>);

fn to_digest(elems: [BabyBearElem; CELLS_OUT]) -> Box<Digest> {
    Box::new(Digest::from(elems.map(|e| e.as_u32_montgomery())))
}

impl HashFn<BabyBear> for CountingHashFn {
    fn hash_pair(&self, a: &Digest, b: &Digest) -> Box<Digest> {
        let _g = InSuite::new(&self.0);
        self.0.pair_calls.fetch_add(1, Relaxed);
        let both: Vec<BabyBearElem> = a
            .as_words()
            .iter()
            .chain(b.as_words())
            .map(|w| BabyBearElem::new_raw(*w))
            .collect();
        assert_eq!(both.len(), CELLS_RATE);
        assert!(both.iter().all(|e| e.is_reduced()));
        to_digest(unpadded_hash(both.iter()))
    }

    fn hash_elem_slice(&self, slice: &[BabyBearElem]) -> Box<Digest> {
        let _g = InSuite::new(&self.0);
        self.0.elem_calls.fetch_add(1, Relaxed);
        self.0
            .elem_perms
            .fetch_add(unpadded_hash_perms(slice.len()), Relaxed);
        *self
            .0
            .elem_hist
            .lock()
            .unwrap()
            .entry(slice.len())
            .or_default() += 1;
        to_digest(unpadded_hash(slice.iter()))
    }

    fn hash_ext_elem_slice(&self, slice: &[BabyBearExtElem]) -> Box<Digest> {
        let _g = InSuite::new(&self.0);
        let n = slice.len() * BabyBearExtElem::EXT_SIZE;
        self.0.ext_calls.fetch_add(1, Relaxed);
        self.0.ext_perms.fetch_add(unpadded_hash_perms(n), Relaxed);
        *self
            .0
            .ext_hist
            .lock()
            .unwrap()
            .entry(slice.len())
            .or_default() += 1;
        to_digest(unpadded_hash(
            slice.iter().flat_map(|e| e.subelems().iter()),
        ))
    }

    fn is_digest_valid(&self, digest: &Digest) -> bool {
        digest
            .as_words()
            .iter()
            .all(|w| BabyBearElem::new_raw(*w).is_reduced())
    }
}

/// Delegates to the stock `Poseidon2Rng` for values and mirrors its
/// `pool_used` accounting to count permutations: `mix` flushes a partially
/// squeezed pool (one permutation) and then permutes once more; squeezing
/// permutes once per `CELLS_RATE` elements drawn.
struct CountingRng {
    inner: Box<dyn Rng<BabyBear>>,
    c: Arc<Counters>,
    pool_used: usize,
}

impl CountingRng {
    fn squeeze(&mut self, n: usize) {
        for _ in 0..n {
            if self.pool_used == CELLS_RATE {
                self.c.rng_perms.fetch_add(1, Relaxed);
                self.pool_used = 0;
            }
            self.pool_used += 1;
        }
        self.c.rng_squeezed.fetch_add(n, Relaxed);
    }
}

impl Rng<BabyBear> for CountingRng {
    fn mix(&mut self, val: &Digest) {
        let _g = InSuite::new(&self.c);
        self.c.rng_mixes.fetch_add(1, Relaxed);
        let flush = usize::from(self.pool_used != 0);
        self.c.rng_perms.fetch_add(1 + flush, Relaxed);
        self.pool_used = 0;
        self.inner.mix(val)
    }

    fn random_bits(&mut self, bits: usize) -> u32 {
        self.squeeze(4); // Poseidon2Rng::random_bits draws four elements
        let _g = InSuite::new(&self.c);
        self.inner.random_bits(bits)
    }

    fn random_elem(&mut self) -> BabyBearElem {
        self.squeeze(1);
        let _g = InSuite::new(&self.c);
        self.inner.random_elem()
    }

    fn random_ext_elem(&mut self) -> BabyBearExtElem {
        self.squeeze(BabyBearExtElem::EXT_SIZE);
        let _g = InSuite::new(&self.c);
        self.inner.random_ext_elem()
    }
}

struct CountingRngFactory {
    inner: Rc<dyn RngFactory<BabyBear>>,
    c: Arc<Counters>,
}

impl RngFactory<BabyBear> for CountingRngFactory {
    fn new_rng(&self) -> Box<dyn Rng<BabyBear>> {
        Box::new(CountingRng {
            inner: self.inner.new_rng(),
            c: self.c.clone(),
            pool_used: 0,
        })
    }
}

/// A `poseidon2` suite that counts; drop-in for the stock one.
pub fn counting_suite() -> (HashSuite<BabyBear>, Arc<Counters>) {
    let c = Arc::new(Counters::default());
    let stock = Poseidon2HashSuite::new_suite();
    let suite = HashSuite {
        name: "poseidon2".into(),
        hashfn: Rc::new(CountingHashFn(c.clone())),
        rng: Rc::new(CountingRngFactory {
            inner: stock.rng,
            c: c.clone(),
        }),
    };
    (suite, c)
}

#[derive(Serialize)]
pub struct Perms {
    pub hash_pair: usize,
    pub hash_elem_slice: usize,
    pub hash_ext_elem_slice: usize,
    pub rng: usize,
    pub total: usize,
}

#[derive(Serialize)]
pub struct Calls {
    pub hash_pair: usize,
    pub hash_elem_slice: usize,
    /// slice length in base elements -> number of calls
    pub hash_elem_slice_len_histogram: BTreeMap<usize, usize>,
    pub hash_ext_elem_slice: usize,
    /// slice length in extension elements -> number of calls
    pub hash_ext_elem_slice_len_histogram: BTreeMap<usize, usize>,
    pub rng_mix: usize,
    pub rng_elems_squeezed: usize,
}

#[derive(Serialize)]
pub struct Hash {
    pub function: &'static str,
    pub state_cells: usize,
    pub rate: usize,
    pub rounds_full: usize,
    pub rounds_partial: usize,
    pub permutations: Perms,
    pub calls: Calls,
}

#[derive(Serialize)]
pub struct Pow {
    /// `Elem::pow` calls, `inv` included. Each is square-and-multiply, so its
    /// multiplication count depends on the exponent bits (query positions are
    /// Fiat-Shamir derived).
    pub calls: u64,
    /// `Elem::inv` calls; each is `pow(P - 2)`, a fixed 61 multiplications.
    pub inv_calls: u64,
    /// Multiplications performed inside those `pow` calls. Kept out of
    /// `residual` because the count varies with the seal (by a few hundred
    /// across guests), so `residual` diffs exactly and this field is compared
    /// within a tolerance. The gate estimate prices it with `residual`: the
    /// verifier circuit's only input is the proof, so exponentiations and
    /// inversions are computed in-circuit, not supplied as witnesses.
    pub mul: u64,
}

#[derive(Serialize)]
pub struct Field {
    pub base: &'static str,
    pub counted_at: &'static str,
    /// Spent inside the hash suite: the Poseidon2 permutations plus the
    /// `Rng::mix` digest absorption. Charged to the hash, not to the verifier.
    pub in_hash_suite: Ops,
    /// The verifier's own arithmetic, excluding the hash suite and the
    /// multiplications inside `pow` (recorded separately as `pow.mul`).
    pub residual: Ops,
    pub pow: Pow,
    /// `in_hash_suite.mul / permutations`; exact, since only permutations multiply.
    pub mul_per_permutation: u64,
}

impl Counters {
    /// `total` is the counter delta over the whole verification.
    pub fn field(&self, total: Ops) -> Field {
        let in_hash_suite = Ops {
            mul: self.suite_mul.load(Relaxed),
            add: self.suite_add.load(Relaxed),
            sub: self.suite_sub.load(Relaxed),
            ..Ops::default()
        };
        let perms = self.report().permutations.total as u64;
        assert_eq!(in_hash_suite.mul % perms, 0);
        let mut residual = total.since(in_hash_suite);
        residual.mul -= total.pow_mul;
        Field {
            base: "babybear",
            counted_at: "Elem Add/Sub/Mul operator impls; extension-field ops decompose into these",
            in_hash_suite,
            residual,
            pow: Pow {
                calls: total.pow_calls,
                inv_calls: total.inv_calls,
                mul: total.pow_mul,
            },
            mul_per_permutation: in_hash_suite.mul / perms,
        }
    }

    pub fn report(&self) -> Hash {
        let get = |a: &AtomicUsize| a.load(Relaxed);
        let (pair, elem, ext, rng) = (
            get(&self.pair_calls),
            get(&self.elem_perms),
            get(&self.ext_perms),
            get(&self.rng_perms),
        );
        Hash {
            function: "poseidon2-babybear",
            state_cells: CELLS,
            rate: CELLS_RATE,
            rounds_full: 2 * ROUNDS_HALF_FULL,
            rounds_partial: ROUNDS_PARTIAL,
            permutations: Perms {
                hash_pair: pair,
                hash_elem_slice: elem,
                hash_ext_elem_slice: ext,
                rng,
                total: pair + elem + ext + rng,
            },
            calls: Calls {
                hash_pair: pair,
                hash_elem_slice: get(&self.elem_calls),
                hash_elem_slice_len_histogram: self.elem_hist.lock().unwrap().clone(),
                hash_ext_elem_slice: get(&self.ext_calls),
                hash_ext_elem_slice_len_histogram: self.ext_hist.lock().unwrap().clone(),
                rng_mix: get(&self.rng_mixes),
                rng_elems_squeezed: get(&self.rng_squeezed),
            },
        }
    }
}
