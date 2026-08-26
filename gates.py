#!/usr/bin/env python3
"""Boolean-gate estimate of each verifier from results/<system>/ops.json.

Costs are nonfree gates under free-XOR (AND-type gates; XOR is free), from
the alpenlabs/g16 gate-count instrumentation: BLAKE3 from g16ckt's production
gadget (commit c9c24b3c); BLAKE2s, Montgomery-31 and Mersenne-31 primitives
built from the same u32 gadgets (commit 3f14a757). Not every figure is a
measured gadget; each entry in COSTS carries a `basis` (measured, priced,
assumed) and the table reports the weakest basis behind each row.

Each system is totalled under its deployed hash and under every hash in
SWAPS (BLAKE3, BLAKE2s, and the two Poseidon2 instances Risc0 and SP1
ship), replacing each hash unit one-for-one and leaving the field
arithmetic unchanged. That mapping is exact for Merkle 2-to-1 compressions
and approximate for sponge absorbs and Fiat-Shamir squeezes, and other than
the deployed hash it assumes a fork of prover and verifier that does not
exist.

Only field arithmetic and hash compressions are priced. Equality checks,
permutation networks, witness wires and re-encodings between field and
32-bit words are counted in the ledgers but not priced here.
"""

import json
import sys

# basis: "measured" = complete gadget built in g16, output validated against the
# crate's native arithmetic, gates counted; "priced" = assembled from measured
# primitives without validating the composite; "assumed" = no measurement.
COSTS = {
    "blake3_compression": {
        "nonfree": 10848,
        "basis": "measured",
        "note": "g16ckt blake3_hash gadget, 64-byte block: 10,752 AND + 96 OR",
    },
    "blake2s_compression": {
        "nonfree": 15360,
        "basis": "measured",
        "note": "BLAKE2s-256 from the same u32 primitives, digests validated: 10 rounds x 8 G x 6 adds x 32 AND",
    },
    "babybear": {
        "mul": {"nonfree": 2091, "basis": "measured", "note": "Montgomery multiply, validated against risc0-core baby_bear::mul"},
        "add": {"nonfree": 128, "basis": "measured", "note": "modular add"},
        "sub": {"nonfree": 128, "basis": "assumed", "note": "taken equal to add; not measured"},
    },
    "koalabear": {
        "mul": {"nonfree": 2190, "basis": "measured", "note": "Montgomery multiply, validated against p3-koala-bear monty_reduce"},
        "add": {"nonfree": 128, "basis": "measured", "note": "modular add"},
        "sub": {"nonfree": 128, "basis": "assumed", "note": "taken equal to add; not measured"},
    },
    "m31": {
        "mul": {
            "nonfree": 1888,
            "basis": "priced",
            "note": "measured 31x31 Karatsuba multiplier (1,702) + Mersenne reduction priced from measured primitives (two 31-bit adds, sub, select = 186); composite not validated",
        },
        "add": {"nonfree": 31, "basis": "priced", "note": "31-bit adder; stwo's partial_reduce conditional subtract not included, so a floor"},
        "sub": {"nonfree": 31, "basis": "priced", "note": "as add"},
    },
}

# M31 operations per QM31 gate. The gate is a field multiplication; how a
# Boolean gadget implements it is a choice. stwo's own code
# (crates/stwo/src/core/fields/{cm31,qm31}.rs) is schoolbook at both levels
# and multiplies by R = 2 + i as a general CM31 multiplication: 20 M31 muls
# and 14 adds. Karatsuba at both levels with R applied by shifts gives 9 muls
# and 29 adds. The estimate uses Karatsuba; both are recorded.
QM31 = {
    "basis": "assumed",
    "used": "karatsuba",
    "karatsuba": {
        "mul": {"mul": 9, "add": 29},
        "pointwise_mul": {"mul": 4, "add": 0},
        "add": {"mul": 0, "add": 4},
        "sub": {"mul": 0, "add": 4},
    },
    "schoolbook_as_in_stwo": {
        "mul": {"mul": 20, "add": 14},
        "pointwise_mul": {"mul": 4, "add": 0},
        "add": {"mul": 0, "add": 4},
        "sub": {"mul": 0, "add": 4},
    },
}


# Poseidon2 permutation composition, from the round structure of the pinned
# code (risc0-zkp poseidon2/mod.rs; p3-poseidon2 with p3-koala-bear's
# specialised internal layer). The field counters count every `Elem * Elem`,
# including multiplications by constants, which a Boolean gadget implements
# far more cheaply than a general multiply; the composition separates them.
# `general`/`const_arbitrary`/`const_pow2` sum to the ledger's
# mul_per_permutation, which the script asserts. There is no measured
# Poseidon2 gadget. "counted_as_general" prices the counted operations with
# every multiplication a general multiply; this is what the table uses. The
# bracket adds any uncounted linear-layer work and then prices constant
# multiplications as general multiplies ("upper"), power-of-two constants as
# modular adds ("lower"), or all constants as modular adds ("floor").
POSEIDON2 = {
    "risc0": {
        "width": 24,
        "sbox": 7,
        "rounds_full": 8,
        "rounds_partial": 21,
        "general": 852,  # 4 muls x 24 cells x 8 full rounds + 4 muls x 21 partial rounds (x^7)
        "const_arbitrary": 504,  # M_INT_DIAG_HZN, 24 per partial round
        "const_pow2": 216,  # M_EXT 4x4 circulant: x2, x4; 4 per chunk x 6 chunks x 9 applications
        "add": 2301,
        "sub": 0,
        "uncounted_add_equiv": 0,
    },
    "sp1": {
        "width": 16,
        "sbox": 3,
        "rounds_full": 8,
        "rounds_partial": 20,
        "general": 296,  # 2 muls x 16 cells x 8 full rounds + 2 muls x 20 partial rounds (x^3)
        "const_arbitrary": 0,
        "const_pow2": 0,
        "add": 832,
        "sub": 20,  # one negation per partial round, in the internal layer
        # The internal (partial-round) diagonal is powers of two applied with raw
        # u64 shifts and sums in p3-koala-bear's specialised layer, invisible to
        # the counters: about 20 rounds x 16 cells x (shift-reduce + add).
        "uncounted_add_equiv": 640,
    },
}


def poseidon2_cost(name, prices, ledger):
    m = POSEIDON2[name]
    f = ledger["field"]
    assert m["general"] + m["const_arbitrary"] + m["const_pow2"] == f["mul_per_permutation"]
    perms = ledger["hash"]["permutations"]["total"]
    # Risc0's suite also does 8 digest additions per Rng::mix outside the permutation.
    assert f["in_hash_suite"]["add"] // perms == m["add"]
    assert f["in_hash_suite"]["sub"] == m["sub"] * perms
    mul, add = nonfree(prices["mul"]), nonfree(prices["add"])
    consts = m["const_arbitrary"] + m["const_pow2"]
    counted_adds = m["add"] * add + m["sub"] * nonfree(prices["sub"])
    adds = counted_adds + m["uncounted_add_equiv"] * add
    return {
        "composition": m,
        "per_permutation": {
            "counted_as_general": (m["general"] + consts) * mul + counted_adds,
            "upper": (m["general"] + consts) * mul + adds,
            "lower": (m["general"] + m["const_arbitrary"]) * mul + m["const_pow2"] * add + adds,
            "floor": m["general"] * mul + consts * add + adds,
        },
        "basis": "assumed",
        "note": "no measured Poseidon2 gadget; counted_as_general is used in the table; upper/lower/floor include uncounted linear-layer work and price constant multiplications as general multiplies, power-of-two ones as adds, or all as adds",
    }


def poseidon2_permutation_cost(name):
    """Per-permutation cost of the Poseidon2 instance `name` ships, priced from
    the measured per-operation gadgets (counted_as_general)."""
    m = POSEIDON2[name]
    prices = COSTS[{"risc0": "babybear", "sp1": "koalabear"}[name]]
    return (
        (m["general"] + m["const_arbitrary"] + m["const_pow2"]) * nonfree(prices["mul"])
        + m["add"] * nonfree(prices["add"])
        + m["sub"] * nonfree(prices["sub"])
    )


# Hash functions a verifier's Merkle tree and Fiat-Shamir channel could be
# built on, priced per unit (one compression or one permutation). Every
# system gets a total under each; a system's own hash reproduces its
# as-deployed total. One unit of the deployed hash is mapped to one unit of
# the replacement, which is exact for Merkle nodes and approximate for
# absorbs and squeezes.
SWAPS = {
    "blake3": {"cost": lambda: nonfree(COSTS["blake3_compression"]), "basis": "measured"},
    "blake2s": {"cost": lambda: nonfree(COSTS["blake2s_compression"]), "basis": "measured"},
    "poseidon2-babybear-w24": {"cost": lambda: poseidon2_permutation_cost("risc0"), "basis": "priced"},
    "poseidon2-koalabear-w16": {"cost": lambda: poseidon2_permutation_cost("sp1"), "basis": "priced"},
}


def nonfree(cost):
    return cost["nonfree"]


def field_cost(ops, prices):
    return sum(ops.get(k, 0) * nonfree(prices[k]) for k in ("mul", "add", "sub"))


def unmeasured(ops, prices):
    """Nonfree gates in `ops` priced by a cost whose basis is not "measured"."""
    return sum(
        ops.get(k, 0) * nonfree(prices[k]) for k in ("mul", "add", "sub") if prices[k]["basis"] != "measured"
    )


def poseidon2_system(name, path):
    ledger = json.load(open(path))
    f = ledger["field"]
    prices = COSTS[f["base"]]
    perms = ledger["hash"]["permutations"]["total"]
    residual = field_cost(f["residual"], prices)
    hash_native = field_cost(f["in_hash_suite"], prices)
    return {
        "system": name,
        "hash": ledger["hash"]["function"],
        "hash_units": perms,
        "residual_field": residual,
        "hash_as_deployed": hash_native,
        "total_as_deployed": residual + hash_native,
        "total_with": {k: residual + perms * v["cost"]() for k, v in SWAPS.items()},
        "unmeasured_as_deployed": unmeasured(f["residual"], prices) + unmeasured(f["in_hash_suite"], prices),
        "unmeasured_residual": unmeasured(f["residual"], prices),
        "basis_note": "subtraction priced as addition (assumed); everything else measured per field operation; the hash column is an upper bound, see poseidon2",
        "poseidon2": poseidon2_cost(name, prices, ledger),
    }


def stwo_system(path):
    ledger = json.load(open(path))
    gates = ledger["field"]["gates"]
    m31 = {"mul": 0, "add": 0}
    for gate, per in QM31[QM31["used"]].items():
        for op in ("mul", "add"):
            m31[op] += gates[gate] * per[op]
    residual = field_cost(m31, COSTS["m31"])
    compressions = ledger["hash"]["compressions"]
    blake2s = compressions * nonfree(COSTS["blake2s_compression"])
    return {
        "system": "stwo",
        "hash": ledger["hash"]["function"],
        "hash_units": compressions,
        "m31_ops": m31,
        "residual_field": residual,
        "hash_as_deployed": blake2s,
        "total_as_deployed": residual + blake2s,
        "total_with": {k: residual + compressions * v["cost"]() for k, v in SWAPS.items()},
        "unmeasured_as_deployed": residual,
        "unmeasured_residual": residual,
        "basis_note": "QM31 gates expanded to M31 operations by an assumed Karatsuba gadget; M31 costs priced, not measured; hashes measured",
    }


def main(out):
    rows = [
        poseidon2_system("risc0", "results/risc0/ops.json"),
        poseidon2_system("sp1", "results/sp1/ops.json"),
        stwo_system("results/stwo/ops.json"),
    ]
    swap_costs = {k: {"per_unit": v["cost"](), "basis": v["basis"]} for k, v in SWAPS.items()}
    with open(out, "w") as fh:
        json.dump(
            {"costs": COSTS, "qm31_in_m31_ops": QM31, "poseidon2": POSEIDON2, "hash_per_unit": swap_costs, "systems": rows},
            fh,
            indent=2,
        )
        fh.write("\n")
    print("Nonfree gates per verification. 'field' is the non-hash arithmetic; 'as deployed' adds the shipped hash;")
    print("the remaining columns replace each hash unit with one unit of the named hash.")
    swaps = list(SWAPS)
    head = f"{'':8s}{'units':>7s}{'field':>15s}{'as deployed':>15s}" + "".join(f"{k:>24s}" for k in swaps) + f"{'unmeasured':>12s}"
    print(head)
    for r in rows:
        share = f"{100 * r['unmeasured_as_deployed'] / r['total_as_deployed']:.2f}%"
        line = f"{r['system']:8s}{r['hash_units']:>7d}{r['residual_field']:>15,d}{r['total_as_deployed']:>15,d}"
        line += "".join(f"{r['total_with'][k]:>24,d}" for k in swaps) + f"{share:>12s}"
        print(line)
    print()
    print("Hash cost per unit (compression or permutation):")
    for k, v in swap_costs.items():
        print(f"{k:26s}{v['per_unit']:>12,d}  {v['basis']}")
    print(
        "unmeasured: share of the as-deployed total priced by a cost that is not a measured gadget. "
        "Poseidon2 is priced from measured per-operation gadgets, not a measured permutation gadget;"
    )
    print("its bracket (constant multiplications, uncounted linear layer) is under poseidon2.per_permutation:")
    for r in rows[:2]:
        pp = r["poseidon2"]["per_permutation"]
        c = r["poseidon2"]["composition"]
        print(
            f"{r['system']:8s} muls {c['general']} general + {c['const_arbitrary']} arbitrary-constant + "
            f"{c['const_pow2']} power-of-two, adds {c['add']} (+{c['uncounted_add_equiv']} uncounted): "
            f"upper {pp['upper']:,d}  lower {pp['lower']:,d}  floor {pp['floor']:,d}"
        )


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "results/gates.json")
