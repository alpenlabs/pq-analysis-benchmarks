#!/usr/bin/env python3
"""Boolean-gate estimate of each verifier from results/<system>/{ops,size}.json.

Writes results/gates.json, prints a summary, and rewrites the table between
the `gates.py` markers in README.md, so the README follows the results.

Costs are nonfree gates (AND-type; the cost under free-XOR) and XOR gates,
read from results/gadgets.json, which gadgets/ produces with the gate-count
instrumentation of alpenlabs/g16 (g16ckt) at a pinned revision. Every gadget
there, the two Poseidon2 permutations and the QM31 operations included, is
validated against the pinned verifier's native arithmetic. The one modelling
choice is the layout of the QM31 multiplication gadget (QM31_MUL); the
alternative is recorded alongside.

Each system is totalled under its deployed hash and under every hash in
SWAPS (BLAKE3, BLAKE2s, and the two Poseidon2 instances Risc0 and SP1 ship),
replacing each hash unit one-for-one and leaving the field arithmetic
unchanged. That mapping is exact for Merkle 2-to-1 compressions and
approximate for sponge absorbs and Fiat-Shamir squeezes, and other than the
deployed hash it assumes a fork of prover and verifier that does not exist.

Only field arithmetic and hash units are priced. Every field operation of the
shipped verifier is priced, the multiplications inside exponentiations and
inversions included (`pow.mul` is added to `residual`): the verifier circuit's
only input is the proof, so nothing is supplied as a witness. Stwo's equality
checks, permutation networks, hint wires and re-encodings between field and
32-bit words are counted in its ledger but not priced here.
"""

import json
import sys

GADGETS = json.load(open("results/gadgets.json"))


def gadget(name, note):
    g = GADGETS["gadgets"][name]
    return {"nonfree": g["nonfree"], "xor": g["xor"], "note": note, "gadget": name}


def nonfree(cost):
    return cost["nonfree"]


def xor(cost):
    return cost["xor"]


# Every entry is a measured gadget (see gadgets/ and results/gadgets.json).
COSTS = {
    "blake3_compression": gadget("blake3_compression_64b", "g16ckt's BLAKE3 gadget, one 64-byte block"),
    "blake2s_compression": gadget("blake2s_compression_64b", "BLAKE2s-256 from the same u32 primitives, one 64-byte block"),
    "babybear": {
        "mul": gadget("babybear_mul", "Montgomery multiply (REDC), as risc0-core"),
        "add": gadget("babybear_add", "add, conditional subtract of p"),
        "sub": gadget("babybear_sub", "subtract, conditional add of p"),
    },
    "koalabear": {
        "mul": gadget("koalabear_mul", "Montgomery multiply (REDC), as p3-koala-bear"),
        "add": gadget("koalabear_add", "add, conditional subtract of p"),
        "sub": gadget("koalabear_sub", "subtract, conditional add of p"),
    },
    "m31": {
        "mul": gadget("m31_mul", "31x31 Karatsuba product, two Mersenne folds, conditional subtract, as stwo M31::reduce"),
        "add": gadget("m31_add", "add, conditional subtract of p (stwo partial_reduce)"),
        "sub": gadget("m31_sub", "a + p - b, conditional subtract of p (stwo partial_reduce)"),
    },
    "qm31": {
        "mul": gadget("qm31_mul_karatsuba", "Karatsuba at both extension levels over the M31 gadgets, 2 + i by adds"),
        "mul_schoolbook": gadget("qm31_mul_schoolbook", "stwo's own layout: 4 M31 products per CM31 product, 5 CM31 products"),
        "pointwise_mul": gadget("qm31_pointwise_mul", "four M31 multiplications"),
        "add": gadget("qm31_add", "four M31 additions"),
        "sub": gadget("qm31_sub", "four M31 subtractions"),
    },
    "poseidon2_babybear_w24": gadget(
        "poseidon2_babybear_w24_permutation",
        "risc0-zkp poseidon2_mix step by step over the BabyBear gadgets: x^7, M_EXT by adds, M_INT by constant Montgomery multiplies",
    ),
    "poseidon2_koalabear_w16": gadget(
        "poseidon2_koalabear_w16_permutation",
        "p3 Poseidon2 as SP1 configures it, over the KoalaBear gadgets: x^3, mat4 external layer by adds, specialised internal layer by u64 sums and REDC",
    ),
}

# Which measured QM31 multiplication gadget prices Stwo's `mul` gates. The gate
# is a field multiplication; the Boolean gadget's layout is a choice. stwo's
# own code (crates/stwo/src/core/fields/{cm31,qm31}.rs) is schoolbook at both
# levels and multiplies by R = 2 + i as a general CM31 product, a layout no
# Boolean-circuit implementer would copy; Karatsuba at both levels with R
# applied by adds is about half the gates. Both are measured; the estimate
# uses Karatsuba and records the other. Risc0's and SP1's extension
# multiplications get no such discount: their ledgers count base operations,
# so they are priced as their code performs them (see README, Gate estimate).
QM31_MUL = "mul"

POSEIDON2_GADGET = {"risc0": "poseidon2_babybear_w24", "sp1": "poseidon2_koalabear_w16"}

# Poseidon2 permutation composition, from the round structure of the pinned
# code (risc0-zkp poseidon2/mod.rs; p3-poseidon2 with p3-koala-bear's
# specialised internal layer). The field counters count every `Elem * Elem`,
# including multiplications by constants; the composition separates them and
# is asserted against the ledgers. The permutation gadget itself is measured;
# `priced_from_ops` prices the counted operations with the per-operation
# gadgets, every multiplication as a general multiply, as the cross-check
# between the two routes.
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
        # The internal diagonal is applied with raw u64 shifts and sums, which the
        # counters do not see; the measured gadget includes it.
    },
}


def field_cost(ops, prices, kind=nonfree):
    return sum(ops.get(k, 0) * kind(prices[k]) for k in ("mul", "add", "sub"))


def residual_ops(field):
    """The verifier's non-hash arithmetic: `residual` plus the multiplications
    inside `pow`, which the ledgers record separately because their number
    varies with the proof (the exponents are Fiat-Shamir derived query
    positions). They are computed in-circuit like everything else, so they
    are priced."""
    ops = dict(field["residual"])
    ops["mul"] += field["pow"]["mul"]
    return ops


def poseidon2_cost(name, prices, ledger):
    m = POSEIDON2[name]
    f = ledger["field"]
    assert m["general"] + m["const_arbitrary"] + m["const_pow2"] == f["mul_per_permutation"]
    perms = ledger["hash"]["permutations"]["total"]
    # Risc0's suite also does 8 digest additions per Rng::mix outside the permutation.
    assert f["in_hash_suite"]["add"] // perms == m["add"]
    assert f["in_hash_suite"]["sub"] == m["sub"] * perms
    priced = (
        (m["general"] + m["const_arbitrary"] + m["const_pow2"]) * nonfree(prices["mul"])
        + m["add"] * nonfree(prices["add"])
        + m["sub"] * nonfree(prices["sub"])
    )
    return {
        "composition": m,
        "per_permutation": {"measured": nonfree(COSTS[POSEIDON2_GADGET[name]]), "priced_from_ops": priced},
    }


# Hash functions a verifier's Merkle tree and Fiat-Shamir channel could be
# built on, priced per unit (one compression or one permutation). Every system
# gets a total under each; a system's own hash reproduces its as-deployed
# total.
SWAPS = {
    "blake3": lambda kind=nonfree: kind(COSTS["blake3_compression"]),
    "blake2s": lambda kind=nonfree: kind(COSTS["blake2s_compression"]),
    "poseidon2-babybear-w24": lambda kind=nonfree: kind(COSTS["poseidon2_babybear_w24"]),
    "poseidon2-koalabear-w16": lambda kind=nonfree: kind(COSTS["poseidon2_koalabear_w16"]),
}


# The artifact each system's own API hands back. Anything else in a ledger's
# `artifact` field is a stage the prover computes but does not return.
SHIPPED = {"succinct receipt", "compressed proof", "leaf circuit proof"}


def row(ledger, path, hash_units, residual, residual_xor, hash_native, hash_native_xor, extra):
    size = json.load(open(path.replace("ops.json", "size.json")))
    return {
        "system": ledger["system"],
        "version": ledger["version"],
        "artifact": ledger["artifact"],
        # How the artifact is obtained; see the README footnotes. "shipped" is
        # what the system's own API returns, "unexposed" is produced by the
        # unmodified prover but not returned by it.
        "availability": "shipped" if ledger["artifact"] in SHIPPED else "unexposed",
        "proof_bytes": size["proof_bytes"],
        "hash": ledger["hash"]["function"],
        "hash_units": hash_units,
        "residual_field": residual,
        "residual_field_xor": residual_xor,
        "hash_as_deployed": hash_native,
        "hash_as_deployed_xor": hash_native_xor,
        "total_as_deployed": residual + hash_native,
        "total_with": {k: residual + hash_units * cost() for k, cost in SWAPS.items()},
        "total_with_xor": {k: residual_xor + hash_units * cost(xor) for k, cost in SWAPS.items()},
        **extra,
    }


def poseidon2_system(name, path):
    ledger = json.load(open(path))
    f = ledger["field"]
    prices = COSTS[f["base"]]
    perms = ledger["hash"]["permutations"]["total"]
    perm = COSTS[POSEIDON2_GADGET[name]]
    residual = residual_ops(f)
    return row(
        ledger,
        path,
        perms,
        field_cost(residual, prices),
        field_cost(residual, prices, xor),
        perms * nonfree(perm),
        perms * xor(perm),
        {
            "residual_ops": residual,
            "pow_mul_priced": f["pow"]["mul"] * nonfree(prices["mul"]),
            "hash_priced_from_ops": field_cost(f["in_hash_suite"], prices),
            "poseidon2": poseidon2_cost(name, prices, ledger),
            "note": "hash_priced_from_ops is the same hash priced per counted field operation, for comparison with the measured permutation gadget",
        },
    )


# Stwo's verifier circuit does not compute inversions: `ops::inv`, `ops::div`
# and `Simd::inv` take the result as a prover hint and check it with one
# multiplication and one equality. With the proof as the circuit's only
# input, the inverses have to be computed in-circuit, and they are priced as
# stwo's own field code computes them (crates/stwo/src/core/fields/), per
# element, in M31 multiplications (squarings priced as multiplications; the
# few additions are ignored):
#   M31:  pow2147483645, an addition chain of 30 squarings + 7 products.
#   CM31: (a - bi) / (a^2 + b^2): 2 squarings, one M31 inverse, 2 products.
#   QM31: (a - bu) / (a^2 - (2 + i) b^2): 2 CM31 squarings, one CM31 inverse,
#         2 CM31 products; a CM31 product is 3 M31 products in the Karatsuba
#         layout the QM31 gadget uses (4 in stwo's schoolbook layout).
# The hint-check multiplication and equality that the computed inverse would
# make redundant are left in the count.
M31_INV_MULS = 37
CM31_INV_MULS = 2 + M31_INV_MULS + 2
CM31_MUL_MULS = 3 if QM31_MUL == "mul" else 4
QM31_INV_MULS = 4 * CM31_MUL_MULS + CM31_INV_MULS


def stwo_system(path):
    ledger = json.load(open(path))
    gates = ledger["field"]["gates"]
    ops = ledger["field"]["ops"]
    q = COSTS["qm31"]
    m31_mul = COSTS["m31"]["mul"]
    price = {"mul": q[QM31_MUL], "pointwise_mul": q["pointwise_mul"], "add": q["add"], "sub": q["sub"]}
    inversions = {
        "m31": ops["m31_inv"],
        "qm31": ops["inv"] + ops["div"],
        "m31_muls_each": {"m31": M31_INV_MULS, "qm31": QM31_INV_MULS},
        "m31_muls": ops["m31_inv"] * M31_INV_MULS + (ops["inv"] + ops["div"]) * QM31_INV_MULS,
    }
    inversions["nonfree"] = inversions["m31_muls"] * nonfree(m31_mul)
    inversions["xor"] = inversions["m31_muls"] * xor(m31_mul)
    residual = sum(gates[g] * nonfree(c) for g, c in price.items()) + inversions["nonfree"]
    compressions = ledger["hash"]["compressions"]
    h = COSTS["blake2s_compression"]
    return row(
        ledger,
        path,
        compressions,
        residual,
        sum(gates[g] * xor(c) for g, c in price.items()) + inversions["xor"],
        compressions * nonfree(h),
        compressions * xor(h),
        {
            "inversions": inversions,
            "residual_field_with_schoolbook_mul": residual + gates["mul"] * (nonfree(q["mul_schoolbook"]) - nonfree(q[QM31_MUL])),
            "note": "QM31 mul gates priced with the Karatsuba gadget; residual_field_with_schoolbook_mul uses stwo's own layout; "
            "inversions are the hint-supplied inverses priced as computed in-circuit",
        },
    )


def groth16_rows():
    """Baseline: g16ckt's own Groth16 (BN254) verifier, one public input.
    Proof bytes are the proof alone (A, C in G1, B in G2): 256 uncompressed,
    128 compressed. No hash, no field-operation ledger; the counts are the
    whole verifier circuit."""
    rev = GADGETS["source"]["rev"][:8]
    rows = []
    for name, artifact, bytes_ in [
        ("groth16_bn254_verify_1_input", "proof, uncompressed", 256),
        ("groth16_bn254_verify_compressed_1_input", "proof, compressed", 128),
    ]:
        g = GADGETS["gadgets"][name]
        rows.append(
            {
                "system": "groth16 (bn254)",
                "version": f"g16ckt@{rev}",
                "artifact": artifact,
                "proof_bytes": bytes_,
                "hash": "-",
                "nonfree": g["nonfree"],
                "xor": g["xor"],
                "total": g["total"],
                "gadget": name,
            }
        )
    return rows


README = "README.md"
MARK_START = "<!-- gates.py: table start -->"
PARAMS_START = "<!-- gates.py: params start -->"
PARAMS_END = "<!-- gates.py: params end -->"
MARK_END = "<!-- gates.py: table end -->"


def fmt_bytes(n):
    return f"{n} B" if n < 1024 else f"{n / 1024:,.1f} KiB" if n < 1024**2 else f"{n / 1024**2:,.2f} MiB"


def render_table(rows, baseline):
    """Markdown table for the README: each system as deployed and with BLAKE3,
    alphabetical, then the compressed-proof Groth16 verifier as baseline.

    A row's name carries a dagger when the artifact is one the prover computes
    but its API does not return (SP1's shrink proof), and a double dagger when
    the hash has been swapped, which no released prover does."""
    ref = next(r for r in baseline if r["gadget"].endswith("compressed_1_input"))
    lines = [
        "| verifier | hash | proof size | nonfree gates\\* (billions) | total gates\\* (billions) | nonfree vs. groth16 |",
        "|---|---|---:|---:|---:|---:|",
    ]

    def line(name, hash_, bytes_, nf, x):
        lines.append(
            f"| {name} | {hash_} | {fmt_bytes(bytes_)} | {nf / 1e9:,.2f} | {(nf + x) / 1e9:,.2f} | "
            f"{nf / ref['nonfree']:.2f}x |"
        )

    def stage(r):
        return "" if r["availability"] == "shipped" else f", {r['artifact'].split()[0]}\u2020"

    for system in dict.fromkeys(r["system"] for r in rows):
        group = [r for r in rows if r["system"] == system]
        for r in group:
            nf, x = r["total_as_deployed"], r["residual_field_xor"] + r["hash_as_deployed_xor"]
            line(f"{system} {r['version'].split('@')[-1]}{stage(r)}", r["hash"], r["proof_bytes"], nf, x)
        for r in group:
            nf, x = r["total_with"]["blake3"], r["total_with_xor"]["blake3"]
            line(f"{system}{stage(r)}, blake3 swap\u2021", "blake3", r["proof_bytes"], nf, x)
    line("groth16 bn254 (baseline)", "-", ref["proof_bytes"], ref["nonfree"], ref["xor"])
    lines += [
        "",
        "\\* The STARK rows price every field operation the shipped verifier performs,",
        "the multiplications inside inversions and exponentiations included, plus the",
        "hash units. Nothing is supplied as a witness: the circuit's only input is the",
        "proof, so the inverses Stwo's circuit takes as prover hints are priced as",
        "computed in-circuit by stwo's own field routines (see",
        "[Gate estimate](#gate-estimate)). Stwo's equality checks are counted but not",
        "priced (about 0.05%); its permutation gates and field-to-word re-encodings",
        "are fixed rewiring in a Boolean circuit. The Groth16 row is the complete",
        "verifier circuit.",
        "",
        "\u2020 Produced by the unmodified prover but not returned by its API, so it is",
        "reachable only by calling into the prover directly (see [Shrink](#shrink)).",
        "Every other STARK row is the artifact its system's own API hands back.",
        "",
        "\u2021 Assumes a fork of prover and verifier that does not exist: the hash is",
        "replaced one-for-one and the field arithmetic left unchanged.",
    ]
    return "\n".join(lines)


# (path, stage suffix for the row label); one entry per parameter set.
PARAM_SETS = [
    ("results/risc0/params.json", ""),
    ("results/sp1/params.json", ""),
    ("results/sp1/shrink/params.json", ", shrink"),
    ("results/stwo/params.json", ""),
]
PARAMS = [(json.load(open(path)), suffix) for path, suffix in PARAM_SETS]


def render_params():
    """Markdown table of the proof-system parameters each verifier is compiled
    with, from results/<system>/params.json."""
    lines = [
        "| verifier | field | rate | queries | fold | PoW bits | trace log size | stated security |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for p, suffix in PARAMS:
        f, fri, sec = p["field"], p["fri"], p["security"]
        trace = p.get("trace_log_size", p.get("log_stacking_height"))
        basis = sec["basis"].split(":")[0].split(";")[0]
        lines.append(
            f"| {p['system']} {p['version'].split('@')[-1]}{suffix} | {f['base']}^{f['extension_degree']} | "
            f"1/{2 ** fri['log_blowup']} | {fri['queries']} | {2 ** fri['log_fold']} | {fri['pow_bits']} | "
            f"{trace} | {sec['stated_bits']} bits, {basis} |"
        )
    return "\n".join(lines)


def replace_between(text, start, end, body):
    a, b = text.index(start) + len(start), text.index(end)
    return text[:a] + "\n" + body + "\n" + text[b:]


def update_readme(rows, baseline):
    text = open(README).read()
    new = replace_between(text, MARK_START, MARK_END, render_table(rows, baseline))
    new = replace_between(new, PARAMS_START, PARAMS_END, render_params())
    if new != text:
        open(README, "w").write(new)


def main(out):
    rows = [
        poseidon2_system("risc0", "results/risc0/ops.json"),
        poseidon2_system("sp1", "results/sp1/ops.json"),
        poseidon2_system("sp1", "results/sp1/shrink/ops.json"),
        stwo_system("results/stwo/ops.json"),
    ]
    baseline = groth16_rows()
    hash_per_unit = {k: {"nonfree": cost(), "xor": cost(xor)} for k, cost in SWAPS.items()}
    update_readme(rows, baseline)
    with open(out, "w") as fh:
        json.dump(
            {
                "gadgets_source": GADGETS["source"],
                "costs": COSTS,
                "qm31_mul_gadget": QM31_MUL,
                "hash_per_unit": hash_per_unit,
                "baseline": baseline,
                "systems": rows,
            },
            fh,
            indent=2,
        )
        fh.write("\n")

    print("Nonfree gates per verification. 'field' is the non-hash arithmetic; 'as deployed' adds the shipped hash;")
    print("the remaining columns replace each hash unit with one unit of the named hash.")
    swaps = list(SWAPS)
    print(f"{'':12s}{'units':>7s}{'field':>15s}{'as deployed':>15s}" + "".join(f"{k:>24s}" for k in swaps))
    for r in rows:
        name = r["system"] if r["availability"] == "shipped" else f"{r['system']} {r['artifact'].split()[0]}"
        line = f"{name:12s}{r['hash_units']:>7d}{r['residual_field']:>15,d}{r['total_as_deployed']:>15,d}"
        print(line + "".join(f"{r['total_with'][k]:>24,d}" for k in swaps))
    print()
    for r in baseline:
        print(f"baseline {r['system']} {r['artifact']:22s} {r['proof_bytes']:>5} B  nonfree {r['nonfree']:>15,d}  xor {r['xor']:>15,d}")
    print()
    print("Hash cost per unit (compression or permutation), measured gadgets:")
    for k, v in hash_per_unit.items():
        print(f"{k:26s}{v['nonfree']:>12,d}")
    print()
    print("Poseidon2 permutation, measured gadget vs the counted field operations priced per operation:")
    for r in (r for r in rows if "poseidon2" in r):
        pp, c = r["poseidon2"]["per_permutation"], r["poseidon2"]["composition"]
        print(
            f"{r['system']:8s} {r['artifact']:18s} muls {c['general']} general + {c['const_arbitrary']} arbitrary-constant + "
            f"{c['const_pow2']} power-of-two, adds {c['add']}, subs {c['sub']}: "
            f"measured {pp['measured']:,d}  priced_from_ops {pp['priced_from_ops']:,d}"
        )
    stwo = next(r for r in rows if "residual_field_with_schoolbook_mul" in r)
    print(f"stwo residual with stwo's schoolbook QM31 mul instead of Karatsuba: {stwo['residual_field_with_schoolbook_mul']:,d}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "results/gates.json")
