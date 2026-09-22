#!/usr/bin/env python3
"""Compare an operation ledger against the committed one.

Everything must match exactly except `field.pow.mul`, the multiplications
inside `pow`: the verifier raises generators to Fiat-Shamir derived query
positions, so that count varies with the proof by a few hundred. It is
compared within a relative tolerance (default 2%) and the difference is
printed.

    ledger_diff.py <measured> <committed> [tolerance]
"""

import json
import sys

TOLERANT = ("field", "pow", "mul")


def dig(d, path):
    for k in path:
        d = d[k] if isinstance(d, dict) and k in d else None
        if d is None:
            return None
    return d


def main(measured_path, committed_path, tolerance=0.02):
    measured = json.load(open(measured_path))
    committed = json.load(open(committed_path))
    a, b = dig(measured, TOLERANT), dig(committed, TOLERANT)
    if a is not None and b is not None:
        rel = abs(a - b) / b if b else float(a != b)
        print(f"pow.mul: measured {a}, committed {b}, difference {a - b:+d} ({rel * 100:.3f}%)")
        if rel > tolerance:
            print(f"pow.mul differs by more than {tolerance * 100:g}%", file=sys.stderr)
            return 1
        dig(measured, TOLERANT[:-1])[TOLERANT[-1]] = b
    if measured != committed:
        print(f"{measured_path} and {committed_path} differ outside pow.mul", file=sys.stderr)
        for k in sorted(set(measured) | set(committed)):
            if measured.get(k) != committed.get(k):
                print(f"  {k}:\n    measured  {json.dumps(measured.get(k), sort_keys=True)}\n    committed {json.dumps(committed.get(k), sort_keys=True)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) not in (2, 3):
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(args[0], args[1], *(float(x) for x in args[2:])))
