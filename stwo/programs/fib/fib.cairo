%builtins output pedersen range_check ecdsa bitwise ec_op keccak poseidon range_check96 add_mod mul_mod

// Several hundred thousand steps, under the 2^20-row limit of the canonical_small preprocessed trace.
func fib(a: felt, b: felt, n: felt) -> felt {
    if (n == 0) {
        return a;
    }
    return fib(b, a + b, n - 1);
}

func main{output_ptr: felt*, pedersen_ptr, range_check_ptr, ecdsa_ptr, bitwise_ptr, ec_op_ptr, keccak_ptr, poseidon_ptr, range_check96_ptr, add_mod_ptr, mul_mod_ptr}() {
    let r = fib(0, 1, 100000);
    assert [output_ptr] = r;
    let output_ptr = output_ptr + 1;
    return ();
}
