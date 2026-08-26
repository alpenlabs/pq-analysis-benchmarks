%builtins output pedersen range_check ecdsa bitwise ec_op keccak poseidon range_check96 add_mod mul_mod

// Writes 1024 values to the output, to separate output size from proof size.
func write(output_ptr: felt*, i: felt, n: felt) -> felt* {
    if (i == n) {
        return output_ptr;
    }
    assert [output_ptr] = i;
    return write(output_ptr + 1, i + 1, n);
}

func main{output_ptr: felt*, pedersen_ptr, range_check_ptr, ecdsa_ptr, bitwise_ptr, ec_op_ptr, keccak_ptr, poseidon_ptr, range_check96_ptr, add_mod_ptr, mul_mod_ptr}() {
    let output_ptr = write(output_ptr, 0, 1024);
    return ();
}
