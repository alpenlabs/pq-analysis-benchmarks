%builtins output pedersen range_check ecdsa bitwise ec_op keccak poseidon range_check96 add_mod mul_mod

// Writes one value to the output.
func main{output_ptr: felt*, pedersen_ptr, range_check_ptr, ecdsa_ptr, bitwise_ptr, ec_op_ptr, keccak_ptr, poseidon_ptr, range_check96_ptr, add_mod_ptr, mul_mod_ptr}() {
    assert [output_ptr] = 42;
    let output_ptr = output_ptr + 1;
    return ();
}
