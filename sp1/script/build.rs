fn main() {
    for p in ["trivial", "fib", "journal"] {
        sp1_build::build_program_with_args(&format!("../programs/{p}"), Default::default());
    }
}
