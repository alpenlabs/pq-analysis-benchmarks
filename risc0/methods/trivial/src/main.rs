use risc0_zkvm::guest::env;

fn main() {
    env::commit(&42u32);
}
