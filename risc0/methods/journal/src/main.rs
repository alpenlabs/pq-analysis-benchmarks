use risc0_zkvm::guest::env;

// A 4 KiB journal, to separate journal size from seal size.
fn main() {
    let data: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
    env::commit_slice(&data);
}
