#![no_main]
sp1_zkvm::entrypoint!(main);

// 4 KiB of public values, to separate their size from the proof size.
pub fn main() {
    let data: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
    sp1_zkvm::io::commit_slice(&data);
}
