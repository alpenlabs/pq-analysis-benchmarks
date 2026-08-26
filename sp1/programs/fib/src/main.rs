#![no_main]
sp1_zkvm::entrypoint!(main);

// Several million cycles; proved with a reduced shard size so the execution
// spans more than one shard.
pub fn main() {
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..1_000_000 {
        let c = a.wrapping_add(b);
        a = b;
        b = std::hint::black_box(c);
    }
    sp1_zkvm::io::commit(&a);
}
