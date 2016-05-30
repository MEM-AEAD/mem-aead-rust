pub fn rotr64(x: u64, c: u8) -> u64 {
    return (x >> c) | (x << (64 - c));
}
