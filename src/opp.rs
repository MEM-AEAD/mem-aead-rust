use std::num::{Wrapping};

type Word = u64;

const OPP_W: usize = 64;         // word size
const OPP_L: usize = 4;          // number of rounds
const OPP_T: usize = OPP_W *  4; // tag size
//const OPP_N: usize = OPP_W *  2; // nonce size
//const OPP_K: usize = OPP_W *  4; // key size
const OPP_B: usize = OPP_W * 16; // permutation size

const R0 : u32 = 32; 
const R1 : u32 = 24; 
const R2 : u32 = 16; 
const R3 : u32 = 63; 

macro_rules! Bytes { ($x: expr) => (($x + 7) / 8;); }
macro_rules! Words { ($x: expr) => (($x + (OPP_W-1)) / OPP_W;); }

#[inline]
fn load_le(v : &[u8]) -> Word {
    let mut x : Word = 0;
    for i in 0..Bytes!(OPP_W) {
        x |= (v[i] as Word) << (8*i);
    }
    return x;
}

#[inline]
fn store_le(v : &mut[u8], x : Word) {
    for i in 0..Bytes!(OPP_W) {
        v[i] = (x >> 8*i) as u8;
    }
}

macro_rules! Add { ($x: expr, $y: expr) => ((Wrapping($x)+Wrapping($y)).0;); }
macro_rules! Sub { ($x: expr, $y: expr) => ((Wrapping($x)-Wrapping($y)).0;); }

macro_rules! G { ($a:expr, $b:expr, $c:expr, $d:expr) => 
    ({
        $a = Add!($a, $b); $d ^= $a; $d = $d.rotate_right(R0); 
        $c = Add!($c, $d); $b ^= $c; $b = $b.rotate_right(R1); 
        $a = Add!($a, $b); $d ^= $a; $d = $d.rotate_right(R2); 
        $c = Add!($c, $d); $b ^= $c; $b = $b.rotate_right(R3);
    });
}

macro_rules! GI { ($a:expr, $b:expr, $c:expr, $d:expr) => 
    ({
        $b = $b.rotate_left(R3); $b ^= $c; $c = Sub!($c, $d);
        $d = $d.rotate_left(R2); $d ^= $a; $a = Sub!($a, $b);
        $b = $b.rotate_left(R1); $b ^= $c; $c = Sub!($c, $d);
        $d = $d.rotate_left(R0); $d ^= $a; $a = Sub!($a, $b);
    });
}

#[inline]
#[allow(non_snake_case)]
fn F(x : &mut[Word; 16]) {
    // column step
    G!(x[ 0], x[ 4], x[ 8], x[12]);
    G!(x[ 1], x[ 5], x[ 9], x[13]);
    G!(x[ 2], x[ 6], x[10], x[14]);
    G!(x[ 3], x[ 7], x[11], x[15]);
    // diagonal step
    G!(x[ 0], x[ 5], x[10], x[15]);
    G!(x[ 1], x[ 6], x[11], x[12]);
    G!(x[ 2], x[ 7], x[ 8], x[13]);
    G!(x[ 3], x[ 4], x[ 9], x[14]);
}

#[inline]
#[allow(non_snake_case)]
fn FI(x : &mut[Word; 16]) {
    // diagonal step
    GI!(x[ 0], x[ 5], x[10], x[15]);
    GI!(x[ 1], x[ 6], x[11], x[12]);
    GI!(x[ 2], x[ 7], x[ 8], x[13]);
    GI!(x[ 3], x[ 4], x[ 9], x[14]);
    // column step
    GI!(x[ 0], x[ 4], x[ 8], x[12]);
    GI!(x[ 1], x[ 5], x[ 9], x[13]);
    GI!(x[ 2], x[ 6], x[10], x[14]);
    GI!(x[ 3], x[ 7], x[11], x[15]);
}

#[inline]
fn opp_permute(x : &mut[Word; 16]) {
    for _ in 0..OPP_L {
        F(x);
    }
}

#[inline]
fn opp_permute_inverse(x : &mut[Word; 16]) {
    for _ in 0..OPP_L {
        FI(x);
    }
}

#[inline]
fn opp_pad(output : &mut[u8], input : &[u8]) {
    for i in 0..input.len() {
        output[i] = input[i];
    }
    for i in input.len()..output.len() {
        output[i] = 0;
    }
    output[input.len()] = 0x01;
}


fn opp_init_mask(mask : &mut[Word; 16], k : &[u8; 32], n : &[u8; 16]) {

    mask[ 0] = load_le(&n[0 * Bytes!(OPP_W)..]);
    mask[ 1] = load_le(&n[1 * Bytes!(OPP_W)..]);
    mask[ 2] = 0;
    mask[ 3] = 0;

    mask[ 4] = 0;
    mask[ 5] = 0;
    mask[ 6] = 0;
    mask[ 7] = 0;

    mask[ 8] = 0;
    mask[ 9] = 0;
    mask[10] = OPP_L as Word;
    mask[11] = OPP_T as Word;

    mask[12] = load_le(&k[0 * Bytes!(OPP_W)..]);
    mask[13] = load_le(&k[1 * Bytes!(OPP_W)..]);
    mask[14] = load_le(&k[2 * Bytes!(OPP_W)..]);
    mask[15] = load_le(&k[3 * Bytes!(OPP_W)..]);

    opp_permute(mask);
}

// alpha(x) = phi(x)
fn opp_alpha(mask : &mut[Word; 16]) {
    let t = mask[0].rotate_left(53) ^ (mask[5] << 13);
    for i in 0..Words!(OPP_B)-1 {
        mask[i] = mask[i+1];
    }
    mask[15] = t;
}

// beta(x) = phi(x) ^ x
fn opp_beta(mask : &mut[Word; 16]) {
    let t = mask[0].rotate_left(53) ^ (mask[5] << 13);
    for i in 0..Words!(OPP_B)-1 {
        mask[i] ^= mask[i+1];
    }
    mask[15] ^= t;
}

// gamma(x) = phi^2(x) ^ phi(x) ^ x
fn opp_gamma(mask : &mut[Word; 16]) {
    let t0 = mask[0].rotate_left(53) ^ (mask[5] << 13);
    let t1 = mask[1].rotate_left(53) ^ (mask[6] << 13);
    for i in 0..Words!(OPP_B)-2 {
        mask[i] ^= mask[i+1] ^ mask[i+2];
    }
    mask[14] ^= mask[15] ^ t0;
    mask[15] ^= t0 ^ t1;
}

fn opp_absorb_block(state : &mut[Word; 16], mask : &[Word; 16], block : &[u8]) {

    let mut b = &mut[0 as Word; 16];

    for i in 0..Words!(OPP_B) {
        b[i] = load_le(&block[i * Bytes!(OPP_W)..]) ^ mask[i];
    }

    opp_permute(b);

    for i in 0..Words!(OPP_B) {
        state[i] ^= b[i] ^ mask[i];
    }
}

fn opp_absorb_lastblock(state : &mut[Word; 16], mask : &[Word; 16], block : &[u8]) {
    let mut b = &mut[0u8; Bytes!(OPP_B)];
    opp_pad(b, block);
    opp_absorb_block(state, mask, b);
}

fn opp_encrypt_block(state : &mut[Word; 16], mask : &mut[Word; 16], block_out : &mut[u8], block_in : &[u8]) {

    let mut b = &mut[0 as Word; 16];

    for i in 0..Words!(OPP_B) {
        b[i] ^= load_le(&block_in[i * Bytes!(OPP_W)..]) ^ mask[i];
    }

    opp_permute(b);

    for i in 0..Words!(OPP_B) {
        store_le(&mut block_out[i * Bytes!(OPP_W)..], b[i] ^ mask[i]);
        state[i] ^= load_le(&block_in[i * Bytes!(OPP_W)..]);
    }
}

fn opp_encrypt_lastblock(state : &mut[Word; 16], mask : &[Word; 16], block_out : &mut[u8], block_in : &[u8]) {

    let mut b = &mut[0 as Word; 16];
    let mut lastblock = &mut[0u8; Bytes!(OPP_B)];

    for i in 0..Words!(OPP_B) {
        b[i] = mask[i];
    }

    opp_permute(b);

    opp_pad(lastblock, block_in);
    for i in 0..Words!(OPP_B) {
        let x = load_le(&lastblock[i * Bytes!(OPP_W)..]);
        state[i] ^= x;
        store_le(&mut lastblock[i * Bytes!(OPP_W)..], b[i] ^ mask[i] ^ x);
    }

    for i in 0..block_in.len() {
        block_out[i] = lastblock[i];
    }
}

fn opp_decrypt_block(state : &mut[Word; 16], mask : &mut[Word; 16], block_out : &mut[u8], block_in : &[u8]) {

    let mut b = &mut[0 as Word; 16];

    for i in 0..Words!(OPP_B) {
        b[i] ^= load_le(&block_in[i * Bytes!(OPP_W)..]) ^ mask[i];
    }

    opp_permute_inverse(b);

    for i in 0..Words!(OPP_B) {
        store_le(&mut block_out[i * Bytes!(OPP_W)..], b[i] ^ mask[i]);
        state[i] ^= load_le(&block_out[i * Bytes!(OPP_W)..]);
    }
}

fn opp_decrypt_lastblock(state : &mut[Word; 16], mask : &[Word; 16], block_out : &mut[u8], block_in : &[u8]) {

    let mut b = &mut[0 as Word; 16];
    let mut lastblock = &mut[0u8; Bytes!(OPP_B)];

    for i in 0..Words!(OPP_B) {
        b[i] = mask[i];
    }

    opp_permute(b);

    opp_pad(lastblock, block_in);
    for i in 0..Words!(OPP_B) {
        let x = load_le(&lastblock[i * Bytes!(OPP_W)..]);
        store_le(&mut lastblock[i * Bytes!(OPP_W)..], b[i] ^ mask[i] ^ x);
    }

    for i in 0..block_in.len() {
        block_out[i] = lastblock[i];
    }

    opp_pad(lastblock, block_out);
    for i in 0..Words!(OPP_B) {
        state[i] ^= load_le(&lastblock[i * Bytes!(OPP_W)..]);
    }

}

fn opp_absorb_data(state : &mut[Word; 16], mask : &mut[Word; 16], data : &[u8]) {

    let mut i = data.len();
    let mut o = 0;
    while i >= Bytes!(OPP_B) {
        opp_absorb_block(state, mask, &data[o..o+Bytes!(OPP_B)]);
        i -= Bytes!(OPP_B);
        o += Bytes!(OPP_B);
        opp_alpha(mask);
    }
    if i > 0 {
        opp_beta(mask);
        opp_absorb_lastblock(state, mask, &data[o..o+i]);
    }
}

fn opp_encrypt_data(state : &mut [Word; 16], mask : &mut[Word; 16], data_out : &mut[u8], data_in : &[u8]) {

    opp_gamma(mask);

    let mut i = data_in.len();
    let mut o = 0;
    while i >= Bytes!(OPP_B) {
        opp_encrypt_block(state, mask, &mut data_out[o..o+Bytes!(OPP_B)], &data_in[o..o+Bytes!(OPP_B)]);
        i -= Bytes!(OPP_B);
        o += Bytes!(OPP_B);
        opp_alpha(mask);
    }
    if i > 0 {
        opp_beta(mask);
        opp_encrypt_lastblock(state, mask, &mut data_out[o..o+i], &data_in[o..o+i]);
    }
}

fn opp_decrypt_data(state : &mut [Word; 16], mask : &mut[Word; 16], data_out : &mut[u8], data_in : &[u8]) {

    opp_gamma(mask);

    let mut i = data_in.len();
    let mut o = 0;
    while i >= Bytes!(OPP_B) {
        opp_decrypt_block(state, mask, &mut data_out[o..o+Bytes!(OPP_B)], &data_in[o..o+Bytes!(OPP_B)]);
        i -= Bytes!(OPP_B);
        o += Bytes!(OPP_B);
        opp_alpha(mask);
    }
    if i > 0 {
        opp_beta(mask);
        opp_decrypt_lastblock(state, mask, &mut data_out[o..o+i], &data_in[o..o+i]);
    }
}

fn opp_finalise(sa : &mut[Word; 16], se : &mut[Word; 16], mask : &mut[Word; 16], tag : &mut[u8], hlen : usize, mlen : usize) {

    let mut b = &mut[0u8; Bytes!(OPP_B)];

    let i = Bytes!(OPP_B);
    let j = 2 + ( ( mlen % i ) + i - 1 ) / i - ( ( hlen % i ) + i - 1 ) / i;

    for _ in 0..j {
        opp_beta(mask);
    }

    for i in 0..Words!(OPP_B) {
        se[i] ^= mask[i];
    }

    opp_permute(se);

    for i in 0..Words!(OPP_B) {
        sa[i] ^= se[i] ^ mask[i];
        store_le(&mut b[i * Bytes!(OPP_W)..], sa[i]);
    }

    for i in 0..Bytes!(OPP_T) {
        tag[i] = b[i];
    }
}

fn opp_verify_tag(x : &[u8], y : &[u8]) -> bool {

    if x.len() != y.len() {
        return false;
    }

    let mut acc = 0;

    for i in 0..Bytes!(OPP_T) {
        acc |= x[i] ^ y[i];
    }

    return acc == 0;
}

pub fn crypto_aead_encrypt(c : &mut[u8], h : &[u8], m : &[u8], nonce : &[u8; 16], key : &[u8; 32]) {

    let mut sa = &mut[0 as Word; Words!(OPP_B)];
    let mut se = &mut[0 as Word; Words!(OPP_B)];
    let mut la = &mut[0 as Word; Words!(OPP_B)];
    let mut le = &mut[0 as Word; Words!(OPP_B)];
    let mlen = m.len();
    let hlen = h.len();

    opp_init_mask(la, key, nonce);
    for i in 0..Words!(OPP_B) { le[i] = la[i]; }

    // absorb header
    opp_absorb_data(sa, la, h);

    // encrypt message
    opp_encrypt_data(se, le, &mut c[0..mlen], m);

    // finalise and extract tag
    opp_finalise(sa, se, la, &mut c[mlen..], hlen, mlen);
}

pub fn crypto_aead_decrypt(m : &mut[u8], h : &[u8], c : &[u8], nonce: &[u8; 16], key : &[u8; 32]) -> bool {

    if c.len() < Bytes!(OPP_T) { return false; }

    let mut sa = &mut[0 as Word; Words!(OPP_B)];
    let mut se = &mut[0 as Word; Words!(OPP_B)];
    let mut la = &mut[0 as Word; Words!(OPP_B)];
    let mut le = &mut[0 as Word; Words!(OPP_B)];
    let mut tag = &mut[0u8; Bytes!(OPP_T)];
    let mlen = c.len() - Bytes!(OPP_T);
    let hlen = h.len();

    opp_init_mask(la, key, nonce);
    for i in 0..Words!(OPP_B) { le[i] = la[i]; }

    // absorb header
    opp_absorb_data(sa, la, h);

    // decrypt message
    opp_decrypt_data(se, le, m, &c[0..mlen]);

    // finalise and extract tag
    opp_finalise(sa, se, la, tag, hlen, mlen);

    // verify tag
    return opp_verify_tag(&c[mlen..], tag);
}
