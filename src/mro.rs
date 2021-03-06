use std::num::{Wrapping};

type Word = u64;

const MRO_W: usize = 64;         // word size
const MRO_L: usize = 4;          // number of rounds
const MRO_T: usize = MRO_W *  4; // tag size
//const MRO_N: usize = MRO_W *  2; // nonce size
//const MRO_K: usize = MRO_W *  4; // key size
const MRO_B: usize = MRO_W * 16; // permutation size

const R0 : u32 = 32; 
const R1 : u32 = 24; 
const R2 : u32 = 16; 
const R3 : u32 = 63; 

#[derive(PartialEq)]
enum Tag {
    HDD, // header data
    MSG  // message data
}

macro_rules! Bytes { ($x: expr) => (($x + 7) / 8;); }
macro_rules! Words { ($x: expr) => (($x + (MRO_W-1)) / MRO_W;); }

#[inline]
fn load_le(v : &[u8]) -> Word {
    let mut x : Word = 0;
    for i in 0..Bytes!(MRO_W) {
        x |= (v[i] as Word) << (8*i);
    }
    return x;
}

#[inline]
fn store_le(v : &mut[u8], x : Word) {
    for i in 0..Bytes!(MRO_W) {
        v[i] = (x >> 8*i) as u8;
    }
}

macro_rules! Add { ($x: expr, $y: expr) => ((Wrapping($x)+Wrapping($y)).0;); }

macro_rules! G { ($a:expr, $b:expr, $c:expr, $d:expr) => 
    ({
        $a = Add!($a, $b); $d ^= $a; $d = $d.rotate_right(R0); 
        $c = Add!($c, $d); $b ^= $c; $b = $b.rotate_right(R1); 
        $a = Add!($a, $b); $d ^= $a; $d = $d.rotate_right(R2); 
        $c = Add!($c, $d); $b ^= $c; $b = $b.rotate_right(R3);
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
fn mro_permute(x : &mut[Word; 16]) {
    for _ in 0..MRO_L {
        F(x);
    }
}

#[inline]
fn mro_pad(output : &mut[u8], input : &[u8]) {
    for i in 0..input.len() {
        output[i] = input[i];
    }
    for i in input.len()..output.len() {
        output[i] = 0;
    }
    output[input.len()] = 0x01;
}

fn mro_init_mask(mask : &mut[Word; 16], k : &[u8; 32], n : &[u8; 16]) {

    mask[ 0] = load_le(&n[0 * Bytes!(MRO_W)..]);
    mask[ 1] = load_le(&n[1 * Bytes!(MRO_W)..]);
    mask[ 2] = 0;
    mask[ 3] = 0;

    mask[ 4] = 0;
    mask[ 5] = 0;
    mask[ 6] = 0;
    mask[ 7] = 0;

    mask[ 8] = 0;
    mask[ 9] = 0;
    mask[10] = MRO_L as Word;
    mask[11] = MRO_T as Word;

    mask[12] = load_le(&k[0 * Bytes!(MRO_W)..]);
    mask[13] = load_le(&k[1 * Bytes!(MRO_W)..]);
    mask[14] = load_le(&k[2 * Bytes!(MRO_W)..]);
    mask[15] = load_le(&k[3 * Bytes!(MRO_W)..]);

    mro_permute(mask);
}

// alpha(x) = phi(x)
fn mro_alpha(mask : &mut[Word; 16]) {
    let t = mask[0].rotate_left(53) ^ (mask[5] << 13);
    for i in 0..Words!(MRO_B)-1 {
        mask[i] = mask[i+1];
    }
    mask[15] = t;
}

// beta(x) = phi(x) ^ x
fn mro_beta(mask : &mut[Word; 16]) {
    let t = mask[0].rotate_left(53) ^ (mask[5] << 13);
    for i in 0..Words!(MRO_B)-1 {
        mask[i] ^= mask[i+1];
    }
    mask[15] ^= t;
}

// gamma(x) = phi^2(x) ^ phi(x) ^ x
fn mro_gamma(mask : &mut[Word; 16]) {
    let t0 = mask[0].rotate_left(53) ^ (mask[5] << 13);
    let t1 = mask[1].rotate_left(53) ^ (mask[6] << 13);
    for i in 0..Words!(MRO_B)-2 {
        mask[i] ^= mask[i+1] ^ mask[i+2];
    }
    mask[14] ^= mask[15] ^ t0;
    mask[15] ^= t0 ^ t1;
}

fn mro_absorb_block(state : &mut[Word; 16], mask : &[Word; 16], block : &[u8]) {

    let mut b = &mut[0 as Word; 16];

    for i in 0..Words!(MRO_B) {
        b[i] = load_le(&block[i * Bytes!(MRO_W)..]) ^ mask[i];
    }

    mro_permute(b);

    for i in 0..Words!(MRO_B) {
        state[i] ^= b[i] ^ mask[i];
    }
}

fn mro_absorb_lastblock(state : &mut[Word; 16], mask : &[Word; 16], block : &[u8]) {
    let mut b = &mut[0u8; Bytes!(MRO_B)];
    mro_pad(b, block);
    mro_absorb_block(state, mask, b);
}

fn mro_encrypt_block(mask : &[Word; 16], tag : &[Word; 16], block_nr : usize, block_out : &mut[u8], block_in : &[u8]) {

    let mut b = &mut[0 as Word; 16];

    for i in 0..Words!(MRO_B) {
        b[i] = mask[i];
    }

    b[ 0] ^= tag[0];
    b[ 1] ^= tag[1];
    b[ 2] ^= tag[2];
    b[ 3] ^= tag[3];
    b[15] ^= block_nr as Word;

    mro_permute(b);

    for i in 0..Words!(MRO_B) {
        b[i] ^= load_le(&block_in[i * Bytes!(MRO_W)..]) ^ mask[i];
        store_le(&mut block_out[i * Bytes!(MRO_W)..], b[i]);
    }
}

fn mro_encrypt_lastblock(mask : &[Word; 16], tag : &[Word; 16], block_nr : usize, block_out : &mut[u8], block_in : &[u8]) {

    let mut b0 = &mut[0u8; Bytes!(MRO_B)];
    let mut b1 = &mut[0u8; Bytes!(MRO_B)];
    for i in 0..block_in.len() {
        b0[i] = block_in[i];
    }
    mro_encrypt_block(mask, tag, block_nr, b1, b0);
    for i in 0..block_in.len() {
        block_out[i] = b1[i];
    }
}

fn mro_absorb_data(state : &mut[Word; 16], mask : &mut[Word; 16], data : &[u8], data_type : Tag) {

    if data_type == Tag::MSG { 
        mro_beta(mask);
    }

    let mut i = data.len();
    let mut o = 0;
    while i >= Bytes!(MRO_B) {
        mro_absorb_block(state, mask, &data[o..o+Bytes!(MRO_B)]);
        i -= Bytes!(MRO_B);
        o += Bytes!(MRO_B);
        mro_alpha(mask);
    }
    if i > 0 {
        mro_absorb_lastblock(state, mask, &data[o..o+i]);
    }
}

fn mro_encrypt_data(mask : &mut[Word; 16], tag : &[Word; 16], data_out : &mut[u8], data_in : &[u8]) {

    mro_gamma(mask);

    let mut i = data_in.len();
    let mut o = 0;
    let mut n = 0;
    while i >= Bytes!(MRO_B) {
        mro_encrypt_block(mask, tag, n, &mut data_out[o..o+Bytes!(MRO_B)], &data_in[o..o+Bytes!(MRO_B)]);
        i -= Bytes!(MRO_B);
        o += Bytes!(MRO_B);
        n += 1;
    }
    if i > 0 {
        mro_encrypt_lastblock(mask, tag, n, &mut data_out[o..o+i], &data_in[o..o+i]);
    }
}

fn mro_decrypt_data(mask : &mut[Word; 16], tag : &[Word; 16], data_out : &mut[u8], data_in : &[u8]) {
    mro_encrypt_data(mask, tag, data_out, data_in);
}

fn mro_finalise(state : &mut[Word; 16], mask : &mut[Word; 16], hlen : usize, mlen : usize) {

    mro_beta(mask);
    mro_beta(mask);

    state[14] ^= hlen as Word;
    state[15] ^= mlen as Word;

    for i in 0..Words!(MRO_B) {
        state[i] ^= mask[i];
    }

    mro_permute(state);

    for i in 0..Words!(MRO_B) {
        state[i] ^= mask[i];
    }
}

fn mro_store_tag(state : &[Word; 16], tag : &mut[u8]) {
    for i in 0..Words!(MRO_T) {
       store_le(&mut tag[i * Bytes!(MRO_W)..], state[i]);
    }
}

fn mro_load_tag(state : &mut[Word; 16], tag : &[u8]) {
    for i in 0..Words!(MRO_T) {
        state[i] = load_le(&tag[i * Bytes!(MRO_W)..]);
    }
}

fn mro_verify_tag(x : &[u8], y : &[u8]) -> bool {

    if x.len() != y.len() {
        return false;
    }

    let mut acc = 0;

    for i in 0..Bytes!(MRO_T) {
        acc |= x[i] ^ y[i];
    }

    return acc == 0;
}

pub fn crypto_aead_encrypt(c : &mut[u8], h : &[u8], m : &[u8], nonce : &[u8; 16], key : &[u8; 32]) {

    let mut state = &mut[0 as Word; Words!(MRO_B)];
    let mut la = &mut[0 as Word; Words!(MRO_B)];
    let mut le = &mut[0 as Word; Words!(MRO_B)];

    // initialise masks
    mro_init_mask(le, key, nonce);
    for i in 0..Words!(MRO_B) { la[i] = le[i]; }

    // absorb header 
    mro_absorb_data(state, la, h, Tag::HDD);

    // absorb message
    for i in 0..Words!(MRO_B) { la[i] = le[i]; }
    mro_absorb_data(state, la, m, Tag::MSG);

    // finalise data absorb
    for i in 0..Words!(MRO_B) { la[i] = le[i]; }
    mro_finalise(state, la, h.len(), m.len());

    // extract tag
    mro_store_tag(state, &mut c[m.len()..]);

    // encrypt data
    mro_encrypt_data(le, state, &mut c[0..m.len()], m);
}

pub fn crypto_aead_decrypt(m : &mut[u8], h : &[u8], c : &[u8], nonce: &[u8; 16], key : &[u8; 32]) -> bool {

    let mut state = &mut[0 as Word; Words!(MRO_B)];
    let mut la = &mut[0 as Word; Words!(MRO_B)];
    let mut le = &mut[0 as Word; Words!(MRO_B)];
    let mut tag = &mut[0u8; Bytes!(MRO_T)];
    let mlen = c.len() - Bytes!(MRO_T);

    // initialise masks
    mro_init_mask(le, key, nonce);
    for i in 0..la.len() { la[i] = le[i]; }

    // load received tag temporarily into the first four state words
    mro_load_tag(state, &c[mlen..]);

    // decrypt message
    mro_decrypt_data(le, state, m, &c[0..mlen]);

    // absorb header
    for i in 0..state.len() { state[i] = 0; le[i] = la[i]; }
    mro_absorb_data(state, la, h, Tag::HDD);

    // absorb message
    for i in 0..la.len() { la[i] = le[i]; }
    mro_absorb_data(state, la, m, Tag::MSG);
    
    // finalise data absorb
    for i in 0..la.len() { la[i] = le[i]; }
    mro_finalise(state, la, h.len(), mlen);

    // extract tag
    mro_store_tag(state,tag);

    // verify tag
    return mro_verify_tag(&c[mlen..], tag);
}
