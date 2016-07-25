use std::num::{Wrapping};

const MRO_W: usize = 64;         // word size
const MRO_L: usize = 4;          // number of rounds
const MRO_T: usize = MRO_W *  4; // tag size
const MRO_N: usize = MRO_W *  2; // nonce size
const MRO_K: usize = MRO_W *  4; // key size
const MRO_B: usize = MRO_W * 16; // permutation size

const R0 : u32 = 32; 
const R1 : u32 = 24; 
const R2 : u32 = 16; 
const R3 : u32 = 63; 

// XXX: remove all the magic constants

#[inline]
pub fn load64_le(v : &[u8]) -> u64 {
    let mut x = 0u64;
    for i in 0..8 {
        x |= (v[i] as u64) << (8*i);
    }
    return x;
}

#[inline]
pub fn store64_le(v : &mut[u8], x : u64) {
    for i in 0..8 {
        v[i] = (x >> 8*i) as u8;
    }
}

macro_rules! Add { ($x: expr, $y: expr) => ( (Wrapping($x)+Wrapping($y)).0;); }

macro_rules! G { ($a:expr, $b:expr, $c:expr, $d:expr) => 
    ({
        $a = Add!($a, $b); $d ^= $a; $d = $d.rotate_right(R0); 
        $c = Add!($c, $d); $b ^= $c; $b = $b.rotate_right(R1); 
        $a = Add!($a, $b); $d ^= $a; $d = $d.rotate_right(R2); 
        $c = Add!($c, $d); $b ^= $c; $b = $b.rotate_right(R3);
    });
}

#[allow(non_snake_case)]
pub fn F(x : &mut[u64; 16]) {
    // Column step
    G!(x[ 0], x[ 4], x[ 8], x[12]);
    G!(x[ 1], x[ 5], x[ 9], x[13]);
    G!(x[ 2], x[ 6], x[10], x[14]);
    G!(x[ 3], x[ 7], x[11], x[15]);
    // Diagonal step
    G!(x[ 0], x[ 5], x[10], x[15]);
    G!(x[ 1], x[ 6], x[11], x[12]);
    G!(x[ 2], x[ 7], x[ 8], x[13]);
    G!(x[ 3], x[ 4], x[ 9], x[14]);
}

pub fn mro_permute(x : &mut[u64; 16]) {
    for _ in 0..MRO_L {
        F(x);
    }
}

#[inline]
pub fn mro_pad(output : &mut[u8], input : &[u8]) {
    for i in 0..input.len() {
        output[i] = input[i];
    }
    for i in input.len()..output.len() {
        output[i] = 0;
    }
    output[input.len()] = 0x01;
}

pub fn mro_init_mask(mask : &mut[u64; 16], k : &[u8; 32], n : &[u8; 16]) {

    mask[ 0] = load64_le(&n[0..]);
    mask[ 1] = load64_le(&n[8..]);
    mask[ 2] = 0;
    mask[ 3] = 0;

    mask[ 4] = 0;
    mask[ 5] = 0;
    mask[ 6] = 0;
    mask[ 7] = 0;

    mask[ 8] = 0;
    mask[ 9] = 0;
    mask[10] = MRO_L as u64;
    mask[11] = MRO_T as u64;

    mask[12] = load64_le(&k[0..]);
    mask[13] = load64_le(&k[8..]);
    mask[14] = load64_le(&k[16..]);
    mask[15] = load64_le(&k[24..]);

    mro_permute(mask);
}

pub fn mro_alpha(mask : &mut[u64; 16]) {
    let t = mask[0].rotate_left(53) ^ (mask[5] << 13);
    for i in 0..15 {
        mask[i] = mask[i+1];
    }
    mask[15] = t;
}

pub fn mro_beta(mask : &mut[u64; 16]) {
    let t = mask[0].rotate_left(53) ^ (mask[5] << 13);
    for i in 0..15 {
        mask[i] ^= mask[i+1];
    }
    mask[15] ^= t;
}

pub fn mro_gamma(mask : &mut[u64; 16]) {
    let t0 = mask[0].rotate_left(53) ^ (mask[5] << 13);
    let t1 = mask[1].rotate_left(53) ^ (mask[6] << 13);
    for i in 0..14 {
        mask[i] ^= mask[i+1] ^ mask[i+2];
    }
    mask[14] ^= (mask[15] ^ t0);
    mask[15] ^= t0 ^ t1;
}

pub fn mro_absorb_block(state : &mut[u64; 16], mask : &[u64; 16], block : &[u8]) {

    let mut b = &mut[0u64; 16];

    for i in 0..16 {
        b[i] = load64_le(&block[8*i..]) ^ mask[i];
    }

    mro_permute(b);

    for i in 0..16 {
        state[i] ^= b[i] ^ mask[i];
    }
}

pub fn mro_absorb_lastblock(state : &mut[u64; 16], mask : &[u64; 16], block : &[u8]) {
    let mut b = &mut[0u8; 128];
    mro_pad(b, block);
    mro_absorb_block(state, mask, b);
}

pub fn mro_encrypt_block(mask : &[u64; 16], tag : &[u64; 16], block_nr : usize, block_out : &mut[u8], block_in : &[u8]) {

    let mut b = &mut[0u64; 16];

    for i in 0..16 {
        b[i] = mask[i];
    }

    b[ 0] ^= tag[0];
    b[ 1] ^= tag[1];
    b[ 2] ^= tag[2];
    b[ 3] ^= tag[3];
    b[15] ^= block_nr as u64;

    mro_permute(b);

    for i in 0..16 {
        b[i] ^= load64_le(&block_in[8*i..]) ^ mask[i];
        store64_le(&mut block_out[8*i..], b[i]);
    }
}

pub fn mro_encrypt_lastblock(mask : &[u64; 16], tag : &[u64; 16], block_nr : usize, block_out : &mut[u8], block_in : &[u8]) {

    let mut b0 = &mut[0u8; 128];
    let mut b1 = &mut[0u8; 128];
    for i in 0..block_in.len() {
        b0[i] = block_in[i];
    }
    mro_encrypt_block(mask, tag, block_nr, b1, b0);
    for i in 0..block_in.len() {
        block_out[i] = b1[i];
    }
}

pub fn mro_absorb_data(state : &mut[u64; 16], mask : &mut[u64; 16], data : &[u8], flag : bool) {

    if flag { // XXX: better name
        mro_beta(mask);
    }

    let mut inlen = data.len();
    let mut offset = 0;
    while inlen >= 128 {
        mro_absorb_block(state, mask, &data[offset..]);
        inlen -= 128;
        offset += 128;
        mro_alpha(mask);
    }
    if inlen > 0 {
        mro_absorb_lastblock(state, mask, &data[offset..]);
    }
}

pub fn mro_encrypt_data(mask : &mut[u64; 16], tag : &[u64; 16], data_out : &mut[u8], data_in : &[u8], inlen : usize) {

    mro_gamma(mask);

    let mut len = inlen;
    let mut offset = 0;
    let mut block_nr : usize = 0;
    while len >= 128 {
        mro_encrypt_block(mask, tag, block_nr, &mut data_out[offset..], &data_in[offset..]);
        len -= 128;
        offset += 128;
        block_nr += 1;
    }
    if len > 0 {
        mro_encrypt_lastblock(mask, tag, block_nr, &mut data_out[offset..], &data_in[offset..]);
    }
}

pub fn mro_decrypt_data(mask : &mut[u64; 16], tag : &[u64; 16], data_out : &mut[u8], data_in : &[u8], inlen : usize) {
    mro_encrypt_data(mask, tag, data_out, data_in, inlen);
}

pub fn mro_finalise(state : &mut[u64; 16], mask : &mut[u64; 16], hlen : usize, mlen : usize) {

    mro_beta(mask);
    mro_beta(mask);

    state[14] ^= hlen as u64;
    state[15] ^= mlen as u64;

    for i in 0..16 {
        state[i] ^= mask[i];
    }

    mro_permute(state);

    for i in 0..16 {
        state[i] ^= mask[i];
    }
}

pub fn mro_output_tag(state : &mut[u64; 16], tag : &mut[u8]) { // XXX: figure out how to extract fixed-size byte slices

    let mut block  = &mut[0u8; 32];

    for i in 0..4 {
       store64_le(&mut block[8*i..], state[i]); // XXX: maybe write directly to tag?
    }

    tag.copy_from_slice(block);
}

pub fn mro_verify_tag(tag1 : &[u8], tag2 : &[u8]) -> bool {

    let mut acc = 0;

    for i in 0..32 {
        acc |= tag1[i] ^ tag2[i];
    }

    return acc == 0;
}


pub fn crypto_aead_encrypt(c : &mut[u8], h : &[u8], m : &[u8], nonce : &[u8; 16], key : &[u8; 32]) {

    let mut state = &mut[0u64; 16];
    let mut la = &mut[0u64; 16];
    let mut le = &mut[0u64; 16];

    mro_init_mask(le, key, nonce);

    // absorb header and message
    for i in 0..la.len() { la[i] = le[i]; }
    mro_absorb_data(state, la, h, false);

    for i in 0..la.len() { la[i] = le[i]; }
    mro_absorb_data(state, la, m, true);

    for i in 0..la.len() { la[i] = le[i]; }
    mro_finalise(state, la, h.len(), m.len());

    mro_output_tag(state, &mut c[m.len()..]);

    mro_encrypt_data(le, state, c, m, m.len());
}

pub fn crypto_aead_decrypt(m : &mut[u8], h : &[u8], c : &[u8], nonce: &[u8; 16], key : &[u8; 32]) -> bool {

    let mut state = &mut[0u64; 16];
    let mut la = &mut[0u64; 16];
    let mut le = &mut[0u64; 16];
    let mut tag = &mut[0u8; 32];

    mro_init_mask(le, key, nonce);
    for i in 0..la.len() { la[i] = le[i]; }

    let mlen = c.len() - 32;

    state[0] = load64_le(&c[mlen +  0..]);
    state[1] = load64_le(&c[mlen +  8..]);
    state[2] = load64_le(&c[mlen + 16..]);
    state[3] = load64_le(&c[mlen + 24..]);

    mro_decrypt_data(le, state, m, c, mlen);

    // prepare state and mask for data absorb
    for i in 0..state.len() { state[i] = 0; le[i] = la[i]; }
    mro_absorb_data(state, la, h, false);

    for i in 0..la.len() { la[i] = le[i]; }
    mro_absorb_data(state, la, m, true);
    
    for i in 0..la.len() { la[i] = le[i]; }
    mro_finalise(state, la, h.len(), mlen);

    mro_output_tag(state,tag);

    return mro_verify_tag(&c[mlen..], tag);
}
