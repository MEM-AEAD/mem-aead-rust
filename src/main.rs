#[macro_use]
extern crate mem_aead;

//use std::num::Int;
//use std::num::{Wrapping};

use mem_aead::{crypto_aead_encrypt,crypto_aead_decrypt};


fn print_state(x : &[u64; 16]) {
    println!("{:016X} {:016X} {:016X} {:016X}", x[ 0], x[ 1], x[ 2], x[ 3]);
    println!("{:016X} {:016X} {:016X} {:016X}", x[ 4], x[ 5], x[ 6], x[ 7]);
    println!("{:016X} {:016X} {:016X} {:016X}", x[ 8], x[ 9], x[10], x[11]);
    println!("{:016X} {:016X} {:016X} {:016X}", x[12], x[13], x[14], x[15]);
}

fn print_bytes(v : &[u8]) {
    for i in 0..v.len() {
        print!("{:02X} ", v[i]);
        if i % 16 == 15 {
            println!("");
        }
    }
    println!("");
}

const HLEN : usize = 129;
const MLEN : usize = 256;

fn main() {

    let k : &[u8; 32] = &[0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00];
    let n : &[u8; 16] = &[0xF0,0xE0,0xD0,0xC0,0xB0,0xA0,0x90,0x80,0x70,0x60,0x50,0x40,0x30,0x20,0x10,0x00];
    let h = &mut[0u8; HLEN];
    let m = &mut[0u8; MLEN];
    let c = &mut[0u8; MLEN + 32];

    for i in 0..HLEN { h[i] = (i & 255 ) as u8; }
    for i in 0..MLEN { m[i] = (i & 255 ) as u8; }

    println!("========== SETUP ==========");
    println!("KEY:");
    print_bytes(k);
    println!("NONCE:");
    print_bytes(n);
    println!("HEADER:");
    print_bytes(h);
    println!("PAYLOAD:");
    print_bytes(m);


    println!("========== ENCRYPTION ==========");
    crypto_aead_encrypt(c, h, m, n, k);
    println!("ENCRYPTED PAYLOAD + TAG:");
    print_bytes(c);

    println!("========== ENCRYPTION ==========");
    let result = crypto_aead_decrypt(m, h, c, n, k);
    println!("DECRYPTED PAYLOAD:");
    print_bytes(m);

    println!("{}", result);

    // key
    //let mut k = &mut[0u8; 32];
    //store64_le(&mut k[0..], w);
    //store64_le(&mut k[8..], x);
    //store64_le(&mut k[16..], y);
    //store64_le(&mut k[24..], z);

    // nonce
    //let mut n = &mut[0u8; 16];
    //store64_le(&mut n[0..], y);
    //store64_le(&mut n[8..], z);

    //print_bytes(v);
    //let a = load64_le(&v[0..]);
    //assert_eq!(a, z);
    //println!("{:016X}", a);
     
    //mro_init_mask(mask, k, n);
   
    //print_state(mask);
       
}
