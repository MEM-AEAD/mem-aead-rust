#[macro_use]
extern crate mem_aead;

use mem_aead::mro::{crypto_aead_encrypt};

pub mod utils;

#[allow(dead_code)]
fn main() {
    utils::genkat(&crypto_aead_encrypt);
}
