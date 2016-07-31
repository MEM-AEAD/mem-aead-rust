#[macro_use]
extern crate mem_aead;

use mem_aead::opp::{crypto_aead_encrypt};

pub mod utils;

fn main() {
    utils::genkat(&crypto_aead_encrypt);
}
