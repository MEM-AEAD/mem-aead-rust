#[macro_use]
extern crate mem_aead;

use mem_aead::opp::{crypto_aead_encrypt,crypto_aead_decrypt};

pub mod utils;

fn main() {
    utils::debug(&crypto_aead_encrypt, &crypto_aead_decrypt);
}
