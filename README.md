# Masked Even-Mansour AEAD Modes (Rust)

## Warning
The cipher designs of this source code package are very new and still **lack extensive analysis**. Therefore, **do not use** them in your applications just now!


## About
This repository provides [Rust](https://www.rust-lang.org) reference implementations for the authenticated encryption modes **OPP** and **MRO** instantiated with a round-reduced [BLAKE2b](https://blake2.net/) permutation. All ciphers target a 256-bit security level.

The specification of the schemes together with many more information can be found at [ia.cr/2015/999](https://eprint.iacr.org/2015/999). 
The C reference source code is available [here](https://github.com/MEM-AEAD/mem-aead).


### Features
* **OPP:**
    - based on the tweakable Masked Even-Mansour (MEM) block cipher
    - requires nonce-uniqueness
    - 1-pass
    - fully parallelisable
    - constant-time
* **MRO:**
    - based on the tweakable Masked Even-Mansour (MEM) block cipher
    - fully misuse-resistant
    - 2-pass
    - fully parallelisable
    - constant-time

### Usage

There are four examples which can be executed through:

    cargo run --example {mro_debug,mro_genkat,opp_debug,opp_genkat}

**Warning:** The `*_genkat` examples generate the test vectors in `tests/*_kat.rs` and produce large amounts of output.

## License
The source code provided in this repository is copyright (c) 2016 [Philipp Jovanovic](https://zerobyte.io) and released under the [CC0 license](https://creativecommons.org/publicdomain/zero/1.0/). The full license text is included in the file `LICENSE`.
