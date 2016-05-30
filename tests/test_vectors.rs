extern crate mem_aead;

use mem_aead::{rotr64};

#[test]
fn test() {
    assert_eq!(rotr64(0x0123456789abcdef,8),0xef0123456789abcd);
}
