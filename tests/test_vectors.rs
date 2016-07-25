#[macro_use]
extern crate mem_aead;

use mem_aead::{ROTR64};

#[test]
fn test() {

    let x = 0x0123456789abcdef;

    //0xef0123456789abcd
   
    //assert_eq!(ROTR64(x,8),ROTR!(x,8));

    //println!("{:?}", g(0,0,0,0));
}
