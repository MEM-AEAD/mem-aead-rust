extern crate mem_aead;

#[cfg(test)]
mod test {

    use mem_aead::mro::{crypto_aead_encrypt,crypto_aead_decrypt};
    use mem_aead::mro_kat; // XXX: this should definitely be part of the test

    #[test]
    fn mro_test() {
    
        const MAX_SIZE : usize = 768;
    
        let k = &mut[0u8; 32];
        let n = &mut[0u8; 16];
        let m = &mut[0u8; MAX_SIZE];
        let h = &mut[0u8; MAX_SIZE];
        let c = &mut[0u8; MAX_SIZE + 32];
    
        for i in 0..MAX_SIZE {
            m[i] = (255 & (i * 197 + 123)) as u8;
            h[i] = (255 & (i * 193 + 123)) as u8;
        }
        for i in 0..k.len() {
            k[i] = (255 & (i * 191 + 123)) as u8;
        }
        for i in 0..n.len() {
            n[i] = (255 & (i * 181 + 123)) as u8;
        }
    
        let mut pos = 0;
    
        for i in 0..MAX_SIZE {
    
            crypto_aead_encrypt(&mut c[0..i+32], &h[0..i], &m[0..i], n, k);
    
            for j in 0..i+32 {
                assert_eq!(mro_kat::KAT[pos + j ], c[j]);
            }
    
            let w = &mut[0u8; MAX_SIZE];
    
            assert!(crypto_aead_decrypt(&mut w[0..i], &h[0..i], &c[0..i+32], n, k));
    
            pos += i+32;
        }
    }

}
