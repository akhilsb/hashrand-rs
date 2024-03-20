// use sha2::{Digest, Sha256};
// use serde::Serialize;
// use hmac::Hmac;
// use aes::{Aes256, cipher::{generic_array::GenericArray, KeyInit, BlockEncrypt}};

// pub const HASH_SIZE:usize = 32;

// pub type Hash = [u8; HASH_SIZE];

// pub const EMPTY_HASH:Hash = [0 as u8; 32];


// type HmacSha256 = Hmac<Sha256>;

// #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"),
//       target_feature = "avx2"))]
// fn foo() {
//     #[cfg(target_arch = "x86")]
//     use std::arch::x86::_mm256_add_epi64;
//     #[cfg(target_arch = "x86_64")]
//     use std::arch::x86_64::_mm256_add_epi64;

//     unsafe {
//         _mm256_add_epi64(...);
//     }
// }
// pub fn do_hash(one: &[u8;32],two: &[u8;32]) {
//     // Hash function implemented from a block cipher according to this paper
//     // https://www.cs.ucdavis.edu/~rogaway/papers/lp.pdf
//     let key0 = GenericArray::from([0u8; 32]);
//     let key1 = GenericArray::from([20u8; 32]);
//     let key2 = GenericArray::from([17u8; 32]);
    
//     let ciph0 = Aes256::new(&key0);
//     let ciph1 = Aes256::new(&key1);
//     let ciph2 = Aes256::new(&key2);

//     let mut x_1 = ;
//     let mut blk_1 = GenericArray::from(x_1.into());
//     let mut pi_1 = ciph0.encrypt_block(&mut blk_1);
// }


// pub fn do_hash_merkle(bytes: &[u8])-> Hash{
//     let mut sha256 = Sha256::new();
//     sha256.update(&[0x00]);
//     sha256.update(bytes);
//     sha256.clone().finalize().into()
// }

// pub fn ser_and_hash(obj: &impl Serialize) -> Hash {
//     let serialized_bytes = bincode::serialize(obj).unwrap();
//     return do_hash(&serialized_bytes);
// }