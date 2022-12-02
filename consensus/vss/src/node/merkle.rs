use std::hash::Hasher;

use crypto::hash::do_hash;
use merkle_light::{hash::Algorithm, proof::Proof};
use sha2::{Sha256, Digest};
use types::appxcon::MerkleProof;

pub struct HashingAlg(Sha256);

impl HashingAlg{
    pub fn new()-> HashingAlg{
        HashingAlg(Sha256::new())
    }
}

impl Default for HashingAlg {
    fn default() -> HashingAlg {
        HashingAlg::new()
    }
}

impl Hasher for HashingAlg{
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.update(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl Algorithm<[u8; 32]> for HashingAlg {
    #[inline]
    fn hash(&mut self) -> [u8; 32] {
        //let mut h = [0u8; 32];
        let result = self.0.clone().finalize().into();
        result
    }

    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }
}

pub fn verify_merkle_proof(mp:&MerkleProof,shard:&Vec<u8>)->bool{
    // 2. Validate Merkle Proof
    let proof:Proof<[u8;32]> = mp.to_proof();
    let hash_of_shard:[u8;32] = do_hash(shard.as_slice());
    let state: bool =  hash_of_shard != proof.item().clone() || !proof.validate::<HashingAlg>();
    return state;
}