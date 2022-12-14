use std::collections::{HashMap, HashSet};

use crypto::hash::Hash;
use num_bigint::BigInt;
use types::{Replica, appxcon::MerkleProof, hash_cc::WSSMsg};

pub struct VSSState{
    /// The structure of the tuple: (Secret, Random nonce, Commitment, Merkle Proof for commitment)
    pub node_secrets: HashMap<Replica,(Vec<u8>,Vec<u8>,Hash,MerkleProof)>,
    pub echos: HashMap<Replica,HashSet<Replica>>,
    pub readys: HashMap<Replica,HashSet<Replica>>,
    pub accepted_secrets: HashMap<Replica,(Vec<u8>,Vec<u8>,Hash,MerkleProof)>,
    pub terminated_secrets: HashSet<Replica>,
    pub secret_shares: HashMap<Replica,HashMap<Replica,WSSMsg>>,
    pub reconstructed_secrets:HashMap<Replica,BigInt>,
    // Gather protocol related state context
    pub witness1: HashMap<Replica,Vec<Replica>>,
    pub witness2: HashMap<Replica,Vec<Replica>>,
    pub send_w1: bool,
    pub send_w2:bool,
    pub accepted_witnesses1: HashSet<Replica>,
    pub accepted_witnesses2: HashSet<Replica>,
    pub nz_appxcon_rs: HashMap<Replica,(BigInt,bool,BigInt)>,

}

impl VSSState{
    pub fn new()-> VSSState{
        VSSState{
            node_secrets: HashMap::default(),
            echos: HashMap::default(),
            readys:HashMap::default(),
            accepted_secrets:HashMap::default(),
            secret_shares:HashMap::default(),
            reconstructed_secrets:HashMap::default(),
            witness1:HashMap::default(),
            witness2: HashMap::default(),
            send_w1:false,
            send_w2:false,
            terminated_secrets:HashSet::default(),
            accepted_witnesses1:HashSet::default(),
            accepted_witnesses2:HashSet::default(),
            nz_appxcon_rs: HashMap::default(),
        }
    }
}