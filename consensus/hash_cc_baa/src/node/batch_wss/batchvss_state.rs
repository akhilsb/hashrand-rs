use std::collections::{HashMap, HashSet};

use crypto::hash::Hash;
use num_bigint::BigInt;
use types::{Replica, appxcon::MerkleProof, hash_cc::{WSSMsg, BatchWSSMsg}};

pub struct BatchVSSState{
    /// The structure of the tuple: (Secret, Random nonce, Commitment, Merkle Proof for commitment)
    pub node_secrets: HashMap<Replica,BatchWSSMsg>,
    pub echos: HashMap<Replica,HashMap<Replica,(Vec<u8>,MerkleProof)>>,
    pub readys: HashMap<Replica,HashMap<Replica,(Vec<u8>,MerkleProof)>>,
    pub recon_msgs:HashMap<Replica,HashMap<Replica,Vec<u8>>>,
    pub comm_vectors:HashMap<Replica,Vec<Hash>>,
    pub terminated_secrets: HashSet<Replica>,
    pub secret_shares: HashMap<Replica,HashMap<Replica,(usize,WSSMsg)>>,
    pub reconstructed_secrets:HashMap<Replica,BigInt>,
    // Gather protocol related state context
    pub witness1: HashMap<Replica,Vec<Replica>>,
    pub witness2: HashMap<Replica,Vec<Replica>>,
    pub send_w1: bool,
    pub send_w2:bool,
    pub accepted_witnesses1: HashSet<Replica>,
    pub accepted_witnesses2: HashSet<Replica>,
    pub recon_secret:usize,
}

impl BatchVSSState{
    pub fn new()-> BatchVSSState{
        BatchVSSState{
            node_secrets: HashMap::default(),
            echos: HashMap::default(),
            readys:HashMap::default(),
            recon_msgs:HashMap::default(),
            comm_vectors:HashMap::default(),
            secret_shares:HashMap::default(),
            reconstructed_secrets:HashMap::default(),
            witness1:HashMap::default(),
            witness2: HashMap::default(),
            send_w1:false,
            send_w2:false,
            terminated_secrets:HashSet::default(),
            accepted_witnesses1:HashSet::default(),
            accepted_witnesses2:HashSet::default(),
            recon_secret:0,
        }
    }
}