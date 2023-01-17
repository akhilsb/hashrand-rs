use std::collections::{HashSet, HashMap};

use crypto::hash::Hash;
use types::appxcon::{Replica, MerkleProof};

#[derive(Debug,Clone)]
pub struct RoundState{
    // Map of Replica, and its corresponding (Shard, MerkleProof of Shard, Merkle Root)
    pub node_msgs: HashMap<Replica,(Vec<u8>,MerkleProof,Hash)>,
    pub echos: HashMap<Replica,HashMap<Replica,(Vec<u8>,MerkleProof)>>,
    pub readys: HashMap<Replica,HashMap<Replica,(Vec<u8>,MerkleProof)>>,
    pub recon_msgs:HashMap<Replica,HashMap<Replica,Vec<u8>>>,
    pub accepted_msgs: HashMap<Replica,Vec<u8>>,
    pub accepted_vals: Vec<i64>,
    pub witnesses: HashMap<Replica,Vec<Replica>>,
    pub terminated_rbcs: HashSet<Replica>,
    pub accepted_witnesses: HashSet<Replica>,
    pub witness_sent:bool
}

impl RoundState{
    pub fn new()-> RoundState{
        RoundState{
            node_msgs: HashMap::default(),
            echos: HashMap::default(),
            readys:HashMap::default(),
            recon_msgs:HashMap::default(),
            witnesses:HashMap::default(),
            accepted_msgs: HashMap::default(),
            accepted_vals: Vec::new(),
            terminated_rbcs:HashSet::default(),
            accepted_witnesses:HashSet::default(),
            witness_sent:false
        }
    }
}