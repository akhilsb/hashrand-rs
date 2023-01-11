use std::collections::{HashSet, HashMap};

use types::{appxcon::{Replica, MerkleProof,reconstruct_and_verify, reconstruct_and_return}, hash_cc::{CTRBCMsg}};

#[derive(Debug,Clone)]
pub struct RBCRoundState{
    // Map of Replica, and its corresponding (Shard, MerkleProof of Shard, Merkle Root)
    pub node_msgs: HashMap<Replica,(Vec<u8>,MerkleProof),nohash_hasher::BuildNoHashHasher<Replica>>,
    pub echos: HashMap<Replica,HashMap<Replica,(Vec<u8>,MerkleProof)>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub readys: HashMap<Replica,HashMap<Replica,(Vec<u8>,MerkleProof)>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub echo_sent: HashSet<Replica,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub ready_sent:HashSet<Replica,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub recon_sent:HashSet<Replica,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub recon_msgs:HashMap<Replica,HashMap<Replica,Vec<u8>>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub accepted_msgs: HashMap<Replica,Vec<u8>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub accepted_vals: Vec<i64>,
    pub witnesses: HashMap<Replica,Vec<Replica>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub terminated_rbcs: HashSet<Replica,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub accepted_witnesses: HashSet<Replica,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub witness_sent:bool,
    pub completed:bool,
}

impl RBCRoundState{
    pub fn new(ctrbc:&CTRBCMsg)-> RBCRoundState{
        let mut rnd_state = RBCRoundState{
            node_msgs: HashMap::default(),
            echos: HashMap::default(),
            readys:HashMap::default(),
            echo_sent: HashSet::default(),
            ready_sent: HashSet::default(),
            recon_sent: HashSet::default(),
            recon_msgs:HashMap::default(),
            witnesses:HashMap::default(),
            accepted_msgs: HashMap::default(),
            accepted_vals: Vec::new(),
            terminated_rbcs:HashSet::default(),
            accepted_witnesses:HashSet::default(),
            witness_sent:false,
            completed:false
        };
        rnd_state.node_msgs.insert(ctrbc.origin, (ctrbc.shard.clone(),ctrbc.mp.clone()));
        return rnd_state;
    }

    pub fn add_rbc_shard(&mut self, ctr:&CTRBCMsg)->(){
        let rbc_origin = ctr.origin;
        self.node_msgs.insert(rbc_origin, (ctr.shard.clone(),ctr.mp.clone()));
    }

    pub fn add_echo(&mut self, rbc_origin: Replica, echo_origin: Replica, ctr:&CTRBCMsg){
        match self.echos.get_mut(&rbc_origin)  {
            None => {
                let mut hash_map = HashMap::default();
                hash_map.insert(echo_origin,(ctr.shard.clone(),ctr.mp.clone()));
                self.echos.insert(rbc_origin, hash_map);
            },
            Some(x) => {
                x.insert(echo_origin,(ctr.shard.clone(),ctr.mp.clone()));
            },
        }
    }

    pub fn add_ready(&mut self, rbc_origin: Replica, ready_origin: Replica, ctr:&CTRBCMsg){
        match self.readys.get_mut(&rbc_origin)  {
            None => {
                let mut hash_map = HashMap::default();
                hash_map.insert(ready_origin,(ctr.shard.clone(),ctr.mp.clone()));
                self.readys.insert(rbc_origin, hash_map);
            },
            Some(x) => {
                x.insert(ready_origin,(ctr.shard.clone(),ctr.mp.clone()));
            },
        }
    }

    pub fn add_recon(&mut self, sec_origin: Replica, recon_origin: Replica, ctr:&CTRBCMsg){
        match self.recon_msgs.get_mut(&sec_origin) {
            None => {
                let mut reconset = HashMap::default();
                reconset.insert(recon_origin,ctr.shard.clone());
                self.recon_msgs.insert(sec_origin, reconset);
            },
            Some(x) => {
                x.insert(recon_origin,ctr.shard.clone());
            }
        }
    }

    pub fn check_merkle_root(&mut self, ctr:&CTRBCMsg) -> bool{
        let merkle_root = self.node_msgs.get(&ctr.origin).unwrap().1.root();
        // Merkle root check. Check if the merkle root of the message matches the merkle root sent by the node
        if merkle_root != ctr.mp.to_proof().root(){
            log::error!("Merkle root verification failed with error {:?}{:?}",merkle_root,ctr.mp.to_proof().root());
            return false;
        }
        true
    }

    pub fn echo_check(&mut self, rbc_origin: Replica, num_nodes: usize,num_faults:usize, myid:Replica)-> Option<(Vec<u8>,MerkleProof)>{
        let echos = self.echos.get_mut(&rbc_origin).unwrap();
        // 2. Check if echos reached the threshold, init already received, and round number is matching
        log::debug!("WSS ECHO check: echos.len {}, contains key: {}"
        ,echos.len(),self.node_msgs.contains_key(&rbc_origin));
        
        if !self.echo_sent.contains(&rbc_origin) && echos.len() >= num_nodes-num_faults && 
            self.node_msgs.contains_key(&rbc_origin){
            // Broadcast readys, otherwise, just wait longer
            // Cachin-Tessaro RBC implies verification needed
            // Send your own shard in the echo phase to every other node. 
            let merkle_root = self.node_msgs.get(&rbc_origin).unwrap().1.root();
            let res_recon = reconstruct_and_verify(echos.clone(), num_nodes, num_faults,myid, merkle_root);
            match res_recon {
                Err(error)=> {
                    log::error!("Shard reconstruction failed because of the following reason {:?}",error);
                    return None;
                },
                Ok(vec_x)=> {
                    self.echo_sent.insert(rbc_origin);
                    return Some(vec_x);
                }
            }   
        }
        None
    }

    pub fn ready_check(&mut self, rbc_origin: Replica, num_nodes: usize,num_faults:usize, myid:Replica)-> Option<(Vec<u8>,MerkleProof,usize)>{
        let readys = self.readys.get_mut(&rbc_origin).unwrap();
        // 2. Check if readys reached the threshold, init already received, and round number is matching
        log::debug!("READY check: echos.len {}, contains key: {}"
        ,readys.len(),self.node_msgs.contains_key(&rbc_origin));
        
        if !self.ready_sent.contains(&rbc_origin) && readys.len() >= num_faults+1 &&
            self.node_msgs.contains_key(&rbc_origin) && !readys.contains_key(&myid){
            // Broadcast readys, otherwise, just wait longer
            // Cachin-Tessaro RBC implies verification needed
            let merkle_root = self.node_msgs.get(&rbc_origin).unwrap().1.root();
            let res = 
                reconstruct_and_verify(readys.clone(), num_nodes, num_faults,myid, merkle_root);
            match res {
                Err(error)=> {
                    log::error!("Shard reconstruction failed because of the following reason {:?}",error);
                    return None;
                },
                Ok(vec_x)=> {
                    self.ready_sent.insert(rbc_origin);
                    return Some((vec_x.0,vec_x.1,num_faults+1));
                }
            };
        }
        else if !self.recon_sent.contains(&rbc_origin) && readys.len() >= num_nodes-num_faults &&
            self.node_msgs.contains_key(&rbc_origin){
            // Terminate RBC, RAccept the value
            // Add value to value list, add rbc to rbc list
            let merkle_root = self.node_msgs.get(&rbc_origin).unwrap().1.root();
            let res = 
                reconstruct_and_verify(readys.clone(), num_nodes, num_faults,myid, merkle_root);
            match res {
                Err(error)=> {
                    log::error!("Shard reconstruction failed because of the following reason {:?}",error);
                    return None;
                },
                Ok(vec_x)=> {
                    self.recon_sent.insert(rbc_origin);
                    return Some((vec_x.0,vec_x.1,num_nodes-num_faults));
                    //let ctrbc = CTRBCMsg::new(vec_x.0, vec_x.1, round, rbc_origin);
                }
            };
        }
        None
    }

    pub fn reconstruct_message(&mut self, rbc_origin: Replica, num_nodes: usize,num_faults:usize)->Option<Vec<u8>>{
        let ready_check = self.readys.get(&rbc_origin).unwrap().len() >= (num_nodes-num_faults);
        if !self.recon_msgs.contains_key(&rbc_origin){
            return None;
        }
        let vec_fmap = self.recon_msgs.get(&rbc_origin).unwrap();
        if vec_fmap.len()>=num_nodes-num_faults && ready_check{
            // Reconstruct here
            let result = reconstruct_and_return(vec_fmap, num_nodes, num_faults);
            match result {
                Err(error)=> {
                    log::error!("Error resulted in constructing erasure-coded data {:?}",error);
                    return None;
                }
                Ok(vec)=>{
                    log::info!("Successfully reconstructed message for RBC, terminating RBC of node {}",rbc_origin);
                    self.accepted_msgs.insert(rbc_origin, vec.clone());
                    self.terminated_rbcs.insert(rbc_origin);
                    return Some(vec);
                }
            }
        }
        None
    }

    pub fn complete_round(&mut self){
        self.completed = true;
    }
}