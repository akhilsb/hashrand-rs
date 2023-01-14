use std::{collections::{HashMap, HashSet}};

use crypto::hash::{Hash, do_hash, do_hash_merkle};
use merkle_light::merkle::MerkleTree;
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use types::{Replica, appxcon::{MerkleProof, reconstruct_and_return, HashingAlg}, hash_cc::{WSSMsg, BatchWSSMsg, CTRBCMsg}};

use crate::node::{ShamirSecretSharing, CoinRoundState};

#[derive(Clone)]
pub struct BatchVSSState{
    /// The structure of the tuple: (Secret, Random nonce, Commitment, Merkle Proof for commitment)
    pub node_secrets: HashMap<Replica,BatchWSSMsg,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub echos: HashMap<Replica,HashMap<Replica,(Vec<u8>,MerkleProof)>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub readys: HashMap<Replica,HashMap<Replica,(Vec<u8>,MerkleProof)>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub recon_msgs:HashMap<Replica,HashMap<Replica,Vec<u8>>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub comm_vectors:HashMap<Replica,Vec<Hash>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub terminated_secrets: HashSet<Replica,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub secret_shares: HashMap<Replica,HashMap<Replica,(usize,WSSMsg)>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub reconstructed_secrets:HashMap<Replica,BigInt,nohash_hasher::BuildNoHashHasher<Replica>>,
    // Gather protocol related state context
    pub witness1: HashMap<Replica,Vec<Replica>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub witness2: HashMap<Replica,Vec<Replica>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub send_w1: bool,
    pub send_w2:bool,
    pub accepted_witnesses1: HashSet<Replica,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub accepted_witnesses2: HashSet<Replica,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub recon_secret:usize,
    pub secret_domain: BigInt,
    pub nz_appxcon_rs: HashMap<Replica,(BigInt,bool,BigInt),nohash_hasher::BuildNoHashHasher<Replica>>,
    pub cc_round_state: HashMap<Replica,CoinRoundState,nohash_hasher::BuildNoHashHasher<Replica>>,
}

impl BatchVSSState{
    pub fn new(sec_domain:BigInt)-> BatchVSSState{
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
            secret_domain:sec_domain,
            nz_appxcon_rs: HashMap::default(),
            cc_round_state: HashMap::default(),
        }
    }

    pub fn add_batch_secrets(&mut self, wss_init:BatchWSSMsg)->(){
        let sec_origin = wss_init.origin;
        self.node_secrets.insert(sec_origin, wss_init);
    }

    pub fn add_echo(&mut self, sec_origin: Replica, echo_origin: Replica, ctr:&CTRBCMsg){
        match self.echos.get_mut(&sec_origin)  {
            None => {
                let mut hash_map = HashMap::default();
                hash_map.insert(echo_origin,(ctr.shard.clone(),ctr.mp.clone()));
                self.echos.insert(sec_origin, hash_map);
            },
            Some(x) => {
                x.insert(echo_origin,(ctr.shard.clone(),ctr.mp.clone()));
            },
        }
    }

    pub fn add_ready(&mut self, sec_origin: Replica, ready_origin: Replica, ctr:&CTRBCMsg){
        match self.readys.get_mut(&sec_origin)  {
            None => {
                let mut hash_map = HashMap::default();
                hash_map.insert(ready_origin,(ctr.shard.clone(),ctr.mp.clone()));
                self.readys.insert(sec_origin, hash_map);
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

    pub fn add_secret_share(&mut self, coin_number:usize, secret_id:usize,share_provider:usize, wss_msg: WSSMsg){
        if self.secret_shares.contains_key(&secret_id){
            self.secret_shares.get_mut(&secret_id).unwrap().insert(share_provider, (coin_number,wss_msg.clone()));
        }
        else{
            let mut secret_map = HashMap::default();
            secret_map.insert(share_provider, (coin_number,wss_msg.clone()));
            self.secret_shares.insert(secret_id, secret_map);
        }
    }

    pub fn validate_secret_share(&mut self, wss_msg:WSSMsg, coin_number: usize)-> bool{
        // first validate Merkle proof
        if !self.comm_vectors.contains_key(&wss_msg.origin){
            return false;
        }
        let sharing_merkle_root:Hash = self.comm_vectors.get(&wss_msg.origin).unwrap()[coin_number].clone();
        let nonce = BigInt::from_bytes_be(Sign::Plus, wss_msg.commitment.0.clone().as_slice());
        let secret = BigInt::from_bytes_be(Sign::Plus, wss_msg.secret.clone().as_slice());
        let comm = nonce+secret;
        let commitment = do_hash(comm.to_bytes_be().1.as_slice());
        let merkle_proof = wss_msg.mp.to_proof();
        if commitment != wss_msg.commitment.1.clone() || 
                do_hash_merkle(commitment.as_slice()) != merkle_proof.item().clone() || 
                !merkle_proof.validate::<HashingAlg>() ||
                merkle_proof.root() != sharing_merkle_root
                {
            log::error!("Merkle proof invalid for WSS Init message comm: {:?} wss_com: {:?} sec_num: {} commvec:mr: {:?} share_merk_root: {:?}  inst: {} merk_hash: {:?} merk_proof_item: {:?}",commitment,wss_msg.commitment.1.clone(),coin_number,sharing_merkle_root,merkle_proof.root(),wss_msg.origin,do_hash_merkle(commitment.as_slice()), merkle_proof.item().clone());
            return false;
        }
        true
    }

    // Returns the root of all individual polynomial merkle root vectors and the polynomial vector itself
    pub fn echo_check(&mut self, sec_origin: Replica, num_nodes: usize,num_faults:usize, batch_size:usize)-> Option<(Hash,Vec<Hash>)>{
        let echos = self.echos.get_mut(&sec_origin).unwrap();
        // 2. Check if echos reached the threshold, init already received, and round number is matching
        log::debug!("WSS ECHO check: echos.len {}, contains key: {}"
        ,echos.len(),self.node_secrets.contains_key(&sec_origin));
        
        if echos.len() == num_nodes-num_faults && 
            self.node_secrets.contains_key(&sec_origin){
            // Broadcast readys, otherwise, just wait longer
            // Cachin-Tessaro RBC implies verification needed
            // Send your own shard in the echo phase to every other node. 
            
            let mut echo_map = HashMap::default();

            for (rep,(shard,_mp)) in echos.clone().into_iter(){
                echo_map.insert(rep, shard);
            }
            return self.verify_reconstructed_root(sec_origin, num_nodes, num_faults, batch_size, echo_map);   
        }
        None
    }

    pub fn ready_check(&mut self, sec_origin: Replica, num_nodes:usize,num_faults:usize, batch_size:usize)-> (usize, Option<(Hash,Vec<Hash>)>){
        let readys = self.readys.get_mut(&sec_origin).unwrap();
        // 2. Check if readys reached the threshold, init already received, and round number is matching
        log::debug!("READY check: readys.len {}, contains key: {}"
        ,readys.len(),self.node_secrets.contains_key(&sec_origin));
        let mut ready_map = HashMap::default();
        for (rep,(shard,_mp)) in readys.clone().into_iter(){
            ready_map.insert(rep, shard);
        }
        if readys.len() == num_faults+1 && self.node_secrets.contains_key(&sec_origin){
            // Broadcast readys, otherwise, just wait longer
            // Cachin-Tessaro RBC implies verification needed
            return (num_faults+1,self.verify_reconstructed_root(sec_origin, num_nodes, num_faults, batch_size, ready_map));
        }
        else if readys.len() == num_nodes-num_faults &&
            self.node_secrets.contains_key(&sec_origin){
            // Terminate RBC, RAccept the value
            // Add value to value list, add rbc to rbc list
            return (num_nodes-num_faults,self.verify_reconstructed_root(sec_origin, num_nodes, num_faults, batch_size, ready_map));
        }
        (0,None)
    }

    pub fn verify_reconstruct_rbc(&mut self, sec_origin:Replica, num_nodes:usize, num_faults:usize, batch_size:usize) -> Option<(Hash,Vec<Hash>)>{
        let ready_check = self.readys.get(&sec_origin).unwrap().len() >= (num_nodes-num_faults);
        let vec_fmap = self.recon_msgs.get(&sec_origin).unwrap().clone();
        if vec_fmap.len()==num_nodes-num_faults && ready_check{
            // Reconstruct here
            let res_root = self.verify_reconstructed_root(sec_origin, num_nodes, num_faults, batch_size, vec_fmap);
            match res_root.clone() {
                None=> {
                    log::error!("Error resulted in constructing erasure-coded data");
                    return None;
                }
                Some(vec)=>{
                    log::debug!("Successfully reconstructed message for Batch WSS, checking validity of root for secret {}",sec_origin);
                    self.terminated_secrets.insert(sec_origin);
                    self.comm_vectors.insert(sec_origin, vec.1);
                    // Initiate next phase of the protocol here
                    return res_root;
                }
            }
        }
        None
    }

    pub fn reconstruct_secret(&mut self, wss_msg: WSSMsg, num_nodes: usize, num_faults:usize)-> Option<BigInt>{
        let sec_origin = wss_msg.origin;
        let sec_map = self.secret_shares.get_mut(&sec_origin).unwrap();
        if sec_map.len() == num_faults+1{
            // on having t+1 secret shares, try reconstructing the original secret
            log::debug!("Received t+1 shares for secret instantiated by {}, reconstructing secret",wss_msg.origin);
            let secret_shares:Vec<(Replica,BigInt)> = 
                sec_map.clone().into_iter()
                .map(|(rep,(_sec_num,wss_msg))| 
                    (rep+1,BigInt::from_bytes_be(Sign::Plus,wss_msg.secret.clone().as_slice()))
                ).collect();
            let shamir_ss = ShamirSecretSharing{
                threshold:num_faults+1,
                share_amount:num_nodes,
                prime: self.secret_domain.clone()
            };
            
            // TODO: Recover all shares of the polynomial and verify if the Merkle tree was correctly constructed
            let secret = shamir_ss.recover(&secret_shares);
            self.reconstructed_secrets.insert(sec_origin, secret.clone());
            if self.nz_appxcon_rs.contains_key(&sec_origin){
                let appxcox_var = self.nz_appxcon_rs.get_mut(&sec_origin).unwrap();
                if !appxcox_var.1{
                    let sec_contribution = appxcox_var.0.clone()*secret.clone();
                    appxcox_var.1 = true;
                    appxcox_var.2 = sec_contribution;
                }
            }
            return Some(secret);
        }
        None
    }

    pub fn secret_shares(&mut self, coin_number:usize)-> Vec<(Replica,WSSMsg)>{
        let mut shares_vector = Vec::new();
        for (rep,batch_wss) in self.node_secrets.clone().into_iter(){
            if self.terminated_secrets.contains(&rep){
                let secret = batch_wss.secrets.get(coin_number).unwrap().clone();
                let nonce = batch_wss.commitments.get(coin_number).unwrap().0.clone();
                let merkle_proof = batch_wss.mps.get(coin_number).unwrap().clone();
                //let mod_prime = cx.secret_domain.clone();
                let sec_bigint = BigInt::from_bytes_be(Sign::Plus, secret.as_slice());
                let nonce_bigint = BigInt::from_bytes_be(Sign::Plus, nonce.as_slice());
                let added_secret = sec_bigint+nonce_bigint;
                let addsec_bytes = added_secret.to_bytes_be().1;
                let hash_add = do_hash(addsec_bytes.as_slice());
                let wss_msg = WSSMsg::new(secret, rep, (nonce,hash_add), merkle_proof);
                shares_vector.push((rep,wss_msg));
            }
        }
        shares_vector
    }

    fn verify_reconstructed_root(&mut self, sec_origin: Replica, num_nodes: usize,num_faults:usize,batch_size:usize, shard_map: HashMap<usize,Vec<u8>>)-> Option<(Hash,Vec<Hash>)>{
        let merkle_root = self.node_secrets.get(&sec_origin).unwrap().master_root.clone();
        let res = 
            reconstruct_and_return(&shard_map, num_nodes, num_faults);
        match res {
            Err(error)=> {
                log::error!("Shard reconstruction failed because of the following reason {:?}",error);
                return None;
            },
            Ok(vec_x)=> {
                // Further verify the merkle root generated by these hashes
                let mut vec_xx = vec_x;
                vec_xx.truncate(batch_size*32);
                //log::debug!("Vec_x: {:?} {}",vec_xx.clone(),vec_xx.len());
                let split_vec:Vec<Hash> = 
                    vec_xx.chunks(32).into_iter()
                    .map(|x| {
                        x.try_into().unwrap()
                    })
                    .collect();
                let merkle_tree_master:MerkleTree<Hash,HashingAlg> = MerkleTree::from_iter(split_vec.clone().into_iter());
                if merkle_tree_master.root() == merkle_root{
                    return Some((merkle_root.clone(),split_vec));
                }
                else {
                    log::error!("Reconstructing root hash polynomial failed, with params {:?} {:?} {:?}", split_vec.clone(),merkle_tree_master.root(),merkle_root);
                    return None;
                }
            }
        }
    }

    pub fn coin_check(&mut self, coin_number: usize, num_nodes: usize)->Option<Replica>{
        if self.nz_appxcon_rs.len() == self.reconstructed_secrets.len(){
            let mut sum_vars = BigInt::from(0i32);
            for (_rep,(_appx,_bcons,sec_contrib)) in self.nz_appxcon_rs.clone().into_iter(){
                sum_vars = sum_vars + sec_contrib;
            }
            let rand_fin = sum_vars.clone() % self.secret_domain.clone();
            let mod_number = self.secret_domain.clone()/(num_nodes);
            let leader_elected = rand_fin.clone()/mod_number;
            // Mark this secret as used, use the next secret from this point on
            self.recon_secret = coin_number+1;
            self.secret_shares.clear();
            self.reconstructed_secrets.clear();
            for (_rep,(_appx_con, processed, _num)) in self.nz_appxcon_rs.iter_mut(){
                *processed = false;
            }
            log::debug!("Random leader election terminated random number: sec_origin {} rand_fin{} leader_elected {}, elected leader is node",sum_vars.clone(),rand_fin.clone(),leader_elected.clone());
            return Some(leader_elected.to_u32().unwrap().try_into().unwrap());
        }
        return None;
    }
}