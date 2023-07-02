use std::{collections::{HashMap, HashSet}};

use crypto::hash::{Hash, do_hash, do_hash_merkle};
use merkle_light::merkle::MerkleTree;
use num_bigint::{BigInt};
use types::{Replica, appxcon::{MerkleProof, reconstruct_and_return, HashingAlg, get_shards}, beacon::{WSSMsg, CTRBCMsg, Val}, beacon::{BeaconMsg, BatchWSSMsg, Round}};

use crate::node::{ShamirSecretSharing, appxcon::RoundState};

// Separate out witnesses into their own thing(Not a big deal, one or two roundtrips more). 
#[derive(Debug,Clone)]
pub struct CTRBCState{
    /// The structure of the tuple: (Secret, Random nonce, Commitment, Merkle Proof for commitment)
    pub msgs: HashMap<Replica,(BeaconMsg,CTRBCMsg),nohash_hasher::BuildNoHashHasher<Replica>>,
    pub node_secrets: HashMap<Replica,BatchWSSMsg,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub echos: HashMap<Replica,HashMap<Replica,(Vec<u8>,MerkleProof)>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub readys: HashMap<Replica,HashMap<Replica,(Vec<u8>,MerkleProof)>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub ready_sent:HashSet<Replica>,
    pub recon_msgs:HashMap<Replica,HashMap<Replica,Vec<u8>>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub comm_vectors:HashMap<Replica,Vec<Hash>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub terminated_secrets: HashSet<Replica,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub secret_shares: HashMap<usize,HashMap<Replica,HashMap<Replica,WSSMsg>>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub reconstructed_secrets:HashMap<Replica,HashMap<Replica,BigInt,nohash_hasher::BuildNoHashHasher<Replica>>,nohash_hasher::BuildNoHashHasher<Replica>>,
    // Gather protocol related state context
    pub witness1: HashMap<Replica,Vec<Replica>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub witness2: HashMap<Replica,Vec<Replica>,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub appxcon_allround_vals: HashMap<Replica,HashMap<Round,Vec<(Replica,Val)>>>,
    pub appxcon_vals: HashMap<Replica,Vec<Val>>,
    // Committee
    pub committee:Vec<Replica>,
    pub appxcon_round: Round,
    pub appxcon_st: Val,
    pub send_w1: bool,
    pub send_w2:bool,
    pub started_baa:bool,
    pub committee_elected:bool,
    pub accepted_witnesses1: HashSet<Replica,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub accepted_witnesses2: HashSet<Replica,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub secret_domain: BigInt,
    pub appx_con_term_vals: HashMap<Replica,BigInt,nohash_hasher::BuildNoHashHasher<Replica>>,
    pub contribution_map: HashMap<Replica,HashMap<Replica,BigInt,nohash_hasher::BuildNoHashHasher<Replica>>>,
    pub recon_secrets:HashSet<Replica>,
    pub alloted_secrets:HashMap<usize,u32>,
    // Code for binary approximate agreement
    pub round_state: HashMap<Round,RoundState>,
    pub cleared:bool,
}

impl CTRBCState{
    pub fn new(sec_domain:BigInt,num_nodes:usize)-> CTRBCState{
        let mut master_committee = Vec::new();
        for i in 0..num_nodes{
            master_committee.push(i);
        }
        CTRBCState{
            msgs: HashMap::default(),
            node_secrets: HashMap::default(),
            echos: HashMap::default(),
            readys:HashMap::default(),
            ready_sent:HashSet::default(),
            recon_msgs:HashMap::default(),
            comm_vectors:HashMap::default(),
            secret_shares:HashMap::default(),
            reconstructed_secrets:HashMap::default(),
            witness1:HashMap::default(),
            witness2: HashMap::default(),
            appxcon_allround_vals: HashMap::default(),
            committee:master_committee,
            appxcon_vals: HashMap::default(),
            appxcon_round: 0,
            appxcon_st: Vec::new(),
            send_w1:false,
            send_w2:false,
            started_baa:false,
            committee_elected:false,
            alloted_secrets:HashMap::default(),
            terminated_secrets:HashSet::default(),
            accepted_witnesses1:HashSet::default(),
            accepted_witnesses2:HashSet::default(),
            secret_domain:sec_domain,

            appx_con_term_vals:HashMap::default(),
            contribution_map: HashMap::default(),
            recon_secrets: HashSet::default(),
            round_state:HashMap::default(),
            cleared:false,
        }
    }

    pub fn add_message(&mut self, beacon_msg:BeaconMsg,ctr:CTRBCMsg)->(){
        let sec_origin = beacon_msg.origin;
        // Message Validation happens in the method calling this method. 
        self.msgs.insert(sec_origin, (beacon_msg,ctr));
    }

    pub fn set_committee(&mut self,committee:Vec<Replica>){
        self.committee = committee.clone();
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
    
    pub fn transform(&mut self, terminated_index:Replica)->BeaconMsg{
        let beacon_msg = self.msgs.get(&terminated_index).unwrap().0.clone();
        if beacon_msg.appx_con.is_some(){
            let appxcon_vals = beacon_msg.appx_con.clone().unwrap();
            let mut hashmap_vals = HashMap::default();
            for (round,vals) in appxcon_vals.into_iter(){
                hashmap_vals.insert(round, vals);
            }
            self.appxcon_allround_vals.insert(beacon_msg.origin.clone(), hashmap_vals);
        }
        if beacon_msg.wss.is_some(){
            let batch_wssmsg = beacon_msg.wss.unwrap().clone();
            self.node_secrets.insert(beacon_msg.origin.clone(), batch_wssmsg.clone());
            self.comm_vectors.insert(terminated_index, beacon_msg.root_vec.unwrap());
        }
        self.terminated_secrets.insert(terminated_index);
        // clean up for memory efficiency
        let beacon_msg = self.msgs.get(&terminated_index).unwrap().0.clone();
        self.msgs.remove(&terminated_index);
        self.echos.remove(&terminated_index);
        self.readys.remove(&terminated_index);
        self.recon_msgs.remove(&terminated_index);
        return beacon_msg;
    }

    pub fn add_secret_share(&mut self, coin_number:usize, secret_id:usize,share_provider:usize, wss_msg: WSSMsg){
        if self.secret_shares.contains_key(&coin_number){
            let coin_shares = self.secret_shares.get_mut(&coin_number).unwrap();
            if coin_shares.contains_key(&secret_id){
                coin_shares.get_mut(&secret_id).unwrap().insert(share_provider, wss_msg.clone());
            }
            else{
                let mut share_map = HashMap::default();
                share_map.insert(share_provider, wss_msg.clone());
                coin_shares.insert(secret_id, share_map);
            }
            //self.secret_shares.get_mut(&coin_number).unwrap().insert(share_provider, (coin_number,wss_msg.clone()));
        }
        else{
            let mut coin_shares = HashMap::default();
            let mut share_map= HashMap::default();
            share_map.insert(share_provider, wss_msg.clone());
            coin_shares.insert(secret_id, share_map);
            self.secret_shares.insert(coin_number, coin_shares);
        }
    }

    pub fn validate_secret_share(&mut self, wss_msg:WSSMsg, coin_number: usize)-> bool{
        // first validate Merkle proof
        log::info!("Validating secret, comm_vector: {:?} terminated RBCs: {:?}",self.comm_vectors.keys(),self.terminated_secrets);
        if !(self.comm_vectors.contains_key(&wss_msg.origin)){
            return false;
        }
        let sharing_merkle_root:Hash = self.comm_vectors.get(&wss_msg.origin).unwrap()[coin_number].clone();
        let nonce = BigInt::from_signed_bytes_be( wss_msg.commitment.0.clone().as_slice());
        let secret = BigInt::from_signed_bytes_be(wss_msg.secret.clone().as_slice());
        let comm = nonce+secret;
        let commitment = do_hash(comm.to_signed_bytes_be().as_slice());
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
        ,echos.len(),self.msgs.contains_key(&sec_origin));
        
        if echos.len() == num_nodes-num_faults && 
            self.msgs.contains_key(&sec_origin) && !self.ready_sent.contains(&sec_origin){
            // Broadcast readys, otherwise, just wait longer
            // Cachin-Tessaro RBC implies verification needed
            // Send your own shard in the echo phase to every other node. 
            let mut echo_map = HashMap::default();
            self.ready_sent.insert(sec_origin);
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
        ,readys.len(),self.msgs.contains_key(&sec_origin));
        let mut ready_map = HashMap::default();
        for (rep,(shard,_mp)) in readys.clone().into_iter(){
            ready_map.insert(rep, shard);
        }
        if readys.len() == num_faults+1 && self.msgs.contains_key(&sec_origin) && !self.ready_sent.contains(&sec_origin){
            // Broadcast readys, otherwise, just wait longer
            // Cachin-Tessaro RBC implies verification needed
            self.ready_sent.insert(sec_origin);
            return (num_faults+1,self.verify_reconstructed_root(sec_origin, num_nodes, num_faults, batch_size, ready_map));
        }
        else if readys.len() == num_nodes-num_faults &&
            self.msgs.contains_key(&sec_origin){
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
                Some(_vec)=>{
                    log::info!("Successfully reconstructed message for Batch WSS, checking validity of root for secret {}",sec_origin);
                    self.terminated_secrets.insert(sec_origin);
                    // Initiate next phase of the protocol here
                    return res_root;
                }
            }
        }
        None
    }

    pub async fn reconstruct_secret(&mut self,coin_number:usize, wss_msg: WSSMsg, _num_nodes: usize, num_faults:usize)-> Option<BigInt>{
        let sec_origin = wss_msg.origin;
        if coin_number == 0{
            log::info!("Coin number: {}, secret shares: {:?}",0,self.secret_shares.get(&0).unwrap());
        }
        let sec_map = self.secret_shares.get_mut(&coin_number).unwrap().get_mut(&wss_msg.origin).unwrap();
        if coin_number == 0{
            log::info!("Sec map: {:?}",sec_map.clone());
        }
        let already_constructed = self.reconstructed_secrets.contains_key(&coin_number) && self.reconstructed_secrets.get(&coin_number).unwrap().contains_key(&sec_origin);
        if sec_map.len() >= num_faults+1 && !already_constructed{
            // on having t+1 secret shares, try reconstructing the original secret
            log::info!("Received t+1 shares for secret instantiated by {}, reconstructing secret for coin_num {}",wss_msg.origin,coin_number);
            let mut secret_shares:Vec<(Replica,BigInt)> = 
                sec_map.clone().into_iter()
                .map(|(rep,wss_msg)| 
                    (rep+1,BigInt::from_signed_bytes_be(wss_msg.secret.clone().as_slice()))
                ).collect();
            secret_shares.truncate(num_faults+1);
            let shamir_ss = ShamirSecretSharing{
                threshold:num_faults+1,
                share_amount:3*num_faults+1,
                prime: self.secret_domain.clone()
            };
            
            // TODO: Recover all shares of the polynomial and verify if the Merkle tree was correctly constructed
            let secret = shamir_ss.recover(&secret_shares);
            if !self.reconstructed_secrets.contains_key(&coin_number){
                let secret_share_map:HashMap<Replica,BigInt,nohash_hasher::BuildNoHashHasher<Replica>> = HashMap::default();
                self.reconstructed_secrets.insert(coin_number, secret_share_map);
            }
            let secret_share_map = self.reconstructed_secrets.get_mut(&coin_number).unwrap();
            secret_share_map.insert(sec_origin, secret.clone());
            self.sync_secret_maps().await;
            return Some(secret);
        }
        None
    }

    pub async fn sync_secret_maps(&mut self){
        //self.reconstructed_secrets.insert(sec_origin, secret.clone());
        for (coin_num,recon_sec) in self.reconstructed_secrets.clone().into_iter(){
            for (rep,sec) in recon_sec.into_iter(){
                if self.appx_con_term_vals.contains_key(&rep){
                    let appxcox_var = self.appx_con_term_vals.get_mut(&rep).unwrap();
                    if !self.contribution_map.contains_key(&coin_num){
                        let contribution_map_coin:HashMap<Replica, BigInt, nohash_hasher::BuildNoHashHasher<Replica>> = HashMap::default();
                        self.contribution_map.insert(coin_num, contribution_map_coin);
                    }
                    let sec_contrib_map = self.contribution_map.get_mut(&coin_num).unwrap();
                    sec_contrib_map.insert(rep, appxcox_var.clone()*sec.clone());
                    // if !appxcox_var.1{
                    //     let sec_contribution = appxcox_var.0.clone()*secret.clone();
                    //     appxcox_var.1 = true;
                    //     appxcox_var.2 = sec_contribution;
                    // }
                }
            }
        }
    }

    pub fn secret_shares(&mut self, coin_number:usize)-> Vec<(Replica,WSSMsg)>{
        let mut shares_vector = Vec::new();
        for (rep,batch_wss) in self.node_secrets.clone().into_iter(){
            if self.terminated_secrets.contains(&rep){
                let secret = batch_wss.secrets.get(coin_number).unwrap().clone();
                let nonce = batch_wss.commitments.get(coin_number).unwrap().0.clone();
                let merkle_proof = batch_wss.mps.get(coin_number).unwrap().clone();
                //let mod_prime = cx.secret_domain.clone();
                let sec_bigint = BigInt::from_signed_bytes_be(secret.as_slice());
                let nonce_bigint = BigInt::from_signed_bytes_be(nonce.as_slice());
                let added_secret = sec_bigint+nonce_bigint;
                let addsec_bytes = added_secret.to_signed_bytes_be();
                let hash_add = do_hash(addsec_bytes.as_slice());
                let wss_msg = WSSMsg::new(secret, rep, (nonce,hash_add), merkle_proof);
                shares_vector.push((rep,wss_msg));
            }
        }
        shares_vector
    }

    fn verify_reconstructed_root(&mut self, sec_origin: Replica, num_nodes: usize,num_faults:usize,_batch_size:usize, shard_map: HashMap<usize,Vec<u8>>)-> Option<(Hash,Vec<Hash>)>{
        let merkle_root = self.msgs.get(&sec_origin).unwrap().1.mp.root().clone();
        let res = 
            reconstruct_and_return(&shard_map, num_nodes, num_faults);
        match res {
            Err(error)=> {
                log::error!("Shard reconstruction failed because of the following reason {:?}",error);
                return None;
            },
            Ok(vec_x)=> {
                // Further verify the merkle root generated by these hashes
                // let mut vec_xx = vec_x;
                // vec_xx.truncate(batch_size*32);
                // //log::info!("Vec_x: {:?} {}",vec_xx.clone(),vec_xx.len());
                // let split_vec:Vec<Hash> = 
                //     vec_xx.chunks(32).into_iter()
                //     .map(|x| {
                //         x.try_into().unwrap()
                //     })
                //     .collect();
                // let merkle_tree_master:MerkleTree<Hash,HashingAlg> = MerkleTree::from_iter(split_vec.clone().into_iter());
                let shards = get_shards(BeaconMsg::deserialize(&vec_x.as_slice()).serialize_ctrbc(),num_faults);
                let hashes_rbc:Vec<Hash> = shards.clone().into_iter().map(|x| do_hash(x.as_slice())).collect();
                let merkle_tree:MerkleTree<[u8; 32],HashingAlg> = MerkleTree::from_iter(hashes_rbc.clone().into_iter());
                if merkle_tree.root() == merkle_root{
                    return Some((merkle_root.clone(),hashes_rbc));
                }
                else {
                    log::error!("Reconstructing root hash polynomial failed, with params {:?} {:?} {:?}", hashes_rbc.clone(),merkle_tree.root(),merkle_root);
                    return None;
                }
            }
        }
    }

    pub async fn coin_check(&mut self, round: Round,coin_number: usize, num_nodes: usize)->Option<Vec<u8>>{
        log::info!("Coin check for round {} coin {}, keys appxcon: {:?}, contrib_map: {:?}",round,coin_number,self.appx_con_term_vals,self.contribution_map);
        if self.contribution_map.contains_key(&coin_number) && self.appx_con_term_vals.len() == self.contribution_map.get(&coin_number).unwrap().len(){
            let mut sum_vars = BigInt::from(0i32);
            log::info!("Reconstruction for round {} and coin {}",round,coin_number);
            for (_rep,sec_contrib) in self.contribution_map.get(&coin_number).unwrap().clone().into_iter(){
                sum_vars = sum_vars + sec_contrib.clone();
                log::info!("Node's secret contribution: {}, node {}",sec_contrib.to_string(),_rep);
            }
            let rand_fin = sum_vars.clone() % self.secret_domain.clone();
            let _mod_number = self.secret_domain.clone()/(num_nodes);
            let _leader_elected = rand_fin.clone()/_mod_number;
            // Mark this secret as used, use the next secret from this point on
            self.recon_secrets.insert(coin_number);
            self.secret_shares.remove(&coin_number);
            self.reconstructed_secrets.remove(&coin_number);
            self.contribution_map.remove(&coin_number);
            // for (_rep,(_appx_con, processed, _num)) in self.contribution_map.iter_mut(){
            //     *processed = false;
            // }
            //log::error!("Random leader election terminated random number: sec_origin {} rand_fin{} leader_elected {}, elected leader is node",sum_vars.clone(),rand_fin.clone(),leader_elected.clone());
            return Some(BigInt::to_signed_bytes_be(&rand_fin));
        }
        return None;
    }

    pub(crate) fn _clear(&mut self) {
        self.msgs.clear();
        self.echos.clear();
        self.readys.clear();
        self.accepted_witnesses1.clear();
        self.accepted_witnesses2.clear();
        self.appx_con_term_vals.clear();
        self.committee.clear();
        self.committee_elected = true;
        self.secret_shares.clear();
        self.appxcon_vals.clear();
        self.appxcon_allround_vals.clear();
        self.recon_msgs.clear();
        self.comm_vectors.clear();
        self.contribution_map.clear();
        self.round_state.clear();
        self.witness1.clear();
        self.witness2.clear();
        self.terminated_secrets.clear();
        self.cleared = true;
    }
}