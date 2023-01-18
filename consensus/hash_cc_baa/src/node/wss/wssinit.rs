use std::{collections::{HashSet}, time::SystemTime};

use crypto::hash::{do_hash, Hash, do_hash_merkle};
use merkle_light::merkle::MerkleTree;
use num_bigint::{BigInt, RandBigInt, Sign};
use types::{appxcon::{HashingAlg, MerkleProof}, hash_cc::{WSSMsg, CoinMsg, WrapperMsg}};

use crate::node::{Context};

use super::ShamirSecretSharing;
impl Context{
    pub async fn start_wss(self: &mut Context){
        let now = SystemTime::now();
        let func_name = String::from("start_wss");
        let faults = self.num_faults;
        let low_r = BigInt::from(0);
        let prime = BigInt::parse_bytes(b"685373784908497",10).unwrap(); 
        let mut rng = rand::thread_rng();
        let shamir_ss = ShamirSecretSharing{
            threshold:faults+1,
            share_amount:3*faults+1,
            prime: prime.clone()
        };
        let secret_sampled = rng.gen_bigint_range(&low_r, &prime.clone());
        let shares = shamir_ss.split(secret_sampled);
        log::info!("Shares generated: {:?}",shares);
        // (Replica, Secret, Random Nonce, One-way commitment)
        let share_comm_hash:Vec<(usize,Vec<u8>,Vec<u8>,Hash)> = 
        shares.clone()
        .into_iter()
        .map(|x| {
            let rand = rng.gen_bigint_range(&low_r, &prime.clone());
            let added_secret = rand.clone()+x.1.clone();
            log::info!("Added_secret {:?} share eval {} secret share {}",added_secret.clone(),x.0,x.1.clone());
            let vec_comm = rand.to_bytes_be().1;
            let comm_secret = added_secret.to_bytes_be().1;
            (x.0,x.1.to_bytes_be().1,vec_comm.clone(),do_hash(comm_secret.as_slice()))
        }).collect();
    
        let hashes:Vec<Hash> = share_comm_hash.clone().into_iter().map(|x| x.3).collect();
        let merkle_tree:MerkleTree<Hash, HashingAlg> = MerkleTree::from_iter(hashes.clone().into_iter());
        for (rep,sec,nonce,hash) in share_comm_hash.into_iter(){
            let replica = rep-1;
            let sec_key = self.sec_key_map.get(&replica).unwrap().clone();
            let mrp = MerkleProof::from_proof(merkle_tree.gen_proof(replica));
            let wssmsg = WSSMsg::new(sec, self.myid, (nonce,hash), mrp);
            if replica != self.myid{
                let wss_init = CoinMsg::WSSInit(wssmsg);
                let wrapper_msg = WrapperMsg::new(wss_init, self.myid, &sec_key);
                self.net_send.send(replica,  wrapper_msg).await;
            }
            else {
                self.process_wss_init(wssmsg).await;
            }
        }
        let passed = now.elapsed().unwrap().as_nanos();
        if self.bench.contains_key(&func_name) && *self.bench.get(&func_name).unwrap() < passed{
            self.bench.insert(func_name, passed);
        }
    }
    
    pub async fn process_wss_init(self: &mut Context, wss_init: WSSMsg) {
        let now = SystemTime::now();
        let func_name = String::from("process_wss_init");
        let sec_origin = wss_init.origin;
        // Verify Merkle proof first
        //let mod_prime = self.secret_domain.clone();
        let nonce = BigInt::from_bytes_be(Sign::Plus, wss_init.commitment.0.clone().as_slice());
        let secret = BigInt::from_bytes_be(Sign::Plus, wss_init.secret.clone().as_slice());
        let comm = nonce+secret;
        let commitment = do_hash(comm.to_bytes_be().1.as_slice());
        let merkle_proof = wss_init.mp.to_proof();
        let mut msgs_to_be_sent:Vec<CoinMsg> = Vec::new();
        if commitment != wss_init.commitment.1.clone() || 
                do_hash_merkle(commitment.as_slice()) != merkle_proof.item().clone() || 
                !merkle_proof.validate::<HashingAlg>(){
            log::error!("Merkle proof invalid for WSS Init message comm: {:?} wss_init: {:?}, merkle_proof_item: {:?}",commitment,wss_init.clone(),merkle_proof.item().clone());
            return;
        }
        let wss_state = &mut self.vss_state;
        wss_state.node_secrets.insert(sec_origin, 
            (wss_init.secret.clone(),wss_init.commitment.0.clone(),wss_init.commitment.1.clone(),wss_init.mp.clone()));
        // 3. Send echos to every other node
        msgs_to_be_sent.push(CoinMsg::WSSEcho(merkle_proof.root(), sec_origin, self.myid));
        // 3. Add your own vote to the map
        match wss_state.echos.get_mut(&sec_origin)  {
            None => {
                let mut hash_set = HashSet::default();
                hash_set.insert(self.myid);
                wss_state.echos.insert(sec_origin, hash_set);
            },
            Some(x) => {
                x.insert(self.myid);
            },
        }
        match wss_state.readys.get_mut(&sec_origin){
            None => {
                let mut hashset = HashSet::default();
                hashset.insert(self.myid);
                wss_state.readys.insert(sec_origin, hashset);
            },
            Some(x) => {
                x.insert(self.myid);
            },
        }
        // Inserting send message block here to not borrow self as mutable again
        log::debug!("Sending echos for RBC from origin {}",sec_origin);
        for prot_msg in msgs_to_be_sent.iter(){
            let sec_key_map = self.sec_key_map.clone();
            for (replica,sec_key) in sec_key_map.into_iter() {
                if replica != self.myid{
                    let wrapper_msg = WrapperMsg::new(prot_msg.clone(), self.myid, &sec_key.as_slice());
                    //let sent_msg = Arc::new(wrapper_msg);
                    self.net_send.send(replica, wrapper_msg).await;
                }
                else {
                    self.process_wssecho( merkle_proof.root(),sec_origin,self.myid).await;
                }
            }
        }
        let passed = now.elapsed().unwrap().as_nanos();
        if self.bench.contains_key(&func_name) && *self.bench.get(&func_name).unwrap() < passed{
            self.bench.insert(func_name, passed);
        }
    }
}