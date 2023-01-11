use std::{time::SystemTime};

use crypto::hash::{do_hash, Hash};
use merkle_light::merkle::MerkleTree;
use num_bigint::{BigInt, RandBigInt};
use types::{appxcon::{HashingAlg, MerkleProof, get_shards}, hash_cc::{CoinMsg, CTRBCMsg, SMRMsg}, hash_cc::BatchWSSMsg, Replica};

use crate::node::{Context, ShamirSecretSharing};

impl Context{
    pub async fn start_batchwss(self: &mut Context)-> Vec<CoinMsg>{
        let now = SystemTime::now();
        let mut ret_vec = Vec::new();
        let faults = self.num_faults;
        // Secret number can be increased to any number possible, but there exists a performance tradeoff with the size of RBC increasing
        // TODO: Does it affect security in any manner?
        let secret_num = self.batch_size;
        let low_r = BigInt::from(0);
        let prime = BigInt::parse_bytes(b"685373784908497",10).unwrap(); 
        let mut rng = rand::thread_rng();
        
        let mut secrets_samp:Vec<BigInt> =Vec::new();
        let mut secret_shares:Vec<Vec<(Replica,BigInt)>> = Vec::new();
        for _i in 0..secret_num{
            let secret = rng.gen_bigint_range(&low_r, &prime.clone());
            secrets_samp.push(secret.clone());
            let shamir_ss = ShamirSecretSharing{
                threshold:faults+1,
                share_amount:3*faults+1,
                prime: prime.clone()
            };
            secret_shares.push(shamir_ss.split(secret));
        }
        let mut hashes_ms:Vec<Vec<Hash>> = Vec::new();
        // (Replica, Secret, Random Nonce, One-way commitment)
        let share_comm_hash:Vec<Vec<(usize,Vec<u8>,Vec<u8>,Hash)>> = secret_shares.clone().into_iter().map(|y| {
            let mut hashes:Vec<Hash> = Vec::new();
            let acc_secs:Vec<(usize, Vec<u8>, Vec<u8>, Hash)> = y.into_iter().map(|x| {
                let rand = rng.gen_bigint_range(&low_r, &prime.clone());
                let added_secret = rand.clone()+x.1.clone();
                let vec_comm = rand.to_bytes_be().1;
                let comm_secret = added_secret.to_bytes_be().1;
                let hash:Hash = do_hash(comm_secret.as_slice());
                hashes.push(hash.clone());
                (x.0,x.1.to_bytes_be().1,vec_comm.clone(),hash)    
            }).collect();
            hashes_ms.push(hashes);
            acc_secs
        }).collect();
        let merkle_tree_vec:Vec<MerkleTree<Hash, HashingAlg>> = hashes_ms.into_iter().map(|x| MerkleTree::from_iter(x.into_iter())).collect();
        let mut vec_msgs_to_be_sent:Vec<(Replica,BatchWSSMsg)> = Vec::new();
        
        for i in 0..self.num_nodes{
            vec_msgs_to_be_sent.push((i+1,
                BatchWSSMsg::new(Vec::new(), self.myid, Vec::new(), Vec::new(),[0;32])));
        }
        let mut roots_vec:Vec<Hash> = Vec::new();
        let mut master_vec:Vec<u8> = Vec::new();
        for (vec,mt) in share_comm_hash.into_iter().zip(merkle_tree_vec.into_iter()).into_iter(){
            let mut i = 0;
            for y in vec.into_iter(){
                vec_msgs_to_be_sent[i].1.secrets.push(y.1);
                vec_msgs_to_be_sent[i].1.commitments.push((y.2,y.3));
                vec_msgs_to_be_sent[i].1.mps.push(MerkleProof::from_proof(mt.gen_proof(i)));
                i = i+1;
            }
            roots_vec.push(mt.root());
            master_vec.append(&mut Vec::from(mt.root()));
        }
        log::info!("Secret sharing for node {}, root_poly {:?}, str_construct {:?}",self.myid,roots_vec.clone(),master_vec.clone());
        let master_root_mt:MerkleTree<Hash, HashingAlg> = MerkleTree::from_iter(roots_vec.into_iter());
        let master_root = master_root_mt.root();
        // reliably broadcast the vector of merkle roots of each secret sharing instance
        let shards = get_shards(master_vec, self.num_faults);
        // Construct Merkle tree
        let hashes_rbc:Vec<Hash> = shards.clone().into_iter().map(|x| do_hash(x.as_slice())).collect();
        log::info!("Vector of hashes during RBC Init {:?}",hashes_rbc);
        let merkle_tree:MerkleTree<[u8; 32],HashingAlg> = MerkleTree::from_iter(hashes_rbc.into_iter());
        for (rep,batch_wss) in vec_msgs_to_be_sent.iter_mut(){
            let replica = rep.clone()-1;
            let ctrbc_msg = CTRBCMsg::new(
                shards[replica].clone(), 
                MerkleProof::from_proof(merkle_tree.gen_proof(replica)), 
                0,
                self.myid
            );
            batch_wss.master_root = master_root.clone();
            let wss_init = CoinMsg::BatchWSSInit(batch_wss.clone(),ctrbc_msg);
            ret_vec.push(wss_init);
            // Call process_init function from the place where we call the original RBC function
        }
        self.add_benchmark(String::from("start_batchwss"), now.elapsed().unwrap().as_nanos());
        ret_vec
    }
    
    pub async fn process_batchwss_init(self: &mut Context, wss_init: BatchWSSMsg, ctr: CTRBCMsg, smr_msg:&mut SMRMsg) {
        let now = SystemTime::now();
        let sec_origin = wss_init.origin;
        // 1. Verify Merkle proof for all secrets first
        if !wss_init.verify_proofs() || !ctr.verify_mr_proof(){
            return;
        }
        // 1. Check if the protocol reached the round for this node
        log::info!("Received RBC Init from node {}",ctr.origin);
        let wss_state = &mut self.cur_batchvss_state;
        let master_merkle_root = wss_init.master_root.clone();
        wss_state.add_batch_secrets(wss_init);
        // 3. Add your own echo and ready to the channel
        wss_state.add_echo(sec_origin, self.myid, &ctr);
        wss_state.add_ready(sec_origin, self.myid, &ctr);
        // 4. Broadcast echos and benchmark results
        // Piggyback echos on top of other smr messages
        smr_msg.coin_msg = CoinMsg::BatchWSSEcho(ctr.clone(), master_merkle_root,self.myid);
        self.broadcast(smr_msg).await;
        self.add_benchmark(String::from("process_batchwss_init"), now.elapsed().unwrap().as_nanos());
    }
}