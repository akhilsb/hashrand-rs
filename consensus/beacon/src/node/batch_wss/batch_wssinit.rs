use std::{ time::SystemTime};

use async_recursion::async_recursion;
use crypto::hash::{do_hash, Hash};
use merkle_light::merkle::MerkleTree;
use num_bigint::{BigInt, RandBigInt};
use types::{appxcon::{HashingAlg, MerkleProof, get_shards}, beacon::{BatchWSSMsg, CoinMsg, CTRBCMsg, WrapperMsg, Val}, Replica, beacon::{Round, BeaconMsg}};

use crate::node::{Context, ShamirSecretSharing};

impl Context{
    #[async_recursion]
    pub async fn start_new_round(&mut self, round:Round,vec_round_vals:Vec<(Round,Vec<(Replica,Val)>)>){
        let now = SystemTime::now();
        let mut new_round = round+1;
        if round == 20000{
            new_round = 0;
        }
        else if self.curr_round>round || self.curr_round>self.max_rounds{
            return;
        }
        
        log::info!("Protocol started");
        let mut beacon_msgs = Vec::new();
        let mut rbc_vec = Vec::new();
        if new_round%self.frequency == 0{
            // Start BatchWSS. 
            let faults = self.num_faults;
            // Secret number can be increased to any number possible, but there exists a performance tradeoff with the size of RBC increasing\
            // TODO: Does it affect security in any manner?
            let secret_num = self.batch_size;
            let low_r = BigInt::from(0);
            let prime = self.secret_domain.clone();
            //let mut rng = rand::thread_rng();
            
            let mut secrets_samp:Vec<BigInt> =Vec::new();
            let mut secret_shares:Vec<Vec<(Replica,BigInt)>> = Vec::new();
            for _i in 0..secret_num{
                let secret = rand::thread_rng().gen_bigint_range(&low_r, &prime.clone());
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
                    let rand = rand::thread_rng().gen_bigint_range(&low_r, &prime.clone());
                    let added_secret = rand.clone()+x.1.clone();
                    let vec_comm = rand.to_signed_bytes_be();
                    let comm_secret = added_secret.to_signed_bytes_be();
                    let hash:Hash = do_hash(comm_secret.as_slice());
                    hashes.push(hash.clone());
                    (x.0,x.1.to_signed_bytes_be(),vec_comm.clone(),hash)    
                }).collect();
                hashes_ms.push(hashes);
                acc_secs
            }).collect();
            let merkle_tree_vec:Vec<MerkleTree<Hash, HashingAlg>> = hashes_ms.into_iter().map(|x| MerkleTree::from_iter(x.into_iter())).collect();
            let mut vec_msgs_to_be_sent:Vec<(Replica,BatchWSSMsg)> = Vec::new();
            
            for i in 0..self.num_nodes{
                vec_msgs_to_be_sent.push((i+1,
                    BatchWSSMsg::new(Vec::new(), self.myid, Vec::new(), Vec::new())));
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
            for (rep,batchwss) in vec_msgs_to_be_sent.into_iter(){
                let beacon_msg = BeaconMsg::new(self.myid, new_round, batchwss,roots_vec.clone(), vec_round_vals.clone());
                if rep == 1{
                    rbc_vec = beacon_msg.clone().serialize_ctrbc();
                }
                else{
                    assert!(do_hash(rbc_vec.as_slice()).iter().zip(do_hash(beacon_msg.serialize_ctrbc().as_slice()).iter()).all(|(a,b)| a == b), "Hashes are not equal");
                }
                beacon_msgs.push((rep,beacon_msg));
            }
            //let master_root_mt:MerkleTree<Hash, HashingAlg> = MerkleTree::from_iter(mr_leaves.into_iter());
            //let master_root = master_root_mt.root();
            // reliably broadcast the vector of merkle roots of each secret sharing instance
        }
        else{
            for i in 0..self.num_nodes{
                let beacon_msg = BeaconMsg::new_with_appx(self.myid, new_round, vec_round_vals.clone());
                if i==0{
                    rbc_vec = beacon_msg.clone().serialize_ctrbc();
                }
                else{
                    assert!(do_hash(rbc_vec.as_slice()).iter().zip(do_hash(beacon_msg.serialize_ctrbc().as_slice()).iter()).all(|(a,b)| a == b), "Hashes are not equal");
                }
                beacon_msgs.push((i+1,beacon_msg));
            }
        }
        let shards = get_shards(rbc_vec, self.num_faults);
        // Construct Merkle tree
        let hashes_rbc:Vec<Hash> = shards.clone().into_iter().map(|x| do_hash(x.as_slice())).collect();
        let merkle_tree:MerkleTree<[u8; 32],HashingAlg> = MerkleTree::from_iter(hashes_rbc.into_iter());
        for (rep,beacon_msg) in beacon_msgs.into_iter(){
            let replica = rep.clone()-1;
            let sec_key = self.sec_key_map.get(&replica).unwrap().clone();
            let ctrbc_msg = CTRBCMsg::new(
                shards[replica].clone(), 
                MerkleProof::from_proof(merkle_tree.gen_proof(replica)), 
                new_round,
                self.myid
            );
            log::info!("Mp verification {}",ctrbc_msg.verify_mr_proof());
            if replica != self.myid{
                //batch_wss.master_root = master_root.clone();
                let beacon_init = CoinMsg::CTRBCInit(beacon_msg,ctrbc_msg);
                let wrapper_msg = WrapperMsg::new(beacon_init, self.myid, &sec_key,new_round);
                self.send(replica, wrapper_msg).await;
            }
            else {
                //batch_wss.master_root = master_root.clone();
                self.process_rbcinit(beacon_msg,ctrbc_msg).await;
            }
        }
        if new_round > 0{
            self.increment_round(round).await;
        }
        self.add_benchmark(String::from("start_batchwss"), now.elapsed().unwrap().as_nanos());
    }
}