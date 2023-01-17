use std::{ collections::HashMap, time::{Duration, SystemTime, UNIX_EPOCH}};

use crypto::hash::{Hash,do_hash};
use merkle_light::merkle::MerkleTree;
use num_bigint::BigInt;
use types::{appxcon::{get_shards, HashingAlg, MerkleProof, verify_merkle_proof}, hash_cc::{CTRBCMsg, CoinMsg, WrapperMsg}, Replica};

use crate::node::{Context, RoundState};

impl Context{
    pub async fn process_rbc_init(self: &mut Context, ctr: CTRBCMsg){
        let shard = ctr.shard.clone();
        let mp = ctr.mp.clone();
        let sender = ctr.origin.clone();
        let round_state_map = &mut self.round_state;
        if self.curr_round > ctr.round{
            return;
        }
        // 1. Check if the protocol reached the round for this node
        log::info!("Received RBC Init from node {} for round {}",sender,ctr.round);
        if !verify_merkle_proof(&mp, &shard){
            log::error!("Failed to evaluate merkle proof for RBC Init received from node {}",sender);
            return;
        }
        let round = ctr.round;
        if round_state_map.contains_key(&round){
            let rnd_state = round_state_map.get_mut(&round).unwrap();
            rnd_state.node_msgs.insert(sender, (shard.clone(),mp.clone(),mp.root().clone()));
            // 2. Send echos to every other node
            // 3. Add your own vote to the map
            match rnd_state.echos.get_mut(&sender)  {
                None => {
                    let mut hash_map = HashMap::default();
                    hash_map.insert(self.myid, (shard.clone(),mp.clone()));
                    rnd_state.echos.insert(sender, hash_map);
                },
                Some(x) => {
                    x.insert(self.myid,(shard.clone(),mp.clone()));
                },
            }
            match rnd_state.readys.get_mut(&sender)  {
                None => {
                    let mut hash_map = HashMap::default();
                    hash_map.insert(self.myid,(shard.clone(),mp.clone()));
                    rnd_state.readys.insert(sender, hash_map);
                },
                Some(x) => {
                    x.insert(self.myid,(shard.clone(),mp.clone()));
                },
            }
            self.broadcast(CoinMsg::AppxConCTECHO(ctr.clone() ,self.myid)).await;
            self.process_echo(ctr, self.myid).await;
        }
        // 1. If the protocol did not reach this round yet, create a new roundstate object
        else{
            let mut rnd_state = RoundState::new();
            rnd_state.node_msgs.insert(sender, (shard.clone(),mp.clone(),mp.root()));
            round_state_map.insert(round, rnd_state);
            // 7. Send messages
            self.broadcast(CoinMsg::AppxConCTECHO(ctr.clone() ,self.myid)).await;
            self.process_echo(ctr, self.myid).await;
        }
    }
    
    pub async fn start_baa(self: &mut Context, round_vecs: Vec<(Replica,BigInt)>){
        // Reliably broadcast the entire vector
        let appxcon_map = &mut self.nz_appxcon_rs;
        if self.curr_round == self.rounds_aa{
            log::error!("Sharing End time: {:?}", SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis());
            log::info!("Approximate Agreement Protocol terminated with values {:?}",round_vecs.clone());
            // Reconstruct values
            let mapped_rvecs:Vec<(Replica,BigInt)> = 
                round_vecs.clone().into_iter()
                .filter(|(_rep,num)| *num > BigInt::from(0i32))
                .collect();
            for (rep,val) in mapped_rvecs.into_iter(){
                appxcon_map.insert(rep, (val,false,BigInt::from(0i32)));
            }
            for i in 0..10{
                self.invoke_coin.insert(i, Duration::from_millis((1000*i).try_into().unwrap()));
            }
            return;
        }
        let transmit_vector:Vec<String> = round_vecs.into_iter().map(|x| x.1.to_str_radix(16)).collect();
        let str_rbc = transmit_vector.join(",");
        log::info!("Transmitted message: {:?} {:?}",str_rbc,str_rbc.as_bytes());
        let f_tran = Vec::from(str_rbc.as_bytes());
        let shards = get_shards(f_tran, self.num_faults);
        let own_shard = shards[self.myid].clone();
        // Construct Merkle tree
        let hashes:Vec<Hash> = shards.clone().into_iter().map(|x| do_hash(x.as_slice())).collect();
        log::info!("Vector of hashes during RBC Init {:?}",hashes);
        let merkle_tree:MerkleTree<[u8; 32],HashingAlg> = MerkleTree::from_iter(hashes.into_iter());
        for (replica,sec_key) in self.sec_key_map.clone().into_iter() {
            if replica != self.myid{
                let mrp = MerkleProof::from_proof(merkle_tree.gen_proof(replica));
                let ctrbc = CTRBCMsg{
                    shard:shards[replica].clone(),
                    mp:mrp,
                    origin:self.myid,
                    round:self.curr_round,
                };
                let prot_msg = CoinMsg::AppxConCTRBCInit(ctrbc);
                let wrapper_msg = WrapperMsg::new(prot_msg, self.myid, &sec_key);
                self.send(replica,wrapper_msg).await;
            }
        }
        let mrp = MerkleProof::from_proof(merkle_tree.gen_proof(self.myid));
        let ctrbc = CTRBCMsg{
            shard:own_shard,
            mp:mrp,
            origin:self.myid,
            round:self.curr_round
        };
        self.process_rbc_init(ctrbc).await;
    }
}