use std::{sync::Arc, collections::HashMap};

use crypto::hash::{Hash,do_hash};
use merkle_light::merkle::MerkleTree;
use num_bigint::BigInt;
use types::{appxcon::{get_shards, HashingAlg, MerkleProof, verify_merkle_proof}, hash_cc::{CTRBCMsg, ProtMsg, WrapperMsg}, Replica};

use crate::node::{Context, RoundState, process_echo, send_reconstruct};

pub async fn process_rbc_init(cx: &mut Context, ctr: CTRBCMsg){
    let shard = ctr.shard.clone();
    let mp = ctr.mp.clone();
    let sender = ctr.origin.clone();
    let round_state_map = &mut cx.round_state;
    if cx.curr_round > ctr.round{
        return;
    }
    // 1. Check if the protocol reached the round for this node
    let mut msgs_to_be_sent:Vec<ProtMsg> = Vec::new();
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
        msgs_to_be_sent.push(ProtMsg::AppxConCTECHO(ctr.clone() ,cx.myid));
        // 3. Add your own vote to the map
        match rnd_state.echos.get_mut(&sender)  {
            None => {
                let mut hash_map = HashMap::default();
                hash_map.insert(cx.myid, (shard.clone(),mp.clone()));
                rnd_state.echos.insert(sender, hash_map);
            },
            Some(x) => {
                x.insert(cx.myid,(shard.clone(),mp.clone()));
            },
        }
        match rnd_state.readys.get_mut(&sender)  {
            None => {
                let mut hash_map = HashMap::default();
                hash_map.insert(cx.myid,(shard.clone(),mp.clone()));
                rnd_state.readys.insert(sender, hash_map);
            },
            Some(x) => {
                x.insert(cx.myid,(shard.clone(),mp.clone()));
            },
        }
    }
    // 1. If the protocol did not reach this round yet, create a new roundstate object
    else{
        let mut rnd_state = RoundState::new();
        rnd_state.node_msgs.insert(sender, (shard.clone(),mp.clone(),mp.root()));
        round_state_map.insert(round, rnd_state);
        // 7. Send messages
        msgs_to_be_sent.push(ProtMsg::AppxConCTECHO(ctr.clone(),cx.myid));
    }
    // Inserting send message block here to not borrow cx as mutable again
    log::debug!("Sending echos for RBC from origin {}",sender);
    for prot_msg in msgs_to_be_sent.iter(){
        let sec_key_map = cx.sec_key_map.clone();
        for (replica,sec_key) in sec_key_map.into_iter() {
            if replica != cx.myid{
                let wrapper_msg = WrapperMsg::new(prot_msg.clone(), cx.myid, &sec_key.as_slice());
                let sent_msg = Arc::new(wrapper_msg);
                cx.c_send(replica, sent_msg).await;
            }
            else {
                process_echo(cx, ctr.clone(), cx.myid).await;
            }
        }
        log::info!("Broadcasted message {:?}",prot_msg.clone());
    }
}

pub async fn start_baa(cx: &mut Context, round_vecs: Vec<(Replica,BigInt)>){
    // Reliably broadcast the entire vector
    let appxcon_map = &mut cx.nz_appxcon_rs;
    if cx.curr_round == cx.rounds_aa{
        log::info!("Approximate Agreement Protocol terminated with values {:?}",round_vecs.clone());
        // Reconstruct values
        let mapped_rvecs:Vec<(Replica,BigInt)> = 
            round_vecs.clone().into_iter()
            .filter(|(_rep,num)| *num > BigInt::from(0i32))
            .collect();
        for (rep,val) in mapped_rvecs.into_iter(){
            appxcon_map.insert(rep, (val,false,BigInt::from(0i32)));
        }
        send_reconstruct(cx).await;
        return;
    }
    let transmit_vector:Vec<String> = round_vecs.into_iter().map(|x| x.1.to_str_radix(16)).collect();
    let str_rbc = transmit_vector.join(",");
    let f_tran = Vec::from(str_rbc.as_bytes());
    let shards = get_shards(f_tran, cx.num_faults);
    let own_shard = shards[cx.myid].clone();
    // Construct Merkle tree
    let hashes:Vec<Hash> = shards.clone().into_iter().map(|x| do_hash(x.as_slice())).collect();
    log::info!("Vector of hashes during RBC Init {:?}",hashes);
    let merkle_tree:MerkleTree<[u8; 32],HashingAlg> = MerkleTree::from_iter(hashes.into_iter());
    for (replica,sec_key) in cx.sec_key_map.clone().into_iter() {
        if replica != cx.myid{
            let mrp = MerkleProof::from_proof(merkle_tree.gen_proof(replica));
            let ctrbc = CTRBCMsg{
                shard:shards[replica].clone(),
                mp:mrp,
                origin:cx.myid,
                round:cx.curr_round,
            };
            let prot_msg = ProtMsg::AppxConCTRBCInit(ctrbc);
            let wrapper_msg = WrapperMsg::new(prot_msg, cx.myid, &sec_key);
            cx.c_send(replica,Arc::new(wrapper_msg)).await;
        }
    }
    let mrp = MerkleProof::from_proof(merkle_tree.gen_proof(cx.myid));
    let ctrbc = CTRBCMsg{
        shard:own_shard,
        mp:mrp,
        origin:cx.myid,
        round:cx.curr_round
    };
    process_rbc_init(cx,ctrbc).await;
}