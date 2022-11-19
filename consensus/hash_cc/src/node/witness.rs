use std::{sync::Arc};

use crypto::hash::{do_hash, Hash};
use merkle_light::merkle::MerkleTree;
use types::appxcon::{Replica, ProtMsg, WrapperMsg, MerkleProof, CTRBCMsg};

use crate::node::{RoundState, get_shards, HashingAlg, process_rbc_init};

use super::Context;

//use async_recursion::async_recursion;


pub async fn handle_witness(cx: &mut Context,vec_rbc_indices:Vec<Replica>, round: u32, witness_sender:Replica){
    let round_state_map = &mut cx.round_state;
    log::info!("Received witness message {:?} from node {} for round {}",vec_rbc_indices.clone(),witness_sender,round);
    if round_state_map.contains_key(&round){
        let rnd_state = round_state_map.get_mut(&round).unwrap();
        rnd_state.witnesses.insert(witness_sender,vec_rbc_indices.clone());
        check_for_ht_witnesses(cx, round).await;
    }
    else{
        // 1. If the protocol did not reach this round yet, create a new roundstate object
        let mut rnd_state = RoundState::new();
        rnd_state.witnesses.insert(witness_sender, vec_rbc_indices);
        round_state_map.insert(round, rnd_state);
    }
}

//#[async_recursion]
pub async fn check_for_ht_witnesses(cx: &mut Context, round:u32){
    let round_state_map = &mut cx.round_state;
    let rnd_state = round_state_map.get_mut(&round).unwrap();

    let mut i = 0;
    //let min_threshold = cx.num_faults;
    if rnd_state.accepted_vals.len() <= cx.num_faults+1{
        return;
    }
    //let high_threshold = rnd_state.accepted_vals.len() - cx.num_faults-1;
    for (_replica,rbc_sets) in rnd_state.witnesses.clone().into_iter(){
        let check = rbc_sets.iter().all(|item| rnd_state.terminated_rbcs.contains(item));
        if check {
            i = i+1;
        }
    }
    if i >= cx.num_nodes-cx.num_faults{
        // Update value for next round
        rnd_state.accepted_vals.sort();
        //let nr_val = (rnd_state.accepted_vals.get(min_threshold).unwrap() 
        //+ rnd_state.accepted_vals.get(high_threshold).unwrap())/2;
        // Update round
        cx.round = round+1;
        if cx.round <= 1{
            // Initiate next RBCInit now
            log::info!("Protocol completed round {}",cx.round);
            //start_rbc(cx).await;
        }
        else {
            log::info!("Protocol terminated!");
        }
    }
}

pub async fn start_rbc(cx: &mut Context){
    
    log::info!("Send RBCInit messages from node {:?} for round {}",cx.myid,cx.round);
    // Add roundstate for round zero
    // if cx.round_state.contains_key(&cx.round){
    //     process_rbc_init(cx,msg.clone()).await;
    // }
    // else{
    //     let rnd_state = create_roundstate(cx.myid, &msg, cx.myid);
    //     cx.round_state.insert(cx.round, rnd_state);
    // }
    let shards = get_shards(cx.value.clone(), cx.num_faults);
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
                round:0
            };
            let prot_msg = ProtMsg::CTRBCInit(ctrbc);
            let wrapper_msg = WrapperMsg::new(prot_msg, cx.myid, &sec_key);
            cx.c_send(replica,Arc::new(wrapper_msg)).await;
        }
    }
    let mrp = MerkleProof::from_proof(merkle_tree.gen_proof(cx.myid));
    let ctrbc = CTRBCMsg{
        shard:own_shard,
        mp:mrp,
        origin:cx.myid,
        round:0
    };
    process_rbc_init(cx,ctrbc).await;
}