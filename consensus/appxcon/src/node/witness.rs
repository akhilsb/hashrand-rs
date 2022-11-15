use std::{sync::Arc};

use types::appxcon::{Replica, Msg, ProtMsg, WrapperMsg};

use crate::node::{RoundState, process_rbc_init};

use super::Context;

use async_recursion::async_recursion;


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

#[async_recursion]
pub async fn check_for_ht_witnesses(cx: &mut Context, round:u32){
    let round_state_map = &mut cx.round_state;
    let rnd_state = round_state_map.get_mut(&round).unwrap();

    let mut i = 0;
    let min_threshold = cx.num_faults;
    if rnd_state.accepted_vals.len() <= cx.num_faults+1{
        return;
    }
    let high_threshold = rnd_state.accepted_vals.len() - cx.num_faults-1;
    for (_replica,rbc_sets) in rnd_state.witnesses.clone().into_iter(){
        let check = rbc_sets.iter().all(|item| rnd_state.terminated_rbcs.contains(item));
        if check {
            i = i+1;
        }
    }
    if i >= cx.num_nodes-cx.num_faults{
        // Update value for next round
        rnd_state.accepted_vals.sort();
        let nr_val = (rnd_state.accepted_vals.get(min_threshold).unwrap() 
        + rnd_state.accepted_vals.get(high_threshold).unwrap())/2;
        // Update round
        cx.value = nr_val;
        cx.round = round+1;
        if cx.round <= 2000{
            // Initiate next RBCInit now
            log::info!("Protocol completed round {} with new round value {} ",cx.round,cx.value);
            start_rbc(cx).await;
        }
        else {
            log::info!("Protocol terminated value {} ",cx.value);
        }
    }
}

pub async fn start_rbc(cx: &mut Context){
    let msg = Msg{
        value: cx.value,
        origin: cx.myid,
        round: cx.round,
    };
    log::info!("Send RBCInit messages from node {:?} for round {}",cx.myid,cx.round);
    // Add roundstate for round zero
    // if cx.round_state.contains_key(&cx.round){
    //     process_rbc_init(cx,msg.clone()).await;
    // }
    // else{
    //     let rnd_state = create_roundstate(cx.myid, &msg, cx.myid);
    //     cx.round_state.insert(cx.round, rnd_state);
    // }

    if cx.myid == 3{
        return;
    }
    for (replica,sec_key) in cx.sec_key_map.clone().into_iter() {
        if replica != cx.myid{
            let prot_msg = ProtMsg::RBCInit(msg.clone(), cx.myid);
            let wrapper_msg = WrapperMsg::new(prot_msg, cx.myid, &sec_key);
            cx.c_send(replica,Arc::new(wrapper_msg)).await;
        }
        else{
            process_rbc_init(cx,msg.clone()).await;
        }
    }
}