use std::{collections::HashMap, sync::Arc};

use types::{hash_cc::{CTRBCMsg, CoinMsg, WrapperMsg}, Replica, appxcon::{verify_merkle_proof, reconstruct_and_verify}};

use crate::node::{Context, RoundState, baa::process_ready};

pub async fn process_echo(cx: &mut Context, ctr:CTRBCMsg, echo_sender:Replica){
    let shard = ctr.shard.clone();
    let mp = ctr.mp.clone();
    let rbc_origin = ctr.origin.clone();
    let round_state_map = &mut cx.round_state;
    let mut msgs_to_be_sent:Vec<CoinMsg> = Vec::new();
    // Highly unlikely that the node will get an echo before rbc_init message
    log::info!("Received ECHO message from {} for RBC of node {}",echo_sender,rbc_origin);
    let round = ctr.round;
    if !verify_merkle_proof(&mp, &shard){
        log::error!("Failed to evaluate merkle proof for ECHO received from node {} for RBC {}",echo_sender,rbc_origin);
        return;
    }
    if cx.curr_round > round{
        return;
    }
    if round_state_map.contains_key(&round){
        // 1. Add echos to the round state object
        let rnd_state = round_state_map.get_mut(&round).unwrap();
        // If RBC already terminated, do not consider this RBC
        if rnd_state.terminated_rbcs.contains(&rbc_origin){
            return;
        }
        match rnd_state.echos.get_mut(&rbc_origin) {
            None => {
                let mut echoset = HashMap::default();
                echoset.insert(echo_sender,(shard.clone(),mp.clone()));
                rnd_state.echos.insert(rbc_origin, echoset);
            },
            Some(x) => {
                x.insert(echo_sender,(shard.clone(),mp.clone()));
            }
        }
        let echos = rnd_state.echos.get_mut(&rbc_origin).unwrap();
        // 2. Check if echos reached the threshold, init already received, and round number is matching
        log::debug!("ECHO check: Round equals: {}, echos.len {}, contains key: {}"
        ,cx.curr_round == round,echos.len(),rnd_state.node_msgs.contains_key(&rbc_origin));
        if echos.len() == cx.num_nodes-cx.num_faults && 
            rnd_state.node_msgs.contains_key(&rbc_origin){
            // Broadcast readys, otherwise, just wait longer
            // Cachin-Tessaro RBC implies verification needed
            // Send your own shard in the echo phase to every other node. 
            let merkle_root = rnd_state.node_msgs.get(&rbc_origin).unwrap().2.clone();
            let res = 
                reconstruct_and_verify(echos.clone(), cx.num_nodes.clone(), cx.num_faults.clone(),cx.myid.clone(), merkle_root);
            match res {
                Err(error)=> log::error!("Shard reconstruction failed because of the following reason {:?}",error),
                Ok(vec_x)=> {
                    let ctrbc = CTRBCMsg::new(vec_x.0, vec_x.1, round, rbc_origin);
                    msgs_to_be_sent.push(CoinMsg::AppxConCTREADY(ctrbc, cx.myid))
                }
            }
        }
    }
    else{
        //let mut rnd_state = create_roundstate(rbc_originator, &main_msg, cx.myid);
        let mut rnd_state = RoundState::new();
        rnd_state.node_msgs.insert(rbc_origin, (shard.clone(),mp.clone(),mp.root()));
        let mut echoset = HashMap::default();
        echoset.insert(echo_sender,(shard.clone(),mp.clone()));
        rnd_state.echos.insert(rbc_origin, echoset);
        round_state_map.insert(round, rnd_state);
        // Do not send echo yet, echo needs to come through from RBC_INIT
        //round_state_map.insert(main_msg.round, rnd_state);
    }
    // Inserting send message block here to not borrow cx as mutable again
    for prot_msg in msgs_to_be_sent.into_iter(){
        let sec_key_map = cx.sec_key_map.clone();
        for (replica,sec_key) in sec_key_map.into_iter() {
            if replica != cx.myid{
                let wrapper_msg = WrapperMsg::new(prot_msg.clone() ,cx.myid, &sec_key.as_slice());
                let sent_msg = Arc::new(wrapper_msg);
                cx.c_send(replica, sent_msg).await;
            }
            else {
                match prot_msg.clone() {
                    CoinMsg::AppxConCTREADY(ctr, sender)
                    => {process_ready(cx,ctr.clone(),sender).await;}
                    _ =>{}
                }
            }
        }
        log::info!("Broadcasted message {:?}",prot_msg.clone());
    }
}