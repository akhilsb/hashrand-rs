use std::sync::Arc;

use async_recursion::async_recursion;
use num_bigint::BigInt;
use num_traits::pow;
use types::{hash_cc::{CoinMsg, WrapperMsg}, Replica};

use crate::node::{Context, start_baa};

pub async fn process_gatherecho(cx: &mut Context,wss_indices:Vec<Replica>, echo_sender:Replica,round: u32){
    let vss_state = &mut cx.vss_state;
    log::info!("Received gather echo message {:?} from node {} for round {}",wss_indices.clone(),echo_sender,round);
    if vss_state.send_w2{
        if round == 2{
            vss_state.witness2.insert(echo_sender, wss_indices);
            witness_check(cx).await;
        }
        else {
            log::warn!("Ignoring echo1 because protocol moved forward to echo2s");
            return;
        }
    }
    else {
        if round == 1{
            vss_state.witness1.insert(echo_sender, wss_indices);
        }
        else{
            vss_state.witness2.insert(echo_sender, wss_indices);
        }
        witness_check(cx).await;
    }
}

#[async_recursion]
pub async fn witness_check(cx: &mut Context){
    let vss_state = &mut cx.vss_state;
    let mut i = 0;
    if vss_state.accepted_secrets.len() <= cx.num_faults+1{
        return;
    }
    let mut msgs_to_be_sent:Vec<CoinMsg> = Vec::new();
    if !vss_state.send_w2{
        for (_replica,ss_inst) in vss_state.witness1.clone().into_iter(){
            let check = ss_inst.iter().all(|item| vss_state.terminated_secrets.contains(item));
            if check {
                i = i+1;
            }
        }
    
        if i >= cx.num_nodes-cx.num_faults{
            // Send out ECHO2 messages
            log::info!("Accepted n-f witnesses, sending ECHO2 messages for Gather from node {}",cx.myid);
            vss_state.send_w2 = true;
            msgs_to_be_sent.push(CoinMsg::GatherEcho2(vss_state.terminated_secrets.clone().into_iter().collect() , cx.myid));
        }
    }
    else{
        for (_replica,ss_inst) in vss_state.witness2.clone().into_iter(){
            let check = ss_inst.iter().all(|item| vss_state.terminated_secrets.contains(item));
            if check {
                i = i+1;
            }
        }    
        if i >= cx.num_nodes-cx.num_faults{
            // Received n-f witness2s. Start approximate agreement from here. 
            log::info!("Accepted n-f witness2 for node {} with set {:?}",cx.myid,vss_state.terminated_secrets.clone());
            let terminated_secrets = vss_state.terminated_secrets.clone();
            let mut transmit_vector:Vec<(Replica,BigInt)> = Vec::new();
            let rounds = cx.rounds_aa;
            for i in 0..cx.num_nodes{
                if !terminated_secrets.contains(&i) {
                    let zero = BigInt::from(0);
                    transmit_vector.push((i,zero));
                }
                else {
                    let max = BigInt::from(2);
                    let max_power = pow(max, rounds as usize);
                    transmit_vector.push((i,max_power));
                }
            }
            start_baa(cx, transmit_vector).await;
        }
    }
    for prot_msg in msgs_to_be_sent.iter(){
        let sec_key_map = cx.sec_key_map.clone();
        for (replica,sec_key) in sec_key_map.into_iter() {
            if replica != cx.myid{
                let wrapper_msg = WrapperMsg::new(prot_msg.clone(), cx.myid, &sec_key.as_slice());
                let sent_msg = Arc::new(wrapper_msg);
                cx.c_send(replica, sent_msg).await;
            }
            else {
                match prot_msg {
                    CoinMsg::GatherEcho2(vec_term_secs, echo_sender) =>{
                        process_gatherecho(cx, vec_term_secs.clone(), *echo_sender, 2).await;
                    },
                    _ => {}
                }
            }
        }
        log::info!("Broadcasted message {:?}",prot_msg.clone());
    }
}