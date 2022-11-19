use std::{sync::Arc, collections::{ HashMap}};

use async_recursion::async_recursion;
use types::appxcon::{ Replica, ProtMsg, WrapperMsg,  CTRBCMsg};

use crate::node::{check_for_ht_witnesses, handle_witness, verify_merkle_proof, reconstruct_and_verify, RoundState, reconstruct_and_return};

use super::{Context};

#[async_recursion]
pub async fn process_ready(cx: &mut Context, ctr:CTRBCMsg, ready_sender:Replica){
    let shard = ctr.shard.clone();
    let mp = ctr.mp.clone();
    let rbc_origin = ctr.origin.clone();
    let round_state_map = &mut cx.round_state;
    let mut msgs_to_be_sent:Vec<ProtMsg> = Vec::new();
    // Highly unlikely that the node will get an echo before rbc_init message
    log::info!("Received READY message from {} for RBC of node {}",ready_sender,rbc_origin);
    let round = 0;
    if !verify_merkle_proof(&mp, &shard){
        log::error!("Failed to evaluate merkle proof for READY received from node {} for RBC {}",ready_sender,rbc_origin);
        return;
    }
    if round_state_map.contains_key(&round){
        // 1. Add readys to the round state object
        let rnd_state = round_state_map.get_mut(&round).unwrap();
        if rnd_state.terminated_rbcs.contains(&rbc_origin){
            return;
        }
        let merkle_root = rnd_state.node_msgs.get(&rbc_origin).unwrap().2.clone();
        // Merkle root check. Check if the merkle root of the message matches the merkle root sent by the node
        if merkle_root != mp.to_proof().root(){
            log::error!("Merkle root verification failed with error {:?}{:?}",merkle_root,mp.to_proof().root());
        }
        match rnd_state.readys.get_mut(&rbc_origin) {
            None => {
                let mut readyset = HashMap::default();
                readyset.insert(ready_sender,(shard.clone(),mp.clone()));
                rnd_state.readys.insert(rbc_origin, readyset);
            },
            Some(x) => {
                x.insert(ready_sender,(shard.clone(),mp.clone()));
            }
        }
        let readys = rnd_state.readys.get_mut(&rbc_origin).unwrap();
        // 2. Check if readys reached the threshold, init already received, and round number is matching
        log::debug!("READY check: Round equals: {}, echos.len {}, contains key: {}"
        ,cx.round == round,readys.len(),rnd_state.node_msgs.contains_key(&rbc_origin));
        if  readys.len() == cx.num_faults+1 &&
            rnd_state.node_msgs.contains_key(&rbc_origin) && !readys.contains_key(&cx.myid){
            // Broadcast readys, otherwise, just wait longer
            // Cachin-Tessaro RBC implies verification needed
            let res = 
                reconstruct_and_verify(readys.clone(), cx.num_nodes.clone(), cx.num_faults.clone(),cx.myid.clone(), merkle_root);
            match res {
                Err(error)=> log::error!("Shard reconstruction failed because of the following reason {:?}",error),
                Ok(vec_x)=> {
                    let ctrbc = CTRBCMsg::new(vec_x.0, vec_x.1, round, rbc_origin);
                    msgs_to_be_sent.push(ProtMsg::CTREADY(ctrbc, cx.myid));
                }
            };
        }
        else if readys.len() >= cx.num_nodes-cx.num_faults &&
            rnd_state.node_msgs.contains_key(&rbc_origin){
            // Terminate RBC, RAccept the value
            // Add value to value list, add rbc to rbc list
            let res = 
                reconstruct_and_verify(readys.clone(), cx.num_nodes.clone(), cx.num_faults.clone(),cx.myid, merkle_root);
            match res {
                Err(error)=> {
                    log::error!("Shard reconstruction failed because of the following reason {:?}",error);
                    return;
                },
                Ok(vec_x)=> {
                    let ctrbc = CTRBCMsg::new(vec_x.0, vec_x.1, round, rbc_origin);
                    msgs_to_be_sent.push(ProtMsg::CTReconstruct(ctrbc, cx.myid));
                }
            };
            log::info!("Terminated RBC of node {} with value",rbc_origin);
            // if rnd_state.terminated_rbcs.len() >= cx.num_nodes - cx.num_faults{
            //     // Has a witness message been sent already? If not, send it. 
            //     if !rnd_state.witness_sent{
            //         log::info!("Terminated n-f RBCs, sending list of first n-f RBCs to other nodes");
            //         log::info!("Round state: {:?}",rnd_state.terminated_rbcs);
            //         let vec_rbcs = Vec::from_iter(rnd_state.terminated_rbcs.clone().into_iter());
            //         let witness_msg = ProtMsg::WITNESS(
            //             vec_rbcs.clone(), 
            //             cx.myid,
            //             cx.round
            //         );
            //         msgs_to_be_sent.push(witness_msg);
            //         rnd_state.witness_sent = true;
            //     }
            //     check_for_ht_witnesses(cx, main_msg.round).await;
            // }
        }
    }
    else{
        let mut rnd_state = RoundState::new();
        rnd_state.node_msgs.insert(rbc_origin, (shard.clone(),mp.clone(),mp.root()));
        let mut readyset = HashMap::default();
        readyset.insert(ready_sender,(shard.clone(),mp.clone()));
        rnd_state.readys.insert(rbc_origin, readyset);
        round_state_map.insert(round, rnd_state);
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
                    ProtMsg::CTREADY(ctr, sender)=>{
                        process_ready(cx, ctr.clone(),sender).await;
                    },
                    ProtMsg::CTReconstruct(ctr, sender) => {
                        process_reconstruct_message(cx,ctr.clone(),sender).await;
                    }
                    _=>{}
                }
                
            }
        }
        log::info!("Broadcasted message {:?}",prot_msg.clone());
    }
}

pub async fn process_reconstruct_message(cx: &mut Context,ctr:CTRBCMsg,recon_sender:Replica){
    let shard = ctr.shard.clone();
    let mp = ctr.mp.clone();
    let rbc_origin = ctr.origin.clone();
    let round_state_map = &mut cx.round_state;
    let mut msgs_to_be_sent:Vec<ProtMsg> = Vec::new();
    // Highly unlikely that the node will get an echo before rbc_init message
    log::info!("Received Reconstruct message from {} for RBC of node {}",recon_sender,rbc_origin);
    let round = 0;
    if !verify_merkle_proof(&mp, &shard){
        log::error!("Failed to evaluate merkle proof for RECON received from node {} for RBC {}",recon_sender,rbc_origin);
        return;
    }
    if round_state_map.contains_key(&round){
        let rnd_state = round_state_map.get_mut(&round).unwrap();
        if rnd_state.terminated_rbcs.contains(&rbc_origin){
            return;
        }
        // Check merkle root validity
        let merkle_root = rnd_state.node_msgs.get(&rbc_origin).unwrap().2.clone();
        // Merkle root check. Check if the merkle root of the message matches the merkle root sent by the node
        if merkle_root != mp.to_proof().root(){
            log::error!("Merkle root verification failed with error {:?}{:?}",merkle_root,mp.to_proof().root());
        }
        match rnd_state.recon_msgs.get_mut(&rbc_origin) {
            None => {
                let mut reconset = HashMap::default();
                reconset.insert(recon_sender,shard.clone());
                rnd_state.recon_msgs.insert(rbc_origin, reconset);
            },
            Some(x) => {
                x.insert(recon_sender,shard.clone());
            }
        }
        // Check if the RBC received n-f readys
        let ready_check = rnd_state.readys.get(&rbc_origin).unwrap().len() >= (cx.num_nodes-cx.num_faults);
        let vec_fmap = rnd_state.recon_msgs.get(&rbc_origin).unwrap();
        if vec_fmap.len()>=cx.num_nodes-cx.num_faults && ready_check{
            // Reconstruct here
            let result = reconstruct_and_return(
                vec_fmap, cx.num_nodes.clone(), cx.num_faults.clone());
            match result {
                Err(error)=> {
                    log::error!("Error resulted in constructing erasure-coded data {:?}",error);
                    return;
                }
                Ok(vec)=>{
                    log::info!("Successfully reconstructed message for RBC, terminating RBC of node {}",rbc_origin);
                    log::info!("Terminated with message: {:?}",String::from_utf8(vec.clone()).expect("Invalid utf8"));
                    rnd_state.accepted_msgs.insert(rbc_origin, vec);
                    rnd_state.terminated_rbcs.insert(rbc_origin);
                    // Initiate next phase of the protocol here
                    if rnd_state.terminated_rbcs.len() >= cx.num_nodes - cx.num_faults{
                        if !rnd_state.witness_sent{
                            log::info!("Terminated n-f RBCs, sending list of first n-f RBCs to other nodes");
                            log::info!("Round state: {:?}",rnd_state.terminated_rbcs);
                            let vec_rbcs = Vec::from_iter(rnd_state.terminated_rbcs.clone().into_iter());
                            let witness_msg = ProtMsg::WITNESS(
                                vec_rbcs.clone(), 
                                cx.myid,
                                cx.round
                            );
                            msgs_to_be_sent.push(witness_msg);
                            rnd_state.witness_sent = true;
                        }
                        check_for_ht_witnesses(cx, 0).await;
                    }
                }
            }
        }
    }
    else {
        let mut rnd_state = RoundState::new();
        let mut reconset = HashMap::default();
        reconset.insert(recon_sender,shard.clone());
        rnd_state.recon_msgs.insert(rbc_origin, reconset);
        round_state_map.insert(round, rnd_state);
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
                    ProtMsg::WITNESS(vec, _origin, round) => {
                        handle_witness(cx,vec.clone(),round.clone(),cx.myid).await;
                    },
                    _ => {}
                }
            }
        }
        log::info!("Broadcasted message {:?}",prot_msg.clone());
    }
}