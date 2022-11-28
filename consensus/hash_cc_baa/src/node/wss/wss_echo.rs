use std::{sync::Arc, collections::HashSet};

use types::{Replica, hash_cc::{ProtMsg, WrapperMsg}};

use crate::node::{Context, process_wssready};
use crypto::hash::{Hash};

pub async fn process_wssecho(cx: &mut Context,mr:Hash,sec_origin:Replica, echo_sender:Replica){
    let vss_state = &mut cx.vss_state;
    let mut msgs_to_be_sent:Vec<ProtMsg> = Vec::new();
    // Highly unlikely that the node will get an echo before rbc_init message
    log::info!("Received ECHO message {:?} for secret from {}",mr.clone(),sec_origin);
    // If RBC already terminated, do not consider this RBC
    if vss_state.terminated_secrets.contains(&sec_origin){
        log::info!("Terminated secretsharing of instance {} already, skipping this echo",sec_origin);
        return;
    }
    match vss_state.node_secrets.get(&sec_origin){
        None => {
            let mut echoset = HashSet::default();
            echoset.insert(echo_sender);
            vss_state.echos.insert(sec_origin, echoset);
            return;
        }
        Some(_x) =>{}
    }
    let mp = vss_state.node_secrets.get(&sec_origin).unwrap().3.clone();
    if mp.to_proof().root() != mr{
        log::error!("Merkle root of WSS Init from {} did not match Merkle root of ECHO from {}",sec_origin,cx.myid);
        return;
    }
    match vss_state.echos.get_mut(&sec_origin) {
        None => {
            let mut echoset = HashSet::default();
            echoset.insert(echo_sender);
            vss_state.echos.insert(sec_origin, echoset);
        },
        Some(x) => {
            x.insert(echo_sender);
        }
    }
    let echos = vss_state.echos.get_mut(&sec_origin).unwrap();
    // 2. Check if echos reached the threshold, init already received, and round number is matching
    log::debug!("WSS ECHO check: echos.len {}, contains key: {}"
        ,echos.len(),vss_state.node_secrets.contains_key(&sec_origin));
    if echos.len() == cx.num_nodes-cx.num_faults && 
        vss_state.node_secrets.contains_key(&sec_origin){
        // Broadcast readys, otherwise, just wait longer
        msgs_to_be_sent.push(ProtMsg::WSSReady(mr.clone(), sec_origin, cx.myid));
    }
    // Inserting send message block here to not borrow cx as mutable again
    for prot_msg in msgs_to_be_sent.iter(){
        let sec_key_map = cx.sec_key_map.clone();
        for (replica,sec_key) in sec_key_map.into_iter() {
            if replica != cx.myid{
                let wrapper_msg = WrapperMsg::new(prot_msg.clone(), cx.myid, &sec_key.as_slice());
                let sent_msg = Arc::new(wrapper_msg);
                cx.c_send(replica, sent_msg).await;
            }
            else {
                process_wssready(cx, mr.clone(), sec_origin, cx.myid).await;
            }
        }
        log::info!("Broadcasted message {:?}",prot_msg.clone());
    }
}