use std::{sync::Arc};

use crypto::hash::{verf_mac};
use types::rbc::{ProtocolMsg,WrapperMsg, Msg};
use crate::node::{
    context::Context
};

pub fn check_proposal(wrapper_msg: Arc<WrapperMsg>,cx:&Context) -> bool {
    // validate MAC
    let byte_val = bincode::serialize(&wrapper_msg.msg).expect("Failed to serialize object");
    let sec_key = match cx.sec_key_map.get(&wrapper_msg.clone().msg.node) {
        Some(val) => {val},
        None => {panic!("Secret key not available, this shouldn't happen")},
    };
    if !verf_mac(&byte_val,&sec_key.as_slice(),&wrapper_msg.mac){
        log::warn!("MAC Verification failed.");
        return false;
    }
    true
}

pub(crate) async fn process_msg(cx: &mut Context,protmsg:ProtocolMsg){
    log::debug!("Received protocol message: {:?}",protmsg);
    match protmsg{
        ProtocolMsg::RBCInit(wrapper_msg) => {
            log::debug!("Received RBC initialization : {:?}",wrapper_msg);
            // Verify MAC first
            let rbc_init = Arc::new(wrapper_msg.clone());
            if check_proposal(rbc_init, cx){
                process_rbc_init(cx, Arc::new(wrapper_msg)).await;
            }
        }
        ProtocolMsg::ECHO(wrapper_msg) => {
            log::debug!("Received RBC Echo : {:?}",wrapper_msg);
            // Verify MAC first
            let rbc_echo = Arc::new(wrapper_msg.clone());
            if check_proposal(rbc_echo, cx){
                process_echo(cx, Arc::new(wrapper_msg)).await;
            }
        }
        ProtocolMsg::READY(wrapper_msg) => {
            log::debug!("Received RBC Ready : {:?}",wrapper_msg);
            // Verify MAC first
            let rbc_ready = Arc::new(wrapper_msg.clone());
            if check_proposal(rbc_ready, cx){
                process_ready(cx, Arc::new(wrapper_msg)).await;
            }
        }
        ProtocolMsg::SECRETSHARE(_) => todo!(),
    }
}

async fn process_rbc_init(context:&mut Context,wrapper_msg:Arc<WrapperMsg>)-> bool{
    // Send Echos to every other node
    let echo_msg = Msg{
        msg_type: 1,
        node: context.myid,
        value: wrapper_msg.msg.value.clone(),
    };
    for (replica,sec_key) in &context.sec_key_map.clone() {
        let wrapper_msg = WrapperMsg::new(echo_msg.clone(),&sec_key.as_slice());
        let prot_msg = ProtocolMsg::ECHO(wrapper_msg);
        let sent_msg = Arc::new(prot_msg);
        context.c_send(*replica,sent_msg).await;
    }
    log::info!("Broadcasted ECHO messages");
    // Add self vote to Echo and Ready sets
    context.echo_set.insert(context.myid);
    context.ready_set.insert(context.myid);
    // let sec_key = match context.sec_key_map.get(&context.myid) {
    //     Some(val) => {val},
    //     None => {panic!("Secret key not available, this shouldn't happen")},
    // };
    // let wrapper_msg = WrapperMsg::new(echo_msg, &sec_key.as_slice());
    // let prot_msg = ProtocolMsg::ECHO(wrapper_msg);
    // let ship_nodes = context.num_nodes;
    // let vote_ship = tokio::spawn(async move {
    //     let msg = Arc::new(prot_msg);
    //     if let Err(e) = ship.send(
    //         (ship_nodes, msg))
    //     {
    //         log::warn!(
    //             "failed to send vote: {}", e);
    //     }
    // });
    // vote_ship.await.expect("Failed to broadcast INIT message");
    true
}

async fn process_echo(context:&mut Context,wrapper_msg:Arc<WrapperMsg>)->bool {
    if context.echo_set.contains(&wrapper_msg.msg.node){
        // Already received echo from this node, do not document
        log::warn!("Already received echo from node {}",wrapper_msg.msg.node);
        return false;
    }
    context.echo_set.insert(wrapper_msg.msg.node);
    let high_threshold = context.num_nodes - context.num_faults;
    log::info!("Num echos: {} {}",context.echo_set.len(),high_threshold);
    if context.echo_set.len() == high_threshold{
        // send out ready messages
        log::debug!("Received enough ECHOs, broadcasting READYs");
        let ready_msg = Msg{
            msg_type:2,
            node: context.myid,
            value: wrapper_msg.msg.value.clone(),
        };
        for (replica,sec_key) in &context.sec_key_map.clone() {
            let wrapper_msg = WrapperMsg::new(ready_msg.clone(),&sec_key.as_slice());
            let prot_msg = ProtocolMsg::READY(wrapper_msg);
            let sent_msg = Arc::new(prot_msg);
            context.c_send(*replica,sent_msg).await;
        }
        // let sec_key = match context.sec_key_map.get(&context.myid) {
        //     Some(val) => {val},
        //     None => {panic!("Secret key not available, this shouldn't happen")},
        // };
        // let prot_msg = ProtocolMsg::READY(WrapperMsg::new(ready_msg, &sec_key.as_slice()));
        // let ship_nodes = context.num_nodes;
        // let vote_ship = tokio::spawn(async move {
        //     let msg = Arc::new(prot_msg);
        //     if let Err(e) = ship.send(
        //         (ship_nodes, msg))
        //     {
        //         log::warn!(
        //             "failed to send echo: {}", e);
        //     }
        // });
        // vote_ship.await.expect("Failed to send ECHO messages");
    }
    true
}

async fn process_ready(context:&mut Context,wrapper_msg:Arc<WrapperMsg>)->bool {
    if context.ready_set.contains(&wrapper_msg.msg.node){
        // Already received echo from this node, do not document
        log::warn!("Already received ready from node {}",wrapper_msg.msg.node);
        return false;
    }
    context.ready_set.insert(wrapper_msg.msg.node);
    let min_threshold =  context.num_faults+1;
    let high_threshold = context.num_nodes - context.num_faults;
    if context.ready_set.len() == min_threshold{
        // Send out readys again
        log::debug!("Sending READYs because of f+1 threshold {}",wrapper_msg.msg.node);
        let ready_msg = Msg{
            msg_type:2,
            node: context.myid,
            value: wrapper_msg.msg.value.clone(),
        };
        for (replica,sec_key) in &context.sec_key_map.clone() {
            let wrapper_msg = WrapperMsg::new(ready_msg.clone(),&sec_key.as_slice());
            let prot_msg = ProtocolMsg::READY(wrapper_msg);
            let sent_msg = Arc::new(prot_msg);
            context.c_send(*replica,sent_msg).await;
        }
        // let sec_key = match context.sec_key_map.get(&context.myid) {
        //     Some(val) => {val},
        //     None => {panic!("Secret key not available, this shouldn't happen")},
        // };
        // let prot_msg = ProtocolMsg::READY(WrapperMsg::new(ready_msg, &sec_key.as_slice()));
        // let ship_nodes = context.num_nodes;
        // let vote_ship = tokio::spawn(async move {
        //     let msg = Arc::new(prot_msg);
        //     if let Err(e) = ship.send(
        //         (ship_nodes, msg))
        //     {
        //         log::warn!(
        //             "failed to send echo: {}", e);
        //     }
        // });
        // vote_ship.await.expect("Failed to broadcast ready");
    }
    else if context.ready_set.len() == high_threshold {
        // Terminate
        log::debug!("Received n-f readys, terminate {}",wrapper_msg.msg.node);
        println!("Terminated!, {}",wrapper_msg.msg.node);
    }
    true
}