use std::{sync::Arc};

use crypto::hash::{verf_mac};
use types::{hash_cc::{CoinMsg, WrapperSMRMsg, DAGMsg, SMRMsg}};

use crate::node::{process_baa_echo, process_baa_echo2, process_batchwss_init, process_batch_wssecho, process_batchwssready, process_batchreconstruct_message, process_batchreconstruct, process_rbc_init, process_echo, process_ready, process_reconstruct_message};

use super::Context;
//use async_recursion::async_recursion;


/*
    DAG-based SMR protocol with an asynchronous common coin based on Hash functions
*/

pub fn check_proposal(wrapper_msg: Arc<WrapperSMRMsg>,cx:&Context) -> bool {
    // validate MAC
    let byte_val = bincode::serialize(&wrapper_msg.protmsg).expect("Failed to serialize object");
    let sec_key = match cx.sec_key_map.get(&wrapper_msg.clone().sender) {
        Some(val) => {val},
        None => {panic!("Secret key not available, this shouldn't happen")},
    };
    if !verf_mac(&byte_val,&sec_key.as_slice(),&wrapper_msg.mac){
        log::warn!("MAC Verification failed.");
        return false;
    }
    true
}

pub(crate) async fn process_msg(cx: &mut Context, wrapper_msg: WrapperSMRMsg){
    log::debug!("Received protocol msg: {:?}",wrapper_msg);
    let msg = Arc::new(wrapper_msg.clone());
    if check_proposal(msg, cx){
        cx.num_messages += 1;
        let mut ret_vec = Vec::new();
        let coin_msg = wrapper_msg.protmsg.coin_msg.clone();
        match wrapper_msg.protmsg.dag_msg {
            DAGMsg::RBCInit(ctr)=>{
                log::debug!("Received RBC Init from node {}",ctr.origin);
                ret_vec.append(&mut process_rbc_init(cx, ctr).await);
            },
            DAGMsg::RBCECHO(ctr, echo_sender)=>{
                log::debug!("Received RBC ECHO from node {} for message {:?}",echo_sender,ctr.clone());
                ret_vec.append(&mut process_echo(cx, ctr,echo_sender).await);
            },
            DAGMsg::RBCREADY(ctr, ready_sender)=>{
                log::debug!("Received RBC READY from node {} for message {:?}",ready_sender,ctr.clone());
                ret_vec.append(&mut process_ready(cx, ctr,ready_sender).await);
            },
            DAGMsg::RBCReconstruct(ctr, recon_sender)=>{
                log::debug!("Received RBC Reconstruct from node {} for message {:?}",recon_sender,ctr.clone());
                ret_vec.append(&mut process_reconstruct_message(cx, ctr,recon_sender).await);
            },
            _ =>{},
        }
        if ret_vec.is_empty(){
            ret_vec.push(DAGMsg::NoMessage());
        }
        for dag_msg in ret_vec.into_iter(){
            let mut smr_msg = SMRMsg::new(dag_msg, coin_msg.clone(), wrapper_msg.protmsg.origin);
            match smr_msg.clone().coin_msg {

                // CoinMsg::GatherEcho(term_secrets, echo_sender)=>{
                //     log::debug!("Received Gather ECHO from node {}",echo_sender);
                //     process_gatherecho(cx,term_secrets, echo_sender, 1u32,smr_msg).await;
                // },
                // CoinMsg::GatherEcho2(term_secrets, echo_sender)=>{
                //     log::debug!("Received Gather ECHO2 from node {}",echo_sender);
                //     process_gatherecho(cx,term_secrets, echo_sender, 2u32,smr_msg).await;
                // },
                CoinMsg::BinaryAAEcho(msgs, echo_sender, round) =>{
                    log::debug!("Received Binary AA Echo1 from node {}",echo_sender);
                    process_baa_echo(cx, msgs, echo_sender, round,&mut smr_msg).await;
                },
                CoinMsg::BinaryAAEcho2(msgs, echo2_sender, round) =>{
                    log::debug!("Received Binary AA Echo2 from node {}",echo2_sender);
                    process_baa_echo2(cx, msgs, echo2_sender, round,&mut smr_msg).await;
                },
                CoinMsg::BatchWSSInit(wss_msg, ctr)=>{
                    log::debug!("Received Batch Secret Sharing init message from node {}",wss_msg.origin.clone());
                    process_batchwss_init(cx,wss_msg, ctr,&mut smr_msg).await;
                },
                CoinMsg::BatchWSSEcho(ctr, mr_root, echo_sender)=>{
                    log::debug!("Received Batch Secret Sharing ECHO message from node {} for secret from {}",echo_sender,ctr.origin);
                    process_batch_wssecho(cx,ctr, mr_root,echo_sender,&mut smr_msg).await;
                },
                CoinMsg::BatchWSSReady(ctr, mr_root, ready_sender)=>{
                    log::debug!("Received Batch Secret Sharing READY message from node {} for secret from {}",ready_sender,ctr.origin);
                    process_batchwssready(cx,ctr, mr_root,ready_sender,&mut smr_msg).await;
                },
                CoinMsg::BatchWSSReconstruct(ctr, mr_root, recon_sender)=>{
                    log::debug!("Received Batch Secret Sharing Recon message from node {} for secret from {}",recon_sender,ctr.origin);
                    process_batchreconstruct_message(cx,ctr, mr_root,recon_sender,&mut smr_msg).await;
                },
                CoinMsg::BatchSecretReconstruct(wssmsg, share_sender, sec_num)=>{
                    log::debug!("Received Batch Secret Sharing secret share from node {} with sec_num {}",share_sender,sec_num);
                    process_batchreconstruct(cx,wssmsg, share_sender,sec_num,&mut smr_msg).await;
                },
                _ => {}
            }
        }
    }
    else {
        log::warn!("MAC Verification failed for message {:?}",wrapper_msg.protmsg);
    }
}