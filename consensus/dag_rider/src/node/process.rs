use std::{sync::Arc};

use crypto::hash::{verf_mac};
use types::{hash_cc::{CoinMsg, WrapperSMRMsg, DAGMsg, SMRMsg}};

use super::Context;
//use async_recursion::async_recursion;


/*
    DAG-based SMR protocol with an asynchronous common coin based on Hash functions
*/

impl Context{
    pub fn check_proposal(self:&Context,wrapper_msg: Arc<WrapperSMRMsg>) -> bool {
        // validate MAC
        let byte_val = bincode::serialize(&wrapper_msg.protmsg).expect("Failed to serialize object");
        let sec_key = match self.sec_key_map.get(&wrapper_msg.clone().sender) {
            Some(val) => {val},
            None => {panic!("Secret key not available, this shouldn't happen")},
        };
        if !verf_mac(&byte_val,&sec_key.as_slice(),&wrapper_msg.mac){
            log::warn!("MAC Verification failed.");
            return false;
        }
        true
    }
    
    pub(crate) async fn process_msg(self: &mut Context, wrapper_msg: WrapperSMRMsg){
        log::trace!("Received protocol msg: {:?}",wrapper_msg);
        let msg = Arc::new(wrapper_msg.clone());
        if self.check_proposal(msg){
            self.num_messages += 1;
            log::trace!("Num messages: {}",self.num_messages);
            let mut ret_vec = Vec::new();
            let coin_msg = wrapper_msg.protmsg.coin_msg.clone();
            match wrapper_msg.protmsg.dag_msg {
                DAGMsg::RBCInit(ctr)=>{
                    log::trace!("Received RBC Init from node {}",ctr.origin);
                    ret_vec.append(&mut self.process_rbc_init( ctr).await);
                },
                DAGMsg::RBCECHO(ctr, echo_sender)=>{
                    log::trace!("Received RBC ECHO from node {} for message {:?}",echo_sender,ctr.clone());
                    ret_vec.append(&mut self.process_echo( ctr,echo_sender).await);
                },
                DAGMsg::RBCREADY(ctr, ready_sender)=>{
                    log::trace!("Received RBC READY from node {} for message {:?}",ready_sender,ctr.clone());
                    ret_vec.append(&mut self.process_ready( ctr,ready_sender).await);
                },
                DAGMsg::RBCReconstruct(ctr, recon_sender)=>{
                    log::trace!("Received RBC Reconstruct from node {} for message {:?}",recon_sender,ctr.clone());
                    ret_vec.append(&mut self.process_reconstruct_message( ctr,recon_sender).await);
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
                    //     log::trace!("Received Gather ECHO from node {}",echo_sender);
                    //     process_gatherecho(self,term_secrets, echo_sender, 1u32,smr_msg).await;
                    // },
                    // CoinMsg::GatherEcho2(term_secrets, echo_sender)=>{
                    //     log::trace!("Received Gather ECHO2 from node {}",echo_sender);
                    //     process_gatherecho(self,term_secrets, echo_sender, 2u32,smr_msg).await;
                    // },
                    CoinMsg::BinaryAAEcho(msgs, echo_sender, round) =>{
                        log::trace!("Received Binary AA Echo1 from node {}",echo_sender);
                        self.process_baa_echo(msgs, echo_sender, round,&mut smr_msg).await;
                    },
                    CoinMsg::BinaryAAEcho2(msgs, echo2_sender, round) =>{
                        log::trace!("Received Binary AA Echo2 from node {}",echo2_sender);
                        self.process_baa_echo2(msgs, echo2_sender, round,&mut smr_msg).await;
                    },
                    CoinMsg::BatchWSSInit(wss_msg, ctr)=>{
                        log::trace!("Received Batch Secret Sharing init message from node {}",wss_msg.origin.clone());
                        self.process_batchwss_init(wss_msg, ctr,&mut smr_msg).await;
                    },
                    CoinMsg::BatchWSSEcho(ctr, mr_root, echo_sender)=>{
                        log::trace!("Received Batch Secret Sharing ECHO message from node {} for secret from {}",echo_sender,ctr.origin);
                        self.process_batch_wssecho(ctr, mr_root,echo_sender,&mut smr_msg).await;
                    },
                    CoinMsg::BatchWSSReady(ctr, mr_root, ready_sender)=>{
                        log::trace!("Received Batch Secret Sharing READY message from node {} for secret from {}",ready_sender,ctr.origin);
                        self.process_batchwssready(ctr, mr_root,ready_sender,&mut smr_msg).await;
                    },
                    CoinMsg::BatchWSSReconstruct(ctr, mr_root, recon_sender)=>{
                        log::trace!("Received Batch Secret Sharing Recon message from node {} for secret from {}",recon_sender,ctr.origin);
                        self.process_batchreconstruct_message(ctr, mr_root,recon_sender,&mut smr_msg).await;
                    },
                    CoinMsg::BatchSecretReconstruct(wssmsg, share_sender, sec_num)=>{
                        log::trace!("Received Batch Secret Sharing secret share from node {} with sec_num {}",share_sender,sec_num);
                        self.process_batchreconstruct(wssmsg, share_sender,sec_num,&mut smr_msg).await;
                    },
                    CoinMsg::NoMessage() =>{
                        match smr_msg.dag_msg {
                            DAGMsg::NoMessage()=>{
                                return;
                            },
                            _=>{
                                log::trace!("Received no coin message, broadcasting message!");
                                self.broadcast(&mut smr_msg).await;
                            }
                        }
                    },
                    _=>{}
                }
            }
        }
        else {
            log::warn!("MAC Verification failed for message {:?}",wrapper_msg.protmsg);
        }
    }
}