use std::{sync::Arc};

use crypto::hash::{verf_mac};
use types::{hash_cc::{WrapperMsg, CoinMsg}};

use super::Context;
//use async_recursion::async_recursion;


/*
    Common coin protocol using hash functions. The protocol proceeds in the following manner. 
    Every node secret shares a randomly picked secret using a Verifiable Secret Sharing protocol.
    Later, nodes run gather protocol on the secrets shared by individual nodes. 
    Using the terminated shares, the nodes run a Bundled Approximate Agreement (BAA) protocol on n inputs. 
    Each node's input i is either 0 or 1 depending on whether the node terminated i's VSS protocol. 
*/

impl Context{
    pub fn check_proposal(self:&Context,wrapper_msg: Arc<WrapperMsg>) -> bool {
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
    
    pub(crate) async fn process_msg(self: &mut Context, wrapper_msg: WrapperMsg){
        log::debug!("Received protocol msg: {:?}",wrapper_msg);
        let msg = Arc::new(wrapper_msg.clone());
        if self.check_proposal(msg){
            self.num_messages +=1;
            match wrapper_msg.clone().protmsg {
                CoinMsg::WSSInit(wss_msg)=>{
                    log::debug!("Received WSS init {:?} from node {}",wss_msg.clone(),wss_msg.clone().origin);
                    self.process_wss_init(wss_msg).await;
                },
                CoinMsg::WSSEcho(mr,sec_origin , echo_sender)=>{
                    log::debug!("Received WSS ECHO from node {} for secret from {}",echo_sender,sec_origin);
                    self.process_wssecho( mr,sec_origin,echo_sender).await;
                },
                CoinMsg::WSSReady(mr, sec_origin, ready_sender)=>{
                    log::debug!("Received WSS READY from node {} for secret from {}",ready_sender,sec_origin);
                    self.process_wssready(mr,sec_origin,ready_sender).await;
                },
                CoinMsg::GatherEcho(term_secrets, echo_sender)=>{
                    log::debug!("Received Gather ECHO from node {}",echo_sender);
                    self.process_gatherecho(term_secrets, echo_sender, 1u32).await;
                },
                CoinMsg::GatherEcho2(term_secrets, echo_sender)=>{
                    log::debug!("Received Gather ECHO2 from node {}",echo_sender);
                    self.process_gatherecho(term_secrets, echo_sender, 2u32).await;
                },
                CoinMsg::AppxConCTRBCInit(ctr)=> {
                    // RBC initialized
                    log::debug!("Received RBC init {:?} from node {} for round {}",ctr.clone(),ctr.clone().origin,ctr.clone().round);
                    // Reject all messages from older rounds
                    if self.curr_round <= ctr.round{
                        self.process_rbc_init(ctr).await;
                    }
                },
                CoinMsg::AppxConCTECHO(ctr,echo_sender) =>{
                    // ECHO for main_msg: RBC originated by orig, echo sent by sender
                    // Reject all messages from older rounds and accepted RBCs
                    if self.curr_round <= ctr.round{
                        self.process_echo(ctr, echo_sender).await;
                    }
                },
                CoinMsg::AppxConCTREADY(ctr,ready_sender) =>{
                    // READY for main_msg: RBC originated by orig, echo sent by sender
                    if self.curr_round <= ctr.round{
                        self.process_ready( ctr,ready_sender).await;
                    }
                },
                CoinMsg::AppxConCTReconstruct(ctr,recon_sender) => {
                    // Reconstruct message for RBC
                    if self.curr_round <= ctr.round{
                        self.process_reconstruct_message(ctr,recon_sender).await;
                    }
                },
                CoinMsg::AppxConWitness(term_rbcs, witness_sender, round) => {
                    // WITNESS for main_msg: RBC originated by orig, echo sent by sender
                    if self.curr_round <= round{
                        self.handle_witness(term_rbcs,witness_sender,round).await;
                    }
                },
                CoinMsg::WSSReconstruct(wss_msg, share_sender)=>{
                    log::debug!("Received secret reconstruct message from node {}",share_sender);
                    self.process_reconstruct( wss_msg, share_sender).await;
                },
                _ => {}
            }
        }
        else {
            log::warn!("MAC Verification failed for message {:?}",wrapper_msg.protmsg);
        }
    }
}