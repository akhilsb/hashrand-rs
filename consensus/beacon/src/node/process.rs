use std::{sync::Arc};

use crypto::hash::{verf_mac};
use types::{beacon::{WrapperMsg, CoinMsg}};

use super::Context;
//use async_recursion::async_recursion;


/*
    Beacon protocol using hash functions. The protocol proceeds in the following manner. 
    Every node secret shares a randomly picked secret using a weak Verifiable Secret Sharing (VSS) protocol.
    Later, nodes run gather protocol on the secrets shared by individual nodes. 
    Using the terminated shares, the nodes run Binary Approximate Agreement (BinAA) protocol on n inputs. 
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
            self.num_messages += 1;
            self.choose_fn(wrapper_msg).await;
        }
        else {
            log::warn!("MAC Verification failed for message {:?}",wrapper_msg.protmsg);
        }
    }

    pub(crate) async fn choose_fn(self: &mut Context, wrapper_msg: WrapperMsg){
        match wrapper_msg.clone().protmsg {
            // Messages related to Cachin-Tessaro's Reliable Broadcast
            CoinMsg::CTRBCInit(beaconmsg,ctr ) =>{
                // need to handle rbc init first or change everything to Cachin Tessaro broadcast?
                self.process_rbcinit(beaconmsg, ctr).await;
            },
            CoinMsg::CTRBCEcho(ctr, root, echo_sender) => {
                self.process_echo(ctr, root, echo_sender).await;
            },
            CoinMsg::CTRBCReady(ctr, root, ready_sender) => {
                self.process_ready(ctr, root, ready_sender).await;
            },
            CoinMsg::CTRBCReconstruct(ctr, root, recon_sender)=>{
                self.process_reconstruct(ctr, root, recon_sender).await;
            },
            // Messages related to the Gather protocol
            CoinMsg::GatherEcho(gather,sender,round) =>{
                self.process_gatherecho(gather.nodes, sender, round).await;
            },
            CoinMsg::GatherEcho2(gather,sender,round) =>{
                self.process_gatherecho2(gather.nodes, sender, round).await;
            },
            // Messages related to Binary Approximate Agreement
            CoinMsg::BinaryAAEcho(msgs, echo_sender, round) =>{
                log::debug!("Received Binary AA Echo1 from node {}",echo_sender);
                self.process_baa_echo(msgs, echo_sender, round).await;
            },
            CoinMsg::BinaryAAEcho2(msgs, echo2_sender, round) =>{
                log::debug!("Received Binary AA Echo2 from node {}",echo2_sender);
                self.process_baa_echo2(msgs, echo2_sender, round).await;
            },
            // Messages related to Beacon Reconstruction
            CoinMsg::BeaconConstruct(shares, share_sender, coin_num, round)=>{
                log::debug!("Received Beacon Construct message from node {} for coin number {} in round {}",share_sender,coin_num,round);
                self.process_secret_shares(shares, share_sender, coin_num, round).await;
            },
            _ => {}
        }
    }

    pub(crate) async fn increment_round(&mut self,round:u32){
        if round>=self.curr_round{
            self.curr_round = round+1;
        }
        else{
            return;
        }
    }
}