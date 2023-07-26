use std::{sync::Arc, collections::HashSet};

use crypto::hash::{verf_mac};
use types::{beacon::{WrapperMsg, CoinMsg}, Round};

use super::HashRand;
//use async_recursion::async_recursion;


/*
    Common coin protocol using hash functions. The protocol proceeds in the following manner. 
    Every node secret shares a randomly picked secret using a Verifiable Secret Sharing protocol.
    Later, nodes run gather protocol on the secrets shared by individual nodes. 
    Using the terminated shares, the nodes run a Bundled Approximate Agreement (BAA) protocol on n inputs. 
    Each node's input i is either 0 or 1 depending on whether the node terminated i's VSS protocol. 
*/
impl HashRand{
    pub fn check_proposal(self:&HashRand,wrapper_msg: Arc<WrapperMsg>) -> bool {
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
    
    pub(crate) async fn process_msg(self: &mut HashRand, wrapper_msg: WrapperMsg){
        log::debug!("Received protocol msg: {:?}",wrapper_msg);
        let msg = Arc::new(wrapper_msg.clone());
        if self.check_proposal(msg){
            self.num_messages += 1;
            self.choose_fn(wrapper_msg).await;
            // if self.curr_round == wrapper_msg.round || wrapper_msg.round == 25000{
            //     self.choose_fn(wrapper_msg).await;
            // }
            // else if wrapper_msg.round < self.curr_round{
            //     // older messages to round 30000
            //     if self.wrapper_msg_queue.contains_key(&30000){
            //         let queue_vec = self.wrapper_msg_queue.get_mut(&30000).unwrap();
            //         queue_vec.push(wrapper_msg);
            //     }
            //     else{
            //         let mut queue_vec = Vec::new();
            //         queue_vec.push(wrapper_msg.clone());
            //         self.wrapper_msg_queue.insert(30000, queue_vec);
            //     }
            // }
            // else {
            //     if self.wrapper_msg_queue.contains_key(&wrapper_msg.round){
            //         let queue_vec = self.wrapper_msg_queue.get_mut(&wrapper_msg.round).unwrap();
            //         queue_vec.push(wrapper_msg);
            //     }
            //     else {
            //         let mut queue_vec = Vec::new();
            //         queue_vec.push(wrapper_msg.clone());
            //         self.wrapper_msg_queue.insert(wrapper_msg.round, queue_vec);
            //     }
            // }
        }
        else {
            log::warn!("MAC Verification failed for message {:?}",wrapper_msg.protmsg);
        }
    }

    pub(crate) async fn choose_fn(self: &mut HashRand, wrapper_msg: WrapperMsg){
        match wrapper_msg.clone().protmsg {
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
            CoinMsg::GatherEcho(gather,sender,round) =>{
                self.process_gatherecho(gather.nodes, sender, round).await;
            },
            CoinMsg::GatherEcho2(gather,sender,round) =>{
                self.process_gatherecho2(gather.nodes, sender, round).await;
            },
            CoinMsg::BinaryAAEcho(msgs, echo_sender, round) =>{
                log::debug!("Received Binary AA Echo1 from node {}",echo_sender);
                self.process_baa_echo(msgs, echo_sender, round).await;
            },
            CoinMsg::BinaryAAEcho2(msgs, echo2_sender, round) =>{
                log::debug!("Received Binary AA Echo2 from node {}",echo2_sender);
                self.process_baa_echo2(msgs, echo2_sender, round).await;
            },
            CoinMsg::BeaconConstruct(shares, share_sender, coin_num, round)=>{
                log::debug!("Received Beacon Construct message from node {} for coin number {} in round {}",share_sender,coin_num,round);
                self.process_secret_shares(shares, share_sender, coin_num, round).await;
            },
            CoinMsg::BeaconValue(asking_index,sender, beacon_val)=>{
                log::debug!("Received beacon value {} from node {} for index {}",beacon_val,sender,asking_index);
                if self.coin_request_mapping.contains_key(&asking_index){
                    let asking_index_state = self.coin_request_mapping.get_mut(&asking_index).unwrap();
                    asking_index_state.1.insert(sender);
                    if asking_index_state.1.len() == self.num_faults + 1{
                        // This request has been reconstructed already, return value
                        if let Err(e) = self.coin_send_channel.send((asking_index,beacon_val)).await {
                            log::warn!(
                                "Failed to beacon {} to the consensus: {}",
                                asking_index, e
                            );
                        }
                    }
                }
                else{
                    let mut rep_index_set = HashSet::default();
                    rep_index_set.insert(sender);
                    self.coin_request_mapping.insert(asking_index, (beacon_val,rep_index_set));
                }
            }
        }
    }

    pub(crate) async fn increment_round(&mut self, round:Round){
        if round>=self.curr_round{
            self.curr_round = round+1;
        }
        else{
            return;
        }
    }
}