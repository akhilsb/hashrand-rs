use std::sync::Arc;

use async_recursion::async_recursion;
use crypto::hash::verf_mac;
use round_based::Msg;
use types::{Round, SyncState, SyncMsg};

use super::{GlowDVRF, WrapperMsg, state_machine::sign::{Sign}};

impl GlowDVRF{
    pub fn check_proposal(&self,wrapper_msg: Arc<WrapperMsg>) -> bool {
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
    pub async fn process(&mut self,wrapper: WrapperMsg){
        log::info!("Received protocol msg: {:?}",wrapper);
        let msg = Arc::new(wrapper.clone());
        if self.check_proposal(msg){
            self.handle_incoming(wrapper.round, wrapper).await;
        }
    }

    pub async fn handle_incoming(&mut self,round:Round, wrapper_msg: WrapperMsg){
        if !self.state.contains_key(&round){
            self.start_round(round).await;
        }
        let sign = self.state.get_mut(&round).unwrap();
        match sign.handle_incoming(Msg{
            sender: wrapper_msg.sender+1,
            receiver:None,
            body:wrapper_msg.protmsg
        }) {
            Ok(x)=>{
                log::info!("Got the following message {:?}",x);
            },
            Err(x) => {
                log::error!("Got the following error message {:?}",x);
            }
        }
        self.empty_queue_and_proceed(round).await;
    }

    #[async_recursion]
    pub async fn start_round(&mut self,round:Round){
        if !self.state.contains_key(&round){
            let mut beacon_msg = self.sign_msg.clone();
            beacon_msg.push_str(round.to_string().as_str());
            log::info!("Signing string {:?}",beacon_msg);
            let glow_bls_state = Sign::new(
                beacon_msg.into_bytes(), 
                self.myid+1, 
                self.num_nodes, 
                self.secret.clone()
            ).unwrap();
            // Send outgoing messages
            self.state.insert(round, glow_bls_state);
            self.empty_queue_and_proceed(round).await;
        }
    }

    async fn empty_queue_and_proceed(&mut self, round:Round){
        let glow_bls_state = self.state.get_mut(&round).unwrap();
        let msg_queue = glow_bls_state.message_queue();
        let mut broadcast_msgs = Vec::new();
        while !msg_queue.is_empty(){
            broadcast_msgs.push(msg_queue.pop().unwrap());
            //self.broadcast(msg.body, round).await;
        }
        if glow_bls_state.wants_to_proceed(){
            glow_bls_state.proceed().unwrap();
        }
        // Send outgoing messages
        let msg_queue = glow_bls_state.message_queue();
        while !msg_queue.is_empty(){
            broadcast_msgs.push(msg_queue.pop().unwrap());
            //let msg = msg_queue.pop().unwrap();
        }
        if glow_bls_state.is_finished(){
            let result = glow_bls_state.pick_output().unwrap().unwrap();
            log::info!("Result obtained, the following is the signature: {:?}",result.1.to_bytes(false));
            let cancel_handler = self.sync_send.send(0, SyncMsg { sender: self.myid as usize, state: SyncState::BeaconRecon(round, self.myid as usize, round as usize, result.1.to_bytes(false)), value:0}).await;
            self.add_cancel_handler(cancel_handler);
            self.curr_round = round+1;
            self.start_round(round+1).await;
        }
        for msg in broadcast_msgs.into_iter(){
            self.broadcast(msg.body, round).await;
        }
    }
}