use std::{collections::HashSet};

use async_recursion::async_recursion;
use types::appxcon::{Msg, Replica, ProtMsg};

use super::{Context, RoundState};

impl Context{
    #[async_recursion]
    pub async fn process_echo(&mut self, main_msg:Msg, echo_sender:Replica){
        let rbc_originator = main_msg.origin;
        let round_state_map = &mut self.round_state;
        // Highly unlikely that the node will get an echo before rbc_init message
        log::info!("Received ECHO message {:?}",main_msg.clone());
        if round_state_map.contains_key(&main_msg.round){
            // 1. Add echos to the round state object
            let rnd_state = round_state_map.get_mut(&main_msg.round).unwrap();
            // If RBC already terminated, do not consider this RBC
            if rnd_state.terminated_rbcs.contains(&rbc_originator){
                return;
            }
            match rnd_state.echos.get_mut(&rbc_originator) {
                None => {
                    let mut echoset = HashSet::default();
                    echoset.insert(echo_sender);
                    rnd_state.echos.insert(rbc_originator, echoset);
                },
                Some(x) => {
                    x.insert(echo_sender);
                }
            }
            let echos = rnd_state.echos.get_mut(&rbc_originator).unwrap();
            // 2. Check if echos reached the threshold, init already received, and round number is matching
            log::debug!("ECHO check: Round equals: {}, echos.len {}, contains key: {}"
            ,self.round == main_msg.round,echos.len(),rnd_state.node_msgs.contains_key(&rbc_originator));
            if echos.len() == self.num_nodes-self.num_faults && 
                rnd_state.node_msgs.contains_key(&rbc_originator){
                // Broadcast readys, otherwise, just wait longer
                self.broadcast(ProtMsg::READY(main_msg.clone(),main_msg.origin, self.myid)).await;
                //msgs_to_be_sent.push(ProtMsg::READY(main_msg.clone(),main_msg.origin, self.myid));
                self.process_ready(main_msg, self.myid).await;
            }
        }
        else{
            let mut rnd_state = create_roundstate(rbc_originator, &main_msg, self.myid);
            rnd_state.echos.get_mut(&rbc_originator).unwrap().insert(echo_sender);
            // Do not send echo yet, echo needs to come through from RBC_INIT
            round_state_map.insert(main_msg.round, rnd_state);
        }
    }
}

pub fn create_roundstate(sender:Replica,main_msg:&Msg,curr_id:Replica)->RoundState{
    // 1. If the protocol did not reach this round yet, create a new roundstate object
    let mut rnd_state = RoundState::new();
    // 2. Insert sender message
    rnd_state.node_msgs.insert(sender, main_msg.clone());
    // 3. Create echo set, add your own vote to it
    let mut echo_set:HashSet<Replica> = HashSet::default();
    // 4. Create ready set, add your own vote to it
    let mut ready_set:HashSet<Replica> = HashSet::default();
    echo_set.insert(curr_id);
    ready_set.insert(curr_id);
    // 5. Add sets to the roundstate
    rnd_state.echos.insert(sender, echo_set);
    rnd_state.readys.insert(sender, ready_set);
    rnd_state
}