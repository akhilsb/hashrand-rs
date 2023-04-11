use types::{appxcon::{Replica, Msg, ProtMsg}, SyncMsg};

use crate::node::{RoundState};

use super::Context;

use async_recursion::async_recursion;

impl Context{
    pub async fn handle_witness(&mut self,vec_rbc_indices:Vec<Replica>, round: u64, witness_sender:Replica){
        let round_state_map = &mut self.round_state;
        log::info!("Received witness message {:?} from node {} for round {}",vec_rbc_indices.clone(),witness_sender,round);
        if round_state_map.contains_key(&round){
            let rnd_state = round_state_map.get_mut(&round).unwrap();
            rnd_state.witnesses.insert(witness_sender,vec_rbc_indices.clone());
            self.check_for_ht_witnesses(round).await;
        }
        else{
            // 1. If the protocol did not reach this round yet, create a new roundstate object
            let mut rnd_state = RoundState::new();
            rnd_state.witnesses.insert(witness_sender, vec_rbc_indices);
            round_state_map.insert(round, rnd_state);
        }
    }
    
    #[async_recursion]
    pub async fn check_for_ht_witnesses(&mut self, round:u64){
        let round_state_map = &mut self.round_state;
        let rnd_state = round_state_map.get_mut(&round).unwrap();
    
        let mut i = 0;
        let min_threshold = self.num_faults;
        if rnd_state.accepted_vals.len() <= self.num_faults+1{
            return;
        }
        let high_threshold = rnd_state.accepted_vals.len() - self.num_faults-1;
        for (_replica,rbc_sets) in rnd_state.witnesses.clone().into_iter(){
            let check = rbc_sets.iter().all(|item| rnd_state.terminated_rbcs.contains(item));
            if check {
                i = i+1;
            }
        }
        if i >= self.num_nodes-self.num_faults{
            // Update value for next round
            rnd_state.accepted_vals.sort();
            let nr_val = (rnd_state.accepted_vals.get(min_threshold).unwrap() 
            + rnd_state.accepted_vals.get(high_threshold).unwrap())/2;
            // Update round
            self.value = nr_val;
            self.round = round+1;
            // write round estimation protocol
            if self.round <= 10{
                // Initiate next RBCInit now
                log::info!("Protocol completed round {} with new round value {} ",self.round,self.value);
                self.start_rbc().await;
            }
            else {
                log::info!("Protocol terminated value {} ",self.value);
                let cancel_handler = self.sync_send.send(0, SyncMsg{sender:self.myid,state:types::SyncState::COMPLETED,value:self.value}).await;
                self.add_cancel_handler(cancel_handler);
            }
        }
    }
    
    pub async fn start_rbc(&mut self){
        let msg = Msg{
            value: self.value,
            origin: self.myid,
            round: self.round,
            rnd_estm: false,
            message: Vec::new()
        };
        log::info!("Send RBCInit messages from node {:?} for round {}",self.myid,self.round);
        // Add roundstate for round zero
        // if self.round_state.contains_key(&self.round){
        //     process_rbc_init(self,msg.clone()).await;
        // }
        // else{
        //     let rnd_state = create_roundstate(self.myid, &msg, self.myid);
        //     self.round_state.insert(self.round, rnd_state);
        // }
    
        // if self.myid == 3{
        //     return;
        // }
        self.broadcast(ProtMsg::RBCInit(msg.clone(), self.myid)).await;
        self.process_rbc_init(msg.clone()).await;
    }
}