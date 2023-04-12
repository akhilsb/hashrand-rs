use std::collections::{HashMap, HashSet};

use types::{appxcon::{Replica, Msg, ProtMsg}};

use crate::node::{RoundState};

use super::Context;

use async_recursion::async_recursion;

impl Context{
    pub async fn handle_witness(&mut self,vec_rbc_indices:Vec<Replica>, round: u64, witness_sender:Replica, wround: u32){
        let round_state_map = &mut self.round_state;
        log::info!("Received witness message{} {:?} from node {} for round {}",wround,vec_rbc_indices.clone(),witness_sender,round);
        if round_state_map.contains_key(&round){
            let rnd_state = round_state_map.get_mut(&round).unwrap();
            if wround == 1{
                rnd_state.witnesses.insert(witness_sender,vec_rbc_indices.clone());
                self.check_for_ht_witnesses(round).await;    
            }
            else{
                //log::info!("Received witness2 message {:?} from node {} for round {}",vec_rbc_indices.clone(),witness_sender,round);
                rnd_state.witnesses2.insert(witness_sender,vec_rbc_indices.clone());
                self.check_for_ht_witnesses(round).await;
            }
        }
        else{
            // 1. If the protocol did not reach this round yet, create a new roundstate object
            let mut rnd_state = RoundState::new();
            if wround == 1{
                rnd_state.witnesses.insert(witness_sender, vec_rbc_indices);
                round_state_map.insert(round, rnd_state);
            }
            else {
                rnd_state.witnesses2.insert(witness_sender, vec_rbc_indices);
                round_state_map.insert(round, rnd_state);
            }
        }
    }
    
    #[async_recursion]
    pub async fn check_for_ht_witnesses(&mut self,round: u64){
        let round_state_map = &mut self.round_state;
        let rnd_state = round_state_map.get_mut(&round).unwrap();
        let min_threshold = self.num_faults;
        if rnd_state.accepted_vals.len() <= self.num_faults+1{
            return;
        }
        let mut node_r_values:HashMap<Replica,u64> = HashMap::default();
        let high_threshold = rnd_state.accepted_vals.len() - self.num_faults-1;
        let mut accepted_witnesses:HashSet<Replica> = HashSet::default();
        if rnd_state.wround == 1{
            for (replica,rbc_sets) in rnd_state.witnesses.clone().into_iter(){
                let check = rbc_sets.iter().all(|item| rnd_state.terminated_rbcs.contains(item));
                if check {
                    accepted_witnesses.insert(replica);
                }
            }
        }
        else{
            for (replica,rbc_sets) in rnd_state.witnesses2.clone().into_iter(){
                let check = rbc_sets.iter().all(|item| rnd_state.terminated_rbcs.contains(item));
                if check {
                    // if node is a witness2, add value to the set of accepted w2 values
                    let vec_node_values:Vec<u64> = rbc_sets.iter().map(|x| rnd_state.node_msgs.get(x).unwrap().value.clone()).collect();
                    node_r_values.insert(replica, (vec_node_values.get(min_threshold).unwrap()+vec_node_values.get(high_threshold).unwrap())/2);
                    log::info!("Witness 2 message from node {}, with indices: {:?}, round {}, value {:?}",replica,rbc_sets,round,node_r_values);
                    accepted_witnesses.insert(replica);
                }
            }
        }
        if accepted_witnesses.len() >= self.num_nodes-self.num_faults{
            if self.round == 0{
                // Round estimation protocol to be run, skip the rest of the protocol
                let mut value_set = Vec::new();
                for replica in accepted_witnesses.iter(){
                    let mut vals_witness = Vec::new();
                    for acc_rep in rnd_state.witnesses.get(replica).unwrap(){
                        vals_witness.push(rnd_state.node_msgs.get(acc_rep).unwrap().value);
                    }
                    vals_witness.sort();
                    log::info!("First n-f values accepted by node {} are {:?}",replica,vals_witness.clone());
                    let median_index = (vals_witness.len()-1)/2;
                    value_set.push(vals_witness[median_index]);
                }
                value_set.sort();
                log::info!("Medians of n-f accepted values by each node {:?}",value_set);
                //let rounds_to_run = (((value_set.last().unwrap() - value_set.first().unwrap())/self.delta) as f64).log2().ceil().round() as u64; 
                // if rounds_to_run == 0{
                //     self.rounds_delta= 1;
                // }
                // else{
                //     self.rounds_delta= rounds_to_run;
                // }
                self.value = value_set.get((value_set.len()-1)/2).unwrap().clone();
                //log::info!("Number of rounds to run: {} with starting value: {}",rounds_to_run,self.value);
                self.round += 1;
                self.start_rbc(false).await;
                return;
            }
            // Update value for next round
            rnd_state.accepted_vals.sort();
            if rnd_state.wround == 1{
                let nr_val = (rnd_state.accepted_vals.get(min_threshold).unwrap() 
                    + rnd_state.accepted_vals.get(high_threshold).unwrap())/2;
                // Update round
                self.value = nr_val;
                if self.round == self.rounds_delta{
                    // Sub-protocol terminated, start BAA
                    // let mut term_values:Vec<u64> = rnd_state.term_values.iter().map(|(_x,y)| y.clone()).collect();
                    // term_values.sort();
                    // let val_nxt_rnd = term_values[term_values.len()/2];
                    //self.value = val_nxt_rnd;
                    log::info!("Sub-protocol terminated, starting BAA");
                    let mut transmit_vector = Vec::new();
                    transmit_vector.push((0,self.value));
                    self.rounds_bin = self.round + self.rounds_bin;
                    self.round = round+1;
                    self.start_baa(transmit_vector,self.round).await;
                }
                else{
                    log::info!("Protocol completed round {} with new round value {} ",self.round,self.value);
                    self.round = round+1;
                    self.start_rbc(false).await;
                }
                // broadcast witness2 message
                // rnd_state.wround = 2;
                // // Send WITNESS2 Message
                // log::info!("Sent WITNESS2 message for round {}",self.round);
                // let vec_rbcs = Vec::from_iter(rnd_state.terminated_rbcs.clone().into_iter());
                // let witness_msg = ProtMsg::WITNESS2(
                //     vec_rbcs.clone(), 
                //     self.myid,
                //     self.round
                // );
                //self.broadcast(witness_msg.clone()).await;
                //self.handle_witness(vec_rbcs, self.round, self.myid, 2).await;
            }
            else if rnd_state.wround == 2{
                self.round = self.round+1;
                let mut range:Vec<u64> = node_r_values.values().into_iter().map(|x| x.clone()).collect();
                range.sort();
                log::info!("Sorted range in witness2 for round {} is {:?}",round,range);
                let delta = range.last().unwrap() - range.first().unwrap();
                if rnd_state.term_values.len() >= min_threshold+1{
                    // Sub-protocol terminated, start BAA
                    let mut term_values:Vec<u64> = rnd_state.term_values.iter().map(|(_x,y)| y.clone()).collect();
                    term_values.sort();
                    let val_nxt_rnd = term_values[term_values.len()/2];
                    self.value = val_nxt_rnd;
                    log::info!("Sub-protocol terminated, starting BAA");
                    let mut transmit_vector = Vec::new();
                    transmit_vector.push((0,self.value));
                    self.rounds_bin = self.round + self.rounds_bin;
                    self.start_baa(transmit_vector,self.round).await;
                }
                else{
                    if delta > self.delta/2{
                        // Initiate next RBCInit now
                        log::info!("Protocol completed round {} with new round value {} ",self.round,self.value);
                        self.start_rbc(false).await;
                    }
                    else{
                        // Initiate next RBCInit now
                        log::info!("Protocol completed round {} with new round value {} ",self.round,self.value);
                        self.start_rbc(true).await;
                    }
                }
                //let cancel_handler = self.sync_send.send(0, SyncMsg{sender:self.myid,state:types::SyncState::COMPLETED}).await;
                //self.add_cancel_handler(cancel_handler);
            }
        }
    }
    
    pub async fn start_rbc(&mut self,term:bool){
        let msg = Msg{
            value: self.value,
            origin: self.myid,
            round: self.round,
            rnd_estm: term,
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

    pub async fn estimate_rounds(&mut self, ls_rbcs: Vec<Replica>){
        let msg = Msg{
            value: self.value,
            origin: self.myid,
            round: self.round,
            rnd_estm: true,
            message: ls_rbcs
        };
        //self.rnd_estm_state.witness_sent = true;
        log::info!("Send RBCInit messages from node {:?} for round {}",self.myid,self.round);
        self.broadcast(ProtMsg::RBCInit(msg.clone(), self.myid)).await;
        self.process_rbc_init(msg.clone()).await;
    }
}