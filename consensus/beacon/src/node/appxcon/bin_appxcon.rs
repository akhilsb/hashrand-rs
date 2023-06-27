use std::{time::{SystemTime}, collections::HashMap};

use async_recursion::async_recursion;
use num_bigint::BigInt;
use types::{beacon::{ CoinMsg, Round}, Replica, SyncMsg, SyncState};

use crate::node::{HashRand, CTRBCState, appxcon::RoundState};

impl HashRand{
    #[async_recursion]
    pub async fn process_baa_echo(self: &mut HashRand, msgs: Vec<(Round,Vec<(Replica,Vec<u8>)>)>, echo_sender:Replica, round:Round){
        let now = SystemTime::now();
        let mut send_valmap_echo1:HashMap<u32, Vec<(Replica, Vec<u8>)>> = HashMap::default();
        let mut send_valmap_echo2:HashMap<u32, Vec<(Replica, Vec<u8>)>> = HashMap::default();
        if round < self.curr_round{
            log::warn!("Older message received, protocol advanced forward, ignoring Binary AA ECHO message");
            return;
        }
        log::info!("Received ECHO1 message from node {} with content {:?} for round {}",echo_sender,msgs,round);
        for (round_iter,values) in msgs.into_iter(){
            if !self.round_state.contains_key(&round_iter){
                let rbc_new_state = CTRBCState::new(self.secret_domain.clone(),self.num_nodes);
                self.round_state.insert(round_iter, rbc_new_state);
            }
            let rbc_state = self.round_state.get_mut(&round_iter).unwrap();
            if rbc_state.round_state.contains_key(&round){
                let rnd_state = rbc_state.round_state.get_mut(&round).unwrap();
                let (echo1_msgs,echo2_msgs) = rnd_state.add_echo(values, echo_sender, self.num_nodes, self.num_faults);
                if rnd_state.term_vals.len() == rbc_state.committee.len() {
                    log::info!("All instances of Binary AA terminated for round {}, checking for termination related to round {}",round,round_iter);
                    if self.check_termination(round){
                        // Begin next round
                        self.next_round_begin(round).await;
                    }
                    //let _vec_vals:Vec<(Replica,Vec<u8>)> = rnd_state.term_vals.clone().into_iter().map(|(rep,val)| (rep,BigInt::to_signed_bytes_be(&val))).collect();
                    // start directly from here
                    //send_valmap.insert(round_iter, vec_vals);
                    return;
                }
                if echo1_msgs.len() > 0{
                    // self.broadcast(CoinMsg::BinaryAAEcho(echo1_msgs.clone(), self.myid, round)).await;
                    // self.process_baa_echo( echo1_msgs, self.myid, round).await;
                    send_valmap_echo1.insert(round_iter, echo1_msgs);
                }
                if echo2_msgs.len() > 0{
                    // self.broadcast(CoinMsg::BinaryAAEcho2(echo2_msgs.clone(), self.myid, round)).await;
                    // self.process_baa_echo2( echo2_msgs, self.myid, round).await;
                    send_valmap_echo2.insert(round_iter, echo2_msgs);
                }
            }
            else{
                let rnd_state  = RoundState::new_with_echo(values,echo_sender);
                rbc_state.round_state.insert(round, rnd_state);
            }
            self.add_benchmark(String::from("process_baa_echo"), now.elapsed().unwrap().as_nanos());
        }
        if send_valmap_echo1.len() > 0{
            let mut vec_transmit = Vec::new();
            for (round,val_map) in send_valmap_echo1.into_iter(){
                vec_transmit.push((round,val_map));
            }
            self.broadcast(CoinMsg::BinaryAAEcho(vec_transmit.clone(), self.myid, round),round).await;
            self.process_baa_echo(vec_transmit, self.myid, round).await;
        }
        if send_valmap_echo2.len() > 0{
            let mut vec_transmit = Vec::new();
            for (round,val_map) in send_valmap_echo2.into_iter(){
                vec_transmit.push((round,val_map));
            }
            self.broadcast(CoinMsg::BinaryAAEcho2(vec_transmit.clone(), self.myid, round),round).await;
            self.process_baa_echo2(vec_transmit, self.myid, round).await;
        }
    }

    pub async fn process_baa_echo2(self: &mut HashRand, msgs: Vec<(Round,Vec<(Replica,Vec<u8>)>)>, echo2_sender:Replica, round:u32){
        let now = SystemTime::now();
        if round < self.curr_round{
            log::warn!("Older message received, protocol advanced forward, ignoring Binary AA ECHO message");
            return;
        }
        for (round_iter,vals) in msgs.into_iter(){
            if !self.round_state.contains_key(&round_iter){
                let rbc_new_state = CTRBCState::new(self.secret_domain.clone(),self.num_nodes);
                self.round_state.insert(round_iter, rbc_new_state);
            }
            let rbc_state = self.round_state.get_mut(&round_iter).unwrap();
            if rbc_state.round_state.contains_key(&round_iter){
                let rnd_state = rbc_state.round_state.get_mut(&round).unwrap();
                rnd_state.add_echo2(vals, echo2_sender, self.num_nodes, self.num_faults);
                if rnd_state.term_vals.len() == rbc_state.committee.len() {
                    log::info!("All n instances of Binary AA terminated for round {} related to WSSInit {}",round,round_iter);
                    //let vec_vals:Vec<(Replica,Vec<u8>)> = rnd_state.term_vals.clone().into_iter().map(|(rep,val)| (rep,BigInt::to_signed_bytes_be(&val))).collect();
                    self.add_benchmark(String::from("process_baa_echo2"), now.elapsed().unwrap().as_nanos());
                    if self.check_termination(round){
                        // Begin next round
                        self.next_round_begin(round).await;
                    }
                }
            }
            else{
                let rnd_state  = RoundState::new_with_echo2(vals,echo2_sender);
                rbc_state.round_state.insert(round, rnd_state);
            }
        }
    }

    fn check_termination(&mut self, round:Round)->bool{
        let round_begin;
        if self.curr_round > round{
            return false;
        }
        if round <= self.rounds_aa + 1{
            round_begin = 0;
        }
        else{
            round_begin = round-self.rounds_aa-1;
        }
        let mut can_begin_next_round = true;
        for round_iter in round_begin..round+1{
            if self.round_state.contains_key(&round_iter){
                let rbc_state = self.round_state.get(&round_iter).unwrap();
                if rbc_state.round_state.contains_key(&round){
                    if rbc_state.round_state.get(&round).unwrap().term_vals.len() < rbc_state.committee.len(){
                        log::info!("Cannot begin next BinAA round because BinAA of RBC in round {} did not terminate round {}, term vals: {:?}",round_iter,round,rbc_state.round_state.get(&round).unwrap().term_vals);
                        can_begin_next_round = false;
                    }
                }
                else {
                    log::info!("Cannot begin next BinAA round because BinAA of RBC in round {} does not have state for round {}",round_iter,round);
                    can_begin_next_round = false;
                }
            }
        }
        can_begin_next_round
    }

    #[async_recursion]
    pub async fn next_round_begin(&mut self,round:Round){
        let round_begin;
        if self.curr_round > round{
            return;
        }
        if round <= self.rounds_aa + 1{
            round_begin = 0;
        }
        else{
            round_begin = round-self.rounds_aa-1;
        }
        let mut vec_newround_vals = Vec::new();
        for round_iter in round_begin..round+1{
            if self.round_state.contains_key(&round_iter){
                let rbc_state = self.round_state.get(&round_iter).unwrap();
                if rbc_state.round_state.contains_key(&round){
                    let mut vec_replica_vals = Vec::new();
                    for (rep,value) in rbc_state.round_state.get(&round).unwrap().term_vals.clone().into_iter(){
                        vec_replica_vals.push((rep,value.to_signed_bytes_be()));
                    }
                    vec_newround_vals.push((round_iter,vec_replica_vals));
                }
            }
        }
        if round_begin > 1{
            log::info!("Round_Begin : {}, round state keys: {:?}, keys : {:?}",round_begin,self.round_state.keys(),self.round_state.get(&0).unwrap().round_state.keys());
        }
        else{
            log::info!("Round_Begin : {}, round state keys: {:?},  keys : {:?}",round_begin,self.round_state.keys(),self.round_state.get(&0).unwrap().round_state.keys());
        }
        if round_begin >= 1 && self.round_state.contains_key(&(round_begin-1)) && self.round_state.get(&(round_begin-1)).unwrap().round_state.contains_key(&(round-1)){
            // terminate round_begin and add values to nz_appxcon
            let rbc_state = self.round_state.get_mut(&(round_begin-1)).unwrap();
            //let nz_appxcon_rs = &mut rbc_state.nz_appxcon_rs;
            //log::info!("Approximate Agreement Protocol terminated with values {:?}",round_vecs.clone());
            // Reconstruct values
            let mapped_rvecs:Vec<(Replica,BigInt)> = 
                rbc_state.round_state.get(&(round-1)).unwrap().term_vals.clone().into_iter()
                .filter(|(_rep,num)| *num > BigInt::from(0i32))
                .collect();
            for (rep,val) in mapped_rvecs.into_iter(){
                rbc_state.appx_con_term_vals.insert(rep, val);
                //rbc_state.contribution_map.insert(rep, (val,false,BigInt::from(0i32)));
            }
            log::error!("Terminated beacon for round {} with committee {:?} and appxcon_vals: {:?}, term_secrets {:?}, comm_vector {:?}", round_begin-1,rbc_state.committee,rbc_state.appx_con_term_vals,rbc_state.terminated_secrets,rbc_state.comm_vectors.keys());
            log::info!("Terminated round {}, sending message to syncer",(round_begin-1).clone());
            let cancel_handler = self.sync_send.send(0, SyncMsg { sender: self.myid, state: SyncState::BeaconFin(round_begin-1, self.myid), value:0}).await;
            self.add_cancel_handler(cancel_handler);
            // Start reconstruction
            self.reconstruct_beacon(round_begin-1, 1).await;
            
        }
        if (round+1) % self.frequency == 0{
            // Start next round with batch secret sharing
            self.start_new_round(round, vec_newround_vals).await;
        }
        else{
            // continue binary approximate agreement from here
            //self.curr_round = round + 1;
            let prot_msg = CoinMsg::BinaryAAEcho(vec_newround_vals.clone(), self.myid, round+1);
            self.broadcast(prot_msg.clone(),round+1).await;
            self.process_baa_echo(vec_newround_vals, self.myid, round+1).await;
            self.increment_round().await;
            log::error!("Started round {} with Binary AA",round+1);
        }
    }
}