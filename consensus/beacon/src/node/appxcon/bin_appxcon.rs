use std::{time::{SystemTime}, collections::HashMap};

use async_recursion::async_recursion;
use types::{beacon::{ CoinMsg, Round}, Replica};

use crate::node::{Context, CTRBCState, appxcon::RoundState};

impl Context{
    #[async_recursion]
    pub async fn process_baa_echo(self: &mut Context, msgs: HashMap<Round,Vec<(Replica,Vec<u8>)>>, echo_sender:Replica, round:Round){
        let now = SystemTime::now();
        let mut send_valmap_echo1 = HashMap::default();
        let mut send_valmap_echo2 = HashMap::default();
        for (round_iter,values) in msgs.into_iter(){
            if !self.round_state.contains_key(&round_iter){
                let rbc_new_state = CTRBCState::new(self.secret_domain.clone());
                self.round_state.insert(round_iter, rbc_new_state);
            }
            let rbc_state = self.round_state.get_mut(&round_iter).unwrap();
            log::info!("Received ECHO1 message from node {} with content {:?} for round {}",echo_sender,values.clone(),round);
            if rbc_state.round_state.contains_key(&round){
                let rnd_state = rbc_state.round_state.get_mut(&round).unwrap();
                let (echo1_msgs,echo2_msgs) = rnd_state.add_echo(values, echo_sender, self.num_nodes, self.num_faults);
                if rnd_state.term_vals.len() == self.num_nodes {
                    log::info!("All n instances of Binary AA terminated for round {}, checking for termination",round);
                    if self.check_termination(round){
                        // Begin next round
                        self.start_new_round(round).await;
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
            self.broadcast(CoinMsg::BinaryAAEcho(send_valmap_echo1.clone(), self.myid, round)).await;
            self.process_baa_echo(send_valmap_echo1, self.myid, round).await;
        }
        if send_valmap_echo2.len() > 0{
            self.broadcast(CoinMsg::BinaryAAEcho2(send_valmap_echo2.clone(), self.myid, round)).await;
            self.process_baa_echo2(send_valmap_echo2, self.myid, round).await;
        }
    }

    pub async fn process_baa_echo2(self: &mut Context, msgs: HashMap<Round,Vec<(Replica,Vec<u8>)>>, echo2_sender:Replica, round:u32){
        let now = SystemTime::now();
        for (round_iter,vals) in msgs.into_iter(){
            if !self.round_state.contains_key(&round_iter){
                let rbc_new_state = CTRBCState::new(self.secret_domain.clone());
                self.round_state.insert(round_iter, rbc_new_state);
            }
            let rbc_state = self.round_state.get_mut(&round_iter).unwrap();
            if rbc_state.round_state.contains_key(&round_iter){
                let rnd_state = rbc_state.round_state.get_mut(&round_iter).unwrap();
                rnd_state.add_echo2(vals, echo2_sender, self.num_nodes, self.num_faults);
                if rnd_state.term_vals.len() == self.num_nodes {
                    log::info!("All n instances of Binary AA terminated for round {}, starting round {}",round,round+1);
                    //let vec_vals:Vec<(Replica,Vec<u8>)> = rnd_state.term_vals.clone().into_iter().map(|(rep,val)| (rep,BigInt::to_signed_bytes_be(&val))).collect();
                    self.add_benchmark(String::from("process_baa_echo2"), now.elapsed().unwrap().as_nanos());
                    if self.check_termination(round){
                        // Begin next round
                        self.start_new_round(round).await;
                    }
                    return;
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
        if round <= self.rounds_aa + 1{
            round_begin = 0;
        }
        else{
            round_begin = round-self.rounds_aa-1;
        }
        let mut can_begin_next_round = true;
        for round_iter in round_begin..round{
            if self.round_state.contains_key(&round_iter){
                let rbc_state = self.round_state.get(&round_iter).unwrap();
                if rbc_state.round_state.contains_key(&round){
                    if rbc_state.round_state.get(&round).unwrap().term_vals.len() < self.num_nodes{
                        can_begin_next_round = false;
                    }
                }
            }
        }
        can_begin_next_round
    }
}