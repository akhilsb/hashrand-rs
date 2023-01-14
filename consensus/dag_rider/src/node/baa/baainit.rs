use std::{time::SystemTime};

use async_recursion::async_recursion;
use num_bigint::{BigInt};
use num_traits::{pow, ToPrimitive};
use types::{hash_cc::{ CoinMsg, SMRMsg}, Replica};

use crate::node::{Context, CoinRoundState,BatchVSSState};
impl Context{
    #[async_recursion]
    pub async fn process_baa_echo(self: &mut Context, msgs: Vec<(Replica,Vec<u8>)>, echo_sender:Replica, round:u32, smr_msg:&mut SMRMsg){
        let now = SystemTime::now();
        let coin_round = get_baa_round(round, self.rounds_aa);
        log::debug!("Received ECHO1 message from node {} with content {:?} for round {}",echo_sender,msgs,round);
        let baa_round:u32 = coin_round.try_into().unwrap();
        let round_state_map = &mut self.cc_round_state;
        smr_msg.coin_msg = CoinMsg::NoMessage();
        if round_state_map.contains_key(&baa_round){
            let rnd_state = round_state_map.get_mut(&baa_round).unwrap();
            let (echo1_msgs,echo2_msgs) = rnd_state.add_echo(msgs, echo_sender, self.num_nodes, self.num_faults);
            if rnd_state.term_vals.len() == self.num_nodes {
                log::debug!("All n instances of Binary AA terminated for round {}, starting round {}",round,round+1);
                rnd_state.complete_round();
                smr_msg.coin_msg = CoinMsg::NoMessage();
                self.broadcast(&mut smr_msg.clone()).await;
                if self.dag_state.new_round(self.num_nodes, self.num_faults,self.curr_round){
                    // propose next block, but send secret share along
                    // Change round only here
                    // Maintain only one round number throughout, use that round number to derive round numbers for other apps
                    self.curr_round+=1;
                    self.start_rbc().await;
                }
                // Start BAA next round with n-parallel reliable broadcast
                //let vec_vals:Vec<(Replica,BigInt)> = rnd_state.term_vals.clone().into_iter().map(|(rep,val)| (rep,val)).collect();
                //start_baa(self, vec_vals, round+1).await;
                return;
            }
            if echo1_msgs.len() > 0{
                smr_msg.coin_msg = CoinMsg::BinaryAAEcho(echo1_msgs.clone(), self.myid, round);
                //self.broadcast(&mut smr_msg.clone()).await;
                self.process_baa_echo(echo1_msgs, self.myid, round,&mut smr_msg.clone()).await;
            }
            if echo2_msgs.len() > 0{
                smr_msg.coin_msg = CoinMsg::BinaryAAEcho2(echo2_msgs.clone(), self.myid, round);
                //self.broadcast(&mut smr_msg.clone()).await;
                self.process_baa_echo2(echo2_msgs, self.myid, round,&mut smr_msg.clone()).await;
            }
            self.broadcast(&mut smr_msg.clone()).await;
        }
        else{
            let rnd_state  = CoinRoundState::new_with_echo(msgs,echo_sender);
            smr_msg.coin_msg = CoinMsg::NoMessage();
            round_state_map.insert(baa_round, rnd_state);
        }
        self.add_benchmark(String::from("process_baa_echo"), now.elapsed().unwrap().as_nanos());
    }

    pub async fn process_baa_echo2(self: &mut Context, msgs: Vec<(Replica,Vec<u8>)>, echo2_sender:Replica, round:u32, _smr_msg:&mut SMRMsg){
        let now = SystemTime::now();
        let coin_round = get_baa_round(round, self.rounds_aa);
        log::debug!("Received ECHO2 message from node {} with content {:?} for round {}",echo2_sender,msgs,round);
        if coin_round<0{
            return;
        }
        let baa_round:u32 = coin_round.try_into().unwrap();
        let round_state_map = &mut self.cc_round_state;
        _smr_msg.coin_msg = CoinMsg::NoMessage();
        if round_state_map.contains_key(&baa_round){
            let rnd_state = round_state_map.get_mut(&baa_round).unwrap();
            rnd_state.add_echo2(msgs, echo2_sender, self.num_nodes, self.num_faults);
            if rnd_state.term_vals.len() == self.num_nodes {
                log::debug!("All n instances of Binary AA terminated for round {}, starting round {}",round,round+1);
                rnd_state.complete_round();
                // definitely complete the broadcast phase
                self.broadcast(&mut _smr_msg.clone()).await;
                if self.dag_state.new_round(self.num_nodes, self.num_faults,self.curr_round){
                    // propose next block, but send secret share along
                    // Change round only here
                    // Maintain only one round number throughout, use that round number to derive round numbers for other apps
                    self.curr_round+=1;
                    self.start_rbc().await;
                }
                //let vec_vals:Vec<(Replica,BigInt)> = rnd_state.term_vals.clone().into_iter().map(|(rep,val)| (rep,val)).collect();
                //self.add_benchmark(String::from("process_baa_echo2"), now.elapsed().unwrap().as_nanos());
                // Start BAA later, along with future RBC round
                //start_baa(self, vec_vals, round+1).await;
                return;
            }
        }
        else{
            let rnd_state  = CoinRoundState::new_with_echo2(msgs,echo2_sender);
            round_state_map.insert(baa_round, rnd_state);
        }
        self.broadcast(&mut _smr_msg.clone()).await;
        self.add_benchmark(String::from("process_baa_echo2"), now.elapsed().unwrap().as_nanos());
    }

    pub async fn start_baa(self: &mut Context,round:u32)-> Option<CoinMsg>{
        let now = SystemTime::now();
        // Translate DAG Round to the coin round here
        // Rounds start from zero!
        // DAG-Round to Coin Round: We run a coin round every 2,3,4th rounds of a wave. The first round of every wave is 
        // taken by the invocation and construction of the common coin. 
        let rounds_for_coin = 4+ (self.rounds_aa*4)/3;
        let mod_round = round % rounds_for_coin;
        let wave_num:i32 = (mod_round/4).try_into().unwrap();
        let wave_round:i32 = (mod_round%4).try_into().unwrap();
        log::debug!("Received request to start BAA for round {} with wave_num:{},{}, max: {}",round, wave_num,wave_round,rounds_for_coin);
        // First wave contributes 2 rounds to BAA from coin, each wave contributes 3 rounds for coin, current wave contributes 1/2 in round 3 and 4. 
        let coin_round:i32 = (wave_num-1)*3+(wave_round-1);
        if coin_round < 0{
            return None;
        }
        if coin_round == 0{
            // Round Zero => Start binary approximate agreement
            let terminated_secrets = self.cur_batchvss_state.terminated_secrets.clone();
            let mut transmit_vector:Vec<(Replica,BigInt)> = Vec::new();
            let rounds = self.rounds_aa;
            for i in 0..self.num_nodes{
                if !terminated_secrets.contains(&i) {
                    let zero = BigInt::from(0);
                    transmit_vector.push((i,zero));
                }
                else {
                    let max = BigInt::from(2);
                    let max_power = pow(max, rounds as usize);
                    transmit_vector.push((i,max_power));
                }
            }
            let transmit_vec:Vec<(Replica,Vec<u8>)> = transmit_vector.into_iter().map(|(rep,val)| (rep,val.to_bytes_be().1)).collect();
            let prot_msg = CoinMsg::BinaryAAEcho(transmit_vec.clone(), self.myid,round);
            return Some(prot_msg);
        }
        else{
            if coin_round.to_u32().unwrap() == self.rounds_aa-1{
                log::info!("Last round of approximate agreement for batch of coins, terminating approx agreement");
                // Last round for approximate agreement, generate the coin here
                let appxcon_map = &mut self.cur_batchvss_state.nz_appxcon_rs;
                let coin_round = (coin_round-1).try_into().unwrap();
                let rnd_state = self.cc_round_state.get(&coin_round).unwrap();
                if rnd_state.completed{
                    let round_vecs:Vec<(Replica,BigInt)> = rnd_state.term_vals.clone().into_iter().map(|(rep,val)|(rep,val)).collect();
                    log::debug!("Approximate Agreement Protocol terminated with values {:?}",round_vecs.clone());
                    // Reconstruct values
                    let mapped_rvecs:Vec<(Replica,BigInt)> = 
                        round_vecs.clone().into_iter()
                        .filter(|(_rep,num)| *num > BigInt::from(0i32))
                        .collect();
                    for (rep,val) in mapped_rvecs.into_iter(){
                        appxcon_map.insert(rep, (val,false,BigInt::from(0i32)));
                    }
                    // Transfer current state to previous state
                    self.prev_batchvss_state = self.cur_batchvss_state.clone();
                    self.cur_batchvss_state = BatchVSSState::new(self.secret_domain.clone());
                }
                None
            }
            else{
                let coin_round = (coin_round-1).try_into().unwrap();
                let rnd_state = self.cc_round_state.get(&coin_round).unwrap();
                //log::debug!("Round State: {:?}",self.cc_round_state);
                if rnd_state.completed{
                    // Start new round with old round's data
                    let vec_vals:Vec<(Replica,BigInt)> = rnd_state.term_vals.clone().into_iter().map(|(rep,val)| (rep,val)).collect();
                    let transmit_vec:Vec<(Replica,Vec<u8>)> = vec_vals.into_iter().map(|(rep,val)| (rep,val.to_bytes_be().1)).collect();
                    let prot_msg = CoinMsg::BinaryAAEcho(transmit_vec.clone(), self.myid,round);
                    //process_baa_echo(self, transmit_vec.clone(), self.myid, round).await;
                    self.add_benchmark(String::from("start_baa"), now.elapsed().unwrap().as_nanos());
                    Some(prot_msg)
                }
                else {
                    None
                }
            }
        }
        // self.curr_round = round;
        // if self.curr_round == self.rounds_aa{
        //     let appxcon_map = &mut self.batchvss_state.nz_appxcon_rs;
        //     log::debug!("Approximate Agreement Protocol terminated with values {:?}",round_vecs.clone());
        //     // Reconstruct values
        //     let mapped_rvecs:Vec<(Replica,BigInt)> = 
        //         round_vecs.clone().into_iter()
        //         .filter(|(_rep,num)| *num > BigInt::from(0i32))
        //         .collect();
        //     for (rep,val) in mapped_rvecs.into_iter(){
        //         appxcon_map.insert(rep, (val,false,BigInt::from(0i32)));
        //     }
        //     send_batchreconstruct(self,0).await;
        //     return;
        // }
        
        //log::debug!("Broadcasted message {:?}",prot_msg);
    }
}

pub fn get_baa_round(dag_round:u32, max_rounds:u32)->i32{
    let rounds_for_coin = 4+ (max_rounds*4)/3;
    let mod_round = dag_round % rounds_for_coin;
    let wave_num:i32 = (mod_round/4).try_into().unwrap();
    let wave_round:i32 = (mod_round%4).try_into().unwrap();
    // First wave contributes 2 rounds to BAA from coin, each wave contributes 3 rounds for coin, current wave contributes 1/2 in round 3 and 4. 
    let coin_round:i32 = (wave_num-1)*3+(wave_round-1);
    coin_round
}