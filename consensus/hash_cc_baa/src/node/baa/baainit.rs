use std::{time::{SystemTime, UNIX_EPOCH}};

use async_recursion::async_recursion;
use num_bigint::{BigInt};
use types::{hash_cc::{ CoinMsg}, Replica, SyncMsg, SyncState};

use crate::node::{Context, RoundState};

impl Context{
    #[async_recursion]
    pub async fn process_baa_echo(self: &mut Context, msgs: Vec<(Replica,Vec<u8>)>, echo_sender:Replica, round:u32){
        let now = SystemTime::now();
        let round_state_map = &mut self.round_state;
        if self.curr_round > round{
            return;
        }
        log::info!("Received ECHO1 message from node {} with content {:?} for round {}",echo_sender,msgs,round);
        if round_state_map.contains_key(&round){
            let rnd_state = round_state_map.get_mut(&round).unwrap();
            let (echo1_msgs,echo2_msgs) = rnd_state.add_echo(msgs, echo_sender, self.num_nodes, self.num_faults);
            if rnd_state.term_vals.len() == self.num_nodes {
                log::info!("All n instances of Binary AA terminated for round {}, starting round {}",round,round+1);
                let vec_vals:Vec<(Replica,BigInt)> = rnd_state.term_vals.clone().into_iter().map(|(rep,val)| (rep,val)).collect();
                self.start_baa( vec_vals, round+1).await;
                return;
            }
            if echo1_msgs.len() > 0{
                self.broadcast(CoinMsg::BinaryAAEcho(echo1_msgs.clone(), self.myid, round)).await;
                self.process_baa_echo( echo1_msgs, self.myid, round).await;
            }
            if echo2_msgs.len() > 0{
                self.broadcast(CoinMsg::BinaryAAEcho2(echo2_msgs.clone(), self.myid, round)).await;
                self.process_baa_echo2( echo2_msgs, self.myid, round).await;
            }
        }
        else{
            let rnd_state  = RoundState::new_with_echo(msgs,echo_sender);
            round_state_map.insert(round, rnd_state);
        }
        self.add_benchmark(String::from("process_baa_echo"), now.elapsed().unwrap().as_nanos());
    }

    pub async fn process_baa_echo2(self: &mut Context, msgs: Vec<(Replica,Vec<u8>)>, echo2_sender:Replica, round:u32){
        let now = SystemTime::now();
        let round_state_map = &mut self.round_state;
        log::info!("Received ECHO2 message from node {} with content {:?} for round {}",echo2_sender,msgs,round);
        if self.curr_round > round{
            return;
        }
        if round_state_map.contains_key(&round){
            let rnd_state = round_state_map.get_mut(&round).unwrap();
            rnd_state.add_echo2(msgs, echo2_sender, self.num_nodes, self.num_faults);
            if rnd_state.term_vals.len() == self.num_nodes {
                log::info!("All n instances of Binary AA terminated for round {}, starting round {}",round,round+1);
                let vec_vals:Vec<(Replica,BigInt)> = rnd_state.term_vals.clone().into_iter().map(|(rep,val)| (rep,val)).collect();
                self.add_benchmark(String::from("process_baa_echo2"), now.elapsed().unwrap().as_nanos());
                self.start_baa( vec_vals, round+1).await;
                return;
            }
        }
        else{
            let rnd_state  = RoundState::new_with_echo2(msgs,echo2_sender);
            round_state_map.insert(round, rnd_state);
        }
    }

    pub async fn start_baa(self: &mut Context, round_vecs: Vec<(Replica,BigInt)>, round:u32){
        let now = SystemTime::now();
        self.curr_round = round;
        if self.curr_round == self.rounds_aa{
            log::error!("Sharing End time: {:?}", SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis());
            let appxcon_map = &mut self.batchvss_state.nz_appxcon_rs;
            log::info!("Approximate Agreement Protocol terminated with values {:?}",round_vecs.clone());
            // Reconstruct values
            let mapped_rvecs:Vec<(Replica,BigInt)> = 
                round_vecs.clone().into_iter()
                .filter(|(_rep,num)| *num > BigInt::from(0i32))
                .collect();
            for (rep,val) in mapped_rvecs.into_iter(){
                appxcon_map.insert(rep, (val,false,BigInt::from(0i32)));
            }
            let cancel_handler = self.sync_send.send(0, SyncMsg { sender: self.myid, state: SyncState::CompletedSharing, value:0}).await;
            self.add_cancel_handler(cancel_handler);
            // for i in 0..10{
            //     self.invoke_coin.insert(i, Duration::from_millis((1000*i).try_into().unwrap()));
            // }
            return;
        }
        let transmit_vec:Vec<(Replica,Vec<u8>)> = round_vecs.into_iter().map(|(rep,val)| (rep,val.to_bytes_be().1)).collect();
        let prot_msg = CoinMsg::BinaryAAEcho(transmit_vec.clone(), self.myid,round);
        self.add_benchmark(String::from("start_baa"), now.elapsed().unwrap().as_nanos());
        self.broadcast(prot_msg.clone()).await;
        self.process_baa_echo(transmit_vec.clone(), self.myid, round);
        log::info!("Broadcasted message {:?}",prot_msg);
    }
}