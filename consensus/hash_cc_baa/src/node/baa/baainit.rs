use std::{time::SystemTime};

use async_recursion::async_recursion;
use num_bigint::{BigInt};
use types::{hash_cc::{ CoinMsg}, Replica};

use crate::node::{Context, RoundState, send_batchreconstruct};

#[async_recursion]
pub async fn process_baa_echo(cx: &mut Context, msgs: Vec<(Replica,Vec<u8>)>, echo_sender:Replica, round:u32){
    let now = SystemTime::now();
    let round_state_map = &mut cx.round_state;
    if cx.curr_round > round{
        return;
    }
    log::info!("Received ECHO1 message from node {} with content {:?} for round {}",echo_sender,msgs,round);
    if round_state_map.contains_key(&round){
        let rnd_state = round_state_map.get_mut(&round).unwrap();
        let (echo1_msgs,echo2_msgs) = rnd_state.add_echo(msgs, echo_sender, cx.num_nodes, cx.num_faults);
        if rnd_state.term_vals.len() == cx.num_nodes {
            log::info!("All n instances of Binary AA terminated for round {}, starting round {}",round,round+1);
            let vec_vals:Vec<(Replica,BigInt)> = rnd_state.term_vals.clone().into_iter().map(|(rep,val)| (rep,val)).collect();
            start_baa(cx, vec_vals, round+1).await;
            return;
        }
        if echo1_msgs.len() > 0{
            cx.broadcast(CoinMsg::BinaryAAEcho(echo1_msgs.clone(), cx.myid, round)).await;
            process_baa_echo(cx, echo1_msgs, cx.myid, round).await;
        }
        if echo2_msgs.len() > 0{
            cx.broadcast(CoinMsg::BinaryAAEcho2(echo2_msgs.clone(), cx.myid, round)).await;
            process_baa_echo2(cx, echo2_msgs, cx.myid, round).await;
        }
    }
    else{
        let rnd_state  = RoundState::new_with_echo(msgs,echo_sender);
        round_state_map.insert(round, rnd_state);
    }
    cx.add_benchmark(String::from("process_baa_echo"), now.elapsed().unwrap().as_nanos());
}

pub async fn process_baa_echo2(cx: &mut Context, msgs: Vec<(Replica,Vec<u8>)>, echo2_sender:Replica, round:u32){
    let now = SystemTime::now();
    let round_state_map = &mut cx.round_state;
    log::info!("Received ECHO2 message from node {} with content {:?} for round {}",echo2_sender,msgs,round);
    if cx.curr_round > round{
        return;
    }
    if round_state_map.contains_key(&round){
        let rnd_state = round_state_map.get_mut(&round).unwrap();
        rnd_state.add_echo2(msgs, echo2_sender, cx.num_nodes, cx.num_faults);
        if rnd_state.term_vals.len() == cx.num_nodes {
            log::info!("All n instances of Binary AA terminated for round {}, starting round {}",round,round+1);
            let vec_vals:Vec<(Replica,BigInt)> = rnd_state.term_vals.clone().into_iter().map(|(rep,val)| (rep,val)).collect();
            cx.add_benchmark(String::from("process_baa_echo2"), now.elapsed().unwrap().as_nanos());
            start_baa(cx, vec_vals, round+1).await;
            return;
        }
    }
    else{
        let rnd_state  = RoundState::new_with_echo2(msgs,echo2_sender);
        round_state_map.insert(round, rnd_state);
    }
}

pub async fn start_baa(cx: &mut Context, round_vecs: Vec<(Replica,BigInt)>, round:u32){
    let now = SystemTime::now();
    cx.curr_round = round;
    if cx.curr_round == cx.rounds_aa{
        let appxcon_map = &mut cx.batchvss_state.nz_appxcon_rs;
        log::info!("Approximate Agreement Protocol terminated with values {:?}",round_vecs.clone());
        // Reconstruct values
        let mapped_rvecs:Vec<(Replica,BigInt)> = 
            round_vecs.clone().into_iter()
            .filter(|(_rep,num)| *num > BigInt::from(0i32))
            .collect();
        for (rep,val) in mapped_rvecs.into_iter(){
            appxcon_map.insert(rep, (val,false,BigInt::from(0i32)));
        }
        send_batchreconstruct(cx,0).await;
        return;
    }
    let transmit_vec:Vec<(Replica,Vec<u8>)> = round_vecs.into_iter().map(|(rep,val)| (rep,val.to_bytes_be().1)).collect();
    let prot_msg = CoinMsg::BinaryAAEcho(transmit_vec.clone(), cx.myid,round);
    cx.add_benchmark(String::from("start_baa"), now.elapsed().unwrap().as_nanos());
    cx.broadcast(prot_msg.clone()).await;
    process_baa_echo(cx, transmit_vec.clone(), cx.myid, round);
    log::info!("Broadcasted message {:?}",prot_msg);
}