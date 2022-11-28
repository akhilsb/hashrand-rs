use std::{sync::Arc, collections::{HashSet}};

use async_recursion::async_recursion;
use num_bigint::{BigInt, Sign};
use types::{hash_cc::{ ProtMsg, WrapperMsg}, Replica};

use crate::node::{Context, RoundState, send_reconstruct, send_batchreconstruct};

#[async_recursion]
pub async fn process_baa_echo(cx: &mut Context, msgs: Vec<(Replica,Vec<u8>)>, echo_sender:Replica, round:u32){
    let round_state_map = &mut cx.round_state;
    if cx.curr_round > round{
        return;
    }
    log::info!("Received ECHO1 message from node {} with content {:?} for round {}",echo_sender,msgs,round);
    let mut msgs_to_be_sent:Vec<ProtMsg> = Vec::new();
    let mut echo1_msgs:Vec<(Replica,Vec<u8>)> = Vec::new();
    let mut echo2_msgs:Vec<(Replica,Vec<u8>)> = Vec::new();
    if round_state_map.contains_key(&round){
        let rnd_state = round_state_map.get_mut(&round).unwrap();
        for (rep,msg) in msgs.into_iter(){
            // If the instance has already terminated, do not process messages from this node
            if rnd_state.term_vals.contains_key(&rep){
                continue;
            }
            let parsed_bigint = BigInt::from_bytes_be(Sign::Plus, msg.clone().as_slice());
            if rnd_state.state.contains_key(&rep){
                let arr_tup = rnd_state.state.get_mut(&rep).unwrap();
                let arr_vec = &mut arr_tup.0;
                // The echo sent by echo_sender was for this value in the bivalent initial value state
                if arr_vec[0].0 == parsed_bigint{
                    arr_vec[0].1.insert(echo_sender);
                    // check for t+1 votes: if it has t+1 votes, send out another echo1 message
                    // check whether an echo has been sent out for this value in this instance
                    //log::info!("Processing values: {:?} inst: {} echo count: {}",arr_vec[0].clone(),rep, arr_vec[0].1.len());
                    if arr_vec[0].1.len() == cx.num_faults+1 && !arr_vec[0].3{
                        log::info!("Got t+1 ECHO messages for BAA inst {} sending ECHO",rep.clone());
                        echo1_msgs.push((rep,msg.clone()));
                        arr_vec[0].3 = true;
                    }
                    // check for 2t+1 votes: if it has 2t+1 votes, send out echo2 message
                    else if arr_vec[0].1.len() >= cx.num_nodes-cx.num_faults && !arr_vec[0].4{
                        log::info!("Got 2t+1 ECHO messages for BAA inst {} sending ECHO2",rep.clone());
                        echo2_msgs.push((rep,msg.clone()));
                        arr_tup.1.insert(parsed_bigint);
                        if arr_tup.1.len() == 2{
                            // terminate protocol for instance &rep
                            let vec_arr:Vec<BigInt> = arr_tup.1.clone().into_iter().map(|x| x).collect();
                            let next_round_val = (vec_arr[0].clone()+vec_arr[1].clone())/2;
                            rnd_state.term_vals.insert(rep, next_round_val);
                        }
                        arr_vec[0].4 = true;
                    }
                }
                else{
                    if arr_vec.len() == 1{
                        // insert new array vector
                        let mut echo_set:HashSet<Replica>= HashSet::default();
                        echo_set.insert(rep);
                        arr_vec.push((parsed_bigint,echo_set,HashSet::default(),false,false));
                    }
                    else {
                        arr_vec[1].1.insert(rep);
                        if arr_vec[1].1.len() == cx.num_faults+1 && !arr_vec[1].3{
                            log::info!("Second value {} got t+1 votes",parsed_bigint.clone());
                            echo1_msgs.push((rep,msg.clone()));
                            arr_vec[1].3 = true;
                        }
                        else if arr_vec[1].1.len() == cx.num_nodes-cx.num_faults && !arr_vec[1].4{
                            echo2_msgs.push((rep,msg.clone()));
                            arr_tup.1.insert(parsed_bigint);
                            if arr_tup.1.len() == 2{
                                // terminate protocol for instance &rep
                                let vec_arr:Vec<BigInt> = arr_tup.1.clone().into_iter().map(|x| x).collect();
                                let next_round_val = (vec_arr[0].clone()+vec_arr[1].clone())/2;
                                rnd_state.term_vals.insert(rep, next_round_val);
                            }
                            arr_vec[1].4 = true;
                        }
                    }
                }
            }
            else{
                let mut echo_set:HashSet<Replica> = HashSet::default();
                echo_set.insert(rep);
                let mut arr_vec:Vec<(BigInt, HashSet<Replica>, HashSet<Replica>,bool,bool)> = Vec::new();
                arr_vec.push((parsed_bigint,echo_set,HashSet::default(),false,false));
                rnd_state.state.insert(rep, (arr_vec,HashSet::default(),Vec::new()));
            }
        }
        if rnd_state.term_vals.len() == cx.num_nodes {
            log::info!("All n instances of Binary AA terminated for round {}, starting round {}",round,round+1);
            let vec_vals:Vec<(Replica,BigInt)> = rnd_state.term_vals.clone().into_iter().map(|(rep,val)| (rep,val)).collect();
            start_baa(cx, vec_vals, round+1).await;
            return;
        }
        if echo1_msgs.len() > 0{
            msgs_to_be_sent.push(ProtMsg::BinaryAAEcho(echo1_msgs, cx.myid, round));
        }
        if echo2_msgs.len() > 0{
            msgs_to_be_sent.push(ProtMsg::BinaryAAEcho2(echo2_msgs, cx.myid, round));
        }
    }
    else{
        let mut rnd_state  = RoundState::new();
        for (rep,msg) in msgs.clone().into_iter(){
            let parsed_bigint = BigInt::from_bytes_be(Sign::Plus,msg.as_slice());
            let mut arr_state:Vec<(BigInt,HashSet<Replica>,HashSet<Replica>,bool,bool)> = Vec::new();
            let mut echo1_set = HashSet::new();
            echo1_set.insert(echo_sender);
            let echo2_set:HashSet<Replica>  =HashSet::new();
            arr_state.push((parsed_bigint,echo1_set,echo2_set,false,false));
            rnd_state.state.insert(rep, (arr_state,HashSet::default(),Vec::new()));
        }
        round_state_map.insert(round, rnd_state);
    }
    // Inserting send message block here to not borrow cx as mutable again
    for prot_msg in msgs_to_be_sent.iter(){
        let sec_key_map = cx.sec_key_map.clone();
        for (replica,sec_key) in sec_key_map.into_iter() {
            if replica != cx.myid{
                let wrapper_msg = WrapperMsg::new(prot_msg.clone(), cx.myid, &sec_key.as_slice());
                let sent_msg = Arc::new(wrapper_msg);
                cx.c_send(replica, sent_msg).await;
            }
            else {
                match prot_msg {
                    ProtMsg::BinaryAAEcho(msgs, sender, round) =>{
                        process_baa_echo(cx, msgs.clone(), sender.clone(), round.clone()).await;
                    },
                    ProtMsg::BinaryAAEcho2(msgs, sender, round)=>{
                        process_baa_echo2(cx, msgs.clone(), sender.clone(), round.clone()).await;
                    },
                    _ => {}
                }
            }
        }
        log::info!("Broadcasted message {:?}",prot_msg.clone());
    }
}

pub async fn process_baa_echo2(cx: &mut Context, msgs: Vec<(Replica,Vec<u8>)>, echo2_sender:Replica, round:u32){
    let round_state_map = &mut cx.round_state;
    log::info!("Received ECHO2 message from node {} with content {:?} for round {}",echo2_sender,msgs,round);
    if cx.curr_round > round{
        return;
    }
    if round_state_map.contains_key(&round){
        let rnd_state = round_state_map.get_mut(&round).unwrap();
        for (rep,msg) in msgs.into_iter(){
            let parsed_bigint = BigInt::from_bytes_be(Sign::Plus, msg.clone().as_slice());
            if rnd_state.state.contains_key(&rep){
                let arr_tup = rnd_state.state.get_mut(&rep).unwrap();
                // this vector can only contain two elements, if the echo corresponds to the first element, the first if block is executed
                let arr_vec = &mut arr_tup.0;
                if arr_vec[0].0 == parsed_bigint{
                    arr_vec[0].2.insert(echo2_sender);
                    // check for 2t+1 votes: if it has 2t+1 votes, send out echo2 message
                    if arr_vec[0].2.len() == cx.num_nodes-cx.num_faults{
                        arr_tup.2.push(parsed_bigint);
                        rnd_state.term_vals.insert(rep, arr_vec[0].0.clone());
                    }
                }
                else{
                    if arr_vec.len() == 1{
                        // insert new array vector
                        let mut echo2_set:HashSet<Replica>= HashSet::default();
                        echo2_set.insert(rep);
                        arr_vec.push((parsed_bigint,HashSet::default(),echo2_set,false,false));
                    }
                    else{
                        arr_vec[1].2.insert(rep);
                        if arr_vec[1].2.len() == cx.num_nodes-cx.num_faults{
                            log::info!("Value {:?} received n-f echo2s for instance {}",arr_vec[1].0.clone(),rep);
                            arr_tup.2.push(parsed_bigint);
                            rnd_state.term_vals.insert(rep, arr_vec[1].0.clone());
                        }
                    }
                }
            }
            else {
                let mut echo_set:HashSet<Replica> = HashSet::default();
                echo_set.insert(rep);
                let mut arr_vec:Vec<(BigInt, HashSet<Replica>, HashSet<Replica>,bool,bool)> = Vec::new();
                arr_vec.push((parsed_bigint,HashSet::default(),echo_set,false,false));
                rnd_state.state.insert(rep, (arr_vec,HashSet::default(),Vec::new()));
            }
        }
        if rnd_state.term_vals.len() == cx.num_nodes {
            log::info!("All n instances of Binary AA terminated for round {}, starting round {}",round,round+1);
            let vec_vals:Vec<(Replica,BigInt)> = rnd_state.term_vals.clone().into_iter().map(|(rep,val)| (rep,val)).collect();
            start_baa(cx, vec_vals, round+1).await;
            return;
        }
    }
    else{
        let mut rnd_state  = RoundState::new();
        for (rep,msg) in msgs.clone().into_iter(){
            let parsed_bigint = BigInt::from_bytes_be(Sign::Plus,msg.as_slice());
            let mut arr_state:Vec<(BigInt,HashSet<Replica>,HashSet<Replica>,bool,bool)> = Vec::new();
            let mut echo2_set = HashSet::new();
            echo2_set.insert(echo2_sender);
            let echo1_set:HashSet<Replica>  =HashSet::new();
            arr_state.push((parsed_bigint,echo1_set,echo2_set,false,false));
            rnd_state.state.insert(rep, (arr_state,HashSet::default(),Vec::new()));
        }
    }
}

pub async fn start_baa(cx: &mut Context, round_vecs: Vec<(Replica,BigInt)>, round:u32){
    cx.curr_round = round;
    if cx.curr_round == cx.rounds_aa{
        let appxcon_map = &mut cx.nz_appxcon_rs;
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
    let prot_msg = ProtMsg::BinaryAAEcho(transmit_vec.clone(), cx.myid,round);
    let sec_key_map = cx.sec_key_map.clone();
    for (replica,sec_key) in sec_key_map.into_iter() {
        if replica != cx.myid{
            let wrapper_msg = WrapperMsg::new(prot_msg.clone(), cx.myid, &sec_key.as_slice());
            let sent_msg = Arc::new(wrapper_msg);
            cx.c_send(replica, sent_msg).await;
        }
        else {
            process_baa_echo(cx,transmit_vec.clone(),cx.myid,round).await;
        }
    }
    log::info!("Broadcasted message {:?}",prot_msg.clone());
}