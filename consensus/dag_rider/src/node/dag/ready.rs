use async_recursion::async_recursion;
use types::{hash_cc::{CTRBCMsg, CoinMsg, DAGMsg}, Replica};

use crate::node::{Context, RBCRoundState};

#[async_recursion]
pub async fn process_ready(cx: &mut Context, ctr:CTRBCMsg, ready_sender:Replica)-> Vec<DAGMsg>{
    let mut ret_vec = Vec::new();
    let rbc_origin = ctr.origin.clone();
    let round_state_map = &mut cx.round_state;
    log::info!("Received READY message from {} for RBC of node {}",ready_sender,rbc_origin);
    let round = ctr.round;
    if cx.curr_round > ctr.round || !ctr.verify_mr_proof(){
        ret_vec.push(DAGMsg::NoMessage());
        return ret_vec;
    }
    if round_state_map.contains_key(&round){
        // 1. Add readys to the round state object
        let rnd_state = round_state_map.get_mut(&round).unwrap();
        if rnd_state.terminated_rbcs.contains(&rbc_origin){
            return ret_vec;
        }
        if !rnd_state.node_msgs.contains_key(&rbc_origin){
            rnd_state.add_ready(rbc_origin, ready_sender, &ctr);
            return ret_vec;
        }
        if !rnd_state.check_merkle_root(&ctr){
            return ret_vec;
        }
        rnd_state.add_ready(rbc_origin, ready_sender, &ctr);
        let res_check = rnd_state.ready_check(rbc_origin, cx.num_nodes, cx.num_faults, cx.myid);
        match res_check {
            None =>{
                return ret_vec;
            }
            Some((shard,mp,num_readys))=>{
                if num_readys == cx.num_faults+1{
                    let ctrbc = CTRBCMsg::new(shard, mp, round, rbc_origin);
                    ret_vec.push(DAGMsg::RBCREADY(ctrbc.clone(), cx.myid));
                    ret_vec.append(&mut process_ready(cx, ctrbc, cx.myid).await);
                }
                else if num_readys == cx.num_nodes-cx.num_faults {
                    let ctrbc = CTRBCMsg::new(shard, mp, round, rbc_origin);
                    ret_vec.push(DAGMsg::RBCReconstruct(ctrbc.clone(), cx.myid));
                    ret_vec.append(&mut process_reconstruct_message(cx, ctrbc, cx.myid).await);
                }
            }
        }
    }
    else{
        let mut rnd_state = RBCRoundState::new(&ctr);
        rnd_state.add_ready(rbc_origin, ready_sender, &ctr);
        round_state_map.insert(round, rnd_state);
    }
    ret_vec
}

pub async fn process_reconstruct_message(cx: &mut Context,ctr:CTRBCMsg,recon_sender:Replica)-> Vec<DAGMsg>{
    let ret_vec = Vec::new();
    let rbc_origin = ctr.origin.clone();
    let round_state_map = &mut cx.round_state;
    log::info!("Received Reconstruct message from {} for RBC of node {}",recon_sender,rbc_origin);
    let round = ctr.round;
    if !ctr.verify_mr_proof(){
        return ret_vec;
    }
    if round_state_map.contains_key(&round){
        let rnd_state = round_state_map.get_mut(&round).unwrap();
        if rnd_state.terminated_rbcs.contains(&rbc_origin){
            return ret_vec;
        }
        if !rnd_state.node_msgs.contains_key(&rbc_origin){
            rnd_state.add_recon(rbc_origin, recon_sender, &ctr);
            return ret_vec;
        }
        // Check merkle root validity
        if !rnd_state.check_merkle_root(&ctr){
            return ret_vec;
        }
        rnd_state.add_recon(rbc_origin, recon_sender, &ctr);
        // Check if the RBC received n-f readys
        let recon_result = rnd_state.reconstruct_message(rbc_origin, cx.num_nodes, cx.num_faults);
        // Initiate next phase of the protocol here
        match recon_result {
            None => {
                return ret_vec;
            },
            Some(_vec) =>{
                // Trigger DAG-related logic here
                if rnd_state.terminated_rbcs.len() >= cx.num_nodes - cx.num_faults{
                    if !rnd_state.witness_sent{
                        log::info!("Terminated n-f RBCs, sending list of first n-f RBCs to other nodes");
                        log::info!("Round state: {:?}",rnd_state.terminated_rbcs);
                        let vec_rbcs = Vec::from_iter(rnd_state.terminated_rbcs.clone().into_iter());
                        let witness_msg = CoinMsg::AppxConWitness(
                            vec_rbcs.clone(), 
                            cx.myid,
                            cx.curr_round
                        );
                        rnd_state.witness_sent = true;
                        //cx.broadcast(witness_msg).await;
                        //handle_witness(cx,vec_rbcs,cx.myid,round).await;
                    }
                    //check_for_ht_witnesses(cx, cx.curr_round).await;
                }
            }
        }
    }
    else {
        let mut rnd_state = RBCRoundState::new(&ctr);
        rnd_state.add_recon(rbc_origin, recon_sender, &ctr);
        round_state_map.insert(round, rnd_state);
    }
    ret_vec
}