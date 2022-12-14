use std::{sync::Arc, time::SystemTime};

use crypto::hash::{Hash,do_hash};
use merkle_light::merkle::MerkleTree;
use types::{appxcon::{get_shards, HashingAlg, MerkleProof}, hash_cc::{CTRBCMsg, CoinMsg, DAGMsg, SMRMsg, WrapperSMRMsg}};

use crate::node::{Context, process_echo, RBCRoundState, start_batchwss, process_batchwss_init, start_baa, process_baa_echo, send_batchreconstruct};

pub async fn process_rbc_init(cx: &mut Context, ctr:CTRBCMsg)-> Vec<DAGMsg>{
    let mut ret_vec = Vec::new();
    let now = SystemTime::now();
    let round_state_map = &mut cx.round_state;
    if cx.curr_round > ctr.round{
        return ret_vec;
    }
    // 1. Check if the protocol reached the round for this node
    log::info!("Received RBC Init from node {} for round {}",ctr.origin,ctr.round);
    if !ctr.verify_mr_proof(){
        return ret_vec;
    }
    let round = ctr.round;
    if round_state_map.contains_key(&round){
        let rnd_state = round_state_map.get_mut(&round).unwrap();
        rnd_state.add_rbc_shard(&ctr);
        rnd_state.add_echo(ctr.origin, cx.myid, &ctr);
        rnd_state.add_ready(ctr.origin, cx.myid, &ctr);
    }
    // 1. If the protocol did not reach this round yet, create a new roundstate object
    else{
        let mut rnd_state = RBCRoundState::new(&ctr);
        rnd_state.add_rbc_shard(&ctr);
        rnd_state.add_echo(ctr.origin, cx.myid, &ctr);
        rnd_state.add_ready(ctr.origin, cx.myid, &ctr);
        round_state_map.insert(round, rnd_state);
    }
    log::debug!("Sending echos for RBC from origin {}",ctr.origin);
    ret_vec.push(DAGMsg::RBCECHO(ctr.clone(),cx.myid));
    ret_vec.append(&mut process_echo(cx,ctr, cx.myid).await);
    cx.add_benchmark(String::from("process_rbc_init"), now.elapsed().unwrap().as_nanos());
    ret_vec
}

pub async fn start_rbc(cx: &mut Context){
    cx.curr_round +=1;
    // Locate round advancing logic in this function
    let wave_num = cx.curr_round/4;
    let round_index = cx.curr_round % 4;
    let num_secrets:u32 = cx.batch_size.try_into().unwrap();
    let data:Vec<u8> = Vec::new();
    let shards = get_shards(data, cx.num_faults);
    let _own_shard = shards[cx.myid].clone();
    // Construct Merkle tree
    let hashes:Vec<Hash> = shards.clone().into_iter().map(|x| do_hash(x.as_slice())).collect();
    log::info!("Vector of hashes during RBC Init {:?}",hashes);
    let merkle_tree:MerkleTree<[u8; 32],HashingAlg> = MerkleTree::from_iter(hashes.into_iter());
    // Some kind of message should be piggybacked here, but which message exactly is decided by the round number
    let mut coin_msgs = Vec::new();
    // TODO: reform logic
    if wave_num % num_secrets == 0 && round_index == 1{
        // Time to start sharing for next 32 secrets
        coin_msgs.append(&mut start_batchwss(cx).await);
    }
    else{
        // Add the case where we are running Binary Approximate Agreement here
        // In the first round of a wave, invoke the coin
        // In the second round of the wave, invoke secret sharing if available, if not, invoke binary common coin
        // In the third and fourth rounds of the wave, invoke binary approximate agreement protocol
        if wave_num == 0{
            let coin_invoke = send_batchreconstruct(cx, wave_num.try_into().unwrap()).await;
            for _i in 0..cx.num_nodes{
                coin_msgs.push(coin_invoke.clone())
            }
        }
        else{
            let baa_msg = start_baa(cx, cx.curr_round).await;
            match baa_msg {
                None=>{},
                Some(coin_msg)=>{
                    for _i in 0..cx.num_nodes{
                        coin_msgs.push(coin_msg.clone())
                    }
                }
            }
        }
    }
    // Advance round here
    cx.curr_round +=1;
    for (replica,sec_key) in cx.sec_key_map.clone().into_iter() {
        let mrp = MerkleProof::from_proof(merkle_tree.gen_proof(replica));
        let ctrbc = CTRBCMsg{
            shard:shards[replica].clone(),
            mp:mrp,
            origin:cx.myid,
            round:cx.curr_round,
        };
        if replica != cx.myid{
            let smr_msg = SMRMsg::new(DAGMsg::RBCInit(ctrbc.clone()), coin_msgs[replica].clone(), cx.myid);
            let wrapper_msg = WrapperSMRMsg::new(&smr_msg, cx.myid, &sec_key);
            cx.c_send(replica,Arc::new(wrapper_msg)).await;
        }
        else {
            // How to send echos and inits to self? Need to start sending echos correct? 
            let ret_vec_dag = process_rbc_init(cx,ctrbc).await;
            for dag_msg in ret_vec_dag.into_iter(){
                let mut smr_msg = SMRMsg::new(dag_msg, coin_msgs[replica].clone(), cx.myid);
                match coin_msgs[replica].clone(){
                    CoinMsg::BatchWSSInit(wss_init, ctr)=>{
                        process_batchwss_init(cx, wss_init, ctr, &mut smr_msg).await;
                    },
                    CoinMsg::BinaryAAEcho(vec_echo_vals, echo_sender, round)=>{
                        process_baa_echo(cx, vec_echo_vals, echo_sender, round, &mut smr_msg).await;
                    }
                    _ => {}
                }
            }
        }
    }
}