use std::{time::SystemTime};

use async_recursion::async_recursion;
use types::{Replica, hash_cc::{CoinMsg, CTRBCMsg, SMRMsg}};

use crate::node::{Context, process_batchwssready};
use crypto::hash::{Hash};

#[async_recursion]
pub async fn process_batch_wssecho(cx: &mut Context,ctrbc:CTRBCMsg,master_root:Hash ,echo_sender:Replica, smr_msg:&mut SMRMsg){
    let now = SystemTime::now();
    let vss_state = &mut cx.cur_batchvss_state;
    let sec_origin = ctrbc.origin;
    // Highly unlikely that the node will get an echo before rbc_init message
    log::info!("Received ECHO message from node {} for secret from {}, in round {}",echo_sender,ctrbc.origin,ctrbc.round);
    // If RBC already terminated, do not consider this RBC
    if vss_state.terminated_secrets.contains(&sec_origin){
        log::info!("Terminated secretsharing of instance {} already, skipping this echo",sec_origin);
        return;
    }
    match vss_state.node_secrets.get(&sec_origin){
        None => {
            vss_state.add_echo(sec_origin, echo_sender, &ctrbc);
            return;
        }
        Some(_x) =>{}
    }
    let mp = vss_state.node_secrets.get(&sec_origin).unwrap().master_root;
    if mp != master_root || !ctrbc.verify_mr_proof(){
        log::error!("Merkle root of WSS Init from {} did not match Merkle root of ECHO from {}",sec_origin,cx.myid);
        return;
    }
    vss_state.add_echo(sec_origin, echo_sender, &ctrbc);
    let hash_root = vss_state.echo_check(sec_origin, cx.num_nodes, cx.num_faults, cx.batch_size);
    match hash_root {
        None => {
            return;
        },
        Some(vec_hash_root) => {
            let echos = vss_state.echos.get_mut(&sec_origin).unwrap();
            let shard = echos.get(&cx.myid).unwrap();
            let ctrbc = CTRBCMsg::new(shard.0.clone(), shard.1.clone(), 0, sec_origin);
            vss_state.add_ready(sec_origin, cx.myid, &ctrbc);
            let coin_msg = CoinMsg::BatchWSSReady(ctrbc.clone(), vec_hash_root.0, cx.myid);
            smr_msg.coin_msg = coin_msg;
            cx.broadcast(&mut smr_msg.clone()).await;
            process_batchwssready(cx, ctrbc.clone(), master_root, cx.myid, smr_msg).await;
        }
    }
    cx.add_benchmark(String::from("process_batch_wssecho"), now.elapsed().unwrap().as_nanos());
}