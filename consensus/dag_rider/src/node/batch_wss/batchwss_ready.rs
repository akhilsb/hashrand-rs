use std::{time::SystemTime};

use async_recursion::async_recursion;
use types::{Replica, hash_cc::{CoinMsg, CTRBCMsg, SMRMsg}};

use crate::node::{Context, process_batchreconstruct_message};
use crypto::hash::{Hash};

#[async_recursion]
pub async fn process_batchwssready(cx: &mut Context, ctrbc:CTRBCMsg,master_root:Hash,ready_sender:Replica, smr_msg:&mut SMRMsg){
    let now = SystemTime::now();
    let vss_state = &mut cx.batchvss_state;
    let sec_origin = ctrbc.origin;
    // Highly unlikely that the node will get an echo before rbc_init message
    log::info!("Received READY message {:?} for secret from {}",ctrbc.clone(),sec_origin);
    // If RBC already terminated, do not consider this RBC
    if vss_state.terminated_secrets.contains(&sec_origin){
        log::info!("Terminated secretsharing of instance {} already, skipping this echo",sec_origin);
        return;
    }
    match vss_state.node_secrets.get(&sec_origin){
        None => {
            vss_state.add_ready(sec_origin, ready_sender, &ctrbc);
            return;
        }
        Some(_x) =>{}
    }
    let mp = vss_state.node_secrets.get(&sec_origin).unwrap().master_root;
    if mp != master_root || !ctrbc.verify_mr_proof(){
        log::error!("Merkle root of WSS Init from {} did not match Merkle root of READY from {}",sec_origin,cx.myid);
        return;
    }
    vss_state.add_ready(sec_origin, ready_sender, &ctrbc);
    let res = vss_state.ready_check(sec_origin, cx.num_nodes.clone(), cx.num_faults.clone(), cx.batch_size.clone());
    match res.1{
        None => {
            return;
        }
        Some(root_vec) =>{
            if res.0 == cx.num_faults +1 && !vss_state.readys.contains_key(&cx.myid){
                let shard = vss_state.echos.get(&sec_origin).unwrap().get(&cx.myid).unwrap();
                let ctrbc = CTRBCMsg::new(shard.0.clone(), shard.1.clone(), 0, sec_origin);
                vss_state.add_ready(sec_origin, cx.myid, &ctrbc);
                smr_msg.coin_msg = CoinMsg::BatchWSSReady(ctrbc.clone(),root_vec.0, cx.myid);
                cx.broadcast(&mut smr_msg.clone()).await;
                process_batchwssready(cx, ctrbc.clone(), master_root, cx.myid,smr_msg).await;
            }
            else if res.0 == cx.num_nodes-cx.num_faults {
                let shard = vss_state.echos.get(&sec_origin).unwrap().get(&cx.myid).unwrap();
                let ctrbc = CTRBCMsg::new(shard.0.clone(), shard.1.clone(), 0, sec_origin);
                smr_msg.coin_msg = CoinMsg::BatchWSSReconstruct(ctrbc.clone(),master_root.clone(), cx.myid);
                cx.broadcast(&mut smr_msg.clone()).await;
                process_batchreconstruct_message(cx,ctrbc,master_root.clone(),cx.myid,smr_msg).await;
            }
            else {
                return;
            }
        }
    }
    cx.add_benchmark(String::from("process_batchwssready"), now.elapsed().unwrap().as_nanos());
}