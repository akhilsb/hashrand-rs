use std::{time::SystemTime};

use types::{Replica, hash_cc::{CTRBCMsg, SMRMsg}};

use crate::node::{Context, start_rbc};
use crypto::hash::{Hash};

pub async fn process_batchreconstruct_message(cx: &mut Context,ctr:CTRBCMsg,master_root:Hash,recon_sender:Replica, _smr_msg:&mut SMRMsg){
    let now = SystemTime::now();
    let vss_state = &mut cx.batchvss_state;
    let sec_origin = ctr.origin.clone();
    if vss_state.terminated_secrets.contains(&sec_origin){
        log::info!("Batch secret instance from node {} already terminated",sec_origin);
        return;
    }
    let mp = vss_state.node_secrets.get(&sec_origin).unwrap().master_root;
    if mp != master_root || !ctr.verify_mr_proof(){
        log::error!("Merkle root of WSS Init from {} did not match Merkle root of Recon from {}",sec_origin,cx.myid);
        return;
    }
    vss_state.add_recon(sec_origin, recon_sender, &ctr);
    // Check if the RBC received n-f readys
    let res_root_vec = vss_state.verify_reconstruct_rbc(sec_origin, cx.num_nodes, cx.num_faults, cx.batch_size);
    match res_root_vec {
        None =>{
            return;
        },
        Some(_res) => {
            // Begin next round of reliable broadcast
            if vss_state.terminated_secrets.len() >= cx.num_nodes - cx.num_faults{
                log::info!("Terminated n-f Reliable Broadcasts, sending list of first n-f reliable broadcasts to other nodes");
                log::info!("Terminated : {:?}",vss_state.terminated_secrets);
                start_rbc(cx).await;
                //cx.add_benchmark(String::from("process_batchreconstruct_message"), now.elapsed().unwrap().as_nanos());
                //witness_check(cx).await;
            }
        }
    }
    cx.add_benchmark(String::from("process_batchreconstruct_message"), now.elapsed().unwrap().as_nanos());
}