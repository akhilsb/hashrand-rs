use std::{time::SystemTime};

use types::{Replica, hash_cc::{CoinMsg, CTRBCMsg}};

use crate::node::{Context, witness_check};
use crypto::hash::{Hash};

pub async fn process_batchreconstruct_message(cx: &mut Context,ctr:CTRBCMsg,master_root:Hash,recon_sender:Replica){
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
            if vss_state.terminated_secrets.len() >= cx.num_nodes - cx.num_faults{
                if !vss_state.send_w1{
                    log::info!("Terminated n-f Batch WSSs, sending list of first n-f Batch WSSs to other nodes");
                    log::info!("Terminated : {:?}",vss_state.terminated_secrets);
                    log::info!("Terminated n-f wss instances. Sending echo2 message to everyone");
                    vss_state.send_w1 = true;
                    let broadcast_msg = CoinMsg::GatherEcho(vss_state.terminated_secrets.clone().into_iter().collect(), cx.myid);
                    cx.broadcast(broadcast_msg).await;
                }
                cx.add_benchmark(String::from("process_batchreconstruct_message"), now.elapsed().unwrap().as_nanos());
                witness_check(cx).await;
            }
        }
    }
}