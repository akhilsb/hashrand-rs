use std::{ time::{SystemTime, UNIX_EPOCH}};
use types::{hash_cc::{WSSMsg, CoinMsg}, Replica};

use crate::node::{Context};

pub async fn send_batchreconstruct(cx: &mut Context, coin_number:usize){
    let now = SystemTime::now();
    let vss_state = &mut cx.batchvss_state;
    let shares_vector = vss_state.secret_shares(coin_number);
    // Add your own share into your own map
    for (rep,wss_share) in shares_vector.clone().into_iter() {
        vss_state.add_secret_share(coin_number, rep.clone(), cx.myid.clone(), wss_share.clone());
    }
    let mut vec_shares = Vec::new();
    for (_rep,wss_share) in shares_vector.into_iter() {
        vec_shares.push(wss_share.clone());
    }
    let prot_msg = CoinMsg::BatchSecretReconstruct(vec_shares, cx.myid.clone(),coin_number);
    cx.broadcast(prot_msg).await;
    cx.add_benchmark(String::from("send_batchreconstruct"), now.elapsed().unwrap().as_nanos());
}

pub async fn process_batchreconstruct(cx: &mut Context,wss_msgs:Vec<WSSMsg>,share_sender:Replica, coin_num:usize){
    let now = SystemTime::now();
    let vss_state = &mut cx.batchvss_state;
    let mut send_next_recon = false;
    for wss_msg in wss_msgs.into_iter(){
        let sec_origin = wss_msg.origin.clone();
        if vss_state.recon_secret > coin_num{
            log::info!("Older secret share received from node {}, not processing share", sec_origin);
            return;
        }
        if !vss_state.validate_secret_share(wss_msg.clone(), coin_num){
            return;
        }
        let time_before_processing = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
        vss_state.add_secret_share(coin_num, wss_msg.origin, share_sender, wss_msg.clone());
        let secret = vss_state.reconstruct_secret(wss_msg.clone(), cx.num_nodes,cx.num_faults);
        // check if for all appxcon non zero termination instances, whether all secrets have been terminated
        // if yes, just output the random number
        match secret{
            None => {
                continue;
            },
            Some(_secret)=>{
                let coin_check = vss_state.coin_check(coin_num, cx.num_nodes);
                match coin_check {
                    None => {
                        // Not enough secrets received
                        continue;
                    },
                    Some(leader)=>{
                        log::error!("{:?} {:?}",SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis(),time_before_processing);
                        log::error!("Leader elected: {:?}",leader);
                        if vss_state.recon_secret < cx.batch_size{
                            send_next_recon = true;
                        }
                        else {
                            log::error!("Number of messages passed between nodes: {}",cx.num_messages);
                            log::error!("Benchmark map: {:?}",cx.bench.clone());
                        }
                        break;
                    }
                }
            }
        }
    }
    if send_next_recon{
        send_batchreconstruct(cx, coin_num+1).await;
    }
    cx.add_benchmark(String::from("process_batchreconstruct"), now.elapsed().unwrap().as_nanos()); 
}