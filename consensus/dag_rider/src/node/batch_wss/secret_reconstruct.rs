use std::{ time::{SystemTime, UNIX_EPOCH}};
use types::{hash_cc::{WSSMsg, CoinMsg, SMRMsg}, Replica};

use crate::node::{Context};

impl Context{
    pub async fn send_batchreconstruct(self: &mut Context, coin_number:usize)-> CoinMsg{
        let now = SystemTime::now();
        let coin_number = coin_number % self.batch_size;
        let vss_state = &mut self.prev_batchvss_state;
        let shares_vector = vss_state.secret_shares(coin_number);
        // Add your own share into your own map
        for (rep,wss_share) in shares_vector.clone().into_iter() {
            vss_state.add_secret_share(coin_number, rep.clone(), self.myid.clone(), wss_share.clone());
        }
        let mut vec_shares = Vec::new();
        for (_rep,wss_share) in shares_vector.into_iter() {
            vec_shares.push(wss_share.clone());
        }
        self.add_benchmark(String::from("send_batchreconstruct"), now.elapsed().unwrap().as_nanos());
        return CoinMsg::BatchSecretReconstruct(vec_shares,self.myid , coin_number);
    }

    pub async fn process_batchreconstruct(self: &mut Context,wss_msg:Vec<WSSMsg>,share_sender:Replica, coin_num:usize, smr_msg:&mut SMRMsg){
        let now = SystemTime::now();
        let vss_state = &mut self.prev_batchvss_state;
        for wss_msg in wss_msg.into_iter(){
            let sec_origin = wss_msg.origin.clone();
            if vss_state.recon_secret > coin_num{
                log::info!("Older secret share received from node {}, not processing share", sec_origin);
                continue;
            }
            if !vss_state.validate_secret_share(wss_msg.clone(), coin_num){
                continue;
            }
            let time_before_processing = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
            vss_state.add_secret_share(coin_num, wss_msg.origin, share_sender, wss_msg.clone());
            let secret = vss_state.reconstruct_secret(wss_msg.clone(), self.num_nodes,self.num_faults);
            // check if for all appxcon non zero termination instances, whether all secrets have been terminated
            // if yes, just output the random number
            match secret{
                None => {
                    continue;
                },
                Some(_secret)=>{
                    let coin_check = vss_state.coin_check(coin_num, self.num_nodes);
                    match coin_check {
                        None => {
                            // Not enough secrets received
                            continue;
                        },
                        Some(leader)=>{
                            log::info!("{:?} {:?}",SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis(),time_before_processing);
                            log::info!("Leader elected: {:?} for round {}",leader,self.curr_round);
                            if vss_state.recon_secret <= self.batch_size{
                                // Leader elected for round, trigger leader checks
                                // Commit vertices for the wave using the leader
                                self.dag_state.commit_vertices( leader, self.num_nodes, self.num_faults,self.curr_round).await;
                            }
                            else {
                                log::info!("Number of messages passed between nodes: {}",self.num_messages);
                                log::info!("Benchmark map: {:?}",self.bench.clone());
                            }
                            break;
                        }
                    }
                }
            }
        }
        smr_msg.coin_msg = CoinMsg::NoMessage();
        self.broadcast(smr_msg).await;
        self.add_benchmark(String::from("process_batchreconstruct"), now.elapsed().unwrap().as_nanos());
    }
}