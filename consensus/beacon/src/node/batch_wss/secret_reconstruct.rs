use std::{ time::{SystemTime, UNIX_EPOCH}};
use types::{beacon::{WSSMsg, CoinMsg}, Replica, SyncState, SyncMsg, beacon::Round};

use crate::node::{Context, CTRBCState};

impl Context{
    pub async fn reconstruct_beacon(self: &mut Context, round:Round,coin_number:usize){
        let now = SystemTime::now();
        if !self.round_state.contains_key(&round){
            log::error!("Round number invalid");
            return;
        }
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        let shares_vector = rbc_state.secret_shares(coin_number);
        // Add your own share into your own map
        for (rep,wss_share) in shares_vector.clone().into_iter() {
            rbc_state.add_secret_share(coin_number, rep.clone(), self.myid.clone(), wss_share.clone());
        }
        let mut vec_shares = Vec::new();
        for (_rep,wss_share) in shares_vector.into_iter() {
            vec_shares.push(wss_share.clone());
        }
        let prot_msg = CoinMsg::BeaconConstruct(vec_shares, self.myid.clone(),coin_number,round);
        self.broadcast(prot_msg).await;
        self.add_benchmark(String::from("reconstruct_beacon"), now.elapsed().unwrap().as_nanos());
    }
    
    pub async fn process_secret_shares(self: &mut Context,wss_msgs:Vec<WSSMsg>,share_sender:Replica, coin_num:usize,round:Round){
        let now = SystemTime::now();
        log::info!("Received Coin construct message from node {} with messages {:?} for round {}",share_sender,wss_msgs.clone(),round);
        if self.recon_round >= round && self.recon_round != 20000{
            log::info!("Reconstruction done already,skipping secret share");
            return;
        }
        if !self.round_state.contains_key(&round){
            let rbc_new_state = CTRBCState::new(self.secret_domain.clone());
            self.round_state.insert(round, rbc_new_state);
        }
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        //let mut send_next_recon = false;
        let mut transmit_vec = Vec::new();
        for wss_msg in wss_msgs.into_iter(){
            let sec_origin = wss_msg.origin.clone();
            if rbc_state.recon_secret > coin_num{
                log::info!("Older secret share received from node {}, not processing share", sec_origin);
                return;
            }
            if !rbc_state.validate_secret_share(wss_msg.clone(), coin_num){
                return;
            }
            let _time_before_processing = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
            rbc_state.add_secret_share(coin_num, wss_msg.origin, share_sender, wss_msg.clone());
            let secret = rbc_state.reconstruct_secret(coin_num,wss_msg.clone(), self.num_nodes,self.num_faults);
            // check if for all appxcon non zero termination instances, whether all secrets have been terminated
            // if yes, just output the random number
            match secret{
                None => {
                    continue;
                },
                Some(_secret)=>{
                    let coin_check = rbc_state.coin_check(round,coin_num, self.num_nodes);
                    match coin_check {
                        None => {
                            // Not enough secrets received
                            continue;
                        },
                        Some(mut _random)=>{
                            //log::error!("Leader elected: {:?}",leader);
                            transmit_vec.append(&mut _random);
                            if rbc_state.recon_secret == self.batch_size - 1{
                                log::info!("Reconstruction ended for round {} at time {:?}",round,SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis());
                                log::info!("Number of messages passed between nodes: {}",self.num_messages);
                            }
                            //log::error!("Benchmark map: {:?}",self.bench.clone());
                            // if rbc_state.recon_secret == self.batch_size-1{
                            //     send_next_recon = false;
                            //     log::error!("Reconstruction ended for round {} at time {:?}",round,SystemTime::now()
                            //     .duration_since(UNIX_EPOCH)
                            //     .unwrap()
                            //     .as_millis());
                            //     log::error!("Number of messages passed between nodes: {}",self.num_messages);
                            //     log::error!("Benchmark map: {:?}",self.bench.clone());
                            // }
                            // else{
                            //     send_next_recon = true;
                            // }
                            break;
                        }
                    }
                }
            }
        }
        if !transmit_vec.is_empty(){
            let cancel_handler = self.sync_send.send(0, SyncMsg { sender: self.myid, state: SyncState::BeaconRecon(round, self.myid, coin_num, transmit_vec), value:0}).await;
            self.add_cancel_handler(cancel_handler);
            if coin_num < self.batch_size - 1{
                self.reconstruct_beacon(round,coin_num+1).await;   
            }
            else{
                self.round_state.remove(&round);
                self.recon_round = round;
            }
        }
        self.add_benchmark(String::from("process_batchreconstruct"), now.elapsed().unwrap().as_nanos()); 
    }
}