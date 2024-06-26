use std::{ time::{SystemTime, UNIX_EPOCH}};
use types::{beacon::{WSSMsg, CoinMsg}, Replica, SyncState, SyncMsg, beacon::Round};

use crate::node::{Context, CTRBCState};

impl Context{
    /**
     * This function reconstructs a prepared beacon. All prepared beacons have a unique identifier determined by the round in which they were instantiated. 
     */
    pub async fn reconstruct_beacon(self: &mut Context, round:Round,mut coin_number:usize){
        let now = SystemTime::now();
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        rbc_state.sync_secret_maps().await;
        let mut vector_coins = Vec::new();
        // Check if there exist prior beacons that can be reconstructed in this batch. If yes, reconstruct them first. Check the definition of random beacons in our draft. 
        for coin in 0..self.batch_size{
            if !rbc_state.recon_secrets.contains(&coin){
                // Check if the beacon has already been reconstructed. 
                let beacon = rbc_state.coin_check(round, coin, self.num_nodes).await;
                match beacon {
                    Some(c)=>{
                        vector_coins.push((coin,c));
                    },
                    None=>{}
                }
            }
        }
        // If the beacon number coin_number has already been reconstructed, move onto the next beacon to be reconstructed. 
        if !vector_coins.is_empty() && coin_number != 0{
            log::error!("Enough information available to reconstruct coins until batch {}, moving forward to coin_num {}",vector_coins.last().unwrap().clone().0,vector_coins.last().unwrap().clone().0+1);
            coin_number = vector_coins.last().unwrap().0 + 1;
        }
        if coin_number > self.batch_size-1{
            return;
        }
        // Start reconstructing coin_number
        let shares_vector = rbc_state.secret_shares(coin_number);
        // Add your own share into your own map
        for (rep,wss_share) in shares_vector.clone().into_iter() {
            if rbc_state.committee.contains(&rep){
                rbc_state.add_secret_share(coin_number, rep.clone(), self.myid.clone(), wss_share.clone());
            }
        }
        let mut vec_shares = Vec::new();
        // Send shares of available secrets for this beacon, along with the Merkle proof of validity of the share. 
        for (_rep,wss_share) in shares_vector.into_iter() {
            if rbc_state.committee.contains(&_rep){
                vec_shares.push(wss_share.clone());
            }
        }
        // Broadcast the shares using the BeaconConstruct message type. 
        let prot_msg = CoinMsg::BeaconConstruct(vec_shares, self.myid.clone(),coin_number,round);
        // 25000 is an arbitrarily high number written to note that reconstruction messages do not require the current round number. 
        self.broadcast(prot_msg,25000).await;
        self.add_benchmark(String::from("reconstruct_beacon"), now.elapsed().unwrap().as_nanos());
        for (coin_num,beacon) in vector_coins.into_iter(){
            self.self_coin_check_transmit(round, coin_num, beacon).await;
        }
    }
    
    /**
     * This function processes secret shares sent by nodes in the beacon reconstruction process. 
     */
    pub async fn process_secret_shares(self: &mut Context,wss_msgs:Vec<WSSMsg>,share_sender:Replica, coin_num:usize,round:Round){
        let now = SystemTime::now();
        log::info!("Received Coin construct message from node {} for coin_num {} for round {} with shares for secrets {:?}",share_sender,coin_num,round,wss_msgs.clone().into_iter().map(|x| x.origin).collect::<Vec<usize>>());
        // if coin_num != 0 && self.recon_round != 20000{
        //     log::info!("Reconstruction done already,skipping secret share");
        //     return;
        // }
        if !self.round_state.contains_key(&round){
            let rbc_new_state = CTRBCState::new(self.secret_domain.clone(),self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        // Skip share processing if the secret has already been reconstructed. 
        if coin_num == 0 && rbc_state.committee_elected{
            log::info!("Committee election over, skipping secret share");
            return;
        }
        if rbc_state.cleared{
            log::info!("State cleared for round {}, exiting",round);
            return;
        }
        //let mut send_next_recon = false;
        //let mut transmit_vec = Vec::new();
        for wss_msg in wss_msgs.into_iter(){
            let sec_origin = wss_msg.origin.clone();
            // coin 0 is set for committee election
            if rbc_state.recon_secrets.contains(&coin_num){
                log::info!("Older secret share received from node {}, not processing share for coin_num {}", sec_origin,coin_num);
                return;
            }
            rbc_state.add_secret_share(coin_num, wss_msg.origin, share_sender, wss_msg.clone());
            if !rbc_state.validate_secret_share(wss_msg.clone(), coin_num){
                log::error!("Invalid share for coin_num {} skipping share...",coin_num);
                continue;
            }
            let _time_before_processing = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
            // Reconstruct the secret
            let secret = rbc_state.reconstruct_secret(coin_num,wss_msg.clone(), self.num_nodes,self.num_faults).await;
            // check if for all appxcon non zero termination instances, whether all secrets have been terminated
            // if yes, just output the random number
            match secret{
                None => {
                    continue;
                },
                Some(_secret)=>{
                    // Check if all the required secrets have been reconstructed for the beacon
                    let coin_check = rbc_state.coin_check(round,coin_num, self.num_nodes).await;
                    match coin_check {
                        None => {
                            // Not enough secrets received
                            continue;
                        },
                        Some(mut _random)=>{
                            // Check if this coin is for AnyTrust sampling
                            self.self_coin_check_transmit(round, coin_num, _random).await;
                            if coin_num < self.batch_size - 1 && coin_num != 0{
                                // If this beacon has been reconstructed, begin reconstruction of the next beacon in the batch
                                self.reconstruct_beacon(round,coin_num+1).await;   
                            }
                            // //log::error!("Leader elected: {:?}",leader);
                            // if coin_num == 0{
                            //     rbc_state.committee_elected = true;
                            //     // This coin is for committee election
                            //     let committee = self.elect_committee(_random).await;
                            //     let round_baa = round+self.rounds_aa;
                            //     // identify closest multiple of self.frequency to round_baa
                            //     let round_baa_fin:Round;
                            //     if round_baa%self.frequency == 0{
                            //         round_baa_fin = round_baa;
                            //     }
                            //     else{
                            //         round_baa_fin = ((round_baa/self.frequency)+1)*self.frequency;
                            //     }
                            //     if self.round_state.contains_key(&round_baa_fin){
                            //         self.round_state.get_mut(&round_baa_fin).unwrap().set_committee(committee);
                            //     }
                            //     self.check_begin_next_round(round_baa_fin).await;
                            // }
                            // else{
                            //     transmit_vec.append(&mut _random);
                            //     if rbc_state.recon_secrets.contains(&(self.batch_size - 1)){
                            //         log::info!("Reconstruction ended for round {} at time {:?}",round,SystemTime::now()
                            //         .duration_since(UNIX_EPOCH)
                            //         .unwrap()
                            //         .as_millis());
                            //         log::info!("Number of messages passed between nodes: {}",self.num_messages);
                            //     }
                            // }
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
        self.add_benchmark(String::from("process_batchreconstruct"), now.elapsed().unwrap().as_nanos()); 
    }
    /**
     * Beacons can be reconstructed in HashRand for two reasons:
     * a) For external consumption (which are sent to the syncer)
     * b) For internal consumption (for AnyTrust sampling and efficiency)
     */
    pub async fn self_coin_check_transmit(&mut self,round:Round,coin_num:usize,number:Vec<u8>){
        let rbc_state = self.round_state.get_mut(&round).unwrap();
        let recon_secrets_size = rbc_state.recon_secrets.len().clone();
        
        if recon_secrets_size == self.batch_size {
            log::error!("Terminated all secrets of round {}, eliminating state",round);
            rbc_state._clear();
        }
        // The first beacon in a batch is always used for AnyTrust sampling
        // This index is only queried by the function inside Gather. 
        if coin_num == 0{
            rbc_state.committee_elected = true;
            // This beacon is for AnyTrust Sampling
            let committee = self.elect_committee(number.clone()).await;
            // TODO: Adding 3 is a bad way for dealing with off-by-one errors
            let round_baa = round+self.rounds_aa+3;
            // identify closest multiple of self.frequency to round_baa
            let round_baa_fin:Round;
            if round_baa%self.frequency == 0{
                round_baa_fin = round_baa;
            }
            else{
                round_baa_fin = ((round_baa/self.frequency)+1)*self.frequency;
            }
            if self.round_state.contains_key(&round_baa_fin){
                // Use this beacon to set the sample for the round
                self.round_state.get_mut(&round_baa_fin).unwrap().set_committee(committee);
            }
            // Start next round only after gather has terminated
            let rbc_started_baa = self.round_state.get(&round_baa_fin).unwrap().started_baa;
            log::error!("Round state fin: {}, started_baa {}",round_baa_fin,rbc_started_baa);
            // Start Binary AA after electing committee
            if rbc_started_baa{
                self.check_begin_next_round(round_baa_fin).await;
            }
        }
        else{
            if rbc_state.recon_secrets.contains(&(self.batch_size - 1)){
                log::info!("Reconstruction ended for round {} at time {:?}",round,SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis());
                log::info!("Number of messages passed between nodes: {}",self.num_messages);
            }
        }
        // Send the beacon output to the syncer node for tracking throughput. 
        let cancel_handler = self.sync_send.send(0, SyncMsg { sender: self.myid, state: SyncState::BeaconRecon(round, self.myid, coin_num, number), value:0}).await;
        self.add_cancel_handler(cancel_handler);
    }
}