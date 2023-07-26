use types::beacon::Round;

use super::HashRand;

impl HashRand {
    pub async fn manage_beacon_request(&mut self,request:bool,request_round:Round,coin_completed:bool){
        // Number of coins available
        let mut rec_round = self.recon_round;
        if self.recon_round == 20000{
            rec_round = 0;
        }
        let mut reconstruct_beacon = false;
        // If it is a beacon is requested, push it into the queue
        if request{
            if self.coin_request_mapping.contains_key(&request_round){
                let num_responses = self.coin_request_mapping.get(&request_round).unwrap();
                if num_responses.1.len() >= self.num_faults + 1{
                    // This request has been reconstructed already, return value
                    if let Err(e) = self.coin_send_channel.send((request_round,num_responses.0)).await {
                        log::warn!(
                            "Failed to beacon {} to the consensus: {}",
                            request_round, e
                        );
                    }
                    return;
                }
            }
            // Check whether there are enough coins to reconstruct at all. If not, push it to the queue.
            self.coin_queue.push_back(request_round);    
            // find closest multiple of self.curr_round that terminated approximate agreement.
            if self.curr_round < self.rounds_aa+3{
                return;
            }
            reconstruct_beacon = true;
        }
        if coin_completed{
            // Start servicing requests for pending vectors
            if !self.coin_queue.is_empty() && self.curr_round>self.rounds_aa+3{
                reconstruct_beacon = true;
            }
        }
        if reconstruct_beacon{
            let last_completed_round = ((self.curr_round - self.rounds_aa -3)/(self.frequency))*self.frequency;
            // Find out if any secrets are there in between recon_round and last_completed_round
            if last_completed_round > rec_round{
                let next_completed_round = rec_round + self.frequency;
                if next_completed_round < last_completed_round{
                    self.service_req_queue(next_completed_round, last_completed_round).await;
                }
            }
            log::debug!("Next round check: tmp_stop_round: {},curr_round: {}, coin_comp: {},rec_round: {}, last_comp_round: {}",self.tmp_stop_round,self.curr_round,coin_completed,rec_round,last_completed_round);
            if coin_completed && self.tmp_stop_round-self.curr_round <= self.frequency && last_completed_round - rec_round < 200 {
                self.tmp_stop_round += 200;
                if self.tmp_stop_round-self.curr_round == 1{
                    self.next_round_begin(self.curr_round,false).await;
                }
            }
        }
    }

    async fn service_req_queue(&mut self, round_beg:Round,round_end:Round){
        let mut coins_to_reconstruct = Vec::new();
        let mut rounds_iter = Vec::new();
        for i in round_beg..round_end{
            if i%self.frequency == 0{
                rounds_iter.push(i);
            }
        }
        if self.coin_queue.is_empty(){
            return;
        }
        for round in rounds_iter.into_iter(){
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            for i in 1..self.batch_size{
                if !rbc_state.alloted_secrets.contains_key(&i){
                    let req_round = self.coin_queue.pop_front().unwrap();
                    rbc_state.alloted_secrets.insert(i, req_round);
                    coins_to_reconstruct.push((round_beg,i,req_round));
                }
                if self.coin_queue.is_empty(){
                    break;
                }
            }
            if self.coin_queue.is_empty(){
                break;
            }
        }
        for recon_params in coins_to_reconstruct.into_iter(){
            self.reconstruct_beacon(recon_params.0,recon_params.1).await;
        }
    }
}