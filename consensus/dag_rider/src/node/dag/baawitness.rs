use async_recursion::async_recursion;
use num_bigint::{BigInt, Sign};
use types::Replica;

use crate::node::{Context, RoundState, start_baa};

impl Context{
    pub async fn handle_witness(self: &mut Context,vec_rbc_indices:Vec<Replica>, witness_sender:Replica,round: u32){
        let round_state_map = &mut self.round_state;
        log::debug!("Received witness message {:?} from node {} for round {}",vec_rbc_indices.clone(),witness_sender,round);
        if round_state_map.contains_key(&round){
            let rnd_state = round_state_map.get_mut(&round).unwrap();
            rnd_state.witnesses.insert(witness_sender,vec_rbc_indices.clone());
            check_for_ht_witnesses(self, round).await;
        }
        else{
            // 1. If the protocol did not reach this round yet, create a new roundstate object
            let mut rnd_state = RoundState::new();
            rnd_state.witnesses.insert(witness_sender, vec_rbc_indices);
            round_state_map.insert(round, rnd_state);
        }
    }
    
    #[async_recursion]
    pub async fn check_for_ht_witnesses(self: &mut Context, round:u32){
        let round_state_map = &mut self.round_state;
        let rnd_state = round_state_map.get_mut(&round).unwrap();
    
        let mut i = 0;
        let min_threshold = self.num_faults;
        if rnd_state.accepted_msgs.len() <= self.num_faults+1{
            return;
        }
        let high_threshold = rnd_state.accepted_msgs.len() - self.num_faults-1;
        for (_replica,rbc_sets) in rnd_state.witnesses.clone().into_iter(){
            let check = rbc_sets.iter().all(|item| rnd_state.terminated_rbcs.contains(item));
            if check {
                i = i+1;
            }
        }
        if i >= self.num_nodes-self.num_faults{
            // Update value for next round
            let terminated_rbcs = &mut rnd_state.accepted_msgs;
            let mut array_vecs:Vec<Vec<BigInt>> = Vec::new();
            for _i in 0..self.num_nodes{
                array_vecs.push(Vec::new());
            } 
            for (_rep,message) in terminated_rbcs.clone().into_iter(){
                let str_m = String::from_utf8(message).unwrap();
                let vals_ind:Vec<&str> = str_m.split(",").collect();
                for i in 0..self.num_nodes{
                    array_vecs[i].push(BigInt::parse_bytes(vals_ind[i].trim_end_matches('\0').to_string().as_bytes(),16).unwrap());
                }
            }
            let mut final_round_vals:Vec<(Replica,BigInt)> = Vec::new();
            log::trace!("Message matrix: {:?}",array_vecs.clone());
            for i in 0..self.num_nodes{
                array_vecs[i].sort();
                let index_val:BigInt = (array_vecs[i][min_threshold].clone()+ array_vecs[i][high_threshold].clone())/2;
                log::trace!("{}",index_val.clone());
                final_round_vals.push((i,index_val));
            }
    
            log::debug!("Completed round {} of BAA, starting round {} with BigInt Array {:?}",round,round+1,final_round_vals.clone());
            self.curr_round = round+1;
            start_baa(self, final_round_vals).await;
        }
    }
}