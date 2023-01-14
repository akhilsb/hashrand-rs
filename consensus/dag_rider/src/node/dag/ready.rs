use async_recursion::async_recursion;
use types::{hash_cc::{CTRBCMsg, DAGMsg}, Replica};

use crate::node::{Context, RBCRoundState};

impl Context{
    #[async_recursion]
    pub async fn process_ready(self: &mut Context, ctr:CTRBCMsg, ready_sender:Replica)-> Vec<DAGMsg>{
        let mut ret_vec = Vec::new();
        let rbc_origin = ctr.origin.clone();
        let round_state_map = &mut self.round_state;
        log::debug!("Received READY message from {} for RBC of node {}",ready_sender,rbc_origin);
        let round = ctr.round;
        if !ctr.verify_mr_proof(){
            ret_vec.push(DAGMsg::NoMessage());
            return ret_vec;
        }
        if round_state_map.contains_key(&round){
            // 1. Add readys to the round state object
            let rnd_state = round_state_map.get_mut(&round).unwrap();
            if rnd_state.terminated_rbcs.contains(&rbc_origin){
                return ret_vec;
            }
            if !rnd_state.node_msgs.contains_key(&rbc_origin){
                rnd_state.add_ready(rbc_origin, ready_sender, &ctr);
                return ret_vec;
            }
            if !rnd_state.check_merkle_root(&ctr){
                return ret_vec;
            }
            rnd_state.add_ready(rbc_origin, ready_sender, &ctr);
            let res_check = rnd_state.ready_check(rbc_origin, self.num_nodes, self.num_faults, self.myid);
            match rnd_state.reconstruct_message(ctr.origin, self.num_nodes, self.num_faults) {
                None => {
                },
                Some(_vec) =>{
                    // Trigger DAG-related logic here
                    log::debug!("Terminated RBC of node {} in round {}", ctr.origin, round);
                    self.dag_state.add_vertex(_vec).await;
                    // If the current round is doing weak secret sharing, the rbc needs to be triggered from WSSEnding
                    // The next round should start from here only when batch secret sharing is not piggybacked on RBC
                    let current_wave = self.curr_round/4;
                    let batch_size:u32 = self.batch_size.try_into().unwrap();
                    let is_current_wave_wss:u32 = current_wave % batch_size;
                    let round_index = self.curr_round %4;
                    if !(is_current_wave_wss == 0 && round_index ==0) {
                        if self.dag_state.new_round(self.num_nodes, self.num_faults,self.curr_round){
                            // propose next block, but send secret share along
                            // Change round only here
                            // Maintain only one round number throughout, use that round number to derive round numbers for other apps
                            self.curr_round+=1;
                            self.start_rbc().await;
                        }
                    }
                }
            }
            match res_check {
                None =>{
                    return ret_vec;
                }
                Some((shard,mp,num_readys))=>{
                    if num_readys == self.num_faults+1{
                        let ctrbc = CTRBCMsg::new(shard, mp, round, rbc_origin);
                        ret_vec.push(DAGMsg::RBCREADY(ctrbc.clone(), self.myid));

                        ret_vec.append(&mut self.process_ready( ctrbc, self.myid).await);
                    }
                    else if num_readys == self.num_nodes-self.num_faults {
                        let ctrbc = CTRBCMsg::new(shard, mp, round, rbc_origin);
                        ret_vec.push(DAGMsg::RBCReconstruct(ctrbc.clone(), self.myid));
                        ret_vec.append(&mut self.process_reconstruct_message(ctrbc, self.myid).await);
                    }
                }
            }
        }
        else{
            let mut rnd_state = RBCRoundState::new(&ctr);
            rnd_state.add_ready(rbc_origin, ready_sender, &ctr);
            round_state_map.insert(round, rnd_state);
        }
        ret_vec
    }

    pub async fn process_reconstruct_message(self: &mut Context,ctr:CTRBCMsg,recon_sender:Replica)-> Vec<DAGMsg>{
        let ret_vec = Vec::new();
        let rbc_origin = ctr.origin.clone();
        let round_state_map = &mut self.round_state;
        let round = ctr.round;
        if !ctr.verify_mr_proof(){
            return ret_vec;
        }
        if round_state_map.contains_key(&round){
            let rnd_state = round_state_map.get_mut(&round).unwrap();
            if rnd_state.terminated_rbcs.contains(&rbc_origin){
                return ret_vec;
            }
            if !rnd_state.node_msgs.contains_key(&rbc_origin){
                rnd_state.add_recon(rbc_origin, recon_sender, &ctr);
                return ret_vec;
            }
            // Check merkle root validity
            if !rnd_state.check_merkle_root(&ctr){
                return ret_vec;
            }
            rnd_state.add_recon(rbc_origin, recon_sender, &ctr);
            // Check if the RBC received n-f readys
            // Initiate next phase of the protocol here
            match rnd_state.reconstruct_message(rbc_origin, self.num_nodes, self.num_faults) {
                None => {
                },
                Some(_vec) =>{
                    // Trigger DAG-related logic here
                    log::debug!("Terminated RBC of node {} in round {}", rbc_origin, round);
                    self.dag_state.add_vertex(_vec).await;
                    // If the current round is doing weak secret sharing, the rbc needs to be triggered from WSSEnding
                    // The next round should start from here only when batch secret sharing is not piggybacked on RBC
                    let current_wave = self.curr_round/4;
                    let batch_size:u32 = self.batch_size.try_into().unwrap();
                    let is_current_wave_wss:u32 = current_wave % batch_size;
                    let round_index = self.curr_round %4;
                    if !(is_current_wave_wss == 0 && round_index ==0) {
                        if self.dag_state.new_round(self.num_nodes, self.num_faults,self.curr_round){
                            // propose next block, but send secret share along
                            // Change round only here
                            // Maintain only one round number throughout, use that round number to derive round numbers for other apps
                            self.curr_round+=1;
                            self.start_rbc().await;
                        }
                    }
                }
            }
        }
        else {
            let mut rnd_state = RBCRoundState::new(&ctr);
            rnd_state.add_recon(rbc_origin, recon_sender, &ctr);
            round_state_map.insert(round, rnd_state);
        }
        ret_vec
    }
}