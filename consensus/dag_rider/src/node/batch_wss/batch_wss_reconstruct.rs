use std::{time::SystemTime};

use types::{Replica, hash_cc::{CTRBCMsg, SMRMsg}};

use crate::node::{Context};
use crypto::hash::{Hash};

impl Context{
    pub async fn process_batchreconstruct_message(self: &mut Context,ctr:CTRBCMsg,master_root:Hash,recon_sender:Replica, _smr_msg:&mut SMRMsg){
        let now = SystemTime::now();
        let vss_state = &mut self.cur_batchvss_state;
        let sec_origin = ctr.origin.clone();
        if vss_state.terminated_secrets.contains(&sec_origin){
            log::debug!("Batch secret instance from node {} already terminated",sec_origin);
            return;
        }
        if !vss_state.node_secrets.contains_key(&sec_origin){
            vss_state.add_recon(sec_origin, recon_sender, &ctr);
            return;
        }
        let mp = vss_state.node_secrets.get(&sec_origin).unwrap().master_root;
        if mp != master_root || !ctr.verify_mr_proof(){
            log::error!("Merkle root of WSS Init from {} did not match Merkle root of Recon from {}",sec_origin,self.myid);
            return;
        }
        vss_state.add_recon(sec_origin, recon_sender, &ctr);
        // Check if the RBC received n-f readys
        let res_root_vec = vss_state.verify_reconstruct_rbc(sec_origin, self.num_nodes, self.num_faults, self.batch_size);
        match res_root_vec {
            None =>{
                return;
            },
            Some(_res) => {
                // Begin next round of reliable broadcast
                if vss_state.terminated_secrets.len() >= self.num_nodes - self.num_faults{
                    log::debug!("Terminated n-f Reliable Broadcasts, sending list of first n-f reliable broadcasts to other nodes");
                    log::debug!("Terminated : {:?}",vss_state.terminated_secrets);
                    let rounds_for_coin = 4+ (self.rounds_aa*4)/3;
                    let is_current_round_wss = self.curr_round % rounds_for_coin;
                    // Next RBC must start here if the current round is doing weak secret sharing
                    if is_current_round_wss == 0{
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
        self.add_benchmark(String::from("process_batchreconstruct_message"), now.elapsed().unwrap().as_nanos());
    }
}