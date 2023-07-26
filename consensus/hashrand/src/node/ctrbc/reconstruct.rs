use std::{time::SystemTime, collections::HashMap};

use crypto::hash::Hash;
use types::{beacon::CTRBCMsg, beacon::{Replica, CoinMsg, GatherMsg}};

use crate::node::{HashRand, CTRBCState};

impl HashRand{
    pub async fn process_reconstruct(&mut self,ctrbc:CTRBCMsg,master_root:Hash,recon_sender:Replica){
        let _now = SystemTime::now();
        if !self.round_state.contains_key(&ctrbc.round){
            let rbc_new_state = CTRBCState::new(self.secret_domain.clone(),self.num_nodes);
            self.round_state.insert(ctrbc.round, rbc_new_state);
        }
        let round = ctrbc.round.clone();
        let rbc_state = self.round_state.get_mut(&ctrbc.round).unwrap();
        let sec_origin = ctrbc.origin;
        let mut msgs_to_be_sent:Vec<CoinMsg> = Vec::new();
        log::debug!("Received RECON message from {} for secret from {} in round {}",recon_sender,ctrbc.origin,ctrbc.round);
        if rbc_state.terminated_secrets.contains(&sec_origin){
            log::debug!("Batch secret instance from node {} already terminated",sec_origin);
            return;
        }
        if !rbc_state.msgs.contains_key(&sec_origin){
            rbc_state.add_recon(sec_origin, recon_sender, &ctrbc);
            return;
        }
        let (_beacon,shard) = rbc_state.msgs.get(&sec_origin).unwrap();
        if shard.mp.root() != master_root || !ctrbc.verify_mr_proof(){
            log::error!("Merkle root of WSS Init from {} did not match Merkle root of Recon from {}",sec_origin,self.myid);
            return;
        }
        rbc_state.add_recon(sec_origin, recon_sender, &ctrbc);
        // Check if the RBC received n-f readys
        let res_root_vec = rbc_state.verify_reconstruct_rbc(sec_origin, self.num_nodes, self.num_faults, self.batch_size);
        match res_root_vec {
            None =>{
                return;
            },
            Some(_res) => {
                /*
                 * Every time an RBC of round r terminates, check for the following three things.
                 * a) Check if the Secret shared is valid
                 * b) Check for witnesses: Witness A and Witness B
                 * c) Check for Approximate Consensus messages. 
                 */
                let beacon_msg = rbc_state.transform(sec_origin);
                // Disseminate all approximate agreement instances to their respective nodes
                //let beacon_msg = rbc_state.msgs.get(&sec_origin).unwrap().0.clone();
                let term_secrets = rbc_state.terminated_secrets.len();
                if term_secrets >= self.num_nodes - self.num_faults{
                    if !rbc_state.send_w1{
                        log::info!("Terminated n-f Batch WSSs, sending list of first n-f Batch WSSs to other nodes");
                        log::info!("Terminated : {:?}",rbc_state.terminated_secrets);
                        log::info!("Terminated n-f wss instances. Sending echo2 message to everyone");
                        rbc_state.send_w1 = true;
                        // Conditions to check before beginning round r+1.
                        // a) Check if n-f RBCs of round r are terminated 
                        // b) Check if n-f witnesses of round r-1 have been received. 
                        // c) Check if n-f double witnesses of round r-2 have been received.
                        let broadcast_msg = CoinMsg::GatherEcho(GatherMsg{nodes:rbc_state.terminated_secrets.clone().into_iter().collect()}, self.myid,round);
                        msgs_to_be_sent.push(broadcast_msg);
                    }
                    //self.add_benchmark(String::from("process_reconstruct"), now.elapsed().unwrap().as_nanos());
                }
                if beacon_msg.appx_con.is_some(){
                    for (round_iter,appx_convals) in beacon_msg.appx_con.clone().unwrap().into_iter(){
                        let rbc_iterstate = self.round_state.get_mut(&round_iter).unwrap();
                        if rbc_iterstate.appxcon_allround_vals.contains_key(&sec_origin){
                            let round_val_map = rbc_iterstate.appxcon_allround_vals.get_mut(&sec_origin).unwrap();
                            round_val_map.insert(round, appx_convals);
                        }
                        else{
                            let mut round_val_map = HashMap::default();
                            round_val_map.insert(round, appx_convals);
                            rbc_iterstate.appxcon_allround_vals.insert(sec_origin, round_val_map);
                        }
                    }
                }
                if term_secrets.clone() >= self.num_nodes-self.num_faults{
                    self.witness_check(round).await;
                }
            }
        }
        for prot_msg in msgs_to_be_sent.iter(){
            self.broadcast(prot_msg.clone(),round.clone()).await;
            match prot_msg {
                CoinMsg::GatherEcho(gather_msg, echo_sender,round) =>{
                    self.process_gatherecho(gather_msg.nodes.clone(), *echo_sender, round.clone()).await;
                    self.witness_check(round.clone()).await;
                },
                _ => {}
            }
        }
    }
}