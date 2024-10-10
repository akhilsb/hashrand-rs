use std::collections::HashMap;

use async_recursion::async_recursion;
use num_bigint::{BigUint};
use num_traits::pow;
use types::{Round, beacon::{Replica}, SyncState, SyncMsg};

use crate::node::Context;
/**
 * This protocol implements the Bundled Approximate Agreement (BunAA) primitive in the paper https://arxiv.org/pdf/2205.11878.pdf.
 * Bundled AA bundles n instances of Abraham et al.'s Approximate Agreement protocol involving Reliable Broadcasts and the Witness technique. 
 */
impl Context{
    #[async_recursion]
    pub async fn next_round_vals(&mut self, round:Round)->HashMap<Round,Vec<(Replica,BigUint)>>{
        //let max_rounds_aa = self.rounds_aa;
        if !self.round_state.contains_key(&round){
            return HashMap::default();
        }
        let rbc_state = self.round_state.get(&round).unwrap();
        let min_threshold = self.num_faults;
        let high_threshold = self.num_nodes-self.num_faults-1;
        // terminate coin for round: round-max_rounds_aa-1
        // if round-max_rounds_aa-1 >= 0{
        //     // terminate batchwss for this round
        // }
        // clear out this appxcon_allround_vals variable after terminating round xx
        let mut hmap:HashMap<Round,HashMap<Replica,Vec<BigUint>>> = HashMap::default();
        for node in 0..self.num_nodes{
            if rbc_state.appxcon_allround_vals.contains_key(&node){
                let values_replica = rbc_state.appxcon_allround_vals.get(&node).unwrap();
                for (round_i,vec_value) in values_replica.clone().into_iter(){
                    if hmap.contains_key(&round_i){
                        let index_map = hmap.get_mut(&round_i).unwrap();
                        for (appxcon_index,val) in vec_value.into_iter(){
                            if index_map.contains_key(&appxcon_index){
                                let vec_values_index = index_map.get_mut(&appxcon_index).unwrap();
                                vec_values_index.push(val);
                            }
                            else{
                                let mut vec_values_index:Vec<BigUint> = Vec::new();
                                vec_values_index.push(val);
                                index_map.insert(appxcon_index, vec_values_index);
                            }
                        }
                    }
                    else{
                        let mut index_map = HashMap::default();
                        for (appxcon_index,val) in vec_value.into_iter(){
                            let mut vec_values_index:Vec<BigUint> = Vec::new();
                            vec_values_index.push(val);
                            index_map.insert(appxcon_index, vec_values_index);
                        }
                        hmap.insert(round_i, index_map);
                    }
                }
            }
        }
        log::info!("Printing values init:{:?} final:{:?}",rbc_state.appxcon_allround_vals,hmap.clone());
        let mut return_map:HashMap<Round,Vec<(Replica,BigUint)>> = HashMap::default();
        let mut term_rounds = Vec::new();
        for (round_iter,hmap_iter) in hmap.clone().into_iter(){
            log::info!("Appxcon indices for round {} in round {} are {:?} and values {:?}",round_iter,round,hmap_iter.keys(),hmap_iter);
            let mut index_returnval_vector = Vec::new();
            for (index,mut values) in hmap_iter.into_iter(){
                values.sort();
                let index_val:BigUint = (values[min_threshold].clone()+ values[high_threshold].clone())/2u32;
                index_returnval_vector.push((index,index_val));
            }
            // After maximum number of approximate agreement instances, terminate beacon and send it back
            if round-round_iter-1 > self.rounds_aa{
                // TODO: terminate round_iter beacon
                term_rounds.push((round_iter,index_returnval_vector.clone()));
            }
            return_map.insert(round_iter, index_returnval_vector);
        }
        // If this round actually terminated a new batchwss instance, start a new approximate agreement instance
        if round%self.frequency == 0{
            let mut index_returnval_vector = Vec::new();
            for index in rbc_state.committee.clone().into_iter(){
                if !rbc_state.terminated_secrets.contains(&index) {
                    let zero = BigUint::from(0u32);
                    index_returnval_vector.push((index,zero));
                }
                else {
                    let max = BigUint::from(2u32);
                    let max_power = pow(max, self.rounds_aa as usize);
                    index_returnval_vector.push((index,max_power));
                }
            }
            return_map.insert(round, index_returnval_vector);
        }
        // Only for bundled approximate agreement
        if self.bin_bun_aa{
            for (term_round,round_vecs) in term_rounds.into_iter(){
                return_map.remove(&term_round);
                let rbc_iter_state = self.round_state.get_mut(&term_round).unwrap();
                let appxcon_map = &mut rbc_iter_state.appx_con_term_vals;
                log::info!("Approximate Agreement Protocol terminated with values {:?}",round_vecs.clone());
                // Reconstruct values
                let mapped_rvecs:Vec<(Replica,BigUint)> = 
                    round_vecs.clone().into_iter()
                    .map(|(_rep,val)| (_rep,val))
                    .filter(|(_rep,num)| *num > BigUint::from(0u32))
                    .collect();
                for (rep,val) in mapped_rvecs.into_iter(){
                    appxcon_map.insert(rep, val);
                }
                rbc_iter_state.sync_secret_maps().await;
                log::info!("Terminated round {}, sending message to syncer",term_round.clone());
                let cancel_handler = self.sync_send.send(0, SyncMsg { sender: self.myid, state: SyncState::BeaconFin(term_round, self.myid), value:0}).await;
                self.add_cancel_handler(cancel_handler);
                // Start reconstruction
                // Set aside first coin for committee election
                self.reconstruct_beacon(term_round, 1).await;
            }
        }
        return return_map;
    }
}