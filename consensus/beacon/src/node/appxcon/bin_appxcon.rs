use std::{time::{SystemTime}, collections::HashMap};

use async_recursion::async_recursion;
use num_bigint::BigUint;
use types::{beacon::{ CoinMsg, Round}, Replica, SyncMsg, SyncState};

use crate::node::{Context, CTRBCState, appxcon::RoundState};

/**
 * The functions in this file implement the Binary Approximate Agreement protocol in https://akhilsb.github.io/posts/2023/3/bp3/.
 * Binary AA consists of two types of messages: An ECHO and ECHO2. The protocol in summary:
 * 1. Each node sends an ECHO for its own value.
 * 2. Upon receiving t+1 ECHOs for a value, it broadcasts an ECHO for this value.
 * 3. Upon receiving 2t+1 ECHOs for a value, it broadcasts an ECHO2 for this value. 
 * 4. Upon receiving 2t+1 ECHO2s for a value, it outputs this value.
 * 5. [OR] it waits for 2t+1 ECHOs for two different values and outputs the average of these two values. 
 */
impl Context{
    /**
     * This method handles an ECHO message from another node. 
     * Nodes bundle ECHOs from multiple Binary AA instances across rounds and send it as a single message for reducing message complexity. 
     * This optimization makes the code harder to read, but makes sure the protocol remains performant. 
     * 
     * From the HashRand's protocol description, c Binary AA instances are instantiated once every \phi rounds. 
     * Each BinaryAA instance runs for self.rounds_aa number of rounds.
     * Therefore, each message contains messages from Binary AA instances over the last self.rounds_aa rounds. 
     * Overall, each msgs vector in this function contains messages from (c*self.rounds_aa)/(\phi) Binary AA instances instantiated in the last self.rounds_aa rounds. 
     * 
     * Each msg in msgs vector signifies a value from c Binary AA instances instantiated in the round vector.
     * The message has been sent for the round round (a parameter to this function). 
     * The c Binary AA instances are chosen from the beacon itself.
     */
    #[async_recursion]
    pub async fn process_baa_echo(self: &mut Context, msgs: Vec<(Round,Vec<(Replica,Vec<u8>)>)>, echo_sender:Replica, round:Round){
        let now = SystemTime::now();
        // List of all ECHOs to be sent after processing this message
        let mut send_valmap_echo1:HashMap<u32, Vec<(Replica, Vec<u8>)>> = HashMap::default();
        // List of all ECHO2s to be sent after processing this message
        let mut send_valmap_echo2:HashMap<u32, Vec<(Replica, Vec<u8>)>> = HashMap::default();
        if round < self.curr_round{
            log::warn!("Older message received, protocol advanced forward, ignoring Binary AA ECHO message");
            return;
        }
        log::info!("Received ECHO1 message from node {} with content {:?} for round {}",echo_sender,msgs,round);
        for (round_iter,values) in msgs.into_iter(){
            if !self.round_state.contains_key(&round_iter){
                // Create a new round state object if there is none
                let rbc_new_state = CTRBCState::new(self.secret_domain.clone(),self.num_nodes);
                self.round_state.insert(round_iter, rbc_new_state);
            }
            // Fetch the required round state
            let rbc_state = self.round_state.get_mut(&round_iter).unwrap();
            // Each round state registers this message as being received in the round `round`. 
            if rbc_state.round_state.contains_key(&round){
                let rnd_state = rbc_state.round_state.get_mut(&round).unwrap();
                // Keep track if this node needs to send a message to other nodes
                let (echo1_msgs,echo2_msgs) = rnd_state.add_echo(values, echo_sender, self.num_nodes, self.num_faults);
                // If all the Binary AA instances in this rbc_state terminate (i.e. finish their required number of rounds), begin the next round
                if rnd_state.term_vals.len() == rbc_state.committee.len() {
                    log::info!("All instances of Binary AA terminated for round {}, checking for termination related to round {}",round,round_iter);
                    // This function contains a list of all checks to conduct before a round can be terminated. 
                    if self.check_termination(round){
                        // Begin next round
                        self.next_round_begin(round).await;
                    }
                    return;
                }
                // If there are messages to send, add them to the maps. 
                if echo1_msgs.len() > 0{
                    send_valmap_echo1.insert(round_iter, echo1_msgs);
                }
                if echo2_msgs.len() > 0{
                    send_valmap_echo2.insert(round_iter, echo2_msgs);
                }
            }
            else{
                let rnd_state  = RoundState::new_with_echo(values,echo_sender);
                rbc_state.round_state.insert(round, rnd_state);
            }
            self.add_benchmark(String::from("process_baa_echo"), now.elapsed().unwrap().as_nanos());
        }
        // Create a message and send out ECHOs and ECHO2s
        if send_valmap_echo1.len() > 0{
            let mut vec_transmit = Vec::new();
            for (round,val_map) in send_valmap_echo1.into_iter(){
                vec_transmit.push((round,val_map));
            }
            self.broadcast(CoinMsg::BinaryAAEcho(vec_transmit.clone(), self.myid, round),round).await;
            self.process_baa_echo(vec_transmit, self.myid, round).await;
        }
        if send_valmap_echo2.len() > 0{
            let mut vec_transmit = Vec::new();
            for (round,val_map) in send_valmap_echo2.into_iter(){
                vec_transmit.push((round,val_map));
            }
            self.broadcast(CoinMsg::BinaryAAEcho2(vec_transmit.clone(), self.myid, round),round).await;
            self.process_baa_echo2(vec_transmit, self.myid, round).await;
        }
    }

    /**
     * This method handles an ECHO2 message from another node. 
     * Nodes bundle ECHO2s from multiple Binary AA instances across rounds and send it as a single message for reducing message complexity. 
     * This optimization makes the code harder to read, but makes sure the protocol remains performant. 
     * 
     * From the HashRand's protocol description, c Binary AA instances are instantiated once every \phi rounds. 
     * Each BinaryAA instance runs for self.rounds_aa number of rounds.
     * Therefore, each message contains messages from Binary AA instances over the last self.rounds_aa rounds. 
     * Overall, each msgs vector in this function contains messages from (c*self.rounds_aa)/(\phi) Binary AA instances instantiated in the last self.rounds_aa rounds. 
     * 
     * Each msg in msgs vector signifies a value from c Binary AA instances instantiated in the round vector.
     * The message has been sent for the round round (a parameter to this function). 
     * The c Binary AA instances are chosen from the beacon itself.
     */
    pub async fn process_baa_echo2(self: &mut Context, msgs: Vec<(Round,Vec<(Replica,Vec<u8>)>)>, echo2_sender:Replica, round:u32){
        let now = SystemTime::now();
        if round < self.curr_round{
            log::warn!("Older message received, protocol advanced forward, ignoring Binary AA ECHO message");
            return;
        }
        for (round_iter,vals) in msgs.into_iter(){
            if !self.round_state.contains_key(&round_iter){
                let rbc_new_state = CTRBCState::new(self.secret_domain.clone(),self.num_nodes);
                self.round_state.insert(round_iter, rbc_new_state);
            }
            let rbc_state = self.round_state.get_mut(&round_iter).unwrap();
            if rbc_state.round_state.contains_key(&round){
                let rnd_state = rbc_state.round_state.get_mut(&round).unwrap();
                rnd_state.add_echo2(vals, echo2_sender, self.num_nodes, self.num_faults);
                if rnd_state.term_vals.len() == rbc_state.committee.len() {
                    log::info!("All n instances of Binary AA terminated for round {} related to WSSInit {}",round,round_iter);
                    self.add_benchmark(String::from("process_baa_echo2"), now.elapsed().unwrap().as_nanos());
                    if self.check_termination(round){
                        // Begin next round
                        self.next_round_begin(round).await;
                    }
                }
            }
            else{
                let rnd_state  = RoundState::new_with_echo2(vals,echo2_sender);
                rbc_state.round_state.insert(round, rnd_state);
            }
        }
    }

    /**
     * This function checks if the protocol can start round round.
     * 
     * For this, the following checks are conducted.
     * 1. All the Binary AA instances instantiated in the last self.rounds_aa rounds must have terminated this round. 
     *      This implies a Binary AA instance instantiated in round r must have terminated the round `r0-r`. 
     */
    fn check_termination(&mut self, r0:Round)->bool{
        let round_begin;
        if self.curr_round > r0{
            return false;
        }
        
        if r0 <= self.rounds_aa + 1{
            round_begin = 0;
        }
        else{
            round_begin = r0-self.rounds_aa-1;
        }
        let mut can_begin_next_round = true;
        // Even if a single Binary AA instance does not terminate round r0, do not begin the next round. 
        for round_iter in round_begin..r0+1{
            if self.round_state.contains_key(&round_iter){
                let rbc_state = self.round_state.get(&round_iter).unwrap();
                if rbc_state.round_state.contains_key(&r0){
                    if rbc_state.round_state.get(&r0).unwrap().term_vals.len() < rbc_state.committee.len(){
                        log::info!("Cannot begin next BinAA round because BinAA of BAwVSS instantiated in round {} did not terminate round {}, term vals: {:?}",round_iter,r0,rbc_state.round_state.get(&r0).unwrap().term_vals);
                        can_begin_next_round = false;
                    }
                }
                else {
                    log::info!("Cannot begin next BinAA round because BinAA of BAwVSS instantiated in round {} does not have state for round {}",round_iter,r0);
                    can_begin_next_round = false;
                }
            }
        }
        can_begin_next_round
    }
    /**
     * This function starts the round `round`. 
     * 
     * This function collects the values from Binary AA instances instantiated in the last self.rounds_aa rounds. 
     * Next, it instantiates round `round-r` for a Binary AA instance instantiated in round r with the value obtained after terminating `round-r-1`. 
     */
    #[async_recursion]
    pub async fn next_round_begin(&mut self,round:Round){
        let round_begin;
        if self.curr_round > round{
            return;
        }
        if round <= self.rounds_aa + 1{
            round_begin = 0;
        }
        else{
            round_begin = round-self.rounds_aa-1;
        }
        let mut vec_newround_vals = Vec::new();
        // Collect next round values for Binary AA instances in the last self.rounds_aa rounds. 
        for round_iter in round_begin..round+1{
            if self.round_state.contains_key(&round_iter){
                let rbc_state = self.round_state.get(&round_iter).unwrap();
                if rbc_state.round_state.contains_key(&round){
                    let mut vec_replica_vals = Vec::new();
                    for (rep,value) in rbc_state.round_state.get(&round).unwrap().term_vals.clone().into_iter(){
                        vec_replica_vals.push((rep,value));
                    }
                    vec_newround_vals.push((round_iter,vec_replica_vals));
                }
            }
        }
        // Logging purposes
        if round_begin > 1{
            log::info!("Round_Begin : {}, round state keys: {:?}, keys : {:?}",round_begin,self.round_state.keys(),self.round_state.get(&0).unwrap().round_state.keys());
        }
        else{
            log::info!("Round_Begin : {}, round state keys: {:?},  keys : {:?}",round_begin,self.round_state.keys(),self.round_state.get(&0).unwrap().round_state.keys());
        }
        // Once round `round` = r+self.rounds_aa for Binary AA instances instantiated in round r, these Binary AA instances can be terminated and beacons can be generated. 
        if round_begin >= 1 && self.round_state.contains_key(&(round_begin-1)) && self.round_state.get(&(round_begin-1)).unwrap().round_state.contains_key(&(round-1)){
            // terminate round round_begin and mark these beacons for reconstruction
            let rbc_state = self.round_state.get_mut(&(round_begin-1)).unwrap();
            //let nz_appxcon_rs = &mut rbc_state.nz_appxcon_rs;
            //log::info!("Approximate Agreement Protocol terminated with values {:?}",round_vecs.clone());
            // Reconstruct values
            let mapped_rvecs:Vec<(Replica,BigUint)> = 
                rbc_state.round_state.get(&(round-1)).unwrap().term_vals.clone().into_iter()
                .filter(|(_rep,num)| *num > BigUint::from(0u32))
                .collect();
            for (rep,val) in mapped_rvecs.into_iter(){
                rbc_state.appx_con_term_vals.insert(rep, val);
                //rbc_state.contribution_map.insert(rep, (val,false,BigUint::from(0i32)));
            }
            log::error!("Terminated beacon for round {} with committee {:?} and appxcon_vals: {:?}, term_secrets {:?}, comm_vector {:?}", round_begin-1,rbc_state.committee,rbc_state.appx_con_term_vals,rbc_state.terminated_secrets,rbc_state.comm_vectors.keys());
            log::info!("Terminated round {}, sending message to syncer",(round_begin-1).clone());
            let cancel_handler = self.sync_send.send(0, SyncMsg { sender: self.myid, state: SyncState::BeaconFin(round_begin-1, self.myid), value:0}).await;
            self.add_cancel_handler(cancel_handler);
            // Start reconstruction
            self.reconstruct_beacon(round_begin-1, 1).await;
            
        }
        // If the next round is a multiple of the frequency parameter \phi, start a new BAwVSS instance
        if (round+1) % self.frequency == 0{
            // Start next round with batch secret sharing
            self.start_new_round(round, vec_newround_vals).await;
        }
        else{
            // continue binary approximate agreement from here
            //self.curr_round = round + 1;
            // Otherwise, just start the next round of Binary AAs
            let vec_round_msgs:Vec<(Round,Vec<(Replica,Vec<u8>)>)> = vec_newround_vals.into_iter().map(|(x,y)| {
                let mut msgs_vec = Vec::new();
                for (rep,val) in y.into_iter(){
                    msgs_vec.push((rep,val.to_bytes_be().to_vec()));
                }
                return (x,msgs_vec);
            }).collect();

            let prot_msg = CoinMsg::BinaryAAEcho(vec_round_msgs.clone(), self.myid, round+1);
            self.broadcast(prot_msg.clone(),round+1).await;
            self.process_baa_echo(vec_round_msgs, self.myid, round+1).await;
            self.increment_round(round).await;
            log::error!("Started round {} with Binary AA",round+1);
        }
    }
}