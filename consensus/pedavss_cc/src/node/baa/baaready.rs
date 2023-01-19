use std::{collections::HashMap};

use async_recursion::async_recursion;
use types::{hash_cc::{CTRBCMsg, CoinMsg}, Replica, appxcon::{verify_merkle_proof, reconstruct_and_verify, reconstruct_and_return}};

use crate::node::{Context, RoundState};

impl Context{
    #[async_recursion]
    pub async fn process_ready(self: &mut Context, ctr:CTRBCMsg, ready_sender:Replica){
        let shard = ctr.shard.clone();
        let mp = ctr.mp.clone();
        let rbc_origin = ctr.origin.clone();
        let round_state_map = &mut self.round_state;
        // Highly unlikely that the node will get an echo before rbc_init message
        //log::info!("Received READY message from {} for RBC of node {}",ready_sender,rbc_origin);
        let round = ctr.round;
        if self.curr_round > ctr.round{
            return;
        }
        if !verify_merkle_proof(&mp, &shard){
            log::error!("Failed to evaluate merkle proof for READY received from node {} for RBC {}",ready_sender,rbc_origin);
            return;
        }
        if round_state_map.contains_key(&round){
            // 1. Add readys to the round state object
            let rnd_state = round_state_map.get_mut(&round).unwrap();
            if rnd_state.terminated_rbcs.contains(&rbc_origin){
                return;
            }
            if !rnd_state.node_msgs.contains_key(&rbc_origin){
                let mut readyset = HashMap::default();
                readyset.insert(ready_sender,(shard.clone(),mp.clone()));
                rnd_state.readys.insert(rbc_origin, readyset);
                return;
            }
            let merkle_root = rnd_state.node_msgs.get(&rbc_origin).unwrap().2.clone();
            // Merkle root check. Check if the merkle root of the message matches the merkle root sent by the node
            if merkle_root != mp.to_proof().root(){
                log::error!("Merkle root verification failed with error {:?}{:?}",merkle_root,mp.to_proof().root());
            }
            match rnd_state.readys.get_mut(&rbc_origin) {
                None => {
                    let mut readyset = HashMap::default();
                    readyset.insert(ready_sender,(shard.clone(),mp.clone()));
                    rnd_state.readys.insert(rbc_origin, readyset);
                },
                Some(x) => {
                    x.insert(ready_sender,(shard.clone(),mp.clone()));
                }
            }
            let readys = rnd_state.readys.get_mut(&rbc_origin).unwrap();
            // 2. Check if readys reached the threshold, init already received, and round number is matching
            log::debug!("READY check: Round equals: {}, echos.len {}, contains key: {}"
            ,self.curr_round == round,readys.len(),rnd_state.node_msgs.contains_key(&rbc_origin));
            if  readys.len() == self.num_faults+1 &&
                rnd_state.node_msgs.contains_key(&rbc_origin) && !readys.contains_key(&self.myid){
                // Broadcast readys, otherwise, just wait longer
                // Cachin-Tessaro RBC implies verification needed
                let res = 
                    reconstruct_and_verify(readys.clone(), self.num_nodes.clone(), self.num_faults.clone(),self.myid.clone(), merkle_root);
                match res {
                    Err(error)=> log::error!("Shard reconstruction failed because of the following reason {:?}",error),
                    Ok(vec_x)=> {
                        let ctrbc = CTRBCMsg::new(vec_x.0, vec_x.1, round, rbc_origin);
                        self.broadcast(CoinMsg::AppxConCTREADY(ctrbc.clone(), self.myid)).await;
                        self.process_ready(ctr, self.myid).await;
                    }
                };
            }
            else if readys.len() >= self.num_nodes-self.num_faults &&
                rnd_state.node_msgs.contains_key(&rbc_origin){
                // Terminate RBC, RAccept the value
                // Add value to value list, add rbc to rbc list
                let res = 
                    reconstruct_and_verify(readys.clone(), self.num_nodes.clone(), self.num_faults.clone(),self.myid, merkle_root);
                match res {
                    Err(error)=> {
                        log::error!("Shard reconstruction failed because of the following reason {:?}",error);
                        return;
                    },
                    Ok(vec_x)=> {
                        log::info!("Reconstructed data successfully, starting reconstruction phase: {:?} {:?}",vec_x.0,rnd_state.node_msgs.get(&rbc_origin).unwrap().0);
                        let ctrbc = CTRBCMsg::new(vec_x.0, vec_x.1, round, rbc_origin);
                        self.broadcast(CoinMsg::AppxConCTReconstruct(ctrbc.clone(), self.myid)).await;
                        self.process_reconstruct_message(ctrbc, self.myid).await;
                    }
                };
            }
        }
        else{
            let mut rnd_state = RoundState::new();
            rnd_state.node_msgs.insert(rbc_origin, (shard.clone(),mp.clone(),mp.root()));
            let mut readyset = HashMap::default();
            readyset.insert(ready_sender,(shard.clone(),mp.clone()));
            rnd_state.readys.insert(rbc_origin, readyset);
            round_state_map.insert(round, rnd_state);
        }
    }

    pub async fn process_reconstruct_message(self: &mut Context,ctr:CTRBCMsg,recon_sender:Replica){
        let shard = ctr.shard.clone();
        let mp = ctr.mp.clone();
        let rbc_origin = ctr.origin.clone();
        let round_state_map = &mut self.round_state;
        let mut msgs_to_be_sent:Vec<CoinMsg> = Vec::new();
        if self.curr_round > ctr.round{
            return;
        }
        // Highly unlikely that the node will get an echo before rbc_init message
        log::info!("Received Reconstruct message from {} for RBC of node {}",recon_sender,rbc_origin);
        let round = ctr.round;
        if !verify_merkle_proof(&mp, &shard){
            log::error!("Failed to evaluate merkle proof for RECON received from node {} for RBC {}",recon_sender,rbc_origin);
            return;
        }
        if round_state_map.contains_key(&round){
            let rnd_state = round_state_map.get_mut(&round).unwrap();
            if rnd_state.terminated_rbcs.contains(&rbc_origin){
                return;
            }
            if !rnd_state.node_msgs.contains_key(&rbc_origin){
                let mut reconset = HashMap::default();
                reconset.insert(recon_sender,shard.clone());
                rnd_state.recon_msgs.insert(rbc_origin, reconset);
                return;
            }
            // Check merkle root validity
            let merkle_root = rnd_state.node_msgs.get(&rbc_origin).unwrap().2.clone();
            // Merkle root check. Check if the merkle root of the message matches the merkle root sent by the node
            if merkle_root != mp.to_proof().root(){
                log::error!("Merkle root verification failed with error {:?}{:?}",merkle_root,mp.to_proof().root());
            }
            match rnd_state.recon_msgs.get_mut(&rbc_origin) {
                None => {
                    let mut reconset = HashMap::default();
                    reconset.insert(recon_sender,shard.clone());
                    rnd_state.recon_msgs.insert(rbc_origin, reconset);
                },
                Some(x) => {
                    x.insert(recon_sender,shard.clone());
                }
            }
            // Check if the RBC received n-f readys
            let ready_check = rnd_state.readys.get(&rbc_origin).unwrap().len() >= (self.num_nodes-self.num_faults);
            let vec_fmap = rnd_state.recon_msgs.get(&rbc_origin).unwrap();
            //log::info!("Recon shard map: {:?} for rbc of node {}",vec_fmap,rbc_origin);
            if vec_fmap.len()>=self.num_nodes-self.num_faults && ready_check{
                // Reconstruct here
                let result = reconstruct_and_return(
                    vec_fmap, self.num_nodes.clone(), self.num_faults.clone());
                match result {
                    Err(error)=> {
                        log::error!("Error resulted in constructing erasure-coded data {:?}",error);
                        return;
                    }
                    Ok(vec)=>{
                        log::info!("Successfully reconstructed message for RBC, terminating RBC of node {}",rbc_origin);
                        //log::info!("Terminated with message: {:?} {:?}",vec.clone(),String::from_utf8(vec.clone()).expect("Invalid utf8"));
                        rnd_state.accepted_msgs.insert(rbc_origin, vec);
                        rnd_state.terminated_rbcs.insert(rbc_origin);
                        // Initiate next phase of the protocol here
                        if rnd_state.terminated_rbcs.len() >= self.num_nodes - self.num_faults{
                            if !rnd_state.witness_sent{
                                log::info!("Terminated n-f RBCs, sending list of first n-f RBCs to other nodes");
                                //log::info!("Round state: {:?}",rnd_state.terminated_rbcs);
                                let vec_rbcs = Vec::from_iter(rnd_state.terminated_rbcs.clone().into_iter());
                                let witness_msg = CoinMsg::AppxConWitness(
                                    vec_rbcs.clone(), 
                                    self.myid,
                                    self.curr_round
                                );
                                msgs_to_be_sent.push(witness_msg);
                                rnd_state.witness_sent = true;
                            }
                            self.check_for_ht_witnesses(self.curr_round).await;
                        }
                    }
                }
            }
        }
        else {
            let mut rnd_state = RoundState::new();
            let mut reconset = HashMap::default();
            reconset.insert(recon_sender,shard.clone());
            rnd_state.recon_msgs.insert(rbc_origin, reconset);
            round_state_map.insert(round, rnd_state);
        }
        for prot_msg in msgs_to_be_sent.iter(){
            self.broadcast(prot_msg.clone()).await;
            match prot_msg {
                CoinMsg::AppxConWitness(vec, _origin, round) => {
                    self.handle_witness(vec.clone(),self.myid,round.clone()).await;
                },
                _ => {}
            }
            // let sec_key_map = self.sec_key_map.clone();
            // for (replica,sec_key) in sec_key_map.into_iter() {
            //     if replica != self.myid{
            //         let wrapper_msg = WrapperMsg::new(prot_msg.clone(), self.myid, &sec_key.as_slice());
            //         let sent_msg = Arc::new(wrapper_msg);
            //         self.c_send(replica, sent_msg).await;
            //     }
            //     else {
            //         match prot_msg {
            //             CoinMsg::AppxConWitness(vec, _origin, round) => {
            //                 handle_witness(self,vec.clone(),self.myid,round.clone()).await;
            //             },
            //             _ => {}
            //         }
            //     }
            // }
            // log::info!("Broadcasted message {:?}",prot_msg.clone());
        }
    }
}