use std::collections::HashMap;

use async_recursion::async_recursion;
use types::{Replica, hash_cc::{CoinMsg, CTRBCMsg}, appxcon::{verify_merkle_proof, reconstruct_and_verify, reconstruct_and_return}};

use crate::node::{Context};

impl Context{
    #[async_recursion]
    pub async fn process_wssready(self: &mut Context, ctr:CTRBCMsg, ready_sender:Replica){
        let shard = ctr.shard.clone();
        let mp = ctr.mp.clone();
        let rbc_origin = ctr.origin.clone();
        // Highly unlikely that the node will get an echo before rbc_init message
        log::info!("Received READY message from {} for RBC of node {}",ready_sender,rbc_origin);
        let round = ctr.round;
        if !verify_merkle_proof(&mp, &shard){
            log::error!("Failed to evaluate merkle proof for READY received from node {} for RBC {}",ready_sender,rbc_origin);
            return;
        }
        // 1. Add readys to the round state object
        let rnd_state = &mut self.aggr_context;
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
                    self.broadcast(CoinMsg::PedAVSSReady(ctrbc.clone(), self.myid)).await;
                    self.process_wssready(ctr, self.myid).await;
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
                    self.broadcast(CoinMsg::PedAVSSReconstruct(ctrbc.clone(), self.myid)).await;
                    self.process_wssrecon(ctrbc, self.myid).await;
                }
            };
        }
    }

    pub async fn process_wssrecon(self: &mut Context,ctr:CTRBCMsg,recon_sender:Replica){
        let shard = ctr.shard.clone();
        let mp = ctr.mp.clone();
        let rbc_origin = ctr.origin.clone();
        let mut msgs_to_be_sent:Vec<CoinMsg> = Vec::new();
        // Highly unlikely that the node will get an echo before rbc_init message
        log::info!("Received Reconstruct message from {} for RBC of node {}",recon_sender,rbc_origin);
        if !verify_merkle_proof(&mp, &shard){
            log::error!("Failed to evaluate merkle proof for RECON received from node {} for RBC {}",recon_sender,rbc_origin);
            return;
        }
        let rnd_state = &mut self.aggr_context;
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
            return;
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
        log::info!("Recon shard map: {:?} for rbc of node {}",vec_fmap,rbc_origin);
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
                    log::info!("Terminated with message: {:?}",vec.clone());
                    
                    rnd_state.accepted_msgs.insert(rbc_origin, vec);
                    rnd_state.terminated_rbcs.insert(rbc_origin);
                    // Initiate next phase of the protocol here
                    if rnd_state.terminated_rbcs.len() >= self.num_nodes - self.num_faults{
                        if !rnd_state.witness_sent{
                            log::info!("Round state: {:?}",rnd_state.terminated_rbcs);
                            log::info!("Terminated n-f wss instances. Sending echo2 message to everyone");
                            msgs_to_be_sent.push(CoinMsg::GatherEcho(rnd_state.terminated_rbcs.clone().into_iter().collect(), self.myid));
                            // let vec_rbcs = Vec::from_iter(rnd_state.terminated_rbcs.clone().into_iter());
                            // let witness_msg = CoinMsg::AppxConWitness(
                            //     vec_rbcs.clone(), 
                            //     self.myid,
                            //     self.curr_round
                            // );
                            //msgs_to_be_sent.push(witness_msg);
                            rnd_state.witness_sent = true;
                        }
                        self.witness_check().await;
                    }
                }
            }
        }
        for prot_msg in msgs_to_be_sent.iter(){
            self.broadcast(prot_msg.clone()).await;
            match prot_msg {
                CoinMsg::GatherEcho(vec_term_secs, echo_sender) =>{
                    self.process_gatherecho( vec_term_secs.clone(), *echo_sender, 1).await;
                },
                _ => {}
            }
        }
    }
}