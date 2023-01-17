use std::{collections::{HashMap}};

use types::{Replica, hash_cc::{CoinMsg, CTRBCMsg}, appxcon::{verify_merkle_proof, reconstruct_and_verify}};

use crate::node::{Context};

impl Context{
    pub async fn process_wssecho(self: &mut Context,ctr:CTRBCMsg, echo_sender:Replica){
        let shard = ctr.shard.clone();
        let mp = ctr.mp.clone();
        let rbc_origin = ctr.origin.clone();
        // Highly unlikely that the node will get an echo before rbc_init message
        log::info!("Received ECHO message from {} for RBC of node {}",echo_sender,rbc_origin);
        let round = ctr.round;
        if !verify_merkle_proof(&mp, &shard){
            log::error!("Failed to evaluate merkle proof for ECHO received from node {} for RBC {}",echo_sender,rbc_origin);
            return;
        }
        // if self.curr_round > round{
        //     return;
        // }
        // 1. Add echos to the round state object
        let rnd_state = &mut self.aggr_context;
        match rnd_state.echos.get_mut(&rbc_origin) {
            None => {
                let mut echoset = HashMap::default();
                echoset.insert(echo_sender,(shard.clone(),mp.clone()));
                rnd_state.echos.insert(rbc_origin, echoset);
            },
            Some(x) => {
                x.insert(echo_sender,(shard.clone(),mp.clone()));
            }
        }
        let echos = rnd_state.echos.get_mut(&rbc_origin).unwrap();
        // 2. Check if echos reached the threshold, init already received, and round number is matching
        log::debug!("ECHO check: Round equals: {}, echos.len {}, contains key: {}"
        ,self.curr_round == round,echos.len(),rnd_state.node_msgs.contains_key(&rbc_origin));
        if echos.len() == self.num_nodes-self.num_faults && 
            rnd_state.node_msgs.contains_key(&rbc_origin){
            // Broadcast readys, otherwise, just wait longer
            // Cachin-Tessaro RBC implies verification needed
            // Send your own shard in the echo phase to every other node. 
            let merkle_root = rnd_state.node_msgs.get(&rbc_origin).unwrap().2.clone();
            let res = 
                reconstruct_and_verify(echos.clone(), self.num_nodes.clone(), self.num_faults.clone(),self.myid.clone(), merkle_root);
            match res {
                Err(error)=> log::error!("Shard reconstruction failed because of the following reason {:?}",error),
                Ok(vec_x)=> {
                    let ctrbc = CTRBCMsg::new(vec_x.0, vec_x.1, round, rbc_origin);
                    self.broadcast(CoinMsg::PedAVSSReady(ctrbc.clone(), self.myid)).await;
                    self.process_wssready(ctrbc,self.myid).await;
                    //msgs_to_be_sent.push(CoinMsg::AppxConCTREADY(ctrbc, self.myid))
                }
            }
        }
    }
}