use std::{collections::HashMap};

use types::{hash_cc::{CTRBCMsg, CoinMsg}, Replica, appxcon::{verify_merkle_proof, reconstruct_and_verify}};

use crate::node::{Context, RoundState};


impl Context{
    pub async fn process_echo(self: &mut Context, ctr:CTRBCMsg, echo_sender:Replica){
        let shard = ctr.shard.clone();
        let mp = ctr.mp.clone();
        let rbc_origin = ctr.origin.clone();
        let round_state_map = &mut self.round_state;
        // Highly unlikely that the node will get an echo before rbc_init message
        log::info!("Received ECHO message from {} for RBC of node {}",echo_sender,rbc_origin);
        let round = ctr.round;
        if !verify_merkle_proof(&mp, &shard){
            log::error!("Failed to evaluate merkle proof for ECHO received from node {} for RBC {}",echo_sender,rbc_origin);
            return;
        }
        if self.curr_round > round{
            return;
        }
        if round_state_map.contains_key(&round){
            // 1. Add echos to the round state object
            let rnd_state = round_state_map.get_mut(&round).unwrap();
            // If RBC already terminated, do not consider this RBC
            if rnd_state.terminated_rbcs.contains(&rbc_origin){
                return;
            }
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
                        self.broadcast(CoinMsg::AppxConCTREADY(ctrbc.clone(), self.myid)).await;
                        self.process_ready(ctrbc,self.myid).await;
                        //msgs_to_be_sent.push(CoinMsg::AppxConCTREADY(ctrbc, self.myid))
                    }
                }
            }
        }
        else{
            //let mut rnd_state = create_roundstate(rbc_originator, &main_msg, self.myid);
            let mut rnd_state = RoundState::new();
            rnd_state.node_msgs.insert(rbc_origin, (shard.clone(),mp.clone(),mp.root()));
            let mut echoset = HashMap::default();
            echoset.insert(echo_sender,(shard.clone(),mp.clone()));
            rnd_state.echos.insert(rbc_origin, echoset);
            round_state_map.insert(round, rnd_state);
            // Do not send echo yet, echo needs to come through from RBC_INIT
            //round_state_map.insert(main_msg.round, rnd_state);
        }
    }
}
