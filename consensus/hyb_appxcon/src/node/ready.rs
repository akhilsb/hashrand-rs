use std::{collections::HashSet};

use async_recursion::async_recursion;
use types::appxcon::{Msg, Replica, ProtMsg};

use super::{Context, create_roundstate};

impl Context{
    #[async_recursion]
    pub async fn process_ready(&mut self, main_msg:Msg, ready_sender:Replica){
        let rbc_originator = main_msg.origin;
        let round_state_map = &mut self.round_state;
        let mut msgs_to_be_sent:Vec<ProtMsg> = Vec::new();
        log::info!("Received READY message {:?}",main_msg.clone());
        // Highly unlikely that the node will get an echo before rbc_init message
        if round_state_map.contains_key(&main_msg.round){
            // 1. Add readys to the round state object
            let rnd_state;
            if main_msg.rnd_estm == true{
                rnd_state = &mut self.rnd_estm_state;
            }
            else{
                rnd_state = round_state_map.get_mut(&main_msg.round).unwrap();
            }
            if rnd_state.terminated_rbcs.contains(&rbc_originator){
                return;
            }
            match rnd_state.readys.get_mut(&rbc_originator) {
                None => {
                    let mut readyset = HashSet::default();
                    readyset.insert(ready_sender);
                    rnd_state.readys.insert(rbc_originator, readyset);
                },
                Some(x) => {
                    x.insert(ready_sender);
                }
            }
            let readys = rnd_state.readys.get_mut(&rbc_originator).unwrap();
            // 2. Check if readys reached the threshold, init already received, and round number is matching
            log::debug!("READY check: Round equals: {}, echos.len {}, contains key: {}"
            ,self.round == main_msg.round,readys.len(),rnd_state.node_msgs.contains_key(&rbc_originator));
            if  readys.len() == self.num_faults+1 &&
                rnd_state.node_msgs.contains_key(&rbc_originator){
                // Broadcast readys, otherwise, just wait longer
                self.broadcast(ProtMsg::READY(main_msg.clone(),main_msg.origin, self.myid)).await;
                //self.process_ready(main_msg.clone(), self.myid).await;
                //msgs_to_be_sent.push(ProtMsg::READY(main_msg.clone(),main_msg.origin, self.myid));
            }
            else if readys.len() >= self.num_nodes-self.num_faults &&
                rnd_state.node_msgs.contains_key(&rbc_originator){
                // Terminate RBC, RAccept the value
                // Add value to value list, add rbc to rbc list
                log::info!("Terminated RBC of node {} with value {}",main_msg.origin,main_msg.value);
                if main_msg.rnd_estm{
                    self.handle_witness(main_msg.message, main_msg.round, main_msg.origin, 1).await;
                    self.check_for_ht_witnesses(main_msg.round).await;
                }
                else{
                    rnd_state.terminated_rbcs.insert(rbc_originator);
                    rnd_state.accepted_vals.push(main_msg.value);
                    if rnd_state.terminated_rbcs.len() >= self.num_nodes - self.num_faults{
                        // Has a witness message been sent already? If not, send it. 
                        if !rnd_state.witness_sent{
                            log::info!("Terminated n-f RBCs, sending list of first n-f RBCs to other nodes");
                            // If the round is round zero, reliable broadcast the list of RBCs to other nodes
                            log::info!("Round state: {:?}",rnd_state.terminated_rbcs);
                            if self.round == 0{
                                // start reliable broadcast of list of witnesses
                                let vec_rbcs = Vec::from_iter(rnd_state.terminated_rbcs.clone().into_iter());
                                let msg = Msg{
                                    value: self.value,
                                    origin: self.myid,
                                    round: self.round,
                                    rnd_estm: true,
                                    message: vec_rbcs
                                };
                                let rbc_init_witness = ProtMsg::RBCInit(msg.clone(), self.myid);
                                msgs_to_be_sent.push(rbc_init_witness);
                                //self.estimate_rounds(vec_rbcs).await;
                            }
                            else{
                                let vec_rbcs = Vec::from_iter(rnd_state.terminated_rbcs.clone().into_iter());
                                let witness_msg = ProtMsg::WITNESS(
                                    vec_rbcs.clone(), 
                                    self.myid,
                                    self.round
                                );
                                msgs_to_be_sent.push(witness_msg);
                            }
                            rnd_state.witness_sent = true;
                        }
                        self.check_for_ht_witnesses(main_msg.round).await;
                    }
                }
            }
        }
        else{
            let mut rnd_state = create_roundstate(rbc_originator, &main_msg, self.myid);
            rnd_state.readys.get_mut(&rbc_originator).unwrap().insert(ready_sender);
            // Do not send echo yet, echo needs to come through from RBC_INIT
            round_state_map.insert(main_msg.round, rnd_state);
        }
        //Inserting send message block here to not borrow self as mutable again
        for prot_msg in msgs_to_be_sent.into_iter(){
            self.broadcast(prot_msg.clone()).await;
            match prot_msg {
                ProtMsg::WITNESS(nodes, id, round)=>{
                    self.handle_witness(nodes,round,id,1).await;
                },
                ProtMsg::RBCInit(msg, _id) =>{
                    self.process_rbc_init(msg.clone()).await;
                },
                _=>{}
            }           
        }
    }
}