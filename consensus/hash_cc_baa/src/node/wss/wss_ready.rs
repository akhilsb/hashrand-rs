use std::{collections::HashSet,time::SystemTime};

use types::{Replica, hash_cc::{CoinMsg, WrapperMsg}};

use crate::node::{Context};
use crypto::hash::{Hash};

impl Context{
    pub async fn process_wssready(self: &mut Context, mr:Hash, sec_origin:Replica, ready_sender:Replica){
        let now = SystemTime::now();
        let func_name = String::from("process_wssready");
        let vss_state = &mut self.vss_state;
        let mut msgs_to_be_sent:Vec<CoinMsg> = Vec::new();
        // Highly unlikely that the node will get an echo before rbc_init message
        log::info!("Received READY message {:?} for secret from {}",mr.clone(),sec_origin);
        // If RBC already terminated, do not consider this RBC
        if vss_state.terminated_secrets.contains(&sec_origin){
            log::info!("Terminated secretsharing of instance {} already, skipping this ready",sec_origin);
            return;
        }
        match vss_state.node_secrets.get(&sec_origin){
            None => {
                log::error!("WSS init not found for echo, discarding message {}",sec_origin);
                return;
            }
            Some(_x) =>{}
        }
        let mp = vss_state.node_secrets.get(&sec_origin).unwrap().3.clone();
        if mp.to_proof().root() != mr{
            log::error!("Merkle root of WSS Init from {} did not match Merkle root of READY from {}",sec_origin,self.myid);
            return;
        }
        match vss_state.readys.get_mut(&sec_origin) {
            None => {
                let mut readyset = HashSet::default();
                readyset.insert(ready_sender);
                vss_state.echos.insert(sec_origin, readyset);
            },
            Some(x) => {
                x.insert(ready_sender);
            }
        }
        let readys = vss_state.readys.get_mut(&sec_origin).unwrap();
        // 2. Check if echos reached the threshold, init already received, and round number is matching
        log::debug!("WSS READY check: echos.len {}, contains key: {}"
            ,readys.len(),vss_state.node_secrets.contains_key(&sec_origin));
        if readys.len() == self.num_faults+1 && 
            vss_state.node_secrets.contains_key(&sec_origin){ 
            // Broadcast readys, otherwise, just wait longer
            msgs_to_be_sent.push(CoinMsg::WSSReady(mr.clone(), sec_origin, self.myid));
        }
        else if readys.len() >= self.num_nodes-self.num_faults && 
            vss_state.node_secrets.contains_key(&sec_origin){
            log::info!("Terminated WSS instance of node {}",sec_origin);
            let secret_info = vss_state.node_secrets.get(&sec_origin).unwrap();
            vss_state.accepted_secrets.insert(sec_origin, secret_info.clone());
            vss_state.terminated_secrets.insert(sec_origin);
            // Check for ECHO2 messages
            if vss_state.terminated_secrets.len() >= self.num_nodes-self.num_faults{
                if !vss_state.send_w1{
                    log::info!("Terminated n-f wss instances. Sending echo2 message to everyone");
                    msgs_to_be_sent.push(CoinMsg::GatherEcho(vss_state.terminated_secrets.clone().into_iter().collect(), self.myid));
                    vss_state.send_w1 = true;
                }
                self.witness_check().await;
            }
        }
        // Inserting send message block here to not borrow self as mutable again
        for prot_msg in msgs_to_be_sent.iter(){
            let sec_key_map = self.sec_key_map.clone();
            for (replica,sec_key) in sec_key_map.into_iter() {
                if replica != self.myid{
                    let wrapper_msg = WrapperMsg::new(prot_msg.clone(), self.myid, &sec_key.as_slice());
                    self.net_send.send(replica, wrapper_msg).await;
                }
                else {
                    match prot_msg {
                        CoinMsg::GatherEcho(vec_term_secs, echo_sender) =>{
                            self.process_gatherecho( vec_term_secs.clone(), *echo_sender, 1).await;
                        },
                        _ => {}
                    }
                }
            }
            //log::info!("Broadcasted message {:?}",prot_msg.clone());
        }
        let passed = now.elapsed().unwrap().as_nanos();
        if self.bench.contains_key(&func_name) && *self.bench.get(&func_name).unwrap() < passed{
            self.bench.insert(func_name, passed);
        }
    }
}