use std::{collections::HashSet};

use types::{Replica, hash_cc::{CoinMsg}};

use crate::node::{Context};
use crypto::hash::{Hash};

impl Context{
    pub async fn process_wssecho(self: &mut Context,mr:Hash,sec_origin:Replica, echo_sender:Replica){
        let vss_state = &mut self.vss_state;
        // Highly unlikely that the node will get an echo before rbc_init message
        log::info!("Received ECHO message {:?} for secret from {}",mr.clone(),echo_sender);
        // If RBC already terminated, do not consider this RBC
        if vss_state.terminated_secrets.contains(&sec_origin){
            log::info!("Terminated secretsharing of instance {} already, skipping this echo",sec_origin);
            return;
        }
        match vss_state.node_secrets.get(&sec_origin){
            None => {
                let mut echoset = HashSet::default();
                echoset.insert(echo_sender);
                vss_state.echos.insert(sec_origin, echoset);
                return;
            }
            Some(_x) =>{}
        }
        let mp = vss_state.node_secrets.get(&sec_origin).unwrap().3.clone();
        if mp.to_proof().root() != mr{
            log::error!("Merkle root of WSS Init from {} did not match Merkle root of ECHO from {}",sec_origin,self.myid);
            return;
        }
        match vss_state.echos.get_mut(&sec_origin) {
            None => {
                let mut echoset = HashSet::default();
                echoset.insert(echo_sender);
                vss_state.echos.insert(sec_origin, echoset);
            },
            Some(x) => {
                x.insert(echo_sender);
            }
        }
        let echos = vss_state.echos.get_mut(&sec_origin).unwrap();
        // 2. Check if echos reached the threshold, init already received, and round number is matching
        log::debug!("WSS ECHO check: echos.len {}, contains key: {}"
            ,echos.len(),vss_state.node_secrets.contains_key(&sec_origin));
        if echos.len() == self.num_nodes-self.num_faults && 
            vss_state.node_secrets.contains_key(&sec_origin){
            // Broadcast readys, otherwise, just wait longer
            self.broadcast(CoinMsg::WSSReady(mr.clone(), sec_origin, self.myid)).await;
            self.process_wssready(mr.clone(),sec_origin,self.myid).await;
        }
    }
}