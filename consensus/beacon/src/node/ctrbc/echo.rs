use std::{time::SystemTime};

use async_recursion::async_recursion;
use types::{Replica, beacon::{CoinMsg, CTRBCMsg}};

use crate::node::{Context, CTRBCState};
use crypto::hash::{Hash};

impl Context{
    #[async_recursion]
    pub async fn process_echo(self: &mut Context,ctrbc:CTRBCMsg,master_root:Hash ,echo_sender:Replica){
        let now = SystemTime::now();
        if !self.round_state.contains_key(&ctrbc.round){
            let rbc_new_state = CTRBCState::new(self.secret_domain.clone(),self.num_nodes);
            self.round_state.insert(ctrbc.round, rbc_new_state);
        }
        let rbc_state = self.round_state.get_mut(&ctrbc.round).unwrap();
        //let vss_state = &mut self.batchvss_state;
        let sec_origin = ctrbc.origin;
        // Highly unlikely that the node will get an echo before rbc_init message
        log::info!("Received ECHO message from {} for secret from {} in round {}",echo_sender,ctrbc.origin,ctrbc.round);
        // If RBC already terminated, do not consider this RBC
        if rbc_state.terminated_secrets.contains(&sec_origin){
            log::info!("Terminated secretsharing of instance {} already, skipping this echo",sec_origin);
            return;
        }
        match rbc_state.msgs.get(&sec_origin){
            None => {
                rbc_state.add_echo(sec_origin, echo_sender, &ctrbc);
                return;
            }
            Some(_x) =>{}
        }
        let (_beacon,shard) = rbc_state.msgs.get(&sec_origin).unwrap();
        let mp = shard.mp.clone();
        if mp.root() != master_root || !ctrbc.verify_mr_proof(){
            log::error!("Merkle root of WSS Init from {} did not match Merkle root of ECHO from {}",sec_origin,self.myid);
            return;
        }
        rbc_state.add_echo(sec_origin, echo_sender, &ctrbc);
        let hash_root = rbc_state.echo_check(sec_origin, self.num_nodes, self.num_faults, self.batch_size);
        match hash_root {
            None => {
                return;
            },
            Some(vec_hash_root) => {
                let echos = rbc_state.echos.get_mut(&sec_origin).unwrap();
                let shard = echos.get(&self.myid).unwrap();
                let ctrbc = CTRBCMsg::new(shard.0.clone(), shard.1.clone(), ctrbc.round, sec_origin);
                rbc_state.add_ready(sec_origin, self.myid, &ctrbc);
                self.broadcast(CoinMsg::CTRBCReady(ctrbc.clone(), vec_hash_root.0, self.myid),ctrbc.round).await;
                self.process_ready( ctrbc.clone(), master_root, self.myid).await;
            }
        }
        self.add_benchmark(String::from("process_batch_wssecho"), now.elapsed().unwrap().as_nanos());
    }
}