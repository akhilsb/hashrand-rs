use std::time::SystemTime;

use async_recursion::async_recursion;
use crypto::hash::Hash;
use types::beacon::{CTRBCMsg, Replica, CoinMsg};

use crate::node::{HashRand, CTRBCState};

impl HashRand{
    #[async_recursion]
    pub async fn process_ready(self: &mut HashRand, ctrbc:CTRBCMsg,master_root:Hash,ready_sender:Replica){
        let _now = SystemTime::now();
        if !self.round_state.contains_key(&ctrbc.round){
            let rbc_new_state = CTRBCState::new(self.secret_domain.clone(),self.num_nodes);
            self.round_state.insert(ctrbc.round, rbc_new_state);
        }
        let rbc_state = self.round_state.get_mut(&ctrbc.round).unwrap();
        let sec_origin = ctrbc.origin;
        log::info!("Received READY message from {} for secret from {} in round {}",ready_sender,ctrbc.origin,ctrbc.round);
        // Highly unlikely that the node will get an echo before rbc_init message
        // If RBC already terminated, do not consider this RBC
        if rbc_state.terminated_secrets.contains(&sec_origin){
            //log::info!("RBC State {:?}",rbc_state);
            log::info!("Terminated secretsharing of instance {} already, skipping this echo",sec_origin);
            return;
        }
        match rbc_state.msgs.get(&sec_origin){
            None => {
                rbc_state.add_ready(sec_origin, ready_sender, &ctrbc);
                return;
            }
            Some(_x) =>{}
        }
        let (_beacon,shard) = rbc_state.msgs.get(&sec_origin).unwrap();
        let mp = shard.mp.clone();
        if mp.root() != master_root || !ctrbc.verify_mr_proof(){
            log::error!("Merkle root of WSS Init from {} did not match Merkle root of READY from {}",sec_origin,self.myid);
            return;
        }
        rbc_state.add_ready(sec_origin, ready_sender, &ctrbc);
        let res = rbc_state.ready_check(sec_origin, self.num_nodes.clone(), self.num_faults.clone(), self.batch_size.clone());
        match res.1{
            None => {
                return;
            }
            Some(root_vec) =>{
                // Conduct Bracha Amplification
                if res.0 == self.num_faults +1{
                    let shard = rbc_state.echos.get(&sec_origin).unwrap().get(&self.myid).unwrap();
                    let ctrbc = CTRBCMsg::new(shard.0.clone(), shard.1.clone(), ctrbc.round, sec_origin);
                    rbc_state.add_ready(sec_origin, self.myid, &ctrbc);
                    self.broadcast(CoinMsg::CTRBCReady(ctrbc.clone(),root_vec.0, self.myid),ctrbc.round).await;
                    //self.process_batchwssready(ctrbc.clone(), master_root, self.myid).await;
                }
                else if res.0 == self.num_nodes-self.num_faults {
                    let shard = rbc_state.echos.get(&sec_origin).unwrap().get(&self.myid).unwrap();
                    let ctrbc = CTRBCMsg::new(shard.0.clone(), shard.1.clone(), ctrbc.round, sec_origin);
                    self.broadcast(CoinMsg::CTRBCReconstruct(ctrbc.clone(),master_root.clone(), self.myid),ctrbc.round).await;
                    self.process_reconstruct(ctrbc,master_root.clone(),self.myid).await;
                }
                else {
                    return;
                }
            }
        }
    }
}