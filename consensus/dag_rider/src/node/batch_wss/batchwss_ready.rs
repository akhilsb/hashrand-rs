use std::{time::SystemTime};

use async_recursion::async_recursion;
use types::{Replica, hash_cc::{CoinMsg, CTRBCMsg, SMRMsg}};

use crate::node::{Context};
use crypto::hash::{Hash};

impl Context{
    #[async_recursion]
    pub async fn process_batchwssready(self: &mut Context, ctrbc:CTRBCMsg,master_root:Hash,ready_sender:Replica, smr_msg:&mut SMRMsg){
        let now = SystemTime::now();
        let vss_state = &mut self.cur_batchvss_state;
        let sec_origin = ctrbc.origin;
        // Highly unlikely that the node will get an echo before rbc_init message
        log::debug!("Received READY message from {} for secret from {} in round {}",ready_sender,sec_origin,ctrbc.round);
        // If RBC already terminated, do not consider this RBC
        if vss_state.terminated_secrets.contains(&sec_origin){
            log::debug!("Terminated secretsharing of instance {} already, skipping this echo",sec_origin);
            return;
        }
        match vss_state.node_secrets.get(&sec_origin){
            None => {
                vss_state.add_ready(sec_origin, ready_sender, &ctrbc);
                return;
            }
            Some(_x) =>{}
        }
        let mp = vss_state.node_secrets.get(&sec_origin).unwrap().master_root;
        if mp != master_root || !ctrbc.verify_mr_proof(){
            log::error!("Merkle root of WSS Init from {} did not match Merkle root of READY from {}",sec_origin,ready_sender);
            return;
        }
        vss_state.add_ready(sec_origin, ready_sender, &ctrbc);
        let res = vss_state.ready_check(sec_origin, self.num_nodes.clone(), self.num_faults.clone(), self.batch_size.clone());
        match res.1{
            None => {
                return;
            }
            Some(root_vec) =>{
                if res.0 == self.num_faults +1 && !vss_state.readys.contains_key(&self.myid){
                    let shard = vss_state.echos.get(&sec_origin).unwrap().get(&self.myid).unwrap();
                    let ctrbc = CTRBCMsg::new(shard.0.clone(), shard.1.clone(), 0, sec_origin);
                    vss_state.add_ready(sec_origin, self.myid, &ctrbc);
                    smr_msg.coin_msg = CoinMsg::BatchWSSReady(ctrbc.clone(),root_vec.0, self.myid);
                    self.broadcast(&mut smr_msg.clone()).await;
                    self.process_batchwssready(ctrbc.clone(), master_root, self.myid,smr_msg).await;
                }
                else if res.0 == self.num_nodes-self.num_faults {
                    let shard = vss_state.echos.get(&sec_origin).unwrap().get(&self.myid).unwrap();
                    let ctrbc = CTRBCMsg::new(shard.0.clone(), shard.1.clone(), 0, sec_origin);
                    smr_msg.coin_msg = CoinMsg::BatchWSSReconstruct(ctrbc.clone(),master_root.clone(), self.myid);
                    self.broadcast(&mut smr_msg.clone()).await;
                    self.process_batchreconstruct_message(ctrbc,master_root.clone(),self.myid,smr_msg).await;
                }
                else {
                    return;
                }
            }
        }
        self.add_benchmark(String::from("process_batchwssready"), now.elapsed().unwrap().as_nanos());
    }
}