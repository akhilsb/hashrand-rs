use std::time::SystemTime;

use types::{beacon::{BeaconMsg, CoinMsg}, beacon::CTRBCMsg};

use crate::node::{Context, CTRBCState};

impl Context{
    pub async fn process_rbcinit(self: &mut Context, beacon_msg:BeaconMsg,ctr:CTRBCMsg){
        let now = SystemTime::now();
        if !ctr.verify_mr_proof(){
            log::error!("Invalid Merkle Proof sent by node {} in round {}, abandoning RBC",ctr.origin,ctr.round);
            return;
        }
        if !beacon_msg.verify_proofs(){
            log::error!("Invalid Merkle Proof of secret sent by node {} in round {}, abandoning RBC",ctr.origin,ctr.round);
            return;
        }
        // if beacon_msg.gather_1.is_some(){
        //     // handle gather message right here
        //     // This message only has Gather messages for round r-1
        //     self.process_gatherecho(beacon_msg.gather_1.unwrap().nodes, beacon_msg.origin, beacon_msg.round-1).await;
        // }
        // if beacon_msg.gather_2.is_some(){
        //     // handle gather message right here
        //     // This message only has Gather messages for round r-1
        //     self.process_gatherecho2(beacon_msg.gather_2.unwrap().nodes, beacon_msg.origin, beacon_msg.round-2).await;
        // }
        // TODO: Approximate Agreement remaining
        // let sec_origin = wss_init.origin;
        // // 1. Verify Merkle proof for all secrets first
        // if !wss_init.verify_proofs() || !ctr.verify_mr_proof(){
        //     return;
        // }
        // clone and validate message here before participating in reliable broadcast. 
        // 1. Check if the protocol reached the round for this node
        log::info!("Received RBC Init from node {} for round {}",ctr.origin,beacon_msg.round);
        if !self.round_state.contains_key(&beacon_msg.round){
            let rbc_new_state = CTRBCState::new(self.secret_domain.clone(),self.num_nodes);
            self.round_state.insert(beacon_msg.round, rbc_new_state);
        }
        let rbc_state = self.round_state.get_mut(&beacon_msg.round).unwrap();
        //let master_merkle_root = wss_init.master_root.clone();
        //wss_state.add_batch_secrets(wss_init);
        rbc_state.add_message(beacon_msg.clone(),ctr.clone());
        // 3. Add your own echo and ready to the channel
        rbc_state.add_echo(beacon_msg.origin, self.myid, &ctr);
        rbc_state.add_ready(beacon_msg.origin, self.myid, &ctr);
        // 4. Broadcast echos and benchmark results
        self.broadcast(CoinMsg::CTRBCEcho(ctr.clone(), ctr.mp.root(),self.myid),ctr.round).await;
        self.add_benchmark(String::from("process_batchwss_init"), now.elapsed().unwrap().as_nanos());
    }
}