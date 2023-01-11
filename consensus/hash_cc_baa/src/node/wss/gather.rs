use std::{time::SystemTime};

use async_recursion::async_recursion;
use network::NetSender;
use num_bigint::BigInt;
use num_traits::pow;
use types::{hash_cc::{CoinMsg, WrapperMsg}, Replica};

use crate::node::{Context};
impl Context {
    pub async fn process_gatherecho(self: &mut Context,wss_indices:Vec<Replica>, echo_sender:Replica,round: u32){
        let now = SystemTime::now();
        let vss_state = &mut self.batchvss_state;
        log::info!("Received gather echo message {:?} from node {} for round {}",wss_indices.clone(),echo_sender,round);
        if vss_state.send_w2{
            if round == 2{
                vss_state.witness2.insert(echo_sender, wss_indices);
                self.add_benchmark(String::from("process_gatherecho"), now.elapsed().unwrap().as_nanos());
                self.witness_check().await;
            }
            else {
                log::warn!("Ignoring echo1 because protocol moved forward to echo2s");
                return;
            }
        }
        else {
            if round == 1{
                vss_state.witness1.insert(echo_sender, wss_indices);
            }
            else{
                vss_state.witness2.insert(echo_sender, wss_indices);
            }
            self.add_benchmark(String::from("process_gatherecho"), now.elapsed().unwrap().as_nanos());
            self.witness_check().await;
        }
    }
    
    #[async_recursion]
    pub async fn witness_check(self: &mut Context){
        let now = SystemTime::now();
        let vss_state = &mut self.batchvss_state;
        let mut i = 0;
        if vss_state.terminated_secrets.len() <= self.num_faults+1{
            return;
        }
        let mut msgs_to_be_sent:Vec<CoinMsg> = Vec::new();
        if !vss_state.send_w2{
            for (_replica,ss_inst) in vss_state.witness1.clone().into_iter(){
                let check = ss_inst.iter().all(|item| vss_state.terminated_secrets.contains(item));
                if check {
                    i = i+1;
                }
            }
        
            if i >= self.num_nodes-self.num_faults{
                // Send out ECHO2 messages
                log::info!("Accepted n-f witnesses, sending ECHO2 messages for Gather from node {}",self.myid);
                vss_state.send_w2 = true;
                msgs_to_be_sent.push(CoinMsg::GatherEcho2(vss_state.terminated_secrets.clone().into_iter().collect() , self.myid));
            }
        }
        else{
            for (_replica,ss_inst) in vss_state.witness2.clone().into_iter(){
                let check = ss_inst.iter().all(|item| vss_state.terminated_secrets.contains(item));
                if check {
                    i = i+1;
                }
            }    
            if i >= self.num_nodes-self.num_faults{
                // Received n-f witness2s. Start approximate agreement from here. 
                log::info!("Accepted n-f witness2 for node {} with set {:?}",self.myid,vss_state.terminated_secrets.clone());
                let terminated_secrets = vss_state.terminated_secrets.clone();
                let mut transmit_vector:Vec<(Replica,BigInt)> = Vec::new();
                let rounds = self.rounds_aa;
                for i in 0..self.num_nodes{
                    if !terminated_secrets.contains(&i) {
                        let zero = BigInt::from(0);
                        transmit_vector.push((i,zero));
                    }
                    else {
                        let max = BigInt::from(2);
                        let max_power = pow(max, rounds as usize);
                        transmit_vector.push((i,max_power));
                    }
                }
                self.add_benchmark(String::from("witness_check"), now.elapsed().unwrap().as_nanos());
                self.start_baa(transmit_vector,0).await;
            }
        }
        for prot_msg in msgs_to_be_sent.iter(){
            let sec_key_map = self.sec_key_map.clone();
            for (replica,sec_key) in sec_key_map.into_iter() {
                if replica != self.myid{
                    let wrapper_msg = WrapperMsg::new(prot_msg.clone(), self.myid, &sec_key.as_slice());
                    self.send(replica, wrapper_msg).await;
                }
                else {
                    match prot_msg {
                        CoinMsg::GatherEcho2(vec_term_secs, echo_sender) =>{
                            self.process_gatherecho( vec_term_secs.clone(), *echo_sender, 2).await;
                        },
                        _ => {}
                    }
                }
            }
            log::info!("Broadcasted message {:?}",prot_msg.clone());
        }
    }
}