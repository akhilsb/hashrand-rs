use std::{sync::Arc, time::{SystemTime, UNIX_EPOCH}};

use async_recursion::async_recursion;
use crypto::hash::verf_mac;
use crypto_blstrs::{crypto::threshold_sig::{SecretKey, CombinableSignature, PublicKey}, threshold_sig::{PartialBlstrsSignature, BlstrsSignature}};
use num_bigint::{BigUint};
use types::{Round};

//use tbls::{schemes::bls12_377::G1Scheme as SigScheme, sig::ThresholdScheme};

use super::{WrapperMsg, GlowLib};

impl GlowLib{
    pub fn check_proposal(&self,wrapper_msg: Arc<WrapperMsg>) -> bool {
        // validate MAC
        let byte_val = bincode::serialize(&wrapper_msg.data).expect("Failed to serialize object");
        let sec_key = match self.sec_key_map.get(&wrapper_msg.clone().sender) {
            Some(val) => {val},
            None => {panic!("Secret key not available, this shouldn't happen")},
        };
        if !verf_mac(&byte_val,&sec_key.as_slice(),&wrapper_msg.mac){
            log::warn!("MAC Verification failed.");
            return false;
        }
        true
    }
    pub async fn process(&mut self,wrapper: WrapperMsg){
        log::debug!("Received protocol msg: {:?}",wrapper);
        let msg = Arc::new(wrapper.clone());
        if self.check_proposal(msg){
            self.handle_incoming_agg(wrapper.round, wrapper).await;
        }
    }

    // pub async fn handle_incoming(&mut self,round:Round, wrapper_msg: WrapperMsg){
    //     if !self.state.contains_key(&round){
    //         self.start_round(round).await;
    //     }
    //     let sign = self.state.get_mut(&round).unwrap();
    //     match sign.handle_incoming(Msg{
    //         sender: wrapper_msg.sender+1,
    //         receiver:None,
    //         body:wrapper_msg.protmsg.unwrap()
    //     }) {
    //         Ok(x)=>{
    //             log::info!("Got the following message {:?}",x);
    //         },
    //         Err(x) => {
    //             log::error!("Got the following error message {:?}",x);
    //         }
    //     }
    //     self.empty_queue_and_proceed(round).await;
    // }

    // #[async_recursion]
    // pub async fn start_round(&mut self,round:Round){
    //     if !self.state.contains_key(&round){
    //         let mut beacon_msg = self.sign_msg.clone();
    //         beacon_msg.push_str(round.to_string().as_str());
    //         log::info!("Signing string {:?}",beacon_msg);
    //         let glow_bls_state = Sign::new(
    //             beacon_msg.into_bytes(), 
    //             self.myid+1, 
    //             self.num_nodes, 
    //             self.secret.clone()
    //         ).unwrap();
    //         // Send outgoing messages
    //         self.state.insert(round, glow_bls_state);
    //         self.empty_queue_and_proceed(round).await;
    //     }
    // }

    #[async_recursion]
    pub async fn start_round_agg(&mut self,round:Round){
        let unix_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
        let mut beacon_msg = self.sign_msg.clone();
        beacon_msg.push_str(round.to_string().as_str());
        let dst = "Test";
        //let partial_sig = SigScheme::partial_sign(&self.secret_key, beacon_msg.as_bytes()).expect("Partial Signature generation failed");
        let psig = self.secret_key.sign(&beacon_msg, &dst);
        log::debug!("Signing string {:?} time: {}",beacon_msg,SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()-unix_time);
        // Send outgoing messages
        let mut partial_sigs:Vec<PartialBlstrsSignature> = Vec::new();
        partial_sigs.push(psig.clone());
        self.thresh_state.insert(round, partial_sigs);
        let sig_data = bincode::serialize(&psig).expect("Serialization error");
        self.broadcast_tsig(sig_data, round).await;
        //self.empty_queue_and_proceed(round).await;
    }

    pub async fn handle_incoming_agg(&mut self,round:Round, wrapper_msg: WrapperMsg){
        if !self.thresh_state.contains_key(&round){
            self.start_round_agg(round).await;
        }
        let mut beacon_msg = self.sign_msg.clone();
        beacon_msg.push_str(round.to_string().as_str());
        let signature = wrapper_msg.data.clone();
        let psig:PartialBlstrsSignature = bincode::deserialize(signature.as_slice()).expect("Deserialization error");
        //let res_verif = SigScheme::partial_verify(&self.pub_poly_key, &beacon_msg.as_bytes()[..], &signature);
        //match res_verif {
        //    Ok(_)=>{
        // Add signature to state
        let sig_vec = self.thresh_state.get_mut(&round).unwrap();
        if sig_vec.len() >= ((self.num_faults + 1) as usize){
            return;
        }
        else{
            let pkey = self.tpubkey_share.get(&(wrapper_msg.sender+1)).unwrap();
            let mut beacon_msg = self.sign_msg.clone();
            beacon_msg.push_str(round.to_string().as_str());
            let dst = "Test";
            if pkey.verify(&psig, &beacon_msg, &dst){
                log::info!("Signature verification successful, adding sig to map");
                sig_vec.push(psig);
            }
            else {
                log::error!("Signature verification unsuccessful");
                return;
            }
            if sig_vec.len() == (self.num_faults+1) as usize{
                let unix_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
                log::debug!("Aggregating signatures for round {}",round);
                //let threshold_sig = SigScheme::aggregate(self.num_faults as usize, &sig_vec).unwrap();
                let sig = BlstrsSignature::combine((self.num_faults+1) as usize, sig_vec.clone()).expect("Unable to combine threshold sigs");
                log::debug!("Result obtained, the following is the signature: {:?} with agg time: {}",sig,SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()-unix_time);
                let sig_bytes = bincode::serialize(&sig).expect("Serialization error");
                let bigint_num = BigUint::from_bytes_be(&sig_bytes.as_slice());
                let bigint_mod = bigint_num % u128::MAX;
                log::debug!("{:?}",bigint_mod);
                let u128_fit:u128 = bigint_mod.to_string().parse().unwrap();
                log::info!("Sending beacon {:?} to consensus",(round,u128_fit));
                if let Err(e) = self.coin_send_channel.send((round,u128_fit)).await {
                    log::warn!(
                        "Failed to beacon {} to the consensus: {}",
                        round, e
                    );
                };
                self.beac_state.insert(round, u128_fit);
                self.curr_round = round+1;
                // self.start_round_agg(round+1).await;
            }
        }
         //   }
         //   Err(x) => {
        //        log::error!("Signature verification from {} failed because of error {:?}",wrapper_msg.sender,x);
        //    }
        //}
    }

    // async fn empty_queue_and_proceed(&mut self, round:Round){
    //     let glow_bls_state = self.state.get_mut(&round).unwrap();
    //     let msg_queue = glow_bls_state.message_queue();
    //     let mut broadcast_msgs = Vec::new();
    //     while !msg_queue.is_empty(){
    //         broadcast_msgs.push(msg_queue.pop().unwrap());
    //         //self.broadcast(msg.body, round).await;
    //     }
    //     if glow_bls_state.wants_to_proceed(){
    //         glow_bls_state.proceed().unwrap();
    //     }
    //     // Send outgoing messages
    //     let msg_queue = glow_bls_state.message_queue();
    //     while !msg_queue.is_empty(){
    //         broadcast_msgs.push(msg_queue.pop().unwrap());
    //         //let msg = msg_queue.pop().unwrap();
    //     }
    //     if glow_bls_state.is_finished(){
    //         let result = glow_bls_state.pick_output().unwrap().unwrap();
    //         log::info!("Result obtained, the following is the signature: {:?}",result.1.to_bytes(false));
    //         let cancel_handler = self.sync_send.send(0, SyncMsg { sender: self.myid as usize, state: SyncState::BeaconRecon(round, self.myid as usize, round as usize, result.1.to_bytes(false)), value:0}).await;
    //         self.add_cancel_handler(cancel_handler);
    //         self.curr_round = round+1;
    //         self.start_round(round+1).await;
    //     }
    //     for msg in broadcast_msgs.into_iter(){
    //         self.broadcast(msg.body, round).await;
    //     }
    // }
}