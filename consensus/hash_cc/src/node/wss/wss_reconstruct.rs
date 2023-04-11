use std::{collections::HashMap, time::{SystemTime, UNIX_EPOCH}};

use crypto::hash::{do_hash, do_hash_merkle};
use num_bigint::{BigInt, Sign};
use types::{hash_cc::{WSSMsg, CoinMsg}, appxcon::{HashingAlg}, Replica, SyncState, SyncMsg};

use crate::node::{Context, ShamirSecretSharing};

impl Context{
    pub async fn send_reconstruct(self: &mut Context){
        let vss_state = &mut self.vss_state;
        let mut msgs_to_be_sent:Vec<CoinMsg> = Vec::new();
        for (rep,(secret,nonce,_merkle_root,merkle_proof)) in vss_state.accepted_secrets.clone().into_iter(){
            let mod_prime = self.secret_domain.clone();
            let sec_num = BigInt::from_bytes_be(Sign::Plus, secret.clone().as_slice());
            let nonce_num = BigInt::from_bytes_be(Sign::Plus, nonce.clone().as_slice());
            let added_secret = sec_num+nonce_num % mod_prime;
            let addsec_bytes = added_secret.to_bytes_be().1;
            let hash_add = do_hash(addsec_bytes.as_slice());
            let wss_msg = WSSMsg::new(secret, rep, (nonce,hash_add), merkle_proof);
            if vss_state.secret_shares.contains_key(&rep){
                vss_state.secret_shares.get_mut(&rep).unwrap().insert(self.myid, wss_msg.clone());
            }
            else{
                let mut secret_map = HashMap::default();
                secret_map.insert(self.myid, wss_msg.clone());
                vss_state.secret_shares.insert(rep, secret_map);
            }
            let prot_msg = CoinMsg::WSSReconstruct(wss_msg, self.myid);
            msgs_to_be_sent.push(prot_msg);
        }
        for prot_msg in msgs_to_be_sent.iter(){
            self.broadcast(prot_msg.clone()).await;
            log::info!("Broadcasted message {:?}",prot_msg.clone());
        }
    }
    
    pub async fn process_reconstruct(self: &mut Context,wss_msg:WSSMsg,recon_sender:Replica){
        let vss_state = &mut self.vss_state;
        let res_appxcon = &mut self.nz_appxcon_rs;
        let sec_origin = wss_msg.origin.clone();
        // first validate Merkle proof
        let mod_prime = self.secret_domain.clone();
        let nonce = BigInt::from_bytes_be(Sign::Plus, wss_msg.commitment.0.clone().as_slice());
        let secret = BigInt::from_bytes_be(Sign::Plus, wss_msg.secret.clone().as_slice());
        let comm = nonce+secret;
        let commitment = do_hash(comm.to_bytes_be().1.as_slice());
        let merkle_proof = wss_msg.mp.to_proof();
        if commitment != wss_msg.commitment.1.clone() || 
                do_hash_merkle(commitment.as_slice()) != merkle_proof.item().clone() || 
                !merkle_proof.validate::<HashingAlg>(){
            log::error!("Merkle proof invalid for WSS Init message comm: {:?} wss_init: {:?}, merkle_proof_item: {:?}",commitment,wss_msg.clone(),merkle_proof.item().clone());
            return;
        }
        if vss_state.secret_shares.contains_key(&sec_origin){
            let sec_map = vss_state.secret_shares.get_mut(&sec_origin).unwrap();
            sec_map.insert(recon_sender, wss_msg.clone());
            if sec_map.len() == self.num_faults+1{
                // on having t+1 secret shares, try reconstructing the original secret
                log::info!("Received t+1 shares for secret instantiated by {}, reconstructing secret",sec_origin);
                let secret_shares:Vec<(Replica,BigInt)> = 
                    sec_map.clone().into_iter()
                    .map(|(rep,wss_msg)| 
                        (rep+1,BigInt::from_bytes_be(Sign::Plus,wss_msg.secret.clone().as_slice()))
                    ).collect();
                let faults = self.num_faults.clone();
                    let shamir_ss = ShamirSecretSharing{
                    threshold:faults+1,
                    share_amount:3*faults+1,
                    prime: mod_prime.clone()
                };
                // TODO: Recover all shares of the polynomial and verify if the Merkle tree was correctly constructed
                let secret = shamir_ss.recover(&secret_shares);
                log::info!("Secret reconstructed: {}",secret);
                vss_state.reconstructed_secrets.insert(sec_origin, secret.clone());
                // check if for all appxcon non zero termination instances, whether all secrets have been terminated
                // if yes, just output the random number
                if res_appxcon.contains_key(&sec_origin){
                    let appxcox_var = res_appxcon.get_mut(&sec_origin).unwrap();
                    if !appxcox_var.1{
                        let sec_contribution = appxcox_var.0.clone()*secret.clone();
                        appxcox_var.1 = true;
                        appxcox_var.2 = sec_contribution;
                    }
                }
                if res_appxcon.len() == vss_state.reconstructed_secrets.len(){
                    log::info!("Implementing common coin: {:?}",res_appxcon.clone());
                    let mut sum_vars = BigInt::from(0i32);
                    for (_rep,(_appx,_bcons,sec_contrib)) in res_appxcon.clone().into_iter(){
                        sum_vars = sum_vars + sec_contrib;
                    }
                    let rand_fin = sum_vars.clone() % mod_prime.clone();
                    let mod_number = mod_prime.clone()/(self.num_nodes);
                    let leader_elected = rand_fin.clone()/mod_number;
                    //log::error!("Random leader election terminated random number: sec_origin {} rand_fin{} leader_elected {}, elected leader is node",sum_vars.clone(),rand_fin.clone(),leader_elected.clone());
                    log::error!("Terminated Recon {:?}",SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis());
                    let cancel_handler = self.sync_send.send(0, SyncMsg { sender: self.myid, state: SyncState::CompletedRecon,value:0 }).await;
                    self.add_cancel_handler(cancel_handler);
                    log::error!("Number of messages sent by nodes: {}",self.num_messages);
                }
            }
        }
        else {
            let mut nhash_map:HashMap<usize, WSSMsg> = HashMap::default();
            nhash_map.insert(recon_sender, wss_msg.clone());
            vss_state.secret_shares.insert(sec_origin, nhash_map);
        }
    }
}