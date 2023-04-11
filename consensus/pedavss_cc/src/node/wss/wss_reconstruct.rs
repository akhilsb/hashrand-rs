use std::{collections::HashMap, time::{SystemTime, UNIX_EPOCH}};

use bls12_381_plus::{Scalar, G1Projective};
use num_bigint::{BigInt, Sign};
use types::{hash_cc::{CoinMsg}, Replica, SyncMsg, SyncState};
use vsss_rs::{Share, FeldmanVerifier, Feldman};

use crate::node::{Context, FAULTS};

impl Context{
    pub async fn send_reconstruct(self: &mut Context){
        let vss_state = &mut self.vss_state;
        let secret_shares = &mut self.secret_shares;
        let mut msgs_to_be_sent:Vec<CoinMsg> = Vec::new();
        for (rep,(secret,_verifier)) in vss_state.clone().into_iter(){
            if secret_shares.contains_key(&rep){
                secret_shares.get_mut(&rep).unwrap().insert(self.myid, secret.clone());
            }
            else{
                let mut secret_map = HashMap::default();
                secret_map.insert(self.myid, secret.clone());
                secret_shares.insert(rep, secret_map);
            }
            let prot_msg = CoinMsg::PedAVSSSRecon(secret.clone(), self.myid,rep.clone());
            msgs_to_be_sent.push(prot_msg);
        }
        for prot_msg in msgs_to_be_sent.iter(){
            self.broadcast(prot_msg.clone()).await;
            log::info!("Broadcasted message {:?}",prot_msg.clone());
        }
    }
    
    pub async fn process_reconstruct(self: &mut Context,secret:Vec<u8>, ss_sender:Replica, ss_init: Replica){
        let sec_origin = ss_init.clone();
        let vss_state = &mut self.vss_state;
        let gather_state = &mut self.witness_state;
        let res_appxcon = &mut self.nz_appxcon_rs;
        let secret_shares = &mut self.secret_shares;
        
        if secret_shares.contains_key(&sec_origin) && vss_state.contains_key(&sec_origin){
            // verify validity of share first
            let (_,verf) = vss_state.get(&sec_origin).unwrap();
            let sec_share = bincode::deserialize::<Share<33>>(&secret.clone().as_slice()).unwrap();
            let verf_verifier = bincode::deserialize::<FeldmanVerifier<Scalar, G1Projective, {FAULTS+1}>>(verf.clone().as_slice()).unwrap();
            if !verf_verifier.verify(&sec_share){
                log::error!("Invalid share sent by node, aborting AVSS");
                return;
            }
            let sec_map = secret_shares.get_mut(&sec_origin).unwrap();
            sec_map.insert(ss_sender, secret.clone());
            if sec_map.len() == FAULTS+1{
                // on having t+1 secret shares, try reconstructing the original secret
                let shares:Vec<Share<33>> = sec_map.iter()
                                                    .map(|(_,share)|{
                                                        bincode::deserialize::<Share<33>>(share.clone().as_slice()).unwrap()
                                                    })
                                                    .collect();
                let share_arr :[Share<33>;FAULTS+1]= shares.try_into().unwrap();
                let res = Feldman::<{FAULTS+1}, {3*FAULTS+1}>::combine_shares::<Scalar, 33>(&share_arr);
                //assert!(res.is_ok());
                let secret_1 = res.unwrap();
                log::info!("Secret reconstructed: {}",secret_1);
                let recon_sec_bi = BigInt::from_bytes_be(Sign::Plus, &secret_1.to_bytes());
                gather_state.reconstructed_secrets.insert(sec_origin, recon_sec_bi.clone());
                // check if for all appxcon non zero termination instances, whether all secrets have been terminated
                // if yes, just output the random number
                if res_appxcon.contains_key(&sec_origin){
                    let appxcox_var = res_appxcon.get_mut(&sec_origin).unwrap();
                    if !appxcox_var.1{
                        let sec_contribution = appxcox_var.0.clone()*recon_sec_bi.clone();
                        appxcox_var.1 = true;
                        appxcox_var.2 = sec_contribution;
                    }
                }
                if res_appxcon.len() == gather_state.reconstructed_secrets.len(){
                    log::info!("Implementing common coin: {:?}",res_appxcon.clone());
                    let mut sum_vars = BigInt::from(0i32);
                    for (_rep,(_appx,_bcons,sec_contrib)) in res_appxcon.clone().into_iter(){
                        sum_vars = sum_vars + sec_contrib;
                    }
                    let cancel_handler = self.sync_send.send(0, SyncMsg { sender: self.myid, state: SyncState::CompletedRecon, value:0}).await;
                    self.add_cancel_handler(cancel_handler);
                    //let rand_fin = sum_vars.clone() % mod_prime.clone();
                    //let mod_number = mod_prime.clone()/(self.num_nodes);
                    //let leader_elected = rand_fin.clone()/mod_number;
                    //log::error!("Random leader election terminated random number: sec_origin {} rand_fin{} leader_elected {}, elected leader is node",sum_vars.clone(),sum_vars.clone(),sum_vars.clone());
                    log::error!("Recon ended: {:?}",SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis());
                    log::error!("Number of messages sent by nodes: {}",self.num_messages);
                }
            }
        }
        else {
            let mut nhash_map:HashMap<usize, Vec<u8>> = HashMap::default();
            nhash_map.insert(ss_sender, secret);
            secret_shares.insert(sec_origin, nhash_map);
        }
    }
}