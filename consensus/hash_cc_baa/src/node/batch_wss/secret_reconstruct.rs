use std::{sync::Arc, collections::HashMap, time::{SystemTime, UNIX_EPOCH}};

use crypto::hash::{do_hash, Hash, do_hash_merkle};
use num_bigint::{BigInt, Sign};
use types::{hash_cc::{WSSMsg, ProtMsg, WrapperMsg}, appxcon::HashingAlg, Replica};

use crate::node::{Context, ShamirSecretSharing};

pub async fn send_batchreconstruct(cx: &mut Context, sec_num:usize){
    let vss_state = &mut cx.batchvss_state;
    let mut msgs_to_be_sent:Vec<ProtMsg> = Vec::new();
    for (rep,batch_wss) in vss_state.node_secrets.clone().into_iter(){
        if vss_state.terminated_secrets.contains(&rep){
            let secret = batch_wss.secrets.get(sec_num).unwrap().clone();
            let nonce = batch_wss.commitments.get(sec_num).unwrap().0.clone();
            let merkle_proof = batch_wss.mps.get(sec_num).unwrap().clone();
            //let mod_prime = cx.secret_domain.clone();
            let sec_bigint = BigInt::from_bytes_be(Sign::Plus, secret.as_slice());
            let nonce_bigint = BigInt::from_bytes_be(Sign::Plus, nonce.as_slice());
            let added_secret = sec_bigint+nonce_bigint;
            let addsec_bytes = added_secret.to_bytes_be().1;
            let hash_add = do_hash(addsec_bytes.as_slice());
            let wss_msg = WSSMsg::new(secret, rep, (nonce,hash_add), merkle_proof);
            if vss_state.secret_shares.contains_key(&rep){
                vss_state.secret_shares.get_mut(&rep).unwrap().insert(cx.myid, (sec_num,wss_msg.clone()));
            }
            else{
                let mut secret_map = HashMap::default();
                secret_map.insert(cx.myid, (sec_num,wss_msg.clone()));
                vss_state.secret_shares.insert(rep, secret_map);
            }
            let prot_msg = ProtMsg::BatchSecretReconstruct(wss_msg, cx.myid,sec_num);
            msgs_to_be_sent.push(prot_msg);
        }
    }
    for prot_msg in msgs_to_be_sent.iter(){
        let sec_key_map = cx.sec_key_map.clone();
        for (replica,sec_key) in sec_key_map.into_iter() {
            if replica != cx.myid{
                let wrapper_msg = WrapperMsg::new(prot_msg.clone(), cx.myid, &sec_key.as_slice());
                let sent_msg = Arc::new(wrapper_msg);
                cx.c_send(replica, sent_msg).await;
            }
        }
        log::info!("Broadcasted message {:?}",prot_msg.clone());
    }
}

pub async fn process_batchreconstruct(cx: &mut Context,wss_msg:WSSMsg,share_sender:Replica, sec_num:usize){
    let vss_state = &mut cx.batchvss_state;
    let res_appxcon = &mut cx.nz_appxcon_rs;
    let sec_origin = wss_msg.origin.clone();
    let sharing_merkle_root:Hash = vss_state.comm_vectors.get(&sec_origin).unwrap()[sec_num].clone();
    if vss_state.recon_secret > sec_num{
        log::info!("Older secret share received from node {}, not processing share", sec_origin);
        return;
    }
    // first validate Merkle proof
    let mod_prime = cx.secret_domain.clone();
    let nonce = BigInt::from_bytes_be(Sign::Plus, wss_msg.commitment.0.clone().as_slice());
    let secret = BigInt::from_bytes_be(Sign::Plus, wss_msg.secret.clone().as_slice());
    let comm = nonce+secret;
    let commitment = do_hash(comm.to_bytes_be().1.as_slice());
    let merkle_proof = wss_msg.mp.to_proof();
    if commitment != wss_msg.commitment.1.clone() || 
            do_hash_merkle(commitment.as_slice()) != merkle_proof.item().clone() || 
            !merkle_proof.validate::<HashingAlg>() ||
            merkle_proof.root() != sharing_merkle_root
            {
        log::error!("Merkle proof invalid for WSS Init message comm: {:?} wss_com: {:?} sec_num: {} commvec:mr: {:?} share_merk_root: {:?}  inst: {} merk_hash: {:?} merk_proof_item: {:?}",commitment,wss_msg.commitment.1.clone(),sec_num,sharing_merkle_root,merkle_proof.root(),sec_origin,do_hash_merkle(commitment.as_slice()), merkle_proof.item().clone());
        return;
    }
    if vss_state.secret_shares.contains_key(&sec_origin){
        let sec_map = vss_state.secret_shares.get_mut(&sec_origin).unwrap();
        sec_map.insert(share_sender, (sec_num,wss_msg.clone()));
        if sec_map.len() == cx.num_faults+1{
            // on having t+1 secret shares, try reconstructing the original secret
            log::info!("Received t+1 shares for secret instantiated by {}, reconstructing secret",sec_origin);
            let secret_shares:Vec<(Replica,BigInt)> = 
                sec_map.clone().into_iter()
                .map(|(rep,(_sec_num,wss_msg))| 
                    (rep+1,BigInt::from_bytes_be(Sign::Plus,wss_msg.secret.clone().as_slice()))
                ).collect();
            let faults = cx.num_faults.clone();
                let shamir_ss = ShamirSecretSharing{
                threshold:faults+1,
                share_amount:3*faults+1,
                prime: mod_prime.clone()
            };
            
            // TODO: Recover all shares of the polynomial and verify if the Merkle tree was correctly constructed
            let secret = shamir_ss.recover(&secret_shares);
            vss_state.reconstructed_secrets.insert(sec_origin, secret.clone());
            // check if for all appxcon non zero termination instances, whether all secrets have been terminated
            // if yes, just output the random number
            if res_appxcon.contains_key(&sec_origin){
                let appxcox_var = res_appxcon.get_mut(&sec_origin).unwrap();
                if !appxcox_var.1{
                    let sec_contribution = (appxcox_var.0.clone()*secret.clone());
                    appxcox_var.1 = true;
                    appxcox_var.2 = sec_contribution;
                }
            }
            if res_appxcon.len() == vss_state.reconstructed_secrets.len(){
                let mut sum_vars = BigInt::from(0i32);
                for (_rep,(_appx,_bcons,sec_contrib)) in res_appxcon.clone().into_iter(){
                    sum_vars = sum_vars + sec_contrib;
                }
                let rand_fin = sum_vars.clone() % mod_prime.clone();
                let mod_number = mod_prime.clone()/(cx.num_nodes);
                let leader_elected = rand_fin.clone()/mod_number;
                log::error!("Random leader election terminated random number: sec_origin {} rand_fin{} leader_elected {}, elected leader is node",sum_vars.clone(),rand_fin.clone(),leader_elected.clone());
                log::error!("{:?}",SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis());
                // Mark this secret as used, use the next secret from this point on
                vss_state.recon_secret = sec_num+1;
                vss_state.secret_shares.clear();
                vss_state.reconstructed_secrets.clear();
                for (_rep,(_appx_con, processed, _num)) in res_appxcon.iter_mut(){
                    *processed = false;
                }
                if vss_state.recon_secret < cx.num_nodes{
                    send_batchreconstruct(cx, sec_num+1).await;
                }
            }
        }
    }
    else {
        let mut nhash_map:HashMap<usize, (usize,WSSMsg)> = HashMap::default();
        nhash_map.insert(share_sender, (sec_num,wss_msg.clone()));
        vss_state.secret_shares.insert(sec_origin, nhash_map);
    }
}