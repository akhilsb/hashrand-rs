use std::{sync::Arc, collections::{HashMap}};

use crypto::hash::{do_hash, Hash, do_hash_merkle};
use merkle_light::merkle::MerkleTree;
use num_bigint::{BigInt, RandBigInt, Sign};
use types::{appxcon::{HashingAlg, MerkleProof, get_shards, verify_merkle_proof}, hash_cc::{ProtMsg, WrapperMsg, BatchWSSMsg, CTRBCMsg}, Replica};

use crate::node::{Context, ShamirSecretSharing, process_batch_wssecho};


pub async fn start_batchwss(cx: &mut Context){
    let faults = cx.num_faults;
    // Secret number can be increased to any number possible, but there exists a performance tradeoff with the size of RBC increasing\
    // TODO: Does it affect security in any manner?
    let secret_num = cx.num_nodes;
    let low_r = BigInt::from(0);
    let prime = BigInt::parse_bytes(b"685373784908497",10).unwrap(); 
    let mut rng = rand::thread_rng();
    
    let mut secrets_samp:Vec<BigInt> =Vec::new();
    let mut secret_shares:Vec<Vec<(Replica,BigInt)>> = Vec::new();
    for _i in 0..secret_num{
        let secret = rng.gen_bigint_range(&low_r, &prime.clone());
        secrets_samp.push(secret.clone());
        let shamir_ss = ShamirSecretSharing{
            threshold:faults+1,
            share_amount:3*faults+1,
            prime: prime.clone()
        };
        secret_shares.push(shamir_ss.split(secret));
    }
    let mut hashes_ms:Vec<Vec<Hash>> = Vec::new();
    // (Replica, Secret, Random Nonce, One-way commitment)
    let share_comm_hash:Vec<Vec<(usize,Vec<u8>,Vec<u8>,Hash)>> = secret_shares.clone().into_iter().map(|y| {
        let mut hashes:Vec<Hash> = Vec::new();
        let acc_secs:Vec<(usize, Vec<u8>, Vec<u8>, Hash)> = y.into_iter().map(|x| {
            let rand = rng.gen_bigint_range(&low_r, &prime.clone());
            let added_secret = rand.clone()+x.1.clone();
            let vec_comm = rand.to_bytes_be().1;
            let comm_secret = added_secret.to_bytes_be().1;
            let hash:Hash = do_hash(comm_secret.as_slice());
            hashes.push(hash.clone());
            (x.0,x.1.to_bytes_be().1,vec_comm.clone(),hash)    
        }).collect();
        hashes_ms.push(hashes);
        acc_secs
    }).collect();
    let merkle_tree_vec:Vec<MerkleTree<Hash, HashingAlg>> = hashes_ms.into_iter().map(|x| MerkleTree::from_iter(x.into_iter())).collect();
    let mut vec_msgs_to_be_sent:Vec<(Replica,BatchWSSMsg)> = Vec::new();
    
    for i in 0..cx.num_nodes{
        vec_msgs_to_be_sent.push((i+1,
            BatchWSSMsg::new(Vec::new(), cx.myid, Vec::new(), Vec::new(),[0;32])));
    }
    let mut roots_vec:Vec<Hash> = Vec::new();
    let mut master_vec:Vec<u8> = Vec::new();
    for (vec,mt) in share_comm_hash.into_iter().zip(merkle_tree_vec.into_iter()).into_iter(){
        let mut i = 0;
        for y in vec.into_iter(){
            vec_msgs_to_be_sent[i].1.secrets.push(y.1);
            vec_msgs_to_be_sent[i].1.commitments.push((y.2,y.3));
            vec_msgs_to_be_sent[i].1.mps.push(MerkleProof::from_proof(mt.gen_proof(i)));
            i = i+1;
        }
        roots_vec.push(mt.root());
        master_vec.append(&mut Vec::from(mt.root()));
    }
    log::info!("Secret sharing for node {}, root_poly {:?}, str_construct {:?}",cx.myid,roots_vec.clone(),master_vec.clone());
    let master_root_mt:MerkleTree<Hash, HashingAlg> = MerkleTree::from_iter(roots_vec.into_iter());
    let master_root = master_root_mt.root();
    // reliably broadcast the vector of merkle roots of each secret sharing instance
    let shards = get_shards(master_vec, cx.num_faults);
    // Construct Merkle tree
    let hashes_rbc:Vec<Hash> = shards.clone().into_iter().map(|x| do_hash(x.as_slice())).collect();
    log::info!("Vector of hashes during RBC Init {:?}",hashes_rbc);
    let merkle_tree:MerkleTree<[u8; 32],HashingAlg> = MerkleTree::from_iter(hashes_rbc.into_iter());
    for (rep,batch_wss) in vec_msgs_to_be_sent.iter_mut(){
        let replica = rep.clone()-1;
        let sec_key = cx.sec_key_map.get(&replica).unwrap().clone();
        let ctrbc_msg = CTRBCMsg::new(
            shards[replica].clone(), 
            MerkleProof::from_proof(merkle_tree.gen_proof(replica)), 
            0,
            cx.myid
        );
        if replica != cx.myid{
            batch_wss.master_root = master_root.clone();
            
            let wss_init = ProtMsg::BatchWSSInit(batch_wss.clone(),ctrbc_msg);
            let wrapper_msg = WrapperMsg::new(wss_init, cx.myid, &sec_key);
            cx.c_send(replica,  Arc::new(wrapper_msg)).await;
        }
        else {
            batch_wss.master_root = master_root.clone();
            process_batchwss_init(cx,batch_wss.clone(),ctrbc_msg).await;
        }
    }

}

pub async fn process_batchwss_init(cx: &mut Context, wss_init: BatchWSSMsg, ctr: CTRBCMsg) {
    let sec_origin = wss_init.origin;
    // 1. Verify Merkle proof for all secrets first
    let secrets = wss_init.secrets.clone();
    let commitments = wss_init.commitments.clone();
    let merkle_proofs = wss_init.mps.clone();
    log::info!("Received WSSInit message {:?} for secret from {}",wss_init.clone(),sec_origin);
    let mut root_ind:Vec<Hash> = Vec::new();
    for i in 0..cx.num_nodes{
        let secret = BigInt::from_bytes_be(Sign::Plus, secrets[i].as_slice());
        let nonce = BigInt::from_bytes_be(Sign::Plus, commitments[i].0.as_slice());
        let added_secret = secret + nonce; 
        let hash = do_hash(added_secret.to_bytes_be().1.as_slice());
        let m_proof = merkle_proofs[i].to_proof();
        if hash != commitments[i].1 || !m_proof.validate::<HashingAlg>() || m_proof.item() != do_hash_merkle(hash.as_slice()){
            log::error!("Merkle proof validation failed for secret {} in inst {}",i,sec_origin);
            return;
        }
        else{
            root_ind.push(m_proof.root());
        }
    }
    let master_merkle_tree:MerkleTree<Hash, HashingAlg> = MerkleTree::from_iter(root_ind.into_iter());
    if master_merkle_tree.root() != wss_init.master_root {
        log::error!("Master root does not match computed master, terminating ss instance {}",sec_origin);
        return;
    }
    // 2. Participate in Reliable Broadcast of commitment vector
    let shard = ctr.shard.clone();
    let mp = ctr.mp.clone();
    let sender = ctr.origin.clone();
    // 1. Check if the protocol reached the round for this node
    let mut msgs_to_be_sent:Vec<ProtMsg> = Vec::new();
    log::info!("Received RBC Init from node {}",sender);
    if !verify_merkle_proof(&mp, &shard){
        log::error!("Failed to evaluate merkle proof for RBC Init received from node {}",sender);
        return;
    }
    let wss_state = &mut cx.batchvss_state;
    wss_state.node_secrets.insert(sec_origin, wss_init);
    // 3. Send echos to every other node
    match wss_state.echos.get_mut(&sec_origin)  {
        None => {
            let mut hash_map = HashMap::default();
            hash_map.insert(cx.myid,(shard.clone(),mp.clone()));
            wss_state.echos.insert(sec_origin, hash_map);
        },
        Some(x) => {
            x.insert(cx.myid,(shard.clone(),mp.clone()));
        },
    }
    match wss_state.readys.get_mut(&sender)  {
        None => {
            let mut hash_map = HashMap::default();
            hash_map.insert(cx.myid,(shard.clone(),mp.clone()));
            wss_state.readys.insert(sender, hash_map);
        },
        Some(x) => {
            x.insert(cx.myid,(shard.clone(),mp.clone()));
        },
    }
    // 4. Send Echos
    msgs_to_be_sent.push(ProtMsg::BatchWSSEcho(ctr.clone(), master_merkle_tree.root(),cx.myid));
    // 5. Inserting send message block here to not borrow cx as mutable again
    log::debug!("Sending echos for RBC from origin {}",sec_origin);
    for prot_msg in msgs_to_be_sent.iter(){
        let sec_key_map = cx.sec_key_map.clone();
        for (replica,sec_key) in sec_key_map.into_iter() {
            if replica != cx.myid{
                let wrapper_msg = WrapperMsg::new(prot_msg.clone(), cx.myid, &sec_key.as_slice());
                let sent_msg = Arc::new(wrapper_msg);
                cx.c_send(replica, sent_msg).await;
            }
            else {
                process_batch_wssecho(cx, ctr.clone(), master_merkle_tree.root(),cx.myid).await;
            }
        }
        log::info!("Broadcasted message {:?}",prot_msg.clone());
    }
}