use std::{collections::{HashMap}, sync::Arc};

use merkle_light::merkle::MerkleTree;
use types::{Replica, hash_cc::{ProtMsg, WrapperMsg, CTRBCMsg}, appxcon::{verify_merkle_proof, reconstruct_and_return, HashingAlg}};

use crate::node::{Context, witness_check, process_gatherecho};
use crypto::hash::{Hash};

pub async fn process_batchreconstruct_message(cx: &mut Context,ctr:CTRBCMsg,master_root:Hash,recon_sender:Replica){
    let shard = ctr.shard.clone();
    let mp = ctr.mp.clone();
    let sec_origin = ctr.origin.clone();
    let vss_state = &mut cx.batchvss_state;
    let mut msgs_to_be_sent:Vec<ProtMsg> = Vec::new();
    // Highly unlikely that the node will get an echo before rbc_init message
    log::info!("Received Reconstruct message from {} for RBC of node {}",recon_sender,sec_origin);
    if !verify_merkle_proof(&mp, &shard){
        log::error!("Failed to evaluate merkle proof for RECON received from node {} for RBC {}",recon_sender,sec_origin);
        return;
    }
    if vss_state.terminated_secrets.contains(&sec_origin){
        log::info!("Batch secret instance from node {} already terminated",sec_origin);
        return;
    }
    // Check merkle root validity
    let merkle_root = vss_state.node_secrets.get(&sec_origin).unwrap().master_root.clone();
    // Merkle root check. Check if the merkle root of the message matches the merkle root sent by the node
    if merkle_root != master_root{
        log::error!("Merkle root verification failed with error {:?}{:?}",merkle_root,master_root);
        return;
    }
    match vss_state.recon_msgs.get_mut(&sec_origin) {
        None => {
            let mut reconset = HashMap::default();
            reconset.insert(recon_sender,shard.clone());
            vss_state.recon_msgs.insert(sec_origin, reconset);
        },
        Some(x) => {
            x.insert(recon_sender,shard.clone());
        }
    }
    // Check if the RBC received n-f readys
    let ready_check = vss_state.readys.get(&sec_origin).unwrap().len() >= (cx.num_nodes-cx.num_faults);
    let vec_fmap = vss_state.recon_msgs.get(&sec_origin).unwrap();
    if vec_fmap.len()==cx.num_nodes-cx.num_faults && ready_check{
        // Reconstruct here
        let result = reconstruct_and_return(
            vec_fmap, cx.num_nodes.clone(), cx.num_faults.clone());
        match result {
            Err(error)=> {
                log::error!("Error resulted in constructing erasure-coded data {:?}",error);
                return;
            }
            Ok(vec)=>{
                log::info!("Successfully reconstructed message for Batch WSS, checking validity of root for secret {}",sec_origin);
                let mut vec = vec;
                vec.truncate(cx.num_nodes*32);
                log::info!("Reconstruct Vec_x: {:?} {}",vec.clone(),vec.len());
                let target_comm_vec:Vec<Hash> = vec.chunks(32).into_iter()
                .map(|x| {
                    x.try_into().unwrap()
                })
                .collect();
                let comm_mt:MerkleTree<Hash, HashingAlg> = MerkleTree::from_iter(target_comm_vec.clone().into_iter());
                if comm_mt.root() != master_root {
                    log::error!("The reconstructed merkle root does not match the original root, terminating... {:?}{:?}",comm_mt.root(),master_root);
                    return;
                }
                vss_state.terminated_secrets.insert(sec_origin);
                vss_state.comm_vectors.insert(sec_origin, target_comm_vec);
                // Initiate next phase of the protocol here
                if vss_state.terminated_secrets.len() >= cx.num_nodes - cx.num_faults{
                    if !vss_state.send_w1{
                        log::info!("Terminated n-f Batch WSSs, sending list of first n-f Batch WSSs to other nodes");
                        log::info!("Terminated : {:?}",vss_state.terminated_secrets);
                        log::info!("Terminated n-f wss instances. Sending echo2 message to everyone");
                        msgs_to_be_sent.push(ProtMsg::GatherEcho(vss_state.terminated_secrets.clone().into_iter().collect(), cx.myid));
                    }
                    witness_check(cx).await;
                }
            }
        }
    }
    // Inserting send message block here to not borrow cx as mutable again
    for prot_msg in msgs_to_be_sent.iter(){
        let sec_key_map = cx.sec_key_map.clone();
        for (replica,sec_key) in sec_key_map.into_iter() {
            if replica != cx.myid{
                let wrapper_msg = WrapperMsg::new(prot_msg.clone(), cx.myid, &sec_key.as_slice());
                let sent_msg = Arc::new(wrapper_msg);
                cx.c_send(replica, sent_msg).await;
            }
            else {
                match prot_msg {
                    ProtMsg::GatherEcho(vec_term_secs, echo_sender) =>{
                        process_gatherecho(cx, vec_term_secs.clone(), *echo_sender, 1).await;
                    },
                    _ => {}
                }
            }
        }
        log::info!("Broadcasted message {:?}",prot_msg.clone());
    }
}