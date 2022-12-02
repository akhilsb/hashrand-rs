use std::{collections::HashMap, sync::Arc};

use super::echo::process_echo;
use super::ready::process_ready;
use crate::node::{context::Context, process_reconstruct_message, verify_merkle_proof, RoundState};
use async_recursion::async_recursion;
use bls12_381_plus::{G1Projective, Scalar};
use crypto::hash::verf_mac;
use types::appxcon::{CTRBCMsg, ProtMsg, WrapperMsg};
use vsss_rs::{FeldmanVerifier, Share};
//use async_recursion::async_recursion;

/*
    Approximate Consensus proceeds in rounds. Every round has a state of its own.
    Every round is composed of three stages: a) n-parallel reliable broadcast, b) Witness technique,
    and c) Value reduction. The three stages form a round for Approximate Agreement.

    The RoundState object is designed to handle all three stages. For the reliable broadcast stage, all n nodes
    initiate a reliable broadcast to broadcast their current round values. This stage of the protocol ends
    when n-f reliable broadcasts are terminated.

    In the witness technique stage, every node broadcasts the first n-f nodes whose values are reliably accepted
    by the current node. We call node $i$ a witness to node $j$ if j reliably accepted the first n-f messages
    reliably accepted by node $i$. Every node stays in this stage until it accepts n-f witnesses.

    After accepting n-f witnesses, the node updates its value for the next round and repeats the process for
    a future round.
*/

pub fn check_proposal(wrapper_msg: Arc<WrapperMsg>, cx: &Context) -> bool {
    // validate MAC
    let byte_val = bincode::serialize(&wrapper_msg.protmsg).expect("Failed to serialize object");
    let sec_key = match cx.sec_key_map.get(&wrapper_msg.clone().sender) {
        Some(val) => val,
        None => {
            panic!("Secret key not available, this shouldn't happen")
        }
    };
    if !verf_mac(&byte_val, &sec_key.as_slice(), &wrapper_msg.mac) {
        log::warn!("MAC Verification failed.");
        return false;
    }
    true
}

pub(crate) async fn process_msg(cx: &mut Context, wrapper_msg: WrapperMsg) {
    log::debug!("Received protocol msg: {:?}", wrapper_msg);
    let msg = Arc::new(wrapper_msg.clone());
    if check_proposal(msg, cx) {
        match wrapper_msg.clone().protmsg {
            ProtMsg::CTRBCInit(ctr) => {
                // RBC initialized
                log::debug!(
                    "Received RBC init {:?} from node {}",
                    ctr.clone(),
                    ctr.clone().origin
                );
                // Reject all messages from older rounds
                //if cx.round <= main_msg.round{
                process_rbc_init(cx, ctr).await;
                //}
            }
            ProtMsg::CTECHO(ctr, echo_sender) => {
                // ECHO for main_msg: RBC originated by orig, echo sent by sender
                // Reject all messages from older rounds and accepted RBCs
                //if cx.round <= main_msg.round{
                process_echo(cx, ctr, echo_sender).await;
                //}
            }
            ProtMsg::CTREADY(ctr, ready_sender) => {
                // READY for main_msg: RBC originated by orig, echo sent by sender
                //if cx.round <= main_msg.round{
                process_ready(cx, ctr, ready_sender).await;
                //}
            }
            ProtMsg::CTReconstruct(ctr, recon_sender) => {
                // WITNESS for main_msg: RBC originated by orig, echo sent by sender
                //if cx.round <= round{
                process_reconstruct_message(cx, ctr, recon_sender).await;
                //}
            }
            ProtMsg::SHARE(share_serial) => {
                log::info!(
                    "Received verifiable secret share from node {}",
                    wrapper_msg.sender
                );
                let share = bincode::deserialize::<Share<33>>(share_serial.as_slice())
                    .expect("Couldn't deserialize verifiable secret share");
                cx.sec_share_map.insert(wrapper_msg.sender, share);
            }
            _ => {}
        }
    } else {
        log::warn!(
            "MAC Verification failed for message {:?}",
            wrapper_msg.protmsg
        );
    }
}

#[async_recursion]
pub async fn process_rbc_init(cx: &mut Context, ctr: CTRBCMsg) {
    let shard = ctr.shard.clone();
    let mp = ctr.mp.clone();
    let sender = ctr.origin.clone();
    let round_state_map = &mut cx.round_state;
    // 1. Check if the protocol reached the round for this node
    let mut msgs_to_be_sent: Vec<ProtMsg> = Vec::new();
    log::info!("Received RBC Init from node {}", sender);
    if !verify_merkle_proof(&mp, &shard) {
        log::error!(
            "Failed to evaluate merkle proof for RBC Init received from node {}",
            sender
        );
        return;
    }
    log::info!("{:?}", ctr.verifier);

    if !ctr.verifier.is_empty() {
        let verifier: FeldmanVerifier<Scalar, G1Projective, 2> =
            bincode::deserialize(ctr.verifier.as_slice()).expect("Couldn't deserialize verifier");
        if !verifier.verify(&cx.sec_share_map[&ctr.origin]) {
            log::error!("Failed to verify secret share");
            return;
        } else {
            log::info!("Verified secret share from node {}", ctr.origin);
        }
    }

    let round = 0;
    if round_state_map.contains_key(&round) {
        let rnd_state = round_state_map.get_mut(&round).unwrap();
        rnd_state
            .node_msgs
            .insert(sender, (shard.clone(), mp.clone(), mp.root().clone()));
        // 3. Send echos to every other node
        msgs_to_be_sent.push(ProtMsg::CTECHO(ctr.clone(), cx.myid));
        // 3. Add your own vote to the map
        match rnd_state.echos.get_mut(&sender) {
            None => {
                let mut hash_map = HashMap::default();
                hash_map.insert(cx.myid, (shard.clone(), mp.clone()));
                rnd_state.echos.insert(sender, hash_map);
            }
            Some(x) => {
                x.insert(cx.myid, (shard.clone(), mp.clone()));
            }
        }
        match rnd_state.readys.get_mut(&sender) {
            None => {
                let mut hash_map = HashMap::default();
                hash_map.insert(cx.myid, (shard.clone(), mp.clone()));
                rnd_state.readys.insert(sender, hash_map);
            }
            Some(x) => {
                x.insert(cx.myid, (shard.clone(), mp.clone()));
            }
        }
    }
    // 1. If the protocol did not reach this round yet, create a new roundstate object
    else {
        let mut rnd_state = RoundState::new();
        rnd_state
            .node_msgs
            .insert(sender, (shard.clone(), mp.clone(), mp.root()));
        round_state_map.insert(round, rnd_state);
        // 7. Send messages
        msgs_to_be_sent.push(ProtMsg::CTECHO(ctr.clone(), cx.myid));
    }
    // Inserting send message block here to not borrow cx as mutable again
    log::debug!("Sending echos for RBC from origin {}", sender);
    for prot_msg in msgs_to_be_sent.iter() {
        let sec_key_map = cx.sec_key_map.clone();
        for (replica, sec_key) in sec_key_map.into_iter() {
            if replica != cx.myid {
                let wrapper_msg = WrapperMsg::new(prot_msg.clone(), cx.myid, &sec_key.as_slice());
                let sent_msg = Arc::new(wrapper_msg);
                cx.c_send(replica, sent_msg).await;
            } else {
                process_echo(cx, ctr.clone(), cx.myid).await;
            }
        }
        log::info!("Broadcasted message {:?}", prot_msg.clone());
    }
}
// async fn broadcast_message(cx: &mut Context, mm: &ProtMsg, origin:Replica, sender:Replica){
//     // create echo messages
//     for (replica,sec_key) in cx.sec_key_map.clone().into_iter() {
//         //let prot_msg = ProtMsg::ECHO(mm.clone(), origin, sender);
//         if replica != cx.myid{
//             let wrapper_msg = WrapperMsg::new(mm.clone(), sender, &sec_key.as_slice());
//             let sent_msg = Arc::new(wrapper_msg);
//             cx.c_send(replica,sent_msg).await;
//         }
//     }
//     log::info!("Broadcasted message {:?}",mm.clone());
// }
