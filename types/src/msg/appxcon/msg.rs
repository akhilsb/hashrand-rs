use crypto::aes_hash::Proof;
use crypto::hash::{Hash};
use crypto::hash::{do_mac};
use serde::{Serialize, Deserialize};
use crate::{WireReady};

use super::Replica;

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct Msg {
    pub value:u64,
    pub origin:Replica,
    pub round:u64,
    pub rnd_estm:bool,
    pub message: Vec<usize>
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct CTRBCMsg{
    pub shard:Vec<u8>,
    pub mp:Proof,
    pub round:u64,
    pub origin:Replica
}

impl CTRBCMsg {
    pub fn new(shard:Vec<u8>,mp:Proof,round:u64,origin:Replica)->Self{
        CTRBCMsg { shard: shard, mp: mp, round: round, origin: origin }
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub enum ProtMsg{
    // Value as a string, Originating node
    RBCInit(Msg,Replica),
    // Value, Originator, ECHO sender
    ECHO(Msg,Replica,Replica),
    // Value, Originator, READY sender
    READY(Msg,Replica,Replica),
    // Witness message
    // List of n-f RBCs we accepted, the sender of the message, and the round number
    WITNESS(Vec<Replica>,Replica,u64),

    WITNESS2(Vec<Replica>,Replica,u64),
    // Erasure-coded shard, corresponding Merkle proof
    CTRBCInit(CTRBCMsg),
    // Echo message with Origin node, and Sender Node
    CTECHO(CTRBCMsg,Replica),
    // Ready message with RBC origin and Sender Node
    CTREADY(CTRBCMsg,Replica),
    // Reconstruction message with Sender
    CTReconstruct(CTRBCMsg,Replica),
    // Echos related to Binary Approximate Agreement
    // (Msg for AA inst, message), sender node, round number
    BinaryAAEcho(Vec<(Replica,Vec<u8>)>,Replica,u64),
    BinaryAAEcho2(Vec<(Replica,Vec<u8>)>,Replica,u64),
}

// #[derive(Debug,Serialize,Deserialize,Clone)]
// pub struct MerkleProof{
//     lemma: Vec<Hash>,
//     path: Vec<bool>,
// }

// impl MerkleProof {
//     pub fn from_proof(proof:Proof<Hash>)->MerkleProof{
//         MerkleProof{
//             lemma:(*proof.lemma()).to_vec(),
//             path:(*proof.path()).to_vec()
//         }
//     }
//     pub fn to_proof(&self)->Proof<Hash>{
//         Proof::new(self.lemma.clone(), self.path.clone())
//     }
//     pub fn root(&self)->Hash {
//         self.lemma.last().clone().unwrap().clone()
//     }
// }

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct WrapperMsg{
    pub protmsg: ProtMsg,
    pub sender:Replica,
    pub mac:Hash,
}

impl WrapperMsg{
    pub fn new(msg:ProtMsg,sender:Replica, sk: &[u8]) -> Self{
        let new_msg = msg.clone();
        let bytes = bincode::serialize(&new_msg).expect("Failed to serialize protocol message");
        let mac = do_mac(&bytes.as_slice(), sk);
        Self{
            protmsg: new_msg,
            mac: mac,
            sender:sender
        }
    }
}

impl WireReady for WrapperMsg{
    fn from_bytes(bytes: &[u8]) -> Self {
        let c:Self = bincode::deserialize(bytes)
            .expect("failed to decode the protocol message");
        c.init()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let bytes = bincode::serialize(self).expect("Failed to serialize client message");
        bytes
    }

    fn init(self) -> Self {
        match self {
            _x=>_x
        }
    }
}