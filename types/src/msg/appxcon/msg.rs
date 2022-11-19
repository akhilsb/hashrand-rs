use crypto::hash::{Hash};
use crypto::hash::{do_mac};
use merkle_light::proof::Proof;
use serde::{Serialize, Deserialize};
use crate::{WireReady};

use super::Replica;

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct Msg {
    pub value:i64,
    pub origin:Replica,
    pub round:u32,
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct CTRBCMsg{
    pub shard:Vec<u8>,
    pub mp:MerkleProof,
    pub round:u32,
    pub origin:Replica
}

impl CTRBCMsg {
    pub fn new(shard:Vec<u8>,mp:MerkleProof,round:u32,origin:Replica)->Self{
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
    WITNESS(Vec<Replica>,Replica,u32),

    // Erasure-coded shard, corresponding Merkle proof
    CTRBCInit(CTRBCMsg),
    // Echo message with Origin node, and Sender Node
    CTECHO(CTRBCMsg,Replica),
    // Ready message with RBC origin and Sender Node
    CTREADY(CTRBCMsg,Replica),
    // Reconstruction message with Sender
    CTReconstruct(CTRBCMsg,Replica)
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct MerkleProof{
    lemma: Vec<Hash>,
    path: Vec<bool>,
}

impl MerkleProof {
    pub fn from_proof(proof:Proof<Hash>)->MerkleProof{
        MerkleProof{
            lemma:(*proof.lemma()).to_vec(),
            path:(*proof.path()).to_vec()
        }
    }
    pub fn to_proof(&self)->Proof<Hash>{
        Proof::new(self.lemma.clone(), self.path.clone())
    }
    pub fn root(&self)->Hash {
        self.lemma.last().clone().unwrap().clone()
    }
}

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
        //log::info!("secret key of: {} {:?}",msg.clone().node,sk);
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