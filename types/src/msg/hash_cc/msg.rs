use crypto::hash::{Hash};
use crypto::hash::{do_mac};
use serde::{Serialize, Deserialize};
use crate::appxcon::MerkleProof;
use crate::{WireReady};

use super::Replica;

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct WSSMsg {
    pub secret:Vec<u8>,
    pub origin:Replica,
    // The tuple is the randomized nonce to be appended to the secret to prevent rainbow table attacks
    pub commitment:(Vec<u8>,Hash),
    // Merkle proof to the root
    pub mp:MerkleProof
}

impl WSSMsg {
    pub fn new(secret:Vec<u8>,origin:Replica,commitment:(Vec<u8>,Hash),mp:MerkleProof)->Self{
        WSSMsg { 
            secret: secret, 
            origin: origin, 
            commitment: commitment, 
            mp: mp 
        }
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct BatchWSSMsg{
    pub secrets: Vec<Vec<u8>>,
    pub origin: Replica,
    pub commitments: Vec<(Vec<u8>,Hash)>,
    pub mps: Vec<MerkleProof>,
    pub master_root: Hash,
}

impl BatchWSSMsg {
    pub fn new(secrets:Vec<Vec<u8>>,origin:Replica,commitments:Vec<(Vec<u8>,Hash)>,mps:Vec<MerkleProof>,master_root:Hash)->Self{
        BatchWSSMsg{
            secrets:secrets,
            origin:origin,
            commitments:commitments,
            mps:mps,
            master_root:master_root
        }
    }
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
    WSSInit(WSSMsg),
    WSSEcho(Hash,Replica,Replica),
    WSSReady(Hash,Replica,Replica),
    WSSReconstruct(WSSMsg,Replica),
    BatchWSSInit(BatchWSSMsg,CTRBCMsg),
    // Batch WSS needs agreement on the commitment vector, hence need to use Cachin-Tessaro Reliable broadcast
    BatchWSSEcho(CTRBCMsg,Hash,Replica),
    BatchWSSReady(CTRBCMsg,Hash,Replica),
    BatchWSSReconstruct(CTRBCMsg,Hash,Replica),
    BatchSecretReconstruct(WSSMsg,Replica,usize),
    // Gather related messages
    GatherEcho(Vec<Replica>,Replica),
    GatherEcho2(Vec<Replica>,Replica),
    // Erasure-coded shard, corresponding Merkle proof
    AppxConCTRBCInit(CTRBCMsg),
    // Echo message with Origin node, and Sender Node
    AppxConCTECHO(CTRBCMsg,Replica),
    // Ready message with RBC origin and Sender Node
    AppxConCTREADY(CTRBCMsg,Replica),
    // Reconstruction message with Sender
    AppxConCTReconstruct(CTRBCMsg,Replica),
    // Witness for Approximate Agreement 
    // List of first n-f accepted rbcs, Sender node, round number
    AppxConWitness(Vec<Replica>,Replica,u32),
    // Echos related to Binary Approximate Agreement
    // (Msg for AA inst, message), sender node, round number
    BinaryAAEcho(Vec<(Replica,Vec<u8>)>,Replica,u32),
    BinaryAAEcho2(Vec<(Replica,Vec<u8>)>,Replica,u32),
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