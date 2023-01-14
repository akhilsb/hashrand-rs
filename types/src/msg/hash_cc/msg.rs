use core::fmt;
use std::{iter::FromIterator, convert::TryInto};

use crypto::hash::{Hash, do_mac, do_hash_merkle, do_hash};
use merkle_light::merkle::MerkleTree;
use num_bigint::{BigInt, Sign};
use serde::{Serialize, Deserialize};

use crate::{appxcon::{MerkleProof, HashingAlg, verify_merkle_proof}, WireReady};

use super::{Replica, Round};

#[derive(Debug,Serialize,Deserialize,Clone)]
pub enum CoinMsg{
    WSSInit(WSSMsg),
    WSSEcho(Hash,Replica,Replica),
    WSSReady(Hash,Replica,Replica),
    WSSReconstruct(WSSMsg,Replica),
    BatchWSSInit(BatchWSSMsg,CTRBCMsg),
    // Batch WSS needs agreement on the commitment vector, hence need to use Cachin-Tessaro Reliable broadcast
    BatchWSSEcho(CTRBCMsg,Hash,Replica),
    BatchWSSReady(CTRBCMsg,Hash,Replica),
    BatchWSSReconstruct(CTRBCMsg,Hash,Replica),
    BatchSecretReconstruct(Vec<WSSMsg>,Replica,usize),
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

    NoMessage(),
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

    pub fn verify_mr_proof(&self) -> bool{
        if !verify_merkle_proof(&self.mp, &self.shard){
            log::error!("Failed to evaluate merkle proof for RBC Init received from node {}",self.origin);
            return false;
        }
        true
    }
}

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

    pub fn verify_proofs(&self) -> bool{
        let sec_origin = self.origin;
        // 1. Verify Merkle proof for all secrets first
        let secrets = self.secrets.clone();
        let commitments = self.commitments.clone();
        let merkle_proofs = self.mps.clone();
        log::debug!("Received WSSInit message for secret from {}",sec_origin);
        let mut root_ind:Vec<Hash> = Vec::new();
        for i in 0..secrets.len(){
            let secret = BigInt::from_bytes_be(Sign::Plus, secrets[i].as_slice());
            let nonce = BigInt::from_bytes_be(Sign::Plus, commitments[i].0.as_slice());
            let added_secret = secret + nonce; 
            let hash = do_hash(added_secret.to_bytes_be().1.as_slice());
            let m_proof = merkle_proofs[i].to_proof();
            if hash != commitments[i].1 || !m_proof.validate::<HashingAlg>() || m_proof.item() != do_hash_merkle(hash.as_slice()){
                log::error!("Merkle proof validation failed for secret {} in inst {}",i,sec_origin);
                return false;
            }
            else{
                root_ind.push(m_proof.root());
            }
        }
        let master_merkle_tree:MerkleTree<Hash, HashingAlg> = MerkleTree::from_iter(root_ind.into_iter());
        if master_merkle_tree.root() != self.master_root {
            log::error!("Master root does not match computed master, terminating ss instance {}",sec_origin);
            return false;
        }
        return true;
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct DAGData{
    pub data: Vec<Vec<u8>>,
    // Store both replica and the original digest of the block as part of the edges
    pub vertices: Vec<(Replica,Round,Hash)>,
    pub round:u32,
    pub origin: Replica
}

impl DAGData {
    pub fn new(data:Vec<Vec<u8>>, vertices:Vec<(Replica,Round,Hash)>, round:u32, origin:Replica)-> DAGData{
        let dag_data = DAGData { 
            data: data, 
            vertices: vertices, 
            round: round, 
            origin: origin 
        };
        let size;
        if dag_data.data.len() > 0{
            size = dag_data.data.len()*dag_data.data[0].len();
        }
        else{
            size = 0;
        }
        let tx_ids: Vec<_> = dag_data.data
            .iter()
            .filter(|tx| tx[0] == 0u8 && tx.len() > 8)
            .filter_map(|tx| tx[1..9].try_into().ok())
            .collect();
        // NOTE: This is one extra hash that is only needed to print the following log entries.
        let digest = dag_data.digest();
        for id in tx_ids {
            // NOTE: This log entry is used to compute performance.
            log::info!(
                "Batch {:?} contains sample tx {}",
                base64::encode(digest).get(0..16).unwrap(),
                u64::from_be_bytes(id)
            );
        }
        // NOTE: This log entry is used to compute performance.
        log::info!("Batch {:?} contains {} B", base64::encode(digest).get(0..16).unwrap(), size);
        dag_data
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes = bincode::serialize(self).expect("Failed to serialize dag_data message");
        bytes
    }
    
    pub fn from_bytes(bytes: Vec<u8>) -> DAGData {
        let dag_data:DAGData = bincode::deserialize(&bytes[..]).unwrap();
        dag_data
    }

    pub fn digest(&self) -> Hash {
        let bytes = self.to_bytes();
        do_hash(bytes.as_slice())
    }
}

impl fmt::Display for DAGData {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.round, self.origin)
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub enum DAGMsg{
    // Erasure-coded shard, corresponding Merkle proof
    RBCInit(CTRBCMsg),
    // Echo message with Origin node, and Sender Node
    RBCECHO(CTRBCMsg,Replica),
    // Ready message with RBC origin and Sender Node
    RBCREADY(CTRBCMsg,Replica),
    // Reconstruction message with Sender
    RBCReconstruct(CTRBCMsg,Replica),

    NoMessage(),
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct SMRMsg{
    pub dag_msg:DAGMsg,
    pub coin_msg:CoinMsg,
    pub origin: Replica
}

impl SMRMsg {
    pub fn new(dag_msg: DAGMsg, coin_msg:CoinMsg, origin:Replica)-> SMRMsg{
        SMRMsg { 
            dag_msg: dag_msg, 
            coin_msg: coin_msg, 
            origin: origin 
        }
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct WrapperMsg{
    pub protmsg: CoinMsg,
    pub sender:Replica,
    pub mac:Hash,
}

impl WrapperMsg{
    pub fn new(msg:CoinMsg,sender:Replica, sk: &[u8]) -> Self{
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

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct WrapperSMRMsg{
    pub protmsg: SMRMsg,
    pub sender:Replica,
    pub mac:Hash,
}

impl WrapperSMRMsg{
    pub fn new(msg:&SMRMsg,sender:Replica, sk: &[u8]) -> Self{
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

impl WireReady for WrapperSMRMsg{
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