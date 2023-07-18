use crypto::hash::{Hash, do_hash_merkle, do_hash, do_mac};
use num_bigint::{BigInt};
use serde::{Serialize, Deserialize};

use crate::{appxcon::{MerkleProof, HashingAlg, verify_merkle_proof}, WireReady, Round};

use super::{Replica};

pub type Val = Vec<u8>;

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct BeaconMsg{
    pub origin: Replica,
    pub round:Round,
    pub wss:Option<BatchWSSMsg>,
    pub root_vec:Option<Vec<Hash>>,
    // Each BeaconMsg can consist AppxCon messages from multiple rounds.
    pub appx_con: Option<Vec<(Round,Vec<(Replica,Val)>)>>,
}

impl BeaconMsg {
    pub fn new(origin:Replica,round:Round,wss_msg:BatchWSSMsg,root_vec:Vec<Hash>,appx_con: Vec<(Round,Vec<(Replica,Val)>)>)->BeaconMsg{
        return BeaconMsg { origin:origin,round: round, wss: Some(wss_msg),root_vec:Some(root_vec), appx_con: Some(appx_con) }
    }

    pub fn new_with_appx(origin:Replica,round:Round,appx_con: Vec<(Round,Vec<(Replica,Val)>)>)->BeaconMsg{
        return BeaconMsg { origin:origin,round: round, wss: None,root_vec:None, appx_con: Some(appx_con) }
    }

    pub fn serialize_ctrbc(&self)->Vec<u8>{
        let beacon_without_wss = BeaconMsg{origin:self.origin,round:self.round,wss:None,root_vec:self.root_vec.clone(),appx_con:self.appx_con.clone()};
        return beacon_without_wss.serialize();
    }

    fn serialize(&self)->Vec<u8>{
        return bincode::serialize(self).expect("Serialization failed");
    }

    pub fn deserialize(bytes:&[u8])->Self{
        let c:Self = bincode::deserialize(bytes)
            .expect("failed to decode the protocol message");
        c.init()
    }

    fn init(self) -> Self {
        match self {
            _x=>_x
        }
    }

    pub fn verify_proofs(&self,) -> bool{
        let sec_origin = self.origin;
        if self.wss.is_some(){
            // 1. Verify Merkle proof for all secrets first
            let secrets = self.wss.clone().unwrap().secrets;
            let commitments = self.wss.clone().unwrap().commitments;
            let merkle_proofs = self.wss.clone().unwrap().mps;
            log::debug!("Received WSSInit message for secret from {}",sec_origin);
            let mut root_ind:Vec<Hash> = Vec::new();
            for i in 0..secrets.len(){
                let secret = BigInt::from_signed_bytes_be(secrets[i].as_slice());
                let nonce = BigInt::from_signed_bytes_be(commitments[i].0.as_slice());
                let added_secret = secret + nonce; 
                let hash = do_hash(added_secret.to_signed_bytes_be().as_slice());
                let m_proof = merkle_proofs[i].to_proof();
                if hash != commitments[i].1 || !m_proof.validate::<HashingAlg>() || m_proof.item() != do_hash_merkle(hash.as_slice()){
                    log::error!("Merkle proof validation failed for secret {} in inst {}",i,sec_origin);
                    return false;
                }
                else{
                    root_ind.push(m_proof.root());
                    if m_proof.root()!= self.root_vec.clone().unwrap()[i]{
                        return false;
                    }
                }
            }
        }
        return true;
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct CTRBCMsg{
    pub shard:Val,
    pub mp:MerkleProof,
    pub round:u32,
    pub origin:Replica
}

impl CTRBCMsg {
    pub fn new(shard:Val,mp:MerkleProof,round:u32,origin:Replica)->Self{
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
pub enum CoinMsg{
    CTRBCInit(BeaconMsg,CTRBCMsg),
    CTRBCEcho(CTRBCMsg,Hash,Replica),
    CTRBCReady(CTRBCMsg,Hash,Replica),
    CTRBCReconstruct(CTRBCMsg,Hash,Replica),
    GatherEcho(GatherMsg,Replica,Round),
    GatherEcho2(GatherMsg,Replica,Round),
    BinaryAAEcho(Vec<(Round,Vec<(Replica,Val)>)>,Replica,Round),
    BinaryAAEcho2(Vec<(Round,Vec<(Replica,Val)>)>,Replica,Round),
    // THe vector of secrets, the source replica, the index in each batch and the round number of Batch Secret Sharing
    BeaconConstruct(Vec<WSSMsg>,Replica,Replica,Round),
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct BatchWSSMsg{
    pub secrets: Vec<Val>,
    pub origin: Replica,
    pub commitments: Vec<(Val,Hash)>,
    pub mps: Vec<MerkleProof>,
    pub empty: bool
}

impl BatchWSSMsg {
    pub fn new(secrets:Vec<Val>,origin:Replica,commitments:Vec<(Val,Hash)>,mps:Vec<MerkleProof>)->Self{
        BatchWSSMsg{
            secrets:secrets,
            origin:origin,
            commitments:commitments,
            mps:mps,
            empty:false
        }
    }
    pub fn empty()->BatchWSSMsg{
        BatchWSSMsg{
            secrets:Vec::new(),
            origin:0,
            commitments:Vec::new(),
            mps:Vec::new(),
            empty:false
        }
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct WSSMsg {
    pub secret:Val,
    pub origin:Replica,
    // The tuple is the randomized nonce to be appended to the secret to prevent rainbow table attacks
    pub commitment:(Val,Hash),
    // Merkle proof to the root
    pub mp:MerkleProof
}

impl WSSMsg {
    pub fn new(secret:Val,origin:Replica,commitment:(Val,Hash),mp:MerkleProof)->Self{
        WSSMsg { 
            secret: secret, 
            origin: origin, 
            commitment: commitment, 
            mp: mp 
        }
    }
}


#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct GatherMsg{
    pub nodes: Vec<Replica>,
}


#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct WrapperMsg{
    pub protmsg: CoinMsg,
    pub sender:Replica,
    pub mac:Hash,
    pub round:Round
}

impl WrapperMsg{
    pub fn new(msg:CoinMsg,sender:Replica, sk: &[u8],round:Round) -> Self{
        let new_msg = msg.clone();
        let bytes = bincode::serialize(&new_msg).expect("Failed to serialize protocol message");
        let mac = do_mac(&bytes.as_slice(), sk);
        Self{
            protmsg: new_msg,
            mac: mac,
            sender:sender,
            round:round
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