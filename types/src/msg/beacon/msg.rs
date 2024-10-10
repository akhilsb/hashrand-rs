use crypto::{hash::{Hash, do_mac, do_hash}, aes_hash::{Proof, HashState, HASH_SIZE}};
use serde::{Serialize, Deserialize};

use crate::{WireReady, Round};

use super::{Replica};

pub type Val = [u8; HASH_SIZE];

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

    pub fn verify_proofs(&self,hf:&HashState) -> bool{
        if self.wss.is_some(){
            let wssmsg = self.wss.as_ref().unwrap();
            // 1. Verify Merkle proof for all secrets first
            let mps = Proof::validate_batch(&wssmsg.mps, hf);
            // Return if the merkle proofs do not verify
            if !mps{
                log::error!("Merkle proof verification failed for wssmsg sent by {}",wssmsg.origin);
                return false;
            }
            let secrets = wssmsg.secrets.clone();
            let nonces = wssmsg.nonces.clone();
            let commitments = hf.hash_batch(secrets, nonces);
            // Match commitments to the items of proofs
            for (pf,comm) in wssmsg.mps.iter().zip(commitments.into_iter()){
                if pf.item() != comm{
                    log::error!("Commitment does not match element in proof for wssmsg sent by {}",wssmsg.origin);
                    return false;
                }
            }
            // let mut root_ind:Vec<Hash> = Vec::new();
            // for i in 0..secrets.len(){
            //     let secret = BigUint::from_bytes_be(secrets[i].as_slice());
            //     let nonce = BigUint::from_bytes_be(nonces[i].0.as_slice());
            //     //let added_secret = secret + nonce; 
            //     let hash = hf.hash_two(, );
            //     let m_proof = merkle_proofs[i].to_proof();
            //     if hash != nonces[i].1 || !m_proof.validate::<HashingAlg>() || m_proof.item() != do_hash_merkle(hash.as_slice()){
            //         log::error!("Merkle proof validation failed for secret {} in inst {}",i,sec_origin);
            //         return false;
            //     }
            //     else{
            //         root_ind.push(m_proof.root());
            //         if m_proof.root()!= self.root_vec.clone().unwrap()[i]{
            //             return false;
            //         }
            //     }
            // }
        }
        return true;
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct CTRBCMsg{
    pub shard:Vec<u8>,
    pub mp:Proof,
    pub round:u32,
    pub origin:Replica
}

impl CTRBCMsg {
    pub fn new(shard:Vec<u8>,mp:Proof,round:u32,origin:Replica)->Self{
        CTRBCMsg { shard: shard, mp: mp, round: round, origin: origin }
    }

    pub fn verify_mr_proof(&self,hf:&HashState) -> bool{
        // 2. Validate Merkle Proof
        let hash_of_shard:[u8;32] = do_hash(&self.shard.as_slice());
        let state: bool =  hash_of_shard == self.mp.item().clone() && self.mp.validate(hf);
        return state;
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
    BinaryAAEcho(Vec<(Round,Vec<(Replica,Vec<u8>)>)>,Replica,Round),
    BinaryAAEcho2(Vec<(Round,Vec<(Replica,Vec<u8>)>)>,Replica,Round),
    // THe vector of secrets, the source replica, the index in each batch and the round number of Batch Secret Sharing
    BeaconConstruct(BatchWSSReconMsg,Replica,Replica,Round),
    BeaconValue(Round,Replica,u128),
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct BatchWSSMsg{
    pub secrets: Vec<Val>,
    pub origin: Replica,
    pub nonces: Vec<Val>,
    pub mps: Vec<Proof>,
    pub empty: bool
}

impl BatchWSSMsg {
    pub fn new(origin:Replica,secrets:Vec<Val>,nonces:Vec<Val>,mps:Vec<Proof>)->Self{
        BatchWSSMsg{
            secrets:secrets,
            origin:origin,
            nonces:nonces,
            mps:mps,
            empty:false
        }
    }
    pub fn empty()->BatchWSSMsg{
        BatchWSSMsg{
            secrets:Vec::new(),
            origin:0,
            nonces:Vec::new(),
            mps:Vec::new(),
            empty:false
        }
    }
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct BatchWSSReconMsg{
    pub origin: Replica,
    pub secrets: Vec<Val>,
    pub nonces: Vec<Val>,
    pub origins: Vec<Replica>,
    pub mps: Vec<Proof>,
    pub empty: bool
}

impl BatchWSSReconMsg {
    pub fn new(origin:Replica,secrets:Vec<Val>,nonces:Vec<Val>,origin_replicas:Vec<Replica>,mps:Vec<Proof>)->Self{
        BatchWSSReconMsg{
            secrets:secrets,
            origin:origin,
            nonces:nonces,
            origins:origin_replicas,
            mps:mps,
            empty:false
        }
    }
}


#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct WSSMsg {
    pub origin:Replica,
    pub secret:Val,
    // The tuple is the randomized nonce to be appended to the secret to prevent rainbow table attacks
    pub nonce:Val,
    // Merkle proof to the root
    pub mp:Proof
}

impl WSSMsg {
    pub fn new(origin:Replica,secret:Val,nonce:Val,mp:Proof)->Self{
        WSSMsg { 
            secret: secret, 
            origin: origin, 
            nonce: nonce, 
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