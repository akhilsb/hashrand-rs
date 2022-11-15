use crypto::hash::{Hash};
use crypto::hash::{do_mac};
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