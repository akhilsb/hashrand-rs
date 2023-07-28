use crypto::hash::{Hash, do_mac};
use serde_derive::{Serialize, Deserialize};
use types::{beacon::{Round}, WireReady};

use super::state_machine::sign::ProtocolMessage;



#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct WrapperMsg{
    pub sender:u16,
    pub mac:Hash,
    pub round:Round,
    pub data:Vec<u8>
}

impl WrapperMsg{
    pub fn new(msg:ProtocolMessage,sender:u16, sk: &[u8],round:Round) -> Self{
        let new_msg = msg.clone();
        let bytes = bincode::serialize(&new_msg).expect("Failed to serialize protocol message");
        let mac = do_mac(&bytes.as_slice(), sk);
        Self{
            mac: mac,
            sender:sender,
            round:round,
            data: Vec::new()
        }
    }
    pub fn new_with_data(sender:u16, sk: &[u8],round:Round,data:Vec<u8>) -> Self{
        //let new_msg = msg.clone();
        let bytes = bincode::serialize(&data).expect("Failed to serialize protocol message");
        let mac = do_mac(&bytes.as_slice(), sk);
        Self{
            mac: mac,
            sender:sender,
            round:round,
            data: data
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