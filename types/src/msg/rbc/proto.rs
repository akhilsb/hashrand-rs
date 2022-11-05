use serde::{
    Serialize,
    Deserialize
};
use crate::WireReady;
use crate::rbc::{WrapperMsg};

#[derive(Debug,Serialize,Deserialize,Clone)]
pub enum ProtocolMsg{
    // Initiating reliable broadcast with this message
    RBCInit(WrapperMsg),
    ECHO(WrapperMsg),
    READY(WrapperMsg)
}

impl ProtocolMsg {
}

impl WireReady for ProtocolMsg{
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
            ProtocolMsg::RBCInit(ref _msg) =>{
                return self;
            },
            ProtocolMsg::ECHO(ref _msg) => {
                return self;
            },
            ProtocolMsg::READY(ref _msg) =>{
                return self;
            }
        }
    }
}

impl WrapperMsg{

}