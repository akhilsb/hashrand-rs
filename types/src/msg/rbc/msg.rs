use crypto::hash::Hash;
use crypto::hash::{do_mac};
use crate::{Replica};
use serde::{
    Serialize,
    Deserialize
};

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct Msg{
    // Represent the data as a generic vector of Integers
    pub value: String,
    pub node:Replica,
    pub msg_type:usize,
}

#[derive(Debug,Serialize,Deserialize,Clone)]
pub struct WrapperMsg{
    pub msg:Msg,
    pub mac:Hash,
}

impl WrapperMsg {
    pub fn new(msg:Msg, sk: &[u8]) -> Self{
        let new_msg = msg.clone();
        let bytes = bincode::serialize(&new_msg).expect("Failed to serialize protocol message");
        let mac = do_mac(&bytes.as_slice(), sk);
        //log::info!("secret key of: {} {:?}",msg.clone().node,sk);
        Self{
            msg: new_msg,
            mac: mac,
        }
    }
}