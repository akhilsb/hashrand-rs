use config::Node;
use fnv::FnvHashMap as HashMap;
use futures::channel::mpsc::UnboundedSender;
use std::{collections::HashSet, sync::Arc};
use types::rbc::{ProtocolMsg, Replica};

use vsss_rs::Share;

pub struct Context {
    /// Networking context
    pub net_send: UnboundedSender<(Replica, Arc<ProtocolMsg>)>,

    /// Data context
    pub num_nodes: usize,
    pub myid: usize,
    pub num_faults: usize,
    pub payload: usize,

    /// PKI
    /// Replica map
    pub sec_key_map: HashMap<Replica, Vec<u8>>,
    pub secret_shares: HashMap<Replica, Share<33>>,

    /// State context
    pub echo_set: HashSet<Replica>,
    pub ready_set: HashSet<Replica>,
}

impl Context {
    pub fn new(config: &Node, net_send: UnboundedSender<(Replica, Arc<ProtocolMsg>)>) -> Self {
        let mut c = Context {
            net_send,
            num_nodes: config.num_nodes,
            sec_key_map: HashMap::default(),
            myid: config.id,
            num_faults: config.num_faults,
            payload: config.payload,

            echo_set: HashSet::default(),
            ready_set: HashSet::default(),
            secret_shares: HashMap::default(),
        };
        for (id, sk_data) in config.sk_map.clone() {
            c.sec_key_map.insert(id, sk_data.clone());
        }
        // Initialize storage
        c
    }
}
