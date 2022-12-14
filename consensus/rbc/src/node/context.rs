use futures::channel::mpsc::UnboundedSender;use types::rbc::{ProtocolMsg, Replica};
use config::Node;
use fnv::FnvHashMap as HashMap;
use std::{sync::Arc, collections::HashSet};

pub struct Context {
    /// Networking context
    pub net_send: UnboundedSender<(Replica, Arc<ProtocolMsg>)>,

    /// Data context
    pub num_nodes: usize,
    pub myid: usize,
    pub num_faults: usize,

    /// PKI
    /// Replica map
    pub secret_share: Vec<u8>,
    pub sec_key_map:HashMap<Replica, Vec<u8>>,

    /// State context
    pub echo_set: HashSet<Replica>,
    pub ready_set: HashSet<Replica>,
}

impl Context {
    pub fn new(
        config: &Node,
        net_send: UnboundedSender<(Replica, Arc<ProtocolMsg>)>,
    ) -> Self {
        let mut c = Context {
            net_send,
            num_nodes: config.num_nodes,
            sec_key_map: HashMap::default(),
            myid: config.id,
            num_faults: config.num_faults,

            secret_share: Vec::new(),
            echo_set: HashSet::default(),
            ready_set: HashSet::default(),
        };
        for (id, sk_data) in config.sk_map.clone() {
            c.sec_key_map.insert(id, sk_data.clone());
        }
        // Initialize storage
        c
    }
}