use futures::{channel::mpsc::UnboundedSender};
use types::appxcon::{WrapperMsg, Replica};
use config::Node;
use fnv::FnvHashMap as HashMap;
use std::{sync::Arc};

use super::RoundState;

pub struct Context {
    /// Networking context
    pub net_send: UnboundedSender<(Replica, Arc<WrapperMsg>)>,

    /// Data context
    pub num_nodes: usize,
    pub myid: usize,
    pub num_faults: usize,
    pub payload:usize,

    /// PKI
    /// Replica map
    pub sec_key_map:HashMap<Replica, Vec<u8>>,

    /// Round number and Approx Consensus related context
    pub round:u32,
    pub value:Vec<u8>,
    pub epsilon:i64,

    /// State context
    pub round_state: HashMap<u32,RoundState>,
    // Using 
    // Map<Round,Map<Node,Set<Echos>>>
    //pub 
    //pub echos_ss: HashMap<u32,HashMap<Replica,HashSet<Replica>>>,
    //pub ready_ss: HashMap<u32,HashMap<Replica,HashSet<Replica>>>,
}

impl Context {
    pub fn new(
        config: &Node,
        net_send: UnboundedSender<(Replica, Arc<WrapperMsg>)>,
    ) -> Self {
        let prot_payload = &config.prot_payload;
        let v:Vec<&str> = prot_payload.split(',').collect();
        if v[0] == "a" {
            let init_value = v[1].as_bytes().to_vec();
            let epsilon:i64 = v[2].parse::<i64>().unwrap();
            let mut c = Context {
                net_send,
                num_nodes: config.num_nodes,
                sec_key_map: HashMap::default(),
                myid: config.id,
                num_faults: config.num_faults,
                payload: config.payload,
    
                round:0,
                value: init_value,
                epsilon: epsilon,
    
                round_state: HashMap::default(),
                //echos_ss: HashMap::default(),
            };
            for (id, sk_data) in config.sk_map.clone() {
                c.sec_key_map.insert(id, sk_data.clone());
            }
            log::debug!("Started n-parallel RBC with value {:?} and epsilon {}",c.value,c.epsilon);
            // Initialize storage
            c
        }
        else {
            panic!("Invalid configuration for protocol");
        }
    }
}