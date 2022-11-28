use futures::{channel::mpsc::UnboundedSender};
use num_bigint::BigInt;
use types::hash_cc::{WrapperMsg, Replica};
use config::Node;
use fnv::FnvHashMap as HashMap;
use vss_state::VSSState;
use std::{sync::Arc};

use crate::node::vss_state;

use super::{RoundState, BatchVSSState};

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

    /// The context parameters related to Verifiable Secret sharing for the common coin
    pub secret_domain: BigInt,
    pub rounds_aa: u32,
    pub epsilon: u32,
    pub curr_round:u32,

    /// State context
    /// Verifiable Secret Sharing context
    pub vss_state: VSSState,
    pub batchvss_state: BatchVSSState,
    /// Approximate agreement context
    pub round_state: HashMap<u32,RoundState>,
    pub nz_appxcon_rs: HashMap<Replica,(BigInt,bool,BigInt)>,
}

impl Context {
    pub fn new(
        config: &Node,
        net_send: UnboundedSender<(Replica, Arc<WrapperMsg>)>,
    ) -> Self {
        let prot_payload = &config.prot_payload;
        let v:Vec<&str> = prot_payload.split(',').collect();
        if v[0] == "cc" {
            // The modulus of the secret is set for probability of coin success = 1- 5*10^{-9}
            let prime = BigInt::parse_bytes(b"685373784908497",10).unwrap();
            let epsilon:u32 = ((1024*1024)/(config.num_nodes*config.num_faults)) as u32;
            let rounds = (50.0 - ((epsilon as f32).log2().ceil())) as u32;
            let mut c = Context {
                net_send,
                num_nodes: config.num_nodes,
                sec_key_map: HashMap::default(),
                myid: config.id,
                num_faults: config.num_faults,
                payload: config.payload,
                
                secret_domain:prime,
                rounds_aa:rounds,
                epsilon:epsilon,
                curr_round:0,

                vss_state: VSSState::new(),
                batchvss_state: BatchVSSState::new(),
                round_state: HashMap::default(),
                nz_appxcon_rs: HashMap::default(),
                //echos_ss: HashMap::default(),
            };
            for (id, sk_data) in config.sk_map.clone() {
                c.sec_key_map.insert(id, sk_data.clone());
            }
            log::debug!("Started n-parallel RBC with value {:?} and epsilon {}",c.rounds_aa,c.epsilon);
            // Initialize storage
            c
        }
        else {
            panic!("Invalid configuration for protocol");
        }
    }
}