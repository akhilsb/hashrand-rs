use std::collections::{HashSet, HashMap};

use types::appxcon::{Replica, Msg};

#[derive(Debug,Clone)]
pub struct RoundState{
    pub node_msgs: HashMap<Replica,Msg>,
    pub echos: HashMap<Replica,HashSet<Replica>>,
    pub readys: HashMap<Replica,HashSet<Replica>>,
    pub accepted_vals: Vec<u64>,
    pub witnesses: HashMap<Replica,Vec<Replica>>,
    pub terminated_rbcs: HashSet<Replica>,
    pub accepted_witnesses: HashSet<Replica>,
    pub witness_sent:bool,
    pub witnesses2 : HashMap<Replica,Vec<Replica>>,
    pub term_values: HashMap<Replica,u64>,
    pub wround:u32,
}

impl RoundState{
    pub fn new()-> RoundState{
        RoundState{
            node_msgs: HashMap::default(),
            echos: HashMap::default(),
            readys:HashMap::default(),
            witnesses:HashMap::default(),
            accepted_vals: Vec::new(),
            terminated_rbcs:HashSet::default(),
            accepted_witnesses:HashSet::default(),
            witness_sent:false,
            term_values: HashMap::default(),
            witnesses2: HashMap::default(),
            wround:1
        }
    }
    pub fn insert_node(&mut self, msg:Msg){
        self.node_msgs.insert(msg.origin, msg.clone());
    }
}