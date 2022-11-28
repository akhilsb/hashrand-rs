use std::collections::{HashSet, HashMap};

use num_bigint::BigInt;
use types::appxcon::{Replica};

#[derive(Debug,Clone)]
pub struct RoundState{
    // Map of Replica, and binary state of two values, their echos list and echo2 list, list of values for which echo1s were sent and echo2s list
    pub state: HashMap<Replica,(Vec<(BigInt,HashSet<Replica>,HashSet<Replica>,bool,bool)>,HashSet<BigInt>,Vec<BigInt>)>,
    pub term_vals:HashMap<Replica,BigInt>,
}

impl RoundState{
    pub fn new()-> RoundState{
        RoundState{
            state:HashMap::default(),
            term_vals:HashMap::default(),
        }
    }
}