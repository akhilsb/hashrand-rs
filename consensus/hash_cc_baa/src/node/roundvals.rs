use std::collections::{HashSet, HashMap};

use num_bigint::{BigInt, Sign};
use types::appxcon::{Replica};

#[derive(Debug,Clone)]
pub struct RoundState{
    // Map of Replica, and binary state of two values, their echos list and echo2 list, list of values for which echo1s were sent and echo2s list
    pub state: HashMap<Replica,(Vec<(BigInt,HashSet<Replica>,HashSet<Replica>,bool,bool)>,HashSet<BigInt>,Vec<BigInt>),nohash_hasher::BuildNoHashHasher<Replica>>,
    pub term_vals:HashMap<Replica,BigInt>,
}

impl RoundState{
    pub fn new_with_echo(msgs: Vec<(Replica,Vec<u8>)>,echo_sender:Replica)-> RoundState{
        let mut rnd_state = RoundState{
            state:HashMap::default(),
            term_vals:HashMap::default(),
        };
        for (rep,msg) in msgs.clone().into_iter(){
            let parsed_bigint = BigInt::from_bytes_be(Sign::Plus,msg.as_slice());
            let mut arr_state:Vec<(BigInt,HashSet<Replica>,HashSet<Replica>,bool,bool)> = Vec::new();
            let mut echo1_set = HashSet::new();
            echo1_set.insert(echo_sender);
            let echo2_set:HashSet<Replica>=HashSet::new();
            arr_state.push((parsed_bigint,echo1_set,echo2_set,false,false));
            rnd_state.state.insert(rep, (arr_state,HashSet::default(),Vec::new()));
        }
        rnd_state
    }

    pub fn new_with_echo2(msgs: Vec<(Replica,Vec<u8>)>,echo_sender:Replica)-> RoundState{
        let mut rnd_state = RoundState{
            state:HashMap::default(),
            term_vals:HashMap::default(),
        };
        for (rep,msg) in msgs.clone().into_iter(){
            let parsed_bigint = BigInt::from_bytes_be(Sign::Plus,msg.as_slice());
            let mut arr_state:Vec<(BigInt,HashSet<Replica>,HashSet<Replica>,bool,bool)> = Vec::new();
            let mut echo2_set = HashSet::new();
            echo2_set.insert(echo_sender);
            let echo1_set:HashSet<Replica>=HashSet::new();
            arr_state.push((parsed_bigint,echo1_set,echo2_set,false,false));
            rnd_state.state.insert(rep, (arr_state,HashSet::default(),Vec::new()));
        }
        rnd_state
    }

    pub fn add_echo(&mut self, msgs: Vec<(Replica,Vec<u8>)>, echo_sender:Replica, num_nodes: usize, num_faults:usize)-> (Vec<(Replica,Vec<u8>)>,Vec<(Replica,Vec<u8>)>){
        let mut echo1_msgs:Vec<(Replica,Vec<u8>)> = Vec::new();
        let mut echo2_msgs:Vec<(Replica,Vec<u8>)> = Vec::new();
        for (rep,msg) in msgs.into_iter(){
            // If the instance has already terminated, do not process messages from this node
            if self.term_vals.contains_key(&rep){
                continue;
            }
            let parsed_bigint = BigInt::from_bytes_be(Sign::Plus, msg.clone().as_slice());
            if self.state.contains_key(&rep){
                let arr_tup = self.state.get_mut(&rep).unwrap();
                let arr_vec = &mut arr_tup.0;
                // The echo sent by echo_sender was for this value in the bivalent initial value state
                if arr_vec[0].0 == parsed_bigint{
                    arr_vec[0].1.insert(echo_sender);
                    // check for t+1 votes: if it has t+1 votes, send out another echo1 message
                    // check whether an echo has been sent out for this value in this instance
                    //log::info!("Processing values: {:?} inst: {} echo count: {}",arr_vec[0].clone(),rep, arr_vec[0].1.len());
                    if arr_vec[0].1.len() >= num_faults+1 && !arr_vec[0].3{
                        log::info!("Got t+1 ECHO messages for BAA inst {} sending ECHO",rep.clone());
                        echo1_msgs.push((rep,msg.clone()));
                        arr_vec[0].3 = true;
                    }
                    // check for 2t+1 votes: if it has 2t+1 votes, send out echo2 message
                    else if arr_vec[0].1.len() >= num_nodes-num_faults && !arr_vec[0].4{
                        log::info!("Got 2t+1 ECHO messages for BAA inst {} sending ECHO2",rep.clone());
                        echo2_msgs.push((rep,msg.clone()));
                        arr_tup.1.insert(parsed_bigint);
                        if arr_tup.1.len() == 2{
                            // terminate protocol for instance &rep
                            let vec_arr:Vec<BigInt> = arr_tup.1.clone().into_iter().map(|x| x).collect();
                            let next_round_val = (vec_arr[0].clone()+vec_arr[1].clone())/2;
                            self.term_vals.insert(rep, next_round_val);
                        }
                        arr_vec[0].4 = true;
                    }
                }
                else{
                    if arr_vec.len() == 1{
                        // insert new array vector
                        let mut echo_set:HashSet<Replica>= HashSet::default();
                        echo_set.insert(rep);
                        arr_vec.push((parsed_bigint,echo_set,HashSet::default(),false,false));
                    }
                    else {
                        arr_vec[1].1.insert(rep);
                        if arr_vec[1].1.len() >= num_faults+1 && !arr_vec[1].3{
                            log::info!("Second value {} got t+1 votes",parsed_bigint.clone());
                            echo1_msgs.push((rep,msg.clone()));
                            arr_vec[1].3 = true;
                        }
                        else if arr_vec[1].1.len() >= num_nodes-num_faults && !arr_vec[1].4{
                            echo2_msgs.push((rep,msg.clone()));
                            arr_tup.1.insert(parsed_bigint);
                            if arr_tup.1.len() == 2{
                                // terminate protocol for instance &rep
                                let vec_arr:Vec<BigInt> = arr_tup.1.clone().into_iter().map(|x| x).collect();
                                let next_round_val = (vec_arr[0].clone()+vec_arr[1].clone())/2;
                                self.term_vals.insert(rep, next_round_val);
                            }
                            arr_vec[1].4 = true;
                        }
                    }
                }
            }
            else{
                let mut echo_set:HashSet<Replica> = HashSet::default();
                echo_set.insert(rep);
                let mut arr_vec:Vec<(BigInt, HashSet<Replica>, HashSet<Replica>,bool,bool)> = Vec::new();
                arr_vec.push((parsed_bigint,echo_set,HashSet::default(),false,false));
                self.state.insert(rep, (arr_vec,HashSet::default(),Vec::new()));
            }
        }
        (echo1_msgs,echo2_msgs)
    }

    pub fn add_echo2(&mut self,msgs: Vec<(Replica,Vec<u8>)>, echo2_sender:Replica,num_nodes: usize,num_faults:usize){
        for (rep,msg) in msgs.into_iter(){
            let parsed_bigint = BigInt::from_bytes_be(Sign::Plus, msg.clone().as_slice());
            if self.state.contains_key(&rep){
                let arr_tup = self.state.get_mut(&rep).unwrap();
                // this vector can only contain two elements, if the echo corresponds to the first element, the first if block is executed
                let arr_vec = &mut arr_tup.0;
                if arr_vec[0].0 == parsed_bigint{
                    arr_vec[0].2.insert(echo2_sender);
                    // check for 2t+1 votes: if it has 2t+1 votes, send out echo2 message
                    if arr_vec[0].2.len() >= num_nodes-num_faults{
                        arr_tup.2.push(parsed_bigint);
                        self.term_vals.insert(rep, arr_vec[0].0.clone());
                    }
                }
                else{
                    if arr_vec.len() == 1{
                        // insert new array vector
                        let mut echo2_set:HashSet<Replica>= HashSet::default();
                        echo2_set.insert(rep);
                        arr_vec.push((parsed_bigint,HashSet::default(),echo2_set,false,false));
                    }
                    else{
                        arr_vec[1].2.insert(rep);
                        if arr_vec[1].2.len() >= num_nodes-num_faults{
                            log::info!("Value {:?} received n-f echo2s for instance {}",arr_vec[1].0.clone(),rep);
                            arr_tup.2.push(parsed_bigint);
                            self.term_vals.insert(rep, arr_vec[1].0.clone());
                        }
                    }
                }
            }
            else {
                let mut echo_set:HashSet<Replica> = HashSet::default();
                echo_set.insert(rep);
                let mut arr_vec:Vec<(BigInt, HashSet<Replica>, HashSet<Replica>,bool,bool)> = Vec::new();
                arr_vec.push((parsed_bigint,HashSet::default(),echo_set,false,false));
                self.state.insert(rep, (arr_vec,HashSet::default(),Vec::new()));
            }
        }
    }
}