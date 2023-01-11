use futures::{channel::mpsc::UnboundedSender, SinkExt};
use num_bigint::BigInt;
use tokio::task::JoinHandle;
use types::{hash_cc::{Replica, WrapperSMRMsg, SMRMsg, WSSMsg, DAGMsg, CoinMsg}};
use config::Node;
use fnv::FnvHashMap as HashMap;

use std::{sync::Arc, path::PathBuf};

use super::{BatchVSSState, RBCRoundState, CoinRoundState, DAGState};

pub struct Context {
    /// Networking context
    pub net_send: UnboundedSender<(Replica, Arc<WrapperSMRMsg>)>,

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
    pub num_messages:u32,

    /// State context
    /// Verifiable Secret Sharing context
    pub cur_batchvss_state: BatchVSSState,
    pub batch_size: usize,
    pub prev_batchvss_state: BatchVSSState,
    pub round_state: HashMap<u32,RBCRoundState>,

    /// Approximate agreement context
    pub cc_round_state: HashMap<u32,CoinRoundState>,
    pub bench: HashMap<String,u128>,

    /// DAG Context
    /// Related details about the Directed Acyclic Graph formed by DAG-Rider
    pub dag_state: DAGState,
}

impl Context {
    pub fn new(
        config: &Node,
        net_send: UnboundedSender<(Replica, Arc<WrapperSMRMsg>)>,
    ) -> Self {
        let prot_payload = &config.prot_payload;
        let v:Vec<&str> = prot_payload.split(',').collect();
        if v[0] == "cc" {
            // The modulus of the secret is set for probability of coin success = 1- 5*10^{-9}
            let prime = BigInt::parse_bytes(b"685373784908497",10).unwrap();
            let epsilon:u32 = ((1024*1024)/(config.num_nodes*config.num_faults)) as u32;
            let rounds = (50.0 - ((epsilon as f32).log2().ceil())) as u32;
            // Configure storage here
            let nearest_multiple_of_3 = match rounds %3 {
                0 => {
                    rounds
                },
                1 => {
                    rounds+2
                },
                2 => {
                    rounds+1
                },
                _=>{
                    rounds
                }
            };
            let num_waves_sustained = ((nearest_multiple_of_3/3)+1).try_into().unwrap();
            let path = {
                let mut path = PathBuf::new();
                // TODO: Change it to something more stable in the future
                path.push(v[1]);
                let file_name = format!("{}" , config.id);
                path.push(file_name);
                path.set_extension("db");
                path
            };
            log::error!("{:?} {:?} {:?}",v[1],v,path);
            let dag_state = DAGState::new(path.to_str().unwrap().to_string(), config.id);
            let mut c = Context {
                net_send,
                num_nodes: config.num_nodes,
                sec_key_map: HashMap::default(),
                myid: config.id,
                num_faults: config.num_faults,
                payload: config.payload,
                
                secret_domain:prime.clone(),
                rounds_aa:nearest_multiple_of_3,
                epsilon:epsilon,
                curr_round:0,
                num_messages:0,

                cur_batchvss_state: BatchVSSState::new(prime.clone()),
                batch_size:num_waves_sustained,
                prev_batchvss_state: BatchVSSState::new(prime),

                round_state: HashMap::default(),
                cc_round_state: HashMap::default(),
                bench: HashMap::default(),
                //echos_ss: HashMap::default(),
                dag_state:dag_state
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
    pub fn add_benchmark(&mut self,func: String, elapsed_time:u128)->(){
        if self.bench.contains_key(&func){
            if *self.bench.get(&func).unwrap() < elapsed_time{
                self.bench.insert(func,elapsed_time);
            }
        }
        else {
            self.bench.insert(func, elapsed_time);
        }
    }

    pub async fn broadcast(&mut self, protmsg:&mut SMRMsg){
        if matches!(protmsg.dag_msg,DAGMsg::NoMessage()) && matches!(protmsg.coin_msg,CoinMsg::NoMessage()){
            return;
        }
        else{
            let sec_key_map = self.sec_key_map.clone();
            for (replica,sec_key) in sec_key_map.into_iter() {
                if replica != self.myid{
                    let wrapper_msg = WrapperSMRMsg::new(protmsg, self.myid, &sec_key.as_slice());
                    let sent_msg = Arc::new(wrapper_msg);
                    self.c_send(replica, sent_msg).await;
                }
            }
        }
    }

    pub(crate) async fn c_send(&self, to:Replica, msg: Arc<WrapperSMRMsg>) -> JoinHandle<()> {
        let mut send_copy = self.net_send.clone();
        let myid = self.myid;
        tokio::spawn(async move {
            if to == myid {
                return;
            }
            send_copy.send((to, msg)).await.unwrap()
        })
    }
}