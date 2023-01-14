use std::{path::PathBuf, collections::HashMap};

use anyhow::{Result, Ok,anyhow};
use network::{plaintcp::{TcpReliableSender, CancelHandler}, Acknowledgement};
use num_bigint::BigInt;
use tokio::{sync::{mpsc::{UnboundedReceiver}, oneshot}};
use types::{hash_cc::{Replica, CoinMsg, WrapperSMRMsg, DAGMsg, SMRMsg}, Round};
use config::Node;

use crate::node::Processor;

use super::{BatchVSSState, Handler, RBCRoundState, CoinRoundState, DAGState, Blk};

use fnv::FnvHashMap;
use network::{plaintcp::{TcpReceiver}};
use tokio::sync::mpsc::unbounded_channel;
use std::{net::{SocketAddr, SocketAddrV4}};

pub struct Context {
    /// Networking context
    pub net_send: TcpReliableSender<Replica,WrapperSMRMsg,Acknowledgement>,
    pub net_recv: UnboundedReceiver<WrapperSMRMsg>,
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
    pub round_state: HashMap<u32,RBCRoundState,nohash_hasher::BuildNoHashHasher<Round>>,

    /// Approximate agreement context
    pub cc_round_state: HashMap<u32,CoinRoundState,nohash_hasher::BuildNoHashHasher<Round>>,
    pub bench: HashMap<String,u128>,

    /// DAG Context
    /// Related details about the Directed Acyclic Graph formed by DAG-Rider
    pub dag_state: DAGState,
    /// Exit protocol
    exit_rx: oneshot::Receiver<()>,
    /// Cancel Handlers
    pub cancel_handlers: HashMap<Round,Vec<CancelHandler<Acknowledgement>>,nohash_hasher::BuildNoHashHasher<Round>>,
    /// Client related Context
    pub rx_stream_from_batcher: UnboundedReceiver<Blk>,
}

impl Context {
    pub fn spawn(
        config:Node
    )->anyhow::Result<oneshot::Sender<()>>{
        let mut consensus_addrs :FnvHashMap<Replica,SocketAddr>= FnvHashMap::default();
        for (replica,address) in config.net_map.iter(){
            let address:SocketAddr = address.parse().expect("Unable to parse address");
            consensus_addrs.insert(*replica, SocketAddr::from(address.clone()));
        }
        let my_port = consensus_addrs.get(&config.id).unwrap();
        let my_address = to_socket_address("0.0.0.0", my_port.port());
        //let client_address = to_socket_address("0.0.0.0", config.client_port);
        // No clients needed

        // let prot_net_rt = tokio::runtime::Builder::new_multi_thread()
        // .enable_all()
        // .build()
        // .unwrap();

        // Setup networking
        let (tx_net_to_consensus, rx_net_to_consensus) = unbounded_channel();
        TcpReceiver::<Acknowledgement, WrapperSMRMsg, _>::spawn(
            my_address.clone(),
            Handler::new(tx_net_to_consensus),
        );

        let (tx_batch_client,rx_batch_client) = unbounded_channel();
        Processor::spawn(tx_batch_client);
        //let (tx_client_str,rx_client_str) = unbounded_channel();
        let consensus_net = TcpReliableSender::<Replica,WrapperSMRMsg,Acknowledgement>::with_peers(
            consensus_addrs.clone()
        );
        let (exit_tx, exit_rx) = oneshot::channel();
        log::info!(" booted on {:?}",my_address);
        tokio::spawn(async move {
            let v:Vec<&str> = config.prot_payload.split(',').collect();
            if v[0] == "cc"{
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
                log::debug!("{:?} {:?} {:?}",v[1],v,path);
                let dag_state = DAGState::new(path.to_str().unwrap().to_string(), config.id);
                let mut c = Context {
                    net_send:consensus_net,
                    net_recv:rx_net_to_consensus,
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
                    dag_state:dag_state,
                    cancel_handlers:HashMap::default(),
                    exit_rx: exit_rx,
                    rx_stream_from_batcher: rx_batch_client,
                };
                for (id, sk_data) in config.sk_map.clone() {
                    c.sec_key_map.insert(id, sk_data.clone());
                }
                if let Err(e) = c.run().await {
                    log::error!("Consensus error: {}", e);
                }
            }
            else {
                panic!("Invalid configuration for protocol");
            }
        });
        Ok(exit_tx)
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

    // pub async fn broadcast(&mut self, protmsg:CoinMsg){
    //     let sec_key_map = self.sec_key_map.clone();
    //     for (replica,sec_key) in sec_key_map.into_iter() {
    //         if replica != self.myid{
    //             let wrapper_msg = WrapperMsg::new(protmsg.clone(), self.myid, &sec_key.as_slice());
    //             let cancel_handler:CancelHandler<Acknowledgement> = self.net_send.send(replica, wrapper_msg).await;
    //             self.add_cancel_handler(cancel_handler);
    //             // let sent_msg = Arc::new(wrapper_msg);
    //             // self.c_send(replica, sent_msg).await;
    //         }
    //     }
    // }

    pub async fn broadcast(&mut self, protmsg:&mut SMRMsg){
        if matches!(protmsg.dag_msg,DAGMsg::NoMessage()) && matches!(protmsg.coin_msg,CoinMsg::NoMessage()){
            return;
        }
        else{
            let sec_key_map = self.sec_key_map.clone();
            for (replica,sec_key) in sec_key_map.into_iter() {
                if replica != self.myid{
                    let wrapper_msg = WrapperSMRMsg::new(protmsg, self.myid, &sec_key.as_slice());
                    let cancel_handler:CancelHandler<Acknowledgement> = self.net_send.send(replica, wrapper_msg).await;
                    self.add_cancel_handler(cancel_handler);
                }
            }
        }
    }

    pub fn add_cancel_handler(&mut self, canc: CancelHandler<Acknowledgement>){
        self.cancel_handlers
            .entry(self.curr_round)
            .or_default()
            .push(canc);
    }

    pub fn clear_cancel_handlers(&mut self){
        // clear all handlers in the last committed wave
        let round_num_latest= self.dag_state.last_committed_wave*4;
        let last_round;
        if round_num_latest > 20{
            last_round = round_num_latest -20;
        }
        else{
            last_round = 0;
        }
        for j in last_round..round_num_latest{
            self.cancel_handlers.remove(&j);
        }
    }

    pub async fn send(&mut self,replica:Replica, wrapper_msg:WrapperSMRMsg){
        let cancel_handler:CancelHandler<Acknowledgement> = self.net_send.send(replica, wrapper_msg).await;
        self.add_cancel_handler(cancel_handler);
    }

    pub async fn run(&mut self)-> Result<()>{
        //let mut num_msgs = 0;
        // start batch wss and then start waiting
        log::debug!("Starting txn loop");
        // Do not start loop until all nodes are up and online
        self.start_rbc().await;
        //let mut flag = true;
        let mut channel_closed = false;
        loop {
            tokio::select! {
                // Receive exit handlers
                exit_val = &mut self.exit_rx => {
                    exit_val.map_err(anyhow::Error::new)?;
                    log::info!("Termination signal received by the server. Exiting.");
                    break
                },
                msg = self.net_recv.recv() => {
                    // Received a protocol message
                    log::trace!("Got a consensus message from the network: {:?}", msg);
                    let msg = msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    self.process_msg( msg).await;
                },
                blk = self.rx_stream_from_batcher.recv(), if !channel_closed => {
                    // Received a protocol message
                    match blk{
                        None=>{
                            log::error!("Empty batch received");
                            channel_closed = true;
                        },
                        Some(blk)=>{
                            self.dag_state.client_batches.push_back(blk);
                        }
                    }
                }
                // b_opt = self.invoke_coin.next(), if !self.invoke_coin.is_empty() => {
                //     // Got something from the timer
                //     match b_opt {
                //         None => {
                //             log::error!("Timer finished");
                //         },
                //         Some(core::result::Result::Ok(b)) => {
                //             log::debug!("Timer expired");
                //             let num = b.into_inner().clone();
                //             if num == 100 && flag{
                //                 self.start_batchwss().await;
                //                 flag = false;
                //             }
                //             else{
                //                 if self.num_messages <= num_msgs+10{
                //                     log::error!("Start reconstruction {:?}",SystemTime::now()
                //                     .duration_since(UNIX_EPOCH)
                //                     .unwrap()
                //                     .as_millis());
                //                     self.send_batchreconstruct(0).await;
                //                 }
                //                 else{
                //                     log::error!("{:?} {:?}",num,num_msgs);
                //                     //self.invoke_coin.insert(0, Duration::from_millis((5000).try_into().unwrap()));
                //                 }
                //                 num_msgs = self.num_messages;
                //             }
                //         },
                //         Some(Err(e)) => {
                //             log::warn!("Timer misfired: {}", e);
                //             continue;
                //         }
                //     }
                // }
            };
        }
        Ok(())
    }
}

pub fn to_socket_address(
    ip_str: &str,
    port: u16,
) -> SocketAddr {
    let addr = SocketAddrV4::new(ip_str.parse().unwrap(), port);
    addr.into()
}
    // pub(crate) async fn c_send(&self, to:Replica, msg: Arc<WrapperMsg>) -> JoinHandle<()> {
    //     let mut send_copy = self.net_send.clone();
    //     let myid = self.myid;
    //     tokio::spawn(async move {
    //         if to == myid {
    //             return;
    //         }
    //         send_copy.send((to, msg)).await.unwrap()
    //     })
    // }