use std::{time::{SystemTime, UNIX_EPOCH, Duration}, collections::HashMap, process::exit};

use anyhow::{Result, Ok,anyhow};
use network::{plaintcp::{TcpReliableSender, CancelHandler}, Acknowledgement};
use num_bigint::BigInt;
use tokio::{sync::{mpsc::UnboundedReceiver, oneshot}};
use tokio_util::time::DelayQueue;
use types::{hash_cc::{WrapperMsg, Replica, CoinMsg}, Round, SyncMsg, SyncState};
use config::Node;
use tokio_stream::StreamExt;

use super::{RoundState, Handler, VSSState, SyncHandler};

use fnv::FnvHashMap;
use network::{plaintcp::{TcpReceiver}};
use tokio::sync::mpsc::unbounded_channel;
use std::{net::{SocketAddr, SocketAddrV4}};

pub struct Context {
    /// Networking context
    pub net_send: TcpReliableSender<Replica,WrapperMsg,Acknowledgement>,
    pub net_recv: UnboundedReceiver<WrapperMsg>,
    pub sync_send:TcpReliableSender<Replica,SyncMsg,Acknowledgement>,
    pub sync_recv: UnboundedReceiver<SyncMsg>,
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
    /// state: Your share of AVSS from node x and its corresponding verifier.
    pub vss_state: HashMap<Replica,(Vec<u8>,Vec<u8>)>,
    pub witness_state:VSSState,
    pub secret_shares: HashMap<Replica,HashMap<Replica,Vec<u8>>>,
    pub aggr_context: RoundState,

    /// Approximate agreement context
    
    pub round_state: HashMap<u32,RoundState>,
    pub bench: HashMap<String,u128>,
    pub nz_appxcon_rs: HashMap<Replica,(BigInt,bool,BigInt)>,
    /// Coin invoke
    pub invoke_coin:DelayQueue<Replica>,
    /// Exit protocol
    pub exit_rx: oneshot::Receiver<()>,
    /// Cancel Handlers
    pub cancel_handlers: HashMap<Round,Vec<CancelHandler<Acknowledgement>>>,
}

impl Context {
    pub fn spawn(
        config:Node,
        sleep:u128
    )->anyhow::Result<oneshot::Sender<()>>{
        let prot_payload = &config.prot_payload;
        let v:Vec<&str> = prot_payload.split(',').collect();
        let mut consensus_addrs :FnvHashMap<Replica,SocketAddr>= FnvHashMap::default();
        for (replica,address) in config.net_map.iter(){
            let address:SocketAddr = address.parse().expect("Unable to parse address");
            consensus_addrs.insert(*replica, SocketAddr::from(address.clone()));
        }
        let my_port = consensus_addrs.get(&config.id).unwrap();
        let my_address = to_socket_address("0.0.0.0", my_port.port());
        let mut syncer_map:FnvHashMap<Replica,SocketAddr> = FnvHashMap::default();
        syncer_map.insert(0, config.client_addr);
        // No clients needed

        // let prot_net_rt = tokio::runtime::Builder::new_multi_thread()
        // .enable_all()
        // .build()
        // .unwrap();

        // Setup networking
        let (tx_net_to_consensus, rx_net_to_consensus) = unbounded_channel();
        TcpReceiver::<Acknowledgement, WrapperMsg, _>::spawn(
            my_address,
            Handler::new(tx_net_to_consensus),
        );
        let sleep_time = sleep - SystemTime::now().duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
        let consensus_net = TcpReliableSender::<Replica,WrapperMsg,Acknowledgement>::with_peers(
            consensus_addrs.clone()
        );
        let syncer_listen_port = config.client_port;
        let syncer_l_address = to_socket_address("0.0.0.0", syncer_listen_port);
        // The server must listen to the client's messages on some port that is not being used to listen to other servers
        let (tx_net_to_client,rx_net_from_client) = unbounded_channel();
        TcpReceiver::<Acknowledgement,SyncMsg,_>::spawn(
            syncer_l_address, 
            SyncHandler::new(tx_net_to_client)
        );
        let sync_net = TcpReliableSender::<Replica,SyncMsg,Acknowledgement>::with_peers(syncer_map);
        if v[0] == "cc" {
            let (exit_tx, exit_rx) = oneshot::channel();
            tokio::spawn(async move {
                // The modulus of the secret is set for probability of coin success = 1- 5*10^{-9}
                let prime = BigInt::parse_bytes(b"685373784908497",10).unwrap();
                let epsilon:u32 = ((1024*1024)/(config.num_nodes*config.num_faults)) as u32;
                let rounds = (50.0 - ((epsilon as f32).log2().ceil())) as u32;
                let mut c = Context {
                    net_send:consensus_net,
                    net_recv:rx_net_to_consensus,
                    sync_send: sync_net,
                    sync_recv: rx_net_from_client,
                    num_nodes: config.num_nodes,
                    sec_key_map: HashMap::default(),
                    myid: config.id,
                    num_faults: config.num_faults,
                    payload: config.payload,
                    
                    secret_domain:prime.clone(),
                    rounds_aa:rounds,
                    epsilon:epsilon,
                    curr_round:0,
                    num_messages:0,

                    vss_state: HashMap::default(),
                    aggr_context: RoundState::new(),
                    witness_state:VSSState::new(),
                    secret_shares:HashMap::new(),
                    round_state: HashMap::default(),
                    bench: HashMap::default(),
                    //echos_ss: HashMap::default(),
                    invoke_coin:tokio_util::time::DelayQueue::new(),
                    exit_rx:exit_rx,
                    cancel_handlers:HashMap::default(),
                    nz_appxcon_rs: HashMap::default()
                };
                for (id, sk_data) in config.sk_map.clone() {
                    c.sec_key_map.insert(id, sk_data.clone());
                }
                //c.invoke_coin.insert(100, Duration::from_millis(sleep_time.try_into().unwrap()));
                if let Err(e) = c.run().await {
                    log::error!("Consensus error: {}", e);
                }
            });
            Ok(exit_tx)
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

    pub async fn broadcast(&mut self, protmsg:CoinMsg){
        let sec_key_map = self.sec_key_map.clone();
        for (replica,sec_key) in sec_key_map.into_iter() {
            if replica != self.myid{
                let wrapper_msg = WrapperMsg::new(protmsg.clone(), self.myid, &sec_key.as_slice());
                let cancel_handler:CancelHandler<Acknowledgement> = self.net_send.send(replica, wrapper_msg).await;
                self.add_cancel_handler(cancel_handler);
                // let sent_msg = Arc::new(wrapper_msg);
                // self.c_send(replica, sent_msg).await;
            }
        }
    }

    pub fn add_cancel_handler(&mut self, canc: CancelHandler<Acknowledgement>){
        self.cancel_handlers
            .entry(self.curr_round)
            .or_default()
            .push(canc);
    }

    pub async fn send(&mut self,replica:Replica, wrapper_msg:WrapperMsg){
        let cancel_handler:CancelHandler<Acknowledgement> = self.net_send.send(replica, wrapper_msg).await;
        self.add_cancel_handler(cancel_handler);
    }

    pub async fn run(&mut self)-> Result<()>{
        let cancel_handler = self.sync_send.send(
            0,
                SyncMsg { sender: self.myid, state: SyncState::ALIVE,value:0}
            ).await;
        self.add_cancel_handler(cancel_handler);
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
                    log::debug!("Got a consensus message from the network: {:?}", msg);
                    let msg = msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    self.process_msg( msg).await;
                },
                sync_msg = self.sync_recv.recv() =>{
                    let sync_msg = sync_msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    match sync_msg.state {
                        SyncState::START =>{
                            log::error!("Consensus Start time: {:?}", SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis());
                            self.start_wss().await;
                            let cancel_handler = self.sync_send.send(0, SyncMsg { sender: self.myid, state: SyncState::STARTED, value:0}).await;
                            self.add_cancel_handler(cancel_handler);
                        },
                        SyncState::StartRecon =>{
                            log::error!("Reconstruction Start time: {:?}", SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis());
                            self.send_reconstruct().await;
                        },
                        SyncState::STOP =>{
                            log::error!("Consensus Stop time: {:?}", SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis());
                            log::info!("Termination signal received by the server. Exiting.");
                            break
                        },
                        _=>{}
                    }
                },
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

// use futures::{channel::mpsc::UnboundedSender};
// use num_bigint::BigInt;
// use types::hash_cc::{WrapperMsg, Replica};
// use config::Node;
// use fnv::FnvHashMap as HashMap;
// use vss_state::VSSState;
// use std::{sync::Arc};

// use crate::node::vss_state;

// use super::RoundState;

// pub struct Context {
//     /// Networking context
//     pub net_send: UnboundedSender<(Replica, Arc<WrapperMsg>)>,

//     /// Data context
//     pub num_nodes: usize,
//     pub myid: usize,
//     pub num_faults: usize,
//     pub payload:usize,

//     /// PKI
//     /// Replica map
//     pub sec_key_map:HashMap<Replica, Vec<u8>>,

//     /// The context parameters related to Verifiable Secret sharing for the common coin
//     pub secret_domain: BigInt,
//     pub rounds_aa: u32,
//     pub epsilon: u32,
//     pub curr_round:u32,
//     pub num_messages:u32,

//     /// State context
//     /// Verifiable Secret Sharing context
//     pub vss_state: VSSState,
//     /// Approximate agreement context
//     pub round_state: HashMap<u32,RoundState>,
//     pub nz_appxcon_rs: HashMap<Replica,(BigInt,bool,BigInt)>,
// }

// impl Context {
//     pub fn new(
//         config: &Node,
//         net_send: UnboundedSender<(Replica, Arc<WrapperMsg>)>,
//     ) -> Self {
//         let prot_payload = &config.prot_payload;
//         let v:Vec<&str> = prot_payload.split(',').collect();
//         if v[0] == "cc" {
//             // The modulus of the secret is set for probability of coin success = 1- 5*10^{-9}
//             let prime = BigInt::parse_bytes(b"685373784908497",10).unwrap();
//             let epsilon:u32 = ((1024*1024)/(config.num_nodes*config.num_faults)) as u32;
//             let rounds = (50.0 - ((epsilon as f32).log2().ceil())) as u32;
//             let mut c = Context {
//                 net_send,
//                 num_nodes: config.num_nodes,
//                 sec_key_map: HashMap::default(),
//                 myid: config.id,
//                 num_faults: config.num_faults,
//                 payload: config.payload,
                
//                 secret_domain:prime,
//                 rounds_aa:rounds,
//                 epsilon:epsilon,
//                 curr_round:0,
//                 num_messages:0,

//                 vss_state: VSSState::new(),
//                 round_state: HashMap::default(),
//                 nz_appxcon_rs: HashMap::default(),
//                 //echos_ss: HashMap::default(),
//             };
//             for (id, sk_data) in config.sk_map.clone() {
//                 c.sec_key_map.insert(id, sk_data.clone());
//             }
//             log::debug!("Started n-parallel RBC with value {:?} and epsilon {}",c.rounds_aa,c.epsilon);
//             // Initialize storage
//             c
//         }
//         else {
//             panic!("Invalid configuration for protocol");
//         }
//     }
// }