use std::{time::{SystemTime, UNIX_EPOCH}};

use anyhow::{Result, Ok,anyhow};
use network::{plaintcp::{TcpReliableSender, CancelHandler}, Acknowledgement};
use num_bigint::BigInt;
use tokio::{sync::{mpsc::UnboundedReceiver, oneshot}};
use types::{beacon::{WrapperMsg, Replica, CoinMsg}, Round, SyncMsg, SyncState};
use config::Node;
use fnv::FnvHashMap as HashMap;

use super::{Handler, SyncHandler, CTRBCState};

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
    pub recon_round:u32,
    pub num_messages:u32,
    pub max_rounds:u32,

    /// Committee election parameters
    pub committee_size: usize,

    /// State context
    pub batch_size: usize,
    pub frequency:Round,
    
    pub round_state:HashMap<Round,CTRBCState>,
    pub bench: HashMap<String,u128>,
    /// Approximate Agreement
    pub bin_bun_aa: bool,
    /// Exit protocol
    exit_rx: oneshot::Receiver<()>,
    /// Queue for future messages
    pub wrapper_msg_queue: HashMap<Round,Vec<WrapperMsg>>,
    /// Cancel Handlers
    pub cancel_handlers: HashMap<Round,Vec<CancelHandler<Acknowledgement>>>,
}

impl Context {
    pub fn spawn(
        config:Node,
        _sleep:u128,
        batch:usize,
        frequency:Round
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
        let syncer_listen_port = config.client_port;
        let syncer_l_address = to_socket_address("0.0.0.0", syncer_listen_port);
        // The server must listen to the client's messages on some port that is not being used to listen to other servers
        let (tx_net_to_client,rx_net_from_client) = unbounded_channel();
        TcpReceiver::<Acknowledgement,SyncMsg,_>::spawn(
            syncer_l_address, 
            SyncHandler::new(tx_net_to_client)
        );
        let consensus_net = TcpReliableSender::<Replica,WrapperMsg,Acknowledgement>::with_peers(
            consensus_addrs.clone()
        );
        
        let sync_net = TcpReliableSender::<Replica,SyncMsg,Acknowledgement>::with_peers(syncer_map);
        if v[0] == "cc" {
            let (exit_tx, exit_rx) = oneshot::channel();
            tokio::spawn(async move {
                // The modulus of the secret is set for probability of coin success = 1- 5*10^{-9}
                let prime = BigInt::parse_bytes(b"685373784908497",10).unwrap();
                let epsilon:u32 = ((1024*1024)/(config.num_nodes*config.num_faults)) as u32;
                let rounds = (50.0 - ((epsilon as f32).log2().ceil())) as u32;
                log::error!("Appx consensus rounds: {}",rounds);
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
                    recon_round:20000,
                    num_messages:0,
                    max_rounds: 20000,
                    bin_bun_aa: false,
                    committee_size:43,
                    
                    round_state:HashMap::default(),
                    batch_size:batch,
                    frequency:frequency,
                    bench: HashMap::default(),
                    exit_rx:exit_rx,
                    cancel_handlers:HashMap::default(),
                    
                    wrapper_msg_queue:HashMap::default(),
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

    pub async fn broadcast(&mut self, protmsg:CoinMsg,round:Round){
        let sec_key_map = self.sec_key_map.clone();
        for (replica,sec_key) in sec_key_map.into_iter() {
            if replica != self.myid{
                let wrapper_msg = WrapperMsg::new(protmsg.clone(), self.myid, &sec_key.as_slice(),round);
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
                            self.start_new_round(20000,Vec::new()).await;
                            let cancel_handler = self.sync_send.send(0, SyncMsg { sender: self.myid, state: SyncState::STARTED, value:0}).await;
                            self.add_cancel_handler(cancel_handler);
                        },
                        SyncState::StartRecon =>{
                            log::error!("Reconstruction Start time: {:?}", SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis());
                            self.reconstruct_beacon(0,0).await;
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
                // b_opt = self.invoke_coin.next(), if !self.invoke_coin.is_empty() => {
                //     // Got something from the timer
                //     match b_opt {
                //         None => {
                //             log::error!("Timer finished");
                //         },
                //         Some(core::result::Result::Ok(b)) => {
                //             //log::error!("Timer expired");
                //             let num = b.into_inner().clone();
                //             num_times+=1;
                //             if num == 100 && flag{
                //                 flag = false;
                //                 log::error!("Sharing Start time: {:?}", SystemTime::now()
                //                 .duration_since(UNIX_EPOCH)
                //                 .unwrap()
                //                 .as_millis());
                //                 self.start_batchwss().await;
                //             }
                //             else{
                //                 // What crappy jugaad is this? Need a client to coordinate
                //                 if self.num_messages <= num_msgs+50{
                //                     log::error!("Start reconstruction {:?}",SystemTime::now()
                //                     .duration_since(UNIX_EPOCH)
                //                     .unwrap()
                //                     .as_millis());
                //                     self.send_batchreconstruct(0).await;
                //                     flag2 = false;
                //                 }
                //                 else{
                //                     log::error!("{:?} {:?}",num,num_msgs);
                //                     //self.invoke_coin.insert(0, Duration::from_millis((5000).try_into().unwrap()));
                //                 }
                //                 num_msgs = self.num_messages;
                //             }
                //             if num_times > 8 && !flag2{
                //                 log::error!("Process exiting!");
                //                 exit(0);
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