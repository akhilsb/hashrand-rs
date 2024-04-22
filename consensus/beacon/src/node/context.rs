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
/**
 * This artifact implements the HashRand asynchronous random beacon protocol.
 * Please refer to our paper for a detailed description of the protocol. 
 * We wrote exhaustive code comments for ease of code interpretation. 
 */
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
    pub nonce_domain: BigInt,
    /// Number of rounds of Approximate Agreement to run?
    pub rounds_aa: u32,
    /// Final epsilon required in the beacon
    pub epsilon: u32,
    pub curr_round:u32,
    pub recon_round:u32,
    /// Benchmarking purposes
    pub num_messages:u32,
    /// How many beacons to generate before stopping automatically?
    pub max_rounds:u32,

    /// Committee election parameters
    pub committee_size: usize,

    /// State context
    /// Batch size \beta in the paper
    pub batch_size: usize,
    /// Frequency of instantiation \phi in the paper
    pub frequency:Round,
    
    /// Round state object keeps track of all the state associated with a round
    pub round_state:HashMap<Round,CTRBCState>,
    /// Benchmarking individual pieces of the code
    pub bench: HashMap<String,u128>,
    /// Approximate Agreement: Use Binary Approximate Agreement 
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
        
        // Hardcoded sizes of the size of the AnyTrust committees used in the protocol
        let committee_sizes:HashMap<usize,usize> = ([
            (4,3),
            (16,11),
            (40,27),
            (64,43),
            (112,49),
            (136,51),
            (160,54)
        ]).iter().cloned().collect();

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
                // Nonce is much bigger (typically the 2^256-1 field)
                let nonce_prime = BigInt::parse_bytes(b"7540413808418633958282852050178074861680062438274790246382209349819426274715021974571290841231123616713073551439231076214330138511767072438590219824049681", 10).unwrap();
                let epsilon:u32 = ((1024*1024)/(config.num_nodes*config.num_faults)) as u32;
                let rounds = (65.0 - ((epsilon as f32).log2().ceil())) as u32;
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
                    nonce_domain:nonce_prime.clone(),
                    rounds_aa:rounds,
                    epsilon:epsilon,
                    curr_round:0,
                    recon_round:20000,
                    num_messages:0,
                    max_rounds: 20000,
                    bin_bun_aa: false,
                    committee_size:committee_sizes.get(&config.num_nodes).unwrap().clone(),
                    
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

    // Broadcast a message to all nodes.
    pub async fn broadcast(&mut self, protmsg:CoinMsg,round:Round){
        let sec_key_map = self.sec_key_map.clone();
        for (replica,sec_key) in sec_key_map.into_iter() {
            if replica != self.myid{
                let wrapper_msg = WrapperMsg::new(protmsg.clone(), self.myid, &sec_key.as_slice(),round);
                let cancel_handler:CancelHandler<Acknowledgement> = self.net_send.send(replica, wrapper_msg).await;
                self.add_cancel_handler(cancel_handler);
            }
        }
    }

    // Cancel handler is a token to attempt repeated delivery of a message. If the cancel handler of a message is kept in memory, the node keeps retrying to send the message
    // Until it is received by the other party. 
    pub fn add_cancel_handler(&mut self, canc: CancelHandler<Acknowledgement>){
        self.cancel_handlers
            .entry(self.curr_round)
            .or_default()
            .push(canc);
    }

    // Send a message to an individual node
    pub async fn send(&mut self,replica:Replica, wrapper_msg:WrapperMsg){
        let cancel_handler:CancelHandler<Acknowledgement> = self.net_send.send(replica, wrapper_msg).await;
        self.add_cancel_handler(cancel_handler);
    }
    /// The main loop starts here. This loop listens to messages and directs them to their appropriate handlers. 
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
                }
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