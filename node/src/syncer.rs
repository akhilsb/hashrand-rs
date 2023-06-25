use std::{collections::{HashSet, HashMap}, net::{SocketAddr,SocketAddrV4}, time::{SystemTime, UNIX_EPOCH, Duration}};

use anyhow::{Result, anyhow};
use beacon::node::num_bigint::BigInt;
use fnv::FnvHashMap;
use hash_cc::node::SyncHandler;
use network::{plaintcp::{TcpReceiver, TcpReliableSender, CancelHandler}, Acknowledgement};
use tokio::sync::{oneshot, mpsc::{unbounded_channel, UnboundedReceiver}};
use types::{Replica, SyncMsg, SyncState, beacon::Round};

pub struct Syncer{
    pub num_nodes: usize,
    pub start_time: u128,
    pub sharing_complete_times: HashMap<Replica,u128>,
    pub recon_start_time: u128,
    pub net_map: FnvHashMap<Replica,String>,
    pub alive: HashSet<Replica>,
    pub timings:HashMap<Replica,u128>,
    pub beacon_round_fin:HashMap<Round,HashMap<Replica,u128>>,
    pub beacon_recon_fin:HashMap<Round,HashMap<usize,HashMap<Replica,(u128,BigInt)>>>,
    pub values: HashMap<Replica,u64>,
    pub cli_addr: SocketAddr,
    pub rx_net: UnboundedReceiver<SyncMsg>,
    pub net_send: TcpReliableSender<Replica,SyncMsg,Acknowledgement>,
    exit_rx: oneshot::Receiver<()>,
    /// Cancel Handlers
    pub cancel_handlers: Vec<CancelHandler<Acknowledgement>>,
}

impl Syncer{
    pub fn spawn(
        net_map: FnvHashMap<Replica,String>,
        cli_addr:SocketAddr,
    )-> anyhow::Result<oneshot::Sender<()>>{
        let (exit_tx, exit_rx) = oneshot::channel();
        let (tx_net_to_server, rx_net_to_server) = unbounded_channel();
        let cli_addr_sock = cli_addr.port();
        let new_sock_address = SocketAddrV4::new("0.0.0.0".parse().unwrap(), cli_addr_sock);
        TcpReceiver::<Acknowledgement, SyncMsg, _>::spawn(
            std::net::SocketAddr::V4(new_sock_address),
            SyncHandler::new(tx_net_to_server),
        );
        let mut server_addrs :FnvHashMap<Replica,SocketAddr>= FnvHashMap::default();
        println!("{:?}",net_map);
        for (replica,address) in net_map.iter(){
            let address:SocketAddr = address.parse().expect("Unable to parse address");
            server_addrs.insert(*replica, SocketAddr::from(address.clone()));
        }
        let net_send = TcpReliableSender::<Replica,SyncMsg,Acknowledgement>::with_peers(server_addrs);
        tokio::spawn(async move{
            let mut syncer = Syncer{
                net_map:net_map.clone(),
                start_time:0,
                sharing_complete_times:HashMap::default(),
                recon_start_time:0,
                num_nodes:net_map.len(),
                alive:HashSet::default(),
                values:HashMap::default(),
                timings:HashMap::default(),
                beacon_round_fin:HashMap::default(),
                beacon_recon_fin:HashMap::default(),
                cli_addr:cli_addr,
                rx_net:rx_net_to_server,
                net_send:net_send,
                exit_rx:exit_rx,
                cancel_handlers:Vec::new()
            };
            if let Err(e) = syncer.run().await {
                log::error!("Consensus error: {}", e);
            }
        });
        Ok(exit_tx)
    }
    pub async fn broadcast(&mut self, sync_msg:SyncMsg){
        for replica in 0..self.num_nodes {
            let cancel_handler:CancelHandler<Acknowledgement> = self.net_send.send(replica, sync_msg.clone()).await;
            self.add_cancel_handler(cancel_handler);    
        }
    }
    pub async fn run(&mut self)-> Result<()>{
        let mut beacons_count:u32 = 0;
        let time_start = 30000;
        let time_end = 90000;
        loop {
            tokio::select! {
                // Receive exit handlers
                exit_val = &mut self.exit_rx => {
                    exit_val.map_err(anyhow::Error::new)?;
                    log::error!("Termination signal received by the server. Exiting.");
                    break
                },
                msg = self.rx_net.recv() => {
                    // Received a protocol message
                    // Received a protocol message
                    log::debug!("Got a message from the server: {:?}", msg);
                    let msg = msg.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    match msg.state{
                        SyncState::ALIVE=>{
                            log::error!("Got ALIVE message from node {}",msg.sender);
                            self.alive.insert(msg.sender);
                            if self.alive.len() == self.num_nodes{
                                // sleep before sending message
                                std::thread::sleep(Duration::from_secs(3));
                                self.broadcast(SyncMsg { 
                                    sender: self.num_nodes, 
                                    state: SyncState::START,
                                    value:0
                                }).await;
                                self.start_time = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis();
                            }
                        },
                        SyncState::STARTED=>{
                            log::error!("Node {} started the protocol",msg.sender);
                        },
                        SyncState::CompletedSharing=>{
                            log::error!("Node {} completed the sharing phase of the protocol",msg.sender);
                            self.sharing_complete_times.insert(msg.sender, SystemTime::now().duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis());
                            self.values.insert(msg.sender,msg.value);
                            if self.sharing_complete_times.len() == (2*self.num_nodes/3)+1{
                                // All nodes terminated sharing protocol
                                let mut vec_times = Vec::new();
                                for (_rep,time) in self.sharing_complete_times.iter(){
                                    vec_times.push(time.clone()-self.start_time);
                                }
                                vec_times.sort();
                                log::error!("All n nodes completed the sharing protocol {:?} {:?}",vec_times,self.values);
                                self.start_time = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis(); 
                                self.broadcast(SyncMsg { sender: self.num_nodes, state: SyncState::StartRecon, value:0 }).await;
                            }
                        },
                        SyncState::CompletedRecon=>{
                            log::error!("Node {} completed the reconstruction phase of the protocol",msg.sender);
                            self.timings.insert(msg.sender, SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis());
                            if self.timings.len() == self.num_nodes{
                                // All nodes terminated protocol
                                let mut vec_times = Vec::new();
                                for (_rep,time) in self.timings.iter(){
                                    vec_times.push(time.clone()-self.start_time);
                                }
                                vec_times.sort();
                                log::error!("All n nodes completed the recon protocol {:?} {:?}",vec_times,self.values);
                                self.broadcast(SyncMsg { sender: self.num_nodes, state: SyncState::STOP, value:0}).await;
                            }
                        },
                        SyncState::BeaconFin(round,sender)=>{
                            log::debug!("Node {} completed the Beacon finish of the protocol for round {}",sender,round);
                            if !self.beacon_round_fin.contains_key(&round){
                                let val_map:HashMap<Replica, u128> = HashMap::default();
                                self.beacon_round_fin.insert(round,val_map);
                            }
                            let val_map = self.beacon_round_fin.get_mut(&round).unwrap();
                            val_map.insert(msg.sender, SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis());
                            // self.timings.insert(msg.sender, SystemTime::now()
                            // .duration_since(UNIX_EPOCH)
                            // .unwrap()
                            // .as_millis());
                            if val_map.len() == self.num_nodes{
                                // All nodes terminated protocol
                                let mut vec_times = Vec::new();
                                for (_rep,time) in val_map.iter(){
                                    vec_times.push(time.clone()-self.start_time);
                                }
                                vec_times.sort();
                                log::error!("All n nodes completed round {:?} {:?}",round,vec_times);
                                //self.broadcast(SyncMsg { sender: self.num_nodes, state: SyncState::STOP, value:0}).await;
                            }
                        },
                        SyncState::BeaconRecon(round,sender,index,secret)=>{
                            let big_int_sec = BigInt::from_signed_bytes_be(secret.as_slice());
                            //log::error!("Node {} completed the Beacon recon of the protocol for round {} and index {} with secret {:?}",sender,round,index,big_int_sec);
                            if !self.beacon_recon_fin.contains_key(&round){
                                let mut val_map:HashMap<usize, HashMap<Replica,(u128,BigInt)>> = HashMap::default();
                                let mut rep_sec_map = HashMap::default();
                                rep_sec_map.insert(sender,(SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis(),big_int_sec));
                                val_map.insert(index,rep_sec_map);
                                self.beacon_recon_fin.insert(round,val_map);
                                continue;
                            }
                            let val_map = self.beacon_recon_fin.get_mut(&round).unwrap();
                            if !val_map.contains_key(&index){
                                let mut rep_sec_map = HashMap::default();
                                rep_sec_map.insert(sender,(SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis(),big_int_sec));
                                val_map.insert(index,rep_sec_map);
                                continue;
                            }
                            let time_sec_map = val_map.get_mut(&index).unwrap();
                            time_sec_map.insert(sender, (SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis(),big_int_sec));
                            
                            // self.timings.insert(msg.sender, SystemTime::now()
                            // .duration_since(UNIX_EPOCH)
                            // .unwrap()
                            // .as_millis());
                            if time_sec_map.len() == self.num_nodes{
                                // All nodes terminated reconstruction protocol
                                let mut vec_times = Vec::new();
                                let mut set_map:HashSet<BigInt> = HashSet::default();
                                for (_rep,(time,secret)) in time_sec_map.iter(){
                                    let time_lat = time.clone()-self.start_time;
                                    if time_lat > time_start && time_lat < time_end{
                                        vec_times.push(time_lat);
                                    } 
                                    set_map.insert(secret.clone());
                                }
                                if set_map.len() == 1 && vec_times.len() == self.num_nodes {
                                    beacons_count +=1;
                                }
                                //vec_times.sort();
                                //log::error!("All n nodes completed reconstruction for round {:?} and index {} with {:?}",round,index,vec_times);
                                //self.broadcast(SyncMsg { sender: self.num_nodes, state: SyncState::STOP, value:0}).await;
                            }
                            let current_time = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis();
                            if current_time - self.start_time > time_end{
                                log::error!("Beacons in 60 seconds: {} stopping protocol",beacons_count);
                                self.broadcast(SyncMsg { sender: self.num_nodes, state: SyncState::STOP, value:0}).await;
                            }
                        },
                        SyncState::COMPLETED=>{
                            log::error!("Got COMPLETED message from node {}",msg.sender);
                            self.timings.insert(msg.sender, SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis());
                            self.values.insert(msg.sender,msg.value);
                            if self.timings.len() == self.num_nodes{
                                // All nodes terminated protocol
                                let mut vec_times = Vec::new();
                                for (_rep,time) in self.timings.iter(){
                                    vec_times.push(time.clone()-self.start_time);
                                }
                                vec_times.sort();
                                //log::error!("All n nodes completed the protocol {:?} with values {:?}",vec_times,self.values);
                                self.broadcast(SyncMsg { sender: self.num_nodes, state: SyncState::STOP, value:0}).await;
                            }
                        }
                        _=>{}
                    }
                },
            }
        }
        Ok(())
    }
    pub fn add_cancel_handler(&mut self, canc: CancelHandler<Acknowledgement>){
        self.cancel_handlers
            .push(canc);
    }
}