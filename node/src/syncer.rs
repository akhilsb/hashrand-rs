use std::{collections::{HashSet, HashMap}, net::SocketAddr, time::{SystemTime, UNIX_EPOCH, Duration}};

use anyhow::{Result, anyhow};
use appxcon::node::SyncHandler;
use fnv::FnvHashMap;
use network::{plaintcp::{TcpReceiver, TcpReliableSender, CancelHandler}, Acknowledgement};
use tokio::sync::{oneshot, mpsc::{unbounded_channel, UnboundedReceiver}};
use types::{Replica, SyncMsg, SyncState};

pub struct Syncer{
    pub num_nodes: usize,
    pub start_time: u128,
    pub sharing_complete_times: HashMap<Replica,u128>,
    pub recon_start_time: u128,
    pub net_map: FnvHashMap<Replica,String>,
    pub alive: HashSet<Replica>,
    pub timings:HashMap<Replica,u128>,
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
        TcpReceiver::<Acknowledgement, SyncMsg, _>::spawn(
            cli_addr,
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
        loop {
            tokio::select! {
                // Receive exit handlers
                exit_val = &mut self.exit_rx => {
                    exit_val.map_err(anyhow::Error::new)?;
                    log::info!("Termination signal received by the server. Exiting.");
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
                            log::info!("Got ALIVE message from node {}",msg.sender);
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
                            log::info!("Node {} started the protocol",msg.sender);
                        },
                        SyncState::CompletedSharing=>{
                            log::info!("Node {} completed the sharing phase of the protocol",msg.sender);
                            self.sharing_complete_times.insert(msg.sender, SystemTime::now().duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis());
                            self.values.insert(msg.sender,msg.value);
                            if self.sharing_complete_times.len() == self.num_nodes{
                                // All nodes terminated sharing protocol
                                let mut vec_times = Vec::new();
                                for (_rep,time) in self.sharing_complete_times.iter(){
                                    vec_times.push(time.clone()-self.start_time);
                                }
                                vec_times.sort();
                                log::info!("All n nodes completed the sharing protocol {:?} {:?}",vec_times,self.values);
                                self.start_time = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis(); 
                                self.broadcast(SyncMsg { sender: self.num_nodes, state: SyncState::StartRecon, value:0 }).await;
                            }
                        },
                        SyncState::CompletedRecon=>{
                            log::info!("Node {} completed the reconstruction phase of the protocol",msg.sender);
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
                                log::info!("All n nodes completed the recon protocol {:?} {:?}",vec_times,self.values);
                                self.broadcast(SyncMsg { sender: self.num_nodes, state: SyncState::STOP, value:0}).await;
                            }
                        },
                        SyncState::COMPLETED=>{
                            log::info!("Got COMPLETED message from node {}",msg.sender);
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
                                log::info!("All n nodes completed the protocol {:?} with values {:?}",vec_times,self.values);
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