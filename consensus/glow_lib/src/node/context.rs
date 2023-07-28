use std::{net::{SocketAddr, SocketAddrV4}, collections::{HashMap, VecDeque}, fs::File, io::Read};

use anyhow::{Result, anyhow};
use config::Node;
use crypto_blstrs::threshold_sig::{PartialBlstrsSignature, BlstrsPublicKey, Partial, BlstrsSecretKey};
use fnv::FnvHashMap;
use network::{plaintcp::{TcpReliableSender, TcpReceiver, CancelHandler}, Acknowledgement};
use tokio::sync::{mpsc::{UnboundedReceiver, unbounded_channel, Receiver, Sender}, oneshot};
use types::{beacon::{Replica}, Round};

use super::{Handler, state_machine::{sign::{Sign, ProtocolMessage}}, WrapperMsg};

pub struct GlowLib{
    pub net_send: TcpReliableSender<Replica,WrapperMsg,Acknowledgement>,
    pub net_recv: UnboundedReceiver<WrapperMsg>,
    /// Data context
    pub num_nodes: u16,
    pub myid: u16,
    pub num_faults: u16,
    /// PKI
    /// Replica map
    pub sec_key_map:HashMap<u16, Vec<u8>>,
    /// Cancel Handlers
    pub cancel_handlers: HashMap<Round,Vec<CancelHandler<Acknowledgement>>>,
    pub curr_round: u32,
    pub state: HashMap<Round,Sign>,
    pub thresh_state: HashMap<Round,Vec<PartialBlstrsSignature>>,
    //pub secret: LocalKey,
    /// Threshold setup parameters
    pub tpubkey_share: HashMap<u16,Partial<BlstrsPublicKey>>,
    pub secret_key: Partial<BlstrsSecretKey>,
    pub sign_msg: String,
    /// Exit protocol
    exit_rx: oneshot::Receiver<()>,
    /// External interface for the beacon
    pub coin_construction: Receiver<Round>,
    pub coin_send_channel: Sender<(u32,u128)>,
    pub coin_queue: VecDeque<Round>,
    pub beac_state: HashMap<Round,u128>
}

impl GlowLib {
    pub fn spawn(
        config:Node,
        secret_loc:&str,
        pkey_vec: Vec<String>,
        // construct coin when there is an element in this queue
        construct_coin: Receiver<u32>,
        // beacon_send channel
        coin_channel: Sender<(u32,u128)>,
    )->anyhow::Result<oneshot::Sender<()>>{
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
        let consensus_net = TcpReliableSender::<Replica,WrapperMsg,Acknowledgement>::with_peers(
            consensus_addrs.clone()
        );
        let (exit_tx, exit_rx) = oneshot::channel();

        //let secret_key:PathBuf = PathBuf::from(secret_loc.clone());
        log::info!("Secret key file path {} {:?}",secret_loc.clone(),pkey_vec.clone());
        //let secret:Vec<u8> = std::fs::read(secret_key)
        //.context("read file with local secret key")?;
        //let secret = serde_json::from_slice(&secret).context("deserialize local secret key")?;

        // let mut pubkey_poly_buffer = Vec::new();
        // File::open(thresh_pub)
        //             .expect("Unable to open polypub file")
        //             .read_to_end(&mut pubkey_poly_buffer)
        //             .expect("Unable to read polydata");
        let publickey_vec = pkey_vec.into_iter().map(|pkey_loc| {
            let mut thresh_pubkey_buffer = Vec::new();
            File::open(pkey_loc.as_str())
                        .expect("Unable to open polypub file")
                        .read_to_end(&mut thresh_pubkey_buffer)
                        .expect("Unable to read polydata");
            let thresh_pubkey:BlstrsPublicKey = bincode::deserialize(thresh_pubkey_buffer.as_slice()).expect("Unable to deserialize pubkey data");
            thresh_pubkey
        }).collect::<Vec<_>>();
        let mut pkey_map = HashMap::default();
        let mut i:u16 = 1;
        for pkey in publickey_vec.into_iter(){
            pkey_map.insert(i, Partial{
                idx: i as usize,
                data:pkey
            });
            i+=1;
        }
        let mut secret_key_buffer = Vec::new();
        File::open(secret_loc)
                    .expect("Unable to open threshold secret key")
                    .read_to_end(&mut secret_key_buffer)
                    .expect("Unable to read threshold secret key");
        //let pubkey_poly:BlstrsPublicKey = bincode::deserialize(pubkey_poly_buffer.as_slice()).expect("Unable to deserialize pubkey poly data");
        let secret_key:BlstrsSecretKey = bincode::deserialize(secret_key_buffer.as_slice()).expect("Unable to deserialize threshold secret key");
        let secret_share:Partial<BlstrsSecretKey> = Partial { 
            idx: config.id+1, 
            data: secret_key
        };
        tokio::spawn(async move {
            // The modulus of the secret is set for probability of coin success = 1- 5*10^{-9}
            let mut c = GlowLib {
                net_send:consensus_net,
                net_recv:rx_net_to_consensus,
                num_nodes: config.num_nodes.try_into().unwrap(),
                sec_key_map: HashMap::default(),
                myid: config.id.try_into().unwrap(),
                num_faults: config.num_faults.try_into().unwrap(),
                cancel_handlers:HashMap::default(),
                curr_round: 0,
                exit_rx:exit_rx,
                state:HashMap::default(),
                sign_msg: "beacon".to_string(),
                thresh_state: HashMap::default(),
                tpubkey_share:pkey_map,
                secret_key:secret_share,
                coin_construction:construct_coin,
                coin_send_channel:coin_channel,
                coin_queue:VecDeque::new(),
                beac_state: HashMap::default()

            };
            for (id, sk_data) in config.sk_map.clone() {
                c.sec_key_map.insert(id.try_into().unwrap(), sk_data.clone());
            }
            //c.invoke_coin.insert(100, Duration::from_millis(sleep_time.try_into().unwrap()));
            if let Err(e) = c.run().await {
                log::error!("Consensus error: {}", e);
            }
        });
        Ok(exit_tx)
    }

    pub async fn broadcast(&mut self, protmsg:ProtocolMessage,round:Round){
        let sec_key_map = self.sec_key_map.clone();
        for (replica,sec_key) in sec_key_map.into_iter() {
            if replica != self.myid{
                let wrapper_msg = WrapperMsg::new(protmsg.clone(), self.myid, &sec_key.as_slice(),round);
                let cancel_handler:CancelHandler<Acknowledgement> = self.net_send.send(replica as usize, wrapper_msg).await;
                self.add_cancel_handler(cancel_handler);
                // let sent_msg = Arc::new(wrapper_msg);
                // self.c_send(replica, sent_msg).await;
            }
        }
    }

    pub async fn broadcast_tsig(&mut self, data:Vec<u8>,round:Round){
        let sec_key_map = self.sec_key_map.clone();
        for (replica,sec_key) in sec_key_map.into_iter() {
            if replica != self.myid{
                let wrapper_msg = WrapperMsg::new_with_data( self.myid, &sec_key.as_slice(),round,data.clone());
                let cancel_handler:CancelHandler<Acknowledgement> = self.net_send.send(replica as usize, wrapper_msg).await;
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
                    self.process( msg).await;
                },
                coin_recon = self.coin_construction.recv() => {
                    log::error!("Got request to reconstruct coin: {:?}", coin_recon);
                    let round = coin_recon.ok_or_else(||
                        anyhow!("Networking layer has closed")
                    )?;
                    if self.beac_state.contains_key(&round){
                        let u128_fit = self.beac_state.get(&round).unwrap();
                        if let Err(e) = self.coin_send_channel.send((round,*u128_fit)).await {
                            log::warn!(
                                "Failed to beacon {} to the consensus: {}",
                                round, e
                            );
                        };
                    }
                    else{
                        self.start_round_agg(round).await;
                    }
                    //self.reconstruct_beacon( msg,self.recon_round).await;
                },
                // sync_msg = self.sync_recv.recv() =>{
                //     let sync_msg = sync_msg.ok_or_else(||
                //         anyhow!("Networking layer has closed")
                //     )?;
                //     match sync_msg.state {
                //         SyncState::START =>{
                //             log::error!("Consensus Start time: {:?}", SystemTime::now()
                //                 .duration_since(UNIX_EPOCH)
                //                 .unwrap()
                //                 .as_millis());
                //             self.start_round(0).await;
                //             let cancel_handler = self.sync_send.send(0, SyncMsg { sender: self.myid as usize, state: SyncState::STARTED, value:0}).await;
                //             self.add_cancel_handler(cancel_handler);
                //         },
                //         SyncState::STOP =>{
                //             log::error!("Consensus Stop time: {:?}", SystemTime::now()
                //                 .duration_since(UNIX_EPOCH)
                //                 .unwrap()
                //                 .as_millis());
                //             log::info!("Termination signal received by the server. Exiting.");
                //             break
                //         },
                //         _=>{}
                //     }
                // },
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