// use anyhow::{anyhow, Result};
// use fnv::FnvHashMap;
// /// The core module used for Asynchronous Approximate Consensus
// /// 
// /// The reactor reacts to all the messages from the network. 

// use futures::{StreamExt};
// use network::Acknowledgement;
// use network::plaintcp::{TcpSimpleSender, TcpReceiver};
// use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
// use types::hash_cc::{WrapperMsg};
// use config::Node;
// use types::hash_cc::Replica;

// use std::net::{SocketAddr, SocketAddrV4};
// use std::sync::Arc;
// use std::time::{SystemTime, UNIX_EPOCH, Duration};

// use crate::node::{process_msg, start_batchwss, send_batchreconstruct, Handler};

// use super::context::Context;

// pub async fn reactor(config:&Node)->Result<()>{
//     let mut consensus_addrs :FnvHashMap<Replica,SocketAddr>= FnvHashMap::default();
//     for (replica,address) in config.net_map.iter(){
//         let address:SocketAddr = address.parse().expect("Unable to parse address");
//         consensus_addrs.insert(*replica, SocketAddr::from(address.clone()));
//     }
//     let my_port = consensus_addrs.get(&config.id).unwrap();
//     let my_address = to_socket_address("0.0.0.0", my_port.port());
//     // No clients needed

//     // let prot_net_rt = tokio::runtime::Builder::new_multi_thread()
//     // .enable_all()
//     // .build()
//     // .unwrap();

//     // Setup networking
//     let (tx_net_to_consensus, mut rx_net_to_consensus) = unbounded_channel();
//     TcpReceiver::<Acknowledgement, WrapperMsg, _>::spawn(
//         my_address,
//         Handler::new(tx_net_to_consensus),
//     );

//     let consensus_net = TcpSimpleSender::<Replica,WrapperMsg,Acknowledgement>::with_peers(
//         consensus_addrs.clone()
//     );
//     // Setup the protocol network

//     // let (net_send, net_recv) = 
//     // prot_net_rt.block_on(
//     //     protocol_network.server_setup(
//     //         config.net_map.clone(), 
//     //         util::codec::EnCodec::new(), 
//     //         util::codec::Decodec::new()
//     //     )
//     // );
//     let mut cx = Context::new(config, consensus_net,rx_net_to_consensus);
//     let _myid = config.id;
//     log::error!("{:?}",SystemTime::now()
//                 .duration_since(UNIX_EPOCH)
//                 .unwrap()
//                 .as_millis());
//     start_batchwss(&mut cx).await;
//     let mut num_msgs = 0;
//     loop {
//         tokio::select! {
//             msg = rx_net_to_consensus.recv() => {
//                 // Received a protocol message
//                 let msg = msg.ok_or_else(||
//                     anyhow!("Networking layer has closed")
//                 )?;
//                 log::debug!("Got a consensus message from the network: {:?}", msg);
//                 process_msg(&mut cx, msg).await;
//             },
//             b_opt = cx.invoke_coin.next(), if !cx.invoke_coin.is_empty() => {
//                 // Got something from the timer
//                 match b_opt {
//                     None => {
//                         log::error!("Timer finished");
//                     },
//                     Some(Ok(b)) => {
//                         let num = b.into_inner().clone();
//                         if cx.num_messages <= num_msgs+10{
//                             log::error!("Start reconstruction {:?}",SystemTime::now()
//                             .duration_since(UNIX_EPOCH)
//                             .unwrap()
//                             .as_millis());
//                             send_batchreconstruct(&mut cx,0).await;
//                         }
//                         else{
//                             log::error!("{:?} {:?}",num,num_msgs);
//                             cx.invoke_coin.insert(0, Duration::from_millis((5000).try_into().unwrap()));
//                         }
//                         num_msgs = cx.num_messages;
//                     },
//                     Some(Err(e)) => {
//                         log::warn!("Timer misfired: {}", e);
//                         continue;
//                     }
//                 }
//             }
//         };
//     }
//     Ok(())
// }

// pub fn to_socket_address(
//     ip_str: &str,
//     port: u16,
// ) -> SocketAddr {
//     let addr = SocketAddrV4::new(ip_str.parse().unwrap(), port);
//     addr.into()
// }