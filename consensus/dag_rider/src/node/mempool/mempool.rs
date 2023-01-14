use std::net::SocketAddr;

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use linked_hash_set::LinkedHashSet;
use types::Replica;

use crate::node::Blk;

pub struct Mempool{
    pub id: Replica,
    pub tx_pool: LinkedHashSet<Vec<u8>>,
    pub client_addr:SocketAddr
}

impl Mempool{
    pub fn spawn(
        client_addr:SocketAddr,
        tx_net_batch:UnboundedSender<Blk>,
        tx_client:UnboundedSender<Vec<u8>>,
        tx_recv:UnboundedReceiver<Vec<u8>>
    ){
        // let store = Vec::new();
        // TcpReceiver::spawn(
        //     client_addr, 
        //     TxReceiveHandler::new(tx_client)
        // );
        // Processor::spawn(store,tx_net_batch, tx_recv);
        log::debug!("{} {:?} {:?} {:?}",client_addr,tx_net_batch,tx_client,tx_recv);
    }
}