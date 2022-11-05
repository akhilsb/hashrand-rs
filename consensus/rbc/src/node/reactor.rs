/// The core module used for Reliable broadcast
/// 
/// The reactor reacts to all the messages from the network, and talks to the
/// clients accordingly.

use tokio::sync::mpsc::{
    UnboundedSender, 
    UnboundedReceiver
};
use types::rbc::{ProtocolMsg};
use config::Node;
use types::rbc::Replica;
use crate::node::{context::Context, process::process_msg};


use std::sync::Arc;

pub async fn reactor(
    config:&Node,
    net_send: UnboundedSender<(Replica, Arc<ProtocolMsg>)>,
    mut net_recv: UnboundedReceiver<(Replica, ProtocolMsg)>
) {
    log::debug!("Started timers");
    let mut cx = Context::new(config, net_send);
    let _block_size = config.block_size;
    let _myid = config.id;
    // Start event loop
    loop {
        tokio::select! {
            pmsg_opt = net_recv.recv() => {
                // Received a protocol message
                let protmsg = match pmsg_opt {
                    None => break,
                    Some((_, x)) => x,
                };
                process_msg(&mut cx, protmsg).await;
            },
        }
    }
}