/// The core module used for Asynchronous Approximate Consensus
/// 
/// The reactor reacts to all the messages from the network. 

use futures::channel::mpsc::{
    UnboundedReceiver,
    UnboundedSender,
};
use futures::{StreamExt};
use types::hash_cc::{WrapperSMRMsg};
use config::Node;
use types::hash_cc::Replica;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::node::{process_msg, start_batchwss};

use super::context::Context;

pub async fn reactor(
    config:&Node,
    net_send: UnboundedSender<(Replica, Arc<WrapperSMRMsg>)>,
    mut net_recv: UnboundedReceiver<(Replica, WrapperSMRMsg)>
){
    let mut cx = Context::new(config, net_send);
    
    let _myid = config.id;
    log::error!("{:?}",SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis());
    start_batchwss(&mut cx).await;
    loop {
        tokio::select! {
            pmsg_opt = net_recv.next() => {
                // Received a protocol message
                if let None = pmsg_opt {
                    log::error!(
                        "Protocol message channel closed");
                    std::process::exit(0);
                }
                let protmsg = match pmsg_opt {
                    None => break,
                    Some((_, x)) => x,
                };
                process_msg(&mut cx, protmsg).await;
            },
        }
    }
}