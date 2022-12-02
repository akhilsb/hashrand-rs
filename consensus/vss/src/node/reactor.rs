/// The core module used for Asynchronous Approximate Consensus
/// 
/// The reactor reacts to all the messages from the network. 

use futures::channel::mpsc::{
    UnboundedReceiver,
    UnboundedSender,
};
use futures::{StreamExt};
use types::appxcon::{WrapperMsg};
use config::Node;
use types::appxcon::Replica;

use std::sync::Arc;

use crate::node::process_msg;

use super::context::Context;
use super::start_rbc;

pub async fn reactor(
    config:&Node,
    net_send: UnboundedSender<(Replica, Arc<WrapperMsg>)>,
    mut net_recv: UnboundedReceiver<(Replica, WrapperMsg)>
){
    let mut cx = Context::new(config, net_send);
    
    let _myid = config.id;
    start_rbc(&mut cx).await;
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