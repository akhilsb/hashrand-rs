/// The core module used for Reliable broadcast
/// 
/// The reactor reacts to all the messages from the network, and talks to the
/// clients accordingly.

use futures::channel::mpsc::{
    UnboundedReceiver,
    UnboundedSender,
};
use futures::{StreamExt};
use types::rbc::{ProtocolMsg, Msg, WrapperMsg};
use config::Node;
use types::rbc::Replica;
use crate::node::{context::Context, process::process_msg};


use std::sync::Arc;

pub async fn reactor(
    config:&Node,
    net_send: UnboundedSender<(Replica, Arc<ProtocolMsg>)>,
    mut net_recv: UnboundedReceiver<(Replica, ProtocolMsg)>
) {
    let mut cx = Context::new(config, net_send);
    let _block_size = config.block_size;
    let _myid = config.id;
    // Start Reliable Broadcast from this node if this is the dealer
    // let string = String::from("This is a huge string to be reliably broadcasted");
    // if cx.myid == 1 {
    //     let echo_msg = Msg{
    //         msg_type: 1,
    //         node: cx.myid,
    //         value: string,
    //     };
    //     for (replica,sec_key) in &cx.sec_key_map.clone() {
    //         let wrapper_msg = WrapperMsg::new(echo_msg.clone(),&sec_key.as_slice());
    //         let prot_msg = ProtocolMsg::RBCInit(wrapper_msg);
    //         let sent_msg = Arc::new(prot_msg);
    //         log::info!("{}",*replica);
    //         cx.c_send(*replica,sent_msg).await;
    //     }
    //     log::debug!("Send RBCInit messages from node {:?}",cx.myid);
    // }
    if cx.myid == 1{
        log::info!("First node, starting RBC now!");
        start_rbc(&mut cx).await;
    }
    // Start event loop
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

pub async fn start_rbc(cx: &mut Context){
    if cx.myid == 1 {
        let echo_msg = Msg{
            msg_type: 1,
            node: cx.myid,
            value: String::from("string"),
        };
        for (replica,sec_key) in &cx.sec_key_map.clone() {
            let wrapper_msg = WrapperMsg::new(echo_msg.clone(),&sec_key.as_slice());
            let prot_msg = ProtocolMsg::RBCInit(wrapper_msg);
            log::info!("{} {:?}",replica,prot_msg.clone());
            let sent_msg = Arc::new(prot_msg);
            cx.c_send(*replica,sent_msg).await;
        }
        log::debug!("Send RBCInit messages from node {:?}",cx.myid);
    }
}