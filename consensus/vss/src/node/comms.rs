use tokio::task::JoinHandle;
use types::rbc::{ProtocolMsg, Replica};

use super::context::Context;
use futures::SinkExt;
use std::sync::Arc;

/// Communication logic
/// Contains three functions
/// - `Send` - Send a message to a specific node
/// - `Multicast` - Send a message to all the peers

impl Context {
    /// Send a message to a specific peer
    // pub(crate) async fn send(&mut self, to: Replica, msg: Arc<ProtocolMsg>) {
    //     self.net_send.send((to, msg)).await.unwrap();
    // }

    /// Send a message concurrently (by launching a new task) to a specific peer
    pub(crate) async fn c_send(&mut self, to:Replica, msg: Arc<ProtocolMsg>) -> JoinHandle<()> {
        let mut send_copy = self.net_send.clone();
        let myid = self.myid;
        tokio::spawn(async move {
            if to == myid {
                return;
            }
            send_copy.send((to, msg)).await.unwrap()
        })
    }
}