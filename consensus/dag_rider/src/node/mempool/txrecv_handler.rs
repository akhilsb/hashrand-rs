use async_trait::async_trait;
use futures::SinkExt;
use network::{Acknowledgement, Handler, Message};
use tokio::sync::mpsc::UnboundedSender;

#[derive(Clone)]
/// Forwards received transactions to the batcher
pub struct TxReceiveHandler<Tx> {
    tx_batcher: UnboundedSender<Tx>,
}

impl<Tx> TxReceiveHandler<Tx> {
    pub fn new(tx_batcher: UnboundedSender<Tx>) -> Self {
        Self { tx_batcher }
    }
}

#[async_trait]
impl<Tx> Handler<Acknowledgement, Tx> for TxReceiveHandler<Tx>
where
    Tx: Message,
{
    async fn dispatch(
        &self,
        msg: Tx,
        writer: &mut network::Writer<Acknowledgement>,
    ) {
        let _ = writer.send(Acknowledgement::Pong).await;
        //let size = bincode::serialized_size(&msg).unwrap() as usize;
        if let Err(e) = self.tx_batcher.send(msg) {
            log::error!("Tx Handler error: {}", e);
        }
    }
}
