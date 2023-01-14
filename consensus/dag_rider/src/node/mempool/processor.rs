use std::time::Duration;

use bytes::{BytesMut, BufMut};
use rand::Rng;
use tokio::{sync::mpsc::{UnboundedSender}, time::{Instant, interval}};

use crate::node::Blk;

pub struct Processor{
    //pub batch:Vec<Vec<u8>>,
    //pub tx_recv_stream:UnboundedReceiver<Vec<u8>>,
    pub tx_blk_queue:UnboundedSender<Blk>,
    pub batch_size:u64,
    pub txn_size:u64,
    pub rate:u64
}

impl Processor{
    pub fn spawn(
        //store: Vec<Vec<u8>>,
        tx_blk_queue:UnboundedSender<Blk>,
        //tx_recv_stream:UnboundedReceiver<Vec<u8>>
    ){
        tokio::spawn(async move {
            Self{
                //batch:store,
                //tx_recv_stream:tx_recv_stream,
                tx_blk_queue:tx_blk_queue,
                batch_size:400,
                txn_size:50,
                rate: 30000
            }.run().await;
        });
    }

    pub async fn run(&mut self){
        // while let Some(batch) = self.tx_recv_stream.recv().await {
        //     self.batch.push(batch);
        //     if self.batch.len() == self.batch_size{
        //         let mut block = Blk::new();
        //         for tx in self.batch.iter(){
        //             block.push(tx.clone());
        //         }
        //         self.batch.clear();
        //         let _ = self.tx_blk_queue.send(block);
        //     }
        // }
        const PRECISION: u64 = 10; // Sample precision.
        const BURST_DURATION: u64 = 1000 / PRECISION;

        // The transaction size must be at least 16 bytes to ensure all txs are different.
        // if self.size < 9 {
        //     return Err(anyhow::Error::msg(
        //         "Transaction size must be at least 9 bytes",
        //     ));
        // }

        // Connect to the mempool.
        // let stream = TcpStream::connect(self.target)
        //     .await
        //     .context(format!("failed to connect to {}", self.target))?;

        // Submit all transactions.
        let burst = self.rate / PRECISION;
        let mut tx = BytesMut::with_capacity(self.txn_size.try_into().unwrap());
        let mut counter = 0;
        let mut r = rand::thread_rng().gen();
        //let mut transport = Framed::new(stream, LengthDelimitedCodec::new());
        let interval = interval(Duration::from_millis(BURST_DURATION));
        let start = tokio::time::interval(Duration::from_millis(1000));
        tokio::pin!(interval);
        tokio::pin!(start);
        
        // NOTE: This log entry is used to compute performance.
        log::info!("Start sending transactions");
        log::info!("Transactions size: {}",self.txn_size);
        log::info!("Transactions rate: {}",self.rate);
        // wait until nodes start
        start.as_mut().tick().await;
        loop {
            interval.as_mut().tick().await;
            let now = Instant::now();
            let mut batch = Vec::new();
            for x in 0..burst {
                if x == counter % burst {
                    // NOTE: This log entry is used to compute performance.
                    log::info!("Sending sample transaction {}", counter);

                    tx.put_u8(0u8); // Sample txs start with 0.
                    tx.put_u64(counter); // This counter identifies the tx.
                } else {
                    r += 1;
                    tx.put_u8(1u8); // Standard txs start with 1.
                    tx.put_u64(r); // Ensures all clients send different txs.
                };

                tx.resize(self.txn_size.try_into().unwrap(), 0u8);
                let bytes = tx.split().freeze().to_vec();
                batch.push(bytes);
                // if let Err(e) = transport.send(bytes).await {
                //     warn!("Failed to send transaction: {}", e);
                //     break 'main;
                // }
            }
            // Send value to the main thread
            let _ = self.tx_blk_queue.send(batch);
            if now.elapsed().as_millis() > BURST_DURATION as u128 {
                // NOTE: This log entry is used to compute performance.
                log::warn!("Transaction rate too high for this client");
            }
            counter += 1;
            if counter >= 100{
                break;
            }
        }
    }
}