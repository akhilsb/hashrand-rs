pub struct Parameters {
    /// The preferred header size. The primary creates a new header when it has enough parents and
    /// enough batches' digests to reach `header_size`. Denominated in bytes.
    pub header_size: usize,
    /// The maximum delay that the primary waits between generating two headers, even if the header
    /// did not reach `max_header_size`. Denominated in ms.
    pub max_header_delay: u64,
    /// The depth of the garbage collection (Denominated in number of rounds).
    pub gc_depth: u64,
    /// The delay after which the synchronizer retries to send sync requests. Denominated in ms.
    pub sync_retry_delay: u64,
    /// Determine with how many nodes to sync when re-trying to send sync-request. These nodes
    /// are picked at random from the committee.
    pub sync_retry_nodes: usize,
    /// The preferred batch size. The workers seal a batch of transactions when it reaches this size.
    /// Denominated in bytes.
    pub batch_size: usize,
    /// The delay after which the workers seal a batch of transactions, even if `max_batch_size`
    /// is not reached. Denominated in ms.
    pub max_batch_delay: u64,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            header_size: 1_000,
            max_header_delay: 100,
            gc_depth: 50,
            sync_retry_delay: 5_000,
            sync_retry_nodes: 3,
            batch_size: 500_000,
            max_batch_delay: 100,
        }
    }
}

impl Parameters {
    pub fn log(&self) {
        log::info!("Header size set to {} B", self.header_size);
        log::info!("Max header delay set to {} ms", self.max_header_delay);
        log::info!("Garbage collection depth set to {} rounds", self.gc_depth);
        log::info!("Sync retry delay set to {} ms", self.sync_retry_delay);
        log::info!("Sync retry nodes set to {} nodes", self.sync_retry_nodes);
        log::info!("Batch size set to {} B", self.batch_size);
        log::info!("Max batch delay set to {} ms", self.max_batch_delay);
    }
}