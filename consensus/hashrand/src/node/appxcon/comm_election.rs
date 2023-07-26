use crypto::hash::do_hash;
use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, RngCore};
use types::beacon::Replica;

use crate::node::HashRand;

impl HashRand{
    pub async fn elect_committee(&self, rng_string:Vec<u8>)->Vec<Replica>{
        let mut rng = ChaCha20Rng::from_seed(do_hash(rng_string.as_slice()));
        let mut all_nodes = Vec::new();
        for i in 0..self.num_nodes{
            all_nodes.push(i);
        }
        let mut committee:Vec<Replica> = Vec::new();
        let comm_size:usize = self.committee_size;
        for _i in 0..comm_size{
            let rand_num = usize::try_from(rng.next_u64()).unwrap();
            let node_in_comm = rand_num % all_nodes.len();
            log::debug!("{} {} {}",rand_num,all_nodes.len(),node_in_comm);
            committee.push(all_nodes.remove(node_in_comm.clone()).clone());
        }
        committee.sort();
        log::debug!("Committee elected: {:?}",committee);
        return committee;
    }
}