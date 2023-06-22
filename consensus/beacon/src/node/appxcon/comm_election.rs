use crypto::hash::do_hash;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use types::beacon::Replica;

use crate::node::Context;

impl Context{
    pub fn elect_committee(&self, rng_string:Vec<u8>)->Vec<Replica>{
        let rng = ChaCha20Rng::from_seed(do_hash(rng_string.as_slice()));
        let mut all_nodes = Vec::new();
        for i in 0..self.num_nodes{
            all_nodes.push(i);
        }
        let mut committee:Vec<Replica> = Vec::new();
        let comm_size:usize = 13;
        for _i in 0..comm_size{
            let node_in_comm = (usize::try_from(rng.get_stream()).unwrap()%(all_nodes.len()))-1;
            committee.push(all_nodes.remove(node_in_comm.clone()).clone());
        }
        return committee;
    }
}