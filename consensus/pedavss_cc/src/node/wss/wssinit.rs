use std::{collections::{HashMap}};

use crypto::hash::{do_hash, Hash};
use merkle_light::merkle::MerkleTree;
use bls12_381_plus::{Scalar, G1Projective};
use rand_core::{OsRng, RngCore};
use types::{appxcon::{HashingAlg, MerkleProof, get_shards, verify_merkle_proof}, hash_cc::{CoinMsg, WrapperMsg, CTRBCMsg}};
use vsss_rs::{Share, FeldmanVerifier, Feldman};

use crate::node::{Context};

pub const FAULTS:usize = 1;

impl Context{
    pub async fn start_wss(self: &mut Context){
        //let faults = self.num_faults;
        if self.num_faults != FAULTS{
            panic!("Invalid configuration, change fault number");
        }
        //let low_r = BigInt::from(0);
        //let prime = BigInt::parse_bytes(b"685373784908497",10).unwrap(); 
        //let mut rng = rand::thread_rng();
        // replace with pedersen VSS and its publicly verifiable information
        let mut key = [0u8;64];
        OsRng.try_fill_bytes(&mut key).unwrap();
        let secret = Scalar::from_bytes_wide(&key);
        let res =
            Feldman::<{FAULTS+1}, {3*FAULTS+1}>::split_secret::<Scalar, G1Projective, OsRng, 33>(secret, None, &mut OsRng);
        //assert!(res.is_ok());
        //let res = Pedersen::<{FAULTS+1}, {3*FAULTS+1}>::split_secret(secret, blinding, share_generator, blind_factor_generator, rng)
        let (shares, verifier) = res.unwrap();
        // for s in &shares {
        //     assert!(verifier.verify(s));
        // }
        let coded_verf= bincode::serialize(&verifier).expect("Failed to serialize verifier");
        let verf = bincode::deserialize::<FeldmanVerifier<Scalar,G1Projective,{FAULTS+1}>>(coded_verf.clone().as_slice()).unwrap();
        let share_ss = bincode::serialize(&shares[0]).unwrap();
        let des_share = bincode::deserialize::<Share<33>>(&share_ss);
        log::error!("Verified serialized shares");
        assert!(verf.verify(&des_share.unwrap()));
        let shards = get_shards(coded_verf.clone(), self.num_faults);
        //let own_shard = shards[self.myid].clone();
        
        // let shamir_ss = ShamirSecretSharing{
        //     threshold:faults+1,
        //     share_amount:3*faults+1,
        //     prime: prime.clone()
        // };

        //let secret_sampled = rand::thread_rng().gen_bigint_range(&low_r, &prime.clone());
        //let shares = shamir_ss.split(secret_sampled);
        log::debug!("Shares generated: {:?}",shares);
        let hashes:Vec<Hash> = shards.clone().into_iter().map(|x| do_hash(x.as_slice())).collect();
        // (Replica, Secret, Random Nonce, One-way commitment)
        // let share_comm_hash:Vec<(usize,Vec<u8>,Vec<u8>,Hash)> = 
        // shares.clone()
        // .into_iter()
        // .map(|x| {
        //     let rand = rand::thread_rng().gen_bigint_range(&low_r, &prime.clone());
        //     let added_secret = rand.clone()+x.1.clone();
        //     log::info!("Added_secret {:?} share eval {} secret share {}",added_secret.clone(),x.0,x.1.clone());
        //     let vec_comm = rand.to_bytes_be().1;
        //     let comm_secret = added_secret.to_bytes_be().1;
        //     (x.0,x.1.to_bytes_be().1,vec_comm.clone(),do_hash(comm_secret.as_slice()))
        // }).collect();
    
        //let hashes:Vec<Hash> = share_comm_hash.clone().into_iter().map(|x| x.3).collect();
        let merkle_tree:MerkleTree<Hash, HashingAlg> = MerkleTree::from_iter(hashes.into_iter());
        let mut replica = 0;
        for share in shares.into_iter(){
            let sec_key = self.sec_key_map.get(&replica).unwrap().clone();
            let mrp = MerkleProof::from_proof(merkle_tree.gen_proof(replica));
            //let wssmsg = WSSMsg::new(share, self.myid, verifier.clone(), mrp);
            let ser_share = bincode::serialize(&share).unwrap();
            let ctrbc_msg = CTRBCMsg{
                round:0,
                origin: self.myid,
                shard: shards[replica].clone(),
                mp: mrp,
            };
            if replica != self.myid{
                let wss_init = CoinMsg::PedAVSSInit(ser_share,coded_verf.clone(),ctrbc_msg);
                let wrapper_msg = WrapperMsg::new(wss_init, self.myid, &sec_key);
                self.send(replica,  wrapper_msg).await;
            }
            else {
                self.process_wss_init(ser_share,coded_verf.clone(),ctrbc_msg).await;
            }
            replica+=1;
        }
    }
    
    pub async fn process_wss_init(self: &mut Context,share:Vec<u8> ,verifier:Vec<u8>,ctr:CTRBCMsg) {
        let sec_share = bincode::deserialize::<Share<33>>(&share).unwrap();
        let verf_verifier = bincode::deserialize::<FeldmanVerifier<Scalar, G1Projective, {FAULTS+1}>>(verifier.as_slice()).unwrap();
        if !verf_verifier.verify(&sec_share){
            log::error!("Invalid share published, aborting AVSS");
            return;
        }
        //log::info!("Added_secret {:?}",comm.clone());
        let shard = ctr.shard.clone();
        let mp = ctr.mp.clone();
        let sender = ctr.origin.clone();
        let round_state = &mut self.aggr_context;
        
        // 1. Check if the protocol reached the round for this node
        log::info!("Received AVSS Init from node {} for round {}",sender,ctr.round);
        if !verify_merkle_proof(&mp, &shard){
            log::error!("Failed to evaluate merkle proof for RBC Init received from node {}",sender);
            return;
        }
        round_state.node_msgs.insert(sender, (shard.clone(),mp.clone(),mp.root().clone()));
        // 2. Send echos to every other node
        // 3. Add your own vote to the map
        match round_state.echos.get_mut(&sender)  {
            None => {
                let mut hash_map = HashMap::default();
                hash_map.insert(self.myid, (shard.clone(),mp.clone()));
                round_state.echos.insert(sender, hash_map);
            },
            Some(x) => {
                x.insert(self.myid,(shard.clone(),mp.clone()));
            },
        }
        match round_state.readys.get_mut(&sender)  {
            None => {
                let mut hash_map = HashMap::default();
                hash_map.insert(self.myid,(shard.clone(),mp.clone()));
                round_state.readys.insert(sender, hash_map);
            },
            Some(x) => {
                x.insert(self.myid,(shard.clone(),mp.clone()));
            },
        }
        self.vss_state.insert(ctr.origin,(share,verifier));
        self.broadcast(CoinMsg::PedAVSSEcho(ctr.clone() ,self.myid)).await;
        self.process_wssecho(ctr, self.myid).await;
    }
}