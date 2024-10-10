use std::{collections::HashMap};

use crypto::{hash::{Hash, do_hash}, aes_hash::{MerkleTree, HashState, Proof}};
use reed_solomon_erasure::{galois_8::ReedSolomon, Error};
use crate::appxcon::{Replica};

pub fn get_shards(data:Vec<u8>,faults:Replica)->Vec<Vec<u8>>{
    let r:ReedSolomon<> = ReedSolomon::new(faults+1,2*faults).unwrap();
    let mut vec_vecs = Vec::new();
    let size_of_vec = (data.len()/(faults+1))+1;
    for b in 0..faults+1{
        let mut indi_vec:Vec<u8> = Vec::new();
        for x in 0..size_of_vec{
            if b*size_of_vec+x >= data.len(){
                indi_vec.push(0);
            }
            else {
                indi_vec.push(data[b*size_of_vec+x]);
            }
        }
        vec_vecs.push(indi_vec);
    }
    for _b in 0..2*faults{
        let mut parity_vec = Vec::new();
        for _x in 0..size_of_vec{
            parity_vec.push(0);
        }
        vec_vecs.push(parity_vec);
    }
    r.encode(&mut vec_vecs).unwrap();
    log::trace!("Vec_vecs for Erasure codes: {:?}",vec_vecs);
    // let mut vec_recon = Vec::new();
    // let mut vec_recon_2 = Vec::new();
    
    // for _i in 0..3*faults+1{
    //     vec_recon.push(None);
    //     vec_recon_2.push(None);
    // }

    // for i in 1..faults+2{
    //     vec_recon[i] = Some(vec_vecs[i].clone());
    //     vec_recon_2[i] = Some(vec_vecs[i].clone());
    // }
    // match r.reconstruct(&mut vec_recon){
    //     Err(error)=> {
    //         log::error!("Erasure reconstruction failed because of {:?}",error);
    //     },
    //     _ => {
    //         log::trace!("Reconstruct shards: {:?}",vec_recon);
    //     }
    // }
    // match r.reconstruct_data(&mut vec_recon_2){
    //     Err(error)=> {
    //         log::error!("Erasure reconstruction failed because of {:?}",error);
    //     },
    //     _=> {
    //         log::trace!("Reconstruct data: {:?}",vec_recon_2);
    //     }
    // }
    vec_vecs
}

// The shards are reconstructed inline with the variable data
fn reconstruct_shards(num_faults:usize, data:&mut Vec<Option<Vec<u8>>>) -> Result<(),Error>{
    let reed_solomon:ReedSolomon<> = ReedSolomon::new(num_faults+1,2*num_faults).unwrap();
    if let Err(error) = reed_solomon.reconstruct(data) {
        return Err(error)
    } else {
        return Ok(());
    };
}

fn reconstruct_data(num_faults:usize, data:&mut Vec<Option<Vec<u8>>>) -> Result<(),Error>{
    let reed_solomon:ReedSolomon<> = ReedSolomon::new(num_faults+1,2*num_faults).unwrap();
    if let Err(error) = reed_solomon.reconstruct_data(data) {
        return Err(error)
    } else {
        return Ok(());
    };
}

pub fn reconstruct_and_verify(map:HashMap<Replica,(Vec<u8>,Proof)>,num_nodes:usize,num_faults:usize,myid:Replica, mr:Hash,hf:&HashState)->Result<(Vec<u8>,Proof),Error>{
    let mut shard_vector = Vec::new();
    for i in 0..num_nodes{
        match map.get(&i) {
            None => shard_vector.push(None),
            Some((shard,_mp)) => shard_vector.push(Some(shard.clone()))
        }
    }
    match reconstruct_shards(num_faults, &mut shard_vector){
        Err(error)=> {
            log::error!("Erasure reconstruction failed because of {:?}",error);
            return Err(error);
        },
        _=> {}
    }
    let hashes:Vec<Hash> = shard_vector.clone().into_iter().map(|x| do_hash(x.unwrap().as_slice())).collect();
    let merkle_tree = MerkleTree::new(hashes,hf);
    if merkle_tree.root() == mr{
        return Ok(
            (shard_vector[myid].clone().unwrap(),
            merkle_tree.gen_proof(myid))
        );
    }
    else{
        log::error!("Merkle Root verification failed because {:?} != {:?}",merkle_tree.root(),mr);
        return Err(Error::TooFewDataShards);
    }
}

// The function receives a map of replicas and their shards in the 
pub fn reconstruct_and_return(map:&HashMap<Replica,Vec<u8>>,num_nodes:usize,num_faults:usize)->Result<Vec<u8>,Error>{
    let mut shard_vector = Vec::new();
    for i in 0..num_nodes{
        match map.get(&i) {
            None => shard_vector.push(None),
            Some(shard) => shard_vector.push(Some(shard.clone()))
        }
    }
    log::trace!("Vector before reconstruction {:?}",shard_vector.clone());
    match reconstruct_data(num_faults, &mut shard_vector){
        Err(error)=> {
            log::error!("Erasure reconstruction failed because of {:?}",error);
            return Err(error);
        },
        _=> {}
    }
    log::trace!("Vector after reconstruction {:?}",shard_vector.clone());
    let mut vec_f = Vec::new();
    for i in 0..num_faults+1{
        for byte in shard_vector[i].clone().unwrap(){
            vec_f.push(byte);
        }
    }
    Ok(vec_f)
}