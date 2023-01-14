use std::{time::SystemTime};

use async_recursion::async_recursion;
use crypto::hash::{Hash,do_hash};
use merkle_light::merkle::MerkleTree;
use types::{appxcon::{get_shards, HashingAlg, MerkleProof}, hash_cc::{CTRBCMsg, CoinMsg, DAGMsg, SMRMsg, WrapperSMRMsg}};

use crate::node::{Context, RBCRoundState};

impl Context{
    #[async_recursion]
    pub async fn process_rbc_init(self: &mut Context, ctr:CTRBCMsg)-> Vec<DAGMsg>{
        let mut ret_vec = Vec::new();
        let now = SystemTime::now();
        let round_state_map = &mut self.round_state;
        // 1. Check if the protocol reached the round for this node
        log::debug!("Received RBC Init from node {} for round {}",ctr.origin,ctr.round);
        if !ctr.verify_mr_proof(){
            return ret_vec;
        }
        let round = ctr.round;
        if round_state_map.contains_key(&round){
            let rnd_state = round_state_map.get_mut(&round).unwrap();
            rnd_state.add_rbc_shard(&ctr);
            rnd_state.add_echo(ctr.origin, self.myid, &ctr);
            rnd_state.add_ready(ctr.origin, self.myid, &ctr);
        }
        // 1. If the protocol did not reach this round yet, create a new roundstate object
        else{
            let mut rnd_state = RBCRoundState::new(&ctr);
            rnd_state.add_rbc_shard(&ctr);
            rnd_state.add_echo(ctr.origin, self.myid, &ctr);
            rnd_state.add_ready(ctr.origin, self.myid, &ctr);
            round_state_map.insert(round, rnd_state);
        }
        log::trace!("Sending echos for RBC from origin {}",ctr.origin);
        ret_vec.push(DAGMsg::RBCECHO(ctr.clone(),self.myid));
        let mut ret_echo = self.process_echo(ctr, self.myid).await;
        ret_vec.append(&mut ret_echo);
        self.add_benchmark(String::from("process_rbc_init"), now.elapsed().unwrap().as_nanos());
        ret_vec
    }

    pub async fn start_rbc(self: &mut Context){
        // Locate round advancing logic in this function
        // start streaming only after first round
        if self.curr_round > 101{
            //log::info!("{:?}",self.dag_state.last_committed);
            return;
        }
        log::debug!("Starting round {} of DAG-Based RBC",self.curr_round);
        let wave_num = self.curr_round/4;
        let round_index = self.curr_round % 4;
        let num_secrets:u32 = self.batch_size.try_into().unwrap();
        // take client transactions here
        let data = self.dag_state.create_dag_vertex(self.curr_round).to_bytes();
        let shards = get_shards(data, self.num_faults);
        let _own_shard = shards[self.myid].clone();
        // Construct Merkle tree
        let hashes:Vec<Hash> = shards.clone().into_iter().map(|x| do_hash(x.as_slice())).collect();
        log::trace!("Vector of hashes during RBC Init {:?}",hashes);
        let merkle_tree:MerkleTree<[u8; 32],HashingAlg> = MerkleTree::from_iter(hashes.into_iter());
        // Some kind of message should be piggybacked here, but which message exactly is decided by the round number
        let mut coin_msgs = Vec::new();
        // TODO: reform logic
        if wave_num % num_secrets == 0{
            if round_index == 0{
                // Time to start sharing for next batch_size secrets
                // The entire first wave is needed to finish batch secret sharing + gather protocol
                coin_msgs.append(&mut self.start_batchwss().await);
            }
            else {
                if wave_num > num_secrets && round_index == 1{
                    let coin_invoke = self.send_batchreconstruct(wave_num.try_into().unwrap()).await;
                    for _i in 0..self.num_nodes{
                        coin_msgs.push(coin_invoke.clone())
                    }
                }
                else{
                    for _i in 0..self.num_nodes{
                        coin_msgs.push(CoinMsg::NoMessage());
                    }
                }
            }
        }
        else{
            // Add the case where we are running Binary Approximate Agreement here
            // In the first round of a wave, invoke the coin
            // In the second round of the wave, invoke secret sharing if available, if not, invoke binary common coin
            // In the third and fourth rounds of the wave, invoke binary approximate agreement protocol
            if round_index == 0{
                if wave_num >= self.batch_size.try_into().unwrap(){
                    let coin_invoke = self.send_batchreconstruct(wave_num.try_into().unwrap()).await;
                    for _i in 0..self.num_nodes{
                        coin_msgs.push(coin_invoke.clone())
                    }
                }
                else{
                    for _i in 0..self.num_nodes{
                        coin_msgs.push(CoinMsg::NoMessage());
                    }
                }
            }
            else{
                let baa_msg = self.start_baa(self.curr_round).await;
                match baa_msg {
                    None=>{
                        for _i in 0..self.num_nodes{
                            coin_msgs.push(CoinMsg::NoMessage());
                        }   
                    },
                    Some(coin_msg)=>{
                        for _i in 0..self.num_nodes{
                            coin_msgs.push(coin_msg.clone())
                        }
                    }
                }
            }
        }
        // Advance round here
        let ctrbc = CTRBCMsg{
            shard:shards[self.myid].clone(),
            mp:MerkleProof::from_proof(merkle_tree.gen_proof(self.myid)),
            origin:self.myid,
            round:self.curr_round,
        };
        let ret_vec_dag = self.process_rbc_init(ctrbc).await;
        for (replica,sec_key) in self.sec_key_map.clone().into_iter() {
            let mrp = MerkleProof::from_proof(merkle_tree.gen_proof(replica));
            let ctrbc = CTRBCMsg{
                shard:shards[replica].clone(),
                mp:mrp,
                origin:self.myid,
                round:self.curr_round,
            };
            if replica != self.myid{
                let smr_msg = SMRMsg::new(DAGMsg::RBCInit(ctrbc.clone()), coin_msgs[replica].clone(), self.myid);
                let wrapper_msg = WrapperSMRMsg::new(&smr_msg, self.myid, &sec_key);
                self.send(replica,wrapper_msg).await;
            }
        }
        for dag_msg in ret_vec_dag.into_iter(){
            let mut smr_msg = SMRMsg::new(dag_msg, coin_msgs[self.myid].clone(), self.myid);
            match coin_msgs[self.myid].clone(){
                CoinMsg::BatchWSSInit(wss_init, ctr)=>{
                    self.process_batchwss_init( wss_init, ctr, &mut smr_msg).await;
                },
                CoinMsg::BinaryAAEcho(vec_echo_vals, echo_sender, round)=>{
                    self.process_baa_echo( vec_echo_vals, echo_sender, round, &mut smr_msg).await;
                },
                CoinMsg::BatchSecretReconstruct(vec_shares, share_sender, coin_number)=>{
                    self.process_batchreconstruct( vec_shares, share_sender, coin_number, &mut smr_msg).await;
                },
                CoinMsg::NoMessage()=>{
                    self.broadcast(&mut smr_msg).await;
                }
                _ => {}
            }
        }
        self.clear_cancel_handlers();
        if wave_num>0 && wave_num <= self.batch_size.try_into().unwrap() && round_index == 0{
            let leader_id = usize::try_from(wave_num).unwrap();
            self.dag_state.commit_vertices(leader_id%self.num_nodes, self.num_nodes, self.num_faults, self.curr_round).await;
        }
    }
}