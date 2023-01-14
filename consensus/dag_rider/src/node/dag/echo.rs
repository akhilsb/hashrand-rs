use types::{hash_cc::{CTRBCMsg,DAGMsg}, Replica};

use crate::node::{Context, RBCRoundState};

impl Context{
    pub async fn process_echo(self: &mut Context, ctr:CTRBCMsg, echo_sender:Replica)-> Vec<DAGMsg>{
        let mut ret_vec = Vec::new();
        let rbc_origin = ctr.origin.clone();
        let round_state_map = &mut self.round_state;
        log::debug!("Received ECHO message from {} for RBC of node {} of round {}",echo_sender,rbc_origin,ctr.round);
        let round = ctr.round;
        if !ctr.verify_mr_proof(){
            return ret_vec;
        }
        if round_state_map.contains_key(&round){
            // 1. Add echos to the round state object
            let rnd_state = round_state_map.get_mut(&round).unwrap();
            // If RBC already terminated, do not consider this RBC
            if rnd_state.terminated_rbcs.contains(&rbc_origin){
                return ret_vec;
            }
            if !rnd_state.node_msgs.contains_key(&rbc_origin){
                rnd_state.add_echo(rbc_origin, echo_sender, &ctr);
                return ret_vec;    
            }
            if !rnd_state.check_merkle_root(&ctr){
                return ret_vec;
            }
            rnd_state.add_echo(rbc_origin, echo_sender, &ctr);
            //let echos = rnd_state.echos.get_mut(&rbc_origin).unwrap();
            // 2. Check if echos reached the threshold, init already received, and round number is matching
            match rnd_state.echo_check(rbc_origin,self.num_nodes,self.num_faults,self.myid){
                None =>{
                    return ret_vec;
                },
                Some(vec_x) =>{
                    let ctrbc = CTRBCMsg::new(vec_x.0, vec_x.1, round, rbc_origin);
                    ret_vec.push(DAGMsg::RBCREADY(ctrbc.clone(), self.myid));
                    ret_vec.append(&mut self.process_ready(ctrbc,self.myid).await);
                }
            }
        }
        else{
            //let mut rnd_state = create_roundstate(rbc_originator, &main_msg, self.myid);
            let mut rnd_state = RBCRoundState::new(&ctr);
            rnd_state.add_echo(rbc_origin, echo_sender, &ctr);
            round_state_map.insert(round, rnd_state);
            // Do not send echo yet, echo needs to come through from RBC_INIT
            //round_state_map.insert(main_msg.round, rnd_state);
        }
        ret_vec
    }
}