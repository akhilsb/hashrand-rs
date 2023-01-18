use std::{collections::{HashMap, HashSet, BTreeSet, VecDeque}};

use crypto::hash::Hash;
use linked_hash_set::LinkedHashSet;
use types::{hash_cc::DAGData, Replica, Round};

use crate::node::Blk;


type Dag = HashMap<Round,HashMap<Replica,(DAGData,Hash),nohash_hasher::BuildNoHashHasher<Replica>>,nohash_hasher::BuildNoHashHasher<Replica>>;

pub struct DAGState {
    myid:Replica,

    pub last_committed: LinkedHashSet<(Replica,Round)>,

    yet_to_be_committed: BTreeSet<Round>,

    wave_leaders: Vec<Option<Replica>>,

    pub last_committed_wave:u32,

    dag:Dag,

    buffer: Vec<(DAGData,Hash)>,

    //storage: Storage,

    pub client_batches: VecDeque<Blk>,
}

impl DAGState{

    pub fn new(path_to_db:String, myid: Replica)->Self{
        // Create the DB
        
        //let store = Storage::new(&path_to_db).unwrap();
        DAGState {
            myid: myid,
            last_committed: LinkedHashSet::default(),
            yet_to_be_committed: BTreeSet::default(),
            wave_leaders: Vec::new(),
            dag: HashMap::default(), 
            buffer: Vec::new(),
            last_committed_wave: 0,
            //storage: store,
            client_batches:VecDeque::new()
        }
    }

    pub async fn add_vertex(&mut self,data: Vec<u8>) -> (){
        let mut dag_vertex = DAGData::from_bytes(data);
        log::debug!("Adding Vertex {:?} to buffer", dag_vertex.clone());
        let round = dag_vertex.round;
        let digest = dag_vertex.digest();
        // Add data as vecu8 to the storage
        // DO NOT KEEP BLOCKS IN MEMORY!!
        for _txn in dag_vertex.data.clone().into_iter(){
            //self.storage.write(digest.clone().into(), txn).await;
        }
        // Are all the parents in the dag previously?
        // If not, trigger the check for every vertex in the buffer
        dag_vertex.data.clear();
        if self.parents_in_dag(&dag_vertex){
            self.yet_to_be_committed.insert(dag_vertex.round);
            //log::debug!("Adding DAG Vertex {:?} to DAG", dag_vertex.clone());
            if self.dag.contains_key(&dag_vertex.round){
                let round_map = self.dag.get_mut(&round).unwrap();
                round_map.insert(dag_vertex.origin,(dag_vertex,digest.clone()));
            }
            else{
                let mut round_map:HashMap<Replica, (DAGData,Hash),nohash_hasher::BuildNoHashHasher<Replica>> = HashMap::default();
                round_map.insert(dag_vertex.origin, (dag_vertex,digest.clone()));
                self.dag.insert(round,round_map);
            }
        }
        else{
            self.buffer.push((dag_vertex,digest.clone()));
        }
        // Clear buffer here
        self.clear_buffer();
        // Periodically trigger checks about whether a vertex in the buffer can be added to the dag
    }

    fn clear_buffer(&mut self){
        // Write to storage here!, so that we are able to clone easily
        //let vec_buffer = &mut self.buffer;
        let mut vertices_to_be_added_to_dag:HashSet<(usize, u32)> = HashSet::default();
        for (dag_data,digest) in self.buffer.iter(){
            if self.parents_in_dag(dag_data){
                if self.dag.contains_key(&dag_data.round){
                    let round_map = self.dag.get_mut(&dag_data.round).unwrap();
                    round_map.insert(dag_data.origin,(dag_data.clone(),digest.clone()));
                }
                else{
                    let mut round_map:HashMap<Replica, (DAGData,Hash),nohash_hasher::BuildNoHashHasher<Replica>> = HashMap::default();
                    round_map.insert(dag_data.origin, (dag_data.clone(),digest.clone()));
                    self.dag.insert(dag_data.round,round_map);
                }
                vertices_to_be_added_to_dag.insert((dag_data.origin,dag_data.round));
                self.yet_to_be_committed.insert(dag_data.round);
            }
        }
        self.buffer.retain(|(dag_data,_digest)| {
            !vertices_to_be_added_to_dag.contains(&(dag_data.origin,dag_data.round))
        });
    }

    fn parents_in_dag(&self, vertex:&DAGData)->bool{
        for (proposer, round, digest) in vertex.vertices.iter(){
            if self.dag.contains_key(round) && 
                self.dag.get(round).unwrap().contains_key(proposer) && 
                self.dag.get(round).unwrap().get(proposer).unwrap().1 == *digest
            {
            }
            else{
                return false
            }
        }
        true
    }

    fn does_path_exist(&self, source: &(Replica, Round, Hash), dest:&(Replica,Round,Hash)) -> usize{
        let mut visited = HashSet::new();
                // Create a stack to store the vertices that need to be visited.
        let mut stack = Vec::new();
    
        // Add the starting vertex to the stack and mark it as visited.
        stack.push(source.clone());
        visited.insert(source.clone());
    
        // Keep looping until the stack is empty.
        while !stack.is_empty() {
            // Get the next vertex from the stack.
            let vertex = stack.pop().unwrap();
    
            // Check if we have reached the end vertex.
            if vertex == *dest {
                return 1;
            }
    
            // Get the neighbors of the current vertex.
            let parents = &self.dag
                                        .get(&vertex.1)
                                        .expect("This round must have finished by now")
                                        .get(&vertex.0)
                                        .unwrap()
                                        .0.vertices;
            
            // Add the neighbors of the current vertex to the stack
            // and mark them as visited.
            for parent in parents {
                // Do not add to the stack if the round of the vertex is lesser than the leader's round
                if parent.1 < dest.1{
                    continue;
                }
                if !visited.contains(&parent) {
                    stack.push(parent.clone());
                    visited.insert(parent.clone());
                }
            }
        } 
        // If we reach here, it means that we have not found a path between the two
        // vertices, so we return false.
        0
    }

    pub async fn commit_vertices(&mut self,leader_id: Replica,num_nodes:usize,num_faults:usize,curr_round:Round){
        log::debug!("Committing vertices in dag using leader election");
        self.clear_buffer();
        let leader_validity = self.validate_leader(leader_id, num_nodes, num_faults,curr_round).await;
        // First, find out all past leaders that were uncommitted and waves that were undecided
        let wave;
        if curr_round % 2 == 0{
            wave = (curr_round-1)/4;
        }
        else{
            wave = (curr_round-2)/4;
        }
        log::debug!("Wave: {}, round {}",wave,curr_round);
        match leader_validity{
            None => {
                log::error!("No leader valid, pushing leader to later");
            },
            Some(leader)=>{
                // If the leader wasn't detected at that stage, then the option has None at that index
                let uncommitted_leaders = &self.wave_leaders;
                let mut stack_leaders = Vec::new();
                // Push the leader to the stack first
                stack_leaders.push(leader);
                if wave != 0{
                    for wave_id in (self.last_committed_wave..wave+1).rev(){
                        // check if the wave leader has a path to the current leader
                        if wave_id >= uncommitted_leaders.len().try_into().unwrap(){
                            // The protocol didn't reach here yet
                            continue;
                        }
                        let round = wave_id*4;
                        let wid_us:usize = wave_id.try_into().unwrap();
                        match uncommitted_leaders.get(wid_us).unwrap(){
                            None => {},
                            Some(leader_o)=>{
                                let leader_vertex = self.dag.get(&round).unwrap().get(leader_o).unwrap();
                                if self.does_path_exist(&leader,&(leader_vertex.0.origin,leader_vertex.0.round,leader_vertex.1)) ==1 {
                                    stack_leaders.push((leader_vertex.0.origin,leader_vertex.0.round,leader_vertex.1));
                                }
                            }
                        }
                    }   
                }
                // Pop through stack and check from beginning about which rounds have data and which do not
                // Check if there are rounds left to be committed
                if self.yet_to_be_committed.is_empty(){
                    log::error!("The DAG to be committed is empty, rectify error....");
                    return;
                }
                while !stack_leaders.is_empty() {
                    // Leader structure: Replica, Round of leader vertex, hash of leader vertex
                    let current_leader = stack_leaders.pop().unwrap();
                    let vec_iterator:Vec<u32> = self.yet_to_be_committed.clone().into_iter().filter(|x| *x< current_leader.1).collect();
                    for round_iter in vec_iterator.into_iter(){
                        let mut tree_set_wave = BTreeSet::default();
                        let round_vertices = self.dag.get(&round_iter).unwrap().clone();
                        let num_vertices_dag = round_vertices.len();
                        let sum_vertices:usize = round_vertices.iter()
                        .map(|(replica, (vertex,digest))|{
                            if !self.last_committed.contains(&(*replica,round_iter)) {
                                let path;
                                path = self.does_path_exist(&current_leader,&(*replica,round_iter,digest.clone()));
                                if path == 1{
                                    // Commit vertex here
                                    log::info!("Committed {} -> {:?}",*vertex,base64::encode(digest.clone()).get(0..16).unwrap());
                                    tree_set_wave.insert((*replica,round_iter));
                                    return 1;
                                }
                                else {
                                    //log::debug!("No path from vertex {:?} to leader {} in round {}, try again later",vertex.clone(),current_leader.0,current_leader.1);
                                    return 0;
                                }
                            }
                            else {
                                return 1;
                            }
                        })
                        .sum();
                        for (rep,round) in tree_set_wave.into_iter(){
                            self.last_committed.insert((rep,round));
                        }
                        if num_vertices_dag == sum_vertices {
                            // All vertices of this round have been committed, remove round from committed rounds list
                            self.yet_to_be_committed.remove(&round_iter);
                            // advance dag rounds
                            self.last_committed_wave = round_iter/4;
                            log::info!("Committed all vertices in round {}",round_iter);
                        }
                        // Eventually, all vertices in the DAG must appear in the last_committed data structure.
                    }
                }
            }
        }
    }

    async fn validate_leader(&mut self, leader: Replica, num_nodes:usize, num_faults:usize, curr_round:Round) -> Option<(Replica,Round,Hash)> {
        // Create a set to store the visited vertices.
        let wave;
        if curr_round % 2 == 0{
            wave = (curr_round-1)/4;
        }
        else{
            wave = (curr_round-2)/4;
        }
        let end_round = wave*4;
        let start_round = wave*4+3;
        let graph = &self.dag;
        let leader_vertex = graph.get(&end_round).unwrap().get(&leader);
        match leader_vertex{
            None=>{
                log::debug!("Leader's vertex not delivered yet, skip adding the leader at all!");
                return None;
            },
            Some(vertex) =>{
                let target_vertex = (vertex.0.origin,vertex.0.round,vertex.1);
                if !self.dag.contains_key(&start_round){
                    self.wave_leaders.push(Some(leader));
                    return None;
                }
                let wave_for_vertices:usize = self.dag
                    .get(&start_round)
                    .expect("This round should have finished by now")
                    .iter()
                    .map(|(rep,dag_data)| 
                        self.does_path_exist(&(*rep,dag_data.0.round,dag_data.1), &target_vertex)    
                    )
                    .sum();
                log::debug!("Wave for vertices: {}",wave_for_vertices);
                self.wave_leaders.push(Some(leader));
                if wave_for_vertices >= num_nodes-num_faults{
                    // If this is the case, this leader can be committed in this round
                    return Some(target_vertex);
                }
                None
            }
        }
    }

    pub fn create_dag_vertex(&mut self,curr_round:Round)-> DAGData{
        let round = curr_round;
        if round == 0{
            return self.genesis_vertex();
        }
        let round_vertices = self.dag.get(&(round-1)).unwrap();
        let mut edges = Vec::new();
        for (_rep,(vertex,digest)) in round_vertices.iter(){
            edges.push((vertex.origin,vertex.round,digest.clone()));
        }
        // Add weak edges too
        for round in self.yet_to_be_committed.iter(){
            for (rep,(vertex,digest)) in self.dag.get(round).unwrap().iter(){
                if self.last_committed.contains(&(vertex.origin,*round)){
                    continue;
                }
                let mut path_exists = false;
                for edge_vertex in edges.iter(){
                    if self.does_path_exist(edge_vertex,&(*rep,vertex.round,digest.clone())) == 1{
                        path_exists = true;
                        break;
                    }
                }
                if !path_exists{
                    edges.push((vertex.origin,vertex.round,digest.clone()));
                }
            }
        }
        let data = self.client_batches.pop_front();
        let dagvertex;
        match data{
            None=> {
                // empty batch
                dagvertex = DAGData::new(Vec::new(), edges, round, self.myid);
            },
            Some(blk)=>{
                dagvertex = DAGData::new(blk, edges, round, self.myid);
            }
        }
        log::info!("Created {} -> {:?}",dagvertex,base64::encode(dagvertex.digest()).get(0..16).unwrap());
        // pull data from storage
        return dagvertex;
    }

    fn genesis_vertex(&mut self)-> DAGData{
        let edges = Vec::new();
        let data = Vec::new();
        // pull data from storage
        return DAGData::new(data, edges, 0, self.myid);
    }

    pub fn new_round(&mut self,num_nodes:usize, num_faults:usize,curr_round:Round)->bool{
        let current_round = curr_round.clone();
        self.clear_buffer();
        return self.dag.contains_key(&current_round) && self.dag.get(&current_round).unwrap().len() >= num_nodes-num_faults;
    }
}