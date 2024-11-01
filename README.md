# Random Beacons in Monte-Carlo: Asynchronous Random Beacon using Hash functions
**On Zenodo**: We organize this artifact into two parts: HashRand asynchronous protocol into `hashrand-rs.zip` and the Post-Quantum Asynchronous SMR protocol into `pqsmr-rs.zip`.

**On Github**: This Github repository and the `hashrand-rs.zip` file on Zenodo contains a Rust implementation of the following distributed protocols. 

1. HashRand beacon protocol
2. Dfinity-DVRF protocol using `blstrs` library
3. DAG-Rider with HashRand - an asynchronous State Machine Replication (SMR) protocol with Post-Quantum security.

The repository uses the libchatter networking library available [here](https://github.com/libdist-rs/libchatter-rs). This code has been written as a research prototype and has not been vetted for security. Therefore, this repository can contain serious security vulnerabilities. Please use at your own risk. 

Please consider citing our paper if you use this artifact. 
```
@misc{bandarupalli2023hashrand,
      author = {Akhil Bandarupalli and Adithya Bhat and Saurabh Bagchi and Aniket Kate and Michael Reiter},
      title = {HashRand: Efficient Asynchronous Random Beacon without Threshold Cryptographic Setup},
      howpublished = {ACM CCS 2024},
      year = {2023},
      note = {\url{https://eprint.iacr.org/2023/1755}},
      url = {https://eprint.iacr.org/2023/1755}
}
```

# Quick Start
We describe the steps to run this artifact. 

## Hardware and OS setup
1. This artifact has been run and tested on `x86_64` and `x64` architectures. However, we are unaware of any issues that would prevent this artifact from running on `x86` architectures. 

2. This artifact has been run and tested on Ubuntu `20.04.5 LTS` OS and Raspbian Linux version released on `2023-02-21`, both of which follow the Debian distro. However, we are unaware of any issues that would prevent this artifact from running on Fedora distros like CentOS and Red Hat Linux. 

## Rust installation and Cargo setup
The repository uses the `Cargo` build tool. The compatibility between dependencies has been tested for Rust version `1.63`.

3. Run the set of following commands to install the toolchain required to compile code written in Rust and create binary executable files. 
```
$ sudo apt-get update
$ sudo apt-get -y upgrade
$ sudo apt-get -y autoremove
$ sudo apt-get -y install build-essential
$ sudo apt-get -y install cmake
$ sudo apt-get -y install curl
# Install rust (non-interactive)
$ curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
$ source $HOME/.cargo/env
$ rustup install 1.63.0
$ rustup override set 1.63.0
```
4. Build the repository using the following command. The command should be run in the directory containing the `Cargo.toml` file. 
```
$ cargo build --release
$ mkdir logs
```
If the build fails because of lack of `lgmp` files, install the `libgmp3-dev` dependency using the following command and try again.
```
sudo apt-get install libgmp3-dev
```

5. Next, generate configuration files for nodes in the system using the following command. Make sure to create the directory (in this example, `testdata/cc_16/`) before running this command. 
```
$ ./target/release/genconfig --base_port 8500 --client_base_port 7000 --client_run_port 9000 --NumNodes 16 --blocksize 100 --delay 100 --target testdata/cc_16/ --local true
```

6. After generating the configuration files, run the script `beacon-test.sh` in the scripts folder with the following command line arguments. This command starts HashRand with `16` nodes. 
```
$ ./scripts/beacon-test.sh testdata/cc_16/syncer {protocol} {batchsize} {frequency}
```
Substitute `{protocol}` with term `bea` to start HashRand. The `{batchsize}` and `{frequency}` parameters correspond to the $\beta$ and $\phi$ parameters in the protocol. For example, setting $\beta=20$ and $\phi=10$ implies a batch of 20 beacons being produced every 10 rounds. 

7. Substitute desired values of `{batchsize},{frequency}`. Example values include $\beta=20,\phi=10$. 

8. The outputs are logged into the `syncer.log` file in logs directory. The protocol runs for 90 seconds. After termination, the program can give an error about missed message delivery because other processes might have already shut down. Check the `syncer.log` file anyway.

This execution measures the throughput of the protocol from 30 seconds to 90 seconds, and gives the total throughput per minute. After running the script, check the `syncer.log` file after 90 seconds to see the throughput. 

9. Running the Dfinity DVRF protocol requires additional configuration. Dfinity uses BLS threshold signatures to generate common coins necessary for beacon generation. This setup includes a master public key in the `pub` file, $n$ partial secret keys (one for each node) as `sec0,...,sec3` files, and the $n$ partial public keys as `pub0,...,pub3` files. We utilized the `crypto_blstrs` library in the [apss](https://github.com/ISTA-SPiDerS/apss) repository to generate these keys. These files are already placed in the `testdata/cc_16` directory for testing and evaluation purposes. Further, we pregenerated these files for $n=16,40,64,136$ in the benchmark folder, in zip files `tkeys-{n}.tar.gz`. After generating these files, place them in the configuration directory (`testdata/cc_16` in this example) and run the following command (We already performed this step and have these files ready in `testdata/cc_16` folder). 
```
# Kill previous processes running on these ports
$ sudo lsof -ti:7000-7015,8500-8515,9000-9015,5000 | xargs kill -9
$ ./scripts/beacon-test.sh testdata/cc_16/syncer glow 20 10
```

## Running in AWS
We utilize the code in the [Narwhal](https://github.com/MystenLabs/sui/tree/main/narwhal/benchmark) repository to execute code in AWS. This repository uses `fabric` to spawn AWS instances, install Rust, and build the repository on individual machines. Please refer to the `benchmark` directory in this Github repository or the `hashrand-rs.zip` file in the Zenodo artifact for more instructions about reproducing the results in the paper. 

# System architecture
Each node runs as an independent process, which communicates with other nodes through sockets. Apart from the $n$ nodes running the protocol, the system also spawns a process called `syncer`. The `syncer` is responsible for measuring latency of completion. It reliably measures the system's latency by issuing `START` and `STOP` commands to all nodes. The nodes begin executing the protocol only after the `syncer` verifies that all nodes are online, and issues the `START` command by sending a message to all nodes. Further, the nodes send a `TERMINATED` message to the `syncer` once they terminate the protocol. The `syncer` records both start and termination times of all processes, which allows it to accurately measure the latency of each protocol. 

# Dependencies
The artifact uses multiple Rust libraries for various functionalities. We give a list of all dependencies used by the artifact in the `Cargo.lock` file. `Cargo` automatically manages these dependencies and fetches the specified versions from the `crates.io` repository manager. 

# Code Organization
The artifact's `hashrand-rs.zip` file is organized into the following modules of code. 
1. The `config` directory contains code pertaining to configuring each node in the distributed system. Each node requires information about port to use, network addresses of other nodes, symmetric keys to establish pairwise authenticated channels between nodes, and protocol specific configuration parameters like values of $\epsilon,\Delta,\rho$. Code related to managing and parsing these parameters is in the `config` directory. This library has been borrowed from the `libchatter` (https://github.com/libdist-rs/libchatter-rs) repository. 

2. The `crypto` directory contains code that manages the pairwise authenticated channels between nodes. Mainly, nodes use Message Authentication Codes (MACs) for message authentication. This repo manages the required secret keys and mechanisms for generating MACs. This library has been borrowed from the `libchatter` (https://github.com/libdist-rs/libchatter-rs) repository. 

3. The `crypto_blstrs` directory contains code that enables nodes to toss common coins from BLS threshold signatures. This library has been borrowed from the `apss` (https://github.com/ISTA-SPiDerS/apss) repository. 

4. The `types` directory governs the message serialization and deserialization. Each message sent between nodes is serialized into bytecode to be sent over the network. Upon receiving a message, each node deserializes the received bytecode into the required message type after receiving. This library has been written on top of the library from `libchatter` (https://github.com/libdist-rs/libchatter-rs) repository. 

5. *Networking*: This repository uses the `libnet-rs` (https://github.com/libdist-rs/libnet-rs) networking library. Similar libraries include networking library from the `narwhal` (https://github.com/MystenLabs/sui/tree/main/narwhal/) repository. The nodes use the `tcp` protocol to send messages to each other. 

6. The `tools` directory consists of code that generates configuration files for nodes. This library has been borrowed from the `libchatter` (https://github.com/libdist-rs/libchatter-rs) repository. 

7. The `consensus` directory contains the implementations of various protocols. Primarily, it contains implementations of the HashRand random beacon protocol in the `beacon` subdirectory, DFinity-DVRF protocol in the `glow_dvrf` subdirectory, and the DAG-Rider SMR protocol in `dag_rider` subdirectory. Further, the library versions of HashRand and Dfinity are in `hashrand` and `glow_lib` directories. These libraries can be imported and used as external dependencies to generate distributed randomness. Each protocol contains a `context.rs` file, which contains a function named `spawn` from where the protocol's execution starts. This function is called by the `node` library in the `node` folder. This library contains a `main.rs` file, which spawns an instance of a node running the respective protocol by invoking the `spawn` function. 

# Post Quantum Asynchronous SMR
The `pqsmr-rs.zip` file implements a post-quantum secure asynchronous SMR protocol on top of Tusk. This protocol uses lattice-based <code>dilithium</code> signatures in place of <code>EdDSA</code> signatures used by Tusk. This protocol also uses <code>HashRand</code> ( https://github.com/akhilsb/hashrand-rs ) as a post-quantum secure random beacon protocol to achieve liveness in asynchrony. Please note that this repository is a research prototype that has **not** been rigorously tested for software bugs. Please use at your own risk. 

This repository has been cloned from [Narwhal](https://github.com/asonnino/narwhal).

This repo provides an implementation of PQ-Tusk. The codebase has been designed to be small, efficient, and easy to benchmark and modify. It has not been designed to run in production but uses real pq-cryptography ([dilithium](https://github.com/akhilsb/pqcrypto)), networking ([tokio](https://docs.rs/tokio)), and storage ([rocksdb](https://docs.rs/rocksdb)).

## Quick Start
The core protocols are written in Rust, but all benchmarking scripts are written in Python and run with [Fabric](http://www.fabfile.org/).
To deploy and benchmark a testbed of 4 nodes on your local machine, clone the repo and install the python dependencies:
```
$ git clone https://github.com/akhilsb/pqsmr-rs.git
$ cd pqsmr-rs/benchmark
$ pip install -r requirements.txt
```
You also need to install Clang (required by rocksdb) and [tmux](https://linuxize.com/post/getting-started-with-tmux/#installing-tmux) (which runs all nodes and clients in the background). 

## Configuring HashRand
HashRand requires configuration files of the form `nodes-{i}.json` and `ip_file` for configuring secure channels among nodes. A set of these configuration files are in the `benchmark/hashrand-config` directory for values $n=4,16,40,64$. Extract these files into the `benchmark` directory.  

Finally, run a local benchmark using fabric:
```
$ fab local
```
This command may take a long time the first time you run it (compiling rust code in `release` mode may be slow) and you can customize a number of benchmark parameters in `fabfile.py`. When the benchmark terminates, it displays a summary of the execution similarly to the one below.
```
-----------------------------------------
 SUMMARY:
-----------------------------------------
 + CONFIG:
 Faults: 0 node(s)
 Committee size: 4 node(s)
 Worker(s) per node: 1 worker(s)
 Collocate primary and workers: True
 Input rate: 50,000 tx/s
 Transaction size: 512 B
 Execution time: 19 s

 Header size: 1,000 B
 Max header delay: 100 ms
 GC depth: 50 round(s)
 Sync retry delay: 10,000 ms
 Sync retry nodes: 3 node(s)
 batch size: 500,000 B
 Max batch delay: 100 ms

 + RESULTS:
 Consensus TPS: 46,478 tx/s
 Consensus BPS: 23,796,531 B/s
 Consensus latency: 464 ms

 End-to-end TPS: 46,149 tx/s
 End-to-end BPS: 23,628,541 B/s
 End-to-end latency: 557 ms
-----------------------------------------
```

## Next Steps
The README file of the [benchmark folder](https://github.com/akhilsb/pqsmr-rs/tree/master/benchmark) in the `pqsmr-rs.zip` file explains how to benchmark the codebase and read benchmarks' results. It also provides a step-by-step tutorial to run benchmarks on [Amazon Web Services (AWS)](https://aws.amazon.com) accross multiple data centers (WAN).

## Running in AWS
We utilize the code in the [Narwhal](https://github.com/MystenLabs/sui/tree/main/narwhal/benchmark) repository to execute code in AWS. This repository uses `fabric` to spawn AWS instances, install Rust, and build the repository on individual machines. Please refer to the `benchmark` directory in this Github repository or the `pqsmr-rs.zip` file in the Zenodo artifact for more instructions about reproducing the results in the paper. 
