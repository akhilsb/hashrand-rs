# HashRand
This repository contains the codebase of HashRand - an asynchronous random beacon protocol without trusted setup and with post-quantum security. The following protocols have been implemented. 
<ol>
  <li>HashRand beacon protocol</li>
  <li>Dfinity-DVRF protocol using <code>blstrs</code> library</li>
  <li>Approximate Common Coin in Freitas et al. </li>
  <li>DAG-Rider with HashRand - a Post-Quantum Asynchronous SMR protocol</li>
</ol>
This repository is built on top of the <code>libnet-rs</code> ( https://github.com/libdist-rs/libnet-rs ) library and the <code>libchatter-rs</code>( https://github.com/libdist-rs/libchatter-rs ) library from the <code>libdist-rs</code> organization. This code has been written for a research prototype and has **not** been tested for use in production. Use at your own risk. 

# Running the code
HashRand can be run as a standalone application and can also be imported as a library to be included in other codebases.
To run as a standalone application, compile the program using Cargo and use the test script <code>appxcon-test.sh</code>.

To run on AWS, use the code in the <code>benchmark</code> folder. This code uses fabric to automate the process of spawning instances, installing rust, and installing this repository. This benchmarking code has been cloned from **narwhal** ( https://github.com/asonnino/narwhal )
