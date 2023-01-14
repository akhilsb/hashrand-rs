use anyhow::{Result,anyhow};
use clap::{
    load_yaml, 
    App
};
use config::Node;
use signal_hook::{iterator::Signals, consts::{SIGINT, SIGTERM}};
use std::{net::{SocketAddr, SocketAddrV4}};

#[tokio::main]
async fn main() -> Result<()> {
    let yaml = load_yaml!("cli.yml");
    let m = App::from_yaml(yaml).get_matches();

    let conf_str = m.value_of("config")
        .expect("unable to convert config file into a string");
    let conf_file = std::path::Path::new(conf_str);
    let str = String::from(conf_str);
    let mut config = match conf_file
        .extension()
        .expect("Unable to get file extension")
        .to_str()
        .expect("Failed to convert the extension into ascii string") 
    {
        "json" => Node::from_json(str),
        "dat" => Node::from_bin(str),
        "toml" => Node::from_toml(str),
        "yaml" => Node::from_yaml(str),
        _ => panic!("Invalid config file extension"),
    };

    simple_logger::SimpleLogger::new().with_utc_timestamps().init().unwrap();
    // match m.occurrences_of("debug") {
    //     0 => log::set_max_level(log::LevelFilter::Info),
    //     1 => log::set_max_level(log::LevelFilter::Debug),
    //     2 | _ => log::set_max_level(log::LevelFilter::Trace),
    // }
    log::set_max_level(log::LevelFilter::Info);
    config
        .validate()
        .expect("The decoded config is not valid");
    if let Some(f) = m.value_of("ip") {
        let f_str = f.to_string();
        log::info!("Logging the file f {}",f_str);
        config.update_config(util::io::file_to_ips(f.to_string()));
    }
    let config = config;
    // Start the Reliable Broadcast protocol
    let exit_tx = dag_rider::node::Context::spawn(config).unwrap();
    // Implement a waiting strategy
    let mut signals = Signals::new(&[SIGINT, SIGTERM])?;
    signals.forever().next();
    log::error!("Received termination signal");
    exit_tx
        .send(())
        .map_err(|_| anyhow!("Server already shut down"))?;
    log::error!("Shutting down server");
    Ok(())
}

pub fn to_socket_address(
    ip_str: &str,
    port: u16,
) -> SocketAddr {
    let addr = SocketAddrV4::new(ip_str.parse().unwrap(), port);
    addr.into()
}