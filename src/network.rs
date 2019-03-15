use bitcoincore_rpc::Client;
use dirs;
use failure::Error;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

#[derive(Serialize)]
pub struct Network {
    name: String,
    network: String,
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    tx_explorer_url: String,
}

lazy_static! {
    static ref NETWORKS: HashMap<String, Network> = {
        let mut networks = HashMap::new();

        let rpc_url = env::var("BITCOIND_URL")
            .ok()
            .unwrap_or_else(|| "http://127.0.0.1:18443".to_string());
        let (rpc_user, rpc_pass) = read_cookie().expect("failed reading cookie file");

        networks.insert(
            "regtest".to_string(),
            Network {
                name: "Regtest".to_string(),
                network: "regtest".to_string(),
                rpc_url,
                rpc_user,
                rpc_pass,
                tx_explorer_url: "https://blockstream.info/tx/".to_string(),
            },
        );
        networks
    };
}

impl Network {
    pub fn networks() -> &'static HashMap<String, Network> {
        &NETWORKS
    }

    pub fn network(id: &String) -> Option<&'static Network> {
        NETWORKS.get(id)
    }

    pub fn connect(&self) -> Client {
        Client::new(
            self.rpc_url.clone(),
            Some(self.rpc_user.clone()),
            Some(self.rpc_pass.clone()),
        )
    }
}

fn read_cookie() -> Result<(String, String), Error> {
    let path = env::var("BITCOIND_DIR").ok().map_or_else(
        || {
            dirs::home_dir()
                .unwrap()
                .join(".bitcoin")
                .join("regtest")
                .join(".cookie")
        },
        |p| Path::new(&p).join(".cookie"),
    );
    let contents = fs::read_to_string(path)?;
    let parts: Vec<&str> = contents.split(":").collect();
    Ok((parts[0].to_string(), parts[1].to_string()))
}
