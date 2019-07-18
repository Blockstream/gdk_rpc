use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

use bitcoincore_rpc::{Auth, Client};
use url::Url;

use crate::errors::{Error, OptionExt};

#[derive(Debug, Serialize)]
pub struct Network {
    name: String,
    network: String,

    rpc_url: String,
    rpc_cred: Option<(String, String)>, // (username, password)
    rpc_cookie: Option<String>,

    bech32_prefix: String,
    p2pkh_version: u32,
    p2sh_version: u32,

    pub development: bool,
    pub liquid: bool,
    pub mainnet: bool,

    tx_explorer_url: String,
    address_explorer_url: String,

    // unimplemented
    default_peers: Vec<String>,
    service_chain_code: String,
    service_pubkey: String,
    wamp_onion_url: String,
    wamp_url: String,
    wamp_cert_pins: Vec<String>,
    wamp_cert_roots: Vec<String>,
}

lazy_static! {
    static ref NETWORKS: HashMap<String, Network> = {
        let mut networks = HashMap::new();

        let rpc_url = env::var("BITCOIND_URL")
            .ok()
            .unwrap_or_else(|| "http://127.0.0.1:18443".to_string());

        let rpc_cookie = env::var("BITCOIND_DIR")
            .ok()
            .map(|p| Path::new(&p).join(".cookie").to_string_lossy().into_owned());

        networks.insert(
            "regtest-cookie".to_string(),
            Network {
                name: "Regtest".to_string(),
                network: "regtest".to_string(),
                rpc_url,
                rpc_cred: None,
                rpc_cookie: rpc_cookie,
                tx_explorer_url: "https://blockstream.info/tx/".to_string(),
                address_explorer_url: "https://blockstream.info/address/".to_string(),

                bech32_prefix: "bcrt".to_string(),
                p2pkh_version: 111,
                p2sh_version: 196,

                development: true, // TODO
                liquid: false,
                mainnet: false,

                default_peers: vec![],
                service_chain_code: "".to_string(),
                service_pubkey: "".to_string(),
                wamp_onion_url: "".to_string(),
                wamp_url: "".to_string(),
                wamp_cert_pins: vec![],
                wamp_cert_roots: vec![],
            },
        );

        networks.insert(
            "mainnet".to_string(),
            Network {
                name: "Regtest LAN".to_string(),
                network: "mainnet".to_string(),
                rpc_url: "http://192.168.2.108:18443".to_string(),
                rpc_cred: Some((
                    "satoshi".to_string(),
                    "02hMwUvA8iu9DFsboCB3JaE7Wc8Oix4XdBA2fjhYzy4=".to_string(),
                )),
                rpc_cookie: None,
                tx_explorer_url: "https://blockstream.info/tx/".to_string(),
                address_explorer_url: "https://blockstream.info/address/".to_string(),

                bech32_prefix: "tb".to_string(),
                p2pkh_version: 111,
                p2sh_version: 196,

                development: true, // TODO
                liquid: false,
                mainnet: false,

                default_peers: vec![],
                service_chain_code: "".to_string(),
                service_pubkey: "".to_string(),
                wamp_onion_url: "".to_string(),
                wamp_url: "".to_string(),
                wamp_cert_pins: vec![],
                wamp_cert_roots: vec![],
            },
        );

        networks
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkId {
    Liquid,
    Bitcoin(bitcoin::Network),
}

impl Network {
    pub fn list() -> &'static HashMap<String, Network> {
        &NETWORKS
    }

    pub fn get(id: &String) -> Option<&'static Network> {
        NETWORKS.get(id)
    }

    pub fn connect(&self, wallet: Option<String>) -> Result<Client, Error> {
        let cred = self
            .rpc_cred
            .clone()
            .or_else(|| {
                self.rpc_cookie
                    .as_ref()
                    .and_then(|path| read_cookie(path).ok())
            })
            .or_err("missing rpc credentials")?;

        let (rpc_user, rpc_pass) = cred;

        let mut rpc_url = Url::parse(&self.rpc_url)?;
        if let Some(wallet) = wallet {
            rpc_url = rpc_url.join(&format!("/wallet/{}", wallet))?;
        }

        Ok(Client::new(
            rpc_url.to_string(),
            Auth::UserPass(rpc_user, rpc_pass),
        )?)
    }

    pub fn id(&self) -> NetworkId {
        match (self.liquid, self.mainnet, self.development) {
            (true, _, _) => NetworkId::Liquid,
            (_, true, false) => NetworkId::Bitcoin(bitcoin::Network::Bitcoin),
            (_, false, true) => NetworkId::Bitcoin(bitcoin::Network::Regtest),
            (l, m, d) => panic!(
                "inconsistent network parameters: lq={}, main={}, dev={}",
                l, m, d
            ),
        }
    }
}

fn read_cookie(path: &String) -> Result<(String, String), Error> {
    let contents = fs::read_to_string(path)?;
    let parts: Vec<&str> = contents.split(":").collect();
    Ok((parts[0].to_string(), parts[1].to_string()))
}
