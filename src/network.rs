use bitcoincore_rpc::Client;
use std::collections::HashMap;

#[derive(Serialize)]
pub struct Network {
    name: String,
    network: String,
    rpc_url: String,
    rpc_user: Option<String>,
    rpc_pass: Option<String>,
    tx_explorer_url: String,
}

lazy_static! {
    static ref NETWORKS: HashMap<String, Network> = {
        let mut networks = HashMap::new();
        networks.insert(
            "regtest".to_string(),
            Network {
                name: "Regtest".to_string(),
                network: "regtest".to_string(),
                rpc_url: "http://127.0.0.1:18443".to_string(),
                rpc_user: Some("__cookie__".to_string()),
                rpc_pass: Some(
                    "bedb993c212435f1c73c76c0a609f4f3f0eaa18b80e46c304e2fe4e0a2eee5ac".to_string(),
                ),
                tx_explorer_url: "https://blockstream.info/tx/".to_string(),
            },
        );
        networks
    };
    static ref CLIENTS: HashMap<String, Client> = NETWORKS
        .iter()
        .map(|(ref name, ref net)| (name.to_string(), net.connect()))
        .collect();
}

impl Network {
    pub fn networks() -> &'static HashMap<String, Network> {
        &NETWORKS
    }

    pub fn network(id: &String) -> Option<&'static Network> {
        NETWORKS.get(id)
    }

    pub fn client(id: &String) -> Option<&'static Client> {
        CLIENTS.get(id)
    }

    pub fn connect(&self) -> Client {
        Client::new(
            self.rpc_url.clone(),
            self.rpc_user.clone(),
            self.rpc_pass.clone(),
        )
    }
}
