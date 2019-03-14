use std::fmt;

use failure::Error;
use serde_json::Value;
use bitcoincore_rpc::{Client as RpcClient, Error as CoreError};
use bip39::{Mnemonic, Language, Seed};
use bitcoin::{Network as BNetwork, PrivateKey};

pub struct Wallet {
    rpc: &'static RpcClient,

}

impl Wallet {
    pub fn new(rpc: &'static RpcClient) -> Self {
        Wallet { rpc }
    }

    // TODO -> Result
    // TODO password is only known at login
    pub fn register(&self, mnemonic: String, password: Option<String>) -> Result<(), Error> {
        let mnem = Mnemonic::from_phrase(&mnemonic[..], Language::English)?;
        let seed = Seed::new(&mnem, &password.unwrap_or("".to_string()));

        // TODO seed -> secret key conversion
        let skey = secp256k1::SecretKey::from_slice(&seed.as_bytes()[0..32]).unwrap();

        // TODO network
        let bkey = PrivateKey { compressed: false, network: BNetwork::Testnet, key: skey };
        let wif = bkey.to_wif();

        // XXX this operation is descrutive and would replace any prior seed stored in bitcoin core
        // TODO make sure the wallet is unused before doing this!
        let args = [ json!(true), json!(wif) ];
        let res: Result<Value, CoreError> = self.rpc.call("sethdseed", &args);

        match res {
            Ok(_) => Ok(()),
            // https://github.com/apoelstra/rust-jsonrpc/pull/16
            Err(CoreError::JsonRpc(jsonrpc::error::Error::NoErrorOrResult)) => Ok(()),
            Err(CoreError::JsonRpc(jsonrpc::error::Error::Rpc(rpc_error))) => {
                if rpc_error.code != -5 || rpc_error.message != "Already have this key (either as an HD seed or as a loose private key)" {
                    bail!("{:?}", rpc_error)
                }
                Ok(())
            },
            Err(err) => bail!(err)
        }
    }
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Wallet {{ }}")
    }
}
