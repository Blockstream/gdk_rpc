use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoincore_rpc::{Client as RpcClient, RpcApi};
use elements::Transaction;
use serde_json::Value;

use crate::errors::Error;
use crate::util;

pub fn tx_props(raw_tx: &[u8]) -> Result<Value, Error> {
    let tx: Transaction = deserialize(&raw_tx)?;
    let weight = tx.get_weight();
    let vsize = (weight as f32 / 4.0) as u32;

    Ok(json!({
        "transaction_version": tx.version,
        "transaction_locktime": tx.lock_time,
        "transaction_size": raw_tx.len(),
        "transaction_vsize": vsize,
        "transaction_weight": weight,
    }))
}

pub fn create_transaction(rpc: &RpcClient, details: &Value) -> Result<Vec<u8>, Error> {
    let outs = util::parse_outs(&details)?;
    if outs.is_empty() {
        return Err(Error::NoRecipients);
    }

    let tx = rpc.create_raw_transaction(&[], &outs, None, None)?;
    Ok(serialize(&tx))
}

pub fn sign_transaction(_: &RpcClient, _: &Value, _: &str) -> Result<Vec<u8>, Error> {
    Ok(Vec::new())
}
