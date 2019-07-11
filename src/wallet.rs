use hex;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::{cell, fmt};

use bip39::{Language, Mnemonic, MnemonicType, Seed};
use bitcoin::{consensus::serialize, util::bip32, Address, Network as BNetwork, Transaction};
use bitcoin_hashes::hex::{FromHex, ToHex};
use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoincore_rpc::bitcoincore_rpc_json::EstimateSmartFeeResult;
use bitcoincore_rpc::{Client as RpcClient, Error as CoreError, RpcApi};
use failure::Error;
use serde_json::Value;

use crate::constants::{SAT_PER_BIT, SAT_PER_BTC, SAT_PER_MBTC};
use crate::errors::OptionExt;
use crate::network::Network;
use crate::util::{btc_to_isat, btc_to_usat, extend, f64_from_val, fmt_time, usat_to_fbtc, SECP};

const PER_PAGE: u32 = 30;
const FEE_ESTIMATES_TTL: Duration = Duration::from_secs(240);

pub struct Wallet {
    network: &'static Network,
    rpc: RpcClient,
    mnemonic: Option<String>,
    xpriv: Option<bip32::ExtendedPrivKey>,
    base_derivation_path: bip32::DerivationPath,
    next_address_child: cell::Cell<bip32::ChildNumber>,
    tip: Option<Sha256dHash>,
    last_tx: Option<Sha256dHash>,
    cached_fees: (Value, Instant),
}

impl Wallet {
    pub fn new(network: &'static Network) -> Result<Self, Error> {
        let rpc = network.connect()?;
        Ok(Wallet {
            network,
            rpc,
            mnemonic: None,
            xpriv: None,
            //TODO(stevenroose) coin type, this is bitcoin mainnet only
            base_derivation_path: "m/44'/0'/0'/0'".parse().unwrap(),
            next_address_child: cell::Cell::new(bip32::ChildNumber::from_normal_idx(0).unwrap()),
            tip: None,
            last_tx: None,
            cached_fees: (Value::Null, Instant::now() - FEE_ESTIMATES_TTL * 2),
        })
    }

    pub fn register(&mut self, mnemonic: &str) -> Result<(), Error> {
        let mnem = Mnemonic::from_phrase(&mnemonic[..], Language::English)?;
        let seed = Seed::new(&mnem, "");
        //TODO(stevenroose) network
        let xpriv = bip32::ExtendedPrivKey::new_master(BNetwork::Regtest, seed.as_bytes())?;

        self.mnemonic = Some(mnemonic.to_owned());
        self.xpriv = Some(xpriv);
        Ok(())
    }

    pub fn login(&mut self, mnemonic: &str) -> Result<(), Error> {
        // just as pass-through to register for now
        self.register(mnemonic)
    }

    pub fn mnemonic(&self) -> Option<String> {
        self.mnemonic.clone()
    }

    pub fn updates(&mut self) -> Result<Vec<Value>, Error> {
        let mut msgs = vec![];

        // check for new blocks
        let tip = self.rpc.get_best_block_hash()?;
        if self.tip != Some(tip) {
            let info = self.rpc.get_block_info(&tip)?;
            msgs.push(json!({ "event": "block", "block": { "block_height": info.height, "block_hash": tip.to_hex() } }));
            self.tip = Some(tip);
        }

        // check for new transactions
        // XXX does the app care about the transaction data in the event?
        if let Some(last_tx) = self._get_transactions(1, 0)?.0.get(0) {
            let txid = last_tx["txhash"].as_str().req()?;
            let txid = Sha256dHash::from_hex(txid)?;
            if self.last_tx != Some(txid) {
                self.last_tx = Some(txid);
                msgs.push(json!({ "event": "transaction", "transaction": last_tx }));
            }
        }

        // update fees once every FEE_ESTIMATES_TTL
        if self.cached_fees.1.elapsed() >= FEE_ESTIMATES_TTL {
            self.cached_fees = (self._make_fee_estimates()?, Instant::now());
            msgs.push(json!({ "event": "fees", "fees": self.cached_fees.0 }));
        }

        // TODO:
        // {"event":"subaccount","subaccount":{"bits":"701144.66","btc":"0.70114466","fiat":"0.7712591260000000622741556099981585311432","fiat_currency":"EUR","fiat_rate":"1.10000000000000008881784197001252","has_transactions":true,"mbtc":"701.14466","name":"","pointer":0,"receiving_id":"GA3MQKVp6pP7royXDuZcw55F2TXTgg","recovery_chain_code":"","recovery_pub_key":"","satoshi":70114466,"type":"2of2","ubtc":"701144.66"}}
        // XXX use zmq?

        Ok(msgs)
    }

    pub fn get_account(&self, subaccount: u32) -> Result<Value, Error> {
        if subaccount != 0 {
            bail!("multi-account is unsupported");
        }

        let has_transactions = self._get_transactions(1, 0)?.1;

        extend(
            json!({
                "type": "core",
                "pointer": 0,
                "receiving_id": "",
                "name": "RPC wallet",
                "has_transactions": has_transactions,
            }),
            self._get_balance(0)?,
        )
    }

    pub fn get_balance(&self, details: &Value) -> Result<Value, Error> {
        let min_conf = details["num_confs"].as_u64().req()? as u32;
        self._get_balance(min_conf)
    }

    fn _get_balance(&self, min_conf: u32) -> Result<Value, Error> {
        let balance: f64 = self
            .rpc
            .call("getbalance", &[Value::Null, json!(min_conf)])?;

        Ok(self._convert_satoshi(btc_to_usat(balance)))
    }

    pub fn get_transactions(&self, details: &Value) -> Result<Value, Error> {
        let page = details["page_id"].as_u64().req()? as u32;
        let (txs, potentially_has_more) = self._get_transactions(PER_PAGE, PER_PAGE * page)?;

        Ok(json!({
            "list": txs,
            "page_id": page,
            "next_page_id": if potentially_has_more { Some(page+1) } else { None },
        }))
    }

    fn _get_transactions(&self, limit: u32, start: u32) -> Result<(Vec<Value>, bool), Error> {
        // fetch listtranssactions
        let txdescs = self.rpc.call::<Value>(
            "listtransactions",
            &[json!("*"), json!(limit), json!(start)],
        )?;
        let txdescs = txdescs.as_array().unwrap();
        let potentially_has_more = txdescs.len() as u32 == limit;

        // fetch full transactions and convert to GDK format
        let txs = txdescs
            .into_iter()
            .map(|txdesc| {
                let txid = Sha256dHash::from_hex(txdesc["txid"].as_str().req()?)?;
                let blockhash = txdesc["blockhash"]
                    .as_str()
                    .map(|b| Sha256dHash::from_hex(&b).unwrap());
                let tx = self.rpc.get_raw_transaction(&txid, blockhash.as_ref())?;

                format_gdk_tx(txdesc, tx)
            })
            .collect::<Result<Vec<Value>, Error>>()?;
        Ok((txs, potentially_has_more))
    }

    pub fn get_transaction(&self, txid: &String) -> Result<Value, Error> {
        let txid = Sha256dHash::from_hex(txid)?;
        let txdesc: Value = self.rpc.call("gettransaction", &[json!(txid)])?;
        let blockhash = txdesc["blockhash"]
            .as_str()
            .map(|b| Sha256dHash::from_hex(&b).unwrap());
        let tx = self.rpc.get_raw_transaction(&txid, blockhash.as_ref())?;
        format_gdk_tx(&txdesc, tx)
    }

    pub fn create_transaction(&self, details: &Value) -> Result<String, Error> {
        debug!("create_transaction(): {:?}", details);

        let outs = parse_outs(&details)?;
        debug!("create_transaction() addresses: {:?}", outs);

        let unfunded_tx = self
            .rpc
            .create_raw_transaction_hex(&[], &outs, None, None)?;

        debug!("create_transaction unfunded tx: {:?}", unfunded_tx);

        // TODO explicit handling for id_no_utxos_found id_no_recipients id_insufficient_funds
        // id_no_amount_specified id_fee_rate_is_below_minimum id_invalid_replacement_fee_rate
        // id_send_all_requires_a_single_output

        Ok(unfunded_tx)
    }

    pub fn sign_transaction(&self, details: &Value) -> Result<String, Error> {
        let funded_tx: Value = self
            .rpc
            .call("fundrawtransaction", &[details["hex"].clone()])?;

        debug!("create_transaction funded_tx: {:?}", funded_tx);

        let signed_tx: Value = self
            .rpc
            .call("signrawtransactionwithwallet", &[funded_tx["hex"].clone()])?;

        let complete = signed_tx["complete"].as_bool().req()?;

        if !complete {
            let errors = signed_tx["errors"].to_string();
            bail!("the transaction cannot be signed: {}", errors)
        }

        Ok(signed_tx["hex"].as_str().req()?.to_string())
    }

    pub fn send_transaction(&self, details: &Value) -> Result<String, Error> {
        let tx_hex = details["hex"].as_str().req()?;
        Ok(self.rpc.send_raw_transaction(tx_hex)?.to_string())
    }

    pub fn send_raw_transaction(&self, tx_hex: &str) -> Result<String, Error> {
        Ok(self.rpc.send_raw_transaction(tx_hex)?.to_string())
    }

    pub fn get_receive_address(&self, _details: &Value) -> Result<Value, Error> {
        // details: {"subaccount":0,"address_type":"csv"}
        let child_path = self
            .base_derivation_path
            // external addresses
            .child(bip32::ChildNumber::from_normal_idx(0).unwrap())
            .child(self.next_address_child.get());
        let child_xpriv = self.xpriv.unwrap().derive_priv(&SECP, &child_path)?;
        let child_xpub = bip32::ExtendedPubKey::from_private(&SECP, &child_xpriv);
        let address = Address::p2wpkh(&child_xpub.public_key, child_xpub.network);

        // Tell the node to watch the new address.
        // Since this is a newly generated address, rescanning is not required.
        self.rpc
            .import_address(&address, None, Some(false), Some(false))?;

        // increment address counter
        self.next_address_child
            .set(match self.next_address_child.get() {
                bip32::ChildNumber::Normal { index } => {
                    bip32::ChildNumber::from_normal_idx(index + 1)?
                }
                _ => unreachable!(),
            });

        //  {
        //    "address": "2N2x4EgizS2w3DUiWYWW9pEf4sGYRfo6PAX",
        //    "address_type": "p2wsh",
        //    "branch": 1,
        //    "pointer": 13,
        //    "script": "52210338832debc5e15ce143d5cf9241147ac0019e7516d3d9569e04b0e18f3278718921025dfaa85d64963252604e1b139b40182bb859a9e2e1aa2904876c34e82158d85452ae",
        //    "script_type": 14,
        //    "subaccount": 0,
        //    "subtype": null
        //  }
        Ok(json!({
            "address": address,
            "address_type": "p2wpkh",
        }))
    }

    pub fn get_fee_estimates(&self) -> Option<&Value> {
        // will not be available before the first "tick", which should
        // happen as soon as GA_connect initializes the wallet
        if self.cached_fees.0.is_null() {
            None
        } else {
            Some(&self.cached_fees.0)
        }
    }
    pub fn _make_fee_estimates(&self) -> Result<Value, Error> {
        let mempoolinfo: Value = self.rpc.call("getmempoolinfo", &[])?;
        let minrelayfee = json!(btc_to_usat(
            mempoolinfo["minrelaytxfee"].as_f64().req()? / 1000.0
        ));

        let mut estimates: Vec<Value> = (2u16..25u16)
            .into_iter()
            .map(|target| {
                let est: EstimateSmartFeeResult =
                    self.rpc.call("estimatesmartfee", &[json!(target)])?;
                Ok(est.feerate.unwrap_or_else(|| minrelayfee.clone()))
            })
            .collect::<Result<Vec<Value>, Error>>()?;

        // prepend the estimate for 2 blocks as the estimate for 1 blocks
        estimates.insert(0, estimates[0].clone());
        // prepend the minrelayfee as the first item
        estimates.insert(0, minrelayfee);

        // the final format is: [ minrelayfee, est_for_2_blocks, est_for_2_blocks, est_for_3_blocks, ... ]
        Ok(json!(estimates))
    }

    pub fn get_available_currencies(&self) -> Value {
        // TODO
        json!({ "all": [ "USD" ], "per_exchange": { "BITSTAMP": [ "USD" ] } })
    }

    pub fn exchange_rate(&self, _currency: &str) -> f64 {
        // TODO
        420.00
    }

    pub fn convert_amount(&self, details: &Value) -> Result<Value, Error> {
        // XXX should convert_amonut support negative numbers?
        let satoshi = details["satoshi"]
            .as_u64()
            .or_else(|| f64_from_val(&details["btc"]).map(btc_to_usat))
            .or_else(|| f64_from_val(&details["fiat"]).map(|x| self._fiat_to_usat(x)))
            .or_err("id_no_amount_specified")?;

        Ok(self._convert_satoshi(satoshi))
    }

    pub fn set_tx_memo(&self, txid: &String, memo: &str) -> Result<(), Error> {
        // we can't really set a tx memo, so we fake it by setting a memo on the address

        let txdesc: Value = self.rpc.call("gettransaction", &[json!(txid)])?;

        let address = txdesc["details"][0]["address"]
            .as_str()
            .or_err("cannot find address to attach memo")?;

        debug!(
            "set_tx_memo() for {}, memo={}, address={}",
            txid, memo, address
        );

        Ok(match self
            .rpc
            .call::<Value>("setlabel", &[json!(address), json!(memo)])
        {
            Ok(_) => Ok(()),
            // https://github.com/apoelstra/rust-jsonrpc/pull/16
            Err(err) => Err(Error::from(err)),
        }?)
    }

    fn _convert_satoshi(&self, amount: u64) -> Value {
        let currency = "USD"; // TODO
        let exchange_rate = self.exchange_rate(currency);
        let amount_f = amount as f64;

        json!({
            "satoshi": amount.to_string(),
            "bits": (amount_f / SAT_PER_BIT).to_string(),
            "ubtc": (amount_f / SAT_PER_BIT).to_string(), // XXX why twice? same as bits
            "mbtc": (amount_f / SAT_PER_MBTC).to_string(),
            "btc": (amount_f / SAT_PER_BTC).to_string(),

            "fiat_rate": (exchange_rate).to_string(),
            "fiat_currency": currency,
            "fiat": (amount_f / SAT_PER_BTC * exchange_rate).to_string(),
        })
    }

    fn _fiat_to_usat(&self, amount: f64) -> u64 {
        btc_to_usat(amount / self.exchange_rate("USD"))
    }
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Wallet {{ }}")
    }
}

pub fn mnemonic_to_hex(mnemonic: &String) -> Result<String, Error> {
    let mnem = Mnemonic::from_phrase(&mnemonic[..], Language::English)?;
    Ok(hex::encode(mnem.entropy()))
}

pub fn hex_to_mnemonic(hex: &String) -> Result<String, Error> {
    let bytes = hex::decode(hex)?;
    let mnem = Mnemonic::from_entropy(&bytes, Language::English)?;
    Ok(mnem.into_phrase())
}

pub fn generate_mnemonic() -> String {
    Mnemonic::new(MnemonicType::Words24, Language::English).into_phrase()
}

pub fn validate_mnemonic(mnemonic: String) -> bool {
    Mnemonic::validate(&mnemonic, Language::English).is_ok()
}

fn format_gdk_tx(txdesc: &Value, tx: Transaction) -> Result<Value, Error> {
    let rawtx = serialize(&tx);
    let amount = btc_to_isat(txdesc["amount"].as_f64().req()?);
    let fee = txdesc["fee"].as_f64().map_or(0, |f| btc_to_usat(f * -1.0));
    let weight = tx.get_weight();
    let vsize = (weight as f32 / 4.0) as u32;

    let type_str = match txdesc["category"].as_str() {
        // for listtransactions, read out the category field
        Some(category) => match category {
            "send" => "outgoing",
            "receive" => "incoming",
            "immature" => "incoming",
            _ => bail!("invalid tx category"),
        },
        // gettransaction doesn't have a top-level category,
        // figure it out from the amount instead.
        None => {
            if amount > 0 {
                "incoming"
            } else {
                "outgoing"
            }
        }
    };

    // read out from the "label" field if available,
    // or fallback to concating the labels for all the "details" items together
    let memo = txdesc["label"]
        .as_str()
        .map(|l| l.to_string())
        .or_else(|| {
            txdesc["details"].as_array().map(|ds| {
                ds.iter()
                    .filter_map(|d| d["label"].as_str())
                    .collect::<Vec<&str>>()
                    .join(", ")
            })
        })
        .unwrap_or("".to_string());

    Ok(json!({
        "block_height": 1, // TODO not available in txdesc. fetch by block hash or derive from tip height and confirmations?
        "created_at": fmt_time(txdesc["time"].as_u64().req()?),

        "type": type_str,
        "memo": memo,

        "txhash": tx.txid().to_hex(),
        "transaction": hex::encode(&rawtx),

        "satoshi": amount,

        "transaction_version": tx.version,
        "transaction_locktime": tx.lock_time,
        "transaction_size": rawtx.len(),
        "transaction_vsize": vsize,
        "transaction_weight": weight,

        "rbf_optin": txdesc["bip125-replaceable"].as_str().req()? == "yes",
        "cap_cpfp": false, // TODO
        "can_rbf": false, // TODO
        "has_payment_request": false, // TODO
        "server_signed": false,
        "user_signed": true,
        "instant": false,

        "subaccount": 0,
        "subaccounts": [],

        "fee": fee,
        "fee_rate": (fee as f64)/(vsize as f64),

        "addressees": [], // notice the extra "e" -- its intentional
        "inputs": [], // tx.input.iter().map(format_gdk_input).collect(),
        "outputs": [], //tx.output.iter().map(format_gdk_output).collect(),
    }))
}

fn parse_outs(details: &Value) -> Result<HashMap<String, f64>, Error> {
    debug!("parse_addresses {:?}", details);

    Ok(details["addressees"]
        .as_array()
        .req()?
        .iter()
        .map(|desc| {
            let mut address = desc["address"].as_str().req()?;
            let value = desc["satoshi"].as_u64().or_err("id_no_amount_specified")?;

            if address.to_lowercase().starts_with("bitcoin:") {
                address = address.split(":").nth(1).req()?;
            }
            // TODO: support BIP21 amount

            Ok((address.to_string(), usat_to_fbtc(value)))
        })
        .collect::<Result<HashMap<String, f64>, Error>>()?)
}
