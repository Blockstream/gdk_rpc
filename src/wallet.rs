//! The wallet module.
//!
//! Since this wallet implementation is supposed to work on top of both a
//! Bitcoin Core node as an Elements or Liquid node, we avoid using the
//! specialized bitcoincore-rpc and liquid-rpc client interfaces, but use
//! general call methods so we can leverage the common parts of the raw
//! responses. This might make the code a but harder to read or error-prone
//! but it avoids having very big code duplication.
//!
#![allow(clippy::redundant_field_names)]

use hex;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::{cell, fmt};

use bitcoin::{util::bip32, Address, Network as BNetwork};
use bitcoin_hashes::hex::{FromHex, ToHex};
use bitcoin_hashes::sha256d;
use bitcoincore_rpc::{json as rpcjson, Client as RpcClient, RpcApi};
use serde_json::Value;

#[cfg(feature = "liquid")]
use elements;

use crate::coins;
use crate::constants::{SAT_PER_BIT, SAT_PER_BTC, SAT_PER_MBTC};
use crate::errors::{Error, OptionExt};
use crate::network::{Network, NetworkId};
use crate::util::{btc_to_isat, btc_to_usat, extend, f64_from_val, fmt_time, SECP};

use crate::wally;

const PER_PAGE: usize = 30;
const FEE_ESTIMATES_TTL: Duration = Duration::from_secs(240);

/// Meta-information about an address that we need to store.
///
/// Since we don't have a persistent database, we use the Core wallet to store
/// the information required for operating GDK.  For addresses, it's important
/// to keep the information needed to re-derive the private key: an identifier
/// of the master private key (i.e. the fingerprint) and the derivation path.
///
/// GDK also allows storing memos on transaction. Because Core doesn't support
/// transaction labels but only address labels, we inject the tx memos inside
/// the address label of an (preferably the first) address used in that
/// transaction.
///
/// This struct is used to structure the data stored in a label. It is
/// serialized as JSON when stored in a label, so that new fields can easily
/// be added.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub(crate) struct AddressMeta {
    /// The fingerprint of the extended private key used to derive the
    /// private key for this address.
    #[serde(rename = "fp", skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<bip32::Fingerprint>,
    /// The derivation path from the extended private key identified
    /// by the fingerprint field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child: Option<bip32::ChildNumber>,
    /// Since an address can be used in multiple transactions, we keep a map
    /// from the txid to the memo for the transaction.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub txmemo: HashMap<sha256d::Hash, String>,
}

impl AddressMeta {
    /// Parse a label from Core.
    pub fn from_label<S: AsRef<str>>(l: Option<S>) -> Result<AddressMeta, Error> {
        match l {
            Some(ref s) if s.as_ref().is_empty() => Ok(Default::default()),
            Some(s) => Ok(serde_json::from_str(s.as_ref())?),
            None => Ok(Default::default()),
        }
    }

    /// Serialize to string to save into a label.
    pub fn to_label(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(self)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PersistentWalletState {
    #[serde(rename = "nec")]
    next_external_child: bip32::ChildNumber,
    #[serde(rename = "nic")]
    next_internal_child: bip32::ChildNumber,
}

pub struct Wallet {
    network: &'static Network,
    rpc: RpcClient,
    mnemonic: String,

    // For the BIP32 keys, the network variable should be ignored and not used.
    /// The BIP32 master extended private key.
    master_xpriv: bip32::ExtendedPrivKey,
    /// The BIP32 extended private key for external addresses.
    external_xpriv: bip32::ExtendedPrivKey,
    /// The BIP32 extended private key for internal (i.e. change) addresses.
    internal_xpriv: bip32::ExtendedPrivKey,
    /// The master blinding key.
    #[cfg(feature = "liquid")]
    master_blinding_key: [u8; 64],

    next_external_child: cell::Cell<bip32::ChildNumber>,
    next_internal_child: cell::Cell<bip32::ChildNumber>,
    tip: Option<sha256d::Hash>,
    last_tx: Option<sha256d::Hash>,
    cached_fees: (Value, Instant),
}

impl Wallet {
    /// Get the address to use to store persistent state.
    fn persistent_state_address(
        network: NetworkId,
        master_xpriv: &bip32::ExtendedPrivKey,
    ) -> String {
        let child = bip32::ChildNumber::from_hardened_idx(350).unwrap();
        let child_xpriv = master_xpriv.derive_priv(&SECP, &[child]).unwrap();
        let child_xpub = bip32::ExtendedPubKey::from_private(&SECP, &child_xpriv);
        match network {
            #[cfg(feature = "liquid")]
            NetworkId::Elements(enet) => elements::Address::p2wpkh(
                &child_xpub.public_key,
                None,
                coins::liq::address_params(enet),
            )
            .to_string(),
            NetworkId::Bitcoin(bnet) => Address::p2wpkh(&child_xpub.public_key, bnet).to_string(),
            #[cfg(not(feature = "liquid"))]
            _ => unimplemented!(),
        }
    }

    /// Store the persistent wallet state.
    fn save_persistent_state(&self) -> Result<(), Error> {
        let state = PersistentWalletState {
            next_external_child: self.next_external_child.get(),
            next_internal_child: self.next_internal_child.get(),
        };

        let store_addr = Wallet::persistent_state_address(self.network.id(), &self.master_xpriv);
        // Generic call for liquid compat.
        self.rpc.call("setlabel", &[store_addr.into(), serde_json::to_string(&state)?.into()])?;
        Ok(())
    }

    /// Load the persistent wallet state from the node.
    #[allow(clippy::match_wild_err_arm)]
    fn load_persistent_state(
        rpc: &bitcoincore_rpc::Client,
        state_addr: &str,
    ) -> Result<PersistentWalletState, Error> {
        let info: Value = rpc.call("getaddressinfo", &[state_addr.into()])?;
        match info.get("label") {
            None => Err(Error::WalletNotRegistered),
            Some(&Value::String(ref label)) => {
                Ok(match serde_json::from_str::<PersistentWalletState>(label) {
                    Err(_) => panic!(
                        "corrupt persistent wallet state label (address: {}): {}",
                        state_addr, label
                    ),
                    Ok(s) => s,
                })
            }
            Some(_) => unreachable!(),
        }
    }

    /// Calculates the bip32 seeds from the mnemonic phrase.
    /// In order are returned:
    /// - the master xpriv
    /// - the external address xpriv
    /// - the internal address xpriv
    fn calc_xkeys(
        seed: &[u8],
    ) -> (bip32::ExtendedPrivKey, bip32::ExtendedPrivKey, bip32::ExtendedPrivKey) {
        // Network isn't of importance here.
        let master_xpriv =
            bip32::ExtendedPrivKey::new_master(BNetwork::Bitcoin, &seed[..]).unwrap();
        // Add BIP-44 derivations for external and internal addresses.
        let external_xpriv = master_xpriv
            .derive_priv(&SECP, &bip32::DerivationPath::from_str("m/44'/0'/0'/0'/0").unwrap())
            .unwrap();
        let internal_xpriv = master_xpriv
            .derive_priv(&SECP, &bip32::DerivationPath::from_str("m/44'/0'/0'/0'/1").unwrap())
            .unwrap();
        (master_xpriv, external_xpriv, internal_xpriv)
    }

    /// Register a new [Wallet].
    pub fn register(network: &'static Network, mnemonic: &str) -> Result<Wallet, Error> {
        let seed = wally::bip39_mnemonic_to_seed(&mnemonic, "")?;
        let (master_xpriv, external_xpriv, internal_xpriv) = Wallet::calc_xkeys(&seed);
        let fp = hex::encode(master_xpriv.fingerprint(&SECP).as_bytes());

        // create the wallet in Core
        let tmp_rpc = network.connect(None)?;
        match tmp_rpc.create_wallet(fp.as_str(), Some(true))?.warning {
            None => {}
            Some(ref s) if s.is_empty() => {}
            Some(warning) => {
                warn!("Received warning when creating wallet {} in Core: {}", fp, warning,)
            }
        }
        let rpc = network.connect(Some(&fp))?;

        // Check if the user was already registered.
        let state_addr = Wallet::persistent_state_address(network.id(), &master_xpriv);
        match Wallet::load_persistent_state(&rpc, &state_addr) {
            Err(Error::WalletNotRegistered) => {} // good
            Ok(_) => return Err(Error::WalletAlreadyRegistered),
            Err(e) => {
                warn!("Unexpected error while registering wallet: {}", e);
                return Err(e);
            }
        }

        let wallet = Wallet {
            network: network,
            rpc: rpc,
            mnemonic: mnemonic.to_owned(),
            master_xpriv: master_xpriv,
            external_xpriv: external_xpriv,
            internal_xpriv: internal_xpriv,
            #[cfg(feature = "liquid")]
            master_blinding_key: wally::asset_blinding_key_from_seed(&seed),
            next_external_child: cell::Cell::new(bip32::ChildNumber::from_normal_idx(0).unwrap()),
            next_internal_child: cell::Cell::new(bip32::ChildNumber::from_normal_idx(0).unwrap()),
            tip: None,
            last_tx: None,
            cached_fees: (Value::Null, Instant::now() - FEE_ESTIMATES_TTL * 2),
        };
        wallet.save_persistent_state()?;
        Ok(wallet)
    }

    /// Login to an existing [Wallet].
    pub fn login(network: &'static Network, mnemonic: &str) -> Result<Wallet, Error> {
        let seed = wally::bip39_mnemonic_to_seed(&mnemonic, "")?;
        let (master_xpriv, external_xpriv, internal_xpriv) = Wallet::calc_xkeys(&seed);
        let fp = hex::encode(master_xpriv.fingerprint(&SECP).as_bytes());

        let tmp_rpc = network.connect(None)?;
        tmp_rpc.load_wallet(&fp)?;

        let rpc = network.connect(Some(&fp))?;
        let state_addr = Wallet::persistent_state_address(network.id(), &master_xpriv);
        let state = Wallet::load_persistent_state(&rpc, &state_addr)?;
        Ok(Wallet {
            network: network,
            rpc: rpc,
            mnemonic: mnemonic.to_owned(),
            master_xpriv: master_xpriv,
            external_xpriv: external_xpriv,
            internal_xpriv: internal_xpriv,
            #[cfg(feature = "liquid")]
            master_blinding_key: wally::asset_blinding_key_from_seed(&seed),
            next_external_child: cell::Cell::new(state.next_external_child),
            next_internal_child: cell::Cell::new(state.next_internal_child),
            tip: None,
            last_tx: None,
            cached_fees: (Value::Null, Instant::now() - FEE_ESTIMATES_TTL * 2),
        })
    }

    pub fn fingerprint(&self) -> bip32::Fingerprint {
        self.master_xpriv.fingerprint(&SECP)
    }

    pub fn logout(self) -> Result<(), Error> {
        self.rpc.unload_wallet(None)?;
        Ok(())
    }

    pub fn mnemonic(&self) -> String {
        self.mnemonic.clone()
    }

    fn derive_private_key(
        &self,
        fp: bip32::Fingerprint,
        child: bip32::ChildNumber,
    ) -> Result<secp256k1::SecretKey, Error> {
        let xpriv = if fp == self.external_xpriv.fingerprint(&SECP) {
            self.external_xpriv
        } else if fp == self.internal_xpriv.fingerprint(&SECP) {
            self.internal_xpriv
        } else {
            error!("Address is labeled with unknown master xpriv fingerprint: {:?}", fp);
            return Err(Error::CorruptNodeData);
        };
        let privkey = xpriv.derive_priv(&SECP, &[child])?.private_key;
        Ok(privkey.key)
    }

    pub fn updates(&mut self) -> Result<Vec<Value>, Error> {
        let mut msgs = vec![];

        // check for new blocks
        let tip = self.rpc.get_best_block_hash()?;
        if self.tip != Some(tip) {
            let info: Value = self.rpc.call("getblock", &[tip.to_hex().into(), 1.into()])?;
            msgs.push(json!({
                "event": "block",
                "block": {
                    "block_height": info["height"].as_u64().req()?,
                    "block_hash": tip.to_hex()
                }
            }));
            self.tip = Some(tip);
        }

        // check for new transactions
        // XXX does the app care about the transaction data in the event?
        if let Some(last_tx) = self._get_transactions(1, 0)?.0.get(0) {
            let txid = last_tx["txhash"].as_str().req()?;
            let txid = sha256d::Hash::from_hex(txid)?;
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

    pub fn get_account(&self) -> Result<Value, Error> {
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
        //TODO(stevenroose) implement in rust-bitcoincore-rpc once bitcoin::Amount lands
        let mut args = vec![Value::Null, json!(min_conf), json!(true)];
        #[cfg(feature = "liquid")]
        {
            if let NetworkId::Elements(net) = self.network.id() {
                args.push(coins::liq::asset_hex(net).into());
            }
        }

        let balance: f64 = self.rpc.call("getbalance", &args)?;
        Ok(self._convert_satoshi(btc_to_usat(balance)))
    }

    pub fn get_transactions(&self, details: &Value) -> Result<Value, Error> {
        let page = details["page_id"].as_u64().req()? as usize;
        let (txs, potentially_has_more) = self._get_transactions(PER_PAGE, PER_PAGE * page)?;

        Ok(json!({
            "list": txs,
            "page_id": page,
            "next_page_id": if potentially_has_more { Some(page+1) } else { None },
        }))
    }

    fn _get_transactions(&self, limit: usize, start: usize) -> Result<(Vec<Value>, bool), Error> {
        // fetch listtranssactions
        let txdescs: Vec<Value> = self
            .rpc
            .call("listtransactions", &["*".into(), limit.into(), start.into(), true.into()])?;
        let potentially_has_more = txdescs.len() == limit;

        // fetch full transactions and convert to GDK format
        let mut txs = Vec::new();
        for desc in txdescs.into_iter() {
            let txid = sha256d::Hash::from_hex(desc["txid"].as_str().req()?)?;
            let blockhash = &desc["blockhash"];
            let tx_hex: String = self.rpc.call(
                "getrawtransaction",
                &[txid.to_hex().into(), false.into(), blockhash.clone()],
            )?;

            txs.push(format_gdk_tx(&desc, &hex::decode(&tx_hex)?, self.network.id())?);
        }
        Ok((txs, potentially_has_more))
    }

    pub fn get_transaction(&self, txid: &str) -> Result<Value, Error> {
        let txid = sha256d::Hash::from_hex(txid)?;
        let desc: Value = self.rpc.call("gettransaction", &[txid.to_hex().into(), true.into()])?;
        let raw_tx = hex::decode(desc["hex"].as_str().req()?)?;

        format_gdk_tx(&desc, &raw_tx, self.network.id())
    }

    pub fn create_transaction(&self, details: &Value) -> Result<String, Error> {
        debug!("create_transaction(): {:?}", details);

        let unfunded_tx = match self.network.id() {
            NetworkId::Bitcoin(..) => coins::btc::create_transaction(&self.rpc, details)?,
            NetworkId::Elements(..) => coins::liq::create_transaction(&self.rpc, details)?,
        };
        debug!("create_transaction unfunded tx: {:?}", hex::encode(&unfunded_tx));

        // TODO explicit handling for id_no_amount_specified id_fee_rate_is_below_minimum id_invalid_replacement_fee_rate
        // id_send_all_requires_a_single_output

        Ok(hex::encode(unfunded_tx))
    }

    pub fn sign_transaction(&self, details: &Value) -> Result<String, Error> {
        debug!("sign_transaction(): {:?}", details);
        let change_address = self.next_address(&self.internal_xpriv, &self.next_internal_child)?;

        // If we don't have any inputs, we can fail early.
        let unspent: Vec<Value> = self.rpc.call("listunspent", &[0.into()])?;
        if unspent.is_empty() {
            return Err(Error::NoUtxosFound);
        }
        debug!("list_unspent: {:?}", unspent);

        let raw_tx = match self.network.id() {
            NetworkId::Bitcoin(_) => {
                coins::btc::sign_transaction(&self.rpc, details, &change_address, |fp, child| {
                    self.derive_private_key(*fp, *child)
                })?
            }
            NetworkId::Elements(net) => coins::liq::sign_transaction(
                &self.rpc,
                net,
                details,
                &change_address,
                |fp, child| self.derive_private_key(*fp, *child),
            )?,
        };
        let hex_tx = hex::encode(&raw_tx);

        //TODO(stevenroose) remove when confident in signing code
        let ret: Vec<Value> = self.rpc.call("testmempoolaccept", &[vec![hex_tx.clone()].into()])?;
        let accept = ret.into_iter().next().unwrap();
        if !(accept["allowed"].as_bool().req()?) {
            error!(
                "sign_transaction(): signed tx is not valid: {}",
                accept["reject-reason"].as_str().req()?
            );
            // TODO(stevenroose) should we return an error??
        }

        Ok(hex_tx)
    }

    pub fn send_transaction(&self, details: &Value) -> Result<String, Error> {
        let tx_hex = details["hex"].as_str().req()?;
        Ok(self.rpc.call::<String>("sendrawtransaction", &[tx_hex.into()])?)
    }

    pub fn send_raw_transaction(&self, tx_hex: &str) -> Result<String, Error> {
        Ok(self.rpc.call::<String>("sendrawtransaction", &[tx_hex.into()])?)
    }

    /// Return the next address for the derivation and import it in Core.
    fn next_address(
        &self,
        xpriv: &bip32::ExtendedPrivKey,
        child: &cell::Cell<bip32::ChildNumber>,
    ) -> Result<String, Error> {
        let child_xpriv = xpriv.derive_priv(&SECP, &[child.get()])?;
        let child_xpub = bip32::ExtendedPubKey::from_private(&SECP, &child_xpriv);

        let meta = AddressMeta {
            fingerprint: Some(xpriv.fingerprint(&SECP)),
            child: Some(child.get()),
            ..Default::default()
        };

        let address_str = match self.network.id() {
            #[cfg(feature = "liquid")]
            NetworkId::Elements(enet) => {
                let mut addr = elements::Address::p2shwpkh(
                    &child_xpub.public_key,
                    None,
                    coins::liq::address_params(enet),
                );
                let blinding_key = wally::asset_blinding_key_to_ec_private_key(
                    &self.master_blinding_key,
                    &addr.script_pubkey(),
                );
                let blinding_pubkey = secp256k1::PublicKey::from_secret_key(&SECP, &blinding_key);
                addr.blinding_pubkey = Some(blinding_pubkey);

                // Store blinding privkey in the node.
                let addr_str = addr.to_string();
                coins::liq::store_blinding_key(&self.rpc, &addr_str, &blinding_key)?;
                addr_str
            }
            NetworkId::Bitcoin(bnet) => Address::p2wpkh(&child_xpub.public_key, bnet).to_string(),
            #[cfg(not(feature = "liquid"))]
            _ => unimplemented!(),
        };

        // Since this is a newly generated address, rescanning is not required.
        self.rpc.import_public_key(&child_xpub.public_key, Some(&meta.to_label()?), Some(false))?;

        child.set(match child.get() {
            bip32::ChildNumber::Normal {
                index,
            } => bip32::ChildNumber::from_normal_idx(index + 1)?,
            _ => unreachable!(),
        });

        self.save_persistent_state()?;

        Ok(address_str)
    }

    pub fn get_receive_address(&self, _details: &Value) -> Result<Value, Error> {
        let address = self.next_address(&self.external_xpriv, &self.next_external_child)?;
        //  {
        //    "address": "2N2x4EgizS2w3DUiWYWW9pEf4sGYRfo6PAX",
        //    "address_type": "p2wsh",
        //    "branch": 1,
        //    "pointer": 13,
        //    "script": "52210338832debc5e15ce143d5cf9241147ac0019e7516d3d9569e04b0e18f3278718921025dfaa85d64963252604e1b139b40182bb859a9e2e1aa2904876c34e82158d85452ae",
        //    "script_type": 14,
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
        let minrelayfee = json!(btc_to_usat(mempoolinfo["minrelaytxfee"].as_f64().req()? / 1000.0));

        let mut estimates: Vec<Value> = (2u16..25u16)
            .map(|target| {
                let est: rpcjson::EstimateSmartFeeResult =
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

    pub fn set_tx_memo(&self, txid: &str, memo: &str) -> Result<(), Error> {
        // we can't really set a tx memo, so we fake it by setting a memo on the address
        let txid = sha256d::Hash::from_hex(txid)?;

        let txdesc: Value =
            self.rpc.call("gettransaction", &[txid.to_hex().into(), true.into()])?;
        let details = txdesc["details"].as_array().req()?;
        if details.is_empty() {
            throw!("Tx info for {} does not contain any details", txid);
        }

        // We just need any usable address label. Let's just take the first
        // and hope Core always orders them in the same way, so we can also
        // efficiently find it back later. We explicitly tag this label with
        // the txid of this tx, so that if an address gets assigned multiple
        // transaction memos, they won't conflict.
        let detail = &details[0];
        let mut label = AddressMeta::from_label(detail["label"].as_str())?;
        label.txmemo.insert(txid, memo.to_owned());

        debug!("set_tx_memo() for {}, memo={}, address={}", txid, memo, detail["address"]);

        self.rpc.call("setlabel", &[detail["address"].clone(), label.to_label()?.into()])?;
        Ok(())
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

/// Finds a transction memo inside the transaction description field.
/// This method can be provided with a response from either
/// `gettransaction` or `listtransactions`.
/// It returns "" if none if found.
fn find_memo_in_desc(txid: sha256d::Hash, txdesc: &Value) -> Result<String, Error> {
    // First we try the top-level label field from listtransactions.
    if let Some(label) = txdesc["label"].as_str() {
        let meta = AddressMeta::from_label(Some(label))?;
        if let Some(memo) = meta.txmemo.get(&txid) {
            return Ok(memo.to_owned());
        }
    }

    // Then we iterate over the details array.
    if let Some(details) = txdesc["details"].as_array() {
        for detail in details {
            let meta = AddressMeta::from_label(detail["label"].as_str())?;
            if let Some(memo) = meta.txmemo.get(&txid) {
                return Ok(memo.to_owned());
            }
        }
    }

    Ok(String::new())
}

fn format_gdk_tx(txdesc: &Value, raw_tx: &[u8], network: NetworkId) -> Result<Value, Error> {
    let txid = sha256d::Hash::from_hex(txdesc["txid"].as_str().req()?)?;
    //TODO(stevenroose) optimize with Amount
    let amount = match network {
        NetworkId::Elements(..) => btc_to_isat(match txdesc["amount"] {
            serde_json::Value::Object(ref v) => v["bitcoin"].as_f64().req()?,
            ref v => v.as_f64().req()?,
        }),
        NetworkId::Bitcoin(..) => btc_to_isat(txdesc["amount"].as_f64().req()?),
    };
    let fee = txdesc["fee"].as_f64().map_or(0, |f| btc_to_usat(f * -1.0));

    let type_str = match txdesc["category"].as_str() {
        // for listtransactions, read out the category field
        Some(category) => match category {
            "send" => "outgoing",
            "receive" => "incoming",
            "immature" => "incoming",
            _ => throw!("invalid tx category"),
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

    let tx_props = match network {
        NetworkId::Bitcoin(_) => coins::btc::tx_props(&raw_tx)?,
        NetworkId::Elements(_) => coins::liq::tx_props(&raw_tx)?,
    };
    let vsize = tx_props["transaction_vsize"].as_u64().unwrap();

    let ret = json!({
        "block_height": 1,
        "created_at": fmt_time(txdesc["time"].as_u64().req()?),

        "type": type_str,
        "memo": find_memo_in_desc(txid, &txdesc)?,

        "txhash": txid.to_hex(),
        "transaction": hex::encode(&raw_tx),

        "satoshi": amount,

        "rbf_optin": txdesc["bip125-replaceable"].as_str().req()? == "yes",
        "cap_cpfp": false, // TODO
        "can_rbf": false, // TODO
        "has_payment_request": false, // TODO
        "server_signed": false,
        "user_signed": true,
        "instant": false,

        "fee": fee,
        "fee_rate": (fee as f64)/(vsize as f64),

        "addressees": [], // notice the extra "e" -- its intentional
        "inputs": [], // tx.input.iter().map(format_gdk_input).collect(),
        "outputs": [], //tx.output.iter().map(format_gdk_output).collect(),
    });
    Ok(extend(ret, tx_props)?)
}
