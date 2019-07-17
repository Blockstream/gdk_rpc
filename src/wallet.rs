use hex;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::{Duration, Instant};
use std::{cell, fmt};

use bip39::{Language, Mnemonic, MnemonicType, Seed};
use bitcoin::{
    consensus::{deserialize, serialize},
    util::bip143,
    util::bip32,
    Address, Network as BNetwork, Transaction,
};
use bitcoin_hashes::hex::{FromHex, ToHex};
use bitcoin_hashes::sha256d;
use bitcoincore_rpc::json as rpcjson;
use bitcoincore_rpc::{Client as RpcClient, RpcApi};
use failure::Error;
use serde_json::Value;

use crate::constants::{SAT_PER_BIT, SAT_PER_BTC, SAT_PER_MBTC};
use crate::errors::OptionExt;
use crate::network::Network;
use crate::util::{btc_to_isat, btc_to_usat, extend, f64_from_val, fmt_time, usat_to_fbtc, SECP};

const PER_PAGE: usize = 30;
const FEE_ESTIMATES_TTL: Duration = Duration::from_secs(240);

/// Meta-information about an address that we need to store.
/// We use this to store multiple fields inside the address label field.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
struct AddressMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp: Option<bip32::Fingerprint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child: Option<bip32::ChildNumber>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub txmemo: HashMap<sha256d::Hash, String>,
}

impl AddressMeta {
    /// Parse a label from Core.
    pub fn from_label(l: Option<&String>) -> Result<AddressMeta, Error> {
        match l {
            Some(s) if s.is_empty() => Ok(Default::default()),
            Some(s) => Ok(serde_json::from_str(s)?),
            None => Ok(Default::default()),
        }
    }
    /// Serialize to string to save into a label.
    pub fn to_label(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(self)?)
    }
}

pub struct Wallet {
    network: &'static Network,
    rpc: RpcClient,
    mnemonic: Option<String>,
    master_xpriv: Option<bip32::ExtendedPrivKey>,
    /// The BIP32 extended private key for external addresses.
    external_xpriv: Option<bip32::ExtendedPrivKey>,
    /// The BIP32 extended private key for internal (i.e. change) addresses.
    internal_xpriv: Option<bip32::ExtendedPrivKey>,
    next_external_child: cell::Cell<bip32::ChildNumber>,
    next_internal_child: cell::Cell<bip32::ChildNumber>,
    tip: Option<sha256d::Hash>,
    last_tx: Option<sha256d::Hash>,
    cached_fees: (Value, Instant),
}

impl Wallet {
    pub fn new(network: &'static Network) -> Result<Self, Error> {
        let rpc = network.connect(None)?;
        Ok(Wallet {
            network,
            rpc: rpc,
            mnemonic: None,
            master_xpriv: None,
            external_xpriv: None,
            internal_xpriv: None,
            next_external_child: cell::Cell::new(bip32::ChildNumber::from_normal_idx(0).unwrap()),
            next_internal_child: cell::Cell::new(bip32::ChildNumber::from_normal_idx(0).unwrap()),
            tip: None,
            last_tx: None,
            cached_fees: (Value::Null, Instant::now() - FEE_ESTIMATES_TTL * 2),
        })
    }

    pub fn register(&mut self, mnemonic: &str) -> Result<(), Error> {
        let mnem = Mnemonic::from_phrase(&mnemonic[..], Language::English)?;
        let seed = Seed::new(&mnem, "");
        // Network isn't of importance here.
        let master_xpriv = bip32::ExtendedPrivKey::new_master(BNetwork::Bitcoin, seed.as_bytes())?;
        // Add BIP-44 derivations for external and internal addresses.
        let external_xpriv = master_xpriv.derive_priv(
            &SECP,
            &bip32::DerivationPath::from_str("m/44'/0'/0'/0'/0").unwrap(),
        )?;
        let internal_xpriv = master_xpriv.derive_priv(
            &SECP,
            &bip32::DerivationPath::from_str("m/44'/0'/0'/0'/1").unwrap(),
        )?;

        // create the wallet in Core
        let fp = hex::encode(master_xpriv.fingerprint(&SECP).as_bytes());
        let ret: Value = self
            .rpc
            .call("createwallet", &[fp.as_str().into(), true.into()])?;
        let ret = ret.as_object().unwrap();
        if ret.contains_key("warning") && !ret["warning"].as_str().unwrap().is_empty() {
            bail!(
                "Received warning when creating wallet {} in Core: {}",
                fp,
                ret["warning"]
            );
        }

        self.mnemonic = Some(mnemonic.to_owned());
        self.master_xpriv = Some(master_xpriv);
        self.external_xpriv = Some(external_xpriv);
        self.internal_xpriv = Some(internal_xpriv);
        self.rpc = self.network.connect(Some(self.fingerprint().unwrap()))?;
        Ok(())
    }

    pub fn login(&mut self, mnemonic: &str) -> Result<(), Error> {
        if self.mnemonic.is_none() {
            // just as pass-through to register for now
            self.register(mnemonic)?;
        }
        self.rpc = self.network.connect(Some(self.fingerprint().unwrap()))?;
        Ok(())
    }

    pub fn fingerprint(&self) -> Option<String> {
        // we can simply use to_string after this PR is merged:
        // https://github.com/rust-bitcoin/rust-bitcoin/pull/271
        self.master_xpriv
            .map(|x| hex::encode(x.fingerprint(&SECP).as_bytes()))
    }

    pub fn is_ready(&self) -> bool {
        self.mnemonic.is_some()
    }

    pub fn mnemonic(&self) -> Option<String> {
        self.mnemonic.clone()
    }

    pub fn updates(&mut self) -> Result<Vec<Value>, Error> {
        if !self.is_ready() {
            return Ok(vec![]);
        }

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
        //TODO(stevenroose) implement in rust-bitcoincore-rpc once bitcoin::Amount lands
        let balance: f64 = self
            .rpc
            .call("getbalance", &[Value::Null, json!(min_conf), json!(true)])?;

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
        let txdescs = self
            .rpc
            .list_transactions(None, Some(limit), Some(start), Some(true))?;
        let potentially_has_more = txdescs.len() == limit;

        // fetch full transactions and convert to GDK format
        let txs = txdescs
            .into_iter()
            .map(|desc| {
                let txid = desc.info.txid;
                let blockhash = desc.info.blockhash;
                let tx = self.rpc.get_raw_transaction(&txid, blockhash.as_ref())?;

                format_gdk_tx(
                    &tx,
                    desc.detail.amount.into_inner(),
                    desc.detail.fee.unwrap().into_inner(),
                    &desc.info,
                    &[&desc.detail],
                )
            })
            .collect::<Result<Vec<Value>, Error>>()?;
        Ok((txs, potentially_has_more))
    }

    pub fn get_transaction(&self, txid: &String) -> Result<Value, Error> {
        let txid = sha256d::Hash::from_hex(txid)?;
        let desc = self.rpc.get_transaction(&txid, Some(true))?;
        let blockhash = desc.info.blockhash;
        let tx = self.rpc.get_raw_transaction(&txid, blockhash.as_ref())?;
        format_gdk_tx(
            &tx,
            desc.amount.into_inner(),
            desc.fee.unwrap().into_inner(),
            &desc.info,
            &desc
                .details
                .iter()
                .collect::<Vec<&rpcjson::GetTransactionResultDetail>>(),
        )
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
        debug!("sign_transaction(): {:?}", details);
        let change_address = self.next_address(
            self.internal_xpriv.as_ref().unwrap(),
            self.next_internal_child.get(),
        )?;

        // check listunspent
        debug!(
            "list_unspent: {:?}",
            self.rpc.list_unspent(Some(0), None, None, None, None)?
        );

        //TODO(stevenroose) liquid
        let fund_opts = bitcoincore_rpc::json::FundRawTransactionOptions {
            change_address: Some(change_address.parse().unwrap()),
            include_watching: Some(true),
            ..Default::default()
        };
        debug!("hex: {}", details["hex"].as_str().unwrap());

        // We start a loop because we need to retry when we find unusable inputs.
        'outer: loop {
            let funded_result = self.rpc.fund_raw_transaction(
                details["hex"].as_str().unwrap(),
                Some(&fund_opts),
                None,
            )?;
            debug!("funded_tx raw: {:?}", hex::encode(&funded_result.hex));
            let mut unsigned_tx: Transaction = deserialize(&funded_result.hex)?;

            // Gather the details for the inputs.
            let mut input_details = Vec::with_capacity(unsigned_tx.input.len());
            for input in &unsigned_tx.input {
                let prevout = input.previous_output;
                let prevtx = self.rpc.get_transaction(&prevout.txid, Some(true))?;
                let details = match prevtx.details.into_iter().find(|d| d.vout == prevout.vout) {
                    None => bail!("transaction has unknown input: {}", prevout),
                    Some(det) => det,
                };

                // If the output is not p2wpkh, we can't spend it for now.
                //TODO(stevenroose) implement non-p2wpkh spending
                //TODO(stevenroose) make this check better after https://github.com/rust-bitcoin/rust-bitcoin/pull/255
                let is_p2wpkh = match details.address.payload {
                    bitcoin::util::address::Payload::WitnessProgram(ref prog) => {
                        prog.program().len() == 20
                    }
                    _ => false,
                };
                if !is_p2wpkh {
                    warn!(
                        "Wallet received a tx on a non-p2wpkh address {}: {}",
                        details.address, prevout
                    );
                    // We lock the unspent so it doesn't get selected anymore.
                    self.rpc.lock_unspent(&[prevout])?;
                    continue 'outer;
                }

                input_details.push(details);
            }
            debug!("unsigned_tx: {:?}", unsigned_tx);

            // Sign the tx.
            let sighash_components = bip143::SighashComponents::new(&unsigned_tx);
            for (idx, details) in input_details.into_iter().enumerate() {
                let label = AddressMeta::from_label(details.label.as_ref())?;
                if label.fp.is_none() || label.child.is_none() {
                    error!(
                        "An address that is not ours is used for coin selection: {}",
                        details.address
                    );
                }
                let fp = label.fp.unwrap();
                let xpriv = if fp == self.external_xpriv.as_ref().unwrap().fingerprint(&SECP) {
                    self.external_xpriv.as_ref().unwrap()
                } else if fp == self.internal_xpriv.as_ref().unwrap().fingerprint(&SECP) {
                    self.internal_xpriv.as_ref().unwrap()
                } else {
                    bail!(
                        "address is labeled with unknown master xpriv fingerprint: {:?}",
                        label.fp
                    )
                };
                let privkey = xpriv
                    .derive_priv(&SECP, &[label.child.unwrap()])?
                    .private_key;
                let pubkey = privkey.public_key(&SECP);

                let script_code = bitcoin::Address::p2pkh(&pubkey, privkey.network).script_pubkey();
                let sighash = sighash_components.sighash_all(
                    &unsigned_tx.input[idx],
                    &script_code,
                    details.amount.into_inner() as u64,
                );
                let msg = secp256k1::Message::from_slice(&sighash[..])?;
                let mut signature = SECP.sign(&msg, &privkey.key).serialize_der();
                signature.push(0x01);
                unsigned_tx.input[idx].witness = vec![signature, pubkey.to_bytes()];
            }

            //TODO(stevenroose) remove when confident in signing code
            let accept = self
                .rpc
                .test_mempool_accept(&[&unsigned_tx])?
                .into_iter()
                .next()
                .unwrap();
            if accept.allowed == false {
                error!(
                    "sign_transaction(): signed tx is not valid: {}",
                    accept.reject_reason.unwrap()
                );
                // TODO(stevenroose) should we return an error??
            }

            Self::increment_child_cell(&self.next_internal_child)?;
            return Ok(hex::encode(&serialize(&unsigned_tx)));
        }
    }

    pub fn send_transaction(&self, details: &Value) -> Result<String, Error> {
        let tx_hex = details["hex"].as_str().req()?;
        Ok(self.rpc.send_raw_transaction(tx_hex)?.to_string())
    }

    pub fn send_raw_transaction(&self, tx_hex: &str) -> Result<String, Error> {
        Ok(self.rpc.send_raw_transaction(tx_hex)?.to_string())
    }

    /// Return the next address for the derivation and import it in Core.
    fn next_address(
        &self,
        xpriv: &bip32::ExtendedPrivKey,
        child: bip32::ChildNumber,
    ) -> Result<String, Error> {
        let child_xpriv = xpriv.derive_priv(&SECP, &[child])?;
        let child_xpub = bip32::ExtendedPubKey::from_private(&SECP, &child_xpriv);

        let address_str: String = if self.network.liquid {
            //TODO(stevenroose) implement
            unimplemented!()
        } else {
            let address = if self.network.mainnet && !self.network.development {
                Address::p2wpkh(&child_xpub.public_key, BNetwork::Bitcoin)
            } else if self.network.development && !self.network.mainnet {
                Address::p2wpkh(&child_xpub.public_key, BNetwork::Regtest)
            } else {
                panic!(
                    "strange network settings: liquid={}, mainnet={}, development={}",
                    self.network.liquid, self.network.mainnet, self.network.development
                );
            };

            // Tell the node to watch the new address.
            // Since this is a newly generated address, rescanning is not required.
            let meta = AddressMeta {
                fp: Some(xpriv.fingerprint(&SECP)),
                child: Some(child),
                ..Default::default()
            };
            self.rpc.import_public_key(
                &child_xpub.public_key,
                Some(&meta.to_label()?),
                Some(false),
            )?;
            address.to_string()
        };

        Ok(address_str)
    }

    /// Increment the bip32 child cell by one.
    fn increment_child_cell(child_cell: &cell::Cell<bip32::ChildNumber>) -> Result<(), Error> {
        child_cell.set(match child_cell.get() {
            bip32::ChildNumber::Normal { index } => bip32::ChildNumber::from_normal_idx(index + 1)?,
            _ => unreachable!(),
        });
        Ok(())
    }

    pub fn get_receive_address(&self, _details: &Value) -> Result<Value, Error> {
        // details: {"subaccount":0,"address_type":"csv"}

        let address = self.next_address(
            self.external_xpriv.as_ref().unwrap(),
            self.next_external_child.get(),
        )?;
        Self::increment_child_cell(&self.next_external_child)?;
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

    pub fn set_tx_memo(&self, txid: &String, memo: &str) -> Result<(), Error> {
        // we can't really set a tx memo, so we fake it by setting a memo on the address
        let txid = sha256d::Hash::from_hex(txid)?;

        let txdesc = self.rpc.get_transaction(&txid, Some(true))?;
        if txdesc.details.is_empty() {
            bail!("Tx info for {} does not contain any details", txid);
        }

        // We just need any usable address label. Let's just take the first and hope Core always
        // orders them in the same way, so we can also efficiently find it back later.
        // We explicitly tag this label with the txid of this tx, so that if an address gets
        // assigned multiple transaction memos, they won't conflict.
        let detail = &txdesc.details[0];
        let mut label = AddressMeta::from_label(detail.label.as_ref())?;
        label.txmemo.insert(txid, memo.to_owned());

        debug!(
            "set_tx_memo() for {}, memo={}, address={}",
            txid, memo, detail.address
        );

        self.rpc.set_label(&detail.address, &label.to_label()?)?;
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

fn format_gdk_tx(
    tx: &Transaction,
    amount: i64,
    fee: i64,
    info: &rpcjson::WalletTxInfo,
    details: &[&rpcjson::GetTransactionResultDetail],
) -> Result<Value, Error> {
    let txid = tx.txid();
    let rawtx = serialize(tx);
    let weight = tx.get_weight();
    let vsize = (weight as f32 / 4.0) as u32;

    let type_str = if amount > 0 { "incoming" } else { "outgoing" };

    //// read out from the "label" field if available,
    //// or fallback to concating the labels for all the "details" items together
    //let memo = txdesc["label"]
    //    .as_str()
    //    .map(|l| l.to_string())
    //    .or_else(|| {
    //        txdesc["details"].as_array().map(|ds| {
    //            ds.iter()
    //                .filter_map(|d| d["label"].as_str())
    //                .collect::<Vec<&str>>()
    //                .join(", ")
    //        })
    //    })
    //    .unwrap_or("".to_string());
    let memo = details.iter().find_map(|d| {
        let label = match AddressMeta::from_label(d.label.as_ref()) {
            Ok(l) => l,
            Err(e) => {
                error!(
                    "Address {} has invalid label `{}`: {}",
                    d.address,
                    d.label.as_ref().unwrap(),
                    e,
                );
                Default::default()
            }
        };
        label.txmemo.get(&txid).cloned()
    });

    Ok(json!({
        "block_height": 1, // TODO not available in txdesc. fetch by block hash or derive from tip height and confirmations?
        "created_at": fmt_time(info.time),

        "type": type_str,
        "memo": memo.unwrap_or(String::new()),

        "txhash": tx.txid().to_hex(),
        "transaction": hex::encode(&rawtx),

        "satoshi": amount,

        "transaction_version": tx.version,
        "transaction_locktime": tx.lock_time,
        "transaction_size": rawtx.len(),
        "transaction_vsize": vsize,
        "transaction_weight": weight,

        "rbf_optin": info.bip125_replaceable == rpcjson::Bip125Replaceable::Yes,
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
