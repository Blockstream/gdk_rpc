use core::fmt;
use std::borrow::Cow;
use std::io;

use backtrace::Backtrace;
use bitcoin::consensus::encode;
use bitcoin::util::bip32;
use bitcoincore_rpc;
#[cfg(feature = "liquid")]
use elements;
use failure;
use hex;
use secp256k1;
use serde_json;
use url;

pub const GDK_ERROR_ID_UNKNOWN: &'static str = "id_unknown";

const CORE_INSUFFICIENT_FUNDS: i32 = -1;
const CORE_WALLET_GENERIC: i32 = -4;

#[derive(Debug)]
pub enum Error {
    // First we specify exact errors that map GDK errors.
    /// There were insufficient funds.
    InsufficientFunds,
    /// User is already logged in.
    AlreadyLoggedIn,
    /// User tried logging into a wallet that was not registered yet.
    WalletNotRegistered,
    /// User tried to register a wallet that was already registered.
    WalletAlreadyRegistered,
    /// Mnemonics should be phrases of 24 words.
    InvalidMnemonic,
    /// A user requested creation of a transaction with no recipients.
    NoRecipients,
    /// The wallet does not have any available UTXOs to fund a transaction.
    NoUtxosFound,
    /// Some of the data stored in the node is corrupt. The wallet will
    /// probably have to be reset.
    CorruptNodeData,

    /// The Elements node returned errors when asked to sign a transaction.
    ElementsCantSign(Vec<bitcoincore_rpc::json::SignRawTransactionResultError>),

    // And then all other errors that we can't convert to GDK codes.
    Bip32(bip32::Error),
    Bip39(failure::Error),
    BitcoinEncode(encode::Error),
    BitcoinRpc(bitcoincore_rpc::Error),
    #[cfg(feature = "liquid")]
    ElementsAddress(elements::AddressError),
    Hashes(bitcoin_hashes::Error),
    Hex(hex::FromHexError),
    Io(io::Error),
    Json(serde_json::Error),
    Secp256k1(secp256k1::Error),
    Url(url::ParseError),

    /// Custom error with message.
    Other(Cow<'static, str>),
}

impl Error {
    /// Convert the error to a GDK-compatible code.
    pub fn to_gdk_code(&self) -> &'static str {
        // Unhandles error codes:
        // id_no_amount_specified
        // id_fee_rate_is_below_minimum
        // id_invalid_replacement_fee_rate
        // id_send_all_requires_a_single_output
        match *self {
            Error::InsufficientFunds => "id_insufficient_funds",
            Error::NoRecipients => "id_no_recipients",
            Error::NoUtxosFound => "id_no_utxos_found",
            _ => GDK_ERROR_ID_UNKNOWN,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl From<bitcoincore_rpc::Error> for Error {
    fn from(e: bitcoincore_rpc::Error) -> Error {
        debug!("backtrace bitcoincore_rpc::Error: {} {:?}", e, Backtrace::new());
        match e {
            bitcoincore_rpc::Error::JsonRpc(ref e) => match e {
                jsonrpc::Error::Rpc(ref e) => match e.code {
                    CORE_INSUFFICIENT_FUNDS => return Error::InsufficientFunds,
                    CORE_WALLET_GENERIC => {
                        if e.message.contains("Duplicate -wallet filename specified.") {
                            return Error::AlreadyLoggedIn;
                        }
                    }
                    _ => {}
                },
                _ => {}
            },
            _ => {}
        }

        Error::BitcoinRpc(e)
    }
}

macro_rules! from_error {
    ($variant:ident, $err:ty) => {
        impl From<$err> for Error {
            fn from(e: $err) -> Error {
                debug!("backtrace {}: {} {:?}", stringify!($err), e, Backtrace::new());
                Error::$variant(e)
            }
        }
    };
}

from_error!(Bip32, bip32::Error);
from_error!(BitcoinEncode, encode::Error);
#[cfg(feature = "liquid")]
from_error!(ElementsAddress, elements::AddressError);
from_error!(Hashes, bitcoin_hashes::Error);
from_error!(Hex, hex::FromHexError);
from_error!(Io, io::Error);
from_error!(Json, serde_json::Error);
from_error!(Secp256k1, secp256k1::Error);
from_error!(Url, url::ParseError);

#[macro_export]
macro_rules! throw {
    ($e:expr) => {
        return Err(Error::Other($e.into()));
    };
    ($fmt:expr, $($arg:tt)*) => {
        return Err(Error::Other(format!($fmt, $($arg)*).into()));
    };
}

pub trait OptionExt<T> {
    fn or_err<E: Into<Cow<'static, str>>>(self, err: E) -> Result<T, Error>;

    fn req(self) -> Result<T, Error>;
}

impl<T> OptionExt<T> for Option<T> {
    fn or_err<E: Into<Cow<'static, str>>>(self, err: E) -> Result<T, Error> {
        self.ok_or_else(|| {
            debug!("backtrace OptionExt::or_else: {:?}", Backtrace::new());
            Error::Other(err.into())
        })
    }

    fn req(self) -> Result<T, Error> {
        self.ok_or_else(|| {
            debug!("backtrace OptionExt::req: {:?}", Backtrace::new());
            Error::Other("missing required option".into())
        })
    }
}
