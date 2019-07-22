use bitcoin;
use bitcoin_hashes::{hmac, sha256, Hash, HashEngine};
use secp256k1;
use slip21;

const SLIP77_DERIVATION: &'static str = "SLIP-0077";

/// A SLIP-77 master blinding key used to derive shared blinding keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MasterBlindingKey(secp256k1::SecretKey);

impl MasterBlindingKey {
    /// Create a new master blinding key from a seed.
    pub fn new(seed: &[u8]) -> MasterBlindingKey {
        let master = slip21::Node::new_master(&seed);
        let child = master.derive_child(&SLIP77_DERIVATION.as_bytes());
        let key = child.key();
        assert_eq!(key.len(), 32);
        MasterBlindingKey(secp256k1::SecretKey::from_slice(key).expect("len is 32"))
    }

    /// Derive a blinding private key for a given scriptPubkey.
    pub fn derive_blinding_key(&self, script_pubkey: &bitcoin::Script) -> secp256k1::SecretKey {
        let mut engine: hmac::HmacEngine<sha256::Hash> = hmac::HmacEngine::new(&self.0[..]);
        engine.input(script_pubkey.as_bytes());

        let bytes = hmac::Hmac::<sha256::Hash>::from_engine(engine).into_inner();
        secp256k1::SecretKey::from_slice(&bytes[..]).expect("len is 32")
    }

    /// Derive a shared nonce from the master blinding key and a blinding pubkey.
    pub fn derive_shared_nonce(&self, other: &secp256k1::PublicKey) -> [u8; 32] {
        let shared_secret = secp256k1::ecdh::SharedSecret::new(&other, &self.0);
        sha256::Hash::hash(&shared_secret[..]).into_inner()
    }
}
