//!
//! Links to libwally methods used.
//!

use std::ptr;

use bitcoin::consensus::encode::serialize;
use bitcoin_hashes::{sha256d, Hash};

use crate::errors::Error;
use crate::util::{make_str, read_str};

mod ffi {
    use std::ops::Drop;
    use std::{mem, ptr, slice};

    use bitcoin::consensus::encode::serialize;
    use bitcoin_hashes::Hash;
    use elements;
    use libc::{c_char, c_int, c_uchar, c_void};

    #[allow(non_camel_case_types)]
    type size_t = usize;

    pub const WALLY_OK: c_int = 0;
    #[allow(unused)]
    pub const WALLY_ERROR: c_int = -1;
    #[allow(unused)]
    pub const WALLY_EINVAL: c_int = -2;
    #[allow(unused)]
    pub const WALLY_ENOMEM: c_int = -3;

    /// Allocate a vector on the heap and return a raw pointer to the buffer.
    fn vec_alloc<'a, T>(v: Vec<T>) -> *const T
    where
        T: 'static,
    {
        let boxed = v.into_boxed_slice();
        let sliced: &'static mut [T] = Box::leak(boxed);
        sliced.as_ptr()
    }

    /// Convert a slice into a slice of another type and return a raw pointer
    /// to the heap-allocated buffer.
    fn slice_convert_alloc<'a, F, T>(f: &'a [F]) -> *const T
    where
        T: 'static + From<&'a F>,
    {
        vec_alloc(f.iter().map(From::from).collect())
    }

    /// Drop the struct inside the given pointer, setting it to null.
    unsafe fn struct_drop<T>(pointer: &mut *const T) {
        let mut p = ptr::null();
        mem::swap(&mut p, pointer);
        let _ = Box::from_raw(p as *mut T);
    }

    /// Drop the slice inside the given pointer, setting it to null.
    unsafe fn slice_drop<T>(pointer: &mut *const T, len: usize) {
        let mut p = ptr::null();
        mem::swap(&mut p, pointer);
        let slice: &[T] = slice::from_raw_parts(p, len);
        let _ = Box::from_raw(slice as *const [T] as *mut [T]);
    }

    //struct wally_tx_witness_item {
    //    unsigned char *witness;
    //    size_t witness_len;
    //};
    #[repr(C)]
    pub struct WallyTxWitnessItem {
        witness: *const c_uchar,
        witness_len: size_t,
    }

    impl<'a> From<&'a Vec<u8>> for WallyTxWitnessItem {
        fn from(i: &'a Vec<u8>) -> WallyTxWitnessItem {
            WallyTxWitnessItem {
                witness: i.as_ptr(),
                witness_len: i.len(),
            }
        }
    }

    //struct wally_tx_witness_stack {
    //    struct wally_tx_witness_item *items;
    //    size_t num_items;
    //    size_t items_allocation_len;
    //};
    #[repr(C)]
    pub struct WallyTxWitnessStack {
        items: *const WallyTxWitnessItem,
        num_items: size_t,
        items_allocation_len: size_t,
    }

    impl<'a> From<&'a Vec<Vec<u8>>> for WallyTxWitnessStack {
        fn from(s: &'a Vec<Vec<u8>>) -> WallyTxWitnessStack {
            WallyTxWitnessStack {
                items: slice_convert_alloc(&s[..]),
                num_items: s.len(),
                items_allocation_len: s.len(),
            }
        }
    }

    impl Drop for WallyTxWitnessStack {
        fn drop(&mut self) {
            unsafe {
                slice_drop(&mut self.items, self.num_items);
            }
        }
    }

    ///** A transaction input */
    //struct wally_tx_input {
    //    unsigned char txhash[WALLY_TXHASH_LEN];
    //    uint32_t index;
    //    uint32_t sequence;
    //    unsigned char *script;
    //    size_t script_len;
    //    struct wally_tx_witness_stack *witness;
    //    uint8_t features;
    //#ifdef BUILD_ELEMENTS
    //    unsigned char blinding_nonce[SHA256_LEN];
    //    unsigned char entropy[SHA256_LEN];
    //    unsigned char *issuance_amount;
    //    size_t issuance_amount_len;
    //    unsigned char *inflation_keys;
    //    size_t inflation_keys_len;
    //    unsigned char *issuance_amount_rangeproof;
    //    size_t issuance_amount_rangeproof_len;
    //    unsigned char *inflation_keys_rangeproof;
    //    size_t inflation_keys_rangeproof_len;
    //    struct wally_tx_witness_stack *pegin_witness;
    //#endif /* BUILD_ELEMENTS */
    //};
    #[repr(C)]
    pub struct WallyTxInput {
        txhash: [c_uchar; 32],
        index: u32,
        sequence: u32,
        script: *const c_uchar,
        script_len: size_t,
        witness: *const WallyTxWitnessStack,
        features: u8,
        blinding_nonce: [c_uchar; 32],
        entropy: [c_uchar; 32],
        issuance_amount: *const c_uchar,
        issuance_amount_len: size_t,
        inflation_keys: *const c_uchar,
        inflation_keys_len: size_t,
        issuance_amount_rangeproof: *const c_uchar,
        issuance_amount_rangeproof_len: size_t,
        inflation_keys_rangeproof: *const c_uchar,
        inflation_keys_rangeproof_len: size_t,
        pegin_witness: *const WallyTxWitnessStack,
    }

    impl<'a> From<&'a elements::TxIn> for WallyTxInput {
        fn from(txin: &'a elements::TxIn) -> WallyTxInput {
            WallyTxInput {
                txhash: txin.previous_output.txid.into_inner(),
                index: txin.previous_output.vout,
                sequence: txin.sequence,
                script: txin.script_sig.as_bytes().as_ptr(),
                script_len: txin.script_sig.as_bytes().len(),
                witness: Box::into_raw(Box::new((&txin.witness.script_witness).into())),
                features: 0, //TODO(stevenroose)
                blinding_nonce: txin.asset_issuance.asset_blinding_nonce,
                entropy: txin.asset_issuance.asset_entropy,
                issuance_amount: { vec_alloc(serialize(&txin.asset_issuance.amount)) },
                issuance_amount_len: txin.asset_issuance.amount.encoded_length(),
                inflation_keys: vec_alloc(serialize(&txin.asset_issuance.inflation_keys)),
                inflation_keys_len: txin.asset_issuance.inflation_keys.encoded_length(),
                issuance_amount_rangeproof: txin.witness.amount_rangeproof.as_ptr(),
                issuance_amount_rangeproof_len: txin.witness.amount_rangeproof.len(),
                inflation_keys_rangeproof: txin.witness.amount_rangeproof.as_ptr(),
                inflation_keys_rangeproof_len: txin.witness.amount_rangeproof.len(),
                pegin_witness: Box::into_raw(Box::new((&txin.witness.pegin_witness).into())),
            }
        }
    }

    impl Drop for WallyTxInput {
        fn drop(&mut self) {
            unsafe {
                slice_drop(&mut self.issuance_amount, self.issuance_amount_len);
                slice_drop(&mut self.inflation_keys, self.inflation_keys_len);
                struct_drop(&mut self.witness);
                struct_drop(&mut self.pegin_witness);
            }
        }
    }

    //struct wally_tx_output {
    //    uint64_t satoshi;
    //    unsigned char *script;
    //    size_t script_len;
    //    uint8_t features;
    //#ifdef BUILD_ELEMENTS
    //    unsigned char *asset;
    //    size_t asset_len;
    //    unsigned char *value;
    //    size_t value_len;
    //    unsigned char *nonce;
    //    size_t nonce_len;
    //    unsigned char *surjectionproof;
    //    size_t surjectionproof_len;
    //    unsigned char *rangeproof;
    //    size_t rangeproof_len;
    //#endif /* BUILD_ELEMENTS */
    //};
    #[repr(C)]
    pub struct WallyTxOutput {
        satoshi: u64,
        script: *const c_uchar,
        script_len: size_t,
        features: u8,
        asset: *const c_uchar,
        asset_len: size_t,
        value: *const c_uchar,
        value_len: size_t,
        nonce: *const c_uchar,
        nonce_len: size_t,
        surjectionproof: *const c_uchar,
        surjectionproof_len: size_t,
        rangeproof: *const c_uchar,
        rangeproof_len: size_t,
    }

    impl<'a> From<&'a elements::TxOut> for WallyTxOutput {
        fn from(txout: &'a elements::TxOut) -> WallyTxOutput {
            WallyTxOutput {
                satoshi: match txout.value {
                    elements::confidential::Value::Explicit(s) => s,
                    _ => 0,
                },
                script: txout.script_pubkey.as_bytes().as_ptr(),
                script_len: txout.script_pubkey.as_bytes().len(),
                features: 0, //TODO(stevenroose)
                asset: vec_alloc(serialize(&txout.asset)),
                asset_len: txout.asset.encoded_length(),
                value: vec_alloc(serialize(&txout.value)),
                value_len: txout.value.encoded_length(),
                nonce: vec_alloc(serialize(&txout.nonce)),
                nonce_len: txout.nonce.encoded_length(),
                surjectionproof: txout.witness.surjection_proof.as_ptr(),
                surjectionproof_len: txout.witness.surjection_proof.len(),
                rangeproof: txout.witness.rangeproof.as_ptr(),
                rangeproof_len: txout.witness.rangeproof.len(),
            }
        }
    }

    impl Drop for WallyTxOutput {
        fn drop(&mut self) {
            unsafe {
                slice_drop(&mut self.asset, self.asset_len);
                slice_drop(&mut self.value, self.value_len);
                slice_drop(&mut self.nonce, self.nonce_len);
            }
        }
    }

    //struct wally_tx {
    //    uint32_t version;
    //    uint32_t locktime;
    //    struct wally_tx_input *inputs;
    //    size_t num_inputs;
    //    size_t inputs_allocation_len;
    //    struct wally_tx_output *outputs;
    //    size_t num_outputs;
    //    size_t outputs_allocation_len;
    //};
    #[repr(C)]
    pub struct WallyTx {
        version: u32,
        locktime: u32,
        inputs: *const WallyTxInput,
        num_inputs: size_t,
        inputs_allocation_len: size_t,
        outputs: *const WallyTxOutput,
        num_outputs: size_t,
        outputs_allocation_len: size_t,
    }

    impl<'a> From<&'a elements::Transaction> for WallyTx {
        fn from(tx: &'a elements::Transaction) -> WallyTx {
            WallyTx {
                version: tx.version,
                locktime: tx.lock_time,
                inputs: slice_convert_alloc(&tx.input[..]),
                num_inputs: tx.input.len(),
                inputs_allocation_len: tx.input.len(),
                outputs: slice_convert_alloc(&tx.output[..]),
                num_outputs: tx.output.len(),
                outputs_allocation_len: tx.output.len(),
            }
        }
    }

    impl Drop for WallyTx {
        fn drop(&mut self) {
            unsafe {
                slice_drop(&mut self.inputs, self.num_inputs);
                slice_drop(&mut self.outputs, self.num_outputs);
            }
        }
    }

    extern "C" {
        //WALLY_CORE_API int bip39_mnemonic_from_bytes(
        //    const struct words *w,
        //    const unsigned char *bytes,
        //    size_t bytes_len,
        //    char **output);
        pub fn bip39_mnemonic_from_bytes(
            word_list: *const c_void,
            bytes: *const c_uchar,
            bytes_len: size_t,
            output: *mut *const c_char,
        ) -> c_int;

        //WALLY_CORE_API int bip39_mnemonic_to_bytes(
        //    const struct words *w,
        //    const char *mnemonic,
        //    unsigned char *bytes_out,
        //    size_t len,
        //    size_t *written);
        pub fn bip39_mnemonic_to_bytes(
            word_list: *const c_void,
            mnemonic: *const c_char,
            bytes_out: *mut c_uchar,
            len: size_t,
            written: *mut size_t,
        ) -> c_int;

        //WALLY_CORE_API int bip39_mnemonic_to_seed(
        //    const char *mnemonic,
        //    const char *passphrase,
        //    unsigned char *bytes_out,
        //    size_t len,
        //    size_t *written);
        pub fn bip39_mnemonic_to_seed(
            mnemonic: *const c_char,
            passphrase: *const c_char,
            bytes_out: *mut c_uchar,
            len: size_t,
            written: *mut size_t,
        ) -> c_int;

        //WALLY_CORE_API int bip39_mnemonic_validate(
        //    const struct words *w,
        //    const char *mnemonic);
        pub fn bip39_mnemonic_validate(word_list: *const c_void, mnemonic: *const c_char) -> c_int;

        //  const struct wally_tx *tx,
        //  size_t index,
        //  const unsigned char *script, size_t script_len,
        //  const unsigned char *value, size_t value_len,
        //  uint32_t sighash, uint32_t flags,
        //  unsigned char *bytes_out, size_t len)
        pub fn wally_tx_get_elements_signature_hash(
            tx: *const WallyTx,
            index: usize,
            script: *const c_uchar,
            script_len: usize,
            value: *const c_uchar,
            value_len: usize,
            sighash: u32,
            flags: u32,
            bytes_out: *mut c_uchar,
            len: usize,
        ) -> c_int;

        //WALLY_CORE_API int wally_asset_blinding_key_from_seed(
        //    const unsigned char *bytes,
        //    size_t bytes_len,
        //    unsigned char *bytes_out,
        //    size_t len);
        pub fn wally_asset_blinding_key_from_seed(
            bytes: *const c_uchar,
            bytes_len: size_t,
            bytes_out: *mut c_uchar,
            len: size_t,
        ) -> c_int;

        //WALLY_CORE_API int wally_asset_blinding_key_to_ec_private_key(
        //    const unsigned char *bytes,
        //    size_t bytes_len,
        //    const unsigned char *script,
        //    size_t script_len,
        //    unsigned char *bytes_out,
        //    size_t len);
        //    }
        pub fn wally_asset_blinding_key_to_ec_private_key(
            bytes: *const c_uchar,
            bytes_len: size_t,
            script: *const c_uchar,
            script_len: size_t,
            bytes_out: *mut c_uchar,
            len: size_t,
        ) -> c_int;
    }
}

/// The max entropy size in bytes for BIP39 mnemonics.
const BIP39_MAX_ENTROPY_BYTES: usize = 32;
/// The size of BIP39-derived seeds in bytes.
const BIP39_SEED_BYTES: usize = 64;

/// Generate a BIP39 mnemonic from entropy bytes.
pub fn bip39_mnemonic_from_bytes(entropy: &[u8]) -> String {
    let mut out = ptr::null();
    let ret = unsafe {
        ffi::bip39_mnemonic_from_bytes(ptr::null(), entropy.as_ptr(), entropy.len(), &mut out)
    };
    assert_eq!(ret, ffi::WALLY_OK);
    read_str(out)
}

/// Validate the validity of a BIP-39 mnemonic.
pub fn bip39_mnemonic_validate(mnemonic: &str) -> Result<(), Error> {
    let ret = unsafe { ffi::bip39_mnemonic_validate(ptr::null(), make_str(mnemonic)) };
    if ret == ffi::WALLY_OK {
        Ok(())
    } else {
        Err(Error::InvalidMnemonic)
    }
}

/// Convert the mnemonic back into the entropy bytes.
pub fn bip39_mnemonic_to_bytes(mnemonic: &str) -> Result<Vec<u8>, Error> {
    bip39_mnemonic_validate(mnemonic)?;

    let c_mnemonic = make_str(mnemonic);
    let mut out = Vec::with_capacity(BIP39_MAX_ENTROPY_BYTES);
    let mut written = 0usize;
    let ret = unsafe {
        ffi::bip39_mnemonic_to_bytes(
            ptr::null(),
            c_mnemonic,
            out.as_mut_ptr(),
            BIP39_MAX_ENTROPY_BYTES,
            &mut written,
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    assert!(written <= BIP39_MAX_ENTROPY_BYTES);
    unsafe {
        out.set_len(written);
    }
    Ok(out)
}

/// Convert the mnemonic phrase and passphrase to a binary seed.
pub fn bip39_mnemonic_to_seed(
    mnemonic: &str,
    passphrase: &str,
) -> Result<[u8; BIP39_SEED_BYTES], Error> {
    bip39_mnemonic_validate(mnemonic)?;

    let c_mnemonic = make_str(mnemonic);
    let c_passphrase = make_str(passphrase);
    let mut out = [0u8; BIP39_SEED_BYTES];
    let mut written = 0usize;
    let ret = unsafe {
        ffi::bip39_mnemonic_to_seed(
            c_mnemonic,
            c_passphrase,
            out.as_mut_ptr(),
            BIP39_SEED_BYTES,
            &mut written,
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    assert_eq!(written, BIP39_SEED_BYTES);
    Ok(out)
}

pub fn tx_get_elements_signature_hash(
    tx: &elements::Transaction,
    index: usize,
    script: &[u8],
    value: &elements::confidential::Value,
    sighash: u32,
    flags: u32,
) -> sha256d::Hash {
    let wally_tx = tx.into();
    let value = serialize(value);
    let mut out = [0u8; 32];
    let ret = unsafe {
        ffi::wally_tx_get_elements_signature_hash(
            &wally_tx,
            index,
            script.as_ptr(),
            script.len(),
            value.as_ptr(),
            value.len(),
            sighash,
            flags,
            out.as_mut_ptr(),
            32,
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    //TODO(stevenroose) use from_inner with hashes 0.7
    sha256d::Hash::from_slice(&out[..]).unwrap()
}

pub fn asset_blinding_key_from_seed(seed: &[u8]) -> [u8; 64] {
    assert_eq!(seed.len(), 64);
    let mut out = [0; 64];
    let ret = unsafe {
        ffi::wally_asset_blinding_key_from_seed(
            seed.as_ptr(),
            seed.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    out
}

pub fn asset_blinding_key_to_ec_private_key(
    master_blinding_key: &[u8; 64],
    script_pubkey: &bitcoin::Script,
) -> secp256k1::SecretKey {
    let mut out = [0; 32];
    let ret = unsafe {
        ffi::wally_asset_blinding_key_to_ec_private_key(
            master_blinding_key.as_ptr(),
            master_blinding_key.len(),
            script_pubkey.as_bytes().as_ptr(),
            script_pubkey.as_bytes().len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    secp256k1::SecretKey::from_slice(&out).expect("size is 32")
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_bip39_mnemonic_to_seed() {
        // test vector from the BIP spec
        let v_entropy = "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c";
        let v_mnem = "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length";
        let v_seed = "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440";
        let v_passphrase = "TREZOR";

        let mnemonic = bip39_mnemonic_from_bytes(&hex::decode(v_entropy).unwrap());
        assert_eq!(mnemonic, v_mnem);
        assert!(bip39_mnemonic_validate(&mnemonic).is_ok());
        assert_eq!(hex::encode(&bip39_mnemonic_to_bytes(&mnemonic).unwrap()), v_entropy);
        let seed = bip39_mnemonic_to_seed(&mnemonic, &v_passphrase).unwrap();
        assert_eq!(v_seed, &hex::encode(&seed[..]));
    }
}
