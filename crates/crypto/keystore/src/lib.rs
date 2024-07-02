#![doc(
    html_logo_url = "https://github.com/supernovahs/eigensdk-rs/assets/91280922/bd13caec-3c00-4afc-839a-b83d2890beb5",
    issue_tracker_base_url = "https://github.com/supernovahs/eigen-rs/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use aes::{
    cipher::{InnerIvInit, KeyInit, StreamCipherCore},
    Aes128,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{fields::PrimeField, Field};
use eth_keystore::{CryptoJson, KdfparamsType};
use ethers::{signers::LocalWallet, utils::keccak256, types::H256};
use eyre::{eyre, Ok, Report};
use rand::{thread_rng, RngCore};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, fs::File, io::Read, path::Path};

use eigen_crypto_bls::{BlsKeypair, PrivateKey, PublicKey};

#[derive(Default)]
pub struct EncodedKeystore {
    encrypted_keystore: Option<Keystore>,
    password: Option<String>,
}

impl EncodedKeystore {
    pub fn from_path<P>(path: &P, password: Option<String>) -> eyre::Result<Self>
    where
        P: AsRef<Path>,
    {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let keystore: Keystore = serde_json::from_str(&contents)?;
        Ok(Self {
            encrypted_keystore: Some(keystore),
            password,
        })
    }

    pub fn from_string(contents: String, password: Option<String>) -> eyre::Result<Self> {
        let keystore: Keystore = serde_json::from_str(&contents)?;
        Ok(Self {
            encrypted_keystore: Some(keystore),
            password,
        })
    }

    pub fn random() -> eyre::Result<Self> {
        Ok(Self::default())
    }

    pub fn into_bls_keypair(self) -> eyre::Result<BlsKeypair> {
        let fr = if let Some(keystore) = self.encrypted_keystore {
            let secret = decrypt_key(keystore, self.password.unwrap_or_default())?;
            PrivateKey::from_be_bytes_mod_order(&secret)
        } else {
            let rnd = &mut [0_u8; 32];
            let mut rng = thread_rng();
            loop {
                rng.fill_bytes(rnd);
                if let Some(key) = PrivateKey::from_random_bytes(rnd) {
                    break key;
                }
            }
        };
        let p = PublicKey::generator() * fr;

        Ok(BlsKeypair {
            private: fr,
            public: p.into_affine(),
        })
    }

    pub fn into_wallet(self) -> eyre::Result<LocalWallet> {
        if let Some(keystore) = self.encrypted_keystore {
            let secret = decrypt_key(keystore, self.password.unwrap_or_default())?;
            Ok(LocalWallet::from_bytes(&secret)?)
        } else {
            Ok(LocalWallet::new(&mut thread_rng()))
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Keystore {
    crypto: CryptoJson,
}

fn decrypt_key<S>(keystore: Keystore, password: S) -> eyre::Result<Vec<u8>>
where
    S: AsRef<[u8]>,
{
    // Derive the key.
    let key = match keystore.crypto.kdfparams {
        KdfparamsType::Pbkdf2 { .. } => {
            return Err(Report::msg("Pbkdf2 not supported"));
        }
        KdfparamsType::Scrypt {
            dklen,
            n,
            p,
            r,
            salt,
        } => {
            let mut key = vec![0u8; dklen as usize];
            let log_n = (n as f32).log2() as u8;
            let scrypt_params = ScryptParams::new(log_n, r, p)?;
            scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;
            key
        }
    };

    // Derive the MAC from the derived key and ciphertext.
    let derived_mac: H256 = keccak256(
        [&key[16..32], &keystore.crypto.ciphertext]
            .concat()
    ).into();

    if derived_mac.as_bytes() != keystore.crypto.mac.as_slice() {
        return Err(eyre!("MacMismatch"));
    }

    // Decrypt the private key bytes using AES-128-CTR
    let decryptor =
        Aes128Ctr::new(&key[..16], &keystore.crypto.cipherparams.iv[..16]).expect("invalid length");

    let mut pk = keystore.crypto.ciphertext;
    decryptor.apply_keystream(&mut pk);

    Ok(pk)
}

struct Aes128Ctr {
    inner: ctr::CtrCore<Aes128, ctr::flavors::Ctr128BE>,
}

impl Aes128Ctr {
    fn new(key: &[u8], iv: &[u8]) -> eyre::Result<Self> {
        let cipher = aes::Aes128::new_from_slice(key).unwrap();
        let inner = ctr::CtrCore::inner_iv_slice_init(cipher, iv)?;
        Ok(Self { inner })
    }

    fn apply_keystream(self, buf: &mut [u8]) {
        self.inner.apply_keystream_partial(buf.into());
    }
}
