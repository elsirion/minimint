//! Scheme for deriving deterministic secret keys

use std::fmt::Formatter;

use fedimint_core::encoding::{Decodable, Encodable};
use hkdf::hashes::Sha512;
use hkdf::{bitcoin_hashes, Hkdf};
use ring::aead;
use secp256k1_zkp::{KeyPair, Secp256k1, Signing};
use tbs::Scalar;

const CHILD_TAG: &[u8; 8] = b"childkey";
const SECP256K1_TAG: &[u8; 8] = b"secp256k";
const BLS12_381_TAG: &[u8; 8] = b"bls12381";
const CHACHA20_POLY1305: &[u8; 8] = b"c20p1305";
const RAW_BYTES: &[u8; 8] = b"rawbytes";

/// Describes a child key of a [`DerivableSecret`]
#[derive(Debug, Copy, Clone, Encodable, Decodable)]
pub struct ChildId(pub u64);

/// Secret key that allows deriving child secret keys
#[derive(Clone)]
pub struct DerivableSecret {
    /// Derivation level, root = 0, every `child_key` increments it
    level: usize,
    // TODO: wrap in some secret protecting wrappers maybe?
    kdf: Hkdf<Sha512>,
}

impl DerivableSecret {
    pub fn new_root(root_key: &[u8], salt: &[u8]) -> Self {
        DerivableSecret {
            level: 0,
            kdf: Hkdf::new(root_key, Some(salt)),
        }
    }

    /// Get derivation level
    ///
    ///
    /// This is useful for ensuring a correct derivation level is used,
    /// in various places.
    ///
    /// Root keys start at `0`, and every derived key increments it.
    pub fn level(&self) -> usize {
        self.level
    }

    pub fn child_key(&self, cid: ChildId) -> DerivableSecret {
        DerivableSecret {
            level: self.level + 1,
            kdf: Hkdf::from_prk(self.kdf.derive_hmac(&tagged_derive(CHILD_TAG, cid))),
        }
    }

    pub fn to_secp_key<C: Signing>(self, ctx: &Secp256k1<C>) -> KeyPair {
        for key_try in 0u64.. {
            let secret = self
                .kdf
                .derive::<32>(&tagged_derive(SECP256K1_TAG, ChildId(key_try)));
            // The secret not forming a valid key is highly unlikely, this approach is the
            // same used when generating a random secp key.
            if let Ok(key) = KeyPair::from_seckey_slice(ctx, &secret) {
                return key;
            }
        }

        unreachable!("If key generation fails this often something else has to be wrong.")
    }

    pub fn to_bls12_381_key(&self) -> Scalar {
        Scalar::from_bytes_wide(&self.kdf.derive(&tagged_derive(BLS12_381_TAG, ChildId(0))))
    }

    // `ring` does not support any way to get raw bytes from a key,
    // so we need to be able to get just the raw bytes here, so we can serialize
    // them, and convert to ring type from it.
    pub fn to_chacha20_poly1305_key_raw(&self) -> [u8; 32] {
        self.kdf
            .derive::<32>(&tagged_derive(CHACHA20_POLY1305, ChildId(0)))
    }

    pub fn to_chacha20_poly1305_key(&self) -> aead::UnboundKey {
        aead::UnboundKey::new(
            &aead::CHACHA20_POLY1305,
            &self.to_chacha20_poly1305_key_raw(),
        )
        .expect("created key")
    }

    /// Generate a pseudo-random byte array from the derivable secret.
    pub fn to_random_bytes<const LEN: usize>(&self) -> [u8; LEN] {
        self.kdf.derive(&tagged_derive(RAW_BYTES, ChildId(0)))
    }
}

fn tagged_derive(tag: &[u8; 8], derivation: ChildId) -> [u8; 16] {
    let mut derivation_info = [0u8; 16];
    derivation_info[0..8].copy_from_slice(&tag[..]);
    derivation_info[8..16].copy_from_slice(&derivation.0.to_le_bytes()[..]);
    derivation_info
}

impl std::fmt::Debug for DerivableSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DerivableSecret#")?;
        bitcoin_hashes::hex::format_hex(
            &self
                .kdf
                .derive::<8>(b"just a debug fingerprint derivation salt"),
            f,
        )
    }
}
