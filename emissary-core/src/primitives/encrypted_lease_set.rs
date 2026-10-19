// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.


//! Encrypted lease set.
//!
//! https://geti2p.net/spec/encryptedleaseset

use crate::{
    crypto::{
        blinding::{date_string, next_midnight, BlindedPublicKey, SIG_TYPE_REDDSA_SHA512_ED25519},
        hmac::hkdf,
        SigningPrivateKey, SigningPublicKey,
    },
    error::parser::LeaseSetParseError,
    primitives::{LeaseSet2, OfflineSignature},
    runtime::Runtime,
};

use bytes::{BufMut, BytesMut};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
    ChaCha20,
};
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32},
    Err, IResult,
};
use rand::Rng;

use alloc::vec::Vec;
use core::time::Duration;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::primitives::encrypted-lease-set";

/// Database store type of a standard lease set.
const STORE_TYPE_LEASESET2: u8 = 3u8;

/// Database store type of an encrypted lease set.
const STORE_TYPE_ENCRYPTED_LEASESET2: u8 = 5u8;

/// Length of the layer salts.
const SALT_LEN: usize = 32usize;

/// Length of the derived key and IV of a layer.
const KEY_IV_LEN: usize = 44usize;

/// Size of the layer 1 flags.
const LAYER1_FLAGS_LEN: usize = 1usize;

/// Lease set is signed with offline keys.
const FLAG_OFFLINE_KEYS: u16 = 1u16;

/// Layer 1 flag for per-client authorization.
const LAYER1_FLAG_CLIENT_AUTH: u8 = 1u8;

/// Length of a RedDSA signature.
const SIGNATURE_LEN: usize = 64usize;

/// Smallest valid outer ciphertext: outer salt, layer 1 flags, inner salt, inner type byte and
/// at least one byte of inner lease set.
const MIN_OUTER_CIPHERTEXT_LEN: usize = SALT_LEN + LAYER1_FLAGS_LEN + SALT_LEN + 2usize;

/// Encrypt or decrypt `data` in place with ChaCha20, using the key and IV derived for a layer.
///
/// The block counter starts at one, as in RFC 7539.
fn chacha20(key_iv: &[u8], data: &mut [u8]) {
    let mut cipher = ChaCha20::new(key_iv[..32].into(), key_iv[32..44].into());
    cipher.seek(64u64);
    cipher.apply_keystream(data);
}

/// Encrypted lease set.
///
/// The outer layer is parsed and its signature is verified with the blinded key, the
/// payload can be decrypted with [`EncryptedLeaseSet2::decrypt()`] if the blinded public key
/// of the destination is known.
#[derive(Debug, Clone)]
pub struct EncryptedLeaseSet2 {
    /// Blinded public key the lease set is signed with.
    pub blinded_public_key: [u8; 32],

    /// When the lease set expires, seconds since epoch.
    pub expires: u32,

    /// Transient key which signed the lease set, if offline keys are used.
    offline_key: Option<SigningPublicKey>,

    /// Outer ciphertext, including its salt.
    outer_ciphertext: Vec<u8>,

    /// When the lease set was published, seconds since epoch.
    pub published: u32,
}

impl EncryptedLeaseSet2 {
    /// Attempt to parse [`EncryptedLeaseSet2`] from `input`, verifying its signature.
    ///
    /// Returns the parsed lease set and rest of `input` on success.
    pub fn parse_frame<R: Runtime>(
        input: &[u8],
    ) -> IResult<&[u8], Self, LeaseSetParseError> {
        let (rest, blinded_sig_type) = be_u16(input)?;

        if blinded_sig_type != SIG_TYPE_REDDSA_SHA512_ED25519 {
            return Err(Err::Error(LeaseSetParseError::UnsupportedBlindedKeyType(
                blinded_sig_type,
            )));
        }

        let (rest, blinded_public_key) = take(32usize)(rest)?;
        let blinded_public_key: [u8; 32] = blinded_public_key.try_into().expect("32 bytes");
        let verifying_key = SigningPublicKey::from_bytes(&blinded_public_key)
            .ok_or(Err::Error(LeaseSetParseError::InvalidBlindedKey))?;

        let (rest, published) = be_u32(rest)?;
        let (rest, expires) = be_u16(rest)?;
        let (rest, flags) = be_u16(rest)?;

        let (rest, offline_key) = if flags & FLAG_OFFLINE_KEYS != 0 {
            let (rest, key) =
                OfflineSignature::parse_frame::<R>(rest, &verifying_key).map_err(Err::convert)?;

            (rest, Some(key))
        } else {
            (rest, None)
        };

        let (rest, outer_len) = be_u16(rest)?;
        let (rest, outer_ciphertext) = take(outer_len as usize)(rest)?;

        if outer_ciphertext.len() < MIN_OUTER_CIPHERTEXT_LEN {
            return Err(Err::Error(LeaseSetParseError::InvalidCiphertext));
        }

        let signed_len = input.len() - rest.len();
        let (rest, signature) = take(SIGNATURE_LEN)(rest)?;

        let mut signed = BytesMut::with_capacity(signed_len + 1);
        signed.put_u8(STORE_TYPE_ENCRYPTED_LEASESET2);
        signed.put_slice(&input[..signed_len]);

        offline_key
            .as_ref()
            .unwrap_or(&verifying_key)
            .verify(&signed, signature)
            .map_err(|_| Err::Error(LeaseSetParseError::InvalidSignature))?;

        Ok((
            rest,
            Self {
                blinded_public_key,
                expires: published.saturating_add(expires as u32),
                offline_key,
                outer_ciphertext: outer_ciphertext.to_vec(),
                published,
            },
        ))
    }

    /// Attempt to parse `input` into [`EncryptedLeaseSet2`].
    pub fn parse<R: Runtime>(input: &[u8]) -> Result<Self, LeaseSetParseError> {
        Ok(Self::parse_frame::<R>(input)?.1)
    }

    /// Has the lease set expired.
    pub fn is_expired<R: Runtime>(&self) -> bool {
        (self.expires as u64) < R::time_since_epoch().as_secs()
    }

    /// When does the lease set expire, as duration since epoch.
    pub fn expires(&self) -> Duration {
        Duration::from_secs(self.expires as u64)
    }

    /// Is the lease set signed with offline keys.
    pub fn is_offline_signed(&self) -> bool {
        self.offline_key.is_some()
    }

    /// Decrypt the lease set of the destination identified by `key`.
    ///
    /// The blinded key of the lease set must be the blinded key of `key` for the day the lease
    /// set was published. Lease sets encrypted per client are not supported.
    pub fn decrypt<R: Runtime>(
        &self,
        key: &BlindedPublicKey,
    ) -> Result<LeaseSet2, LeaseSetParseError> {
        let date = date_string(Duration::from_secs(self.published as u64));

        if key.blinded_key(&date) != Some(self.blinded_public_key) {
            tracing::debug!(
                target: LOG_TARGET,
                ?key,
                "blinded public key doesn't match",
            );
            return Err(LeaseSetParseError::BlindedKeyMismatch);
        }

        // outerInput = subcredential || publishedTimestamp
        let mut layer_input = [0u8; 36];
        layer_input[..32].copy_from_slice(&key.subcredential(&self.blinded_public_key));
        layer_input[32..].copy_from_slice(&self.published.to_be_bytes());

        // layer 1
        let (outer_salt, outer_ciphertext) = self.outer_ciphertext.split_at(SALT_LEN);
        let mut outer = outer_ciphertext.to_vec();
        chacha20(&hkdf(outer_salt, &layer_input, b"ELS2_L1K", KEY_IV_LEN), &mut outer);

        if outer[0] & LAYER1_FLAG_CLIENT_AUTH != 0 {
            tracing::debug!(
                target: LOG_TARGET,
                ?key,
                flags = ?outer[0],
                "lease set requires per-client authorization",
            );
            return Err(LeaseSetParseError::ClientAuthorizationRequired);
        }

        // layer 2
        let (inner_salt, inner_ciphertext) = outer[LAYER1_FLAGS_LEN..].split_at(SALT_LEN);
        let mut inner = inner_ciphertext.to_vec();
        chacha20(&hkdf(inner_salt, &layer_input, b"ELS2_L2K", KEY_IV_LEN), &mut inner);

        match inner[0] {
            STORE_TYPE_LEASESET2 => LeaseSet2::parse::<R>(&inner[1..]),
            inner_type => Err(LeaseSetParseError::UnsupportedInnerType(inner_type)),
        }
    }

    /// Encrypt `lease_set`, a serialized [`LeaseSet2`] without the store type byte, for its
    /// destination whose signing key is `signing_key`.
    ///
    /// `expires` is when the inner lease set expires, seconds since epoch. The encrypted lease
    /// set expires at the latest at the next UTC midnight since the blinded key changes daily.
    ///
    /// Returns `None` if the signing key cannot be blinded.
    pub fn encrypt<R: Runtime>(
        lease_set: &[u8],
        expires: u32,
        signing_key: &SigningPrivateKey,
    ) -> Option<EncryptedLeaseSet2Bundle> {
        Self::encrypt_with_flags::<R>(lease_set, expires, signing_key, 0u8)
    }

    /// Encrypt `lease_set` with `layer1_flags`.
    fn encrypt_with_flags<R: Runtime>(
        lease_set: &[u8],
        expires: u32,
        signing_key: &SigningPrivateKey,
        layer1_flags: u8,
    ) -> Option<EncryptedLeaseSet2Bundle> {
        let now = R::time_since_epoch();
        let date = date_string(now);
        let blinded = BlindedPublicKey::new(&signing_key.public())?;
        let signer = blinded.blind_private_key(signing_key, &date)?;
        let store_hash = blinded.store_hash(&date)?;

        let published = now.as_secs() as u32;
        let expires = expires.min(next_midnight(now).as_secs() as u32).max(published);
        let expires_in = (expires - published).min(u16::MAX as u32) as u16;

        let mut layer_input = [0u8; 36];
        layer_input[..32].copy_from_slice(&blinded.subcredential(signer.public_key()));
        layer_input[32..].copy_from_slice(&published.to_be_bytes());

        // layer 2: inner salt || ENCRYPT(type || lease set)
        let mut inner_salt = [0u8; SALT_LEN];
        R::rng().fill_bytes(&mut inner_salt);

        let mut inner = Vec::with_capacity(1 + lease_set.len());
        inner.push(STORE_TYPE_LEASESET2);
        inner.extend_from_slice(lease_set);
        chacha20(&hkdf(&inner_salt, &layer_input, b"ELS2_L2K", KEY_IV_LEN), &mut inner);

        // layer 1: outer salt || ENCRYPT(flags || inner salt || inner ciphertext)
        let mut outer_salt = [0u8; SALT_LEN];
        R::rng().fill_bytes(&mut outer_salt);

        let mut outer = Vec::with_capacity(LAYER1_FLAGS_LEN + SALT_LEN + inner.len());
        outer.push(layer1_flags);
        outer.extend_from_slice(&inner_salt);
        outer.extend_from_slice(&inner);
        chacha20(&hkdf(&outer_salt, &layer_input, b"ELS2_L1K", KEY_IV_LEN), &mut outer);

        let mut out = BytesMut::with_capacity(
            1 + 2 + 32 + 4 + 2 + 2 + 2 + SALT_LEN + outer.len() + SIGNATURE_LEN,
        );
        out.put_u8(STORE_TYPE_ENCRYPTED_LEASESET2);
        out.put_u16(SIG_TYPE_REDDSA_SHA512_ED25519);
        out.put_slice(signer.public_key());
        out.put_u32(published);
        out.put_u16(expires_in);
        out.put_u16(0u16); // flags
        out.put_u16((SALT_LEN + outer.len()) as u16);
        out.put_slice(&outer_salt);
        out.put_slice(&outer);

        let signature = signer.sign::<R>(&out);
        out.put_slice(&signature);

        Some(EncryptedLeaseSet2Bundle {
            expires: Duration::from_secs(published as u64 + expires_in as u64),
            payload: out[1..].to_vec(),
            store_hash,
        })
    }
}

/// Encrypted lease set ready to be published.
#[derive(Debug, Clone)]
pub struct EncryptedLeaseSet2Bundle {
    /// When the encrypted lease set expires, as duration since epoch.
    pub expires: Duration,

    /// Serialized encrypted lease set, without the store type byte.
    pub payload: Vec<u8>,

    /// Key under which the lease set is stored in NetDb.
    pub store_hash: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    #[test]
    fn encrypt_and_decrypt() {
        let (lease_set, signing_key) = LeaseSet2::random();
        let destination_id = lease_set.header.destination.id();
        let serialized = lease_set.serialize(&signing_key);
        let original = LeaseSet2::parse::<MockRuntime>(&serialized).unwrap();
        let inner_expires = original.header.expires;

        let bundle =
            EncryptedLeaseSet2::encrypt::<MockRuntime>(&serialized, inner_expires, &signing_key)
                .unwrap();
        let blinded = BlindedPublicKey::new(&signing_key.public()).unwrap();
        let now = MockRuntime::time_since_epoch();
        assert_eq!(
            bundle.store_hash,
            blinded.store_hash(&date_string(now)).unwrap()
        );
        assert!(bundle.expires <= next_midnight(now));
        assert!(bundle.expires > now);

        let (rest, encrypted) =
            EncryptedLeaseSet2::parse_frame::<MockRuntime>(&bundle.payload).unwrap();
        assert!(rest.is_empty());
        assert!(!encrypted.is_expired::<MockRuntime>());
        assert!(!encrypted.is_offline_signed());
        assert_eq!(encrypted.expires(), bundle.expires);
        assert_eq!(
            encrypted.blinded_public_key,
            blinded.blinded_key(&date_string(now)).unwrap()
        );

        let decrypted = encrypted.decrypt::<MockRuntime>(&blinded).unwrap();
        assert_eq!(decrypted.header.destination.id(), destination_id);
        assert_eq!(decrypted.header.expires, inner_expires);
        assert_eq!(decrypted.leases.len(), original.leases.len());
        assert_eq!(decrypted.public_keys.len(), original.public_keys.len());

        // the key of another destination can't decrypt it
        let other = BlindedPublicKey::new(&SigningPrivateKey::random(MockRuntime::rng()).public())
            .unwrap();
        assert_eq!(
            encrypted.decrypt::<MockRuntime>(&other).err(),
            Some(LeaseSetParseError::BlindedKeyMismatch)
        );

        // a key parsed from the b33 address works too
        let from_address = BlindedPublicKey::from_b33(&blinded.to_b33()).unwrap();
        assert!(encrypted.decrypt::<MockRuntime>(&from_address).is_ok());
    }

    #[test]
    fn tampering_is_detected() {
        let (lease_set, signing_key) = LeaseSet2::random();
        let expires = lease_set.header.expires;
        let bundle = EncryptedLeaseSet2::encrypt::<MockRuntime>(
            &lease_set.serialize(&signing_key),
            expires,
            &signing_key,
        )
        .unwrap();
        assert!(EncryptedLeaseSet2::parse::<MockRuntime>(&bundle.payload).is_ok());

        // every byte is covered by the signature
        for i in 0..bundle.payload.len() - SIGNATURE_LEN {
            let mut payload = bundle.payload.clone();
            payload[i] ^= 0x01;

            if i < 2 {
                assert_eq!(
                    EncryptedLeaseSet2::parse::<MockRuntime>(&payload).err(),
                    Some(LeaseSetParseError::UnsupportedBlindedKeyType(u16::from_be_bytes([
                        payload[0], payload[1]
                    ])))
                );
            } else {
                let result = EncryptedLeaseSet2::parse::<MockRuntime>(&payload);
                assert!(result.is_err(), "byte {i} tampered, parse succeeded");

                // flags and the outer ciphertext length change the structure of the message so
                // any error is fine, everything else must fail the signature check
                if !(40..44).contains(&i) {
                    assert!(
                        matches!(
                            result,
                            Err(LeaseSetParseError::InvalidSignature
                                | LeaseSetParseError::InvalidBlindedKey)
                        ),
                        "byte {i} tampered, unexpected error {result:?}"
                    );
                }
            }
        }

        // a corrupted signature and a truncated payload are rejected
        let mut payload = bundle.payload.clone();
        let last = payload.len() - 1;
        payload[last] ^= 0x01;
        assert_eq!(
            EncryptedLeaseSet2::parse::<MockRuntime>(&payload).err(),
            Some(LeaseSetParseError::InvalidSignature)
        );
        assert!(
            EncryptedLeaseSet2::parse::<MockRuntime>(&bundle.payload[..bundle.payload.len() - 1])
                .is_err()
        );
        assert!(EncryptedLeaseSet2::parse::<MockRuntime>(&[]).is_err());
    }

    #[test]
    fn client_authorization_not_supported() {
        let (lease_set, signing_key) = LeaseSet2::random();
        let expires = lease_set.header.expires;
        let bundle = EncryptedLeaseSet2::encrypt_with_flags::<MockRuntime>(
            &lease_set.serialize(&signing_key),
            expires,
            &signing_key,
            LAYER1_FLAG_CLIENT_AUTH,
        )
        .unwrap();
        let blinded = BlindedPublicKey::new(&signing_key.public()).unwrap();

        let encrypted = EncryptedLeaseSet2::parse::<MockRuntime>(&bundle.payload).unwrap();
        assert_eq!(
            encrypted.decrypt::<MockRuntime>(&blinded).err(),
            Some(LeaseSetParseError::ClientAuthorizationRequired)
        );
    }

    #[test]
    fn expiration_capped_at_midnight() {
        // 2023-11-14 22:13:20 UTC
        let now = Duration::from_secs(1_700_000_000);
        MockRuntime::set_time(Some(now));

        let (lease_set, signing_key) = LeaseSet2::random();
        let serialized = lease_set.serialize(&signing_key);

        // inner lease set expires after midnight
        let bundle = EncryptedLeaseSet2::encrypt::<MockRuntime>(
            &serialized,
            (now + Duration::from_secs(10 * 60 * 60)).as_secs() as u32,
            &signing_key,
        )
        .unwrap();
        assert_eq!(bundle.expires, next_midnight(now));

        let encrypted = EncryptedLeaseSet2::parse::<MockRuntime>(&bundle.payload).unwrap();
        assert_eq!(encrypted.published, now.as_secs() as u32);
        assert_eq!(encrypted.expires(), next_midnight(now));

        // inner lease set expires before midnight
        let bundle = EncryptedLeaseSet2::encrypt::<MockRuntime>(
            &serialized,
            (now + Duration::from_secs(600)).as_secs() as u32,
            &signing_key,
        )
        .unwrap();
        assert_eq!(bundle.expires, now + Duration::from_secs(600));

        // the lease set is decryptable with the key of its publication day only
        let blinded = BlindedPublicKey::new(&signing_key.public()).unwrap();
        let encrypted = EncryptedLeaseSet2::parse::<MockRuntime>(&bundle.payload).unwrap();
        assert!(encrypted.decrypt::<MockRuntime>(&blinded).is_ok());
        assert_ne!(
            blinded.blinded_key(&date_string(next_midnight(now))),
            Some(encrypted.blinded_public_key)
        );

        MockRuntime::set_time(None);
    }
}
