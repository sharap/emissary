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

//! Offline signatures and transient signing keys.
//!
//! https://geti2p.net/spec/common-structures#struct-offlinesignature

use crate::{
    crypto::{SigningPrivateKey, SigningPublicKey},
    error::parser::OfflineSignatureParseError,
    runtime::Runtime,
};

use bytes::{BufMut, Bytes, BytesMut};
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32},
    Err, IResult,
};

use alloc::vec::Vec;
use core::fmt;

/// Signature kind for `EdDSA_SHA512_Ed25519`.
///
/// https://geti2p.net/spec/common-structures#key-certificates
const SIGNATURE_KIND_EDDSA_SHA512_ED25519: u16 = 0x0007;

/// Signature kind for `ECDSA_SHA256_P256`.
///
/// https://geti2p.net/spec/common-structures#key-certificates
const SIGNATURE_KIND_ECDSA_SHA256_P256: u16 = 0x0001;

/// Length of the fixed part of the section: expiration + signature kind.
const HEADER_LEN: usize = 4 + 2;

/// Length of an Ed25519 private key.
const ED25519_PRIVATE_KEY_LEN: usize = 32;

/// Offline signature section.
///
/// Contains an expiration, a transient signing public key and a signature of both, made with the
/// signing key of a destination. Anything the destination would normally sign (lease sets,
/// streaming packets, datagrams) is signed with the transient key instead while the section is
/// valid, allowing the destination's own key to stay offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineSignature {
    /// When the transient key expires, seconds since epoch.
    expires: u32,

    /// Serialized section: expiration, signature kind, transient public key and signature.
    serialized: Bytes,

    /// Transient signing public key.
    transient_key: SigningPublicKey,
}

impl OfflineSignature {
    /// Attempt to parse [`OfflineSignature`] from `input` and verify the signature using `key`.
    ///
    /// Returns the parsed section and rest of `input` on success.
    pub fn parse_frame<'a, R: Runtime>(
        input: &'a [u8],
        key: &SigningPublicKey,
    ) -> IResult<&'a [u8], Self, OfflineSignatureParseError> {
        let (rest, expires) = be_u32(input)?;

        if R::time_since_epoch().as_secs() > expires as u64 {
            return Err(Err::Error(OfflineSignatureParseError::Expired));
        }

        let (rest, signature_kind) = be_u16(rest)?;

        // extract verifying key from the offline signature
        //
        // this key is used to verify whatever the section is attached to
        let (rest, transient_key, transient_key_len) = match signature_kind {
            SIGNATURE_KIND_EDDSA_SHA512_ED25519 => {
                let (rest, key) = take(32usize)(rest)?;

                // must succeed since `key` has sufficient length
                let transient_key = SigningPublicKey::from_bytes(
                    &TryInto::<[u8; 32]>::try_into(key).expect("to succeed"),
                )
                .ok_or(Err::Error(OfflineSignatureParseError::InvalidPublicKey))?;

                (rest, transient_key, 32usize)
            }
            SIGNATURE_KIND_ECDSA_SHA256_P256 => {
                let (rest, key) = take(64usize)(rest)?;
                let transient_key = SigningPublicKey::p256(key)
                    .ok_or(Err::Error(OfflineSignatureParseError::InvalidPublicKey))?;

                (rest, transient_key, 64usize)
            }
            _ => {
                return Err(Err::Error(
                    OfflineSignatureParseError::UnsupportedPublicKey(signature_kind),
                ));
            }
        };

        // extract offline signature and verify it with the destination's verifying key
        //
        // the signed portion covers expiration + signature kind + verifying key
        let signed_len = HEADER_LEN + transient_key_len;
        let (rest, signature) = take(key.signature_len())(rest)?;

        key.verify(&input[..signed_len], signature)
            .map_err(|_| Err::Error(OfflineSignatureParseError::InvalidSignature))?;

        Ok((
            rest,
            Self {
                expires,
                serialized: Bytes::copy_from_slice(&input[..signed_len + signature.len()]),
                transient_key,
            },
        ))
    }

    /// Attempt to parse [`OfflineSignature`] from `input` and verify it using `key`.
    pub fn parse<R: Runtime>(
        input: &[u8],
        key: &SigningPublicKey,
    ) -> Result<Self, OfflineSignatureParseError> {
        Ok(Self::parse_frame::<R>(input, key)?.1)
    }

    /// Create a new offline signature with a random Ed25519 transient key, signed by
    /// `signing_key` and valid until `expires` (seconds since epoch).
    ///
    /// Returns the section and the transient private key.
    pub fn create<R: Runtime>(
        signing_key: &SigningPrivateKey,
        expires: u32,
    ) -> (Self, SigningPrivateKey) {
        let transient_key = SigningPrivateKey::random(R::rng());
        let transient_public = transient_key.public();

        let mut out = BytesMut::with_capacity(
            HEADER_LEN + transient_public.as_ref().len() + signing_key.signature_len(),
        );
        out.put_u32(expires);
        out.put_u16(SIGNATURE_KIND_EDDSA_SHA512_ED25519);
        out.put_slice(transient_public.as_ref());

        let signature = signing_key.sign(&out);
        out.put_slice(&signature);

        (
            Self {
                expires,
                serialized: out.freeze(),
                transient_key: transient_public,
            },
            transient_key,
        )
    }

    /// When the transient key expires, seconds since epoch.
    pub fn expires(&self) -> u32 {
        self.expires
    }

    /// Has the transient key expired.
    pub fn is_expired<R: Runtime>(&self) -> bool {
        R::time_since_epoch().as_secs() > self.expires as u64
    }

    /// Get the transient signing public key.
    pub fn transient_key(&self) -> &SigningPublicKey {
        &self.transient_key
    }

    /// Get the serialized section.
    pub fn serialized(&self) -> &[u8] {
        &self.serialized
    }

    /// Get length of the serialized section.
    pub fn serialized_len(&self) -> usize {
        self.serialized.len()
    }
}

/// Offline keys of a local destination.
///
/// Consists of the offline signature section and the matching transient private key. The
/// destination's own signing private key is not needed (and not stored) while these are used.
///
/// Serialized form, as stored in private key files after the all-zero signing private key:
/// offline signature section followed by the transient signing private key.
#[derive(Clone)]
pub struct OfflineKeys {
    /// Offline signature.
    signature: OfflineSignature,

    /// Transient signing private key.
    transient_key: SigningPrivateKey,
}

impl OfflineKeys {
    /// Create new offline keys for the destination whose signing key is `signing_key`.
    ///
    /// The transient key is valid until `expires`, seconds since epoch.
    pub fn create<R: Runtime>(signing_key: &SigningPrivateKey, expires: u32) -> Self {
        let (signature, transient_key) = OfflineSignature::create::<R>(signing_key, expires);

        Self {
            signature,
            transient_key,
        }
    }

    /// Attempt to parse [`OfflineKeys`] from `input`, verifying the offline signature with
    /// `key`, the signing public key of the destination.
    ///
    /// Only Ed25519 transient keys are supported.
    pub fn parse_frame<'a, R: Runtime>(
        input: &'a [u8],
        key: &SigningPublicKey,
    ) -> IResult<&'a [u8], Self, OfflineSignatureParseError> {
        let (rest, signature) = OfflineSignature::parse_frame::<R>(input, key)?;

        let SigningPublicKey::Ed25519(_) = signature.transient_key() else {
            return Err(Err::Error(
                OfflineSignatureParseError::UnsupportedPublicKey(SIGNATURE_KIND_ECDSA_SHA256_P256),
            ));
        };

        let (rest, private_key) = take(ED25519_PRIVATE_KEY_LEN)(rest)?;
        let transient_key = SigningPrivateKey::from_bytes(private_key)
            .ok_or(Err::Error(OfflineSignatureParseError::InvalidPrivateKey))?;

        if &transient_key.public() != signature.transient_key() {
            return Err(Err::Error(OfflineSignatureParseError::InvalidPrivateKey));
        }

        Ok((
            rest,
            Self {
                signature,
                transient_key,
            },
        ))
    }

    /// Attempt to parse [`OfflineKeys`] from `input`, verifying them with `key`.
    pub fn parse<R: Runtime>(
        input: &[u8],
        key: &SigningPublicKey,
    ) -> Result<Self, OfflineSignatureParseError> {
        Ok(Self::parse_frame::<R>(input, key)?.1)
    }

    /// Serialize [`OfflineKeys`]: offline signature section followed by the transient private key.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.signature.serialized_len() + ED25519_PRIVATE_KEY_LEN);
        out.extend_from_slice(self.signature.serialized());
        out.extend_from_slice(self.transient_key.as_ref());

        out
    }

    /// Get the offline signature section.
    pub fn signature(&self) -> &OfflineSignature {
        &self.signature
    }

    /// Get the transient signing private key.
    pub fn transient_key(&self) -> &SigningPrivateKey {
        &self.transient_key
    }
}

impl fmt::Debug for OfflineKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfflineKeys")
            .field("signature", &self.signature)
            .finish_non_exhaustive()
    }
}

impl PartialEq for OfflineKeys {
    fn eq(&self, other: &Self) -> bool {
        self.signature == other.signature
            && self.transient_key.as_ref() == other.transient_key.as_ref()
    }
}

impl Eq for OfflineKeys {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    use core::time::Duration;

    fn expires_in(secs: u64) -> u32 {
        (MockRuntime::time_since_epoch() + Duration::from_secs(secs)).as_secs() as u32
    }

    #[test]
    fn create_and_parse() {
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let expires = expires_in(3600);
        let (signature, transient_key) =
            OfflineSignature::create::<MockRuntime>(&signing_key, expires);

        assert_eq!(signature.expires(), expires);
        assert_eq!(signature.serialized_len(), 6 + 32 + 64);
        assert_eq!(signature.transient_key(), &transient_key.public());
        assert!(!signature.is_expired::<MockRuntime>());

        // trailing bytes are left alone
        let mut input = signature.serialized().to_vec();
        input.extend_from_slice(&[1, 2, 3]);

        let (rest, parsed) =
            OfflineSignature::parse_frame::<MockRuntime>(&input, &signing_key.public()).unwrap();
        assert_eq!(rest, &[1, 2, 3]);
        assert_eq!(parsed, signature);
    }

    #[test]
    fn signature_by_wrong_key_rejected() {
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let other = SigningPrivateKey::random(MockRuntime::rng());
        let (signature, _) = OfflineSignature::create::<MockRuntime>(&signing_key, expires_in(60));

        assert_eq!(
            OfflineSignature::parse::<MockRuntime>(signature.serialized(), &other.public())
                .unwrap_err(),
            OfflineSignatureParseError::InvalidSignature
        );
    }

    #[test]
    fn tampered_section_rejected() {
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let (signature, _) =
            OfflineSignature::create::<MockRuntime>(&signing_key, expires_in(3600));
        let serialized = signature.serialized();

        for i in 0..serialized.len() {
            let mut tampered = serialized.to_vec();
            tampered[i] ^= 0x01;

            assert!(
                OfflineSignature::parse::<MockRuntime>(&tampered, &signing_key.public()).is_err(),
                "byte {i} accepted"
            );
        }
    }

    #[test]
    fn expired_section_rejected() {
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let expires = MockRuntime::time_since_epoch().as_secs() as u32 - 1;
        let (signature, _) = OfflineSignature::create::<MockRuntime>(&signing_key, expires);

        assert!(signature.is_expired::<MockRuntime>());
        assert_eq!(
            OfflineSignature::parse::<MockRuntime>(signature.serialized(), &signing_key.public())
                .unwrap_err(),
            OfflineSignatureParseError::Expired
        );
    }

    #[test]
    fn unsupported_transient_key_kind() {
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let mut input = Vec::new();
        input.extend_from_slice(&expires_in(60).to_be_bytes());
        input.extend_from_slice(&0x0003u16.to_be_bytes());
        input.extend_from_slice(&[0u8; 128]);

        assert_eq!(
            OfflineSignature::parse::<MockRuntime>(&input, &signing_key.public()).unwrap_err(),
            OfflineSignatureParseError::UnsupportedPublicKey(3)
        );
    }

    #[test]
    fn offline_keys_round_trip() {
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let keys = OfflineKeys::create::<MockRuntime>(&signing_key, expires_in(3600));
        let serialized = keys.serialize();

        assert_eq!(serialized.len(), 6 + 32 + 64 + 32);

        let (rest, parsed) =
            OfflineKeys::parse_frame::<MockRuntime>(&serialized, &signing_key.public()).unwrap();
        assert!(rest.is_empty());
        assert_eq!(parsed, keys);
        assert_eq!(
            parsed.transient_key().as_ref(),
            keys.transient_key().as_ref()
        );

        // the transient key signs, the offline section proves it belongs to the destination
        let message = b"hello, world";
        let signature = parsed.transient_key().sign(message);
        parsed.signature().transient_key().verify(message, &signature).unwrap();
        assert!(signing_key.public().verify(message, &signature).is_err());
    }

    #[test]
    fn offline_keys_private_key_mismatch() {
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let keys = OfflineKeys::create::<MockRuntime>(&signing_key, expires_in(3600));
        let mut serialized = keys.serialize();

        // replace the transient private key with another key
        let len = serialized.len();
        serialized[len - 32..]
            .copy_from_slice(SigningPrivateKey::random(MockRuntime::rng()).as_ref());

        assert_eq!(
            OfflineKeys::parse::<MockRuntime>(&serialized, &signing_key.public()).unwrap_err(),
            OfflineSignatureParseError::InvalidPrivateKey
        );

        // truncated private key
        assert!(OfflineKeys::parse::<MockRuntime>(
            &keys.serialize()[..len - 1],
            &signing_key.public()
        )
        .is_err());
    }
}
