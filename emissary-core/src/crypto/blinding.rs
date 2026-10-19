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


//! Key blinding for encrypted lease sets.
//!
//! https://geti2p.net/spec/encryptedleaseset

use crate::{
    crypto::{
        base32_decode, base32_encode, hmac::hkdf, sha256::Sha256, SigningPrivateKey,
        SigningPublicKey,
    },
    runtime::Runtime,
};

use curve25519_elligator2::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use rand::Rng;
use sha2::{Digest, Sha512};

use alloc::{string::String, vec::Vec};
use core::{fmt, time::Duration};

/// Signature type of EdDSA-SHA512-Ed25519 keys.
pub const SIG_TYPE_EDDSA_SHA512_ED25519: u16 = 7;

/// Signature type of RedDSA-SHA512-Ed25519 keys, the type of every blinded key.
pub const SIG_TYPE_REDDSA_SHA512_ED25519: u16 = 11;

/// Suffix of base32 addresses.
pub const B32_SUFFIX: &str = ".b32.i2p";

/// Length of an encoded b33 address, without the suffix.
pub const B33_LEN: usize = 56;

/// The signature types in the b33 address take two bytes each.
const B33_FLAG_TWO_BYTE_SIG_TYPES: u8 = 0x01;

/// The address needs a secret to be resolved.
const B33_FLAG_PER_SECRET: u8 = 0x02;

/// The lease set is encrypted per client.
const B33_FLAG_PER_CLIENT_AUTH: u8 = 0x04;

/// Seconds in a day.
const DAY: u64 = 24 * 60 * 60;

/// `H(p, d) = SHA256(p || d)`.
fn h(personalization: &str, parts: &[&[u8]]) -> [u8; 32] {
    parts
        .iter()
        .fold(Sha256::new().update(personalization.as_bytes()), |hasher, part| {
            hasher.update(part)
        })
        .finalize_new()
}

/// Get the UTC date of `timestamp` (duration since epoch) as `YYYYMMDD`.
pub fn date_string(timestamp: Duration) -> [u8; 8] {
    // days to civil date, see https://howardhinnant.github.io/date_algorithms.html
    let z = (timestamp.as_secs() / DAY) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };

    let mut out = [b'0'; 8];
    let mut write = |mut value: i64, range: core::ops::Range<usize>| {
        for i in range.rev() {
            out[i] = b'0' + (value % 10) as u8;
            value /= 10;
        }
    };
    write(year, 0..4);
    write(month, 4..6);
    write(day, 6..8);

    out
}

/// Get the start of the UTC day following `timestamp`.
pub fn next_midnight(timestamp: Duration) -> Duration {
    Duration::from_secs((timestamp.as_secs() / DAY + 1) * DAY)
}

/// Blinded public key of a destination.
///
/// Identifies a destination whose lease set is published encrypted. Can be created from the
/// destination's signing key or parsed from a b33 address and gives the per-day blinded keys,
/// the store hash under which the encrypted lease set is published and the subcredential used
/// to derive the encryption keys.
#[derive(Clone, PartialEq, Eq)]
pub struct BlindedPublicKey {
    /// Is the lease set encrypted per client.
    client_auth: bool,

    /// Signing public key of the destination.
    public_key: [u8; 32],

    /// Signature type of the destination's signing key.
    sig_type: u16,
}

impl fmt::Debug for BlindedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindedPublicKey")
            .field("address", &self.to_b33())
            .field("client_auth", &self.client_auth)
            .finish()
    }
}

impl BlindedPublicKey {
    /// Create new [`BlindedPublicKey`] from the signing key of a destination.
    ///
    /// Only Ed25519 keys can be blinded.
    pub fn new(key: &SigningPublicKey) -> Option<Self> {
        match key {
            SigningPublicKey::Ed25519(key) => Some(Self {
                client_auth: false,
                public_key: key.to_bytes(),
                sig_type: SIG_TYPE_EDDSA_SHA512_ED25519,
            }),
            _ => None,
        }
    }

    /// Parse [`BlindedPublicKey`] from a b33 address, with or without the `.b32.i2p` suffix.
    ///
    /// Addresses that need a secret are not supported.
    pub fn from_b33(address: &str) -> Option<Self> {
        let address = address.strip_suffix(B32_SUFFIX).unwrap_or(address);
        let mut bytes = base32_decode(address)?;

        if bytes.len() < 3 + 32 {
            return None;
        }

        // the checksum is xored into the three header bytes
        let checksum = crc32fast::hash(&bytes[3..]).to_le_bytes();
        bytes[0] ^= checksum[0];
        bytes[1] ^= checksum[1];
        bytes[2] ^= checksum[2];

        let flags = bytes[0];
        let (sig_type, blinded_sig_type, offset) = if flags & B33_FLAG_TWO_BYTE_SIG_TYPES != 0 {
            if bytes.len() < 5 + 32 {
                return None;
            }

            (
                u16::from_be_bytes([bytes[1], bytes[2]]),
                u16::from_be_bytes([bytes[3], bytes[4]]),
                5usize,
            )
        } else {
            (bytes[1] as u16, bytes[2] as u16, 3usize)
        };

        if flags & B33_FLAG_PER_SECRET != 0 {
            return None;
        }

        if !matches!(
            sig_type,
            SIG_TYPE_EDDSA_SHA512_ED25519 | SIG_TYPE_REDDSA_SHA512_ED25519
        ) || blinded_sig_type != SIG_TYPE_REDDSA_SHA512_ED25519
            || bytes.len() != offset + 32
        {
            return None;
        }

        Some(Self {
            client_auth: flags & B33_FLAG_PER_CLIENT_AUTH != 0,
            public_key: bytes[offset..].try_into().expect("32 bytes"),
            sig_type,
        })
    }

    /// Encode [`BlindedPublicKey`] as a b33 address, without the `.b32.i2p` suffix.
    pub fn to_b33(&self) -> String {
        let mut bytes = Vec::with_capacity(3 + 32);
        bytes.push(if self.client_auth {
            B33_FLAG_PER_CLIENT_AUTH
        } else {
            0u8
        });
        bytes.push(self.sig_type as u8);
        bytes.push(SIG_TYPE_REDDSA_SHA512_ED25519 as u8);
        bytes.extend_from_slice(&self.public_key);

        let checksum = crc32fast::hash(&self.public_key).to_le_bytes();
        bytes[0] ^= checksum[0];
        bytes[1] ^= checksum[1];
        bytes[2] ^= checksum[2];

        base32_encode(&bytes)
    }

    /// Is the lease set encrypted per client.
    pub fn client_auth(&self) -> bool {
        self.client_auth
    }

    /// Signing public key of the destination.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// `keydata = A || stA || stA'`.
    fn keydata(&self) -> [u8; 36] {
        let mut out = [0u8; 36];
        out[..32].copy_from_slice(&self.public_key);
        out[32..34].copy_from_slice(&self.sig_type.to_be_bytes());
        out[34..].copy_from_slice(&SIG_TYPE_REDDSA_SHA512_ED25519.to_be_bytes());
        out
    }

    /// `credential = H("credential", keydata)`.
    pub fn credential(&self) -> [u8; 32] {
        h("credential", &[&self.keydata()])
    }

    /// `subcredential = H("subcredential", credential || blindedPublicKey)`.
    pub fn subcredential(&self, blinded_public_key: &[u8; 32]) -> [u8; 32] {
        h("subcredential", &[&self.credential(), blinded_public_key])
    }

    /// Blinding factor for `date`.
    ///
    /// `alpha = HKDF(H("I2PGenerateAlpha", keydata), date, "i2pblinding1", 64) mod L`
    fn alpha(&self, date: &[u8; 8]) -> Scalar {
        let salt = h("I2PGenerateAlpha", &[&self.keydata()]);
        let seed = hkdf(&salt, date, b"i2pblinding1", 64);

        Scalar::from_bytes_mod_order_wide(&seed.try_into().expect("64 bytes"))
    }

    /// Get the blinded public key for `date`.
    ///
    /// `A' = A + alpha * B`
    pub fn blinded_key(&self, date: &[u8; 8]) -> Option<[u8; 32]> {
        let public_key = CompressedEdwardsY(self.public_key).decompress()?;
        let blinded = public_key + EdwardsPoint::mul_base(&self.alpha(date));

        Some(blinded.compress().to_bytes())
    }

    /// Blind `key`, the destination's signing key, for `date`.
    ///
    /// `a' = (a + alpha) mod L`, where `a` is the clamped lower half of `SHA512(seed)`.
    ///
    /// Returns `None` if `key` is not the private key of this public key.
    pub fn blind_private_key(
        &self,
        key: &SigningPrivateKey,
        date: &[u8; 8],
    ) -> Option<BlindedSigningKey> {
        if key.public() != SigningPublicKey::from_bytes(&self.public_key)? {
            return None;
        }

        let mut expanded: [u8; 32] = Sha512::digest(key.as_ref())[..32].try_into().expect("32 bytes");
        expanded[0] &= 0xf8;
        expanded[31] &= 0x3f;
        expanded[31] |= 0x40;

        let scalar = Scalar::from_bytes_mod_order(expanded) + self.alpha(date);
        let public_key = EdwardsPoint::mul_base(&scalar).compress().to_bytes();

        Some(BlindedSigningKey { public_key, scalar })
    }

    /// Get the hash under which the encrypted lease set is stored on `date`.
    pub fn store_hash(&self, date: &[u8; 8]) -> Option<[u8; 32]> {
        self.blinded_key(date).map(|blinded| store_hash(&blinded))
    }
}

/// Get the hash under which an encrypted lease set signed with `blinded_public_key` is stored.
///
/// `SHA256(stA' || A')`
pub fn store_hash(blinded_public_key: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .update(SIG_TYPE_REDDSA_SHA512_ED25519.to_be_bytes())
        .update(blinded_public_key)
        .finalize_new()
}

/// Blinded signing key.
///
/// A RedDSA-SHA512-Ed25519 key: an Ed25519 key given as a scalar instead of a seed.
pub struct BlindedSigningKey {
    /// Public key.
    public_key: [u8; 32],

    /// Private scalar.
    scalar: Scalar,
}

impl BlindedSigningKey {
    /// Get public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Sign `message`.
    ///
    /// The nonce is derived from random bytes, the public key and the message, the signature
    /// is a regular Ed25519 signature and verifies with the blinded public key.
    pub fn sign<R: Runtime>(&self, message: &[u8]) -> [u8; 64] {
        let mut random = [0u8; 80];
        R::rng().fill_bytes(&mut random);

        let r = Scalar::from_bytes_mod_order_wide(
            &Sha512::new()
                .chain_update(random)
                .chain_update(self.public_key)
                .chain_update(message)
                .finalize()
                .into(),
        );
        let big_r = EdwardsPoint::mul_base(&r).compress();
        let k = Scalar::from_bytes_mod_order_wide(
            &Sha512::new()
                .chain_update(big_r.as_bytes())
                .chain_update(self.public_key)
                .chain_update(message)
                .finalize()
                .into(),
        );
        let s = r + k * self.scalar;

        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(big_r.as_bytes());
        signature[32..].copy_from_slice(&s.to_bytes());
        signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::mock::MockRuntime;

    #[test]
    fn date_strings() {
        assert_eq!(&date_string(Duration::from_secs(0)), b"19700101");
        assert_eq!(&date_string(Duration::from_secs(86_399)), b"19700101");
        assert_eq!(&date_string(Duration::from_secs(86_400)), b"19700102");
        assert_eq!(&date_string(Duration::from_secs(951_782_400)), b"20000229");
        assert_eq!(&date_string(Duration::from_secs(1_700_000_000)), b"20231114");
        assert_eq!(&date_string(Duration::from_secs(4_102_444_799)), b"20991231");
        assert_eq!(&date_string(Duration::from_secs(4_102_444_800)), b"21000101");
        assert_eq!(&date_string(Duration::from_secs(4_107_542_400)), b"21000301");

        assert_eq!(
            next_midnight(Duration::from_secs(1_700_000_000)),
            Duration::from_secs(1_700_006_400)
        );
        assert_eq!(&date_string(next_midnight(Duration::from_secs(1_700_000_000))), b"20231115");
        assert_eq!(next_midnight(Duration::from_secs(86_400)), Duration::from_secs(172_800));
    }

    #[test]
    fn b33_round_trip() {
        let key = SigningPrivateKey::random(MockRuntime::rng());
        let blinded = BlindedPublicKey::new(&key.public()).unwrap();

        let address = blinded.to_b33();
        assert_eq!(address.len(), B33_LEN);
        assert_eq!(BlindedPublicKey::from_b33(&address), Some(blinded.clone()));
        assert_eq!(
            BlindedPublicKey::from_b33(&alloc::format!("{address}{B32_SUFFIX}")),
            Some(blinded.clone())
        );

        // per-client authorization is carried in the flags
        let with_auth = BlindedPublicKey {
            client_auth: true,
            ..blinded.clone()
        };
        let parsed = BlindedPublicKey::from_b33(&with_auth.to_b33()).unwrap();
        assert!(parsed.client_auth());
        assert_eq!(parsed.public_key(), blinded.public_key());

        // the checksum covers the key: a corrupted key, wrong length, secret required and
        // non-ed25519 keys are rejected
        for i in 3..35 {
            let mut bytes = base32_decode(&address).unwrap();
            bytes[i] ^= 0x01;
            assert!(BlindedPublicKey::from_b33(&base32_encode(&bytes)).is_none());
        }

        assert!(BlindedPublicKey::from_b33(&address[..52]).is_none());
        assert!(BlindedPublicKey::from_b33("").is_none());
        assert!(BlindedPublicKey::from_b33("not base32!").is_none());

        // the header is xored with the checksum so flipping bits in it flips the parsed flags
        let mut bytes = base32_decode(&address).unwrap();
        bytes[0] ^= B33_FLAG_PER_SECRET;
        assert!(BlindedPublicKey::from_b33(&base32_encode(&bytes)).is_none());

        let mut bytes = base32_decode(&address).unwrap();
        bytes[1] ^= 7u8 ^ 1u8; // ed25519 -> dsa
        assert!(BlindedPublicKey::from_b33(&base32_encode(&bytes)).is_none());

        // two-byte signature types are accepted
        let mut bytes = alloc::vec![B33_FLAG_TWO_BYTE_SIG_TYPES, 0, 7, 0, 11];
        bytes.extend_from_slice(blinded.public_key());
        let checksum = crc32fast::hash(&bytes[3..]).to_le_bytes();
        bytes[0] ^= checksum[0];
        bytes[1] ^= checksum[1];
        bytes[2] ^= checksum[2];
        assert_eq!(BlindedPublicKey::from_b33(&base32_encode(&bytes)), Some(blinded));
    }

    #[test]
    fn blinded_public_key_matches_blinded_private_key() {
        let key = SigningPrivateKey::random(MockRuntime::rng());
        let blinded = BlindedPublicKey::new(&key.public()).unwrap();

        let today = date_string(Duration::from_secs(1_700_000_000));
        let tomorrow = date_string(Duration::from_secs(1_700_086_400));

        let signer = blinded.blind_private_key(&key, &today).unwrap();
        assert_eq!(blinded.blinded_key(&today).unwrap(), *signer.public_key());

        // the blinded key changes every day and differs from the unblinded key
        let signer_tomorrow = blinded.blind_private_key(&key, &tomorrow).unwrap();
        assert_eq!(blinded.blinded_key(&tomorrow).unwrap(), *signer_tomorrow.public_key());
        assert_ne!(signer.public_key(), signer_tomorrow.public_key());
        assert_ne!(signer.public_key(), blinded.public_key());

        // store hashes follow the blinded keys
        assert_eq!(
            blinded.store_hash(&today).unwrap(),
            Sha256::new().update([0u8, 11u8]).update(signer.public_key()).finalize_new()
        );
        assert_ne!(blinded.store_hash(&today), blinded.store_hash(&tomorrow));

        // the wrong private key is rejected
        let other = SigningPrivateKey::random(MockRuntime::rng());
        assert!(blinded.blind_private_key(&other, &today).is_none());

        // subcredential depends on the blinded key
        assert_ne!(
            blinded.subcredential(signer.public_key()),
            blinded.subcredential(signer_tomorrow.public_key())
        );
        assert_ne!(
            blinded.credential(),
            BlindedPublicKey::new(&other.public()).unwrap().credential()
        );
    }

    #[test]
    fn blinded_signature_verifies_as_ed25519() {
        let key = SigningPrivateKey::random(MockRuntime::rng());
        let blinded = BlindedPublicKey::new(&key.public()).unwrap();
        let date = date_string(MockRuntime::time_since_epoch());
        let signer = blinded.blind_private_key(&key, &date).unwrap();

        let message = b"encrypted lease set";
        let signature = signer.sign::<MockRuntime>(message);
        let verifying_key = SigningPublicKey::from_bytes(signer.public_key()).unwrap();

        assert!(verifying_key.verify(message, &signature).is_ok());
        assert!(verifying_key.verify(b"another message", &signature).is_err());
        assert!(key.public().verify(message, &signature).is_err());

        // signatures are randomized but all of them verify
        let another = signer.sign::<MockRuntime>(message);
        assert_ne!(signature, another);
        assert!(verifying_key.verify(message, &another).is_ok());
    }

    #[test]
    fn scalar_signing_matches_ed25519() {
        // signing with the unblinded scalar must verify with the unblinded public key, which
        // shows the signer implements plain ed25519 over the scalar
        let key = SigningPrivateKey::random(MockRuntime::rng());
        let mut expanded: [u8; 32] = Sha512::digest(key.as_ref())[..32].try_into().unwrap();
        expanded[0] &= 0xf8;
        expanded[31] &= 0x3f;
        expanded[31] |= 0x40;

        let signer = BlindedSigningKey {
            public_key: key.public().as_ref().try_into().unwrap(),
            scalar: Scalar::from_bytes_mod_order(expanded),
        };
        assert_eq!(
            EdwardsPoint::mul_base(&signer.scalar).compress().to_bytes(),
            signer.public_key
        );

        let signature = signer.sign::<MockRuntime>(b"hello, world");
        assert!(key.public().verify(b"hello, world", &signature).is_ok());
    }
}
