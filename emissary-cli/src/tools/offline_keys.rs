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

//! Create offline keys for a destination.
//!
//! The destination's signing private key is replaced with a transient signing key which is signed
//! by the destination's key and valid for a limited time. The resulting private key file can be
//! given to the router (e.g., as `destination_path` of a server tunnel) while the original file
//! stays offline.

use anyhow::anyhow;
use emissary_core::{
    crypto::{base32_encode, base64_decode, base64_encode, SigningPrivateKey},
    primitives::{Destination, OfflineKeys},
    runtime::Runtime,
};
use emissary_util::runtime::tokio::Runtime as TokioRuntime;

use std::{
    fs,
    io::{self, Write},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::tools::offline-keys";

/// Create offline keys for the destination stored in `file`, valid for `days` days, and write the
/// new private key file to `output` (or stdout) as Base64.
///
/// `file` is either a Base64 string, as written by the router for server tunnels, or binary.
pub fn generate(file: String, output: Option<String>, days: u32) -> anyhow::Result<()> {
    let contents = fs::read(&file)?;
    let private_key = match std::str::from_utf8(&contents)
        .ok()
        .and_then(|contents| base64_decode(contents.trim()))
    {
        Some(decoded) => decoded,
        None => contents,
    };

    let (private_key, destination, expires) = create::<TokioRuntime>(&private_key, days)?;
    let encoded = base64_encode(private_key);

    tracing::info!(
        target: LOG_TARGET,
        address = %format!("{}.b32.i2p", base32_encode(destination.id().to_vec())),
        expires = %expires,
        "offline keys created, keep the original private key file offline",
    );

    match output {
        Some(output) => fs::write(output, encoded)?,
        None => io::stdout().write_all(encoded.as_ref())?,
    }

    Ok(())
}

/// Create offline keys for `private_key` (destination, encryption private key and signing private
/// key), valid for `days` days.
///
/// Returns the new private key file contents, the destination and the expiration of the transient
/// key as seconds since epoch.
fn create<R: Runtime>(
    private_key: &[u8],
    days: u32,
) -> anyhow::Result<(Vec<u8>, Destination, u32)> {
    let (rest, destination) = Destination::parse_frame(private_key)
        .map_err(|error| anyhow!("invalid destination: {error:?}"))?;

    if rest.len() < destination.private_key_length() + destination.signing_key_length() {
        return Err(anyhow!("private key file is too short"));
    }

    let (encryption_key, rest) = rest.split_at(destination.private_key_length());
    let (signing_key, _) = rest.split_at(destination.signing_key_length());

    if signing_key.iter().all(|byte| *byte == 0) {
        return Err(anyhow!(
            "the file already contains offline keys, the destination's own signing key is needed"
        ));
    }

    let signing_key = SigningPrivateKey::from_bytes(signing_key)
        .ok_or_else(|| anyhow!("unsupported signing key"))?;

    if &signing_key.public() != destination.verifying_key() {
        return Err(anyhow!("signing key doesn't match the destination"));
    }

    let expires =
        (R::time_since_epoch() + Duration::from_secs(u64::from(days) * 24 * 60 * 60)).as_secs();
    let expires =
        u32::try_from(expires).map_err(|_| anyhow!("expiration is too far in the future"))?;
    let keys = OfflineKeys::create::<R>(&signing_key, expires);

    let mut out = Vec::with_capacity(private_key.len() + keys.serialize().len());
    out.extend_from_slice(destination.serialized());
    out.extend_from_slice(encryption_key);
    out.extend_from_slice(&vec![0u8; destination.signing_key_length()]);
    out.extend_from_slice(&keys.serialize());

    Ok((out, destination, expires))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_key_file() -> (Vec<u8>, SigningPrivateKey) {
        let signing_key = SigningPrivateKey::random(TokioRuntime::rng());
        let destination = Destination::new::<TokioRuntime>(signing_key.public());

        let mut out = destination.serialized().to_vec();
        out.extend_from_slice(&[1u8; 256]);
        out.extend_from_slice(signing_key.as_ref());

        (out, signing_key)
    }

    #[test]
    fn create_offline_keys() {
        let (file, signing_key) = private_key_file();
        let (offline_file, destination, expires) = create::<TokioRuntime>(&file, 7).unwrap();

        assert_eq!(destination.verifying_key(), &signing_key.public());
        assert_eq!(
            expires,
            (TokioRuntime::time_since_epoch() + Duration::from_secs(7 * 24 * 60 * 60)).as_secs()
                as u32
        );

        // the file is parsed like the router parses it: destination, encryption key, all-zero
        // signing key, offline keys
        let (rest, parsed) = Destination::parse_frame(&offline_file).unwrap();
        assert_eq!(parsed.id(), destination.id());
        assert_eq!(&rest[..256], &[1u8; 256]);
        assert_eq!(&rest[256..288], &[0u8; 32]);

        let keys =
            OfflineKeys::parse::<TokioRuntime>(&rest[288..], destination.verifying_key()).unwrap();
        assert_eq!(keys.signature().expires(), expires);

        // offline keys cannot be created from a file that already contains them
        assert!(create::<TokioRuntime>(&offline_file, 7).is_err());

        // the signing key must belong to the destination
        let mut wrong_key = file.clone();
        let len = wrong_key.len();
        wrong_key[len - 32..]
            .copy_from_slice(SigningPrivateKey::random(TokioRuntime::rng()).as_ref());
        assert!(create::<TokioRuntime>(&wrong_key, 7).is_err());

        // truncated files are rejected
        assert!(create::<TokioRuntime>(&file[..len - 1], 7).is_err());
    }
}
