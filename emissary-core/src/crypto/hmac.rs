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

use hmac::Mac;
use sha2::Sha256;

use alloc::vec::Vec;

pub struct Hmac {
    hmac: hmac::Hmac<Sha256>,
}

impl Hmac {
    /// Create new [`Hmac`].
    pub fn new(key: &[u8]) -> Self {
        Self {
            hmac: hmac::Hmac::new_from_slice(key).expect("valid key size"),
        }
    }

    /// Update state.
    pub fn update(mut self, bytes: impl AsRef<[u8]>) -> Self {
        self.hmac.update(bytes.as_ref());
        self
    }

    /// Finalize and return MAC.
    //
    // TODO: remove
    pub fn finalize(self) -> Vec<u8> {
        self.hmac.finalize().into_bytes().to_vec()
    }

    /// Finalize and return MAC.
    //
    // TODO: rename
    pub fn finalize_new(self) -> [u8; 32] {
        self.hmac.finalize().into_bytes().into()
    }
}

/// HKDF-SHA256 as specified in RFC 5869.
///
/// Extracts a pseudorandom key from `ikm` using `salt` and expands it with `info` into
/// `out_len` bytes.
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let prk = Hmac::new(salt).update(ikm).finalize_new();
    let mut out = Vec::with_capacity(out_len.next_multiple_of(32));
    let mut previous: &[u8] = &[];
    let mut counter = 1u8;

    while out.len() < out_len {
        let block = Hmac::new(&prk).update(previous).update(info).update([counter]).finalize_new();
        out.extend_from_slice(&block);
        previous = &out[out.len() - 32..];
        counter += 1;
    }

    out.truncate(out_len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_rfc5869_test_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = (0u8..=0x0c).collect::<Vec<_>>();
        let info = (0xf0u8..=0xf9).collect::<Vec<_>>();
        let okm = hkdf(&salt, &ikm, &info, 42);

        assert_eq!(
            okm,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
            ]
        );
    }

    #[test]
    fn hkdf_rfc5869_test_case_2() {
        let ikm = (0u8..=0x4f).collect::<Vec<_>>();
        let salt = (0x60u8..=0xaf).collect::<Vec<_>>();
        let info = (0xb0u8..=0xff).collect::<Vec<_>>();
        let okm = hkdf(&salt, &ikm, &info, 82);

        assert_eq!(
            &okm[..16],
            [0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34]
        );
        assert_eq!(okm.len(), 82);

        // the output is a prefix of a longer output
        assert_eq!(hkdf(&salt, &ikm, &info, 100)[..82], okm[..]);
    }
}
