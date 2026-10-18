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

#[cfg(feature = "tokio")]
pub mod tokio;

#[cfg(feature = "smol")]
pub mod smol;

/// GZIP-decompress `bytes`, rejecting output larger than `max_size` bytes.
#[cfg(any(feature = "tokio", feature = "smol"))]
pub(crate) fn gzip_decompress(bytes: &[u8], max_size: usize) -> Option<Vec<u8>> {
    use std::io::Read;

    // read at most one byte more than allowed to detect oversized output
    let mut decompressed = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .take(max_size as u64 + 1)
        .read_to_end(&mut decompressed)
        .ok()?;

    (decompressed.len() <= max_size).then_some(decompressed)
}

#[cfg(all(test, any(feature = "tokio", feature = "smol")))]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    fn compress(payload: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(payload).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn gzip_decompress_respects_max_size() {
        let payload = vec![0u8; 1024 * 1024];
        let compressed = compress(&payload);
        assert!(compressed.len() < 2048);

        assert!(gzip_decompress(&compressed, 64 * 1024).is_none());
        assert!(gzip_decompress(&compressed, payload.len() - 1).is_none());
        assert_eq!(gzip_decompress(&compressed, payload.len()), Some(payload.clone()));
        assert_eq!(gzip_decompress(&compressed, 2 * payload.len()), Some(payload));

        assert!(gzip_decompress(&compressed[..compressed.len() / 2], 1024 * 1024).is_none());
        assert_eq!(gzip_decompress(&compress(b"hello"), 5), Some(b"hello".to_vec()));
        assert!(gzip_decompress(&compress(b"hello"), 4).is_none());
    }
}
