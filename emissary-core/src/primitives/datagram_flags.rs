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

//! Datagram2 and Datagram3 flags.
//!
//! https://geti2p.net/spec/datagrams

use crate::{
    error::parser::DatagramFlagsParseError,
    primitives::{Mapping, LOG_TARGET},
};

use bytes::{BufMut, Bytes, BytesMut};
use nom::{bytes::complete::take, number::complete::be_u16, Err, IResult};

/// Serialized length of [`DatagramFlags`].
const FLAGS_LEN: usize = 2;

/// Version mask, bits 3-0 of the flags.
const VERSION_MASK: u16 = 0x000f;

/// Options mask, bit 4 of the flags.
const OPTIONS_MASK: u16 = 0x0010;

/// Offline signature mask, bit 5 of the flags (Datagram2 only).
const OFFLINE_MASK: u16 = 0x0020;

/// Datagram2 version.
const V2: u16 = 2;

/// Datagram3 version.
const V3: u16 = 3;

/// Datagram flags.
///
/// The flags are a big-endian 2-byte field: the version is in bits 3-0, i.e., the low nibble of the
/// second byte, as in the specification and other routers.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DatagramFlags {
    /// Used in Datagram2.
    ///
    /// https://geti2p.net/spec/datagrams#id9
    V2 {
        options: Option<Mapping>,
        has_offsig: bool,
    },
    /// Used in Datagram3.
    ///
    /// https://geti2p.net/spec/datagrams#id14
    V3 { options: Option<Mapping> },
}

impl DatagramFlags {
    /// Create Datagram2 flags.
    pub fn new_v2(options: Option<Mapping>, has_offsig: bool) -> DatagramFlags {
        DatagramFlags::V2 {
            options,
            has_offsig,
        }
    }

    /// Create Datagram3 flags.
    pub fn new_v3(options: Option<Mapping>) -> DatagramFlags {
        DatagramFlags::V3 { options }
    }

    /// Serialize [`DatagramFlags`] (and the options, if any) into a byte vector.
    pub fn serialize(&self) -> Bytes {
        let (version, options, has_offsig) = match self {
            Self::V2 {
                options,
                has_offsig,
            } => (V2, options.as_ref(), *has_offsig),
            Self::V3 { options } => (V3, options.as_ref(), false),
        };

        let mut flags = version;
        if has_offsig {
            flags |= OFFLINE_MASK;
        }

        let mut out = BytesMut::with_capacity(FLAGS_LEN);

        match options {
            Some(options) => {
                out.put_u16(flags | OPTIONS_MASK);
                options.serialize_into(out).freeze()
            }
            None => {
                out.put_u16(flags);
                out.freeze()
            }
        }
    }

    /// Parse [`DatagramFlags`] from `input`, returning rest of `input` and parsed
    /// [`DatagramFlags`].
    pub fn parse_frame(input: &[u8]) -> IResult<&[u8], DatagramFlags, DatagramFlagsParseError> {
        if input.len() < FLAGS_LEN {
            tracing::warn!(
                target: LOG_TARGET,
                serialized_len = ?input.len(),
                "not enough bytes in flags",
            );

            return Err(Err::Error(DatagramFlagsParseError::InvalidLength));
        }

        let (rest, flags) = be_u16(input)?;
        let version = flags & VERSION_MASK;

        if version != V2 && version != V3 {
            tracing::trace!(
                target: LOG_TARGET,
                ?version,
                "unknown flags version",
            );

            return Err(Err::Error(DatagramFlagsParseError::UnknownVersion));
        }

        // parse options
        let (rest, options) = if flags & OPTIONS_MASK == 0 {
            (rest, None)
        } else {
            let (_, optlen) = be_u16(rest)?;

            match optlen {
                0 => (take(2usize)(rest)?.0, None),
                len if rest.len() < len as usize + 2 => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        serialized_len = ?rest.len(),
                        "not enough bytes for mapping",
                    );
                    return Err(Err::Error(DatagramFlagsParseError::InvalidBitstream));
                }
                _ => {
                    let (rest, mapping) = Mapping::parse_frame(rest).map_err(Err::convert)?;
                    (rest, Some(mapping))
                }
            }
        };

        match version {
            V2 => Ok((
                rest,
                DatagramFlags::V2 {
                    options,
                    has_offsig: flags & OFFLINE_MASK != 0,
                },
            )),
            _ => Ok((rest, DatagramFlags::V3 { options })),
        }
    }

    /// Try to parse [`DatagramFlags`] from `bytes`.
    pub fn parse(bytes: impl AsRef<[u8]>) -> Result<Self, DatagramFlagsParseError> {
        Ok(Self::parse_frame(bytes.as_ref())?.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_flags() {
        assert_eq!(
            DatagramFlags::parse(b"\0\0"),
            Err(DatagramFlagsParseError::UnknownVersion)
        );
    }

    #[test]
    fn undersized() {
        assert_eq!(
            DatagramFlags::parse(b"\x01"),
            Err(DatagramFlagsParseError::InvalidLength)
        );
    }

    #[test]
    fn wire_format_matches_other_routers() {
        // version in the low nibble of the second byte, options bit 4, offline signature bit 5
        assert_eq!(
            DatagramFlags::new_v2(None, false).serialize().as_ref(),
            &[0x00, 0x02]
        );
        assert_eq!(
            DatagramFlags::new_v2(None, true).serialize().as_ref(),
            &[0x00, 0x22]
        );
        assert_eq!(
            DatagramFlags::new_v3(None).serialize().as_ref(),
            &[0x00, 0x03]
        );

        let mut options = Mapping::default();
        options.insert("a".into(), "b".into());
        let serialized = DatagramFlags::new_v3(Some(options)).serialize();
        assert_eq!(&serialized[..2], &[0x00, 0x13]);

        // the version in the first byte is not accepted
        assert_eq!(
            DatagramFlags::parse(b"\x02\x00"),
            Err(DatagramFlagsParseError::UnknownVersion)
        );
        assert_eq!(
            DatagramFlags::parse(b"\x00\x03"),
            Ok(DatagramFlags::V3 { options: None })
        );
    }

    #[test]
    fn valid_flags() {
        let flags = DatagramFlags::V2 {
            options: None,
            has_offsig: false,
        };
        let ser = flags.serialize();

        assert_eq!(DatagramFlags::parse(ser), Ok(flags));

        let flags = DatagramFlags::V3 { options: None };
        let ser = flags.serialize();

        assert_eq!(DatagramFlags::parse(ser), Ok(flags));
    }

    #[test]
    fn valid_flags_with_all_fields() {
        let mut opts = Mapping::default();
        opts.insert("hello".into(), "world".into());

        let flags = DatagramFlags::V2 {
            options: Some(opts.clone()),
            has_offsig: true,
        };
        let ser = flags.serialize();
        assert_eq!(DatagramFlags::parse(ser), Ok(flags));

        let flags = DatagramFlags::V3 {
            options: Some(opts),
        };
        let ser = flags.serialize();
        assert_eq!(DatagramFlags::parse(ser), Ok(flags));
    }

    #[test]
    fn options_flag_without_options() {
        // options bit set but the mapping is truncated
        assert!(DatagramFlags::parse(b"\x00\x13").is_err());
        assert!(DatagramFlags::parse(b"\x00\x13\x00").is_err());
        assert_eq!(
            DatagramFlags::parse(b"\x00\x13\x00\x10\x01"),
            Err(DatagramFlagsParseError::InvalidBitstream)
        );
        // empty mapping
        assert_eq!(
            DatagramFlags::parse_frame(b"\x00\x13\x00\x00\x01").unwrap(),
            (&b"\x01"[..], DatagramFlags::V3 { options: None })
        );
    }

    #[test]
    fn valid_string_with_extra_bytes() {
        let mut opts = Mapping::default();
        opts.insert("hello".into(), "world".into());

        let flags = DatagramFlags::V2 {
            options: Some(opts),
            has_offsig: true,
        };

        let mut ser = flags.serialize().to_vec();
        ser.push(1);
        ser.push(2);
        ser.push(3);
        ser.push(4);

        assert_eq!(DatagramFlags::parse(ser), Ok(flags));
    }

    #[test]
    fn extra_bytes_returned() {
        let mut opts = Mapping::default();
        opts.insert("hello".into(), "world".into());

        let flags = DatagramFlags::V2 {
            options: Some(opts),
            has_offsig: true,
        };

        let mut ser = flags.serialize().to_vec();
        ser.push(1);
        ser.push(2);
        ser.push(3);
        ser.push(4);

        let (rest, parsed_mapping) = DatagramFlags::parse_frame(&ser).unwrap();

        assert_eq!(parsed_mapping, flags);
        assert_eq!(rest, [1, 2, 3, 4]);
    }
}
