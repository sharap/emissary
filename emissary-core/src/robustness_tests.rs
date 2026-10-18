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

//! Robustness tests for parsers of network and client input.
//!
//! Every parser is fed random bytes and mutated copies of valid encodings. The parsers are free
//! to reject the input but must never panic. This is a cheap stand-in for fuzzing that runs on
//! every `cargo test`; it is not a replacement for a real fuzzer.

use crate::{
    i2np::{
        database::{
            lookup::DatabaseLookup,
            search_reply::DatabaseSearchReply,
            store::{DatabaseStore, DatabaseStoreBuilder, DatabaseStoreKind},
        },
        delivery_status::DeliveryStatus,
        garlic::{DeliveryInstructions, GarlicMessage, GarlicMessageBuilder},
        tunnel::{
            build::{short, variable},
            data::{EncryptedTunnelData, TunnelData},
            gateway::TunnelGateway,
        },
        Message as I2npMessage, MessageBuilder, MessageType as I2npMessageType,
    },
    primitives::{
        Date, DatagramFlags, Destination, LeaseSet2, Mapping, MessageId, OfflineSignature,
        RouterIdentity, RouterInfo, RouterInfoBuilder, Str,
    },
    runtime::{mock::MockRuntime, Runtime},
    Block, Datagram, HeaderReader, Message as I2cpMessage, MessageBlock,
    MessageType as I2cpMessageType, Packet, PacketBuilder, SamCommand,
};

use bytes::Bytes;
use rand::{Rng, RngExt};

use std::{panic::AssertUnwindSafe, time::Duration};

/// Number of random inputs per parser.
const NUM_RANDOM_INPUTS: usize = 400;

/// Number of mutated copies per valid sample.
const NUM_MUTATIONS: usize = 400;

/// Random bytes of random length up to `max_len`.
fn random_bytes(max_len: usize) -> Vec<u8> {
    let len = MockRuntime::rng().random_range(0..=max_len);
    let mut bytes = vec![0u8; len];
    MockRuntime::rng().fill_bytes(&mut bytes);
    bytes
}

/// Randomly mutated copy of `sample`.
fn mutate(sample: &[u8]) -> Vec<u8> {
    let mut rng = MockRuntime::rng();
    let mut out = sample.to_vec();

    match rng.random_range(0..6) {
        // truncate
        0 => out.truncate(rng.random_range(0..=out.len())),
        // flip a few random bits
        1 => {
            for _ in 0..rng.random_range(1..=8) {
                if !out.is_empty() {
                    let index = rng.random_range(0..out.len());
                    out[index] ^= 1 << rng.random_range(0..8);
                }
            }
        }
        // overwrite a few bytes with extreme values
        2 => {
            for _ in 0..rng.random_range(1..=4) {
                if !out.is_empty() {
                    let index = rng.random_range(0..out.len());
                    out[index] = if rng.random::<bool>() { 0xff } else { 0x00 };
                }
            }
        }
        // insert random bytes
        3 => {
            let index = rng.random_range(0..=out.len());
            let insert = random_bytes(64);
            out.splice(index..index, insert);
        }
        // remove a random range
        4 => {
            if !out.is_empty() {
                let start = rng.random_range(0..out.len());
                let end = rng.random_range(start..=out.len());
                out.drain(start..end);
            }
        }
        // overwrite a 2- or 4-byte field with a large value
        _ => {
            if out.len() >= 4 {
                let index = rng.random_range(0..out.len() - 3);
                let width = if rng.random::<bool>() { 2 } else { 4 };
                out[index..index + width].fill(0xff);
            }
        }
    }

    out
}

/// Inputs for a parser: random bytes plus mutations of `samples`.
fn inputs(samples: &[Vec<u8>], max_random_len: usize) -> Vec<Vec<u8>> {
    let mut all = (0..NUM_RANDOM_INPUTS).map(|_| random_bytes(max_random_len)).collect::<Vec<_>>();

    for sample in samples {
        all.push(sample.clone());
        all.extend((0..NUM_MUTATIONS).map(|_| mutate(sample)));
    }

    all
}

/// Run `parse` on every input and fail with the offending input if it panics.
fn check(name: &str, inputs: &[Vec<u8>], mut parse: impl FnMut(&[u8])) {
    for input in inputs {
        if std::panic::catch_unwind(AssertUnwindSafe(|| parse(input))).is_err() {
            let hex = input.iter().take(512).map(|byte| format!("{byte:02x}")).collect::<String>();
            panic!(
                "parser `{name}` panicked on a {}-byte input, first 512 bytes: {hex}",
                input.len()
            );
        }
    }
}

fn router_info_sample() -> Vec<u8> {
    let (router_info, _, signing_key) = RouterInfoBuilder::default().build();
    router_info.serialize(&signing_key)
}

fn lease_set_sample() -> Vec<u8> {
    let (lease_set, signing_key) = LeaseSet2::random();
    lease_set.serialize(&signing_key).to_vec()
}

fn i2np_sample() -> Vec<u8> {
    MessageBuilder::standard()
        .with_expiration(MockRuntime::time_since_epoch() + Duration::from_secs(10))
        .with_message_type(I2npMessageType::Data)
        .with_message_id(1337u32)
        .with_payload(&[1, 2, 3, 4, 5, 6, 7, 8])
        .build()
}

fn garlic_sample() -> Vec<u8> {
    GarlicMessageBuilder::default()
        .with_date_time(MockRuntime::time_since_epoch().as_secs() as u32)
        .with_garlic_clove(
            I2npMessageType::Data,
            MessageId::from(1337u32),
            MockRuntime::time_since_epoch() + Duration::from_secs(10),
            DeliveryInstructions::Local,
            &i2np_sample(),
        )
        .with_ack_request()
        .with_ack(vec![(1, 2), (3, 4)])
        .build()
}

#[test]
fn primitives_never_panic() {
    let router_info = router_info_sample();
    let lease_set = lease_set_sample();
    let (destination, _) = Destination::random();
    let destination = destination.to_vec();
    let mapping = Mapping::from_iter([
        (Str::from("caps"), Str::from("LR")),
        (Str::from("netId"), Str::from("2")),
    ])
    .serialize()
    .to_vec();

    check("RouterInfo", &inputs(&[router_info.clone()], 4096), |input| {
        let _ = RouterInfo::parse::<MockRuntime>(input);
    });
    check("RouterIdentity", &inputs(&[router_info], 1024), |input| {
        let _ = RouterIdentity::parse(input);
    });
    check("LeaseSet2", &inputs(&[lease_set], 4096), |input| {
        let _ = LeaseSet2::parse::<MockRuntime>(input);
    });
    check("Destination", &inputs(&[destination.clone()], 1024), |input| {
        let _ = Destination::parse(input);
    });
    check("Mapping", &inputs(&[mapping], 1024), |input| {
        let _ = Mapping::parse(input);
    });
    check("Str", &inputs(&[Str::from("hello").serialize().to_vec()], 512), |input| {
        let _ = Str::parse(input);
    });
    check("Date", &inputs(&[], 16), |input| {
        let _ = Date::parse(input);
    });
    check("DatagramFlags", &inputs(&[], 64), |input| {
        let _ = DatagramFlags::parse(input);
    });

    let (destination, _) = Destination::random();
    check("OfflineSignature", &inputs(&[], 512), |input| {
        let _ = OfflineSignature::parse_frame::<MockRuntime>(input, destination.verifying_key());
    });
}

#[test]
fn i2np_messages_never_panic() {
    let standard = i2np_sample();
    let short = MessageBuilder::short()
        .with_expiration(MockRuntime::time_since_epoch() + Duration::from_secs(10))
        .with_message_type(I2npMessageType::Data)
        .with_message_id(1337u32)
        .with_payload(&[1, 2, 3, 4])
        .build();

    check("I2NP standard", &inputs(&[standard], 2048), |input| {
        let _ = I2npMessage::parse_standard(input);
    });
    check("I2NP short", &inputs(&[short], 2048), |input| {
        let _ = I2npMessage::parse_short(input);
    });
    check("GarlicMessage", &inputs(&[garlic_sample()], 2048), |input| {
        let _ = GarlicMessage::parse(input);
    });
    check("DeliveryStatus", &inputs(&[], 64), |input| {
        let _ = DeliveryStatus::parse(input);
    });
}

#[test]
fn database_messages_never_panic() {
    let router_info = router_info_sample();
    let store = DatabaseStoreBuilder::new(
        Bytes::from(vec![0xaa; 32]),
        DatabaseStoreKind::RouterInfo {
            router_info: Bytes::from(MockRuntime::gzip_compress(&router_info).unwrap()),
        },
    )
    .build()
    .to_vec();

    check("DatabaseStore", &inputs(&[store], 4096), |input| {
        let _ = DatabaseStore::<MockRuntime>::parse(input);
    });
    check("DatabaseLookup", &inputs(&[], 2048), |input| {
        let _ = DatabaseLookup::parse(input);
    });
    check("DatabaseSearchReply", &inputs(&[], 2048), |input| {
        let _ = DatabaseSearchReply::parse(input);
    });
}

#[test]
fn tunnel_messages_never_panic() {
    check("ShortTunnelBuildRecord", &inputs(&[], 512), |input| {
        let _ = short::TunnelBuildRecord::parse(input);
    });
    check("VariableTunnelBuildRecord", &inputs(&[], 1024), |input| {
        let _ = variable::TunnelBuildRecord::parse(input);
    });
    check("EncryptedTunnelData", &inputs(&[], 2048), |input| {
        let _ = EncryptedTunnelData::parse(input);
    });
    check("TunnelData", &inputs(&[], 2048), |input| {
        let _ = TunnelData::parse(input);
    });
    check("TunnelGateway", &inputs(&[], 2048), |input| {
        let _ = TunnelGateway::parse(input);
    });
}

#[test]
fn transport_messages_never_panic() {
    let i2np = MessageBlock::new_i2np_message(&i2np_sample());
    let router_info = MessageBlock::new_router_info(&router_info_sample());

    check("NTCP2 MessageBlock", &inputs(&[i2np, router_info], 4096), |input| {
        let _ = MessageBlock::parse_multiple(input);
    });
    check("SSU2 Block", &inputs(&[], 4096), |input| {
        let _ = Block::parse::<MockRuntime>(input);
    });
    check("SSU2 HeaderReader", &inputs(&[], 1500), |input| {
        let mut pkt = input.to_vec();
        if let Ok(mut reader) = HeaderReader::new([0x11; 32], &mut pkt) {
            let _ = reader.dst_id();
            let _ = reader.parse([0x22; 32]);
        }
    });
}

#[test]
fn client_messages_never_panic() {
    let (destination, signing_key) = Destination::random();
    let syn = PacketBuilder::new(1337u32)
        .with_synchronize()
        .with_send_stream_id(0u32)
        .with_replay_protection(&destination.id())
        .with_from_included(&destination)
        .with_signature()
        .build_and_sign(&signing_key)
        .to_vec();

    check("Streaming Packet", &inputs(&[syn], 4096), |input| {
        let _ = Packet::parse::<MockRuntime>(input);
    });

    let commands = [
        "HELLO VERSION MIN=3.0 MAX=3.1\n",
        "SESSION CREATE STYLE=STREAM ID=test DESTINATION=TRANSIENT i2cp.leaseSetEncType=4\n",
        "STREAM CONNECT ID=test DESTINATION=abcd SILENT=false FROM_PORT=0 TO_PORT=0\n",
        "STREAM ACCEPT ID=test SILENT=true\n",
        "NAMING LOOKUP NAME=ME\n",
        "DEST GENERATE SIGNATURE_TYPE=7\n",
        "PING hello world\n",
    ]
    .into_iter()
    .map(|command| command.as_bytes().to_vec())
    .collect::<Vec<_>>();

    check("SamCommand", &inputs(&commands, 1024), |input| {
        let _ = SamCommand::parse::<MockRuntime>(&String::from_utf8_lossy(input));
    });
    check(
        "SAM Datagram",
        &inputs(&[b"3.0 session abcd\npayload".to_vec()], 1024),
        |input| {
            let _ = Datagram::parse(input);
        },
    );

    let message_types = (0..=u8::MAX).filter_map(I2cpMessageType::from_u8).collect::<Vec<_>>();
    assert!(!message_types.is_empty());

    for message_type in message_types {
        check(&format!("I2CP {message_type:?}"), &inputs(&[], 2048), |input| {
            let _ = I2cpMessage::parse::<MockRuntime>(message_type, input);
        });
    }
}
