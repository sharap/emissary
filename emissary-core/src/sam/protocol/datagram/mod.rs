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

use crate::{
    crypto::{base64_encode, sha256::Sha256, SigningPrivateKey, SigningPublicKey},
    error::Error,
    i2cp::I2cpPayload,
    primitives::{DatagramFlags, Destination, DestinationId, Mapping, OfflineSignature},
    protocol::Protocol,
    runtime::Runtime,
    sam::parser::SessionKind,
};

use bytes::{BufMut, Bytes, BytesMut};
use hashbrown::HashMap;
use nom::bytes::complete::take;
use thingbuf::mpsc::Sender;

use alloc::{borrow::Cow, format, string::String, sync::Arc, vec::Vec};
use core::{
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::datagram";

/// I2CP protocol number of raw datagrams, the only one supported for `RAW` sessions.
const RAW_PROTOCOL: u8 = 18u8;

/// Datagram forwarded to a client over UDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedDatagram {
    /// Datagram, prefixed with a header line where the session kind requires one.
    pub datagram: Vec<u8>,

    /// Address of the client's UDP socket.
    pub target: SocketAddr,
}

impl Default for ForwardedDatagram {
    fn default() -> Self {
        Self {
            datagram: Vec::new(),
            target: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0u16),
        }
    }
}

/// Datagram listener.
///
/// Created from the `PORT`/`HOST`/`LISTEN_PORT`/`LISTEN_PROTOCOL`/`HEADER` options of a
/// `SESSION CREATE` or `SESSION ADD` command. Inbound datagrams are routed to a listener based on
/// their I2CP protocol and destination port and forwarded to `target` over UDP.
///
/// https://geti2p.net/en/docs/api/samv3#primary-sessions
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramListener {
    /// Should forwarded raw datagrams be prefixed with a header line (`HEADER=true`).
    header: bool,

    /// Session kind: `Datagram`, `Anonymous` or `Datagram2`.
    kind: SessionKind,

    /// Local I2CP port the listener accepts datagrams on, `0` is a wildcard.
    listen_port: u16,

    /// I2CP protocol the listener accepts, `0` is a wildcard. Only meaningful for raw sessions.
    listen_protocol: u8,

    /// ID of the (sub-)session which owns the listener.
    session_id: Arc<str>,

    /// Where the datagrams are forwarded to.
    target: SocketAddr,
}

impl DatagramListener {
    /// Create [`DatagramListener`] for `session_id` of kind `kind` from `options`.
    ///
    /// `PORT` is required, `HOST` defaults to `127.0.0.1` and must be an IP address, `LISTEN_PORT`
    /// defaults to `FROM_PORT` which defaults to `0` and `LISTEN_PROTOCOL` defaults to `PROTOCOL`
    /// which defaults to `18` for raw sessions. Only protocol `18` (and the wildcard `0`) is
    /// supported for raw sessions.
    fn new(
        session_id: Arc<str>,
        kind: SessionKind,
        options: &HashMap<String, String>,
    ) -> Result<Self, ()> {
        let port = options
            .get("PORT")
            .ok_or_else(|| {
                tracing::warn!(
                    target: LOG_TARGET,
                    %session_id,
                    "tried to register datagram listener without specifying `PORT`",
                );
            })?
            .parse::<u16>()
            .map_err(|error| {
                tracing::warn!(
                    target: LOG_TARGET,
                    %session_id,
                    ?error,
                    "invalid `PORT` for datagram listener",
                );
            })?;
        let host = match options.get("HOST") {
            None => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(host) => host.parse::<IpAddr>().map_err(|error| {
                tracing::warn!(
                    target: LOG_TARGET,
                    %session_id,
                    %host,
                    ?error,
                    "invalid `HOST` for datagram listener, must be an ip address",
                );
            })?,
        };
        let parse_port = |key: &str, default: u16| -> Result<u16, ()> {
            options.get(key).map_or(Ok(default), |value| {
                value.parse::<u16>().map_err(|error| {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %session_id,
                        %key,
                        %value,
                        ?error,
                        "invalid port for datagram listener",
                    );
                })
            })
        };
        let from_port = parse_port("FROM_PORT", 0u16)?;
        let listen_port = parse_port("LISTEN_PORT", from_port)?;

        let listen_protocol = match kind {
            SessionKind::Anonymous => {
                let protocol = options
                    .get("LISTEN_PROTOCOL")
                    .or_else(|| options.get("PROTOCOL"))
                    .map_or(Ok(RAW_PROTOCOL), |value| {
                        value.parse::<u8>().map_err(|_| ())
                    })
                    .map_err(|()| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            %session_id,
                            "invalid protocol for raw datagram listener",
                        );
                    })?;

                if protocol != 0 && protocol != RAW_PROTOCOL {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %session_id,
                        %protocol,
                        "only protocol 18 is supported for raw datagram listeners",
                    );
                    return Err(());
                }

                protocol
            }
            _ => 0u8,
        };
        let header = core::matches!(kind, SessionKind::Anonymous)
            && options
                .get("HEADER")
                .is_some_and(|value| value.parse::<bool>().unwrap_or(false));

        Ok(Self {
            header,
            kind,
            listen_port,
            listen_protocol,
            session_id,
            target: SocketAddr::new(host, port),
        })
    }

    /// Does the listener accept datagrams of `protocol`.
    ///
    /// Repliable datagram listeners only accept the datagram kind they were created for. Raw
    /// listeners accept raw datagrams, or any non-streaming protocol if their listen protocol is
    /// the wildcard `0`.
    fn accepts(&self, protocol: Protocol) -> bool {
        match self.kind {
            SessionKind::Datagram => protocol == Protocol::Datagram,
            SessionKind::Datagram2 => protocol == Protocol::Datagram2,
            SessionKind::Datagram3 => protocol == Protocol::Datagram3,
            SessionKind::Anonymous =>
                protocol == Protocol::Anonymous
                    || (self.listen_protocol == 0 && protocol != Protocol::Streaming),
            SessionKind::Stream | SessionKind::Primary => false,
        }
    }

    /// Is the listener an exact match for `protocol`, as opposed to a raw wildcard listener.
    fn is_exact(&self, protocol: Protocol) -> bool {
        match self.kind {
            SessionKind::Anonymous => protocol == Protocol::Anonymous,
            _ => true,
        }
    }

    /// Would the listener conflict with `other`, i.e., accept the same traffic.
    fn conflicts_with(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.listen_port == other.listen_port
            && self.listen_protocol == other.listen_protocol
    }
}

/// Datagram manager.
pub struct DatagramManager<R: Runtime> {
    /// TX channel which can be used to send datagrams to clients.
    datagram_tx: Sender<ForwardedDatagram>,

    /// Local destination.
    destination: Destination,

    /// Local destination SHA256 hash.
    destination_hash: [u8; 32],

    /// Listeners.
    listeners: Vec<DatagramListener>,

    /// Serialized offline signature section, if the local destination uses offline keys.
    offline_signature: Option<Bytes>,

    /// Signing key.
    signing_key: SigningPrivateKey,

    /// Marker for `Runtime`
    _runtime: PhantomData<R>,
}

impl<R: Runtime> DatagramManager<R> {
    /// Create new [`DatagramManager`].
    pub fn new(
        destination: Destination,
        datagram_tx: Sender<ForwardedDatagram>,
        signing_key: SigningPrivateKey,
    ) -> Self {
        Self {
            destination_hash: Sha256::new().update(&*destination).finalize_new(),
            datagram_tx,
            destination,
            listeners: Vec::new(),
            offline_signature: None,
            signing_key,
            _runtime: Default::default(),
        }
    }

    /// Use offline keys: `signing_key` given to [`DatagramManager::new()`] is the transient key
    /// and `offline_signature` is the serialized offline signature section proving it belongs to
    /// the destination.
    ///
    /// Only Datagram2 supports offline signatures, repliable Datagram1 datagrams cannot be sent.
    pub fn with_offline_signature(mut self, offline_signature: Option<Bytes>) -> Self {
        self.offline_signature = offline_signature;
        self
    }

    /// Make anonymous datagram.
    #[inline]
    pub fn make_anonymous(&mut self, datagram: Vec<u8>) -> Bytes {
        Bytes::from(datagram)
    }

    /// Make repliable datagram.
    pub fn make_datagram(&mut self, datagram: Vec<u8>) -> Bytes {
        let signature = self.signing_key.sign(&datagram);

        let mut out = BytesMut::with_capacity(
            self.destination.serialized_len() + signature.len() + datagram.len(),
        );
        out.put_slice(&self.destination);
        out.put_slice(&signature);
        out.put_slice(&datagram);

        out.freeze()
    }

    /// Make repliable datagram2.
    pub fn make_datagram2(
        &mut self,
        payload: Vec<u8>,
        destination_hash: &[u8],
        options: Option<Mapping>,
    ) -> Bytes {
        let flags = DatagramFlags::new_v2(options, self.offline_signature.is_some()).serialize();
        let offline_signature = self.offline_signature.as_deref().unwrap_or(&[]);

        let mut out = BytesMut::with_capacity(
            self.destination.serialized_len()
                + flags.len()
                + offline_signature.len()
                + payload.len()
                + self.signing_key.signature_len(),
        );

        out.put_slice(&self.destination);

        // start of signed data
        let signed_data_start = out.len();

        out.put_slice(destination_hash);
        out.put_slice(&flags);
        out.put_slice(offline_signature);
        out.put_slice(&payload);
        // end of signed data

        let signature = self.signing_key.sign(&out[signed_data_start..]);

        // remove destination hash from message
        out.truncate(signed_data_start);
        out.put_slice(&flags);
        out.put_slice(offline_signature);
        out.put_slice(&payload);
        out.put_slice(&signature);

        out.freeze()
    }

    /// Make repliable datagram3.
    ///
    /// The sender is identified by the hash of its destination and the datagram is not signed.
    pub fn make_datagram3(&mut self, payload: Vec<u8>, options: Option<Mapping>) -> Bytes {
        let flags = DatagramFlags::new_v3(options).serialize();

        let mut out = BytesMut::with_capacity(32 + flags.len() + payload.len());
        out.put_slice(&self.destination_hash);
        out.put_slice(&flags);
        out.put_slice(&payload);

        out.freeze()
    }

    /// Find listener for a datagram of `protocol` sent to `dst_port`.
    ///
    /// A listener of the matching kind with the exact port is preferred, then one with the
    /// wildcard port, then a raw wildcard listener with the exact port and finally a raw wildcard
    /// listener with the wildcard port (the default sub-session).
    fn find_listener(&self, protocol: Protocol, dst_port: u16) -> Option<&DatagramListener> {
        let candidates = self.listeners.iter().filter(|listener| listener.accepts(protocol));

        candidates
            .clone()
            .find(|listener| listener.is_exact(protocol) && listener.listen_port == dst_port)
            .or_else(|| {
                candidates
                    .clone()
                    .find(|listener| listener.is_exact(protocol) && listener.listen_port == 0)
            })
            .or_else(|| candidates.clone().find(|listener| listener.listen_port == dst_port))
            .or_else(|| candidates.clone().find(|listener| listener.listen_port == 0))
    }

    /// Handle inbound datagram sent by `sender`, the remote destination the garlic session which
    /// delivered the datagram is bound to.
    ///
    /// Datagram2 and Datagram3 datagrams must come from the destination they claim to come from
    /// (Datagram3 is otherwise unauthenticated), Datagram1 and raw datagrams are forwarded as they
    /// are.
    pub fn on_datagram(&self, payload: I2cpPayload, sender: &DestinationId) -> crate::Result<()> {
        let I2cpPayload {
            dst_port,
            payload,
            protocol,
            src_port,
        } = payload;

        let Some(listener) = self.find_listener(protocol, dst_port) else {
            tracing::warn!(
                target: LOG_TARGET,
                ?protocol,
                ?dst_port,
                "no datagram listener for destination port",
            );
            return Err(Error::InvalidState);
        };
        let target = listener.target;

        // a raw listener with a wildcard protocol receives other datagram kinds as-is
        if core::matches!(listener.kind, SessionKind::Anonymous) {
            let mut out = BytesMut::with_capacity(payload.len() + 64);

            if listener.header {
                out.put_slice(
                    format!(
                        "FROM_PORT={src_port} TO_PORT={dst_port} PROTOCOL={}\n",
                        protocol.as_u8()
                    )
                    .as_bytes(),
                );
            }
            out.put_slice(&payload);

            let _ = self.datagram_tx.try_send(ForwardedDatagram {
                datagram: out.to_vec(),
                target,
            });

            return Ok(());
        }

        match protocol {
            Protocol::Datagram => {
                let (rest, destination) =
                    Destination::parse_frame(&payload).map_err(|_| Error::InvalidData)?;
                let (rest, signature) =
                    take::<_, _, ()>(destination.verifying_key().signature_len())(rest)
                        .map_err(|_| Error::InvalidData)?;

                match destination.verifying_key() {
                    SigningPublicKey::DsaSha1(_) => return Err(Error::NotSupported),
                    verifying_key => verifying_key.verify(rest, signature)?,
                }

                let info = format!(
                    "{} FROM_PORT={src_port} TO_PORT={dst_port}\n",
                    base64_encode(&*destination)
                );

                let info = info.as_bytes();

                let mut out = BytesMut::with_capacity(info.len() + rest.len());
                out.put_slice(info);
                out.put_slice(rest);

                let _ = self.datagram_tx.try_send(ForwardedDatagram {
                    datagram: out.to_vec(),
                    target,
                });

                Ok(())
            }
            Protocol::Datagram2 => {
                let (rest, destination) =
                    Destination::parse_frame(&payload).map_err(|_| Error::InvalidData)?;

                if &destination.id() != sender {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %sender,
                        claimed = %destination.id(),
                        "datagram2 sender doesn't match the garlic session, dropping",
                    );
                    return Err(Error::InvalidData);
                }

                // signed data starts right after the sender's destination
                let signed_data_start = payload.len() - rest.len();

                let (rest, flags) =
                    DatagramFlags::parse_frame(rest).map_err(|_| Error::InvalidData)?;

                let (_options, has_offsig) = match flags {
                    DatagramFlags::V2 {
                        options,
                        has_offsig,
                    } => (options, has_offsig),
                    _ => return Err(Error::InvalidData),
                };

                let (rest, verifying_key) = if has_offsig {
                    let (rest, offsig) =
                        OfflineSignature::parse_frame::<R>(rest, destination.verifying_key())
                            .map_err(|_| Error::InvalidData)?;

                    (rest, Cow::Owned(offsig.transient_key().clone()))
                } else {
                    (rest, Cow::Borrowed(destination.verifying_key()))
                };

                // signature is the last `signature_len` bytes of the datagram
                let signature_len = verifying_key.signature_len();

                if rest.len() < signature_len {
                    tracing::warn!(
                        target: LOG_TARGET,
                        datagram_len = ?payload.len(),
                        ?signature_len,
                        "datagram2 is too short to contain a signature",
                    );
                    return Err(Error::InvalidData);
                }

                // signed data = local destination hash + datagram2 content from flags to signature
                let signed_data = &payload[signed_data_start..payload.len() - signature_len];

                // allocate enough memory to store signed data and final output.
                let mut out =
                    BytesMut::with_capacity(signed_data.len() + self.destination_hash.len());

                out.put_slice(&self.destination_hash);
                out.put_slice(signed_data);

                // verify signature
                let (signature, payload) = take::<_, _, ()>(rest.len() - signature_len)(rest)
                    .map_err(|_| Error::InvalidData)?;

                match verifying_key.as_ref() {
                    SigningPublicKey::DsaSha1(_) => return Err(Error::NotSupported),
                    verifying_key => verifying_key.verify(&out, signature)?,
                }

                out.clear();

                let info = format!(
                    "{} FROM_PORT={src_port} TO_PORT={dst_port}\n",
                    base64_encode(&*destination)
                );

                let info = info.as_bytes();

                out.put_slice(info);
                out.put_slice(payload);

                let _ = self.datagram_tx.try_send(ForwardedDatagram {
                    datagram: out.to_vec(),
                    target,
                });

                Ok(())
            }
            Protocol::Datagram3 => {
                let (rest, hash) = take::<_, _, ()>(32usize)(payload.as_slice())
                    .map_err(|_| Error::InvalidData)?;

                // datagram3 isn't signed, the only assurance about the sender is that the garlic
                // session which delivered it is bound to the claimed destination
                if &DestinationId::from(hash) != sender {
                    tracing::warn!(
                        target: LOG_TARGET,
                        %sender,
                        claimed = %DestinationId::from(hash),
                        "datagram3 sender doesn't match the garlic session, dropping",
                    );
                    return Err(Error::InvalidData);
                }

                let (rest, flags) =
                    DatagramFlags::parse_frame(rest).map_err(|_| Error::InvalidData)?;
                let DatagramFlags::V3 { .. } = flags else {
                    return Err(Error::InvalidData);
                };

                // the client gets the base64 hash of the sender and resolves it with a naming
                // lookup if it wants to reply
                let info = format!(
                    "{} FROM_PORT={src_port} TO_PORT={dst_port}\n",
                    base64_encode(hash)
                );
                let info = info.as_bytes();

                let mut out = BytesMut::with_capacity(info.len() + rest.len());
                out.put_slice(info);
                out.put_slice(rest);

                let _ = self.datagram_tx.try_send(ForwardedDatagram {
                    datagram: out.to_vec(),
                    target,
                });

                Ok(())
            }
            // handled above, raw datagrams are only accepted by raw listeners
            Protocol::Anonymous => Err(Error::InvalidState),
            Protocol::Streaming => unreachable!(),
        }
    }

    /// Attempt to add datagram listener for `session_id` of kind `kind`.
    ///
    /// The forwarding target and the accepted traffic are parsed from `options`, see
    /// [`DatagramListener::new()`]. If a listener accepting the same traffic (kind, listen port and
    /// listen protocol) already exists, the listener is not added and `Err(())` is returned.
    pub fn add_listener(
        &mut self,
        session_id: Arc<str>,
        kind: SessionKind,
        options: &HashMap<String, String>,
    ) -> Result<(), ()> {
        let listener = DatagramListener::new(session_id, kind, options)?;

        if let Some(existing) =
            self.listeners.iter().find(|existing| existing.conflicts_with(&listener))
        {
            tracing::warn!(
                target: LOG_TARGET,
                ?existing,
                ?listener,
                "listener for the specified kind, listen port and protocol already exists",
            );
            return Err(());
        }

        tracing::debug!(
            target: LOG_TARGET,
            ?listener,
            "datagram listener added",
        );
        self.listeners.push(listener);

        Ok(())
    }

    /// Remove all datagram listeners of `session_id`.
    pub fn remove_listener(&mut self, session_id: &Arc<str>) {
        self.listeners.retain(|listener| &listener.session_id != session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{primitives::OfflineKeys, runtime::mock::MockRuntime};
    use thingbuf::mpsc::channel;

    fn options(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(key, value)| (key.to_string(), value.to_string())).collect()
    }

    fn localhost(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn create_datagram_session() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let mut manager = DatagramManager::<MockRuntime>::new(destination, tx, signing_key);
        manager
            .add_listener(
                "test".into(),
                SessionKind::Datagram,
                &options(&[("PORT", "8888")]),
            )
            .unwrap();

        let listener = manager.find_listener(Protocol::Datagram, 0).unwrap();
        assert_eq!(listener.target, localhost(8888));
        assert_eq!(listener.listen_port, 0);
        assert!(manager.find_listener(Protocol::Anonymous, 0).is_none());
        assert!(manager.find_listener(Protocol::Datagram2, 0).is_none());
    }

    #[test]
    fn create_datagram_session_with_dst_port() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let mut manager = DatagramManager::<MockRuntime>::new(destination, tx, signing_key);
        manager
            .add_listener(
                "test".into(),
                SessionKind::Datagram,
                &options(&[
                    ("PORT", "1337"),
                    ("FROM_PORT", "8889"),
                    ("HOST", "127.0.0.2"),
                ]),
            )
            .unwrap();

        // `LISTEN_PORT` defaults to `FROM_PORT`
        let listener = manager.find_listener(Protocol::Datagram, 8889).unwrap();
        assert_eq!(listener.target, "127.0.0.2:1337".parse().unwrap());
        assert_eq!(listener.listen_port, 8889);
        assert!(manager.find_listener(Protocol::Datagram, 0).is_none());
        assert!(manager.find_listener(Protocol::Datagram, 8890).is_none());
    }

    #[test]
    fn create_primary_session() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let manager = DatagramManager::<MockRuntime>::new(destination, tx, signing_key);

        assert!(manager.listeners.is_empty());
    }

    #[test]
    fn datagram2_roundtrip() {
        let (sender_destination, sender_signing_key) = Destination::random();
        let (receiver_destination, receiver_signing_key) = Destination::random();
        let (sender_tx, _sender_rx) = channel(16);
        let (receiver_tx, receiver_rx) = channel(16);

        let mut sender = DatagramManager::<MockRuntime>::new(
            sender_destination.clone(),
            sender_tx,
            sender_signing_key,
        );
        let mut receiver = DatagramManager::<MockRuntime>::new(
            receiver_destination,
            receiver_tx,
            receiver_signing_key,
        );
        receiver
            .add_listener(
                "test".into(),
                SessionKind::Datagram2,
                &options(&[("PORT", "8888")]),
            )
            .unwrap();

        let datagram =
            sender.make_datagram2(b"hello, world".to_vec(), &receiver.destination_hash, None);

        receiver
            .on_datagram(
                I2cpPayload {
                    dst_port: 0,
                    payload: datagram.to_vec(),
                    protocol: Protocol::Datagram2,
                    src_port: 0,
                },
                &sender_destination.id(),
            )
            .unwrap();

        let ForwardedDatagram {
            target,
            datagram: data,
        } = receiver_rx.try_recv().unwrap();
        let info = format!(
            "{} FROM_PORT=0 TO_PORT=0\n",
            base64_encode(&*sender_destination)
        );

        assert_eq!(target, localhost(8888));
        assert!(data.starts_with(info.as_bytes()));
        assert_eq!(&data[info.len()..], b"hello, world");

        // a datagram2 delivered by a garlic session of another destination is dropped
        assert!(receiver
            .on_datagram(
                I2cpPayload {
                    dst_port: 0,
                    payload: datagram.to_vec(),
                    protocol: Protocol::Datagram2,
                    src_port: 0,
                },
                &DestinationId::random(),
            )
            .is_err());
        assert!(receiver_rx.try_recv().is_err());
    }

    #[test]
    fn truncated_datagram2_is_rejected() {
        let (sender_destination, sender_signing_key) = Destination::random();
        let (receiver_destination, receiver_signing_key) = Destination::random();
        let (sender_tx, _sender_rx) = channel(16);
        let (receiver_tx, receiver_rx) = channel(16);

        let mut sender =
            DatagramManager::<MockRuntime>::new(sender_destination, sender_tx, sender_signing_key);
        let mut receiver = DatagramManager::<MockRuntime>::new(
            receiver_destination,
            receiver_tx,
            receiver_signing_key,
        );
        receiver
            .add_listener(
                "test".into(),
                SessionKind::Datagram2,
                &options(&[("PORT", "8888")]),
            )
            .unwrap();

        let datagram =
            sender.make_datagram2(b"hello, world".to_vec(), &receiver.destination_hash, None);
        let destination_len = sender.destination.serialized_len();

        // every truncation must yield an error, never a panic
        for len in [
            0,
            1,
            destination_len - 1,
            destination_len,
            destination_len + 1,
            destination_len + 2,
            destination_len + 10,
            datagram.len() - sender.signing_key.signature_len(),
            datagram.len() - 1,
        ] {
            assert!(receiver
                .on_datagram(
                    I2cpPayload {
                        dst_port: 0,
                        payload: datagram[..len].to_vec(),
                        protocol: Protocol::Datagram2,
                        src_port: 0,
                    },
                    &sender.destination.id()
                )
                .is_err());
        }

        assert!(receiver_rx.try_recv().is_err());
    }

    #[test]
    fn receive_datagram_on_non_existent_port() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let manager = DatagramManager::<MockRuntime>::new(destination, tx, signing_key);

        match manager.on_datagram(
            I2cpPayload {
                dst_port: 0,
                payload: vec![1, 3, 3, 7],
                protocol: Protocol::Datagram,
                src_port: 0,
            },
            &DestinationId::random(),
        ) {
            Err(Error::InvalidState) => {}
            _ => panic!("invalid result"),
        }
    }

    #[test]
    fn add_listener() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let mut manager = DatagramManager::<MockRuntime>::new(destination, tx, signing_key);

        assert!(manager
            .add_listener(
                "test".into(),
                SessionKind::Datagram,
                &options(&[("PORT", "2048"), ("FROM_PORT", "7777")])
            )
            .is_ok());
        assert_eq!(
            manager.find_listener(Protocol::Datagram, 7777).map(|listener| listener.target),
            Some(localhost(2048))
        );

        // explicit listen port takes precedence over `FROM_PORT`
        assert!(manager
            .add_listener(
                "test2".into(),
                SessionKind::Datagram,
                &options(&[
                    ("PORT", "2049"),
                    ("FROM_PORT", "7777"),
                    ("LISTEN_PORT", "7778")
                ])
            )
            .is_ok());
        assert_eq!(
            manager.find_listener(Protocol::Datagram, 7778).map(|listener| listener.target),
            Some(localhost(2049))
        );
    }

    #[test]
    fn add_listener_with_default_port() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let mut manager = DatagramManager::<MockRuntime>::new(destination, tx, signing_key);

        assert!(manager
            .add_listener(
                "test".into(),
                SessionKind::Datagram,
                &options(&[("PORT", "2048")])
            )
            .is_ok());
        assert_eq!(
            manager.find_listener(Protocol::Datagram, 0).map(|listener| listener.target),
            Some(localhost(2048))
        );
        // wildcard port receives datagrams sent to any port
        assert_eq!(
            manager.find_listener(Protocol::Datagram, 1337).map(|listener| listener.target),
            Some(localhost(2048))
        );
    }

    #[test]
    fn add_listener_invalid_options() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let mut manager = DatagramManager::<MockRuntime>::new(destination, tx, signing_key);

        // invalid port
        assert!(manager
            .add_listener(
                "test".into(),
                SessionKind::Datagram,
                &options(&[("PORT", "hello")])
            )
            .is_err());

        // port missing
        assert!(manager
            .add_listener(
                "test".into(),
                SessionKind::Datagram,
                &options(&[("FROM_PORT", "1")])
            )
            .is_err());

        // invalid listen port
        assert!(manager
            .add_listener(
                "test".into(),
                SessionKind::Datagram,
                &options(&[("PORT", "1"), ("FROM_PORT", "hello, world")])
            )
            .is_err());
        assert!(manager
            .add_listener(
                "test".into(),
                SessionKind::Datagram,
                &options(&[("PORT", "1"), ("LISTEN_PORT", "70000")])
            )
            .is_err());

        // host is not an ip address
        assert!(manager
            .add_listener(
                "test".into(),
                SessionKind::Datagram,
                &options(&[("PORT", "1"), ("HOST", "localhost")])
            )
            .is_err());

        // unsupported raw protocol
        assert!(manager
            .add_listener(
                "test".into(),
                SessionKind::Anonymous,
                &options(&[("PORT", "1"), ("PROTOCOL", "200")])
            )
            .is_err());
        assert!(manager
            .add_listener(
                "test".into(),
                SessionKind::Anonymous,
                &options(&[("PORT", "1"), ("LISTEN_PROTOCOL", "6")])
            )
            .is_err());

        assert!(manager.listeners.is_empty());
    }

    #[test]
    fn add_listener_src_port_already_taken() {
        let (destination, signing_key) = Destination::random();
        let (tx, _rx) = channel(16);

        let mut manager = DatagramManager::<MockRuntime>::new(destination, tx, signing_key);
        manager
            .add_listener(
                "test".into(),
                SessionKind::Datagram,
                &options(&[("PORT", "1337")]),
            )
            .unwrap();

        // same kind and listen port
        assert!(manager
            .add_listener(
                "test2".into(),
                SessionKind::Datagram,
                &options(&[("PORT", "1338")])
            )
            .is_err());
        assert_eq!(
            manager.find_listener(Protocol::Datagram, 0).map(|listener| listener.target),
            Some(localhost(1337))
        );

        // another kind with the same listen port is fine
        assert!(manager
            .add_listener(
                "test3".into(),
                SessionKind::Anonymous,
                &options(&[("PORT", "1339")])
            )
            .is_ok());
        assert_eq!(
            manager.find_listener(Protocol::Anonymous, 0).map(|listener| listener.target),
            Some(localhost(1339))
        );

        // removing the owner frees the port
        manager.remove_listener(&Arc::from("test"));
        assert!(manager
            .add_listener(
                "test2".into(),
                SessionKind::Datagram,
                &options(&[("PORT", "1338")])
            )
            .is_ok());
        assert_eq!(
            manager.find_listener(Protocol::Datagram, 0).map(|listener| listener.target),
            Some(localhost(1338))
        );
    }

    #[test]
    fn datagrams_routed_by_port_and_protocol() {
        let (destination, signing_key) = Destination::random();
        let (tx, rx) = channel(16);

        let mut manager = DatagramManager::<MockRuntime>::new(destination, tx, signing_key);
        // default raw sub-session, catches everything that isn't routed elsewhere
        manager
            .add_listener(
                "raw-any".into(),
                SessionKind::Anonymous,
                &options(&[("PORT", "1"), ("LISTEN_PROTOCOL", "0")]),
            )
            .unwrap();
        // raw sub-session for port 10
        manager
            .add_listener(
                "raw-10".into(),
                SessionKind::Anonymous,
                &options(&[("PORT", "2"), ("LISTEN_PORT", "10"), ("HEADER", "true")]),
            )
            .unwrap();
        // repliable sub-sessions for port 10 and any port
        manager
            .add_listener(
                "dgram-10".into(),
                SessionKind::Datagram,
                &options(&[("PORT", "3"), ("LISTEN_PORT", "10")]),
            )
            .unwrap();
        manager
            .add_listener(
                "dgram-any".into(),
                SessionKind::Datagram,
                &options(&[("PORT", "4")]),
            )
            .unwrap();

        let (sender, sender_key) = Destination::random();
        let (sender_tx, _sender_rx) = channel(16);
        let mut sender = DatagramManager::<MockRuntime>::new(sender, sender_tx, sender_key);

        let sender_id = sender.destination.id();
        let deliver =
            |manager: &DatagramManager<MockRuntime>, protocol, dst_port, payload: Bytes| {
                manager
                    .on_datagram(
                        I2cpPayload {
                            dst_port,
                            payload: payload.to_vec(),
                            protocol,
                            src_port: 7,
                        },
                        &sender_id,
                    )
                    .unwrap();
                let ForwardedDatagram { target, datagram } = rx.try_recv().unwrap();
                (target, datagram)
            };

        // raw to port 10 -> raw-10, with header
        let (target, data) = deliver(
            &manager,
            Protocol::Anonymous,
            10,
            Bytes::from_static(b"raw"),
        );
        assert_eq!(target, localhost(2));
        assert_eq!(data, b"FROM_PORT=7 TO_PORT=10 PROTOCOL=18\nraw");

        // raw to port 11 -> raw-any, no header
        let (target, data) = deliver(
            &manager,
            Protocol::Anonymous,
            11,
            Bytes::from_static(b"raw"),
        );
        assert_eq!(target, localhost(1));
        assert_eq!(data, b"raw");

        // repliable to port 10 -> dgram-10, to port 11 -> dgram-any
        let datagram = sender.make_datagram(b"hello".to_vec());
        let (target, _) = deliver(&manager, Protocol::Datagram, 10, datagram.clone());
        assert_eq!(target, localhost(3));
        let (target, _) = deliver(&manager, Protocol::Datagram, 11, datagram);
        assert_eq!(target, localhost(4));

        // datagram2 has no listener of its own kind -> raw wildcard listener, as-is
        let datagram = sender.make_datagram2(b"hello".to_vec(), &manager.destination_hash, None);
        let (target, data) = deliver(&manager, Protocol::Datagram2, 10, datagram.clone());
        assert_eq!(target, localhost(1));
        assert_eq!(data, datagram.to_vec());

        // once the default sub-session is removed, unrouted datagrams are dropped
        manager.remove_listener(&Arc::from("raw-any"));
        assert!(manager
            .on_datagram(
                I2cpPayload {
                    dst_port: 11,
                    payload: b"raw".to_vec(),
                    protocol: Protocol::Anonymous,
                    src_port: 7,
                },
                &sender_id
            )
            .is_err());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn datagram2_offline_signed_roundtrip() {
        let (sender_destination, sender_signing_key) = Destination::random();
        let (receiver_destination, receiver_signing_key) = Destination::random();
        let (sender_tx, _sender_rx) = channel(16);
        let (receiver_tx, receiver_rx) = channel(16);
        let now = MockRuntime::time_since_epoch().as_secs() as u32;
        let keys = OfflineKeys::create::<MockRuntime>(&sender_signing_key, now + 3600);

        let mut sender = DatagramManager::<MockRuntime>::new(
            sender_destination.clone(),
            sender_tx,
            keys.transient_key().clone(),
        )
        .with_offline_signature(Some(Bytes::copy_from_slice(keys.signature().serialized())));
        let mut receiver = DatagramManager::<MockRuntime>::new(
            receiver_destination,
            receiver_tx,
            receiver_signing_key,
        );
        receiver
            .add_listener(
                "test".into(),
                SessionKind::Datagram2,
                &options(&[("PORT", "8888")]),
            )
            .unwrap();

        let datagram =
            sender.make_datagram2(b"hello, world".to_vec(), &receiver.destination_hash, None);

        // flags advertise the offline signature
        let (rest, _) = Destination::parse_frame(&datagram).unwrap();
        match DatagramFlags::parse_frame(rest).unwrap().1 {
            DatagramFlags::V2 { has_offsig, .. } => assert!(has_offsig),
            _ => panic!("invalid flags"),
        }

        receiver
            .on_datagram(
                I2cpPayload {
                    dst_port: 0,
                    payload: datagram.to_vec(),
                    protocol: Protocol::Datagram2,
                    src_port: 0,
                },
                &sender_destination.id(),
            )
            .unwrap();

        let ForwardedDatagram {
            target,
            datagram: data,
        } = receiver_rx.try_recv().unwrap();
        let info = format!(
            "{} FROM_PORT=0 TO_PORT=0\n",
            base64_encode(&*sender_destination)
        );

        assert_eq!(target, localhost(8888));
        assert!(data.starts_with(info.as_bytes()));
        assert_eq!(&data[info.len()..], b"hello, world");

        // transient key without the offline signature section is rejected
        let mut sender = DatagramManager::<MockRuntime>::new(
            sender_destination,
            sender.datagram_tx.clone(),
            keys.transient_key().clone(),
        );
        let datagram =
            sender.make_datagram2(b"hello, world".to_vec(), &receiver.destination_hash, None);

        assert!(receiver
            .on_datagram(
                I2cpPayload {
                    dst_port: 0,
                    payload: datagram.to_vec(),
                    protocol: Protocol::Datagram2,
                    src_port: 0,
                },
                &sender.destination.id()
            )
            .is_err());
        assert!(receiver_rx.try_recv().is_err());
    }

    #[test]
    fn datagram3_roundtrip() {
        let (sender_destination, sender_signing_key) = Destination::random();
        let (receiver_destination, receiver_signing_key) = Destination::random();
        let (sender_tx, _sender_rx) = channel(16);
        let (receiver_tx, receiver_rx) = channel(16);

        let mut sender = DatagramManager::<MockRuntime>::new(
            sender_destination.clone(),
            sender_tx,
            sender_signing_key,
        );
        let mut receiver = DatagramManager::<MockRuntime>::new(
            receiver_destination,
            receiver_tx,
            receiver_signing_key,
        );
        receiver
            .add_listener(
                "test".into(),
                SessionKind::Datagram3,
                &options(&[("PORT", "8888")]),
            )
            .unwrap();

        let mut mapping = Mapping::default();
        mapping.insert("hello".into(), "world".into());
        let datagram = sender.make_datagram3(b"hello, world".to_vec(), Some(mapping));

        // sender hash, flags with options, payload
        assert_eq!(&datagram[..32], &sender.destination_hash);
        assert_eq!(&datagram[32..34], &[0x00, 0x13]);
        assert!(datagram.ends_with(b"hello, world"));

        receiver
            .on_datagram(
                I2cpPayload {
                    dst_port: 5,
                    payload: datagram.to_vec(),
                    protocol: Protocol::Datagram3,
                    src_port: 7,
                },
                &sender_destination.id(),
            )
            .unwrap();

        let ForwardedDatagram {
            target,
            datagram: data,
        } = receiver_rx.try_recv().unwrap();
        let info = format!(
            "{} FROM_PORT=7 TO_PORT=5\n",
            base64_encode(sender_destination.id().to_vec())
        );

        assert_eq!(target, localhost(8888));
        assert_eq!(info.len(), 44 + " FROM_PORT=7 TO_PORT=5\n".len());
        assert!(data.starts_with(info.as_bytes()));
        assert_eq!(&data[info.len()..], b"hello, world");

        // datagram3 without options
        let datagram = sender.make_datagram3(b"hi".to_vec(), None);
        assert_eq!(&datagram[32..34], &[0x00, 0x03]);
        receiver
            .on_datagram(
                I2cpPayload {
                    dst_port: 0,
                    payload: datagram.to_vec(),
                    protocol: Protocol::Datagram3,
                    src_port: 0,
                },
                &sender_destination.id(),
            )
            .unwrap();
        let ForwardedDatagram { datagram: data, .. } = receiver_rx.try_recv().unwrap();
        assert!(data.ends_with(b"\nhi"));

        // the claimed sender must be the destination of the garlic session
        assert!(receiver
            .on_datagram(
                I2cpPayload {
                    dst_port: 0,
                    payload: datagram.to_vec(),
                    protocol: Protocol::Datagram3,
                    src_port: 0,
                },
                &DestinationId::random(),
            )
            .is_err());

        // truncated datagrams are rejected
        for len in [0, 1, 31, 32, 33] {
            assert!(receiver
                .on_datagram(
                    I2cpPayload {
                        dst_port: 0,
                        payload: datagram[..len].to_vec(),
                        protocol: Protocol::Datagram3,
                        src_port: 0,
                    },
                    &sender_destination.id(),
                )
                .is_err());
        }

        // datagram2 flags in a datagram3 are rejected
        let mut wrong_version = datagram.to_vec();
        wrong_version[33] = 0x02;
        assert!(receiver
            .on_datagram(
                I2cpPayload {
                    dst_port: 0,
                    payload: wrong_version,
                    protocol: Protocol::Datagram3,
                    src_port: 0,
                },
                &sender_destination.id(),
            )
            .is_err());
        assert!(receiver_rx.try_recv().is_err());
    }
}
