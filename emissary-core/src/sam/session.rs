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
    crypto::{
        base32_decode, base32_encode, base64_encode, blinding::BlindedPublicKey, sha256::Sha256,
        SigningPrivateKey,
    },
    destination::{DeliveryStyle, Destination, DestinationEvent, LeaseSetStatus},
    error::QueryError,
    events::EventHandle,
    i2cp::{I2cpPayload, I2cpPayloadBuilder},
    primitives::{
        Destination as Dest, DestinationId, EncryptedLeaseSet2, Lease, LeaseSet2, LeaseSet2Header,
        Mapping, OfflineKeys, Str,
    },
    protocol::Protocol,
    runtime::{AddressBook, JoinSet, Runtime},
    sam::{
        parser::{DestinationContext, SamCommand, SessionKind},
        pending::session::SamSessionContext,
        protocol::{
            datagram::DatagramManager,
            streaming::{Direction, ListenerKind, StreamManager, StreamManagerEvent},
        },
        socket::SamSocket,
        types::{
            PendingSession, PendingSessionState, PublicKeyContext, SamSessionCommand,
            SamSessionCommandRecycle, SamSessionKind, SubSession,
        },
        SubSessionCommand,
    },
};

use bytes::{BufMut, Bytes, BytesMut};
use futures::StreamExt;
use hashbrown::HashMap;
use thingbuf::mpsc::{Receiver, Sender};

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::sam::session";

/// How long a published lease set is valid.
const LEASE_SET_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// Create a lease set for the local destination `destination` from `leases`.
///
/// The lease set is signed with `signing_key` which is the transient key if `offline_keys` is
/// `Some`, in which case the lease set header advertises the offline signature.
fn make_local_lease_set(
    destination: &Dest,
    options: &HashMap<String, String>,
    public_key_context: &PublicKeyContext,
    signing_key: &SigningPrivateKey,
    offline_keys: Option<&OfflineKeys>,
    leases: Vec<Lease>,
    published: u32,
) -> Bytes {
    Bytes::from(
        LeaseSet2 {
            header: LeaseSet2Header {
                destination: destination.clone(),
                expires: LEASE_SET_LIFETIME.as_secs() as u32,
                is_unpublished: options
                    .get("i2cp.dontPublishLeaseSet")
                    .map(|value| value.parse::<bool>().unwrap_or(false))
                    .unwrap_or(false),
                offline_signature: offline_keys.map(|keys| keys.signature().clone()),
                published,
            },
            public_keys: public_key_context.public_keys(),
            leases,
        }
        .serialize(signing_key),
    )
}

/// Does the session publish its lease set encrypted (`i2cp.leaseSetType=5`).
fn is_encrypted_lease_set(options: &HashMap<String, String>) -> bool {
    options
        .get("i2cp.leaseSetType")
        .map(|value| value.trim() == "5")
        .unwrap_or(false)
}

/// Publish `lease_set`, expiring at `expires` (seconds since epoch), to `NetDb`.
///
/// If `encrypted` is true, the lease set is published as an encrypted lease set under the
/// blinded key of `signing_key`. Keys that cannot be blinded fall back to a plain lease set.
fn publish_local_lease_set<R: Runtime>(
    destination: &mut Destination<R>,
    lease_set: Bytes,
    expires: u32,
    signing_key: &SigningPrivateKey,
    encrypted: bool,
) {
    if encrypted {
        match EncryptedLeaseSet2::encrypt::<R>(&lease_set, expires, signing_key) {
            Some(bundle) => return destination.publish_encrypted_lease_set(lease_set, bundle),
            None => tracing::warn!(
                target: LOG_TARGET,
                "signing key cannot be blinded, publishing a plain lease set",
            ),
        }
    }

    destination.publish_lease_set(lease_set);
}

/// Active SAMv3 session.
pub struct SamSession<R: Runtime> {
    /// Address book.
    address_book: Option<Arc<dyn AddressBook>>,

    /// I2P datagram manager.
    datagram_manager: DatagramManager<R>,

    /// [`Dest`] of the session.
    ///
    /// Used to create new lease sets.
    dest: Dest,

    /// [`Destination`] of the session.
    destination: Destination<R>,

    /// Event handle.
    #[allow(unused)]
    event_handle: EventHandle<R>,

    /// Pending host lookups
    lookup_futures: R::JoinSet<(String, Option<String>)>,

    /// Offline keys, if the destination's own signing key is kept offline.
    ///
    /// `signing_key` is the transient key in that case.
    offline_keys: Option<OfflineKeys>,

    /// Session options.
    options: HashMap<String, String>,

    /// Pending host lookups.
    ///
    /// Pending `NAMING LOOKUP` queries for `.b32.i2p` addresses are stored here
    /// while the corresponding lease set is being queried.
    pending_host_lookups: HashMap<DestinationId, String>,

    /// Pending outbound sessions.
    ///
    /// `STREAM CONNECT` is marked pending if there is no active lease set for the remote
    /// destination. The stream is moved from pending to active/rejected, based on the lease set
    /// query result. The stream is also set into pending state even if a lease set is found,
    /// for the duration of the handshake process and if the remote doesn't answer any of the three
    /// `SYN` messages that are sent, the stream is destroyed.
    ///
    /// If a datagram is sent to a remote destination whose lease set is not available, the session
    /// is marked as pending until the lease set is found and all datagrams sent while the lease
    /// set is being queried are stored in the pending session state.
    pending_outbound: HashMap<DestinationId, PendingSession<R>>,

    /// Public key context for the session.
    public_key_context: PublicKeyContext,

    /// Receiver for commands sent for this session.
    ///
    /// Commands are dispatched by `SamServer` which ensures that [`SamCommand::CreateSession`]
    /// is never received by an active session.
    receiver: Receiver<SamSessionCommand<R>, SamSessionCommandRecycle>,

    /// Session ID.
    session_id: Arc<str>,

    /// Session kind.
    session_kind: SamSessionKind,

    /// Signing key.
    signing_key: SigningPrivateKey,

    /// Socket for reading session-related commands from the client.
    ///
    /// Set to `None` after the socket has been closed and th session is being destroyed.
    socket: Option<Box<SamSocket<R>>>,

    /// I2P virtual stream manager.
    stream_manager: StreamManager<R>,

    /// Number of sub-sessions created so far, used to order sub-sessions by creation time.
    sub_session_counter: u64,

    /// TX channel for sending session IDs of sub-sessions to `SamServer`
    ///
    /// `None` if `session_kind` is not `SessionKind::Primary`.
    sub_session_tx: Option<Sender<SubSessionCommand>>,

    /// Waker.
    waker: Option<Waker>,
}

impl<R: Runtime> SamSession<R> {
    /// Create new [`SamSession`].
    pub fn new(context: SamSessionContext<R>) -> Self {
        let SamSessionContext {
            address_book,
            datagram_tx,
            destination,
            event_handle,
            inbound,
            mut socket,
            netdb_handle,
            options,
            outbound,
            profile_storage,
            receiver,
            session_id,
            session_kind,
            sub_session_tx,
            tunnel_pool_handle,
        } = context;

        let (session_destination, dest, privkey, public_key_context, signing_key, offline_keys) = {
            let DestinationContext {
                destination,
                private_key,
                signing_key,
                offline_keys,
            } = destination;
            let destination_id = destination.id();

            // from specification:
            //
            // "The $privkey is the base 64 of the concatenation of the Destination followed by the
            // Private Key followed by the Signing Private Key, optionally followed by the Offline
            // Signature, which is 663 or more bytes in binary and 884 or more bytes in base 64,
            // depending on signature type. The binary format is specified in Private Key File."
            //
            // "If the SESSION CREATE contained a signing private key of all zeros and an Offline
            // Signature section, the SESSION STATUS reply will include the same data in the same
            // format."
            let privkey = {
                let mut out = BytesMut::with_capacity(destination.serialized_len() + 2 * 32);
                out.put_slice(&destination.serialize());
                out.put_slice((*private_key).as_ref());

                match &offline_keys {
                    Some(offline_keys) => {
                        out.put_slice(&vec![0u8; destination.signing_key_length()]);
                        out.put_slice(&offline_keys.serialize());
                    }
                    None => out.put_slice((*signing_key).as_ref()),
                }

                base64_encode(out)
            };

            // create public key context for the session.
            let public_key_context = PublicKeyContext::new::<R>(&options);

            // create leaseset for the destination and store it in `NetDb`
            let is_unpublished = options
                .get("i2cp.dontPublishLeaseSet")
                .map(|value| value.parse::<bool>().unwrap_or(false))
                .unwrap_or(false);
            let is_encrypted = is_encrypted_lease_set(&options);
            let published = R::time_since_epoch().as_secs() as u32;

            let local_leaseset = make_local_lease_set(
                &destination,
                &options,
                &public_key_context,
                &signing_key,
                offline_keys.as_ref(),
                inbound.values().cloned().collect(),
                published,
            );

            // publish the new destination to the event system
            //
            // destinations with encrypted lease sets are reachable through their b33 address
            let address = match is_encrypted {
                true => BlindedPublicKey::new(&signing_key.public()).map(|key| key.to_b33()),
                false => None,
            };
            if is_unpublished {
                event_handle.client_destination_started(session_id.to_string());
            } else {
                event_handle.server_destination_started(
                    session_id.to_string(),
                    address.clone().unwrap_or_else(|| base32_encode(destination_id.to_vec())),
                );
            }

            let mut session_destination = Destination::new(
                destination_id.clone(),
                public_key_context.private_key(),
                public_key_context.public_keys(),
                local_leaseset.clone(),
                netdb_handle,
                tunnel_pool_handle,
                outbound.into_iter().collect(),
                inbound.into_values().collect(),
                is_unpublished,
                profile_storage,
            );
            // TODO: not needed anymore?
            publish_local_lease_set::<R>(
                &mut session_destination,
                local_leaseset.clone(),
                published.saturating_add(LEASE_SET_LIFETIME.as_secs() as u32),
                &signing_key,
                is_encrypted,
            );

            tracing::info!(
                target: LOG_TARGET,
                %session_id,
                %destination_id,
                b33 = ?address,
                offline_keys = ?offline_keys.as_ref().map(|keys| keys.signature().expires()),
                "start active session",
            );

            (
                session_destination,
                destination,
                privkey,
                public_key_context,
                signing_key,
                offline_keys,
            )
        };

        socket.send_message(
            format!("SESSION STATUS RESULT=OK DESTINATION={privkey}\n").as_bytes().to_vec(),
        );

        let offline_signature = offline_keys
            .as_ref()
            .map(|keys| Bytes::copy_from_slice(keys.signature().serialized()));

        let mut datagram_manager =
            DatagramManager::new(dest.clone(), datagram_tx, *signing_key.clone())
                .with_offline_signature(offline_signature.clone());

        // datagram sessions forward inbound datagrams to the client's udp socket
        if core::matches!(
            session_kind,
            SessionKind::Datagram | SessionKind::Anonymous | SessionKind::Datagram2
        ) && datagram_manager
            .add_listener(Arc::clone(&session_id), session_kind, &options)
            .is_err()
        {
            tracing::warn!(
                target: LOG_TARGET,
                %session_id,
                "invalid datagram forwarding configuration, inbound datagrams are dropped",
            );
        }

        Self {
            address_book,
            datagram_manager,
            dest: dest.clone(),
            destination: session_destination,
            public_key_context,
            event_handle,
            lookup_futures: R::join_set(),
            offline_keys,
            options,
            pending_host_lookups: HashMap::new(),
            pending_outbound: HashMap::new(),
            receiver,
            session_id,
            session_kind: match session_kind {
                SessionKind::Stream => SamSessionKind::Stream,
                SessionKind::Datagram => SamSessionKind::Datagram {
                    kind: SessionKind::Datagram,
                },
                SessionKind::Anonymous => SamSessionKind::Datagram {
                    kind: SessionKind::Anonymous,
                },
                SessionKind::Datagram2 => SamSessionKind::Datagram {
                    kind: SessionKind::Datagram2,
                },
                SessionKind::Primary => SamSessionKind::Primary {
                    sub_sessions: HashMap::new(),
                },
            },
            signing_key: *signing_key.clone(),
            socket: Some(socket),
            stream_manager: StreamManager::new(dest, *signing_key)
                .with_offline_signature(offline_signature),
            sub_session_counter: 0u64,
            sub_session_tx,
            waker: None,
        }
    }

    /// Create outbound stream for a remote destiantion who's lease set has been resolved.
    ///
    /// The stream is considered pending and it's acceptance contingent on the remote destination
    /// responding to us within a reasonable time frame.
    fn create_outbound_stream(
        &mut self,
        destination_id: DestinationId,
        socket: Box<SamSocket<R>>,
        options: HashMap<String, String>,
        listen_port: u16,
    ) {
        let handle = self.destination.routing_path_handle(destination_id.clone());
        let (stream_id, packet, delivery_style, src_port, dst_port) = self
            .stream_manager
            .create_stream(destination_id.clone(), handle, socket, options, listen_port);

        tracing::trace!(
            target: LOG_TARGET,
            %destination_id,
            ?stream_id,
            ?src_port,
            ?dst_port,
            "create pending outbound stream",
        );

        // mark the stream as pending & waiting for session to be opened
        //
        // from now on `StreamManager` will drive forward the stream progress and will
        // emit an event when the stream opens/fails to open
        self.pending_outbound
            .entry(destination_id.clone())
            .or_insert(PendingSession::<R>::new())
            .streams
            .push(PendingSessionState::AwaitingSession { stream_id });

        let Some(message) = I2cpPayloadBuilder::<R>::new(&packet)
            .with_protocol(Protocol::Streaming)
            .with_source_port(src_port)
            .with_destination_port(dst_port)
            .build()
        else {
            tracing::error!(
                target: LOG_TARGET,
                session_id = ?self.session_id,
                "failed to create i2cp payload",
            );
            debug_assert!(false);
            return;
        };

        if let Err(error) = self.destination.send_message(delivery_style, message) {
            tracing::error!(
                target: LOG_TARGET,
                session_id = ?self.session_id,
                ?error,
                "failed to send message to remote peer",
            );
            debug_assert!(false);
        }
    }

    /// Handle `STREAM CONNECT`.
    fn on_stream_connect(
        &mut self,
        mut socket: Box<SamSocket<R>>,
        destination_id: DestinationId,
        blinded: Option<BlindedPublicKey>,
        options: HashMap<String, String>,
        session_id: Arc<str>,
    ) {
        if !self.session_kind.supports_streams(&session_id) {
            tracing::warn!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                stream_kind = ?self.session_kind,
                "session style doesn't support streams",
            );

            return drop(socket);
        };

        if destination_id == self.dest.id() {
            tracing::warn!(
                target: LOG_TARGET,
                "tried to open connection to self",
            );

            R::spawn(async move {
                let _ = socket
                    .send_message_blocking(b"STREAM STATUS RESULT=CANT_REACH_PEER\n".to_vec())
                    .await;
            });
            return;
        }

        tracing::info!(
            target: LOG_TARGET,
            session_id = %self.session_id,
            destination_id = %destination_id,
            encrypted = ?blinded.is_some(),
            "connect to destination",
        );

        // the lease set of a blinded destination is looked up and decrypted with its blinded key
        if let Some(key) = blinded {
            let registered = self.destination.register_blinded_destination(key);
            debug_assert_eq!(registered, destination_id);
        }

        let listen_port = self.session_kind.listen_port(&session_id);

        match self.destination.query_lease_set(&destination_id) {
            LeaseSetStatus::Found => {
                tracing::trace!(
                    target: LOG_TARGET,
                    session_id = ?self.session_id,
                    %destination_id,
                    "lease set found, create outbound stream",
                );

                self.create_outbound_stream(destination_id, socket, options, listen_port);
            }
            status @ (LeaseSetStatus::NotFound | LeaseSetStatus::Pending) => {
                tracing::trace!(
                    target: LOG_TARGET,
                    session_id = %self.session_id,
                    %destination_id,
                    ?status,
                    "lease set query started or pending, mark outbound stream as pending",
                );

                self.pending_outbound
                    .entry(destination_id.clone())
                    .or_insert(PendingSession::<R>::new())
                    .streams
                    .push(PendingSessionState::AwaitingLeaseSet {
                        socket,
                        options,
                        listen_port,
                    });
            }
        }
    }

    /// Handle `STREAM ACCEPT` command.
    ///
    /// Register the socket as an active listener to [`StreamManager`].
    ///
    /// If the session wasn't configured to use streams, reject the accept request.
    fn on_stream_accept(
        &mut self,
        socket: Box<SamSocket<R>>,
        options: HashMap<String, String>,
        session_id: Arc<str>,
    ) {
        if !self.session_kind.supports_streams(&session_id) {
            tracing::warn!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                stream_kind = ?self.session_kind,
                "session style doesn't support streams",
            );

            return drop(socket);
        };

        let listen_port = self.session_kind.listen_port(&session_id);

        if let Err(error) = self.stream_manager.register_listener(
            ListenerKind::Ephemeral {
                pending_routing_path_handle: self.destination.pending_routing_path_handle(),
                socket,
                silent: options
                    .get("SILENT")
                    .is_some_and(|value| value.parse::<bool>().unwrap_or(false)),
            },
            listen_port,
        ) {
            tracing::warn!(
                target: LOG_TARGET,
                ?error,
                session_id = %self.session_id,
                "failed to register ephemeral listener",
            );
        }
    }

    /// Handle `STREAM FORWARD` command.
    ///
    /// Register the socket as an active listener to [`StreamManager`].
    ///
    /// If the session wasn't configured to use streams, reject the forward request.
    fn on_stream_forward(
        &mut self,
        socket: Box<SamSocket<R>>,
        port: u16,
        options: HashMap<String, String>,
        session_id: Arc<str>,
    ) {
        if !self.session_kind.supports_streams(&session_id) {
            tracing::warn!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                stream_kind = ?self.session_kind,
                "session style doesn't support streams",
            );

            return drop(socket);
        };

        // streams are forwarded to `HOST`:`PORT`, `HOST` defaults to localhost
        let host = match options.get("HOST") {
            None => IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(host) => match host.parse::<IpAddr>() {
                Ok(host) => host,
                Err(error) => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        %host,
                        ?error,
                        "invalid `HOST` for `STREAM FORWARD`, must be an ip address",
                    );

                    let mut socket = socket;
                    R::spawn(async move {
                        let _ = socket
                            .send_message_blocking(
                                b"STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"invalid host\"\n"
                                    .to_vec(),
                            )
                            .await;
                    });
                    return;
                }
            },
        };
        let listen_port = self.session_kind.listen_port(&session_id);

        if let Err(error) = self.stream_manager.register_listener(
            ListenerKind::Persistent {
                pending_routing_path_handle: self.destination.pending_routing_path_handle(),
                socket,
                address: SocketAddr::new(host, port),
                silent: options
                    .get("SILENT")
                    .is_some_and(|value| value.parse::<bool>().unwrap_or(false)),
            },
            listen_port,
        ) {
            tracing::warn!(
                target: LOG_TARGET,
                ?error,
                session_id = %self.session_id,
                "failed to register persistent listener",
            );
        }
    }

    /// Send datagram to destination.
    ///
    /// If the session wasn't configured to use streams, the datagram is dropped.
    fn on_send_datagram(
        &mut self,
        destination: Dest,
        datagram: Vec<u8>,
        session_id: Arc<str>,
        options: Option<Mapping>,
    ) {
        if !self.session_kind.supports_datagrams(&session_id) {
            tracing::warn!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                stream_kind = ?self.session_kind,
                "session style doesn't support datagrams",
            );
            return;
        }

        tracing::info!(
            target: LOG_TARGET,
            session_id = %self.session_id,
            destination_id = %destination.id(),
            style = ?self.session_kind,
            "send datagram",
        );
        let destination_id = destination.id();
        let protocol = self.session_kind.as_protocol(&session_id);

        match self.destination.query_lease_set(&destination_id) {
            LeaseSetStatus::Found => {
                let datagram = match protocol {
                    Protocol::Anonymous => self.datagram_manager.make_anonymous(datagram),
                    Protocol::Datagram => self.datagram_manager.make_datagram(datagram),
                    Protocol::Datagram2 => self.datagram_manager.make_datagram2(
                        datagram,
                        &Sha256::new().update(&*destination).finalize(),
                        options,
                    ),
                    Protocol::Streaming => unreachable!(),
                };

                if let Some(message) =
                    I2cpPayloadBuilder::<R>::new(&datagram).with_protocol(protocol).build()
                {
                    if let Err(error) = self
                        .destination
                        .send_message(DeliveryStyle::Unspecified { destination_id }, message)
                    {
                        tracing::warn!(
                            target: LOG_TARGET,
                            session_id = %self.session_id,
                            destination_id = %destination.id(),
                            ?error,
                            "failed to send repliable datagram",
                        )
                    }
                };
            }
            LeaseSetStatus::NotFound => {
                tracing::trace!(
                    target: LOG_TARGET,
                    session_id = %self.session_id,
                    %destination_id,
                    "lease set query started, mark outbound datagram as pending",
                );

                match self.pending_outbound.get_mut(&destination_id) {
                    Some(PendingSession { datagrams, .. }) => match datagrams {
                        None => {
                            *datagrams = Some((destination, vec![(protocol, datagram, options)]));
                        }
                        Some((_, datagrams)) => datagrams.push((protocol, datagram, options)),
                    },
                    None => {
                        self.pending_outbound.insert(
                            destination_id,
                            PendingSession {
                                streams: Vec::new(),
                                datagrams: Some((destination, vec![(protocol, datagram, options)])),
                            },
                        );
                    }
                }
            }
            LeaseSetStatus::Pending => {
                tracing::warn!(
                    target: LOG_TARGET,
                    session_id = %self.session_id,
                    %destination_id,
                    "received datagram while session was pending",
                );

                match self.pending_outbound.get_mut(&destination_id) {
                    Some(PendingSession { datagrams, .. }) => match datagrams {
                        None => {
                            *datagrams = Some((destination, vec![(protocol, datagram, options)]));
                        }
                        Some((_, datagrams)) => datagrams.push((protocol, datagram, options)),
                    },
                    None => {
                        self.pending_outbound.insert(
                            destination_id,
                            PendingSession {
                                streams: Vec::new(),
                                datagrams: Some((destination, vec![(protocol, datagram, options)])),
                            },
                        );
                    }
                }
            }
        }
    }

    /// Handle succeeded lease set query result.
    ///
    /// For each of the pending streams, create a new outbound stream which allocates context in
    /// [`StreamManger`] for it and creates a `SYN` packet which is sent sent in an NS message to
    /// remote destination.
    ///
    /// Same deal for datagrams: send all pending datagrams to remote destination in NS messages.
    ///
    /// All pending host lookups are also resolved with a success and the destination of the remote
    /// peer is sent via the active socket to client.
    fn on_lease_set_found(&mut self, destination_id: DestinationId) {
        tracing::trace!(
            target: LOG_TARGET,
            session_id = %self.session_id,
            %destination_id,
            "lease set found",
        );

        if let Some(PendingSession { streams, datagrams }) =
            self.pending_outbound.remove(&destination_id)
        {
            streams.into_iter().for_each(|state| match state {
                PendingSessionState::AwaitingLeaseSet {
                    socket,
                    options,
                    listen_port,
                } => {
                    self.create_outbound_stream(
                        destination_id.clone(),
                        socket,
                        options,
                        listen_port,
                    );
                }
                PendingSessionState::AwaitingSession { .. } => {
                    // new stream was opened but by the the time the initial `SYN` packet was sent,
                    // remote's lease set had expired and they had not sent us, a new lease set a
                    // lease set query was started and the lease set was found
                    //
                    // the new lease set can be ignored for `PendingSessionState::AwaitinSession`
                    // since the `SYN` packet was queued in `Destination` and
                    // was sent to remote destination when the lease set was
                    // received
                }
            });

            if let Some((destination, datagrams)) = datagrams {
                datagrams.into_iter().for_each(|(protocol, datagram, options)| {
                    let datagram = match protocol {
                        Protocol::Anonymous => self.datagram_manager.make_anonymous(datagram),
                        Protocol::Datagram => self.datagram_manager.make_datagram(datagram),
                        Protocol::Datagram2 => self.datagram_manager.make_datagram2(
                            datagram,
                            &Sha256::new().update(&*destination).finalize(),
                            options,
                        ),
                        Protocol::Streaming => unreachable!(),
                    };

                    if let Some(message) =
                        I2cpPayloadBuilder::<R>::new(&datagram).with_protocol(protocol).build()
                    {
                        if let Err(error) = self.destination.send_message(
                            DeliveryStyle::Unspecified {
                                destination_id: destination_id.clone(),
                            },
                            message,
                        ) {
                            tracing::warn!(
                                target: LOG_TARGET,
                                session_id = %self.session_id,
                                destination_id = %destination.id(),
                                ?error,
                                "failed to send repliable datagram",
                            )
                        }
                    };
                });
            }
        } else {
            tracing::debug!(
                target: LOG_TARGET,
                session_id = ?self.session_id,
                %destination_id,
                "lease set query succeeded but no stream is interested in the lease set",
            );
        }

        if let Some(name) = self.pending_host_lookups.remove(&destination_id) {
            tracing::trace!(
                target: LOG_TARGET,
                session_id = ?self.session_id,
                %destination_id,
                ?name,
                "lease set query succeeded for pending host lookup",
            );

            if let Some(socket) = &mut self.socket {
                socket.send_message(
                    format!(
                        "NAMING REPLY RESULT=OK NAME={name} VALUE={}\n",
                        base64_encode(
                            self.destination
                                .lease_set(&destination_id)
                                .header
                                .destination
                                .serialized()
                        ),
                    )
                    .as_bytes()
                    .to_vec(),
                );

                if let Some(waker) = self.waker.take() {
                    waker.wake_by_ref();
                }
            }
        }
    }

    /// Handle lease set query error for `destination_id`.
    ///
    /// Lease set query can fail for either streams, datagrams or a host lookup, either one of them,
    /// some of them all or all of them at the same time, depending on what kind protocol is being
    /// used.
    ///
    /// Any pending datagrams for the unreachable destiantion are discarded, an error is sent to the
    /// user on each of the active stream and if there are pending host lookups, the client is
    /// notified of the error via the open socket
    fn on_lease_set_not_found(&mut self, destination_id: DestinationId, error: QueryError) {
        tracing::trace!(
            target: LOG_TARGET,
            session_id = %self.session_id,
            %destination_id,
            ?error,
            "lease set not found",
        );

        if let Some(PendingSession { streams, datagrams }) =
            self.pending_outbound.remove(&destination_id)
        {
            if let Some((_, datagrams)) = datagrams {
                tracing::debug!(
                    target: LOG_TARGET,
                    %destination_id,
                    num_datagrams = ?datagrams.len(),
                    "discarding pending datagrams, lease set not found",
                );
            }

            let sockets = streams
                .into_iter()
                .filter_map(|state| match state {
                    PendingSessionState::AwaitingLeaseSet { socket, .. } => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            session_id = ?self.session_id,
                            %destination_id,
                            ?error,
                            "unable to open stream, lease set not found",
                        );

                        Some(socket)
                    }
                    PendingSessionState::AwaitingSession { stream_id } => {
                        // new stream was opened but by the the time the initial `SYN` packet was
                        // sent, remote's lease set had expired and they had
                        // not sent us, a new lease set a lease
                        // set query was started but the lease set was not found in the netdb
                        //
                        // as the remote cannot be contacted, remove the pending stream from
                        // `StreamManager`
                        tracing::warn!(
                            target: LOG_TARGET,
                            session_id = ?self.session_id,
                            %destination_id,
                            ?stream_id,
                            "stream awaiting session but remote lease set not found",
                        );

                        self.stream_manager.remove_session(&destination_id);
                        None
                    }
                })
                .collect::<Vec<_>>();

            if !sockets.is_empty() {
                R::spawn(async move {
                    for mut socket in sockets {
                        let _ = socket
                            .send_message_blocking(b"STREAM STATUS RESULT=CANT_REACH_PEER".to_vec())
                            .await;
                    }
                });
            }
        } else {
            tracing::debug!(
                target: LOG_TARGET,
                session_id = ?self.session_id,
                %destination_id,
                ?error,
                "lease set query failure but no stream is interested in the lease set",
            );
        }

        if let Some(name) = self.pending_host_lookups.remove(&destination_id) {
            tracing::debug!(
                target: LOG_TARGET,
                session_id = ?self.session_id,
                %destination_id,
                ?name,
                ?error,
                "lease set query failed for pending host lookup",
            );

            if let Some(socket) = &mut self.socket {
                socket.send_message(
                    format!("NAMING REPLY RESULT=KEY_NOT_FOUND NAME={name}\n").as_bytes().to_vec(),
                );

                if let Some(waker) = self.waker.take() {
                    waker.wake_by_ref();
                }
            }
        }
    }

    /// Handle one or more inbound messages.
    fn on_inbound_message(&mut self, messages: Vec<Vec<u8>>) {
        messages
            .into_iter()
            .for_each(|message| match I2cpPayload::decompress::<R>(message) {
                Some(payload) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        src_port = ?payload.src_port,
                        dst_port = ?payload.dst_port,
                        protocol = ?payload.protocol,
                        "handle protocol payload",
                    );

                    match payload.protocol {
                        Protocol::Streaming => {
                            if let Err(error) = self.stream_manager.on_packet(payload) {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    session_id = ?self.session_id,
                                    ?error,
                                    "failed to handle streaming protocol packet",
                                );
                            }
                        }
                        protocol =>
                            if let Err(error) = self.datagram_manager.on_datagram(payload) {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    session_id = ?self.session_id,
                                    ?protocol,
                                    ?error,
                                    "failed to handle datagram",
                                );
                            },
                    }
                }
                None => tracing::warn!(
                    target: LOG_TARGET,
                    session_id = ?self.session_id,
                    "failed to decompress i2cp payload",
                ),
            })
    }

    /// Handle `NAMING LOOKUP` query from the client.
    ///
    /// The query can either be for `ME`, meaning the [`Destination`] of [`SamSession`] is returned,
    /// a `.b32.i2p` which starts a lease set query for the destination. or a `.i2p` host name which
    /// is looked up from an address book if it exists.
    ///
    /// For `.b32.i2p`/`.i2p`, naming reply is deferred until the query is finished.
    fn on_naming_lookup(&mut self, name: String) {
        if name.as_str() == "ME" {
            tracing::debug!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                "naming lookup for self",
            );

            if let Some(socket) = &mut self.socket {
                socket.send_message(
                    format!(
                        "NAMING REPLY RESULT=OK NAME=ME VALUE={}\n",
                        base64_encode(self.dest.serialized())
                    )
                    .as_bytes()
                    .to_vec(),
                );
            }

            return;
        }

        // if the host name ends in `.b32.i2p`, validate the hostname and check if [`Destination`]
        // already holds the host's lease set and if not, start a query
        //
        // once the query finishes, the naming reply is sent to client
        if let Some(end) = name.find(".b32.i2p") {
            tracing::debug!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                "naming lookup for .b32.i2p address",
            );

            let start = if name.starts_with("http://") {
                7usize
            } else if name.starts_with("https://") {
                8usize
            } else {
                0usize
            };

            let message = match base32_decode(&name[start..end]) {
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        ?name,
                        "invalid .b32.i2p address",
                    );

                    Some(
                        format!("NAMING REPLY RESULT=INVALID_KEY NAME={name}\n")
                            .as_bytes()
                            .to_vec(),
                    )
                }
                Some(destination) => {
                    let destination_id = DestinationId::from(destination);

                    match self.destination.query_lease_set(&destination_id) {
                        LeaseSetStatus::Found => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                session_id = %self.session_id,
                                %destination_id,
                                ?name,
                                "lease set found for host",
                            );

                            Some(
                                format!(
                                    "NAMING REPLY RESULT=OK NAME={name} VALUE={}\n",
                                    base64_encode(
                                        self.destination
                                            .lease_set(&destination_id)
                                            .header
                                            .destination
                                            .serialized()
                                    )
                                )
                                .as_bytes()
                                .to_vec(),
                            )
                        }
                        status => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                session_id = %self.session_id,
                                %destination_id,
                                ?name,
                                ?status,
                                "lease set not found for host, query started",
                            );
                            self.pending_host_lookups.insert(destination_id, name);

                            None
                        }
                    }
                }
            };

            if let (Some(socket), Some(message)) = (&mut self.socket, message) {
                socket.send_message(message);
            }

            return;
        }

        let message = match name.find(".i2p") {
            None => {
                tracing::warn!(
                    target: LOG_TARGET,
                    session_id = %self.session_id,
                    ?name,
                    "invalid host name",
                );

                Some(format!("NAMING REPLY RESULT=INVALID_KEY NAME={name}\n").as_bytes().to_vec())
            }
            Some(_) => match &self.address_book {
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        ?name,
                        "address book doesn't exist",
                    );

                    Some(
                        format!("NAMING REPLY RESULT=KEY_NOT_FOUND NAME={name}\n")
                            .as_bytes()
                            .to_vec(),
                    )
                }
                Some(address_book) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?name,
                        "lookup name from address book",
                    );

                    let future = address_book.resolve_base64(name.clone());
                    self.lookup_futures.push(async move { (name, future.await) });

                    None
                }
            },
        };

        if let (Some(socket), Some(message)) = (&mut self.socket, message) {
            socket.send_message(message);
        }
    }

    /// Attempt to create new sub-session.
    ///
    /// The sub-session is rejected if [`SamSessionKind`] is not `Primary`, if there already exists
    /// a sub-session with the same session ID or if [`SamServer`] fails to send the sub-session ->
    /// primary session ID mapping to [`SamServer`].
    ///
    /// On success, the sub-session ID is added to the list of sub-sessions the primary session has.
    ///
    /// Returns a message indicating whether the sub-session was created successfully, which must be
    /// sent to the client.
    fn on_create_sub_session(
        &mut self,
        session_id: Arc<str>,
        session_kind: SessionKind,
        options: HashMap<String, String>,
    ) -> Vec<u8> {
        let SamSessionKind::Primary { sub_sessions } = &mut self.session_kind else {
            tracing::warn!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                sub_session_id = %session_id,
                kind = ?self.session_kind,
                "sub-sessions not supported for the configured session kind",
            );

            return b"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"not a primary session\"\n".to_vec();
        };

        if let Some(session_kind) = sub_sessions.get(&session_id) {
            tracing::warn!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                sub_session_id = %session_id,
                ?session_kind,
                "duplicate sub-session id",
            );

            return b"SESSION STATUS RESULT=DUPLICATE_ID\n".to_vec();
        }

        // inbound traffic is routed to sub-sessions by its local port, `LISTEN_PORT` which
        // defaults to `FROM_PORT`
        //
        // https://geti2p.net/en/docs/api/samv3#primary-sessions
        let listen_port = match options
            .get("LISTEN_PORT")
            .or_else(|| options.get("FROM_PORT"))
            .map_or(Ok(0u16), |port| port.parse::<u16>())
        {
            Ok(listen_port) => listen_port,
            Err(error) => {
                tracing::warn!(
                    target: LOG_TARGET,
                    session_id = %self.session_id,
                    sub_session_id = %session_id,
                    ?error,
                    "invalid listen port for sub-session",
                );

                return b"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"invalid listen port\"\n"
                    .to_vec();
            }
        };

        match session_kind {
            SessionKind::Stream => {
                // inbound streams are routed by port alone, two stream sub-sessions cannot share
                // a listen port
                if sub_sessions.values().any(|sub_session| {
                    core::matches!(sub_session.kind, SessionKind::Stream)
                        && sub_session.listen_port == listen_port
                }) {
                    tracing::warn!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        sub_session_id = %session_id,
                        ?listen_port,
                        "stream sub-session with the same listen port already exists",
                    );

                    return b"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"duplicate listen port\"\n"
                        .to_vec();
                }
            }
            SessionKind::Datagram | SessionKind::Anonymous | SessionKind::Datagram2 => {
                // repliable datagram1 datagrams cannot carry an offline signature
                if self.offline_keys.is_some()
                    && core::matches!(session_kind, SessionKind::Datagram)
                {
                    tracing::warn!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        sub_session_id = %session_id,
                        "offline keys are not supported for `STYLE=DATAGRAM` sub-sessions",
                    );

                    return b"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"offline keys not supported for datagram sessions\"\n".to_vec();
                }

                // inbound datagrams are routed to the sub-session's udp socket by the datagram
                // manager
                if self
                    .datagram_manager
                    .add_listener(Arc::clone(&session_id), session_kind, &options)
                    .is_err()
                {
                    return b"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"invalid datagram configuration\"\n".to_vec();
                }
            }
            SessionKind::Primary => {
                return b"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"invalid sub-session style\"\n"
                    .to_vec();
            }
        }

        // `sub_session_tx` must exist since the session kind is `Primary`
        if let Err(error) =
            self.sub_session_tx
                .as_ref()
                .expect("to exist")
                .try_send(SubSessionCommand::Add {
                    primary_session_id: Arc::clone(&self.session_id),
                    sub_session_id: Arc::clone(&session_id),
                })
        {
            tracing::warn!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                sub_session_id = %session_id,
                ?error,
                "failed register sub-session to sam server",
            );
            self.datagram_manager.remove_listener(&session_id);

            return b"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"internal error\"\n".to_vec();
        }

        tracing::debug!(
            target: LOG_TARGET,
            session_id = %self.session_id,
            sub_session_id = %session_id,
            ?session_kind,
            ?listen_port,
            "create new sub-session",
        );

        self.sub_session_counter += 1;
        sub_sessions.insert(
            Arc::clone(&session_id),
            SubSession {
                kind: session_kind,
                listen_port,
                created: self.sub_session_counter,
            },
        );

        format!("SESSION STATUS RESULT=OK ID=\"{session_id}\" MESSAGE=\"ADD {session_id}\"\n")
            .as_bytes()
            .to_vec()
    }

    /// Handle `DATAGRAM SEND`/`RAW SEND` received over the control socket.
    ///
    /// The datagram is sent through the session itself if it's a datagram session of `kind` or,
    /// for primary sessions, through the most recently added sub-session of `kind`.
    ///
    /// https://geti2p.net/en/docs/api/samv3#datagrams
    fn on_send_datagram_command(
        &mut self,
        destination: Dest,
        kind: SessionKind,
        datagram: Vec<u8>,
        options: HashMap<String, String>,
    ) {
        let session_id = match &self.session_kind {
            SamSessionKind::Datagram { kind: session_kind } if *session_kind == kind =>
                Arc::clone(&self.session_id),
            SamSessionKind::Primary { sub_sessions } => match sub_sessions
                .iter()
                .filter(|(_, sub_session)| sub_session.kind == kind)
                .max_by_key(|(_, sub_session)| sub_session.created)
                .map(|(session_id, _)| Arc::clone(session_id))
            {
                Some(session_id) => session_id,
                None => {
                    tracing::warn!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        ?kind,
                        "no sub-session for datagram sent over the control socket",
                    );
                    return;
                }
            },
            session_kind => {
                tracing::warn!(
                    target: LOG_TARGET,
                    session_id = %self.session_id,
                    ?session_kind,
                    ?kind,
                    "session style doesn't support datagrams sent over the control socket",
                );
                return;
            }
        };
        let options = (!options.is_empty()).then(|| {
            Mapping::from(
                options
                    .into_iter()
                    .map(|(key, value)| (Str::from(key), Str::from(value)))
                    .collect::<HashMap<Str, Str>>(),
            )
        });

        self.on_send_datagram(destination, datagram, session_id, options);
    }

    /// Handle `SESSION REMOVE` command.
    ///
    /// The sub-session's listeners are removed and its streams are closed, after which the
    /// sub-session ID can no longer be used to send or receive data.
    fn on_remove_sub_session(&mut self, session_id: Arc<str>) -> Vec<u8> {
        let SamSessionKind::Primary { sub_sessions } = &mut self.session_kind else {
            tracing::warn!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                sub_session_id = %session_id,
                kind = ?self.session_kind,
                "sub-sessions not supported for the configured session kind",
            );

            return b"SESSION STATUS RESULT=I2P_ERROR MESSAGE=\"not a primary session\"\n".to_vec();
        };

        let Some(sub_session) = sub_sessions.remove(&session_id) else {
            tracing::warn!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                sub_session_id = %session_id,
                "cannot remove unknown sub-session",
            );

            return b"SESSION STATUS RESULT=INVALID_ID MESSAGE=\"unknown sub-session\"\n".to_vec();
        };

        match sub_session.kind {
            SessionKind::Stream => self.stream_manager.remove_sub_session(sub_session.listen_port),
            _ => self.datagram_manager.remove_listener(&session_id),
        }

        // `sub_session_tx` must exist since the session kind is `Primary`
        if let Err(error) =
            self.sub_session_tx
                .as_ref()
                .expect("to exist")
                .try_send(SubSessionCommand::Remove {
                    sub_session_id: Arc::clone(&session_id),
                })
        {
            tracing::warn!(
                target: LOG_TARGET,
                session_id = %self.session_id,
                sub_session_id = %session_id,
                ?error,
                "failed to unregister sub-session from sam server",
            );
        }

        tracing::info!(
            target: LOG_TARGET,
            session_id = %self.session_id,
            sub_session_id = %session_id,
            kind = ?sub_session.kind,
            "sub-session removed",
        );

        format!("SESSION STATUS RESULT=OK ID=\"{session_id}\" MESSAGE=\"REMOVE {session_id}\"\n")
            .as_bytes()
            .to_vec()
    }
}

impl<R: Runtime> Future for SamSession<R> {
    type Output = Arc<str>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let command = match &mut self.socket {
                None => break,
                Some(socket) => match socket.poll_next_unpin(cx) {
                    Poll::Pending => break,
                    Poll::Ready(None) => {
                        tracing::info!(
                            target: LOG_TARGET,
                            session_id = %self.session_id,
                            "session socket closed, destroy session",
                        );

                        self.stream_manager.shutdown();
                        self.socket = None;
                        break;
                    }
                    Poll::Ready(Some(command)) => command,
                },
            };

            match command {
                SamCommand::NamingLookup { name } => self.on_naming_lookup(name),
                SamCommand::CreateSubSession {
                    session_id,
                    session_kind,
                    options,
                } => {
                    let message =
                        self.on_create_sub_session(Arc::from(session_id), session_kind, options);

                    if let Some(socket) = &mut self.socket {
                        socket.send_message(message);

                        if let Some(waker) = self.waker.take() {
                            waker.wake_by_ref();
                        }
                    }
                }
                SamCommand::SendDatagram {
                    destination,
                    kind,
                    datagram,
                    options,
                    ..
                } => self.on_send_datagram_command(*destination, kind, datagram, options),
                SamCommand::RemoveSubSession { session_id } => {
                    let message = self.on_remove_sub_session(Arc::from(session_id));

                    if let Some(socket) = &mut self.socket {
                        socket.send_message(message);

                        if let Some(waker) = self.waker.take() {
                            waker.wake_by_ref();
                        }
                    }
                }
                SamCommand::Quit => {
                    tracing::info!(
                        target: LOG_TARGET,
                        session_id = %self.session_id,
                        "shutting down session",
                    );
                    return Poll::Ready(Arc::clone(&self.session_id));
                }
                SamCommand::Ping(text) => {
                    let Some(ref mut socket) = self.socket else {
                        continue;
                    };

                    match text {
                        Some(text) => {
                            socket.send_message(format!("PONG {text}\n").as_bytes().to_vec());
                        }
                        None => {
                            socket.send_message(b"PONG\n".to_vec());
                        }
                    }
                }
                command => tracing::warn!(
                    target: LOG_TARGET,
                    %command,
                    "ignoring command for active session",
                ),
            }
        }

        loop {
            match self.receiver.poll_recv(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(SamSessionCommand::Connect {
                    socket,
                    blinded,
                    destination_id,
                    options,
                    session_id,
                })) => self.on_stream_connect(socket, destination_id, blinded, options, session_id),
                Poll::Ready(Some(SamSessionCommand::Accept {
                    socket,
                    options,
                    session_id,
                })) => self.on_stream_accept(socket, options, session_id),
                Poll::Ready(Some(SamSessionCommand::Forward {
                    socket,
                    port,
                    options,
                    session_id,
                })) => self.on_stream_forward(socket, port, options, session_id),
                Poll::Ready(Some(SamSessionCommand::SendDatagram {
                    destination,
                    datagram,
                    session_id,
                    options,
                })) => self.on_send_datagram(*destination, datagram, session_id, options),
                Poll::Ready(Some(SamSessionCommand::Dummy)) => unreachable!(),
            }
        }

        loop {
            match self.stream_manager.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(StreamManagerEvent::SendPacket {
                    delivery_style,
                    dst_port,
                    packet,
                    src_port,
                })) => {
                    let Some(message) = I2cpPayloadBuilder::<R>::new(&packet)
                        .with_protocol(Protocol::Streaming)
                        .with_source_port(src_port)
                        .with_destination_port(dst_port)
                        .build()
                    else {
                        tracing::warn!(
                            target: LOG_TARGET,
                            session_id = ?self.session_id,
                            "failed to create i2cp payload",
                        );
                        continue;
                    };

                    if let Err(error) = self.destination.send_message(delivery_style, message) {
                        tracing::warn!(
                            target: LOG_TARGET,
                            session_id = ?self.session_id,
                            ?error,
                            "failed to encrypt message",
                        );
                        debug_assert!(false);
                    };
                }
                Poll::Ready(Some(StreamManagerEvent::StreamOpened {
                    destination_id,
                    direction,
                })) => match direction {
                    Direction::Inbound => {}
                    Direction::Outbound => {
                        self.pending_outbound.remove(&destination_id);
                    }
                },
                Poll::Ready(Some(StreamManagerEvent::StreamRejected { destination_id })) => {
                    self.pending_outbound.remove(&destination_id);
                }
                Poll::Ready(Some(StreamManagerEvent::StreamClosed { destination_id })) => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        ?destination_id,
                        "stream closed",
                    );
                }
                Poll::Ready(Some(StreamManagerEvent::ShutDown)) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        "stream manager shut down, shutting down tunnel pool",
                    );
                    self.destination.shutdown();
                }
            }
        }

        loop {
            match self.destination.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some(DestinationEvent::Messages { messages })) =>
                    self.on_inbound_message(messages),
                Poll::Ready(Some(DestinationEvent::LeaseSetFound { destination_id })) =>
                    self.on_lease_set_found(destination_id),
                Poll::Ready(Some(DestinationEvent::BlindedLeaseSetFound {
                    blinded_id,
                    destination_id,
                })) => {
                    // streams and datagrams were queued under the blinded id, the remote is
                    // known by its real id from now on
                    if let Some(pending) = self.pending_outbound.remove(&blinded_id) {
                        self.pending_outbound.insert(destination_id.clone(), pending);
                    }
                    self.on_lease_set_found(destination_id);
                }
                Poll::Ready(Some(DestinationEvent::LeaseSetNotFound {
                    destination_id,
                    error,
                })) => self.on_lease_set_not_found(destination_id, error),
                Poll::Ready(Some(DestinationEvent::TunnelPoolShutDown)) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        "tunnel pool shut down, shutting down session",
                    );

                    return Poll::Ready(Arc::clone(&self.session_id));
                }
                Poll::Ready(Some(DestinationEvent::CreateLeaseSet { leases })) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        num_leases = ?leases.len(),
                        "create new lease set",
                    );

                    let published = R::time_since_epoch().as_secs() as u32;
                    let lease_set = make_local_lease_set(
                        &self.dest,
                        &self.options,
                        &self.public_key_context,
                        &self.signing_key,
                        self.offline_keys.as_ref(),
                        leases,
                        published,
                    );

                    let this = self.as_mut().get_mut();
                    publish_local_lease_set::<R>(
                        &mut this.destination,
                        lease_set,
                        published.saturating_add(LEASE_SET_LIFETIME.as_secs() as u32),
                        &this.signing_key,
                        is_encrypted_lease_set(&this.options),
                    );
                }
                Poll::Ready(Some(DestinationEvent::SessionTerminated { destination_id })) => {
                    tracing::info!(
                        target: LOG_TARGET,
                        session_id = ?self.session_id,
                        destination_id = %destination_id,
                        "session termianted with remote",
                    );
                    self.stream_manager.remove_session(&destination_id);
                }
            }
        }

        loop {
            match self.lookup_futures.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(Arc::clone(&self.session_id)),
                Poll::Ready(Some((name, result))) => {
                    let message = match result {
                        Some(destination) => {
                            tracing::trace!(
                                target: LOG_TARGET,
                                session_id = ?self.session_id,
                                %name,
                                "naming lookup succeeded",
                            );

                            format!("NAMING REPLY RESULT=OK NAME={name} VALUE={destination}\n")
                                .as_bytes()
                                .to_vec()
                        }
                        None => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                session_id = ?self.session_id,
                                %name,
                                "naming lookup failed",
                            );

                            format!("NAMING REPLY RESULT=KEY_NOT_FOUND NAME={name}\n")
                                .as_bytes()
                                .to_vec()
                        }
                    };

                    if let Some(socket) = &mut self.socket {
                        socket.send_message(message);

                        if let Some(waker) = self.waker.take() {
                            waker.wake_by_ref();
                        }
                    }
                }
            }
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::SigningPrivateKey,
        events::{EventManager, EventSubscriber},
        netdb::{NetDbAction, NetDbActionRecycle, NetDbHandle},
        primitives::Destination,
        profile::ProfileStorage,
        runtime::{
            mock::{MockRuntime, MockTcpStream},
            TcpStream,
        },
        sam::{parser::SessionKind, protocol::datagram::ForwardedDatagram, socket::SamSocket},
        tunnel::{TunnelMessage, TunnelMessageRecycle, TunnelPoolEvent, TunnelPoolHandle},
    };
    use thingbuf::mpsc;
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, BufReader},
        net,
    };

    #[allow(unused)]
    struct TestSessionContext {
        client_socket: net::TcpStream,
        datagram_rx: Receiver<ForwardedDatagram>,
        event_manager: EventManager<MockRuntime>,
        event_subscriber: EventSubscriber,
        netdb_rx: mpsc::Receiver<NetDbAction, NetDbActionRecycle>,
        shutdown_rx: futures_channel::oneshot::Receiver<()>,
        sub_rx: Receiver<SubSessionCommand>,
        tm_recv: mpsc::Receiver<TunnelMessage, TunnelMessageRecycle>,
        tp_event: mpsc::Sender<TunnelPoolEvent>,
        tx: Sender<SamSessionCommand<MockRuntime>, SamSessionCommandRecycle>,
    }

    #[test]
    fn encrypted_lease_set_option() {
        assert!(!is_encrypted_lease_set(&HashMap::new()));
        assert!(!is_encrypted_lease_set(&HashMap::from_iter([(
            "i2cp.leaseSetType".to_string(),
            "3".to_string()
        )])));
        assert!(is_encrypted_lease_set(&HashMap::from_iter([(
            "i2cp.leaseSetType".to_string(),
            "5".to_string()
        )])));
    }

    #[tokio::test]
    async fn encrypted_lease_set_published_under_store_hash() {
        use crate::crypto::blinding::{date_string, BlindedPublicKey};

        let (mut session, ctx) = create_session().await;
        let signing_key = session.signing_key.clone();
        let published = MockRuntime::time_since_epoch().as_secs() as u32;
        let lease_set = Bytes::from(
            LeaseSet2 {
                header: LeaseSet2Header {
                    destination: session.dest.clone(),
                    expires: LEASE_SET_LIFETIME.as_secs() as u32,
                    is_unpublished: false,
                    offline_signature: None,
                    published,
                },
                public_keys: session.public_key_context.public_keys(),
                leases: vec![LeaseSet2::random().0.leases[0].clone()],
            }
            .serialize(&signing_key),
        );

        // drain the actions caused by session creation
        while ctx.netdb_rx.try_recv().is_ok() {}

        publish_local_lease_set::<MockRuntime>(
            &mut session.destination,
            lease_set,
            published + LEASE_SET_LIFETIME.as_secs() as u32,
            &signing_key,
            true,
        );

        // the lease set manager looks for the floodfills closest to the store hash of the day
        let blinded = BlindedPublicKey::new(&signing_key.public()).unwrap();
        let store_hash = blinded.store_hash(&date_string(MockRuntime::time_since_epoch())).unwrap();

        match ctx.netdb_rx.try_recv().unwrap() {
            NetDbAction::GetClosestFloodfills { key, .. } => {
                assert_eq!(key, Bytes::from(store_hash.to_vec()));
            }
            _ => panic!("unexpected action"),
        }
    }

    #[tokio::test]
    async fn connect_to_blinded_destination() {
        let (mut session, _ctx) = create_session().await;
        let listener = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (stream, _) = tokio::join!(
            MockTcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream.unwrap()));

        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let blinded = BlindedPublicKey::new(&signing_key.public()).unwrap();
        let destination_id = DestinationId::from(blinded.public_key());

        session.on_stream_connect(
            socket,
            destination_id.clone(),
            Some(blinded.clone()),
            HashMap::new(),
            Arc::from("hello"),
        );

        // the destination is registered as blinded and its lease set is being queried
        assert_eq!(
            session.destination.blinded_key(&destination_id),
            Some(&blinded)
        );
        assert!(session.pending_outbound.contains_key(&destination_id));
    }

    async fn create_session() -> (SamSession<MockRuntime>, TestSessionContext) {
        create_session_with_keys(None).await
    }

    /// Create session, optionally for a destination with the given signing key and offline keys.
    async fn create_session_with_keys(
        offline_keys: Option<(SigningPrivateKey, OfflineKeys)>,
    ) -> (SamSession<MockRuntime>, TestSessionContext) {
        let listener = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let (signing_key, offline_keys) = match offline_keys {
            Some((signing_key, offline_keys)) => (signing_key, Some(offline_keys)),
            None => (SigningPrivateKey::random(MockRuntime::rng()), None),
        };
        let destination = Destination::new::<MockRuntime>(signing_key.public());

        let (datagram_tx, datagram_rx) = mpsc::channel(10);
        let (sub_tx, sub_rx) = mpsc::channel(10);
        let (netdb_handle, netdb_rx) = NetDbHandle::create();
        let (event_manager, event_subscriber, event_handle) =
            EventManager::new(None, MockRuntime::register_metrics(vec![], None));
        let (tunnel_pool_handle, tm_recv, tp_event, shutdown_rx) = TunnelPoolHandle::create();
        let (tx, rx) = mpsc::with_recycle(64, SamSessionCommandRecycle::default());

        let (stream1, stream2) = tokio::join!(MockTcpStream::connect(address), listener.accept());

        let socket = Box::new(SamSocket::<MockRuntime>::new(stream1.unwrap()));
        let (client_socket, _) = stream2.unwrap();
        let options =
            HashMap::from_iter([(String::from("i2cp.leaseSetEncType"), String::from("6,4"))]);

        (
            SamSession::new(SamSessionContext {
                address_book: None,
                datagram_tx,
                destination: DestinationContext {
                    destination,
                    private_key: Vec::new(),
                    signing_key: Box::new(match &offline_keys {
                        Some(offline_keys) => offline_keys.transient_key().clone(),
                        None => signing_key,
                    }),
                    offline_keys,
                },
                event_handle,
                inbound: Default::default(),
                netdb_handle,
                options,
                outbound: Default::default(),
                profile_storage: ProfileStorage::new(&[], &[], None),
                receiver: rx,
                session_id: "test".into(),
                session_kind: SessionKind::Stream,
                socket,
                sub_session_tx: Some(sub_tx),
                tunnel_pool_handle,
            }),
            TestSessionContext {
                client_socket,
                datagram_rx,
                event_manager,
                event_subscriber,
                netdb_rx,
                shutdown_rx,
                sub_rx,
                tm_recv,
                tp_event,
                tx,
            },
        )
    }

    #[tokio::test]
    async fn create_stream_sub_session() {
        let (mut session, _ctx) = create_session().await;
        session.session_kind = SamSessionKind::Primary {
            sub_sessions: HashMap::new(),
        };

        let result =
            session.on_create_sub_session("sub1".into(), SessionKind::Stream, HashMap::new());
        assert!(String::from_utf8_lossy(&result).contains("RESULT=OK"));

        if let SamSessionKind::Primary { sub_sessions } = &session.session_kind {
            assert!(sub_sessions.contains_key("sub1"));
            assert_eq!(
                sub_sessions.get("sub1").map(|sub_session| sub_session.kind),
                Some(SessionKind::Stream)
            );
        }
    }

    #[tokio::test]
    async fn duplicate_sub_session() {
        let (mut session, _ctx) = create_session().await;
        session.session_kind = SamSessionKind::Primary {
            sub_sessions: HashMap::new(),
        };

        // Create first sub-session
        let _ = session.on_create_sub_session("sub1".into(), SessionKind::Stream, HashMap::new());

        // Try to create duplicate
        let result =
            session.on_create_sub_session("sub1".into(), SessionKind::Stream, HashMap::new());
        assert!(String::from_utf8_lossy(&result).contains("DUPLICATE_ID"));
    }

    #[tokio::test]
    async fn non_primary_sub_session() {
        let (mut session, _ctx) = create_session().await;
        session.session_kind = SamSessionKind::Stream;

        let result =
            session.on_create_sub_session("sub1".into(), SessionKind::Stream, HashMap::new());
        assert!(String::from_utf8_lossy(&result).contains("not a primary session"));
    }

    #[tokio::test]
    async fn create_datagram_sub_session() {
        let (mut session, _ctx) = create_session().await;
        session.session_kind = SamSessionKind::Primary {
            sub_sessions: HashMap::new(),
        };

        let mut options = HashMap::new();
        options.insert("HOST".to_string(), "127.0.0.1".to_string());
        options.insert("PORT".to_string(), "1234".to_string());

        let result = session.on_create_sub_session("sub1".into(), SessionKind::Datagram, options);
        assert!(String::from_utf8_lossy(&result).contains("RESULT=OK"));

        if let SamSessionKind::Primary { sub_sessions } = &session.session_kind {
            assert!(sub_sessions.contains_key("sub1"));
            assert_eq!(
                sub_sessions.get("sub1").map(|sub_session| sub_session.kind),
                Some(SessionKind::Datagram)
            );
        }
    }

    #[tokio::test]
    async fn create_multiple_datagram_sub_sessions() {
        let (mut session, _ctx) = create_session().await;
        session.session_kind = SamSessionKind::Primary {
            sub_sessions: HashMap::new(),
        };

        // First subsession with default FROM_PORT (0)
        let mut options1 = HashMap::new();
        options1.insert("HOST".to_string(), "127.0.0.1".to_string());
        options1.insert("PORT".to_string(), "1234".to_string());

        let result = session.on_create_sub_session("sub1".into(), SessionKind::Datagram, options1);
        assert!(String::from_utf8_lossy(&result).contains("RESULT=OK"));

        // Second subsession with explicit FROM_PORT
        let mut options2 = HashMap::new();
        options2.insert("HOST".to_string(), "127.0.0.1".to_string());
        options2.insert("PORT".to_string(), "5678".to_string());
        options2.insert("FROM_PORT".to_string(), "9999".to_string());

        let result = session.on_create_sub_session("sub2".into(), SessionKind::Datagram, options2);
        assert!(String::from_utf8_lossy(&result).contains("RESULT=OK"));

        // Third subsession with different FROM_PORT
        let mut options3 = HashMap::new();
        options3.insert("HOST".to_string(), "127.0.0.1".to_string());
        options3.insert("PORT".to_string(), "8080".to_string());
        options3.insert("FROM_PORT".to_string(), "7777".to_string());

        let result = session.on_create_sub_session("sub3".into(), SessionKind::Datagram, options3);
        assert!(String::from_utf8_lossy(&result).contains("RESULT=OK"));

        // Verify all subsessions were registered
        if let SamSessionKind::Primary { sub_sessions } = &session.session_kind {
            assert_eq!(sub_sessions.len(), 3);
            assert_eq!(
                sub_sessions.get("sub1").map(|sub_session| sub_session.kind),
                Some(SessionKind::Datagram)
            );
            assert_eq!(
                sub_sessions.get("sub2").map(|sub_session| sub_session.kind),
                Some(SessionKind::Datagram)
            );
            assert_eq!(
                sub_sessions.get("sub3").map(|sub_session| sub_session.kind),
                Some(SessionKind::Datagram)
            );
        }

        // Try to create subsession with duplicate FROM_PORT (should fail)
        let mut options4 = HashMap::new();
        options4.insert("HOST".to_string(), "127.0.0.1".to_string());
        options4.insert("PORT".to_string(), "4444".to_string());
        options4.insert("FROM_PORT".to_string(), "9999".to_string());

        let result = session.on_create_sub_session("sub4".into(), SessionKind::Datagram, options4);
        assert!(String::from_utf8_lossy(&result).contains("invalid datagram configuration"));

        // Verify the failed attempt didn't affect existing mappings
        if let SamSessionKind::Primary { sub_sessions } = &session.session_kind {
            assert_eq!(sub_sessions.len(), 3);
        }
    }

    #[tokio::test]
    async fn reject_datagram_sub_session_with_occupied_port() {
        let (mut session, _ctx) = create_session().await;
        session.session_kind = SamSessionKind::Primary {
            sub_sessions: HashMap::new(),
        };

        // Create first subsession with PORT 1234
        let mut options1 = HashMap::new();
        options1.insert("HOST".to_string(), "127.0.0.1".to_string());
        options1.insert("PORT".to_string(), "1234".to_string());
        options1.insert("FROM_PORT".to_string(), "5555".to_string());

        let result = session.on_create_sub_session("sub1".into(), SessionKind::Datagram, options1);
        assert!(String::from_utf8_lossy(&result).contains("RESULT=OK"));

        // Try to create another subsession with same PORT but different FROM_PORT
        let mut options2 = HashMap::new();
        options2.insert("HOST".to_string(), "127.0.0.1".to_string());
        options2.insert("PORT".to_string(), "1234".to_string());
        options2.insert("FROM_PORT".to_string(), "5555".to_string());

        let result = session.on_create_sub_session("sub2".into(), SessionKind::Datagram, options2);
        assert!(String::from_utf8_lossy(&result).contains("invalid datagram configuration"));

        // Verify only the first subsession was registered
        if let SamSessionKind::Primary { sub_sessions } = &session.session_kind {
            assert_eq!(sub_sessions.len(), 1);
            assert_eq!(
                sub_sessions.get("sub1").map(|sub_session| sub_session.kind),
                Some(SessionKind::Datagram)
            );
        }
    }

    #[tokio::test]
    async fn register_sub_session_sam_server_exited() {
        let (mut session, _) = create_session().await;
        session.session_kind = SamSessionKind::Primary {
            sub_sessions: HashMap::new(),
        };

        let result =
            session.on_create_sub_session("sub1".into(), SessionKind::Stream, HashMap::new());
        assert!(String::from_utf8_lossy(&result).contains("internal error"));
    }

    #[tokio::test]
    async fn naming_lookup_me() {
        let (mut session, mut ctx) = create_session().await;
        session.on_naming_lookup("ME".to_string());
        tokio::spawn(async move { session.socket.as_mut().expect("to exist").next().await });

        // verify response contains base64 encoded destination
        let mut reader = BufReader::new(&mut ctx.client_socket);
        let mut response = String::new();

        // discard `SESSION STATUS` message
        reader.read_line(&mut response).await.expect("to succeed");

        // read `NAMING LOOKUP` message
        reader.read_line(&mut response).await.expect("to succeed");

        assert!(response.contains("NAMING REPLY RESULT=OK NAME=ME VALUE="));
        assert!(response.ends_with("\n"));
    }

    #[tokio::test]
    async fn naming_lookup_b32_invalid() {
        let (mut session, mut ctx) = create_session().await;
        session.on_naming_lookup("invalid.b32.i2p".to_string());
        tokio::spawn(async move { session.socket.as_mut().expect("to exist").next().await });

        // verify response contains base64 encoded destination
        let mut reader = BufReader::new(&mut ctx.client_socket);
        let mut response = String::new();

        // discard `SESSION STATUS` message
        reader.read_line(&mut response).await.expect("to succeed");

        // read `NAMING LOOKUP` message
        reader.read_line(&mut response).await.expect("to succeed");
        assert!(response.contains("RESULT=INVALID_KEY"));
        assert!(response.ends_with("\n"));
    }

    #[tokio::test]
    async fn naming_lookup_b32_with_http() {
        let (mut session, mut ctx) = create_session().await;

        // test with http:// prefix
        session.on_naming_lookup("http://abcdef.b32.i2p".to_string());
        tokio::spawn(async move { session.socket.as_mut().expect("to exist").next().await });

        // verify error response when no address book exists
        let mut reader = BufReader::new(&mut ctx.client_socket);
        let mut response = String::new();

        // discard `SESSION STATUS` message
        reader.read_line(&mut response).await.expect("to succeed");

        // read `NAMING LOOKUP` message
        reader.read_line(&mut response).await.expect("to succeed");
        assert!(response.contains("RESULT=INVALID_KEY"));
    }

    #[tokio::test]
    async fn naming_lookup_b32_with_https() {
        let (mut session, mut ctx) = create_session().await;

        // test with https:// prefix
        session.on_naming_lookup("https://abcdef.b32.i2p".to_string());
        tokio::spawn(async move { session.socket.as_mut().expect("to exist").next().await });

        // verify error response when no address book exists
        let mut reader = BufReader::new(&mut ctx.client_socket);
        let mut response = String::new();

        // discard `SESSION STATUS` message
        reader.read_line(&mut response).await.expect("to succeed");

        // read `NAMING LOOKUP` message
        reader.read_line(&mut response).await.expect("to succeed");
        assert!(response.contains("RESULT=INVALID_KEY"));
    }

    #[tokio::test]
    async fn naming_lookup_i2p_no_addressbook() {
        let (mut session, mut ctx) = create_session().await;
        session.on_naming_lookup("example.i2p".to_string());
        tokio::spawn(async move { session.socket.as_mut().expect("to exist").next().await });

        // verify error response when no address book exists
        let mut reader = BufReader::new(&mut ctx.client_socket);
        let mut response = String::new();

        // discard `SESSION STATUS` message
        reader.read_line(&mut response).await.expect("to succeed");

        // read `NAMING LOOKUP` message
        reader.read_line(&mut response).await.expect("to succeed");

        assert!(response.contains("RESULT=KEY_NOT_FOUND"));
        assert!(response.ends_with("\n"));
    }

    #[tokio::test]
    async fn naming_lookup_invalid_name() {
        let (mut session, mut ctx) = create_session().await;
        session.on_naming_lookup("invalid-name-without-tld".to_string());
        tokio::spawn(async move { session.socket.as_mut().expect("to exist").next().await });

        // verify error response for invalid hostname
        let mut reader = BufReader::new(&mut ctx.client_socket);
        let mut response = String::new();

        // discard `SESSION STATUS` message
        reader.read_line(&mut response).await.expect("to succeed");

        // read `NAMING LOOKUP` message
        reader.read_line(&mut response).await.expect("to succeed");

        assert!(response.contains("RESULT=INVALID_KEY"));
        assert!(response.ends_with("\n"));
    }

    #[tokio::test]
    async fn naming_lookup_clearnet() {
        let (mut session, mut ctx) = create_session().await;
        session.on_naming_lookup("https://google.com".to_string());
        tokio::spawn(async move { session.socket.as_mut().expect("to exist").next().await });

        // verify error response for invalid hostname
        let mut reader = BufReader::new(&mut ctx.client_socket);
        let mut response = String::new();

        // discard `SESSION STATUS` message
        reader.read_line(&mut response).await.expect("to succeed");

        // read `NAMING LOOKUP` message
        reader.read_line(&mut response).await.expect("to succeed");

        assert!(response.contains("RESULT=INVALID_KEY"));
        assert!(response.ends_with("\n"));
    }

    #[tokio::test]
    async fn stream_connect_for_repliable() {
        let (mut session, _ctx) = create_session().await;
        session.session_kind = SamSessionKind::Datagram {
            kind: SessionKind::Datagram,
        };

        let listener = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(MockTcpStream::connect(address), listener.accept());
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream1.unwrap()));
        let (mut client_socket, _) = stream2.unwrap();

        session.on_stream_connect(
            socket,
            DestinationId::random(),
            None,
            HashMap::new(),
            Arc::from("hello"),
        );

        let mut buf = vec![0u8; 128];
        match client_socket.read(&mut buf).await {
            Err(_) | Ok(0) => {}
            _ => panic!("invalid response"),
        }
    }

    #[tokio::test]
    async fn stream_connect_for_anonymous() {
        let (mut session, _ctx) = create_session().await;
        session.session_kind = SamSessionKind::Datagram {
            kind: SessionKind::Anonymous,
        };

        let listener = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(MockTcpStream::connect(address), listener.accept());
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream1.unwrap()));
        let (mut client_socket, _) = stream2.unwrap();

        session.on_stream_connect(
            socket,
            DestinationId::random(),
            None,
            HashMap::new(),
            Arc::from("hello"),
        );

        let mut buf = vec![0u8; 128];
        match client_socket.read(&mut buf).await {
            Err(_) | Ok(0) => {}
            _ => panic!("invalid response"),
        }
    }

    #[tokio::test]
    async fn stream_connect_for_self() {
        let (mut session, _ctx) = create_session().await;

        let listener = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(MockTcpStream::connect(address), listener.accept());
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream1.unwrap()));
        let (mut client_socket, _) = stream2.unwrap();

        session.on_stream_connect(
            socket,
            session.dest.id(),
            None,
            HashMap::new(),
            Arc::from("hello"),
        );
        tokio::spawn(async move { session.socket.as_mut().expect("to exist").next().await });

        // verify error response for invalid hostname
        let mut reader = BufReader::new(&mut client_socket);
        let mut response = String::new();

        // read `NAMING LOOKUP` message
        reader.read_line(&mut response).await.expect("to succeed");

        assert!(response.contains("STREAM STATUS RESULT=CANT_REACH_PEER"));
    }

    #[tokio::test]
    async fn stream_accept_for_repliable() {
        let (mut session, _ctx) = create_session().await;
        session.session_kind = SamSessionKind::Datagram {
            kind: SessionKind::Datagram,
        };

        let listener = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(MockTcpStream::connect(address), listener.accept());
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream1.unwrap()));
        let (mut client_socket, _) = stream2.unwrap();

        session.on_stream_accept(socket, HashMap::new(), Arc::from("hello"));

        let mut buf = vec![0u8; 128];
        match client_socket.read(&mut buf).await {
            Err(_) | Ok(0) => {}
            _ => panic!("invalid response"),
        }
    }

    #[tokio::test]
    async fn stream_accept_for_anonymous() {
        let (mut session, _ctx) = create_session().await;
        session.session_kind = SamSessionKind::Datagram {
            kind: SessionKind::Anonymous,
        };

        let listener = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(MockTcpStream::connect(address), listener.accept());
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream1.unwrap()));
        let (mut client_socket, _) = stream2.unwrap();

        session.on_stream_accept(socket, HashMap::new(), Arc::from("hello"));

        let mut buf = vec![0u8; 128];
        match client_socket.read(&mut buf).await {
            Err(_) | Ok(0) => {}
            _ => panic!("invalid response"),
        }
    }

    #[tokio::test]
    async fn stream_forward_for_repliable() {
        let (mut session, _ctx) = create_session().await;
        session.session_kind = SamSessionKind::Datagram {
            kind: SessionKind::Datagram,
        };

        let listener = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(MockTcpStream::connect(address), listener.accept());
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream1.unwrap()));
        let (mut client_socket, _) = stream2.unwrap();

        session.on_stream_forward(socket, 8888, HashMap::new(), Arc::from("hello"));

        let mut buf = vec![0u8; 128];
        match client_socket.read(&mut buf).await {
            Err(_) | Ok(0) => {}
            _ => panic!("invalid response"),
        }
    }

    #[tokio::test]
    async fn stream_forward_for_anonymous() {
        let (mut session, _ctx) = create_session().await;
        session.session_kind = SamSessionKind::Datagram {
            kind: SessionKind::Anonymous,
        };

        let listener = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(MockTcpStream::connect(address), listener.accept());
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream1.unwrap()));
        let (mut client_socket, _) = stream2.unwrap();

        session.on_stream_forward(socket, 8888, HashMap::new(), Arc::from("hello"));

        let mut buf = vec![0u8; 128];
        match client_socket.read(&mut buf).await {
            Err(_) | Ok(0) => {}
            _ => panic!("invalid response"),
        }
    }

    #[tokio::test]
    async fn stream_accept_then_forward() {
        let (mut session, _ctx) = create_session().await;

        let listener = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(MockTcpStream::connect(address), listener.accept());
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream1.unwrap()));
        let (mut client_socket, _) = stream2.unwrap();

        session.on_stream_accept(socket, HashMap::new(), Arc::from("hello"));

        // read `STREAM ACCEPT` response
        let future = async {
            let mut reader = BufReader::new(&mut client_socket);
            let mut response = String::new();
            reader.read_line(&mut response).await.expect("to succeed");
            assert!(response.contains("STREAM STATUS RESULT=OK"));
        };
        assert!(tokio::time::timeout(Duration::from_secs(1), future).await.is_ok());

        let (stream1, stream2) = tokio::join!(MockTcpStream::connect(address), listener.accept());
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream1.unwrap()));
        let (mut client_socket, _) = stream2.unwrap();

        session.on_stream_forward(socket, 8888, HashMap::new(), Arc::from("hello"));

        // read `STREAM FORWARD` response
        let future = async {
            let mut reader = BufReader::new(&mut client_socket);
            let mut response = String::new();
            reader.read_line(&mut response).await.expect("to succeed");
            assert!(response.contains("STREAM STATUS RESULT=I2P_ERROR"));
        };
        assert!(tokio::time::timeout(Duration::from_secs(1), future).await.is_ok());
    }

    #[tokio::test]
    async fn stream_forward_then_accept() {
        let (mut session, _ctx) = create_session().await;

        let listener = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stream1, stream2) = tokio::join!(MockTcpStream::connect(address), listener.accept());
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream1.unwrap()));
        let (mut client_socket, _) = stream2.unwrap();

        session.on_stream_forward(socket, address.port(), HashMap::new(), Arc::from("hello"));

        // read `STREAM FORWARD` response
        let future = async {
            let mut reader = BufReader::new(&mut client_socket);
            let mut response = String::new();
            reader.read_line(&mut response).await.expect("to succeed");
            assert!(response.contains("STREAM STATUS RESULT=OK"));
        };
        assert!(tokio::time::timeout(Duration::from_secs(1), future).await.is_ok());

        let (stream1, stream2) = tokio::join!(MockTcpStream::connect(address), listener.accept());
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream1.unwrap()));
        let (mut client_socket, _) = stream2.unwrap();

        session.on_stream_accept(socket, HashMap::new(), Arc::from("hello"));

        // read `STREAM ACCEPT` response
        let future = async {
            let mut reader = BufReader::new(&mut client_socket);
            let mut response = String::new();
            reader.read_line(&mut response).await.expect("to succeed");
            assert!(response.contains("STREAM STATUS RESULT=I2P_ERROR"));
        };
        assert!(tokio::time::timeout(Duration::from_secs(1), future).await.is_ok());
    }

    #[tokio::test]
    async fn offline_keys_sign_lease_set_and_are_reported_back() {
        use crate::crypto::base64_decode;

        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let now = MockRuntime::time_since_epoch().as_secs() as u32;
        let keys = OfflineKeys::create::<MockRuntime>(&signing_key, now + 3600);
        let (mut session, mut ctx) =
            create_session_with_keys(Some((signing_key.clone(), keys.clone()))).await;

        // the session signs with the transient key and advertises the offline signature
        assert_eq!(session.signing_key.as_ref(), keys.transient_key().as_ref());

        let lease_set = make_local_lease_set(
            &session.dest,
            &session.options,
            &session.public_key_context,
            &session.signing_key,
            session.offline_keys.as_ref(),
            vec![LeaseSet2::random().0.leases[0].clone()],
            now,
        );
        let parsed = LeaseSet2::parse::<MockRuntime>(&lease_set).unwrap();
        assert_eq!(parsed.header.destination.id(), session.dest.id());
        assert_eq!(
            parsed.header.offline_signature,
            Some(keys.signature().clone())
        );

        // the same lease set without the offline section wouldn't verify
        let mut without_section = parsed.clone();
        without_section.header.offline_signature = None;
        assert!(
            LeaseSet2::parse::<MockRuntime>(&without_section.serialize(keys.transient_key()))
                .is_err()
        );

        // `SESSION STATUS` reports the all-zero signing key followed by the offline keys
        let destination_id = session.dest.id();
        tokio::spawn(async move { session.socket.as_mut().expect("to exist").next().await });

        let mut reader = BufReader::new(&mut ctx.client_socket);
        let mut response = String::new();
        reader.read_line(&mut response).await.expect("to succeed");

        let privkey = response
            .trim()
            .strip_prefix("SESSION STATUS RESULT=OK DESTINATION=")
            .unwrap_or_else(|| panic!("unexpected response: {response}"));
        let decoded = base64_decode(privkey).unwrap();
        let (rest, destination) = Destination::parse_frame(&decoded).unwrap();

        // the test session has an empty encryption private key
        assert_eq!(destination.id(), destination_id);
        assert_eq!(&rest[..32], &[0u8; 32]);
        assert_eq!(&rest[32..], &keys.serialize()[..]);
    }

    #[tokio::test]
    async fn remove_sub_session() {
        let (mut session, ctx) = create_session().await;
        session.session_kind = SamSessionKind::Primary {
            sub_sessions: HashMap::new(),
        };

        // stream sub-session on port 10 and a datagram sub-session on port 20
        let result = session.on_create_sub_session(
            "stream".into(),
            SessionKind::Stream,
            HashMap::from_iter([("LISTEN_PORT".to_string(), "10".to_string())]),
        );
        assert!(String::from_utf8_lossy(&result).contains("RESULT=OK"));

        let result = session.on_create_sub_session(
            "datagram".into(),
            SessionKind::Datagram,
            HashMap::from_iter([
                ("PORT".to_string(), "1234".to_string()),
                ("LISTEN_PORT".to_string(), "20".to_string()),
            ]),
        );
        assert!(String::from_utf8_lossy(&result).contains("RESULT=OK"));
        assert_eq!(session.session_kind.listen_port(&Arc::from("stream")), 10);
        assert_eq!(session.session_kind.listen_port(&Arc::from("datagram")), 20);

        // both sub-sessions were registered to the sam server
        for _ in 0..2 {
            assert!(core::matches!(
                ctx.sub_rx.try_recv(),
                Ok(SubSessionCommand::Add { .. })
            ));
        }

        // unknown sub-session cannot be removed
        let result = session.on_remove_sub_session("unknown".into());
        assert!(String::from_utf8_lossy(&result).contains("RESULT=INVALID_ID"));

        // remove the datagram sub-session, its listener is gone
        let result = session.on_remove_sub_session("datagram".into());
        assert!(String::from_utf8_lossy(&result).contains("RESULT=OK"));
        assert!(session
            .datagram_manager
            .on_datagram(I2cpPayload {
                dst_port: 20,
                payload: vec![1, 2, 3, 4],
                protocol: Protocol::Datagram,
                src_port: 0,
            })
            .is_err());
        assert!(!session.session_kind.supports_datagrams(&Arc::from("datagram")));
        match ctx.sub_rx.try_recv() {
            Ok(SubSessionCommand::Remove { sub_session_id }) => {
                assert_eq!(&*sub_session_id, "datagram");
            }
            command => panic!("unexpected command: {command:?}"),
        }

        // the listen port can be reused by a new sub-session
        let result = session.on_create_sub_session(
            "datagram2".into(),
            SessionKind::Datagram,
            HashMap::from_iter([
                ("PORT".to_string(), "1234".to_string()),
                ("LISTEN_PORT".to_string(), "20".to_string()),
            ]),
        );
        assert!(String::from_utf8_lossy(&result).contains("RESULT=OK"));

        // remove the stream sub-session
        let result = session.on_remove_sub_session("stream".into());
        assert!(String::from_utf8_lossy(&result).contains("RESULT=OK"));
        assert!(!session.session_kind.supports_streams(&Arc::from("stream")));
        assert_eq!(session.session_kind.listen_port(&Arc::from("stream")), 0);

        // a plain stream session has no sub-sessions to remove
        session.session_kind = SamSessionKind::Stream;
        let result = session.on_remove_sub_session("stream".into());
        assert!(String::from_utf8_lossy(&result).contains("not a primary session"));
    }

    #[tokio::test]
    async fn stream_sub_sessions_need_unique_listen_ports() {
        let (mut session, _ctx) = create_session().await;
        session.session_kind = SamSessionKind::Primary {
            sub_sessions: HashMap::new(),
        };

        // default listen port
        let result =
            session.on_create_sub_session("sub1".into(), SessionKind::Stream, HashMap::new());
        assert!(String::from_utf8_lossy(&result).contains("RESULT=OK"));

        // same listen port, explicitly
        let result = session.on_create_sub_session(
            "sub2".into(),
            SessionKind::Stream,
            HashMap::from_iter([("LISTEN_PORT".to_string(), "0".to_string())]),
        );
        assert!(String::from_utf8_lossy(&result).contains("duplicate listen port"));

        // `LISTEN_PORT` defaults to `FROM_PORT`
        let result = session.on_create_sub_session(
            "sub3".into(),
            SessionKind::Stream,
            HashMap::from_iter([("FROM_PORT".to_string(), "10".to_string())]),
        );
        assert!(String::from_utf8_lossy(&result).contains("RESULT=OK"));
        assert_eq!(session.session_kind.listen_port(&Arc::from("sub3")), 10);

        let result = session.on_create_sub_session(
            "sub4".into(),
            SessionKind::Stream,
            HashMap::from_iter([("LISTEN_PORT".to_string(), "10".to_string())]),
        );
        assert!(String::from_utf8_lossy(&result).contains("duplicate listen port"));

        // datagram sub-sessions don't conflict with stream sub-sessions
        let result = session.on_create_sub_session(
            "sub5".into(),
            SessionKind::Anonymous,
            HashMap::from_iter([
                ("PORT".to_string(), "1234".to_string()),
                ("LISTEN_PORT".to_string(), "10".to_string()),
            ]),
        );
        assert!(String::from_utf8_lossy(&result).contains("RESULT=OK"));

        // invalid listen port
        let result = session.on_create_sub_session(
            "sub6".into(),
            SessionKind::Stream,
            HashMap::from_iter([("LISTEN_PORT".to_string(), "70000".to_string())]),
        );
        assert!(String::from_utf8_lossy(&result).contains("invalid listen port"));

        if let SamSessionKind::Primary { sub_sessions } = &session.session_kind {
            assert_eq!(sub_sessions.len(), 3);
        }
    }

    #[tokio::test]
    async fn stream_forward_with_invalid_host_is_rejected() {
        let (mut session, _ctx) = create_session().await;
        let listener = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (stream, mut client) = tokio::join!(
            MockTcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let socket = Box::new(SamSocket::<MockRuntime>::new(stream.unwrap()));
        let (mut client, _) = client.as_mut().map(|(stream, address)| (stream, *address)).unwrap();

        session.on_stream_forward(
            socket,
            8080,
            HashMap::from_iter([("HOST".to_string(), "not-an-ip".to_string())]),
            Arc::from("test"),
        );

        let mut reader = BufReader::new(&mut client);
        let mut response = String::new();
        reader.read_line(&mut response).await.expect("to succeed");
        assert!(response.contains("STREAM STATUS RESULT=I2P_ERROR"));
    }

    #[tokio::test]
    async fn datagram_send_over_control_socket() {
        let (mut session, _ctx) = create_session().await;
        let (remote, _) = Destination::random();

        // stream sessions cannot send datagrams
        session.on_send_datagram_command(
            remote.clone(),
            SessionKind::Anonymous,
            b"hello".to_vec(),
            HashMap::new(),
        );
        assert!(session.pending_outbound.is_empty());

        // primary session with a raw sub-session
        session.session_kind = SamSessionKind::Primary {
            sub_sessions: HashMap::new(),
        };
        let result = session.on_create_sub_session(
            "raw".into(),
            SessionKind::Anonymous,
            HashMap::from_iter([("PORT".to_string(), "1234".to_string())]),
        );
        assert!(String::from_utf8_lossy(&result).contains("RESULT=OK"));

        // `DATAGRAM SEND` needs a repliable sub-session
        session.on_send_datagram_command(
            remote.clone(),
            SessionKind::Datagram,
            b"hello".to_vec(),
            HashMap::new(),
        );
        assert!(session.pending_outbound.is_empty());

        // `RAW SEND` is sent through the raw sub-session, the remote's lease set is unknown so the
        // datagram is queued
        session.on_send_datagram_command(
            remote.clone(),
            SessionKind::Anonymous,
            b"hello".to_vec(),
            HashMap::from_iter([("TO_PORT".to_string(), "7".to_string())]),
        );
        match session.pending_outbound.get(&remote.id()) {
            Some(PendingSession {
                datagrams: Some((_, datagrams)),
                ..
            }) => {
                assert_eq!(datagrams.len(), 1);
                assert_eq!(datagrams[0].0, Protocol::Anonymous);
                assert_eq!(datagrams[0].1, b"hello");
                assert_eq!(
                    datagrams[0].2.as_ref().and_then(|options| options.get(&Str::from("TO_PORT"))),
                    Some(&Str::from("7"))
                );
            }
            _ => panic!("datagram not queued"),
        }
    }
}
