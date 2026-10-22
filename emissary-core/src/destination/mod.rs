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
        blinding::{date_string, BlindedPublicKey},
        StaticPrivateKey, StaticPublicKey,
    },
    destination::{
        lease_set::LeaseSetManager,
        routing_path::{
            PendingRoutingPathHandle, RoutingPath, RoutingPathHandle, RoutingPathManager,
        },
        session::{SessionManager, SessionManagerEvent},
    },
    error::{Error, QueryError},
    i2np::{
        database::{
            search_reply::DatabaseSearchReply,
            store::{DatabaseStore, DatabaseStorePayload},
        },
        delivery_status::DeliveryStatus,
        Message, MessageBuilder, MessageType, I2NP_MESSAGE_EXPIRATION,
    },
    netdb::{NetDbHandle, QueriedLeaseSet},
    primitives::{DestinationId, EncryptedLeaseSet2Bundle, Lease, LeaseSet2, TunnelId},
    profile::ProfileStorage,
    runtime::{JoinSet, Runtime},
    tunnel::{NoiseContext, TunnelPoolEvent, TunnelPoolHandle},
};

use bytes::Bytes;
use futures::{FutureExt, Stream, StreamExt};
use hashbrown::{HashMap, HashSet};
use rand::Rng;

use alloc::{collections::VecDeque, vec::Vec};
use core::{
    mem,
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

mod lease_set;

pub mod routing_path;
pub mod session;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::destination";

/// How long should [`Destination`] wait before attempting to recontact [`NetDb`]
/// after the previous call was rejected.
const NETDB_BACKOFF_TIMEOUT: Duration = Duration::from_secs(5);

/// Number of retries before lease set query is aborted.
///
/// This is the number retries made when trying to contact [`NetDb`] for a lease set query
/// in case the channel used by [`NetDbHandle`] is clogged.
const NUM_QUERY_RETRIES: usize = 3usize;

/// Number of lease set lookups attempted before the remote is reported unreachable.
///
/// A single NetDb query is bounded by its own timeout. A failed query usually teaches NetDb about
/// floodfills closer to the key, so a retry has a better chance of succeeding than the first
/// attempt, which matters when tunnels are slow or the local NetDb is still small.
const LEASE_SET_QUERY_ATTEMPTS: usize = 3usize;

/// Delay between two lease set lookup attempts.
const LEASE_SET_QUERY_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Stale lease set prune interval.
const LEASE_SET_PRUNE_INTERVAL: Duration = Duration::from_secs(2 * 60);

/// How the message should be delivered to remote destination.
#[derive(Default, Clone)]
pub enum DeliveryStyle {
    /// Deliver the message to remote using the explicitly specified routing path.
    ViaRoute {
        /// Routing path.
        routing_path: RoutingPath,
    },

    /// Deliver the message to remote via any available route.
    Unspecified {
        /// ID of the remote destination.
        destination_id: DestinationId,
    },

    #[default]
    Dummy,
}

impl DeliveryStyle {
    /// Get reference to [`DestinationId`].
    pub fn destination_id(&self) -> &DestinationId {
        match self {
            Self::ViaRoute { routing_path } => &routing_path.destination_id,
            Self::Unspecified { destination_id } => destination_id,
            Self::Dummy => unreachable!(),
        }
    }
}

/// Events emitted by [`Destination`].
#[derive(Debug)]
pub enum DestinationEvent {
    /// One or more messages received.
    Messages {
        /// ID of the remote destination which sent the messages.
        destination_id: DestinationId,

        /// One or more I2NP Data messages.
        messages: Vec<Vec<u8>>,
    },

    /// Lease set of the remote found in NetDb.
    LeaseSetFound {
        /// ID of the remote destination.
        destination_id: DestinationId,
    },

    /// Encrypted lease set of a blinded remote found in NetDb and decrypted.
    ///
    /// The remote is known by `destination_id` from now on, `blinded_id` is the ID the query was
    /// made with.
    BlindedLeaseSetFound {
        /// ID the lease set was queried with.
        blinded_id: DestinationId,

        /// ID of the remote destination.
        destination_id: DestinationId,
    },

    /// Lease set of the remote not found in NetDb.
    LeaseSetNotFound {
        /// ID of the remote destination.
        destination_id: DestinationId,

        /// Query error.
        error: QueryError,
    },

    /// Tunnel pool shut down.
    TunnelPoolShutDown,

    /// Create new lease set from leases.
    CreateLeaseSet {
        /// Leases.
        leases: Vec<Lease>,
    },

    /// Session with remote destination has been termianted.
    SessionTerminated {
        /// ID of the remote destination.
        destination_id: DestinationId,
    },
}

/// Lease set status of remote destination.
///
/// Remote's lease set must exist in [`Destination`] in order to send message to them.
#[derive(Debug, PartialEq, Eq)]
pub enum LeaseSetStatus {
    /// [`LeaseSet2`] for destination found in [`Destination`].
    ///
    /// Caller doesn't need to buffer messages and wait for the query to finish.
    Found,

    /// [`LeaseSet2`] for destination not found in [`Destination`].
    ///
    /// Query will be started in the backgroun and the caller is notified
    /// of the query result via [`Destination::poll_next()`].
    NotFound,

    /// Query for destination's [`LeaseSet2`] is pending.
    Pending,
}

/// Context associated with a remote destination.
pub struct DestinationContext {
    /// Lease set.
    lease_set: LeaseSet2,

    /// Pending messages, if any.
    ///
    /// Outbound messages are put on hold if remote lease set has expired
    /// and a new lease set is being queried.
    pending_messages: VecDeque<Vec<u8>>,

    /// Expiring lease sets.
    ///
    /// Some routing paths may still use these lease sets if they haven't expired and since the
    /// `RoutingPath` doesn't hold the `RouterId` of the lease set, these lease sets are stored
    /// separately.
    ///
    /// The stale lease sets are periodically pruned at an interval of `LEASE_SET_PRUNE_INTERVAL`.
    expiring_leases: HashMap<TunnelId, Lease>,
}

/// Client destination.
pub struct Destination<R: Runtime> {
    /// Remote destinations whose lease sets are encrypted, by the ID under which they're known.
    blinded_destinations: HashMap<DestinationId, BlindedPublicKey>,

    /// Real IDs of blinded remote destinations whose lease sets have been decrypted.
    resolved_blinded: HashMap<DestinationId, DestinationId>,

    /// Destination ID of the client.
    destination_id: DestinationId,

    /// Serialized [`LeaseSet2`] for client's inbound tunnels.
    #[allow(unused)]
    lease_set: Bytes,

    /// Local lease set manager.
    lease_set_manager: LeaseSetManager<R>,

    /// Timer for periodic pruning of stale lease sets.
    lease_set_prune_timer: R::Timer,

    /// Handle to [`NetDb`].
    netdb_handle: NetDbHandle,

    /// Pending lease set queries:
    pending_queries: HashSet<DestinationId>,

    /// Public keys.
    public_keys: Vec<StaticPublicKey>,

    /// Pending `LeaseSet2` query futures.
    query_futures: R::JoinSet<(DestinationId, Result<LeaseSet2, QueryError>)>,

    /// Known remote destinations.
    remote_destinations: HashMap<DestinationId, DestinationContext>,

    /// Routing path manager.
    routing_path_manager: RoutingPathManager<R>,

    /// Session manager.
    session_manager: SessionManager<R>,

    /// Handle to destination's [`TunnelPool`].
    tunnel_pool_handle: TunnelPoolHandle,

    /// Waker.
    waker: Option<Waker>,
}

impl<R: Runtime> Destination<R> {
    /// Create new [`Destination`].
    ///
    /// `private_key` is the private key of the client destination and `lease`
    /// is a serialized [`LeaseSet2`] for the client's inbound tunnel(s).
    pub fn new(
        destination_id: DestinationId,
        private_key: StaticPrivateKey,
        public_keys: Vec<StaticPublicKey>,
        lease_set: Bytes,
        netdb_handle: NetDbHandle,
        tunnel_pool_handle: TunnelPoolHandle,
        outbound_tunnels: Vec<TunnelId>,
        inbound_tunnels: Vec<Lease>,
        unpublished: bool,
        profile_storage: ProfileStorage<R>,
    ) -> Self {
        Self {
            blinded_destinations: HashMap::new(),
            resolved_blinded: HashMap::new(),
            destination_id: destination_id.clone(),
            lease_set: lease_set.clone(),
            lease_set_manager: LeaseSetManager::new(
                inbound_tunnels,
                destination_id.clone(),
                tunnel_pool_handle.sender(),
                tunnel_pool_handle.config().num_inbound,
                netdb_handle.clone(),
                NoiseContext::new(private_key.clone(), Bytes::from(destination_id.to_vec())),
                profile_storage,
                unpublished,
                lease_set.clone(),
            ),
            lease_set_prune_timer: R::timer(LEASE_SET_PRUNE_INTERVAL),
            netdb_handle,
            pending_queries: HashSet::new(),
            public_keys: public_keys.clone(),
            query_futures: R::join_set(),
            remote_destinations: HashMap::new(),
            routing_path_manager: RoutingPathManager::new(destination_id.clone(), outbound_tunnels),
            session_manager: SessionManager::new(
                destination_id,
                private_key,
                public_keys,
                lease_set,
            ),
            tunnel_pool_handle,
            waker: None,
        }
    }

    /// Look up lease set status of remote destination.
    ///
    /// Before sending a message to remote, the caller must ensure [`Destination`] holds a valid
    /// lease for the remote destination. This needs to be done only once, when sending the first
    /// message to remote destination. If this function is called when there is no active lease set
    /// for `destination`, a lease set query is started in the background and its result can be
    /// polled via [`Destinatin::poll_next()`].
    ///
    /// If this function returns [`LeaseSetStatus::Found`], [`Destination::send_message()`] can be
    /// called as the remote is reachable. If it returns [`LeaseStatus::NotFound`] or
    /// [`LeaseStatus::Pending`], the caller must wait until [`Destination`] emits
    /// [`DestinationEvent::LeaseSetFound`], indicating that a lease set is foun and the remote
    /// destination is reachable.
    pub fn query_lease_set(&mut self, destination_id: &DestinationId) -> LeaseSetStatus {
        if self.pending_queries.contains(destination_id) {
            return LeaseSetStatus::Pending;
        }

        let blinded = self.blinded_destinations.get(destination_id).cloned();

        if let Some(context) = self.remote_destinations.get(destination_id) {
            if !context.lease_set.is_expired::<R>() {
                return LeaseSetStatus::Found;
            }

            tracing::debug!(
                target: LOG_TARGET,
                %destination_id,
                "lease set found but it's expired",
            );
        }

        tracing::trace!(
            target: LOG_TARGET,
            %destination_id,
            "lookup destination",
        );

        let handle = self.netdb_handle.clone();
        let destination_id = destination_id.clone();

        self.pending_queries.insert(destination_id.clone());
        self.query_futures.push(async move {
            let mut attempt = 1usize;

            loop {
                let result = 'query: {
                    for _ in 0..NUM_QUERY_RETRIES {
                        // encrypted lease sets are stored under the hash of the blinded key of the
                        // day
                        let key = match &blinded {
                            None => Bytes::from(destination_id.to_vec()),
                            Some(blinded) =>
                                match blinded.store_hash(&date_string(R::time_since_epoch())) {
                                    Some(hash) => Bytes::from(hash.to_vec()),
                                    None => break 'query Err(QueryError::ValueNotFound),
                                },
                        };

                        let Ok(rx) = handle.query_lease_set(key) else {
                            R::delay(NETDB_BACKOFF_TIMEOUT).await;
                            continue;
                        };

                        tracing::trace!(
                            target: LOG_TARGET,
                            %destination_id,
                            encrypted = ?blinded.is_some(),
                            "lease set query started",
                        );

                        let result = match rx.await {
                            Err(_) => Err(QueryError::Timeout),
                            Ok(Err(error)) => Err(error),
                            Ok(Ok(QueriedLeaseSet::Standard(lease_set))) => match &blinded {
                                None => Ok(*lease_set),
                                Some(_) => {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        %destination_id,
                                        "standard lease set received for a blinded destination",
                                    );
                                    Err(QueryError::Malformed)
                                }
                            },
                            Ok(Ok(QueriedLeaseSet::Encrypted(lease_set))) => match &blinded {
                                None => {
                                    tracing::warn!(
                                        target: LOG_TARGET,
                                        %destination_id,
                                        "encrypted lease set received for a regular destination",
                                    );
                                    Err(QueryError::Malformed)
                                }
                                Some(blinded) => match lease_set.decrypt::<R>(blinded) {
                                    Ok(lease_set) => Ok(lease_set),
                                    Err(error) => {
                                        tracing::warn!(
                                            target: LOG_TARGET,
                                            %destination_id,
                                            ?error,
                                            "failed to decrypt lease set",
                                        );
                                        Err(QueryError::Malformed)
                                    }
                                },
                            },
                        };

                        break 'query result;
                    }

                    tracing::warn!(
                        target: LOG_TARGET,
                        %destination_id,
                        "failed to start lease set query after {NUM_QUERY_RETRIES} retries",
                    );

                    Err(QueryError::RetryFailure)
                };

                // a query that timed out or came back empty is retried a few times, the netdb may
                // have learned about closer floodfills in the meantime
                match result {
                    Err(
                        error @ (QueryError::Timeout
                        | QueryError::ValueNotFound
                        | QueryError::NoFloodfills),
                    ) if attempt < LEASE_SET_QUERY_ATTEMPTS => {
                        tracing::debug!(
                            target: LOG_TARGET,
                            %destination_id,
                            ?error,
                            ?attempt,
                            "lease set query failed, retrying",
                        );
                        attempt += 1;
                        R::delay(LEASE_SET_QUERY_RETRY_DELAY).await;
                    }
                    result => return (destination_id, result),
                }
            }
        });

        LeaseSetStatus::NotFound
    }

    /// Get reference to a [`LeaseSet2`] of the destination identified by `destination_id`.
    ///
    /// Caller must calle [`Destination::query_lease_set()`] and get a return value of
    /// [`LeaseSetStatus::Found`] before calling this function.
    pub fn lease_set(&self, destination_id: &DestinationId) -> &LeaseSet2 {
        &self.remote_destinations.get(destination_id).expect("to exist").lease_set
    }

    /// Send encrypted `message` to remote `destination`.
    ///
    /// Lease set for the remote destination must exist in [`Destination`], otherwise the call is
    /// rejected. Lease set can be queried with [`Destination::query_lease_set()`] which returns a
    /// result indicating whether the remote is "reachable" right now.
    ///
    /// After the message has been encrypted, it's sent to remote destination via one of the
    /// outbound tunnels of [`Destination`].
    fn send_message_inner(
        &mut self,
        delivery_style: DeliveryStyle,
        message: Vec<u8>,
    ) -> crate::Result<()> {
        let Some(context) = self.remote_destinations.get_mut(delivery_style.destination_id())
        else {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.destination_id,
                remote = %delivery_style.destination_id(),
                "`Destination::encrypt()` called but lease set is missing",
            );
            debug_assert!(false);
            return Err(Error::InvalidState);
        };

        // if remote lease set is expired, mark `message` as pending and start lease set query
        if context.lease_set.is_expired::<R>() {
            tracing::debug!(
                target: LOG_TARGET,
                local = %self.destination_id,
                remote = %delivery_style.destination_id(),
                "postpone outbound message, remote lease set is expired"
            );

            context.pending_messages.push_back(message);
            self.query_lease_set(delivery_style.destination_id());

            return Ok(());
        }

        // wrap the garlic message inside a standard i2np message and send it over
        // the one of the pool's outbound tunnels to remote destination
        let message = MessageBuilder::standard()
            .with_message_type(MessageType::Garlic)
            .with_expiration(R::time_since_epoch() + I2NP_MESSAGE_EXPIRATION)
            .with_message_id(R::rng().next_u32())
            .with_payload(&message)
            .build();

        match delivery_style {
            DeliveryStyle::ViaRoute {
                routing_path:
                    RoutingPath {
                        destination_id,
                        inbound,
                        outbound,
                    },
            } => match context.lease_set.leases.iter().find(|lease| lease.tunnel_id == inbound) {
                Some(Lease { router_id, .. }) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        remote = %destination_id,
                        ibgw_tunnel_id = %inbound,
                        ibgw_router_id = %router_id,
                        obgw_tunnel_id = %outbound,
                        "send message via route",
                    );

                    if let Err(error) = self
                        .tunnel_pool_handle
                        .send_message(message)
                        .tunnel_delivery(router_id.clone(), inbound)
                        .via_outbound_tunnel(outbound)
                        .try_send()
                    {
                        tracing::debug!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            remote = %destination_id,
                            %inbound,
                            %router_id,
                            %outbound,
                            ?error,
                            "failed to send message to tunnel via routing path",
                        );
                    }
                }
                None => match context.expiring_leases.get(&inbound) {
                    Some(Lease { router_id, .. }) => {
                        tracing::trace!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            remote = %destination_id,
                            ibgw_tunnel_id = %inbound,
                            ibgw_router_id = %router_id,
                            obgw_tunnel_id = %outbound,
                            "send message via route",
                        );

                        if let Err(error) = self
                            .tunnel_pool_handle
                            .send_message(message)
                            .tunnel_delivery(router_id.clone(), inbound)
                            .via_outbound_tunnel(outbound)
                            .try_send()
                        {
                            tracing::debug!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                remote = %destination_id,
                                %inbound,
                                %router_id,
                                %outbound,
                                ?error,
                                "failed to send message to tunnel via routing path",
                            );
                        }
                    }
                    None => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            %destination_id,
                            %inbound,
                            %outbound,
                            "lease set for selected ibgw doesn't exist",
                        );
                        debug_assert!(false);
                    }
                },
            },
            DeliveryStyle::Unspecified { destination_id } => {
                // select random tunnel for delivery
                let random_lease = R::rng().next_u32() as usize % context.lease_set.leases.len();

                if let Err(error) = self
                    .tunnel_pool_handle
                    .send_message(message)
                    .tunnel_delivery(
                        context.lease_set.leases[random_lease].router_id.clone(),
                        context.lease_set.leases[random_lease].tunnel_id,
                    )
                    .try_send()
                {
                    tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        remote = %destination_id,
                        ?error,
                        "failed to send message to tunnel",
                    );
                }
            }
            DeliveryStyle::Dummy => unreachable!(),
        }

        Ok(())
    }

    /// Encrypt and send `message` to remote destination.
    ///
    /// Session manager is expected to have public key of the remote destination.
    pub fn send_message(
        &mut self,
        delivery_style: DeliveryStyle,
        message: Vec<u8>,
    ) -> crate::Result<()> {
        match self.session_manager.encrypt(delivery_style.destination_id(), message) {
            Ok(message) => self.send_message_inner(delivery_style, message),
            Err(error) => Err(Error::Session(error)),
        }
    }

    /// Handle garlic messages received into one of the [`Destination`]'s inbound tunnels.
    ///
    /// The decrypted garlic message may contain a database store for an up-to-date [`LeaseSet2`] of
    /// the remote destination and if so, the currently stored lease set is overriden with the new
    /// lease set.
    ///
    /// Any garlic clove containing an I2NP Data message is returned to user.
    ///
    /// Returns the ID of the remote destination which sent the message and the messages for the
    /// client, or `None` if the message was consumed by the destination itself.
    fn decrypt_message(
        &mut self,
        message: Message,
    ) -> crate::Result<Option<(DestinationId, Vec<Vec<u8>>)>> {
        tracing::trace!(
            target: LOG_TARGET,
            local = %self.destination_id,
            message_id = ?message.message_id,
            message_type = ?message.message_type,
            "inbound message to destination",
        );

        match message.message_type {
            MessageType::DatabaseStore => {
                let (key, payload) = match DatabaseStore::<R>::parse(&message.payload) {
                    Ok(DatabaseStore { key, payload, .. }) => (key, payload),
                    Err(error) => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            ?error,
                            "received a malformed database store",
                        );

                        return Err(Error::InvalidData);
                    }
                };

                match payload {
                    DatabaseStorePayload::LeaseSet2 { .. }
                    | DatabaseStorePayload::EncryptedLeaseSet2 { .. } => {
                        self.lease_set_manager.register_database_store(key.clone());
                        return Ok(None);
                    }
                    DatabaseStorePayload::RouterInfo { .. } => {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            "unexpected router info database store",
                        );
                        return Err(Error::InvalidData);
                    }
                }
            }
            MessageType::DatabaseSearchReply => {
                let DatabaseSearchReply { key, routers, .. } =
                    DatabaseSearchReply::parse(&message.payload).map_err(|error| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            ?error,
                            "received malformed database search reply",
                        );
                        Error::InvalidData
                    })?;

                self.lease_set_manager.register_database_search_reply(key.clone(), routers);
                return Ok(None);
            }
            MessageType::DeliveryStatus => {
                let DeliveryStatus { message_id, .. } = DeliveryStatus::parse(&message.payload)
                    .ok_or_else(|| {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            "received malformed delivery status",
                        );
                        Error::InvalidData
                    })?;

                tracing::trace!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    token = %message_id,
                    "delivery status",
                );

                return Ok(None);
            }
            MessageType::Garlic => {}
            _ => {
                tracing::warn!(
                    target: LOG_TARGET,
                    local = %self.destination_id,
                    message_type = ?message.message_type,
                    message_id = ?message.message_id,
                    "unsupported message type for destination",
                );
                return Err(Error::NotSupported);
            }
        }

        if message.payload.len() <= 12 {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.destination_id,
                payload_len = ?message.payload.len(),
                "garlic message is too short",
            );
            return Err(Error::InvalidData);
        }

        let (destination_id, cloves) =
            self.session_manager.decrypt_from(message).map_err(Error::Session)?;
        let messages = cloves
            .filter_map(|clove| match clove.message_type {
                MessageType::DatabaseStore => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        "remote lease set received",
                    );

                    match DatabaseStore::<R>::parse(&clove.message_body) {
                        Ok(DatabaseStore {
                            payload: DatabaseStorePayload::LeaseSet2 { lease_set },
                            ..
                        }) => {
                            let destination_id = lease_set.header.destination.id();

                            if lease_set.leases.is_empty() {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    local = %self.destination_id,
                                    remote = %destination_id,
                                    "remote didn't send any leases",
                                );
                                return None;
                            }

                            tracing::trace!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                remote = %destination_id,
                                "store lease set for remote destination",
                            );

                            self.routing_path_manager
                                .register_leases(&destination_id, Ok(lease_set.leases.clone()));

                            match self.remote_destinations.get_mut(&destination_id) {
                                Some(context) => {
                                    mem::replace(&mut context.lease_set, lease_set)
                                        .leases
                                        .into_iter()
                                        .for_each(|lease| {
                                            context.expiring_leases.insert(lease.tunnel_id, lease);
                                        });
                                }
                                None => {
                                    self.remote_destinations.insert(
                                        destination_id,
                                        DestinationContext {
                                            lease_set,
                                            pending_messages: VecDeque::new(),
                                            expiring_leases: HashMap::new(),
                                        },
                                    );
                                }
                            }
                        }
                        database_store => {
                            tracing::warn!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                ?database_store,
                                "ignoring `DatabaseStore`",
                            )
                        }
                    }

                    None
                }
                MessageType::Data => {
                    if clove.message_body.len() <= 4 {
                        tracing::warn!(
                            target: LOG_TARGET,
                            "empty i2np data message",
                        );
                        debug_assert!(false);
                        return None;
                    }

                    Some(clove.message_body[4..].to_vec())
                }
                msg_type => {
                    tracing::debug!(
                        target: LOG_TARGET,
                        ?msg_type,
                        "unhandled message type"
                    );
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(Some((destination_id, messages)))
    }

    /// Attempt to publish new lease set to `NetDb`.
    pub fn publish_lease_set(&mut self, lease_set: Bytes) {
        // store our new lease set proactively to `SessionManager` so it can be given to all active
        // session right away while publishing the new lease set to NetDb in the background
        self.session_manager.register_lease_set(lease_set.clone());
        self.lease_set_manager.register_lease_set(lease_set.clone());
    }

    /// Publish `encrypted`, the encrypted form of `lease_set`, to `NetDb`.
    ///
    /// Active sessions keep receiving the plain lease set, it's bundled in garlic messages.
    pub fn publish_encrypted_lease_set(
        &mut self,
        lease_set: Bytes,
        encrypted: EncryptedLeaseSet2Bundle,
    ) {
        self.session_manager.register_lease_set(lease_set);
        self.lease_set_manager.register_encrypted_lease_set(encrypted);
    }

    /// Register a remote destination whose lease set is published encrypted.
    ///
    /// Returns the [`DestinationId`] under which the destination is known locally. Until the
    /// lease set has been decrypted, that is an ID derived from the destination's signing key
    /// and a query for it looks up the encrypted lease set of the day and decrypts it with
    /// `key`, after which [`DestinationEvent::BlindedLeaseSetFound`] gives the real ID. Once
    /// resolved, the real ID is returned and used for everything.
    pub fn register_blinded_destination(&mut self, key: BlindedPublicKey) -> DestinationId {
        let blinded_id = DestinationId::from(key.public_key());

        if let Some(destination_id) = self.resolved_blinded.get(&blinded_id) {
            return destination_id.clone();
        }

        self.blinded_destinations.insert(blinded_id.clone(), key);
        blinded_id
    }

    /// Get the blinded key of a remote destination, if its lease set is encrypted.
    #[cfg(test)]
    pub fn blinded_key(&self, destination_id: &DestinationId) -> Option<&BlindedPublicKey> {
        self.blinded_destinations.get(destination_id)
    }

    /// Shutdown session by shutting down the tunnel pool.
    pub fn shutdown(&mut self) {
        self.tunnel_pool_handle.shutdown();
    }

    /// Get [`RoutingPathHandle`].
    pub fn routing_path_handle(&mut self, destination_id: DestinationId) -> RoutingPathHandle<R> {
        self.routing_path_manager.handle(destination_id)
    }

    /// Get [`PendingRoutingPathHandle`].
    pub fn pending_routing_path_handle(&self) -> PendingRoutingPathHandle {
        self.routing_path_manager.pending_handle()
    }
}

impl<R: Runtime> Stream for Destination<R> {
    type Item = DestinationEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.tunnel_pool_handle.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => {
                    return Poll::Ready(None);
                }
                Poll::Ready(Some(TunnelPoolEvent::TunnelPoolShutDown)) => {
                    return Poll::Ready(Some(DestinationEvent::TunnelPoolShutDown));
                }
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelBuilt { tunnel_id, lease })) => {
                    tracing::trace!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        ?tunnel_id,
                        "inbound tunnel built",
                    );

                    // new lease set is always created using the inbound tunnel and given to any
                    // active e2e sessions
                    //
                    // new lease set is published to netdb only when all tunnels have been built
                    return Poll::Ready(Some(DestinationEvent::CreateLeaseSet {
                        leases: self.lease_set_manager.register_inbound_tunnel(lease.clone()),
                    }));
                }
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelBuilt { tunnel_id })) => {
                    self.routing_path_manager.register_outbound_tunnel_built(tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelExpired { tunnel_id })) => {
                    self.routing_path_manager.register_outbound_tunnel_expired(tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelExpired { tunnel_id })) => {
                    self.lease_set_manager.register_expired_inbound_tunnel(tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::InboundTunnelExpiring { tunnel_id })) => {
                    self.lease_set_manager.register_expiring_inbound_tunnel(tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::OutboundTunnelExpiring { tunnel_id })) => {
                    self.routing_path_manager.register_outbound_tunnel_expiring(tunnel_id);
                }
                Poll::Ready(Some(TunnelPoolEvent::Message { message })) => {
                    match self.decrypt_message(message) {
                        Err(error) => tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            ?error,
                            "failed to handle inbound message",
                        ),
                        Ok(Some((destination_id, messages))) if !messages.is_empty() =>
                            return Poll::Ready(Some(DestinationEvent::Messages {
                                destination_id,
                                messages,
                            })),
                        Ok(_) => {}
                    }
                }
                Poll::Ready(Some(TunnelPoolEvent::Dummy)) => unreachable!(),
            }
        }

        loop {
            match self.session_manager.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(SessionManagerEvent::SessionTerminated { destination_id })) =>
                    return Poll::Ready(Some(DestinationEvent::SessionTerminated {
                        destination_id,
                    })),
                Poll::Ready(Some(SessionManagerEvent::SendMessage {
                    destination_id,
                    message,
                })) => {
                    if let Err(error) = self
                        .send_message_inner(DeliveryStyle::Unspecified { destination_id }, message)
                    {
                        tracing::warn!(
                            target: LOG_TARGET,
                            local = %self.destination_id,
                            ?error,
                            "failed to send message",
                        );
                    }
                }
            }
        }

        match self.query_futures.poll_next_unpin(cx) {
            Poll::Pending => {}
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some((queried_id, result))) => {
                self.pending_queries.remove(&queried_id);

                // a blinded destination is known by the ID derived from its signing key until its
                // lease set has been decrypted, after that by its real ID which the streaming
                // protocol needs for replay protection
                let destination_id = match (&result, self.blinded_destinations.get(&queried_id)) {
                    (Ok(lease_set), Some(key)) => {
                        let destination_id = lease_set.header.destination.id();

                        if destination_id != queried_id {
                            tracing::debug!(
                                target: LOG_TARGET,
                                local = %self.destination_id,
                                blinded = %queried_id,
                                remote = %destination_id,
                                "blinded destination resolved",
                            );

                            let key = key.clone();
                            self.resolved_blinded
                                .insert(queried_id.clone(), destination_id.clone());
                            self.blinded_destinations.insert(destination_id.clone(), key);
                        }

                        destination_id
                    }
                    _ => queried_id.clone(),
                };

                // always register lease set query result, regardless of its status as one or more
                // routing paths might've initiated the query and need to know whether it succeeded
                // or not
                self.routing_path_manager.register_leases(
                    &destination_id,
                    result
                        .as_ref()
                        .map(|lease_set| lease_set.leases.clone())
                        .map_err(|error| *error),
                );

                match result {
                    Err(error) => {
                        return Poll::Ready(Some(DestinationEvent::LeaseSetNotFound {
                            destination_id: queried_id,
                            error,
                        }));
                    }
                    Ok(lease_set) => {
                        match lease_set.public_keys.iter().find(|&remote_key| {
                            self.public_keys
                                .iter()
                                .any(|key| mem::discriminant(remote_key) == mem::discriminant(key))
                        }) {
                            Some(key) => {
                                self.session_manager
                                    .add_remote_destination(destination_id.clone(), key.clone());
                            }
                            None => {
                                tracing::warn!(
                                    target: LOG_TARGET,
                                    local = %self.destination_id,
                                    "no compatible key found",
                                );

                                return Poll::Ready(Some(DestinationEvent::LeaseSetNotFound {
                                    destination_id: queried_id,
                                    error: QueryError::ValueNotFound,
                                }));
                            }
                        }

                        // add new lease set for destination or create new destination of it didn't
                        // exist
                        //
                        // if the destination has pending messages, sending those before returning
                        // the lease set caller
                        match self.remote_destinations.get_mut(&destination_id) {
                            Some(context) => {
                                context.lease_set = lease_set;

                                mem::take(&mut context.pending_messages).into_iter().for_each(
                                    |message| {
                                        if let Err(error) = self.send_message_inner(
                                            DeliveryStyle::Unspecified {
                                                destination_id: destination_id.clone(),
                                            },
                                            message,
                                        ) {
                                            tracing::debug!(
                                                target: LOG_TARGET,
                                                local = %self.destination_id,
                                                remote = %destination_id,
                                                ?error,
                                                "failed to send pending message",
                                            );
                                        }
                                    },
                                );
                            }
                            None => {
                                self.remote_destinations.insert(
                                    destination_id.clone(),
                                    DestinationContext {
                                        lease_set,
                                        pending_messages: VecDeque::new(),
                                        expiring_leases: HashMap::new(),
                                    },
                                );
                            }
                        }

                        return Poll::Ready(Some(if destination_id != queried_id {
                            DestinationEvent::BlindedLeaseSetFound {
                                blinded_id: queried_id,
                                destination_id,
                            }
                        } else {
                            DestinationEvent::LeaseSetFound { destination_id }
                        }));
                    }
                }
            }
        }

        loop {
            match self.routing_path_manager.poll_next_unpin(cx) {
                Poll::Pending => break,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(destination_id)) => match self.query_lease_set(&destination_id) {
                    LeaseSetStatus::Found => tracing::debug!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        %destination_id,
                        "lease set requsted by routing path manager but it's available",
                    ),
                    status => tracing::trace!(
                        target: LOG_TARGET,
                        local = %self.destination_id,
                        %destination_id,
                        ?status,
                        "lease set requested by routing path manager",
                    ),
                },
            }
        }

        if self.lease_set_manager.poll_unpin(cx).is_ready() {
            tracing::warn!(
                target: LOG_TARGET,
                local = %self.destination_id,
                "lease set manager exited"
            );
            return Poll::Ready(None);
        }

        if self.lease_set_prune_timer.poll_unpin(cx).is_ready() {
            tracing::debug!(
                target: LOG_TARGET,
                local = %self.destination_id,
                "pruning stale lease sets",
            );

            let now = R::time_since_epoch();
            self.remote_destinations.iter_mut().for_each(|(_, context)| {
                context.expiring_leases.retain(|_, lease| lease.expires > now);
            });

            self.lease_set_prune_timer = R::timer(LEASE_SET_PRUNE_INTERVAL);
            let _ = self.lease_set_prune_timer.poll_unpin(cx);
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
        i2np::garlic::GarlicClove,
        netdb::{NetDbAction, NetDbActionRecycle},
        primitives::{Destination as Dest, LeaseSet2Header, MessageId, RouterId, TunnelId},
        runtime::{mock::MockRuntime, Runtime},
        tunnel::{TunnelMessage, TunnelMessageRecycle, TunnelPoolConfig, TunnelPoolEvent},
    };
    use std::collections::VecDeque;
    use thingbuf::mpsc;

    #[tokio::test]
    async fn query_lease_set_found() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let private_key = StaticPrivateKey::random(MockRuntime::rng());
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            private_key.clone(),
            vec![private_key.public()],
            Bytes::new(),
            netdb_handle,
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
            ProfileStorage::new(&[], &[], None),
        );

        // insert dummy lease set for `remote` into `Destination`
        let remote = DestinationId::random();
        let (lease_set, _) = LeaseSet2::random();
        destination.remote_destinations.insert(
            remote.clone(),
            DestinationContext {
                lease_set,
                pending_messages: VecDeque::new(),
                expiring_leases: HashMap::new(),
            },
        );

        // query lease set and verify it exists
        assert_eq!(destination.query_lease_set(&remote), LeaseSetStatus::Found);
    }

    #[tokio::test]
    async fn query_lease_set_expired() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let private_key = StaticPrivateKey::random(MockRuntime::rng());
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            private_key.clone(),
            vec![private_key.public()],
            Bytes::new(),
            netdb_handle,
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
            ProfileStorage::new(&[], &[], None),
        );

        // insert lease set which expired 10 seconds ago
        let remote = DestinationId::random();
        let (mut lease_set, _) = LeaseSet2::random();
        lease_set.header.expires =
            (MockRuntime::time_since_epoch() - Duration::from_secs(10)).as_secs() as u32;
        destination.remote_destinations.insert(
            remote.clone(),
            DestinationContext {
                lease_set,
                pending_messages: VecDeque::new(),
                expiring_leases: HashMap::new(),
            },
        );

        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::NotFound
        );

        assert!(destination.pending_queries.contains(&remote));
        assert_eq!(destination.query_futures.len(), 1);
    }

    #[tokio::test]
    async fn query_lease_set_not_found() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let private_key = StaticPrivateKey::random(MockRuntime::rng());
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            private_key.clone(),
            vec![private_key.public()],
            Bytes::new(),
            netdb_handle,
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
            ProfileStorage::new(&[], &[], None),
        );

        // query lease set and verify it's not found and that a query has been started
        let remote = DestinationId::random();

        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::NotFound
        );

        assert!(destination.pending_queries.contains(&remote));
        assert_eq!(destination.query_futures.len(), 1);
    }

    #[tokio::test]
    async fn query_lease_set_pending() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let private_key = StaticPrivateKey::random(MockRuntime::rng());
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            private_key.clone(),
            vec![private_key.public()],
            Bytes::new(),
            netdb_handle,
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
            ProfileStorage::new(&[], &[], None),
        );

        // query lease set and verify it's not found and that a query has been started
        let remote = DestinationId::random();

        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::NotFound
        );

        assert!(destination.pending_queries.contains(&remote));
        assert_eq!(destination.query_futures.len(), 1);

        // verify that the status is pending on subsequent queries
        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::Pending
        );
    }

    /// Create destination for lease set query tests and return it with the netdb action receiver.
    ///
    /// The tunnel pool handles are returned as well, dropping them would shut the destination down.
    fn query_test_destination() -> (
        Destination<MockRuntime>,
        mpsc::Receiver<NetDbAction, NetDbActionRecycle>,
        (
            mpsc::Receiver<TunnelMessage, TunnelMessageRecycle>,
            mpsc::Sender<TunnelPoolEvent>,
            futures_channel::oneshot::Receiver<()>,
        ),
    ) {
        let (netdb_handle, rx) = NetDbHandle::create();
        let (tp_handle, tm_rx, tp_tx, srx) = TunnelPoolHandle::create();
        let private_key = StaticPrivateKey::random(MockRuntime::rng());
        let destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            private_key.clone(),
            vec![private_key.public()],
            Bytes::new(),
            netdb_handle,
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
            ProfileStorage::new(&[], &[], None),
        );

        (destination, rx, (tm_rx, tp_tx, srx))
    }

    /// Poll `destination` until netdb receives a lease set query and answer it with `reply`.
    ///
    /// Other actions are stored in `kept`, dropping their reply channels would make the lease set
    /// manager exit and with it the destination.
    async fn answer_lease_set_query(
        destination: &mut Destination<MockRuntime>,
        rx: &mpsc::Receiver<NetDbAction, NetDbActionRecycle>,
        kept: &mut Vec<NetDbAction>,
        reply: Result<QueriedLeaseSet, QueryError>,
    ) {
        let tx = loop {
            match rx.try_recv() {
                Ok(NetDbAction::QueryLeaseSet2 { tx, .. }) => break tx,
                Ok(action) => kept.push(action),
                Err(_) => {}
            }

            if let Ok(event) =
                tokio::time::timeout(Duration::from_millis(100), destination.next()).await
            {
                panic!("unexpected event: {event:?}");
            }
        };

        let _ = tx.send(reply);
    }

    #[tokio::test(start_paused = true)]
    async fn lease_set_query_retried_after_timeout_and_not_found() {
        let (mut destination, rx, _guards) = query_test_destination();
        let mut kept = Vec::new();
        let remote = DestinationId::random();
        let (lease_set, _) = LeaseSet2::random();

        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::NotFound
        );

        // first two queries fail, the third one succeeds
        answer_lease_set_query(&mut destination, &rx, &mut kept, Err(QueryError::Timeout)).await;
        answer_lease_set_query(
            &mut destination,
            &rx,
            &mut kept,
            Err(QueryError::ValueNotFound),
        )
        .await;
        answer_lease_set_query(
            &mut destination,
            &rx,
            &mut kept,
            Ok(QueriedLeaseSet::Standard(Box::new(lease_set))),
        )
        .await;

        match tokio::time::timeout(Duration::from_secs(5), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::LeaseSetFound { destination_id } => {
                assert_eq!(destination_id, remote);
            }
            _ => panic!("invalid event"),
        }
        assert!(!destination.pending_queries.contains(&remote));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn lease_set_query_gives_up_after_last_attempt() {
        let (mut destination, rx, _guards) = query_test_destination();
        let mut kept = Vec::new();
        let remote = DestinationId::random();

        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::NotFound
        );

        for _ in 0..LEASE_SET_QUERY_ATTEMPTS {
            answer_lease_set_query(&mut destination, &rx, &mut kept, Err(QueryError::Timeout))
                .await;
        }

        match tokio::time::timeout(Duration::from_secs(5), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::LeaseSetNotFound {
                destination_id,
                error,
            } => {
                assert_eq!(destination_id, remote);
                assert_eq!(error, QueryError::Timeout);
            }
            _ => panic!("invalid event"),
        }
        assert!(!destination.pending_queries.contains(&remote));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn malformed_lease_set_reply_not_retried() {
        let (mut destination, rx, _guards) = query_test_destination();
        let mut kept = Vec::new();
        let remote = DestinationId::random();

        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::NotFound
        );
        answer_lease_set_query(&mut destination, &rx, &mut kept, Err(QueryError::Malformed)).await;

        match tokio::time::timeout(Duration::from_secs(5), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::LeaseSetNotFound { error, .. } => {
                assert_eq!(error, QueryError::Malformed);
            }
            _ => panic!("invalid event"),
        }
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn query_lease_set_channel_clogged() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let private_key = StaticPrivateKey::random(MockRuntime::rng());
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            private_key.clone(),
            vec![private_key.public()],
            Bytes::new(),
            netdb_handle.clone(),
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
            ProfileStorage::new(&[], &[], None),
        );

        // spam the netdb handle full of queries
        loop {
            if netdb_handle.query_lease_set(Bytes::new()).is_err() {
                break;
            }
        }

        // query lease set and verify it's not found and that a query has been started
        let remote = DestinationId::random();
        assert_eq!(
            destination.query_lease_set(&remote),
            LeaseSetStatus::NotFound
        );

        assert!(destination.pending_queries.contains(&remote));
        assert_eq!(destination.query_futures.len(), 1);

        match destination.next().await {
            Some(DestinationEvent::LeaseSetNotFound {
                destination_id,
                error,
            }) => {
                assert_eq!(destination_id, remote);
                assert_eq!(error, QueryError::RetryFailure)
            }
            _ => panic!("invalid event"),
        }
    }

    #[test]
    #[should_panic]
    fn encrypt_message_lease_set_not_found() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let private_key = StaticPrivateKey::random(MockRuntime::rng());
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            private_key.clone(),
            vec![private_key.public()],
            Bytes::new(),
            netdb_handle,
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
            ProfileStorage::new(&[], &[], None),
        );

        destination
            .send_message(
                DeliveryStyle::Unspecified {
                    destination_id: DestinationId::random(),
                },
                vec![1, 2, 3, 4],
            )
            .unwrap();
    }

    #[tokio::test]
    async fn create_lease_set_immediately() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, tp_tx, _srx) = TunnelPoolHandle::from_config(TunnelPoolConfig {
            num_inbound: 1usize,
            ..Default::default()
        });
        let private_key = StaticPrivateKey::random(MockRuntime::rng());
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            private_key.clone(),
            vec![private_key.public()],
            Bytes::new(),
            netdb_handle.clone(),
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
            ProfileStorage::new(&[], &[], None),
        );

        // new inbound tunnel built
        tp_tx
            .send(TunnelPoolEvent::InboundTunnelBuilt {
                tunnel_id: TunnelId::random(),
                lease: Lease {
                    router_id: RouterId::random(),
                    tunnel_id: TunnelId::random(),
                    expires: MockRuntime::time_since_epoch() + Duration::from_secs(10 * 60),
                },
            })
            .await
            .unwrap();

        // verify event is emitted even though the timer is still active
        futures::future::poll_fn(|cx| match destination.lease_set_manager.poll_unpin(cx) {
            Poll::Pending => Poll::Ready(()),
            _ => panic!("timer is ready"),
        })
        .await;

        match tokio::time::timeout(Duration::from_secs(15), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::CreateLeaseSet { .. } => {}
            _ => panic!("invalid event"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn send_message_expired_lease_set() {
        let (netdb_handle, rx) = NetDbHandle::create();
        let (tp_handle, tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let private_key = StaticPrivateKey::random(MockRuntime::rng());
        let mut destination = Destination::<MockRuntime>::new(
            DestinationId::random(),
            private_key.clone(),
            vec![private_key.public()],
            Bytes::new(),
            netdb_handle,
            tp_handle,
            Vec::new(),
            Vec::new(),
            true,
            ProfileStorage::new(&[], &[], None),
        );

        // insert lease set which expired 10 seconds ago
        let remote = DestinationId::random();
        let (lease_set, _) = LeaseSet2::random();
        let expired_lease_set = {
            let mut expired = lease_set.clone();
            expired.header.expires =
                (MockRuntime::time_since_epoch() - Duration::from_secs(10)).as_secs() as u32;

            expired
        };
        destination.remote_destinations.insert(
            remote.clone(),
            DestinationContext {
                lease_set: expired_lease_set,
                pending_messages: VecDeque::new(),
                expiring_leases: HashMap::new(),
            },
        );

        destination
            .session_manager
            .add_remote_destination(remote.clone(), lease_set.public_keys[0].clone());

        // send three messages and verify they're all queried
        destination
            .send_message(
                DeliveryStyle::Unspecified {
                    destination_id: remote.clone(),
                },
                vec![1, 1, 1, 1],
            )
            .unwrap();
        destination
            .send_message(
                DeliveryStyle::Unspecified {
                    destination_id: remote.clone(),
                },
                vec![2, 2, 2, 2],
            )
            .unwrap();
        destination
            .send_message(
                DeliveryStyle::Unspecified {
                    destination_id: remote.clone(),
                },
                vec![3, 3, 3, 3],
            )
            .unwrap();

        assert!(destination.pending_queries.contains(&remote));
        assert_eq!(destination.query_futures.len(), 1);
        assert_eq!(
            destination.remote_destinations.get(&remote).unwrap().pending_messages.len(),
            3
        );

        // poll destination for a while so that the query future is polled
        assert!(tokio::time::timeout(Duration::from_secs(2), destination.next()).await.is_err());

        match rx.try_recv().unwrap() {
            NetDbAction::QueryLeaseSet2 { tx, .. } => {
                let _ = tx.send(Ok(QueriedLeaseSet::Standard(Box::new(lease_set))));
            }
            _ => panic!("unexpected event"),
        }

        // poll destination until the leaset set is registered
        match tokio::time::timeout(Duration::from_secs(5), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::LeaseSetFound { destination_id } => {
                assert_eq!(destination_id, remote);
            }
            _ => panic!("invalid event"),
        }

        // verify that the three pending messages are sent to tunnel pool
        for _ in 0..3 {
            match tokio::time::timeout(Duration::from_secs(5), tm_rx.recv())
                .await
                .expect("no timeout")
                .expect("to succeed")
            {
                TunnelMessage::TunnelDeliveryViaRoute { .. } => {}
                _ => panic!("invalid tunnel message type"),
            }
        }
    }

    use crate::primitives::EncryptedLeaseSet2;

    /// Create a client destination and the receiver of its netdb actions.
    ///
    /// The returned tunnel pool handles must be kept alive for the destination to stay alive.
    fn blinded_test_destination() -> (
        Destination<MockRuntime>,
        thingbuf::mpsc::Receiver<NetDbAction, NetDbActionRecycle>,
        impl Sized,
    ) {
        let (netdb_handle, rx) = NetDbHandle::create();
        let (tp_handle, tm_rx, tp_tx, srx) = TunnelPoolHandle::create();
        let private_key = StaticPrivateKey::random(MockRuntime::rng());

        (
            Destination::<MockRuntime>::new(
                DestinationId::random(),
                private_key.clone(),
                vec![private_key.public()],
                Bytes::new(),
                netdb_handle,
                tp_handle,
                Vec::new(),
                Vec::new(),
                true,
                ProfileStorage::new(&[], &[], None),
            ),
            rx,
            (tm_rx, tp_tx, srx),
        )
    }

    /// Encrypted lease set of a random destination, its blinded key and the ID of the destination.
    fn encrypted_remote() -> (
        EncryptedLeaseSet2,
        BlindedPublicKey,
        DestinationId,
        [u8; 32],
    ) {
        let (lease_set, signing_key) = LeaseSet2::random();
        let remote_id = lease_set.header.destination.id();
        let serialized = lease_set.serialize(&signing_key);
        let expires = LeaseSet2::parse::<MockRuntime>(&serialized).unwrap().header.expires;
        let bundle =
            EncryptedLeaseSet2::encrypt::<MockRuntime>(&serialized, expires, &signing_key).unwrap();

        (
            EncryptedLeaseSet2::parse::<MockRuntime>(&bundle.payload).unwrap(),
            BlindedPublicKey::new(&signing_key.public()).unwrap(),
            remote_id,
            bundle.store_hash,
        )
    }

    #[tokio::test]
    async fn query_blinded_lease_set() {
        let (mut destination, rx, _pool) = blinded_test_destination();
        let (encrypted, blinded, remote_id, store_hash) = encrypted_remote();

        // the blinded destination is known by an id derived from its signing key
        let blinded_id = destination.register_blinded_destination(blinded.clone());
        assert_ne!(blinded_id, remote_id);
        assert_eq!(
            destination.query_lease_set(&blinded_id),
            LeaseSetStatus::NotFound
        );
        assert!(tokio::time::timeout(Duration::from_secs(2), destination.next()).await.is_err());

        // the query is for the store hash of the day and the reply is an encrypted lease set
        match rx.try_recv().unwrap() {
            NetDbAction::QueryLeaseSet2 { key, tx } => {
                assert_eq!(key, Bytes::from(store_hash.to_vec()));
                let _ = tx.send(Ok(QueriedLeaseSet::Encrypted(Box::new(encrypted))));
            }
            _ => panic!("unexpected event"),
        }

        match tokio::time::timeout(Duration::from_secs(5), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::BlindedLeaseSetFound {
                blinded_id: queried_id,
                destination_id,
            } => {
                assert_eq!(queried_id, blinded_id);
                assert_eq!(destination_id, remote_id);
            }
            _ => panic!("invalid event"),
        }

        // the decrypted lease set is stored under the real id of the destination which is used
        // for everything from now on
        let context = destination.remote_destinations.get(&remote_id).unwrap();
        assert_eq!(context.lease_set.header.destination.id(), remote_id);
        assert!(!destination.remote_destinations.contains_key(&blinded_id));
        assert_eq!(
            destination.query_lease_set(&remote_id),
            LeaseSetStatus::Found
        );
        assert!(!destination.pending_queries.contains(&blinded_id));
        assert_eq!(
            destination.register_blinded_destination(blinded.clone()),
            remote_id
        );
        assert_eq!(destination.blinded_key(&remote_id), Some(&blinded));
    }

    #[tokio::test]
    async fn blinded_lease_set_of_another_destination_rejected() {
        let (mut destination, rx, _pool) = blinded_test_destination();
        let (encrypted, _, _, _) = encrypted_remote();
        let (_, other_blinded, _, _) = encrypted_remote();

        let blinded_id = destination.register_blinded_destination(other_blinded);
        assert_eq!(
            destination.query_lease_set(&blinded_id),
            LeaseSetStatus::NotFound
        );
        assert!(tokio::time::timeout(Duration::from_secs(2), destination.next()).await.is_err());

        match rx.try_recv().unwrap() {
            NetDbAction::QueryLeaseSet2 { tx, .. } => {
                let _ = tx.send(Ok(QueriedLeaseSet::Encrypted(Box::new(encrypted))));
            }
            _ => panic!("unexpected event"),
        }

        match tokio::time::timeout(Duration::from_secs(5), destination.next())
            .await
            .expect("no timeout")
            .expect("to succeed")
        {
            DestinationEvent::LeaseSetNotFound {
                destination_id,
                error,
            } => {
                assert_eq!(destination_id, blinded_id);
                assert_eq!(error, QueryError::Malformed);
            }
            _ => panic!("invalid event"),
        }
        assert!(!destination.remote_destinations.contains_key(&blinded_id));
        assert!(!destination.pending_queries.contains(&blinded_id));
    }

    #[tokio::test]
    async fn lease_set_kind_must_match_destination_kind() {
        // standard lease set for a blinded destination
        {
            let (mut destination, rx, _pool) = blinded_test_destination();
            let (_, blinded, _, _) = encrypted_remote();
            let blinded_id = destination.register_blinded_destination(blinded);
            assert_eq!(
                destination.query_lease_set(&blinded_id),
                LeaseSetStatus::NotFound
            );
            assert!(
                tokio::time::timeout(Duration::from_secs(2), destination.next()).await.is_err()
            );

            match rx.try_recv().unwrap() {
                NetDbAction::QueryLeaseSet2 { tx, .. } => {
                    let _ = tx.send(Ok(QueriedLeaseSet::Standard(Box::new(
                        LeaseSet2::random().0,
                    ))));
                }
                _ => panic!("unexpected event"),
            }

            match tokio::time::timeout(Duration::from_secs(5), destination.next())
                .await
                .expect("no timeout")
                .expect("to succeed")
            {
                DestinationEvent::LeaseSetNotFound { error, .. } => {
                    assert_eq!(error, QueryError::Malformed);
                }
                _ => panic!("invalid event"),
            }
        }

        // encrypted lease set for a regular destination
        {
            let (mut destination, rx, _pool) = blinded_test_destination();
            let (encrypted, _, remote_id, _) = encrypted_remote();
            assert_eq!(
                destination.query_lease_set(&remote_id),
                LeaseSetStatus::NotFound
            );
            assert!(
                tokio::time::timeout(Duration::from_secs(2), destination.next()).await.is_err()
            );

            match rx.try_recv().unwrap() {
                NetDbAction::QueryLeaseSet2 { key, tx } => {
                    assert_eq!(key, Bytes::from(remote_id.to_vec()));
                    let _ = tx.send(Ok(QueriedLeaseSet::Encrypted(Box::new(encrypted))));
                }
                _ => panic!("unexpected event"),
            }

            match tokio::time::timeout(Duration::from_secs(5), destination.next())
                .await
                .expect("no timeout")
                .expect("to succeed")
            {
                DestinationEvent::LeaseSetNotFound { error, .. } => {
                    assert_eq!(error, QueryError::Malformed);
                }
                _ => panic!("invalid event"),
            }
        }
    }

    #[tokio::test]
    async fn new_lease_set_received() {
        let (netdb_handle, _rx) = NetDbHandle::create();
        let (tp_handle, _tm_rx, _tp_tx, _srx) = TunnelPoolHandle::create();
        let private_key = StaticPrivateKey::random(MockRuntime::rng());
        let destination_id = DestinationId::random();
        let public_key = private_key.public();
        let mut destination = Destination::<MockRuntime>::new(
            destination_id.clone(),
            private_key.clone(),
            vec![private_key.public()],
            Bytes::new(),
            netdb_handle,
            tp_handle,
            Vec::new(),
            Vec::new(),
            false,
            ProfileStorage::new(&[], &[], None),
        );

        // create remote destination and two leases for it
        let signing_key = SigningPrivateKey::random(MockRuntime::rng());
        let encryption_key = StaticPrivateKey::random(MockRuntime::rng());
        let dest = Dest::new::<MockRuntime>(signing_key.public());
        let remote_dest_id = dest.id();
        let expiring_inbound1 = Lease {
            router_id: RouterId::random(),
            tunnel_id: TunnelId::random(),
            expires: MockRuntime::time_since_epoch() + Duration::from_secs(10),
        };
        let expiring_inbound2 = Lease {
            router_id: RouterId::random(),
            tunnel_id: TunnelId::random(),
            expires: MockRuntime::time_since_epoch() + Duration::from_secs(10),
        };
        let lease_set = Bytes::from(
            LeaseSet2 {
                header: LeaseSet2Header {
                    destination: dest.clone(),
                    expires: Duration::from_secs(10).as_secs() as u32,
                    is_unpublished: false,
                    offline_signature: None,
                    published: MockRuntime::time_since_epoch().as_secs() as u32,
                },
                public_keys: vec![encryption_key.public()],
                leases: vec![expiring_inbound1.clone(), expiring_inbound2.clone()],
            }
            .serialize(&signing_key),
        );

        // create session manager and an NS message
        let mut session_manager = SessionManager::<MockRuntime>::new(
            remote_dest_id.clone(),
            encryption_key.clone(),
            vec![encryption_key.public()],
            lease_set,
        );
        session_manager.add_remote_destination(destination_id.clone(), public_key);
        let payload = session_manager.encrypt(&destination_id, vec![1, 3, 3, 7]).unwrap();
        let message = Message {
            message_type: MessageType::Garlic,
            message_id: *MessageId::random(),
            expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
            payload,
        };

        // verify that the remote destination isn't known to `destination`
        assert!(destination.remote_destinations.get(&remote_dest_id).is_none());

        // decrypt NS
        let (_, messages) = destination.decrypt_message(message).unwrap().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], vec![1, 3, 3, 7]);

        match destination.remote_destinations.get(&remote_dest_id) {
            Some(context) => {
                assert!(context
                    .lease_set
                    .leases
                    .iter()
                    .find(|lease| lease.tunnel_id == expiring_inbound1.tunnel_id
                        && lease.router_id == expiring_inbound1.router_id)
                    .is_some());
                assert!(context
                    .lease_set
                    .leases
                    .iter()
                    .find(|lease| lease.tunnel_id == expiring_inbound2.tunnel_id
                        && lease.router_id == expiring_inbound2.router_id)
                    .is_some());
                assert!(context.expiring_leases.is_empty())
            }
            None => panic!("expected to find context"),
        }

        // send NSR
        let message = Message {
            message_type: MessageType::Garlic,
            message_id: *MessageId::random(),
            expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
            payload: destination
                .session_manager
                .encrypt(&remote_dest_id, vec![1, 3, 3, 8])
                .unwrap(),
        };

        let Some(GarlicClove { message_body, .. }) = session_manager
            .decrypt(message)
            .unwrap()
            .find(|message| message.message_type == MessageType::Data)
        else {
            panic!("data message not found");
        };
        assert_eq!(message_body, vec![0, 0, 0, 4, 1, 3, 3, 8]);

        // send ES which starts a new session
        let payload = session_manager.encrypt(&destination_id, vec![1, 3, 3, 9]).unwrap();
        let message = Message {
            message_type: MessageType::Garlic,
            message_id: *MessageId::random(),
            expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
            payload,
        };

        // decrypt NS
        let (_, messages) = destination.decrypt_message(message).unwrap().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], vec![1, 3, 3, 9]);

        // create new lease set for `session_manager`
        let new_inbound1 = Lease {
            router_id: RouterId::random(),
            tunnel_id: TunnelId::random(),
            expires: MockRuntime::time_since_epoch() + Duration::from_secs(10),
        };
        let new_inbound2 = Lease {
            router_id: RouterId::random(),
            tunnel_id: TunnelId::random(),
            expires: MockRuntime::time_since_epoch() + Duration::from_secs(10),
        };
        let new_lease_set = Bytes::from(
            LeaseSet2 {
                header: LeaseSet2Header {
                    destination: dest.clone(),
                    expires: Duration::from_secs(10).as_secs() as u32,
                    is_unpublished: false,
                    offline_signature: None,
                    published: MockRuntime::time_since_epoch().as_secs() as u32,
                },
                public_keys: vec![encryption_key.public()],
                leases: vec![new_inbound1.clone(), new_inbound2.clone()],
            }
            .serialize(&signing_key),
        );
        session_manager.register_lease_set(new_lease_set);

        // send ES with a bundled lease set
        let payload = session_manager.encrypt(&destination_id, vec![1, 3, 4, 0]).unwrap();
        let message = Message {
            message_type: MessageType::Garlic,
            message_id: *MessageId::random(),
            expiration: MockRuntime::time_since_epoch() + I2NP_MESSAGE_EXPIRATION,
            payload,
        };

        // decrypt NS
        let (_, messages) = destination.decrypt_message(message).unwrap().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0], vec![1, 3, 4, 0]);

        // verify that the old lease set is now `expiring_leases`
        match destination.remote_destinations.get(&remote_dest_id) {
            Some(context) => {
                assert!(context
                    .lease_set
                    .leases
                    .iter()
                    .find(|lease| lease.tunnel_id == new_inbound1.tunnel_id
                        && lease.router_id == new_inbound1.router_id)
                    .is_some());
                assert!(context
                    .lease_set
                    .leases
                    .iter()
                    .find(|lease| lease.tunnel_id == new_inbound2.tunnel_id
                        && lease.router_id == new_inbound2.router_id)
                    .is_some());

                match context.expiring_leases.get(&expiring_inbound1.tunnel_id) {
                    Some(lease) => {
                        assert_eq!(lease.router_id, expiring_inbound1.router_id);
                        assert_eq!(lease.expires.as_secs(), expiring_inbound1.expires.as_secs());
                    }
                    None => panic!("expected lease set to be found"),
                }

                match context.expiring_leases.get(&expiring_inbound2.tunnel_id) {
                    Some(lease) => {
                        assert_eq!(lease.router_id, expiring_inbound2.router_id);
                        assert_eq!(lease.expires.as_secs(), expiring_inbound2.expires.as_secs());
                    }
                    None => panic!("expected lease set to be found"),
                }
            }
            None => panic!("expected to find context"),
        }

        // set the lease set prune interval to a shorter timeout and poll `destination` until the
        // timer expires
        destination.lease_set_prune_timer = MockRuntime::timer(Duration::from_secs(11));

        assert!(tokio::time::timeout(Duration::from_secs(15), destination.next()).await.is_err());

        // verify the old lease set has been pruned
        match destination.remote_destinations.get(&remote_dest_id) {
            Some(context) => {
                assert!(context
                    .lease_set
                    .leases
                    .iter()
                    .find(|lease| lease.tunnel_id == new_inbound1.tunnel_id
                        && lease.router_id == new_inbound1.router_id)
                    .is_some());
                assert!(context
                    .lease_set
                    .leases
                    .iter()
                    .find(|lease| lease.tunnel_id == new_inbound2.tunnel_id
                        && lease.router_id == new_inbound2.router_id)
                    .is_some());
                assert!(context.expiring_leases.is_empty());
            }
            None => panic!("expected to find context"),
        }
    }
}
