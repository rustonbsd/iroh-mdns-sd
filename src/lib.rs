use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Instant,
};

use iroh::{
    Endpoint, EndpointId, PublicKey, Watcher,
    address_lookup::{
        AddressLookup, AddressLookupBuilder, AddressLookupBuilderError,
        Error as AddressLookupError, Item as AddressLookupItem,
    },
    endpoint_info::{AddrFilter, EndpointData, EndpointInfo, UserData},
};
use n0_future::{
    Stream,
    boxed::BoxStream,
    task::{self, AbortOnDropHandle},
    time,
};
use n0_watcher::Watchable;
use tokio::{
    sync::mpsc::{self, error::TrySendError},
    task::JoinSet,
};
use tracing::{Instrument, debug, error, info_span, trace, warn};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

const NAME: &str = "mdns-sd";
const SERVICE_TYPE: &str = "_irohsd._udp.local.";
const USER_DATA_KEY: &str = "user-data";

pub(crate) type TxtData = BTreeMap<String, Option<String>>;

/// A peer discovered by the swarm discovery service.
///
/// The discovery yields service instances, which are located by a port and a list of IP addresses.
/// Both IPv4 and IPv6 addresses may be present, depending on the configuration.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Peer {
    addrs: Vec<(IpAddr, u16)>,
    last_seen: Instant,
    txt: TxtData,
}

/// Address Lookup using the `mdns-sd` crate.
#[derive(Debug, Clone)]
pub struct MdnsAddressLookup {
    #[allow(dead_code)]
    handle: Arc<AbortOnDropHandle<()>>,
    sender: mpsc::Sender<Message>,
    advertise: bool,
    /// When `local_addrs` changes, we re-publish our info.
    local_addrs: Watchable<Option<EndpointData>>,
}

#[derive(Debug)]
enum Message {
    Mdns(ServiceEvent),
    Resolve(
        EndpointId,
        mpsc::Sender<Result<AddressLookupItem, AddressLookupError>>,
    ),
    Timeout(EndpointId, usize),
    Subscribe(mpsc::Sender<DiscoveryEvent>),
}

/// Manages the list of subscribers that are subscribed to this Address Lookup.
#[derive(Debug)]
struct Subscribers(Vec<mpsc::Sender<DiscoveryEvent>>);

impl Subscribers {
    fn new() -> Self {
        Self(vec![])
    }

    /// Add the subscriber to the list of subscribers.
    fn push(&mut self, subscriber: mpsc::Sender<DiscoveryEvent>) {
        self.0.push(subscriber);
    }

    /// Sends the `endpoint_id` and `item` to each subscriber.
    ///
    /// Cleans up any subscribers that have been dropped.
    fn send(&mut self, item: DiscoveryEvent) {
        let mut clean_up = vec![];
        for (i, subscriber) in self.0.iter().enumerate() {
            // assume subscriber was dropped
            if let Err(err) = subscriber.try_send(item.clone()) {
                match err {
                    TrySendError::Full(_) => {
                        warn!(?item, idx = i, "mdns subscriber is blocked, dropping item")
                    }
                    TrySendError::Closed(_) => clean_up.push(i),
                }
            }
        }
        for i in clean_up.into_iter().rev() {
            self.0.swap_remove(i);
        }
    }
}

/// Builder for [`MdnsAddressLookup`].
#[derive(Debug)]
pub struct MdnsAddressLookupBuilder {
    advertise: bool,
    service_type: String,
    filter: AddrFilter,
}

impl MdnsAddressLookupBuilder {
    /// Creates a new [`MdnsAddressLookupBuilder`] with default settings.
    fn new() -> Self {
        Self {
            advertise: true,
            service_type: SERVICE_TYPE.to_string(),
            filter: AddrFilter::default(),
        }
    }

    /// Sets whether this endpoint should advertise its presence.
    ///
    /// Default is true.
    pub fn advertise(mut self, advertise: bool) -> Self {
        self.advertise = advertise;
        self
    }

    /// Sets a custom service name.
    ///
    /// The default is `irohsd`, which will show up on a record in the
    /// following form, for example:
    /// `7rutqynuzu65fcdgoerbt4uoh3p62wuto2mp56x3uvhitqzssxga._irohsd._udp.local.`
    ///
    /// Any custom service name will take the form, for example:
    /// `7rutqynuzu65fcdgoerbt4uoh3p62wuto2mp56x3uvhitqzssxga._{service_name}._udp.local.`
    pub fn service_name(mut self, service_name: impl Into<String>) -> Self {
        self.service_type = format!("_{}._udp.local.", service_name.into());
        self
    }

    /// Sets a filter to control which addresses are published by this service.
    pub fn addr_filter(mut self, filter: AddrFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Builds an [`MdnsAddressLookup`] instance with the configured settings.
    pub fn build(
        self,
        endpoint_id: EndpointId,
    ) -> Result<MdnsAddressLookup, AddressLookupBuilderError> {
        MdnsAddressLookup::new(endpoint_id, self.advertise, self.service_type, self.filter)
    }
}

impl Default for MdnsAddressLookupBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressLookupBuilder for MdnsAddressLookupBuilder {
    fn into_address_lookup(
        self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        self.build(endpoint.id())
    }
}

impl AddressLookup for MdnsAddressLookup {
    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<BoxStream<Result<AddressLookupItem, AddressLookupError>>> {
        use futures_util::FutureExt;

        let (send, recv) = mpsc::channel(20);
        let address_lookup_sender = self.sender.clone();
        let stream = async move {
            address_lookup_sender
                .send(Message::Resolve(endpoint_id, send))
                .await
                .ok();
            tokio_stream::wrappers::ReceiverStream::new(recv)
        };
        Some(Box::pin(stream.flatten_stream()))
    }

    fn publish(&self, data: &EndpointData) {
        if self.advertise {
            self.local_addrs.set(Some(data.clone())).ok();
        }
    }
}

struct DaemonGuard(ServiceDaemon);
impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.0.shutdown();
    }
}

/// An event emitted from the [`MdnsAddressLookup`] service.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiscoveryEvent {
    /// A peer was discovered or it's information was updated.
    Discovered {
        /// The endpoint info for the endpoint, as discovered.
        endpoint_info: EndpointInfo,
        /// Optional timestamp when this endpoint address info was last updated.
        last_updated: Option<u64>,
    },
    /// A peer was expired due to being inactive, unreachable, or otherwise
    /// unavailable.
    Expired {
        /// The id of the endpoint that expired.
        endpoint_id: EndpointId,
    },
}

impl MdnsAddressLookup {
    /// Returns a [`MdnsAddressLookupBuilder`] used to construct [`MdnsAddressLookup`].
    pub fn builder() -> MdnsAddressLookupBuilder {
        MdnsAddressLookupBuilder::default()
    }

    /// Create a new [`MdnsAddressLookup`] Service.
    ///
    /// This starts a [`Discoverer`] that broadcasts your addresses (if advertise is set to true)
    /// and receives addresses from other endpoints in your local network.
    ///
    /// # Errors
    /// Returns an error if the network does not allow ipv4 OR ipv6.
    ///
    /// # Panics
    /// This relies on [`tokio::runtime::Handle::current`] and will panic if called outside of the context of a tokio runtime.
    fn new(
        endpoint_id: EndpointId,
        advertise: bool,
        service_name: String,
        filter: AddrFilter,
    ) -> Result<Self, AddressLookupBuilderError> {
        let err = |e| AddressLookupBuilderError::from_err(NAME, e);
        let daemon = ServiceDaemon::new().map_err(err)?;
        let browse_rx = daemon.browse(&service_name).map_err(err)?;

        let (send, mut recv) = mpsc::channel(64);

        // bridges mdns-sd thread via flume channel to tokio actor.
        let bridge_tx = send.clone();
        let bridge = task::spawn(async move {
            while let Ok(ev) = browse_rx.recv_async().await {
                if let Err(e) = bridge_tx.send(Message::Mdns(ev)).await {
                    warn!(?e, "mdns-sd bridge channel closed, stopping mdns-sd bridge");
                    break;
                }
            }
        });

        let local_addrs: Watchable<Option<EndpointData>> = Watchable::default();
        let mut addrs_change = local_addrs.watch();
        let task_sender = send.clone();
        let my_instance = instance_name(&endpoint_id);

        let address_lookup_fut = async move {
            let guard = DaemonGuard(daemon);
            let mut endpoint_addrs: HashMap<PublicKey, AddressLookupItem> = HashMap::default();
            let mut subscribers = Subscribers::new();
            let mut senders: HashMap<
                PublicKey,
                HashMap<usize, mpsc::Sender<Result<AddressLookupItem, AddressLookupError>>>,
            > = HashMap::default();
            let mut last_id: usize = 0usize;
            let mut timeouts = JoinSet::new();
            loop {
                let msg = tokio::select! {
                    Some(_) = timeouts.join_next(), if !timeouts.is_empty() => {
                        continue
                    },
                    msg = recv.recv() => match msg {
                        Some(m) => m,
                        None => {
                            error!("Mdns channel closed");
                            error!("closing Mdns");
                            timeouts.abort_all();
                            // guard drops here, shutting down mdns-sd daemon
                            return
                        },
                    },
                    Ok(Some(data)) = addrs_change.updated() => {
                        let data = data.apply_filter(&filter).into_owned();
                        match build_service_info(&endpoint_id, &data) {
                            Ok(info) => if let Err(e) = guard.0.register(info) {
                                warn!(?e, "mdns-sd register failed");
                            }
                            Err(e) => warn!(?e, "bad service info"),
                        }
                        continue;
                    }
                };

                trace!(?endpoint_addrs, "Mdns Service loop tick");
                
                match msg {
                    Message::Mdns(ServiceEvent::ServiceResolved(resolved_service)) => {
                        trace!(
                            ?resolved_service,
                            "Mdns Message::Mdns(ServiceEvent::ServiceResolved)"
                        );
                        let Some(discovered_eid) = parse_id(&resolved_service.fullname) else {
                            debug!("failed to parse EndpointId");
                            continue;
                        };
                        if discovered_eid == endpoint_id {
                            continue;
                        }
                        let item = todo!();
                        if !cache_discovery(&mut endpoint_addrs, item.clone()) {
                            debug!(?endpoint_addr, "unchanged");
                            continue;
                        }
                        
                        if let Some(senders) = senders.get(&discovered_eid) {
                            trace!(?item, senders = senders.len(), "sending AddressLookupItem");
                            for sender in senders.values() {
                                sender.send(Ok(item.clone())).await.ok();
                            }
                        }

                        // In the `iroh-mdns-address-lookup` impl by the n0 team this is only done for "passively" discovered endpoints.
                        // My guess to their reasoning is the following: we either use this in "manual" discovery mode in which
                        // case `subscribers` get passed the discovered endpoints or the "used as AddressLookup"
                        // within iroh. I prefer to have the option to use "and/or" this decision.
                        // The danger I see here is that users getting `Discovered` events might think they have to
                        // manually add discovered endpoints to the `iroh` [`Endpoint`] but I think a comment will clarify
                        // and then we get the best of both worlds :shrug:
                        subscribers.send(DiscoveryEvent::Discovered {
                            endpoint_info: item.endpoint_info().clone(),
                            last_updated: item.last_updated(),
                        });
                    },
                    Message::Mdns(ServiceEvent::ServiceRemoved(_, removed_service)) => {
                        trace!(removed_service, "Mdns Message::Mdns(ServiceEvent::ServiceRemoved)");
                        if let Some(id) = parse_id(&removed_service) {
                            endpoint_addrs.remove(&id);
                            subscribers.send(DiscoveryEvent::Expired { endpoint_id: id });
                        }
                    },
                    Message::Mdns(service_event) => {
                        trace!(?service_event, "Mdns Message::Mdns(other)");
                    },
                    Message::Resolve(public_key, sender) => todo!(),
                    Message::Timeout(public_key, _) => todo!(),
                    Message::Subscribe(sender) =>  {
                        trace!("Mdns Message::Subscribe");
                        subscribers.push(sender);
                    },
                }
                /*
                match msg {
                    Message::Discovered(discovered_endpoint_id, peer_info) => {
                        trace!(
                            ?discovered_endpoint_id,
                            ?peer_info,
                            "Mdns Message::Discovered"
                        );
                        let discovered_endpoint_id =
                            match PublicKey::from_str(&discovered_endpoint_id) {
                                Ok(endpoint_id) => endpoint_id,
                                Err(e) => {
                                    warn!(
                                        discovered_endpoint_id,
                                        "couldn't parse endpoint_id from mdns Address Lookup: {e:?}"
                                    );
                                    continue;
                                }
                            };

                        if discovered_endpoint_id == endpoint_id {
                            continue;
                        }

                        if peer_info.is_expiry() {
                            trace!(
                                ?discovered_endpoint_id,
                                "removing endpoint from Mdns address book"
                            );
                            endpoint_addrs.remove(&discovered_endpoint_id);
                            subscribers.send(DiscoveryEvent::Expired {
                                endpoint_id: discovered_endpoint_id,
                            });
                            continue;
                        }

                        let item = peer_to_discovery_item(&peer_info, &discovered_endpoint_id);
                        if !cache_discovery(&mut endpoint_addrs, item.clone()) {
                            continue;
                        }
                        debug!(
                            ?discovered_endpoint_id,
                            ?peer_info,
                            "adding endpoint to Mdns address book"
                        );
                        let mut resolved = false;
                        if let Some(senders) = senders.get(&discovered_endpoint_id) {
                            trace!(?item, senders = senders.len(), "sending AddressLookupItem");
                            resolved = true;
                            for sender in senders.values() {
                                sender.send(Ok(item.clone())).await.ok();
                            }
                        }

                        // only send endpoints to the `subscriber` if they weren't explicitly resolved
                        // in other words, endpoints sent to the `subscribers` should only be the ones that
                        // have been "passively" discovered
                        if !resolved {
                            subscribers.send(DiscoveryEvent::Discovered {
                                endpoint_info: item.endpoint_info().clone(),
                                last_updated: item.last_updated(),
                            });
                        }
                    }
                    Message::Resolve(endpoint_id, sender) => {
                        let id = last_id + 1;
                        last_id = id;
                        trace!(?endpoint_id, "Mdns Message::SendAddrs");
                        if let Some(item) = endpoint_addrs.get(&endpoint_id) {
                            debug!(?item, "sending AddressLookupItem");
                            sender.send(Ok(item.clone())).await.ok();
                        }
                        if let Some(senders_for_endpoint_id) = senders.get_mut(&endpoint_id) {
                            senders_for_endpoint_id.insert(id, sender);
                        } else {
                            let mut senders_for_endpoint_id = HashMap::new();
                            senders_for_endpoint_id.insert(id, sender);
                            senders.insert(endpoint_id, senders_for_endpoint_id);
                        }
                        let timeout_sender = task_sender.clone();
                        timeouts.spawn(async move {
                            time::sleep(lookup_duration).await;
                            trace!(?endpoint_id, "resolution timeout");
                            timeout_sender
                                .send(Message::Timeout(endpoint_id, id))
                                .await
                                .ok();
                        });
                    }
                    Message::Timeout(endpoint_id, id) => {
                        trace!(?endpoint_id, "Mdns Message::Timeout");
                        if let Some(senders_for_endpoint_id) = senders.get_mut(&endpoint_id) {
                            senders_for_endpoint_id.remove(&id);
                            if senders_for_endpoint_id.is_empty() {
                                senders.remove(&endpoint_id);
                            }
                        }
                    }
                    Message::Subscribe(subscriber) => {
                        trace!("Mdns Message::Subscribe");
                        subscribers.push(subscriber);
                    }
                }
                 */
            }
        };

        let handle = task::spawn(address_lookup_fut.instrument(info_span!("mdns-sd.actor")));
        Ok(Self {
            handle: Arc::new(AbortOnDropHandle::new(handle)),
            sender: send,
            advertise,
            local_addrs,
        })
    }

    /// Subscribe to discovered endpoints.
    pub async fn subscribe(&self) -> impl Stream<Item = DiscoveryEvent> + Unpin + use<> {
        let (sender, recv) = mpsc::channel(20);
        let address_lookup_sender = self.sender.clone();
        address_lookup_sender
            .send(Message::Subscribe(sender))
            .await
            .ok();
        tokio_stream::wrappers::ReceiverStream::new(recv)
    }

    fn spawn_discoverer(
        endpoint_id: PublicKey,
        advertise: bool,
        sender: mpsc::Sender<Message>,
        socketaddrs: BTreeSet<SocketAddr>,
        service_name: String,
        rt: &tokio::runtime::Handle,
    ) -> Result<DaemonGuard, AddressLookupBuilderError> {
        /*let spawn_rt = rt.clone();
        let callback = move |endpoint_id: &str, peer: &Peer| {
            trace!(endpoint_id, ?peer, "Received peer information from Mdns");

            let sender = sender.clone();
            let endpoint_id = endpoint_id.to_string();
            let peer = peer.clone();
            spawn_rt.spawn(async move {
                sender
                    .send(Message::Discovered(endpoint_id, peer))
                    .await
                    .ok();
            });
        };
        let endpoint_id_str = data_encoding::BASE32_NOPAD
            .encode(endpoint_id.as_bytes())
            .to_ascii_lowercase();
        let mut discoverer = Discoverer::new_interactive(service_name, endpoint_id_str)
            .with_cadence(cadence)
            .with_callback(callback)
            .with_ip_class(IpClass::Auto);
        if advertise {
            let addrs = MdnsAddressLookup::socketaddrs_to_addrs(socketaddrs.iter());
            for addr in addrs {
                discoverer = discoverer.with_addrs(addr.0, addr.1);
            }
        }
        discoverer
            .spawn(rt)
            .map_err(|e| AddressLookupBuilderError::from_err("mdns", e))
            */
        todo!("")
    }

    fn socketaddrs_to_addrs<'a>(
        socketaddrs: impl Iterator<Item = &'a SocketAddr>,
    ) -> HashMap<u16, Vec<IpAddr>> {
        let mut addrs: HashMap<u16, Vec<IpAddr>> = HashMap::default();
        for socketaddr in socketaddrs {
            addrs
                .entry(socketaddr.port())
                .and_modify(|a| a.push(socketaddr.ip()))
                .or_insert(vec![socketaddr.ip()]);
        }
        addrs
    }
}

fn instance_name(id: &EndpointId) -> String {
    data_encoding::BASE32_NOPAD
        .encode(id.as_bytes())
        .to_ascii_lowercase()
}

/// Caches the latest discovery item for an endpoint.
///
/// Returns `true` if the endpoint is new or its advertised content changed.
/// Observation timestamps do not affect the comparison. The cached item is
/// always replaced so later lookups use the latest addresses.
fn cache_discovery(
    cache: &mut HashMap<PublicKey, AddressLookupItem>,
    item: AddressLookupItem,
) -> bool {
    let id = item.endpoint_id();
    let changed = cache
        .get(&id)
        .is_none_or(|old| old.endpoint_info() != item.endpoint_info());
    cache.insert(id, item);
    changed
}

struct RecordData {
    first_addr: Option<SocketAddr>,
    rest_addrs: Vec<SocketAddr>,
    relays: Vec<String>,
    user_data: Option<UserData>,
}

impl TryFrom<&EndpointData> for RecordData {
    type Error = String;

    /// Returns [`RecordData`] for a given [`EndpointData`].
    ///
    /// If there are neither [`TransportAddr::Ip(SocketAddr)`] nor [`TransportAddr::Relay(RelayUrl)`] addresses we return `None` since we can't be connected to anyways.
    ///
    /// Note: if there are no [`TransportAddr::Ip(SocketAddr)`] but do have [`TransportAddr::Relay(RelayUrl)`] addresses
    /// we create a [`ServiceInfo`] with no A/AAAA records and only TXT for relay and optional user data. (this needs to be tested)
    fn try_from(data: &EndpointData) -> Result<Self, Self::Error> {
        let mut addrs = data.ip_addrs();
        let first_addr = addrs.next().cloned();
        let rest_addrs = addrs.cloned().collect::<Vec<SocketAddr>>();

        // Relay urls are encoded in kv as `r0` to `r99`; we don't pad the zeros to not transmit more bytes then we need
        // but we also don't allow relay urls to be longer then 252 bytes even tough it is technially possible
        // to have the first 10 entries (`r0=` to `r9=`) be 253 bytes long but this has no real advandate and could lead
        // to rejection of a relay url or not based on the order they appear in the [`EndpointData`]
        let relays = data
            .relay_urls()
            .map(|url| url.as_str().to_string())
            .filter(|url| url.len() < 253)
            .collect::<Vec<_>>();

        if first_addr.is_none() && relays.is_empty() {
            return Err("no valid addresses to publish".into());
        }

        // this needs no sice check since [`iroh_dns::endpoint_info::UserData`] already enforces a max size of 255 bytes
        // as long as the KV entry key is `user-data`.
        let user_data = data.user_data().cloned();

        Ok(Self {
            first_addr,
            rest_addrs,
            relays,
            user_data,
        })
    }
}

fn build_service_info(
    endpoint_id: &EndpointId,
    data: &EndpointData,
) -> Result<ServiceInfo, mdns_sd::Error> {
    let record_data: RecordData = data.try_into().map_err(mdns_sd::Error::Msg)?;

    // If we don't have any [`TransportAddr::Ip(SocketAddr)`] to advertise and only [`TransportAddr::Relay(RelayUrl)`]
    // we have to still supply a port to [`ServiceInfo::new`]. In that case we pass 0u16 as the port, this should be allowed according to:
    // [rfc6763 section 8](https://www.rfc-editor.org/rfc/rfc6763.html#section-8)
    // "[..] creates a placeholder SRV record (priority=0, weight=0, port=0, target host = host name of device) [..]".
    //
    // This is technically ment for announcing we are not supporting the service but i also found other protocols and implementations
    // using it to indicate service unavailability (see for example https://docs.oracle.com/cd/E88353_01/html/E72487/dns-sd-8.html).
    // Here it says "Registering a service on port 0 allows an application to explicitly advertise the non-availability of a service."
    // which is kind of correct since the service *is* not available at that instance in time. So i am using it here :shrug:
    let (ip, port) = if let Some(addr) = record_data.first_addr {
        (vec![addr.ip()], addr.port())
    } else {
        (Vec::new(), 0)
    };

    let mut props = if let Some(user_data) = record_data.user_data {
        vec![(USER_DATA_KEY.to_string(), user_data.to_string())]
    } else {
        Vec::new()
    };

    // add rest of socket addrs
    props.extend(
        record_data
            .rest_addrs
            .iter()
            .enumerate()
            .map(|(i, addr)| (format!("a{i}"), addr.to_string())),
    );

    // add relays
    props.extend(
        record_data
            .relays
            .iter()
            .enumerate()
            .map(|(i, relay)| (format!("r{i}"), relay.clone())),
    );

    let instance = data_encoding::BASE32_NOPAD
        .encode(endpoint_id.as_bytes())
        .to_ascii_lowercase();
    let host = format!("{instance}.local.");

    Ok(ServiceInfo::new(
        SERVICE_TYPE,
        &instance,
        &host,
        ip.as_slice(),
        port,
        props.as_slice(),
    )?)
}

fn parse_id(fullname: &str) -> Option<PublicKey> {
    let inst = fullname.strip_suffix(SERVICE_TYPE)?.strip_suffix('.')?;
    PublicKey::from_str(inst).ok()
}