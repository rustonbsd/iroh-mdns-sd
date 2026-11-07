use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use iroh::{
    Endpoint, EndpointId, PublicKey, RelayUrl, Watcher,
    address_lookup::{
        AddressLookup, AddressLookupBuilder, AddressLookupBuilderError,
        Error as AddressLookupError, Item as AddressLookupItem,
    },
    endpoint_info::{AddrFilter, EndpointData, EndpointInfo},
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

use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};

const DEFAULT_RESOLVE_DURATION: Duration = Duration::from_secs(10);

const NAME: &str = "mdns-sd";
const SERVICE_TYPE: &str = "_irohsd._udp.local.";
const USER_DATA_KEY: &str = "user-data";

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
    resolve_duration: Duration,
}

impl MdnsAddressLookupBuilder {
    /// Creates a new [`MdnsAddressLookupBuilder`] with default settings.
    fn new() -> Self {
        Self {
            advertise: true,
            service_type: SERVICE_TYPE.to_string(),
            filter: AddrFilter::default(),
            resolve_duration: DEFAULT_RESOLVE_DURATION,
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

    /// Sets the resolve duration.
    ///
    /// This sets the duration we wait after a resolve request for discovery information about the
    /// requested peer to come in and to refresh.
    ///
    /// If address information is already known at resolve time it is forwarded instantly
    /// and any further updates that come in during the active `resolve_duration` is additionally
    /// forwarded to the subscribers and `iroh`s [`AddressLookupItem`] [`BoxStream<Result<AddressLookupItem>>`]
    pub fn resolve_duration(mut self, resolve_duration: Duration) -> Self {
        assert!(!resolve_duration.is_zero());
        self.resolve_duration = resolve_duration;
        self
    }

    /// Builds an [`MdnsAddressLookup`] instance with the configured settings.
    pub fn build(
        self,
        endpoint_id: EndpointId,
    ) -> Result<MdnsAddressLookup, AddressLookupBuilderError> {
        MdnsAddressLookup::new(
            endpoint_id,
            self.advertise,
            self.service_type,
            self.filter,
            self.resolve_duration,
        )
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
    /// # Panics
    /// This relies on [`tokio::runtime::Handle::current`] and will panic if called outside of the context of a tokio runtime.
    fn new(
        endpoint_id: EndpointId,
        advertise: bool,
        service_name: String,
        filter: AddrFilter,
        resolve_duration: Duration,
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

        let address_lookup_fut = async move {
            let _bridge_ref = AbortOnDropHandle::new(bridge);
            let guard = DaemonGuard(daemon);
            let mut endpoint_addr_cache: HashMap<PublicKey, AddressLookupItem> = HashMap::default();
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

                trace!(?endpoint_addr_cache, "Mdns Service loop tick");

                match msg {
                    Message::Mdns(ServiceEvent::ServiceResolved(resolved_service)) => {
                        trace!(
                            ?resolved_service,
                            "Mdns Message::Mdns(ServiceEvent::ServiceResolved)"
                        );
                        let Some(discovered_endpoint_id) = parse_id(&resolved_service.fullname)
                        else {
                            debug!("failed to parse EndpointId");
                            continue;
                        };
                        if discovered_endpoint_id == endpoint_id {
                            continue;
                        }

                        let item =
                            match resolved_to_item(&resolved_service, &discovered_endpoint_id) {
                                Ok(item) => item,
                                Err(error) => {
                                    warn!(?error, "empty service entry");
                                    continue;
                                }
                            };

                        debug!(
                            ?discovered_endpoint_id,
                            ?item,
                            "adding endpoint to Mdns address book"
                        );

                        if !cache_discovery(&mut endpoint_addr_cache, item.clone()) {
                            debug!(?discovered_endpoint_id, "updated but unchanged");
                            continue;
                        }

                        if let Some(senders) = senders.get(&discovered_endpoint_id) {
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
                    }
                    Message::Mdns(ServiceEvent::ServiceRemoved(_, removed_service)) => {
                        trace!(
                            removed_service,
                            "Mdns Message::Mdns(ServiceEvent::ServiceRemoved)"
                        );
                        if let Some(removed_endpoint_id) = parse_id(&removed_service) {
                            endpoint_addr_cache.remove(&removed_endpoint_id);
                            subscribers.send(DiscoveryEvent::Expired { endpoint_id: removed_endpoint_id });
                        }
                    }
                    Message::Mdns(service_event) => {
                        trace!(?service_event, "Mdns Message::Mdns(other)");
                    }
                    Message::Resolve(resolved_endpoint_id, sender) => {
                        trace!(?resolved_endpoint_id, "Mdns Message::Resolve");

                        let id = last_id + 1;
                        last_id = id;

                        // if we have it in cache send it right away
                        if let Some(item) = endpoint_addr_cache.get(&resolved_endpoint_id) {
                            debug!(?item, "sending AddressLookupItem");
                            sender.send(Ok(item.clone())).await.ok();
                        }

                        // register for any new mdns resolved events to be passed along
                        if let Some(senders_for_endpoint_id) =
                            senders.get_mut(&resolved_endpoint_id)
                        {
                            senders_for_endpoint_id.insert(id, sender);
                        } else {
                            let mut senders_for_endpoint_id = HashMap::new();
                            senders_for_endpoint_id.insert(id, sender);
                            senders.insert(resolved_endpoint_id, senders_for_endpoint_id);
                        }
                        let timeout_sender = task_sender.clone();
                        timeouts.spawn(async move {
                            time::sleep(resolve_duration).await;
                            trace!(?resolved_endpoint_id, "resolution timeout");
                            timeout_sender
                                .send(Message::Timeout(resolved_endpoint_id, id))
                                .await
                                .ok();
                        });
                    }
                    Message::Timeout(timedout_endpoint_id, id) => {
                        trace!(?timedout_endpoint_id, "Mdns Message::Timeout");
                        if let Some(senders_for_endpoint_id) =
                            senders.get_mut(&timedout_endpoint_id)
                        {
                            senders_for_endpoint_id.remove(&id);
                            if senders_for_endpoint_id.is_empty() {
                                senders.remove(&timedout_endpoint_id);
                            }
                        }
                    }
                    Message::Subscribe(sender) => {
                        trace!("Mdns Message::Subscribe");
                        subscribers.push(sender);
                    }
                }
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

/// Takes [`EndpointData`] and creates [`ServiceInfo`] that can be published with `mdns-sd`.
fn build_service_info(
    endpoint_id: &EndpointId,
    data: &EndpointData,
) -> Result<ServiceInfo, mdns_sd::Error> {
    // If there are neither [`TransportAddr::Ip(SocketAddr)`] nor [`TransportAddr::Relay(RelayUrl)`] addresses we return
    // a `mdns_sd::Error` since we can't be connected to anyways and therefore not build a [`ServiceInfo`].
    //
    // Note: if we don't have any [`TransportAddr::Ip(SocketAddr)`] but we do have [`TransportAddr::Relay(RelayUrl)`] addresses
    // we create a [`ServiceInfo`] with no A/AAAA records and only TXT for relay and optional user data and set the port to 0
    // (see comment in this fn below, above: "let (ip, port) = if..."). [!] todo: this still needs to be tested
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

    // this needs no sice check since [`iroh_dns::endpoint_info::UserData`] already enforces a max size of 255 bytes
    // as long as the KV entry key is `user-data`.
    let user_data = data.user_data().cloned();

    // probably possible to just gate on `first_addr.is_empty()` and `relays.is_empty()` but this way if a lib user
    // provides their own custom non iroh native discovery information they can do whatever they do with it
    // and e.g. decrypt their custom `user_data` ip's and add them manually. Who knows :shrug:
    if first_addr.is_none() && relays.is_empty() && user_data.is_none() {
        return Err(mdns_sd::Error::Msg("no valid addresses to publish".into()));
    }

    // If we don't have any [`TransportAddr::Ip(SocketAddr)`] to advertise and only [`TransportAddr::Relay(RelayUrl)`]
    // we have to still supply a port to [`ServiceInfo::new`]. In that case we pass 0u16 as the port, this should be allowed according to:
    // [rfc6763 section 8](https://www.rfc-editor.org/rfc/rfc6763.html#section-8)
    // "[..] creates a placeholder SRV record (priority=0, weight=0, port=0, target host = host name of device) [..]".
    //
    // This is technically ment for announcing we are not supporting the service but i also found other protocols and implementations
    // using it to indicate service unavailability (see for example https://docs.oracle.com/cd/E88353_01/html/E72487/dns-sd-8.html).
    // Here it says "Registering a service on port 0 allows an application to explicitly advertise the non-availability of a service."
    // which is kind of correct since the service *is* not available at that instance in time. So i am using it here :shrug:
    let (ip, port) = if let Some(addr) = first_addr {
        (vec![addr.ip()], addr.port())
    } else {
        (Vec::new(), 0)
    };

    let mut props = if let Some(user_data) = user_data {
        vec![(USER_DATA_KEY.to_string(), user_data.to_string())]
    } else {
        Vec::new()
    };

    // add rest of socket addrs
    props.extend(
        rest_addrs
            .iter()
            .enumerate()
            .map(|(i, addr)| (format!("a{i}"), addr.to_string())),
    );

    // add relays
    // Note: i know `iroh` only holds a single active relay except when actively dialing a peer whos
    // home relay is different to the home relay of our node, and in local scenarios like mdns it is even
    // less likely but i don't really see a reason not to include all realys besides larger mdns records.
    // But this lib is intended as a replacement for `iroh-mdns-peer-lookup` and not for `iroh-mdns-address-lookup`
    // and since the trade off between them is faster connection speeds + meant for fast cli apps vs.
    // larger scaling + longer running clusters respectively i think including as many relays for best effort
    // dialing is more inline with the niche this lib is intending to fill/replace.
    // This could be wrong, i haven't looked at the underlying `iroh`/`noq` code but the downside is minimal so what ever ^^.
    props.extend(
        relays
            .iter()
            .enumerate()
            .map(|(i, relay)| (format!("r{i}"), relay.clone())),
    );

    let instance = instance_name(endpoint_id);
    let host = format!("{instance}.local.");

    ServiceInfo::new(
        SERVICE_TYPE,
        &instance,
        &host,
        ip.as_slice(),
        port,
        props.as_slice(),
    )
}

/// Takes [`ResolvedService`] and creates [`AddressLookupItem`] that is used for `iroh` peer discovery.
/// Returns an `Error` if no discovery information could be found.
fn resolved_to_item(
    info: &ResolvedService,
    eid: &EndpointId,
) -> Result<AddressLookupItem, &'static str> {
    let ip_addrs: BTreeSet<SocketAddr> = info
        .addresses
        .iter()
        .map(|scoped_ip| SocketAddr::new(scoped_ip.to_ip_addr(), info.get_port()))
        .chain(info.get_properties().iter().filter_map(|prop| {
            if prop.key().starts_with("a") {
                prop.val_str().parse().ok()
            } else {
                None
            }
        }))
        .collect();

    let relays: BTreeSet<RelayUrl> = info
        .get_properties()
        .iter()
        .filter_map(|prop| {
            // as defined above we cap at 100 records ("r0" to "r99")
            // see comment in fn [`build_service_info`] for reason
            if prop.key().starts_with("r") && prop.key().len() <= 3 {
                prop.val_str().parse().ok()
            } else {
                None
            }
        })
        .collect();

    let user_data = if let Some(user_data) = info.get_property_val_str(USER_DATA_KEY) {
        match user_data.parse() {
            Err(err) => {
                debug!("failed to parse user data from TXT attribute: {err}");
                None
            }
            Ok(data) => Some(data),
        }
    } else {
        None
    };

    if ip_addrs.is_empty() && relays.is_empty() && user_data.is_none() {
        return Err("no discovery information provided");
    }

    let mut data = EndpointData::from(ip_addrs);
    for relay in relays {
        data.add_relay_url(relay);
    }
    data.set_user_data(user_data);

    let endpoint_info = EndpointInfo::from_parts(*eid, data);
    Ok(AddressLookupItem::new(endpoint_info, NAME, None))
}

fn instance_name(id: &EndpointId) -> String {
    data_encoding::BASE32_NOPAD
        .encode(id.as_bytes())
        .to_ascii_lowercase()
}

fn parse_id(fullname: &str) -> Option<PublicKey> {
    let inst = fullname.strip_suffix(SERVICE_TYPE)?.strip_suffix('.')?;
    PublicKey::from_str(inst).ok()
}
