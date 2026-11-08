//! An address lookup service that uses mdns to discover and lookup the addresses of local endpoints.
//!
//! This allows you to use an `mdns-sd`'s mdns impl to find address information about endpoints that are on your local network, no relay or outside internet needed.
//! See the [`mdns-sd`](https://crates.io/crates/mdns-sd) crate for more details.
//!
//! When [`MdnsAddressLookup`] is enabled, it's possible to get a list of the locally discovered endpoints by filtering a list of `RemoteInfo`s.
//!
//! In order to get a list of locally discovered addresses, you must call `MdnsAddressLookup::subscribe` to subscribe
//! to a stream of discovered addresses.
//!
//! ```no_run
//! use iroh::{Endpoint, endpoint::presets};
//! use iroh_mdns_sd::{DiscoveryEvent, MdnsAddressLookup};
//! use n0_future::StreamExt;
//!
//! #[tokio::main]
//! async fn main() {
//!     let endpoint = Endpoint::bind(presets::Minimal).await.unwrap();
//!
//!     // Register the Address Lookupwith the endpoint
//!     let mdns = MdnsAddressLookup::builder().build(endpoint.id()).unwrap();
//!     endpoint.address_lookup().unwrap().add(mdns.clone());
//!
//!     // Subscribe to the mdns discovery events
//!     let mut events = mdns.subscribe().await;
//!     while let Some(event) = events.next().await {
//!         match event {
//!             DiscoveryEvent::Discovered { endpoint_info, .. } => {
//!                 println!("MDNS discovered: {:?}", endpoint_info);
//!             }
//!             DiscoveryEvent::Expired { endpoint_id } => {
//!                 println!("MDNS expired: {endpoint_id}");
//!             }
//!             _ => {}
//!         }
//!     }
//! }
//! ```
//!
//! ## Filtering
//!
//! By default, [`MdnsAddressLookup`] publishes all addresses it receives:
//! direct IP addresses and up to one [`RelayUrl`]. The following constraints apply regardless
//! of any user-supplied filter:
//!
//! - Only the first [`RelayUrl`] in the address set is published.
//! - A [`RelayUrl`] longer than 249 bytes is silently dropped.
//!
//! You can supply an [`AddrFilter`] via [`MdnsAddressLookupBuilder::addr_filter`] to
//! control which addresses are published and in what order. The filter is applied before the
//! constraints above, so for example you can use it to exclude relay URLs entirely or to
//! prioritize certain addresses.
//!
//! [`AddrFilter`]: iroh::address_lookup::AddrFilter
//! [`RelayUrl`]: iroh_base::RelayUrl
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
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

use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};

const DEFAULT_RESOLVE_DURATION: Duration = Duration::from_secs(10);

const NAME: &str = "mdns-sd";
const SERVICE_TYPE: &str = "_irohsd._udp.local.";
const USER_DATA_KEY: &str = "user-data";

type ResolveSender = HashMap<usize, mpsc::Sender<Result<AddressLookupItem, AddressLookupError>>>;

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

#[derive(Clone, PartialEq, Eq, Debug, Default)]
struct Record {
    addrs: BTreeSet<SocketAddr>,
    relays: BTreeSet<RelayUrl>,
    user_data: Option<UserData>,
}

struct RegistrationUpdate {
    register: Vec<ServiceInfo>,
    unregister: Vec<String>,
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
    ///
    /// [Service Name rfc rules](https://www.rfc-editor.org/info/rfc6335/#section-5.1):
    /// - MUST NOT start with an `_` underscore, the `_` this is automatically appended
    /// - MUST contain only US-ASCII [ANSI.X3.4-1986] letters 'A' - 'Z' and 'a' - 'z', digits '0' - '9', and hyphens ('-', ASCII 0x2D or decimal 45)
    /// - MUST be at least 1 character and no more than 15 characters long
    /// - MUST contain at least one letter ('A' - 'Z' or 'a' - 'z')
    /// - MUST NOT begin or end with a hyphen
    /// - hyphens MUST NOT be adjacent to other hyphens
    pub fn service_name(mut self, service_name: impl Into<String>) -> Self {
        let sn_str = service_name.into();
        assert!(
            sn_str
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "service_name: MUST contain only US-ASCII [ANSI.X3.4-1986] letters 'A' - 'Z' and 'a' - 'z', digits '0' - '9', and hyphens"
        );
        assert!(
            !sn_str.is_empty() && sn_str.len() < 16,
            "service_name: MUST be at least 1 character and no more than 15 characters long"
        );
        assert!(
            !sn_str.starts_with("-") && !sn_str.ends_with("-"),
            "service_name: MUST NOT begin or end with a hyphen"
        );
        assert!(
            !sn_str.contains("--"),
            "service_name: hyphens MUST NOT be adjacent to other hyphens"
        );
        self.service_type = format!("_{}._udp.local.", sn_str);
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
        tracing::info!(service_type = self.service_type, "service_name");
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
        trace!(?endpoint_id, "AddressLookup resolve request");
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

    fn publish(&self, endpoint_data: &EndpointData) {
        if self.advertise {
            trace!(?endpoint_data, "AddressLookup publish request");
            self.local_addrs.set(Some(endpoint_data.clone())).ok();
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
        service_type: String,
        filter: AddrFilter,
        resolve_duration: Duration,
    ) -> Result<Self, AddressLookupBuilderError> {
        let err = |e| AddressLookupBuilderError::from_err(NAME, e);
        let daemon = ServiceDaemon::new().map_err(err)?;
        let browse_rx = daemon.browse(&service_type).map_err(err)?;

        let (send, mut recv) = mpsc::channel(64);

        // bridges mdns-sd thread via flume channel to tokio actor.
        let bridge_tx = send.clone();
        let bridge = task::spawn(async move {
            while let Ok(ev) = browse_rx.recv_async().await {
                if let Err(e) = bridge_tx.send(Message::Mdns(ev)).await {
                    warn!(?e, "bridge channel closed, stopping mdns-sd bridge");
                    break;
                }
            }
        });

        #[cfg(debug_assertions)]
        {
            tracing::debug!("Starting mdns-sd Daemon monitor (debug mode)...");
            let monitor_rx = daemon.monitor().map_err(err)?;
            std::thread::spawn(move || {
                while let Ok(event) = monitor_rx.recv() {
                    tracing::debug!(?event, "monitor");
                }
            });
        }

        let local_addrs: Watchable<Option<EndpointData>> = Watchable::default();
        let mut addrs_change = local_addrs.watch();
        let task_sender = send.clone();

        let address_lookup_fut = async move {
            let _bridge_ref = AbortOnDropHandle::new(bridge);
            let guard = DaemonGuard(daemon);

            let mut subscribers = Subscribers::new();
            let mut endpoint_addr_cache: HashMap<PublicKey, AddressLookupItem> = HashMap::default();
            let mut resolve_senders: HashMap<EndpointId, ResolveSender> = HashMap::default();
            let mut published: BTreeMap<u16, Record> = BTreeMap::new();
            let mut discovered: HashMap<PublicKey, BTreeMap<String, Record>> = HashMap::default();

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
                        trace!(?data, "address info updated");
                        let data = data.apply_filter(&filter).into_owned();
                        // untested
                        match sync_registrations(&service_type, &endpoint_id, &data, &mut published) {
                            Some(updates) => {
                                for svc in updates.register {
                                    if let Err(e) = guard.0.register(svc.clone()) {
                                        warn!(?e, "register failed");
                                    } else {
                                        debug!(?svc, "registered");
                                    }
                                }
                                for fullname in updates.unregister {
                                    if let Err(e) = guard.0.unregister(&fullname) {
                                        warn!(?e, "unregister failed");
                                    } else {
                                        debug!(fullname, "unregistered");
                                    }
                                }
                            }
                            None => debug!("no update needed even tough address change.updated() was called"),
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
                        let Some(resolved_endpoint_id) =
                            parse_id(&service_type, &resolved_service.fullname)
                        else {
                            debug!("failed to parse EndpointId");
                            continue;
                        };
                        if resolved_endpoint_id == endpoint_id {
                            continue;
                        }
                        let Some(record) = Record::from_resolved(&resolved_service) else {
                            debug!("empty service entry");
                            continue;
                        };
                        let endpoint_records = discovered.entry(resolved_endpoint_id).or_default();
                        endpoint_records.insert(resolved_service.fullname, record);

                        update_item(
                            &resolved_endpoint_id,
                            endpoint_records,
                            &mut endpoint_addr_cache,
                            &resolve_senders,
                            &mut subscribers,
                        )
                        .await;
                    }
                    Message::Mdns(ServiceEvent::ServiceRemoved(_, fullname)) => {
                        trace!(fullname, "Mdns Message::Mdns(ServiceEvent::ServiceRemoved)");
                        let Some(modified_endpoint_id) = parse_id(&service_type, &fullname) else {
                            continue;
                        };
                        let Some(endpoint_records) = discovered.get_mut(&modified_endpoint_id)
                        else {
                            continue;
                        };
                        endpoint_records.remove(&fullname);

                        if endpoint_records.is_empty() {
                            discovered.remove(&modified_endpoint_id);
                            endpoint_addr_cache.remove(&modified_endpoint_id);
                            subscribers.send(DiscoveryEvent::Expired {
                                endpoint_id: modified_endpoint_id,
                            });
                        } else {
                            update_item(
                                &modified_endpoint_id,
                                endpoint_records,
                                &mut endpoint_addr_cache,
                                &resolve_senders,
                                &mut subscribers,
                            )
                            .await;
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
                            resolve_senders.get_mut(&resolved_endpoint_id)
                        {
                            senders_for_endpoint_id.insert(id, sender);
                        } else {
                            let mut senders_for_endpoint_id = HashMap::new();
                            senders_for_endpoint_id.insert(id, sender);
                            resolve_senders.insert(resolved_endpoint_id, senders_for_endpoint_id);
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
                            resolve_senders.get_mut(&timedout_endpoint_id)
                        {
                            senders_for_endpoint_id.remove(&id);
                            if senders_for_endpoint_id.is_empty() {
                                resolve_senders.remove(&timedout_endpoint_id);
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

impl Record {
    fn to_txt(&self) -> Vec<(String, String)> {
        let mut txt = Vec::new();
        if let Some(user_data) = self.user_data.as_ref() {
            txt.push((USER_DATA_KEY.to_string(), user_data.to_string()));
        };

        // Relay urls are encoded in kv as `r0` to `r99`; we don't pad the zeros to not transmit more bytes then we need
        // but we also don't allow relay urls to be longer then 252 bytes even tough it is technially possible
        // to have the first 10 entries (`r0=` to `r9=`) be 253 bytes long but this has no real advandate and could lead
        // to rejection of a relay url or not based on the order they appear in the [`EndpointData`]
        //
        // Note: i know `iroh` mostly holds a single active relay except when actively dialing a peer whos
        // home relay is different to the home relay of our node, and in local scenarios like mdns it is even
        // less likely but i don't really see a reason not to include all realys besides larger mdns records.
        // But this lib is intended as a replacement for `iroh-mdns-peer-lookup` and not for `iroh-mdns-address-lookup`
        // and since the trade off between them is faster connection speeds + meant for fast cli apps vs.
        // larger scaling + longer running clusters respectively i think including as many relays for best effort
        // dialing is more inline with the niche this lib is intending to fill/replace.
        // This could be wrong, i haven't looked at the underlying `iroh`/`noq` code but the downside is minimal so what ever ^^.
        txt.extend(
            self.relays
                .iter()
                .map(|url| url.as_str().to_string())
                .filter(|url| url.len() < 253)
                .enumerate()
                .map(|(i, relay)| (format!("r{i}"), relay.clone())),
        );
        txt
    }

    fn from_resolved(svc: &ResolvedService) -> Option<Self> {
        let addrs: BTreeSet<SocketAddr> = svc
            .addresses
            .iter()
            .map(|scoped_ip| SocketAddr::new(scoped_ip.to_ip_addr(), svc.get_port()))
            .collect();

        let relays: BTreeSet<RelayUrl> = svc
            .get_properties()
            .iter()
            .filter_map(|prop| {
                // as defined above we cap at 100 records ("r0" to "r99")
                // see comment in fn [`to_txt`] for reason
                if prop.key().starts_with("r") && prop.key().len() <= 3 {
                    prop.val_str().parse().ok()
                } else {
                    None
                }
            })
            .collect();

        let user_data: Option<UserData> =
            if let Some(user_data) = svc.get_property_val_str(USER_DATA_KEY) {
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

        if addrs.is_empty() && relays.is_empty() && user_data.is_none() {
            None
        } else {
            Some(Self {
                addrs,
                relays,
                user_data,
            })
        }
    }
}

/// Caches the latest discovery item for an endpoint.
///
/// Returns `true` if the endpoint is new or its advertised content changed.
/// Observation timestamps do not affect the comparison. The cached item is
/// always replaced so later lookups use the latest addresses.
fn cache_discovery(
    cache: &mut HashMap<EndpointId, AddressLookupItem>,
    item: AddressLookupItem,
) -> bool {
    let id = item.endpoint_id();
    let changed = cache
        .get(&id)
        .is_none_or(|old| old.endpoint_info() != item.endpoint_info());
    cache.insert(id, item);
    changed
}

/// Takes [`EndpointData`] and creates [`RegistrationUpdate`] which in turn is used to:
/// - re/register services with `mdns-sd` 
/// - unregister endpoints with no active paths left (records with only [`RelayUrl`] or even [`UserData`] count as active paths)
fn sync_registrations(
    service_type: &str,
    endpoint_id: &EndpointId,
    data: &EndpointData,
    published: &mut BTreeMap<u16, Record>,
) -> Option<RegistrationUpdate> {
    let mut desired_state: BTreeMap<u16, Record> = BTreeMap::new();
    let txt_only_record = Record {
        addrs: BTreeSet::new(),
        relays: data.relay_urls().cloned().collect::<BTreeSet<_>>(),
        user_data: data.user_data().cloned(),
    };
    for addr in data.ip_addrs() {
        desired_state
            .entry(addr.port())
            .or_insert(txt_only_record.clone())
            .addrs
            .insert(*addr);
    }

    // Probably possible to just gate on `no addresses` and `no relays` but this way if a user
    // provides their own custom non iroh native discovery information they can do whatever they do with it
    // and e.g. decrypt their custom `user_data` ip's and add them manually. Who knows :shrug:
    //
    // Note: if we don't have any [`TransportAddr::Ip(SocketAddr)`] but we do have [`TransportAddr::Relay(RelayUrl)`] addresses
    // we create a [`ServiceInfo`] with no A/AAAA records and only TXT for relay and optional user data and set the port to 0.
    // Since in this case we still have to supply a port to [`ServiceInfo::new`] we pass 0u16 as the port, this should be allowed according to:
    // [rfc6763 section 8](https://www.rfc-editor.org/rfc/rfc6763.html#section-8)
    // "[..] creates a placeholder SRV record (priority=0, weight=0, port=0, target host = host name of device) [..]".
    //
    // This is technically ment for announcing we are not supporting the service but i also found other protocols and implementations
    // using it to indicate service unavailability (see for example https://docs.oracle.com/cd/E88353_01/html/E72487/dns-sd-8.html).
    // Here it says "Registering a service on port 0 allows an application to explicitly advertise the non-availability of a service."
    // which is kind of correct since the service *is* not available at that instance in time. So i am using it here :shrug:
    if desired_state.is_empty()
        && (!txt_only_record.relays.is_empty() || txt_only_record.user_data.is_some())
    {
        desired_state.insert(0, txt_only_record.clone());
    }

    let mut register = Vec::new();
    let mut unregister = Vec::new();
    let txt = txt_only_record.to_txt();
    for (port, record) in &desired_state {
        if published.get(port) != Some(record) {
            let instance = instance_label(endpoint_id, *port);
            let host = format!("{instance}.local.");
            match ServiceInfo::new(
                service_type,
                &instance,
                &host,
                record
                    .addrs
                    .iter()
                    .map(|addr| addr.ip())
                    .collect::<Vec<_>>()
                    .as_slice(),
                *port,
                txt.as_slice(),
            ) {
                Ok(svc) => {
                    published.insert(*port, record.clone());
                    register.push(svc);
                }
                Err(e) => warn!(?e, "bad service info"),
            }
        }
    }

    published.retain(|port, _| {
        if desired_state.contains_key(port) {
            return true;
        }
        let fullname = format!("{}.{service_type}", instance_label(endpoint_id, *port));
        unregister.push(fullname);
        false
    });

    if unregister.is_empty() && register.is_empty() {
        None
    } else {
        Some(RegistrationUpdate {
            register,
            unregister,
        })
    }
}

/// Handles any changes to `records` and shares [`AddressLookupItem`] with `AddressLookup` and `Subscribe`rs.
///
/// Returns `true` if item was updated and `false` if nothing changed and no update was necessary.
async fn update_item(
    updated_endpoint_id: &EndpointId,
    records: &BTreeMap<String, Record>,
    endpoint_addr_cache: &mut HashMap<PublicKey, AddressLookupItem>,
    senders: &HashMap<EndpointId, ResolveSender>,
    subscribers: &mut Subscribers,
) -> bool {
    let mut addrs = BTreeSet::new();
    let mut relays = BTreeSet::new();
    let mut user_data = None;

    for record in records.values() {
        addrs.extend(record.addrs.iter().copied());
        relays.extend(record.relays.iter().cloned());
        if user_data.is_none() {
            user_data = record.user_data.clone();
        }
    }

    let mut data = EndpointData::from(addrs);
    for relay in relays {
        data.add_relay_url(relay);
    }
    data.set_user_data(user_data);

    let endpoint_info = EndpointInfo::from_parts(*updated_endpoint_id, data);
    let item = AddressLookupItem::new(endpoint_info, NAME, None);

    if !cache_discovery(endpoint_addr_cache, item.clone()) {
        debug!(?updated_endpoint_id, "updated but unchanged");
        return false;
    }

    debug!(
        ?updated_endpoint_id,
        ?item,
        "updating endpoint address book"
    );

    if let Some(senders) = senders.get(updated_endpoint_id) {
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

    true
}

/// Address format is "<z32 EndpointId>-<port 0-65536>._irohsd._udp.local."
fn instance_label(id: &EndpointId, port: u16) -> String {
    format!(
        "{}-{port}",
        data_encoding::BASE32_NOPAD
            .encode(id.as_bytes())
            .to_ascii_lowercase()
    )
}

/// Parses out [`EndpointId`] from record `fullname`
fn parse_id(service_type: &str, fullname: &str) -> Option<PublicKey> {
    let inst = fullname.strip_suffix(service_type)?.strip_suffix('.')?;
    let (id, port) = inst.rsplit_once('-')?;
    port.parse::<u16>().ok()?;
    PublicKey::from_str(id).ok()
}

/// These are all the original `iroh-mdns-address-lookup` tests with only minimal changes:
/// - tests in `run_in_isolation` have been assigned a service_name per test since we fail the uniquenes checks with during mdns `probe`
/// - added `service_name` rfc complient assertion tests since `mdns-sd` enforces default mdns rfc rules
/// - replaced `0.0.0.0:PORT` test addresses with `127.0.0.1:PORT` since `mdns-sd` enforces default mdns rfc rules
/// 
/// Otherwise these tests are identical
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refreshes_are_quiet_and_changed_addresses_replace_the_cache() {
        let id = iroh_base::SecretKey::from_bytes(&[7; 32]).public();
        let make = |port| {
            let data = EndpointData::from_iter([iroh_base::TransportAddr::Ip(
                ([192, 168, 1, 8], port).into(),
            )]);
            AddressLookupItem::new(EndpointInfo::from_parts(id, data), NAME, None)
        };
        let mut cache = HashMap::new();
        assert!(cache_discovery(&mut cache, make(1234)));
        assert!(!cache_discovery(&mut cache, make(1234)));
        assert!(cache_discovery(&mut cache, make(5678)));
        assert_eq!(cache[&id].endpoint_info(), make(5678).endpoint_info());
        assert!(!cache_discovery(&mut cache, make(5678)));
        // Expiry forgets the record, so the same peer is announced on return.
        cache.remove(&id);
        assert!(cache_discovery(&mut cache, make(5678)));
    }

    #[test]
    fn relay_and_user_data_changes_are_not_suppressed() {
        let id = iroh_base::SecretKey::from_bytes(&[7; 32]).public();
        let mut cache = HashMap::new();
        let mut data = EndpointData::default();
        for relay in ["https://one.example", "https://two.example"] {
            data.add_relay_url(relay.parse().unwrap());
            assert!(cache_discovery(
                &mut cache,
                AddressLookupItem::new(EndpointInfo::from_parts(id, data.clone()), NAME, None,)
            ));
        }
        data.set_user_data(Some("new metadata".parse().unwrap()));
        assert!(cache_discovery(
            &mut cache,
            AddressLookupItem::new(EndpointInfo::from_parts(id, data), NAME, None,)
        ));
    }

    mod service_name_rfc_rule_enforcement {
        use std::panic;

        use crate::MdnsAddressLookup;

        // ugly hack to prevent assertion panic from printing during test time
        struct PanicHookGuard {
            #[allow(clippy::type_complexity)]
            _prev_hook: Option<Box<dyn Fn(&panic::PanicHookInfo<'_>) + Send + Sync + 'static>>,
        }

        impl PanicHookGuard {
            fn silence() -> Self {
                let prev_hook = panic::take_hook();
                panic::set_hook(Box::new(|_| { /* Silence! Do nothing here */ }));
                Self {
                    _prev_hook: Some(prev_hook),
                }
            }
        }

        #[test]
        #[should_panic]
        fn service_name_smaller_15() {
            let _guard = PanicHookGuard::silence();
            MdnsAddressLookup::builder().service_name("0123456789abcdef");
        }

        #[test]
        #[should_panic]
        fn service_name_not_empty() {
            let _guard = PanicHookGuard::silence();
            MdnsAddressLookup::builder().service_name("");
        }

        #[test]
        #[should_panic]
        fn service_name_only_ascii() {
            let _guard = PanicHookGuard::silence();
            MdnsAddressLookup::builder().service_name(" ");
        }

        #[test]
        #[should_panic]
        fn service_name_no_hyphen_at_start() {
            let _guard = PanicHookGuard::silence();
            MdnsAddressLookup::builder().service_name("-test");
        }

        #[test]
        #[should_panic]
        fn service_name_no_hyphen_at_end() {
            let _guard = PanicHookGuard::silence();
            MdnsAddressLookup::builder().service_name("test-");
        }

        #[test]
        #[should_panic]
        fn service_name_no_double_hyphen() {
            let _guard = PanicHookGuard::silence();
            MdnsAddressLookup::builder().service_name("test--test");
        }
    }

    /// This module's name signals nextest to run test in a single thread (no other concurrent
    /// tests).
    mod run_in_isolation {
        use iroh::endpoint_info::UserData;
        use iroh_base::{SecretKey, TransportAddr};
        use n0_error::{AnyError as Error, Result, StdResultExt, bail_any};
        use n0_future::StreamExt;
        use n0_tracing_test::traced_test;
        use rand::{CryptoRng, RngExt, SeedableRng};

        use super::super::*;

        #[tokio::test]
        #[traced_test]
        async fn mdns_publish_resolve() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            // Create Address LookupA with advertise=false (only listens)
            let (_, address_lookup_a) = make_address_lookup(&mut rng, false, "irohtest-res")?;
            // Create Address LookupB with advertise=true (will broadcast)
            let (endpoint_id_b, address_lookup_b) =
                make_address_lookup(&mut rng, true, "irohtest-res")?;

            // make addr info for discoverer b
            let user_data: UserData = "foobar".parse()?;
            let endpoint_data =
                EndpointData::from_iter([TransportAddr::Ip("127.0.0.1:11111".parse().unwrap())])
                    .with_user_data(user_data.clone());

            // resolve twice to ensure we can create separate streams for the same endpoint_id
            let mut s1 = address_lookup_a
                .subscribe()
                .await
                .filter(|event| match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. } => {
                        endpoint_info.endpoint_id == endpoint_id_b
                    }
                    _ => false,
                });
            let mut s2 = address_lookup_a
                .subscribe()
                .await
                .filter(|event| match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. } => {
                        endpoint_info.endpoint_id == endpoint_id_b
                    }
                    _ => false,
                });

            tracing::debug!(?endpoint_id_b, "Discovering endpoint id b");
            // publish address_lookup_b's address
            address_lookup_b.publish(&endpoint_data);
            let DiscoveryEvent::Discovered {
                endpoint_info: s1_endpoint_info,
                ..
            } = tokio::time::timeout(Duration::from_secs(5), s1.next())
                .await
                .std_context("timeout")?
                .unwrap()
            else {
                panic!("Received unexpected discovery event");
            };
            let DiscoveryEvent::Discovered {
                endpoint_info: s2_endpoint_info,
                ..
            } = tokio::time::timeout(Duration::from_secs(5), s2.next())
                .await
                .std_context("timeout")?
                .unwrap()
            else {
                panic!("Received unexpected discovery event");
            };
            assert_eq!(s1_endpoint_info.data, endpoint_data);
            assert_eq!(s2_endpoint_info.data, endpoint_data);

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn mdns_publish_expire() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
            let (_, address_lookup_a) = make_address_lookup(&mut rng, false, "irohtest-exp")?;
            let (endpoint_id_b, address_lookup_b) =
                make_address_lookup(&mut rng, true, "irohtest-exp")?;

            // publish address_lookup_b's address
            let endpoint_data =
                EndpointData::from_iter([TransportAddr::Ip("127.0.0.1:11111".parse().unwrap())])
                    .with_user_data("".parse()?);
            address_lookup_b.publish(&endpoint_data);

            let mut s1 = address_lookup_a.subscribe().await;
            tracing::debug!(?endpoint_id_b, "Discovering endpoint id b");

            // Wait for the specific endpoint to be discovered
            loop {
                let event = tokio::time::timeout(Duration::from_secs(5), s1.next())
                    .await
                    .std_context("timeout")?
                    .expect("Stream should not be closed");

                match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. }
                        if endpoint_info.endpoint_id == endpoint_id_b =>
                    {
                        break;
                    }
                    _ => continue, // Ignore other discovery events
                }
            }

            // Shutdown endpoint B
            drop(address_lookup_b);
            tokio::time::sleep(Duration::from_secs(5)).await;

            // Wait for the expiration event for the specific endpoint
            loop {
                let event = tokio::time::timeout(Duration::from_secs(10), s1.next())
                    .await
                    .std_context("timeout waiting for expiration event")?
                    .expect("Stream should not be closed");

                match event {
                    DiscoveryEvent::Expired {
                        endpoint_id: expired_endpoint_id,
                    } if expired_endpoint_id == endpoint_id_b => {
                        break;
                    }
                    _ => continue, // Ignore other events
                }
            }

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn mdns_subscribe() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            let num_endpoints = 5;
            let mut endpoint_ids = BTreeSet::new();
            let mut address_lookup_list = vec![];

            let (_, address_lookup) = make_address_lookup(&mut rng, false, "irohtest-sub")?;
            let endpoint_data =
                EndpointData::from_iter([TransportAddr::Ip("127.0.0.1:11111".parse().unwrap())]);

            for i in 0..num_endpoints {
                let (endpoint_id, address_lookup) =
                    make_address_lookup(&mut rng, true, "irohtest-sub")?;
                let user_data: UserData = format!("endpoint{i}").parse()?;
                let endpoint_data = endpoint_data.clone().with_user_data(user_data.clone());
                endpoint_ids.insert((endpoint_id, Some(user_data)));
                address_lookup.publish(&endpoint_data);
                address_lookup_list.push(address_lookup);
            }

            let mut events = address_lookup.subscribe().await;

            let test = async move {
                let mut got_ids = BTreeSet::new();
                while got_ids.len() != num_endpoints {
                    if let Some(DiscoveryEvent::Discovered { endpoint_info, .. }) =
                        events.next().await
                    {
                        let data = endpoint_info.data.user_data().cloned();
                        if endpoint_ids.contains(&(endpoint_info.endpoint_id, data.clone())) {
                            got_ids.insert((endpoint_info.endpoint_id, data));
                        }
                    } else {
                        bail_any!(
                            "no more events, only got {} ids, expected {num_endpoints}\n",
                            got_ids.len()
                        );
                    }
                }
                assert_eq!(got_ids, endpoint_ids);
                Ok::<_, Error>(())
            };
            tokio::time::timeout(Duration::from_secs(5), test)
                .await
                .std_context("timeout")?
        }

        #[tokio::test]
        #[traced_test]
        async fn non_advertising_endpoint_not_discovered() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            let (_, address_lookup_a) = make_address_lookup(&mut rng, false, "irohtest-nodisc")?;
            let (endpoint_id_b, address_lookup_b) =
                make_address_lookup(&mut rng, false, "irohtest-nodisc")?;

            let (endpoint_id_c, address_lookup_c) =
                make_address_lookup(&mut rng, true, "irohtest-nodisc")?;
            let endpoint_data_c =
                EndpointData::from_iter([TransportAddr::Ip("127.0.0.1:11111".parse().unwrap())]);
            address_lookup_c.publish(&endpoint_data_c);

            let endpoint_data_b =
                EndpointData::from_iter([TransportAddr::Ip("127.0.0.1:22222".parse().unwrap())]);
            address_lookup_b.publish(&endpoint_data_b);

            let mut stream_c = address_lookup_a.resolve(endpoint_id_c).unwrap();
            let result_c = tokio::time::timeout(Duration::from_secs(2), stream_c.next()).await;
            assert!(
                result_c.is_ok(),
                "Advertising endpoint should be discoverable"
            );

            let mut stream_b = address_lookup_a.resolve(endpoint_id_b).unwrap();
            let result_b = tokio::time::timeout(Duration::from_secs(2), stream_b.next()).await;
            assert!(
                result_b.is_err(),
                "Expected timeout since endpoint b isn't advertising"
            );

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn test_service_names() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            // Create an Address Lookupusing the default
            // service name
            let id_a = SecretKey::from_bytes(&rng.random()).public();
            let address_lookup_a = MdnsAddressLookup::builder().build(id_a)?;

            // Create a Address Lookupusing a custom
            // service name
            let id_b = SecretKey::from_bytes(&rng.random()).public();
            let address_lookup_b = MdnsAddressLookup::builder()
                .service_name("different-name")
                .build(id_b)?;

            // Create an Address Lookupusing the same
            // custom service name
            let id_c = SecretKey::from_bytes(&rng.random()).public();
            let address_lookup_c = MdnsAddressLookup::builder()
                .service_name("different-name")
                .build(id_c)?;

            let endpoint_data_a =
                EndpointData::from_iter([TransportAddr::Ip("127.0.0.1:11111".parse().unwrap())]);
            println!("Publishing endpoint data for a: {:?}", endpoint_data_a);
            address_lookup_a.publish(&endpoint_data_a);

            let endpoint_data_b =
                EndpointData::from_iter([TransportAddr::Ip("127.0.0.1:22222".parse().unwrap())]);
            address_lookup_b.publish(&endpoint_data_b);

            let endpoint_data_c =
                EndpointData::from_iter([TransportAddr::Ip("127.0.0.1:33333".parse().unwrap())]);
            address_lookup_c.publish(&endpoint_data_c);

            let mut stream_a = address_lookup_a.resolve(id_b).unwrap();
            let result_a = tokio::time::timeout(Duration::from_secs(2), stream_a.next()).await;
            assert!(
                result_a.is_err(),
                "Endpoint on a different service should NOT be discoverable"
            );

            let mut stream_b = address_lookup_b.resolve(id_c).unwrap();
            let result_b = tokio::time::timeout(Duration::from_secs(2), stream_b.next()).await;
            assert!(
                result_b.is_ok(),
                "Endpoint on the same service should be discoverable"
            );

            let mut stream_b = address_lookup_b.resolve(id_a).unwrap();
            let result_b = tokio::time::timeout(Duration::from_secs(2), stream_b.next()).await;
            assert!(
                result_b.is_err(),
                "Endpoint on a different service should NOT be discoverable"
            );

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn mdns_publish_relay_url() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            // Create an mdns address lookup A that only listens
            let (_, mdns_a) = make_address_lookup(&mut rng, false, "irohtest-relay")?;

            // Create an mdns address lookup B that includes a relay url for publishing
            let (endpoint_id_b, mdns_b) = make_address_lookup(&mut rng, true, "irohtest-relay")?;
            let relay_url: iroh_base::RelayUrl = "https://relay.example.com".parse().unwrap();
            let endpoint_data = EndpointData::from_iter([
                TransportAddr::Ip("127.0.0.1:11111".parse().unwrap()),
                TransportAddr::Relay(relay_url.clone()),
            ]);

            // Subscribe to discovery events filtered for endpoint B
            let mut events = mdns_a.subscribe().await.filter(|event| match event {
                DiscoveryEvent::Discovered { endpoint_info, .. } => {
                    endpoint_info.endpoint_id == endpoint_id_b
                }
                _ => false,
            });

            // Publish mdns_b's address with relay URL
            mdns_b.publish(&endpoint_data);

            // Wait for discovery
            let DiscoveryEvent::Discovered { endpoint_info, .. } =
                tokio::time::timeout(Duration::from_secs(10), events.next())
                    .await
                    .std_context("timeout")?
                    .unwrap()
            else {
                panic!("Received unexpected discovery event");
            };

            // Verify the relay URL was received
            let discovered_relay_urls: Vec<_> = endpoint_info.data.relay_urls().collect();
            assert_eq!(discovered_relay_urls.len(), 1);
            assert_eq!(discovered_relay_urls[0], &relay_url);

            Ok(())
        }

        fn make_address_lookup<R: CryptoRng + ?Sized>(
            rng: &mut R,
            advertise: bool,
            service_name: &str,
        ) -> Result<(PublicKey, MdnsAddressLookup)> {
            let endpoint_id = SecretKey::from_bytes(&rng.random()).public();
            Ok((
                endpoint_id,
                MdnsAddressLookup::builder()
                    .advertise(advertise)
                    .service_name(service_name)
                    .build(endpoint_id)?,
            ))
        }
    }
}
