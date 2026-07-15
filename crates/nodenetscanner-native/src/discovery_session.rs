use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::io::IoSliceMut;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use napi_derive::napi;
use nix::libc;
use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, setsockopt};
use nodenet_linux_context::{NetworkSnapshot, RouteContext, RouteQuery};
use nodenet_protocols::{
    DISCOVERY_OPERATION_REGISTRY, DISCOVERY_OPERATION_REGISTRY_VERSION, DiscoveryDnsRecordData,
    DiscoveryOperationId, TftpDiscoveryResponse, UdpCatalogueProbe, UdpProbeBuildContext,
    build_discovery_dns_query, build_llmnr_query, build_mdns_service_enumeration_query,
    build_nat_pmp_external_address_request, build_quic_version_negotiation_request,
    build_rpcbind_getaddr_request, build_sql_browser_enumeration_request, build_tftp_discovery_rrq,
    build_tftp_termination_error, build_udp_catalogue_request, build_ws_discovery_probe,
    discovery_operation_registry_sha256_hex, parse_discovery_dns_message, parse_llmnr_response,
    parse_nat_pmp_external_address_response, parse_quic_version_negotiation_response,
    parse_rpcbind_getaddr_response, parse_rpcbind_universal_address, parse_sql_browser_response,
    parse_tftp_discovery_response, parse_udp_catalogue_response, parse_ws_discovery_probe_matches,
};
use nodenetscanner_engine::{DiscoveryBudget, DiscoveryQueryLease, TargetEndpoint};

use crate::error::ScannerError;
use crate::model::{
    ValidatedDiscoveryOperation, ValidatedDiscoveryPlan, ValidatedDiscoveryScope,
    to_protocol_address,
};

const MAX_NATIVE_DISCOVERY_QUERIES: usize = 1_024;
const MAX_NATIVE_DISCOVERY_SOCKETS: usize = 256;
const MAX_MDNS_QUERIES_PER_SCOPE_MEMBER: usize = 256;
const MAX_RECEIVED_DATAGRAMS: usize = 65_536;
const MAX_RECEIVED_BYTES: usize = 64 * 1_024 * 1_024;
const MAX_METADATA_FIELDS_PER_ROW: usize = 128;
const MAX_METADATA_BYTES_PER_ROW: usize = 16 * 1_024;

const RUNNING: u8 = 1;
const PAUSED: u8 = 3;
const CANCELLING: u8 = 4;
const COMPLETED: u8 = 5;

pub(crate) struct DiscoveryControl {
    state: AtomicU8,
    progress: Mutex<Counters>,
}

impl DiscoveryControl {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            state: AtomicU8::new(RUNNING),
            progress: Mutex::new(Counters::default()),
        }
    }

    pub(crate) fn pause(&self) -> Result<(), ScannerError> {
        self.state
            .compare_exchange(RUNNING, PAUSED, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| ScannerError::lifecycle("pause discovery", "session is not running"))
    }

    pub(crate) fn resume(&self) -> Result<(), ScannerError> {
        self.state
            .compare_exchange(PAUSED, RUNNING, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| ScannerError::lifecycle("resume discovery", "session is not paused"))
    }

    pub(crate) fn cancel(&self) {
        let state = self.state.load(Ordering::Acquire);
        if state != COMPLETED {
            self.state.store(CANCELLING, Ordering::Release);
        }
    }

    #[must_use]
    pub(crate) fn state_name(&self) -> &'static str {
        match self.state.load(Ordering::Acquire) {
            RUNNING => "running",
            PAUSED => "paused",
            CANCELLING => "cancelling",
            COMPLETED => "completed",
            _ => "failed",
        }
    }

    fn cancelling(&self) -> bool {
        self.state.load(Ordering::Acquire) == CANCELLING
    }

    fn complete(&self) {
        self.state.store(COMPLETED, Ordering::Release);
    }

    fn publish(&self, counters: &Counters) {
        *self
            .progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = counters.clone();
    }

    #[must_use]
    pub(crate) fn progress(&self) -> NativeDiscoveryProgress {
        self.progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .into()
    }
}

#[napi(object)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDiscoveryMetadataField {
    pub key: String,
    pub value: Vec<u8>,
    pub text: Option<String>,
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct NativeDiscoveryRow {
    pub entity_id: String,
    pub parent_entity_id: Option<String>,
    pub derivation_kind: Option<String>,
    pub operation_id: u32,
    pub protocol: String,
    pub kind: String,
    pub evidence: String,
    pub outcome: String,
    pub responder: String,
    pub responder_port: u32,
    pub interface_index: Option<u32>,
    pub identity: Vec<u8>,
    pub addresses: Vec<String>,
    pub metadata: Vec<NativeDiscoveryMetadataField>,
    pub truncated: bool,
}

#[napi(object)]
#[derive(Clone, Debug, Default)]
pub struct NativeDiscoveryProgress {
    pub queries: String,
    pub sent: String,
    pub received: String,
    pub received_bytes: String,
    pub accepted: String,
    pub duplicate: String,
    pub rejected: String,
    pub truncated: String,
    pub cleanup_sent: String,
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct NativeDiscoveryRun {
    pub schema_version: u32,
    pub registry_version: String,
    pub registry_sha256: String,
    pub state: String,
    pub allow_risks: Vec<String>,
    pub receive_modes: Vec<String>,
    pub rows: Vec<NativeDiscoveryRow>,
    pub progress: NativeDiscoveryProgress,
}

struct Query {
    operation: ValidatedDiscoveryOperation,
    interface_index: Option<u32>,
    expected_target: Option<IpAddr>,
    destination: SocketAddr,
    socket: UdpSocket,
    context: QueryContext,
    pending_outbound: Option<OutboundDatagram>,
    response_deadline: Option<Instant>,
    retained_entities: usize,
    retained_metadata_bytes: usize,
    lease: Option<DiscoveryQueryLease>,
    settled: bool,
}

struct ReceivedDatagram {
    length: usize,
    source: SocketAddr,
    interface_index: Option<u32>,
    hop_limit: Option<u32>,
}

enum QueryContext {
    Mdns(MdnsContext),
    WsDiscovery {
        message_id: String,
    },
    Llmnr {
        transaction_id: u16,
        query_name: String,
        query_type: u16,
    },
    NatPmp,
    SqlBrowser,
    Rpcbind {
        transaction_id: u32,
        token: [u8; 16],
        state: RpcbindState,
    },
    Tftp {
        entropy: [u8; 16],
        pinned_port: Option<u16>,
    },
    Quic(nodenet_protocols::QuicVersionNegotiationRequest),
}

struct MdnsContext {
    initial_transaction_id: u16,
    next_transaction_id: u16,
    outstanding: BTreeMap<u16, (Vec<u8>, u16)>,
    scheduled: BTreeSet<(Vec<u8>, u16)>,
    queued: VecDeque<OutboundDatagram>,
    services: BTreeMap<Vec<u8>, MdnsService>,
}

#[derive(Default)]
struct MdnsService {
    service_type: Option<String>,
    instance: Option<String>,
    target_wire: Option<Vec<u8>>,
    target: Option<String>,
    port: Option<u16>,
    addresses: BTreeSet<String>,
    txt: Vec<NativeDiscoveryMetadataField>,
    ttls: BTreeSet<u32>,
    partial_wire_response: bool,
}

impl MdnsContext {
    fn new(transaction_id: u16) -> Self {
        let enumeration = b"\x09_services\x07_dns-sd\x04_udp\x05local\0".to_vec();
        let mut outstanding = BTreeMap::new();
        outstanding.insert(transaction_id, (enumeration.clone(), 12));
        let mut scheduled = BTreeSet::new();
        scheduled.insert((enumeration, 12));
        Self {
            initial_transaction_id: transaction_id,
            next_transaction_id: transaction_id.wrapping_add(1).max(1),
            outstanding,
            scheduled,
            queued: VecDeque::new(),
            services: BTreeMap::new(),
        }
    }

    fn schedule(
        &mut self,
        name_wire: &[u8],
        name_text: Option<&str>,
        query_type: u16,
        destination: SocketAddr,
    ) {
        let Some(name_text) = name_text else {
            return;
        };
        let key = (name_wire.to_vec(), query_type);
        if self.scheduled.len() >= MAX_MDNS_QUERIES_PER_SCOPE_MEMBER
            || !self.scheduled.insert(key.clone())
        {
            return;
        }
        let mut transaction_id = self.next_transaction_id;
        while transaction_id == 0 || self.outstanding.contains_key(&transaction_id) {
            transaction_id = transaction_id.wrapping_add(1);
        }
        self.next_transaction_id = transaction_id.wrapping_add(1).max(1);
        let Ok(bytes) = build_discovery_dns_query(transaction_id, name_text, query_type, true)
        else {
            return;
        };
        self.outstanding.insert(transaction_id, key);
        self.queued.push_back(OutboundDatagram {
            bytes,
            destination,
            kind: OutboundKind::AdaptiveQuery,
        });
    }
}

enum RpcbindState {
    AwaitingGetAddress,
    AwaitingNfs {
        request: Vec<u8>,
        parent_identity: Vec<u8>,
        port: u16,
    },
}

#[derive(Clone, Default)]
struct Counters {
    queries: u64,
    sent: u64,
    received: u64,
    received_bytes: u64,
    accepted: u64,
    duplicate: u64,
    rejected: u64,
    truncated: u64,
    cleanup_sent: u64,
}

struct DiscoveryPacer {
    packets_per_second: u32,
    capacity: u128,
    tokens: u128,
    updated: Instant,
}

impl DiscoveryPacer {
    const UNITS_PER_PACKET: u128 = 1_000_000_000;

    fn new(packets_per_second: u32, burst: u32) -> Self {
        let capacity = u128::from(burst) * Self::UNITS_PER_PACKET;
        Self {
            packets_per_second,
            capacity,
            tokens: capacity,
            updated: Instant::now(),
        }
    }

    fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.updated).as_nanos();
        let replenished = elapsed.saturating_mul(u128::from(self.packets_per_second));
        self.tokens = self.tokens.saturating_add(replenished).min(self.capacity);
        self.updated = now;
        if self.tokens < Self::UNITS_PER_PACKET {
            return false;
        }
        self.tokens -= Self::UNITS_PER_PACKET;
        true
    }
}

#[derive(Clone, Copy)]
enum OutboundKind {
    InitialQuery,
    AdaptiveQuery,
    Cleanup,
}

struct OutboundDatagram {
    bytes: Vec<u8>,
    destination: SocketAddr,
    kind: OutboundKind,
}

type ParsedRows = (Vec<NativeDiscoveryRow>, Option<OutboundDatagram>);

#[allow(
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    reason = "the async task transfers one finite plan into a single visible ownership transaction"
)]
pub(crate) fn run_discovery(
    plan: ValidatedDiscoveryPlan,
    control: &DiscoveryControl,
) -> Result<NativeDiscoveryRun, ScannerError> {
    let started = Instant::now();
    let deadline = started.checked_add(plan.deadline).ok_or_else(|| {
        ScannerError::resource("start discovery", "discovery deadline overflowed")
    })?;
    let mut context = RouteContext::new()
        .map_err(|error| ScannerError::context("start discovery", error.to_string()))?;
    let kernel_default_ipv4_gateway = match &plan.scope {
        ValidatedDiscoveryScope::Targets {
            kernel_default_ipv4_gateway: true,
            ..
        } => {
            let route = context
                .resolve_route(
                    &RouteQuery::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                    None,
                )
                .map_err(|error| {
                    ScannerError::context("resolve default IPv4 gateway", error.to_string())
                })?;
            let gateway = route.gateway.filter(IpAddr::is_ipv4).ok_or_else(|| {
                ScannerError::context(
                    "resolve default IPv4 gateway",
                    "the kernel-selected IPv4 route has no IPv4 gateway",
                )
            })?;
            Some((gateway, route.interface_index))
        }
        _ => None,
    };
    let snapshot = context
        .snapshot()
        .map_err(|error| ScannerError::context("snapshot discovery context", error.to_string()))?;
    let products = products(&plan, &snapshot, kernel_default_ipv4_gateway)?;
    if products.len() > MAX_NATIVE_DISCOVERY_SOCKETS {
        return Err(ScannerError::resource(
            "start discovery",
            "one discovery session may own at most 256 UDP sockets",
        ));
    }
    let possible_derived = products
        .iter()
        .filter(|(operation, ..)| operation.id.get() == 7 && operation.follow_up)
        .count();
    let possible_mdns_adaptive = products
        .iter()
        .filter(|(operation, ..)| operation.id.get() == 1)
        .count()
        .checked_mul(MAX_MDNS_QUERIES_PER_SCOPE_MEMBER - 1)
        .ok_or_else(|| {
            ScannerError::resource("start discovery", "adaptive query count overflow")
        })?;
    let possible_queries = products
        .len()
        .checked_add(possible_derived)
        .and_then(|value| value.checked_add(possible_mdns_adaptive))
        .ok_or_else(|| {
            ScannerError::resource("start discovery", "physical query count overflow")
        })?;
    if possible_queries > MAX_NATIVE_DISCOVERY_QUERIES {
        return Err(ScannerError::resource(
            "start discovery",
            "one native discovery session may contain at most 1024 physical queries",
        ));
    }
    let mut entropy = Entropy::new()?;
    let mut queries = Vec::with_capacity(products.len());
    let mut counters = Counters {
        queries: u64::try_from(products.len()).unwrap_or(u64::MAX),
        ..Counters::default()
    };
    control.publish(&counters);
    // Descriptor admission and all request construction complete before the
    // first irreversible send.
    for (operation, destination, source, interface_index, expected_target) in products {
        queries.push(prepare_query(
            operation,
            destination,
            source,
            interface_index,
            expected_target,
            &mut entropy,
        )?);
    }
    for query in &mut queries {
        let (bytes, destination) = request_bytes_and_destination(query)?;
        query.pending_outbound = Some(OutboundDatagram {
            bytes,
            destination,
            kind: OutboundKind::InitialQuery,
        });
    }

    let mut rows = Vec::new();
    let mut retained_metadata_bytes = 0_usize;
    let mut budget = DiscoveryBudget::new(plan.limits);
    let mut identities = std::collections::BTreeMap::new();
    let mut buffer = vec![0_u8; 65_535];
    let mut pacer = DiscoveryPacer::new(plan.packets_per_second, plan.burst);
    while Instant::now() < deadline
        && queries.iter().any(|query| {
            query
                .response_deadline
                .is_some_and(|value| Instant::now() < value)
                || query.pending_outbound.is_some()
        })
        && !control.cancelling()
    {
        let mut progressed = false;
        for query in &mut queries {
            if query
                .response_deadline
                .is_some_and(|value| Instant::now() >= value)
                && query.pending_outbound.is_none()
                && !query.settled
            {
                if let Some(mut lease) = query.lease.take() {
                    budget
                        .settle(
                            &mut lease,
                            query.retained_entities,
                            query.retained_metadata_bytes,
                        )
                        .map_err(|error| {
                            ScannerError::internal(
                                "settle discovery query lease",
                                format!("{error:?}"),
                            )
                        })?;
                }
                query.settled = true;
                query.response_deadline = None;
            }
            if query.pending_outbound.as_ref().is_some_and(|outbound| {
                matches!(outbound.kind, OutboundKind::AdaptiveQuery)
                    && counters.queries >= MAX_NATIVE_DISCOVERY_QUERIES as u64
            }) {
                query.pending_outbound = None;
                counters.truncated += 1;
            }
            let send_allowed = query.pending_outbound.as_ref().is_some_and(|outbound| {
                matches!(outbound.kind, OutboundKind::Cleanup)
                    || control.state.load(Ordering::Acquire) == RUNNING
            });
            if send_allowed && query.lease.is_none() && !query.settled {
                let operation = descriptor(query.operation.id)?;
                if let Ok(lease) = budget.try_lease(
                    usize::from(operation.maximum_entities_per_query),
                    usize::try_from(operation.maximum_metadata_bytes_per_query)
                        .unwrap_or(usize::MAX),
                ) {
                    query.lease = Some(lease);
                }
            }
            if send_allowed
                && query.lease.is_some()
                && pacer.try_take(Instant::now())
                && let Some(outbound) = query.pending_outbound.take()
            {
                progressed = true;
                if query
                    .socket
                    .send_to(&outbound.bytes, outbound.destination)
                    .is_ok()
                {
                    counters.sent += 1;
                    if matches!(outbound.kind, OutboundKind::Cleanup) {
                        counters.cleanup_sent += 1;
                        query.response_deadline = None;
                    } else {
                        if matches!(outbound.kind, OutboundKind::AdaptiveQuery) {
                            counters.queries = counters.queries.saturating_add(1);
                        }
                        let window = Duration::from_millis(u64::from(
                            descriptor(query.operation.id)?.response_window_ms,
                        ));
                        query.response_deadline = Some(
                            Instant::now()
                                .checked_add(window)
                                .map_or(deadline, |value| value.min(deadline)),
                        );
                    }
                } else {
                    counters.rejected += 1;
                    query.response_deadline = None;
                }
            }
            if query
                .response_deadline
                .is_none_or(|value| Instant::now() >= value)
            {
                continue;
            }
            for _ in 0..8 {
                match receive_datagram(&query.socket, &mut buffer) {
                    Ok(Some(received)) => {
                        let length = received.length;
                        let source = received.source;
                        progressed = true;
                        counters.received += 1;
                        counters.received_bytes = counters
                            .received_bytes
                            .saturating_add(u64::try_from(length).unwrap_or(u64::MAX));
                        if counters.received > MAX_RECEIVED_DATAGRAMS as u64
                            || counters.received_bytes > MAX_RECEIVED_BYTES as u64
                        {
                            counters.truncated += 1;
                            break;
                        }
                        if query
                            .expected_target
                            .is_some_and(|target| target != source.ip())
                        {
                            counters.rejected += 1;
                            continue;
                        }
                        if query.interface_index.is_some()
                            && received.interface_index != query.interface_index
                        {
                            counters.rejected += 1;
                            continue;
                        }
                        let descriptor = descriptor(query.operation.id).map_err(|_| {
                            ScannerError::internal(
                                "receive discovery response",
                                "operation descriptor disappeared",
                            )
                        })?;
                        if length > descriptor.maximum_response_bytes
                            || !source_port_matches(query, source.port())
                        {
                            counters.rejected += 1;
                            continue;
                        }
                        let parsed = parse_rows(
                            query,
                            source,
                            received.interface_index,
                            received.hop_limit,
                            &buffer[..length],
                        );
                        match parsed {
                            Ok((mut parsed_rows, cleanup)) => {
                                if let Some(outbound) = cleanup
                                    && Instant::now() < deadline
                                    && query.pending_outbound.is_none()
                                {
                                    query.pending_outbound = Some(outbound);
                                }
                                for mut row in parsed_rows.drain(..) {
                                    if rows.len() >= plan.limits.max_results {
                                        counters.truncated += 1;
                                        continue;
                                    }
                                    let key = (
                                        row.operation_id,
                                        row.interface_index,
                                        row.responder.clone(),
                                        row.responder_port,
                                        row.identity.clone(),
                                    );
                                    let is_new_entity = !identities.contains_key(&key);
                                    if is_new_entity
                                        && query.retained_entities
                                            >= usize::from(descriptor.maximum_entities_per_query)
                                    {
                                        counters.truncated += 1;
                                        continue;
                                    }
                                    if let Some(index) = identities.get(&key).copied() {
                                        counters.duplicate += 1;
                                        let existing: &mut NativeDiscoveryRow = &mut rows[index];
                                        let before = discovery_row_metadata_bytes(existing);
                                        let mut merged = existing.clone();
                                        for address in row.addresses {
                                            if merged.addresses.len() < 32
                                                && !merged.addresses.contains(&address)
                                            {
                                                merged.addresses.push(address);
                                            }
                                        }
                                        for field in row.metadata {
                                            if !merged.metadata.contains(&field) {
                                                merged.metadata.push(field);
                                            }
                                        }
                                        if row.outcome == "truncatedByPolicy" {
                                            merged.outcome = "truncatedByPolicy".into();
                                            merged.truncated = true;
                                        } else if row.outcome == "complete"
                                            && merged.outcome == "partial"
                                        {
                                            merged.outcome = "complete".into();
                                        }
                                        let merged = bounded_row(merged).map_err(|()| {
                                            ScannerError::internal(
                                                "aggregate discovery entity",
                                                "an accepted identity became invalid",
                                            )
                                        })?;
                                        let after = discovery_row_metadata_bytes(&merged);
                                        let additional = after.saturating_sub(before);
                                        if query
                                            .retained_metadata_bytes
                                            .checked_add(additional)
                                            .is_none_or(|total| {
                                                total
                                                    > usize::try_from(
                                                        descriptor.maximum_metadata_bytes_per_query,
                                                    )
                                                    .unwrap_or(usize::MAX)
                                            })
                                        {
                                            existing.truncated = true;
                                            existing.outcome = "truncatedByPolicy".into();
                                            counters.truncated += 1;
                                        } else if retained_metadata_bytes
                                            .checked_add(additional)
                                            .is_some_and(|total| {
                                                total <= plan.limits.max_metadata_bytes
                                            })
                                        {
                                            query.retained_metadata_bytes += additional;
                                            if merged.truncated && !existing.truncated {
                                                counters.truncated += 1;
                                            }
                                            retained_metadata_bytes += additional;
                                            *existing = merged;
                                        } else {
                                            existing.truncated = true;
                                            existing.outcome = "truncatedByPolicy".into();
                                            counters.truncated += 1;
                                        }
                                        continue;
                                    }
                                    let row_metadata_bytes = discovery_row_metadata_bytes(&row);
                                    if query
                                        .retained_metadata_bytes
                                        .checked_add(row_metadata_bytes)
                                        .is_none_or(|total| {
                                            total
                                                > usize::try_from(
                                                    descriptor.maximum_metadata_bytes_per_query,
                                                )
                                                .unwrap_or(usize::MAX)
                                        })
                                    {
                                        counters.truncated += 1;
                                        continue;
                                    }
                                    if retained_metadata_bytes
                                        .checked_add(row_metadata_bytes)
                                        .is_none_or(|total| total > plan.limits.max_metadata_bytes)
                                    {
                                        counters.truncated += 1;
                                        continue;
                                    }
                                    retained_metadata_bytes += row_metadata_bytes;
                                    query.retained_metadata_bytes += row_metadata_bytes;
                                    query.retained_entities += 1;
                                    row.entity_id = (rows.len() + 1).to_string();
                                    identities.insert(key, rows.len());
                                    counters.accepted += 1;
                                    if row.truncated {
                                        counters.truncated += 1;
                                    }
                                    rows.push(row);
                                    if query.retained_entities
                                        >= usize::from(descriptor.maximum_entities_per_query)
                                        && query.pending_outbound.is_none()
                                    {
                                        query.response_deadline = None;
                                    }
                                }
                            }
                            Err(()) => counters.rejected += 1,
                        }
                    }
                    Ok(None) => break,
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(_) => {
                        counters.rejected += 1;
                        break;
                    }
                }
            }
            if query.pending_outbound.is_none()
                && let QueryContext::Mdns(context) = &mut query.context
            {
                query.pending_outbound = context.queued.pop_front();
            }
        }
        if counters.received > MAX_RECEIVED_DATAGRAMS as u64
            || counters.received_bytes > MAX_RECEIVED_BYTES as u64
        {
            control.publish(&counters);
            break;
        }
        control.publish(&counters);
        if !progressed {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    // A TFTP DATA/OACK response creates server-side transfer state. Once such
    // a response has been accepted, send the one bounded terminal ERROR even
    // when cancellation wins the next loop boundary. No other queued work is
    // transmitted during this cleanup sweep.
    for query in &mut queries {
        if query
            .pending_outbound
            .as_ref()
            .is_some_and(|outbound| !matches!(outbound.kind, OutboundKind::Cleanup))
        {
            counters.truncated = counters.truncated.saturating_add(1);
        }
        if let QueryContext::Mdns(context) = &query.context {
            counters.truncated = counters
                .truncated
                .saturating_add(u64::try_from(context.queued.len()).unwrap_or(u64::MAX));
        }
        if query
            .pending_outbound
            .as_ref()
            .is_some_and(|outbound| matches!(outbound.kind, OutboundKind::Cleanup))
            && let Some(outbound) = query.pending_outbound.take()
            && query
                .socket
                .send_to(&outbound.bytes, outbound.destination)
                .is_ok()
        {
            counters.sent = counters.sent.saturating_add(1);
            counters.cleanup_sent = counters.cleanup_sent.saturating_add(1);
        }
    }
    for row in &mut rows {
        row.addresses.sort();
        row.addresses.dedup();
        row.metadata.sort_by(|left, right| {
            (&left.key, &left.value, &left.text).cmp(&(&right.key, &right.value, &right.text))
        });
        row.metadata.dedup();
    }
    rows.sort_by(|left, right| {
        (
            left.operation_id,
            left.interface_index,
            &left.responder,
            left.responder_port,
            &left.identity,
        )
            .cmp(&(
                right.operation_id,
                right.interface_index,
                &right.responder,
                right.responder_port,
                &right.identity,
            ))
    });
    let rpcbind_parents: std::collections::BTreeSet<_> = rows
        .iter()
        .filter(|row| row.operation_id == 7 && row.derivation_kind.is_none())
        .map(|row| {
            (
                row.interface_index,
                row.responder.clone(),
                row.identity.clone(),
            )
        })
        .collect();
    let before_parent_filter = rows.len();
    rows.retain(|row| {
        row.derivation_kind.is_none()
            || row.parent_entity_id.as_ref().is_some_and(|parent| {
                rpcbind_parents.contains(&(
                    row.interface_index,
                    row.responder.clone(),
                    parent.as_bytes().to_vec(),
                ))
            })
    });
    counters.rejected = counters
        .rejected
        .saturating_add((before_parent_filter - rows.len()) as u64);
    counters.accepted = counters
        .accepted
        .saturating_sub((before_parent_filter - rows.len()) as u64);
    for (index, row) in rows.iter_mut().enumerate() {
        row.entity_id = (index + 1).to_string();
    }
    let parent_ids: std::collections::BTreeMap<_, _> = rows
        .iter()
        .filter(|row| row.operation_id == 7 && row.derivation_kind.is_none())
        .map(|row| {
            (
                (
                    row.interface_index,
                    row.responder.clone(),
                    row.identity.clone(),
                ),
                row.entity_id.clone(),
            )
        })
        .collect();
    for row in &mut rows {
        if row.derivation_kind.is_some()
            && let Some(parent) = &row.parent_entity_id
        {
            row.parent_entity_id = parent_ids
                .get(&(
                    row.interface_index,
                    row.responder.clone(),
                    parent.as_bytes().to_vec(),
                ))
                .cloned();
        }
    }
    let cancelled = control.cancelling();
    control.publish(&counters);
    control.complete();
    Ok(NativeDiscoveryRun {
        schema_version: 1,
        registry_version: DISCOVERY_OPERATION_REGISTRY_VERSION.into(),
        registry_sha256: discovery_operation_registry_sha256_hex(DISCOVERY_OPERATION_REGISTRY),
        state: if cancelled { "cancelled" } else { "completed" }.into(),
        allow_risks: risk_names(plan.allow_risks),
        receive_modes: if plan
            .operations
            .iter()
            .any(|operation| operation.id.get() == 1)
        {
            vec!["legacyUnicast".into()]
        } else {
            Vec::new()
        },
        rows,
        progress: counters.into(),
    })
}

fn discovery_row_metadata_bytes(row: &NativeDiscoveryRow) -> usize {
    row.identity
        .len()
        .saturating_add(row.addresses.iter().map(String::len).sum::<usize>())
        .saturating_add(
            row.metadata
                .iter()
                .map(|field| {
                    field
                        .key
                        .len()
                        .saturating_add(field.value.len())
                        .saturating_add(field.text.as_ref().map_or(0, String::len))
                })
                .sum::<usize>(),
        )
}

fn risk_names(risks: nodenet_protocols::UdpProbeRiskSet) -> Vec<String> {
    [
        (
            nodenet_protocols::UdpProbeRisk::HighAmplification,
            "highAmplification",
        ),
        (
            nodenet_protocols::UdpProbeRisk::StatefulHandshake,
            "statefulHandshake",
        ),
        (
            nodenet_protocols::UdpProbeRisk::FixedSourcePort,
            "fixedSourcePort",
        ),
        (
            nodenet_protocols::UdpProbeRisk::MulticastOrBroadcast,
            "multicastOrBroadcast",
        ),
        (
            nodenet_protocols::UdpProbeRisk::AuthenticationAttempt,
            "authenticationAttempt",
        ),
        (
            nodenet_protocols::UdpProbeRisk::SensitiveRead,
            "sensitiveRead",
        ),
    ]
    .into_iter()
    .filter(|(risk, _)| risks.contains(*risk))
    .map(|(_, name)| name.into())
    .collect()
}

type Product = (
    ValidatedDiscoveryOperation,
    SocketAddr,
    SocketAddr,
    Option<u32>,
    Option<IpAddr>,
);

#[allow(
    clippy::too_many_lines,
    reason = "link and target product normalization share one fail-before-send transaction"
)]
fn products(
    plan: &ValidatedDiscoveryPlan,
    snapshot: &NetworkSnapshot,
    resolved_default_ipv4_gateway: Option<(IpAddr, Option<u32>)>,
) -> Result<Vec<Product>, ScannerError> {
    let mut output = Vec::new();
    match &plan.scope {
        ValidatedDiscoveryScope::Links {
            interfaces,
            ipv4,
            ipv6,
        } => {
            let selected_interfaces = if interfaces.is_empty() {
                let mut eligible: Vec<String> = snapshot
                    .interfaces
                    .iter()
                    .filter(|interface| interface.flags & 0x1 != 0 && interface.flags & 0x8 == 0)
                    .filter(|interface| {
                        snapshot.addresses.iter().any(|address| {
                            address.interface_index == interface.index
                                && ((*ipv4 && i32::from(address.family) == libc::AF_INET)
                                    || (*ipv6 && i32::from(address.family) == libc::AF_INET6))
                        })
                    })
                    .map(|interface| interface.name.clone())
                    .collect();
                eligible.sort();
                if eligible.is_empty() || eligible.len() > 16 {
                    return Err(ScannerError::context(
                        "resolve eligible discovery interfaces",
                        "allEligible selected zero or more than 16 eligible interfaces",
                    ));
                }
                eligible
            } else {
                interfaces.clone()
            };
            for interface_name in &selected_interfaces {
                let interface = snapshot
                    .interfaces
                    .iter()
                    .find(|interface| &interface.name == interface_name)
                    .ok_or_else(|| {
                        ScannerError::context(
                            "resolve discovery interface",
                            format!("interface {interface_name} is absent"),
                        )
                    })?;
                for operation in &plan.operations {
                    let descriptor = descriptor(operation.id)?;
                    if *ipv4 {
                        let source = snapshot
                            .addresses
                            .iter()
                            .filter(|address| address.interface_index == interface.index)
                            .filter_map(|address| address.local.or(address.address))
                            .find(|address| matches!(address, IpAddr::V4(_)))
                            .ok_or_else(|| {
                                ScannerError::context(
                                    "resolve discovery interface",
                                    format!("interface {interface_name} has no IPv4 address"),
                                )
                            })?;
                        if let Some(group) = descriptor.ipv4_multicast {
                            output.push((
                                operation.clone(),
                                SocketAddr::new(
                                    IpAddr::V4(Ipv4Addr::from(group)),
                                    descriptor.destination_port,
                                ),
                                match source {
                                    IpAddr::V6(address) => SocketAddr::V6(SocketAddrV6::new(
                                        address,
                                        0,
                                        0,
                                        interface.index,
                                    )),
                                    IpAddr::V4(address) => SocketAddr::new(IpAddr::V4(address), 0),
                                },
                                Some(interface.index),
                                None,
                            ));
                        }
                    }
                    if *ipv6 {
                        let source = snapshot
                            .addresses
                            .iter()
                            .filter(|address| address.interface_index == interface.index)
                            .filter_map(|address| address.local.or(address.address))
                            .find(|address| matches!(address, IpAddr::V6(_)))
                            .ok_or_else(|| {
                                ScannerError::context(
                                    "resolve discovery interface",
                                    format!("interface {interface_name} has no IPv6 address"),
                                )
                            })?;
                        if let Some(group) = descriptor.ipv6_multicast {
                            let group = Ipv6Addr::from(group);
                            output.push((
                                operation.clone(),
                                SocketAddr::V6(SocketAddrV6::new(
                                    group,
                                    descriptor.destination_port,
                                    0,
                                    interface.index,
                                )),
                                SocketAddr::new(source, 0),
                                Some(interface.index),
                                None,
                            ));
                        }
                    }
                }
            }
        }
        ValidatedDiscoveryScope::Targets {
            targets,
            kernel_default_ipv4_gateway,
            exclusions,
        } => {
            let mut resolved = targets.clone();
            if *kernel_default_ipv4_gateway {
                let (gateway, output_interface) =
                    resolved_default_ipv4_gateway.ok_or_else(|| {
                        ScannerError::context(
                            "resolve default IPv4 gateway",
                            "no kernel-selected IPv4 gateway is available",
                        )
                    })?;
                let excluded = exclusions.as_ref().is_some_and(|set| {
                    set.contains(TargetEndpoint {
                        address: to_protocol_address(gateway),
                        scope: None,
                    })
                });
                if !excluded {
                    resolved.push((gateway, output_interface));
                }
            }
            resolved.sort_unstable();
            resolved.dedup();
            if resolved.is_empty() {
                return Err(ScannerError::invalid(
                    "resolve discovery targets",
                    "discovery exclusions removed every target",
                ));
            }
            for operation in &plan.operations {
                let descriptor = descriptor(operation.id)?;
                for (target, interface_index) in &resolved {
                    if operation.id.get() == 5
                        && !same_link_ipv4_target(*target, *interface_index, snapshot)
                        && !*kernel_default_ipv4_gateway
                    {
                        return Err(ScannerError::invalid(
                            "resolve NAT-PMP target",
                            "explicit NAT-PMP targets must be on a directly attached IPv4 link",
                        ));
                    }
                    let compatible = match target {
                        IpAddr::V4(_) => matches!(
                            descriptor.families,
                            nodenet_protocols::UdpAddressFamilies::Ipv4
                                | nodenet_protocols::UdpAddressFamilies::Both
                        ),
                        IpAddr::V6(_) => matches!(
                            descriptor.families,
                            nodenet_protocols::UdpAddressFamilies::Ipv6
                                | nodenet_protocols::UdpAddressFamilies::Both
                        ),
                    };
                    if compatible {
                        let source = match target {
                            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
                        };
                        output.push((
                            operation.clone(),
                            match target {
                                IpAddr::V4(address) => SocketAddr::new(
                                    IpAddr::V4(*address),
                                    descriptor.destination_port,
                                ),
                                IpAddr::V6(address) => SocketAddr::V6(SocketAddrV6::new(
                                    *address,
                                    descriptor.destination_port,
                                    0,
                                    interface_index.unwrap_or(0),
                                )),
                            },
                            source,
                            *interface_index,
                            Some(*target),
                        ));
                    }
                }
            }
        }
    }
    Ok(output)
}

fn same_link_ipv4_target(
    target: IpAddr,
    interface_index: Option<u32>,
    snapshot: &NetworkSnapshot,
) -> bool {
    let IpAddr::V4(target) = target else {
        return false;
    };
    let target = u32::from(target);
    snapshot.addresses.iter().any(|address| {
        if i32::from(address.family) != libc::AF_INET
            || interface_index.is_some_and(|index| index != address.interface_index)
        {
            return false;
        }
        let Some(IpAddr::V4(local)) = address.local.or(address.address) else {
            return false;
        };
        let prefix = address.prefix_length.min(32);
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        u32::from(local) & mask == target & mask
    })
}

fn descriptor(
    id: DiscoveryOperationId,
) -> Result<&'static nodenet_protocols::DiscoveryOperationDescriptor, ScannerError> {
    DISCOVERY_OPERATION_REGISTRY
        .iter()
        .find(|entry| entry.id == id)
        .ok_or_else(|| ScannerError::internal("run discovery", "operation disappeared"))
}

#[allow(
    clippy::too_many_lines,
    reason = "operation-specific entropy and correlation state is initialized in one fail-before-send transaction"
)]
fn prepare_query(
    operation: ValidatedDiscoveryOperation,
    destination: SocketAddr,
    source: SocketAddr,
    interface_index: Option<u32>,
    expected_target: Option<IpAddr>,
    entropy: &mut Entropy,
) -> Result<Query, ScannerError> {
    let socket =
        UdpSocket::bind(source).map_err(|error| io_error("bind discovery UDP socket", &error))?;
    socket
        .set_nonblocking(true)
        .map_err(|error| io_error("configure discovery UDP socket", &error))?;
    match destination {
        SocketAddr::V4(_) => {
            setsockopt(&socket, nix::sys::socket::sockopt::Ipv4PacketInfo, &true).map_err(
                |error| ScannerError::system("enable discovery IPv4 packet info", error),
            )?;
            setsockopt(&socket, nix::sys::socket::sockopt::Ipv4RecvTtl, &true).map_err(
                |error| ScannerError::system("enable discovery IPv4 TTL receipt", error),
            )?;
        }
        SocketAddr::V6(_) => {
            setsockopt(
                &socket,
                nix::sys::socket::sockopt::Ipv6RecvPacketInfo,
                &true,
            )
            .map_err(|error| ScannerError::system("enable discovery IPv6 packet info", error))?;
            setsockopt(&socket, nix::sys::socket::sockopt::Ipv6RecvHopLimit, &true).map_err(
                |error| ScannerError::system("enable discovery IPv6 hop-limit receipt", error),
            )?;
        }
    }
    if destination.ip().is_multicast() {
        match destination {
            SocketAddr::V4(_) => {
                let hops = if operation.id.get() == 1 { 255 } else { 1 };
                socket
                    .set_multicast_ttl_v4(hops)
                    .map_err(|error| io_error("set discovery multicast TTL", &error))?;
                socket
                    .set_multicast_loop_v4(false)
                    .map_err(|error| io_error("disable discovery multicast loopback", &error))?;
            }
            SocketAddr::V6(_) => {
                let hops = if operation.id.get() == 1 { 255 } else { 1 };
                nix::sys::socket::setsockopt(
                    &socket,
                    nix::sys::socket::sockopt::Ipv6MulticastHops,
                    &hops,
                )
                .map_err(|error| ScannerError::system("set discovery multicast hops", error))?;
                socket
                    .set_multicast_loop_v6(false)
                    .map_err(|error| io_error("disable discovery multicast loopback", &error))?;
            }
        }
    }
    let context = match operation.id.get() {
        1 => QueryContext::Mdns(MdnsContext::new(entropy.u16_nonzero()?)),
        3 => {
            let bytes = entropy.bytes_16()?;
            QueryContext::WsDiscovery {
                message_id: uuid_urn(bytes),
            }
        }
        4 => QueryContext::Llmnr {
            transaction_id: entropy.u16_nonzero()?,
            query_name: operation.query.clone().unwrap_or_default(),
            query_type: if destination.is_ipv6() { 28 } else { 1 },
        },
        5 => QueryContext::NatPmp,
        6 => QueryContext::SqlBrowser,
        7 => QueryContext::Rpcbind {
            transaction_id: entropy.u32_nonzero()?,
            token: entropy.bytes_16()?,
            state: RpcbindState::AwaitingGetAddress,
        },
        8 => QueryContext::Tftp {
            entropy: entropy.bytes_16()?,
            pinned_port: None,
        },
        9 => QueryContext::Quic(
            build_quic_version_negotiation_request(entropy.bytes_8()?, entropy.bytes_8()?)
                .map_err(|error| {
                    ScannerError::invalid("build QUIC discovery", error.to_string())
                })?,
        ),
        _ => {
            return Err(ScannerError::invalid(
                "start discovery",
                "operation is not executable",
            ));
        }
    };
    Ok(Query {
        operation,
        interface_index,
        expected_target,
        destination,
        socket,
        context,
        pending_outbound: None,
        response_deadline: None,
        retained_entities: 0,
        retained_metadata_bytes: 0,
        lease: None,
        settled: false,
    })
}

fn source_port_matches(query: &Query, source_port: u16) -> bool {
    match &query.context {
        QueryContext::Tftp { .. } => source_port != 0,
        QueryContext::Rpcbind {
            state: RpcbindState::AwaitingNfs { port, .. },
            ..
        } => source_port == *port,
        _ => descriptor(query.operation.id)
            .is_ok_and(|operation| source_port == operation.destination_port),
    }
}

fn receive_datagram(
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> Result<Option<ReceivedDatagram>, nix::errno::Errno> {
    let capacity = buffer.len();
    let mut slices = [IoSliceMut::new(buffer)];
    let mut control = nix::cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo, i32, i32);
    let message = match recvmsg::<SockaddrStorage>(
        socket.as_raw_fd(),
        &mut slices,
        Some(&mut control),
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
    ) {
        Ok(value) => value,
        Err(nix::errno::Errno::EAGAIN) => return Ok(None),
        Err(error) => return Err(error),
    };
    if message.flags.contains(MsgFlags::MSG_TRUNC) || message.bytes > capacity {
        return Ok(None);
    }
    let source = message.address.and_then(|address| {
        address
            .as_sockaddr_in()
            .map(|value| SocketAddr::from(*value))
            .or_else(|| {
                address
                    .as_sockaddr_in6()
                    .map(|value| SocketAddr::from(*value))
            })
    });
    let Some(source) = source else {
        return Ok(None);
    };
    let mut interface_index = None;
    let mut hop_limit = None;
    for item in message.cmsgs().map_err(|_| nix::errno::Errno::EINVAL)? {
        match item {
            ControlMessageOwned::Ipv4PacketInfo(info) => {
                interface_index = u32::try_from(info.ipi_ifindex).ok();
            }
            ControlMessageOwned::Ipv6PacketInfo(info) => {
                interface_index = Some(info.ipi6_ifindex);
            }
            ControlMessageOwned::Ipv4Ttl(value) | ControlMessageOwned::Ipv6HopLimit(value) => {
                hop_limit = u32::try_from(value).ok();
            }
            _ => {}
        }
    }
    Ok(Some(ReceivedDatagram {
        length: message.bytes,
        source,
        interface_index,
        hop_limit,
    }))
}

fn request_bytes_and_destination(query: &Query) -> Result<(Vec<u8>, SocketAddr), ScannerError> {
    request_destination_from_query(query)
}

// UdpSocket deliberately remains unconnected for multicast/unicast responder
// fan-out. The normalized destination retains any required IPv6 scope ID.
fn request_destination_from_query(query: &Query) -> Result<(Vec<u8>, SocketAddr), ScannerError> {
    Ok((request_bytes(query)?, query.destination))
}

fn request_bytes(query: &Query) -> Result<Vec<u8>, ScannerError> {
    match &query.context {
        QueryContext::Mdns(context) => {
            build_mdns_service_enumeration_query(context.initial_transaction_id, true)
                .map_err(|error| ScannerError::invalid("build mDNS query", error.to_string()))
        }
        QueryContext::WsDiscovery { message_id } => {
            let bytes = parse_uuid_urn(message_id).ok_or_else(|| {
                ScannerError::internal("build WS-Discovery query", "invalid retained UUID")
            })?;
            build_ws_discovery_probe(bytes).map_err(|error| {
                ScannerError::invalid("build WS-Discovery query", error.to_string())
            })
        }
        QueryContext::Llmnr {
            transaction_id,
            query_name,
            query_type,
        } => build_llmnr_query(*transaction_id, query_name, *query_type)
            .map_err(|error| ScannerError::invalid("build LLMNR query", error.to_string())),
        QueryContext::NatPmp => Ok(build_nat_pmp_external_address_request().to_vec()),
        QueryContext::SqlBrowser => Ok(build_sql_browser_enumeration_request().to_vec()),
        QueryContext::Rpcbind { transaction_id, .. } => build_rpcbind_getaddr_request(
            *transaction_id,
            100_003,
            3,
            query
                .expected_target
                .is_some_and(|address| address.is_ipv6()),
        )
        .map_err(|error| ScannerError::invalid("build rpcbind query", error.to_string())),
        QueryContext::Tftp { entropy, .. } => Ok(build_tftp_discovery_rrq(*entropy)),
        QueryContext::Quic(request) => Ok(request.bytes.clone()),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "exhaustive operation dispatch keeps parser/result ownership and cleanup explicit"
)]
fn parse_rows(
    query: &mut Query,
    source: SocketAddr,
    observed_interface_index: Option<u32>,
    hop_limit: Option<u32>,
    bytes: &[u8],
) -> Result<ParsedRows, ()> {
    let descriptor = descriptor(query.operation.id).map_err(|_| ())?;
    let operation_id = u32::from(query.operation.id.get());
    let protocol = descriptor.name.to_owned();
    let evidence = format!("{:?}", descriptor.evidence);
    let interface_index = observed_interface_index.or(query.interface_index);
    let destination = query.destination;
    let base = |identity: Vec<u8>, kind: &str, metadata: Vec<NativeDiscoveryMetadataField>| {
        let mut metadata = metadata;
        if let Some(value) = hop_limit {
            metadata.push(field_text("receivedHopLimit", &value.to_string()));
        }
        bounded_row(NativeDiscoveryRow {
            entity_id: String::new(),
            parent_entity_id: None,
            derivation_kind: None,
            operation_id,
            protocol: protocol.clone(),
            kind: kind.into(),
            evidence: evidence.clone(),
            outcome: "complete".into(),
            responder: source.ip().to_string(),
            responder_port: u32::from(source.port()),
            interface_index,
            identity,
            addresses: vec![source.ip().to_string()],
            metadata,
            truncated: false,
        })
    };
    match &mut query.context {
        QueryContext::Mdns(context) => {
            let message = parse_discovery_dns_message(bytes).map_err(|_| ())?;
            if !message.is_response() || !context.outstanding.contains_key(&message.id) {
                return Err(());
            }
            let partial_wire_response = message.truncated();
            let enumeration = b"\x09_services\x07_dns-sd\x04_udp\x05local\0";
            let mut schedules: Vec<(Vec<u8>, Option<String>, u16)> = Vec::new();
            for record in message.records() {
                match &record.data {
                    DiscoveryDnsRecordData::Ptr(name) => {
                        if record.name.canonical_wire == enumeration {
                            schedules.push((name.canonical_wire.clone(), name.text.clone(), 12));
                        } else {
                            let service = context
                                .services
                                .entry(name.canonical_wire.clone())
                                .or_default();
                            service.service_type.clone_from(&record.name.text);
                            service.instance.clone_from(&name.text);
                            service.ttls.insert(record.ttl);
                            service.partial_wire_response |= partial_wire_response;
                            schedules.push((name.canonical_wire.clone(), name.text.clone(), 33));
                            schedules.push((name.canonical_wire.clone(), name.text.clone(), 16));
                        }
                    }
                    DiscoveryDnsRecordData::Srv { port, target, .. } => {
                        let service = context
                            .services
                            .entry(record.name.canonical_wire.clone())
                            .or_default();
                        service.instance.clone_from(&record.name.text);
                        service.target_wire = Some(target.canonical_wire.clone());
                        service.target.clone_from(&target.text);
                        service.port = Some(*port);
                        service.ttls.insert(record.ttl);
                        service.partial_wire_response |= partial_wire_response;
                        schedules.push((target.canonical_wire.clone(), target.text.clone(), 1));
                        schedules.push((target.canonical_wire.clone(), target.text.clone(), 28));
                    }
                    DiscoveryDnsRecordData::Txt(entries) => {
                        let service = context
                            .services
                            .entry(record.name.canonical_wire.clone())
                            .or_default();
                        service.instance.clone_from(&record.name.text);
                        service.ttls.insert(record.ttl);
                        service.partial_wire_response |= partial_wire_response;
                        for entry in entries {
                            let field = NativeDiscoveryMetadataField {
                                key: entry.key.clone(),
                                value: entry.value.clone(),
                                text: entry.text_value.clone(),
                            };
                            if !service.txt.contains(&field) {
                                service.txt.push(field);
                            }
                        }
                    }
                    DiscoveryDnsRecordData::A(address) => {
                        let address = Ipv4Addr::from(*address).to_string();
                        for service in context.services.values_mut().filter(|service| {
                            service.target_wire.as_deref()
                                == Some(record.name.canonical_wire.as_slice())
                        }) {
                            service.addresses.insert(address.clone());
                            service.ttls.insert(record.ttl);
                            service.partial_wire_response |= partial_wire_response;
                        }
                    }
                    DiscoveryDnsRecordData::Aaaa(address) => {
                        let address = Ipv6Addr::from(*address).to_string();
                        for service in context.services.values_mut().filter(|service| {
                            service.target_wire.as_deref()
                                == Some(record.name.canonical_wire.as_slice())
                        }) {
                            service.addresses.insert(address.clone());
                            service.ttls.insert(record.ttl);
                            service.partial_wire_response |= partial_wire_response;
                        }
                    }
                    DiscoveryDnsRecordData::Unknown => {}
                }
            }
            for (wire, text, query_type) in schedules {
                context.schedule(&wire, text.as_deref(), query_type, destination);
            }
            let mut rows = Vec::new();
            for (identity, service) in &context.services {
                let mut metadata = Vec::new();
                if let Some(value) = &service.instance {
                    metadata.push(field_text("instance", value));
                }
                if let Some(value) = &service.service_type {
                    metadata.push(field_text("serviceType", value));
                }
                if let Some(value) = &service.target {
                    metadata.push(field_text("target", value));
                }
                if let Some(value) = service.port {
                    metadata.push(field_text("port", &value.to_string()));
                }
                for ttl in &service.ttls {
                    metadata.push(field_text("ttl", &ttl.to_string()));
                }
                metadata.extend(service.txt.clone());
                let mut row = base(identity.clone(), "service", metadata)?;
                row.addresses = service.addresses.iter().cloned().collect();
                if service.port.is_none()
                    || service.target.is_none()
                    || service.addresses.is_empty()
                    || service.partial_wire_response
                {
                    row.outcome = "partial".into();
                }
                rows.push(row);
            }
            Ok((rows, None))
        }
        QueryContext::WsDiscovery { message_id } => {
            let response = parse_ws_discovery_probe_matches(bytes, message_id).map_err(|_| ())?;
            let mut rows = Vec::new();
            for item in response.matches {
                let mut metadata = Vec::new();
                for value in item.types {
                    metadata.push(field_text("type", &value));
                }
                for value in item.scopes {
                    metadata.push(field_text("scope", &value));
                }
                for value in item.xaddrs {
                    metadata.push(field_text("xaddr", &value));
                }
                metadata.push(field_text(
                    "metadataVersion",
                    &item.metadata_version.to_string(),
                ));
                rows.push(base(
                    item.endpoint_address.as_bytes().to_vec(),
                    "device",
                    metadata,
                )?);
            }
            if rows.is_empty() {
                Err(())
            } else {
                Ok((rows, None))
            }
        }
        QueryContext::Llmnr {
            transaction_id,
            query_name,
            query_type,
        } => {
            let response = parse_llmnr_response(bytes, *transaction_id).map_err(|_| ())?;
            let expected_name = query_name.trim_end_matches('.');
            let mut rows = Vec::new();
            for record in &response.message.answers {
                if record.record_class != 1
                    || record.record_type != *query_type
                    || !record.name.text.as_deref().is_some_and(|name| {
                        name.trim_end_matches('.')
                            .eq_ignore_ascii_case(expected_name)
                    })
                {
                    continue;
                }
                let address = match &record.data {
                    DiscoveryDnsRecordData::A(value) if *query_type == 1 => {
                        Ipv4Addr::from(*value).to_string()
                    }
                    DiscoveryDnsRecordData::Aaaa(value) if *query_type == 28 => {
                        Ipv6Addr::from(*value).to_string()
                    }
                    _ => continue,
                };
                let mut row = base(
                    record.name.canonical_wire.clone(),
                    "name",
                    vec![
                        field_text("address", &address),
                        field_text("conflict", &response.conflict.to_string()),
                        field_text("tentative", &response.tentative.to_string()),
                        field_text("ttl", &record.ttl.to_string()),
                    ],
                )?;
                row.addresses = vec![address];
                rows.push(row);
            }
            if rows.is_empty() {
                Err(())
            } else {
                Ok((rows, None))
            }
        }
        QueryContext::NatPmp => {
            let response = parse_nat_pmp_external_address_response(bytes).map_err(|_| ())?;
            Ok((
                vec![base(
                    source.ip().to_string().into_bytes(),
                    "gateway",
                    vec![
                        field_text("externalAddress", &response.external_address.to_string()),
                        field_text("epochSeconds", &response.epoch_seconds.to_string()),
                        field_text("resultCode", &response.result_code.to_string()),
                    ],
                )?],
                None,
            ))
        }
        QueryContext::SqlBrowser => {
            let instances = parse_sql_browser_response(bytes).map_err(|_| ())?;
            let instance_count = instances.len();
            let instance_rows: Result<Vec<_>, _> = instances
                .into_iter()
                .map(|instance| {
                    let identity = format!("{}\\{}", instance.server_name, instance.instance_name)
                        .into_bytes();
                    let mut metadata = Vec::new();
                    for (key, value) in instance.fields {
                        metadata.push(field_text(&key, &value));
                    }
                    base(identity, "databaseInstance", metadata)
                })
                .collect();
            let mut rows = Vec::with_capacity(instance_count.saturating_add(1));
            rows.push(base(
                format!("sql-browser://{}:1434", source.ip()).into_bytes(),
                "service",
                vec![
                    field_text("transport", "udp"),
                    field_text("port", "1434"),
                    field_text("instanceCount", &instance_count.to_string()),
                ],
            )?);
            rows.extend(instance_rows?);
            Ok((rows, None))
        }
        QueryContext::Rpcbind {
            transaction_id,
            token,
            state,
        } => match state {
            RpcbindState::AwaitingGetAddress => {
                let universal =
                    parse_rpcbind_getaddr_response(bytes, *transaction_id).map_err(|_| ())?;
                let (address, port) =
                    parse_rpcbind_universal_address(&universal).map_err(|_| ())?;
                if Some(address) != query.expected_target || port == 0 {
                    return Err(());
                }
                let parent_identity = format!("{address}:{port}").into_bytes();
                let parent = base(
                    parent_identity.clone(),
                    "service",
                    vec![
                        field_text("rpcProgram", "100003"),
                        field_text("rpcVersion", "3"),
                        field_text("derivedPort", &port.to_string()),
                    ],
                )?;
                if !query.operation.follow_up {
                    return Ok((vec![parent], None));
                }
                let local = query.socket.local_addr().map_err(|_| ())?;
                let request = build_udp_catalogue_request(
                    UdpCatalogueProbe::NfsV3Null,
                    *token,
                    UdpProbeBuildContext {
                        source: to_protocol_address(local.ip()),
                        destination: to_protocol_address(address),
                        source_port: local.port(),
                        destination_port: port,
                    },
                )
                .map_err(|_| ())?;
                *state = RpcbindState::AwaitingNfs {
                    request: request.clone(),
                    parent_identity: parent_identity.clone(),
                    port,
                };
                Ok((
                    vec![parent],
                    Some(OutboundDatagram {
                        bytes: request,
                        destination: SocketAddr::new(address, port),
                        kind: OutboundKind::AdaptiveQuery,
                    }),
                ))
            }
            RpcbindState::AwaitingNfs {
                request,
                parent_identity,
                port,
            } => {
                if source.port() != *port {
                    return Err(());
                }
                let matched =
                    parse_udp_catalogue_response(UdpCatalogueProbe::NfsV3Null, request, bytes)
                        .map_err(|_| ())?;
                let mut row = base(
                    format!("nfs3://{}:{port}", source.ip()).into_bytes(),
                    "derivedService",
                    vec![
                        field_text("rpcProgram", "100003"),
                        field_text("rpcVersion", "3"),
                        NativeDiscoveryMetadataField {
                            key: "catalogueMetadata".into(),
                            value: matched.metadata.into_vec(),
                            text: None,
                        },
                    ],
                )?;
                row.parent_entity_id = String::from_utf8(parent_identity.clone()).ok();
                row.derivation_kind = Some("rpcbindGetAddress".into());
                Ok((vec![row], None))
            }
        },
        QueryContext::Tftp { pinned_port, .. } => {
            let response = parse_tftp_discovery_response(bytes).map_err(|_| ())?;
            if pinned_port.is_some_and(|port| port != source.port()) {
                return Err(());
            }
            if pinned_port.is_none() {
                *pinned_port = Some(source.port());
            }
            let (metadata, cleanup) = match response {
                TftpDiscoveryResponse::Error { code, message } => (
                    vec![
                        field_text("response", "error"),
                        field_text("code", &code.to_string()),
                        field_text("message", &message),
                    ],
                    None,
                ),
                TftpDiscoveryResponse::Data {
                    block,
                    payload_bytes,
                } => (
                    vec![
                        field_text("response", "data"),
                        field_text("block", &block.to_string()),
                        field_text("payloadBytes", &payload_bytes.to_string()),
                    ],
                    build_tftp_termination_error("nodenet discovery complete"),
                ),
                TftpDiscoveryResponse::OptionAcknowledgement(options) => {
                    let mut metadata = vec![field_text("response", "oack")];
                    for (key, value) in options {
                        metadata.push(field_text(&key, &value));
                    }
                    (
                        metadata,
                        build_tftp_termination_error("nodenet discovery complete"),
                    )
                }
            };
            Ok((
                vec![base(
                    format!("{}:{}", source.ip(), source.port()).into_bytes(),
                    "service",
                    metadata,
                )?],
                cleanup.map(|bytes| OutboundDatagram {
                    bytes,
                    destination: source,
                    kind: OutboundKind::Cleanup,
                }),
            ))
        }
        QueryContext::Quic(request) => {
            let response =
                parse_quic_version_negotiation_response(bytes, request).map_err(|_| ())?;
            let metadata = response
                .versions
                .into_iter()
                .map(|version| field_text("version", &format!("0x{version:08x}")))
                .collect();
            Ok((
                vec![base(
                    source.ip().to_string().into_bytes(),
                    "service",
                    metadata,
                )?],
                None,
            ))
        }
    }
}

fn bounded_row(mut row: NativeDiscoveryRow) -> Result<NativeDiscoveryRow, ()> {
    if row.identity.is_empty() || row.identity.len() > 1_024 {
        return Err(());
    }
    let address_count = row.addresses.len();
    row.addresses
        .retain(|address| !address.is_empty() && address.len() <= 128);
    if row.addresses.len() != address_count {
        row.truncated = true;
        row.outcome = "truncatedByPolicy".into();
    }
    if row.addresses.len() > 32 {
        row.addresses.truncate(32);
        row.truncated = true;
        row.outcome = "truncatedByPolicy".into();
    }
    if row.metadata.len() > MAX_METADATA_FIELDS_PER_ROW {
        row.metadata.truncate(MAX_METADATA_FIELDS_PER_ROW);
        row.truncated = true;
        row.outcome = "truncatedByPolicy".into();
    }
    let mut total = 0_usize;
    row.metadata.retain(|field| {
        let text_length = field.text.as_ref().map_or(0, String::len);
        let length = field
            .key
            .len()
            .saturating_add(field.value.len())
            .saturating_add(text_length);
        if field.key.is_empty()
            || field.key.len() > 1_024
            || field.value.len() > 1_024
            || text_length > 1_024
            || total.saturating_add(length) > MAX_METADATA_BYTES_PER_ROW
        {
            row.truncated = true;
            row.outcome = "truncatedByPolicy".into();
            false
        } else {
            total += length;
            true
        }
    });
    Ok(row)
}

fn field_text(key: &str, value: &str) -> NativeDiscoveryMetadataField {
    NativeDiscoveryMetadataField {
        key: key.into(),
        value: value.as_bytes().to_vec(),
        text: Some(value.into()),
    }
}

impl From<Counters> for NativeDiscoveryProgress {
    fn from(value: Counters) -> Self {
        Self {
            queries: value.queries.to_string(),
            sent: value.sent.to_string(),
            received: value.received.to_string(),
            received_bytes: value.received_bytes.to_string(),
            accepted: value.accepted.to_string(),
            duplicate: value.duplicate.to_string(),
            rejected: value.rejected.to_string(),
            truncated: value.truncated.to_string(),
            cleanup_sent: value.cleanup_sent.to_string(),
        }
    }
}

struct Entropy(File);

impl Entropy {
    fn new() -> Result<Self, ScannerError> {
        File::open("/dev/urandom")
            .map(Self)
            .map_err(|error| io_error("open discovery entropy", &error))
    }

    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), ScannerError> {
        self.0
            .read_exact(bytes)
            .map_err(|error| io_error("read discovery entropy", &error))
    }

    fn bytes_8(&mut self) -> Result<[u8; 8], ScannerError> {
        let mut value = [0; 8];
        self.fill(&mut value)?;
        Ok(value)
    }

    fn bytes_16(&mut self) -> Result<[u8; 16], ScannerError> {
        let mut value = [0; 16];
        self.fill(&mut value)?;
        Ok(value)
    }

    fn u16_nonzero(&mut self) -> Result<u16, ScannerError> {
        loop {
            let mut value = [0; 2];
            self.fill(&mut value)?;
            let value = u16::from_be_bytes(value);
            if value != 0 {
                return Ok(value);
            }
        }
    }

    fn u32_nonzero(&mut self) -> Result<u32, ScannerError> {
        loop {
            let mut value = [0; 4];
            self.fill(&mut value)?;
            let value = u32::from_be_bytes(value);
            if value != 0 {
                return Ok(value);
            }
        }
    }
}

fn uuid_urn(bytes: [u8; 16]) -> String {
    format!(
        "urn:uuid:{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn parse_uuid_urn(value: &str) -> Option<[u8; 16]> {
    let hex: String = value
        .strip_prefix("urn:uuid:")?
        .chars()
        .filter(|value| *value != '-')
        .collect();
    if hex.len() != 32 {
        return None;
    }
    let mut output = [0_u8; 16];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(output)
}

fn io_error(operation: &'static str, error: &std::io::Error) -> ScannerError {
    ScannerError::system(
        operation,
        nix::errno::Errno::from_raw(error.raw_os_error().unwrap_or(libc_fallback::EIO)),
    )
}

mod libc_fallback {
    pub const EIO: i32 = 5;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rpc_reply(xid: u32, body: Option<&str>) -> Vec<u8> {
        let mut reply = Vec::new();
        for word in [xid, 1, 0, 0, 0, 0] {
            reply.extend_from_slice(&word.to_be_bytes());
        }
        if let Some(value) = body {
            reply.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
            reply.extend_from_slice(value.as_bytes());
            reply.resize((reply.len() + 3) & !3, 0);
        }
        reply
    }

    #[test]
    fn rpcbind_getaddr_executes_one_transaction_correlated_nfs_child() {
        let target = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let transaction_id = 0x1020_3040;
        let mut query = Query {
            operation: ValidatedDiscoveryOperation {
                id: DiscoveryOperationId::new(7).unwrap(),
                query: None,
                follow_up: true,
            },
            interface_index: None,
            expected_target: Some(target),
            destination: SocketAddr::new(target, 111),
            socket: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            context: QueryContext::Rpcbind {
                transaction_id,
                token: [0xa5; 16],
                state: RpcbindState::AwaitingGetAddress,
            },
            pending_outbound: None,
            response_deadline: Some(Instant::now() + Duration::from_secs(1)),
            retained_entities: 0,
            retained_metadata_bytes: 0,
            lease: None,
            settled: false,
        };
        let (parent, child) = parse_rows(
            &mut query,
            SocketAddr::new(target, 111),
            None,
            None,
            &rpc_reply(transaction_id, Some("127.0.0.1.8.1")),
        )
        .unwrap();
        assert_eq!(parent.len(), 1);
        let child = child.unwrap();
        let child_request = child.bytes;
        let child_destination = child.destination;
        assert_eq!(child_destination, SocketAddr::new(target, 2_049));

        let child_xid = u32::from_be_bytes(child_request[..4].try_into().unwrap());
        let (rows, follow_up) = parse_rows(
            &mut query,
            child_destination,
            None,
            None,
            &rpc_reply(child_xid, None),
        )
        .unwrap();
        assert!(follow_up.is_none());
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].derivation_kind.as_deref(),
            Some("rpcbindGetAddress")
        );
        assert_eq!(rows[0].parent_entity_id.as_deref(), Some("127.0.0.1:2049"));
    }

    #[test]
    fn tftp_pins_the_first_structured_transfer_port() {
        let target = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut query = Query {
            operation: ValidatedDiscoveryOperation {
                id: DiscoveryOperationId::new(8).unwrap(),
                query: None,
                follow_up: false,
            },
            interface_index: None,
            expected_target: Some(target),
            destination: SocketAddr::new(target, 69),
            socket: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            context: QueryContext::Tftp {
                entropy: [0xa5; 16],
                pinned_port: None,
            },
            pending_outbound: None,
            response_deadline: Some(Instant::now() + Duration::from_secs(1)),
            retained_entities: 0,
            retained_metadata_bytes: 0,
            lease: None,
            settled: false,
        };
        let response = [0, 5, 0, 1, b'x', 0];
        assert!(
            parse_rows(
                &mut query,
                SocketAddr::new(target, 40_000),
                None,
                None,
                &response,
            )
            .is_ok()
        );
        assert!(
            parse_rows(
                &mut query,
                SocketAddr::new(target, 40_001),
                None,
                None,
                &response,
            )
            .is_err()
        );
    }
}
