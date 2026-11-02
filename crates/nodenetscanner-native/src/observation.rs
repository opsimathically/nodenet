#![allow(
    unsafe_code,
    reason = "localized reviewed Linux packet-socket sockaddr and membership ABI adapters"
)]

use std::collections::{BTreeSet, VecDeque};
use std::io::IoSliceMut;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use napi_derive::napi;
use nix::libc;
use nix::sys::socket::{ControlMessageOwned, LinkAddr, MsgFlags, recvmsg};
use nodenet_protocols::{
    FragmentState, IpProtocol, ParseMode, PassiveProtocol, TransportChecksumContext,
    UpperLayerState, decode_passive_frame_with_checksum_policy, parse_ipv4_packet,
    parse_ipv6_packet, validate_transport_checksum,
};
use rustix::net::{AddressFamily, Protocol, SocketFlags, SocketType, socket_with};

use crate::error::ScannerError;

pub(crate) const MAX_OBSERVATION_INTERFACES: usize = 4;
pub(crate) const MAX_OBSERVATION_RESULTS: usize = 8_192;
pub(crate) const MAX_OBSERVATION_METADATA_BYTES: usize = 16 * 1024 * 1024;
const MAX_OBSERVATION_DURATION_MS: u32 = 300_000;
const MAX_OBSERVATION_SNAP_LENGTH: u32 = 16_384;
const MAX_INSPECTED_FRAMES: u64 = 1_000_000;
const MAX_CAPTURED_BYTES: u64 = 64 * 1024 * 1024;
const ETH_P_ALL: u16 = 0x0003;
const RUNNING: u8 = 1;
const PAUSED: u8 = 2;
const CANCELLING: u8 = 3;
const COMPLETED: u8 = 4;
const FAILED: u8 = 5;

#[napi(object)]
#[derive(Clone)]
pub struct NativeObservationPlan {
    pub interfaces: Vec<String>,
    pub protocols: Vec<String>,
    pub duration_ms: Option<u32>,
    pub snap_length: Option<u32>,
    pub max_results: Option<u32>,
    pub max_metadata_bytes: Option<u32>,
    pub include_outgoing: Option<bool>,
    pub promiscuous: Option<bool>,
    pub allow_risks: Option<Vec<String>>,
}

#[derive(Clone, Debug)]
pub(crate) struct ValidatedObservationPlan {
    interfaces: Vec<String>,
    protocols: Vec<String>,
    ether_types: BTreeSet<u16>,
    control_plane: bool,
    duration: Duration,
    snap_length: usize,
    max_results: usize,
    pub(crate) max_metadata_bytes: usize,
    include_outgoing: bool,
    promiscuous: bool,
}

impl NativeObservationPlan {
    #[allow(
        clippy::too_many_lines,
        reason = "one fail-before-I/O transaction validates every observation resource and authority field"
    )]
    pub(crate) fn validate(self) -> Result<ValidatedObservationPlan, ScannerError> {
        if self.interfaces.is_empty() || self.interfaces.len() > MAX_OBSERVATION_INTERFACES {
            return Err(ScannerError::invalid(
                "start observation session",
                "interfaces must contain from one through four explicit interface names",
            ));
        }
        let mut interfaces = self.interfaces;
        interfaces.sort_unstable();
        if interfaces
            .iter()
            .any(|name| name.is_empty() || name.len() > libc::IFNAMSIZ - 1)
            || interfaces.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(ScannerError::invalid(
                "start observation session",
                "interface names must be unique, nonempty Linux interface names",
            ));
        }
        if self.protocols.is_empty() || self.protocols.len() > 5 {
            return Err(ScannerError::invalid(
                "start observation session",
                "protocols must contain one through five explicit protocol groups",
            ));
        }
        let mut protocol_names = self.protocols;
        protocol_names.sort_unstable();
        if protocol_names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ScannerError::invalid(
                "start observation session",
                "observation protocol groups must be unique",
            ));
        }
        let mut ether_types = BTreeSet::new();
        let mut control_plane = false;
        for protocol in &protocol_names {
            match protocol.as_str() {
                "arp" => {
                    ether_types.insert(0x0806);
                }
                "ipv4" => {
                    ether_types.insert(0x0800);
                }
                "ipv6" => {
                    ether_types.insert(0x86dd);
                }
                "lldp" => {
                    ether_types.insert(0x88cc);
                }
                "controlPlane" => {
                    control_plane = true;
                }
                _ => {
                    return Err(ScannerError::invalid(
                        "start observation session",
                        "unsupported observation protocol group",
                    ));
                }
            }
        }
        let duration_ms = self.duration_ms.unwrap_or(30_000);
        if duration_ms == 0 || duration_ms > MAX_OBSERVATION_DURATION_MS {
            return Err(ScannerError::invalid(
                "start observation session",
                "durationMs must be from 1 through 300000",
            ));
        }
        let snap_length = self.snap_length.unwrap_or(4_096);
        if !(64..=MAX_OBSERVATION_SNAP_LENGTH).contains(&snap_length) {
            return Err(ScannerError::invalid(
                "start observation session",
                "snapLength must be from 64 through 16384",
            ));
        }
        let max_results = self.max_results.unwrap_or(8_192);
        if max_results == 0
            || usize::try_from(max_results).unwrap_or(usize::MAX) > MAX_OBSERVATION_RESULTS
        {
            return Err(ScannerError::invalid(
                "start observation session",
                "maxResults must be from 1 through 8192",
            ));
        }
        let max_metadata_bytes = self.max_metadata_bytes.unwrap_or(16 * 1024 * 1024);
        if max_metadata_bytes == 0
            || usize::try_from(max_metadata_bytes).unwrap_or(usize::MAX)
                > MAX_OBSERVATION_METADATA_BYTES
        {
            return Err(ScannerError::invalid(
                "start observation session",
                "maxMetadataBytes must be from 1 through 16777216",
            ));
        }
        let promiscuous = self.promiscuous.unwrap_or(false);
        let risks = self.allow_risks.unwrap_or_default();
        if promiscuous && !risks.iter().any(|risk| risk == "promiscuousCapture") {
            return Err(ScannerError::invalid(
                "start observation session",
                "promiscuous capture requires allowRisks to contain promiscuousCapture",
            ));
        }
        if risks
            .iter()
            .any(|risk| risk != "passiveMetadata" && risk != "promiscuousCapture")
        {
            return Err(ScannerError::invalid(
                "start observation session",
                "allowRisks contains an unsupported observation risk",
            ));
        }
        Ok(ValidatedObservationPlan {
            interfaces,
            protocols: protocol_names,
            ether_types,
            control_plane,
            duration: Duration::from_millis(u64::from(duration_ms)),
            snap_length: usize::try_from(snap_length).unwrap_or(16_384),
            max_results: usize::try_from(max_results).unwrap_or(MAX_OBSERVATION_RESULTS),
            max_metadata_bytes: usize::try_from(max_metadata_bytes)
                .unwrap_or(MAX_OBSERVATION_METADATA_BYTES),
            include_outgoing: self.include_outgoing.unwrap_or(false),
            promiscuous,
        })
    }
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct NativeObservationMetadataField {
    pub key: String,
    pub value: Vec<u8>,
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct NativeObservationRow {
    pub sequence: String,
    pub interface_index: u32,
    pub timestamp_nanoseconds: String,
    pub wall_time_milliseconds: Option<String>,
    pub original_length: u32,
    pub captured_length: u32,
    pub packet_type: u32,
    pub direction: String,
    pub protocol: String,
    pub source_mac: Vec<u8>,
    pub destination_mac: Vec<u8>,
    pub ether_type: u32,
    pub vlan_ids: Vec<u32>,
    pub source_address: Option<String>,
    pub destination_address: Option<String>,
    pub source_port: Option<u32>,
    pub destination_port: Option<u32>,
    pub metadata: Vec<NativeObservationMetadataField>,
    pub truncated: bool,
}

#[napi(object)]
#[derive(Clone, Debug, Default)]
pub struct NativeObservationProgress {
    pub inspected: String,
    pub captured_bytes: String,
    pub accepted: String,
    pub dropped: String,
    pub kernel_dropped: String,
    pub retention_dropped: String,
    pub filtered: String,
    pub truncated: String,
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct NativeObservationBatch {
    pub state: String,
    pub rows: Vec<NativeObservationRow>,
    pub progress: NativeObservationProgress,
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct NativeObservationRun {
    pub schema_version: u32,
    pub state: String,
    pub interfaces: Vec<String>,
    pub protocols: Vec<String>,
    pub promiscuous: bool,
    pub include_outgoing: bool,
    pub progress: NativeObservationProgress,
}

#[derive(Clone, Debug, Default)]
struct Counters {
    inspected: u64,
    captured_bytes: u64,
    accepted: u64,
    dropped: u64,
    kernel_dropped: u64,
    retention_dropped: u64,
    filtered: u64,
    truncated: u64,
    metadata_bytes: usize,
}

impl From<&Counters> for NativeObservationProgress {
    fn from(value: &Counters) -> Self {
        Self {
            inspected: value.inspected.to_string(),
            captured_bytes: value.captured_bytes.to_string(),
            accepted: value.accepted.to_string(),
            dropped: value.dropped.to_string(),
            kernel_dropped: value.kernel_dropped.to_string(),
            retention_dropped: value.retention_dropped.to_string(),
            filtered: value.filtered.to_string(),
            truncated: value.truncated.to_string(),
        }
    }
}

pub(crate) struct ObservationControl {
    state: AtomicU8,
    rows: Mutex<VecDeque<NativeObservationRow>>,
    counters: Mutex<Counters>,
    readiness: Mutex<Option<Result<(), ScannerError>>>,
    ready_changed: Condvar,
}

impl ObservationControl {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            state: AtomicU8::new(RUNNING),
            rows: Mutex::new(VecDeque::new()),
            counters: Mutex::new(Counters::default()),
            readiness: Mutex::new(None),
            ready_changed: Condvar::new(),
        }
    }

    pub(crate) fn pause(&self) -> Result<(), ScannerError> {
        self.state
            .compare_exchange(RUNNING, PAUSED, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| ScannerError::lifecycle("pause observation", "session is not running"))
    }

    pub(crate) fn resume(&self) -> Result<(), ScannerError> {
        self.state
            .compare_exchange(PAUSED, RUNNING, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| ScannerError::lifecycle("resume observation", "session is not paused"))
    }

    pub(crate) fn cancel(&self) {
        if self.state.load(Ordering::Acquire) != COMPLETED {
            self.state.store(CANCELLING, Ordering::Release);
        }
    }

    #[must_use]
    pub(crate) fn state_name(&self) -> &'static str {
        state_name(self.state.load(Ordering::Acquire))
    }

    pub(crate) fn batch(&self, maximum: usize) -> NativeObservationBatch {
        let mut queue = lock(&self.rows);
        let count = maximum.min(queue.len());
        let rows = queue.drain(..count).collect();
        drop(queue);
        NativeObservationBatch {
            state: self.state_name().into(),
            rows,
            progress: NativeObservationProgress::from(&*lock(&self.counters)),
        }
    }

    pub(crate) fn progress(&self) -> NativeObservationProgress {
        NativeObservationProgress::from(&*lock(&self.counters))
    }

    pub(crate) fn ready(&self) -> Result<(), ScannerError> {
        let mut readiness = lock(&self.readiness);
        while readiness.is_none() {
            readiness = self
                .ready_changed
                .wait(readiness)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        readiness.clone().unwrap_or_else(|| {
            Err(ScannerError::internal(
                "start observation session",
                "readiness settled without a result",
            ))
        })
    }

    pub(crate) fn settle_ready(&self, result: Result<(), ScannerError>) {
        let mut readiness = lock(&self.readiness);
        if readiness.is_none() {
            *readiness = Some(result);
            self.ready_changed.notify_all();
        }
    }

    pub(crate) fn fail(&self) {
        self.state.store(FAILED, Ordering::Release);
    }
}

fn state_name(state: u8) -> &'static str {
    match state {
        RUNNING => "running",
        PAUSED => "paused",
        CANCELLING => "cancelling",
        COMPLETED => "completed",
        _ => "failed",
    }
}

struct CaptureSocket {
    descriptor: OwnedFd,
    interface_index: u32,
    membership: Option<libc::packet_mreq>,
    buffer: Vec<u8>,
}

impl Drop for CaptureSocket {
    fn drop(&mut self) {
        if let Some(membership) = self.membership {
            let length =
                libc::socklen_t::try_from(std::mem::size_of_val(&membership)).unwrap_or_default();
            // SAFETY: the membership value is fully initialized, pointer-free,
            // and lives for the exact duration of this syscall.
            unsafe {
                libc::setsockopt(
                    self.descriptor.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_DROP_MEMBERSHIP,
                    (&raw const membership).cast(),
                    length,
                );
            }
        }
    }
}

impl CaptureSocket {
    fn open(name: &str, plan: &ValidatedObservationPlan) -> Result<Self, ScannerError> {
        let c_name = std::ffi::CString::new(name).map_err(|_| {
            ScannerError::invalid("start observation session", "interface name contains NUL")
        })?;
        // SAFETY: CString guarantees a terminated readable interface name.
        let interface_index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if interface_index == 0 {
            return Err(ScannerError::system(
                "resolve observation interface",
                nix::errno::Errno::last(),
            ));
        }
        let protocol = NonZeroU32::new(u32::from(ETH_P_ALL.to_be()))
            .map(Protocol::from_raw)
            .ok_or_else(|| {
                ScannerError::internal("open observation packet socket", "zero protocol")
            })?;
        let descriptor = socket_with(
            AddressFamily::PACKET,
            SocketType::RAW,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            Some(protocol),
        )
        .map_err(|error| ScannerError::system_rustix("open observation packet socket", error))?;
        let address = libc::sockaddr_ll {
            sll_family: u16::try_from(libc::AF_PACKET).unwrap_or_default(),
            sll_protocol: ETH_P_ALL.to_be(),
            sll_ifindex: i32::try_from(interface_index).unwrap_or(i32::MAX),
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let address_length =
            libc::socklen_t::try_from(std::mem::size_of_val(&address)).map_err(|_| {
                ScannerError::internal("bind observation socket", "sockaddr size overflow")
            })?;
        // SAFETY: address is a fully initialized sockaddr_ll and the descriptor
        // is exclusively owned for this binding transaction.
        let bound = unsafe {
            libc::bind(
                descriptor.as_raw_fd(),
                (&raw const address).cast(),
                address_length,
            )
        };
        if bound != 0 {
            return Err(ScannerError::system(
                "bind observation packet socket",
                nix::errno::Errno::last(),
            ));
        }
        if !plan.include_outgoing {
            set_int_option(
                &descriptor,
                libc::SOL_PACKET,
                libc::PACKET_IGNORE_OUTGOING,
                1,
                "exclude outgoing observation packets",
            )?;
        }
        set_int_option(
            &descriptor,
            libc::SOL_PACKET,
            libc::PACKET_AUXDATA,
            1,
            "enable observation packet auxiliary metadata",
        )?;
        attach_filter(
            &descriptor,
            &plan.ether_types,
            plan.control_plane,
            plan.snap_length,
        )?;
        let membership = if plan.promiscuous {
            let request = libc::packet_mreq {
                mr_ifindex: i32::try_from(interface_index).unwrap_or(i32::MAX),
                mr_type: u16::try_from(libc::PACKET_MR_PROMISC).unwrap_or_default(),
                mr_alen: 0,
                mr_address: [0; 8],
            };
            set_membership(&descriptor, &request)?;
            Some(request)
        } else {
            None
        };
        Ok(Self {
            descriptor,
            interface_index,
            membership,
            buffer: vec![0; plan.snap_length],
        })
    }

    fn receive(&mut self) -> Result<Option<NativeObservationRow>, ScannerError> {
        let capacity = self.buffer.len();
        let (length, packet_type, checksum_status) = {
            let mut slices = [IoSliceMut::new(&mut self.buffer)];
            let mut control = nix::cmsg_space!(libc::tpacket_auxdata);
            let message = match recvmsg::<LinkAddr>(
                self.descriptor.as_raw_fd(),
                &mut slices,
                Some(&mut control),
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
            ) {
                Ok(value) => value,
                Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => return Ok(None),
                Err(error) => {
                    return Err(ScannerError::system("receive observation packet", error));
                }
            };
            let packet_type = message
                .address
                .map_or(0, |address| address.as_ref().sll_pkttype);
            let mut checksum_status = 0_u32;
            for message in message
                .cmsgs()
                .map_err(|error| ScannerError::system("read observation metadata", error))?
            {
                if let ControlMessageOwned::Unknown(unknown) = message
                    && unknown.cmsg_header.cmsg_level == libc::SOL_PACKET
                    && unknown.cmsg_header.cmsg_type == libc::PACKET_AUXDATA
                    && let Some(bytes) = unknown.data_bytes.get(..4)
                {
                    checksum_status = u32::from_ne_bytes(bytes.try_into().unwrap_or([0_u8; 4]));
                }
            }
            (message.bytes, packet_type, checksum_status)
        };
        let captured = length.min(capacity);
        let data = &self.buffer[..captured];
        Ok(Some(decode_row(
            data,
            length,
            self.interface_index,
            packet_type,
            checksum_status,
        )))
    }

    fn kernel_drops(&self) -> Result<u64, ScannerError> {
        let mut statistics = libc::tpacket_stats {
            tp_packets: 0,
            tp_drops: 0,
        };
        let mut length =
            libc::socklen_t::try_from(std::mem::size_of_val(&statistics)).unwrap_or_default();
        // SAFETY: statistics is writable for the advertised size and the
        // kernel shortens `length` to the initialized output it returned.
        let result = unsafe {
            libc::getsockopt(
                self.descriptor.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                (&raw mut statistics).cast(),
                &raw mut length,
            )
        };
        if result != 0 {
            return Err(ScannerError::system(
                "read observation packet statistics",
                nix::errno::Errno::last(),
            ));
        }
        Ok(u64::from(statistics.tp_drops))
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one finite capture lifecycle keeps readiness, budgets, statistics, and descriptor cleanup auditable"
)]
pub(crate) fn run_observation(
    plan: ValidatedObservationPlan,
    control: &ObservationControl,
) -> Result<NativeObservationRun, ScannerError> {
    let deadline = Instant::now()
        .checked_add(plan.duration)
        .ok_or_else(|| ScannerError::resource("start observation session", "deadline overflow"))?;
    let sockets = plan
        .interfaces
        .iter()
        .map(|name| CaptureSocket::open(name, &plan))
        .collect::<Result<Vec<_>, _>>();
    let mut sockets = match sockets {
        Ok(value) => {
            control.settle_ready(Ok(()));
            value
        }
        Err(error) => {
            control.settle_ready(Err(error.clone()));
            return Err(error);
        }
    };
    let mut counters = Counters::default();
    while Instant::now() < deadline
        && control.state.load(Ordering::Acquire) != CANCELLING
        && counters.inspected < MAX_INSPECTED_FRAMES
        && counters.captured_bytes < MAX_CAPTURED_BYTES
    {
        let mut progressed = false;
        for socket in &mut sockets {
            let Some(mut row) = socket.receive()? else {
                continue;
            };
            progressed = true;
            counters.inspected = counters.inspected.saturating_add(1);
            counters.captured_bytes = counters
                .captured_bytes
                .saturating_add(u64::from(row.captured_length));
            if control.state.load(Ordering::Acquire) == PAUSED {
                counters.filtered = counters.filtered.saturating_add(1);
                continue;
            }
            if row.packet_type == u32::from(libc::PACKET_OUTGOING) && !plan.include_outgoing {
                counters.filtered = counters.filtered.saturating_add(1);
                continue;
            }
            let selected_ether_type = plan
                .ether_types
                .contains(&u16::try_from(row.ether_type).unwrap_or_default());
            let selected_control = plan.control_plane
                && matches!(
                    row.protocol.as_str(),
                    "routerAdvertisement"
                        | "routerSolicitation"
                        | "ipv6Redirect"
                        | "lldp"
                        | "stp"
                        | "lacp"
                        | "vrrp"
                        | "igmp"
                        | "mld"
                        | "rip"
                        | "ospf"
                );
            if !selected_ether_type && !selected_control {
                counters.filtered = counters.filtered.saturating_add(1);
                continue;
            }
            let estimated = 160_usize
                .saturating_add(row.source_address.as_ref().map_or(0, String::len))
                .saturating_add(row.destination_address.as_ref().map_or(0, String::len))
                .saturating_add(row.metadata.iter().fold(0_usize, |total, field| {
                    total
                        .saturating_add(field.key.len())
                        .saturating_add(field.value.len())
                }));
            if usize::try_from(counters.accepted).unwrap_or(usize::MAX) >= plan.max_results
                || counters.metadata_bytes.saturating_add(estimated) > plan.max_metadata_bytes
            {
                counters.dropped = counters.dropped.saturating_add(1);
                counters.retention_dropped = counters.retention_dropped.saturating_add(1);
                continue;
            }
            row.sequence = counters.accepted.to_string();
            if row.truncated {
                counters.truncated = counters.truncated.saturating_add(1);
            }
            counters.accepted = counters.accepted.saturating_add(1);
            counters.metadata_bytes = counters.metadata_bytes.saturating_add(estimated);
            lock(&control.rows).push_back(row);
        }
        *lock(&control.counters) = counters.clone();
        if !progressed {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    counters.kernel_dropped = sockets.iter().try_fold(0_u64, |total, socket| {
        socket
            .kernel_drops()
            .map(|drops| total.saturating_add(drops))
    })?;
    counters.dropped = counters.dropped.saturating_add(counters.kernel_dropped);
    let cancelled = control.state.load(Ordering::Acquire) == CANCELLING;
    control.state.store(COMPLETED, Ordering::Release);
    *lock(&control.counters) = counters.clone();
    Ok(NativeObservationRun {
        schema_version: 1,
        state: if cancelled { "cancelled" } else { "completed" }.into(),
        interfaces: plan.interfaces,
        protocols: plan.protocols,
        promiscuous: plan.promiscuous,
        include_outgoing: plan.include_outgoing,
        progress: NativeObservationProgress::from(&counters),
    })
}

fn decode_row(
    data: &[u8],
    original_length: usize,
    interface_index: u32,
    packet_type: u8,
    checksum_status: u32,
) -> NativeObservationRow {
    let destination_mac = data.get(..6).map_or_else(Vec::new, <[u8]>::to_vec);
    let source_mac = data.get(6..12).map_or_else(Vec::new, <[u8]>::to_vec);
    let mut offset = 14_usize;
    let mut ether_type = data
        .get(12..14)
        .map_or(0, |value| u16::from_be_bytes([value[0], value[1]]));
    let mut vlan_ids = Vec::new();
    while matches!(ether_type, 0x8100 | 0x88a8) && vlan_ids.len() < 2 {
        let Some(header) = data.get(offset..offset.saturating_add(4)) else {
            break;
        };
        vlan_ids.push(u32::from(
            u16::from_be_bytes([header[0], header[1]]) & 0x0fff,
        ));
        ether_type = u16::from_be_bytes([header[2], header[3]]);
        offset = offset.saturating_add(4);
    }
    let (mut protocol, source_address, destination_address, source_port, destination_port) =
        decode_network(data, offset, ether_type, checksum_status);
    let checksum_supplied_by_kernel =
        checksum_status & (libc::TP_STATUS_CSUM_VALID | libc::TP_STATUS_CSUMNOTREADY) != 0;
    let metadata = decode_passive_frame_with_checksum_policy(
        data,
        original_length,
        !checksum_supplied_by_kernel,
    )
    .ok();
    if let Some(metadata) = &metadata
        && metadata.protocol != PassiveProtocol::Other
    {
        protocol = passive_protocol_name(metadata.protocol).into();
    }
    NativeObservationRow {
        sequence: String::new(),
        interface_index,
        timestamp_nanoseconds: monotonic_nanoseconds().to_string(),
        wall_time_milliseconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_millis().to_string()),
        original_length: u32::try_from(original_length).unwrap_or(u32::MAX),
        captured_length: u32::try_from(data.len()).unwrap_or(u32::MAX),
        packet_type: u32::from(packet_type),
        direction: if packet_type == libc::PACKET_OUTGOING {
            "outgoing"
        } else {
            "incoming"
        }
        .into(),
        protocol,
        source_mac,
        destination_mac,
        ether_type: u32::from(ether_type),
        vlan_ids,
        source_address,
        destination_address,
        source_port,
        destination_port,
        metadata: metadata.map_or_else(Vec::new, |metadata| {
            let mut fields = metadata
                .fields
                .into_iter()
                .map(|field| NativeObservationMetadataField {
                    key: field.name.into(),
                    value: field.value,
                })
                .collect::<Vec<_>>();
            if checksum_status & libc::TP_STATUS_CSUM_VALID != 0 {
                fields.push(NativeObservationMetadataField {
                    key: "transportChecksumStatus".into(),
                    value: b"kernelValidated".to_vec(),
                });
            } else if checksum_status & libc::TP_STATUS_CSUMNOTREADY != 0 {
                fields.push(NativeObservationMetadataField {
                    key: "transportChecksumStatus".into(),
                    value: b"offloadPending".to_vec(),
                });
            }
            fields
        }),
        truncated: original_length > data.len(),
    }
}

fn monotonic_nanoseconds() -> u128 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is a valid writable timespec for one clock_gettime call.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut value) };
    if result != 0 {
        return 0;
    }
    u128::try_from(value.tv_sec)
        .unwrap_or_default()
        .saturating_mul(1_000_000_000)
        .saturating_add(u128::try_from(value.tv_nsec).unwrap_or_default())
}

const fn passive_protocol_name(protocol: PassiveProtocol) -> &'static str {
    match protocol {
        PassiveProtocol::Arp => "arp",
        PassiveProtocol::Ipv6NeighborDiscovery => "ndp",
        PassiveProtocol::Dhcpv4 => "dhcpv4",
        PassiveProtocol::Dhcpv6 => "dhcpv6",
        PassiveProtocol::Mdns => "mdns",
        PassiveProtocol::Llmnr => "llmnr",
        PassiveProtocol::Nbns => "nbns",
        PassiveProtocol::Ssdp => "ssdp",
        PassiveProtocol::WsDiscovery => "wsDiscovery",
        PassiveProtocol::RouterAdvertisement => "routerAdvertisement",
        PassiveProtocol::RouterSolicitation => "routerSolicitation",
        PassiveProtocol::Ipv6Redirect => "ipv6Redirect",
        PassiveProtocol::Lldp => "lldp",
        PassiveProtocol::Stp => "stp",
        PassiveProtocol::Lacp => "lacp",
        PassiveProtocol::Vrrp => "vrrp",
        PassiveProtocol::Igmp => "igmp",
        PassiveProtocol::Mld => "mld",
        PassiveProtocol::Rip => "rip",
        PassiveProtocol::Ospf => "ospf",
        PassiveProtocol::Other => "other",
    }
}

fn decode_network(
    data: &[u8],
    offset: usize,
    ether_type: u16,
    checksum_status: u32,
) -> (
    String,
    Option<String>,
    Option<String>,
    Option<u32>,
    Option<u32>,
) {
    if ether_type == 0x0806 {
        return ("arp".into(), None, None, None, None);
    }
    if ether_type == 0x0800 {
        let Ok(packet) =
            parse_ipv4_packet(data.get(offset..).unwrap_or_default(), ParseMode::Strict)
        else {
            return ("ipv4".into(), None, None, None, None);
        };
        let source = std::net::Ipv4Addr::from(packet.source).to_string();
        let destination = std::net::Ipv4Addr::from(packet.destination).to_string();
        return network_transport_fields(
            packet.upper_layer,
            source,
            destination,
            TransportChecksumContext::Ipv4 {
                source: packet.source,
                destination: packet.destination,
            },
            true,
            checksum_status,
        );
    }
    if ether_type == 0x86dd {
        let Ok(packet) =
            parse_ipv6_packet(data.get(offset..).unwrap_or_default(), ParseMode::Strict)
        else {
            return ("ipv6".into(), None, None, None, None);
        };
        return network_transport_fields(
            packet.upper_layer,
            std::net::Ipv6Addr::from(packet.source).to_string(),
            std::net::Ipv6Addr::from(packet.destination).to_string(),
            TransportChecksumContext::Ipv6 {
                source: packet.source,
                destination: packet.destination,
            },
            false,
            checksum_status,
        );
    }
    (
        format!("etherType-0x{ether_type:04x}"),
        None,
        None,
        None,
        None,
    )
}

fn network_transport_fields(
    upper_layer: UpperLayerState<'_>,
    source: String,
    destination: String,
    checksum_context: TransportChecksumContext,
    zero_udp_checksum_allowed: bool,
    checksum_status: u32,
) -> (
    String,
    Option<String>,
    Option<String>,
    Option<u32>,
    Option<u32>,
) {
    let (protocol, payload, fragment) = match upper_layer {
        UpperLayerState::Reachable {
            protocol,
            payload,
            fragment,
        }
        | UpperLayerState::Unknown {
            protocol,
            payload,
            fragment,
        } => (protocol.get(), payload, fragment),
        UpperLayerState::Insufficient { protocol, .. }
        | UpperLayerState::NonFirstFragment { protocol, .. } => {
            return (
                network_protocol_name(protocol.get()).into(),
                Some(source),
                Some(destination),
                None,
                None,
            );
        }
        UpperLayerState::Esp { .. } | UpperLayerState::NoNextHeader { .. } => {
            return ("ip".into(), Some(source), Some(destination), None, None);
        }
    };
    let checksum_supplied_by_kernel =
        checksum_status & (libc::TP_STATUS_CSUM_VALID | libc::TP_STATUS_CSUMNOTREADY) != 0;
    let transport_valid = match protocol {
        17 => {
            let Some(header) = payload.get(..8) else {
                return ("udp".into(), Some(source), Some(destination), None, None);
            };
            let length = usize::from(u16::from_be_bytes([header[4], header[5]]));
            let checksum = u16::from_be_bytes([header[6], header[7]]);
            length >= 8
                && payload.get(..length).is_some_and(|datagram| {
                    checksum_supplied_by_kernel
                        || (zero_udp_checksum_allowed && checksum == 0)
                        || validate_transport_checksum(
                            checksum_context,
                            IpProtocol::new(17),
                            datagram,
                        )
                })
        }
        6 => payload.get(..20).is_some_and(|header| {
            let header_length = usize::from(header[12] >> 4) * 4;
            header_length >= 20
                && payload.len() >= header_length
                && (checksum_supplied_by_kernel
                    || validate_transport_checksum(checksum_context, IpProtocol::new(6), payload))
        }),
        _ => true,
    };
    let ports = transport_valid
        .then_some(payload)
        .filter(|_| fragment == FragmentState::Unfragmented)
        .and_then(|payload| payload.get(..4))
        .map(|value| {
            (
                u32::from(u16::from_be_bytes([value[0], value[1]])),
                u32::from(u16::from_be_bytes([value[2], value[3]])),
            )
        });
    let name = network_protocol_name(protocol);
    (
        name.into(),
        Some(source),
        Some(destination),
        ports
            .filter(|_| matches!(protocol, 6 | 17))
            .map(|value| value.0),
        ports
            .filter(|_| matches!(protocol, 6 | 17))
            .map(|value| value.1),
    )
}

const fn network_protocol_name(protocol: u8) -> &'static str {
    match protocol {
        1 => "icmpv4",
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _ => "ip",
    }
}

fn set_int_option(
    descriptor: &OwnedFd,
    level: i32,
    name: i32,
    value: i32,
    operation: &'static str,
) -> Result<(), ScannerError> {
    let length = libc::socklen_t::try_from(std::mem::size_of_val(&value)).unwrap_or_default();
    // SAFETY: value is initialized and borrowed only for this setsockopt call.
    let result = unsafe {
        libc::setsockopt(
            descriptor.as_raw_fd(),
            level,
            name,
            (&raw const value).cast(),
            length,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(ScannerError::system(operation, nix::errno::Errno::last()))
    }
}

fn set_membership(descriptor: &OwnedFd, request: &libc::packet_mreq) -> Result<(), ScannerError> {
    let length = libc::socklen_t::try_from(std::mem::size_of_val(request)).unwrap_or_default();
    // SAFETY: request is fully initialized and borrowed only for this syscall.
    let result = unsafe {
        libc::setsockopt(
            descriptor.as_raw_fd(),
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            (std::ptr::from_ref(request)).cast(),
            length,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(ScannerError::system(
            "enable promiscuous observation membership",
            nix::errno::Errno::last(),
        ))
    }
}

fn attach_filter(
    descriptor: &OwnedFd,
    ether_types: &BTreeSet<u16>,
    control_plane: bool,
    snap_length: usize,
) -> Result<(), ScannerError> {
    const BPF_LD_H_ABS: u16 = 0x28;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    let mut types: Vec<u16> = ether_types.iter().copied().collect();
    if !control_plane {
        types.extend([0x8100, 0x88a8]);
        types.sort_unstable();
        types.dedup();
    }
    let mut program = Vec::with_capacity(types.len().saturating_add(3));
    program.push(libc::sock_filter {
        code: BPF_LD_H_ABS,
        jt: 0,
        jf: 0,
        k: 12,
    });
    if control_plane {
        program.push(libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: u32::try_from(snap_length).unwrap_or(u32::MAX),
        });
    } else {
        for (index, ether_type) in types.iter().enumerate() {
            let jump = u8::try_from(types.len().saturating_sub(index)).map_err(|_| {
                ScannerError::internal("attach observation filter", "filter jump overflow")
            })?;
            program.push(libc::sock_filter {
                code: BPF_JMP_JEQ_K,
                jt: jump,
                jf: 0,
                k: u32::from(*ether_type),
            });
        }
        program.push(libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: 0,
        });
        program.push(libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: u32::try_from(snap_length).unwrap_or(u32::MAX),
        });
    }
    let native = libc::sock_fprog {
        len: u16::try_from(program.len()).map_err(|_| {
            ScannerError::internal("attach observation filter", "filter length overflow")
        })?,
        filter: program.as_mut_ptr(),
    };
    let length = libc::socklen_t::try_from(std::mem::size_of_val(&native)).unwrap_or_default();
    // SAFETY: the kernel copies the fprog and complete instruction array
    // during this call; both remain alive and immutable until it returns.
    let result = unsafe {
        libc::setsockopt(
            descriptor.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&raw const native).cast(),
            length,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(ScannerError::system(
            "attach observation filter",
            nix::errno::Errno::last(),
        ))
    }
}

fn lock<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_requires_explicit_promiscuous_consent() {
        let error = NativeObservationPlan {
            interfaces: vec!["lo".into()],
            protocols: vec!["ipv4".into()],
            duration_ms: Some(1),
            snap_length: Some(64),
            max_results: Some(1),
            max_metadata_bytes: Some(1),
            include_outgoing: None,
            promiscuous: Some(true),
            allow_risks: Some(vec!["passiveMetadata".into()]),
        }
        .validate()
        .expect_err("consent must be required");
        assert_eq!(error.kind, "invalidPlan");
    }

    #[test]
    fn metadata_decoder_never_retains_payload() {
        let mut dns = vec![0_u8; 12];
        dns[2..4].copy_from_slice(&0x8400_u16.to_be_bytes());
        dns[6..8].copy_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&[7, b'f', b'i', b'x', b't', b'u', b'r', b'e', 0]);
        dns.extend_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&120_u32.to_be_bytes());
        dns.extend_from_slice(&4_u16.to_be_bytes());
        dns.extend_from_slice(&[192, 0, 2, 10]);
        let udp_length = 8 + dns.len();
        let total_length = 20 + udp_length;
        let mut frame = vec![0_u8; 14 + total_length];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&u16::try_from(total_length).unwrap().to_be_bytes());
        frame[22] = 64;
        frame[23] = 17;
        frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
        frame[30..34].copy_from_slice(&[192, 0, 2, 2]);
        frame[34..36].copy_from_slice(&53_u16.to_be_bytes());
        frame[36..38].copy_from_slice(&5353_u16.to_be_bytes());
        frame[38..40].copy_from_slice(&u16::try_from(udp_length).unwrap().to_be_bytes());
        frame[42..].copy_from_slice(&dns);
        let checksum = nodenet_protocols::compute_internet_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        let row = decode_row(&frame, frame.len(), 2, 0, 0);
        assert_eq!(row.protocol, "mdns");
        assert_eq!(row.source_port, Some(53));
        assert_eq!(row.destination_port, Some(5353));
        assert_eq!(row.source_address.as_deref(), Some("192.0.2.1"));

        frame[40..42].copy_from_slice(&0x1234_u16.to_be_bytes());
        let offloaded = decode_row(&frame, frame.len(), 2, 0, libc::TP_STATUS_CSUMNOTREADY);
        assert_eq!(offloaded.protocol, "mdns");
        assert!(offloaded.metadata.iter().any(|field| {
            field.key == "transportChecksumStatus" && field.value == b"offloadPending"
        }));
    }
}
