#![allow(
    unsafe_code,
    reason = "localized Linux raw ICMPv6 socket and interface-index ABI adapters"
)]

use std::collections::BTreeSet;
use std::ffi::{CString, OsString};
use std::io::IoSliceMut;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use napi_derive::napi;
use nix::libc;
use nix::sys::socket::{
    ControlMessageOwned, MsgFlags, SockaddrIn6, recvmsg, sendto, setsockopt, sockopt,
};
use nodenet_protocols::parse_router_advertisement_metadata;

use crate::error::ScannerError;

const MAX_ROUTER_SOLICITATION_RESULTS: u32 = 64;
const MAX_ROUTER_SOLICITATION_DEADLINE_MS: u32 = 10_000;
const MAX_ROUTER_SOLICITATION_RECEIVES: u32 = 4_096;
pub(crate) const ROUTER_SOLICITATION_RESERVATION_BYTES: usize = 1_048_576;

#[napi(object)]
#[derive(Clone)]
pub struct NativeRouterSolicitationPlan {
    pub interface: String,
    pub deadline_ms: Option<u32>,
    pub max_results: Option<u32>,
    pub allow_risks: Option<Vec<String>>,
}

pub(crate) struct ValidatedPlan {
    interface: String,
    deadline: Duration,
    max_results: usize,
}

impl NativeRouterSolicitationPlan {
    pub(crate) fn validate(self) -> std::result::Result<ValidatedPlan, ScannerError> {
        if self.interface.is_empty()
            || self.interface.len() >= libc::IFNAMSIZ
            || self.interface.as_bytes().contains(&0)
        {
            return Err(ScannerError::invalid(
                "start router solicitation",
                "interface must be an explicit nonempty Linux interface name",
            ));
        }
        let risks = self.allow_risks.unwrap_or_default();
        if risks.as_slice() != ["linkMulticast"] {
            return Err(ScannerError::invalid(
                "start router solicitation",
                "active Router Solicitation requires allowRisks: [\"linkMulticast\"]",
            ));
        }
        let deadline_ms = self.deadline_ms.unwrap_or(3_000);
        if deadline_ms == 0 || deadline_ms > MAX_ROUTER_SOLICITATION_DEADLINE_MS {
            return Err(ScannerError::invalid(
                "start router solicitation",
                "deadlineMs must be from 1 through 10000",
            ));
        }
        let max_results = self.max_results.unwrap_or(16);
        if max_results == 0 || max_results > MAX_ROUTER_SOLICITATION_RESULTS {
            return Err(ScannerError::invalid(
                "start router solicitation",
                "maxResults must be from 1 through 64",
            ));
        }
        Ok(ValidatedPlan {
            interface: self.interface,
            deadline: Duration::from_millis(u64::from(deadline_ms)),
            max_results: usize::try_from(max_results).unwrap_or(64),
        })
    }
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct NativeRouterAdvertisementField {
    pub key: String,
    pub value: Vec<u8>,
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct NativeRouterAdvertisement {
    pub responder: String,
    pub interface_index: u32,
    pub round_trip_microseconds: String,
    pub metadata: Vec<NativeRouterAdvertisementField>,
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct NativeRouterSolicitationRun {
    pub schema_version: u32,
    pub interface: String,
    pub interface_index: u32,
    pub transmitted: u32,
    pub received: u32,
    pub rejected: u32,
    pub state: String,
    pub advertisements: Vec<NativeRouterAdvertisement>,
}

pub(crate) struct RouterSolicitationControl {
    cancelled: AtomicBool,
}

impl RouterSolicitationControl {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
        }
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the single finite raw-socket transaction keeps its descriptor and authority lifecycle auditable"
)]
pub(crate) fn run(
    plan: ValidatedPlan,
    control: &RouterSolicitationControl,
) -> std::result::Result<NativeRouterSolicitationRun, ScannerError> {
    let name = CString::new(plan.interface.as_bytes()).map_err(|_| {
        ScannerError::invalid("start router solicitation", "interface contains NUL")
    })?;
    // SAFETY: `name` is NUL-terminated and remains alive for this call.
    let interface_index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if interface_index == 0 {
        return Err(ScannerError::system(
            "resolve router solicitation interface",
            nix::errno::Errno::last(),
        ));
    }
    // SAFETY: arguments are constant Linux socket-domain/type/protocol values.
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_ICMPV6,
        )
    };
    if raw_fd < 0 {
        return Err(ScannerError::system(
            "open router solicitation socket",
            nix::errno::Errno::last(),
        ));
    }
    // SAFETY: successful `socket` returned a uniquely owned descriptor.
    let socket = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    setsockopt(
        &socket,
        sockopt::BindToDevice,
        &OsString::from_vec(plan.interface.as_bytes().to_vec()),
    )
    .map_err(|error| ScannerError::system("bind router solicitation interface", error))?;
    set_integer_option(
        &socket,
        libc::IPPROTO_IPV6,
        libc::IPV6_MULTICAST_IF,
        i32::try_from(interface_index).unwrap_or(i32::MAX),
        "select router solicitation interface",
    )?;
    setsockopt(&socket, sockopt::Ipv6MulticastHops, &255)
        .map_err(|error| ScannerError::system("set router solicitation hop limit", error))?;
    setsockopt(&socket, sockopt::Ipv6RecvHopLimit, &true)
        .map_err(|error| ScannerError::system("receive router advertisement hop limit", error))?;
    // Linux owns the fixed ICMPv6 checksum offset for IPPROTO_ICMPV6 raw
    // sockets and rejects an IPV6_CHECKSUM override with EINVAL.
    let destination = SockaddrIn6::from(SocketAddrV6::new(
        "ff02::2"
            .parse::<Ipv6Addr>()
            .expect("constant IPv6 address"),
        0,
        0,
        interface_index,
    ));
    let request = [133_u8, 0, 0, 0, 0, 0, 0, 0];
    sendto(
        socket.as_raw_fd(),
        &request,
        &destination,
        MsgFlags::empty(),
    )
    .map_err(|error| ScannerError::system("send router solicitation", error))?;
    let started = Instant::now();
    let deadline = started + plan.deadline;
    let mut received = 0_u32;
    let mut rejected = 0_u32;
    let mut advertisements = Vec::new();
    let mut responders = BTreeSet::new();
    while !control.is_cancelled()
        && Instant::now() < deadline
        && advertisements.len() < plan.max_results
    {
        if received >= MAX_ROUTER_SOLICITATION_RECEIVES {
            break;
        }
        if !wait_readable(&socket, deadline, control)? {
            break;
        }
        let mut bytes = [0_u8; 4_096];
        let capacity = bytes.len();
        let mut slices = [IoSliceMut::new(&mut bytes)];
        let mut control = nix::cmsg_space!(i32);
        let message = match recvmsg::<SockaddrIn6>(
            socket.as_raw_fd(),
            &mut slices,
            Some(&mut control),
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
        ) {
            Ok(value) => value,
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => continue,
            Err(error) => {
                return Err(ScannerError::system("receive router advertisement", error));
            }
        };
        received = received.saturating_add(1);
        if message.flags.contains(MsgFlags::MSG_TRUNC) || message.bytes > capacity {
            rejected = rejected.saturating_add(1);
            continue;
        }
        let hop_limit = message
            .cmsgs()
            .map_err(|error| {
                ScannerError::system("decode router advertisement control data", error)
            })?
            .find_map(|message| match message {
                ControlMessageOwned::Ipv6HopLimit(value) => Some(value),
                _ => None,
            });
        let source = message.address.map(SocketAddrV6::from);
        let payload_length = message.bytes;
        let Some(source) = source else {
            rejected = rejected.saturating_add(1);
            continue;
        };
        if hop_limit != Some(255) || !source.ip().is_unicast_link_local() {
            rejected = rejected.saturating_add(1);
            continue;
        }
        let responder = source.ip().to_string();
        let Ok(fields) = parse_router_advertisement_metadata(&bytes[..payload_length]) else {
            rejected = rejected.saturating_add(1);
            continue;
        };
        if !responders.insert(responder.clone()) {
            continue;
        }
        advertisements.push(NativeRouterAdvertisement {
            responder,
            interface_index,
            round_trip_microseconds: started.elapsed().as_micros().to_string(),
            metadata: fields
                .into_iter()
                .map(|field| NativeRouterAdvertisementField {
                    key: field.name.into(),
                    value: field.value,
                })
                .collect(),
        });
    }
    Ok(NativeRouterSolicitationRun {
        schema_version: 1,
        interface: plan.interface,
        interface_index,
        transmitted: 1,
        received,
        rejected,
        state: if control.is_cancelled() {
            "cancelled"
        } else {
            "completed"
        }
        .into(),
        advertisements,
    })
}

fn set_integer_option(
    socket: &OwnedFd,
    level: i32,
    option: i32,
    value: i32,
    operation: &'static str,
) -> std::result::Result<(), ScannerError> {
    // SAFETY: the value pointer is valid for its exact advertised length.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&raw const value).cast(),
            libc::socklen_t::try_from(size_of::<i32>()).unwrap_or_default(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(ScannerError::system(operation, nix::errno::Errno::last()))
    }
}

fn wait_readable(
    socket: &OwnedFd,
    deadline: Instant,
    control: &RouterSolicitationControl,
) -> std::result::Result<bool, ScannerError> {
    loop {
        if control.is_cancelled() {
            return Ok(false);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        let timeout = i32::try_from(remaining.as_millis().clamp(1, 25)).unwrap_or(25);
        let mut descriptor = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `descriptor` points to one initialized pollfd for the call.
        let result = unsafe { libc::poll(&raw mut descriptor, 1, timeout) };
        if result < 0 {
            let error = nix::errno::Errno::last();
            if error == nix::errno::Errno::EINTR {
                continue;
            }
            return Err(ScannerError::system("wait for router advertisement", error));
        }
        if result > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(ScannerError::system(
                    "wait for router advertisement",
                    nix::errno::Errno::EBADF,
                ));
            }
            if descriptor.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                return Ok(true);
            }
        }
    }
}
