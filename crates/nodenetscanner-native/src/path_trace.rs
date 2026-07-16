#![allow(
    unsafe_code,
    reason = "localized Linux socket, poll, and error-queue ABI adapters"
)]

use std::io::IoSliceMut;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use napi_derive::napi;
use nix::libc;
use nix::sys::socket::{
    ControlMessageOwned, MsgFlags, SockaddrIn, SockaddrIn6, SockaddrStorage, recvfrom, recvmsg,
    sendto, setsockopt, sockopt,
};
use nodenet_protocols::compute_internet_checksum;

use crate::error::ScannerError;

const MAX_PATH_HOP: u32 = 64;
const MAX_PATH_ATTEMPTS: u32 = 8;
const MAX_PATH_DEADLINE_MS: u32 = 300_000;
const MAX_PATH_PACING_MS: u32 = 1_000;
const MAX_PATH_RECEIVE_EVENTS: usize = 4_096;
const PATH_METADATA_RESERVATION: usize = 1_048_576;

#[napi(object)]
#[derive(Clone)]
pub struct NativePathPlan {
    pub target: String,
    pub mode: String,
    pub port: Option<u32>,
    pub first_hop: Option<u32>,
    pub maximum_hop: Option<u32>,
    pub attempts_per_hop: Option<u32>,
    pub pacing_ms: Option<u32>,
    pub deadline_ms: u32,
}

#[derive(Clone, Copy)]
enum Mode {
    IcmpEcho,
    Udp(u16),
    TcpSyn(u16),
}

#[derive(Clone, Copy)]
pub(crate) struct ValidatedPlan {
    target: IpAddr,
    mode: Mode,
    first_hop: u8,
    maximum_hop: u8,
    attempts_per_hop: u8,
    pacing: Duration,
    deadline: Duration,
}

impl NativePathPlan {
    pub(crate) fn validate(self) -> std::result::Result<ValidatedPlan, ScannerError> {
        let target = self.target.parse::<IpAddr>().map_err(|_| {
            ScannerError::invalid("start path trace", "target must be an IPv4 or IPv6 literal")
        })?;
        let port = self.port.and_then(|value| u16::try_from(value).ok());
        let mode = match (self.mode.as_str(), port) {
            ("icmpEcho", None) => Mode::IcmpEcho,
            ("udp", Some(port)) if port != 0 => Mode::Udp(port),
            ("tcpSyn", Some(port)) if port != 0 => Mode::TcpSyn(port),
            _ => {
                return Err(ScannerError::invalid(
                    "start path trace",
                    "path mode and port combination is invalid",
                ));
            }
        };
        let first_hop = self.first_hop.unwrap_or(1);
        let maximum_hop = self.maximum_hop.unwrap_or(30);
        let attempts_per_hop = self.attempts_per_hop.unwrap_or(3);
        let pacing_ms = self.pacing_ms.unwrap_or(0);
        if first_hop == 0
            || maximum_hop < first_hop
            || maximum_hop > MAX_PATH_HOP
            || attempts_per_hop == 0
            || attempts_per_hop > MAX_PATH_ATTEMPTS
            || pacing_ms > MAX_PATH_PACING_MS
            || self.deadline_ms == 0
            || self.deadline_ms > MAX_PATH_DEADLINE_MS
        {
            return Err(ScannerError::invalid(
                "start path trace",
                "path bounds exceed the finite public limits",
            ));
        }
        Ok(ValidatedPlan {
            target,
            mode,
            first_hop: u8::try_from(first_hop).unwrap_or(1),
            maximum_hop: u8::try_from(maximum_hop).unwrap_or(64),
            attempts_per_hop: u8::try_from(attempts_per_hop).unwrap_or(8),
            pacing: Duration::from_millis(u64::from(pacing_ms)),
            deadline: Duration::from_millis(u64::from(self.deadline_ms)),
        })
    }
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct NativePathAttempt {
    pub hop: u32,
    pub attempt: u32,
    pub responder: Option<String>,
    pub round_trip_microseconds: Option<String>,
    pub outcome: String,
    pub correlation: String,
    pub icmp_family: Option<u32>,
    pub icmp_type: Option<u32>,
    pub icmp_code: Option<u32>,
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct NativePathRun {
    pub schema_version: u32,
    pub target: String,
    pub mode: String,
    pub state: String,
    pub destination_reached: bool,
    pub truncated: bool,
    pub attempts: Vec<NativePathAttempt>,
}

pub(crate) struct PathControl {
    cancelled: AtomicBool,
}

impl PathControl {
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

pub(crate) const PATH_RESERVATION_BYTES: usize = PATH_METADATA_RESERVATION;

#[derive(Clone, Debug)]
struct AttemptOutcome {
    responder: Option<IpAddr>,
    outcome: &'static str,
    correlation: &'static str,
    icmp: Option<(u8, u8, u8)>,
}

pub(crate) fn run(
    plan: ValidatedPlan,
    control: &PathControl,
) -> std::result::Result<NativePathRun, ScannerError> {
    let started = Instant::now();
    let deadline = started + plan.deadline;
    let trace_nonce = trace_nonce()?;
    let mut attempts = Vec::new();
    let mut destination_reached = false;
    'hops: for hop in plan.first_hop..=plan.maximum_hop {
        for attempt in 1..=plan.attempts_per_hop {
            if control.is_cancelled() || Instant::now() >= deadline {
                break 'hops;
            }
            let sent_at = Instant::now();
            let attempt_deadline = deadline.min(sent_at + Duration::from_secs(1));
            let outcome = match plan.mode {
                Mode::TcpSyn(port) => trace_tcp(plan.target, port, hop, attempt_deadline, control)?,
                Mode::Udp(port) => trace_datagram(
                    plan.target,
                    Mode::Udp(port),
                    hop,
                    attempt,
                    attempt_deadline,
                    control,
                    trace_nonce,
                )?,
                Mode::IcmpEcho => trace_datagram(
                    plan.target,
                    Mode::IcmpEcho,
                    hop,
                    attempt,
                    attempt_deadline,
                    control,
                    trace_nonce,
                )?,
            };
            if control.is_cancelled() {
                break 'hops;
            }
            let terminal = matches!(outcome.outcome, "destinationReached" | "unreachable");
            attempts.push(NativePathAttempt {
                hop: u32::from(hop),
                attempt: u32::from(attempt),
                responder: outcome.responder.map(|value| value.to_string()),
                round_trip_microseconds: outcome
                    .responder
                    .map(|_| sent_at.elapsed().as_micros().to_string()),
                outcome: outcome.outcome.into(),
                correlation: outcome.correlation.into(),
                icmp_family: outcome.icmp.map(|value| u32::from(value.0)),
                icmp_type: outcome.icmp.map(|value| u32::from(value.1)),
                icmp_code: outcome.icmp.map(|value| u32::from(value.2)),
            });
            if terminal {
                destination_reached = outcome.outcome == "destinationReached";
                break 'hops;
            }
            let has_next_probe = attempt < plan.attempts_per_hop || hop < plan.maximum_hop;
            if has_next_probe && !pace(plan.pacing, deadline, control) {
                break 'hops;
            }
        }
    }
    let cancelled = control.is_cancelled();
    let truncated = !destination_reached && !cancelled && Instant::now() >= deadline;
    Ok(NativePathRun {
        schema_version: 1,
        target: plan.target.to_string(),
        mode: match plan.mode {
            Mode::IcmpEcho => "icmpEcho",
            Mode::Udp(_) => "udp",
            Mode::TcpSyn(_) => "tcpSyn",
        }
        .into(),
        state: if cancelled {
            "cancelled"
        } else if destination_reached {
            "completed"
        } else {
            "partial"
        }
        .into(),
        destination_reached,
        truncated,
        attempts,
    })
}

fn pace(duration: Duration, deadline: Instant, control: &PathControl) -> bool {
    let pace_deadline = Instant::now()
        .checked_add(duration)
        .unwrap_or(deadline)
        .min(deadline);
    while Instant::now() < pace_deadline {
        if control.is_cancelled() {
            return false;
        }
        let remaining = pace_deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(remaining.min(Duration::from_millis(25)));
    }
    !control.is_cancelled() && Instant::now() < deadline
}

fn trace_datagram(
    target: IpAddr,
    mode: Mode,
    hop: u8,
    attempt: u8,
    deadline: Instant,
    control: &PathControl,
    trace_nonce: [u8; 8],
) -> std::result::Result<AttemptOutcome, ScannerError> {
    let protocol = match (target, mode) {
        (_, Mode::Udp(_)) => libc::IPPROTO_UDP,
        (IpAddr::V4(_), Mode::IcmpEcho) => libc::IPPROTO_ICMP,
        (IpAddr::V6(_), Mode::IcmpEcho) => libc::IPPROTO_ICMPV6,
        _ => unreachable!("validated datagram path mode"),
    };
    let socket = open_socket(
        target,
        if matches!(mode, Mode::IcmpEcho) {
            libc::SOCK_RAW
        } else {
            libc::SOCK_DGRAM
        },
        protocol,
    )?;
    enable_error_queue(&socket, target)?;
    set_hop_limit(&socket, target, hop)?;
    let mut token = [0_u8; 16];
    token[..8].copy_from_slice(&trace_nonce);
    token[8..12].copy_from_slice(b"NNPT");
    token[12] = hop;
    token[13] = attempt;
    token[14..].copy_from_slice(&[0xa5, 0x5a]);
    let identifier = u16::from_be_bytes([trace_nonce[0], trace_nonce[1]]);
    let payload = match mode {
        Mode::Udp(_) => token.to_vec(),
        Mode::IcmpEcho => {
            let mut message = vec![
                if target.is_ipv4() { 8 } else { 128 },
                0,
                0,
                0,
                trace_nonce[0],
                trace_nonce[1],
                hop,
                attempt,
            ];
            message.extend_from_slice(&token);
            if target.is_ipv4() {
                let checksum = compute_internet_checksum(&message);
                message[2..4].copy_from_slice(&checksum.to_be_bytes());
            }
            message
        }
        Mode::TcpSyn(_) => unreachable!("TCP uses connect tracing"),
    };
    let port = match mode {
        Mode::Udp(port) => port,
        _ => 0,
    };
    send_bytes(&socket, target, port, &payload)?;
    wait_datagram(&socket, target, mode, &token, identifier, deadline, control)
}

fn trace_tcp(
    target: IpAddr,
    port: u16,
    hop: u8,
    deadline: Instant,
    control: &PathControl,
) -> std::result::Result<AttemptOutcome, ScannerError> {
    let socket = open_socket(target, libc::SOCK_STREAM, libc::IPPROTO_TCP)?;
    enable_error_queue(&socket, target)?;
    set_hop_limit(&socket, target, hop)?;
    let connect_result = connect_socket(&socket, target, port);
    if let Err(error) = connect_result
        && error != nix::errno::Errno::EINPROGRESS
        && error != nix::errno::Errno::EALREADY
    {
        if error == nix::errno::Errno::ECONNREFUSED {
            return Ok(destination(target));
        }
        return Err(ScannerError::system("connect path TCP socket", error));
    }
    loop {
        if !wait_socket(&socket, deadline, libc::POLLOUT | libc::POLLERR, control)? {
            return Ok(timeout());
        }
        if let Some(outcome) = receive_error(&socket, target, &[])? {
            return Ok(outcome);
        }
        let error = socket_error(&socket)?;
        if error == 0 || error == libc::ECONNREFUSED {
            return Ok(destination(target));
        }
        if matches!(error, libc::EINPROGRESS | libc::EALREADY) {
            continue;
        }
        return Ok(AttemptOutcome {
            responder: None,
            outcome: "unreachable",
            correlation: "weak",
            icmp: None,
        });
    }
}

fn wait_datagram(
    socket: &OwnedFd,
    target: IpAddr,
    mode: Mode,
    token: &[u8],
    identifier: u16,
    deadline: Instant,
    control: &PathControl,
) -> std::result::Result<AttemptOutcome, ScannerError> {
    let mut events = 0_usize;
    loop {
        if control.is_cancelled() {
            return Ok(timeout());
        }
        if !wait_socket(socket, deadline, libc::POLLIN | libc::POLLERR, control)? {
            return Ok(timeout());
        }
        events = events.saturating_add(1);
        if events > MAX_PATH_RECEIVE_EVENTS {
            return Ok(timeout());
        }
        if let Some(outcome) = receive_error(socket, target, token)? {
            return Ok(outcome);
        }
        let mut response = [0_u8; 4_096];
        match recvfrom::<SockaddrStorage>(socket.as_raw_fd(), &mut response) {
            Ok((bytes, source)) => {
                let source = source.and_then(|address| {
                    address
                        .as_sockaddr_in()
                        .map(|value| SocketAddr::from(*value))
                        .or_else(|| {
                            address
                                .as_sockaddr_in6()
                                .map(|value| SocketAddr::from(*value))
                        })
                });
                if direct_response_matches(
                    mode,
                    target,
                    token,
                    identifier,
                    &response[..bytes.min(response.len())],
                    source,
                ) {
                    return Ok(destination(target));
                }
            }
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => {}
            Err(error) => return Err(ScannerError::system("receive path response", error)),
        }
    }
}

fn receive_error(
    socket: &OwnedFd,
    target: IpAddr,
    token: &[u8],
) -> std::result::Result<Option<AttemptOutcome>, ScannerError> {
    let mut data = [0_u8; 4_096];
    let mut slices = [IoSliceMut::new(&mut data)];
    let mut control = nix::cmsg_space!(
        libc::sock_extended_err,
        libc::sockaddr_in,
        libc::sockaddr_in6
    );
    let message = match recvmsg::<SockaddrStorage>(
        socket.as_raw_fd(),
        &mut slices,
        Some(&mut control),
        MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
    ) {
        Ok(value) => value,
        Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => return Ok(None),
        Err(error) => return Err(ScannerError::system("receive path error queue", error)),
    };
    let received_bytes = message.bytes;
    let messages = message
        .cmsgs()
        .map_err(|error| ScannerError::system("decode path error queue", error))?
        .collect::<Vec<_>>();
    let _ = message;
    if !token.is_empty()
        && !data[..received_bytes.min(data.len())]
            .windows(token.len())
            .any(|window| window == token)
    {
        return Ok(None);
    }
    for item in messages {
        let (error, offender, family) = match item {
            ControlMessageOwned::Ipv4RecvErr(error, offender) => (
                error,
                offender.map(|address| {
                    IpAddr::V4(std::net::Ipv4Addr::from(
                        address.sin_addr.s_addr.to_ne_bytes(),
                    ))
                }),
                4,
            ),
            ControlMessageOwned::Ipv6RecvErr(error, offender) => (
                error,
                offender
                    .map(|address| IpAddr::V6(std::net::Ipv6Addr::from(address.sin6_addr.s6_addr))),
                6,
            ),
            _ => continue,
        };
        let remote_origin = matches!(
            error.ee_origin,
            libc::SO_EE_ORIGIN_ICMP | libc::SO_EE_ORIGIN_ICMP6
        );
        let responder = offender.filter(|_| remote_origin);
        let terminal = responder == Some(target)
            && ((family == 4 && error.ee_type == 3 && error.ee_code == 3)
                || (family == 6 && error.ee_type == 1 && error.ee_code == 4));
        let hop_response =
            (family == 4 && error.ee_type == 11) || (family == 6 && error.ee_type == 3);
        return Ok(Some(AttemptOutcome {
            responder,
            outcome: if terminal {
                "destinationReached"
            } else if hop_response {
                "hopResponse"
            } else if error.ee_code == 13 || (family == 6 && error.ee_code == 1) {
                "administrativelyFiltered"
            } else {
                "unreachable"
            },
            correlation: if responder.is_some() {
                "strong"
            } else {
                "weak"
            },
            icmp: Some((family, error.ee_type, error.ee_code)),
        }));
    }
    Ok(None)
}

fn open_socket(
    target: IpAddr,
    kind: i32,
    protocol: i32,
) -> std::result::Result<OwnedFd, ScannerError> {
    // SAFETY: all values are validated Linux socket constants.
    let descriptor = unsafe {
        libc::socket(
            if target.is_ipv4() {
                libc::AF_INET
            } else {
                libc::AF_INET6
            },
            kind | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    if descriptor < 0 {
        Err(ScannerError::system(
            "open path socket",
            nix::errno::Errno::last(),
        ))
    } else {
        // SAFETY: successful socket creation returns unique descriptor ownership.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

fn enable_error_queue(socket: &OwnedFd, target: IpAddr) -> std::result::Result<(), ScannerError> {
    if target.is_ipv4() {
        setsockopt(socket, sockopt::Ipv4RecvErr, &true)
    } else {
        setsockopt(socket, sockopt::Ipv6RecvErr, &true)
    }
    .map_err(|error| ScannerError::system("enable path error queue", error))
}

fn set_hop_limit(
    socket: &OwnedFd,
    target: IpAddr,
    hop: u8,
) -> std::result::Result<(), ScannerError> {
    let value = i32::from(hop);
    if target.is_ipv4() {
        setsockopt(socket, sockopt::Ipv4Ttl, &value)
    } else {
        setsockopt(socket, sockopt::Ipv6Ttl, &value)
    }
    .map_err(|error| ScannerError::system("set path hop limit", error))
}

fn send_bytes(
    socket: &OwnedFd,
    target: IpAddr,
    port: u16,
    payload: &[u8],
) -> std::result::Result<(), ScannerError> {
    let sent = match target {
        IpAddr::V4(address) => sendto(
            socket.as_raw_fd(),
            payload,
            &SockaddrIn::from(SocketAddrV4::new(address, port)),
            MsgFlags::empty(),
        ),
        IpAddr::V6(address) => sendto(
            socket.as_raw_fd(),
            payload,
            &SockaddrIn6::from(SocketAddrV6::new(address, port, 0, 0)),
            MsgFlags::empty(),
        ),
    }
    .map_err(|error| ScannerError::system("send path probe", error))?;
    if sent != payload.len() {
        return Err(ScannerError::internal(
            "send path probe",
            "short datagram send",
        ));
    }
    Ok(())
}

fn connect_socket(
    socket: &OwnedFd,
    target: IpAddr,
    port: u16,
) -> std::result::Result<(), nix::errno::Errno> {
    match target {
        IpAddr::V4(address) => nix::sys::socket::connect(
            socket.as_raw_fd(),
            &SockaddrIn::from(SocketAddrV4::new(address, port)),
        ),
        IpAddr::V6(address) => nix::sys::socket::connect(
            socket.as_raw_fd(),
            &SockaddrIn6::from(SocketAddrV6::new(address, port, 0, 0)),
        ),
    }
}

fn socket_error(socket: &OwnedFd) -> std::result::Result<i32, ScannerError> {
    let mut value = 0_i32;
    let mut length = libc::socklen_t::try_from(size_of::<i32>()).unwrap_or_default();
    // SAFETY: value is writable for the exact supplied length.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&raw mut value).cast(),
            &raw mut length,
        )
    };
    if result == 0 {
        Ok(value)
    } else {
        Err(ScannerError::system(
            "read path socket error",
            nix::errno::Errno::last(),
        ))
    }
}

fn wait_socket(
    socket: &OwnedFd,
    deadline: Instant,
    events: i16,
    control: &PathControl,
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
            events,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd.
        let result = unsafe { libc::poll(&raw mut descriptor, 1, timeout) };
        if result < 0 {
            let error = nix::errno::Errno::last();
            if error == nix::errno::Errno::EINTR {
                continue;
            }
            return Err(ScannerError::system("wait for path response", error));
        }
        if result > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(ScannerError::system(
                    "wait for path response",
                    nix::errno::Errno::EBADF,
                ));
            }
            if descriptor.revents & (events | libc::POLLHUP) != 0 {
                return Ok(true);
            }
        }
    }
}

fn direct_response_matches(
    mode: Mode,
    target: IpAddr,
    token: &[u8],
    identifier: u16,
    response: &[u8],
    source: Option<SocketAddr>,
) -> bool {
    let Some(source) = source else {
        return false;
    };
    if source.ip() != target {
        return false;
    }
    match mode {
        Mode::Udp(port) => source.port() == port,
        Mode::IcmpEcho => {
            let message = if target.is_ipv4() {
                let Some(first) = response.first() else {
                    return false;
                };
                let header_length = usize::from(first & 0x0f) * 4;
                if header_length < 20 || response.len() < header_length {
                    return false;
                }
                &response[header_length..]
            } else {
                response
            };
            let expected_type = if target.is_ipv4() { 0 } else { 129 };
            message.len() >= 8
                && message[0] == expected_type
                && message[1] == 0
                && message[4..6] == identifier.to_be_bytes()
                && message[8..].windows(token.len()).any(|item| item == token)
        }
        Mode::TcpSyn(_) => false,
    }
}

fn trace_nonce() -> std::result::Result<[u8; 8], ScannerError> {
    let mut nonce = [0_u8; 8];
    let mut offset = 0_usize;
    while offset < nonce.len() {
        // SAFETY: the remaining nonce slice is valid writable memory for the
        // exact length supplied, and getrandom retains no pointer.
        let read = unsafe {
            libc::getrandom(
                nonce[offset..].as_mut_ptr().cast(),
                nonce.len().saturating_sub(offset),
                0,
            )
        };
        if read < 0 {
            let error = nix::errno::Errno::last();
            if error == nix::errno::Errno::EINTR {
                continue;
            }
            return Err(ScannerError::system(
                "generate path correlation nonce",
                error,
            ));
        }
        if read == 0 {
            return Err(ScannerError::internal(
                "generate path correlation nonce",
                "getrandom returned no bytes",
            ));
        }
        offset = offset.saturating_add(usize::try_from(read).unwrap_or_default());
    }
    Ok(nonce)
}

const fn timeout() -> AttemptOutcome {
    AttemptOutcome {
        responder: None,
        outcome: "timeout",
        correlation: "weak",
        icmp: None,
    }
}

const fn destination(target: IpAddr) -> AttemptOutcome {
    AttemptOutcome {
        responder: Some(target),
        outcome: "destinationReached",
        correlation: "strong",
        icmp: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(pacing_ms: u32) -> NativePathPlan {
        NativePathPlan {
            target: "192.0.2.1".into(),
            mode: "udp".into(),
            port: Some(33_434),
            first_hop: Some(1),
            maximum_hop: Some(2),
            attempts_per_hop: Some(1),
            pacing_ms: Some(pacing_ms),
            deadline_ms: 1_000,
        }
    }

    #[test]
    fn pacing_is_bounded_and_cancellation_aware() {
        assert!(plan(1_000).validate().is_ok());
        assert!(plan(1_001).validate().is_err());

        let control = PathControl::new();
        control.cancel();
        assert!(!pace(
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
            &control,
        ));
    }
}
