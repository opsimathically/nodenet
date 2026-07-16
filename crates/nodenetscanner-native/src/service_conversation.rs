#![allow(
    unsafe_code,
    reason = "localized Linux nonblocking TCP and poll ABI adapter"
)]

use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use napi_derive::napi;
use nix::libc;
use nix::sys::socket::{SockaddrIn, SockaddrIn6};
use nodenet_protocols::{
    SERVICE_REGISTRY, ServiceCodecError, ServiceDisposition, ServiceRisk, parse_service_response,
};

use crate::error::ScannerError;

const MAX_CONVERSATION_DEADLINE_MS: u32 = 30_000;
pub(crate) const CONVERSATION_RESERVATION_BYTES: usize = 128 * 1_024;

#[napi(object)]
#[derive(Clone)]
pub struct NativeServiceIdentificationPlan {
    pub capability_id: String,
    pub target: String,
    pub port: u32,
    pub deadline_ms: u32,
    pub allow_risks: Vec<String>,
}

pub(crate) struct ValidatedServicePlan {
    capability_id: &'static str,
    target: IpAddr,
    port: u16,
    deadline: Duration,
    maximum_response_bytes: usize,
    request: Vec<u8>,
}

impl NativeServiceIdentificationPlan {
    pub(crate) fn validate(mut self) -> Result<ValidatedServicePlan, ScannerError> {
        let target = self.target.parse::<IpAddr>().map_err(|_| {
            ScannerError::invalid(
                "start service identification",
                "target must be an IPv4 or IPv6 literal",
            )
        })?;
        if matches!(target, IpAddr::V6(address) if address.is_unicast_link_local()) {
            return Err(ScannerError::invalid(
                "start service identification",
                "link-local IPv6 targets require an interface-aware API",
            ));
        }
        let port = u16::try_from(self.port)
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| {
                ScannerError::invalid(
                    "start service identification",
                    "port must be from 1 through 65535",
                )
            })?;
        if self.deadline_ms == 0 || self.deadline_ms > MAX_CONVERSATION_DEADLINE_MS {
            return Err(ScannerError::invalid(
                "start service identification",
                "deadlineMs must be from 1 through 30000",
            ));
        }
        let descriptor = SERVICE_REGISTRY
            .iter()
            .find(|entry| entry.id == self.capability_id)
            .ok_or_else(|| {
                ScannerError::invalid("start service identification", "unknown service capability")
            })?;
        if descriptor.disposition == ServiceDisposition::NoGo {
            return Err(ScannerError::invalid(
                "start service identification",
                "service capability is an executable no-go",
            ));
        }
        let required_risk = risk_name(descriptor.risk);
        self.allow_risks.sort_unstable();
        if self.allow_risks.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ScannerError::invalid(
                "start service identification",
                "allowRisks must not contain duplicates",
            ));
        }
        if self.allow_risks.len() != 1 || self.allow_risks[0] != required_risk {
            return Err(ScannerError::invalid(
                "start service identification",
                "allowRisks must contain exactly the capability's required risk",
            ));
        }
        let request = request_bytes(descriptor.id, target)?;
        if request.len() > descriptor.maximum_request_bytes {
            return Err(ScannerError::internal(
                "start service identification",
                "registered request exceeds its declared bound",
            ));
        }
        Ok(ValidatedServicePlan {
            capability_id: descriptor.id,
            target,
            port,
            deadline: Duration::from_millis(u64::from(self.deadline_ms)),
            maximum_response_bytes: descriptor.maximum_response_bytes,
            request,
        })
    }
}

fn risk_name(risk: ServiceRisk) -> &'static str {
    match risk {
        ServiceRisk::ServerFirst => "serverFirst",
        ServiceRisk::ClientNegotiation => "clientNegotiation",
        ServiceRisk::StatefulHandshake => "statefulHandshake",
        ServiceRisk::SensitiveRead => "sensitiveRead",
    }
}

fn request_bytes(capability: &str, target: IpAddr) -> Result<Vec<u8>, ScannerError> {
    match capability {
        "ssh-identification"
        | "ftp-greeting"
        | "smtp-greeting"
        | "pop3-greeting"
        | "imap-greeting"
        | "mysql-initial-handshake" => Ok(Vec::new()),
        "postgresql-ssl-request" => Ok(vec![0, 0, 0, 8, 4, 210, 22, 47]),
        "redis-ping" => Ok(b"*1\r\n$4\r\nPING\r\n".to_vec()),
        "http-head" => {
            let host = match target {
                IpAddr::V4(address) => address.to_string(),
                IpAddr::V6(address) => format!("[{address}]"),
            };
            Ok(
                format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                    .into_bytes(),
            )
        }
        _ => Err(ScannerError::invalid(
            "start service identification",
            "service capability has no admitted native conversation",
        )),
    }
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct NativeServiceField {
    pub key: String,
    pub value: Vec<u8>,
}

#[napi(object)]
#[derive(Clone, Debug)]
pub struct NativeServiceIdentificationRun {
    pub schema_version: u32,
    pub capability_id: String,
    pub target: String,
    pub port: u32,
    pub state: String,
    pub outcome: String,
    pub protocol: Option<String>,
    pub confidence: Option<String>,
    pub fields: Vec<NativeServiceField>,
    pub request_bytes: u32,
    pub response_bytes: u32,
}

pub(crate) struct ServiceControl {
    cancelled: AtomicBool,
}

impl ServiceControl {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
        }
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

pub(crate) fn run(
    plan: &ValidatedServicePlan,
    control: &ServiceControl,
) -> Result<NativeServiceIdentificationRun, ScannerError> {
    let deadline = Instant::now().checked_add(plan.deadline).ok_or_else(|| {
        ScannerError::resource("start service identification", "deadline overflow")
    })?;
    let socket = open_socket(plan.target)?;
    let outcome = connect_nonblocking(&socket, plan.target, plan.port, deadline, control)?;
    if outcome != "connected" {
        return Ok(result(plan, outcome, None, 0));
    }
    let mut written = 0_usize;
    while written < plan.request.len() {
        if !wait_socket(&socket, libc::POLLOUT | libc::POLLERR, deadline, control)? {
            return Ok(result(
                plan,
                if control.cancelled() {
                    "cancelled"
                } else {
                    "timeout"
                },
                None,
                0,
            ));
        }
        // SAFETY: the remaining request slice is readable for its exact length.
        let sent = unsafe {
            libc::send(
                socket.as_raw_fd(),
                plan.request[written..].as_ptr().cast(),
                plan.request.len() - written,
                libc::MSG_NOSIGNAL,
            )
        };
        match sent.cmp(&0) {
            std::cmp::Ordering::Greater => {
                written = written.saturating_add(usize::try_from(sent).unwrap_or(usize::MAX));
            }
            std::cmp::Ordering::Equal => return Ok(result(plan, "writeError", None, 0)),
            std::cmp::Ordering::Less => {
                let error = nix::errno::Errno::last();
                if !matches!(error, nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) {
                    return Ok(result(plan, "writeError", None, 0));
                }
            }
        }
    }
    let mut response = Vec::with_capacity(plan.maximum_response_bytes.min(4_096));
    let mut parse_scan_offset = 0_usize;
    loop {
        if response_complete(plan.capability_id, &response, &mut parse_scan_offset) {
            match parse_service_response(plan.capability_id, &response) {
                Ok(identity) => {
                    return Ok(result(plan, "identified", Some(identity), response.len()));
                }
                Err(ServiceCodecError::Malformed | ServiceCodecError::Unsupported) => {
                    return Ok(result(plan, "parserRejected", None, response.len()));
                }
                Err(ServiceCodecError::LimitExceeded) => {
                    return Ok(result(plan, "responseLimit", None, response.len()));
                }
                Err(ServiceCodecError::Truncated) => {}
            }
        }
        if response.len() >= plan.maximum_response_bytes {
            return Ok(result(plan, "responseLimit", None, response.len()));
        }
        if !wait_socket(&socket, libc::POLLIN | libc::POLLERR, deadline, control)? {
            return Ok(result(
                plan,
                if control.cancelled() {
                    "cancelled"
                } else {
                    "timeout"
                },
                None,
                response.len(),
            ));
        }
        let available = (plan.maximum_response_bytes - response.len()).min(4_096);
        let offset = response.len();
        response.resize(offset + available, 0);
        // SAFETY: the newly resized tail is writable for `available` bytes.
        let received = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                response[offset..].as_mut_ptr().cast(),
                available,
                0,
            )
        };
        if received > 0 {
            response.truncate(offset + usize::try_from(received).unwrap_or(available));
        } else {
            response.truncate(offset);
            if received == 0 {
                return Ok(result(plan, "closed", None, response.len()));
            }
            let error = nix::errno::Errno::last();
            if !matches!(error, nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) {
                return Ok(result(plan, "readError", None, response.len()));
            }
        }
    }
}

fn response_complete(capability: &str, response: &[u8], scan_offset: &mut usize) -> bool {
    match capability {
        "ssh-identification" | "ftp-greeting" | "smtp-greeting" | "pop3-greeting"
        | "imap-greeting" | "redis-ping" => {
            let start = (*scan_offset).saturating_sub(1).min(response.len());
            *scan_offset = response.len();
            response[start..].contains(&b'\n')
        }
        "http-head" => {
            let start = (*scan_offset).saturating_sub(3).min(response.len());
            *scan_offset = response.len();
            response[start..]
                .windows(4)
                .any(|window| window == b"\r\n\r\n")
        }
        "mysql-initial-handshake" => {
            if response.len() < 4 {
                return false;
            }
            let length = usize::from(response[0])
                | (usize::from(response[1]) << 8)
                | (usize::from(response[2]) << 16);
            response.len() >= length.saturating_add(4)
        }
        _ => !response.is_empty(),
    }
}

fn result(
    plan: &ValidatedServicePlan,
    outcome: &str,
    identity: Option<nodenet_protocols::ServiceIdentity>,
    response_bytes: usize,
) -> NativeServiceIdentificationRun {
    let cancelled = outcome == "cancelled";
    NativeServiceIdentificationRun {
        schema_version: 1,
        capability_id: plan.capability_id.into(),
        target: plan.target.to_string(),
        port: u32::from(plan.port),
        state: if cancelled { "cancelled" } else { "completed" }.into(),
        outcome: outcome.into(),
        protocol: identity.as_ref().map(|value| value.protocol.into()),
        confidence: identity.as_ref().map(|value| value.confidence.into()),
        fields: identity.map_or_else(Vec::new, |value| {
            value
                .fields
                .into_iter()
                .map(|(key, value)| NativeServiceField {
                    key: key.into(),
                    value,
                })
                .collect()
        }),
        request_bytes: u32::try_from(plan.request.len()).unwrap_or(u32::MAX),
        response_bytes: u32::try_from(response_bytes).unwrap_or(u32::MAX),
    }
}

fn open_socket(target: IpAddr) -> Result<OwnedFd, ScannerError> {
    // SAFETY: all values are fixed Linux socket constants.
    let descriptor = unsafe {
        libc::socket(
            if target.is_ipv4() {
                libc::AF_INET
            } else {
                libc::AF_INET6
            },
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_TCP,
        )
    };
    if descriptor < 0 {
        Err(ScannerError::system(
            "open service TCP socket",
            nix::errno::Errno::last(),
        ))
    } else {
        // SAFETY: successful socket creation returns unique descriptor ownership.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

fn connect_nonblocking(
    socket: &OwnedFd,
    target: IpAddr,
    port: u16,
    deadline: Instant,
    control: &ServiceControl,
) -> Result<&'static str, ScannerError> {
    let status = match target {
        IpAddr::V4(address) => nix::sys::socket::connect(
            socket.as_raw_fd(),
            &SockaddrIn::from(SocketAddrV4::new(address, port)),
        ),
        IpAddr::V6(address) => nix::sys::socket::connect(
            socket.as_raw_fd(),
            &SockaddrIn6::from(SocketAddrV6::new(address, port, 0, 0)),
        ),
    };
    match status {
        Ok(()) => return Ok("connected"),
        Err(nix::errno::Errno::ECONNREFUSED) => return Ok("connectRefused"),
        Err(nix::errno::Errno::EINPROGRESS | nix::errno::Errno::EALREADY) => {}
        Err(_) => return Ok("connectError"),
    }
    if !wait_socket(socket, libc::POLLOUT | libc::POLLERR, deadline, control)? {
        return Ok(if control.cancelled() {
            "cancelled"
        } else {
            "timeout"
        });
    }
    let error = socket_error(socket)?;
    Ok(match error {
        0 => "connected",
        libc::ECONNREFUSED => "connectRefused",
        _ => "connectError",
    })
}

fn socket_error(socket: &OwnedFd) -> Result<i32, ScannerError> {
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
            "read service socket error",
            nix::errno::Errno::last(),
        ))
    }
}

fn wait_socket(
    socket: &OwnedFd,
    events: i16,
    deadline: Instant,
    control: &ServiceControl,
) -> Result<bool, ScannerError> {
    loop {
        if control.cancelled() {
            return Ok(false);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        let mut descriptor = libc::pollfd {
            fd: socket.as_raw_fd(),
            events,
            revents: 0,
        };
        let timeout = i32::try_from(remaining.as_millis().clamp(1, 25)).unwrap_or(25);
        // SAFETY: descriptor points to one initialized pollfd.
        let result = unsafe { libc::poll(&raw mut descriptor, 1, timeout) };
        if result < 0 {
            let error = nix::errno::Errno::last();
            if error == nix::errno::Errno::EINTR {
                continue;
            }
            return Err(ScannerError::system("wait for service socket", error));
        }
        if result > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(ScannerError::system(
                    "wait for service socket",
                    nix::errno::Errno::EBADF,
                ));
            }
            if descriptor.revents & (events | libc::POLLHUP) != 0 {
                return Ok(true);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NativeServiceIdentificationPlan;

    #[test]
    fn duplicate_risk_authorizations_are_rejected() {
        let error = NativeServiceIdentificationPlan {
            capability_id: "redis-ping".into(),
            target: "127.0.0.1".into(),
            port: 6_379,
            deadline_ms: 1_000,
            allow_risks: vec!["clientNegotiation".into(), "clientNegotiation".into()],
        }
        .validate()
        .err()
        .expect("duplicate authorization must fail");
        assert!(error.to_string().contains("must not contain duplicates"));
    }
}
