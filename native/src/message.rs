use std::io::{IoSlice, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use nix::libc;
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, SockaddrIn, SockaddrIn6, recvmsg, sendmsg,
};

use crate::error::{NativeError, Operation};

pub const DEFAULT_CONTROL_CAPACITY: usize = 4 * 1024;
pub const MAX_CONTROL_CAPACITY: usize = 64 * 1024;
pub const MAX_MESSAGE_ALLOCATION: usize = 128 * 1024;
pub const MAX_CONTROL_MESSAGES: usize = 64;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SendMessageFlags {
    pub dont_route: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceiveMessageFlags {
    pub peek: bool,
    pub error_queue: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendControlMessage {
    Ipv4PacketInfo {
        interface_index: u32,
        source_address: Option<Ipv4Addr>,
    },
    Ipv4Ttl(u8),
    Ipv6PacketInfo {
        interface_index: u32,
        source_address: Option<Ipv6Addr>,
    },
    Ipv6HopLimit(u8),
    Ipv6TrafficClass(u8),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceivedControlMessage {
    Ipv4PacketInfo {
        interface_index: u32,
        selected_address: Ipv4Addr,
        destination_address: Ipv4Addr,
    },
    Ipv4Ttl(u8),
    Ipv4TypeOfService(u8),
    TimestampNanoseconds {
        seconds: i64,
        nanoseconds: u32,
    },
    ReceiveQueueOverflow(u32),
    Ipv4ExtendedError {
        errno: u32,
        origin: u8,
        error_type: u8,
        error_code: u8,
        info: u32,
        data: u32,
        offender: Option<Ipv4Addr>,
    },
    Ipv6PacketInfo {
        interface_index: u32,
        destination_address: Ipv6Addr,
    },
    Ipv6HopLimit(u8),
    Ipv6TrafficClass(u8),
    Ipv6ExtendedError {
        errno: u32,
        origin: u8,
        error_type: u8,
        error_code: u8,
        info: u32,
        data: u32,
        offender: Option<SocketAddrV6>,
    },
    Unknown {
        level: i32,
        message_type: i32,
        data: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceivedMessageFlags {
    pub end_of_record: bool,
    pub out_of_band: bool,
    pub error_queue: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ReceivedIpv4Message {
    pub data: Vec<u8>,
    pub source_address: Option<Ipv4Addr>,
    pub data_length: usize,
    pub data_truncated: bool,
    pub control_truncated: bool,
    pub flags: ReceivedMessageFlags,
    pub control: Vec<ReceivedControlMessage>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ReceivedIpv6Message {
    pub data: Vec<u8>,
    pub source_address: Option<SocketAddrV6>,
    pub data_length: usize,
    pub data_truncated: bool,
    pub control_truncated: bool,
    pub flags: ReceivedMessageFlags,
    pub control: Vec<ReceivedControlMessage>,
}

/// Sends one IPv4 message with typed flags and ancillary data.
///
/// # Errors
///
/// Returns a validation or structured Linux `sendmsg(2)` failure.
pub fn send_ipv4_message(
    descriptor: BorrowedFd<'_>,
    operation: Operation,
    data: &[u8],
    destination: SocketAddrV4,
    flags: SendMessageFlags,
    control: &[SendControlMessage],
) -> Result<usize, NativeError> {
    let storage = SendControlStorage::new(control)?;
    let control_messages = storage.control_messages();
    let destination = SockaddrIn::from(destination);
    let buffers = [IoSlice::new(data)];
    let mut native_flags = MsgFlags::MSG_NOSIGNAL;
    if flags.dont_route {
        native_flags |= MsgFlags::from_bits_retain(libc::MSG_DONTROUTE);
    }

    retry_nix(|| {
        sendmsg(
            descriptor.as_raw_fd(),
            &buffers,
            &control_messages,
            native_flags,
            Some(&destination),
        )
    })
    .map_err(|error| NativeError::system_nix(operation, error))
}

/// Receives one IPv4 message into bounded initialized storage.
///
/// # Errors
///
/// Returns a validation, malformed-control, unsupported-control, or structured
/// Linux `recvmsg(2)` failure.
#[allow(
    clippy::drop_non_drop,
    reason = "ending the IoSliceMut borrow before truncating its backing Vec"
)]
pub fn receive_ipv4_message(
    descriptor: BorrowedFd<'_>,
    operation: Operation,
    data_capacity: usize,
    control_capacity: usize,
    flags: ReceiveMessageFlags,
) -> Result<ReceivedIpv4Message, NativeError> {
    validate_capacities(data_capacity, control_capacity, operation)?;
    let mut data = vec![0_u8; data_capacity];
    let mut control_buffer = vec![0_u8; control_capacity];
    let mut buffers = [IoSliceMut::new(&mut data)];
    let mut native_flags = MsgFlags::MSG_TRUNC | MsgFlags::MSG_CMSG_CLOEXEC;
    if flags.peek {
        native_flags |= MsgFlags::MSG_PEEK;
    }
    if flags.error_queue {
        native_flags |= MsgFlags::MSG_ERRQUEUE;
    }

    let message = loop {
        match recvmsg::<SockaddrIn>(
            descriptor.as_raw_fd(),
            &mut buffers,
            Some(&mut control_buffer),
            native_flags,
        ) {
            Err(nix::errno::Errno::EINTR) => {}
            result => {
                break result.map_err(|error| NativeError::system_nix(operation, error))?;
            }
        }
    };

    let data_length = message.bytes;
    let data_truncated = message.flags.contains(MsgFlags::MSG_TRUNC) || data_length > data_capacity;
    let control_truncated = message.flags.contains(MsgFlags::MSG_CTRUNC);
    let source_address = message.address.map(|address| address.ip());
    let returned_flags = ReceivedMessageFlags {
        end_of_record: message.flags.contains(MsgFlags::MSG_EOR),
        out_of_band: message.flags.contains(MsgFlags::MSG_OOB),
        error_queue: message.flags.contains(MsgFlags::MSG_ERRQUEUE),
    };
    let received_control = if control_truncated {
        Vec::new()
    } else {
        let messages = message.cmsgs().map_err(|error| {
            NativeError::malformed_control(
                operation,
                format!("failed to traverse control messages: {error}"),
            )
        })?;
        convert_control_messages(messages, operation)?
    };
    drop(buffers);
    data.truncate(data_length.min(data_capacity));

    Ok(ReceivedIpv4Message {
        data,
        source_address,
        data_length,
        data_truncated,
        control_truncated,
        flags: returned_flags,
        control: received_control,
    })
}

/// Sends one IPv6 protocol message and typed controls.
///
/// # Errors
/// Returns validation or structured Linux `sendmsg(2)` errors.
pub fn send_ipv6_message(
    descriptor: BorrowedFd<'_>,
    operation: Operation,
    data: &[u8],
    destination: SocketAddrV6,
    flags: SendMessageFlags,
    control: &[SendControlMessage],
) -> Result<usize, NativeError> {
    let storage = SendControlStorage::new(control)?;
    let control_messages = storage.control_messages();
    let destination = SockaddrIn6::from(destination);
    let buffers = [IoSlice::new(data)];
    let mut native_flags = MsgFlags::MSG_NOSIGNAL;
    if flags.dont_route {
        native_flags |= MsgFlags::from_bits_retain(libc::MSG_DONTROUTE);
    }
    retry_nix(|| {
        sendmsg(
            descriptor.as_raw_fd(),
            &buffers,
            &control_messages,
            native_flags,
            Some(&destination),
        )
    })
    .map_err(|error| NativeError::system_nix(operation, error))
}

#[allow(
    clippy::drop_non_drop,
    reason = "ending IoSliceMut borrow before truncating its Vec"
)]
/// Receives one bounded IPv6 protocol message and ancillary controls.
///
/// # Errors
/// Returns validation, control decoding, or Linux `recvmsg(2)` errors.
pub fn receive_ipv6_message(
    descriptor: BorrowedFd<'_>,
    operation: Operation,
    data_capacity: usize,
    control_capacity: usize,
    flags: ReceiveMessageFlags,
) -> Result<ReceivedIpv6Message, NativeError> {
    validate_capacities(data_capacity, control_capacity, operation)?;
    let mut data = vec![0_u8; data_capacity];
    let mut control_buffer = vec![0_u8; control_capacity];
    let mut buffers = [IoSliceMut::new(&mut data)];
    let mut native_flags = MsgFlags::MSG_TRUNC | MsgFlags::MSG_CMSG_CLOEXEC;
    if flags.peek {
        native_flags |= MsgFlags::MSG_PEEK;
    }
    if flags.error_queue {
        native_flags |= MsgFlags::MSG_ERRQUEUE;
    }
    let message = loop {
        match recvmsg::<SockaddrIn6>(
            descriptor.as_raw_fd(),
            &mut buffers,
            Some(&mut control_buffer),
            native_flags,
        ) {
            Err(nix::errno::Errno::EINTR) => {}
            result => break result.map_err(|error| NativeError::system_nix(operation, error))?,
        }
    };
    let data_length = message.bytes;
    let data_truncated = message.flags.contains(MsgFlags::MSG_TRUNC) || data_length > data_capacity;
    let control_truncated = message.flags.contains(MsgFlags::MSG_CTRUNC);
    let source_address = message.address.map(SocketAddrV6::from);
    let returned_flags = ReceivedMessageFlags {
        end_of_record: message.flags.contains(MsgFlags::MSG_EOR),
        out_of_band: message.flags.contains(MsgFlags::MSG_OOB),
        error_queue: message.flags.contains(MsgFlags::MSG_ERRQUEUE),
    };
    let received_control = if control_truncated {
        Vec::new()
    } else {
        convert_control_messages(
            message.cmsgs().map_err(|error| {
                NativeError::malformed_control(
                    operation,
                    format!("failed to traverse control messages: {error}"),
                )
            })?,
            operation,
        )?
    };
    drop(buffers);
    data.truncate(data_length.min(data_capacity));
    Ok(ReceivedIpv6Message {
        data,
        source_address,
        data_length,
        data_truncated,
        control_truncated,
        flags: returned_flags,
        control: received_control,
    })
}

pub(crate) fn validate_capacities(
    data_capacity: usize,
    control_capacity: usize,
    operation: Operation,
) -> Result<(), NativeError> {
    if data_capacity == 0 || data_capacity > 65_535 {
        return Err(NativeError::invalid_argument(
            operation,
            "data capacity must be from 1 through 65535",
        ));
    }
    if control_capacity > MAX_CONTROL_CAPACITY {
        return Err(NativeError::invalid_argument(
            operation,
            format!("control capacity must not exceed {MAX_CONTROL_CAPACITY}"),
        ));
    }
    let combined = data_capacity
        .checked_add(control_capacity)
        .ok_or_else(|| NativeError::invalid_argument(operation, "message allocation overflowed"))?;
    if combined > MAX_MESSAGE_ALLOCATION {
        return Err(NativeError::invalid_argument(
            operation,
            format!("combined message allocation must not exceed {MAX_MESSAGE_ALLOCATION}"),
        ));
    }
    Ok(())
}

struct SendControlStorage {
    packet_info: Option<libc::in_pktinfo>,
    ttl: Option<libc::c_int>,
    ipv6_packet_info: Option<libc::in6_pktinfo>,
    ipv6_hop_limit: Option<libc::c_int>,
    ipv6_traffic_class: Option<i32>,
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_send_controls(messages: &[SendControlMessage]) {
    if let Ok(storage) = SendControlStorage::new(messages) {
        let _ = storage.control_messages();
    }
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_received_controls(a: u32, b: u32, data: &[u8]) {
    use nix::sys::socket::UnknownCmsg;
    use nix::sys::time::TimeSpec;

    let messages = [
        ControlMessageOwned::Ipv4Ttl(a.cast_signed()),
        ControlMessageOwned::Ipv4Tos(a as u8),
        ControlMessageOwned::ScmTimestampns(TimeSpec::new(
            i64::from(a),
            i64::from(b.cast_signed()),
        )),
        ControlMessageOwned::Ipv4PacketInfo(libc::in_pktinfo {
            ipi_ifindex: b.cast_signed(),
            ipi_spec_dst: libc::in_addr { s_addr: a },
            ipi_addr: libc::in_addr { s_addr: b },
        }),
        ControlMessageOwned::Unknown(UnknownCmsg {
            cmsg_header: libc::cmsghdr {
                cmsg_len: data.len(),
                cmsg_level: a.cast_signed(),
                cmsg_type: b.cast_signed(),
            },
            data_bytes: data.to_vec(),
        }),
    ];
    let _ = convert_control_messages(messages, Operation::ReceiveMessage);
}

impl SendControlStorage {
    fn new(messages: &[SendControlMessage]) -> Result<Self, NativeError> {
        if messages.len() > MAX_CONTROL_MESSAGES {
            return Err(NativeError::invalid_argument(
                Operation::SendMessage,
                format!("control message count must not exceed {MAX_CONTROL_MESSAGES}"),
            ));
        }
        let mut storage = Self {
            packet_info: None,
            ttl: None,
            ipv6_packet_info: None,
            ipv6_hop_limit: None,
            ipv6_traffic_class: None,
        };
        for message in messages {
            match message {
                SendControlMessage::Ipv4PacketInfo {
                    interface_index,
                    source_address,
                } => {
                    if storage.packet_info.is_some() {
                        return Err(duplicate_send_control("ipv4PacketInfo"));
                    }
                    let interface_index = i32::try_from(*interface_index).map_err(|_| {
                        NativeError::invalid_argument(
                            Operation::SendMessage,
                            "interface index must fit in a signed 32-bit integer",
                        )
                    })?;
                    storage.packet_info = Some(libc::in_pktinfo {
                        ipi_ifindex: interface_index,
                        ipi_spec_dst: ipv4_to_in_addr(
                            source_address.unwrap_or(Ipv4Addr::UNSPECIFIED),
                        ),
                        ipi_addr: ipv4_to_in_addr(Ipv4Addr::UNSPECIFIED),
                    });
                }
                SendControlMessage::Ipv4Ttl(ttl) => {
                    if storage.ttl.replace(i32::from(*ttl)).is_some() {
                        return Err(duplicate_send_control("ipv4Ttl"));
                    }
                }
                SendControlMessage::Ipv6PacketInfo {
                    interface_index,
                    source_address,
                } => {
                    if storage.ipv6_packet_info.is_some() {
                        return Err(duplicate_send_control("ipv6PacketInfo"));
                    }
                    storage.ipv6_packet_info = Some(libc::in6_pktinfo {
                        ipi6_addr: ipv6_to_in6_addr(
                            source_address.unwrap_or(Ipv6Addr::UNSPECIFIED),
                        ),
                        ipi6_ifindex: *interface_index,
                    });
                }
                SendControlMessage::Ipv6HopLimit(value) => {
                    if storage.ipv6_hop_limit.replace(i32::from(*value)).is_some() {
                        return Err(duplicate_send_control("ipv6HopLimit"));
                    }
                }
                SendControlMessage::Ipv6TrafficClass(value) => {
                    if storage
                        .ipv6_traffic_class
                        .replace(i32::from(*value))
                        .is_some()
                    {
                        return Err(duplicate_send_control("ipv6TrafficClass"));
                    }
                }
            }
        }
        Ok(storage)
    }

    fn control_messages(&self) -> Vec<ControlMessage<'_>> {
        let mut messages = Vec::with_capacity(5);
        if let Some(packet_info) = &self.packet_info {
            messages.push(ControlMessage::Ipv4PacketInfo(packet_info));
        }
        if let Some(ttl) = &self.ttl {
            messages.push(ControlMessage::Ipv4Ttl(ttl));
        }
        if let Some(info) = &self.ipv6_packet_info {
            messages.push(ControlMessage::Ipv6PacketInfo(info));
        }
        if let Some(limit) = &self.ipv6_hop_limit {
            messages.push(ControlMessage::Ipv6HopLimit(limit));
        }
        if let Some(class) = &self.ipv6_traffic_class {
            messages.push(ControlMessage::Ipv6TClass(class));
        }
        messages
    }
}

fn duplicate_send_control(name: &str) -> NativeError {
    NativeError::invalid_argument(
        Operation::SendMessage,
        format!("send control message {name} may appear at most once"),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "exhaustive typed cmsg conversion is centralized"
)]
fn convert_control_messages(
    messages: impl IntoIterator<Item = ControlMessageOwned>,
    operation: Operation,
) -> Result<Vec<ReceivedControlMessage>, NativeError> {
    let mut converted = Vec::new();
    for message in messages {
        if converted.len() >= MAX_CONTROL_MESSAGES {
            return Err(NativeError::malformed_control(
                operation,
                format!("received more than {MAX_CONTROL_MESSAGES} control messages"),
            ));
        }
        match message {
            ControlMessageOwned::Ipv4PacketInfo(info) => {
                let interface_index = u32::try_from(info.ipi_ifindex).map_err(|_| {
                    NativeError::malformed_control(
                        operation,
                        "kernel returned a negative interface index",
                    )
                })?;
                converted.push(ReceivedControlMessage::Ipv4PacketInfo {
                    interface_index,
                    selected_address: in_addr_to_ipv4(info.ipi_spec_dst),
                    destination_address: in_addr_to_ipv4(info.ipi_addr),
                });
            }
            ControlMessageOwned::Ipv4Ttl(ttl) => {
                let ttl = u8::try_from(ttl).map_err(|_| {
                    NativeError::malformed_control(
                        operation,
                        "kernel returned an IPv4 TTL outside 0 through 255",
                    )
                })?;
                converted.push(ReceivedControlMessage::Ipv4Ttl(ttl));
            }
            ControlMessageOwned::Ipv4Tos(tos) => {
                converted.push(ReceivedControlMessage::Ipv4TypeOfService(tos));
            }
            ControlMessageOwned::ScmTimestampns(timestamp) => {
                let nanoseconds = u32::try_from(timestamp.tv_nsec()).map_err(|_| {
                    NativeError::malformed_control(
                        operation,
                        "kernel returned a negative timestamp nanosecond field",
                    )
                })?;
                if nanoseconds >= 1_000_000_000 {
                    return Err(NativeError::malformed_control(
                        operation,
                        "kernel returned an invalid timestamp nanosecond field",
                    ));
                }
                converted.push(ReceivedControlMessage::TimestampNanoseconds {
                    seconds: timestamp.tv_sec(),
                    nanoseconds,
                });
            }
            ControlMessageOwned::RxqOvfl(count) => {
                converted.push(ReceivedControlMessage::ReceiveQueueOverflow(count));
            }
            ControlMessageOwned::Ipv4RecvErr(error, offender) => {
                converted.push(ReceivedControlMessage::Ipv4ExtendedError {
                    errno: error.ee_errno,
                    origin: error.ee_origin,
                    error_type: error.ee_type,
                    error_code: error.ee_code,
                    info: error.ee_info,
                    data: error.ee_data,
                    offender: offender.and_then(sockaddr_in_to_ipv4),
                });
            }
            ControlMessageOwned::Ipv6PacketInfo(info) => {
                converted.push(ReceivedControlMessage::Ipv6PacketInfo {
                    interface_index: info.ipi6_ifindex,
                    destination_address: in6_addr_to_ipv6(info.ipi6_addr),
                });
            }
            ControlMessageOwned::Ipv6HopLimit(limit) => {
                converted.push(ReceivedControlMessage::Ipv6HopLimit(
                    u8::try_from(limit).map_err(|_| {
                        NativeError::malformed_control(
                            operation,
                            "kernel returned an IPv6 hop limit outside 0 through 255",
                        )
                    })?,
                ));
            }
            ControlMessageOwned::Ipv6TClass(class) => {
                converted.push(ReceivedControlMessage::Ipv6TrafficClass(
                    u8::try_from(class).map_err(|_| {
                        NativeError::malformed_control(
                            operation,
                            "kernel returned an IPv6 traffic class outside 0 through 255",
                        )
                    })?,
                ));
            }
            ControlMessageOwned::Ipv6RecvErr(error, offender) => {
                converted.push(ReceivedControlMessage::Ipv6ExtendedError {
                    errno: error.ee_errno,
                    origin: error.ee_origin,
                    error_type: error.ee_type,
                    error_code: error.ee_code,
                    info: error.ee_info,
                    data: error.ee_data,
                    offender: offender.and_then(sockaddr_in6_to_ipv6),
                });
            }
            ControlMessageOwned::Unknown(message) => {
                converted.push(ReceivedControlMessage::Unknown {
                    level: message.cmsg_header.cmsg_level,
                    message_type: message.cmsg_header.cmsg_type,
                    data: message.data_bytes,
                });
            }
            ControlMessageOwned::ScmRights(descriptors) => {
                close_received_descriptors(descriptors);
                return Err(NativeError::unsupported(
                    operation,
                    "SCM_RIGHTS is not supported on raw network sockets",
                ));
            }
            _ => {
                return Err(NativeError::unsupported(
                    operation,
                    "received a known ancillary message unsupported by IPv4 raw sockets",
                ));
            }
        }
    }
    Ok(converted)
}

#[allow(
    unsafe_code,
    reason = "recvmsg returned new owned descriptors in SCM_RIGHTS"
)]
fn close_received_descriptors(descriptors: Vec<i32>) {
    for descriptor in descriptors {
        // SAFETY: SCM_RIGHTS returns newly installed descriptors owned by the
        // receiver. This branch never exposes them, so converting each exactly
        // once to OwnedFd and immediately dropping it is the required cleanup.
        drop(unsafe { OwnedFd::from_raw_fd(descriptor) });
    }
}

fn ipv4_to_in_addr(address: Ipv4Addr) -> libc::in_addr {
    libc::in_addr {
        s_addr: u32::from_ne_bytes(address.octets()),
    }
}

fn ipv6_to_in6_addr(address: Ipv6Addr) -> libc::in6_addr {
    libc::in6_addr {
        s6_addr: address.octets(),
    }
}
fn in6_addr_to_ipv6(address: libc::in6_addr) -> Ipv6Addr {
    Ipv6Addr::from(address.s6_addr)
}

fn sockaddr_in6_to_ipv6(address: libc::sockaddr_in6) -> Option<SocketAddrV6> {
    (i32::from(address.sin6_family) == libc::AF_INET6).then(|| {
        SocketAddrV6::new(
            in6_addr_to_ipv6(address.sin6_addr),
            u16::from_be(address.sin6_port),
            u32::from_be(address.sin6_flowinfo),
            address.sin6_scope_id,
        )
    })
}

fn in_addr_to_ipv4(address: libc::in_addr) -> Ipv4Addr {
    Ipv4Addr::from(address.s_addr.to_ne_bytes())
}

fn sockaddr_in_to_ipv4(address: libc::sockaddr_in) -> Option<Ipv4Addr> {
    (i32::from(address.sin_family) == libc::AF_INET).then(|| in_addr_to_ipv4(address.sin_addr))
}

fn retry_nix<T>(mut operation: impl FnMut() -> nix::Result<T>) -> nix::Result<T> {
    loop {
        match operation() {
            Err(nix::errno::Errno::EINTR) => {}
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use nix::libc;
    use nix::sys::socket::ControlMessageOwned;
    use nix::sys::time::TimeSpec;

    use super::{
        MAX_CONTROL_CAPACITY, ReceivedControlMessage, SendControlMessage, SendControlStorage,
        convert_control_messages, validate_capacities,
    };
    use crate::error::Operation;

    #[test]
    fn validates_combined_message_capacities() {
        assert!(
            validate_capacities(65_535, MAX_CONTROL_CAPACITY, Operation::ReceiveMessage).is_ok()
        );
        assert!(validate_capacities(0, 0, Operation::ReceiveMessage).is_err());
        assert!(validate_capacities(65_536, 0, Operation::ReceiveMessage).is_err());
        assert!(
            validate_capacities(1, MAX_CONTROL_CAPACITY + 1, Operation::ReceiveMessage).is_err()
        );
    }

    #[test]
    fn rejects_duplicate_outbound_control_messages() {
        let messages = [
            SendControlMessage::Ipv4Ttl(1),
            SendControlMessage::Ipv4Ttl(2),
        ];
        assert!(SendControlStorage::new(&messages).is_err());
    }

    #[test]
    fn converts_known_and_unknown_control_messages() {
        let messages = [
            ControlMessageOwned::Ipv4Ttl(64),
            ControlMessageOwned::Ipv4Tos(0xb8),
            ControlMessageOwned::ScmTimestampns(TimeSpec::new(123, 456)),
            ControlMessageOwned::RxqOvfl(7),
            ControlMessageOwned::Unknown(nix::sys::socket::UnknownCmsg {
                cmsg_header: nix::sys::socket::cmsghdr {
                    cmsg_len: 19,
                    cmsg_level: 222,
                    cmsg_type: 333,
                },
                data_bytes: vec![1, 2, 3],
            }),
        ];
        let converted = convert_control_messages(messages, Operation::ReceiveMessage).unwrap();
        assert_eq!(converted[0], ReceivedControlMessage::Ipv4Ttl(64));
        assert_eq!(
            converted[1],
            ReceivedControlMessage::Ipv4TypeOfService(0xb8)
        );
        assert_eq!(
            converted[2],
            ReceivedControlMessage::TimestampNanoseconds {
                seconds: 123,
                nanoseconds: 456
            }
        );
        assert_eq!(
            converted[3],
            ReceivedControlMessage::ReceiveQueueOverflow(7)
        );
        assert_eq!(
            converted[4],
            ReceivedControlMessage::Unknown {
                level: 222,
                message_type: 333,
                data: vec![1, 2, 3]
            }
        );
    }

    #[test]
    fn converts_ipv6_control_messages_without_fabricating_headers() {
        let converted = convert_control_messages(
            [
                ControlMessageOwned::Ipv6PacketInfo(libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: std::net::Ipv6Addr::LOCALHOST.octets(),
                    },
                    ipi6_ifindex: 1,
                }),
                ControlMessageOwned::Ipv6HopLimit(64),
                ControlMessageOwned::Ipv6TClass(0xb8),
            ],
            Operation::ReceiveMessage,
        )
        .unwrap();
        assert_eq!(
            converted[0],
            ReceivedControlMessage::Ipv6PacketInfo {
                interface_index: 1,
                destination_address: std::net::Ipv6Addr::LOCALHOST
            }
        );
        assert_eq!(converted[1], ReceivedControlMessage::Ipv6HopLimit(64));
        assert_eq!(converted[2], ReceivedControlMessage::Ipv6TrafficClass(0xb8));
    }

    #[test]
    fn rejects_malformed_timestamp_and_interface_index() {
        assert!(
            convert_control_messages(
                [ControlMessageOwned::ScmTimestampns(TimeSpec::new(0, -1))],
                Operation::ReceiveMessage,
            )
            .is_err()
        );
        assert!(
            convert_control_messages(
                [ControlMessageOwned::Ipv4PacketInfo(libc::in_pktinfo {
                    ipi_ifindex: -1,
                    ipi_spec_dst: libc::in_addr { s_addr: 0 },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                })],
                Operation::ReceiveMessage,
            )
            .is_err()
        );
    }
}
