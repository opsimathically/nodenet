use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, BorrowedFd};

use nix::libc;

use crate::error::{NativeError, Operation};
use crate::message::{ReceivedIpv4Message, ReceivedIpv6Message, ReceivedMessageFlags};
use crate::packet::{MAX_LINK_ADDRESS_LENGTH, PacketAddress, ReceivedPacketMessage};

pub const MAX_BATCH_MESSAGES: usize = 64;
pub const MAX_BATCH_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub enum BatchDestination {
    Ipv4(SocketAddrV4),
    Ipv6(SocketAddrV6),
    Packet(PacketAddress),
}

#[derive(Clone, Debug)]
pub struct BatchSendMessage {
    pub data: Vec<u8>,
    pub destination: BatchDestination,
}

#[derive(Debug)]
pub enum BatchReceivedMessage {
    Ipv4(ReceivedIpv4Message),
    Ipv6(ReceivedIpv6Message),
    Packet(ReceivedPacketMessage),
}

#[derive(Debug)]
pub struct BatchSendResult {
    pub lengths: Vec<usize>,
    pub requested: usize,
}

pub(crate) fn validate_count_and_bytes(
    count: usize,
    bytes: usize,
    operation: Operation,
) -> Result<(), NativeError> {
    if !(1..=MAX_BATCH_MESSAGES).contains(&count) {
        return Err(NativeError::invalid_argument(
            operation,
            "batch must contain 1 through 64 messages",
        ));
    }
    if bytes == 0 || bytes > MAX_BATCH_BYTES {
        return Err(NativeError::invalid_argument(
            operation,
            "batch-owned bytes must be from 1 through 1048576",
        ));
    }
    Ok(())
}

fn blank_header() -> libc::mmsghdr {
    libc::mmsghdr {
        msg_hdr: libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        },
        msg_len: 0,
    }
}

fn ipv4_native(address: SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::sa_family_t::try_from(libc::AF_INET).expect("AF_INET fits sa_family_t"),
        sin_port: address.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

fn ipv6_native(address: SocketAddrV6) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_family: libc::sa_family_t::try_from(libc::AF_INET6)
            .expect("AF_INET6 fits sa_family_t"),
        sin6_port: address.port().to_be(),
        sin6_flowinfo: address.flowinfo().to_be(),
        sin6_addr: libc::in6_addr {
            s6_addr: address.ip().octets(),
        },
        sin6_scope_id: address.scope_id(),
    }
}

#[allow(unsafe_code, reason = "D-024 reviewed stable mmsghdr/iovec send arena")]
fn call_sendmmsg(
    descriptor: BorrowedFd<'_>,
    headers: &mut [libc::mmsghdr],
) -> Result<usize, NativeError> {
    let count = u32::try_from(headers.len()).map_err(|_| {
        NativeError::invalid_argument(Operation::SendBatch, "batch length does not fit u32")
    })?;
    loop {
        // SAFETY: all pointers refer to initialized stable caller-owned vectors
        // that remain alive for the complete syscall.
        let result = unsafe {
            libc::sendmmsg(
                descriptor.as_raw_fd(),
                headers.as_mut_ptr(),
                count,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if result >= 0 {
            return usize::try_from(result).map_err(|_| {
                NativeError::internal(Operation::SendBatch, "sendmmsg count did not fit usize")
            });
        }
        let error = nix::errno::Errno::last();
        if error != nix::errno::Errno::EINTR {
            return Err(NativeError::system_nix(Operation::SendBatch, error));
        }
    }
}

fn batch_family(messages: &[BatchSendMessage]) -> Result<u8, NativeError> {
    let family = match messages.first().map(|message| &message.destination) {
        Some(BatchDestination::Ipv4(_)) => 4,
        Some(BatchDestination::Ipv6(_)) => 6,
        Some(BatchDestination::Packet(_)) => 17,
        None => {
            return Err(NativeError::invalid_argument(
                Operation::SendBatch,
                "empty batch",
            ));
        }
    };
    let mixed = messages.iter().any(|message| {
        !matches!(
            (&message.destination, family),
            (BatchDestination::Ipv4(_), 4)
                | (BatchDestination::Ipv6(_), 6)
                | (BatchDestination::Packet(_), 17)
        )
    });
    if mixed {
        Err(NativeError::invalid_argument(
            Operation::SendBatch,
            "all batch destinations must use the socket family",
        ))
    } else {
        Ok(family)
    }
}

/// Sends one validated same-family message vector in one Linux syscall.
///
/// # Errors
/// Returns validation or structured `sendmmsg(2)` errors.
#[allow(
    clippy::too_many_lines,
    reason = "the three fixed address arenas share one reviewed syscall path"
)]
pub fn send_batch(
    descriptor: BorrowedFd<'_>,
    messages: &[BatchSendMessage],
) -> Result<BatchSendResult, NativeError> {
    let total = messages.iter().try_fold(0_usize, |total, message| {
        total.checked_add(message.data.len()).ok_or_else(|| {
            NativeError::invalid_argument(Operation::SendBatch, "batch byte count overflowed")
        })
    })?;
    validate_count_and_bytes(messages.len(), total, Operation::SendBatch)?;
    if messages
        .iter()
        .any(|message| message.data.is_empty() || message.data.len() > 65_535)
    {
        return Err(NativeError::invalid_argument(
            Operation::SendBatch,
            "each batch message must contain 1 through 65535 bytes",
        ));
    }
    let family = batch_family(messages)?;
    let mut iovecs: Vec<libc::iovec> = messages
        .iter()
        .map(|message| libc::iovec {
            iov_base: message.data.as_ptr().cast_mut().cast(),
            iov_len: message.data.len(),
        })
        .collect();
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut packet = Vec::new();
    let name_length = match family {
        4 => {
            ipv4 = messages
                .iter()
                .map(|message| match message.destination {
                    BatchDestination::Ipv4(value) => ipv4_native(value),
                    _ => unreachable!("family checked"),
                })
                .collect();
            std::mem::size_of::<libc::sockaddr_in>()
        }
        6 => {
            ipv6 = messages
                .iter()
                .map(|message| match message.destination {
                    BatchDestination::Ipv6(value) => ipv6_native(value),
                    _ => unreachable!("family checked"),
                })
                .collect();
            std::mem::size_of::<libc::sockaddr_in6>()
        }
        _ => {
            packet = messages
                .iter()
                .map(|message| match &message.destination {
                    BatchDestination::Packet(value) => value.to_native(),
                    _ => unreachable!("family checked"),
                })
                .collect();
            std::mem::size_of::<libc::sockaddr_ll>()
        }
    };
    let name_length = libc::socklen_t::try_from(name_length).map_err(|_| {
        NativeError::internal(Operation::SendBatch, "address size did not fit socklen_t")
    })?;
    let mut headers: Vec<libc::mmsghdr> = (0..messages.len()).map(|_| blank_header()).collect();
    for index in 0..headers.len() {
        headers[index].msg_hdr.msg_iov = &raw mut iovecs[index];
        headers[index].msg_hdr.msg_iovlen = 1;
        headers[index].msg_hdr.msg_namelen = name_length;
        headers[index].msg_hdr.msg_name = match family {
            4 => (&raw mut ipv4[index]).cast(),
            6 => (&raw mut ipv6[index]).cast(),
            _ => (&raw mut packet[index]).cast(),
        };
    }
    let completed = call_sendmmsg(descriptor, &mut headers)?;
    let lengths = headers[..completed]
        .iter()
        .map(|header| {
            usize::try_from(header.msg_len).map_err(|_| {
                NativeError::internal(Operation::SendBatch, "message length did not fit usize")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BatchSendResult {
        lengths,
        requested: messages.len(),
    })
}

fn returned_flags(flags: i32) -> ReceivedMessageFlags {
    ReceivedMessageFlags {
        end_of_record: flags & libc::MSG_EOR != 0,
        out_of_band: flags & libc::MSG_OOB != 0,
        error_queue: false,
    }
}

#[allow(
    unsafe_code,
    reason = "D-024 reviewed initialized sockaddr storage reads"
)]
fn receive_source(
    family: u8,
    storage: &libc::sockaddr_storage,
    returned_length: libc::socklen_t,
) -> Result<BatchSource, NativeError> {
    let minimum_length = match family {
        4 => std::mem::size_of::<libc::sockaddr_in>(),
        6 => std::mem::size_of::<libc::sockaddr_in6>(),
        17 => std::mem::size_of::<libc::sockaddr_ll>(),
        _ => {
            return Err(NativeError::internal(
                Operation::ReceiveBatch,
                "unknown batch socket family",
            ));
        }
    };
    let returned_length = usize::try_from(returned_length).map_err(|_| {
        NativeError::malformed_control(
            Operation::ReceiveBatch,
            "kernel batch source length overflowed",
        )
    })?;
    if returned_length < minimum_length {
        return Err(NativeError::malformed_control(
            Operation::ReceiveBatch,
            "kernel returned a truncated batch source address",
        ));
    }
    match family {
        4 => {
            // SAFETY: recvmmsg initialized msg_name with at least sockaddr_in bytes.
            let native = unsafe {
                std::ptr::read_unaligned((std::ptr::from_ref(storage)).cast::<libc::sockaddr_in>())
            };
            if i32::from(native.sin_family) != libc::AF_INET {
                return Err(NativeError::internal(
                    Operation::ReceiveBatch,
                    "kernel returned a non-IPv4 batch source",
                ));
            }
            Ok(BatchSource::Ipv4(Ipv4Addr::from(
                native.sin_addr.s_addr.to_ne_bytes(),
            )))
        }
        6 => {
            // SAFETY: recvmmsg initialized msg_name with at least sockaddr_in6 bytes.
            let native = unsafe {
                std::ptr::read_unaligned((std::ptr::from_ref(storage)).cast::<libc::sockaddr_in6>())
            };
            if i32::from(native.sin6_family) != libc::AF_INET6 {
                return Err(NativeError::internal(
                    Operation::ReceiveBatch,
                    "kernel returned a non-IPv6 batch source",
                ));
            }
            Ok(BatchSource::Ipv6(SocketAddrV6::new(
                Ipv6Addr::from(native.sin6_addr.s6_addr),
                u16::from_be(native.sin6_port),
                u32::from_be(native.sin6_flowinfo),
                native.sin6_scope_id,
            )))
        }
        17 => {
            // SAFETY: recvmmsg initialized msg_name with at least sockaddr_ll bytes.
            let native = unsafe {
                std::ptr::read_unaligned((std::ptr::from_ref(storage)).cast::<libc::sockaddr_ll>())
            };
            if i32::from(native.sll_family) != libc::AF_PACKET || native.sll_ifindex < 0 {
                return Err(NativeError::internal(
                    Operation::ReceiveBatch,
                    "kernel returned a malformed packet batch source",
                ));
            }
            Ok(BatchSource::Packet(native))
        }
        _ => unreachable!("family validated above"),
    }
}

enum BatchSource {
    Ipv4(Ipv4Addr),
    Ipv6(SocketAddrV6),
    Packet(libc::sockaddr_ll),
}

/// Receives up to `count` same-sized messages in one nonblocking Linux syscall.
///
/// # Errors
/// Returns validation, malformed-address, or structured `recvmmsg(2)` errors.
#[allow(
    unsafe_code,
    clippy::too_many_lines,
    reason = "D-024 reviewed initialized mmsghdr receive arena and family conversion"
)]
pub fn receive_batch(
    descriptor: BorrowedFd<'_>,
    family: u8,
    count: usize,
    data_capacity: usize,
) -> Result<Vec<BatchReceivedMessage>, NativeError> {
    let bytes = count.checked_mul(data_capacity).ok_or_else(|| {
        NativeError::invalid_argument(Operation::ReceiveBatch, "batch allocation overflowed")
    })?;
    validate_count_and_bytes(count, bytes, Operation::ReceiveBatch)?;
    if data_capacity == 0 || data_capacity > 65_535 {
        return Err(NativeError::invalid_argument(
            Operation::ReceiveBatch,
            "data capacity must be from 1 through 65535",
        ));
    }
    let mut data = vec![vec![0_u8; data_capacity]; count];
    // SAFETY: all-zero is a valid initialized sockaddr_storage value.
    let mut addresses: Vec<libc::sockaddr_storage> =
        (0..count).map(|_| unsafe { std::mem::zeroed() }).collect();
    let mut iovecs: Vec<libc::iovec> = data
        .iter_mut()
        .map(|value| libc::iovec {
            iov_base: value.as_mut_ptr().cast(),
            iov_len: value.len(),
        })
        .collect();
    let mut headers: Vec<libc::mmsghdr> = (0..count).map(|_| blank_header()).collect();
    let address_capacity = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_storage>())
        .map_err(|_| {
            NativeError::internal(
                Operation::ReceiveBatch,
                "sockaddr storage size did not fit socklen_t",
            )
        })?;
    let native_count = u32::try_from(count).map_err(|_| {
        NativeError::invalid_argument(Operation::ReceiveBatch, "batch count does not fit u32")
    })?;
    for index in 0..count {
        headers[index].msg_hdr.msg_name = (&raw mut addresses[index]).cast();
        headers[index].msg_hdr.msg_namelen = address_capacity;
        headers[index].msg_hdr.msg_iov = &raw mut iovecs[index];
        headers[index].msg_hdr.msg_iovlen = 1;
    }
    let completed = loop {
        // SAFETY: all writable arenas remain stable for this nonblocking call.
        let result = unsafe {
            libc::recvmmsg(
                descriptor.as_raw_fd(),
                headers.as_mut_ptr(),
                native_count,
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                std::ptr::null_mut(),
            )
        };
        if result >= 0 {
            break usize::try_from(result).map_err(|_| {
                NativeError::internal(Operation::ReceiveBatch, "recvmmsg count did not fit usize")
            })?;
        }
        let error = nix::errno::Errno::last();
        if error != nix::errno::Errno::EINTR {
            return Err(NativeError::system_nix(Operation::ReceiveBatch, error));
        }
    };
    let mut received = Vec::with_capacity(completed);
    for index in 0..completed {
        let length = usize::try_from(headers[index].msg_len).map_err(|_| {
            NativeError::internal(Operation::ReceiveBatch, "message length did not fit usize")
        })?;
        data[index].truncate(length.min(data_capacity));
        let flags = headers[index].msg_hdr.msg_flags;
        let truncated = flags & libc::MSG_TRUNC != 0 || length > data_capacity;
        let payload = std::mem::take(&mut data[index]);
        match receive_source(
            family,
            &addresses[index],
            headers[index].msg_hdr.msg_namelen,
        )? {
            BatchSource::Ipv4(source) => {
                received.push(BatchReceivedMessage::Ipv4(ReceivedIpv4Message {
                    data: payload,
                    source_address: Some(source),
                    data_length: length,
                    data_truncated: truncated,
                    control_truncated: false,
                    flags: returned_flags(flags),
                    control: Vec::new(),
                }));
            }
            BatchSource::Ipv6(source) => {
                received.push(BatchReceivedMessage::Ipv6(ReceivedIpv6Message {
                    data: payload,
                    source_address: Some(source),
                    data_length: length,
                    data_truncated: truncated,
                    control_truncated: false,
                    flags: returned_flags(flags),
                    control: Vec::new(),
                }));
            }
            BatchSource::Packet(native) => {
                let address_length = usize::from(native.sll_halen);
                if address_length > MAX_LINK_ADDRESS_LENGTH {
                    return Err(NativeError::malformed_control(
                        Operation::ReceiveBatch,
                        "kernel packet batch source exceeded sockaddr_ll address capacity",
                    ));
                }
                received.push(BatchReceivedMessage::Packet(ReceivedPacketMessage {
                    data: payload,
                    source: PacketAddress {
                        interface_index: native.sll_ifindex.cast_unsigned(),
                        protocol: u16::from_be(native.sll_protocol),
                        hardware_address: native.sll_addr[..address_length].to_vec(),
                    },
                    hardware_type: native.sll_hatype,
                    packet_type: native.sll_pkttype,
                    data_length: length,
                    data_truncated: truncated,
                    control_truncated: false,
                    flags: returned_flags(flags),
                    auxdata: None,
                }));
            }
        }
    }
    Ok(received)
}

#[cfg(test)]
mod tests {
    use super::{MAX_BATCH_BYTES, MAX_BATCH_MESSAGES, validate_count_and_bytes};
    use crate::error::Operation;

    #[test]
    fn batch_bounds_are_independent_and_checked() {
        assert!(validate_count_and_bytes(1, 1, Operation::SendBatch).is_ok());
        assert!(
            validate_count_and_bytes(MAX_BATCH_MESSAGES, MAX_BATCH_BYTES, Operation::ReceiveBatch)
                .is_ok()
        );
        assert!(validate_count_and_bytes(0, 1, Operation::SendBatch).is_err());
        assert!(validate_count_and_bytes(MAX_BATCH_MESSAGES + 1, 1, Operation::SendBatch).is_err());
        assert!(validate_count_and_bytes(1, MAX_BATCH_BYTES + 1, Operation::ReceiveBatch).is_err());
    }
}
