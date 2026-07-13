use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use nix::libc;

use crate::error::{NativeError, Operation};

pub const MAX_RAW_OPTION_LENGTH: usize = 4096;
pub const MAX_CLASSIC_BPF_INSTRUCTIONS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassicBpfInstruction {
    pub code: u16,
    pub jump_true: u8,
    pub jump_false: u8,
    pub value: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketMembershipKind {
    Promiscuous,
    AllMulticast,
    Multicast,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketMembership {
    pub interface_index: u32,
    pub kind: PacketMembershipKind,
    pub address: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketStatistics {
    pub packets: u32,
    pub drops: u32,
}

fn option_length(length: usize, operation: Operation) -> Result<libc::socklen_t, NativeError> {
    if length > MAX_RAW_OPTION_LENGTH {
        return Err(NativeError::invalid_argument(
            operation,
            "socket option length exceeds 4096 bytes",
        ));
    }
    libc::socklen_t::try_from(length).map_err(|_| {
        NativeError::invalid_argument(operation, "socket option length does not fit socklen_t")
    })
}

fn reserved_option(level: i32, name: i32) -> bool {
    (level == libc::SOL_SOCKET
        && matches!(
            name,
            libc::SO_ATTACH_FILTER
                | libc::SO_ATTACH_BPF
                | libc::SO_DETACH_FILTER
                | libc::SO_LOCK_FILTER
                | libc::SO_BINDTODEVICE
        ))
        || (level == libc::SOL_PACKET
            && matches!(
                name,
                libc::PACKET_ADD_MEMBERSHIP
                    | libc::PACKET_DROP_MEMBERSHIP
                    | libc::PACKET_FANOUT
                    | libc::PACKET_RX_RING
                    | libc::PACKET_TX_RING
                    | libc::PACKET_STATISTICS
                    | libc::PACKET_AUXDATA
            ))
        || (level == libc::IPPROTO_IP
            && matches!(
                name,
                libc::IP_HDRINCL
                    | libc::IP_FREEBIND
                    | libc::IP_TRANSPARENT
                    | libc::IP_MTU_DISCOVER
                    | libc::IP_TTL
                    | libc::IP_TOS
                    | libc::IP_PKTINFO
                    | libc::IP_RECVTTL
                    | libc::IP_RECVTOS
                    | libc::IP_RECVERR
                    | libc::IP_MULTICAST_TTL
                    | libc::IP_MULTICAST_LOOP
            ))
        || (level == libc::IPPROTO_IPV6
            && matches!(
                name,
                libc::IPV6_CHECKSUM
                    | libc::IPV6_MTU_DISCOVER
                    | libc::IPV6_UNICAST_HOPS
                    | libc::IPV6_TCLASS
                    | libc::IPV6_RECVPKTINFO
                    | libc::IPV6_RECVHOPLIMIT
                    | libc::IPV6_RECVTCLASS
                    | libc::IPV6_RECVERR
                    | libc::IPV6_MULTICAST_HOPS
                    | libc::IPV6_MULTICAST_LOOP
                    | libc::IPV6_V6ONLY
            ))
        || (level == libc::SOL_SOCKET
            && matches!(
                name,
                libc::SO_PRIORITY
                    | libc::SO_MARK
                    | libc::SO_RCVBUF
                    | libc::SO_SNDBUF
                    | libc::SO_BROADCAST
                    | libc::SO_TIMESTAMPNS
                    | libc::SO_RXQ_OVFL
                    | libc::SO_BUSY_POLL
            ))
}

pub(crate) fn validate_raw_option(
    level: i32,
    name: i32,
    operation: Operation,
) -> Result<(), NativeError> {
    if level < 0 || name < 0 {
        return Err(NativeError::invalid_argument(
            operation,
            "socket option level and name must be nonnegative signed integers",
        ));
    }
    if reserved_option(level, name) {
        return Err(NativeError::unsupported(
            operation,
            "socket option is reserved for a typed ownership-aware API",
        ));
    }
    Ok(())
}

/// Gets one bounded initialized opaque socket-option value.
///
/// # Errors
/// Returns validation or structured Linux errors.
#[allow(
    unsafe_code,
    reason = "D-023 reviewed bounded getsockopt output adapter"
)]
pub fn get_raw_option(
    descriptor: BorrowedFd<'_>,
    level: i32,
    name: i32,
    maximum: usize,
) -> Result<Vec<u8>, NativeError> {
    validate_raw_option(level, name, Operation::GetSocketOption)?;
    if maximum == 0 {
        return Err(NativeError::invalid_argument(
            Operation::GetSocketOption,
            "maximum option length must be nonzero",
        ));
    }
    let mut length = option_length(maximum, Operation::GetSocketOption)?;
    let mut value = vec![0_u8; maximum];
    // SAFETY: value is initialized writable storage of `length` bytes; Linux
    // receives the address of a valid socklen_t and cannot exceed that bound.
    let result = unsafe {
        libc::getsockopt(
            descriptor.as_raw_fd(),
            level,
            name,
            value.as_mut_ptr().cast(),
            &raw mut length,
        )
    };
    nix::errno::Errno::result(result)
        .map_err(|error| NativeError::system_nix(Operation::GetSocketOption, error))?;
    let returned = usize::try_from(length).map_err(|_| {
        NativeError::internal(
            Operation::GetSocketOption,
            "kernel option length did not fit usize",
        )
    })?;
    if returned > maximum {
        return Err(NativeError::internal(
            Operation::GetSocketOption,
            "kernel option length exceeded supplied storage",
        ));
    }
    value.truncate(returned);
    Ok(value)
}

/// Sets one bounded initialized opaque socket-option value.
///
/// # Errors
/// Returns validation or structured Linux errors.
#[allow(
    unsafe_code,
    reason = "D-023 reviewed bounded setsockopt input adapter"
)]
pub fn set_raw_option(
    descriptor: BorrowedFd<'_>,
    level: i32,
    name: i32,
    value: &[u8],
) -> Result<(), NativeError> {
    validate_raw_option(level, name, Operation::SetSocketOption)?;
    let length = option_length(value.len(), Operation::SetSocketOption)?;
    // SAFETY: value is initialized immutable storage valid for the syscall and
    // length is its exact checked byte length.
    let result = unsafe {
        libc::setsockopt(
            descriptor.as_raw_fd(),
            level,
            name,
            value.as_ptr().cast(),
            length,
        )
    };
    nix::errno::Errno::result(result)
        .map(drop)
        .map_err(|error| NativeError::system_nix(Operation::SetSocketOption, error))
}

pub(crate) fn validate_classic_bpf(program: &[ClassicBpfInstruction]) -> Result<(), NativeError> {
    if program.is_empty() || program.len() > MAX_CLASSIC_BPF_INSTRUCTIONS {
        return Err(NativeError::invalid_argument(
            Operation::AttachFilter,
            "classic BPF program must contain 1 through 4096 instructions",
        ));
    }
    for (index, instruction) in program.iter().enumerate() {
        let class = instruction.code & 0x07;
        if class == 0x05 {
            let operation = instruction.code & 0xf0;
            if operation == 0x00 {
                let target = index
                    .checked_add(1)
                    .and_then(|value| value.checked_add(instruction.value as usize));
                if target.is_none_or(|target| target >= program.len()) {
                    return Err(NativeError::invalid_argument(
                        Operation::AttachFilter,
                        "classic BPF absolute jump leaves the program",
                    ));
                }
            } else {
                for offset in [instruction.jump_true, instruction.jump_false] {
                    if index + 1 + usize::from(offset) >= program.len() {
                        return Err(NativeError::invalid_argument(
                            Operation::AttachFilter,
                            "classic BPF conditional jump leaves the program",
                        ));
                    }
                }
            }
        }
    }
    if program
        .last()
        .is_none_or(|instruction| instruction.code & 0x07 != 0x06)
    {
        return Err(NativeError::invalid_argument(
            Operation::AttachFilter,
            "classic BPF program must end with RET",
        ));
    }
    Ok(())
}

/// Attaches a copied classic BPF program after structural validation.
///
/// # Errors
/// Returns validation, kernel verifier, or Linux option errors.
#[allow(
    unsafe_code,
    reason = "D-023 reviewed transient sock_fprog pointer adapter"
)]
pub fn attach_classic_bpf(
    descriptor: BorrowedFd<'_>,
    program: &[ClassicBpfInstruction],
) -> Result<(), NativeError> {
    validate_classic_bpf(program)?;
    let native: Vec<libc::sock_filter> = program
        .iter()
        .map(|instruction| libc::sock_filter {
            code: instruction.code,
            jt: instruction.jump_true,
            jf: instruction.jump_false,
            k: instruction.value,
        })
        .collect();
    let mut native = native;
    let descriptor_program = libc::sock_fprog {
        len: u16::try_from(native.len()).map_err(|_| {
            NativeError::invalid_argument(
                Operation::AttachFilter,
                "classic BPF program length does not fit u16",
            )
        })?,
        filter: native.as_mut_ptr(),
    };
    let length =
        libc::socklen_t::try_from(std::mem::size_of::<libc::sock_fprog>()).map_err(|_| {
            NativeError::internal(
                Operation::AttachFilter,
                "sock_fprog size does not fit socklen_t",
            )
        })?;
    // SAFETY: sock_fprog and its initialized instruction Vec remain alive and
    // immovable for the call; Linux copies the program before returning.
    let result = unsafe {
        libc::setsockopt(
            descriptor.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&raw const descriptor_program).cast(),
            length,
        )
    };
    nix::errno::Errno::result(result)
        .map(drop)
        .map_err(|error| NativeError::system_nix(Operation::AttachFilter, error))
}

#[allow(
    unsafe_code,
    reason = "D-023 reviewed initialized scalar setsockopt adapter"
)]
fn set_integer_option(
    descriptor: BorrowedFd<'_>,
    level: i32,
    name: i32,
    value: i32,
    operation: Operation,
) -> Result<(), NativeError> {
    let bytes = value.to_ne_bytes();
    let length = libc::socklen_t::try_from(bytes.len()).map_err(|_| {
        NativeError::internal(operation, "integer option size does not fit socklen_t")
    })?;
    // SAFETY: bytes is initialized fixed-size input valid for this call.
    let result = unsafe {
        libc::setsockopt(
            descriptor.as_raw_fd(),
            level,
            name,
            bytes.as_ptr().cast(),
            length,
        )
    };
    nix::errno::Errno::result(result)
        .map(drop)
        .map_err(|error| NativeError::system_nix(operation, error))
}

#[allow(
    unsafe_code,
    reason = "D-023 reviewed initialized scalar getsockopt adapter"
)]
/// Reads one fixed-width integer option through the reviewed typed adapter.
///
/// # Errors
/// Returns a structured Linux error or an internal size-conversion failure.
pub fn get_typed_integer_option(
    descriptor: BorrowedFd<'_>,
    level: i32,
    name: i32,
    operation: Operation,
) -> Result<i32, NativeError> {
    let mut value = 0_i32;
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<i32>())
        .map_err(|_| NativeError::internal(operation, "integer size does not fit socklen_t"))?;
    // SAFETY: value and length are initialized fixed-size writable outputs.
    let result = unsafe {
        libc::getsockopt(
            descriptor.as_raw_fd(),
            level,
            name,
            (&raw mut value).cast(),
            &raw mut length,
        )
    };
    nix::errno::Errno::result(result).map_err(|error| NativeError::system_nix(operation, error))?;
    Ok(value)
}

/// Writes one fixed-width integer option through the reviewed typed adapter.
///
/// # Errors
/// Returns a structured Linux error or an internal size-conversion failure.
pub fn set_typed_integer_option(
    descriptor: BorrowedFd<'_>,
    level: i32,
    name: i32,
    value: i32,
    operation: Operation,
) -> Result<(), NativeError> {
    set_integer_option(descriptor, level, name, value, operation)
}

#[allow(unsafe_code, reason = "D-023 reviewed scalar option helper")]
/// Detaches the socket's currently installed classic or extended BPF filter.
///
/// # Errors
/// Returns the structured Linux option error, including a locked-filter denial.
pub fn detach_filter(descriptor: BorrowedFd<'_>) -> Result<(), NativeError> {
    set_integer_option(
        descriptor,
        libc::SOL_SOCKET,
        libc::SO_DETACH_FILTER,
        0,
        Operation::AttachFilter,
    )
}
#[allow(unsafe_code, reason = "D-023 reviewed scalar option helper")]
/// Permanently locks the socket's currently installed filter set.
///
/// # Errors
/// Returns the structured Linux option error.
pub fn lock_filter(descriptor: BorrowedFd<'_>) -> Result<(), NativeError> {
    set_integer_option(
        descriptor,
        libc::SOL_SOCKET,
        libc::SO_LOCK_FILTER,
        1,
        Operation::AttachFilter,
    )
}

/// Attaches a compatible eBPF program through a temporary close-on-exec duplicate.
///
/// # Errors
/// Returns validation, duplication, compatibility, permission, or Linux option errors.
#[allow(
    unsafe_code,
    reason = "D-023 reviewed caller-fd duplication and immediate ownership"
)]
pub fn attach_ebpf(descriptor: BorrowedFd<'_>, caller_fd: i32) -> Result<(), NativeError> {
    if caller_fd < 0 {
        return Err(NativeError::invalid_argument(
            Operation::AttachFilter,
            "eBPF fd must be nonnegative",
        ));
    }
    // SAFETY: fcntl does not consume caller_fd. A nonnegative result is a new
    // descriptor owned by this function and converted exactly once to OwnedFd.
    let duplicated = unsafe { libc::fcntl(caller_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(NativeError::system_nix(
            Operation::AttachFilter,
            nix::errno::Errno::last(),
        ));
    }
    let duplicated = unsafe { OwnedFd::from_raw_fd(duplicated) };
    set_integer_option(
        descriptor,
        libc::SOL_SOCKET,
        libc::SO_ATTACH_BPF,
        duplicated.as_raw_fd(),
        Operation::AttachFilter,
    )
}

/// Adds or drops one deterministic packet membership.
///
/// # Errors
/// Returns validation or structured Linux errors.
#[allow(unsafe_code, reason = "D-023 reviewed fixed-size packet_mreq adapter")]
pub fn set_packet_membership(
    descriptor: BorrowedFd<'_>,
    membership: &PacketMembership,
    add: bool,
) -> Result<(), NativeError> {
    if membership.interface_index == 0
        || membership.interface_index > i32::MAX.cast_unsigned()
        || membership.address.len() > 8
    {
        return Err(NativeError::invalid_argument(
            Operation::PacketMembership,
            "invalid packet membership interface/address",
        ));
    }
    let mut native = libc::packet_mreq {
        mr_ifindex: membership.interface_index.cast_signed(),
        mr_type: u16::try_from(match membership.kind {
            PacketMembershipKind::Promiscuous => libc::PACKET_MR_PROMISC,
            PacketMembershipKind::AllMulticast => libc::PACKET_MR_ALLMULTI,
            PacketMembershipKind::Multicast => libc::PACKET_MR_MULTICAST,
        })
        .map_err(|_| {
            NativeError::internal(
                Operation::PacketMembership,
                "packet membership type does not fit u16",
            )
        })?,
        mr_alen: u16::try_from(membership.address.len()).map_err(|_| {
            NativeError::invalid_argument(
                Operation::PacketMembership,
                "membership address length does not fit u16",
            )
        })?,
        mr_address: [0; 8],
    };
    native.mr_address[..membership.address.len()].copy_from_slice(&membership.address);
    let length =
        libc::socklen_t::try_from(std::mem::size_of::<libc::packet_mreq>()).map_err(|_| {
            NativeError::internal(
                Operation::PacketMembership,
                "packet_mreq size does not fit socklen_t",
            )
        })?;
    let name = if add {
        libc::PACKET_ADD_MEMBERSHIP
    } else {
        libc::PACKET_DROP_MEMBERSHIP
    };
    // SAFETY: native is a fully initialized pointer-free packet_mreq valid for the call.
    let result = unsafe {
        libc::setsockopt(
            descriptor.as_raw_fd(),
            libc::SOL_PACKET,
            name,
            (&raw const native).cast(),
            length,
        )
    };
    nix::errno::Errno::result(result)
        .map(drop)
        .map_err(|error| NativeError::system_nix(Operation::PacketMembership, error))
}

#[allow(unsafe_code, reason = "D-023 reviewed scalar packet option helper")]
/// Enables or disables `PACKET_AUXDATA` delivery for packet receives.
///
/// # Errors
/// Returns the structured Linux option error.
pub fn set_packet_auxdata(descriptor: BorrowedFd<'_>, enabled: bool) -> Result<(), NativeError> {
    set_integer_option(
        descriptor,
        libc::SOL_PACKET,
        libc::PACKET_AUXDATA,
        i32::from(enabled),
        Operation::SetSocketOption,
    )
}

#[allow(unsafe_code, reason = "D-023 reviewed scalar packet fanout helper")]
/// Joins the socket to a Linux packet fanout group with a checked mode.
///
/// # Errors
/// Returns an argument error for an unknown mode or a structured Linux option error.
pub fn set_packet_fanout(
    descriptor: BorrowedFd<'_>,
    group: u16,
    mode: u16,
) -> Result<(), NativeError> {
    if mode > 7 {
        return Err(NativeError::invalid_argument(
            Operation::SetSocketOption,
            "packet fanout mode must be from 0 through 7",
        ));
    }
    let value = i32::from(group) | (i32::from(mode) << 16);
    set_integer_option(
        descriptor,
        libc::SOL_PACKET,
        libc::PACKET_FANOUT,
        value,
        Operation::SetSocketOption,
    )
}

/// Reads and resets Linux packet statistics.
///
/// # Errors
/// Returns structured Linux errors.
#[allow(
    unsafe_code,
    reason = "D-023 reviewed fixed-size packet statistics output"
)]
pub fn packet_statistics(descriptor: BorrowedFd<'_>) -> Result<PacketStatistics, NativeError> {
    let mut native = libc::tpacket_stats {
        tp_packets: 0,
        tp_drops: 0,
    };
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::tpacket_stats>())
        .map_err(|_| {
            NativeError::internal(
                Operation::GetStatistics,
                "tpacket_stats size does not fit socklen_t",
            )
        })?;
    // SAFETY: native is initialized writable fixed-size output and length is exact.
    let result = unsafe {
        libc::getsockopt(
            descriptor.as_raw_fd(),
            libc::SOL_PACKET,
            libc::PACKET_STATISTICS,
            (&raw mut native).cast(),
            &raw mut length,
        )
    };
    nix::errno::Errno::result(result)
        .map_err(|error| NativeError::system_nix(Operation::GetStatistics, error))?;
    Ok(PacketStatistics {
        packets: native.tp_packets,
        drops: native.tp_drops,
    })
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::os::fd::AsFd;

    use super::{
        ClassicBpfInstruction, attach_classic_bpf, detach_filter, get_raw_option,
        validate_classic_bpf,
    };

    #[test]
    fn raw_options_are_bounded_and_reserved_tuples_are_rejected() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket_type =
            get_raw_option(socket.as_fd(), nix::libc::SOL_SOCKET, nix::libc::SO_TYPE, 4).unwrap();
        assert_eq!(socket_type.len(), 4);
        assert!(
            get_raw_option(
                socket.as_fd(),
                nix::libc::SOL_SOCKET,
                nix::libc::SO_ATTACH_FILTER,
                16
            )
            .is_err()
        );
        assert!(
            get_raw_option(
                socket.as_fd(),
                nix::libc::SOL_SOCKET,
                nix::libc::SO_TYPE,
                4097
            )
            .is_err()
        );
    }

    #[test]
    fn classic_filter_validation_and_kernel_copy_are_deterministic() {
        let accept = [ClassicBpfInstruction {
            code: 0x06,
            jump_true: 0,
            jump_false: 0,
            value: u32::MAX,
        }];
        assert!(validate_classic_bpf(&accept).is_ok());
        let invalid = [ClassicBpfInstruction {
            code: 0x05,
            jump_true: 0,
            jump_false: 0,
            value: 1,
        }];
        assert!(validate_classic_bpf(&invalid).is_err());

        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        attach_classic_bpf(socket.as_fd(), &accept).unwrap();
        detach_filter(socket.as_fd()).unwrap();
    }
}
