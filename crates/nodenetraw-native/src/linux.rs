use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use nix::sys::socket::{getsockopt, setsockopt, sockopt};
use rustix::net::sockopt::{
    ip_tos, ip_ttl, set_ip_tos, set_ip_ttl, set_socket_broadcast, set_socket_recv_buffer_size,
    set_socket_send_buffer_size, socket_broadcast, socket_recv_buffer_size,
    socket_send_buffer_size,
};
use rustix::net::{
    AddressFamily, Protocol, SocketFlags, SocketType, bind, connect, connect_unspec, getsockname,
    socket_with,
};

use crate::advanced::{get_typed_integer_option, set_typed_integer_option};
use crate::conversion::{RawIpv4Protocol, RawIpv6Protocol};
use crate::error::{NativeError, Operation};
use crate::lifecycle::SocketCore;
use crate::packet::PacketMode;

pub const MAX_SOCKET_BUFFER_SIZE: u32 = 16 * 1024 * 1024;
pub const MAX_INTERFACE_NAME_BYTES: usize = nix::libc::IFNAMSIZ - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4SocketOption {
    Broadcast,
    IpTtl,
    IpTypeOfService,
    ReceiveBufferSize,
    SendBufferSize,
    ReceivePacketInfo,
    ReceiveTtl,
    ReceiveTypeOfService,
    ReceiveTimestampNanoseconds,
    ReceiveQueueOverflow,
    ReceiveErrors,
    HeaderIncluded,
    Freebind,
    Transparent,
    Priority,
    Mark,
    PathMtuDiscovery,
    MulticastTtl,
    MulticastLoop,
    BusyPollMicroseconds,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv6SocketOption {
    Ipv6Only,
    UnicastHops,
    TrafficClass,
    MulticastHops,
    ReceiveBufferSize,
    SendBufferSize,
    ReceivePacketInfo,
    ReceiveHopLimit,
    ReceiveTrafficClass,
    ReceiveTimestampNanoseconds,
    ReceiveQueueOverflow,
    ReceiveErrors,
    ChecksumOffset,
    Priority,
    Mark,
    PathMtuDiscovery,
    MulticastLoop,
    BusyPollMicroseconds,
}

impl Ipv6SocketOption {
    /// Parses one public IPv6 option name.
    ///
    /// # Errors
    /// Returns an argument error for unsupported names.
    pub fn parse(name: &str, operation: Operation) -> Result<Self, NativeError> {
        match name {
            "ipv6Only" => Ok(Self::Ipv6Only),
            "ipv6UnicastHops" => Ok(Self::UnicastHops),
            "ipv6TrafficClass" => Ok(Self::TrafficClass),
            "ipv6MulticastHops" => Ok(Self::MulticastHops),
            "receiveBufferSize" => Ok(Self::ReceiveBufferSize),
            "sendBufferSize" => Ok(Self::SendBufferSize),
            "receivePacketInfo" => Ok(Self::ReceivePacketInfo),
            "receiveHopLimit" => Ok(Self::ReceiveHopLimit),
            "receiveTrafficClass" => Ok(Self::ReceiveTrafficClass),
            "receiveTimestampNanoseconds" => Ok(Self::ReceiveTimestampNanoseconds),
            "receiveQueueOverflow" => Ok(Self::ReceiveQueueOverflow),
            "receiveErrors" => Ok(Self::ReceiveErrors),
            "ipv6ChecksumOffset" => Ok(Self::ChecksumOffset),
            "priority" => Ok(Self::Priority),
            "mark" => Ok(Self::Mark),
            "pathMtuDiscovery" => Ok(Self::PathMtuDiscovery),
            "multicastLoop" => Ok(Self::MulticastLoop),
            "busyPollMicroseconds" => Ok(Self::BusyPollMicroseconds),
            _ => Err(NativeError::invalid_argument(
                operation,
                "unsupported IPv6 raw socket option",
            )),
        }
    }
}

/// Binds a socket to a Linux interface, or removes the binding with `None`.
///
/// # Errors
///
/// Returns a validation error or the structured Linux `setsockopt(2)` error.
pub fn set_bind_to_device(
    descriptor: BorrowedFd<'_>,
    name: Option<&str>,
) -> Result<(), NativeError> {
    let name = match name {
        Some(name) => {
            let bytes = name.as_bytes();
            if bytes.is_empty() || bytes.len() > MAX_INTERFACE_NAME_BYTES || bytes.contains(&0) {
                return Err(NativeError::invalid_argument(
                    Operation::SetSocketOption,
                    "interface name must be 1 through IFNAMSIZ-1 non-NUL bytes",
                ));
            }
            OsString::from_vec(bytes.to_vec())
        }
        None => OsString::new(),
    };
    setsockopt(&descriptor, sockopt::BindToDevice, &name)
        .map_err(|error| NativeError::system_nix(Operation::SetSocketOption, error))
}

/// Gets the socket's current Linux device binding.
///
/// # Errors
///
/// Returns a structured Linux error or rejects a non-UTF-8 kernel value.
pub fn get_bind_to_device(descriptor: BorrowedFd<'_>) -> Result<Option<String>, NativeError> {
    let value = getsockopt(&descriptor, sockopt::BindToDevice)
        .map_err(|error| NativeError::system_nix(Operation::GetSocketOption, error))?;
    if value.as_bytes().is_empty() {
        return Ok(None);
    }
    value.into_string().map(Some).map_err(|_| {
        NativeError::internal(
            Operation::GetSocketOption,
            "kernel returned a non-UTF-8 interface name",
        )
    })
}

impl Ipv4SocketOption {
    /// Parses one stable public option name.
    ///
    /// # Errors
    ///
    /// Returns `ERR_INVALID_ARGUMENT` for unsupported names.
    pub fn parse(name: &str, operation: Operation) -> Result<Self, NativeError> {
        match name {
            "broadcast" => Ok(Self::Broadcast),
            "ipTtl" => Ok(Self::IpTtl),
            "ipTypeOfService" => Ok(Self::IpTypeOfService),
            "receiveBufferSize" => Ok(Self::ReceiveBufferSize),
            "sendBufferSize" => Ok(Self::SendBufferSize),
            "receivePacketInfo" => Ok(Self::ReceivePacketInfo),
            "receiveTtl" => Ok(Self::ReceiveTtl),
            "receiveTypeOfService" => Ok(Self::ReceiveTypeOfService),
            "receiveTimestampNanoseconds" => Ok(Self::ReceiveTimestampNanoseconds),
            "receiveQueueOverflow" => Ok(Self::ReceiveQueueOverflow),
            "receiveErrors" => Ok(Self::ReceiveErrors),
            "headerIncluded" => Ok(Self::HeaderIncluded),
            "freebind" => Ok(Self::Freebind),
            "transparent" => Ok(Self::Transparent),
            "priority" => Ok(Self::Priority),
            "mark" => Ok(Self::Mark),
            "pathMtuDiscovery" => Ok(Self::PathMtuDiscovery),
            "multicastTtl" => Ok(Self::MulticastTtl),
            "multicastLoop" => Ok(Self::MulticastLoop),
            "busyPollMicroseconds" => Ok(Self::BusyPollMicroseconds),
            _ => Err(NativeError::invalid_argument(
                operation,
                "unsupported raw socket option",
            )),
        }
    }
}

/// Creates an owned, nonblocking, close-on-exec IPv4 raw socket.
///
/// Linux performs the capability check. Permission failures are returned with
/// their original errno and no privilege elevation is attempted.
///
/// # Errors
///
/// Returns `ERR_SYSTEM` with the Linux errno if `socket(2)` fails.
pub fn create_ipv4_raw_socket(protocol: RawIpv4Protocol) -> Result<SocketCore, NativeError> {
    create_socket(
        AddressFamily::INET,
        SocketType::RAW,
        Some(protocol.as_rustix()),
        Operation::CreateRawIpv4Socket,
    )
    .map(SocketCore::from_owned_fd)
}

/// Creates an owned nonblocking, close-on-exec IPv6 raw socket.
///
/// # Errors
/// Returns the structured Linux socket creation error.
pub fn create_ipv6_raw_socket(protocol: RawIpv6Protocol) -> Result<SocketCore, NativeError> {
    create_socket(
        AddressFamily::INET6,
        SocketType::RAW,
        Some(protocol.as_rustix()),
        Operation::CreateRawIpv6Socket,
    )
    .map(SocketCore::from_owned_fd)
}

/// Creates one owned nonblocking Linux packet socket.
///
/// # Errors
/// Returns validation or the structured Linux socket creation error.
pub fn create_packet_socket(mode: PacketMode, protocol: u16) -> Result<SocketCore, NativeError> {
    if protocol == 0 {
        return Err(NativeError::invalid_argument(
            Operation::CreatePacketSocket,
            "packet protocol must be from 1 through 65535",
        ));
    }
    let socket_type = match mode {
        PacketMode::Raw => SocketType::RAW,
        PacketMode::Cooked => SocketType::DGRAM,
    };
    let raw_protocol = std::num::NonZeroU32::new(u32::from(protocol.to_be())).ok_or_else(|| {
        NativeError::invalid_argument(
            Operation::CreatePacketSocket,
            "packet protocol converted to zero",
        )
    })?;
    create_socket(
        AddressFamily::PACKET,
        socket_type,
        Some(Protocol::from_raw(raw_protocol)),
        Operation::CreatePacketSocket,
    )
    .map(SocketCore::from_owned_fd)
}

/// Resolves a Linux interface name to its nonzero index.
///
/// # Errors
/// Returns validation or the structured libc lookup error.
pub fn interface_index(name: &str) -> Result<u32, NativeError> {
    if name.is_empty() || name.len() > MAX_INTERFACE_NAME_BYTES || name.as_bytes().contains(&0) {
        return Err(NativeError::invalid_argument(
            Operation::LookupInterface,
            "interface name must be 1 through IFNAMSIZ-1 non-NUL bytes",
        ));
    }
    nix::net::if_::if_nametoindex(name)
        .map_err(|error| NativeError::system_nix(Operation::LookupInterface, error))
}

/// Resolves a nonzero Linux interface index to its UTF-8 name.
///
/// # Errors
/// Returns validation, lookup, or UTF-8 conversion errors.
pub fn interface_name(index: u32) -> Result<String, NativeError> {
    if index == 0 {
        return Err(NativeError::invalid_argument(
            Operation::LookupInterface,
            "interface index must be nonzero",
        ));
    }
    let name = nix::net::if_::if_indextoname(index)
        .map_err(|error| NativeError::system_nix(Operation::LookupInterface, error))?;
    name.into_string().map_err(|_| {
        NativeError::internal(Operation::LookupInterface, "interface name was not UTF-8")
    })
}

fn create_socket(
    address_family: AddressFamily,
    socket_type: SocketType,
    protocol: Option<Protocol>,
    operation: Operation,
) -> Result<OwnedFd, NativeError> {
    socket_with(
        address_family,
        socket_type,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        protocol,
    )
    .map_err(|errno| NativeError::system(operation, errno))
}

/// # Errors
/// Returns the structured Linux bind error.
pub fn bind_ipv6(descriptor: BorrowedFd<'_>, address: SocketAddrV6) -> Result<(), NativeError> {
    bind(descriptor, &address).map_err(|error| NativeError::system(Operation::Bind, error))
}

/// # Errors
/// Returns a Linux query error or address-family mismatch.
pub fn local_ipv6_address(descriptor: BorrowedFd<'_>) -> Result<SocketAddrV6, NativeError> {
    let address = getsockname(descriptor)
        .map_err(|error| NativeError::system(Operation::GetLocalAddress, error))?;
    SocketAddrV6::try_from(address)
        .map_err(|error| NativeError::system(Operation::GetLocalAddress, error))
}

/// # Errors
/// Returns the structured Linux connect error.
pub fn connect_ipv6(descriptor: BorrowedFd<'_>, address: SocketAddrV6) -> Result<(), NativeError> {
    connect(descriptor, &address).map_err(|error| NativeError::system(Operation::Connect, error))
}

/// # Errors
/// Returns the structured Linux IPv4 connect error.
pub fn connect_ipv4(descriptor: BorrowedFd<'_>, address: Ipv4Addr) -> Result<(), NativeError> {
    connect(descriptor, &SocketAddrV4::new(address, 0))
        .map_err(|error| NativeError::system(Operation::Connect, error))
}

/// # Errors
/// Returns the structured Linux disconnect error.
pub fn disconnect_socket(descriptor: BorrowedFd<'_>) -> Result<(), NativeError> {
    connect_unspec(descriptor).map_err(|error| NativeError::system(Operation::Disconnect, error))
}

/// Binds an IPv4 socket to a local address and port zero.
///
/// # Errors
///
/// Returns a structured Linux `bind(2)` failure.
pub fn bind_ipv4(descriptor: BorrowedFd<'_>, address: Ipv4Addr) -> Result<(), NativeError> {
    bind(descriptor, &SocketAddrV4::new(address, 0))
        .map_err(|error| NativeError::system(Operation::Bind, error))
}

/// Reads the socket's current local IPv4 address.
///
/// # Errors
///
/// Returns a structured Linux error or address-family mismatch.
pub fn local_ipv4_address(descriptor: BorrowedFd<'_>) -> Result<Ipv4Addr, NativeError> {
    let address = getsockname(descriptor)
        .map_err(|error| NativeError::system(Operation::GetLocalAddress, error))?;
    SocketAddrV4::try_from(address)
        .map(|address| *address.ip())
        .map_err(|error| NativeError::system(Operation::GetLocalAddress, error))
}

/// Sets one validated typed IPv4/socket-level option.
///
/// # Errors
///
/// Returns an argument error for an invalid value or a structured Linux error.
#[allow(
    clippy::too_many_lines,
    reason = "exhaustive typed option dispatch keeps every Linux mapping auditable"
)]
pub fn set_ipv4_socket_option(
    descriptor: BorrowedFd<'_>,
    option: Ipv4SocketOption,
    value: u32,
) -> Result<(), NativeError> {
    validate_socket_option_value(option, value)?;
    let result = match option {
        Ipv4SocketOption::Broadcast => set_socket_broadcast(descriptor, value != 0),
        Ipv4SocketOption::IpTtl => set_ip_ttl(descriptor, value),
        Ipv4SocketOption::IpTypeOfService => set_ip_tos(
            descriptor,
            u8::try_from(value).map_err(|_| {
                NativeError::invalid_argument(
                    Operation::SetSocketOption,
                    "IPv4 type of service must fit in u8",
                )
            })?,
        ),
        Ipv4SocketOption::ReceiveBufferSize => {
            set_socket_recv_buffer_size(descriptor, value as usize)
        }
        Ipv4SocketOption::SendBufferSize => set_socket_send_buffer_size(descriptor, value as usize),
        Ipv4SocketOption::ReceivePacketInfo => {
            setsockopt(&descriptor, sockopt::Ipv4PacketInfo, &(value != 0))
                .map_err(|error| NativeError::system_nix(Operation::SetSocketOption, error))?;
            Ok(())
        }
        Ipv4SocketOption::ReceiveTtl => {
            setsockopt(&descriptor, sockopt::Ipv4RecvTtl, &(value != 0))
                .map_err(|error| NativeError::system_nix(Operation::SetSocketOption, error))?;
            Ok(())
        }
        Ipv4SocketOption::ReceiveTypeOfService => {
            setsockopt(&descriptor, sockopt::IpRecvTos, &(value != 0))
                .map_err(|error| NativeError::system_nix(Operation::SetSocketOption, error))?;
            Ok(())
        }
        Ipv4SocketOption::ReceiveTimestampNanoseconds => {
            setsockopt(&descriptor, sockopt::ReceiveTimestampns, &(value != 0))
                .map_err(|error| NativeError::system_nix(Operation::SetSocketOption, error))?;
            Ok(())
        }
        Ipv4SocketOption::ReceiveQueueOverflow => {
            setsockopt(
                &descriptor,
                sockopt::RxqOvfl,
                &i32::try_from(value).map_err(|_| {
                    NativeError::invalid_argument(
                        Operation::SetSocketOption,
                        "queue-overflow enablement must be zero or one",
                    )
                })?,
            )
            .map_err(|error| NativeError::system_nix(Operation::SetSocketOption, error))?;
            Ok(())
        }
        Ipv4SocketOption::ReceiveErrors => {
            setsockopt(&descriptor, sockopt::Ipv4RecvErr, &(value != 0))
                .map_err(|error| NativeError::system_nix(Operation::SetSocketOption, error))?;
            Ok(())
        }
        Ipv4SocketOption::HeaderIncluded => {
            return set_typed_integer_option(
                descriptor,
                nix::libc::IPPROTO_IP,
                nix::libc::IP_HDRINCL,
                i32::from(value != 0),
                Operation::SetSocketOption,
            );
        }
        Ipv4SocketOption::Freebind => {
            return set_typed_integer_option(
                descriptor,
                nix::libc::IPPROTO_IP,
                nix::libc::IP_FREEBIND,
                i32::from(value != 0),
                Operation::SetSocketOption,
            );
        }
        Ipv4SocketOption::Transparent => {
            return set_typed_integer_option(
                descriptor,
                nix::libc::IPPROTO_IP,
                nix::libc::IP_TRANSPARENT,
                i32::from(value != 0),
                Operation::SetSocketOption,
            );
        }
        Ipv4SocketOption::Priority => {
            return set_typed_integer_option(
                descriptor,
                nix::libc::SOL_SOCKET,
                nix::libc::SO_PRIORITY,
                i32::try_from(value).map_err(|_| {
                    NativeError::invalid_argument(
                        Operation::SetSocketOption,
                        "priority must fit i32",
                    )
                })?,
                Operation::SetSocketOption,
            );
        }
        Ipv4SocketOption::Mark => {
            return set_typed_integer_option(
                descriptor,
                nix::libc::SOL_SOCKET,
                nix::libc::SO_MARK,
                value.cast_signed(),
                Operation::SetSocketOption,
            );
        }
        Ipv4SocketOption::PathMtuDiscovery => {
            return set_typed_integer_option(
                descriptor,
                nix::libc::IPPROTO_IP,
                nix::libc::IP_MTU_DISCOVER,
                i32::try_from(value).map_err(|_| {
                    NativeError::invalid_argument(
                        Operation::SetSocketOption,
                        "PMTU mode must fit i32",
                    )
                })?,
                Operation::SetSocketOption,
            );
        }
        Ipv4SocketOption::MulticastTtl => {
            return set_typed_integer_option(
                descriptor,
                nix::libc::IPPROTO_IP,
                nix::libc::IP_MULTICAST_TTL,
                i32::try_from(value).map_err(|_| {
                    NativeError::invalid_argument(
                        Operation::SetSocketOption,
                        "multicast TTL must fit i32",
                    )
                })?,
                Operation::SetSocketOption,
            );
        }
        Ipv4SocketOption::MulticastLoop => {
            return set_typed_integer_option(
                descriptor,
                nix::libc::IPPROTO_IP,
                nix::libc::IP_MULTICAST_LOOP,
                i32::from(value != 0),
                Operation::SetSocketOption,
            );
        }
        Ipv4SocketOption::BusyPollMicroseconds => {
            return set_typed_integer_option(
                descriptor,
                nix::libc::SOL_SOCKET,
                nix::libc::SO_BUSY_POLL,
                i32::try_from(value).map_err(|_| {
                    NativeError::invalid_argument(
                        Operation::SetSocketOption,
                        "busy-poll duration must fit i32",
                    )
                })?,
                Operation::SetSocketOption,
            );
        }
    };
    result.map_err(|error| NativeError::system(Operation::SetSocketOption, error))
}

/// Reads one typed IPv4/socket-level option.
///
/// # Errors
///
/// Returns a structured Linux error or an internal conversion failure.
#[allow(
    clippy::too_many_lines,
    reason = "exhaustive typed option dispatch keeps every Linux mapping auditable"
)]
pub fn get_ipv4_socket_option(
    descriptor: BorrowedFd<'_>,
    option: Ipv4SocketOption,
) -> Result<u32, NativeError> {
    let value = match option {
        Ipv4SocketOption::Broadcast => u32::from(
            socket_broadcast(descriptor)
                .map_err(|error| NativeError::system(Operation::GetSocketOption, error))?,
        ),
        Ipv4SocketOption::IpTtl => ip_ttl(descriptor)
            .map_err(|error| NativeError::system(Operation::GetSocketOption, error))?,
        Ipv4SocketOption::IpTypeOfService => u32::from(
            ip_tos(descriptor)
                .map_err(|error| NativeError::system(Operation::GetSocketOption, error))?,
        ),
        Ipv4SocketOption::ReceiveBufferSize => u32::try_from(
            socket_recv_buffer_size(descriptor)
                .map_err(|error| NativeError::system(Operation::GetSocketOption, error))?,
        )
        .map_err(|_| {
            NativeError::internal(
                Operation::GetSocketOption,
                "kernel receive buffer size does not fit in u32",
            )
        })?,
        Ipv4SocketOption::SendBufferSize => u32::try_from(
            socket_send_buffer_size(descriptor)
                .map_err(|error| NativeError::system(Operation::GetSocketOption, error))?,
        )
        .map_err(|_| {
            NativeError::internal(
                Operation::GetSocketOption,
                "kernel send buffer size does not fit in u32",
            )
        })?,
        Ipv4SocketOption::ReceivePacketInfo => u32::from(
            getsockopt(&descriptor, sockopt::Ipv4PacketInfo)
                .map_err(|error| NativeError::system_nix(Operation::GetSocketOption, error))?,
        ),
        Ipv4SocketOption::ReceiveTtl => u32::from(
            getsockopt(&descriptor, sockopt::Ipv4RecvTtl)
                .map_err(|error| NativeError::system_nix(Operation::GetSocketOption, error))?,
        ),
        Ipv4SocketOption::ReceiveTypeOfService => u32::from(
            getsockopt(&descriptor, sockopt::IpRecvTos)
                .map_err(|error| NativeError::system_nix(Operation::GetSocketOption, error))?,
        ),
        Ipv4SocketOption::ReceiveTimestampNanoseconds => u32::from(
            getsockopt(&descriptor, sockopt::ReceiveTimestampns)
                .map_err(|error| NativeError::system_nix(Operation::GetSocketOption, error))?,
        ),
        Ipv4SocketOption::ReceiveQueueOverflow => u32::try_from(
            getsockopt(&descriptor, sockopt::RxqOvfl)
                .map_err(|error| NativeError::system_nix(Operation::GetSocketOption, error))?,
        )
        .map_err(|_| {
            NativeError::internal(
                Operation::GetSocketOption,
                "kernel returned a negative queue-overflow option",
            )
        })?,
        Ipv4SocketOption::ReceiveErrors => u32::from(
            getsockopt(&descriptor, sockopt::Ipv4RecvErr)
                .map_err(|error| NativeError::system_nix(Operation::GetSocketOption, error))?,
        ),
        Ipv4SocketOption::HeaderIncluded => u32::from(
            get_typed_integer_option(
                descriptor,
                nix::libc::IPPROTO_IP,
                nix::libc::IP_HDRINCL,
                Operation::GetSocketOption,
            )? != 0,
        ),
        Ipv4SocketOption::Freebind => u32::from(
            get_typed_integer_option(
                descriptor,
                nix::libc::IPPROTO_IP,
                nix::libc::IP_FREEBIND,
                Operation::GetSocketOption,
            )? != 0,
        ),
        Ipv4SocketOption::Transparent => u32::from(
            get_typed_integer_option(
                descriptor,
                nix::libc::IPPROTO_IP,
                nix::libc::IP_TRANSPARENT,
                Operation::GetSocketOption,
            )? != 0,
        ),
        Ipv4SocketOption::Priority => checked_nonnegative(get_typed_integer_option(
            descriptor,
            nix::libc::SOL_SOCKET,
            nix::libc::SO_PRIORITY,
            Operation::GetSocketOption,
        )?)?,
        Ipv4SocketOption::Mark => get_typed_integer_option(
            descriptor,
            nix::libc::SOL_SOCKET,
            nix::libc::SO_MARK,
            Operation::GetSocketOption,
        )?
        .cast_unsigned(),
        Ipv4SocketOption::PathMtuDiscovery => checked_nonnegative(get_typed_integer_option(
            descriptor,
            nix::libc::IPPROTO_IP,
            nix::libc::IP_MTU_DISCOVER,
            Operation::GetSocketOption,
        )?)?,
        Ipv4SocketOption::MulticastTtl => checked_nonnegative(get_typed_integer_option(
            descriptor,
            nix::libc::IPPROTO_IP,
            nix::libc::IP_MULTICAST_TTL,
            Operation::GetSocketOption,
        )?)?,
        Ipv4SocketOption::MulticastLoop => u32::from(
            get_typed_integer_option(
                descriptor,
                nix::libc::IPPROTO_IP,
                nix::libc::IP_MULTICAST_LOOP,
                Operation::GetSocketOption,
            )? != 0,
        ),
        Ipv4SocketOption::BusyPollMicroseconds => checked_nonnegative(get_typed_integer_option(
            descriptor,
            nix::libc::SOL_SOCKET,
            nix::libc::SO_BUSY_POLL,
            Operation::GetSocketOption,
        )?)?,
    };
    Ok(value)
}

fn validate_socket_option_value(option: Ipv4SocketOption, value: u32) -> Result<(), NativeError> {
    let valid = match option {
        Ipv4SocketOption::Broadcast
        | Ipv4SocketOption::ReceivePacketInfo
        | Ipv4SocketOption::ReceiveTtl
        | Ipv4SocketOption::ReceiveTypeOfService
        | Ipv4SocketOption::ReceiveTimestampNanoseconds
        | Ipv4SocketOption::ReceiveQueueOverflow
        | Ipv4SocketOption::ReceiveErrors
        | Ipv4SocketOption::HeaderIncluded
        | Ipv4SocketOption::Freebind
        | Ipv4SocketOption::Transparent
        | Ipv4SocketOption::MulticastLoop => value <= 1,
        Ipv4SocketOption::Priority => value <= i32::MAX.cast_unsigned(),
        Ipv4SocketOption::Mark => true,
        Ipv4SocketOption::PathMtuDiscovery => value <= 3,
        Ipv4SocketOption::BusyPollMicroseconds => value <= 1_000_000,
        Ipv4SocketOption::MulticastTtl | Ipv4SocketOption::IpTypeOfService => value <= 255,
        Ipv4SocketOption::IpTtl => (1..=255).contains(&value),
        Ipv4SocketOption::ReceiveBufferSize | Ipv4SocketOption::SendBufferSize => {
            (1..=MAX_SOCKET_BUFFER_SIZE).contains(&value)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(NativeError::invalid_argument(
            Operation::SetSocketOption,
            "socket option value is outside its supported range",
        ))
    }
}

/// Sets one checked IPv6 or common socket option.
///
/// # Errors
/// Returns validation or structured Linux option errors.
#[allow(
    clippy::too_many_lines,
    reason = "exhaustive typed option dispatch keeps every Linux mapping auditable"
)]
pub fn set_ipv6_socket_option(
    descriptor: BorrowedFd<'_>,
    option: Ipv6SocketOption,
    value: u32,
) -> Result<(), NativeError> {
    let signed_value = value.cast_signed();
    let valid = match option {
        Ipv6SocketOption::Ipv6Only
        | Ipv6SocketOption::ReceivePacketInfo
        | Ipv6SocketOption::ReceiveHopLimit
        | Ipv6SocketOption::ReceiveTrafficClass
        | Ipv6SocketOption::ReceiveTimestampNanoseconds
        | Ipv6SocketOption::ReceiveQueueOverflow
        | Ipv6SocketOption::ReceiveErrors
        | Ipv6SocketOption::MulticastLoop => value <= 1,
        Ipv6SocketOption::UnicastHops
        | Ipv6SocketOption::MulticastHops
        | Ipv6SocketOption::TrafficClass => value <= 255,
        Ipv6SocketOption::ReceiveBufferSize | Ipv6SocketOption::SendBufferSize => {
            (1..=MAX_SOCKET_BUFFER_SIZE).contains(&value)
        }
        Ipv6SocketOption::ChecksumOffset => value <= 65_535,
        Ipv6SocketOption::Priority => value <= i32::MAX.cast_unsigned(),
        Ipv6SocketOption::Mark => true,
        Ipv6SocketOption::PathMtuDiscovery => value <= 3,
        Ipv6SocketOption::BusyPollMicroseconds => value <= 1_000_000,
    };
    if !valid {
        return Err(NativeError::invalid_argument(
            Operation::SetSocketOption,
            "IPv6 socket option value is outside its supported range",
        ));
    }
    let nix_result = match option {
        Ipv6SocketOption::Ipv6Only => setsockopt(&descriptor, sockopt::Ipv6V6Only, &(value != 0)),
        Ipv6SocketOption::UnicastHops => setsockopt(&descriptor, sockopt::Ipv6Ttl, &signed_value),
        Ipv6SocketOption::TrafficClass => {
            setsockopt(&descriptor, sockopt::Ipv6TClass, &signed_value)
        }
        Ipv6SocketOption::MulticastHops => {
            setsockopt(&descriptor, sockopt::Ipv6MulticastHops, &signed_value)
        }
        Ipv6SocketOption::ReceivePacketInfo => {
            setsockopt(&descriptor, sockopt::Ipv6RecvPacketInfo, &(value != 0))
        }
        Ipv6SocketOption::ReceiveHopLimit => {
            setsockopt(&descriptor, sockopt::Ipv6RecvHopLimit, &(value != 0))
        }
        Ipv6SocketOption::ReceiveTrafficClass => {
            setsockopt(&descriptor, sockopt::Ipv6RecvTClass, &(value != 0))
        }
        Ipv6SocketOption::ReceiveTimestampNanoseconds => {
            setsockopt(&descriptor, sockopt::ReceiveTimestampns, &(value != 0))
        }
        Ipv6SocketOption::ReceiveQueueOverflow => {
            setsockopt(&descriptor, sockopt::RxqOvfl, &signed_value)
        }
        Ipv6SocketOption::ReceiveErrors => {
            setsockopt(&descriptor, sockopt::Ipv6RecvErr, &(value != 0))
        }
        Ipv6SocketOption::ChecksumOffset => {
            return set_typed_integer_option(
                descriptor,
                nix::libc::IPPROTO_IPV6,
                nix::libc::IPV6_CHECKSUM,
                signed_value,
                Operation::SetSocketOption,
            );
        }
        Ipv6SocketOption::Priority => {
            return set_typed_integer_option(
                descriptor,
                nix::libc::SOL_SOCKET,
                nix::libc::SO_PRIORITY,
                signed_value,
                Operation::SetSocketOption,
            );
        }
        Ipv6SocketOption::Mark => {
            return set_typed_integer_option(
                descriptor,
                nix::libc::SOL_SOCKET,
                nix::libc::SO_MARK,
                signed_value,
                Operation::SetSocketOption,
            );
        }
        Ipv6SocketOption::PathMtuDiscovery => {
            return set_typed_integer_option(
                descriptor,
                nix::libc::IPPROTO_IPV6,
                nix::libc::IPV6_MTU_DISCOVER,
                signed_value,
                Operation::SetSocketOption,
            );
        }
        Ipv6SocketOption::MulticastLoop => {
            return set_typed_integer_option(
                descriptor,
                nix::libc::IPPROTO_IPV6,
                nix::libc::IPV6_MULTICAST_LOOP,
                i32::from(value != 0),
                Operation::SetSocketOption,
            );
        }
        Ipv6SocketOption::BusyPollMicroseconds => {
            return set_typed_integer_option(
                descriptor,
                nix::libc::SOL_SOCKET,
                nix::libc::SO_BUSY_POLL,
                signed_value,
                Operation::SetSocketOption,
            );
        }
        Ipv6SocketOption::ReceiveBufferSize => {
            return set_socket_recv_buffer_size(descriptor, value as usize)
                .map_err(|error| NativeError::system(Operation::SetSocketOption, error));
        }
        Ipv6SocketOption::SendBufferSize => {
            return set_socket_send_buffer_size(descriptor, value as usize)
                .map_err(|error| NativeError::system(Operation::SetSocketOption, error));
        }
    };
    nix_result.map_err(|error| NativeError::system_nix(Operation::SetSocketOption, error))
}

/// Reads one IPv6 or common socket option.
///
/// # Errors
/// Returns structured Linux or checked conversion errors.
pub fn get_ipv6_socket_option(
    descriptor: BorrowedFd<'_>,
    option: Ipv6SocketOption,
) -> Result<u32, NativeError> {
    let value = match option {
        Ipv6SocketOption::Ipv6Only => {
            u32::from(getsockopt(&descriptor, sockopt::Ipv6V6Only).map_err(nix_get_error)?)
        }
        Ipv6SocketOption::UnicastHops => {
            checked_nonnegative(getsockopt(&descriptor, sockopt::Ipv6Ttl).map_err(nix_get_error)?)?
        }
        Ipv6SocketOption::TrafficClass => checked_nonnegative(
            getsockopt(&descriptor, sockopt::Ipv6TClass).map_err(nix_get_error)?,
        )?,
        Ipv6SocketOption::MulticastHops => checked_nonnegative(
            getsockopt(&descriptor, sockopt::Ipv6MulticastHops).map_err(nix_get_error)?,
        )?,
        Ipv6SocketOption::ReceivePacketInfo => {
            u32::from(getsockopt(&descriptor, sockopt::Ipv6RecvPacketInfo).map_err(nix_get_error)?)
        }
        Ipv6SocketOption::ReceiveHopLimit => {
            u32::from(getsockopt(&descriptor, sockopt::Ipv6RecvHopLimit).map_err(nix_get_error)?)
        }
        Ipv6SocketOption::ReceiveTrafficClass => {
            u32::from(getsockopt(&descriptor, sockopt::Ipv6RecvTClass).map_err(nix_get_error)?)
        }
        Ipv6SocketOption::ReceiveTimestampNanoseconds => {
            u32::from(getsockopt(&descriptor, sockopt::ReceiveTimestampns).map_err(nix_get_error)?)
        }
        Ipv6SocketOption::ReceiveQueueOverflow => {
            checked_nonnegative(getsockopt(&descriptor, sockopt::RxqOvfl).map_err(nix_get_error)?)?
        }
        Ipv6SocketOption::ReceiveErrors => {
            u32::from(getsockopt(&descriptor, sockopt::Ipv6RecvErr).map_err(nix_get_error)?)
        }
        Ipv6SocketOption::ChecksumOffset => checked_nonnegative(get_typed_integer_option(
            descriptor,
            nix::libc::IPPROTO_IPV6,
            nix::libc::IPV6_CHECKSUM,
            Operation::GetSocketOption,
        )?)?,
        Ipv6SocketOption::Priority => checked_nonnegative(get_typed_integer_option(
            descriptor,
            nix::libc::SOL_SOCKET,
            nix::libc::SO_PRIORITY,
            Operation::GetSocketOption,
        )?)?,
        Ipv6SocketOption::Mark => get_typed_integer_option(
            descriptor,
            nix::libc::SOL_SOCKET,
            nix::libc::SO_MARK,
            Operation::GetSocketOption,
        )?
        .cast_unsigned(),
        Ipv6SocketOption::PathMtuDiscovery => checked_nonnegative(get_typed_integer_option(
            descriptor,
            nix::libc::IPPROTO_IPV6,
            nix::libc::IPV6_MTU_DISCOVER,
            Operation::GetSocketOption,
        )?)?,
        Ipv6SocketOption::MulticastLoop => u32::from(
            get_typed_integer_option(
                descriptor,
                nix::libc::IPPROTO_IPV6,
                nix::libc::IPV6_MULTICAST_LOOP,
                Operation::GetSocketOption,
            )? != 0,
        ),
        Ipv6SocketOption::BusyPollMicroseconds => checked_nonnegative(get_typed_integer_option(
            descriptor,
            nix::libc::SOL_SOCKET,
            nix::libc::SO_BUSY_POLL,
            Operation::GetSocketOption,
        )?)?,
        Ipv6SocketOption::ReceiveBufferSize => u32::try_from(
            socket_recv_buffer_size(descriptor)
                .map_err(|error| NativeError::system(Operation::GetSocketOption, error))?,
        )
        .map_err(|_| {
            NativeError::internal(
                Operation::GetSocketOption,
                "kernel receive buffer size does not fit u32",
            )
        })?,
        Ipv6SocketOption::SendBufferSize => u32::try_from(
            socket_send_buffer_size(descriptor)
                .map_err(|error| NativeError::system(Operation::GetSocketOption, error))?,
        )
        .map_err(|_| {
            NativeError::internal(
                Operation::GetSocketOption,
                "kernel send buffer size does not fit u32",
            )
        })?,
    };
    Ok(value)
}

fn nix_get_error(error: nix::errno::Errno) -> NativeError {
    NativeError::system_nix(Operation::GetSocketOption, error)
}
fn checked_nonnegative(value: i32) -> Result<u32, NativeError> {
    u32::try_from(value).map_err(|_| {
        NativeError::internal(
            Operation::GetSocketOption,
            "kernel returned a negative IPv6 option",
        )
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::os::fd::AsFd;

    use rustix::fs::{OFlags, fcntl_getfl};
    use rustix::io::{FdFlags, fcntl_getfd};
    use rustix::net::{AddressFamily, SocketType, ipproto};

    use crate::conversion::RawIpv4Protocol;
    use crate::error::{ErrorKind, Operation};
    use crate::lifecycle::SocketStatus;

    use super::{
        Ipv4SocketOption, bind_ipv4, create_ipv4_raw_socket, create_socket, get_ipv4_socket_option,
        local_ipv4_address, set_ipv4_socket_option,
    };

    #[test]
    fn socket_creation_sets_safety_flags_atomically() {
        let descriptor = create_socket(
            AddressFamily::INET,
            SocketType::DGRAM,
            None,
            Operation::CreateRawIpv4Socket,
        )
        .unwrap();

        assert!(fcntl_getfd(&descriptor).unwrap().contains(FdFlags::CLOEXEC));
        assert!(fcntl_getfl(&descriptor).unwrap().contains(OFlags::NONBLOCK));
    }

    #[test]
    fn syscall_creation_failure_retains_errno() {
        let error = create_socket(
            AddressFamily::UNSPEC,
            SocketType::RAW,
            Some(ipproto::RAW),
            Operation::CreateRawIpv4Socket,
        )
        .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::System);
        assert_eq!(error.operation(), Operation::CreateRawIpv4Socket);
        assert!(error.errno().is_some());
        assert!(error.errno_name().is_some());
    }

    #[test]
    fn raw_socket_creation_preserves_permission_or_success_result() {
        let protocol = RawIpv4Protocol::try_from(1).unwrap();

        match create_ipv4_raw_socket(protocol) {
            Ok(socket) => {
                assert_eq!(socket.status(), SocketStatus::Open);
                assert!(socket.close().initiated());
            }
            Err(error) => {
                assert_eq!(error.kind(), ErrorKind::System);
                assert_eq!(error.operation(), Operation::CreateRawIpv4Socket);
                assert!(error.errno().is_some());
            }
        }
    }

    #[test]
    fn interface_lookup_round_trips_loopback() {
        let index = super::interface_index("lo").unwrap();
        assert_ne!(index, 0);
        assert_eq!(super::interface_name(index).unwrap(), "lo");
        assert!(super::interface_index("").is_err());
        assert!(super::interface_name(0).is_err());
    }

    #[test]
    fn typed_options_and_bind_use_safe_checked_wrappers() {
        let descriptor = create_socket(
            AddressFamily::INET,
            SocketType::DGRAM,
            None,
            Operation::CreateRawIpv4Socket,
        )
        .unwrap();

        bind_ipv4(descriptor.as_fd(), Ipv4Addr::LOCALHOST).unwrap();
        assert_eq!(
            local_ipv4_address(descriptor.as_fd()).unwrap(),
            Ipv4Addr::LOCALHOST
        );

        set_ipv4_socket_option(descriptor.as_fd(), Ipv4SocketOption::IpTtl, 42).unwrap();
        assert_eq!(
            get_ipv4_socket_option(descriptor.as_fd(), Ipv4SocketOption::IpTtl).unwrap(),
            42
        );
        assert!(set_ipv4_socket_option(descriptor.as_fd(), Ipv4SocketOption::IpTtl, 0).is_err());
        assert!(Ipv4SocketOption::parse("arbitrary", Operation::SetSocketOption).is_err());
    }
}
