use std::io::IoSliceMut;
use std::os::fd::{AsRawFd, BorrowedFd};

use nix::libc;
use nix::sys::socket::{ControlMessageOwned, LinkAddr, MsgFlags, recvmsg};

use crate::error::{NativeError, Operation};
use crate::message::{ReceiveMessageFlags, ReceivedMessageFlags, SendMessageFlags};

pub const MAX_LINK_ADDRESS_LENGTH: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketMode {
    Raw,
    Cooked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketAddress {
    pub interface_index: u32,
    pub protocol: u16,
    pub hardware_address: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ReceivedPacketMessage {
    pub data: Vec<u8>,
    pub source: PacketAddress,
    pub hardware_type: u16,
    pub packet_type: u8,
    pub data_length: usize,
    pub data_truncated: bool,
    pub control_truncated: bool,
    pub flags: ReceivedMessageFlags,
    pub auxdata: Option<PacketAuxdata>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketAuxdata {
    pub status: u32,
    pub original_length: u32,
    pub snapshot_length: u32,
    pub mac_offset: u16,
    pub network_offset: u16,
    pub vlan_tci: u16,
    pub vlan_tpid: u16,
}

pub(crate) fn parse_auxdata(
    bytes: &[u8],
    operation: Operation,
) -> Result<PacketAuxdata, NativeError> {
    if bytes.len() < 20 {
        return Err(NativeError::malformed_control(
            operation,
            "PACKET_AUXDATA payload is shorter than tpacket_auxdata",
        ));
    }
    Ok(PacketAuxdata {
        status: u32::from_ne_bytes(bytes[0..4].try_into().expect("checked slice")),
        original_length: u32::from_ne_bytes(bytes[4..8].try_into().expect("checked slice")),
        snapshot_length: u32::from_ne_bytes(bytes[8..12].try_into().expect("checked slice")),
        mac_offset: u16::from_ne_bytes(bytes[12..14].try_into().expect("checked slice")),
        network_offset: u16::from_ne_bytes(bytes[14..16].try_into().expect("checked slice")),
        vlan_tci: u16::from_ne_bytes(bytes[16..18].try_into().expect("checked slice")),
        vlan_tpid: u16::from_ne_bytes(bytes[18..20].try_into().expect("checked slice")),
    })
}

fn checked_link_address_length(
    reported: libc::c_uchar,
    operation: Operation,
) -> Result<usize, NativeError> {
    let length = usize::from(reported);
    if length > MAX_LINK_ADDRESS_LENGTH {
        return Err(NativeError::malformed_control(
            operation,
            "kernel packet source exceeded sockaddr_ll address capacity",
        ));
    }
    Ok(length)
}

impl PacketAddress {
    /// Creates a checked Linux packet address.
    ///
    /// # Errors
    /// Returns an argument error for zero indices/protocols or addresses over eight bytes.
    pub fn new(
        interface_index: u32,
        protocol: u16,
        hardware_address: Vec<u8>,
        operation: Operation,
    ) -> Result<Self, NativeError> {
        if interface_index == 0 || interface_index > i32::MAX.cast_unsigned() {
            return Err(NativeError::invalid_argument(
                operation,
                "packet interface index must be from 1 through i32::MAX",
            ));
        }
        if protocol == 0 {
            return Err(NativeError::invalid_argument(
                operation,
                "packet protocol must be from 1 through 65535",
            ));
        }
        if hardware_address.len() > MAX_LINK_ADDRESS_LENGTH {
            return Err(NativeError::invalid_argument(
                operation,
                "packet hardware address must not exceed eight bytes",
            ));
        }
        Ok(Self {
            interface_index,
            protocol,
            hardware_address,
        })
    }

    pub(crate) fn to_native(&self) -> libc::sockaddr_ll {
        let mut address = libc::sockaddr_ll {
            sll_family: libc::c_ushort::try_from(libc::AF_PACKET).expect("AF_PACKET fits c_ushort"),
            sll_protocol: self.protocol.to_be(),
            sll_ifindex: self.interface_index.cast_signed(),
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: libc::c_uchar::try_from(self.hardware_address.len())
                .expect("validated link address length"),
            sll_addr: [0; 8],
        };
        address.sll_addr[..self.hardware_address.len()].copy_from_slice(&self.hardware_address);
        address
    }
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_packet_address(address: &PacketAddress) {
    let _ = address.to_native();
}

/// Binds a packet socket to an interface and `EtherType`.
///
/// # Errors
/// Returns the structured Linux `bind(2)` error.
#[allow(
    unsafe_code,
    reason = "D-022 reviewed fixed-size sockaddr_ll bind adapter"
)]
pub fn bind_packet(descriptor: BorrowedFd<'_>, address: &PacketAddress) -> Result<(), NativeError> {
    let native = address.to_native();
    let native_length = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_ll>())
        .map_err(|_| {
            NativeError::internal(Operation::Bind, "sockaddr_ll size did not fit socklen_t")
        })?;
    // SAFETY: `native` is a fully initialized pointer-free `sockaddr_ll`; its
    // address and exact size remain valid for the duration of this call.
    let result = unsafe {
        libc::bind(
            descriptor.as_raw_fd(),
            (&raw const native).cast(),
            native_length,
        )
    };
    nix::errno::Errno::result(result)
        .map(drop)
        .map_err(|error| NativeError::system_nix(Operation::Bind, error))
}

/// Sends one bounded packet message to a checked link address.
///
/// # Errors
/// Returns the structured Linux `sendto(2)` error.
#[allow(
    unsafe_code,
    reason = "D-022 reviewed fixed-size sockaddr_ll send adapter"
)]
pub fn send_packet_message(
    descriptor: BorrowedFd<'_>,
    operation: Operation,
    data: &[u8],
    destination: &PacketAddress,
    flags: SendMessageFlags,
) -> Result<usize, NativeError> {
    let native = destination.to_native();
    let native_length = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_ll>())
        .map_err(|_| NativeError::internal(operation, "sockaddr_ll size did not fit socklen_t"))?;
    let mut native_flags = libc::MSG_NOSIGNAL;
    if flags.dont_route {
        native_flags |= libc::MSG_DONTROUTE;
    }
    loop {
        // SAFETY: data is borrowed for the call; `native` is fully initialized,
        // pointer-free, and passed with its exact Linux ABI size.
        let result = unsafe {
            libc::sendto(
                descriptor.as_raw_fd(),
                data.as_ptr().cast(),
                data.len(),
                native_flags,
                (&raw const native).cast(),
                native_length,
            )
        };
        if result >= 0 {
            return usize::try_from(result).map_err(|_| {
                NativeError::internal(operation, "packet send length did not fit usize")
            });
        }
        let error = nix::errno::Errno::last();
        if error != nix::errno::Errno::EINTR {
            return Err(NativeError::system_nix(operation, error));
        }
    }
}

/// Receives one bounded packet message and decoded `sockaddr_ll` metadata.
///
/// # Errors
/// Returns validation, unsupported-control, or Linux `recvmsg(2)` errors.
#[allow(
    clippy::drop_non_drop,
    reason = "ends IoSliceMut borrow before Vec truncation"
)]
pub fn receive_packet_message(
    descriptor: BorrowedFd<'_>,
    operation: Operation,
    data_capacity: usize,
    flags: ReceiveMessageFlags,
) -> Result<ReceivedPacketMessage, NativeError> {
    if data_capacity == 0 || data_capacity > 65_535 {
        return Err(NativeError::invalid_argument(
            operation,
            "packet capacity must be from 1 through 65535",
        ));
    }
    let mut data = vec![0_u8; data_capacity];
    let mut buffers = [IoSliceMut::new(&mut data)];
    let mut control_buffer = vec![0_u8; 256];
    // AF_PACKET rejects MSG_CMSG_CLOEXEC on supported baseline kernels. Packet
    // controls are kernel metadata and never SCM_RIGHTS descriptor transfers.
    let mut native_flags = MsgFlags::MSG_TRUNC;
    if flags.peek {
        native_flags |= MsgFlags::MSG_PEEK;
    }
    if flags.error_queue {
        return Err(NativeError::unsupported(
            operation,
            "packet sockets do not expose errorQueue in Phase 7",
        ));
    }
    let message = loop {
        match recvmsg::<LinkAddr>(
            descriptor.as_raw_fd(),
            &mut buffers,
            Some(&mut control_buffer),
            native_flags,
        ) {
            Err(nix::errno::Errno::EINTR) => {}
            result => break result.map_err(|error| NativeError::system_nix(operation, error))?,
        }
    };
    let source = message
        .address
        .ok_or_else(|| NativeError::internal(operation, "kernel omitted packet source address"))?;
    let native = source.as_ref();
    let address_length = checked_link_address_length(native.sll_halen, operation)?;
    let interface_index = u32::try_from(native.sll_ifindex).map_err(|_| {
        NativeError::malformed_control(
            operation,
            "kernel returned a negative packet interface index",
        )
    })?;
    let data_length = message.bytes;
    let data_truncated = message.flags.contains(MsgFlags::MSG_TRUNC) || data_length > data_capacity;
    let returned_flags = ReceivedMessageFlags {
        end_of_record: message.flags.contains(MsgFlags::MSG_EOR),
        out_of_band: message.flags.contains(MsgFlags::MSG_OOB),
        error_queue: false,
    };
    let control_truncated = message.flags.contains(MsgFlags::MSG_CTRUNC);
    let mut auxdata = None;
    if !control_truncated {
        for control in message.cmsgs().map_err(|error| {
            NativeError::malformed_control(
                operation,
                format!("failed to traverse packet controls: {error}"),
            )
        })? {
            match control {
                ControlMessageOwned::Unknown(message)
                    if message.cmsg_header.cmsg_level == libc::SOL_PACKET
                        && message.cmsg_header.cmsg_type == libc::PACKET_AUXDATA =>
                {
                    if auxdata.is_some() {
                        return Err(NativeError::malformed_control(
                            operation,
                            "duplicate PACKET_AUXDATA control",
                        ));
                    }
                    auxdata = Some(parse_auxdata(&message.data_bytes, operation)?);
                }
                _ => {
                    return Err(NativeError::unsupported(
                        operation,
                        "unexpected packet control message",
                    ));
                }
            }
        }
    }
    drop(buffers);
    data.truncate(data_length.min(data_capacity));
    Ok(ReceivedPacketMessage {
        data,
        source: PacketAddress {
            interface_index,
            protocol: u16::from_be(native.sll_protocol),
            hardware_address: native.sll_addr[..address_length].to_vec(),
        },
        hardware_type: native.sll_hatype,
        packet_type: native.sll_pkttype,
        data_length,
        data_truncated,
        control_truncated,
        flags: returned_flags,
        auxdata,
    })
}

#[cfg(test)]
mod tests {
    use super::{MAX_LINK_ADDRESS_LENGTH, PacketAddress};
    use crate::error::Operation;

    #[test]
    fn packet_address_checks_bounds_and_encodes_network_order() {
        let address =
            PacketAddress::new(7, 0x88b5, vec![1, 2, 3, 4, 5, 6], Operation::Bind).unwrap();
        let native = address.to_native();
        assert_eq!(
            native.sll_family,
            u16::try_from(nix::libc::AF_PACKET).unwrap()
        );
        assert_eq!(u16::from_be(native.sll_protocol), 0x88b5);
        assert_eq!(native.sll_ifindex, 7);
        assert_eq!(&native.sll_addr[..6], &[1, 2, 3, 4, 5, 6]);
        assert!(PacketAddress::new(0, 1, Vec::new(), Operation::Bind).is_err());
        assert!(PacketAddress::new(1, 0, Vec::new(), Operation::Bind).is_err());
        assert!(
            PacketAddress::new(1, 1, vec![0; MAX_LINK_ADDRESS_LENGTH + 1], Operation::Bind)
                .is_err()
        );
    }
}
