//! Pure, syscall-free entry points used only by the out-of-tree libFuzzer crate.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::advanced::{ClassicBpfInstruction, validate_classic_bpf, validate_raw_option};
use crate::batch::validate_count_and_bytes;
use crate::conversion::{BufferRange, PacketBufferLength, RawIpv4Protocol, RawIpv6Protocol};
use crate::error::Operation;
use crate::linux::{Ipv4SocketOption, Ipv6SocketOption};
use crate::message::{
    SendControlMessage, fuzz_received_controls, fuzz_send_controls, validate_capacities,
};
use crate::packet::{PacketAddress, fuzz_packet_address, parse_auxdata};
use crate::reactor::parse_ipv4_packet_metadata;
use crate::ring::PacketRingConfig;

fn u32_at(data: &[u8], offset: usize) -> u32 {
    let mut value = [0_u8; 4];
    let available = data.len().saturating_sub(offset).min(4);
    if available != 0 {
        value[..available].copy_from_slice(&data[offset..offset + available]);
    }
    u32::from_ne_bytes(value)
}

/// Exercises every pure parser/serializer and allocation-bound validator.
/// This function must remain deterministic and must never perform a syscall.
pub fn fuzz_surface(data: &[u8]) {
    let a = u32_at(data, 0);
    let b = u32_at(data, 4);
    let c = u32_at(data, 8);
    let d = u32_at(data, 12);
    let _ = RawIpv4Protocol::try_from(a);
    let _ = RawIpv6Protocol::try_from(b);
    let _ = PacketBufferLength::try_from(u64::from(a) << 32 | u64::from(b));
    let _ = BufferRange::new(data.len(), u64::from(b), u64::from(c));
    let _ = validate_capacities(a as usize, b as usize, Operation::ReceiveMessage);
    let _ = validate_count_and_bytes(a as usize, b as usize, Operation::ReceiveBatch);
    let _ = validate_raw_option(a.cast_signed(), b.cast_signed(), Operation::GetSocketOption);
    let _ = parse_auxdata(data, Operation::ReceiveMessage);
    let _ = parse_ipv4_packet_metadata(data);
    fuzz_received_controls(a, b, data);
    let text = String::from_utf8_lossy(data);
    let _ = text.parse::<Ipv4Addr>();
    let _ = text.parse::<Ipv6Addr>();
    let _ = Ipv4SocketOption::parse(&text, Operation::GetSocketOption);
    let _ = Ipv6SocketOption::parse(&text, Operation::GetSocketOption);

    let address = PacketAddress::new(
        a,
        b as u16,
        data.get(16..).unwrap_or_default().to_vec(),
        Operation::Send,
    );
    if let Ok(address) = address {
        fuzz_packet_address(&address);
    }
    let _ = PacketRingConfig {
        block_size: a,
        block_count: b,
        frame_size: c,
        retire_timeout_ms: d,
    }
    .validate();

    let instructions = data
        .chunks_exact(8)
        .take(4097)
        .map(|bytes| ClassicBpfInstruction {
            code: u16::from_ne_bytes([bytes[0], bytes[1]]),
            jump_true: bytes[2],
            jump_false: bytes[3],
            value: u32::from_ne_bytes(bytes[4..8].try_into().expect("exact chunk")),
        })
        .collect::<Vec<_>>();
    let _ = validate_classic_bpf(&instructions);

    let controls = [
        SendControlMessage::Ipv4PacketInfo {
            interface_index: a,
            source_address: Some(Ipv4Addr::from(b)),
        },
        SendControlMessage::Ipv4Ttl(c as u8),
        SendControlMessage::Ipv6PacketInfo {
            interface_index: d,
            source_address: Some(Ipv6Addr::from(
                u128::from(a) << 96 | u128::from(b) << 64 | u128::from(c) << 32 | u128::from(d),
            )),
        },
        SendControlMessage::Ipv6HopLimit(a as u8),
        SendControlMessage::Ipv6TrafficClass(b as u8),
    ];
    fuzz_send_controls(&controls);
}
