//! Non-public Phase 25 Linux backend prototypes.
//!
//! This executable deliberately does not attach an XDP program or expose mapped
//! storage. It validates `PACKET_TX_RING` ownership/cleanup and `AF_XDP` socket/UMEM
//! setup independently from the published scanner API.

#![allow(
    unsafe_code,
    reason = "isolated Phase 25 Linux packet-ring and AF_XDP ABI prototype"
)]

use std::env;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;
use std::time::{Duration, Instant};

use nix::libc;

const ETH_P_ALL: u16 = 0x0003;
const EXPERIMENTAL_PROTOCOL: u16 = 0x88b7;
const TPACKET_V2: i32 = 1;
const BLOCK_SIZE: u32 = 65_536;
const BLOCK_COUNT: u32 = 4;
const FRAME_SIZE: u32 = 2_048;
const UMEM_FRAME_SIZE: usize = 2_048;
const UMEM_FRAME_COUNT: usize = 2_048;
const XDP_COPY: u16 = 1 << 1;
const XDP_ZEROCOPY: u16 = 1 << 2;

fn last_error(context: &str) -> io::Error {
    io::Error::new(
        io::Error::last_os_error().kind(),
        format!("{context}: {}", io::Error::last_os_error()),
    )
}

fn interface_index(name: &str) -> io::Result<u32> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface contains NUL"))?;
    // SAFETY: `name` is a live NUL-terminated C string for the complete call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        Err(last_error("resolve interface"))
    } else {
        Ok(index)
    }
}

fn packet_socket() -> io::Result<OwnedFd> {
    // SAFETY: scalar socket arguments contain no pointers; ownership is captured.
    let descriptor = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            i32::from(ETH_P_ALL.to_be()),
        )
    };
    if descriptor == -1 {
        Err(last_error("open AF_PACKET socket"))
    } else {
        // SAFETY: successful `socket` returned one newly owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

fn set_option<T>(descriptor: &OwnedFd, level: i32, name: i32, value: &T) -> io::Result<()> {
    let length = libc::socklen_t::try_from(std::mem::size_of::<T>())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "option size overflow"))?;
    // SAFETY: `value` is initialized input of exactly `length` bytes.
    let result = unsafe {
        libc::setsockopt(
            descriptor.as_raw_fd(),
            level,
            name,
            std::ptr::from_ref(value).cast(),
            length,
        )
    };
    if result == -1 {
        Err(last_error("setsockopt"))
    } else {
        Ok(())
    }
}

fn bind_packet(descriptor: &OwnedFd, index: u32) -> io::Result<()> {
    let address = libc::sockaddr_ll {
        sll_family: u16::try_from(libc::AF_PACKET).unwrap_or_default(),
        sll_protocol: ETH_P_ALL.to_be(),
        sll_ifindex: i32::try_from(index)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface overflow"))?,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    let length = libc::socklen_t::try_from(std::mem::size_of_val(&address))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "address size overflow"))?;
    // SAFETY: fixed-size initialized sockaddr is borrowed for the call.
    let result = unsafe {
        libc::bind(
            descriptor.as_raw_fd(),
            std::ptr::from_ref(&address).cast(),
            length,
        )
    };
    if result == -1 {
        Err(last_error("bind AF_PACKET socket"))
    } else {
        Ok(())
    }
}

struct TxRing {
    descriptor: OwnedFd,
    mapping: NonNull<u8>,
    mapping_length: usize,
    frame_count: usize,
}

impl TxRing {
    fn open(interface: u32) -> io::Result<Self> {
        let descriptor = packet_socket()?;
        bind_packet(&descriptor, interface)?;
        set_option(
            &descriptor,
            libc::SOL_PACKET,
            libc::PACKET_VERSION,
            &TPACKET_V2,
        )?;
        let bypass = 1_i32;
        set_option(
            &descriptor,
            libc::SOL_PACKET,
            libc::PACKET_QDISC_BYPASS,
            &bypass,
        )?;
        let frames_per_block = BLOCK_SIZE / FRAME_SIZE;
        let request = libc::tpacket_req {
            tp_block_size: BLOCK_SIZE,
            tp_block_nr: BLOCK_COUNT,
            tp_frame_size: FRAME_SIZE,
            tp_frame_nr: frames_per_block * BLOCK_COUNT,
        };
        set_option(
            &descriptor,
            libc::SOL_PACKET,
            libc::PACKET_TX_RING,
            &request,
        )?;
        let mapping_length = usize::try_from(BLOCK_SIZE)
            .ok()
            .and_then(|size| size.checked_mul(usize::try_from(BLOCK_COUNT).ok()?))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ring size overflow"))?;
        // SAFETY: the successful PACKET_TX_RING configuration defines this
        // shared mapping; the unique address is captured and unmapped in Drop.
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapping_length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                descriptor.as_raw_fd(),
                0,
            )
        };
        let mapping = NonNull::new(mapped.cast::<u8>()).filter(|_| mapped != libc::MAP_FAILED);
        let Some(mapping) = mapping else {
            return Err(last_error("mmap PACKET_TX_RING"));
        };
        Ok(Self {
            descriptor,
            mapping,
            mapping_length,
            frame_count: usize::try_from(request.tp_frame_nr)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame count overflow"))?,
        })
    }

    fn frame_base(&self, index: usize) -> *mut u8 {
        debug_assert!(index < self.frame_count);
        // SAFETY: index is reduced modulo frame_count and validated geometry
        // makes each complete FRAME_SIZE region part of the owned mapping.
        unsafe {
            self.mapping
                .as_ptr()
                .add(index * usize::try_from(FRAME_SIZE).unwrap_or_default())
        }
    }

    #[allow(
        clippy::cast_ptr_alignment,
        reason = "mmap and fixed frame strides guarantee u32 header alignment"
    )]
    fn wait_available(&self, index: usize, deadline: Instant) -> io::Result<()> {
        let status = self.frame_base(index).cast::<u32>();
        loop {
            // SAFETY: status is the aligned first field of a live mapped frame.
            let value = unsafe { std::ptr::read_volatile(status) };
            if value == libc::TP_STATUS_AVAILABLE {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "kernel did not release TX frame",
                ));
            }
            std::thread::yield_now();
        }
    }

    #[allow(
        clippy::cast_ptr_alignment,
        reason = "mmap and fixed frame strides guarantee tpacket2 header alignment"
    )]
    fn stage(&self, index: usize, destination: [u8; 6], sequence: u32) -> io::Result<()> {
        self.wait_available(index, Instant::now() + Duration::from_secs(1))?;
        let frame = self.frame_base(index);
        let data_offset = libc::TPACKET2_HDRLEN
            .checked_sub(std::mem::size_of::<libc::sockaddr_ll>())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid header offset"))?;
        let data_length = 96_usize;
        if data_offset + data_length > usize::try_from(FRAME_SIZE).unwrap_or_default() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame leaves TX slot",
            ));
        }
        let mut bytes = [0x5a_u8; 96];
        bytes[0..6].copy_from_slice(&destination);
        bytes[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0x25, 1]);
        bytes[12..14].copy_from_slice(&EXPERIMENTAL_PROTOCOL.to_be_bytes());
        bytes[14..18].copy_from_slice(&sequence.to_be_bytes());
        // SAFETY: the complete source fits the validated writable frame slot.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), frame.add(data_offset), bytes.len());
        }
        let header = frame.cast::<libc::tpacket2_hdr>();
        // SAFETY: frame is naturally aligned and covers the complete header.
        unsafe {
            (*header).tp_len = u32::try_from(data_length).unwrap_or_default();
            (*header).tp_snaplen = u32::try_from(data_length).unwrap_or_default();
            (*header).tp_mac = u16::try_from(data_offset).unwrap_or_default();
            (*header).tp_net = u16::try_from(data_offset + 14).unwrap_or_default();
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
        // SAFETY: status is the aligned first field and all frame bytes are ready.
        unsafe {
            std::ptr::write_volatile(header.cast::<u32>(), libc::TP_STATUS_SEND_REQUEST);
        }
        Ok(())
    }

    fn kick(&self) -> io::Result<()> {
        // SAFETY: a zero-length send on a configured TX ring asks Linux to
        // transmit every SEND_REQUEST frame and borrows no pointers.
        let result = unsafe {
            libc::sendto(
                self.descriptor.as_raw_fd(),
                std::ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                std::ptr::null(),
                0,
            )
        };
        if result == -1 {
            Err(last_error("kick PACKET_TX_RING"))
        } else {
            Ok(())
        }
    }

    fn send(&self, count: usize, destination: [u8; 6]) -> io::Result<usize> {
        let mut completed = 0;
        while completed < count {
            let batch = (count - completed).min(self.frame_count);
            for offset in 0..batch {
                self.stage(
                    offset,
                    destination,
                    u32::try_from(completed + offset).unwrap_or(u32::MAX),
                )?;
            }
            self.kick()?;
            let deadline = Instant::now() + Duration::from_secs(2);
            for offset in 0..batch {
                self.wait_available(offset, deadline)?;
            }
            completed += batch;
        }
        Ok(completed)
    }
}

impl Drop for TxRing {
    fn drop(&mut self) {
        // SAFETY: this instance uniquely owns the successful mapping.
        unsafe {
            libc::munmap(self.mapping.as_ptr().cast(), self.mapping_length);
        }
        let disabled = libc::tpacket_req {
            tp_block_size: 0,
            tp_block_nr: 0,
            tp_frame_size: 0,
            tp_frame_nr: 0,
        };
        let _ = set_option(
            &self.descriptor,
            libc::SOL_PACKET,
            libc::PACKET_TX_RING,
            &disabled,
        );
    }
}

fn parse_mac(value: &str) -> io::Result<[u8; 6]> {
    let values = value
        .split(':')
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid MAC address"))?;
    values
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "MAC must contain six bytes"))
}

fn packet_mmap(arguments: &[String]) -> io::Result<()> {
    if arguments.len() != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet-mmap requires INTERFACE DESTINATION-MAC COUNT",
        ));
    }
    let index = interface_index(&arguments[0])?;
    let destination = parse_mac(&arguments[1])?;
    let count = arguments[2]
        .parse::<usize>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid count"))?;
    let ring = TxRing::open(index)?;
    let started = Instant::now();
    let completed = ring.send(count, destination)?;
    let elapsed = started.elapsed();
    println!(
        "{{\"status\":\"ok\",\"backend\":\"PACKET_TX_RING\",\"version\":\"TPACKET_V2\",\"submitted\":{count},\"completed\":{completed},\"elapsedNanoseconds\":\"{}\",\"mappingBytes\":{}}}",
        elapsed.as_nanos(),
        ring.mapping_length
    );
    Ok(())
}

fn xdp_socket() -> io::Result<OwnedFd> {
    // SAFETY: scalar socket arguments contain no pointers; ownership is captured.
    let descriptor = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
    if descriptor == -1 {
        Err(last_error("open AF_XDP socket"))
    } else {
        // SAFETY: successful `socket` returned one newly owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

fn probe_xdp_mode(interface: u32, flags: u16) -> io::Result<()> {
    let descriptor = xdp_socket()?;
    let mut umem = vec![0_u8; UMEM_FRAME_SIZE * UMEM_FRAME_COUNT];
    let registration = libc::xdp_umem_reg {
        addr: umem.as_mut_ptr() as u64,
        len: u64::try_from(umem.len()).unwrap_or_default(),
        chunk_size: u32::try_from(UMEM_FRAME_SIZE).unwrap_or_default(),
        headroom: 0,
        flags: 0,
        tx_metadata_len: 0,
    };
    set_option(
        &descriptor,
        libc::SOL_XDP,
        libc::XDP_UMEM_REG,
        &registration,
    )?;
    let entries = 2_048_u32;
    for option in [
        libc::XDP_UMEM_FILL_RING,
        libc::XDP_UMEM_COMPLETION_RING,
        libc::XDP_RX_RING,
        libc::XDP_TX_RING,
    ] {
        set_option(&descriptor, libc::SOL_XDP, option, &entries)?;
    }
    let address = libc::sockaddr_xdp {
        sxdp_family: u16::try_from(libc::AF_XDP).unwrap_or_default(),
        sxdp_flags: flags,
        sxdp_ifindex: interface,
        sxdp_queue_id: 0,
        sxdp_shared_umem_fd: 0,
    };
    let length = libc::socklen_t::try_from(std::mem::size_of_val(&address))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "XDP address overflow"))?;
    // SAFETY: initialized sockaddr_xdp is borrowed for the complete bind call.
    let result = unsafe {
        libc::bind(
            descriptor.as_raw_fd(),
            std::ptr::from_ref(&address).cast(),
            length,
        )
    };
    let outcome = if result == -1 {
        Err(last_error("bind AF_XDP socket"))
    } else {
        Ok(())
    };
    // The socket must release its registered UMEM before its backing allocation.
    drop(descriptor);
    drop(umem);
    outcome
}

fn af_xdp(arguments: &[String]) -> io::Result<()> {
    if arguments.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "af-xdp requires INTERFACE",
        ));
    }
    let index = interface_index(&arguments[0])?;
    let copy = probe_xdp_mode(index, XDP_COPY);
    let zero_copy = probe_xdp_mode(index, XDP_ZEROCOPY);
    println!(
        "{{\"status\":\"probed\",\"backend\":\"AF_XDP\",\"copy\":{},\"zeroCopy\":{},\"dataPlaneQualified\":false,\"reason\":\"no benchmark-owned XDP program or XSKMAP was attached\"}}",
        if copy.is_ok() { "true" } else { "false" },
        if zero_copy.is_ok() { "true" } else { "false" }
    );
    Ok(())
}

fn main() -> io::Result<()> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let Some((command, rest)) = arguments.split_first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected packet-mmap or af-xdp",
        ));
    };
    match command.as_str() {
        "packet-mmap" => packet_mmap(rest),
        "af-xdp" => af_xdp(rest),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown Phase 25 lab command",
        )),
    }
}
