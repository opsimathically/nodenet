use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};

use nix::libc;

use crate::error::{NativeError, Operation};

pub const MAX_PACKET_RING_BYTES: usize = 64 * 1024 * 1024;
const TPACKET_ALIGNMENT: usize = 16;
const BLOCK_HEADER_OFFSET: usize = 8;
const TPACKET_V3: i32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketRingConfig {
    pub block_size: u32,
    pub block_count: u32,
    pub frame_size: u32,
    pub retire_timeout_ms: u32,
}

#[derive(Debug)]
pub struct RingFrame {
    pub data: Vec<u8>,
    pub original_length: u32,
    pub snapshot_length: u32,
    pub seconds: u32,
    pub nanoseconds: u32,
    pub status: u32,
    pub vlan_tci: u32,
    pub vlan_tpid: u16,
}

pub struct PacketRing {
    mapping: NonNull<u8>,
    mapping_length: usize,
    block_size: usize,
    block_count: usize,
    current_block: usize,
    packets_remaining: usize,
    next_packet_offset: usize,
}

// SAFETY: PacketRing is moved to and accessed only by the reactor thread. The
// marker is required because its owned mmap address has no Rust provenance
// type that carries Send; no reference into the mapping leaves `next_frame`.
#[allow(unsafe_code, reason = "D-024 reactor-confined owned mmap address")]
unsafe impl Send for PacketRing {}

impl PacketRingConfig {
    /// Validates a bounded `TPACKET_V3` receive-ring geometry.
    ///
    /// # Errors
    /// Returns an argument error for unsafe or unsupported geometry.
    #[allow(unsafe_code, reason = "D-024 page-size query has no pointer ownership")]
    pub fn validate(self) -> Result<usize, NativeError> {
        // SAFETY: sysconf is a side-effect-free scalar query.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page_size = usize::try_from(page_size).map_err(|_| {
            NativeError::internal(
                Operation::ConfigurePacketRing,
                "could not determine Linux page size",
            )
        })?;
        let block_size = usize::try_from(self.block_size).map_err(|_| {
            NativeError::invalid_argument(Operation::ConfigurePacketRing, "block size overflowed")
        })?;
        let block_count = usize::try_from(self.block_count).map_err(|_| {
            NativeError::invalid_argument(Operation::ConfigurePacketRing, "block count overflowed")
        })?;
        let frame_size = usize::try_from(self.frame_size).map_err(|_| {
            NativeError::invalid_argument(Operation::ConfigurePacketRing, "frame size overflowed")
        })?;
        let mapping_length = block_size.checked_mul(block_count).ok_or_else(|| {
            NativeError::invalid_argument(Operation::ConfigurePacketRing, "ring size overflowed")
        })?;
        if block_size < page_size
            || block_size % page_size != 0
            || block_count == 0
            || frame_size < 256
            || frame_size % TPACKET_ALIGNMENT != 0
            || block_size % frame_size != 0
            || mapping_length > MAX_PACKET_RING_BYTES
            || self.retire_timeout_ms == 0
            || self.retire_timeout_ms > 60_000
        {
            return Err(NativeError::invalid_argument(
                Operation::ConfigurePacketRing,
                "invalid TPACKET_V3 ring geometry",
            ));
        }
        Ok(mapping_length)
    }
}

impl PacketRing {
    /// Configures and maps one bounded `TPACKET_V3` receive ring.
    ///
    /// # Errors
    /// Returns validation or structured Linux option/mapping errors.
    #[allow(
        unsafe_code,
        reason = "D-024 reviewed PACKET_RX_RING and mmap ownership adapter"
    )]
    pub fn configure(
        descriptor: BorrowedFd<'_>,
        config: PacketRingConfig,
    ) -> Result<Self, NativeError> {
        let mapping_length = config.validate()?;
        let version = TPACKET_V3;
        let version_length =
            libc::socklen_t::try_from(std::mem::size_of_val(&version)).map_err(|_| {
                NativeError::internal(Operation::ConfigurePacketRing, "version size overflowed")
            })?;
        // SAFETY: version is initialized fixed-width input valid for the call.
        let version_result = unsafe {
            libc::setsockopt(
                descriptor.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_VERSION,
                (&raw const version).cast(),
                version_length,
            )
        };
        nix::errno::Errno::result(version_result)
            .map_err(|error| NativeError::system_nix(Operation::ConfigurePacketRing, error))?;
        let frames_per_block = config.block_size / config.frame_size;
        let request = libc::tpacket_req3 {
            tp_block_size: config.block_size,
            tp_block_nr: config.block_count,
            tp_frame_size: config.frame_size,
            tp_frame_nr: frames_per_block
                .checked_mul(config.block_count)
                .ok_or_else(|| {
                    NativeError::invalid_argument(
                        Operation::ConfigurePacketRing,
                        "frame count overflowed",
                    )
                })?,
            tp_retire_blk_tov: config.retire_timeout_ms,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };
        let request_length =
            libc::socklen_t::try_from(std::mem::size_of_val(&request)).map_err(|_| {
                NativeError::internal(Operation::ConfigurePacketRing, "request size overflowed")
            })?;
        // SAFETY: request is initialized pointer-free fixed-size input.
        let ring_result = unsafe {
            libc::setsockopt(
                descriptor.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_RX_RING,
                (&raw const request).cast(),
                request_length,
            )
        };
        nix::errno::Errno::result(ring_result)
            .map_err(|error| NativeError::system_nix(Operation::ConfigurePacketRing, error))?;
        // SAFETY: Linux maps the configured packet ring for mapping_length;
        // successful ownership is captured immediately and unmapped in Drop.
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
            let mapping_error =
                NativeError::system_nix(Operation::ConfigurePacketRing, nix::errno::Errno::last());
            let disabled = libc::tpacket_req3 {
                tp_block_size: 0,
                tp_block_nr: 0,
                tp_frame_size: 0,
                tp_frame_nr: 0,
                tp_retire_blk_tov: 0,
                tp_sizeof_priv: 0,
                tp_feature_req_word: 0,
            };
            // SAFETY: a zero initialized request disables the ring and avoids
            // leaving a half-configured socket after mmap failure.
            unsafe {
                libc::setsockopt(
                    descriptor.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_RX_RING,
                    (&raw const disabled).cast(),
                    request_length,
                );
            }
            return Err(mapping_error);
        };
        Ok(Self {
            mapping,
            mapping_length,
            block_size: usize::try_from(config.block_size).map_err(|_| {
                NativeError::internal(Operation::ConfigurePacketRing, "block size overflowed")
            })?,
            block_count: usize::try_from(config.block_count).map_err(|_| {
                NativeError::internal(Operation::ConfigurePacketRing, "block count overflowed")
            })?,
            current_block: 0,
            packets_remaining: 0,
            next_packet_offset: 0,
        })
    }

    #[allow(unsafe_code, reason = "D-024 checked block offset within owned mmap")]
    fn block_base(&self) -> *mut u8 {
        // SAFETY: current_block is always reduced modulo block_count and the
        // validated product is exactly mapping_length.
        unsafe {
            self.mapping
                .as_ptr()
                .add(self.current_block * self.block_size)
        }
    }

    #[allow(
        unsafe_code,
        clippy::cast_ptr_alignment,
        reason = "mmap is page-aligned and the ABI block status offset is u32-aligned"
    )]
    fn block_status(&self) -> &AtomicU32 {
        // SAFETY: block_base is live for self, BLOCK_HEADER_OFFSET is specified
        // by the TPACKET_V3 ABI and u32-aligned, and ownership of this status
        // word is exchanged with the kernel using acquire/release ordering.
        unsafe { AtomicU32::from_ptr(self.block_base().add(BLOCK_HEADER_OFFSET).cast::<u32>()) }
    }

    /// Copies the next validated frame from a userspace-owned ring block.
    ///
    /// # Errors
    /// Returns malformed-control errors for kernel offsets outside the mapping.
    #[allow(
        unsafe_code,
        clippy::too_many_lines,
        reason = "D-024 reviewed bounded TPACKET_V3 block traversal"
    )]
    pub fn next_frame(&mut self) -> Result<Option<RingFrame>, NativeError> {
        let result = self.next_frame_from_current_block();
        if result.is_err() {
            // A userspace-owned malformed block must not poison all future
            // receives or remain permanently withheld from the kernel.
            self.packets_remaining = 0;
            self.release_current_block();
        }
        result
    }

    #[allow(
        unsafe_code,
        clippy::too_many_lines,
        reason = "D-024 reviewed bounded TPACKET_V3 block traversal"
    )]
    fn next_frame_from_current_block(&mut self) -> Result<Option<RingFrame>, NativeError> {
        let block = self.block_base();
        if self.packets_remaining == 0 {
            let status = self.block_status().load(Ordering::Acquire);
            if status & libc::TP_STATUS_USER == 0 {
                return Ok(None);
            }
            // SAFETY: the v1 block header begins at fixed aligned offset eight.
            let mut header = unsafe {
                std::ptr::read_volatile(
                    block
                        .add(BLOCK_HEADER_OFFSET)
                        .cast::<libc::tpacket_hdr_v1>(),
                )
            };
            header.block_status = status;
            self.packets_remaining = usize::try_from(header.num_pkts).map_err(|_| {
                NativeError::malformed_control(
                    Operation::ReceiveRingFrame,
                    "packet count overflowed",
                )
            })?;
            self.next_packet_offset =
                usize::try_from(header.offset_to_first_pkt).map_err(|_| {
                    NativeError::malformed_control(
                        Operation::ReceiveRingFrame,
                        "packet offset overflowed",
                    )
                })?;
            if self.packets_remaining == 0 {
                self.release_current_block();
                return Ok(None);
            }
        }
        let header_end = self
            .next_packet_offset
            .checked_add(std::mem::size_of::<libc::tpacket3_hdr>())
            .ok_or_else(|| {
                NativeError::malformed_control(
                    Operation::ReceiveRingFrame,
                    "ring header offset overflowed",
                )
            })?;
        if header_end > self.block_size {
            return Err(NativeError::malformed_control(
                Operation::ReceiveRingFrame,
                "ring header leaves block",
            ));
        }
        // SAFETY: bounds above cover the complete possibly unaligned header.
        let header = unsafe {
            std::ptr::read_unaligned(
                block
                    .add(self.next_packet_offset)
                    .cast::<libc::tpacket3_hdr>(),
            )
        };
        let data_offset = self
            .next_packet_offset
            .checked_add(usize::from(header.tp_mac))
            .ok_or_else(|| {
                NativeError::malformed_control(
                    Operation::ReceiveRingFrame,
                    "ring payload offset overflowed",
                )
            })?;
        let data_end = data_offset
            .checked_add(usize::try_from(header.tp_snaplen).map_err(|_| {
                NativeError::malformed_control(
                    Operation::ReceiveRingFrame,
                    "snapshot length overflowed",
                )
            })?)
            .ok_or_else(|| {
                NativeError::malformed_control(
                    Operation::ReceiveRingFrame,
                    "ring payload end overflowed",
                )
            })?;
        if data_offset < header_end || data_end > self.block_size {
            return Err(NativeError::malformed_control(
                Operation::ReceiveRingFrame,
                "ring payload leaves block",
            ));
        }
        // SAFETY: validated payload range lies completely within the mapping.
        let data =
            unsafe { std::slice::from_raw_parts(block.add(data_offset), data_end - data_offset) }
                .to_vec();
        let frame = RingFrame {
            data,
            original_length: header.tp_len,
            snapshot_length: header.tp_snaplen,
            seconds: header.tp_sec,
            nanoseconds: header.tp_nsec,
            status: header.tp_status,
            vlan_tci: header.hv1.tp_vlan_tci,
            vlan_tpid: header.hv1.tp_vlan_tpid,
        };
        self.packets_remaining -= 1;
        if self.packets_remaining == 0 {
            self.release_current_block();
        } else {
            let next = usize::try_from(header.tp_next_offset).map_err(|_| {
                NativeError::malformed_control(
                    Operation::ReceiveRingFrame,
                    "next offset overflowed",
                )
            })?;
            if next < std::mem::size_of::<libc::tpacket3_hdr>() || next % TPACKET_ALIGNMENT != 0 {
                return Err(NativeError::malformed_control(
                    Operation::ReceiveRingFrame,
                    "invalid next ring offset",
                ));
            }
            self.next_packet_offset =
                self.next_packet_offset.checked_add(next).ok_or_else(|| {
                    NativeError::malformed_control(
                        Operation::ReceiveRingFrame,
                        "next ring header overflowed",
                    )
                })?;
        }
        Ok(Some(frame))
    }

    fn release_current_block(&mut self) {
        self.block_status()
            .store(libc::TP_STATUS_KERNEL, Ordering::Release);
        self.current_block = (self.current_block + 1) % self.block_count;
        self.next_packet_offset = 0;
    }
}

#[allow(unsafe_code, reason = "D-024 unique mmap ownership cleanup")]
impl Drop for PacketRing {
    fn drop(&mut self) {
        // SAFETY: mapping/mapping_length are the unique successful mmap result
        // owned by this instance and are unmapped exactly once.
        unsafe {
            libc::munmap(self.mapping.as_ptr().cast(), self.mapping_length);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::NonNull;
    use std::sync::atomic::{AtomicU32, Ordering};

    use nix::libc;

    use super::{BLOCK_HEADER_OFFSET, MAX_PACKET_RING_BYTES, PacketRing, PacketRingConfig};

    #[test]
    fn ring_geometry_is_bounded_and_aligned() {
        let valid = PacketRingConfig {
            block_size: 4096,
            block_count: 2,
            frame_size: 2048,
            retire_timeout_ms: 64,
        };
        assert_eq!(valid.validate().unwrap(), 8192);
        assert!(
            PacketRingConfig {
                frame_size: 257,
                ..valid
            }
            .validate()
            .is_err()
        );
        assert!(
            PacketRingConfig {
                block_count: 0,
                ..valid
            }
            .validate()
            .is_err()
        );
        assert!(
            PacketRingConfig {
                block_size: u32::try_from(MAX_PACKET_RING_BYTES).unwrap(),
                block_count: 2,
                ..valid
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    #[allow(
        unsafe_code,
        clippy::cast_ptr_alignment,
        reason = "constructs a private anonymous test mapping for malformed-block recovery"
    )]
    fn malformed_userspace_block_is_returned_to_kernel_ownership() {
        // SAFETY: the anonymous mapping is uniquely transferred to PacketRing,
        // which unmaps it exactly once in Drop.
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .expect("positive test page size");
        let mapping_length = page_size.checked_mul(2).expect("test mapping size");
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapping_length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        let mapping = NonNull::new(mapped.cast::<u8>())
            .filter(|_| mapped != libc::MAP_FAILED)
            .expect("anonymous test mapping");
        let mut header: libc::tpacket_hdr_v1 = unsafe { std::mem::zeroed() };
        header.block_status = libc::TP_STATUS_USER;
        header.num_pkts = 1;
        header.offset_to_first_pkt = u32::try_from(page_size).unwrap();
        unsafe {
            std::ptr::write(
                mapping
                    .as_ptr()
                    .add(BLOCK_HEADER_OFFSET)
                    .cast::<libc::tpacket_hdr_v1>(),
                header,
            );
        }
        let mut ring = PacketRing {
            mapping,
            mapping_length,
            block_size: page_size,
            block_count: 2,
            current_block: 0,
            packets_remaining: 0,
            next_packet_offset: 0,
        };

        assert!(ring.next_frame().is_err());
        assert_eq!(ring.current_block, 1);
        assert_eq!(ring.packets_remaining, 0);
        let status = unsafe {
            AtomicU32::from_ptr(mapping.as_ptr().add(BLOCK_HEADER_OFFSET).cast::<u32>())
                .load(Ordering::Acquire)
        };
        assert_eq!(status, libc::TP_STATUS_KERNEL);
    }
}
