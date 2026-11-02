use std::num::NonZeroU8;

use rustix::net::Protocol;

use crate::error::{NativeError, Operation};

pub const MAX_IPV4_PACKET_LENGTH: u64 = 65_535;

/// A nonzero IPv4 protocol number suitable for a raw IPv4 socket.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RawIpv4Protocol(NonZeroU8);
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RawIpv6Protocol(NonZeroU8);

impl RawIpv4Protocol {
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0.get()
    }

    #[must_use]
    pub fn as_rustix(self) -> Protocol {
        Protocol::from_raw(self.0.into())
    }
}

impl TryFrom<u32> for RawIpv4Protocol {
    type Error = NativeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let narrowed = u8::try_from(value).ok().and_then(NonZeroU8::new);
        narrowed.map(Self).ok_or_else(|| {
            NativeError::invalid_argument(
                Operation::ValidateRawIpv4Protocol,
                "raw IPv4 protocol must be an integer from 1 through 255",
            )
        })
    }
}

impl RawIpv6Protocol {
    #[must_use]
    pub fn as_rustix(self) -> Protocol {
        Protocol::from_raw(self.0.into())
    }
}

impl TryFrom<u32> for RawIpv6Protocol {
    type Error = NativeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        u8::try_from(value)
            .ok()
            .and_then(NonZeroU8::new)
            .map(Self)
            .ok_or_else(|| {
                NativeError::invalid_argument(
                    Operation::ValidateRawIpv6Protocol,
                    "raw IPv6 protocol must be an integer from 1 through 255",
                )
            })
    }
}

/// A bounded, nonzero buffer size for one IPv4 packet.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PacketBufferLength(u16);

impl PacketBufferLength {
    #[must_use]
    pub const fn get(self) -> usize {
        self.0 as usize
    }
}

impl TryFrom<u64> for PacketBufferLength {
    type Error = NativeError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let narrowed = u16::try_from(value).ok().filter(|length| *length != 0);
        narrowed.map(Self).ok_or_else(|| {
            NativeError::invalid_argument(
                Operation::ValidatePacketBufferLength,
                format!("packet buffer length must be from 1 through {MAX_IPV4_PACKET_LENGTH}"),
            )
        })
    }
}

/// A checked range into an already validated buffer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BufferRange {
    offset: usize,
    length: usize,
}

impl BufferRange {
    /// Creates a range after checked integer conversion, addition, and bounds.
    ///
    /// # Errors
    ///
    /// Returns `ERR_INVALID_ARGUMENT` if either value cannot fit `usize`, if
    /// offset plus length overflows, or if the resulting end exceeds the buffer.
    pub fn new(total_length: usize, offset: u64, length: u64) -> Result<Self, NativeError> {
        let offset = usize::try_from(offset).map_err(|_| invalid_buffer_range())?;
        let length = usize::try_from(length).map_err(|_| invalid_buffer_range())?;
        let end = offset
            .checked_add(length)
            .ok_or_else(invalid_buffer_range)?;

        if end > total_length {
            return Err(invalid_buffer_range());
        }

        Ok(Self { offset, length })
    }

    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }

    #[must_use]
    pub const fn length(self) -> usize {
        self.length
    }

    #[must_use]
    pub const fn end(self) -> usize {
        self.offset + self.length
    }
}

fn invalid_buffer_range() -> NativeError {
    NativeError::invalid_argument(
        Operation::ValidateBufferRange,
        "buffer offset and length must describe a range inside the buffer",
    )
}

#[cfg(test)]
mod tests {
    use crate::error::{ErrorKind, Operation};

    use super::{
        BufferRange, MAX_IPV4_PACKET_LENGTH, PacketBufferLength, RawIpv4Protocol, RawIpv6Protocol,
    };

    #[test]
    fn raw_protocol_accepts_full_valid_range() {
        assert_eq!(RawIpv4Protocol::try_from(1).unwrap().value(), 1);
        assert_eq!(RawIpv4Protocol::try_from(255).unwrap().value(), 255);
    }

    #[test]
    fn raw_protocol_rejects_zero_and_narrowing_overflow() {
        for value in [0, 256, u32::MAX] {
            let error = RawIpv4Protocol::try_from(value).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::InvalidArgument);
            assert_eq!(error.operation(), Operation::ValidateRawIpv4Protocol);
        }
    }

    #[test]
    fn ipv6_protocol_has_the_same_checked_numeric_domain() {
        assert!(RawIpv6Protocol::try_from(58).is_ok());
        for value in [0, 256, u32::MAX] {
            let error = RawIpv6Protocol::try_from(value).unwrap_err();
            assert_eq!(error.operation(), Operation::ValidateRawIpv6Protocol);
        }
    }

    #[test]
    fn packet_length_checks_both_boundaries() {
        assert_eq!(PacketBufferLength::try_from(1).unwrap().get(), 1);
        assert_eq!(
            PacketBufferLength::try_from(MAX_IPV4_PACKET_LENGTH)
                .unwrap()
                .get(),
            65_535
        );

        for value in [0, MAX_IPV4_PACKET_LENGTH + 1, u64::MAX] {
            assert!(PacketBufferLength::try_from(value).is_err());
        }
    }

    #[test]
    fn buffer_range_checks_addition_and_buffer_bounds() {
        let range = BufferRange::new(64, 16, 32).unwrap();
        assert_eq!(range.offset(), 16);
        assert_eq!(range.length(), 32);
        assert_eq!(range.end(), 48);

        assert!(BufferRange::new(64, 65, 0).is_err());
        assert!(BufferRange::new(64, 32, 33).is_err());
        assert!(BufferRange::new(64, u64::MAX, 1).is_err());
    }

    #[test]
    fn empty_range_at_buffer_end_is_valid() {
        assert_eq!(BufferRange::new(64, 64, 0).unwrap().end(), 64);
    }
}
