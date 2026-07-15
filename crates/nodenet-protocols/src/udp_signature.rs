//! Finite, allocation-bounded byte signatures for simple UDP responses.
//!
//! This deliberately is not a regular-expression engine. A signature is a
//! short ordered list of exact, prefix, masked-byte, and capped ASCII
//! extraction operations. Matching performs one forward bounded pass per
//! clause and never recurses or backtracks.

use core::fmt;

pub const MAX_UDP_SIGNATURE_CLAUSES: usize = 32;
pub const MAX_UDP_SIGNATURE_EXTRACT_BYTES: usize = 255;
pub const MAX_UDP_SIGNATURE_WORK: usize = 65_527;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpSignatureClause {
    Prefix(&'static [u8]),
    ExactAt {
        offset: u16,
        value: &'static [u8],
    },
    MaskedByteAt {
        offset: u16,
        mask: u8,
        value: u8,
    },
    ExtractAscii {
        offset: u16,
        maximum_bytes: u8,
        terminator: Option<u8>,
        field_id: u16,
        required: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpByteSignature {
    pub maximum_input_bytes: usize,
    pub clauses: &'static [UdpSignatureClause],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpSignatureMatch {
    pub extracted: Vec<(u16, String)>,
    pub work: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpSignatureError {
    EmptySignature,
    TooManyClauses,
    InvalidInputCeiling,
    EmptyTest,
    OffsetOutOfBounds,
    InvalidMask,
    InvalidExtraction,
    DuplicateFieldId,
    WorkLimitExceeded,
    InputTooLarge,
    NoMatch,
    InvalidText,
}

impl fmt::Display for UdpSignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid UDP byte signature: {self:?}")
    }
}

impl std::error::Error for UdpSignatureError {}

/// Validates that a signature has finite offsets, extraction, and worst-case
/// work before it enters a packet path.
///
/// # Errors
///
/// Returns the first deterministic structural or resource violation.
pub fn validate_udp_signature(signature: UdpByteSignature) -> Result<usize, UdpSignatureError> {
    if signature.clauses.is_empty() {
        return Err(UdpSignatureError::EmptySignature);
    }
    if signature.clauses.len() > MAX_UDP_SIGNATURE_CLAUSES {
        return Err(UdpSignatureError::TooManyClauses);
    }
    if signature.maximum_input_bytes == 0 || signature.maximum_input_bytes > MAX_UDP_SIGNATURE_WORK
    {
        return Err(UdpSignatureError::InvalidInputCeiling);
    }
    let mut work = 0_usize;
    let mut fields = [0_u16; MAX_UDP_SIGNATURE_CLAUSES];
    let mut field_count = 0_usize;
    for clause in signature.clauses {
        let (offset, length) = match clause {
            UdpSignatureClause::Prefix(value) => {
                if value.is_empty() {
                    return Err(UdpSignatureError::EmptyTest);
                }
                (0_usize, value.len())
            }
            UdpSignatureClause::ExactAt { offset, value } => {
                if value.is_empty() {
                    return Err(UdpSignatureError::EmptyTest);
                }
                (usize::from(*offset), value.len())
            }
            UdpSignatureClause::MaskedByteAt {
                offset,
                mask,
                value,
            } => {
                if *mask == 0 || value & !mask != 0 {
                    return Err(UdpSignatureError::InvalidMask);
                }
                (usize::from(*offset), 1)
            }
            UdpSignatureClause::ExtractAscii {
                offset,
                maximum_bytes,
                field_id,
                ..
            } => {
                if *maximum_bytes == 0
                    || usize::from(*maximum_bytes) > MAX_UDP_SIGNATURE_EXTRACT_BYTES
                    || *field_id == 0
                {
                    return Err(UdpSignatureError::InvalidExtraction);
                }
                if fields[..field_count].contains(field_id) {
                    return Err(UdpSignatureError::DuplicateFieldId);
                }
                fields[field_count] = *field_id;
                field_count += 1;
                (usize::from(*offset), usize::from(*maximum_bytes))
            }
        };
        offset
            .checked_add(length)
            .filter(|end| *end <= signature.maximum_input_bytes)
            .ok_or(UdpSignatureError::OffsetOutOfBounds)?;
        work = work
            .checked_add(length)
            .filter(|work| *work <= MAX_UDP_SIGNATURE_WORK)
            .ok_or(UdpSignatureError::WorkLimitExceeded)?;
    }
    Ok(work)
}

/// Matches a previously defined finite signature and copies only its capped
/// normalized text fields.
///
/// # Errors
///
/// Rejects an invalid signature, oversized input, failed clause, or non-ASCII
/// extraction. It never partially returns extracted fields.
pub fn match_udp_signature(
    signature: UdpByteSignature,
    input: &[u8],
) -> Result<UdpSignatureMatch, UdpSignatureError> {
    let maximum_work = validate_udp_signature(signature)?;
    if input.len() > signature.maximum_input_bytes {
        return Err(UdpSignatureError::InputTooLarge);
    }
    let mut extracted = Vec::new();
    let mut work = 0_usize;
    for clause in signature.clauses {
        match clause {
            UdpSignatureClause::Prefix(value) => {
                work += value.len();
                if !input.starts_with(value) {
                    return Err(UdpSignatureError::NoMatch);
                }
            }
            UdpSignatureClause::ExactAt { offset, value } => {
                work += value.len();
                let start = usize::from(*offset);
                if input.get(start..start + value.len()) != Some(*value) {
                    return Err(UdpSignatureError::NoMatch);
                }
            }
            UdpSignatureClause::MaskedByteAt {
                offset,
                mask,
                value,
            } => {
                work += 1;
                if input.get(usize::from(*offset)).map(|byte| byte & mask) != Some(*value) {
                    return Err(UdpSignatureError::NoMatch);
                }
            }
            UdpSignatureClause::ExtractAscii {
                offset,
                maximum_bytes,
                terminator,
                field_id,
                required,
            } => {
                let start = usize::from(*offset);
                let available = input.get(start..).ok_or(UdpSignatureError::NoMatch)?;
                let maximum = usize::from(*maximum_bytes).min(available.len());
                work += usize::from(*maximum_bytes);
                let candidate = &available[..maximum];
                let end = terminator
                    .and_then(|terminator| candidate.iter().position(|byte| *byte == terminator))
                    .unwrap_or(candidate.len());
                let value = &candidate[..end];
                if value.is_empty() {
                    if *required {
                        return Err(UdpSignatureError::NoMatch);
                    }
                    continue;
                }
                if !value.iter().all(|byte| matches!(byte, 0x20..=0x7e | b'\t')) {
                    return Err(UdpSignatureError::InvalidText);
                }
                let value = String::from_utf8(value.to_vec())
                    .map_err(|_| UdpSignatureError::InvalidText)?;
                extracted.push((*field_id, value));
            }
        }
    }
    debug_assert!(work <= maximum_work);
    Ok(UdpSignatureMatch { extracted, work })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNATURE: UdpByteSignature = UdpByteSignature {
        maximum_input_bytes: 64,
        clauses: &[
            UdpSignatureClause::Prefix(b"OK "),
            UdpSignatureClause::ExactAt {
                offset: 3,
                value: b"v",
            },
            UdpSignatureClause::MaskedByteAt {
                offset: 4,
                mask: 0xf0,
                value: 0x30,
            },
            UdpSignatureClause::ExtractAscii {
                offset: 4,
                maximum_bytes: 16,
                terminator: Some(b'\r'),
                field_id: 2,
                required: true,
            },
        ],
    };

    #[test]
    fn finite_signature_matches_and_extracts_without_backtracking() {
        assert_eq!(validate_udp_signature(SIGNATURE), Ok(21));
        let matched = match_udp_signature(SIGNATURE, b"OK v3.2\r\n").unwrap();
        assert_eq!(matched.extracted, vec![(2, "3.2".into())]);
        assert_eq!(matched.work, 21);
    }

    #[test]
    fn hostile_signatures_and_inputs_are_rejected() {
        let empty = UdpByteSignature {
            maximum_input_bytes: 1,
            clauses: &[],
        };
        assert_eq!(
            validate_udp_signature(empty),
            Err(UdpSignatureError::EmptySignature)
        );
        assert_eq!(
            match_udp_signature(SIGNATURE, &[b'O'; 65]),
            Err(UdpSignatureError::InputTooLarge)
        );
        assert_eq!(
            match_udp_signature(SIGNATURE, b"OK v3\xff"),
            Err(UdpSignatureError::InvalidText)
        );
        assert_eq!(
            match_udp_signature(SIGNATURE, b"NO v3.2\r\n"),
            Err(UdpSignatureError::NoMatch)
        );
    }

    #[test]
    fn extraction_work_is_bound_by_definition_not_packet_contents() {
        let a = match_udp_signature(SIGNATURE, b"OK v3\r").unwrap();
        let b = match_udp_signature(SIGNATURE, b"OK v3333333333333333").unwrap();
        assert_eq!(a.work, b.work);
    }
}
