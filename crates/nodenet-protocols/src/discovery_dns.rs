//! Bounded DNS-wire primitives for mDNS/DNS-SD and LLMNR discovery.

use core::fmt;
use std::collections::BTreeSet;

pub const MAX_DISCOVERY_DNS_MESSAGE_BYTES: usize = 9_000;
pub const MAX_DISCOVERY_DNS_RECORDS: usize = 1_024;
pub const MAX_DISCOVERY_DNS_POINTERS: usize = 32;
pub const MAX_DISCOVERY_DNS_NAME_BYTES: usize = 255;
pub const MAX_DISCOVERY_DNS_TXT_ENTRIES: usize = 128;
pub const MAX_DISCOVERY_DNS_TXT_BYTES: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryDnsError {
    Truncated,
    MessageTooLarge,
    TooManyRecords,
    InvalidLabel,
    NameTooLong,
    CompressionLoop,
    TooManyPointers,
    InvalidRecordLength,
    InvalidTxt,
    DuplicateTxtKey,
    ArithmeticOverflow,
}

impl fmt::Display for DiscoveryDnsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid discovery DNS message: {self:?}")
    }
}

impl std::error::Error for DiscoveryDnsError {}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DiscoveryDnsName {
    /// Canonical uncompressed DNS wire bytes with ASCII letters folded to
    /// lowercase. The terminal zero label is included.
    pub canonical_wire: Vec<u8>,
    /// Strict UTF-8 presentation when every label is valid UTF-8.
    pub text: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryDnsQuestion {
    pub name: DiscoveryDnsName,
    pub query_type: u16,
    pub query_class: u16,
    pub requests_unicast: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryDnsTxtEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub text_value: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryDnsRecordData {
    Ptr(DiscoveryDnsName),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: DiscoveryDnsName,
    },
    Txt(Vec<DiscoveryDnsTxtEntry>),
    A([u8; 4]),
    Aaaa([u8; 16]),
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryDnsRecord {
    pub name: DiscoveryDnsName,
    pub record_type: u16,
    pub record_class: u16,
    pub cache_flush: bool,
    pub ttl: u32,
    pub data: DiscoveryDnsRecordData,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryDnsMessage {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<DiscoveryDnsQuestion>,
    pub answers: Vec<DiscoveryDnsRecord>,
    pub authorities: Vec<DiscoveryDnsRecord>,
    pub additionals: Vec<DiscoveryDnsRecord>,
}

impl DiscoveryDnsMessage {
    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.flags & 0x0200 != 0
    }

    pub fn records(&self) -> impl Iterator<Item = &DiscoveryDnsRecord> {
        self.answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.additionals.iter())
    }
}

/// Builds a single-question DNS-wire query.
///
/// # Errors
///
/// Rejects invalid or oversized names and checked length overflow.
pub fn build_discovery_dns_query(
    id: u16,
    name: &str,
    query_type: u16,
    requests_unicast: bool,
) -> Result<Vec<u8>, DiscoveryDnsError> {
    let encoded_name = encode_name(name)?;
    let capacity = 12_usize
        .checked_add(encoded_name.len())
        .and_then(|value| value.checked_add(4))
        .ok_or(DiscoveryDnsError::ArithmeticOverflow)?;
    if capacity > 512 {
        return Err(DiscoveryDnsError::MessageTooLarge);
    }
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(&id.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&1_u16.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&encoded_name);
    output.extend_from_slice(&query_type.to_be_bytes());
    let query_class = 1_u16 | if requests_unicast { 0x8000 } else { 0 };
    output.extend_from_slice(&query_class.to_be_bytes());
    Ok(output)
}

/// Builds the DNS-SD service-type enumeration query.
///
/// # Errors
///
/// Returns the bounded DNS builder error if the frozen query cannot be encoded.
pub fn build_mdns_service_enumeration_query(
    id: u16,
    requests_unicast: bool,
) -> Result<Vec<u8>, DiscoveryDnsError> {
    build_discovery_dns_query(id, "_services._dns-sd._udp.local.", 12, requests_unicast)
}

/// Parses one complete bounded DNS, mDNS, or LLMNR datagram.
///
/// # Errors
///
/// Rejects malformed, truncated, oversized, cyclic, or over-budget messages.
pub fn parse_discovery_dns_message(input: &[u8]) -> Result<DiscoveryDnsMessage, DiscoveryDnsError> {
    if input.len() > MAX_DISCOVERY_DNS_MESSAGE_BYTES {
        return Err(DiscoveryDnsError::MessageTooLarge);
    }
    if input.len() < 12 {
        return Err(DiscoveryDnsError::Truncated);
    }
    let id = read_u16(input, 0)?;
    let flags = read_u16(input, 2)?;
    let question_count = usize::from(read_u16(input, 4)?);
    let answer_count = usize::from(read_u16(input, 6)?);
    let authority_count = usize::from(read_u16(input, 8)?);
    let additional_count = usize::from(read_u16(input, 10)?);
    let record_count = question_count
        .checked_add(answer_count)
        .and_then(|value| value.checked_add(authority_count))
        .and_then(|value| value.checked_add(additional_count))
        .ok_or(DiscoveryDnsError::ArithmeticOverflow)?;
    if record_count > MAX_DISCOVERY_DNS_RECORDS {
        return Err(DiscoveryDnsError::TooManyRecords);
    }

    let mut offset = 12;
    let mut questions = Vec::with_capacity(question_count);
    for _ in 0..question_count {
        let (name, consumed) = decode_name(input, offset)?;
        offset = offset
            .checked_add(consumed)
            .ok_or(DiscoveryDnsError::ArithmeticOverflow)?;
        let query_type = read_u16(input, offset)?;
        let raw_class = read_u16(input, offset + 2)?;
        offset += 4;
        questions.push(DiscoveryDnsQuestion {
            name,
            query_type,
            query_class: raw_class & 0x7fff,
            requests_unicast: raw_class & 0x8000 != 0,
        });
    }
    let answers = parse_records(input, &mut offset, answer_count)?;
    let authorities = parse_records(input, &mut offset, authority_count)?;
    let additionals = parse_records(input, &mut offset, additional_count)?;
    if offset != input.len() {
        return Err(DiscoveryDnsError::InvalidRecordLength);
    }
    Ok(DiscoveryDnsMessage {
        id,
        flags,
        questions,
        answers,
        authorities,
        additionals,
    })
}

fn parse_records(
    input: &[u8],
    offset: &mut usize,
    count: usize,
) -> Result<Vec<DiscoveryDnsRecord>, DiscoveryDnsError> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let (name, consumed) = decode_name(input, *offset)?;
        *offset = offset
            .checked_add(consumed)
            .ok_or(DiscoveryDnsError::ArithmeticOverflow)?;
        let record_type = read_u16(input, *offset)?;
        let raw_class = read_u16(input, *offset + 2)?;
        let ttl = read_u32(input, *offset + 4)?;
        let data_length = usize::from(read_u16(input, *offset + 8)?);
        *offset += 10;
        let data_end = offset
            .checked_add(data_length)
            .ok_or(DiscoveryDnsError::ArithmeticOverflow)?;
        if data_end > input.len() {
            return Err(DiscoveryDnsError::Truncated);
        }
        let data = match record_type {
            1 if data_length == 4 => {
                DiscoveryDnsRecordData::A(input[*offset..data_end].try_into().unwrap())
            }
            12 => {
                let (value, value_length) = decode_name(input, *offset)?;
                if value_length != data_length {
                    return Err(DiscoveryDnsError::InvalidRecordLength);
                }
                DiscoveryDnsRecordData::Ptr(value)
            }
            16 => DiscoveryDnsRecordData::Txt(parse_txt(&input[*offset..data_end])?),
            28 if data_length == 16 => {
                DiscoveryDnsRecordData::Aaaa(input[*offset..data_end].try_into().unwrap())
            }
            33 if data_length >= 7 => {
                let priority = read_u16(input, *offset)?;
                let weight = read_u16(input, *offset + 2)?;
                let port = read_u16(input, *offset + 4)?;
                let (target, target_length) = decode_name(input, *offset + 6)?;
                if target_length + 6 != data_length {
                    return Err(DiscoveryDnsError::InvalidRecordLength);
                }
                DiscoveryDnsRecordData::Srv {
                    priority,
                    weight,
                    port,
                    target,
                }
            }
            1 | 28 | 33 => return Err(DiscoveryDnsError::InvalidRecordLength),
            _ => DiscoveryDnsRecordData::Unknown,
        };
        *offset = data_end;
        records.push(DiscoveryDnsRecord {
            name,
            record_type,
            record_class: raw_class & 0x7fff,
            cache_flush: raw_class & 0x8000 != 0,
            ttl,
            data,
        });
    }
    Ok(records)
}

fn parse_txt(input: &[u8]) -> Result<Vec<DiscoveryDnsTxtEntry>, DiscoveryDnsError> {
    if input.len() > MAX_DISCOVERY_DNS_TXT_BYTES {
        return Err(DiscoveryDnsError::InvalidTxt);
    }
    let mut offset = 0;
    let mut entries = Vec::new();
    let mut keys = BTreeSet::new();
    while offset < input.len() {
        if entries.len() >= MAX_DISCOVERY_DNS_TXT_ENTRIES {
            return Err(DiscoveryDnsError::InvalidTxt);
        }
        let length = usize::from(input[offset]);
        offset += 1;
        let end = offset
            .checked_add(length)
            .ok_or(DiscoveryDnsError::ArithmeticOverflow)?;
        if end > input.len() {
            return Err(DiscoveryDnsError::Truncated);
        }
        let entry = &input[offset..end];
        let split = entry
            .iter()
            .position(|byte| *byte == b'=')
            .unwrap_or(entry.len());
        let key_bytes = &entry[..split];
        if key_bytes.is_empty()
            || key_bytes
                .iter()
                .any(|byte| !(0x20..=0x7e).contains(byte) || *byte == b'=')
        {
            return Err(DiscoveryDnsError::InvalidTxt);
        }
        let key =
            String::from_utf8(key_bytes.to_vec()).map_err(|_| DiscoveryDnsError::InvalidTxt)?;
        let canonical_key = key.to_ascii_lowercase();
        if !keys.insert(canonical_key) {
            return Err(DiscoveryDnsError::DuplicateTxtKey);
        }
        let value = if split == entry.len() {
            Vec::new()
        } else {
            entry[split + 1..].to_vec()
        };
        let text_value = String::from_utf8(value.clone()).ok();
        entries.push(DiscoveryDnsTxtEntry {
            key,
            value,
            text_value,
        });
        offset = end;
    }
    Ok(entries)
}

fn decode_name(input: &[u8], start: usize) -> Result<(DiscoveryDnsName, usize), DiscoveryDnsError> {
    if start >= input.len() {
        return Err(DiscoveryDnsError::Truncated);
    }
    let mut cursor = start;
    let mut consumed = 0_usize;
    let mut jumped = false;
    let mut traversals = 0_usize;
    let mut visited = Vec::with_capacity(MAX_DISCOVERY_DNS_POINTERS);
    let mut wire = Vec::new();
    let mut text_labels = Vec::new();
    let mut all_text = true;
    loop {
        let Some(&length_byte) = input.get(cursor) else {
            return Err(DiscoveryDnsError::Truncated);
        };
        if length_byte & 0xc0 == 0xc0 {
            let Some(&second) = input.get(cursor + 1) else {
                return Err(DiscoveryDnsError::Truncated);
            };
            if !jumped {
                consumed = consumed
                    .checked_add(2)
                    .ok_or(DiscoveryDnsError::ArithmeticOverflow)?;
            }
            let pointer = usize::from(u16::from(length_byte & 0x3f) << 8 | u16::from(second));
            if pointer >= input.len() || visited.contains(&pointer) {
                return Err(DiscoveryDnsError::CompressionLoop);
            }
            traversals += 1;
            if traversals > MAX_DISCOVERY_DNS_POINTERS {
                return Err(DiscoveryDnsError::TooManyPointers);
            }
            visited.push(pointer);
            cursor = pointer;
            jumped = true;
            continue;
        }
        if length_byte & 0xc0 != 0 {
            return Err(DiscoveryDnsError::InvalidLabel);
        }
        cursor += 1;
        if !jumped {
            consumed = consumed
                .checked_add(1)
                .ok_or(DiscoveryDnsError::ArithmeticOverflow)?;
        }
        let length = usize::from(length_byte);
        if length == 0 {
            wire.push(0);
            break;
        }
        if length > 63 {
            return Err(DiscoveryDnsError::InvalidLabel);
        }
        let end = cursor
            .checked_add(length)
            .ok_or(DiscoveryDnsError::ArithmeticOverflow)?;
        if end > input.len() {
            return Err(DiscoveryDnsError::Truncated);
        }
        if wire.len().saturating_add(length).saturating_add(2) > MAX_DISCOVERY_DNS_NAME_BYTES {
            return Err(DiscoveryDnsError::NameTooLong);
        }
        wire.push(length_byte);
        wire.extend(input[cursor..end].iter().map(u8::to_ascii_lowercase));
        match core::str::from_utf8(&input[cursor..end]) {
            Ok(label) if all_text => text_labels.push(label.to_owned()),
            _ => all_text = false,
        }
        if !jumped {
            consumed = consumed
                .checked_add(length)
                .ok_or(DiscoveryDnsError::ArithmeticOverflow)?;
        }
        cursor = end;
    }
    let text = all_text.then(|| {
        if text_labels.is_empty() {
            ".".to_owned()
        } else {
            format!("{}.", text_labels.join("."))
        }
    });
    Ok((
        DiscoveryDnsName {
            canonical_wire: wire,
            text,
        },
        consumed,
    ))
}

fn encode_name(name: &str) -> Result<Vec<u8>, DiscoveryDnsError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return Ok(vec![0]);
    }
    let mut output = Vec::new();
    for label in name.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(DiscoveryDnsError::InvalidLabel);
        }
        output.push(u8::try_from(bytes.len()).map_err(|_| DiscoveryDnsError::InvalidLabel)?);
        output.extend_from_slice(bytes);
    }
    output.push(0);
    if output.len() > MAX_DISCOVERY_DNS_NAME_BYTES {
        return Err(DiscoveryDnsError::NameTooLong);
    }
    Ok(output)
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, DiscoveryDnsError> {
    let bytes = input
        .get(offset..offset.saturating_add(2))
        .ok_or(DiscoveryDnsError::Truncated)?;
    Ok(u16::from_be_bytes(bytes.try_into().unwrap()))
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, DiscoveryDnsError> {
    let bytes = input
        .get(offset..offset.saturating_add(4))
        .ok_or(DiscoveryDnsError::Truncated)?;
    Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_enumeration_query_is_exact_and_bounded() {
        let query = build_mdns_service_enumeration_query(0x1234, true).unwrap();
        assert_eq!(&query[..6], &[0x12, 0x34, 0, 0, 0, 1]);
        assert_eq!(&query[query.len() - 4..], &[0, 12, 0x80, 1]);
        let parsed = parse_discovery_dns_message(&query).unwrap();
        assert_eq!(
            parsed.questions[0].name.text.as_deref(),
            Some("_services._dns-sd._udp.local.")
        );
        assert!(parsed.questions[0].requests_unicast);
    }

    #[test]
    fn compressed_ptr_srv_txt_and_addresses_parse_strictly() {
        let mut packet = build_discovery_dns_query(7, "_http._tcp.local.", 12, false).unwrap();
        packet[2] = 0x84;
        packet[6..8].copy_from_slice(&4_u16.to_be_bytes());
        let owner_offset = 12_u16;
        let owner_pointer = [
            0xc0 | u8::try_from(owner_offset >> 8).unwrap(),
            u8::try_from(owner_offset & 0xff).unwrap(),
        ];
        packet.extend_from_slice(&owner_pointer);
        packet.extend_from_slice(&12_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&120_u32.to_be_bytes());
        let instance = encode_name("Printer._http._tcp.local.").unwrap();
        packet.extend_from_slice(&u16::try_from(instance.len()).unwrap().to_be_bytes());
        packet.extend_from_slice(&instance);
        packet.extend_from_slice(&instance);
        packet.extend_from_slice(&33_u16.to_be_bytes());
        packet.extend_from_slice(&0x8001_u16.to_be_bytes());
        packet.extend_from_slice(&120_u32.to_be_bytes());
        let host = encode_name("printer.local.").unwrap();
        packet.extend_from_slice(&u16::try_from(6 + host.len()).unwrap().to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&631_u16.to_be_bytes());
        packet.extend_from_slice(&host);
        packet.extend_from_slice(&instance);
        packet.extend_from_slice(&16_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&120_u32.to_be_bytes());
        packet.extend_from_slice(&10_u16.to_be_bytes());
        packet.extend_from_slice(&[9, b'n', b'o', b't', b'e', b'=', 0xff, 0, 1, 2]);
        packet.extend_from_slice(&host);
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&120_u32.to_be_bytes());
        packet.extend_from_slice(&4_u16.to_be_bytes());
        packet.extend_from_slice(&[192, 0, 2, 10]);
        let parsed = parse_discovery_dns_message(&packet).unwrap();
        assert_eq!(parsed.answers.len(), 4);
        assert!(matches!(
            parsed.answers[0].data,
            DiscoveryDnsRecordData::Ptr(_)
        ));
        assert!(matches!(
            parsed.answers[1].data,
            DiscoveryDnsRecordData::Srv { port: 631, .. }
        ));
        let DiscoveryDnsRecordData::Txt(entries) = &parsed.answers[2].data else {
            panic!()
        };
        assert_eq!(entries[0].key, "note");
        assert!(entries[0].text_value.is_none());
        assert!(matches!(
            parsed.answers[3].data,
            DiscoveryDnsRecordData::A([192, 0, 2, 10])
        ));
    }

    #[test]
    fn loops_duplicates_and_truncation_fail_closed() {
        let looped = [
            0_u8, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1,
        ];
        assert_eq!(
            parse_discovery_dns_message(&looped),
            Err(DiscoveryDnsError::CompressionLoop)
        );
        let mut duplicate_txt = build_discovery_dns_query(1, "x.local.", 16, false).unwrap();
        duplicate_txt[2] = 0x80;
        duplicate_txt[4..6].copy_from_slice(&0_u16.to_be_bytes());
        duplicate_txt[6..8].copy_from_slice(&1_u16.to_be_bytes());
        duplicate_txt.truncate(12);
        duplicate_txt.extend_from_slice(&encode_name("x.local.").unwrap());
        duplicate_txt.extend_from_slice(&16_u16.to_be_bytes());
        duplicate_txt.extend_from_slice(&1_u16.to_be_bytes());
        duplicate_txt.extend_from_slice(&1_u32.to_be_bytes());
        duplicate_txt.extend_from_slice(&8_u16.to_be_bytes());
        duplicate_txt.extend_from_slice(&[3, b'A', b'=', b'1', 3, b'a', b'=', b'2']);
        assert_eq!(
            parse_discovery_dns_message(&duplicate_txt),
            Err(DiscoveryDnsError::DuplicateTxtKey)
        );
        for length in 0..duplicate_txt.len() {
            let _ = parse_discovery_dns_message(&duplicate_txt[..length]);
        }
    }
}
