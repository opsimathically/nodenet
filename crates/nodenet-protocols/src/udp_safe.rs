//! Independently authored, bounded safe-profile UDP request/response codecs.

use crate::IpAddress;

pub const MAX_UDP_SERVICE_METADATA_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum UdpSafeProbe {
    Dns = 1,
    Ntp = 2,
    SnmpV3 = 3,
    Rpcbind = 4,
    Stun = 5,
    Coap = 6,
    AsfRmcp = 7,
    Memcached = 8,
    Pcp = 9,
}

impl UdpSafeProbe {
    #[must_use]
    pub const fn from_id(id: u16) -> Option<Self> {
        match id {
            1 => Some(Self::Dns),
            2 => Some(Self::Ntp),
            3 => Some(Self::SnmpV3),
            4 => Some(Self::Rpcbind),
            5 => Some(Self::Stun),
            6 => Some(Self::Coap),
            7 => Some(Self::AsfRmcp),
            8 => Some(Self::Memcached),
            9 => Some(Self::Pcp),
            _ => None,
        }
    }

    #[must_use]
    pub const fn port(self) -> u16 {
        match self {
            Self::Dns => 53,
            Self::Ntp => 123,
            Self::SnmpV3 => 161,
            Self::Rpcbind => 111,
            Self::Stun => 3478,
            Self::Coap => 5683,
            Self::AsfRmcp => 623,
            Self::Memcached => 11_211,
            Self::Pcp => 5351,
        }
    }

    #[must_use]
    pub const fn service_family(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpSafeMatch {
    pub service_family: u16,
    pub confidence: u8,
    pub metadata: Box<[u8]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpSafeCodecError {
    UnsupportedProbe,
    InvalidSourceAddress,
    MalformedResponse,
    WrongTransaction,
    MetadataTooLarge,
}

/// Builds one exact protocol request. `token` supplies per-transmission entropy.
///
/// # Errors
///
/// Returns an error when the probe or source-address form cannot be encoded.
pub fn build_udp_safe_request(
    probe: UdpSafeProbe,
    token: [u8; 16],
    source: IpAddress,
) -> Result<Vec<u8>, UdpSafeCodecError> {
    Ok(match probe {
        UdpSafeProbe::Dns => build_dns(token),
        UdpSafeProbe::Ntp => build_ntp(token),
        UdpSafeProbe::SnmpV3 => build_snmpv3(token),
        UdpSafeProbe::Rpcbind => build_rpcbind(token),
        UdpSafeProbe::Stun => build_stun(token),
        UdpSafeProbe::Coap => vec![0x40, 0x00, token[0], token[1]],
        UdpSafeProbe::AsfRmcp => build_asf(token),
        UdpSafeProbe::Memcached => build_memcached(token),
        UdpSafeProbe::Pcp => build_pcp(source),
    })
}

/// Strictly validates one complete response against the request transaction.
///
/// # Errors
///
/// Returns an error for malformed, oversized, unsupported, or transaction-
/// mismatched responses.
pub fn parse_udp_safe_response(
    probe: UdpSafeProbe,
    request: &[u8],
    response: &[u8],
) -> Result<UdpSafeMatch, UdpSafeCodecError> {
    let (confidence, version, extras) = match probe {
        UdpSafeProbe::Dns => parse_dns(request, response)?,
        UdpSafeProbe::Ntp => parse_ntp(request, response)?,
        UdpSafeProbe::SnmpV3 => parse_snmpv3(request, response)?,
        UdpSafeProbe::Rpcbind => parse_rpcbind(request, response)?,
        UdpSafeProbe::Stun => parse_stun(request, response)?,
        UdpSafeProbe::Coap => parse_coap(request, response)?,
        UdpSafeProbe::AsfRmcp => parse_asf(request, response)?,
        UdpSafeProbe::Memcached => parse_memcached(request, response)?,
        UdpSafeProbe::Pcp => parse_pcp(response)?,
    };
    let metadata = encode_metadata(product_name(probe), version.as_deref(), &extras)?;
    Ok(UdpSafeMatch {
        service_family: probe.service_family(),
        confidence,
        metadata,
    })
}

fn product_name(probe: UdpSafeProbe) -> &'static str {
    match probe {
        UdpSafeProbe::Dns => "DNS",
        UdpSafeProbe::Ntp => "NTP",
        UdpSafeProbe::SnmpV3 => "SNMPv3",
        UdpSafeProbe::Rpcbind => "ONC RPC rpcbind",
        UdpSafeProbe::Stun => "STUN",
        UdpSafeProbe::Coap => "CoAP",
        UdpSafeProbe::AsfRmcp => "ASF RMCP",
        UdpSafeProbe::Memcached => "memcached",
        UdpSafeProbe::Pcp => "PCP",
    }
}

fn build_dns(token: [u8; 16]) -> Vec<u8> {
    let mut value = vec![0_u8; 128];
    value[0..2].copy_from_slice(&token[0..2]);
    value[4..6].copy_from_slice(&1_u16.to_be_bytes());
    value[10..12].copy_from_slice(&1_u16.to_be_bytes());
    // Root A IN question followed by an EDNS(0) OPT advertising a 512-byte UDP ceiling.
    value[12..17].copy_from_slice(&[0, 0, 1, 0, 1]);
    value[17..28].copy_from_slice(&[0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 100]);
    value[28..32].copy_from_slice(&[0, 12, 0, 96]);
    value
}

fn build_ntp(token: [u8; 16]) -> Vec<u8> {
    let mut value = vec![0_u8; 48];
    value[0] = 0x23; // LI=0, version=4, client mode=3.
    value[40..48].copy_from_slice(&token[0..8]);
    value
}

fn build_rpcbind(token: [u8; 16]) -> Vec<u8> {
    let mut value = Vec::with_capacity(40);
    value.extend_from_slice(&token[0..4]);
    for word in [0_u32, 2, 100_000, 2, 0, 0, 0, 0, 0] {
        value.extend_from_slice(&word.to_be_bytes());
    }
    value
}

fn build_stun(token: [u8; 16]) -> Vec<u8> {
    let mut value = vec![0_u8; 20];
    value[0..2].copy_from_slice(&1_u16.to_be_bytes());
    value[4..8].copy_from_slice(&0x2112_a442_u32.to_be_bytes());
    value[8..20].copy_from_slice(&token[0..12]);
    value
}

fn build_asf(token: [u8; 16]) -> Vec<u8> {
    vec![
        0x06, 0x00, 0xff, 0x06, // RMCP v1, class ASF
        0x00, 0x00, 0x11, 0xbe, // ASF IANA enterprise
        0x80, token[0], 0x00, 0x00, // presence ping, tag, reserved, data length
    ]
}

fn build_memcached(token: [u8; 16]) -> Vec<u8> {
    let mut value = vec![token[0], token[1], 0, 0, 0, 1, 0, 0];
    value.extend_from_slice(b"version\r\n");
    value
}

fn build_pcp(source: IpAddress) -> Vec<u8> {
    let mut value = vec![0_u8; 24];
    value[0] = 2;
    value[1] = 0; // ANNOUNCE request, lifetime zero.
    match source {
        IpAddress::V4(address) => {
            value[8..18].fill(0);
            value[18..20].fill(0xff);
            value[20..24].copy_from_slice(&address.octets());
        }
        IpAddress::V6(address) => value[8..24].copy_from_slice(&address.octets()),
    }
    value
}

fn build_snmpv3(token: [u8; 16]) -> Vec<u8> {
    let message_id = u32::from_be_bytes(token[0..4].try_into().unwrap()) & 0x7fff_ffff;
    let request_id = u32::from_be_bytes(token[4..8].try_into().unwrap()) & 0x7fff_ffff;
    let header = ber_sequence(&[
        ber_integer(message_id),
        vec![0x02, 0x03, 0x00, 0xff, 0xe3],
        vec![0x04, 0x01, 0x04],
        vec![0x02, 0x01, 0x03],
    ]);
    let security = ber_sequence(&[
        vec![0x04, 0x00],
        vec![0x02, 0x01, 0],
        vec![0x02, 0x01, 0],
        vec![0x04, 0x00],
        vec![0x04, 0x00],
        vec![0x04, 0x00],
    ]);
    let pdu = ber_tagged(
        0xa0,
        &[
            ber_integer(request_id),
            vec![0x02, 0x01, 0],
            vec![0x02, 0x01, 0],
            vec![0x30, 0x00],
        ],
    );
    let scoped = ber_sequence(&[vec![0x04, 0x00], vec![0x04, 0x00], pdu]);
    ber_sequence(&[
        vec![0x02, 0x01, 0x03],
        header,
        ber_octets(&security),
        scoped,
    ])
}

fn ber_integer(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
    let slice = &bytes[first..];
    let mut output = vec![
        0x02,
        u8::try_from(slice.len() + usize::from(slice[0] & 0x80 != 0)).unwrap(),
    ];
    if slice[0] & 0x80 != 0 {
        output.push(0);
    }
    output.extend_from_slice(slice);
    output
}

fn ber_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    ber_tagged(0x30, parts)
}
fn ber_tagged(tag: u8, parts: &[Vec<u8>]) -> Vec<u8> {
    let length: usize = parts.iter().map(Vec::len).sum();
    let mut output = vec![tag, u8::try_from(length).expect("safe request is short")];
    for part in parts {
        output.extend_from_slice(part);
    }
    output
}
fn ber_octets(value: &[u8]) -> Vec<u8> {
    let mut output = vec![
        0x04,
        u8::try_from(value.len()).expect("safe request is short"),
    ];
    output.extend_from_slice(value);
    output
}

type Parsed = (u8, Option<String>, Vec<(u16, String)>);

fn parse_dns(request: &[u8], response: &[u8]) -> Result<Parsed, UdpSafeCodecError> {
    if response.len() < 12 || response.len() > 512 || request.len() < 2 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    if response[0..2] != request[0..2] {
        return Err(UdpSafeCodecError::WrongTransaction);
    }
    if response[2] & 0x80 == 0 || response[2] & 0x78 != 0 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let questions = u16::from_be_bytes([response[4], response[5]]);
    if questions > 1 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    validate_dns_message(response)?;
    Ok((3, None, vec![(1, (response[3] & 0x0f).to_string())]))
}

fn validate_dns_message(value: &[u8]) -> Result<(), UdpSafeCodecError> {
    let counts = [4_usize, 6, 8, 10]
        .map(|offset| usize::from(u16::from_be_bytes([value[offset], value[offset + 1]])));
    let mut cursor = 12;
    for _ in 0..counts[0] {
        cursor = dns_name_end(value, cursor)?;
        cursor = cursor
            .checked_add(4)
            .filter(|end| *end <= value.len())
            .ok_or(UdpSafeCodecError::MalformedResponse)?;
    }
    let records = counts[1]
        .saturating_add(counts[2])
        .saturating_add(counts[3]);
    if records > value.len() / 11 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    for _ in 0..records {
        cursor = dns_name_end(value, cursor)?;
        let header_end = cursor
            .checked_add(10)
            .filter(|end| *end <= value.len())
            .ok_or(UdpSafeCodecError::MalformedResponse)?;
        let data_len = usize::from(u16::from_be_bytes([
            value[header_end - 2],
            value[header_end - 1],
        ]));
        cursor = header_end
            .checked_add(data_len)
            .filter(|end| *end <= value.len())
            .ok_or(UdpSafeCodecError::MalformedResponse)?;
    }
    if cursor != value.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    Ok(())
}

fn dns_name_end(value: &[u8], mut cursor: usize) -> Result<usize, UdpSafeCodecError> {
    for _ in 0..128 {
        let length = *value
            .get(cursor)
            .ok_or(UdpSafeCodecError::MalformedResponse)?;
        cursor += 1;
        if length == 0 {
            return Ok(cursor);
        }
        if length & 0xc0 == 0xc0 {
            let second = *value
                .get(cursor)
                .ok_or(UdpSafeCodecError::MalformedResponse)?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(second);
            if pointer >= value.len() {
                return Err(UdpSafeCodecError::MalformedResponse);
            }
            return Ok(cursor + 1);
        }
        if length > 63 {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        cursor = cursor
            .checked_add(usize::from(length))
            .filter(|end| *end <= value.len())
            .ok_or(UdpSafeCodecError::MalformedResponse)?;
    }
    Err(UdpSafeCodecError::MalformedResponse)
}

fn parse_ntp(request: &[u8], response: &[u8]) -> Result<Parsed, UdpSafeCodecError> {
    if request.len() != 48 || response.len() < 48 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let version = (response[0] >> 3) & 7;
    if response[0] & 7 != 4 || version == 0 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    if response[24..32] != request[40..48] {
        return Err(UdpSafeCodecError::WrongTransaction);
    }
    Ok((
        3,
        Some(format!("v{version}")),
        vec![(2, response[1].to_string())],
    ))
}

fn parse_rpcbind(request: &[u8], response: &[u8]) -> Result<Parsed, UdpSafeCodecError> {
    if request.len() < 4 || response.len() < 24 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    if response[0..4] != request[0..4] {
        return Err(UdpSafeCodecError::WrongTransaction);
    }
    let word = |offset: usize| u32::from_be_bytes(response[offset..offset + 4].try_into().unwrap());
    if word(4) != 1 || word(8) != 0 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let verifier_length =
        usize::try_from(word(16)).map_err(|_| UdpSafeCodecError::MalformedResponse)?;
    let accept_offset = 20_usize
        .checked_add((verifier_length + 3) & !3)
        .ok_or(UdpSafeCodecError::MalformedResponse)?;
    if accept_offset.checked_add(4) != Some(response.len()) || word(accept_offset) != 0 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    Ok((3, Some("v2".into()), Vec::new()))
}

fn parse_stun(request: &[u8], response: &[u8]) -> Result<Parsed, UdpSafeCodecError> {
    if request.len() != 20 || response.len() < 20 || response[0] & 0xc0 != 0 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let length = usize::from(u16::from_be_bytes([response[2], response[3]]));
    if length % 4 != 0 || response.len() != 20 + length || response[4..8] != request[4..8] {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    if response[8..20] != request[8..20] {
        return Err(UdpSafeCodecError::WrongTransaction);
    }
    let message_type = u16::from_be_bytes([response[0], response[1]]);
    if !matches!(message_type, 0x0101 | 0x0111) {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let mut cursor = 20;
    let mut software = None;
    while cursor < response.len() {
        if cursor + 4 > response.len() {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        let kind = u16::from_be_bytes([response[cursor], response[cursor + 1]]);
        let size = usize::from(u16::from_be_bytes([
            response[cursor + 2],
            response[cursor + 3],
        ]));
        cursor += 4;
        let end = cursor
            .checked_add(size)
            .ok_or(UdpSafeCodecError::MalformedResponse)?;
        if end > response.len() {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        if kind == 0x8022 {
            software = bounded_text(&response[cursor..end]);
        }
        cursor = (end + 3) & !3;
        if cursor > response.len() {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
    }
    Ok((3, software, Vec::new()))
}

fn parse_coap(request: &[u8], response: &[u8]) -> Result<Parsed, UdpSafeCodecError> {
    if request.len() != 4 || response.len() != 4 || response[0] != 0x70 || response[1] != 0 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    if response[2..4] != request[2..4] {
        return Err(UdpSafeCodecError::WrongTransaction);
    }
    Ok((3, None, Vec::new()))
}

fn parse_asf(request: &[u8], response: &[u8]) -> Result<Parsed, UdpSafeCodecError> {
    if request.len() != 12
        || response.len() < 12
        || response[0..8] != [6, 0, 0xff, 6, 0, 0, 0x11, 0xbe]
    {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    if response[9] != request[9] {
        return Err(UdpSafeCodecError::WrongTransaction);
    }
    if response[8] != 0x40 || response.len() != 12 + usize::from(response[11]) {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    Ok((3, None, Vec::new()))
}

fn parse_memcached(request: &[u8], response: &[u8]) -> Result<Parsed, UdpSafeCodecError> {
    if request.len() < 8
        || response.len() < 18
        || response.len() > 512
        || response[0..2] != request[0..2]
        || response[2..4] != [0, 0]
        || response[4..6] != [0, 1]
        || !response[8..].starts_with(b"VERSION ")
        || !response.ends_with(b"\r\n")
    {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let version = bounded_text(&response[16..response.len() - 2])
        .ok_or(UdpSafeCodecError::MalformedResponse)?;
    Ok((3, Some(version), Vec::new()))
}

fn parse_pcp(response: &[u8]) -> Result<Parsed, UdpSafeCodecError> {
    if response.len() < 24
        || !response.len().is_multiple_of(4)
        || response[0] != 2
        || response[1] != 0x80
        || response[3] > 13
    {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let epoch = u32::from_be_bytes(response[8..12].try_into().unwrap());
    Ok((
        2,
        Some("v2".into()),
        vec![(4, epoch.to_string()), (1, response[3].to_string())],
    ))
}

fn parse_snmpv3(request: &[u8], response: &[u8]) -> Result<Parsed, UdpSafeCodecError> {
    let request = parse_snmpv3_message(request, 0xa0)?;
    let response = parse_snmpv3_message(response, 0xa8)?;
    if request != response {
        return Err(UdpSafeCodecError::WrongTransaction);
    }
    Ok((3, Some("v3".into()), Vec::new()))
}

fn parse_snmpv3_message(
    value: &[u8],
    expected_pdu_tag: u8,
) -> Result<(u32, u32), UdpSafeCodecError> {
    let (outer_end, outer) = ber_field(value, 0, 0x30)?;
    if outer_end != value.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }

    let (mut cursor, version) = ber_field(outer, 0, 0x02)?;
    if version != [3] {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let (header_end, header) = ber_field(outer, cursor, 0x30)?;
    cursor = header_end;
    let (message_id, header_cursor) = parse_ber_u32(header, 0)?;
    let (_, header_cursor) = parse_ber_u32(header, header_cursor)?; // msgMaxSize
    let (header_cursor, flags) = ber_field(header, header_cursor, 0x04)?;
    if flags.len() != 1 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let (security_model, header_cursor) = parse_ber_u32(header, header_cursor)?;
    if security_model != 3 || header_cursor != header.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }

    let (security_end, security) = ber_field(outer, cursor, 0x04)?;
    cursor = security_end;
    validate_usm_security_parameters(security)?;

    let (scoped_end, scoped) = ber_field(outer, cursor, 0x30)?;
    if scoped_end != outer.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let (scoped_cursor, _) = ber_field(scoped, 0, 0x04)?; // contextEngineID
    let (scoped_cursor, _) = ber_field(scoped, scoped_cursor, 0x04)?; // contextName
    let (pdu_end, pdu) = ber_field(scoped, scoped_cursor, expected_pdu_tag)?;
    if pdu_end != scoped.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let (request_id, pdu_cursor) = parse_ber_u32(pdu, 0)?;
    let (_, pdu_cursor) = parse_ber_u32(pdu, pdu_cursor)?; // error-status
    let (_, pdu_cursor) = parse_ber_u32(pdu, pdu_cursor)?; // error-index
    let (varbind_end, varbinds) = ber_field(pdu, pdu_cursor, 0x30)?;
    if varbind_end != pdu.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    validate_varbinds(varbinds)?;
    Ok((message_id, request_id))
}

fn validate_usm_security_parameters(value: &[u8]) -> Result<(), UdpSafeCodecError> {
    let (end, sequence) = ber_field(value, 0, 0x30)?;
    if end != value.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let (cursor, _) = ber_field(sequence, 0, 0x04)?; // authoritativeEngineID
    let (_, cursor) = parse_ber_u32(sequence, cursor)?; // authoritativeEngineBoots
    let (_, cursor) = parse_ber_u32(sequence, cursor)?; // authoritativeEngineTime
    let (cursor, _) = ber_field(sequence, cursor, 0x04)?; // userName
    let (cursor, authentication) = ber_field(sequence, cursor, 0x04)?;
    let (cursor, privacy) = ber_field(sequence, cursor, 0x04)?;
    if cursor != sequence.len() || authentication.len() > 64 || privacy.len() > 64 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    Ok(())
}

fn validate_varbinds(value: &[u8]) -> Result<(), UdpSafeCodecError> {
    let mut cursor = 0;
    for _ in 0..64 {
        if cursor == value.len() {
            return Ok(());
        }
        let (next, varbind) = ber_field(value, cursor, 0x30)?;
        let (varbind_cursor, oid) = ber_field(varbind, 0, 0x06)?;
        if oid.is_empty() || varbind_cursor >= varbind.len() {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        let (value_end, _) = ber_tlv(varbind, varbind_cursor)?;
        if value_end != varbind.len() {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        cursor = next;
    }
    Err(UdpSafeCodecError::MalformedResponse)
}

fn parse_ber_u32(value: &[u8], start: usize) -> Result<(u32, usize), UdpSafeCodecError> {
    let (end, integer) = ber_field(value, start, 0x02)?;
    if integer.is_empty()
        || integer.len() > 5
        || integer[0] & 0x80 != 0
        || (integer.len() > 1 && integer[0] == 0 && integer[1] & 0x80 == 0)
        || (integer.len() == 5 && integer[0] != 0)
    {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let parsed = integer.iter().fold(0_u32, |value, byte| {
        value.wrapping_shl(8) | u32::from(*byte)
    });
    Ok((parsed, end))
}

fn ber_field(
    value: &[u8],
    start: usize,
    expected_tag: u8,
) -> Result<(usize, &[u8]), UdpSafeCodecError> {
    if value.get(start) != Some(&expected_tag) {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    ber_tlv(value, start)
}

fn ber_tlv(value: &[u8], start: usize) -> Result<(usize, &[u8]), UdpSafeCodecError> {
    if start + 2 > value.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let first = value[start + 1];
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 2 || start + 2 + count > value.len() {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        let mut length = 0;
        for byte in &value[start + 2..start + 2 + count] {
            length = (length << 8) | usize::from(*byte);
        }
        (length, 2 + count)
    };
    let body = start + header;
    let end = body
        .checked_add(length)
        .ok_or(UdpSafeCodecError::MalformedResponse)?;
    if end > value.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    Ok((end, &value[body..end]))
}

pub(crate) fn bounded_text(value: &[u8]) -> Option<String> {
    if value.is_empty()
        || value.len() > 255
        || value.iter().any(|byte| !(0x20..=0x7e).contains(byte))
    {
        return None;
    }
    String::from_utf8(value.to_vec()).ok()
}

pub(crate) fn encode_metadata(
    product: &str,
    version: Option<&str>,
    extras: &[(u16, String)],
) -> Result<Box<[u8]>, UdpSafeCodecError> {
    let product = product.as_bytes();
    let version = version.unwrap_or("").as_bytes();
    if product.len() > 255 || version.len() > 255 || extras.len() > 32 {
        return Err(UdpSafeCodecError::MetadataTooLarge);
    }
    let mut output = Vec::new();
    output.push(1);
    output.extend_from_slice(
        &u16::try_from(product.len())
            .map_err(|_| UdpSafeCodecError::MetadataTooLarge)?
            .to_le_bytes(),
    );
    output.extend_from_slice(product);
    output.extend_from_slice(
        &u16::try_from(version.len())
            .map_err(|_| UdpSafeCodecError::MetadataTooLarge)?
            .to_le_bytes(),
    );
    output.extend_from_slice(version);
    output.push(u8::try_from(extras.len()).map_err(|_| UdpSafeCodecError::MetadataTooLarge)?);
    for (id, value) in extras {
        if value.len() > 255 {
            return Err(UdpSafeCodecError::MetadataTooLarge);
        }
        output.extend_from_slice(&id.to_le_bytes());
        output.extend_from_slice(
            &u16::try_from(value.len())
                .map_err(|_| UdpSafeCodecError::MetadataTooLarge)?
                .to_le_bytes(),
        );
        output.extend_from_slice(value.as_bytes());
    }
    if output.len() > MAX_UDP_SERVICE_METADATA_BYTES {
        return Err(UdpSafeCodecError::MetadataTooLarge);
    }
    Ok(output.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ipv4Address;

    const TOKEN: [u8; 16] = *b"0123456789abcdef";
    fn source() -> IpAddress {
        IpAddress::V4(Ipv4Address::new([192, 0, 2, 10]))
    }

    #[test]
    fn golden_requests_have_protocol_lengths_and_transactions() {
        assert_eq!(
            build_udp_safe_request(UdpSafeProbe::Dns, TOKEN, source())
                .unwrap()
                .len(),
            128
        );
        assert_eq!(
            build_udp_safe_request(UdpSafeProbe::Ntp, TOKEN, source()).unwrap()[40..48],
            TOKEN[..8]
        );
        assert_eq!(
            build_udp_safe_request(UdpSafeProbe::Stun, TOKEN, source()).unwrap()[8..20],
            TOKEN[..12]
        );
        assert_eq!(
            build_udp_safe_request(UdpSafeProbe::Coap, TOKEN, source()).unwrap(),
            [0x40, 0, b'0', b'1']
        );
        assert_eq!(
            &build_udp_safe_request(UdpSafeProbe::Memcached, TOKEN, source()).unwrap()[8..],
            b"version\r\n"
        );
        assert!(
            build_udp_safe_request(UdpSafeProbe::SnmpV3, TOKEN, source())
                .unwrap()
                .len()
                < 128
        );
    }

    #[test]
    fn strict_transactions_and_bounded_memcached_metadata() {
        let request = build_udp_safe_request(UdpSafeProbe::Ntp, TOKEN, source()).unwrap();
        let mut response = vec![0_u8; 48];
        response[0] = 0x24;
        response[1] = 2;
        response[24..32].copy_from_slice(&request[40..48]);
        assert_eq!(
            parse_udp_safe_response(UdpSafeProbe::Ntp, &request, &response)
                .unwrap()
                .confidence,
            3
        );
        response[24] ^= 1;
        assert_eq!(
            parse_udp_safe_response(UdpSafeProbe::Ntp, &request, &response),
            Err(UdpSafeCodecError::WrongTransaction)
        );
        let request = build_udp_safe_request(UdpSafeProbe::Memcached, TOKEN, source()).unwrap();
        let mut response = request[..8].to_vec();
        response.extend_from_slice(b"VERSION 1.6.22\r\n");
        let match_ = parse_udp_safe_response(UdpSafeProbe::Memcached, &request, &response).unwrap();
        assert_eq!(match_.confidence, 3);
        assert!(match_.metadata.len() <= MAX_UDP_SERVICE_METADATA_BYTES);
    }

    #[test]
    fn every_safe_family_accepts_one_independent_canonical_response() {
        let request = build_udp_safe_request(UdpSafeProbe::Dns, TOKEN, source()).unwrap();
        let mut response = request.clone();
        response[2] = 0x80;
        assert!(parse_udp_safe_response(UdpSafeProbe::Dns, &request, &response).is_ok());

        let request = build_udp_safe_request(UdpSafeProbe::Rpcbind, TOKEN, source()).unwrap();
        let mut response = request[..4].to_vec();
        for word in [1_u32, 0, 0, 0, 0] {
            response.extend_from_slice(&word.to_be_bytes());
        }
        assert!(parse_udp_safe_response(UdpSafeProbe::Rpcbind, &request, &response).is_ok());

        let request = build_udp_safe_request(UdpSafeProbe::Stun, TOKEN, source()).unwrap();
        let mut response = request.clone();
        response[0..2].copy_from_slice(&0x0101_u16.to_be_bytes());
        assert!(parse_udp_safe_response(UdpSafeProbe::Stun, &request, &response).is_ok());

        let request = build_udp_safe_request(UdpSafeProbe::Coap, TOKEN, source()).unwrap();
        let response = [0x70, 0, request[2], request[3]];
        assert!(parse_udp_safe_response(UdpSafeProbe::Coap, &request, &response).is_ok());

        let request = build_udp_safe_request(UdpSafeProbe::AsfRmcp, TOKEN, source()).unwrap();
        let mut response = request.clone();
        response[8] = 0x40;
        assert!(parse_udp_safe_response(UdpSafeProbe::AsfRmcp, &request, &response).is_ok());

        let request = build_udp_safe_request(UdpSafeProbe::Pcp, TOKEN, source()).unwrap();
        let mut response = vec![0_u8; 24];
        response[0] = 2;
        response[1] = 0x80;
        response[8..12].copy_from_slice(&7_u32.to_be_bytes());
        assert!(parse_udp_safe_response(UdpSafeProbe::Pcp, &request, &response).is_ok());

        let request = build_udp_safe_request(UdpSafeProbe::SnmpV3, TOKEN, source()).unwrap();
        let mut response = request.clone();
        let pdu = response.iter().position(|byte| *byte == 0xa0).unwrap();
        response[pdu] = 0xa8;
        assert!(parse_udp_safe_response(UdpSafeProbe::SnmpV3, &request, &response).is_ok());
    }

    #[test]
    fn strict_snmp_and_rpc_parsers_reject_embedded_markers_and_trailing_data() {
        let request = build_udp_safe_request(UdpSafeProbe::Rpcbind, TOKEN, source()).unwrap();
        let mut response = request[..4].to_vec();
        for word in [1_u32, 0, 0, 0, 0] {
            response.extend_from_slice(&word.to_be_bytes());
        }
        response.push(0);
        assert_eq!(
            parse_udp_safe_response(UdpSafeProbe::Rpcbind, &request, &response),
            Err(UdpSafeCodecError::MalformedResponse)
        );

        let request = build_udp_safe_request(UdpSafeProbe::SnmpV3, TOKEN, source()).unwrap();
        let mut response = request.clone();
        // An A8 byte in a BER value is not a Report PDU.
        let security = response
            .windows(3)
            .position(|value| value == [0x04, 0x01, 0x04])
            .unwrap();
        response[security + 2] = 0xa8;
        assert_eq!(
            parse_udp_safe_response(UdpSafeProbe::SnmpV3, &request, &response),
            Err(UdpSafeCodecError::MalformedResponse)
        );

        let mut response = request.clone();
        let pdu = response.iter().position(|byte| *byte == 0xa0).unwrap();
        response[pdu] = 0xa8;
        response.push(0);
        assert_eq!(
            parse_udp_safe_response(UdpSafeProbe::SnmpV3, &request, &response),
            Err(UdpSafeCodecError::MalformedResponse)
        );
    }

    #[test]
    fn truncation_and_arbitrary_bytes_are_rejected_without_panics() {
        for probe in [
            UdpSafeProbe::Dns,
            UdpSafeProbe::Ntp,
            UdpSafeProbe::SnmpV3,
            UdpSafeProbe::Rpcbind,
            UdpSafeProbe::Stun,
            UdpSafeProbe::Coap,
            UdpSafeProbe::AsfRmcp,
            UdpSafeProbe::Memcached,
            UdpSafeProbe::Pcp,
        ] {
            let request = build_udp_safe_request(probe, TOKEN, source()).unwrap();
            for length in 0..request.len().min(32) {
                assert!(parse_udp_safe_response(probe, &request, &request[..length]).is_err());
            }
        }
    }
}
