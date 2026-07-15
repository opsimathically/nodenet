//! Independently authored extended UDP probe codecs.
//!
//! These probes are never selected by the safe profile. Their catalogue risk
//! declarations are enforced by native admission before a request can be sent.

use crate::udp_safe::{bounded_text, encode_metadata};
use crate::{
    IpAddress, UdpByteSignature, UdpSafeCodecError, UdpSafeMatch, UdpSafeProbe, UdpSignatureClause,
    build_udp_safe_request, match_udp_signature, parse_udp_safe_response,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum UdpCatalogueProbe {
    Dns = 1,
    Ntp = 2,
    SnmpV3 = 3,
    Rpcbind = 4,
    Stun = 5,
    Coap = 6,
    AsfRmcp = 7,
    Memcached = 8,
    Pcp = 9,
    NetbiosNodeStatus = 10,
    NfsV3Null = 11,
    SipOptions = 12,
    SsdpUnicast = 13,
    L2tpSccrq = 14,
    SnmpV1SystemDescription = 15,
    MemcachedStatistics = 16,
    Echo = 17,
    Daytime = 18,
    QuoteOfTheDay = 19,
    CharacterGenerator = 20,
    ActiveUsers = 21,
    NetworkStatus = 22,
    RipV2Table = 23,
    XdmcpQuery = 24,
    SourceEngineInfo = 25,
    RaknetUnconnectedPing = 26,
    BacnetWhoIs = 27,
    EthernetIpListIdentity = 28,
    KnxnetIpSearch = 29,
    BitTorrentDhtPing = 30,
    DnsChaosVersion = 31,
    NtpControlReadVariables = 32,
    SlpServiceAgent = 33,
}

impl UdpCatalogueProbe {
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
            10 => Some(Self::NetbiosNodeStatus),
            11 => Some(Self::NfsV3Null),
            12 => Some(Self::SipOptions),
            13 => Some(Self::SsdpUnicast),
            14 => Some(Self::L2tpSccrq),
            15 => Some(Self::SnmpV1SystemDescription),
            16 => Some(Self::MemcachedStatistics),
            17 => Some(Self::Echo),
            18 => Some(Self::Daytime),
            19 => Some(Self::QuoteOfTheDay),
            20 => Some(Self::CharacterGenerator),
            21 => Some(Self::ActiveUsers),
            22 => Some(Self::NetworkStatus),
            23 => Some(Self::RipV2Table),
            24 => Some(Self::XdmcpQuery),
            25 => Some(Self::SourceEngineInfo),
            26 => Some(Self::RaknetUnconnectedPing),
            27 => Some(Self::BacnetWhoIs),
            28 => Some(Self::EthernetIpListIdentity),
            29 => Some(Self::KnxnetIpSearch),
            30 => Some(Self::BitTorrentDhtPing),
            31 => Some(Self::DnsChaosVersion),
            32 => Some(Self::NtpControlReadVariables),
            33 => Some(Self::SlpServiceAgent),
            _ => None,
        }
    }

    const fn safe(self) -> Option<UdpSafeProbe> {
        match self {
            Self::Dns => Some(UdpSafeProbe::Dns),
            Self::Ntp => Some(UdpSafeProbe::Ntp),
            Self::SnmpV3 => Some(UdpSafeProbe::SnmpV3),
            Self::Rpcbind => Some(UdpSafeProbe::Rpcbind),
            Self::Stun => Some(UdpSafeProbe::Stun),
            Self::Coap => Some(UdpSafeProbe::Coap),
            Self::AsfRmcp => Some(UdpSafeProbe::AsfRmcp),
            Self::Memcached => Some(UdpSafeProbe::Memcached),
            Self::Pcp => Some(UdpSafeProbe::Pcp),
            Self::NetbiosNodeStatus
            | Self::NfsV3Null
            | Self::SipOptions
            | Self::SsdpUnicast
            | Self::L2tpSccrq
            | Self::SnmpV1SystemDescription
            | Self::MemcachedStatistics
            | Self::Echo
            | Self::Daytime
            | Self::QuoteOfTheDay
            | Self::CharacterGenerator
            | Self::ActiveUsers
            | Self::NetworkStatus
            | Self::RipV2Table
            | Self::XdmcpQuery
            | Self::SourceEngineInfo
            | Self::RaknetUnconnectedPing
            | Self::BacnetWhoIs
            | Self::EthernetIpListIdentity
            | Self::KnxnetIpSearch
            | Self::BitTorrentDhtPing
            | Self::DnsChaosVersion
            | Self::NtpControlReadVariables
            | Self::SlpServiceAgent => None,
        }
    }

    const fn service_family(self) -> u16 {
        match self {
            Self::MemcachedStatistics => UdpCatalogueProbe::Memcached as u16,
            Self::DnsChaosVersion => UdpCatalogueProbe::Dns as u16,
            Self::NtpControlReadVariables => UdpCatalogueProbe::Ntp as u16,
            _ => self as u16,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpProbeBuildContext {
    pub source: IpAddress,
    pub destination: IpAddress,
    pub source_port: u16,
    pub destination_port: u16,
}

/// Builds one complete catalogue request without a private payload prefix.
///
/// # Errors
///
/// Returns an error when a selected probe cannot be encoded for the supplied
/// address or port context.
pub fn build_udp_catalogue_request(
    probe: UdpCatalogueProbe,
    token: [u8; 16],
    context: UdpProbeBuildContext,
) -> Result<Vec<u8>, UdpSafeCodecError> {
    if let Some(safe) = probe.safe() {
        return build_udp_safe_request(safe, token, context.source);
    }
    Ok(match probe {
        UdpCatalogueProbe::NetbiosNodeStatus => build_netbios_node_status(token),
        UdpCatalogueProbe::NfsV3Null => build_nfs_v3_null(token),
        UdpCatalogueProbe::SipOptions => build_sip_options(token, context),
        UdpCatalogueProbe::SsdpUnicast => build_ssdp_unicast(context),
        UdpCatalogueProbe::L2tpSccrq => build_l2tp_sccrq(token),
        UdpCatalogueProbe::SnmpV1SystemDescription => build_snmpv1(token),
        UdpCatalogueProbe::MemcachedStatistics => build_memcached_stats(token),
        UdpCatalogueProbe::Echo => token.to_vec(),
        UdpCatalogueProbe::Daytime
        | UdpCatalogueProbe::QuoteOfTheDay
        | UdpCatalogueProbe::CharacterGenerator
        | UdpCatalogueProbe::ActiveUsers
        | UdpCatalogueProbe::NetworkStatus => vec![0],
        UdpCatalogueProbe::RipV2Table => build_ripv2(),
        UdpCatalogueProbe::XdmcpQuery => vec![0, 1, 0, 2, 0, 1, 0],
        UdpCatalogueProbe::SourceEngineInfo => build_source_info(),
        UdpCatalogueProbe::RaknetUnconnectedPing => build_raknet_ping(token),
        UdpCatalogueProbe::BacnetWhoIs => vec![0x81, 0x0a, 0, 8, 1, 0, 0x10, 8],
        UdpCatalogueProbe::EthernetIpListIdentity => build_enip_list_identity(token),
        UdpCatalogueProbe::KnxnetIpSearch => build_knx_search(context)?,
        UdpCatalogueProbe::BitTorrentDhtPing => build_dht_ping(token),
        UdpCatalogueProbe::DnsChaosVersion => build_dns_chaos(token),
        UdpCatalogueProbe::NtpControlReadVariables => build_ntp_control(token),
        UdpCatalogueProbe::SlpServiceAgent => build_slp(token),
        _ => return Err(UdpSafeCodecError::UnsupportedProbe),
    })
}

/// Strictly validates one complete catalogue response.
///
/// # Errors
///
/// Returns an error for malformed, truncated, transaction-mismatched, or
/// unsupported responses.
pub fn parse_udp_catalogue_response(
    probe: UdpCatalogueProbe,
    request: &[u8],
    response: &[u8],
) -> Result<UdpSafeMatch, UdpSafeCodecError> {
    if let Some(safe) = probe.safe() {
        return parse_udp_safe_response(safe, request, response);
    }
    if probe == UdpCatalogueProbe::DnsChaosVersion {
        return parse_udp_safe_response(UdpSafeProbe::Dns, request, response);
    }
    let (product, confidence, version, extras) = match probe {
        UdpCatalogueProbe::NetbiosNodeStatus => parse_netbios(request, response)?,
        UdpCatalogueProbe::NfsV3Null => parse_nfs(request, response)?,
        UdpCatalogueProbe::SipOptions => parse_sip(request, response)?,
        UdpCatalogueProbe::SsdpUnicast => parse_ssdp(response)?,
        UdpCatalogueProbe::L2tpSccrq => parse_l2tp(request, response)?,
        UdpCatalogueProbe::SnmpV1SystemDescription => parse_snmpv1(request, response)?,
        UdpCatalogueProbe::MemcachedStatistics => parse_memcached_stats(request, response)?,
        UdpCatalogueProbe::Echo => parse_echo(request, response)?,
        UdpCatalogueProbe::Daytime => parse_legacy_text("Daytime", response)?,
        UdpCatalogueProbe::QuoteOfTheDay => parse_legacy_text("Quote of the Day", response)?,
        UdpCatalogueProbe::CharacterGenerator => {
            parse_legacy_text("Character Generator", response)?
        }
        UdpCatalogueProbe::ActiveUsers => parse_legacy_text("Active Users", response)?,
        UdpCatalogueProbe::NetworkStatus => parse_legacy_text("Network Status", response)?,
        UdpCatalogueProbe::RipV2Table => parse_ripv2(response)?,
        UdpCatalogueProbe::XdmcpQuery => parse_xdmcp(response)?,
        UdpCatalogueProbe::SourceEngineInfo => parse_source_info(response)?,
        UdpCatalogueProbe::RaknetUnconnectedPing => parse_raknet(request, response)?,
        UdpCatalogueProbe::BacnetWhoIs => parse_bacnet(response)?,
        UdpCatalogueProbe::EthernetIpListIdentity => parse_enip(request, response)?,
        UdpCatalogueProbe::KnxnetIpSearch => parse_knx(response)?,
        UdpCatalogueProbe::BitTorrentDhtPing => parse_dht(request, response)?,
        UdpCatalogueProbe::NtpControlReadVariables => parse_ntp_control(request, response)?,
        UdpCatalogueProbe::SlpServiceAgent => parse_slp(request, response)?,
        UdpCatalogueProbe::DnsChaosVersion => unreachable!("handled above"),
        _ => return Err(UdpSafeCodecError::UnsupportedProbe),
    };
    Ok(UdpSafeMatch {
        service_family: probe.service_family(),
        confidence,
        metadata: encode_metadata(product, version.as_deref(), &extras)?,
    })
}

type ExtendedParsed = (&'static str, u8, Option<String>, Vec<(u16, String)>);

const RAKNET_MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];

fn build_ripv2() -> Vec<u8> {
    let mut value = vec![1, 2, 0, 0];
    value.extend_from_slice(&[0; 16]);
    value.extend_from_slice(&16_u32.to_be_bytes());
    value
}

fn build_source_info() -> Vec<u8> {
    let mut value = vec![0xff; 4];
    value.push(0x54);
    value.extend_from_slice(b"Source Engine Query\0");
    value
}

fn build_raknet_ping(token: [u8; 16]) -> Vec<u8> {
    let mut value = vec![0x01];
    value.extend_from_slice(&token[..8]);
    value.extend_from_slice(&RAKNET_MAGIC);
    value.extend_from_slice(&token[8..16]);
    value
}

fn build_enip_list_identity(token: [u8; 16]) -> Vec<u8> {
    let mut value = vec![0_u8; 24];
    value[..2].copy_from_slice(&0x0063_u16.to_le_bytes());
    value[12..20].copy_from_slice(&token[..8]);
    value
}

fn build_knx_search(context: UdpProbeBuildContext) -> Result<Vec<u8>, UdpSafeCodecError> {
    let IpAddress::V4(source) = context.source else {
        return Err(UdpSafeCodecError::InvalidSourceAddress);
    };
    let mut value = vec![0x06, 0x10, 0x02, 0x01, 0, 14, 8, 1];
    value.extend_from_slice(&source.octets());
    value.extend_from_slice(&context.source_port.to_be_bytes());
    Ok(value)
}

fn build_dht_ping(token: [u8; 16]) -> Vec<u8> {
    let mut value = b"d1:ad2:id20:".to_vec();
    value.extend_from_slice(&token);
    value.extend_from_slice(&token[..4]);
    value.extend_from_slice(b"e1:q4:ping1:t2:");
    value.extend_from_slice(&token[..2]);
    value.extend_from_slice(b"1:y1:qe");
    value
}

fn build_dns_chaos(token: [u8; 16]) -> Vec<u8> {
    let mut value = Vec::with_capacity(30);
    value.extend_from_slice(&token[..2]);
    value.extend_from_slice(&[0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    value.extend_from_slice(&[7]);
    value.extend_from_slice(b"version");
    value.extend_from_slice(&[4]);
    value.extend_from_slice(b"bind");
    value.extend_from_slice(&[0, 0, 16, 0, 3]);
    value
}

fn build_ntp_control(token: [u8; 16]) -> Vec<u8> {
    let mut value = vec![0x26, 0x02];
    value.extend_from_slice(&token[..2]);
    value.extend_from_slice(&[0; 8]);
    value
}

fn push_slp_string(value: &mut Vec<u8>, text: &[u8]) {
    value.extend_from_slice(
        &u16::try_from(text.len())
            .expect("bounded SLP field")
            .to_be_bytes(),
    );
    value.extend_from_slice(text);
}

fn build_slp(token: [u8; 16]) -> Vec<u8> {
    let mut value = vec![2, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    value.extend_from_slice(&token[..2]);
    push_slp_string(&mut value, b"en");
    push_slp_string(&mut value, b"");
    push_slp_string(&mut value, b"service:service-agent");
    push_slp_string(&mut value, b"DEFAULT");
    push_slp_string(&mut value, b"");
    push_slp_string(&mut value, b"");
    let length = value.len();
    value[2] = u8::try_from((length >> 16) & 0xff).unwrap();
    value[3] = u8::try_from((length >> 8) & 0xff).unwrap();
    value[4] = u8::try_from(length & 0xff).unwrap();
    value
}

fn parse_echo(request: &[u8], response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    if response != request {
        return Err(UdpSafeCodecError::WrongTransaction);
    }
    Ok(("UDP Echo", 3, None, Vec::new()))
}

fn parse_legacy_text(
    product: &'static str,
    response: &[u8],
) -> Result<ExtendedParsed, UdpSafeCodecError> {
    const CLAUSES: &[UdpSignatureClause] = &[UdpSignatureClause::ExtractAscii {
        offset: 0,
        maximum_bytes: 255,
        terminator: Some(b'\n'),
        field_id: 3,
        required: true,
    }];
    let matched = match_udp_signature(
        UdpByteSignature {
            maximum_input_bytes: 1_024,
            clauses: CLAUSES,
        },
        response,
    )
    .map_err(|_| UdpSafeCodecError::MalformedResponse)?;
    Ok((product, 1, None, matched.extracted))
}

fn parse_ripv2(response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    if response.len() < 24
        || response.len() > 504
        || !(response.len() - 4).is_multiple_of(20)
        || response[..4] != [2, 2, 0, 0]
    {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let routes = (response.len() - 4) / 20;
    for entry in response[4..].chunks_exact(20) {
        let metric = u32::from_be_bytes(entry[16..20].try_into().unwrap());
        if metric == 0 || metric > 16 {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
    }
    Ok(("RIPv2", 2, Some("2".into()), vec![(4, routes.to_string())]))
}

fn parse_xdmcp(response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    if response.len() < 6 || response[..2] != [0, 1] {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let opcode = u16::from_be_bytes([response[2], response[3]]);
    let length = usize::from(u16::from_be_bytes([response[4], response[5]]));
    if !matches!(opcode, 5 | 6) || length != response.len() - 6 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let mut cursor = 6;
    if opcode == 5 {
        parse_xdmcp_array(response, &mut cursor, false)?; // authentication name
    }
    let hostname = parse_xdmcp_array(response, &mut cursor, true)?;
    parse_xdmcp_array(response, &mut cursor, true)?; // status
    if cursor != response.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    Ok((
        "XDMCP",
        2,
        Some("1".into()),
        hostname
            .into_iter()
            .map(|value| (3, value))
            .chain(core::iter::once((4, opcode.to_string())))
            .collect(),
    ))
}

fn parse_xdmcp_array(
    value: &[u8],
    cursor: &mut usize,
    text: bool,
) -> Result<Option<String>, UdpSafeCodecError> {
    let header_end = cursor
        .checked_add(2)
        .filter(|end| *end <= value.len())
        .ok_or(UdpSafeCodecError::MalformedResponse)?;
    let length = usize::from(u16::from_be_bytes([value[*cursor], value[*cursor + 1]]));
    let end = header_end
        .checked_add(length)
        .filter(|end| *end <= value.len())
        .ok_or(UdpSafeCodecError::MalformedResponse)?;
    let parsed = if text && length != 0 {
        Some(bounded_text(&value[header_end..end]).ok_or(UdpSafeCodecError::MalformedResponse)?)
    } else {
        None
    };
    *cursor = end;
    Ok(parsed)
}

fn c_string(value: &[u8], start: usize, maximum: usize) -> Option<(String, usize)> {
    let bytes = value.get(start..start.checked_add(maximum)?.min(value.len()))?;
    let end = bytes.iter().position(|byte| *byte == 0)?;
    let text = bounded_text(&bytes[..end])?;
    Some((text, start + end + 1))
}

fn parse_source_info(response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    if response.len() == 9 && response[..5] == [0xff, 0xff, 0xff, 0xff, 0x41] {
        return Ok(("Source engine query", 1, None, Vec::new()));
    }
    if response.len() < 8 || response[..5] != [0xff, 0xff, 0xff, 0xff, 0x49] {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let (name, _) = c_string(response, 6, 128).ok_or(UdpSafeCodecError::MalformedResponse)?;
    Ok(("Source engine server", 2, None, vec![(3, name)]))
}

fn parse_raknet(request: &[u8], response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    if request.len() != 33
        || response.len() < 35
        || response[0] != 0x1c
        || response[1..9] != request[1..9]
        || response[17..33] != RAKNET_MAGIC
    {
        return Err(UdpSafeCodecError::WrongTransaction);
    }
    let length = usize::from(u16::from_be_bytes([response[33], response[34]]));
    if length > 255 || response.len() != 35 + length {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let description = bounded_text(&response[35..]).ok_or(UdpSafeCodecError::MalformedResponse)?;
    Ok(("RakNet", 3, None, vec![(3, description)]))
}

fn parse_bacnet(response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    if response.len() < 20
        || response[0] != 0x81
        || !matches!(response[1], 0x0a | 0x0b)
        || usize::from(u16::from_be_bytes([response[2], response[3]])) != response.len()
        || response[4] != 1
        || response[6..8] != [0x10, 0]
    {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let (object, cursor) = parse_bacnet_unsigned(response, 8, 12, 4)?;
    let object_type = object >> 22;
    let instance = object & 0x003f_ffff;
    let (maximum_apdu, cursor) = parse_bacnet_unsigned(response, cursor, 2, 4)?;
    let (segmentation, cursor) = parse_bacnet_unsigned(response, cursor, 9, 1)?;
    let (vendor, cursor) = parse_bacnet_unsigned(response, cursor, 2, 2)?;
    if cursor != response.len() || object_type != 8 || maximum_apdu == 0 || segmentation > 3 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    Ok((
        "BACnet/IP",
        2,
        None,
        vec![(4, instance.to_string()), (5, vendor.to_string())],
    ))
}

fn parse_bacnet_unsigned(
    value: &[u8],
    start: usize,
    expected_tag: u8,
    maximum_length: usize,
) -> Result<(u32, usize), UdpSafeCodecError> {
    let tag = *value
        .get(start)
        .ok_or(UdpSafeCodecError::MalformedResponse)?;
    let length = usize::from(tag & 7);
    if tag >> 4 != expected_tag || tag & 8 != 0 || length == 0 || length > maximum_length {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let end = start
        .checked_add(1 + length)
        .filter(|end| *end <= value.len())
        .ok_or(UdpSafeCodecError::MalformedResponse)?;
    let parsed = value[start + 1..end]
        .iter()
        .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte));
    Ok((parsed, end))
}

fn parse_enip(request: &[u8], response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    if request.len() != 24
        || response.len() < 26
        || u16::from_le_bytes(response[..2].try_into().unwrap()) != 0x63
        || 24 + usize::from(u16::from_le_bytes(response[2..4].try_into().unwrap()))
            != response.len()
        || response[8..12] != [0; 4]
        || response[12..20] != request[12..20]
    {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let item_count = usize::from(u16::from_le_bytes([response[24], response[25]]));
    if item_count == 0 || item_count > 64 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let mut cursor = 26_usize;
    for _ in 0..item_count {
        let header_end = cursor
            .checked_add(4)
            .filter(|end| *end <= response.len())
            .ok_or(UdpSafeCodecError::MalformedResponse)?;
        let item_type = u16::from_le_bytes([response[cursor], response[cursor + 1]]);
        let item_length = usize::from(u16::from_le_bytes([
            response[cursor + 2],
            response[cursor + 3],
        ]));
        let item_end = header_end
            .checked_add(item_length)
            .filter(|end| *end <= response.len())
            .ok_or(UdpSafeCodecError::MalformedResponse)?;
        if item_type != 0x000c || item_length < 34 {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        let item = &response[header_end..item_end];
        let product_name_length = usize::from(item[32]);
        if item[0..2] != 1_u16.to_le_bytes()
            || item[2..4] != 2_u16.to_be_bytes()
            || 34_usize.checked_add(product_name_length) != Some(item.len())
            || (product_name_length != 0
                && bounded_text(&item[33..33 + product_name_length]).is_none())
        {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        cursor = item_end;
    }
    if cursor != response.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    Ok(("EtherNet/IP", 3, None, Vec::new()))
}

fn parse_knx(response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    if response.len() < 72
        || response[..4] != [6, 0x10, 2, 2]
        || usize::from(u16::from_be_bytes([response[4], response[5]])) != response.len()
        || response[6] != 8
        || response[7] != 1
    {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let mut cursor = 14;
    let mut device_information = false;
    let mut service_families = false;
    for _ in 0..32 {
        if cursor == response.len() {
            break;
        }
        let length = usize::from(
            *response
                .get(cursor)
                .ok_or(UdpSafeCodecError::MalformedResponse)?,
        );
        let end = cursor
            .checked_add(length)
            .filter(|end| length >= 4 && length.is_multiple_of(2) && *end <= response.len())
            .ok_or(UdpSafeCodecError::MalformedResponse)?;
        match response[cursor + 1] {
            1 if length == 54
                && matches!(response[cursor + 2], 0x01 | 0x02 | 0x04 | 0x10 | 0x20) =>
            {
                device_information = true;
            }
            2 => {
                if !response[cursor + 2..end]
                    .chunks_exact(2)
                    .all(|entry| entry[0] != 0 && entry[1] != 0)
                {
                    return Err(UdpSafeCodecError::MalformedResponse);
                }
                service_families = true;
            }
            _ => {}
        }
        cursor = end;
    }
    if cursor != response.len() || !device_information || !service_families {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    Ok(("KNXnet/IP", 2, Some("1.0".into()), Vec::new()))
}

fn parse_dht(request: &[u8], response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    let request_transaction = parse_dht_message(request, b"q", false)?;
    let response_transaction = parse_dht_message(response, b"r", true)?;
    if request_transaction != response_transaction {
        return Err(UdpSafeCodecError::WrongTransaction);
    }
    Ok(("BitTorrent DHT", 3, None, Vec::new()))
}

fn parse_dht_message<'a>(
    value: &'a [u8],
    expected_kind: &[u8],
    require_response_id: bool,
) -> Result<&'a [u8], UdpSafeCodecError> {
    if value.len() > 512 || value.first() != Some(&b'd') {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let mut cursor = 1;
    let mut prior_key: Option<&[u8]> = None;
    let mut transaction = None;
    let mut kind = None;
    let mut response_id = !require_response_id;
    for _ in 0..32 {
        if value.get(cursor) == Some(&b'e') {
            cursor += 1;
            if cursor != value.len() {
                return Err(UdpSafeCodecError::MalformedResponse);
            }
            return match (transaction, kind, response_id) {
                (Some(transaction), Some(kind), true) if kind == expected_kind => Ok(transaction),
                _ => Err(UdpSafeCodecError::MalformedResponse),
            };
        }
        let key = parse_bencode_bytes(value, &mut cursor)?;
        if prior_key.is_some_and(|prior| prior >= key) {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        prior_key = Some(key);
        match key {
            b"t" => {
                let parsed = parse_bencode_bytes(value, &mut cursor)?;
                if parsed.len() != 2 || transaction.replace(parsed).is_some() {
                    return Err(UdpSafeCodecError::MalformedResponse);
                }
            }
            b"y" => {
                let parsed = parse_bencode_bytes(value, &mut cursor)?;
                if parsed.len() != 1 || kind.replace(parsed).is_some() {
                    return Err(UdpSafeCodecError::MalformedResponse);
                }
            }
            b"r" if require_response_id => {
                if response_id {
                    return Err(UdpSafeCodecError::MalformedResponse);
                }
                response_id = parse_dht_response_dictionary(value, &mut cursor)?;
            }
            _ => skip_bencode_value(value, &mut cursor, 0)?,
        }
    }
    Err(UdpSafeCodecError::MalformedResponse)
}

fn parse_dht_response_dictionary(
    value: &[u8],
    cursor: &mut usize,
) -> Result<bool, UdpSafeCodecError> {
    if value.get(*cursor) != Some(&b'd') {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    *cursor += 1;
    let mut prior_key: Option<&[u8]> = None;
    let mut has_id = false;
    for _ in 0..32 {
        if value.get(*cursor) == Some(&b'e') {
            *cursor += 1;
            return Ok(has_id);
        }
        let key = parse_bencode_bytes(value, cursor)?;
        if prior_key.is_some_and(|prior| prior >= key) {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        prior_key = Some(key);
        if key == b"id" {
            let id = parse_bencode_bytes(value, cursor)?;
            if id.len() != 20 || has_id {
                return Err(UdpSafeCodecError::MalformedResponse);
            }
            has_id = true;
        } else {
            skip_bencode_value(value, cursor, 1)?;
        }
    }
    Err(UdpSafeCodecError::MalformedResponse)
}

fn parse_bencode_bytes<'a>(
    value: &'a [u8],
    cursor: &mut usize,
) -> Result<&'a [u8], UdpSafeCodecError> {
    let start = *cursor;
    let mut length = 0_usize;
    let mut digits = 0_usize;
    while let Some(byte @ b'0'..=b'9') = value.get(*cursor).copied() {
        if digits == 0 && byte == b'0' && value.get(*cursor + 1) != Some(&b':') {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        length = length
            .checked_mul(10)
            .and_then(|length| length.checked_add(usize::from(byte - b'0')))
            .ok_or(UdpSafeCodecError::MalformedResponse)?;
        digits += 1;
        *cursor += 1;
        if digits > 9 {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
    }
    if digits == 0 || value.get(*cursor) != Some(&b':') || *cursor == start {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    *cursor += 1;
    let end = cursor
        .checked_add(length)
        .filter(|end| *end <= value.len())
        .ok_or(UdpSafeCodecError::MalformedResponse)?;
    let parsed = &value[*cursor..end];
    *cursor = end;
    Ok(parsed)
}

fn skip_bencode_value(
    value: &[u8],
    cursor: &mut usize,
    depth: usize,
) -> Result<(), UdpSafeCodecError> {
    if depth > 4 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    match value.get(*cursor).copied() {
        Some(b'0'..=b'9') => {
            parse_bencode_bytes(value, cursor)?;
        }
        Some(b'i') => {
            *cursor += 1;
            let start = *cursor;
            if value.get(*cursor) == Some(&b'-') {
                *cursor += 1;
            }
            let digit_start = *cursor;
            while value.get(*cursor).is_some_and(u8::is_ascii_digit) {
                *cursor += 1;
            }
            if *cursor == digit_start
                || value.get(*cursor) != Some(&b'e')
                || (value.get(digit_start) == Some(&b'0') && *cursor - digit_start > 1)
                || (value.get(start) == Some(&b'-') && value.get(digit_start) == Some(&b'0'))
            {
                return Err(UdpSafeCodecError::MalformedResponse);
            }
            *cursor += 1;
        }
        Some(kind @ (b'l' | b'd')) => {
            *cursor += 1;
            let mut prior_key: Option<&[u8]> = None;
            for _ in 0..64 {
                if value.get(*cursor) == Some(&b'e') {
                    *cursor += 1;
                    return Ok(());
                }
                if kind == b'd' {
                    let key = parse_bencode_bytes(value, cursor)?;
                    if prior_key.is_some_and(|prior| prior >= key) {
                        return Err(UdpSafeCodecError::MalformedResponse);
                    }
                    prior_key = Some(key);
                }
                skip_bencode_value(value, cursor, depth + 1)?;
            }
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        _ => return Err(UdpSafeCodecError::MalformedResponse),
    }
    Ok(())
}

fn parse_ntp_control(request: &[u8], response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    if request.len() != 12
        || response.len() < 12
        || response[0] & 7 != 6
        || (response[0] >> 3) & 7 != (request[0] >> 3) & 7
        || response[1] & 0x80 == 0
        || response[1] & 0x20 != 0
        || response[1] & 0x1f != request[1] & 0x1f
        || response[2..4] != request[2..4]
        || response[8..10] != [0, 0]
        || 12 + usize::from(u16::from_be_bytes([response[10], response[11]])) != response.len()
    {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    Ok(("NTP control", 3, None, Vec::new()))
}

fn parse_slp(request: &[u8], response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    if request.len() < 14
        || response.len() < 20
        || response.len() > 1_400
        || response[..2] != [2, 2]
    {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    if response[10..12] != request[10..12] {
        return Err(UdpSafeCodecError::WrongTransaction);
    }
    let length = (usize::from(response[2]) << 16)
        | (usize::from(response[3]) << 8)
        | usize::from(response[4]);
    let next_extension = (usize::from(response[7]) << 16)
        | (usize::from(response[8]) << 8)
        | usize::from(response[9]);
    let language_length = usize::from(u16::from_be_bytes([response[12], response[13]]));
    let body = 14_usize
        .checked_add(language_length)
        .filter(|body| body.checked_add(4).is_some_and(|end| end <= response.len()))
        .ok_or(UdpSafeCodecError::MalformedResponse)?;
    if length != response.len()
        || next_extension != 0
        || language_length == 0
        || language_length > 64
        || bounded_text(&response[14..body]).is_none()
    {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let error_code = u16::from_be_bytes([response[body], response[body + 1]]);
    let url_count = usize::from(u16::from_be_bytes([response[body + 2], response[body + 3]]));
    if url_count > 64 || (error_code != 0 && url_count != 0) {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let mut cursor = body + 4;
    for _ in 0..url_count {
        cursor = parse_slp_url_entry(response, cursor)?;
    }
    if cursor != response.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    Ok(("SLP service agent", 3, Some("2".into()), Vec::new()))
}

fn parse_slp_url_entry(value: &[u8], start: usize) -> Result<usize, UdpSafeCodecError> {
    let header_end = start
        .checked_add(5)
        .filter(|end| *end <= value.len())
        .ok_or(UdpSafeCodecError::MalformedResponse)?;
    if value[start] != 0 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let url_length = usize::from(u16::from_be_bytes([value[start + 3], value[start + 4]]));
    let url_end = header_end
        .checked_add(url_length)
        .filter(|end| *end < value.len())
        .ok_or(UdpSafeCodecError::MalformedResponse)?;
    if url_length == 0 || bounded_text(&value[header_end..url_end]).is_none() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let auth_count = usize::from(value[url_end]);
    if auth_count > 16 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let mut cursor = url_end + 1;
    for _ in 0..auth_count {
        let block_header = cursor
            .checked_add(10)
            .filter(|end| *end <= value.len())
            .ok_or(UdpSafeCodecError::MalformedResponse)?;
        let block_length = usize::from(u16::from_be_bytes([value[cursor + 2], value[cursor + 3]]));
        if block_length < 10 {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        let block_end = cursor
            .checked_add(block_length)
            .filter(|end| *end <= value.len())
            .ok_or(UdpSafeCodecError::MalformedResponse)?;
        let spi_length = usize::from(u16::from_be_bytes([value[cursor + 8], value[cursor + 9]]));
        if block_header
            .checked_add(spi_length)
            .is_none_or(|spi_end| spi_end > block_end)
        {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        cursor = block_end;
    }
    Ok(cursor)
}

fn build_netbios_node_status(token: [u8; 16]) -> Vec<u8> {
    let mut output = Vec::with_capacity(50);
    output.extend_from_slice(&token[..2]);
    output.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    output.push(32);
    let mut name = [0_u8; 16];
    name[0] = b'*';
    for byte in name {
        output.push(b'A' + (byte >> 4));
        output.push(b'A' + (byte & 0x0f));
    }
    output.extend_from_slice(&[0, 0, 0x21, 0, 1]);
    output
}

fn build_nfs_v3_null(token: [u8; 16]) -> Vec<u8> {
    let mut output = Vec::with_capacity(40);
    output.extend_from_slice(&token[..4]);
    for word in [0_u32, 2, 100_003, 3, 0, 0, 0, 0, 0] {
        output.extend_from_slice(&word.to_be_bytes());
    }
    output
}

fn address_text(address: IpAddress) -> String {
    match address {
        IpAddress::V4(value) => {
            let octets = value.octets();
            format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
        }
        IpAddress::V6(value) => std::net::Ipv6Addr::from(value.octets()).to_string(),
    }
}

fn authority(address: IpAddress, port: u16) -> String {
    match address {
        IpAddress::V4(_) => format!("{}:{port}", address_text(address)),
        IpAddress::V6(_) => format!("[{}]:{port}", address_text(address)),
    }
}

fn token_hex(token: &[u8]) -> String {
    let mut output = String::with_capacity(token.len() * 2);
    for byte in token {
        use core::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn build_sip_options(token: [u8; 16], context: UdpProbeBuildContext) -> Vec<u8> {
    let destination = authority(context.destination, context.destination_port);
    let source = authority(context.source, context.source_port);
    let transaction = token_hex(&token);
    format!(
        "OPTIONS sip:{destination} SIP/2.0\r\nVia: SIP/2.0/UDP {source};branch=z9hG4bK{transaction};rport\r\nMax-Forwards: 0\r\nTo: <sip:{destination}>\r\nFrom: <sip:nodenet@{source}>;tag={}\r\nCall-ID: {transaction}@nodenet.invalid\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
        token_hex(&token[..8])
    )
    .into_bytes()
}

fn build_ssdp_unicast(context: UdpProbeBuildContext) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {}\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\r\nUSER-AGENT: Linux/unknown UPnP/1.1 nodenet/0.1\r\n\r\n",
        authority(context.destination, context.destination_port)
    )
    .into_bytes()
}

fn l2tp_avp(attribute: u16, value: &[u8]) -> Vec<u8> {
    let length = u16::try_from(6 + value.len()).expect("bounded L2TP AVP");
    let mut output = Vec::with_capacity(usize::from(length));
    output.extend_from_slice(&(0x8000 | length).to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&attribute.to_be_bytes());
    output.extend_from_slice(value);
    output
}

fn build_l2tp_sccrq(token: [u8; 16]) -> Vec<u8> {
    let tunnel_id = nonzero_u16(u16::from_be_bytes([token[0], token[1]]));
    let mut output = vec![0xc8, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for avp in [
        l2tp_avp(0, &1_u16.to_be_bytes()),
        l2tp_avp(2, &[1, 0]),
        l2tp_avp(7, b"nodenet"),
        l2tp_avp(3, &3_u32.to_be_bytes()),
        l2tp_avp(9, &tunnel_id.to_be_bytes()),
        l2tp_avp(10, &4_u16.to_be_bytes()),
    ] {
        output.extend_from_slice(&avp);
    }
    let length = u16::try_from(output.len()).expect("bounded L2TP SCCRQ");
    output[2..4].copy_from_slice(&length.to_be_bytes());
    output
}

fn nonzero_u16(value: u16) -> u16 {
    if value == 0 { 1 } else { value }
}

fn ber_integer(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(3);
    let slice = &bytes[first..];
    let needs_zero = slice[0] & 0x80 != 0;
    let mut output = vec![
        0x02,
        u8::try_from(slice.len() + usize::from(needs_zero)).unwrap(),
    ];
    if needs_zero {
        output.push(0);
    }
    output.extend_from_slice(slice);
    output
}

fn ber(tag: u8, parts: &[Vec<u8>]) -> Vec<u8> {
    let length: usize = parts.iter().map(Vec::len).sum();
    let mut output = vec![tag, u8::try_from(length).expect("bounded SNMPv1 request")];
    for part in parts {
        output.extend_from_slice(part);
    }
    output
}

fn build_snmpv1(token: [u8; 16]) -> Vec<u8> {
    let request_id = u32::from_be_bytes(token[..4].try_into().unwrap()) & 0x7fff_ffff;
    let variable = ber(
        0x30,
        &[vec![0x06, 8, 0x2b, 6, 1, 2, 1, 1, 1, 0], vec![0x05, 0]],
    );
    let pdu = ber(
        0xa0,
        &[
            ber_integer(request_id),
            vec![0x02, 1, 0],
            vec![0x02, 1, 0],
            ber(0x30, &[variable]),
        ],
    );
    ber(
        0x30,
        &[
            vec![0x02, 1, 0],
            vec![0x04, 6, b'p', b'u', b'b', b'l', b'i', b'c'],
            pdu,
        ],
    )
}

fn build_memcached_stats(token: [u8; 16]) -> Vec<u8> {
    let mut output = vec![token[0], token[1], 0, 0, 0, 1, 0, 0];
    output.extend_from_slice(b"stats\r\n");
    output
}

fn parse_netbios(request: &[u8], response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    if request.len() != 50 || response.len() < 25 || response[..2] != request[..2] {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    if response[2] & 0x80 == 0 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let question_count = usize::from(u16::from_be_bytes([response[4], response[5]]));
    let answer_count = usize::from(u16::from_be_bytes([response[6], response[7]]));
    if question_count > 1 || answer_count == 0 || answer_count > 64 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let mut cursor = 12;
    for _ in 0..question_count {
        cursor = dns_name_end(response, cursor)?;
        cursor = cursor
            .checked_add(4)
            .filter(|end| *end <= response.len())
            .ok_or(UdpSafeCodecError::MalformedResponse)?;
    }
    for _ in 0..answer_count {
        cursor = dns_name_end(response, cursor)?;
        let header_end = cursor
            .checked_add(10)
            .filter(|end| *end <= response.len())
            .ok_or(UdpSafeCodecError::MalformedResponse)?;
        let kind = u16::from_be_bytes([response[cursor], response[cursor + 1]]);
        let class = u16::from_be_bytes([response[cursor + 2], response[cursor + 3]]);
        let data_length = usize::from(u16::from_be_bytes([
            response[header_end - 2],
            response[header_end - 1],
        ]));
        let end = header_end
            .checked_add(data_length)
            .filter(|end| *end <= response.len())
            .ok_or(UdpSafeCodecError::MalformedResponse)?;
        if kind == 0x21 && class & 0x7fff == 1 {
            let data = &response[header_end..end];
            let count = usize::from(*data.first().ok_or(UdpSafeCodecError::MalformedResponse)?);
            let names_end = 1_usize
                .checked_add(
                    count
                        .checked_mul(18)
                        .ok_or(UdpSafeCodecError::MalformedResponse)?,
                )
                .ok_or(UdpSafeCodecError::MalformedResponse)?;
            if count > 100 || names_end > data.len() {
                return Err(UdpSafeCodecError::MalformedResponse);
            }
            let name = data.get(1..16).and_then(|value| {
                let end = value.iter().rposition(|byte| *byte != b' ' && *byte != 0)? + 1;
                bounded_text(&value[..end])
            });
            return Ok((
                "NetBIOS Name Service",
                3,
                None,
                name.into_iter().map(|value| (3, value)).collect(),
            ));
        }
        cursor = end;
    }
    Err(UdpSafeCodecError::MalformedResponse)
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

fn parse_rpc_accepted(request: &[u8], response: &[u8]) -> Result<(), UdpSafeCodecError> {
    if request.len() < 4 || response.len() < 24 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    if response[..4] != request[..4] {
        return Err(UdpSafeCodecError::WrongTransaction);
    }
    let word = |offset: usize| u32::from_be_bytes(response[offset..offset + 4].try_into().unwrap());
    if word(4) != 1 || word(8) != 0 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let verifier = usize::try_from(word(16)).map_err(|_| UdpSafeCodecError::MalformedResponse)?;
    let accept = 20_usize
        .checked_add(
            verifier
                .checked_add(3)
                .ok_or(UdpSafeCodecError::MalformedResponse)?
                & !3,
        )
        .ok_or(UdpSafeCodecError::MalformedResponse)?;
    if accept.checked_add(4) != Some(response.len()) || word(accept) != 0 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    Ok(())
}

fn parse_nfs(request: &[u8], response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    parse_rpc_accepted(request, response)?;
    Ok(("NFS", 3, Some("v3".into()), Vec::new()))
}

fn ascii_message(value: &[u8], maximum: usize) -> Result<&str, UdpSafeCodecError> {
    if value.is_empty()
        || value.len() > maximum
        || value
            .iter()
            .any(|byte| !matches!(*byte, b'\t' | b'\r' | b'\n' | 0x20..=0x7e))
    {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    core::str::from_utf8(value).map_err(|_| UdpSafeCodecError::MalformedResponse)
}

fn header_value<'a>(message: &'a str, name: &str) -> Option<&'a str> {
    message.split("\r\n").skip(1).find_map(|line| {
        let (field, value) = line.split_once(':')?;
        field.eq_ignore_ascii_case(name).then_some(value.trim())
    })
}

fn parse_sip(request: &[u8], response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    let request = ascii_message(request, 1_024)?;
    let response = ascii_message(response, 1_024)?;
    let status = response
        .split("\r\n")
        .next()
        .filter(|line| {
            line.starts_with("SIP/2.0 ")
                && line
                    .as_bytes()
                    .get(8..11)
                    .is_some_and(|v| v.iter().all(u8::is_ascii_digit))
        })
        .ok_or(UdpSafeCodecError::MalformedResponse)?;
    if header_value(response, "Call-ID") != header_value(request, "Call-ID")
        || !header_value(response, "CSeq").is_some_and(|value| value.ends_with(" OPTIONS"))
    {
        return Err(UdpSafeCodecError::WrongTransaction);
    }
    let server = header_value(response, "Server").and_then(|value| bounded_text(value.as_bytes()));
    Ok(("SIP", 3, server, vec![(1, status[8..11].to_string())]))
}

fn parse_ssdp(response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    let response = ascii_message(response, 4_096)?;
    let status = response
        .split("\r\n")
        .next()
        .filter(|line| line.starts_with("HTTP/1.1 200"))
        .ok_or(UdpSafeCodecError::MalformedResponse)?;
    let st = header_value(response, "ST").ok_or(UdpSafeCodecError::MalformedResponse)?;
    let server = header_value(response, "Server").and_then(|value| bounded_text(value.as_bytes()));
    let st = bounded_text(st.as_bytes()).ok_or(UdpSafeCodecError::MalformedResponse)?;
    let _ = status;
    Ok(("SSDP/UPnP", 2, server, vec![(3, st)]))
}

fn request_l2tp_tunnel_id(request: &[u8]) -> Result<u16, UdpSafeCodecError> {
    l2tp_avps(request)?
        .into_iter()
        .find_map(|(attribute, value)| {
            (attribute == 9 && value.len() == 2).then(|| u16::from_be_bytes([value[0], value[1]]))
        })
        .ok_or(UdpSafeCodecError::MalformedResponse)
}

fn l2tp_avps(value: &[u8]) -> Result<Vec<(u16, &[u8])>, UdpSafeCodecError> {
    if value.len() < 12 || value[0] & 0xc8 != 0xc8 || value[1] & 0x0f != 2 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let declared = usize::from(u16::from_be_bytes([value[2], value[3]]));
    if declared != value.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let mut output = Vec::new();
    let mut cursor = 12;
    while cursor < value.len() {
        if output.len() == 64 || cursor + 6 > value.len() {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        let flags_length = u16::from_be_bytes([value[cursor], value[cursor + 1]]);
        let length = usize::from(flags_length & 0x03ff);
        if length < 6 || cursor + length > value.len() || value[cursor + 2..cursor + 4] != [0, 0] {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        let attribute = u16::from_be_bytes([value[cursor + 4], value[cursor + 5]]);
        output.push((attribute, &value[cursor + 6..cursor + length]));
        cursor += length;
    }
    Ok(output)
}

fn parse_l2tp(request: &[u8], response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    let expected = request_l2tp_tunnel_id(request)?;
    if response.len() < 12 || u16::from_be_bytes([response[4], response[5]]) != expected {
        return Err(UdpSafeCodecError::WrongTransaction);
    }
    let avps = l2tp_avps(response)?;
    let mut message = None;
    let mut protocol = false;
    let mut framing = false;
    let mut assigned = None;
    let mut host = None;
    for (attribute, value) in avps {
        match attribute {
            0 if value.len() == 2 => message = Some(u16::from_be_bytes([value[0], value[1]])),
            2 if value == [1, 0] => protocol = true,
            3 if value.len() == 4 => framing = true,
            7 => host = bounded_text(value),
            9 if value.len() == 2 => assigned = Some(u16::from_be_bytes([value[0], value[1]])),
            _ => {}
        }
    }
    if message != Some(2) || !protocol || !framing || assigned.is_none() || host.is_none() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    Ok((
        "L2TP",
        3,
        Some("v2".into()),
        vec![(3, host.unwrap()), (4, assigned.unwrap().to_string())],
    ))
}

fn ber_tlv(value: &[u8], start: usize) -> Result<(u8, &[u8], usize), UdpSafeCodecError> {
    if start + 2 > value.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let tag = value[start];
    let first = value[start + 1];
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 2 || start + 2 + count > value.len() {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        let mut length = 0_usize;
        for byte in &value[start + 2..start + 2 + count] {
            length = (length << 8) | usize::from(*byte);
        }
        (length, 2 + count)
    };
    let body = start + header;
    let end = body
        .checked_add(length)
        .filter(|end| *end <= value.len())
        .ok_or(UdpSafeCodecError::MalformedResponse)?;
    Ok((tag, &value[body..end], end))
}

fn ber_unsigned(value: &[u8]) -> Result<u32, UdpSafeCodecError> {
    if value.is_empty() || value.len() > 5 || (value.len() == 5 && value[0] != 0) {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    Ok(value
        .iter()
        .fold(0_u32, |acc, byte| (acc << 8) | u32::from(*byte)))
}

fn snmp_request_id(
    message: &[u8],
    expected_pdu: u8,
) -> Result<(u32, Option<String>), UdpSafeCodecError> {
    let (tag, outer, end) = ber_tlv(message, 0)?;
    if tag != 0x30 || end != message.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let (tag, version, mut cursor) = ber_tlv(outer, 0)?;
    if tag != 0x02 || version != [0] {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let (tag, community, next) = ber_tlv(outer, cursor)?;
    if tag != 0x04 || community != b"public" {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    cursor = next;
    let (tag, pdu, next) = ber_tlv(outer, cursor)?;
    if tag != expected_pdu || next != outer.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let (tag, id, mut pdu_cursor) = ber_tlv(pdu, 0)?;
    if tag != 0x02 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let id = ber_unsigned(id)?;
    let (tag, error, next) = ber_tlv(pdu, pdu_cursor)?;
    if tag != 0x02 || ber_unsigned(error)? > 5 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    pdu_cursor = next;
    let (tag, _, next) = ber_tlv(pdu, pdu_cursor)?;
    if tag != 0x02 {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let (tag, list, next) = ber_tlv(pdu, next)?;
    if tag != 0x30 || next != pdu.len() {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let description = if list.is_empty() {
        None
    } else {
        let (tag, binding, _) = ber_tlv(list, 0)?;
        if tag != 0x30 {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        let (tag, oid, next) = ber_tlv(binding, 0)?;
        if tag != 0x06 || oid != [0x2b, 6, 1, 2, 1, 1, 1, 0] {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        let (tag, value, end) = ber_tlv(binding, next)?;
        if end != binding.len() {
            return Err(UdpSafeCodecError::MalformedResponse);
        }
        (tag == 0x04).then(|| bounded_text(value)).flatten()
    };
    Ok((id, description))
}

fn parse_snmpv1(request: &[u8], response: &[u8]) -> Result<ExtendedParsed, UdpSafeCodecError> {
    let (request_id, _) = snmp_request_id(request, 0xa0)?;
    let (response_id, description) = snmp_request_id(response, 0xa2)?;
    if request_id != response_id {
        return Err(UdpSafeCodecError::WrongTransaction);
    }
    Ok((
        "SNMP",
        3,
        Some("v1".into()),
        description.into_iter().map(|value| (3, value)).collect(),
    ))
}

fn parse_memcached_stats(
    request: &[u8],
    response: &[u8],
) -> Result<ExtendedParsed, UdpSafeCodecError> {
    if request.len() < 8
        || response.len() < 13
        || response[..2] != request[..2]
        || u16::from_be_bytes([response[2], response[3]])
            >= u16::from_be_bytes([response[4], response[5]])
        || response[6..8] != [0, 0]
    {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let payload = ascii_message(&response[8..], 4_088)?;
    if !payload.starts_with("STAT ") && payload != "END\r\n" {
        return Err(UdpSafeCodecError::MalformedResponse);
    }
    let version = payload.split("\r\n").find_map(|line| {
        line.strip_prefix("STAT version ")
            .and_then(|value| bounded_text(value.as_bytes()))
    });
    Ok(("memcached", 3, version, Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ipv4Address, UDP_PROBE_CATALOGUE};

    const TOKEN: [u8; 16] = *b"0123456789abcdef";

    fn context(port: u16) -> UdpProbeBuildContext {
        UdpProbeBuildContext {
            source: IpAddress::V4(Ipv4Address::new([192, 0, 2, 10])),
            destination: IpAddress::V4(Ipv4Address::new([198, 51, 100, 20])),
            source_port: 50_000,
            destination_port: port,
        }
    }

    #[test]
    fn extended_golden_requests_are_protocol_framed() {
        let netbios =
            build_udp_catalogue_request(UdpCatalogueProbe::NetbiosNodeStatus, TOKEN, context(137))
                .unwrap();
        assert_eq!(netbios.len(), 50);
        assert_eq!(&netbios[46..], &[0, 0x21, 0, 1]);

        let nfs = build_udp_catalogue_request(UdpCatalogueProbe::NfsV3Null, TOKEN, context(2049))
            .unwrap();
        assert_eq!(nfs.len(), 40);
        assert_eq!(&nfs[12..20], &[0, 1, 0x86, 0xa3, 0, 0, 0, 3]);

        let sip = build_udp_catalogue_request(UdpCatalogueProbe::SipOptions, TOKEN, context(5060))
            .unwrap();
        let sip = core::str::from_utf8(&sip).unwrap();
        assert!(sip.starts_with("OPTIONS sip:198.51.100.20:5060 SIP/2.0\r\n"));
        assert!(sip.contains("Via: SIP/2.0/UDP 192.0.2.10:50000"));

        let ssdp =
            build_udp_catalogue_request(UdpCatalogueProbe::SsdpUnicast, TOKEN, context(1900))
                .unwrap();
        assert!(ssdp.starts_with(b"M-SEARCH * HTTP/1.1\r\n"));

        let l2tp = build_udp_catalogue_request(UdpCatalogueProbe::L2tpSccrq, TOKEN, context(1701))
            .unwrap();
        assert_eq!(
            usize::from(u16::from_be_bytes([l2tp[2], l2tp[3]])),
            l2tp.len()
        );

        let snmp = build_udp_catalogue_request(
            UdpCatalogueProbe::SnmpV1SystemDescription,
            TOKEN,
            context(161),
        )
        .unwrap();
        assert!(snmp.windows(6).any(|value| value == b"public"));
        assert!(snmp.contains(&0xa0));

        let stats = build_udp_catalogue_request(
            UdpCatalogueProbe::MemcachedStatistics,
            TOKEN,
            context(11_211),
        )
        .unwrap();
        assert_eq!(&stats[8..], b"stats\r\n");
    }

    #[test]
    fn every_catalogue_builder_stays_inside_declared_request_bounds() {
        for descriptor in UDP_PROBE_CATALOGUE {
            let probe = UdpCatalogueProbe::from_id(descriptor.request_builder_id).unwrap();
            let request =
                build_udp_catalogue_request(probe, TOKEN, context(descriptor.ports[0].start))
                    .unwrap();
            assert!(
                request.len() >= descriptor.minimum_request_bytes,
                "{} request is below its conservative minimum",
                descriptor.name
            );
            assert!(
                request.len() <= descriptor.request_template_bytes,
                "{} request exceeds its declared maximum",
                descriptor.name
            );
        }
    }

    #[test]
    fn extended_responses_require_structure_and_transactions() {
        let request = build_nfs_v3_null(TOKEN);
        let mut response = request[..4].to_vec();
        for word in [1_u32, 0, 0, 0, 0] {
            response.extend_from_slice(&word.to_be_bytes());
        }
        assert!(parse_nfs(&request, &response).is_ok());
        response[0] ^= 1;
        assert_eq!(
            parse_nfs(&request, &response),
            Err(UdpSafeCodecError::WrongTransaction)
        );

        let request = build_memcached_stats(TOKEN);
        let mut response = request[..8].to_vec();
        response.extend_from_slice(b"STAT version 1.6.22\r\nEND\r\n");
        let parsed = parse_memcached_stats(&request, &response).unwrap();
        assert_eq!(parsed.2.as_deref(), Some("1.6.22"));

        let request = build_sip_options(TOKEN, context(5060));
        let call_id = header_value(core::str::from_utf8(&request).unwrap(), "Call-ID").unwrap();
        let response = format!(
            "SIP/2.0 200 OK\r\nCall-ID: {call_id}\r\nCSeq: 1 OPTIONS\r\nServer: fixture/1\r\nContent-Length: 0\r\n\r\n"
        );
        assert!(parse_sip(&request, response.as_bytes()).is_ok());
    }

    #[test]
    fn every_extended_family_accepts_an_independent_canonical_response() {
        let request = build_netbios_node_status(TOKEN);
        let mut response = Vec::new();
        response.extend_from_slice(&request[..2]);
        response.extend_from_slice(&[0x85, 0, 0, 1, 0, 1, 0, 0, 0, 0]);
        response.extend_from_slice(&request[12..]);
        response.extend_from_slice(&[0xc0, 0x0c, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 65, 1]);
        let mut name = [b' '; 15];
        name[..7].copy_from_slice(b"FIXTURE");
        response.extend_from_slice(&name);
        response.extend_from_slice(&[0, 4, 0]);
        response.extend_from_slice(&[0; 46]);
        assert!(parse_netbios(&request, &response).is_ok());

        let request = build_ssdp_unicast(context(1900));
        let response = b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nServer: fixture/1\r\n\r\n";
        assert!(parse_ssdp(response).is_ok());
        assert!(
            parse_udp_catalogue_response(UdpCatalogueProbe::SsdpUnicast, &request, response,)
                .is_ok()
        );

        let request = build_l2tp_sccrq(TOKEN);
        let expected = request_l2tp_tunnel_id(&request).unwrap();
        let mut response = vec![0xc8, 2, 0, 0];
        response.extend_from_slice(&expected.to_be_bytes());
        response.extend_from_slice(&[0, 0, 0, 0, 0, 1]);
        for avp in [
            l2tp_avp(0, &2_u16.to_be_bytes()),
            l2tp_avp(2, &[1, 0]),
            l2tp_avp(3, &3_u32.to_be_bytes()),
            l2tp_avp(7, b"fixture"),
            l2tp_avp(9, &0x4242_u16.to_be_bytes()),
        ] {
            response.extend_from_slice(&avp);
        }
        let length = u16::try_from(response.len()).unwrap();
        response[2..4].copy_from_slice(&length.to_be_bytes());
        assert!(parse_l2tp(&request, &response).is_ok());

        let request = build_snmpv1(TOKEN);
        let mut response = request.clone();
        let pdu = response.iter().position(|byte| *byte == 0xa0).unwrap();
        response[pdu] = 0xa2;
        assert!(parse_snmpv1(&request, &response).is_ok());

        for probe in [
            UdpCatalogueProbe::Echo,
            UdpCatalogueProbe::Daytime,
            UdpCatalogueProbe::QuoteOfTheDay,
            UdpCatalogueProbe::CharacterGenerator,
            UdpCatalogueProbe::ActiveUsers,
            UdpCatalogueProbe::NetworkStatus,
            UdpCatalogueProbe::RipV2Table,
            UdpCatalogueProbe::XdmcpQuery,
            UdpCatalogueProbe::SourceEngineInfo,
            UdpCatalogueProbe::RaknetUnconnectedPing,
            UdpCatalogueProbe::BacnetWhoIs,
            UdpCatalogueProbe::EthernetIpListIdentity,
            UdpCatalogueProbe::KnxnetIpSearch,
            UdpCatalogueProbe::BitTorrentDhtPing,
            UdpCatalogueProbe::DnsChaosVersion,
            UdpCatalogueProbe::NtpControlReadVariables,
            UdpCatalogueProbe::SlpServiceAgent,
        ] {
            let request = build_udp_catalogue_request(probe, TOKEN, context(1)).unwrap();
            let response = phase31_response(probe, &request);
            assert!(
                parse_udp_catalogue_response(probe, &request, &response).is_ok(),
                "canonical response failed for {probe:?}"
            );
        }
    }

    fn phase31_response(probe: UdpCatalogueProbe, request: &[u8]) -> Vec<u8> {
        match probe {
            UdpCatalogueProbe::Echo => request.to_vec(),
            UdpCatalogueProbe::Daytime
            | UdpCatalogueProbe::QuoteOfTheDay
            | UdpCatalogueProbe::CharacterGenerator
            | UdpCatalogueProbe::ActiveUsers
            | UdpCatalogueProbe::NetworkStatus => b"fixture response\n".to_vec(),
            UdpCatalogueProbe::RipV2Table => {
                let mut value = vec![2, 2, 0, 0];
                value.extend_from_slice(&[0; 16]);
                value.extend_from_slice(&1_u32.to_be_bytes());
                value
            }
            UdpCatalogueProbe::XdmcpQuery => {
                vec![0, 1, 0, 5, 0, 6, 0, 0, 0, 0, 0, 0]
            }
            UdpCatalogueProbe::SourceEngineInfo => {
                let mut value = vec![0xff, 0xff, 0xff, 0xff, 0x49, 17];
                value.extend_from_slice(b"fixture\0");
                value
            }
            UdpCatalogueProbe::RaknetUnconnectedPing => {
                let mut value = vec![0x1c];
                value.extend_from_slice(&request[1..9]);
                value.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
                value.extend_from_slice(&RAKNET_MAGIC);
                value.extend_from_slice(&7_u16.to_be_bytes());
                value.extend_from_slice(b"fixture");
                value
            }
            UdpCatalogueProbe::BacnetWhoIs => vec![
                0x81, 0x0a, 0, 20, 1, 0, 0x10, 0, 0xc4, 0x02, 0, 0, 1, 0x22, 1, 0xe0, 0x91, 3,
                0x21, 1,
            ],
            UdpCatalogueProbe::EthernetIpListIdentity => {
                let mut value = request.to_vec();
                value[2..4].copy_from_slice(&40_u16.to_le_bytes());
                value.extend_from_slice(&1_u16.to_le_bytes());
                value.extend_from_slice(&0x000c_u16.to_le_bytes());
                value.extend_from_slice(&34_u16.to_le_bytes());
                value.extend_from_slice(&1_u16.to_le_bytes());
                value.extend_from_slice(&2_u16.to_be_bytes());
                value.extend_from_slice(&[0; 14]);
                value.extend_from_slice(&1_u16.to_le_bytes());
                value.extend_from_slice(&2_u16.to_le_bytes());
                value.extend_from_slice(&3_u16.to_le_bytes());
                value.extend_from_slice(&[1, 0]);
                value.extend_from_slice(&0_u16.to_le_bytes());
                value.extend_from_slice(&7_u32.to_le_bytes());
                value.extend_from_slice(&[0, 0]);
                value
            }
            UdpCatalogueProbe::KnxnetIpSearch => {
                let mut value = vec![6, 0x10, 2, 2, 0, 72, 8, 1, 192, 0, 2, 1, 0x0e, 0x57];
                value.extend_from_slice(&[54, 1, 2]);
                value.extend_from_slice(&[0; 51]);
                value.extend_from_slice(&[4, 2, 2, 1]);
                value
            }
            UdpCatalogueProbe::BitTorrentDhtPing => {
                let marker = request
                    .windows(5)
                    .position(|value| value == b"1:t2:")
                    .unwrap()
                    + 5;
                let mut value = b"d1:rd2:id20:".to_vec();
                value.extend_from_slice(b"abcdefghijklmnopqrst");
                value.extend_from_slice(b"e1:t2:");
                value.extend_from_slice(&request[marker..marker + 2]);
                value.extend_from_slice(b"1:y1:re");
                value
            }
            UdpCatalogueProbe::DnsChaosVersion => {
                let mut value = request[..2].to_vec();
                value.extend_from_slice(&[0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0]);
                value
            }
            UdpCatalogueProbe::NtpControlReadVariables => {
                let mut value = request.to_vec();
                value[1] = 0x82;
                value
            }
            UdpCatalogueProbe::SlpServiceAgent => {
                let mut value = vec![2, 2, 0, 0, 20, 0, 0, 0, 0, 0];
                value.extend_from_slice(&request[10..12]);
                value.extend_from_slice(&[0, 2, b'e', b'n', 0, 0, 0, 0]);
                value
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn phase31_structured_parsers_reject_marker_smuggling_and_incomplete_messages() {
        let request =
            build_udp_catalogue_request(UdpCatalogueProbe::BitTorrentDhtPing, TOKEN, context(1))
                .unwrap();
        let marker = request
            .windows(5)
            .position(|value| value == b"1:t2:")
            .unwrap()
            + 5;
        let transaction = &request[marker..marker + 2];
        let mut smuggled = b"d1:rd2:id20:abcdefghijklmnopqrste1:x7:1:t2:".to_vec();
        smuggled.extend_from_slice(transaction);
        smuggled.extend_from_slice(b"1:y1:re");
        assert_eq!(
            parse_udp_catalogue_response(UdpCatalogueProbe::BitTorrentDhtPing, &request, &smuggled,),
            Err(UdpSafeCodecError::MalformedResponse)
        );

        let request = build_udp_catalogue_request(
            UdpCatalogueProbe::NtpControlReadVariables,
            TOKEN,
            context(1),
        )
        .unwrap();
        let mut fragmented = request.clone();
        fragmented[1] = 0xa2;
        assert_eq!(
            parse_udp_catalogue_response(
                UdpCatalogueProbe::NtpControlReadVariables,
                &request,
                &fragmented,
            ),
            Err(UdpSafeCodecError::MalformedResponse)
        );

        let request =
            build_udp_catalogue_request(UdpCatalogueProbe::SlpServiceAgent, TOKEN, context(1))
                .unwrap();
        let mut incomplete = vec![2, 2, 0, 0, 18, 0, 0, 0, 0, 0];
        incomplete.extend_from_slice(&request[10..12]);
        incomplete.extend_from_slice(&[0, 2, b'e', b'n', 0, 0]);
        assert_eq!(
            parse_udp_catalogue_response(UdpCatalogueProbe::SlpServiceAgent, &request, &incomplete,),
            Err(UdpSafeCodecError::MalformedResponse)
        );
    }

    #[test]
    fn every_extended_parser_rejects_truncation_and_arbitrary_bytes() {
        for probe in [
            UdpCatalogueProbe::NetbiosNodeStatus,
            UdpCatalogueProbe::NfsV3Null,
            UdpCatalogueProbe::SipOptions,
            UdpCatalogueProbe::SsdpUnicast,
            UdpCatalogueProbe::L2tpSccrq,
            UdpCatalogueProbe::SnmpV1SystemDescription,
            UdpCatalogueProbe::MemcachedStatistics,
            UdpCatalogueProbe::Echo,
            UdpCatalogueProbe::Daytime,
            UdpCatalogueProbe::QuoteOfTheDay,
            UdpCatalogueProbe::CharacterGenerator,
            UdpCatalogueProbe::ActiveUsers,
            UdpCatalogueProbe::NetworkStatus,
            UdpCatalogueProbe::RipV2Table,
            UdpCatalogueProbe::XdmcpQuery,
            UdpCatalogueProbe::SourceEngineInfo,
            UdpCatalogueProbe::RaknetUnconnectedPing,
            UdpCatalogueProbe::BacnetWhoIs,
            UdpCatalogueProbe::EthernetIpListIdentity,
            UdpCatalogueProbe::KnxnetIpSearch,
            UdpCatalogueProbe::BitTorrentDhtPing,
            UdpCatalogueProbe::DnsChaosVersion,
            UdpCatalogueProbe::NtpControlReadVariables,
            UdpCatalogueProbe::SlpServiceAgent,
        ] {
            let request = build_udp_catalogue_request(probe, TOKEN, context(1)).unwrap();
            for length in 0..request.len().min(48) {
                assert!(parse_udp_catalogue_response(probe, &request, &request[..length]).is_err());
            }
            assert!(parse_udp_catalogue_response(probe, &request, &[0xa5; 127]).is_err());
        }
    }
}
