//! Bounded targeted and state-transition UDP discovery codecs.

use core::fmt;
use core::fmt::Write as _;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const MAX_SQL_BROWSER_RESPONSE_BYTES: usize = 65_507;
pub const MAX_SQL_BROWSER_INSTANCES: usize = 128;
pub const MAX_SQL_BROWSER_FIELDS: usize = 64;
pub const MAX_SQL_BROWSER_TEXT_BYTES: usize = 1_024;
pub const QUIC_VERSION_NEGOTIATION_REQUEST_BYTES: usize = 1_200;
pub const MAX_QUIC_ADVERTISED_VERSIONS: usize = 64;
pub const MAX_TFTP_DISCOVERY_RESPONSE_BYTES: usize = 1_024;
pub const RIPV1_TABLE_REQUEST_BYTES: usize = 24;
pub const MAX_RIPV1_RESPONSE_BYTES: usize = 504;
pub const MAX_RIPV1_ROUTES_PER_DATAGRAM: usize = 25;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetedDiscoveryError {
    Truncated,
    UnexpectedMessage,
    InvalidLength,
    InvalidText,
    DuplicateField,
    TooManyValues,
    InvalidTransaction,
    InvalidEndpoint,
    ArithmeticOverflow,
}

impl fmt::Display for TargetedDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid targeted discovery message: {self:?}")
    }
}

impl std::error::Error for TargetedDiscoveryError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NatPmpExternalAddressResponse {
    pub result_code: u16,
    pub epoch_seconds: u32,
    pub external_address: Ipv4Addr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqlBrowserInstance {
    pub server_name: String,
    pub instance_name: String,
    pub tcp_port: Option<u16>,
    pub named_pipe: Option<String>,
    pub version: Option<String>,
    pub clustered: Option<bool>,
    pub fields: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TftpDiscoveryResponse {
    Error { code: u16, message: String },
    Data { block: u16, payload_bytes: usize },
    OptionAcknowledgement(BTreeMap<String, String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicVersionNegotiationRequest {
    pub bytes: Vec<u8>,
    pub destination_connection_id: [u8; 8],
    pub source_connection_id: [u8; 8],
    pub reserved_version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicVersionNegotiationResponse {
    pub versions: Vec<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RipV1Route {
    pub destination: Ipv4Addr,
    pub metric: u32,
}

/// Builds the RFC 1058 request for the target's complete `RIPv1` routing table.
#[must_use]
pub fn build_ripv1_table_request() -> [u8; RIPV1_TABLE_REQUEST_BYTES] {
    let mut request = [0_u8; RIPV1_TABLE_REQUEST_BYTES];
    request[0] = 1;
    request[1] = 1;
    request[20..24].copy_from_slice(&16_u32.to_be_bytes());
    request
}

/// Parses one independently bounded `RIPv1` response datagram.
///
/// # Errors
///
/// Rejects non-response commands, non-v1 messages, reserved-field drift,
/// non-IPv4 routes, incomplete entries, and metrics outside 1 through 16.
pub fn parse_ripv1_table_response(input: &[u8]) -> Result<Vec<RipV1Route>, TargetedDiscoveryError> {
    if input.len() < RIPV1_TABLE_REQUEST_BYTES
        || input.len() > MAX_RIPV1_RESPONSE_BYTES
        || !(input.len() - 4).is_multiple_of(20)
        || input[..4] != [2, 1, 0, 0]
    {
        return Err(TargetedDiscoveryError::UnexpectedMessage);
    }
    let route_count = (input.len() - 4) / 20;
    if route_count == 0 || route_count > MAX_RIPV1_ROUTES_PER_DATAGRAM {
        return Err(TargetedDiscoveryError::TooManyValues);
    }
    let mut routes = Vec::with_capacity(route_count);
    for entry in input[4..].chunks_exact(20) {
        let family = u16::from_be_bytes([entry[0], entry[1]]);
        let metric = u32::from_be_bytes(
            entry[16..20]
                .try_into()
                .map_err(|_| TargetedDiscoveryError::InvalidLength)?,
        );
        if family != 2
            || entry[2..4] != [0, 0]
            || entry[8..16] != [0; 8]
            || !(1..=16).contains(&metric)
        {
            return Err(TargetedDiscoveryError::UnexpectedMessage);
        }
        routes.push(RipV1Route {
            destination: Ipv4Addr::new(entry[4], entry[5], entry[6], entry[7]),
            metric,
        });
    }
    Ok(routes)
}

#[must_use]
pub fn build_nat_pmp_external_address_request() -> [u8; 2] {
    [0, 0]
}

/// Parses one exact NAT-PMP external-address response.
///
/// # Errors
///
/// Rejects wrong lengths, versions, or opcodes.
pub fn parse_nat_pmp_external_address_response(
    input: &[u8],
) -> Result<NatPmpExternalAddressResponse, TargetedDiscoveryError> {
    if input.len() != 12 {
        return Err(TargetedDiscoveryError::InvalidLength);
    }
    if input[0] != 0 || input[1] != 128 {
        return Err(TargetedDiscoveryError::UnexpectedMessage);
    }
    Ok(NatPmpExternalAddressResponse {
        result_code: u16::from_be_bytes([input[2], input[3]]),
        epoch_seconds: u32::from_be_bytes(
            input[4..8]
                .try_into()
                .map_err(|_| TargetedDiscoveryError::InvalidLength)?,
        ),
        external_address: Ipv4Addr::from(
            <[u8; 4]>::try_from(&input[8..12])
                .map_err(|_| TargetedDiscoveryError::InvalidLength)?,
        ),
    })
}

#[must_use]
pub fn build_sql_browser_enumeration_request() -> [u8; 1] {
    [2]
}

/// Parses one bounded SQL Browser enumeration response.
///
/// # Errors
///
/// Rejects malformed framing, text, duplicate fields, and excessive instances.
pub fn parse_sql_browser_response(
    input: &[u8],
) -> Result<Vec<SqlBrowserInstance>, TargetedDiscoveryError> {
    if input.len() < 3 || input.len() > MAX_SQL_BROWSER_RESPONSE_BYTES {
        return Err(TargetedDiscoveryError::InvalidLength);
    }
    if input[0] != 5 {
        return Err(TargetedDiscoveryError::UnexpectedMessage);
    }
    let declared = usize::from(u16::from_le_bytes([input[1], input[2]]));
    if declared != input.len() - 3 {
        return Err(TargetedDiscoveryError::InvalidLength);
    }
    let text =
        core::str::from_utf8(&input[3..]).map_err(|_| TargetedDiscoveryError::InvalidText)?;
    if text
        .bytes()
        .any(|byte| byte != b'\r' && byte != b'\n' && !(0x20..=0x7e).contains(&byte))
    {
        return Err(TargetedDiscoveryError::InvalidText);
    }
    let mut instances = Vec::new();
    for raw_instance in text.split(";;").filter(|value| !value.trim().is_empty()) {
        if instances.len() >= MAX_SQL_BROWSER_INSTANCES {
            return Err(TargetedDiscoveryError::TooManyValues);
        }
        let values: Vec<&str> = raw_instance
            .trim_matches(['\r', '\n', ';'])
            .split(';')
            .collect();
        if !values.len().is_multiple_of(2) || values.len() / 2 > MAX_SQL_BROWSER_FIELDS {
            return Err(TargetedDiscoveryError::InvalidLength);
        }
        let mut fields = BTreeMap::new();
        for pair in values.chunks_exact(2) {
            if pair[0].is_empty()
                || pair[0].len() > MAX_SQL_BROWSER_TEXT_BYTES
                || pair[1].len() > MAX_SQL_BROWSER_TEXT_BYTES
            {
                return Err(TargetedDiscoveryError::InvalidText);
            }
            let key = pair[0].to_ascii_lowercase();
            if fields.insert(key, pair[1].to_owned()).is_some() {
                return Err(TargetedDiscoveryError::DuplicateField);
            }
        }
        let server_name = required_field(&fields, "servername")?;
        let instance_name = required_field(&fields, "instancename")?;
        let tcp_port = fields
            .get("tcp")
            .map(|value| {
                value
                    .parse::<u16>()
                    .map_err(|_| TargetedDiscoveryError::InvalidEndpoint)
            })
            .transpose()?;
        let clustered = fields
            .get("isclustered")
            .map(|value| match value.to_ascii_lowercase().as_str() {
                "yes" => Ok(true),
                "no" => Ok(false),
                _ => Err(TargetedDiscoveryError::InvalidText),
            })
            .transpose()?;
        instances.push(SqlBrowserInstance {
            server_name,
            instance_name,
            tcp_port,
            named_pipe: fields.get("np").cloned(),
            version: fields.get("version").cloned(),
            clustered,
            fields,
        });
    }
    if instances.is_empty() {
        return Err(TargetedDiscoveryError::UnexpectedMessage);
    }
    Ok(instances)
}

/// Builds a collision-resistant synthetic RRQ. The filename is not claimed to
/// be impossible on a remote server; callers must handle positive DATA/OACK.
#[must_use]
pub fn build_tftp_discovery_rrq(entropy: [u8; 16]) -> Vec<u8> {
    let suffix = entropy
        .iter()
        .fold(String::with_capacity(32), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
            output
        });
    let filename = format!("nodenet-discovery-{suffix}.invalid");
    let mut output = Vec::with_capacity(96);
    output.extend_from_slice(&1_u16.to_be_bytes());
    output.extend_from_slice(filename.as_bytes());
    output.push(0);
    output.extend_from_slice(b"octet\0blksize\0");
    output.extend_from_slice(b"32\0tsize\0");
    output.extend_from_slice(b"0\0");
    output
}

/// Parses the first bounded TFTP DATA, ERROR, or OACK response.
///
/// # Errors
///
/// Rejects unsupported opcodes, malformed text/options, and oversized payloads.
pub fn parse_tftp_discovery_response(
    input: &[u8],
) -> Result<TftpDiscoveryResponse, TargetedDiscoveryError> {
    if input.len() < 4 || input.len() > MAX_TFTP_DISCOVERY_RESPONSE_BYTES {
        return Err(TargetedDiscoveryError::InvalidLength);
    }
    match u16::from_be_bytes([input[0], input[1]]) {
        3 => {
            let block = u16::from_be_bytes([input[2], input[3]]);
            if block != 1 {
                return Err(TargetedDiscoveryError::InvalidTransaction);
            }
            Ok(TftpDiscoveryResponse::Data {
                block,
                payload_bytes: input.len() - 4,
            })
        }
        5 => {
            if input.last() != Some(&0) || input.len() < 5 {
                return Err(TargetedDiscoveryError::InvalidLength);
            }
            let message = core::str::from_utf8(&input[4..input.len() - 1])
                .map_err(|_| TargetedDiscoveryError::InvalidText)?;
            if message.bytes().any(|byte| !(0x20..=0x7e).contains(&byte)) {
                return Err(TargetedDiscoveryError::InvalidText);
            }
            Ok(TftpDiscoveryResponse::Error {
                code: u16::from_be_bytes([input[2], input[3]]),
                message: message.to_owned(),
            })
        }
        6 => Ok(TftpDiscoveryResponse::OptionAcknowledgement(
            parse_tftp_options(&input[2..])?,
        )),
        _ => Err(TargetedDiscoveryError::UnexpectedMessage),
    }
}

#[must_use]
pub fn build_tftp_termination_error(message: &str) -> Option<Vec<u8>> {
    if message.is_empty()
        || message.len() > 127
        || message.bytes().any(|byte| !(0x20..=0x7e).contains(&byte))
    {
        return None;
    }
    let mut output = Vec::with_capacity(message.len() + 5);
    output.extend_from_slice(&5_u16.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(message.as_bytes());
    output.push(0);
    Some(output)
}

/// Builds a minimum-size QUIC reserved-version request with caller-owned IDs.
///
/// # Errors
///
/// Rejects all-zero or identical connection IDs.
pub fn build_quic_version_negotiation_request(
    destination_connection_id: [u8; 8],
    source_connection_id: [u8; 8],
) -> Result<QuicVersionNegotiationRequest, TargetedDiscoveryError> {
    if destination_connection_id == source_connection_id
        || destination_connection_id.iter().all(|byte| *byte == 0)
        || source_connection_id.iter().all(|byte| *byte == 0)
    {
        return Err(TargetedDiscoveryError::InvalidTransaction);
    }
    let reserved_version = 0x0a0a_0a0a_u32;
    let mut bytes = Vec::with_capacity(QUIC_VERSION_NEGOTIATION_REQUEST_BYTES);
    bytes.push(0xc0);
    bytes.extend_from_slice(&reserved_version.to_be_bytes());
    bytes.push(8);
    bytes.extend_from_slice(&destination_connection_id);
    bytes.push(8);
    bytes.extend_from_slice(&source_connection_id);
    bytes.resize(QUIC_VERSION_NEGOTIATION_REQUEST_BYTES, 0);
    Ok(QuicVersionNegotiationRequest {
        bytes,
        destination_connection_id,
        source_connection_id,
        reserved_version,
    })
}

/// Parses a QUIC Version Negotiation packet related by reversed connection IDs.
///
/// # Errors
///
/// Rejects malformed headers, unrelated IDs, duplicate versions, and excess work.
pub fn parse_quic_version_negotiation_response(
    input: &[u8],
    request: &QuicVersionNegotiationRequest,
) -> Result<QuicVersionNegotiationResponse, TargetedDiscoveryError> {
    if input.len() < 7 || input[0] & 0xc0 != 0xc0 || input[1..5] != [0, 0, 0, 0] {
        return Err(TargetedDiscoveryError::UnexpectedMessage);
    }
    let destination_length = usize::from(input[5]);
    let destination_start = 6;
    let destination_end = destination_start + destination_length;
    let source_length_index = destination_end;
    let Some(&source_length) = input.get(source_length_index) else {
        return Err(TargetedDiscoveryError::Truncated);
    };
    let source_start = source_length_index + 1;
    let source_end = source_start + usize::from(source_length);
    if source_end > input.len()
        || input[destination_start..destination_end] != request.source_connection_id
        || input[source_start..source_end] != request.destination_connection_id
    {
        return Err(TargetedDiscoveryError::InvalidTransaction);
    }
    let version_bytes = &input[source_end..];
    if version_bytes.is_empty() || !version_bytes.len().is_multiple_of(4) {
        return Err(TargetedDiscoveryError::InvalidLength);
    }
    if version_bytes.len() / 4 > MAX_QUIC_ADVERTISED_VERSIONS {
        return Err(TargetedDiscoveryError::TooManyValues);
    }
    let mut versions = Vec::with_capacity(version_bytes.len() / 4);
    let mut unique = BTreeSet::new();
    for chunk in version_bytes.chunks_exact(4) {
        let version = u32::from_be_bytes(
            chunk
                .try_into()
                .map_err(|_| TargetedDiscoveryError::InvalidLength)?,
        );
        if version == 0 || !unique.insert(version) {
            return Err(TargetedDiscoveryError::UnexpectedMessage);
        }
        versions.push(version);
    }
    Ok(QuicVersionNegotiationResponse { versions })
}

/// Builds one rpcbind v4 `GETADDR` request.
///
/// # Errors
///
/// Rejects invalid transaction, programme, or version values.
pub fn build_rpcbind_getaddr_request(
    xid: u32,
    programme: u32,
    version: u32,
    ipv6: bool,
) -> Result<Vec<u8>, TargetedDiscoveryError> {
    if xid == 0 || programme == 0 || version == 0 {
        return Err(TargetedDiscoveryError::InvalidTransaction);
    }
    let mut output = Vec::with_capacity(80);
    for value in [xid, 0, 2, 100_000, 4, 3, 0, 0, 0, 0, programme, version] {
        output.extend_from_slice(&value.to_be_bytes());
    }
    push_xdr_string(&mut output, if ipv6 { "udp6" } else { "udp" })?;
    push_xdr_string(&mut output, "")?;
    push_xdr_string(&mut output, "nodenet")?;
    Ok(output)
}

/// Parses one exact accepted rpcbind `GETADDR` reply.
///
/// # Errors
///
/// Rejects unrelated transactions, rejected RPC replies, and malformed XDR.
pub fn parse_rpcbind_getaddr_response(
    input: &[u8],
    expected_xid: u32,
) -> Result<String, TargetedDiscoveryError> {
    if input.len() < 28 || read_u32(input, 0)? != expected_xid || read_u32(input, 4)? != 1 {
        return Err(TargetedDiscoveryError::InvalidTransaction);
    }
    if read_u32(input, 8)? != 0 {
        return Err(TargetedDiscoveryError::UnexpectedMessage);
    }
    let verifier_length =
        usize::try_from(read_u32(input, 16)?).map_err(|_| TargetedDiscoveryError::InvalidLength)?;
    let verifier_padded = verifier_length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(TargetedDiscoveryError::ArithmeticOverflow)?;
    let accept_offset = 20_usize
        .checked_add(verifier_padded)
        .ok_or(TargetedDiscoveryError::ArithmeticOverflow)?;
    if read_u32(input, accept_offset)? != 0 {
        return Err(TargetedDiscoveryError::UnexpectedMessage);
    }
    let value_offset = accept_offset + 4;
    let length = usize::try_from(read_u32(input, value_offset)?)
        .map_err(|_| TargetedDiscoveryError::InvalidLength)?;
    if length == 0 || length > 255 {
        return Err(TargetedDiscoveryError::InvalidEndpoint);
    }
    let end = value_offset
        .checked_add(4)
        .and_then(|value| value.checked_add(length))
        .ok_or(TargetedDiscoveryError::ArithmeticOverflow)?;
    let padded_end = (end + 3) & !3;
    if padded_end != input.len() || input[end..padded_end].iter().any(|byte| *byte != 0) {
        return Err(TargetedDiscoveryError::InvalidLength);
    }
    let value = core::str::from_utf8(&input[value_offset + 4..end])
        .map_err(|_| TargetedDiscoveryError::InvalidText)?;
    Ok(value.to_owned())
}

/// Parses an IPv4 or IPv6 rpcbind universal address and nonzero port.
///
/// # Errors
///
/// Rejects malformed addresses, port bytes, and zero ports.
pub fn parse_rpcbind_universal_address(
    value: &str,
) -> Result<(IpAddr, u16), TargetedDiscoveryError> {
    let Some((host_and_high, low)) = value.rsplit_once('.') else {
        return Err(TargetedDiscoveryError::InvalidEndpoint);
    };
    let Some((host, high)) = host_and_high.rsplit_once('.') else {
        return Err(TargetedDiscoveryError::InvalidEndpoint);
    };
    let high = high
        .parse::<u8>()
        .map_err(|_| TargetedDiscoveryError::InvalidEndpoint)?;
    let low = low
        .parse::<u8>()
        .map_err(|_| TargetedDiscoveryError::InvalidEndpoint)?;
    let port = u16::from(high) * 256 + u16::from(low);
    if port == 0 {
        return Err(TargetedDiscoveryError::InvalidEndpoint);
    }
    let address = host
        .parse::<Ipv4Addr>()
        .map(IpAddr::V4)
        .or_else(|_| host.parse::<Ipv6Addr>().map(IpAddr::V6))
        .map_err(|_| TargetedDiscoveryError::InvalidEndpoint)?;
    Ok((address, port))
}

fn parse_tftp_options(input: &[u8]) -> Result<BTreeMap<String, String>, TargetedDiscoveryError> {
    if input.is_empty() || input.last() != Some(&0) {
        return Err(TargetedDiscoveryError::InvalidLength);
    }
    let pieces: Vec<&[u8]> = input[..input.len() - 1].split(|byte| *byte == 0).collect();
    if !pieces.len().is_multiple_of(2) || pieces.len() / 2 > 16 {
        return Err(TargetedDiscoveryError::InvalidLength);
    }
    let mut options = BTreeMap::new();
    for pair in pieces.chunks_exact(2) {
        let key = core::str::from_utf8(pair[0])
            .map_err(|_| TargetedDiscoveryError::InvalidText)?
            .to_ascii_lowercase();
        let value = core::str::from_utf8(pair[1])
            .map_err(|_| TargetedDiscoveryError::InvalidText)?
            .to_owned();
        if key.is_empty()
            || value.is_empty()
            || key.len() > 64
            || value.len() > 64
            || !key.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(TargetedDiscoveryError::InvalidText);
        }
        if options.insert(key, value).is_some() {
            return Err(TargetedDiscoveryError::DuplicateField);
        }
    }
    Ok(options)
}

fn required_field(
    fields: &BTreeMap<String, String>,
    name: &str,
) -> Result<String, TargetedDiscoveryError> {
    fields
        .get(name)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or(TargetedDiscoveryError::InvalidText)
}

fn push_xdr_string(output: &mut Vec<u8>, value: &str) -> Result<(), TargetedDiscoveryError> {
    let length = u32::try_from(value.len()).map_err(|_| TargetedDiscoveryError::InvalidLength)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    let padding = (4 - value.len() % 4) % 4;
    output.resize(output.len() + padding, 0);
    Ok(())
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, TargetedDiscoveryError> {
    let value = input
        .get(offset..offset.saturating_add(4))
        .ok_or(TargetedDiscoveryError::Truncated)?;
    Ok(u32::from_be_bytes(value.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_pmp_and_sql_browser_are_complete_and_bounded() {
        assert_eq!(build_nat_pmp_external_address_request(), [0, 0]);
        let nat =
            parse_nat_pmp_external_address_response(&[0, 128, 0, 0, 0, 0, 0, 9, 198, 51, 100, 4])
                .unwrap();
        assert_eq!(nat.external_address, Ipv4Addr::new(198, 51, 100, 4));
        let body = b"ServerName;LAB;InstanceName;SQLEXPRESS;IsClustered;No;Version;16.0;tcp;1433;;";
        let mut response = vec![5];
        response.extend_from_slice(&u16::try_from(body.len()).unwrap().to_le_bytes());
        response.extend_from_slice(body);
        let instances = parse_sql_browser_response(&response).unwrap();
        assert_eq!(instances[0].instance_name, "SQLEXPRESS");
        assert_eq!(instances[0].tcp_port, Some(1433));
    }

    #[test]
    fn ripv1_table_datagrams_are_strict_and_preserve_routes() {
        assert_eq!(
            build_ripv1_table_request(),
            [
                1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
            ]
        );
        let mut response = vec![2, 1, 0, 0];
        for (address, metric) in [([192, 0, 2, 0], 1_u32), ([198, 51, 100, 0], 16)] {
            response.extend_from_slice(&2_u16.to_be_bytes());
            response.extend_from_slice(&[0; 2]);
            response.extend_from_slice(&address);
            response.extend_from_slice(&[0; 8]);
            response.extend_from_slice(&metric.to_be_bytes());
        }
        assert_eq!(
            parse_ripv1_table_response(&response).unwrap(),
            [
                RipV1Route {
                    destination: Ipv4Addr::new(192, 0, 2, 0),
                    metric: 1,
                },
                RipV1Route {
                    destination: Ipv4Addr::new(198, 51, 100, 0),
                    metric: 16,
                },
            ]
        );
        response[2] = 1;
        assert!(parse_ripv1_table_response(&response).is_err());
        response[2] = 0;
        response[20..24].copy_from_slice(&17_u32.to_be_bytes());
        assert!(parse_ripv1_table_response(&response).is_err());
    }

    #[test]
    fn tftp_positive_and_error_paths_require_cleanup_capable_structure() {
        let rrq = build_tftp_discovery_rrq([0xab; 16]);
        assert_eq!(&rrq[..2], &[0, 1]);
        assert!(rrq.windows(17).any(|value| value == b"nodenet-discovery"));
        assert_eq!(
            parse_tftp_discovery_response(&[0, 3, 0, 1, 1, 2]).unwrap(),
            TftpDiscoveryResponse::Data {
                block: 1,
                payload_bytes: 2
            }
        );
        assert!(build_tftp_termination_error("discovery complete").is_some());
        assert!(parse_tftp_discovery_response(&[0, 5, 0, 1, b'x']).is_err());
    }

    #[test]
    fn quic_version_negotiation_reverses_cids_and_rejects_duplicates() {
        let request = build_quic_version_negotiation_request([1; 8], [2; 8]).unwrap();
        assert_eq!(request.bytes.len(), QUIC_VERSION_NEGOTIATION_REQUEST_BYTES);
        let mut response = vec![0xc0, 0, 0, 0, 0, 8];
        response.extend_from_slice(&[2; 8]);
        response.push(8);
        response.extend_from_slice(&[1; 8]);
        response.extend_from_slice(&1_u32.to_be_bytes());
        response.extend_from_slice(&0x6b33_43cf_u32.to_be_bytes());
        assert_eq!(
            parse_quic_version_negotiation_response(&response, &request)
                .unwrap()
                .versions,
            [1, 0x6b33_43cf]
        );
        response.extend_from_slice(&1_u32.to_be_bytes());
        assert!(parse_quic_version_negotiation_response(&response, &request).is_err());
    }

    #[test]
    fn rpcbind_getaddr_is_transactional_and_universal_addresses_are_checked() {
        let request = build_rpcbind_getaddr_request(7, 100_003, 3, false).unwrap();
        assert_eq!(&request[..4], &7_u32.to_be_bytes());
        assert_eq!(
            parse_rpcbind_universal_address("192.0.2.4.8.1").unwrap(),
            (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4)), 2049)
        );
        assert!(parse_rpcbind_universal_address("192.0.2.4.0.0").is_err());
    }
}
