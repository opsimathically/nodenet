//! Strict, allocation-bounded passive discovery classification.

use crate::{
    DiscoveryDnsRecordData, Field, IpProtocol, Ipv6Address, Layer, ParseError, ParseMode,
    TransportChecksumContext, UpperLayerState, parse_discovery_dns_message, parse_ipv4_packet,
    parse_ipv6_packet, validate_transport_checksum,
};
use quick_xml::{Reader, events::Event};

pub const MAX_PASSIVE_FIELDS: usize = 32;
pub const MAX_PASSIVE_FIELD_BYTES: usize = 512;
pub const MAX_LLDP_TLVS: usize = 64;
pub const MAX_RA_OPTIONS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassiveProtocol {
    Arp,
    Ipv6NeighborDiscovery,
    Dhcpv4,
    Dhcpv6,
    Mdns,
    Llmnr,
    Nbns,
    Ssdp,
    WsDiscovery,
    RouterAdvertisement,
    RouterSolicitation,
    Ipv6Redirect,
    Lldp,
    Stp,
    Lacp,
    Vrrp,
    Igmp,
    Mld,
    Rip,
    Ospf,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassiveField {
    pub name: &'static str,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassivePacketMetadata {
    pub protocol: PassiveProtocol,
    pub ether_type: u16,
    pub source_mac: [u8; 6],
    pub destination_mac: [u8; 6],
    pub vlan_ids: Vec<u16>,
    pub fields: Vec<PassiveField>,
    pub fragmented: bool,
    pub truncated: bool,
}

/// Classifies a captured Ethernet frame without retaining application payload.
/// Incomplete IP fragments are identified but never passed into a service parser.
///
/// # Errors
///
/// Returns a bounded parse error for a truncated Ethernet/VLAN/IP envelope.
pub fn decode_passive_frame(
    frame: &[u8],
    original_length: usize,
) -> Result<PassivePacketMetadata, ParseError> {
    decode_passive_frame_with_checksum_policy(frame, original_length, true)
}

/// Internal capture entry point for packets whose transport checksum status was
/// supplied by Linux `PACKET_AUXDATA` rather than materialized in the frame.
#[doc(hidden)]
pub fn decode_passive_frame_with_checksum_policy(
    frame: &[u8],
    original_length: usize,
    validate_transport_checksum_bytes: bool,
) -> Result<PassivePacketMetadata, ParseError> {
    if frame.len() < 14 {
        return Err(truncated(Layer::Link, 14, frame.len()));
    }
    let mut destination_mac = [0_u8; 6];
    let mut source_mac = [0_u8; 6];
    destination_mac.copy_from_slice(&frame[..6]);
    source_mac.copy_from_slice(&frame[6..12]);
    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14_usize;
    let mut vlan_ids = Vec::new();
    while matches!(ether_type, 0x8100 | 0x88a8) {
        if vlan_ids.len() == 2 {
            break;
        }
        let header = frame
            .get(offset..offset.saturating_add(4))
            .ok_or_else(|| truncated(Layer::Vlan, offset.saturating_add(4), frame.len()))?;
        vlan_ids.push(u16::from_be_bytes([header[0], header[1]]) & 0x0fff);
        ether_type = u16::from_be_bytes([header[2], header[3]]);
        offset = offset.saturating_add(4);
    }
    let (protocol, fields, fragmented) = match ether_type {
        0x0806 => (PassiveProtocol::Arp, arp_fields(frame, offset)?, false),
        0x0800 => ipv4_metadata(frame, offset, validate_transport_checksum_bytes)?,
        0x86dd => ipv6_metadata(frame, offset, validate_transport_checksum_bytes)?,
        0x88cc => (
            PassiveProtocol::Lldp,
            parse_lldp_fields(frame.get(offset..).unwrap_or_default())?,
            false,
        ),
        0x8809 => (PassiveProtocol::Lacp, Vec::new(), false),
        _ if destination_mac == [0x01, 0x80, 0xc2, 0, 0, 0] => {
            (PassiveProtocol::Stp, Vec::new(), false)
        }
        _ => (PassiveProtocol::Other, Vec::new(), false),
    };
    Ok(PassivePacketMetadata {
        protocol,
        ether_type,
        source_mac,
        destination_mac,
        vlan_ids,
        fields,
        fragmented,
        truncated: original_length > frame.len(),
    })
}

fn arp_fields(frame: &[u8], offset: usize) -> Result<Vec<PassiveField>, ParseError> {
    let packet = frame
        .get(offset..offset.saturating_add(28))
        .ok_or_else(|| truncated(Layer::Arp, offset.saturating_add(28), frame.len()))?;
    if u16::from_be_bytes([packet[0], packet[1]]) != 1 {
        return Err(ParseError::Unsupported {
            layer: Layer::Arp,
            field: Field::HardwareType,
        });
    }
    if u16::from_be_bytes([packet[2], packet[3]]) != 0x0800 {
        return Err(ParseError::Unsupported {
            layer: Layer::Arp,
            field: Field::ProtocolType,
        });
    }
    if packet[4] != 6 || packet[5] != 4 {
        return Err(ParseError::Malformed {
            layer: Layer::Arp,
            field: Field::AddressLength,
        });
    }
    if !matches!(u16::from_be_bytes([packet[6], packet[7]]), 1 | 2) {
        return Err(ParseError::Unsupported {
            layer: Layer::Arp,
            field: Field::Operation,
        });
    }
    Ok(vec![
        field("senderMac", &packet[8..14]),
        field("senderIpv4", &packet[14..18]),
        field("targetMac", &packet[18..24]),
        field("targetIpv4", &packet[24..28]),
    ])
}

fn ipv4_metadata(
    frame: &[u8],
    offset: usize,
    validate_transport_checksum_bytes: bool,
) -> Result<(PassiveProtocol, Vec<PassiveField>, bool), ParseError> {
    let packet = parse_ipv4_packet(frame.get(offset..).unwrap_or_default(), ParseMode::Strict)?;
    let fragmented = packet.fragment.is_fragmented();
    let mut fields = vec![
        field("sourceIpv4", &packet.source.octets()),
        field("destinationIpv4", &packet.destination.octets()),
    ];
    let protocol = match packet.protocol.get() {
        2 => PassiveProtocol::Igmp,
        89 => PassiveProtocol::Ospf,
        112 => PassiveProtocol::Vrrp,
        17 if !fragmented => match packet.upper_layer {
            UpperLayerState::Reachable { payload, .. } => classify_udp(
                validated_udp_payload(
                    payload,
                    TransportChecksumContext::Ipv4 {
                        source: packet.source,
                        destination: packet.destination,
                    },
                    true,
                    validate_transport_checksum_bytes,
                )?,
                &mut fields,
            ),
            _ => PassiveProtocol::Other,
        },
        _ => PassiveProtocol::Other,
    };
    Ok((protocol, fields, fragmented))
}

fn ipv6_metadata(
    frame: &[u8],
    offset: usize,
    validate_transport_checksum_bytes: bool,
) -> Result<(PassiveProtocol, Vec<PassiveField>, bool), ParseError> {
    let packet = parse_ipv6_packet(frame.get(offset..).unwrap_or_default(), ParseMode::Strict)?;
    let source = packet.source.octets();
    let destination = packet.destination.octets();
    let mut fields = vec![
        field("sourceIpv6", &source),
        field("destinationIpv6", &destination),
        field("hopLimit", &[packet.hop_limit]),
    ];
    let fragmented = packet.fragment.is_fragmented();
    let (next, payload) = match packet.upper_layer {
        UpperLayerState::Reachable {
            protocol, payload, ..
        }
        | UpperLayerState::Unknown {
            protocol, payload, ..
        } => (protocol.get(), payload),
        _ => (packet.first_next_header.get(), &[][..]),
    };
    let protocol = match next {
        17 if !fragmented => classify_udp(
            validated_udp_payload(
                payload,
                TransportChecksumContext::Ipv6 {
                    source: packet.source,
                    destination: packet.destination,
                },
                false,
                validate_transport_checksum_bytes,
            )?,
            &mut fields,
        ),
        58 => {
            let kind = payload.first().copied().unwrap_or_default();
            if (133..=137).contains(&kind) && packet.hop_limit != 255 {
                return Err(ParseError::Malformed {
                    layer: Layer::Ndp,
                    field: Field::HopLimit,
                });
            }
            if matches!(kind, 134 | 137) && (source[0] != 0xfe || source[1] & 0xc0 != 0x80) {
                return Err(ParseError::Malformed {
                    layer: Layer::Ndp,
                    field: Field::Address,
                });
            }
            if validate_transport_checksum_bytes
                && !validate_transport_checksum(
                    TransportChecksumContext::Ipv6 {
                        source: Ipv6Address::new(source),
                        destination: Ipv6Address::new(destination),
                    },
                    IpProtocol::new(58),
                    payload,
                )
            {
                return Err(ParseError::Malformed {
                    layer: Layer::Icmpv6,
                    field: Field::Checksum,
                });
            }
            classify_icmpv6(payload, &mut fields)?
        }
        89 => PassiveProtocol::Ospf,
        112 => PassiveProtocol::Vrrp,
        _ => PassiveProtocol::Other,
    };
    Ok((protocol, fields, fragmented))
}

fn validated_udp_payload(
    payload: &[u8],
    context: TransportChecksumContext,
    zero_checksum_allowed: bool,
    validate_checksum_bytes: bool,
) -> Result<&[u8], ParseError> {
    let header = payload
        .get(..8)
        .ok_or_else(|| truncated(Layer::Udp, 8, payload.len()))?;
    let length = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if length < 8 {
        return Err(ParseError::Malformed {
            layer: Layer::Udp,
            field: Field::TotalLength,
        });
    }
    let datagram = payload
        .get(..length)
        .ok_or_else(|| truncated(Layer::Udp, length, payload.len()))?;
    let checksum = u16::from_be_bytes([header[6], header[7]]);
    if validate_checksum_bytes
        && (!zero_checksum_allowed || checksum != 0)
        && !validate_transport_checksum(context, IpProtocol::new(17), datagram)
    {
        return Err(ParseError::Malformed {
            layer: Layer::Udp,
            field: Field::Checksum,
        });
    }
    Ok(datagram)
}

fn classify_udp(payload: &[u8], fields: &mut Vec<PassiveField>) -> PassiveProtocol {
    let Some(header) = payload.get(..8) else {
        return PassiveProtocol::Other;
    };
    let source = u16::from_be_bytes([header[0], header[1]]);
    let destination = u16::from_be_bytes([header[2], header[3]]);
    fields.push(field("sourcePort", &source.to_be_bytes()));
    fields.push(field("destinationPort", &destination.to_be_bytes()));
    let candidate = match (source, destination) {
        (67 | 68, 67 | 68) => PassiveProtocol::Dhcpv4,
        (546 | 547, 546 | 547) => PassiveProtocol::Dhcpv6,
        (5353, _) | (_, 5353) => PassiveProtocol::Mdns,
        (5355, _) | (_, 5355) => PassiveProtocol::Llmnr,
        (137, _) | (_, 137) => PassiveProtocol::Nbns,
        (1900, _) | (_, 1900) => PassiveProtocol::Ssdp,
        (3702, _) | (_, 3702) => PassiveProtocol::WsDiscovery,
        (520, _) | (_, 520) => PassiveProtocol::Rip,
        _ => PassiveProtocol::Other,
    };
    let body = payload.get(8..).unwrap_or_default();
    let valid = match candidate {
        PassiveProtocol::Dhcpv4 => parse_dhcpv4_fields(body, fields),
        PassiveProtocol::Dhcpv6 => parse_dhcpv6_fields(body, fields),
        PassiveProtocol::Mdns | PassiveProtocol::Llmnr | PassiveProtocol::Nbns => {
            parse_dns_fields(body, fields)
        }
        PassiveProtocol::Ssdp => parse_ssdp_fields(body, fields),
        PassiveProtocol::WsDiscovery => parse_ws_discovery_fields(body, fields),
        PassiveProtocol::Rip => valid_rip_message(body),
        _ => false,
    };
    if valid {
        candidate
    } else {
        PassiveProtocol::Other
    }
}

fn parse_dhcpv4_fields(payload: &[u8], fields: &mut Vec<PassiveField>) -> bool {
    if payload.len() < 240 || payload[236..240] != [99, 130, 83, 99] {
        return false;
    }
    fields.push(field("dhcpClientAddress", &payload[12..16]));
    fields.push(field("dhcpYourAddress", &payload[16..20]));
    fields.push(field("dhcpServerAddress", &payload[20..24]));
    let hardware_length = usize::from(payload[2]).min(16);
    fields.push(field(
        "dhcpClientHardwareAddress",
        &payload[28..28 + hardware_length],
    ));
    let mut offset = 240_usize;
    let mut count = 0_usize;
    let mut message_type = false;
    let mut terminated = false;
    while offset < payload.len() && count < MAX_PASSIVE_FIELDS {
        let code = payload[offset];
        offset += 1;
        if code == 0 {
            continue;
        }
        if code == 255 {
            terminated = true;
            break;
        }
        let Some(length) = payload.get(offset).copied().map(usize::from) else {
            break;
        };
        offset += 1;
        let Some(value) = payload.get(offset..offset.saturating_add(length)) else {
            break;
        };
        match code {
            6 => fields.push(field("dhcpDnsServers", value)),
            12 => fields.push(field("dhcpHostName", value)),
            15 => fields.push(field("dhcpDomainName", value)),
            50 => fields.push(field("dhcpRequestedAddress", value)),
            51 => fields.push(field("dhcpLeaseTime", value)),
            53 if value.len() == 1 && (1..=8).contains(&value[0]) => {
                fields.push(field("dhcpMessageType", value));
                message_type = true;
            }
            54 => fields.push(field("dhcpServerIdentifier", value)),
            55 => fields.push(field("dhcpParameterRequestList", value)),
            60 => fields.push(field("dhcpVendorClass", value)),
            61 => fields.push(field("dhcpClientIdentifier", value)),
            119 => fields.push(field("dhcpDomainSearch", value)),
            _ => {}
        }
        offset = offset.saturating_add(length);
        count += 1;
    }
    terminated && message_type
}

fn parse_dhcpv6_fields(payload: &[u8], fields: &mut Vec<PassiveField>) -> bool {
    let Some(message_type) = payload.first().copied() else {
        return false;
    };
    if !(1..=13).contains(&message_type) {
        return false;
    }
    fields.push(field("dhcpv6MessageType", &payload[..1]));
    let mut offset: usize = if matches!(message_type, 12 | 13) {
        if payload.len() < 34 {
            return false;
        }
        fields.push(field("dhcpv6RelayHopCount", &payload[1..2]));
        fields.push(field("dhcpv6RelayLinkAddress", &payload[2..18]));
        fields.push(field("dhcpv6RelayPeerAddress", &payload[18..34]));
        34
    } else {
        if payload.len() < 4 {
            return false;
        }
        fields.push(field("dhcpv6TransactionId", &payload[1..4]));
        4
    };
    let mut count = 0_usize;
    while offset.saturating_add(4) <= payload.len() && count < MAX_PASSIVE_FIELDS {
        let code = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([
            payload[offset + 2],
            payload[offset + 3],
        ]));
        offset += 4;
        let Some(value) = payload.get(offset..offset.saturating_add(length)) else {
            break;
        };
        match code {
            1 => fields.push(field("dhcpv6ClientId", value)),
            2 => fields.push(field("dhcpv6ServerId", value)),
            3 => fields.push(field("dhcpv6IdentityAssociation", value)),
            23 => fields.push(field("dhcpv6DnsServers", value)),
            24 => fields.push(field("dhcpv6DomainSearch", value)),
            39 => fields.push(field("dhcpv6ClientFqdn", value)),
            _ => {}
        }
        offset = offset.saturating_add(length);
        count += 1;
    }
    offset == payload.len()
}

fn parse_dns_fields(payload: &[u8], fields: &mut Vec<PassiveField>) -> bool {
    let Ok(message) = parse_discovery_dns_message(payload) else {
        return false;
    };
    if !message.is_response() || message.truncated() || message.records().next().is_none() {
        return false;
    }
    fields.push(field("dnsTransactionId", &message.id.to_be_bytes()));
    for record in message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
        .take(MAX_PASSIVE_FIELDS.saturating_sub(fields.len()))
    {
        fields.push(field("dnsRecordName", &record.name.canonical_wire));
        fields.push(field("dnsRecordType", &record.record_type.to_be_bytes()));
        fields.push(field("dnsTtl", &record.ttl.to_be_bytes()));
        fields.push(field("dnsCacheFlush", &[u8::from(record.cache_flush)]));
        match &record.data {
            DiscoveryDnsRecordData::Ptr(name) => {
                fields.push(field("dnsPtr", &name.canonical_wire));
            }
            DiscoveryDnsRecordData::Srv { port, target, .. } => {
                fields.push(field("dnsSrvPort", &port.to_be_bytes()));
                fields.push(field("dnsSrvTarget", &target.canonical_wire));
            }
            DiscoveryDnsRecordData::A(address) => fields.push(field("dnsIpv4", address)),
            DiscoveryDnsRecordData::Aaaa(address) => fields.push(field("dnsIpv6", address)),
            DiscoveryDnsRecordData::Txt(entries) => {
                for entry in entries.iter().take(8) {
                    fields.push(field("dnsTxtKey", entry.key.as_bytes()));
                    fields.push(field("dnsTxtValue", &entry.value));
                }
            }
            DiscoveryDnsRecordData::Unknown => {}
        }
    }
    fields.truncate(MAX_PASSIVE_FIELDS);
    true
}

fn parse_ssdp_fields(payload: &[u8], fields: &mut Vec<PassiveField>) -> bool {
    if payload.len() > MAX_PASSIVE_FIELD_BYTES.saturating_mul(8) || !payload.ends_with(b"\r\n\r\n")
    {
        return false;
    }
    let mut lines = payload.split(|byte| *byte == b'\n').take(64);
    let first = lines.next().unwrap_or_default();
    let first = first.strip_suffix(b"\r").unwrap_or(first);
    let advertisement = first.eq_ignore_ascii_case(b"NOTIFY * HTTP/1.1")
        || first
            .strip_prefix(b"HTTP/1.1 ")
            .is_some_and(|status| status.len() >= 3 && status[..3].iter().all(u8::is_ascii_digit));
    if !advertisement {
        return false;
    }
    fields.push(field("ssdpStartLine", first));
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let (name, value) = (&line[..separator], trim_ascii(&line[separator + 1..]));
        if name.eq_ignore_ascii_case(b"cache-control") {
            fields.push(field("ssdpCacheControl", value));
            if let Some(seconds) = parse_ascii_max_age(value) {
                fields.push(field("ssdpMaxAge", &seconds.to_be_bytes()));
            }
        } else if name.eq_ignore_ascii_case(b"location") {
            fields.push(field("ssdpLocation", value));
        } else if name.eq_ignore_ascii_case(b"usn") {
            fields.push(field("ssdpUsn", value));
        } else if name.eq_ignore_ascii_case(b"nt") || name.eq_ignore_ascii_case(b"st") {
            fields.push(field("ssdpTarget", value));
        } else if name.eq_ignore_ascii_case(b"nts") {
            fields.push(field("ssdpNts", value));
        } else if name.eq_ignore_ascii_case(b"server") {
            fields.push(field("ssdpServer", value));
        }
    }
    fields.truncate(MAX_PASSIVE_FIELDS);
    true
}

fn parse_ascii_max_age(value: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(value).ok()?;
    text.split(',').find_map(|part| {
        let (name, number) = part.trim().split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("max-age")
            .then(|| number.trim().parse::<u32>().ok())?
    })
}

fn parse_ws_discovery_fields(payload: &[u8], fields: &mut Vec<PassiveField>) -> bool {
    if payload.len() > MAX_PASSIVE_FIELD_BYTES.saturating_mul(8) || !payload.is_ascii() {
        return false;
    }
    let mut reader = Reader::from_reader(payload);
    reader.config_mut().enable_all_checks(true);
    reader.config_mut().expand_empty_elements = true;
    let mut depth = 0_usize;
    let mut tokens = 0_usize;
    let mut saw_discovery_evidence = false;
    loop {
        tokens = tokens.saturating_add(1);
        if tokens > 512 {
            return false;
        }
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                depth = depth.saturating_add(1);
                if depth > 32 {
                    return false;
                }
                let name = start.local_name();
                if matches!(name.as_ref(), b"ProbeMatches" | b"Hello" | b"Bye") {
                    saw_discovery_evidence = true;
                }
            }
            Ok(Event::End(_)) => {
                let Some(next) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next;
            }
            Ok(Event::Eof) => break,
            Err(_) => return false,
            _ => {}
        }
    }
    if depth != 0 || !saw_discovery_evidence {
        return false;
    }
    for (local_name, field_name) in [
        ("MessageID", "wsMessageId"),
        ("RelatesTo", "wsRelatesTo"),
        ("Address", "wsEndpointAddress"),
        ("Types", "wsTypes"),
        ("Scopes", "wsScopes"),
        ("XAddrs", "wsXAddrs"),
        ("MetadataVersion", "wsMetadataVersion"),
    ] {
        if let Some(value) = extract_xml_local_text(payload, local_name) {
            fields.push(field(field_name, value));
        }
    }
    true
}

fn valid_rip_message(payload: &[u8]) -> bool {
    payload.len() >= 4
        && (payload.len() - 4).is_multiple_of(20)
        && matches!(payload[0], 1 | 2)
        && matches!(payload[1], 1 | 2)
        && payload[2..4] == [0, 0]
}

fn extract_xml_local_text<'a>(payload: &'a [u8], local_name: &str) -> Option<&'a [u8]> {
    let suffix = format!("{local_name}>");
    let start = payload
        .windows(suffix.len())
        .position(|window| window.eq_ignore_ascii_case(suffix.as_bytes()))?;
    if start == 0 || !matches!(payload[start - 1], b'<' | b':') {
        return None;
    }
    let value_start = start.saturating_add(suffix.len());
    let remaining = payload.get(value_start..)?;
    let end = remaining.windows(2).position(|window| window == b"</")?;
    let value = trim_ascii(&remaining[..end]);
    (!value.is_empty() && value.len() <= MAX_PASSIVE_FIELD_BYTES).then_some(value)
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn classify_icmpv6(
    payload: &[u8],
    fields: &mut Vec<PassiveField>,
) -> Result<PassiveProtocol, ParseError> {
    let kind = *payload
        .first()
        .ok_or_else(|| truncated(Layer::Icmpv6, 1, payload.len()))?;
    fields.push(field("icmpv6Type", &[kind]));
    Ok(match kind {
        130..=132 | 143 => PassiveProtocol::Mld,
        133 => PassiveProtocol::RouterSolicitation,
        134 => {
            fields.extend(parse_ra_fields(payload)?);
            PassiveProtocol::RouterAdvertisement
        }
        135 | 136 => {
            fields.extend(parse_neighbor_fields(payload, kind)?);
            PassiveProtocol::Ipv6NeighborDiscovery
        }
        137 => {
            fields.extend(parse_redirect_fields(payload)?);
            PassiveProtocol::Ipv6Redirect
        }
        _ => PassiveProtocol::Other,
    })
}

fn parse_neighbor_fields(payload: &[u8], kind: u8) -> Result<Vec<PassiveField>, ParseError> {
    if payload.len() < 24 {
        return Err(truncated(Layer::Ndp, 24, payload.len()));
    }
    let mut fields = vec![field("ndpTargetAddress", &payload[8..24])];
    if kind == 136 {
        fields.push(field("ndpAdvertisementFlags", &payload[4..8]));
    }
    parse_ndp_link_options(&payload[24..], &mut fields)?;
    Ok(fields)
}

fn parse_redirect_fields(payload: &[u8]) -> Result<Vec<PassiveField>, ParseError> {
    if payload.len() < 40 {
        return Err(truncated(Layer::Ndp, 40, payload.len()));
    }
    let mut fields = vec![
        field("ndpRedirectTarget", &payload[8..24]),
        field("ndpRedirectDestination", &payload[24..40]),
    ];
    parse_ndp_link_options(&payload[40..], &mut fields)?;
    Ok(fields)
}

fn parse_ndp_link_options(
    options: &[u8],
    fields: &mut Vec<PassiveField>,
) -> Result<(), ParseError> {
    let mut offset = 0_usize;
    let mut count = 0_usize;
    while offset < options.len() && count < MAX_RA_OPTIONS {
        let header = options
            .get(offset..offset.saturating_add(2))
            .ok_or_else(|| truncated(Layer::Ndp, offset.saturating_add(2), options.len()))?;
        let length = usize::from(header[1]).saturating_mul(8);
        if length == 0 || offset.saturating_add(length) > options.len() {
            return Err(ParseError::Malformed {
                layer: Layer::Ndp,
                field: Field::OptionLength,
            });
        }
        match (header[0], length) {
            (1, 8) => fields.push(field("ndpSourceMac", &options[offset + 2..offset + 8])),
            (2, 8) => fields.push(field("ndpTargetMac", &options[offset + 2..offset + 8])),
            _ => {}
        }
        offset = offset.saturating_add(length);
        count += 1;
    }
    if offset != options.len() {
        return Err(ParseError::Malformed {
            layer: Layer::Ndp,
            field: Field::OptionLength,
        });
    }
    Ok(())
}

fn parse_ra_fields(payload: &[u8]) -> Result<Vec<PassiveField>, ParseError> {
    if payload.len() < 16 {
        return Err(truncated(Layer::Icmpv6, 16, payload.len()));
    }
    let mut fields = vec![
        field("currentHopLimit", &payload[4..5]),
        field("routerFlags", &payload[5..6]),
        field("routerPreference", &[((payload[5] >> 3) & 0x03)]),
        field("routerLifetime", &payload[6..8]),
        field("reachableTime", &payload[8..12]),
        field("retransTimer", &payload[12..16]),
    ];
    let mut offset = 16_usize;
    let mut options = 0_usize;
    while offset < payload.len() && options < MAX_RA_OPTIONS {
        let header = payload
            .get(offset..offset.saturating_add(2))
            .ok_or_else(|| truncated(Layer::Ndp, offset.saturating_add(2), payload.len()))?;
        let length = usize::from(header[1]).saturating_mul(8);
        if length == 0 || offset.saturating_add(length) > payload.len() {
            return Err(ParseError::Malformed {
                layer: Layer::Ndp,
                field: Field::OptionLength,
            });
        }
        match (header[0], length) {
            (1, 8) => fields.push(field("routerSourceMac", &payload[offset + 2..offset + 8])),
            (3, 32) => {
                fields.push(field("prefixLength", &payload[offset + 2..offset + 3]));
                fields.push(field("prefixFlags", &payload[offset + 3..offset + 4]));
                fields.push(field(
                    "prefixValidLifetime",
                    &payload[offset + 4..offset + 8],
                ));
                fields.push(field(
                    "prefixPreferredLifetime",
                    &payload[offset + 8..offset + 12],
                ));
                fields.push(field("prefix", &payload[offset + 16..offset + 32]));
            }
            (5, 8) => fields.push(field("mtu", &payload[offset + 4..offset + 8])),
            (24, 8..=24) => {
                fields.push(field("routePrefixLength", &payload[offset + 2..offset + 3]));
                fields.push(field(
                    "routePreference",
                    &[((payload[offset + 3] >> 3) & 0x03)],
                ));
                fields.push(field("routeLifetime", &payload[offset + 4..offset + 8]));
                fields.push(field("routePrefix", &payload[offset + 8..offset + length]));
            }
            (25, 24..=MAX_PASSIVE_FIELD_BYTES) => {
                fields.push(field("rdnssLifetime", &payload[offset + 4..offset + 8]));
                fields.push(field("rdnssServers", &payload[offset + 8..offset + length]));
            }
            (31, 16..=MAX_PASSIVE_FIELD_BYTES) => {
                fields.push(field("dnsslLifetime", &payload[offset + 4..offset + 8]));
                fields.push(field("dnsslDomains", &payload[offset + 8..offset + length]));
            }
            (37, 8..=MAX_PASSIVE_FIELD_BYTES) => {
                fields.push(field(
                    "captivePortal",
                    &payload[offset + 2..offset + length],
                ));
            }
            _ => {
                fields.push(field("unknownRaOptionType", &payload[offset..=offset]));
                fields.push(field(
                    "unknownRaOptionLength",
                    &payload[offset + 1..offset + 2],
                ));
            }
        }
        offset = offset.saturating_add(length);
        options += 1;
    }
    if offset != payload.len() {
        return Err(ParseError::Malformed {
            layer: Layer::Ndp,
            field: Field::OptionLength,
        });
    }
    fields.truncate(MAX_PASSIVE_FIELDS);
    Ok(fields)
}

/// Parses one already envelope-validated `ICMPv6` Router Advertisement.
///
/// Callers remain responsible for enforcing the IPv6 source scope, hop limit,
/// and checksum because those properties live outside the `ICMPv6` payload.
///
/// # Errors
///
/// Returns a bounded error when the message is not an RA or has malformed
/// options.
pub fn parse_router_advertisement_metadata(
    payload: &[u8],
) -> Result<Vec<PassiveField>, ParseError> {
    if payload.first() != Some(&134) {
        return Err(ParseError::Malformed {
            layer: Layer::Icmpv6,
            field: Field::Type,
        });
    }
    if payload.get(1) != Some(&0) {
        return Err(ParseError::Malformed {
            layer: Layer::Icmpv6,
            field: Field::Code,
        });
    }
    parse_ra_fields(payload)
}

fn parse_lldp_fields(payload: &[u8]) -> Result<Vec<PassiveField>, ParseError> {
    let mut fields = Vec::new();
    let mut offset = 0_usize;
    let mut count = 0_usize;
    let mut saw_end = false;
    while offset < payload.len() && count < MAX_LLDP_TLVS {
        let header = payload
            .get(offset..offset.saturating_add(2))
            .ok_or_else(|| truncated(Layer::Link, offset.saturating_add(2), payload.len()))?;
        let combined = u16::from_be_bytes([header[0], header[1]]);
        let kind = u8::try_from(combined >> 9).unwrap_or_default();
        let length = usize::from(combined & 0x01ff);
        offset = offset.saturating_add(2);
        let value = payload
            .get(offset..offset.saturating_add(length))
            .ok_or_else(|| truncated(Layer::Link, offset.saturating_add(length), payload.len()))?;
        if count < 3 && kind != [1, 2, 3][count] {
            return Err(ParseError::Malformed {
                layer: Layer::Link,
                field: Field::OptionKind,
            });
        }
        if matches!(kind, 1 | 2) && length < 2
            || kind == 3 && length != 2
            || kind == 0 && length != 0
        {
            return Err(ParseError::Malformed {
                layer: Layer::Link,
                field: Field::OptionLength,
            });
        }
        if length <= MAX_PASSIVE_FIELD_BYTES {
            match kind {
                1 if !value.is_empty() => {
                    fields.push(field("chassisIdSubtype", &value[..1]));
                    fields.push(field("chassisId", &value[1..]));
                }
                2 if !value.is_empty() => {
                    fields.push(field("portIdSubtype", &value[..1]));
                    fields.push(field("portId", &value[1..]));
                }
                3 => fields.push(field("ttl", value)),
                4 => fields.push(field("portDescription", value)),
                5 => fields.push(field("systemName", value)),
                6 => fields.push(field("systemDescription", value)),
                7 if value.len() == 4 => {
                    fields.push(field("systemCapabilitiesAvailable", &value[..2]));
                    fields.push(field("systemCapabilitiesEnabled", &value[2..4]));
                }
                8 if value.len() >= 2 => {
                    let address_length = usize::from(value[0]);
                    if address_length >= 1 && address_length < value.len() {
                        fields.push(field("managementAddressSubtype", &value[1..2]));
                        fields.push(field("managementAddress", &value[2..=address_length]));
                    }
                }
                127 if value.len() >= 6 && value[..3] == [0x00, 0x80, 0xc2] => {
                    fields.push(field("lldpOrganizationSubtype", &value[3..4]));
                    if value[3] == 1 && value.len() == 6 {
                        fields.push(field("portVlanId", &value[4..6]));
                    }
                }
                _ => {}
            }
        }
        offset = offset.saturating_add(length);
        count += 1;
        if kind == 0 {
            saw_end = true;
            break;
        }
    }
    if !saw_end || payload[offset..].iter().any(|byte| *byte != 0) {
        return Err(ParseError::Malformed {
            layer: Layer::Link,
            field: Field::OptionLength,
        });
    }
    fields.truncate(MAX_PASSIVE_FIELDS);
    Ok(fields)
}

fn field(name: &'static str, bytes: &[u8]) -> PassiveField {
    PassiveField {
        name,
        value: bytes[..bytes.len().min(MAX_PASSIVE_FIELD_BYTES)].to_vec(),
    }
}

const fn truncated(layer: Layer, required: usize, actual: usize) -> ParseError {
    ParseError::Truncated {
        layer,
        required,
        actual,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arp_requires_an_ethernet_ipv4_request_or_reply_header() {
        let mut frame = vec![0_u8; 14 + 28];
        frame[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        frame[14..16].copy_from_slice(&1_u16.to_be_bytes());
        frame[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[18] = 6;
        frame[19] = 4;
        frame[20..22].copy_from_slice(&1_u16.to_be_bytes());
        frame[22..28].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        frame[28..32].copy_from_slice(&[192, 0, 2, 1]);
        frame[38..42].copy_from_slice(&[192, 0, 2, 2]);
        assert_eq!(
            decode_passive_frame(&frame, frame.len())
                .expect("valid Ethernet/IPv4 ARP request")
                .protocol,
            PassiveProtocol::Arp
        );

        frame[20..22].copy_from_slice(&3_u16.to_be_bytes());
        assert!(matches!(
            decode_passive_frame(&frame, frame.len()),
            Err(ParseError::Unsupported {
                layer: Layer::Arp,
                field: Field::Operation
            })
        ));
        assert!(matches!(
            decode_passive_frame(&frame[..frame.len() - 1], frame.len() - 1),
            Err(ParseError::Truncated {
                layer: Layer::Arp,
                ..
            })
        ));
    }

    #[test]
    fn classifies_mdns_without_retaining_payload() {
        let mut dns = vec![0_u8; 12];
        dns[2..4].copy_from_slice(&0x8400_u16.to_be_bytes());
        dns[6..8].copy_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&[7, b'f', b'i', b'x', b't', b'u', b'r', b'e', 0]);
        dns.extend_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&120_u32.to_be_bytes());
        dns.extend_from_slice(&4_u16.to_be_bytes());
        dns.extend_from_slice(&[192, 0, 2, 10]);
        let frame = ipv4_udp_frame(5353, 5353, &dns, false);
        let decoded = decode_passive_frame(&frame, frame.len()).expect("valid frame");
        assert_eq!(decoded.protocol, PassiveProtocol::Mdns);
        assert!(
            decoded
                .fields
                .iter()
                .all(|field| field.value.len() <= MAX_PASSIVE_FIELD_BYTES)
        );
    }

    #[test]
    fn fragments_do_not_enter_udp_classifier() {
        let frame = ipv4_udp_frame(5353, 5353, &[], true);
        let decoded = decode_passive_frame(&frame, frame.len()).expect("valid fragment");
        assert!(decoded.fragmented);
        assert_eq!(decoded.protocol, PassiveProtocol::Other);
    }

    #[test]
    fn queries_and_malformed_udp_never_become_service_protocols() {
        let mut query = vec![0_u8; 12];
        query[4..6].copy_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&[7, b'f', b'i', b'x', b't', b'u', b'r', b'e', 0]);
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        let frame = ipv4_udp_frame(5353, 5353, &query, false);
        assert_eq!(
            decode_passive_frame(&frame, frame.len())
                .expect("valid query envelope")
                .protocol,
            PassiveProtocol::Other
        );

        let mut malformed = frame;
        malformed[38..40].copy_from_slice(&7_u16.to_be_bytes());
        assert!(decode_passive_frame(&malformed, malformed.len()).is_err());
    }

    fn ipv4_udp_frame(
        source_port: u16,
        destination_port: u16,
        body: &[u8],
        fragmented: bool,
    ) -> Vec<u8> {
        let udp_length = 8_usize.saturating_add(body.len());
        let total_length = 20_usize.saturating_add(udp_length);
        let mut frame = vec![0_u8; 14 + total_length];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        let ip = &mut frame[14..34];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&u16::try_from(total_length).unwrap().to_be_bytes());
        if fragmented {
            ip[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        }
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[192, 0, 2, 1]);
        ip[16..20].copy_from_slice(&[224, 0, 0, 251]);
        let checksum = crate::compute_internet_checksum(ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        let udp = &mut frame[34..];
        udp[..2].copy_from_slice(&source_port.to_be_bytes());
        udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        udp[4..6].copy_from_slice(&u16::try_from(udp_length).unwrap().to_be_bytes());
        udp[8..].copy_from_slice(body);
        frame
    }

    #[test]
    fn dhcp_identity_and_lifetime_options_are_bounded_and_typed() {
        let mut udp = vec![0_u8; 8 + 240];
        udp[..2].copy_from_slice(&67_u16.to_be_bytes());
        udp[2..4].copy_from_slice(&68_u16.to_be_bytes());
        udp[8 + 236..8 + 240].copy_from_slice(&[99, 130, 83, 99]);
        udp.extend_from_slice(&[53, 1, 5, 12, 4, b'h', b'o', b's', b't']);
        udp.extend_from_slice(&[51, 4, 0, 0, 0x0e, 0x10, 255]);
        let mut fields = Vec::new();
        assert_eq!(classify_udp(&udp, &mut fields), PassiveProtocol::Dhcpv4);
        assert!(
            fields
                .iter()
                .any(|field| field.name == "dhcpHostName" && field.value == b"host")
        );
        assert!(
            fields
                .iter()
                .any(|field| field.name == "dhcpLeaseTime" && field.value == [0, 0, 0x0e, 0x10])
        );
    }

    #[test]
    fn ssdp_lifetime_and_withdrawal_are_structured() {
        let mut udp = vec![0_u8; 8];
        udp[..2].copy_from_slice(&1900_u16.to_be_bytes());
        udp[2..4].copy_from_slice(&1900_u16.to_be_bytes());
        udp.extend_from_slice(b"NOTIFY * HTTP/1.1\r\nCACHE-CONTROL: max-age=1800\r\nNTS: ssdp:byebye\r\nUSN: uuid:fixture\r\n\r\n");
        let mut fields = Vec::new();
        assert_eq!(classify_udp(&udp, &mut fields), PassiveProtocol::Ssdp);
        assert!(
            fields
                .iter()
                .any(|field| field.name == "ssdpMaxAge" && field.value == 1800_u32.to_be_bytes())
        );
        assert!(
            fields
                .iter()
                .any(|field| field.name == "ssdpNts" && field.value == b"ssdp:byebye")
        );
    }

    #[test]
    fn neighbor_advertisement_exposes_target_and_link_identity() {
        let mut message = vec![0_u8; 32];
        message[0] = 136;
        message[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        message[24] = 2;
        message[25] = 1;
        message[26..32].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        let mut fields = Vec::new();
        assert_eq!(
            classify_icmpv6(&message, &mut fields).expect("valid NA"),
            PassiveProtocol::Ipv6NeighborDiscovery
        );
        assert!(
            fields
                .iter()
                .any(|field| field.name == "ndpTargetMac" && field.value == [2, 0, 0, 0, 0, 1])
        );
    }

    #[test]
    fn mdns_goodbye_and_cache_flush_are_typed() {
        let mut dns = vec![0_u8; 12];
        dns[2..4].copy_from_slice(&0x8400_u16.to_be_bytes());
        dns[6..8].copy_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&[
            7, b'f', b'i', b'x', b't', b'u', b'r', b'e', 5, b'l', b'o', b'c', b'a', b'l', 0,
        ]);
        dns.extend_from_slice(&1_u16.to_be_bytes());
        dns.extend_from_slice(&0x8001_u16.to_be_bytes());
        dns.extend_from_slice(&0_u32.to_be_bytes());
        dns.extend_from_slice(&4_u16.to_be_bytes());
        dns.extend_from_slice(&[192, 0, 2, 10]);
        let mut udp = vec![0_u8; 8];
        udp[..2].copy_from_slice(&5353_u16.to_be_bytes());
        udp[2..4].copy_from_slice(&5353_u16.to_be_bytes());
        udp.extend_from_slice(&dns);
        let mut fields = Vec::new();
        assert_eq!(classify_udp(&udp, &mut fields), PassiveProtocol::Mdns);
        assert!(
            fields
                .iter()
                .any(|field| field.name == "dnsTtl" && field.value == 0_u32.to_be_bytes())
        );
        assert!(
            fields
                .iter()
                .any(|field| field.name == "dnsCacheFlush" && field.value == [1])
        );
    }

    #[test]
    fn hostile_frames_never_panic_or_exceed_output_bounds() {
        let mut state = 0x5a17_9c3d_u32;
        for length in 0..=1_024 {
            let mut frame = vec![0_u8; length];
            for byte in &mut frame {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = state.to_be_bytes()[0];
            }
            if let Ok(decoded) = decode_passive_frame(&frame, length.saturating_add(length % 7)) {
                assert!(decoded.fields.len() <= MAX_PASSIVE_FIELDS);
                assert!(
                    decoded
                        .fields
                        .iter()
                        .all(|field| field.value.len() <= MAX_PASSIVE_FIELD_BYTES)
                );
                assert!(decoded.vlan_ids.len() <= 2);
            }
        }
    }

    #[test]
    fn router_advertisements_require_link_scope_hop_limit_and_valid_checksum() {
        let source = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let destination = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut message = vec![0_u8; 48];
        message[0] = 134;
        message[4] = 64;
        message[5] = 0x08;
        message[6..8].copy_from_slice(&1_800_u16.to_be_bytes());
        message[16] = 3;
        message[17] = 4;
        message[18] = 64;
        message[19] = 0xc0;
        message[20..24].copy_from_slice(&3_600_u32.to_be_bytes());
        message[24..28].copy_from_slice(&1_800_u32.to_be_bytes());
        message[32..48].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let checksum = crate::compute_transport_checksum(
            TransportChecksumContext::Ipv6 {
                source: Ipv6Address::new(source),
                destination: Ipv6Address::new(destination),
            },
            IpProtocol::new(58),
            &message,
        )
        .expect("bounded checksum");
        message[2..4].copy_from_slice(&checksum.to_be_bytes());
        let mut frame = vec![0_u8; 14 + 40];
        frame[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        frame[14] = 0x60;
        frame[18..20].copy_from_slice(
            &u16::try_from(message.len())
                .expect("fixture length")
                .to_be_bytes(),
        );
        frame[20] = 58;
        frame[21] = 255;
        frame[22..38].copy_from_slice(&source);
        frame[38..54].copy_from_slice(&destination);
        frame.extend_from_slice(&message);
        let decoded = decode_passive_frame(&frame, frame.len()).expect("valid RA");
        assert_eq!(decoded.protocol, PassiveProtocol::RouterAdvertisement);
        assert!(decoded.fields.iter().any(|field| {
            field.name == "prefixValidLifetime" && field.value == 3_600_u32.to_be_bytes()
        }));

        frame[21] = 64;
        assert!(matches!(
            decode_passive_frame(&frame, frame.len()),
            Err(ParseError::Malformed {
                layer: Layer::Ndp,
                field: Field::HopLimit
            })
        ));
    }
}
